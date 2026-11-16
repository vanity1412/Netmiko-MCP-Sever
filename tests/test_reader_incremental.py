"""Reader cache invalidation and conservative XML-prefix veto regressions."""
from pathlib import Path
import random
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'mcp'))
import collector_backend as b
from test_ssh_scenarios import TimelineChannel, VirtualClock


class IncrementalReaderTests(unittest.TestCase):
    def read(self, command, events, timeout=2, pattern=r'(?m)^router#$'):
        clock = VirtualClock()
        conn = TimelineChannel(clock, events)
        conn._network_prompt_text = 'router#'
        conn._network_prompt_regex = r'(?m)^router#$'
        with patch.object(b, 'time', SimpleNamespace(monotonic=clock.now, sleep=clock.sleep)):
            result = b.read_cli_output(conn, command, timeout, pattern)
        return result, conn

    def test_settle_reuses_snapshot_but_late_data_invalidates_it(self):
        original = b.OutputBuffer.value
        reads = []
        def counted(buffer):
            value = original(buffer)
            reads.append(value)
            return value
        with patch.object(b.OutputBuffer, 'value', counted):
            (output, failure), conn = self.read('show data', [(0, 'body\nrouter#')])
        self.assertIsNone(failure)
        self.assertEqual(reads, [output])
        with patch.object(b.OutputBuffer, 'value', counted):
            (output, failure), conn = self.read('show data', [(0, 'body\nrouter#'), (.1, '\nlate\nrouter#')])
        self.assertIn('late', output)
        self.assertEqual(failure['error_reason'], 'prompt_candidate_continuation')
        self.assertEqual(conn.writes, ['show data\n'])

    def test_xml_prompt_prefixes_do_not_materialize_whole_buffer(self):
        events = [(0, '<data>\n')]
        events += [(0, '<row>mạng</row>\nrouter#'), (0, '\n')] * 100
        events += [(0, '</data>\nrouter#')]
        original = b.OutputBuffer.value
        reads = []
        def counted(buffer):
            reads.append(1)
            return original(buffer)
        with patch.object(b.OutputBuffer, 'value', counted):
            (output, failure), conn = self.read('show data | display xml', events, timeout=10)
        self.assertIsNone(failure)
        self.assertTrue(output.endswith('</data>\nrouter#'))
        self.assertEqual(len(reads), 1)
        self.assertEqual(conn.writes, ['show data | display xml\n'])

    def test_open_xml_timeout_and_eof_keep_all_received_data(self):
        for ending in ([], [(.1, None)]):
            with self.subTest(eof=bool(ending)):
                (output, failure), conn = self.read('show data | display xml', [(0, '<data>\nrouter#')] + ending)
                self.assertEqual(output, '<data>\nrouter#')
                self.assertIn(failure['error_category'], ('read_timeout', 'connection_lost'))
                self.assertEqual(len(conn.writes), 1)

    def test_callback_failure_after_snapshot_retains_new_data(self):
        clock = VirtualClock()
        conn = TimelineChannel(clock, [(0, 'body\nrouter#'), (.1, '\nlate bytes')])
        def callback(data):
            if 'late' in data: raise OSError('fixture sink failure')
        with patch.object(b, 'time', SimpleNamespace(monotonic=clock.now, sleep=clock.sleep)):
            output, failure = b.read_cli_output(conn, 'show data', 2, r'(?m)^router#$', on_data=callback)
        self.assertEqual(output, 'body\nrouter#\nlate bytes')
        self.assertIsNotNone(failure)

    def test_partial_spool_write_failure_does_not_reuse_old_snapshot(self):
        original = b.OutputBuffer.append
        def partial(buffer, data):
            if 'late' in data:
                original(buffer, data[:5])
                raise OSError('fixture partial write')
            return original(buffer, data)
        with patch.object(b.OutputBuffer, 'append', partial):
            (output, failure), _ = self.read('show data', [(0, 'body\nrouter#'), (.1, '\nlate bytes')])
        self.assertEqual(output, 'body\nrouter#\nlate')
        self.assertIsNotNone(failure)

    def test_unterminated_last_line_uses_full_verifier_for_custom_expect(self):
        text = '<data>\n</data> <!-- closed -->'
        (output, failure), _ = self.read('show data | display xml', [(0, text)], pattern=r'closed -->$')
        self.assertIsNone(failure)
        self.assertEqual(output, text)

    def test_guard_veto_agrees_with_full_verifier_for_fragmented_prefixes(self):
        transcripts = [
            '<data>\nrouter#\n</data>\nrouter#',
            '<?xml version="1.0"?>\r\n<data>\r\nrouter#\r\n</data>\r\nrouter#',
            '<data>\n<![CDATA[\nrouter#\n</data>\n]]>\n</data>\nrouter#',
            '<data>\n<!-- router# -->\n<row a="x > y"/>\n</data>\nrouter#',
            '<data>\n<broken>\n</other>\nrouter#',
            '<data>\nrouter#\n\x1b[31m</data>\x1b[0m\nrouter#',
            '<data>\ntext\b\b\n</data>\nrouter#',
            '<data>\ntext\x00\n</data>\nrouter#',
            '<data>\rrouter#\r</data>\rrouter#',
            '<data>\u2028router#\u2028</data>\nrouter#',
            '<data>\n' + 'x'*70000 + '\nrouter#\n</data>\nrouter#',
        ]
        for seed in range(30):
            rng = random.Random(seed)
            for text in transcripts:
                guard = b.XMLPrefixGuard('show data | display xml')
                prefix, position = '', 0
                while position < len(text):
                    end = position + rng.randint(1, 4096)
                    part = text[position:end]
                    prefix += part
                    guard.feed(part)
                    if guard.definitely_open():
                        self.assertTrue(b.output_container_open('show data | display xml', prefix), (seed, repr(prefix[-100:])))
                    position = end

    def test_long_lines_and_terminal_rewrites_disable_fast_guard(self):
        for text in ('<data>\n' + 'x'*70000, '<data>\n\x1b[0mrouter#', '<data>\ntext\brouter#'):
            guard = b.XMLPrefixGuard('show data | display xml')
            guard.feed(text)
            self.assertFalse(guard.safe)
            self.assertLessEqual(len(guard.pending), 65536)

    def test_unsupported_incremental_parser_error_falls_back(self):
        guard = b.XMLPrefixGuard('show data | display xml')
        class UnsupportedParser:
            def feed(self, text): raise UnicodeError('fixture unsupported encoding')
        with patch('xml.etree.ElementTree.XMLParser', return_value=UnsupportedParser()):
            guard.feed('<data>\nrouter#')
        self.assertFalse(guard.safe)
        self.assertFalse(guard.definitely_open())
        self.assertIsNone(guard.parser)

    def test_guard_uses_the_same_first_pipeline_format_as_full_verifier(self):
        text = '<data>\nrouter#'
        for command in ('show data | display json | display xml',
                        'show data | json | xml', 'show running-config | display xml'):
            guard = b.XMLPrefixGuard(command)
            guard.feed(text)
            self.assertFalse(guard.definitely_open(), command)
        xml_first = b.XMLPrefixGuard('show data | display xml | display json')
        xml_first.feed(text)
        self.assertTrue(xml_first.definitely_open())
        self.assertTrue(b.output_container_open('show data | display xml | display json', text))
