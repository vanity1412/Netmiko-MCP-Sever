"""Preparation/timing boundaries with deterministic CLI transcripts, no SSH."""
from pathlib import Path
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'mcp'))
import collector_backend as b
from test_ssh_scenarios import TimelineChannel, VirtualClock
from test_junos_fallback import JunosChannel, ACKS, CAPS


SETUP_COMMANDS = ('set cli screen-width 511', 'set cli complete-on-space off',
                  'set cli screen-length 0')


class PreparationChannel(JunosChannel):
    prompt = 'noc@router>'

    def __init__(self, clock, responses):
        # Preserve each command's independent response delay; echo is available
        # before Enter so the adaptive probe exercises the real input guard.
        super().__init__(clock, responses)


class PreparationTimingTests(unittest.TestCase):
    def setUp(self):
        self.clock = VirtualClock()
        context = patch.object(b, 'time', SimpleNamespace(monotonic=self.clock.now, sleep=self.clock.sleep, time=time.time))
        context.start()
        self.addCleanup(context.stop)
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def prepare(self, responses):
        from netmiko.juniper.juniper import JuniperBase
        b.install_tolerant_preparation()
        conn = PreparationChannel(self.clock, responses)
        JuniperBase.session_preparation(conn)
        return conn

    def test_junos_each_setup_command_can_respond_slowly_within_existing_budget(self):
        for delayed_command in SETUP_COMMANDS:
            with self.subTest(command=delayed_command):
                responses = {cmd: [(0, ACKS[cmd] + '\nnoc@router>')] for cmd in SETUP_COMMANDS}
                responses[delayed_command] = [(0, ACKS[delayed_command] + '\n'), (4.5, 'noc@router>')]
                started = self.clock.now()
                conn = self.prepare(responses)
                self.assertGreaterEqual(self.clock.now() - started, 4.5)
                self.assertEqual(conn.writes, [cmd + '\n' for cmd in SETUP_COMMANDS])
                self.assertEqual(conn._network_prompt_text, 'noc@router>')
                self.assertEqual(conn.base_prompt, 'noc@router')

    def test_junos_width_waits_for_late_ack_after_provisional_prompt(self):
        from netmiko.juniper.juniper import JuniperBase
        b.install_tolerant_preparation()
        width = SETUP_COMMANDS[0]
        conn = PreparationChannel(self.clock, {
            width: [(0, width + '\nnoc@router>\n'),
                    (4.5, ACKS[width] + '\n'), (4.6, 'noc@router>')],
            'show version': 'Junos: 23.4R2',
        })
        c = self.collector(conn)

        def connect(**kwargs):
            JuniperBase.session_preparation(conn)
            return conn

        c._connect = connect
        result = c.execute('local', 'show version')
        self.assertEqual(conn.submitted, [*SETUP_COMMANDS, 'show version'])
        self.assertEqual(conn.events, [])
        self.assertEqual(conn._network_junos_capabilities['screen_width'], 511)
        self.assertEqual(result['status'], 'SUCCESS')
        self.assertTrue(result['output_complete'])
        self.assertIn('Junos: 23.4R2', result['output'])
        self.assertNotIn(ACKS[width], result['output'])

    def test_junos_cli_setup_error_with_valid_prompt_keeps_existing_preparation_contract(self):
        for rejected_command in SETUP_COMMANDS:
            with self.subTest(command=rejected_command):
                responses = {cmd: [(0, ACKS[cmd] + '\nnoc@router>')] for cmd in SETUP_COMMANDS}
                responses[rejected_command] = [(0, 'error: permission denied\nnoc@router>')]
                conn = self.prepare(responses)
                index = SETUP_COMMANDS.index(rejected_command)
                self.assertEqual(conn.submitted, list(SETUP_COMMANDS[:index+1]) + ['show cli'])
                self.assertEqual(conn._network_prompt_text, 'noc@router>')
                # Preparation readiness must not make a business CLI error SUCCESS.
                result = self.collector(conn)._result('local', rejected_command,
                    'error: permission denied\nnoc@router>', 0, device_type='juniper_junos')
                self.assertEqual(result['status'], 'CLI_ERROR')
                self.assertTrue(result['output_complete'])

    def test_junos_setup_beyond_existing_budget_fails_without_next_command(self):
        from netmiko.juniper.juniper import JuniperBase
        b.install_tolerant_preparation()
        conn = PreparationChannel(self.clock, {SETUP_COMMANDS[0]: [(5.2, 'noc@router>')]})
        with self.assertRaises(b.CollectionError) as caught:
            JuniperBase.session_preparation(conn)
        self.assertEqual(caught.exception.details['error_category'], 'read_timeout')
        self.assertEqual(conn.writes, [SETUP_COMMANDS[0] + '\n', '\x03'])

    def test_complete_syntax_error_uses_prompt_event_without_echo_deadline(self):
        started = self.clock.now()
        conn = self.prepare({SETUP_COMMANDS[0]: [(0, 'set cli screen-width511\n  ^\nsyntax error, expecting <command>.\nnoc@router>')]})
        self.assertLess(self.clock.now() - started, 1.1)
        self.assertEqual(conn.submitted, [SETUP_COMMANDS[0], 'show cli'])

    def test_syntax_without_prompt_waits_for_late_completion_within_budget(self):
        started = self.clock.now()
        conn = self.prepare({SETUP_COMMANDS[0]: [(0, 'syntax error, expecting <command>.\n'),
                                                (4.5, 'noc@router>')]})
        self.assertGreaterEqual(self.clock.now() - started, 4.5)
        self.assertEqual(conn.submitted, [SETUP_COMMANDS[0], 'show cli'])
        self.assertNotIn('\x03', conn.writes)

    def collector(self, conn):
        c = b.Collector({'defaults': {'output_dir': self.tmp.name, 'session_sweep_seconds': 0},
            'devices': {'local': {'host': '192.0.2.1', 'device_type': 'juniper_junos'}}},
            connect_factory=lambda **kw: conn)
        self.addCleanup(c.shutdown)
        return c

    def test_preparation_failure_reports_readiness_and_keeps_unredacted_partial_output(self):
        from netmiko import BaseConnection
        from netmiko.juniper.juniper import JuniperBase
        b.install_tolerant_preparation()
        for driver, command in [('juniper_junos', SETUP_COMMANDS[0]), ('cisco_ios', 'terminal width 511')]:
            with self.subTest(driver=driver):
                conn = PreparationChannel(self.clock, {command: [(0, 'bằng chứng secret-value\n')]})
                conn.global_cmd_verify = False
                c = self.collector(conn)
                c.defaults.update(username='tester', password='secret-value')
                c.redaction_enabled = False  # Preserve evidence exactly in unredacted mode.
                def connect(**kw):
                    if driver == 'juniper_junos':
                        JuniperBase.session_preparation(conn)
                    else:
                        BaseConnection.set_terminal_width(conn, command=command, pattern='width')
                    return conn
                c._connect = connect
                with self.assertRaises(b.CollectionError) as caught:
                    c.execute('local', 'request system reboot', device_type=driver)
                result = c.failure_result(caught.exception, 'local', 'request system reboot')
                self.assertEqual(result['error_stage'], 'preparation')
                self.assertTrue(result['ssh_authenticated'])
                self.assertIs(result['cli_ready'], False)
                self.assertIs(result['command_sent'], False)
                self.assertEqual(result['status'], 'TIMEOUT')
                self.assertEqual(result['execution_state'], 'NOT_SENT')
                self.assertEqual(result['data_state'], 'PARTIAL')
                self.assertIn('bằng chứng', result['output'])
                self.assertIn('secret-value', result['output'])
                self.assertEqual(result['preparation_command'], command)
                self.assertEqual(conn.writes, [command + '\n'] + (['\x03'] if driver == 'juniper_junos' else []))

    def test_unrecognized_question_with_timing_preserves_output_without_success_or_replay(self):
        question = 'Chọn thao tác\nSelect maintenance slot (A/B):'
        self.assertFalse(b.pending_interaction(question))
        for interactive in (False, True):
            with self.subTest(interactive=interactive):
                conn = TimelineChannel(self.clock, [(0, question)], prompt='noc@router>')
                c = self.collector(conn)
                if interactive:
                    aggregate = c.interact('local', ['request system reboot', 'B'], read_timeout=1)
                    self.assertEqual(len(aggregate['steps']), 1)
                    result = aggregate['steps'][0]
                    self.assertNotEqual(aggregate['status'], 'SUCCESS')
                else:
                    result = c.execute('local', 'request system reboot', use_timing=True,
                                       read_timeout=1, save_output=True)
                    saved = Path(c.output_dir, result['output_id'] + '.txt').read_text(encoding='utf-8')
                    self.assertEqual(saved, question)
                self.assertEqual(result.get('output', result.get('preview')), question)
                self.assertFalse(result['ok'])
                self.assertFalse(result['output_complete'])
                self.assertEqual(result['status'], 'UNKNOWN')
                self.assertEqual(result['fault_status'], 'TIMEOUT')
                self.assertEqual(result['execution_state'], 'UNCERTAIN')
                self.assertFalse(result['replay_safe'])
                self.assertEqual(conn.writes, ['request system reboot\n'])
                self.assertTrue(conn.remote_conn.closed)


if __name__ == '__main__':
    unittest.main()
