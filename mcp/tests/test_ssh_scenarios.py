"""Deterministic fault matrix and seeded chunk-boundary replay (no device SSH)."""
import concurrent.futures
from pathlib import Path
import random
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import collector_backend as backend


class VirtualClock:
    def __init__(self): self.value = 100.0
    def now(self): return self.value
    def sleep(self, seconds): self.value += max(seconds, .00001)


class TimelineChannel:
    def __init__(self, clock, events, prompt='router#', stale=()):
        self.clock, self.events, self.prompt = clock, list(events), prompt
        self.stale = list(stale)
        self.sent_at = None
        self.writes = []
        self.waiting_space = False
        self.remote_conn = SimpleNamespace(closed=False, eof_received=False)

    def find_prompt(self): return self.prompt
    def normalize_cmd(self, command): return command + '\n'
    def disconnect(self): self.remote_conn.closed = True
    def is_alive(self): return not self.remote_conn.closed

    def write_channel(self, command):
        self.writes.append(command)
        if command == ' ':
            self.waiting_space = False
        else:
            self.sent_at = self.clock.now()

    def read_channel(self):
        if self.sent_at is None:
            return self.stale.pop(0) if self.stale else ''
        if self.waiting_space or not self.events or self.events[0][0] > self.clock.now() - self.sent_at:
            return ''
        event = self.events.pop(0)
        data = event[1]
        if isinstance(data, Exception): raise data
        if data is None:
            self.remote_conn.closed = True
            self.remote_conn.eof_received = True
            return ''
        if len(event) > 2 and event[2]: self.waiting_space = True
        return data


class ScenarioTests(unittest.TestCase):
    def setUp(self):
        self.clock = VirtualClock()
        self.time_patches = [patch.object(backend.time, 'monotonic', self.clock.now),
                             patch.object(backend.time, 'sleep', self.clock.sleep)]
        for context in self.time_patches: context.start(); self.addCleanup(context.stop)
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def collector(self, conn):
        c = backend.Collector({'defaults': {'output_dir': self.tmp.name, 'session_sweep_seconds': 0},
                               'devices': {'test': {'host': '192.0.2.1', 'device_type': 'cisco_ios'}}},
                              connect_factory=lambda **kwargs: conn)
        self.addCleanup(c.shutdown)
        return c

    def test_literal_pager_and_confirmation_in_data_are_not_errors(self):
        conn = TimelineChannel(self.clock, [(0, 'description "--More--"\nmessage "[yes/no]"\nrouter#')])
        result = self.collector(conn).execute('test', 'show running-config')
        self.assertTrue(result['ok'])
        self.assertIn('description "--More--"', result['output'])
        self.assertEqual(conn.writes, ['show running-config\n'])

    def test_pagination_does_not_delete_literal_markers_in_data(self):
        conn = TimelineChannel(self.clock, [(0, 'description "--More--"\n'),
            (.02, '\x1b[7m--More--\x1b[0m', True), (.04, '\nlast-page\nrouter#')])
        output, failure = backend.read_cli_output(conn, 'show running-config', 2, r'(?m)^router#$')
        self.assertIsNone(failure)
        self.assertIn('description "--More--"', output)
        self.assertIn('last-page', output)
        self.assertEqual(conn.writes.count(' '), 1)

    def test_closed_channel_detected_without_waiting_full_read_timeout(self):
        conn = TimelineChannel(self.clock, [(0, 'partial\n'), (.04, None)])
        started = self.clock.now()
        output, failure = backend.read_cli_output(conn, 'show version', 10, r'(?m)^router#$')
        self.assertEqual(output, 'partial\n')
        self.assertEqual(failure['error_category'], 'connection_lost')
        self.assertTrue(failure['retryable'])
        self.assertLess(self.clock.now() - started, .5)

    def test_closed_channel_after_complete_prompt_keeps_complete_result(self):
        conn = TimelineChannel(self.clock, [(0, 'complete\nrouter#'), (.02, None)])
        output, failure = backend.read_cli_output(conn, 'show version', 10, r'(?m)^router#$')
        self.assertIsNone(failure)
        self.assertEqual(output, 'complete\nrouter#')

    def test_connection_reset_and_eof_are_retryable_transport_errors(self):
        for exc in [EOFError('EOF'), ConnectionResetError('reset'), BrokenPipeError('broken pipe')]:
            with self.subTest(error=type(exc).__name__):
                result = backend.classify_error(exc, 'command')
                self.assertEqual(result['error_category'], 'connection_lost')
                self.assertTrue(result['retryable'])

    def test_interact_preserves_command_specific_bgp_counter_classification(self):
        data = "Peer: 192.0.2.2\nError: 'Cease' Sent: 0 Recv: 0\nrouter#"
        conn = TimelineChannel(self.clock, [(0, data)])
        result = self.collector(conn).interact('test', ['show bgp neighbor'])
        self.assertTrue(result['steps'][0]['ok'])
        self.assertTrue(result['ok'])

    def test_multiple_fragmented_pagers_and_terminal_erasure(self):
        conn = TimelineChannel(self.clock, [(0, 'page-one\n--Mo'), (.02, 're--', True),
            (.04, '\b' * 8 + ' ' * 8 + '\b' * 8 + '\npage-two\n---(more 50%)---', True),
            (.06, '\npage-three\n---- More ----', True), (.08, '\npage-four\nrouter#')])
        output, failure = backend.read_cli_output(conn, 'show version', 2, r'(?m)^router#$')
        self.assertIsNone(failure)
        for page in ['page-one', 'page-two', 'page-three', 'page-four']: self.assertIn(page, output)
        self.assertEqual(conn.writes.count(' '), 3)

    def test_delay_and_false_prompt_from_other_host_do_not_truncate(self):
        conn = TimelineChannel(self.clock, [(0, 'other-router#'), (.6, '\nmore data\n'), (1.2, 'router#')])
        output, failure = backend.read_cli_output(conn, 'show version', 2, r'(?m)^router#$')
        self.assertIsNone(failure)
        self.assertEqual(output, 'other-router#\nmore data\nrouter#')

    def test_stale_banner_is_drained_before_probe(self):
        conn = TimelineChannel(self.clock, [(0, 'Linux\nrouter#')], stale=['JUNOS old banner\nrouter#'])
        output, failure = backend.read_cli_output(conn, 'uname -s', 2, r'(?m)^router#$')
        self.assertIsNone(failure)
        self.assertEqual(output, 'Linux\nrouter#')
        self.assertNotIn('JUNOS', output)

    def test_changed_prompt_fails_and_does_not_send_next_command(self):
        conn = TimelineChannel(self.clock, [(0, 'version\nchanged-router#')])
        with self.assertRaises(backend.BatchError) as caught:
            self.collector(conn).execute_many('test', ['show version', 'show clock'], read_timeout=1)
        self.assertFalse(caught.exception.results[0]['ok'])
        self.assertEqual(conn.writes, ['show version\n'])
        self.assertTrue(conn.remote_conn.closed)

    def test_password_and_confirmation_questions_never_get_a_response(self):
        for text in ['Are you sure? [Y/N]:', 'Proceed? (yes/no):', '[confirm]', 'Enter new password:']:
            with self.subTest(question=text):
                conn = TimelineChannel(self.clock, [(0, text)])
                result = self.collector(conn).execute('test', 'show version', read_timeout=1)
                self.assertFalse(result['ok'])
                self.assertEqual(conn.writes, ['show version\n'])

    def test_log_line_with_confirmation_marker_is_not_an_active_question(self):
        conn = TimelineChannel(self.clock, [(0, 'Nov 9 event recorded [confirm]'), (.2, '\nrouter#')])
        result = self.collector(conn).execute('test', 'show logging', read_timeout=1)
        self.assertTrue(result['ok'])
        self.assertIn('event recorded [confirm]', result['output'])

    def test_no_existing_session_is_retryable_handshake_failure(self):
        import paramiko
        error = paramiko.SSHException('No existing session')
        result = backend.classify_error(error, 'connect')
        self.assertEqual(result['error_category'], 'handshake_incomplete')
        self.assertEqual(result['error_stage'], 'key_exchange')
        self.assertTrue(result['retryable'])

    def test_ssh_failure_categories_do_not_trigger_blind_auth_retry(self):
        import socket
        import paramiko
        banner_timeout = paramiko.SSHException('Error reading SSH protocol banner')
        banner_timeout.__cause__ = TimeoutError('timed out')
        cases = [(paramiko.ssh_exception.IncompatiblePeer('no acceptable kex algorithm'), 'algorithm_mismatch', False),
                 (paramiko.BadAuthenticationType('Bad authentication type', ['publickey', 'keyboard-interactive']), 'auth_method', False),
                 (paramiko.AuthenticationException('Authentication failed'), 'authentication', False),
                 (banner_timeout, 'banner_timeout', True),
                 (socket.gaierror(socket.EAI_NONAME, 'Name or service not known'), 'dns_error', False),
                 (ConnectionRefusedError('Connection refused'), 'connection_refused', False),
                 (PermissionError('Command outside policy'), 'policy_denied', False)]
        for exc, category, retryable in cases:
            with self.subTest(category=category):
                result = backend.classify_error(exc, 'connect')
                self.assertEqual(result['error_category'], category)
                self.assertEqual(result['retryable'], retryable)

    def test_seeded_2000_chunk_replays_preserve_every_character(self):
        rng = random.Random(20261109)
        prompts = ['router#', 'router>', 'noc@router>', '<router>', '[router]',
                   '[noc@router ~]$', 'RP/0/RP0/CPU0:router#']
        for seed in range(2000):
            prompt = prompts[seed % len(prompts)]
            lines = [f'case-{seed} row-{row} tín hiệu {rng.randrange(100000)}' for row in range(rng.randrange(1, 12))]
            expected = '\n'.join(lines) + '\n' + prompt
            raw = '\x1b[32m' + expected.replace('\n', '\r\n') + '\x1b[0m'
            events, offset, delay = [], 0, 0.0
            while offset < len(raw):
                size = rng.randrange(1, 75)
                events.append((delay, raw[offset:offset+size]))
                offset += size
                delay += rng.random() * .02
            conn = TimelineChannel(self.clock, events, prompt)
            output, failure = backend.read_cli_output(conn, 'show version', 3,
                r'(?m)^' + backend.re.escape(prompt) + r'[ \t]*$')
            with self.subTest(seed=seed, prompt=prompt):
                self.assertIsNone(failure)
                self.assertEqual(output, expected)
                self.assertEqual(conn.writes, ['show version\n'])


if __name__ == '__main__': unittest.main()
