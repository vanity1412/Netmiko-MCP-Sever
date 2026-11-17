"""Junos optional prep and pre-Enter echo guards, synthetic/loopback only."""
import importlib.util
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'mcp'))
if os.environ.get('JUNOS_TEST_BACKEND'):
    spec = importlib.util.spec_from_file_location('junos_baseline', os.environ['JUNOS_TEST_BACKEND'])
    b = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(b)
else:
    import collector_backend as b
from test_ssh_scenarios import VirtualClock

PREP = ('set cli screen-width 511', 'set cli complete-on-space off', 'set cli screen-length 0')


class JunosChannel:
    device_type = 'juniper_junos'
    RETURN = '\n'
    prompt = 'noc@mx>'
    def __init__(self, clock, responses=None, echo=None):
        self.clock, self.responses, self.echo = clock, responses or {}, echo or (lambda cmd: cmd)
        self.events, self.writes, self.submitted = [], [], []
        self.pending, self.page = '', None
        self.remote_conn = SimpleNamespace(closed=False, eof_received=False)
    def _test_channel_read(self, **kw): pass
    def enter_cli_mode(self): pass
    def find_prompt(self): return self.prompt
    def is_alive(self): return not self.remote_conn.closed
    def disconnect(self): self.remote_conn.closed = True
    def normalize_cmd(self, cmd): return cmd.rstrip() + self.RETURN
    def write_channel(self, text):
        self.writes.append(text)
        if text == ' ' and self.page is not None:
            self.events.extend((self.clock.now()+delay, data) for delay, data in self.page)
            self.page = None
            return
        if text.endswith('\n'):
            command = self.pending if self.pending else text[:-1]
            prefix = '\n' if self.pending else ''
            self.pending = ''
            self.submitted.append(command)
            response = self.responses.get(command, 'Disabling complete-on-space' if command == PREP[1] else 'DATA')
            if isinstance(response, str):
                response = [(0, response + '\n' + self.prompt)]
            self.events.extend((self.clock.now()+delay, prefix + data if i == 0 else data)
                               for i, (delay, data) in enumerate(response))
        else:
            self.pending += text
            echo = self.echo(text)
            if echo is not None:
                self.events.append((self.clock.now(), echo))
    def read_channel(self):
        if self.events and self.events[0][0] <= self.clock.now():
            return self.events.pop(0)[1]
        return ''


class JunosFallbackTests(unittest.TestCase):
    def setUp(self):
        self.clock = VirtualClock()
        context = patch.object(b, 'time', SimpleNamespace(monotonic=self.clock.now, sleep=self.clock.sleep))
        context.start(); self.addCleanup(context.stop)
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        b.install_tolerant_preparation()
    def prepare(self, responses=None, echo=None):
        from netmiko.juniper.juniper import JuniperBase
        conn = JunosChannel(self.clock, responses, echo)
        JuniperBase.session_preparation(conn)
        return conn
    def collector(self, conn):
        c = b.Collector({'defaults': {'output_dir': self.tmp.name, 'session_sweep_seconds': 0},
            'devices': {'mx': {'host': '192.0.2.1', 'device_type': 'juniper_junos'}}},
            connect_factory=lambda **kw: conn)
        self.addCleanup(c.shutdown)
        return c
    def test_normal_prep_has_same_writes_and_no_guard_delay(self):
        conn = self.prepare()
        elapsed = self.clock.now() - 100
        self.assertLess(elapsed, 1.1)
        self.assertEqual(conn.writes, [cmd+'\n' for cmd in PREP])
        self.assertFalse(getattr(conn, '_network_junos_verify_echo', False))
        c = self.collector(conn)
        self.assertTrue(c.execute('mx', 'show version')['ok'])
        self.assertTrue(c.execute('mx', 'show version')['session_reused'])
        self.assertEqual(c.status()['connections_opened'], 1)
    def test_permission_and_syntax_denials_are_optional_and_recorded(self):
        for diagnostic, reason in [('error: permission denied', 'permission_denied'),
                                   ('syntax error, expecting command.', 'syntax_error')]:
            with self.subTest(diagnostic=diagnostic):
                conn = self.prepare({cmd: diagnostic for cmd in PREP})
                c = self.collector(conn)
                result = c.execute('mx', 'show version')
                self.assertTrue(result['ok'], result)
                self.assertEqual([x['reason'] for x in result['junos_preparation']], [reason]*3)
                self.assertEqual(conn.submitted.count('show version'), 1)
                self.assertEqual(conn.submitted[:3], list(PREP))
    def test_ambiguous_width_resyncs_once_without_replaying_prep(self):
        events = [(0, 'Screen width set to 511\n' + JunosChannel.prompt),
                  (.05, '\nset cli screen-width 511\nerror: permission denied\n' + JunosChannel.prompt)]
        conn = self.prepare({PREP[0]: events})
        self.assertEqual(conn.submitted, [PREP[0], 'show cli', PREP[1], PREP[2]])
        self.assertTrue(self.collector(conn).execute('mx', 'show version')['ok'])
        self.assertIn('resync_output', conn._network_junos_preparation[0])

    def test_resync_wrong_echo_never_sends_enter_or_show_version(self):
        events = [(0, 'Screen width set to 511\n' + JunosChannel.prompt),
                  (.05, '\nlate response\n' + JunosChannel.prompt)]
        with self.assertRaises(b.CollectionError) as caught:
            self.prepare({PREP[0]: events}, echo=lambda cmd: 'show clisomething')
        self.assertEqual(caught.exception.details['error_reason'], 'junos_echo_mismatch')
        self.assertIn('late response', caught.exception.details['output'])
    def test_spaces_quotes_and_unicode_preserved_before_enter(self):
        command = 'show interfaces | match "a  b đường"  '
        conn = self.prepare({PREP[1]: 'error: permission denied'})
        result = self.collector(conn).execute('mx', command)
        self.assertTrue(result['ok'], result)
        self.assertEqual(conn.writes[-2:], [command, '\n'])
        self.assertEqual(conn.submitted[-1], command)
    def test_auto_complete_wrong_echo_is_not_executed(self):
        for echo in ['show version detail', 'showversion', 'show  version', 'show version\x1b[1A']:
            with self.subTest(echo=repr(echo)):
                conn = self.prepare({PREP[1]: 'error: permission denied'}, echo=lambda cmd: echo)
                result = self.collector(conn).execute('mx', 'show version')
                self.assertFalse(result['ok'])
                self.assertFalse(result['command_sent'])
                self.assertEqual(result['error_reason'], 'junos_echo_mismatch')
                self.assertNotIn('show version', conn.submitted)
                self.assertTrue(conn.remote_conn.closed)
    def test_echo_repaint_known_controls_keeps_exact_input(self):
        conn = self.prepare({PREP[1]: 'error: permission denied'},
            echo=lambda cmd: 'show versiox\r\x1b[K' + conn.prompt + ' ' + cmd)
        self.assertTrue(self.collector(conn).execute('mx', 'show version')['ok'])
    def test_missing_echo_and_partial_output_do_not_succeed(self):
        conn = self.prepare({PREP[1]: 'error: permission denied'}, echo=lambda cmd: None)
        result = self.collector(conn).execute('mx', 'show version', read_timeout=1)
        self.assertFalse(result['ok']); self.assertFalse(result['command_sent'])
        self.assertNotIn('show version', conn.submitted)
        conn = self.prepare({PREP[2]: 'error: permission denied', 'show version': [(0, 'partial')]})
        result = self.collector(conn).execute('mx', 'show version', read_timeout=1)
        self.assertFalse(result['output_complete']); self.assertIn('partial', result['output'])
    def test_pager_after_screen_length_denial_and_incomplete_pager(self):
        conn = self.prepare({PREP[2]: 'error: permission denied', 'show version': [(0, 'page1\n---(more)---')]})
        conn.page = [(0, '\npage2\n' + conn.prompt)]
        result = self.collector(conn).execute('mx', 'show version')
        self.assertTrue(result['ok']); self.assertIn('page2', result['output'])
        self.assertEqual(conn.writes.count(' '), 1)
        conn = self.prepare({PREP[2]: 'error: permission denied', 'show version': [(0, 'page1\n---(more)---')]})
        result = self.collector(conn).execute('mx', 'show version', read_timeout=1)
        self.assertFalse(result['ok']); self.assertFalse(result['output_complete'])
    def test_prep_timeout_does_not_fallback_or_refresh_driver(self):
        with self.assertRaises(b.CollectionError) as caught:
            self.prepare({PREP[0]: [(0, 'partial preparation')]})
        self.assertEqual(caught.exception.details['error_category'], 'read_timeout')
        self.assertTrue(caught.exception._network_no_driver_refresh)
    def test_mutated_prep_echo_enables_strict_business_echo(self):
        conn = self.prepare({PREP[1]: 'setcli complete-on-space off'})
        self.assertTrue(conn._network_junos_verify_echo)
        self.assertEqual(conn._network_junos_preparation[0]['reason'], 'echo_mismatch')






class JunosLoopbackFallbackTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from test_ssh_reliability import RealSSHTests
        RealSSHTests.setUpClass.__func__(cls)
    def setUp(self):
        import paramiko
        from test_ssh_reliability import RealSSHTests
        RealSSHTests.setUp(self)
        self.server.prompt = 'noc@router>'
        self.server.responses.update({cmd: 'error: permission denied' for cmd in PREP})
        self.server.responses['show version'] = 'Junos: 23.4R2'
        original = paramiko.Channel.recv
        owner = self
        self.mutate = False
        self.repaint = False
        def echo_server(channel, size):
            data = original(channel, size)
            if channel.transport in owner.server.transports and data:
                echoed = data.replace(b'show version', b'show version detail') if owner.mutate else data
                if owner.repaint:
                    echoed = data.replace(b'show version', b'show versiox\r\x1b[Kshow version')
                channel.sendall(echoed)
            return data
        context = patch.object(paramiko.Channel, 'recv', echo_server)
        context.start(); self.addCleanup(context.stop)
    def collector(self, driver):
        from test_ssh_reliability import RealSSHTests
        return RealSSHTests.collector(self, driver)
    def test_direct_denied_prep_reuses_verified_session(self):
        c = self.collector('juniper_junos')
        for _ in range(2):
            result = c.execute('local', 'show version', read_timeout=3)
            self.assertTrue(result['ok'], result)
            self.assertEqual(len(result['junos_preparation']), 3)
        self.assertEqual(self.server.auth_attempts, 1)
        self.assertEqual(self.server.commands.count('show version'), 2)
        for cmd in PREP: self.assertEqual(self.server.commands.count(cmd), 1)
    def test_probe_worker_denied_prep_keeps_guard_and_diagnostics(self):
        c = self.collector('autodetect')
        first = c.execute('local', 'show version', read_timeout=3)
        second = c.execute('local', 'show version', read_timeout=3)
        self.assertTrue(first['ok'], first); self.assertTrue(second['ok'], second)
        self.assertEqual(len(first['junos_preparation']), 3)
        self.assertEqual(self.server.auth_attempts, 1)
        self.assertEqual(self.server.commands.count('show version'), 3)  # Probe + two reads.
    def test_wrong_echo_never_submits_show_on_real_ssh(self):
        c = self.collector('juniper_junos')
        self.mutate = True
        result = c.execute('local', 'show version', read_timeout=3)
        self.assertFalse(result['ok']); self.assertFalse(result['command_sent'])
        self.assertEqual(result['error_reason'], 'junos_echo_mismatch')
        self.assertNotIn('show version', self.server.commands)
    def test_real_repaint_retains_cr_for_verification_and_restores_netmiko(self):
        self.repaint = True
        c = self.collector('juniper_junos')
        result = c.execute('local', 'show version', read_timeout=3)
        self.assertTrue(result['ok'], result)
        conn = next(iter(c._sessions.values()))['conn']
        self.assertFalse(conn.disable_lf_normalization)
    def test_real_pager_after_denied_screen_length_keeps_all_pages(self):
        def pages(channel):
            channel.sendall(b'page1\r\n---(more)---')
            channel.settimeout(3)
            self.assertEqual(channel.recv(1), b' ')
            channel.sendall(('\r\npage2\r\n' + self.server.prompt).encode())
        self.server.responses['show interfaces'] = pages
        result = self.collector('juniper_junos').execute('local', 'show interfaces', read_timeout=4)
        self.assertTrue(result['ok'], result)
        self.assertIn('page1', result['output']); self.assertIn('page2', result['output'])


if __name__ == '__main__': unittest.main()
