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
ACKS = dict(zip(PREP, ('Screen width set to 511', 'Disabling complete-on-space', 'Screen length set to 0')))
CAPS = "CLI complete-on-space set to on\nCLI screen-length set to 1000\nCLI screen-width set to 511\nCLI terminal is 'vt100'"


class JunosChannel:
    device_type = 'juniper_junos'
    RETURN = '\n'
    prompt = 'noc@mx>'
    def __init__(self, clock, responses=None, echo=None):
        self.clock, self.responses, self.echo = clock, responses or {}, echo or (lambda cmd: cmd)
        self.events, self.writes, self.submitted = [], [], []
        self.pending, self.page = '', None
        self.cancel_input = False
        self.remote_conn = SimpleNamespace(closed=False, eof_received=False)
    def _test_channel_read(self, **kw): pass
    def enter_cli_mode(self): pass
    def find_prompt(self): return self.prompt
    def is_alive(self): return not self.remote_conn.closed
    def disconnect(self): self.remote_conn.closed = True
    def normalize_cmd(self, cmd): return cmd.rstrip() + self.RETURN
    def write_channel(self, text):
        self.writes.append(text)
        if text == '\x03':
            if self.cancel_input:
                self.pending = ''
                self.events.append((self.clock.now(), '^C\n' + self.prompt))
            return
        if text == ' ' and self.page is not None:
            self.events.extend((self.clock.now()+delay, data) for delay, data in self.page)
            self.page = None
            return
        if text.endswith('\n'):
            command = self.pending if self.pending else text[:-1]
            prefix = '\n' if self.pending else ''
            self.pending = ''
            self.submitted.append(command)
            response = self.responses.get(command, ACKS.get(command, CAPS if command == 'show cli' else 'DATA'))
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
        self.events.sort(key=lambda event: event[0])
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
        conn = JunosChannel(self.clock, responses, (lambda cmd: cmd if cmd == 'show cli' else echo(cmd)) if echo else None)
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
                self.assertEqual([x['reason'] for x in result['junos_preparation']], [reason, 'capability_probe', 'using_echo_guard', 'using_reader_fallback'])
                self.assertEqual(conn.submitted.count('show version'), 1)
                self.assertEqual(conn.submitted[:2], [PREP[0], 'show cli'])
    def test_ambiguous_width_resyncs_once_without_replaying_prep(self):
        events = [(0, 'Screen width set to 511\n' + JunosChannel.prompt),
                  (.05, '\nset cli screen-width 511\nerror: permission denied\n' + JunosChannel.prompt)]
        conn = self.prepare({PREP[0]: events})
        self.assertEqual(conn.submitted, [PREP[0], 'show cli'])
        self.assertTrue(self.collector(conn).execute('mx', 'show version')['ok'])
        self.assertEqual(conn.submitted.count('show cli'), 1)

    def test_resync_wrong_echo_never_sends_enter_or_show_version(self):
        events = [(0, 'Screen width set to 511\n' + JunosChannel.prompt),
                  (.05, '\nlate response\n' + JunosChannel.prompt)]
        with self.assertRaises(b.CollectionError) as caught:
            b.junos_prepare_session(JunosChannel(self.clock, {PREP[0]: events}, echo=lambda cmd: 'show clisomething'))
        details = caught.exception.details
        self.assertEqual(details['error_reason'], 'junos_echo_mismatch')
        self.assertEqual(details['preparation_command'], 'show cli')
        self.assertIn('show clisomething', details['output'])
        self.assertIn('late response', details['junos_preparation'][0]['output'])
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
        self.assertFalse(result['output_complete'])
        self.assertEqual(result['recovery_attempts'], 1)
        self.assertIn('partial', result['previous_attempt']['output'])
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
        self.assertEqual(conn._network_junos_preparation[0]['reason'], 'unconfirmed_response')


    def test_truncated_and_joined_width_fail_fast_then_probe_once(self):
        for malformed in ('set cli screen-width', 'set cli screen-width511'):
            with self.subTest(command=malformed):
                started = self.clock.now()
                conn = self.prepare({PREP[0]: malformed + '\n                      ^\nsyntax error, expecting <command>.'})
                self.assertLess(self.clock.now() - started, 1.1)
                self.assertEqual(conn.submitted, [PREP[0], 'show cli'])
                self.assertEqual(conn._network_junos_capabilities['screen_width'], 511)
                self.assertFalse(conn._network_junos_capabilities['paging_disabled'])
                self.assertTrue(conn._network_junos_verify_echo)
                result = self.collector(conn).execute('mx', 'show version')
                self.assertTrue(result['ok'], result)
                self.assertTrue(result['command_echo_verified'])
                self.assertEqual(conn.writes[-2:], ['show version', '\n'])

    def test_unknown_localized_bare_and_mixed_ack_do_not_confirm_settings(self):
        from netmiko.juniper.juniper import JuniperBase
        for response in ('', 'không được hỗ trợ', 'Screen width set to 511\nstrange response'):
            with self.subTest(response=response):
                conn = JunosChannel(self.clock, {PREP[0]: response, 'show cli': 'CLI terminal is vt100'})
                conn.cancel_input = True
                JuniperBase.session_preparation(conn)
                self.assertEqual(conn.writes.count('\x03'), 0 if response else 1)
                self.assertEqual(conn._network_junos_capabilities, {})
                self.assertTrue(conn._network_junos_verify_echo)
                self.assertTrue(self.collector(conn).execute('mx', 'show version')['ok'])
                self.assertEqual(conn.submitted[:2], [PREP[0], 'show cli'])

    def test_capability_parser_rejects_missing_conflicting_and_error_body(self):
        parsed = b.junos_cli_capabilities(CAPS + '\n' + JunosChannel.prompt, JunosChannel.prompt)
        self.assertEqual(parsed, {'screen_width': 511, 'screen_length': 1000,
                                 'complete_on_space': True, 'paging_disabled': False})
        for output in (CAPS.replace('CLI screen-width set to 511', ''),
                       CAPS + '\nCLI complete-on-space set to off',
                       CAPS + '\nerror: unexpected', CAPS.replace('511', '999999')):
            with self.subTest(output=output):
                self.assertEqual(b.junos_cli_capabilities(output, JunosChannel.prompt), {})

    def test_verified_off_capability_skips_remaining_prep_and_echo_guard(self):
        conn = self.prepare({PREP[0]: 'syntax error', 'show cli': CAPS.replace('set to on', 'set to off').replace('1000', '0')})
        self.assertFalse(conn._network_junos_verify_echo)
        self.assertTrue(conn._network_junos_capabilities['paging_disabled'])
        self.assertEqual(conn.submitted, [PREP[0], 'show cli'])
        self.assertEqual([x['reason'] for x in conn._network_junos_preparation[-2:]], ['already_verified']*2)

    def test_partial_probe_cannot_keep_prior_autocomplete_off_assumption(self):
        conn = self.prepare({PREP[2]: 'syntax error', 'show cli': 'CLI complete-on-space set to on'})
        self.assertEqual(conn._network_junos_capabilities, {})
        self.assertTrue(conn._network_junos_verify_echo)

    def test_syntax_without_clean_prompt_stops_without_business_command(self):
        conn = JunosChannel(self.clock, {PREP[0]: [(0, 'syntax error\nnoc@other>')]})
        with self.assertRaises(b.CollectionError) as caught:
            b.junos_prepare_session(conn)
        self.assertFalse(self.collector(conn).failure_result(caught.exception, 'mx', 'show version')['command_sent'])
        self.assertEqual(conn.submitted, [PREP[0]])
        self.assertEqual(conn.writes.count('\x03'), 1)
        self.assertNotIn('show cli', conn.submitted)

    def test_single_ctrl_c_cancels_pending_probe_without_enter(self):
        conn = JunosChannel(self.clock, {PREP[0]: 'syntax error'}, echo=lambda cmd: 'showcli')
        conn.cancel_input = True
        b.junos_prepare_session(conn)
        self.assertEqual(conn.submitted, [PREP[0]])  # Probe was typed, never entered.
        self.assertEqual(conn.pending, '')
        self.assertEqual(conn.writes[-2:], ['show cli', '\x03'])
        conn.echo = lambda cmd: cmd
        self.assertTrue(self.collector(conn).execute('mx', 'show version')['ok'])
        self.assertEqual(conn.submitted, [PREP[0], 'show version'])

    def test_late_old_prompt_without_cancel_ack_does_not_resync(self):
        conn = JunosChannel(self.clock)
        conn.events = [(self.clock.now() + .1, conn.prompt)]
        _, failure = b.junos_resync(conn, conn.prompt, timeout=1)
        self.assertEqual(failure['error_reason'], 'junos_resync_failed')
        self.assertEqual(conn.writes, ['\x03'])

    def test_pending_question_with_prompt_is_not_a_clean_boundary(self):
        conn = JunosChannel(self.clock, {PREP[0]: 'Continue? [yes/no]\n' + JunosChannel.prompt})
        with self.assertRaises(b.CollectionError):
            b.junos_prepare_session(conn)
        self.assertEqual(conn.submitted, [PREP[0]])
        self.assertNotIn('show cli', conn.submitted)
        self.assertEqual(conn._network_junos_capabilities, {})

    def test_cancel_marker_inside_payload_cannot_verify_resync(self):
        conn = JunosChannel(self.clock)
        conn.events = [(self.clock.now() + .1, 'description contains ^C text\n' + conn.prompt)]
        _, failure = b.junos_resync(conn, conn.prompt, timeout=1)
        self.assertIsNotNone(failure)

    def test_resync_rejects_late_continuation_after_cancel_prompt(self):
        for continuation in ('\nlate output\n' + JunosChannel.prompt,
                             '\nContinue? [yes/no]'):
            with self.subTest(continuation=continuation):
                conn = JunosChannel(self.clock)
                conn.cancel_input = True
                conn.events = [(self.clock.now() + .1, continuation)]
                output, failure = b.junos_resync(conn, conn.prompt, timeout=1)
                self.assertIsNotNone(failure)
                self.assertIn(continuation.strip(), output)
                self.assertEqual(conn.writes, ['\x03'])
                self.assertEqual(conn.submitted, [])

    def test_slow_prefix_echo_is_not_declared_mismatch_before_deadline(self):
        conn = self.prepare({PREP[0]: 'syntax error'})
        def delayed_echo(command):
            conn.events.append((self.clock.now() + .7, command[5:]))
            return command[:5]
        conn.echo = delayed_echo
        result = self.collector(conn).execute('mx', 'show version', read_timeout=2)
        self.assertTrue(result['ok'], result)
        self.assertEqual(conn.submitted.count('show version'), 1)

    def test_echo_after_deadline_never_causes_enter_or_success(self):
        conn = self.prepare({PREP[0]: 'syntax error'})
        def late_echo(command):
            conn.events.append((self.clock.now() + 1.1, command))
            return None
        conn.echo = late_echo
        result = self.collector(conn).execute('mx', 'show version', read_timeout=1)
        self.assertFalse(result['ok']); self.assertFalse(result['command_sent'])
        self.assertNotIn('show version', conn.submitted)
        self.assertNotIn('\n', conn.writes[-1:])

    def test_session_capabilities_reused_then_cleared_at_disconnect(self):
        conn = self.prepare({PREP[0]: 'syntax error'})
        writes = list(conn.writes)
        b.junos_prepare_session(conn)
        self.assertEqual(conn.writes, writes)
        c = self.collector(conn)
        self.assertTrue(c.execute('mx', 'show version')['ok'])
        self.assertTrue(c.execute('mx', 'show version')['session_reused'])
        self.assertEqual(conn.submitted.count('show cli'), 1)
        c.shutdown()
        self.assertEqual(conn._network_junos_capabilities, {})
        self.assertFalse(conn._network_junos_prepared)
        fresh = self.prepare()
        self.assertEqual(fresh.submitted, list(PREP))

    def test_user_cli_preference_change_invalidates_session_capabilities(self):
        conn = self.prepare()
        result = self.collector(conn).execute('mx', 'set cli complete-on-space on')
        self.assertTrue(result['ok'], result)
        self.assertEqual(conn._network_junos_capabilities, {})
        self.assertTrue(conn._network_junos_verify_echo)

    def test_cli_preference_change_guards_next_command_on_reused_session(self):
        for correct_echo in (True, False):
            with self.subTest(correct_echo=correct_echo):
                conn = self.prepare()
                c = self.collector(conn)
                self.assertTrue(c.execute('mx', 'set cli complete-on-space on')['ok'])
                before = list(conn.submitted)
                conn.echo = lambda cmd: cmd if correct_echo else cmd.replace(' ', '')
                result = c.execute('mx', 'show version')
                self.assertTrue(result['session_reused'])
                if correct_echo:
                    self.assertTrue(result['ok'], result)
                    self.assertTrue(result['command_echo_verified'])
                    self.assertEqual(conn.writes[-2:], ['show version', '\n'])
                else:
                    self.assertFalse(result['ok'])
                    self.assertFalse(result['command_sent'])
                    self.assertEqual(result['error_reason'], 'junos_echo_mismatch')
                    self.assertEqual(conn.submitted, before)
                    self.assertEqual(conn.writes[-1], 'show version')

    def test_pipes_quotes_explicit_no_more_and_config_are_not_rewritten(self):
        for command in ('show interfaces | no-more', 'show route | match "a | b" | count',
                        'show configuration | display set | match "a  b"',
                        'show interfaces | match "no-more"', 'set interfaces lo0 description "a  b"'):
            with self.subTest(command=command):
                conn = self.prepare({PREP[0]: 'syntax error'})
                result = self.collector(conn).execute('mx', command)
                self.assertTrue(result['ok'], result)
                self.assertEqual(conn.writes[-2:], [command, '\n'])
                self.assertEqual(conn.submitted[-1], command)

    def test_probe_error_is_advisory_but_business_error_is_not_success(self):
        conn = self.prepare({PREP[0]: 'unfamiliar error', 'show cli': 'syntax error',
                             'show version': 'syntax error'})
        result = self.collector(conn).execute('mx', 'show version')
        self.assertFalse(result['ok'])
        self.assertEqual(result['error_category'], 'cli_error')
        self.assertTrue(result['command_sent'])
        self.assertTrue(result['output_complete'])






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
        self.server.cancel_input = True
        self.server.responses['show cli'] = CAPS
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
            self.assertEqual(len(result['junos_preparation']), 4)
        self.assertEqual(self.server.auth_attempts, 1)
        self.assertEqual(self.server.commands.count('show version'), 2)
        self.assertEqual(self.server.commands.count(PREP[0]), 1)
        self.assertEqual(self.server.commands.count('show cli'), 1)
        for cmd in PREP[1:]: self.assertNotIn(cmd, self.server.commands)

    def test_batch_reopens_after_failed_resync_on_ssh_localhost(self):
        self.server.cancel_input = False
        self.server.responses[PREP[0]] = lambda channel: channel.sendall(b'partial width reply\r\n')
        self.server.responses['show lldp neighbors'] = 'LLDP peer'
        self.server.responses['show isis adjacency'] = 'IS-IS peer'
        c = self.collector('juniper_junos')
        c.defaults['junos_minimal_recovery'] = True
        commands = ['show version', 'show lldp neighbors', 'show isis adjacency']
        result = c.execute_many('local', commands, read_timeout=4)
        self.assertTrue(result['ok'], result)
        self.assertEqual(result['recovery_attempts'], 1)
        self.assertIn('partial width reply', result['previous_attempt']['output'])
        self.assertEqual(self.server.auth_attempts, 2)
        self.assertEqual(self.server.commands, [PREP[0], 'show cli', *commands])
        self.assertTrue(all(item['command_echo_verified'] for item in result['results']))
        reuse = c.execute('local', 'show version', read_timeout=4)
        self.assertTrue(reuse['session_reused'], reuse)
        self.assertEqual(self.server.auth_attempts, 2)
    def test_all_three_prep_rejected_still_collects_complete_paged_show_version(self):
        self.server.responses.update(dict(zip(PREP, (
            'set cli screen-width511\n  ^\nsyntax error, expecting <command>.',
            'error: permission denied', 'unrecognized CLI preparation option'))))
        first_page = 'Hostname: LAB-MX\nModel: mx204'
        last_page = 'Junos: 23.4R2\nEND-OF-SHOW-VERSION'
        def pages(channel):
            channel.sendall((first_page.replace('\n', '\r\n') + '\r\n---(more)---').encode())
            channel.settimeout(3)
            self.assertEqual(channel.recv(1), b' ')
            channel.sendall(('\r\n' + last_page.replace('\n', '\r\n')
                             + '\r\n' + self.server.prompt).encode())
        self.server.responses['show version'] = pages
        result = self.collector('juniper_junos').execute('local', 'show version', read_timeout=4)
        self.assertTrue(result['ok'], result)
        self.assertEqual(result['status'], 'SUCCESS')
        self.assertTrue(result['command_sent'])
        self.assertTrue(result['command_echo_verified'])
        self.assertTrue(result['output_complete'])
        body = result['output'][result['output'].index('Hostname: LAB-MX'):]
        # Reader erases the pager into a blank line; compare every payload
        # line exactly, including the final sentinel and operational prompt.
        self.assertEqual([line for line in body.splitlines() if line.strip()],
                         (first_page + '\n' + last_page + '\n' + self.server.prompt).splitlines())
        self.assertNotIn('---(more)---', result['output'])
        # All three settings are rejected by the fixture. Adaptive preparation
        # sends the first once and skips the other two, rather than provoking
        # three errors before allowing business collection.
        self.assertEqual(self.server.commands, [PREP[0], 'show cli', 'show version'])
        self.assertEqual(self.server.auth_attempts, 1)
        self.assertEqual([item['command'] for item in result['junos_preparation']
                          if item.get('command_sent') is False], list(PREP[1:]))

    def test_probe_worker_denied_prep_keeps_guard_and_diagnostics(self):
        c = self.collector('autodetect')
        first = c.execute('local', 'show version', read_timeout=3)
        second = c.execute('local', 'show version', read_timeout=3)
        self.assertTrue(first['ok'], first); self.assertTrue(second['ok'], second)
        self.assertEqual(len(first['junos_preparation']), 4)
        self.assertEqual(self.server.auth_attempts, 1)
        self.assertEqual(self.server.commands.count('show version'), 3)  # Probe + two reads.
        conn = next(iter(c._sessions.values()))['conn']
        self.assertEqual(conn._network_junos_capabilities['screen_width'], 511)
        self.assertFalse(conn._network_junos_capabilities['paging_disabled'])
        self.assertEqual(self.server.commands.count('show cli'), 1)
        c.shutdown()
        self.assertEqual(conn._network_junos_capabilities, {})
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
