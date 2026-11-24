"""Preparation/timing boundaries with deterministic CLI transcripts, no SSH."""
import json
from contextlib import ExitStack
from pathlib import Path
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from collector_test_clock import patch_collector_clock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'mcp'))
import collector_backend as b
from mcp_rpc import handle_rpc
import scan
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
        context = patch_collector_clock(b, SimpleNamespace(monotonic=self.clock.now, sleep=self.clock.sleep, time=time.time))
        stack = ExitStack()
        self.addCleanup(stack.close)
        stack.enter_context(context)
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
                self.assertEqual(conn.writes, [SETUP_COMMANDS[0], '\n', SETUP_COMMANDS[1], '\n', SETUP_COMMANDS[2]+'\n'])
                self.assertEqual(conn._network_prompt_text, 'noc@router>')
                self.assertEqual(conn.base_prompt, 'noc@router')

    def test_junos_width_waits_for_late_ack_after_provisional_prompt(self):
        for ack_at, prompt_at in ((4.5, 4.6), (4.6, 4.75)):
            with self.subTest(ack_at=ack_at, prompt_at=prompt_at):
                self.check_junos_width_ack(ack_at, prompt_at)

    def check_junos_width_ack(self, ack_at, prompt_at):
        from netmiko.juniper.juniper import JuniperBase
        b.install_tolerant_preparation()
        width = SETUP_COMMANDS[0]
        conn = PreparationChannel(self.clock, {
            width: [(0, width + '\nnoc@router>\n'),
                    (ack_at, ACKS[width] + '\n'), (prompt_at, 'noc@router>')],
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

    def test_junos_width_ack_after_timeout_is_kept_as_resync_evidence(self):
        from netmiko.juniper.juniper import JuniperBase
        b.install_tolerant_preparation()
        width = SETUP_COMMANDS[0]
        initial = width + '\nnoc@router>\n'
        late = ACKS[width] + '\nnoc@router>'
        for cancelled in (False, True):
            with self.subTest(cancelled=cancelled):
                response = [(0, initial), (5.8, late)]
                if cancelled:
                    response.append((5.9, '\n^C\nnoc@router>'))
                conn = PreparationChannel(self.clock, {width: response})
                c = self.collector(conn)

                def connect(**kwargs):
                    JuniperBase.session_preparation(conn)
                    return conn

                with patch.object(c, '_connect', connect):
                    if cancelled:
                        result = c.execute('local', 'show version')
                        self.assertTrue(result['ok'], result)
                        record = result['junos_preparation'][0]
                        self.assertEqual(record['output'], width + '\n' + initial)
                        self.assertIn(late, record['resync_output'])
                        self.assertNotIn(ACKS[width], result['output'])
                        self.assertEqual(conn.submitted, [width, 'show cli', 'show version'])
                    else:
                        with self.assertRaises(b.CollectionError) as caught:
                            c.execute('local', 'show version')
                        result = c.failure_result(caught.exception, 'local', 'show version')
                        self.assertEqual(result['output'], width + '\n' + initial)
                        self.assertEqual(result['resync_output'], late)
                        self.assertIs(result['command_sent'], False)
                        self.assertEqual(result['execution_state'], 'NOT_SENT')
                        self.assertEqual(conn.submitted, [width])
                        self.assertEqual(conn.writes, [width, '\n', '\x03'])

    def test_junos_width_settling_rejects_extra_data_and_keeps_it(self):
        width = SETUP_COMMANDS[0]
        conn = PreparationChannel(self.clock, {
            width: [(4.75, ACKS[width] + '\nnoc@router>'),
                    (5.02, '\nlate continuation\nnoc@router>')],
        })
        with self.assertRaises(b.CollectionError) as caught:
            b.junos_prepare_session(conn)
        details = caught.exception.details
        self.assertEqual(details['error_category'], 'read_timeout')
        self.assertIn(ACKS[width], details['output'])
        self.assertIn('late continuation', details['output'])
        self.assertEqual(conn.submitted, [width])

    def test_read_in_junos_configuration_mode_is_not_replayed(self):
        conn = PreparationChannel(self.clock, {
            'configure': [(0, 'Entering configuration mode\nnoc@router#')],
            'show interfaces': [(0, 'candidate interface fragment\n')],
        })
        c = self.collector(conn)
        with patch.object(c, '_connect', wraps=c._connect) as opened:
            self.assertTrue(c.execute('local', 'configure')['ok'])
            result = c.execute('local', 'show interfaces', read_timeout=1)
        self.assertEqual(result['status'], 'TIMEOUT')
        self.assertEqual(result['recovery_skipped'], 'cli_context_unverified')
        self.assertIn('candidate interface fragment', result['output'])
        self.assertEqual(conn.submitted, ['configure', 'show interfaces'])
        opened.assert_called_once()

    def test_probe_resync_failure_reports_show_cli_and_reopens_only_when_enabled(self):
        width = SETUP_COMMANDS[0]
        for enabled in (False, True):
            with self.subTest(enabled=enabled):
                first = PreparationChannel(self.clock, {width: 'error: permission denied'})
                first.echo = lambda command: command + ' wrong' if command == 'show cli' else command
                second = PreparationChannel(self.clock, {})
                c = self.batch_collector(first, second)
                c.defaults['junos_minimal_recovery'] = enabled
                request = {'id': 1, 'method': 'tools/call', 'params': {
                    'name': 'ssh_execute_many',
                    'arguments': {'target': 'local', 'commands': ['show version']}}}
                response = handle_rpc(request, c)
                payload = json.loads(response['result']['content'][0]['text'])
                self.assertEqual(payload['ok'], enabled)
                audit = json.loads(c._audit_path.read_text(encoding='utf-8').splitlines()[-1])
                if enabled:
                    self.assertEqual(payload['recovery_attempts'], 1)
                    self.assertEqual(second.submitted, ['show cli', 'show version'])
                    failure = payload['previous_attempt']
                    self.assertEqual(audit['previous_preparation_command'], 'show cli')
                else:
                    self.assertEqual(second.submitted, [])
                    self.assertEqual(audit['preparation_command'], 'show cli')
                    failure = payload
                self.assertEqual(failure['preparation_command'], 'show cli')
                self.assertEqual(failure['error_reason'], 'junos_echo_mismatch')
                self.assertIn('show cli wrong', failure['output'])
                self.assertEqual(failure['junos_preparation'][0]['command'], width)
                self.assertIn('permission denied', failure['junos_preparation'][0]['output'])
                self.assertIn('resync_output', failure)
                self.assertIs(failure['command_sent'], False)
                self.assertEqual(first.submitted, [width])

    def test_opt_in_batch_recovers_in_fresh_junos_session_and_keeps_both_transcripts(self):
        from netmiko.juniper.juniper import JuniperBase
        b.install_tolerant_preparation()
        width = SETUP_COMMANDS[0]
        commands = ['show version', 'show lldp neighbors', 'show isis adjacency']
        for diagnostic in (width + '\nnoc@router>\n', 'error: permission denied\n'):
            for valid_probe in (True, False):
                with self.subTest(diagnostic=diagnostic, valid_probe=valid_probe):
                    first = PreparationChannel(self.clock, {width: [(0, diagnostic)]})
                    second = PreparationChannel(self.clock, {
                        'show cli': CAPS if valid_probe else 'invalid capability evidence',
                        'show version': [(0, 'Junos: 23.4R2\nlong value\n wrapped row\n---(more)---')],
                    })
                    second.page = [(0, '\nsecond page\nnoc@router>')]
                    attempts = []
                    c = self.collector(first)
                    c.profiles['fixture'] = {'junos_minimal_recovery': True, 'port': 2222,
                                             'ssh_mode': 'strict', 'username': 'fixture',
                                             'password': 'fixture-only'}

                    def connect(**params):
                        conn = (first, second)[len(attempts)]
                        attempts.append(params)
                        try:
                            JuniperBase.session_preparation(conn)
                        except Exception:
                            conn.disconnect()
                            raise
                        return conn

                    with patch.object(c, '_connect', connect):
                        if valid_probe:
                            result = c.execute_many('local', commands, profile='fixture', save_output=True)
                            self.assertTrue(result['ok'], result)
                            self.assertEqual(second.submitted, ['show cli', *commands])
                            self.assertTrue(all(item['command_echo_verified'] for item in result['results']))
                            saved = Path(c.output_dir, result['results'][0]['output_id'] + '.txt')
                            self.assertIn('long value\n wrapped row', saved.read_text(encoding='utf-8'))
                            self.assertIn('second page', saved.read_text(encoding='utf-8'))
                            self.assertIn(' ', second.writes)
                        else:
                            with self.assertRaises(b.CollectionError) as caught:
                                c.execute_many('local', commands, profile='fixture')
                            result = c.failure_result(caught.exception, 'local')
                            self.assertEqual(result['error_reason'], 'junos_minimal_probe_unverified')
                            self.assertIn('invalid capability evidence', result['output'])
                            self.assertIs(result['command_sent'], False)
                            self.assertEqual(second.submitted, ['show cli'])
                            self.assertTrue(second.remote_conn.closed)
                    self.assertEqual(first.submitted, [width])
                    self.assertTrue(first.remote_conn.closed)
                    self.assertEqual(result['recovery_attempts'], 1)
                    self.assertEqual(result['previous_attempt']['output'], width + '\n' + diagnostic)
                    self.assertEqual(len(attempts), 2)
                    for key in ('host', 'port', 'device_type', 'ssh_strict', 'alt_key_file', 'username', 'password'):
                        self.assertEqual(attempts[0][key], attempts[1][key])

    def test_opt_in_batch_does_not_reconnect_after_sending_business_command(self):
        from netmiko.juniper.juniper import JuniperBase
        b.install_tolerant_preparation()
        conn = PreparationChannel(self.clock, {
            SETUP_COMMANDS[0]: [(0, SETUP_COMMANDS[0] + '\nnoc@router>\n'),
                                (4.6, ACKS[SETUP_COMMANDS[0]] + '\nnoc@router>')],
            'show version': [(0, 'partial version\n')],
        })
        c = self.collector(conn)
        c.defaults['junos_minimal_recovery'] = True

        def connect(**kwargs):
            JuniperBase.session_preparation(conn)
            return conn

        with patch.object(c, '_connect', side_effect=connect) as open_session:
            with self.assertRaises(b.BatchError) as caught:
                c.execute_many('local', ['show version', 'show lldp neighbors'], read_timeout=1)
        open_session.assert_called_once()
        self.assertEqual(conn.submitted, [*SETUP_COMMANDS, 'show version'])
        result, skipped = caught.exception.results
        self.assertIn('partial version', result['output'])
        self.assertIs(result['command_sent'], True)
        self.assertEqual(skipped['status'], 'SKIPPED')

    def batch_collector(self, *channels):
        from netmiko.juniper.juniper import JuniperBase
        b.install_tolerant_preparation()
        c = self.collector(channels[0])
        pending = iter(channels)
        def connect(**kwargs):
            channel = next(pending)
            if isinstance(channel, Exception):
                raise channel
            try:
                JuniperBase.session_preparation(channel)
            except Exception:
                channel.disconnect()
                raise
            return channel
        c._connect = connect
        return c

    def test_opt_out_profile_does_not_reuse_minimal_session(self):
        width = SETUP_COMMANDS[0]
        first = PreparationChannel(self.clock, {width: [(0, 'partial width\n')]})
        minimal = PreparationChannel(self.clock, {})
        normal = PreparationChannel(self.clock, {})
        c = self.batch_collector(first, minimal, normal)
        c.profiles.update({'enabled': {'junos_minimal_recovery': True},
                           'disabled': {'junos_minimal_recovery': False}})
        enabled = c.execute_many('local', ['show version'], profile='enabled')
        self.assertEqual(enabled['recovery_attempts'], 1)
        disabled = c.execute_many('local', ['show version'], profile='disabled')
        self.assertTrue(disabled['ok'])
        self.assertFalse(disabled['results'][0]['session_reused'])
        self.assertEqual(normal.submitted, [*SETUP_COMMANDS, 'show version'])
        reused = c.execute('local', 'show version', profile='enabled')
        self.assertTrue(reused['session_reused'])
        self.assertTrue(reused['command_echo_verified'])
        self.assertEqual(minimal.submitted, ['show cli', 'show version', 'show version'])

    def scan_batch(self, collector, name):
        collector.defaults['junos_minimal_recovery'] = True
        target = {'target': 'local', 'device_type': 'juniper_junos',
                  'commands': ['show version', 'show lldp neighbors']}
        directory = Path(self.tmp.name, name)
        scan.run_scan(collector, [target], directory, workers=2, slow_workers=1,
                      fast_timeout=35, slow_timeout=50, device_timeout=85)
        record, = (directory / 'results').glob('*.json')
        return json.loads(record.read_text(encoding='utf-8'))

    def test_scan_shares_retry_budget_with_junos_recovery(self):
        width = SETUP_COMMANDS[0]
        for first_connect_times_out in (False, True):
            with self.subTest(first_connect_times_out=first_connect_times_out):
                failed_prep = PreparationChannel(self.clock, {width: [(0, 'partial width\n')]})
                if first_connect_times_out:
                    channels = (TimeoutError('TCP fixture timeout'), failed_prep)
                    expected_attempts = 2
                else:
                    failed_minimal = PreparationChannel(self.clock, {'show cli': [(0, 'partial probe\n')]})
                    channels = (failed_prep, failed_minimal)
                    expected_attempts = 1
                c = self.batch_collector(*channels)
                with patch.object(c, '_connect', wraps=c._connect) as connect:
                    record = self.scan_batch(c, f'retry-{first_connect_times_out}')
                self.assertEqual(connect.call_count, 2)
                self.assertEqual(record['status'], 'failed')
                self.assertEqual(len(record['attempts']), expected_attempts)
                self.assertEqual(failed_prep.submitted, [width])

    def test_scan_keeps_first_preparation_transcript_when_recovered_batch_stops(self):
        width = SETUP_COMMANDS[0]
        first = PreparationChannel(self.clock, {width: [(0, 'first preparation output\n')]})
        second = PreparationChannel(self.clock, {'show version': 'error: permission denied'})
        c = self.batch_collector(first, second)
        record = self.scan_batch(c, 'keep-recovery')
        attempt, = record['attempts']
        result = attempt['result']
        self.assertEqual(result['recovery_attempts'], 1)
        self.assertEqual(result['previous_attempt']['output'], width + '\nfirst preparation output\n')
        self.assertEqual([item['status'] for item in result['results']], ['CLI_ERROR', 'SKIPPED'])

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
        self.assertEqual(conn.writes, [SETUP_COMMANDS[0], '\n', '\x03'])

    def test_complete_syntax_error_uses_prompt_event_without_echo_deadline(self):
        started = self.clock.now()
        conn = self.prepare({SETUP_COMMANDS[0]: [(0, 'set cli screen-width511\n  ^\nsyntax error, expecting <command>.\nnoc@router>')]})
        self.assertLess(self.clock.now() - started, 1.4)
        self.assertEqual(conn.submitted, [SETUP_COMMANDS[0], 'show cli'])

    def test_syntax_without_prompt_waits_for_late_completion_within_budget(self):
        started = self.clock.now()
        conn = self.prepare({SETUP_COMMANDS[0]: [(0, 'syntax error, expecting <command>.\n'),
                                                (4.5, 'noc@router>')]})
        self.assertGreaterEqual(self.clock.now() - started, 4.5)
        self.assertEqual(conn.submitted, [SETUP_COMMANDS[0], 'show cli'])
        self.assertNotIn('\x03', conn.writes)

    def collector(self, conn):
        c = b.Collector({'defaults': {'execution_policy': 'read_write', 'output_dir': self.tmp.name, 'session_sweep_seconds': 0},
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
                expected_writes = [command, '\n', '\x03'] if driver == 'juniper_junos' else [command + '\n']
                self.assertEqual(conn.writes, expected_writes)

    def test_unrecognized_question_with_timing_preserves_output_without_success_or_replay(self):
        question = 'Chọn thao tác\nSelect maintenance slot (A/B):'
        self.assertFalse(b.pending_interaction(question))
        for interactive in (False, True):
            with self.subTest(interactive=interactive):
                conn = TimelineChannel(self.clock, [(0, question)], prompt='noc@router>')
                c = self.collector(conn)
                if interactive:
                    aggregate = c.interact('local', ['request system reboot', 'B'], read_timeout=1)
                    self.assertEqual(aggregate['steps'][1]['status'], 'SKIPPED')
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
