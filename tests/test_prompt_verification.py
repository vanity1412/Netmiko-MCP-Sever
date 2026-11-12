"""Prompt/echo verification regressions (no SSH, no device).

Replays two prompt cases reported from live devices using synthetic fixtures:
  * a stale prompt that arrives after the channel drain but before the echo;
  * a Junos CLI that repaints its input line and echoes the command twice.
Also covers `error_reason` propagation and the normalized batch payload.
"""
import importlib.util
import json
import sys
import types
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'mcp'))
spec = importlib.util.spec_from_file_location('collector_backend', ROOT / 'mcp' / 'collector_backend.py')
backend = importlib.util.module_from_spec(spec)
spec.loader.exec_module(backend)


class FakeConn:
    def __init__(self, chunks, prompt):
        self.chunks = list(chunks)
        self.prompt = prompt
        self.written = []
        self.sent = False
        self._network_prompt_text = prompt
        self._network_prompt_root = prompt
        self.remote_conn = types.SimpleNamespace(closed=False, eof_received=False)

    def read_channel(self):
        # Before write_channel the collector drains stale data; these scripted
        # chunks are device responses produced only after the command is sent.
        if not self.sent:
            return ''
        return self.chunks.pop(0) if self.chunks else ''

    def write_channel(self, data):
        self.written.append(data)
        self.sent = True

    def normalize_cmd(self, command):
        return command + '\n'

    def find_prompt(self):
        return self.prompt

    def is_alive(self):
        return True


def run(chunks, command, prompt, timeout=2.5):
    conn = FakeConn(chunks, prompt)
    return backend.read_cli_output(conn, command, timeout, r'(?m)^' + prompt.replace('.', r'\.') + r'[ \t]*\r?$')


class PromptVerificationTests(unittest.TestCase):
    def test_stale_prompt_before_echo_is_not_completion(self):
        output, failure = run(['\nCORE1#',
                               'show clock\n07:00:00 UTC Thu Nov 12 2026\nCORE1#'],
                              'show clock', 'CORE1#')
        self.assertIsNone(failure)
        self.assertIn('07:00:00', output)

    def test_junos_repaint_prompt_is_not_completion(self):
        chunks = ['\n{master:0}\nnoc@sw> set cli screen-width 511\n',
                  '\n{master:0}\nnoc@sw> ',
                  'set cli screen-width 511 \nScreen width set to 511\n\n{master:0}\nnoc@sw> ']
        output, failure = run(chunks, 'set cli screen-width 511', 'noc@sw>')
        self.assertIsNone(failure, failure)
        self.assertIn('Screen width set to 511', output)

    def test_genuine_continuation_after_prompt_still_fails(self):
        output, failure = run(['show version\nCORE1#', 'extra line after prompt\nCORE1#'],
                              'show version', 'CORE1#')
        self.assertIsNotNone(failure)
        self.assertEqual(failure['error_category'], 'output_verification')
        self.assertEqual(failure['error_reason'], 'prompt_candidate_continuation')
        self.assertIn('extra line', output)

    def test_complete_output_without_echo_still_completes(self):
        output, failure = run(['07:00:00 UTC\nCORE1#'], 'show clock', 'CORE1#')
        self.assertIsNone(failure)
        self.assertIn('07:00:00', output)

    def test_log_ambiguity_has_reason(self):
        output, failure = run(['show log messages\nmessage line\nCORE1#'],
                              'show log messages', 'CORE1#')
        self.assertEqual(failure['error_reason'], 'log_prompt_ambiguity')

    def test_enter_only_interaction_step_still_completes(self):
        # ssh_interact may send a bare Enter, which has no command echo.
        output, failure = run(['\nCORE1#'], '\n', 'CORE1#')
        self.assertIsNone(failure)

    def test_echo_with_irregular_spacing_is_recognized(self):
        output, failure = run(['show  clock\n07:00:00 UTC\nCORE1#'], 'show  clock', 'CORE1#')
        self.assertIsNone(failure)
        self.assertIn('07:00:00', output)

    def test_repeated_echo_after_real_payload_does_not_hide_continuation(self):
        output, failure = run(['show version\nVersion 1\nCORE1#',
                               '\nshow version\nlate payload\nCORE1#'],
                              'show version', 'CORE1#')
        self.assertEqual(failure['error_reason'], 'prompt_candidate_continuation')
        self.assertIn('late payload', output)

    def test_width_repaint_after_response_body_remains_ambiguous(self):
        output, failure = run(['set cli screen-width 511\nScreen width set to 511\nCORE1#',
                               '\nset cli screen-width 511\nlate payload\nCORE1#'],
                              'set cli screen-width 511', 'CORE1#')
        self.assertEqual(failure['error_reason'], 'prompt_candidate_continuation')
        self.assertIn('late payload', output)

    def test_long_command_prefix_inside_payload_is_not_echo(self):
        command='show ' + 'x' * 70
        output, failure = run(['CORE1#', '\n' + command[:60] + ' unrelated data\nCORE1#'],
                              command, 'CORE1#')
        self.assertEqual(failure['error_reason'], 'prompt_candidate_continuation')
        self.assertIn('unrelated data', output)


class ErrorReasonTests(unittest.TestCase):
    def test_error_reason_survives_normalization_for_non_cli_category(self):
        result = backend.normalize_result({'ok': False, 'error_category': 'read_timeout',
                                           'error_stage': 'command', 'error_reason': 'read_timeout',
                                           'command_sent': True, 'output': 'partial'})
        self.assertEqual(result['error_reason'], 'read_timeout')
        self.assertEqual(result['status'], 'TIMEOUT')

    def test_error_reason_removed_on_success(self):
        result = backend.normalize_result({'ok': True, 'output_complete': True, 'output': 'x',
                                           'error_reason': 'stale'})
        self.assertNotIn('error_reason', result)

    def test_preparation_error_keeps_specific_message(self):
        err = backend.preparation_error({'error_category': 'output_verification',
                                         'message': 'Data continued after a prompt candidate',
                                         'retryable': False}, 'raw', 'set cli screen-width 511')
        self.assertEqual(err.details['error'], 'PreparationOutputVerificationError')
        self.assertEqual(err.details['error_stage'], 'preparation')
        self.assertIn('prompt candidate', err.details['message'])


class BatchSummaryTests(unittest.TestCase):
    def results(self):
        return [
            {'target': 'r1', 'command': 'show clock', 'command_index': 0, 'ok': True, 'status': 'SUCCESS'},
            {'target': 'r1', 'command': 'bad', 'command_index': 1, 'ok': False, 'status': 'CLI_ERROR',
             'error_category': 'cli_error', 'error_stage': 'cli', 'error_reason': 'syntax_error'},
            {'target': 'r1', 'command': 'show ip int brief', 'command_index': 2, 'ok': False,
             'skipped': True, 'status': 'SKIPPED', 'blocked_by_command_index': 1},
        ]

    def test_partial_batch_has_same_fields_as_success(self):
        summary = backend.batch_summary('r1', 3, self.results(), False)
        for key in ('target', 'results', 'ok', 'total', 'successes', 'failures', 'continue_on_error'):
            self.assertIn(key, summary)
        self.assertFalse(summary['ok'])
        self.assertTrue(summary['partial_failure'])
        self.assertEqual(summary['successes'], 1)
        self.assertEqual(summary['failures'], 2)
        self.assertEqual(summary['skipped_commands'], 1)
        self.assertEqual(summary['failed_command_index'], 1)
        self.assertEqual(summary['failed_error_reason'], 'syntax_error')

    def test_batch_error_carries_summary(self):
        err = backend.BatchError(self.results(), {'ok': False, 'results': self.results()})
        self.assertFalse(err.summary['ok'])
        self.assertEqual(err.last_result['command_index'], 1)

    def test_rpc_stopped_batch_preserves_normalized_diagnostics(self):
        results = self.results()
        summary = backend.batch_summary('r1', 3, results, False)
        def execute_many(**kwargs):
            raise backend.BatchError(results, summary)
        collector = types.SimpleNamespace(execute_many=execute_many, audit=lambda *args: None)
        reply = backend.handle_rpc({'jsonrpc': '2.0', 'id': 1, 'method': 'tools/call',
                                    'params': {'name': 'ssh_execute_many', 'arguments': {
                                        'target': 'r1', 'commands': ['show clock', 'bad', 'show interfaces']}}}, collector)
        self.assertTrue(reply['result']['isError'])
        payload = json.loads(reply['result']['content'][0]['text'])
        for key in ['total', 'successes', 'failures', 'partial_failure', 'skipped_commands',
                    'failed_command_index', 'failed_status', 'failed_error_category', 'failed_error_reason']:
            self.assertEqual(payload[key], summary[key])


if __name__ == '__main__':
    unittest.main()
