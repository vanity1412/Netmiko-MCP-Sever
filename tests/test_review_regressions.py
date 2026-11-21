"""Regression cases from the 1.2.2 review; all targets are synthetic."""
import json
import unittest
import concurrent.futures
import threading
from unittest.mock import patch
import test_collector as fixtures

b = fixtures.b


class ReviewRegression(unittest.TestCase):
    setUp = fixtures.Regression.setUp
    tearDown = fixtures.Regression.tearDown

    def test_noc_commands(self):
        commands = [
            'show interfaces xe-0/0/2 terse',
            'show interfaces diagnostics optics xe-0/0/2',
            'show route 172.19.44.0/24 exact',
            'show configuration interfaces xe-0/0/2',
            'show route 2405:4800:f002::538/126 exact',
            'show rsvp interface',
            'show bfd session',
            'show interfaces | match "error|CRC|drop" | no-more',
            'show configuration | match "shutdown"',
        ]
        for command in commands:
            with self.subTest(command=command):
                self.assertEqual(b.readonly_command(command, 'juniper_junos'), command)
        for platform, command in [
            ('cisco_ios', 'show interfaces GigabitEthernet0/0/2'),
            ('cisco_xr', 'show route ipv6 2001:db8::/64 location 0/RP0/CPU0'),
            ('huawei', 'display interface GigabitEthernet0/0/1'),
        ]:
            self.assertEqual(b.readonly_command(command, platform), command)

    def test_pipeline_content_not_filtered(self):
        for command in ['show version | match x | save /tmp/x','configure','commit','show version $x']:
            self.assertEqual(b.readonly_command(command,'juniper_junos'),command)

    def test_interact_failure_serializes_and_saves(self):
        result = self.c.interact('MOCK', ['show version', 'show system bad'], save_output=True)
        self.assertFalse(result['ok'])
        self.assertEqual(len(result['steps']), 2)
        json.dumps(result)
        self.assertIn('Authorization failed', self.c.read_output(result['output_id'])['text'])

    def test_echo_must_match_whole_command(self):
        for output in ['show version detail\nMOCK>', 'prefix show version suffix\nMOCK>']:
            self.assertFalse(self.c._result('MOCK', 'show version', output, 0)['command_echo_verified'])
        self.assertTrue(self.c._result('MOCK', 'show version', 'MOCK> show version\nDATA\nMOCK>', 0)['ok'])

    def test_hierarchical_login_redaction(self):
        self.assertNotIn('alice', b.redact_text('    user alice {\n uid 2000;\n}'))

    def test_rpc_interact_preserves_cli_error(self):
        result = b.handle_rpc({'id': 1, 'method': 'tools/call', 'params': {
            'name': 'ssh_interact', 'arguments': {'target': 'MOCK', 'steps': ['show system bad']}}}, self.c)
        body = json.loads(result['result']['content'][0]['text'])
        self.assertEqual(body['error'], 'CliError')
        self.assertEqual(len(body['steps']), 1)

    def test_rpc_interact_cancel_between_steps_keeps_prefix_and_sent_flags(self):
        cancel = threading.Event()
        command_result = self.c._command_result

        def complete_then_cancel(*args, **kwargs):
            result = command_result(*args, **kwargs)
            cancel.set()
            return result

        request = {'id': 1, 'method': 'tools/call', 'params': {
            'name': 'ssh_interact', 'arguments': {'target': 'MOCK',
            'steps': ['configure terminal', 'interface Gi0/1', 'end'], 'save_output': True}}}
        with self.c.request_budget(cancel=cancel), patch.object(
                self.c, '_command_result', side_effect=complete_then_cancel):
            response = b.handle_rpc(request, self.c)
        result = json.loads(response['result']['content'][0]['text'])
        prefix, cancelled, skipped = result['steps']
        self.assertEqual(result['status'], 'CANCELLED')
        self.assertEqual(result['failed_step_index'], 1)
        self.assertIn('configure terminal', self.c.read_output(prefix['output_id'])['text'])
        self.assertEqual([step['step_index'] for step in result['steps']], [0, 1, 2])
        self.assertEqual([step['command_sent'] for step in result['steps']], [True, False, False])
        self.assertEqual(cancelled['execution_state'], 'NOT_SENT')
        self.assertEqual(skipped['status'], 'SKIPPED')
        self.assertEqual(self.connections[0].commands, ['configure terminal'])

    def test_rpc_interact_storage_errors_preserve_step_and_aggregate_evidence(self):
        commands = ['show version', 'show interfaces', 'show clock']
        for fail_at in (2, 4):
            with self.subTest(fail_at=fail_at):
                self.c.close()
                save = self.c._save_output
                saves = []

                def fail_one_save(output, **kwargs):
                    saves.append(output)
                    if len(saves) == fail_at:
                        raise OSError('fixture disk full')
                    return save(output, **kwargs)

                request = {'id': 1, 'method': 'tools/call', 'params': {
                    'name': 'ssh_interact', 'arguments': {'target': 'MOCK',
                    'steps': commands, 'save_output': True}}}
                with patch.object(self.c, '_save_output', side_effect=fail_one_save):
                    response = b.handle_rpc(request, self.c)
                result = json.loads(response['result']['content'][0]['text'])
                self.assertEqual(result['status'], 'STORAGE_ERROR')
                self.assertIn(commands[0], self.c.read_output(result['steps'][0]['output_id'])['text'])
                if fail_at == 2:
                    self.assertEqual(result['failed_step_index'], 1)
                    self.assertEqual(result['steps'][2]['status'], 'SKIPPED')
                    self.assertEqual(self.connections[-1].commands, commands[:2])
                    self.assertIn(commands[1], result['steps'][1]['output'])
                else:
                    self.assertNotIn('failed_step_index', result)
                    self.assertEqual(self.connections[-1].commands, commands)
                    for command, step in zip(commands, result['steps']):
                        self.assertIn(command, self.c.read_output(step['output_id'])['text'])
                        self.assertIn(command, result['output'])

    def test_autodetect_different_hosts_do_not_serialize(self):
        rendezvous = threading.Barrier(2)
        class Detector:
            def autodetect(self):
                rendezvous.wait(timeout=2)
                return 'juniper_junos'
        self.c._custom_detect = lambda **kw: Detector()
        params = [self.c._get_settings(host, 'autodetect', None) for host in ['mock-one', 'mock-two']]
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            list(pool.map(self.c._resolve_platform, params))
        self.assertEqual([p['device_type'] for p in params], ['juniper_junos'] * 2)
        self.assertFalse(self.c._detection_locks)
