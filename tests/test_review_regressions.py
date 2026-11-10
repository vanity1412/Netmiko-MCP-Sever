"""Regression cases from the 1.2.2 review; all targets are synthetic."""
import json
import unittest
import concurrent.futures
import threading
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
