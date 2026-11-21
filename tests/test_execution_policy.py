"""Execution policy contract with mocked SSH only."""
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

import test_collector as fixtures
import scan
from readonly_client import CLIConnection

b = fixtures.b


class ExecutionPolicyTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.directory = Path(directory.name)
        self.connect = Mock(side_effect=lambda **_: fixtures.Fake())

    def collector(self, policy='read_only', driver='juniper_junos'):
        defaults = {'output_dir': str(self.directory), 'session_sweep_seconds': 0}
        if policy is not None:
            defaults['execution_policy'] = policy
        collector = b.Collector({'defaults': defaults, 'devices': {
            'fixture': {'host': '192.0.2.1', 'device_type': driver},
        }}, connect_factory=self.connect)
        self.addCleanup(collector.shutdown)
        return collector

    def call(self, collector, tool, **arguments):
        request = {'id': 1, 'method': 'tools/call',
                   'params': {'name': tool, 'arguments': arguments}}
        result = b.handle_rpc(request, collector)['result']
        return json.loads(result['content'][0]['text'])

    def test_read_only_reports_policy_and_allows_observation(self):
        for driver, command in (('juniper_junos', 'show configuration | display set | no-more'),
                                ('cisco_ios', 'show running-config | include hostname'),
                                ('huawei', 'display interface brief'),
                                ('linux', 'ip route show')):
            with self.subTest(driver=driver):
                collector = self.collector(driver=driver)
                status = self.call(collector, 'ssh_status')
                self.assertEqual(status['execution_policy'], 'read_only')
                self.assertTrue(status['execution_policy_configured'])
                result = self.call(collector, 'ssh_execute', target='fixture', command=command)
                self.assertTrue(result['ok'], result)
                self.assertTrue(result['command_sent'])

    def test_read_only_blocks_writes_before_ssh_in_each_execution_path(self):
        collector = self.collector()
        commands = ['configure', 'commit', 'show configuration | save /tmp/config.txt',
                    'show version; configure', 'show version | redirect flash:backup',
                    "show version | include 'text | redirect flash:backup'"]
        for command in commands:
            with self.subTest(command=command):
                result = self.call(collector, 'ssh_execute', target='fixture', command=command)
                self.assertEqual(result['status'], 'POLICY_DENIED')
                self.assertFalse(result['command_sent'])
                self.assertFalse(result['transport_ok'])
        result = self.call(collector, 'ssh_execute_many', target='fixture',
                           commands=['show version', 'set interfaces lo0 disable'], continue_on_error=True)
        self.assertEqual(result['status'], 'POLICY_DENIED')
        self.assertFalse(result['command_sent'])
        result = self.call(collector, 'ssh_parallel', tasks=[
            {'target': 'fixture', 'command': 'commit'},
            {'target': 'fixture', 'commands': ['show version', 'configure']},
        ])
        self.assertEqual([task['status'] for task in result['results']], ['POLICY_DENIED'] * 2)
        result = self.call(collector, 'ssh_interact', target='fixture', steps=['show version', ''])
        self.assertEqual(result['status'], 'POLICY_DENIED')
        override = b.handle_rpc({'id': 1, 'method': 'tools/call', 'params': {
            'name': 'ssh_execute_many', 'arguments': {'target': 'fixture', 'commands': ['show version'],
                                                     '_resolved_scan_params': {}}}}, collector)
        self.assertEqual(override['error']['code'], -32602)
        with self.assertRaises(b.CollectionError):
            scan.prepare_tasks(collector, [{'target': 'fixture', 'commands': ['configure']}])
        self.connect.assert_not_called()

    def test_read_only_checks_resolved_driver_before_writing(self):
        collector = self.collector(driver='autodetect')
        collector._custom_detect = lambda **_: Mock(autodetect=Mock(return_value='linux'))
        result = self.call(collector, 'ssh_execute', target='fixture', command='show version')
        self.assertEqual(result['status'], 'POLICY_DENIED')
        self.assertFalse(result['command_sent'])
        entry, = collector._sessions.values()
        self.assertEqual(entry['conn'].commands, [])
        rejected = self.call(collector, 'ssh_execute', target='fixture',
                             command='show version', device_type='juniper_junos')
        self.assertEqual(rejected['status'], 'POLICY_DENIED')
        self.connect.assert_called_once()

    def test_scanner_runs_safe_autodetect_plan_on_resolved_driver(self):
        collector = self.collector(driver='autodetect')
        detector = Mock(autodetect=Mock(return_value='juniper_junos'))
        collector._custom_detect = Mock(return_value=detector)
        job = self.directory / 'scan'
        scan.run_scan(collector, [{'target': 'fixture', 'device_type': 'autodetect'}],
                      job, workers=2, slow_workers=1)
        entry, = collector._sessions.values()
        self.assertEqual(entry['conn'].commands, ['show version'])
        collector._custom_detect.assert_called_once()
        self.connect.assert_called_once()
        self.assertTrue(any((job / 'bang-chung').glob('*.txt')))

    def test_python_client_retains_policy_from_deployment_config(self):
        config_path = self.directory / 'devices.json'
        config_path.write_text(json.dumps({'defaults': {
            'execution_policy': 'read_only', 'session_sweep_seconds': 0,
            'username': 'fixture-user', 'password': 'fixture-password',
        }, 'devices': {'fixture': {'host': '192.0.2.1', 'device_type': 'juniper_junos'}}}),
            encoding='utf-8')
        with patch.dict(os.environ, {'NETWORK_SSH_USER': 'fixture-user', 'NETWORK_SSH_PASSWORD': 'fixture-password'}), \
                patch('readonly_client.Collector', side_effect=lambda config: b.Collector(
                    config, connect_factory=self.connect)):
            client = CLIConnection.from_config(config_path, target='fixture', output_dir=self.directory)
        with client:
            denied = client.execute_many(['show version', 'configure'])
            self.assertEqual(denied['status'], 'POLICY_DENIED')
            self.assertFalse(denied['command_sent'])
            self.connect.assert_not_called()
            self.assertTrue(client.execute('show version')['ok'])

    def test_explicit_read_write_and_legacy_mode_keep_configuration_path(self):
        for policy in ('read_write', None):
            with self.subTest(policy=policy):
                collector = self.collector(policy=policy)
                status = self.call(collector, 'ssh_status')
                self.assertEqual(status['execution_policy'], 'read_write')
                self.assertIs(status['execution_policy_configured'], policy is not None)
                result = self.call(collector, 'ssh_execute_many', target='fixture',
                                    commands=['configure', 'set interfaces lo0 description fixture', 'commit'])
                self.assertTrue(result['ok'], result)
                self.assertTrue(all(item['command_sent'] for item in result['results']))

    def test_invalid_policy_is_a_startup_error(self):
        with self.assertRaisesRegex(ValueError, 'execution_policy'):
            self.collector(policy='writable')
        self.connect.assert_not_called()
