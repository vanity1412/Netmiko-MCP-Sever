"""Execution policy contract with mocked SSH only."""
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

import test_collector as fixtures
import scan
from readonly_client import CLIConnection, ReadOnlyConnection

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

    def test_missing_policy_defaults_to_read_only(self):
        collector = self.collector(policy=None)
        status = self.call(collector, 'ssh_status')
        self.assertEqual(status['execution_policy'], 'read_only')
        self.assertFalse(status['execution_policy_configured'])
        result = self.call(collector, 'ssh_execute', target='fixture', command='configure')
        self.assertEqual(result['status'], 'POLICY_DENIED')
        self.connect.assert_not_called()

    def test_json_read_write_keeps_configuration_path(self):
        config_path = self.directory / 'write.json'
        config_path.write_text(json.dumps({'defaults': {'execution_policy': 'read_write',
            'output_dir': str(self.directory), 'session_sweep_seconds': 0},
            'devices': {'fixture': {'host': '192.0.2.1', 'device_type': 'juniper_junos'}}}), encoding='utf-8')
        collector = b.Collector(b.load_config(str(config_path)), connect_factory=self.connect)
        self.addCleanup(collector.shutdown)
        status = self.call(collector, 'ssh_status')
        self.assertEqual(status['execution_policy'], 'read_write')
        self.assertTrue(status['execution_policy_configured'])
        commands = ['configure', 'set interfaces lo0 description fixture', 'commit']
        result = self.call(collector, 'ssh_execute_many', target='fixture', commands=commands)
        self.assertTrue(result['ok'], result)
        entry, = collector._sessions.values()
        self.assertEqual(entry['conn'].commands, commands)
        with patch.dict(os.environ, {'NETWORK_SSH_USER': 'fixture-user', 'NETWORK_SSH_PASSWORD': 'fixture-password'}), \
                patch('readonly_client.Collector', return_value=collector):
            with self.assertRaisesRegex(ValueError, 'ReadOnlyConnection requires read_only'):
                ReadOnlyConnection.from_config(config_path, target='fixture')
            client = CLIConnection.from_config(config_path, target='fixture', output_dir=self.directory)
            self.assertTrue(client.execute_many(commands)['ok'])

    def test_direct_read_only_wrapper_cannot_opt_into_writes(self):
        with patch('readonly_client.Collector', side_effect=lambda config: b.Collector(
                config, connect_factory=self.connect)):
            with ReadOnlyConnection(host='192.0.2.1', device_type='juniper_junos',
                                    output_dir=str(self.directory)) as client:
                result = client.execute('commit')
                self.assertEqual(result['status'], 'POLICY_DENIED')
                self.assertFalse(result['command_sent'])
            for policy in ('operational', 'read_write'):
                with self.assertRaisesRegex(ValueError, 'ReadOnlyConnection requires read_only'):
                    ReadOnlyConnection(host='192.0.2.1', device_type='juniper_junos', execution_policy=policy)
        self.connect.assert_not_called()

    def test_invalid_policy_is_a_startup_error(self):
        with self.assertRaisesRegex(ValueError, 'execution_policy'):
            self.collector(policy='writable')
        self.connect.assert_not_called()

    def test_operational_blacklist_by_driver(self):
        cases = {
            'juniper_junos': (['ping 192.0.2.2 count 3 wait 2 routing-instance core',
                               'traceroute 192.0.2.2', 'show system commit', 'file list /var/log'],
                              ['configure private', 'edi', 'commit confirmed', 'load merge x',
                               'show configuration | sav example', 'request system reboot', 'clear bgp neighbor x',
                               'request support information', 'monitor start fixture.log', 'protect interfaces']),
            'cisco_ios': (['traceroute vrf core 192.0.2.2 ttl 1 12 probe 2 timeout 1',
                           'ping 192.0.2.2', 'show running-config | include hostname', 'dir flash:'],
                          ['conf t', 'wr mem', 'copy running-config startup-config', 'do configure terminal',
                           'delete nvram:startup-config', 'show running-config | redirect flash:backup',
                           'clear counters', 'debug ip packet', 'terminal monitor', 'config-register x',
                           'ip route 192.0.2.0 255.255.255.0 192.0.2.1']),
            'huawei': (['display current-configuration', 'ping -c 3 -t 1000 192.0.2.2',
                        'tracert 192.0.2.2', 'dir flash:/'],
                       ['sys', 'commit', 'save', 'reset saved-configuration', 'debugging ip packet',
                        'terminal debugging', 'undo interface GigabitEthernet0/0/1',
                        'display diagnostic-information flash:/report.txt']),
            'linux': (['ip -br address show', 'ip route show', 'systemctl status sshd', 'df -h',
                       "cat /var/log/fixture | grep -E 'up|down'", 'ethtool eth0'],
                      ['touch example', 'ip address flush', 'ip link set eth0 down', 'sudo -n ip route show',
                       'systemctl restart sshd', 'nmcli con up eth0', 'ethtool -K eth0 rx off',
                       'ethtool --offload eth0 rx off', 'sed -f fixture.sed example',
                       'ss -K', 'cat /var/log/fixture | tee example', 'crontab -e',
                       'sed -ni p example', '/usr/bin/rm example']),
        }
        for driver, (allowed, blocked) in cases.items():
            for expected, commands in ((True, allowed), (False, blocked)):
                for command in commands:
                    with self.subTest(driver=driver, command=command):
                        self.assertEqual(b.operational_policy_allows(command, driver), expected)
        self.assertFalse(b.operational_policy_allows('ping 192.0.2.2', 'unknown_driver'))

    def test_operational_policy_on_mcp_batch_parallel_and_interact(self):
        collector = self.collector(policy='operational')
        status = self.call(collector, 'ssh_status')
        self.assertEqual(status['execution_policy'], 'operational')
        for tool, arguments in (
                ('ssh_execute_many', {'target': 'fixture', 'commands': ['ping 192.0.2.2 count 3 wait 2', 'commit']}),
                ('ssh_interact', {'target': 'fixture', 'steps': ['show version', '']})):
            result = self.call(collector, tool, **arguments)
            self.assertEqual(result['status'], 'POLICY_DENIED')
            self.assertFalse(result['command_sent'])
        result = self.call(collector, 'ssh_parallel', tasks=[{'target': 'fixture', 'command': 'configure'}])
        self.assertEqual(result['results'][0]['status'], 'POLICY_DENIED')
        self.connect.assert_not_called()
        result = self.call(collector, 'ssh_execute', target='fixture', command='ping 192.0.2.2 count 3 wait 2')
        self.assertTrue(result['ok'], result)
        self.connect.assert_called_once()
        linux = self.collector(policy='operational', driver='linux')
        self.assertEqual(self.call(linux, 'ssh_execute', target='fixture', command='systemctl restart sshd')['status'],
                         'POLICY_DENIED')
        self.connect.assert_called_once()
        conn = fixtures.Fake()
        conn.find_prompt = lambda: 'MOCK#'
        conn.send_command = Mock(return_value='Filesystem summary\nMOCK#')
        self.connect.side_effect = None
        self.connect.return_value = conn
        self.assertTrue(self.call(linux, 'ssh_execute', target='fixture', command='df -h')['ok'])

    def test_operational_blocks_config_prompt_and_driver_override(self):
        conn = fixtures.Fake()
        conn.find_prompt = lambda: 'MOCK(config)#'
        self.connect.side_effect = None
        self.connect.return_value = conn
        collector = self.collector(policy='operational', driver='cisco_ios')
        collector.defaults['auto_enable'] = True
        result = self.call(collector, 'ssh_execute', target='fixture', command='show version', device_type='linux')
        self.assertEqual(result['status'], 'POLICY_DENIED')
        self.connect.assert_not_called()
        result = self.call(collector, 'ssh_execute', target='fixture', command='show version')
        self.assertEqual(result['status'], 'POLICY_DENIED')
        self.assertFalse(result['command_sent'])
        self.connect.assert_called_once()
        self.assertEqual(conn.commands, [])

    def test_operational_scanner_pins_autodetected_driver(self):
        collector = self.collector(policy='operational', driver='autodetect')
        collector._custom_detect = Mock(return_value=Mock(autodetect=Mock(return_value='juniper_junos')))
        with self.assertRaises(b.CollectionError):
            scan.prepare_tasks(collector, [{'target': 'fixture', 'commands': ['commit confirmed']}])
        self.connect.assert_not_called()
        command = 'ping 192.0.2.2 count 3 wait 2'
        result = scan.run_scan(collector, [{'target': 'fixture', 'commands': [command]}],
                               self.directory / 'scan-operational', workers=2, slow_workers=1)
        self.assertTrue(result['ok'], result)
        collector._custom_detect.assert_called_once()
        entry, = collector._sessions.values()
        self.assertEqual(entry['conn'].commands, [command])

    def test_mcp_negotiates_only_supported_handshake_versions(self):
        collector = self.collector()
        status = self.call(collector, 'ssh_status')
        versions = ['2024-11-05', '2025-03-26', '2025-06-18', '2025-11-25']
        self.assertEqual(status['mcp_protocol_versions'], versions)
        for request, expected in [(v, v) for v in versions] + [('2026-07-28', '2025-11-25')]:
            with self.subTest(request=request):
                reply = b.handle_rpc({'id': 1, 'method': 'initialize',
                                      'params': {'protocolVersion': request}}, collector)
                self.assertEqual(reply['result']['protocolVersion'], expected)
        self.connect.assert_not_called()
