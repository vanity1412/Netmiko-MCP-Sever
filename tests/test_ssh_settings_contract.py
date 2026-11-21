"""Assert host-key policy at the final Netmiko ConnectHandler boundary."""
import json
from pathlib import Path
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'mcp'))
import collector_backend as b
import bootstrap
import readonly_client
import scan
import validate_fleet
from test_ssh_reliability import FakeConnection
from test_ssh_scenarios import TimelineChannel, VirtualClock


class SSHSettingsContractTests(unittest.TestCase):
    def test_python_from_config_matches_mcp_and_scanner_for_alias_and_override_profile(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config_path = root / 'devices.json'
            inventory = root / 'inventory.csv'
            credentials = root / 'fixture auth.json'
            store = root / 'keys'
            config_path.write_text(json.dumps({'defaults': {'session_sweep_seconds': 0},
                'profiles': {'override': {'ssh_mode': 'strict', 'alt_key_file': str(store),
                    'junos_minimal_recovery': True, 'prompt_quiet_seconds': .7}}}), encoding='utf-8')
            inventory.write_text('name,ip,netmiko_device_type,profile,port\n'
                                 'EDGE,192.0.2.12,juniper_junos,inventory,2222\n', encoding='utf-8')
            credentials.write_text(json.dumps({'profiles': {
                'inventory': {'username': 'inventory-user', 'password': 'fixture-default'},
                'override': {'username': 'selected-user', 'password': 'fixture-selected'},
            }}), encoding='utf-8')
            options = {'inventory_csv': inventory, 'credentials_file': Path(credentials.name),
                       'output_dir': root / 'out'}
            with patch.dict('os.environ', {'NETWORK_SSH_USER': 'env-fixture', 'NETWORK_SSH_PASSWORD': 'env-only'}), \
                    patch('netmiko.ConnectHandler', side_effect=lambda **kwargs: FakeConnection(['fixture version\nrouter#'])) as connect:
                config = bootstrap.load_deployment_config(b, config_path, **options)
                mcp = b.Collector(config)
                self.addCleanup(mcp.shutdown)
                request = {'id': 1, 'method': 'tools/call', 'params': {'name': 'ssh_execute',
                    'arguments': {'target': 'edge', 'profile': 'override', 'command': 'show version'}}}
                rpc = json.loads(b.handle_rpc(request, mcp)['result']['content'][0]['text'])
                self.assertTrue(rpc['ok'])
                desired = connect.call_args.kwargs
                with readonly_client.CLIConnection.from_config(config_path, target='edge',
                        profile='override', **options) as client:
                    result = client.execute_many(['show version'], save_output=True)
                    self.assertTrue(result['ok'])
                    self.assertIn('fixture version',
                                  client.read_output_bytes(result['results'][0]['output_id'])['text'])
                    fallback = connect.call_args.kwargs
                    self.assertEqual(client.collector.prompt_quiet, mcp.prompt_quiet)
                    self.assertEqual(client.collector._request.cli_options['prompt_quiet_seconds'], .7)
                    self.assertIs(client.collector._request.cli_options['junos_minimal_recovery'], True)
                checks = ('host', 'port', 'device_type', 'username', 'password', 'ssh_strict', 'alt_key_file')
                self.assertEqual({key: fallback[key] for key in checks}, {key: desired[key] for key in checks})
                self.assertEqual((fallback['host'], fallback['port'], fallback['username'], fallback['ssh_strict']),
                                 ('192.0.2.12', 2222, 'selected-user', True))
                prepared, _ = scan.prepare_tasks(mcp, [{'target': 'edge', 'profile': 'override'}])
                item = prepared[0]
                scanned = mcp._get_settings(item['target'], item.get('device_type'), item['profile'])
                self.assertEqual({key: scanned[key] for key in checks}, {key: desired[key] for key in checks})
                self.assertEqual(connect.call_count, 2)
                mcp.shutdown()

    def test_python_fallback_error_keeps_current_and_previous_output(self):
        clock = VirtualClock()
        first = TimelineChannel(clock, [(0, 'first partial\n')])
        second = TimelineChannel(clock, [(0, 'second partial\n')])
        with tempfile.TemporaryDirectory() as directory, \
                patch.object(b, 'time', SimpleNamespace(monotonic=clock.now, sleep=clock.sleep, time=time.time)), \
                patch('netmiko.ConnectHandler', side_effect=[first, second]) as connect:
            with readonly_client.CLIConnection(host='192.0.2.1', device_type='cisco_ios', output_dir=directory) as client:
                with self.assertRaises(RuntimeError) as caught:
                    client.send_command('show version', read_timeout=1, save_output=True)
                result = caught.exception.result
                self.assertEqual(result['status'], 'TIMEOUT')
                self.assertEqual(result['recovery_attempts'], 1)
                for attempt, text in ((result, 'second partial'), (result['previous_attempt'], 'first partial')):
                    self.assertIn(text, client.read_output_bytes(attempt['output_id'])['text'])
                with self.assertRaisesRegex(ValueError, 'unsupported_option'):
                    client.execute('show clock', unsupported_option=True)
            self.assertEqual(connect.call_count, 2)

    def test_python_fallback_batch_keeps_partial_output_and_skipped_suffix(self):
        conn = FakeConnection(['fixture version\nrouter#', 'partial interfaces'])
        with tempfile.TemporaryDirectory() as directory, patch('netmiko.ConnectHandler', return_value=conn):
            with readonly_client.CLIConnection(host='192.0.2.1', device_type='cisco_ios', output_dir=directory) as client:
                commands = ['show version', 'show interfaces', 'show clock']
                result = client.execute_many(commands, continue_on_error=True, save_output=True)
                self.assertEqual([item['status'] for item in result['results']], ['SUCCESS', 'PARTIAL', 'SKIPPED'])
                partial = result['results'][1]
                self.assertIn('partial interfaces', client.read_output_bytes(partial['output_id'])['text'])
                self.assertEqual([command for command, _ in conn.sent], commands[:2])

    def test_python_fallback_preserves_strict_store_at_connect_boundary(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            store = root / 'private' / 'known_hosts'
            with patch.object(readonly_client, '__file__', str(root / 'mcp' / 'readonly_client.py')), \
                    patch('netmiko.ConnectHandler', return_value=FakeConnection(['data\nrouter#'])) as connect:
                with readonly_client.ReadOnlyConnection(host='192.0.2.1', device_type='cisco_ios',
                                                        ssh_mode='strict', alt_key_file=str(store)) as wrapper:
                    wrapper.send_command('show version')
                self.assertTrue(connect.call_args.kwargs['ssh_strict'])
                self.assertTrue(connect.call_args.kwargs['alt_host_keys'])
                self.assertEqual(connect.call_args.kwargs['alt_key_file'], str(store.resolve()))

    def test_scanner_and_fleet_preserve_configured_trust_store(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            store = root / 'private_known_hosts'
            config = {'defaults': {'ssh_mode': 'strict', 'alt_key_file': str(store)}}
            args = ['scan.py', '--all', '--output', str(root / 'scan')]
            with patch.object(sys, 'argv', args), patch.object(b, 'load_config', return_value=config), \
                    patch.object(b, 'load_inventory_csv', side_effect=lambda cfg, _: cfg), \
                    patch.object(scan, 'Collector') as collector, patch.object(scan, 'prepare_tasks', return_value=([], {})):
                self.assertEqual(scan.main(), 0)
                self.assertEqual(collector.call_args.args[0]['defaults']['alt_key_file'], str(store))
            with patch.object(validate_fleet, 'Collector', wraps=b.Collector) as collector:
                validate_fleet.validate(config, root / 'fleet')
                self.assertEqual(collector.call_args.args[0]['defaults']['alt_key_file'], str(store))

    def test_host_with_conflicting_modes_requires_exact_alias(self):
        with tempfile.TemporaryDirectory() as directory:
            devices = {
                'compatible': {'host': '192.0.2.1', 'ssh_mode': 'compatible'},
                'strict': {'host': '192.0.2.1', 'ssh_mode': 'strict'},
            }
            with patch('netmiko.ConnectHandler') as connect:
                c = b.Collector({'defaults': {'output_dir': directory, 'session_sweep_seconds': 0},
                                 'devices': devices})
                try:
                    with self.assertRaisesRegex(ValueError, 'Inventory host is ambiguous'):
                        c.execute('192.0.2.1', 'show version')
                    connect.assert_not_called()
                    for alias in devices:
                        self.assertIs(c._get_settings(alias, None, None)['ssh_strict'], alias == 'strict')
                finally:
                    c.shutdown()

    def test_mode_controls_flags_and_preserves_custom_store_at_netmiko_boundary(self):
        for mode in ('compatible', 'strict'):
            for configured in (False, True):
                with self.subTest(mode=mode, configured=configured), tempfile.TemporaryDirectory() as directory:
                    store = Path(directory) / 'custom_known_hosts'
                    with patch('netmiko.ConnectHandler', return_value=FakeConnection(['data\nrouter#'])) as connect:
                        c = b.Collector({'defaults': {'ssh_mode': mode, 'alt_host_keys': configured,
                            'system_host_keys': configured, 'ssh_strict': configured,
                            'alt_key_file': str(store), 'device_type': 'cisco_ios',
                            'output_dir': directory, 'autodetect_cache_file': str(Path(directory)/'drivers.sqlite3'),
                            'session_sweep_seconds': 0}})
                        try:
                            self.assertTrue(c.execute('192.0.2.1', 'show version')['ok'])
                            connect.assert_called_once()
                            settings = connect.call_args.kwargs
                            self.assertNotIn('ssh_mode', settings)
                            for key in ('ssh_strict', 'alt_host_keys', 'system_host_keys'):
                                self.assertIs(settings[key], mode == 'strict')
                            self.assertEqual(settings['alt_key_file'], str(store.resolve()))
                        finally:
                            c.shutdown()
