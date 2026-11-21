"""Assert host-key policy at the final Netmiko ConnectHandler boundary."""
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'mcp'))
import collector_backend as b
import readonly_client
import scan
import validate_fleet
from test_ssh_reliability import FakeConnection


class SSHSettingsContractTests(unittest.TestCase):
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
