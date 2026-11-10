"""Assert host-key policy at the final Netmiko ConnectHandler boundary."""
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'mcp'))
import collector_backend as b
from test_ssh_reliability import FakeConnection


class SSHSettingsContractTests(unittest.TestCase):
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
