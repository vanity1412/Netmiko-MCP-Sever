"""Fresh public-file deployment; synthetic credentials and no device SSH."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'mcp'))
import collector_backend as b


class OnboardingTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='fresh install ')
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def inventory(self, text):
        path = self.root / 'devices.csv'
        path.write_text(text, encoding='utf-8-sig')
        return b.load_inventory_csv({}, str(path))

    def test_blank_driver_falls_back_but_explicit_driver_is_unchanged(self):
        config = self.inventory('name,ip,netmiko_device_type\nA,192.0.2.1,  \nB,192.0.2.2,juniper_junos\n')
        self.assertEqual(config['devices']['A']['device_type'], 'autodetect')
        c = b.Collector({**config, 'defaults': {'output_dir': str(self.root/'out'),
            'device_type': 'cisco_ios', 'session_sweep_seconds': 0}},
            connect_factory=lambda **kw: self.fail('Inventory validation must not SSH'))
        try:
            self.assertEqual(c._get_settings('B', None, None)['device_type'], 'juniper_junos')
            self.assertEqual(c.status()['connections_opened'], 0)
        finally:
            c.shutdown()

    def test_absent_driver_column_defaults_to_autodetect(self):
        config = self.inventory('name,ip\nA,192.0.2.1\n')
        self.assertEqual(config['devices']['A']['device_type'], 'autodetect')

    def test_missing_identity_still_fails(self):
        for text in ('name,ip\n,192.0.2.1\n', 'name,ip\nA,\n', 'name\nA\n'):
            with self.subTest(text=text), self.assertRaises(ValueError):
                self.inventory(text)

    def fresh_check(self, credentials=True, inventory=False):
        folder = self.root/'new checkout'; (folder/'mcp').mkdir(parents=True)
        for source in (ROOT/'mcp').glob('*.py'):
            shutil.copy2(source, folder/'mcp'/source.name)
        shutil.copy2(ROOT/'mcp/devices.example.json', folder/'mcp/devices.json')
        shutil.copy2(ROOT/'mcp/credentials.example.json', folder/'mcp/credentials.json')
        env = {k:v for k,v in os.environ.items() if not k.startswith(('NETWORK_', 'SITE_B_'))}
        if credentials:
            env.update(NETWORK_SSH_USER='fixture-user', NETWORK_SSH_PASSWORD='fixture-password')
        command = [sys.executable, str(folder/'mcp/check_install.py'), '--config', str(folder/'mcp/devices.json')]
        if inventory:
            path = folder/'inventory.csv'
            path.write_text('name,ip\nfixture,192.0.2.1\n', encoding='utf-8')
            command += ['--inventory-csv', str(path)]
        result = subprocess.run(command, cwd=self.root, env=env, capture_output=True,
                                text=True, encoding='utf-8', timeout=35)
        return result, json.loads(result.stdout)

    def test_copied_examples_need_only_default_credentials_and_work_outside_cwd(self):
        result, report = self.fresh_check()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(report['mcp_connected'])
        self.assertEqual(report['tools'], 10)
        self.assertFalse(report['ssh_tested'])
        self.assertNotIn('fixture-password', result.stdout + result.stderr)

    def test_install_check_with_driverless_inventory_does_not_ssh(self):
        result, report = self.fresh_check(inventory=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(report['ssh_tested'])
        self.assertEqual(report['credential_validity_on_device'], 'not_tested')

    def test_missing_credentials_fail_without_leaking_traceback(self):
        result, report = self.fresh_check(credentials=False)
        self.assertEqual(result.returncode, 1)
        self.assertFalse(report['ok'])
        self.assertFalse(report['ssh_tested'])
        self.assertNotIn('Traceback', result.stdout + result.stderr)


if __name__ == '__main__': unittest.main()
