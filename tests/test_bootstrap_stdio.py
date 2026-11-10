"""Real bootstrap JSON-RPC subprocess against synthetic SSH on localhost only."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

import paramiko
from test_ssh_reliability import LocalSSHServer

ROOT = Path(__file__).resolve().parents[1]


class BootstrapStdioTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.key = paramiko.RSAKey.generate(2048)

    def test_preparation_timeout_keeps_evidence_and_readiness_over_stdio(self):
        for driver in ('juniper_junos', 'autodetect'):
            with self.subTest(driver=driver), tempfile.TemporaryDirectory() as directory:
                folder = Path(directory)
                server = LocalSSHServer(self.key)
                try:
                    server.prompt = 'noc@router>'
                    server.responses['show version'] = 'Junos: 23.4R1'
                    server.responses['set cli screen-width 511'] = lambda ch: ch.sendall(
                        'bằng chứng loopback-only\n'.encode('utf-8'))
                    config = {'defaults': {'device_type': driver, 'port': server.port,
                        'username': 'tester', 'password': 'loopback-only', 'session_sweep_seconds': 0,
                        'alt_key_file': str(folder / 'known_hosts'),
                        'autodetect_cache_file': str(folder / 'drivers.sqlite3')}}
                    path = folder / 'config.json'
                    path.write_text(json.dumps(config), encoding='utf-8')
                    request = {'jsonrpc': '2.0', 'id': 1, 'method': 'tools/call', 'params': {
                        'name': 'ssh_execute', 'arguments': {'target': '127.0.0.1', 'command': 'show interfaces terse'}}}
                    env = dict(os.environ, NETWORK_MCP_DATA_DIR=str(folder / 'data'),
                               NETWORK_SSH_USER='tester', NETWORK_SSH_PASSWORD='loopback-only')
                    env.pop('NETWORK_MCP_CREDENTIALS_FILE', None)
                    proc = subprocess.run([sys.executable, '-u', str(ROOT / 'mcp/bootstrap.py'),
                        '--config', str(path)], input=json.dumps(request) + '\n', capture_output=True,
                        text=True, encoding='utf-8', env=env, timeout=45)
                    self.assertEqual(proc.returncode, 0, proc.stderr)
                    reply = json.loads(proc.stdout)
                    self.assertTrue(reply['result']['isError'])
                    result = json.loads(reply['result']['content'][0]['text'])
                    self.assertEqual(result['error_stage'], 'preparation')
                    self.assertEqual(result['status'], 'TIMEOUT')
                    self.assertTrue(result['ssh_authenticated'])
                    self.assertIs(result['cli_ready'], False)
                    self.assertIs(result['command_sent'], False)
                    self.assertEqual(result['execution_state'], 'NOT_SENT')
                    self.assertEqual(result['data_state'], 'PARTIAL')
                    self.assertIn('bằng chứng', result['output'])
                    self.assertNotIn('loopback-only', reply['result']['content'][0]['text'])
                    self.assertNotIn('show interfaces terse', server.commands)
                    self.assertEqual(server.commands.count('set cli screen-width 511'), 1)
                    self.assertEqual(server.auth_attempts, 1)
                finally:
                    server.close()

    def test_dynamic_target_config_devices_and_optional_csv_over_stdio(self):
        for mode in ('dynamic', 'config', 'csv'):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as directory:
                folder = Path(directory)
                server = LocalSSHServer(self.key)
                try:
                    response = 'thiết bị thử nghiệm\nđường truyền'
                    question = 'Select maintenance slot (A/B):'
                    server.responses.update({'hostname': response,
                        'request maintenance': lambda channel: channel.sendall(question.encode('utf-8'))})
                    config = {'defaults': {'device_type': 'linux', 'port': server.port,
                        'username': 'tester', 'password': 'loopback-only', 'session_sweep_seconds': 0,
                        'conn_timeout': 3, 'auth_timeout': 3, 'banner_timeout': 3,
                        'alt_key_file': str(folder / 'custom_known_hosts'), 'alt_host_keys': True,
                        'autodetect_cache_file': str(folder / 'drivers.sqlite3')},
                        'devices': {} if mode == 'dynamic' else {'thiết-bị': {'host': '127.0.0.1'}}}
                    config_path = folder / 'config.json'
                    config_path.write_text(json.dumps(config, ensure_ascii=False), encoding='utf-8')
                    argv = [sys.executable, '-u', str(ROOT / 'mcp/bootstrap.py'), '--config', str(config_path)]
                    if mode == 'csv':
                        inventory = folder / 'devices.csv'
                        inventory.write_text('name,ip,netmiko_device_type\ncsv-device,127.0.0.1,linux\n', encoding='utf-8')
                        argv += ['--inventory-csv', str(inventory)]
                    target = '127.0.0.1' if mode == 'dynamic' else 'thiết-bị'
                    requests = [
                        {'id': 1, 'method': 'initialize', 'params': {'protocolVersion': '2025-06-18'}},
                        {'method': 'notifications/initialized'},
                        {'id': 2, 'method': 'tools/list'},
                        {'id': 3, 'method': 'ping'},
                        {'id': 4, 'method': 'tools/call', 'params': {'name': 'ssh_inventory', 'arguments': {}}},
                        {'id': 5, 'method': 'tools/call', 'params': {'name': 'ssh_status', 'arguments': {}}},
                        {'id': 6, 'method': 'tools/call', 'params': {'name': 'ssh_execute',
                            'arguments': {'target': target, 'command': 'hostname', 'read_timeout': 3}}},
                    ]
                    # A promptless configuration response is uncertain, even with timing enabled.
                    if mode == 'dynamic':
                        requests.append({'id': 7, 'method': 'tools/call', 'params': {'name': 'ssh_execute',
                            'arguments': {'target': target, 'command': 'request maintenance',
                                'use_timing': True, 'read_timeout': 1, 'save_output': True}}})
                    wire = ''.join(json.dumps({'jsonrpc': '2.0', **request}, ensure_ascii=False) + '\n' for request in requests)
                    env = dict(os.environ, NETWORK_MCP_DATA_DIR=str(folder / 'data'),
                               NETWORK_SSH_USER='tester', NETWORK_SSH_PASSWORD='loopback-only')
                    env.pop('NETWORK_MCP_CREDENTIALS_FILE', None)
                    proc = subprocess.run(argv, input=wire, capture_output=True, text=True,
                                          encoding='utf-8', env=env, timeout=45)
                    self.assertEqual(proc.returncode, 0, proc.stderr)
                    messages = [json.loads(line) for line in proc.stdout.splitlines()]
                    replies = {message['id']: message for message in messages}
                    self.assertEqual(len(messages), len(requests) - 1)
                    self.assertEqual(set(replies), {request['id'] for request in requests if 'id' in request})
                    self.assertTrue(all('result' in message and message['jsonrpc'] == '2.0' for message in messages))
                    self.assertEqual(replies[1]['result']['serverInfo']['version'], '1.9.1')
                    tools = replies[2]['result']['tools']
                    schema = [{'name': tool['name'], 'inputSchema': tool['inputSchema']} for tool in tools]
                    self.assertEqual(schema, json.loads((ROOT / 'tests/tool-schema-v1.json').read_text(encoding='utf-8')))
                    self.assertEqual(len(tools), 10)
                    self.assertEqual(replies[3]['result'], {})
                    def payload(rid):
                        return json.loads(replies[rid]['result']['content'][0]['text'])
                    inventory_text = replies[4]['result']['content'][0]['text']
                    if mode != 'dynamic': self.assertIn('thiết-bị', inventory_text)
                    if mode == 'csv': self.assertIn('csv-device', inventory_text)
                    self.assertEqual(payload(5)['version'], '1.9.1')
                    result = payload(6)
                    self.assertFalse(replies[6]['result']['isError'])
                    self.assertEqual(result['status'], 'SUCCESS')
                    self.assertIn(response, result['output'])
                    self.assertTrue((folder / 'custom_known_hosts').is_file())
                    self.assertTrue((folder / 'data' / 'outputs').is_dir())
                    if mode == 'dynamic':
                        result = payload(7)
                        self.assertTrue(replies[7]['result']['isError'])
                        self.assertEqual(result['execution_state'], 'UNCERTAIN')
                        self.assertEqual(result['status'], 'UNKNOWN')
                        self.assertFalse(result['output_complete'])
                        saved = folder / 'data' / 'outputs' / (result['output_id'] + '.txt')
                        self.assertIn(question, saved.read_text(encoding='utf-8'))
                        self.assertEqual(server.commands.count('request maintenance'), 1)
                finally:
                    server.close()


if __name__ == '__main__':
    unittest.main()
