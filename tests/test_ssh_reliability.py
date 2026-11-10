"""Regression tests: simulated failures plus real Netmiko SSH on loopback only."""
import concurrent.futures
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

import paramiko

MCP = (Path(__file__).resolve().parents[1] / 'mcp')
sys.path.insert(0, str(MCP))
import bootstrap
import collector_backend as backend
import scan


class FakeConnection:
    def __init__(self, replies):
        self.replies = iter(replies)
        self.sent = []
        self.closed = False

    def find_prompt(self): return 'router#'
    def is_alive(self): return not self.closed
    def disconnect(self): self.closed = True

    def send_command(self, command, **kwargs):
        self.sent.append((command, kwargs))
        return next(self.replies)

    send_command_timing = send_command


class CollectorTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def collector(self, conn=None, factory=None, profiles=None, devices=None):
        cfg = {'defaults': {'output_dir': self.tmp.name, 'session_sweep_seconds': 0,
                            'alt_key_file': str(Path(self.tmp.name) / 'known_hosts')},
               'devices': devices or {'test': {'host': '192.0.2.1', 'device_type': 'cisco_ios'}},
               'profiles': profiles or {}}
        c = backend.Collector(cfg, connect_factory=factory or (lambda **kw: conn))
        self.addCleanup(c.shutdown)
        return c

    def test_truncated_single_fails_and_disconnects(self):
        conn = FakeConnection(['show version\nPARTIAL'])
        result = self.collector(conn).execute('test', 'show version', save_output=True)
        self.assertFalse(result['ok'])
        self.assertFalse(result['output_complete'])
        self.assertTrue(conn.closed)
        self.assertIn('PARTIAL', (Path(self.tmp.name) / (result['output_id'] + '.txt')).read_text())

    def test_truncated_batch_stops_before_next_command(self):
        conn = FakeConnection(['show version\nPARTIAL', 'show clock\nrouter#'])
        with self.assertRaises(backend.BatchError) as caught:
            self.collector(conn).execute_many('test', ['show version', 'show clock'])
        self.assertEqual(len(conn.sent), 1)
        self.assertFalse(caught.exception.results[0]['ok'])
        self.assertTrue(conn.closed)

    def test_pager_and_confirm_never_become_success(self):
        for marker in ['--More--', '---(more 20%)---', '---- More ----', '[confirm]', '[Y/N]', '[yes/no]']:
            with self.subTest(marker=marker):
                conn = FakeConnection(['show version\n' + marker])
                result = self.collector(conn).execute('test', 'show version', expect_string='.*')
                self.assertFalse(result['ok'])
                self.assertFalse(result['output_complete'])

    def test_no_echo_complete_output_reuses_session(self):
        conn = FakeConnection(['Cisco IOS Software\nrouter#', '12:00\nrouter#'])
        opened = []
        c = self.collector(factory=lambda **kw: opened.append(kw) or conn)
        for command in ['show version', 'show clock']:
            result = c.execute('test', command)
            self.assertTrue(result['ok'])
            self.assertFalse(result['command_echo_verified'])
        self.assertEqual(len(opened), 1)
        self.assertTrue(all(not options['cmd_verify'] for _, options in conn.sent))

    def test_custom_expect_does_not_override_actual_prompt(self):
        conn = FakeConnection(['show version\nVersion: 1.2'])
        result = self.collector(conn).execute('test', 'show version', expect_string='Version:.*')
        self.assertFalse(result['ok'])
        self.assertFalse(result['output_complete'])

    def test_cli_error_is_not_success(self):
        conn = FakeConnection(['% Invalid input detected\nrouter#'])
        result = self.collector(conn).execute('test', 'show version')
        self.assertFalse(result['ok'])
        self.assertEqual(result['error_category'], 'cli_error')

    def test_complete_no_echo_cli_error_keeps_synchronized_session(self):
        conn = FakeConnection(['% Invalid command\nrouter#', 'version\nrouter#'])
        opened = []
        c = self.collector(factory=lambda **kw: opened.append(1) or conn)
        with self.assertRaises(backend.BatchError): c.execute_many('test', ['show version'])
        self.assertFalse(conn.closed)
        self.assertTrue(c.execute('test', 'show version')['ok'])
        self.assertEqual(len(opened), 1)

    def test_linux_diagnostic_errors_are_not_success(self):
        c = self.collector()
        for error in ['-bash: traceroute: command not found', 'sh: 1: ping: not found',
                      'ping: socket: Operation not permitted', 'ping: example.invalid: Name or service not known',
                      'Usage: ping [options] destination', '% Unrecognized host or address']:
            with self.subTest(error=error):
                result = c._result('test', 'ping example.invalid -c 5', error + '\nrouter#', 0, prompt_pattern=r'(?m)^router#$')
                self.assertFalse(result['ok'])
                self.assertEqual(result['error_category'], 'cli_error')

    def test_reader_preserves_partial_data_on_cancellation(self):
        class Channel:
            sent = False
            read = False
            def normalize_cmd(self, command): return command + '\n'
            def write_channel(self, command): self.sent = True
            def read_channel(self):
                if self.sent and not self.read:
                    self.read = True
                    return 'partial-data\n'
                return ''
        conn = Channel()
        def checkpoint():
            if conn.read: raise concurrent.futures.CancelledError('Request cancelled')
        output, failure = backend.read_cli_output(conn, 'show version', 1, r'(?m)^router#$', checkpoint)
        self.assertEqual(output, 'partial-data\n')
        self.assertEqual(failure['error_category'], 'cancelled')

    def test_large_output_is_retained_in_full(self):
        line = 'interface-statistics ' + 'x' * 100 + '\n'
        output = line * 10000 + 'router#'
        class Channel:
            sent = False
            def __init__(self): self.chunks = iter(output[i:i+32768] for i in range(0, len(output), 32768))
            def normalize_cmd(self, command): return command + '\n'
            def write_channel(self, command): self.sent = True
            def read_channel(self): return next(self.chunks, '') if self.sent else ''
        actual, failure = backend.read_cli_output(Channel(), 'show interfaces', 3, r'(?m)^router#$')
        self.assertIsNone(failure)
        self.assertEqual(actual, output)

    def test_auth_timeout_allows_next_connection(self):
        conn = FakeConnection(['version\nrouter#'])
        calls = []
        def factory(**kwargs):
            calls.append(1)
            if len(calls) == 1:
                raise paramiko.AuthenticationException('Authentication timeout')
            return conn
        c = self.collector(factory=factory)
        with self.assertRaises(paramiko.AuthenticationException) as caught:
            c.execute('test', 'show version')
        self.assertTrue(backend.classify_error(caught.exception)['retryable'])
        self.assertTrue(c.execute('test', 'show version')['ok'])
        self.assertEqual(len(calls), 2)

    def test_rejected_password_is_not_retried(self):
        calls = []
        def factory(**kwargs):
            calls.append(1)
            raise paramiko.AuthenticationException('Authentication failed')
        c = self.collector(factory=factory)
        for _ in range(2):
            with self.assertRaises((paramiko.AuthenticationException, PermissionError)):
                c.execute('test', 'show version')
        self.assertEqual(len(calls), 1)

    def test_scanner_retries_auth_timeout_once(self):
        calls = []
        def factory(**kwargs):
            calls.append(1)
            if len(calls) == 1:
                raise paramiko.AuthenticationException('Authentication timeout')
            return FakeConnection(['Cisco IOS Software\nrouter#'])
        c = self.collector(factory=factory)
        result = scan.run_scan(c, [{'target': 'test'}], Path(self.tmp.name) / 'scan', workers=2, slow_workers=1)
        self.assertEqual(result['success'], 1)
        self.assertEqual(len(calls), 2)
        records = list((Path(self.tmp.name) / 'scan' / 'results').glob('*.json'))
        record = json.loads(records[0].read_text())
        self.assertEqual([a['lane'] for a in record['attempts']], ['fast', 'slow'])

    def test_csv_profile_selects_matching_credentials(self):
        path = Path(self.tmp.name) / 'devices.csv'
        path.write_text('name,ip,netmiko_device_type,profile\na,192.0.2.1,cisco_ios,branch\n', encoding='utf-8')
        cfg = backend.load_inventory_csv({'profiles': {'branch': {'username': 'branch-user', 'password': 'local-test'}}}, str(path))
        cfg['defaults'] = {'output_dir': self.tmp.name, 'session_sweep_seconds': 0}
        c = backend.Collector(cfg, connect_factory=lambda **kw: None)
        self.addCleanup(c.shutdown)
        self.assertEqual(c._get_settings('a', None, None)['username'], 'branch-user')
        with self.assertRaises(ValueError): c._get_settings('a', None, 'missing')

    def test_changed_password_does_not_inherit_old_auth_cooldown(self):
        calls = []
        def factory(**params):
            calls.append(1)
            if params['password'] == 'wrong': raise paramiko.AuthenticationException('Authentication failed')
            return FakeConnection(['version\nrouter#'])
        c = self.collector(factory=factory, profiles={'default': {'username': 'tester', 'password': 'wrong'}})
        with self.assertRaises(paramiko.AuthenticationException): c.execute('test', 'show version')
        c.profiles['default']['password'] = 'correct'
        self.assertTrue(c.execute('test', 'show version')['ok'])
        self.assertEqual(len(calls), 2)

    def test_same_ip_different_profiles_keep_separate_sessions(self):
        calls = []
        def factory(**params):
            calls.append(params['username'])
            marker = 'scope=A' if params['username'] == 'alpha' else 'scope=B'
            return FakeConnection([marker + '\nrouter#'] * 3)
        devices = {name: {'host': '192.0.2.1', 'device_type': 'cisco_ios', 'profile': name} for name in ('one', 'two')}
        profiles = {'one': {'username': 'alpha', 'password': 'first'}, 'two': {'username': 'beta', 'password': 'second'}}
        c = self.collector(factory=factory, profiles=profiles, devices=devices)
        for target, marker in [('one', 'scope=A'), ('two', 'scope=B'), ('one', 'scope=A')]:
            result = c.execute(target, 'show version')
            self.assertTrue(result['ok'])
            self.assertIn(marker, result['output'])
        self.assertEqual(calls, ['alpha', 'beta'])

    def test_storage_quota_failure_is_not_ssh_success_or_retry(self):
        c = self.collector(FakeConnection(['version output\nrouter#']))
        c.output_quota = 1
        request = {'jsonrpc': '2.0', 'id': 1, 'method': 'tools/call',
                   'params': {'name': 'ssh_execute', 'arguments': {'target': 'test', 'command': 'show version', 'save_output': True}}}
        reply = backend.handle_rpc(request, c)
        self.assertTrue(reply['result']['isError'])
        result = json.loads(reply['result']['content'][0]['text'])
        self.assertFalse(result['ok'])
        self.assertEqual(result['error_category'], 'storage_error')
        self.assertFalse(result['retryable'])
        self.assertTrue(result['ssh_authenticated'])

    def test_duplicate_csv_profile_conflict_is_reported(self):
        path = Path(self.tmp.name) / 'devices.csv'
        path.write_text('name,ip,netmiko_device_type,profile\na,192.0.2.1,cisco_ios,one\na,192.0.2.1,cisco_ios,two\n')
        cfg = backend.load_inventory_csv({}, str(path))
        self.assertEqual(cfg['devices']['a']['profile'], 'one')
        self.assertIn('conflicts', cfg['inventory_warnings'][0])

    def test_bootstrap_does_not_require_global_password_for_profiles(self):
        with patch.dict(os.environ, {}, clear=True), patch.object(bootstrap, 'ROOT', Path(self.tmp.name)):
            self.assertFalse(bootstrap.prepare_environment())

    def test_mcp_unicode_inventory_round_trip_with_legacy_windows_encoding(self):
        alias = 'THIẾT-BỊ-01'
        config = Path(self.tmp.name) / 'config.json'
        config.write_text(json.dumps({'defaults': {'output_dir': self.tmp.name, 'session_sweep_seconds': 0},
                                      'devices': {alias: {'host': '192.0.2.1', 'device_type': 'cisco_ios'}}}), encoding='utf-8')
        request = {'jsonrpc': '2.0', 'id': 1, 'method': 'tools/call',
                   'params': {'name': 'ssh_inventory', 'arguments': {'query': alias}}}
        run = subprocess.run([sys.executable, str(MCP / 'collector_backend.py'), '--config', str(config)],
                             input=(json.dumps(request, ensure_ascii=False) + '\n').encode('utf-8'),
                             capture_output=True, timeout=10, env={**os.environ, 'PYTHONIOENCODING': 'cp1252'})
        self.assertEqual(run.returncode, 0)
        reply = json.loads(run.stdout.decode('utf-8'))
        self.assertFalse(reply['result']['isError'])
        self.assertIn(alias, reply['result']['content'][0]['text'])

    def test_noc_commands_and_finite_ping(self):
        for platform, commands in {
            'cisco_ios': ['ping 192.0.2.1', 'traceroute 192.0.2.1', 'show ntp associations', 'show mac address-table', 'show spanning-tree'],
            'juniper_junos': ['ping 192.0.2.1', 'show ntp associations', 'show security flow session', 'show route | match "error|CRC"'],
            'huawei': ['ping -c 5 192.0.2.1', 'tracert 192.0.2.1', 'display ntp-service status', 'display stp brief'],
            'linux': ['ping 192.0.2.1', 'traceroute 192.0.2.1', 'ip -s link show', 'ip route get 192.0.2.1', 'getent hosts example.com'],
        }.items():
            for command in commands:
                with self.subTest(platform=platform, command=command):
                    backend.readonly_command(command, platform)
        self.assertEqual(backend.prepare_noc_command('ping 192.0.2.1', 'juniper_junos'), 'ping 192.0.2.1 count 5')
        self.assertEqual(backend.prepare_noc_command('ping 192.0.2.1', 'linux'), 'ping 192.0.2.1 -c 5')
        for command in ['reload', 'show version; reload', 'show version | redirect flash:x', 'ping -f 192.0.2.1']:
            with self.assertRaises(PermissionError): backend.readonly_command(command, 'cisco_ios')
        with self.assertRaises(ValueError): backend.readonly_command('ping -c 100 192.0.2.1', 'linux')


class LocalSSHServer:
    """Minimal no-echo SSH CLI; binds only 127.0.0.1 and uses temporary keys."""
    def __init__(self, key, port=0):
        self.key = key
        self.prompt = 'router#'
        self.responses = {}
        self.banner_delay = 0
        self.auth_delay = 0
        self.stop = threading.Event()
        self.commands = []
        self.auth_attempts = 0
        self.transports = []
        self.listener = socket.socket()
        self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listener.bind(('127.0.0.1', port))
        self.port = self.listener.getsockname()[1]
        self.listener.listen(10)
        self.listener.settimeout(.1)
        self.thread = threading.Thread(target=self.accept, daemon=True)
        self.thread.start()

    def accept(self):
        while not self.stop.is_set():
            try: client, _ = self.listener.accept()
            except socket.timeout: continue
            except OSError: break
            threading.Thread(target=self.serve, args=(client,), daemon=True).start()

    def serve(self, client):
        shell = threading.Event()
        owner = self
        class Auth(paramiko.ServerInterface):
            def check_auth_password(self, username, password):
                owner.auth_attempts += 1
                time.sleep(owner.auth_delay)
                return paramiko.AUTH_SUCCESSFUL if (username, password) == ('tester', 'loopback-only') else paramiko.AUTH_FAILED
            def get_allowed_auths(self, username): return 'password'
            def check_channel_request(self, kind, chanid): return paramiko.OPEN_SUCCEEDED if kind == 'session' else paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED
            def check_channel_pty_request(self, *args): return True
            def check_channel_shell_request(self, channel): shell.set(); return True
        transport = paramiko.Transport(client)
        self.transports.append(transport)
        try:
            time.sleep(self.banner_delay)
            transport.add_server_key(self.key)
            transport.start_server(server=Auth())
            channel = transport.accept(5)
            if channel is None or not shell.wait(5): return
            channel.settimeout(.1)
            channel.sendall(self.prompt.encode())
            buffer, paging = '', False
            while not self.stop.is_set() and transport.is_active():
                try: data = channel.recv(4096).decode('utf-8')
                except socket.timeout: continue
                if not data: break
                data = data.replace('\x00', '')
                if paging and ' ' in data:
                    channel.sendall(b'\b\b\b\b\b\b\b\b        \b\b\b\b\b\b\b\b\r\nsecond-page\r\nrouter#')
                    paging = False
                    data = data.replace(' ', '', 1)
                buffer += data.replace('\r', '\n')
                while '\n' in buffer:
                    command, buffer = buffer.split('\n', 1)
                    command = command.strip()
                    if not command:
                        channel.sendall(('\r\n' + self.prompt).encode()); continue
                    self.commands.append(command)
                    if command in self.responses:
                        reply = self.responses[command]
                        if callable(reply): reply(channel)
                        else: channel.sendall((reply + '\r\n' + self.prompt).encode())
                    elif command.startswith(('terminal width ', 'terminal length ', 'screen-length ', 'set cli ')):
                        channel.sendall(('\r\n' + self.prompt).encode())
                    elif command == 'uname -s':
                        channel.sendall(b'Lin'); time.sleep(.03); channel.sendall(b'ux\r\nrouter#')
                    elif command == 'ip route show':
                        channel.sendall(b'first-page\r\n--More--'); paging = True
                    elif command == 'hostname': channel.sendall(b'partial-hostname\r\n')
                    elif command == 'date': channel.sendall(b'[confirm]')
                    elif command == 'uptime':
                        channel.sendall(b'up '); time.sleep(.2); channel.sendall(b'10 days\r\nrouter#')
                    elif command == 'exit': return
                    else: channel.sendall(('% Invalid input\r\n' + self.prompt).encode())
        except (OSError, EOFError, paramiko.SSHException):
            pass
        finally:
            transport.close()

    def close(self):
        self.stop.set()
        self.listener.close()
        for transport in self.transports: transport.close()
        self.thread.join(2)


class RealSSHTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.key = paramiko.RSAKey.generate(2048)

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.server = LocalSSHServer(self.key)
        self.addCleanup(self.server.close)
        self.hosts = Path(self.tmp.name) / 'known_hosts'

    def collector(self, dtype='linux', hosts=None):
        c = backend.Collector({'defaults': {'username': 'tester', 'password': 'loopback-only',
            'output_dir': self.tmp.name, 'session_sweep_seconds': 0, 'conn_timeout': 3, 'auth_timeout': 3,
            'banner_timeout': 3, 'autodetect_cache_file': str(Path(self.tmp.name)/'autodetect.sqlite3'), 'alt_key_file': str(hosts or self.hosts)},
            'devices': {'local': {'host': '127.0.0.1', 'port': self.server.port, 'device_type': dtype}}})
        self.addCleanup(c.shutdown)
        return c

    def test_real_no_echo_fragmented_delayed_paged_and_session_reuse(self):
        c = self.collector()
        result = c.execute_many('local', ['uname -s', 'uptime', 'ip route show'], read_timeout=3)
        self.assertTrue(result['ok'])
        self.assertTrue(all(r['output_complete'] for r in result['results']))
        self.assertTrue(all(not r['command_echo_verified'] for r in result['results']))
        self.assertIn('Linux', result['results'][0]['output'])
        self.assertIn('10 days', result['results'][1]['output'])
        self.assertIn('first-page', result['results'][2]['output'])
        self.assertIn('second-page', result['results'][2]['output'])
        self.assertTrue(c.execute('local', 'uname -s')['ok'])
        self.assertEqual(c.status()['connections_opened'], 1)
        self.assertEqual(self.server.commands.count('ip route show'), 1)
        keys = paramiko.HostKeys(str(self.hosts))
        self.assertTrue(keys.check(f'[127.0.0.1]:{self.server.port}', self.key))

    def test_real_timeout_retains_partial_output_and_stops_batch(self):
        c = self.collector()
        with self.assertRaises(backend.BatchError) as caught:
            c.execute_many('local', ['hostname', 'uname -s'], read_timeout=1, save_output=True)
        result = caught.exception.results[0]
        self.assertFalse(result['ok'])
        self.assertFalse(result['output_complete'])
        self.assertEqual(result['error_category'], 'read_timeout')
        self.assertIn('partial-hostname', (Path(self.tmp.name) / (result['output_id'] + '.txt')).read_text())
        self.assertNotIn('uname -s', self.server.commands)

    def test_real_confirmation_fails_without_sending_response(self):
        result = self.collector().execute('local', 'date', read_timeout=2)
        self.assertFalse(result['ok'])
        self.assertFalse(result['output_complete'])
        self.assertEqual(self.server.commands, ['date'])

    def test_real_detection_subprocess_without_echo_persists_key(self):
        c = self.collector('autodetect')
        self.assertTrue(c.execute('local', 'uname -s', read_timeout=3)['ok'])
        self.assertEqual(c.status()['autodetect_probes'], 1)
        self.assertIn('display version', self.server.commands)
        self.assertTrue(paramiko.HostKeys(str(self.hosts)).check(f'[127.0.0.1]:{self.server.port}', self.key))

    def test_unwritable_host_store_does_not_prevent_real_ssh(self):
        bad_path = Path(self.tmp.name) / 'file-is-not-directory'
        bad_path.write_text('occupied')
        result = self.collector(hosts=bad_path / 'known_hosts').execute('local', 'uname -s')
        self.assertTrue(result['ok'])
        self.assertTrue(result['warnings'])

    def test_changed_host_key_is_accepted_and_updated(self):
        old_key = paramiko.RSAKey.generate(2048)
        backend.persist_host_key(self.hosts, f'[127.0.0.1]:{self.server.port}', old_key)
        result = self.collector().execute('local', 'uname -s')
        self.assertTrue(result['ok'])
        self.assertTrue(paramiko.HostKeys(str(self.hosts)).check(f'[127.0.0.1]:{self.server.port}', self.key))

    def test_two_clients_keep_separate_host_stores(self):
        other = Path(self.tmp.name) / 'other_hosts'
        first = self.collector()
        second = self.collector(hosts=other)
        self.assertTrue(first.execute('local', 'uname -s')['ok'])
        self.assertTrue(second.execute('local', 'uname -s')['ok'])
        self.assertTrue(self.hosts.exists())
        self.assertTrue(other.exists())

    def test_concurrent_processes_merge_without_lost_keys(self):
        # Bulk writers get a 5s lock budget; SSH callbacks keep the fast 0.5s default.
        code = ('import sys; from types import SimpleNamespace; sys.path.insert(0,sys.argv[1]); '
                'from collector_backend import persist_host_key; '
                'persist_host_key(sys.argv[2],sys.argv[3],SimpleNamespace(get_name=lambda:"ssh-rsa",get_base64=lambda:sys.argv[4]),lock_timeout=5)')
        def write(index):
            return subprocess.run([sys.executable, '-c', code, str(MCP), str(self.hosts),
                                   f'host-{index}', self.key.get_base64()], capture_output=True, text=True, timeout=15)
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(write, range(8)))
        self.assertTrue(all(r.returncode == 0 for r in results), [r.stderr for r in results])
        keys = paramiko.HostKeys(str(self.hosts))
        self.assertEqual(len(keys), 8)
        self.assertTrue(all(keys.check(f'host-{i}', self.key) for i in range(8)))

    def test_real_vendor_preparation_without_echo(self):
        vendors = [('cisco_ios', 'router#', 'show version', 'Cisco IOS Software'),
                   ('cisco_xr', 'RP/0/RP0/CPU0:router#', 'show version', 'Cisco IOS XR'),
                   ('cisco_nxos', 'router#', 'show version', 'Cisco Nexus NX-OS'),
                   ('huawei', '<router>', 'display version', 'Huawei VRP Software'),
                   ('juniper_junos', 'noc@router>', 'show version', 'Junos: 23.4R1')]
        for dtype, prompt, command, response in vendors:
            with self.subTest(driver=dtype):
                self.server.close()
                self.server = LocalSSHServer(self.key)
                self.addCleanup(self.server.close)
                self.server.prompt = prompt
                self.server.responses[command] = response
                c = self.collector(dtype)
                result = c.execute('local', command, read_timeout=3)
                self.assertTrue(result['ok'])
                self.assertIn(response, result['output'])
                self.assertFalse(result['command_echo_verified'])
                c.shutdown()

    def test_real_closed_channel_preserves_partial_and_fails_fast(self):
        c = self.collector()
        self.assertTrue(c.execute('local', 'uname -s')['ok'])
        def close_midway(channel):
            channel.sendall(b'partial-before-disconnect\r\n')
            channel.close()
        self.server.responses['hostname'] = close_midway
        started = time.monotonic()
        result = c.execute('local', 'hostname', read_timeout=10)
        self.assertFalse(result['ok'])
        self.assertFalse(result['transport_ok'])
        self.assertEqual(result['error_category'], 'connection_lost')
        self.assertIn('partial-before-disconnect', result['output'])
        self.assertLess(time.monotonic() - started, 3)

    def test_real_slow_banner_can_retry_with_larger_handshake_budget(self):
        self.server.banner_delay = 1.5
        c = self.collector()
        with c.request_budget(connection_timeouts={'conn_timeout': .3, 'banner_timeout': 3, 'auth_timeout': 3}):
            with self.assertRaises(Exception) as caught: c.execute('local', 'uname -s')
        details = backend.classify_error(caught.exception, 'connect')
        self.assertIn(details['error_category'], {'handshake_incomplete', 'banner_timeout', 'connection_lost'})
        self.assertTrue(details['retryable'])
        with c.request_budget(connection_timeouts={'conn_timeout': 3, 'banner_timeout': 3, 'auth_timeout': 3}):
            self.assertTrue(c.execute('local', 'uname -s')['ok'])

    def test_real_auth_timeout_does_not_suppress_next_login(self):
        self.server.auth_delay = .7
        c = self.collector()
        with c.request_budget(connection_timeouts={'conn_timeout': 3, 'banner_timeout': 3, 'auth_timeout': .2}):
            with self.assertRaises(Exception) as caught: c.execute('local', 'uname -s')
        self.assertEqual(backend.classify_error(caught.exception)['error_category'], 'auth_timeout')
        self.server.auth_delay = 0
        self.assertTrue(c.execute('local', 'uname -s')['ok'])


if __name__ == '__main__': unittest.main()
