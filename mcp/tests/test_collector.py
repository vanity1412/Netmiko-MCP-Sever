"""Offline regression: no real targets, credentials or device writes."""
import concurrent.futures
import importlib.util
import io
import os
import json
from pathlib import Path
import tempfile
import threading
import time
import unittest
import socket
from unittest.mock import patch

BACKEND = Path(os.environ.get('NETMIKO_TEST_BACKEND') or Path(__file__).resolve().parents[1] / 'collector_backend.py')
spec = importlib.util.spec_from_file_location('tested_collector', BACKEND)
b = importlib.util.module_from_spec(spec)
spec.loader.exec_module(b)


class Fake:
    device_type = 'juniper_junos'
    def __init__(self): self.commands = []; self.alive = True
    def find_prompt(self): return 'MOCK>'
    def is_alive(self): return self.alive
    def disconnect(self): self.alive = False
    def send_command(self, command, **kwargs):
        self.commands.append(command)
        if command == 'show system bad': return command + '\n% Authorization failed.\nMOCK>'
        if command == 'show system partial': return command + '\nPARTIAL'
        if command == 'show system confirm': return command + '\n[yes/no]'
        if command == 'show system slow': time.sleep(.15)
        return command + '\nMOCK DATA\nMOCK>'
    send_command_timing = send_command


class Regression(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.connections = []
        self.params = []
        def connect(**params):
            self.params.append(params)
            f = Fake(); self.connections.append(f); return f
        self.c = b.Collector({'defaults': {'device_type': 'juniper_junos', 'ssh_strict': False, 'output_dir': self.temp.name, 'session_sweep_seconds': 0}, 'devices': {'MOCK': {'host': 'mock-host', 'device_type': 'juniper_junos'}}}, connect_factory=connect)
    def tearDown(self): self.c.shutdown(); self.temp.cleanup()

    def test_tools_unchanged(self):
        self.assertEqual(len(b.make_tool_list()), 10)

    def test_readonly_positive(self):
        for platform, command in [('juniper_junos', 'show configuration | display set | no-more'), ('cisco_ios', 'show ip route | include 10.0'), ('huawei', 'display interface brief'), ('linux', 'ip route show')]:
            with self.subTest(platform=platform): self.assertEqual(b.readonly_command(command, platform), command)

    def test_readonly_negative(self):
        for platform in ['juniper_junos', 'cisco_ios', 'huawei', 'linux', 'generic_termserver']:
            for command in ['configure', 'erase startup-config', 'show version; reboot', 'show version | save x', 'show version > x', 'show version\nconfigure', 'show version && id', 'show version `id`', 'show version | tee x', 'show version |', 'show version || reboot', 'sh version', 'cat /etc/shadow', 'show tech-support', 'show version | append x']:
                with self.subTest(platform=platform, command=command), self.assertRaises((PermissionError, ValueError)):
                    b.readonly_command(command, platform)

    def test_denied_before_ssh(self):
        with self.assertRaises(PermissionError): self.c.execute('MOCK', 'configure')
        self.assertFalse(self.connections)

    def test_batch_prevalidates_all(self):
        with self.assertRaises(PermissionError): self.c.execute_many('MOCK', ['show version', 'configure'])
        self.assertFalse(self.connections)

    def test_hostkey_permissive_collector_policy(self):
        self.c.execute('MOCK', 'show version')
        self.assertIs(self.params[0]['ssh_strict'], False)

    def test_explicit_upstream_strict_rejects_before_auth(self):
        import paramiko
        from netmiko import ConnectHandler
        server_key = paramiko.RSAKey.generate(2048)
        wrong_key = paramiko.RSAKey.generate(2048)
        for changed in [False, True]:
            with self.subTest(changed=changed):
                listener = socket.socket(); listener.bind(('127.0.0.1',0)); listener.listen(1)
                port = listener.getsockname()[1]
                hostfile = Path(self.temp.name) / 'known_hosts'
                keys = paramiko.HostKeys()
                if changed: keys.add(f'[127.0.0.1]:{port}',wrong_key.get_name(),wrong_key)
                keys.save(str(hostfile))
                auth = []
                class Server(paramiko.ServerInterface):
                    def check_auth_password(self, username, password):
                        auth.append(True); return paramiko.AUTH_FAILED
                def serve():
                    transport = None
                    try:
                        listener.settimeout(5)
                        sock, _ = listener.accept()
                        transport = paramiko.Transport(sock); transport.add_server_key(server_key)
                        transport.start_server(server=Server())
                        transport.join(2)
                    except (EOFError, OSError, paramiko.SSHException): pass
                    finally:
                        if transport: transport.close()
                        listener.close()
                thread = threading.Thread(target=serve); thread.start()
                params = self.c._get_settings('127.0.0.1','cisco_ios',None)
                params.update(ssh_strict=True,port=port,username='MOCK',password='MOCK',system_host_keys=False,alt_host_keys=True,alt_key_file=str(hostfile),conn_timeout=2,auth_timeout=2,banner_timeout=2)
                try:
                    with self.assertRaises((paramiko.SSHException, paramiko.BadHostKeyException)):
                        ConnectHandler(**params)
                finally: thread.join(6)
                self.assertFalse(auth, 'Host key must be checked before any authentication')

    def test_redaction_vendor(self):
        samples = ['username alice secret 9 HASHVALUE', 'password 7 HASHVALUE', 'local-user alice password irreversible-cipher HASHVALUE', 'set system login user alice authentication encrypted-password "HASHVALUE"', 'snmp-server community HASHVALUE RO', 'snmp-agent usm-user v3 alice authentication-mode sha HASHVALUE', 'snmp-server user alice auth sha HASHVALUE priv aes HASHVALUE', 'Authorization: Bearer HASHVALUE', '{"password":"HASHVALUE"}', 'https://alice:HASHVALUE@example.net']
        for sample in samples:
            with self.subTest(sample=sample): self.assertNotIn('HASHVALUE', b.redact_text(sample))

    def test_login_redaction(self):
        self.assertNotIn('alice', b.redact_text('set system login user alice authentication encrypted-password "x"'))

    def test_structured_redaction_keeps_types(self):
        result = b.redact_data({'password':123, 'rows':[{'description':'password 9 HASHVALUE','count':4}]})
        self.assertEqual(result['password'],'[redacted]')
        self.assertEqual(result['rows'][0]['count'],4)
        self.assertNotIn('HASHVALUE',json.dumps(result))
        self.c.profiles['mock'] = {'password':'KNOWNVALUE'}
        self.assertEqual(self.c.redact_structured({'data':'KNOWNVALUE','count':2}),{'data':'[redacted]','count':2})

    def test_additional_key_formats(self):
        for sample in ['radius-server key 7 HASHVALUE','key-string HASHVALUE','set protocols bgp group MOCK authentication-key HASHVALUE','Last configured: yesterday by alice']:
            result = b.redact_text(sample)
            self.assertNotIn('HASHVALUE',result)
            self.assertNotIn('alice',result)

    def test_concurrent_parallel_calls_share_worker_limit(self):
        self.c.max_workers = 2
        self.c._task_pool.shutdown()
        self.c._task_pool = concurrent.futures.ThreadPoolExecutor(max_workers=2)
        guard = threading.Lock(); counts = {'active':0,'max':0}
        def fake_execute(**kw):
            with guard:
                counts['active'] += 1; counts['max'] = max(counts['max'],counts['active'])
            time.sleep(.03)
            with guard: counts['active'] -= 1
            return {'ok':True}
        self.c.execute = fake_execute
        tasks = [{'target':str(i),'command':'show version'} for i in range(4)]
        with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
            results = list(pool.map(lambda _:self.c.parallel(tasks),range(3)))
        self.assertTrue(all(r['ok'] for r in results)); self.assertLessEqual(counts['max'],2)

    def test_redaction_save_error_audit(self):
        self.c.profiles['mock'] = {'password': 'SYNTHETICVALUE'}
        self.assertNotIn('SYNTHETICVALUE', self.c.scrub_error('failure SYNTHETICVALUE'))
        oid = self.c._save_output('username alice secret 9 HASHVALUE')
        self.assertNotIn('HASHVALUE', self.c.read_output(oid)['text'])
        self.c.audit('ssh_execute', {'target':'MOCK','command':'username alice secret 9 HASHVALUE'}, False, 0)
        self.assertNotIn('HASHVALUE', self.c._audit_path.read_text())

    def test_cli_errors(self):
        for error in ['% Authorization failed.', 'syntax error.', 'invalid command', 'permission denied', 'Error: Wrong parameter', '% Command authorization failed.', 'Access denied', 'Insufficient privilege']:
            with self.subTest(error=error):
                r = self.c._result('MOCK','show version','show version\n'+error+'\nMOCK>',0)
                self.assertFalse(r['ok']); self.assertTrue(r['transport_ok']); self.assertFalse(r['cli_ok']); self.assertTrue(r['output_complete'])

    def test_incomplete_and_echo(self):
        for text in ['show version\nPARTIAL', 'show version\n--More--']:
            self.assertFalse(self.c._result('MOCK','show version',text,0)['ok'])

    def test_custom_expect_cannot_accept_confirmation(self):
        r = self.c.execute('MOCK', 'show system confirm', expect_string=r'\[yes/no\]')
        self.assertFalse(r['ok']); self.assertFalse(self.connections[0].alive)

    def test_interact_stops_on_failure(self):
        for bad in ['show system bad', 'show system partial', 'show system confirm']:
            r = self.c.interact('MOCK', ['show version', bad, 'show interfaces'])
            self.assertFalse(r['ok']); self.assertEqual(len(r['steps']), 2)
            self.assertNotIn('show interfaces', self.connections[-1].commands)

    def test_interact_rejects_blind_confirmations(self):
        for response in ['yes', '', '\n', 'configure']:
            with self.assertRaises((ValueError, PermissionError)):
                self.c.interact('MOCK', ['show version', response])
        self.assertFalse(self.connections)

    def test_interact_success(self):
        self.assertTrue(self.c.interact('MOCK', ['show version', 'show interfaces'])['ok'])

    def test_pool_alias_reuse(self):
        self.c.execute('MOCK','show version'); self.c.execute('mock-host','show version')
        self.assertEqual(len(self.connections),1); self.assertEqual(self.c.status()['session_reuses'],1)

    def test_batch_stops(self):
        with self.assertRaises(b.BatchError) as err:
            self.c.execute_many('MOCK',['show version','show system bad','show interfaces'])
        self.assertEqual(len(err.exception.results),2)
        self.assertNotIn('show interfaces', self.connections[-1].commands)

    def test_parallel_partial(self):
        r = self.c.parallel([{'target':'MOCK','command':'show version'}, {'target':'other','command':'show system bad'}])
        self.assertFalse(r['ok']); self.assertTrue(r['partial_failure'])

    def test_cancellation_before_send(self):
        event = threading.Event(); event.set()
        self.c._request.context = (event, time.monotonic()+5)
        with self.assertRaises(concurrent.futures.CancelledError): self.c.execute('MOCK','show version')
        self.assertFalse(self.connections)

    def test_deadline_waiting_for_lease(self):
        self.c.execute('MOCK','show version')
        entry = next(iter(self.c._sessions.values()))
        done = []
        def worker():
            self.c._request.context = (threading.Event(),time.monotonic()+.05)
            try: self.c.execute('MOCK','show version')
            except TimeoutError: done.append(True)
        with entry['lock']:
            t = threading.Thread(target=worker); t.start(); t.join(1)
        self.assertEqual(done,[True])

    def test_utf8_and_traversal(self):
        oid = self.c._save_output('Đường truyền\n'*100)
        offset = 0; text = ''
        while True:
            r = self.c.read_output_bytes(oid,offset,7); text += r['text']; offset = r['next_byte_offset']
            if not r['more']: break
        self.assertEqual(text,'Đường truyền\n'*100)
        with self.assertRaises(ValueError): self.c.read_output('../escape')

    def test_stdio_slow_does_not_block_ping(self):
        requests = [{'jsonrpc':'2.0','id':1,'method':'tools/call','params':{'name':'ssh_execute','arguments':{'target':'MOCK','command':'show system slow'}}}, {'jsonrpc':'2.0','id':2,'method':'ping'}]
        output = io.StringIO()
        with patch('sys.stdin',io.StringIO('\n'.join(map(json.dumps,requests)))), patch('sys.stdout',output):
            b.run_stdio(self.c)
        replies = list(map(json.loads,output.getvalue().splitlines()))
        self.assertEqual([r['id'] for r in replies],[2,1])

    def test_stdio_cancel_stops_batch(self):
        event_sent = threading.Event()
        fake = Fake()
        original = fake.send_command
        def send(command, **kwargs):
            event_sent.set()
            return original(command,**kwargs)
        fake.send_command = send
        self.c._connect = lambda **kw: fake
        request = {'jsonrpc':'2.0','id':1,'method':'tools/call','params':{'name':'ssh_execute_many','arguments':{'target':'MOCK','commands':['show system slow','show interfaces']}}}
        class Input:
            def __iter__(self):
                yield json.dumps(request)
                self_wait = event_sent.wait(2)
                if not self_wait: raise AssertionError('worker did not start')
                yield json.dumps({'jsonrpc':'2.0','method':'notifications/cancelled','params':{'requestId':1}})
        output = io.StringIO()
        with patch('sys.stdin',Input()), patch('sys.stdout',output): b.run_stdio(self.c)
        self.assertNotIn('show interfaces',fake.commands)
        self.assertTrue(json.loads(output.getvalue())['result']['isError'])


if __name__ == '__main__': unittest.main()
