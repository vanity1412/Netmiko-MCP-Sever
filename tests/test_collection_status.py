import hashlib
import json
from pathlib import Path
import sys
import tempfile
import time
import subprocess
from types import SimpleNamespace
import unittest
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'mcp'))
import collector_backend as b
from result_status import normalize_result
from netmiko.exceptions import ReadTimeout, NetmikoAuthenticationException
import test_ssh_reliability as fixtures
import probe_session
from test_ssh_scenarios import VirtualClock, TimelineChannel

class StatusTests(unittest.TestCase):
    def test_fault_status_vocabulary_and_partial_data(self):
        for category,status in [('authentication','AUTH_ERROR'),('connection_lost','CONNECT_ERROR'),
              ('cli_error','CLI_ERROR'),('parsing_error','PARSE_ERROR'),('read_timeout','TIMEOUT'),
              ('storage_error','STORAGE_ERROR'),('cancelled','CANCELLED')]:
            with self.subTest(category=category):
                r=normalize_result({'ok':False,'error_category':category,'output_complete':False,'output':'partial'})
                self.assertEqual(r['status'],status);self.assertEqual(r['data_state'],'PARTIAL')
    def test_mutation_timeout_is_unknown_not_safe_to_repeat(self):
        r=normalize_result({'ok':False,'error_category':'read_timeout','command_sent':True,
                            'replay_safe':False,'output_complete':False})
        self.assertEqual(r['status'],'UNKNOWN');self.assertEqual(r['fault_status'],'TIMEOUT')
        self.assertEqual(r['execution_state'],'UNCERTAIN')
    def test_aggregate_exposes_pending_question(self):
        r=normalize_result({'ok':False,'results':[{'ok':True},{'ok':False,'awaiting_input':True}]})
        self.assertEqual(r['status'],'AWAITING_INPUT')
    def test_completed_interaction_does_not_stay_pending(self):
        r=normalize_result({'ok':True,'steps':[{'ok':False,'awaiting_input':True},{'ok':True}]})
        self.assertEqual(r['status'],'SUCCESS')
    def test_spool_spills_without_dropping_unicode(self):
        buffer=b.OutputBuffer();self.addCleanup(buffer.close)
        content='đường truyền\n'*150000
        buffer.append(content)
        self.assertTrue(buffer.file._rolled)
        self.assertEqual(buffer.value(),content)
    def test_bounded_receiver_retains_decoded_chunk_at_cancellation(self):
        script='''import json,sys,time
sys.stdin.readline()
print(json.dumps({'device_type':'linux','prompt':'router#'}),flush=True)
sys.stdin.readline()
for i in range(100):
 print(json.dumps({'event':'data','data':'chunk-%03d\\n'%i}),flush=True)
time.sleep(60)
'''
        spawn=subprocess.Popen
        with patch.object(probe_session.subprocess,'Popen',lambda *a,**kw:spawn([sys.executable,'-u','-c',script],**kw)):
            proxy=probe_session.ProbeSession({},lambda:None,3)
        self.addCleanup(proxy.close)
        append=b.OutputBuffer.append
        def slow(buffer,data):time.sleep(.02);append(buffer,data)
        with patch.object(b.OutputBuffer,'append',slow):
            output,failure=proxy.collect_in_worker('hostname',.05,'router#$',.03,lambda:None)
        self.assertIsNotNone(failure)
        self.assertIn('chunk-000',output)
        if proxy._interrupted_message:
            self.assertIn(proxy._interrupted_message['data'],output)
    def test_new_pager_footer_variants(self):
        for marker in ['Press any key to continue (Q to quit)','--More-- or (q)uit']:
            clock=VirtualClock();conn=TimelineChannel(clock,[(0,'first\n'+marker,True),(.1,'\nlast\nrouter#')])
            with patch.object(b,'time',SimpleNamespace(monotonic=clock.now,sleep=clock.sleep)):
                output,failure=b.read_cli_output(conn,'show version',1,r'(?m)^router#$')
            self.assertIsNone(failure);self.assertIn('last',output);self.assertEqual(conn.writes.count(' '),1)
            self.assertNotIn(marker,output)

class CacheTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.opens=[];self.probes=[];self.bad_driver=True
        owner=self
        class Connection:
            def __init__(self,driver):self.device_type=driver;self.closed=False
            def find_prompt(self):return 'router#'
            def is_alive(self):return not self.closed
            def disconnect(self):self.closed=True
            def send_command(self,*a,**k):return 'version data\nrouter#'
        def factory(**params):
            self.opens.append(params['device_type'])
            if params['device_type']=='cisco_ios' and self.bad_driver:
                raise ReadTimeout('simulated preparation mismatch')
            return Connection(params['device_type'])
        self.c=b.Collector({'defaults':{'execution_policy': 'read_write', 'device_type':'autodetect','output_dir':self.tmp.name,
             'session_sweep_seconds':0,'max_workers':1,
             'autodetect_cache_file':str(Path(self.tmp.name)/'drivers.sqlite3')}},connect_factory=factory)
        self.addCleanup(self.c.shutdown)
        class Detector:
            def autodetect(self):owner.probes.append(1);return 'juniper_junos'
        self.c._custom_detect=lambda **k:Detector()
    def seed(self):
        params=self.c._get_settings('192.0.2.1',None,None)
        self.c._disk_detection(params,'cisco_ios')
        return params
    def test_stale_disk_driver_refreshes_once_without_semaphore_deadlock(self):
        self.seed();r=self.c.execute('192.0.2.1','show version')
        self.assertTrue(r['ok']);self.assertTrue(r['driver_refreshed'])
        self.assertEqual(self.opens,['cisco_ios','juniper_junos']);self.assertEqual(len(self.probes),1)
    def test_auth_failure_does_not_invalidate_or_probe(self):
        params=self.seed()
        self.c._connect=lambda **k:(_ for _ in ()).throw(NetmikoAuthenticationException('Authentication failed'))
        with self.assertRaises(NetmikoAuthenticationException):self.c.execute('192.0.2.1','show version')
        self.assertFalse(self.probes);self.assertEqual(self.c._disk_detection(params)[0],'cisco_ios')
    def test_network_failure_does_not_invalidate_or_probe(self):
        params=self.seed()
        self.c._connect=lambda **k:(_ for _ in ()).throw(ConnectionRefusedError('fixture'))
        with self.assertRaises(ConnectionRefusedError):self.c.execute('192.0.2.1','show version')
        self.assertFalse(self.probes);self.assertEqual(self.c._disk_detection(params)[0],'cisco_ios')
    def test_explicit_driver_never_switches_on_preparation_failure(self):
        with self.assertRaises(ReadTimeout):self.c.execute('192.0.2.1','show version',device_type='cisco_ios')
        self.assertFalse(self.probes)
    def test_active_session_wins_over_expired_or_missing_cache(self):
        self.c.execute('192.0.2.1','show version')
        params=self.c._get_settings('192.0.2.1',None,None)
        self.c._detect_cache.clear();self.c._disk_detection(params,invalidate=True)
        self.assertTrue(self.c.execute('192.0.2.1','show version')['ok'])
        self.assertEqual(len(self.opens),1);self.assertEqual(len(self.probes),1)
    def test_dead_session_status_and_reopen_without_reprobe(self):
        self.c.execute('192.0.2.1','show version')
        conn=next(iter(self.c._sessions.values()))['conn'];conn.closed=True
        self.assertFalse(self.c.status()['sessions'][0]['connected'])
        self.assertTrue(self.c.execute('192.0.2.1','show version')['ok'])
        self.assertEqual(len(self.opens),2);self.assertEqual(len(self.probes),1)
    def test_bad_refresh_is_not_repeated(self):
        self.seed()
        def fail(**params):self.opens.append(params['device_type']);raise ReadTimeout('fixture prep')
        self.c._connect=fail
        with self.assertRaises(ReadTimeout):self.c.execute('192.0.2.1','show version')
        self.assertEqual(len(self.opens),2);self.assertEqual(len(self.probes),1)
    def test_locked_invalidation_still_bypasses_stale_disk_entry(self):
        self.seed();original=self.c._disk_detection
        def locked(params,driver=None,invalidate=False):
            if invalidate:return None
            return original(params,driver)
        with patch.object(self.c,'_disk_detection',locked):
            self.assertTrue(self.c.execute('192.0.2.1','show version')['ok'])
        self.assertEqual(self.opens,['cisco_ios','juniper_junos'])
        self.assertEqual(len(self.probes),1)
    def test_configuration_log_error_is_data_but_first_error_is_not(self):
        for driver,cmd in [('cisco_ios','show running-config'),('juniper_junos','show configuration'),
                           ('huawei','display current-configuration')]:
            r=self.c._result('a',cmd,'configuration header\nError: historical log\nrouter#',0,device_type=driver)
            self.assertTrue(r['ok'],r)
            r=self.c._result('a',cmd,'Error: permission denied\nrouter#',0,device_type=driver)
            self.assertEqual(r['status'],'CLI_ERROR')
    def test_junos_rpc_error_is_cli_error(self):
        r=self.c._result('a','show interfaces | display xml',
            '<rpc-reply><rpc-error><error-severity>error</error-severity></rpc-error></rpc-reply>\nrouter#',0,
            device_type='juniper_junos')
        self.assertEqual(r['status'],'CLI_ERROR')
    def test_storage_error_after_uncertain_write_does_not_claim_transport_ok(self):
        self.bad_driver=False
        def send(conn,command,*a,**kw):
            conn._network_command_sent=True
            conn._network_read_failure={'error':'EOFError','error_category':'connection_lost','error_stage':'command'}
            return 'partial\nrouter#',conn._network_prompt_regex
        with patch.object(self.c,'_send',send),patch.object(self.c,'_save_output',side_effect=OSError('fixture disk full')):
            with self.assertRaises(OSError) as caught:
                self.c.execute('192.0.2.1','configure terminal',device_type='cisco_ios',save_output=True)
        r=self.c.failure_result(caught.exception,'192.0.2.1','configure terminal')
        self.assertFalse(r['transport_ok']);self.assertFalse(r['output_complete'])
        self.assertEqual(r['status'],'UNKNOWN');self.assertEqual(r['fault_status'],'STORAGE_ERROR')
        self.assertEqual(r['execution_state'],'UNCERTAIN')
    def test_failed_reconnect_preserves_first_partial_response(self):
        first={'ok':False,'error_category':'connection_lost','output_complete':False,
               'output':'first partial','command_sent':True,'replay_safe':True,
               '_replay_context': ('juniper_junos', 'noc@router>')}
        with patch.object(self.c,'_execute_once',side_effect=[first,NetmikoAuthenticationException('Authentication failed')]):
            r=self.c.execute('192.0.2.1','show version')
        self.assertEqual(r['status'],'AUTH_ERROR')
        self.assertEqual(r['previous_attempt']['output'],'first partial')
    def test_budget_before_reconnect_retains_partial_and_does_not_replay(self):
        first={'ok':False,'error_category':'connection_lost','output_complete':False,
               'output':'first partial','command_sent':True,'replay_safe':True,
               '_replay_context': ('juniper_junos', 'noc@router>')}
        with patch.object(self.c,'_execute_once',return_value=first) as execute, \
             patch.object(self.c,'_checkpoint',side_effect=[120,TimeoutError('Request deadline exceeded')]):
            r=self.c.execute('192.0.2.1','show version')
        self.assertEqual(r['status'],'TIMEOUT');self.assertEqual(r['output'],'first partial')
        self.assertEqual(execute.call_count,1)

    def test_pre_send_recovery_keeps_profile_and_host_key_settings(self):
        self.c.profiles['noc'] = {
            'username': 'fixture-noc', 'password': 'fixture-only',
            'port': 2222, 'ssh_mode': 'strict',
            'alt_key_file': str(Path(self.tmp.name, 'known_hosts')),
        }
        connect = self.c._connect
        attempts = []

        def open_session(**params):
            attempts.append(params)
            if len(attempts) == 1:
                raise TimeoutError('fixture TCP timeout')
            return connect(**params)

        with patch.object(self.c, '_connect', open_session):
            result = self.c.execute('192.0.2.1', 'show version',
                                    device_type='juniper_junos', profile='noc')
        self.assertTrue(result['ok'])
        self.assertEqual(len(attempts), 2)
        expected = {'host': '192.0.2.1', 'port': 2222, 'username': 'fixture-noc',
                    'device_type': 'juniper_junos', 'ssh_strict': True,
                    'alt_key_file': self.c.profiles['noc']['alt_key_file']}
        for attempt in attempts:
            self.assertEqual({key: attempt[key] for key in expected}, expected)

        self.c.audit('ssh_execute', {'target': '192.0.2.1', 'command': 'show version'},
                     True, 0, result=result)
        raw = Path(self.tmp.name, 'collector_audit.jsonl').read_text(encoding='utf-8')
        audit = json.loads(raw.splitlines()[-1])
        self.assertEqual(audit['recovery_attempts'], 1)
        self.assertEqual(audit['previous_error_category'], 'connect_timeout')
        self.assertEqual(audit['previous_error_stage'], 'tcp')
        self.assertNotIn('fixture-only', raw)

    def test_pre_send_recovery_shares_single_attempt_with_read_recovery(self):
        first = b.CollectionError({'error_category': 'banner_timeout',
                                   'error_stage': 'banner', 'retryable': True})
        second = {'ok': False, 'error_category': 'connection_lost',
                  'command_sent': True, 'output_complete': False, 'output': 'partial'}
        with patch.object(self.c, '_execute_once', side_effect=[first, second]) as execute:
            result = self.c.execute('192.0.2.1', 'show version')
        self.assertEqual(execute.call_count, 2)
        self.assertEqual(result['recovery_attempts'], 1)
        self.assertEqual(result['output'], 'partial')
        self.assertIs(result['previous_attempt']['command_sent'], False)

    def test_pre_send_recovery_retains_first_failure_if_second_connection_fails(self):
        first = b.CollectionError({'error_category': 'handshake_incomplete',
                                   'error_stage': 'key_exchange', 'retryable': True})
        second = NetmikoAuthenticationException('Authentication failed')
        with patch.object(self.c, '_execute_once', side_effect=[first, second]) as execute:
            with self.assertRaises(NetmikoAuthenticationException) as caught:
                self.c.execute('192.0.2.1', 'show version')
        self.assertEqual(execute.call_count, 2)
        result = self.c.failure_result(caught.exception, '192.0.2.1', 'show version')
        self.assertEqual(result['status'], 'AUTH_ERROR')
        self.assertEqual(result['recovery_attempts'], 1)
        self.assertEqual(result['previous_attempt']['error_category'], 'handshake_incomplete')

    def test_pre_send_recovery_excludes_other_failures_and_mutations(self):
        for category, stage, command in (
            ('host_key_changed', 'host_key', 'show version'),
            ('auth_timeout', 'authentication', 'show version'),
            ('read_timeout', 'preparation', 'show version'),
            ('banner_timeout', 'banner', 'configure terminal'),
        ):
            with self.subTest(category=category, command=command):
                failure = b.CollectionError({'error_category': category,
                                             'error_stage': stage, 'retryable': True})
                with patch.object(self.c, '_execute_once', side_effect=failure) as execute:
                    with self.assertRaises(b.CollectionError):
                        self.c.execute('192.0.2.1', command)
                self.assertEqual(execute.call_count, 1)

    def test_pre_send_recovery_does_not_open_again_after_deadline(self):
        first = b.CollectionError({'error_category': 'banner_timeout',
                                   'error_stage': 'banner', 'retryable': True})
        with patch.object(self.c, '_execute_once', side_effect=first) as execute, \
             patch.object(self.c, '_checkpoint', side_effect=[120, TimeoutError('Request deadline exceeded')]):
            result = self.c.execute('192.0.2.1', 'show version')
        self.assertEqual(execute.call_count, 1)
        self.assertEqual(result['error_category'], 'deadline')
        self.assertEqual(result['error_reason'], 'request_deadline')
        self.assertEqual(result['previous_error_category'], 'banner_timeout')
        self.assertIs(result['command_sent'], False)

class RealRecoveryTests(unittest.TestCase):
    setUpClass=classmethod(fixtures.RealSSHTests.setUpClass.__func__)
    setUp=fixtures.RealSSHTests.setUp
    collector=fixtures.RealSSHTests.collector
    def test_delayed_first_banner_reconnects_before_sending_show(self):
        accepted = []
        serve = self.server.serve

        def delay_first_banner(client):
            accepted.append(client)
            if len(accepted) == 1:
                with client:
                    self.server.stop.wait(2)
                return
            serve(client)

        self.server.serve = delay_first_banner
        self.server.responses['show version'] = 'Fixture OS 1.0'
        c = self.collector('cisco_ios')
        with c.request_budget(timeout=15, connection_timeouts={'banner_timeout': .5}):
            result = c.execute('local', 'show version')

        self.assertEqual(result['status'], 'SUCCESS', result)
        self.assertIn('Fixture OS 1.0', result['output'])
        self.assertEqual(result['recovery_attempts'], 1)
        self.assertEqual(result['previous_attempt']['error_category'], 'banner_timeout')
        self.assertIs(result['previous_attempt']['command_sent'], False)
        self.assertEqual(len(accepted), 2)
        self.assertEqual(self.server.auth_attempts, 1)
        self.assertEqual(self.server.commands.count('show version'), 1)

    def test_read_recovers_once_and_retains_previous_partial(self):
        calls=[]
        def reply(ch):
            calls.append(1)
            if len(calls)==1:
                ch.sendall(b'partial first\r\n');ch.close()
            else:ch.sendall(b'final answer\r\nrouter#')
        self.server.responses['hostname']=reply
        c=self.collector();r=c.execute('local','hostname')
        self.assertEqual(r['status'],'SUCCESS');self.assertEqual(r['recovery_attempts'],1)
        self.assertIn('partial first',r['previous_attempt']['output']);self.assertEqual(len(calls),2)
    def test_configuration_disconnect_is_not_replayed(self):
        def reply(ch):ch.sendall(b'possibly applied\r\n');ch.close()
        self.server.responses['set fixture value']=reply
        r=self.collector().execute('local','set fixture value')
        self.assertEqual(r['status'],'UNKNOWN');self.assertEqual(r['execution_state'],'UNCERTAIN')
        self.assertEqual(self.server.commands.count('set fixture value'),1)
    def test_worker_large_unicode_is_saved_without_loss(self):
        body='dữ liệu đường truyền αβγ\r\n'*100000
        self.server.responses['hostname']=body
        c=self.collector('autodetect');c.redaction_enabled=False
        r=c.execute('local','hostname',read_timeout=20,save_output=True)
        self.assertEqual(r['status'],'SUCCESS')
        actual=(Path(self.tmp.name)/(r['output_id']+'.txt')).read_bytes()
        expected=b.clean_terminal(body+'\r\nrouter#').encode('utf-8')
        self.assertEqual(hashlib.sha256(actual).digest(),hashlib.sha256(expected).digest())
        self.assertEqual(self.server.auth_attempts,1)
    def test_pending_question_status_is_not_success(self):
        r=self.collector().execute('local','date')
        self.assertEqual(r['status'],'AWAITING_INPUT');self.assertFalse(r['ok'])

if __name__=='__main__':unittest.main()
