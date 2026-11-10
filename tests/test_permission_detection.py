"""Permission diagnostics remain additive CLI errors; no production SSH."""
from pathlib import Path
import sys
import tempfile
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'mcp'))
import collector_backend as b
from result_status import normalize_result
import test_ssh_reliability as ssh

class PermissionTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.opens=0
        owner=self
        class Connection:
            device_type='cisco_ios'
            def __init__(self):self.alive=True
            def find_prompt(self):return 'router#'
            def is_alive(self):return self.alive
            def disconnect(self):self.alive=False
            def send_command(self,command,**options):
                return ('% Authorization failed.' if command=='show accounts' else 'valid output')+'\nrouter#'
            send_command_timing=send_command
        def connect(**params):self.opens+=1;return Connection()
        self.c=b.Collector({'defaults':{'output_dir':self.tmp.name,'session_sweep_seconds':0},
            'devices':{'mock':{'host':'192.0.2.1','device_type':'cisco_ios'}}},connect_factory=connect)
        self.addCleanup(self.c.shutdown)
    def result(self,message,driver='cisco_ios',command='show accounts',save=False):
        return self.c._result('mock',command,message+'\nrouter#',0,save,r'(?m)^router#$',device_type=driver)
    def test_permission_matrix_by_vendor(self):
        fixtures=[('cisco_ios','% Authorization failed.'),('cisco_xr','% This command is not authorized'),
            ('cisco_nxos','% Permission denied for the role'),('juniper_junos','error: permission denied'),
            ('huawei','Error: The user does not have permission to run the command.'),
            ('huawei','Error: Insufficient user privilege.'),('linux','cat: /etc/shadow: Permission denied'),
            ('linux','sudo: unable to execute /bin/cat: Permission denied'),
            ('linux','ip: RTNETLINK answers: Operation not permitted')]
        for driver,message in fixtures:
            with self.subTest(driver=driver,message=message):
                r=self.result(message,driver)
                self.assertEqual(r['status'],'CLI_ERROR');self.assertEqual(r['error_category'],'cli_error')
                self.assertEqual(r['error_reason'],'permission_denied');self.assertFalse(r['retryable'])
                self.assertTrue(r['output_complete']);self.assertFalse(r['ok']);self.assertTrue(r['transport_ok'])
    def test_syntax_and_other_failures_are_not_permissions(self):
        for message,reason in [('% Invalid input detected','syntax_error'),('syntax error, expecting command.','syntax_error'),
                              ('Error: resource unavailable','command_failed'),('% Command rejected','command_failed')]:
            with self.subTest(message=message):self.assertEqual(self.result(message)['error_reason'],reason)
    def test_permission_text_in_payload_is_not_a_failure(self):
        for command,body in [('show accounts','description "permission denied"\naccess-denied-count: 0'),
            ('show running-config','version 1\n banner login "Permission denied"'),
            ('show logging','log header\nError: permission denied while reading historical file')]:
            with self.subTest(command=command):
                r=self.result(body,command=command)
                self.assertTrue(r['ok']);self.assertNotIn('error_reason',r)
    def test_rpc_access_denied_only_for_error_response(self):
        r=self.result('<rpc-reply><rpc-error><error-severity>error</error-severity><error-tag>access-denied</error-tag></rpc-error></rpc-reply>','juniper_junos')
        self.assertEqual(r['error_reason'],'permission_denied')
        r=self.result('<rpc-reply><rpc-error><error-severity>warning</error-severity><error-tag>access-denied</error-tag></rpc-error></rpc-reply>','juniper_junos')
        self.assertTrue(r['ok'])
    def test_authentication_is_not_cli_permission(self):
        from netmiko.exceptions import NetmikoAuthenticationException
        r=self.c.failure_result(NetmikoAuthenticationException('Authentication failed'),'mock')
        self.assertEqual(r['status'],'AUTH_ERROR');self.assertNotIn('error_reason',r)
    def test_normalization_clears_stale_reason(self):
        for r in [{'ok':True,'output_complete':True,'error_reason':'permission_denied'},
                  {'ok':False,'output_complete':False,'error_category':'read_timeout','error_reason':'permission_denied'}]:
            with self.subTest(r=r):self.assertNotIn('error_reason',normalize_result(r))
    def test_execute_keeps_synchronized_session_without_retry(self):
        r=self.c.execute('mock','show accounts')
        self.assertEqual(r['error_reason'],'permission_denied');self.assertNotIn('recovery_attempts',r)
        self.assertTrue(self.c.execute('mock','show version')['ok']);self.assertEqual(self.opens,1)
    def test_batch_stops_and_parallel_preserves_child_reason(self):
        with self.assertRaises(b.BatchError) as caught:self.c.execute_many('mock',['show accounts','show version'])
        self.assertEqual(len(caught.exception.results),2)
        self.assertEqual(caught.exception.results[1]["status"],"SKIPPED")
        self.assertEqual(caught.exception.results[0]['error_reason'],'permission_denied')
        r=self.c.parallel([{'target':'mock','command':'show accounts'},{'target':'mock','command':'show version'}])
        self.assertEqual(r['status'],'PARTIAL');self.assertEqual(r['results'][0]['error_reason'],'permission_denied')
        self.assertEqual(self.opens,1)
    def test_interact_preserves_reason(self):
        r=self.c.interact('mock',['show accounts'])
        self.assertEqual(r['steps'][0]['error_reason'],'permission_denied')
        self.assertEqual(r['status'],'CLI_ERROR')
    def test_evidence_preserved(self):
        r=self.result('% Authorization failed.',save=True)
        self.assertEqual(r['error_reason'],'permission_denied')
        self.assertIn('Authorization failed',(self.c.output_dir/(r['output_id']+'.txt')).read_text(encoding='utf-8'))

class LocalPermissionTests(unittest.TestCase):
    def test_localhost_denial_keeps_transport_and_next_command_works(self):
        import paramiko
        with tempfile.TemporaryDirectory() as folder:
            server=ssh.LocalSSHServer(paramiko.RSAKey.generate(2048))
            c=None
            try:
                server.responses['cat /etc/shadow']='cat: /etc/shadow: Permission denied'
                c=b.Collector({'defaults':{'username':'tester','password':'loopback-only',
                    'output_dir':folder,'alt_key_file':str(Path(folder)/'known_hosts'),
                    'autodetect_cache_file':str(Path(folder)/'cache.sqlite3'),'session_sweep_seconds':0},
                    'devices':{'local':{'host':'127.0.0.1','port':server.port,'device_type':'linux'}}})
                denied=c.execute('local','cat /etc/shadow',read_timeout=3)
                self.assertEqual(denied['status'],'CLI_ERROR');self.assertEqual(denied['error_reason'],'permission_denied')
                self.assertTrue(denied['output_complete']);self.assertTrue(c.execute('local','uname -s',read_timeout=3)['ok'])
                self.assertEqual(server.auth_attempts,1);self.assertEqual(server.commands.count('cat /etc/shadow'),1)
            finally:
                if c:c.shutdown()
                server.close()

if __name__=='__main__':unittest.main()
