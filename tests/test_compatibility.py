import json
import os
from pathlib import Path
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch
sys.path[:0]=[str(Path(__file__).resolve().parents[1]/'mcp')]
import collector_backend as b
import scan
import test_ssh_reliability as fixtures
from test_ssh_scenarios import VirtualClock, TimelineChannel

class Compatibility(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
    def collector(self, **defaults):
        c=b.Collector({'defaults':{'output_dir':self.tmp.name,'session_sweep_seconds':0,**defaults}},
                      connect_factory=lambda **kw:None)
        self.addCleanup(c.shutdown);return c
    def test_password_literal_and_explicit_reference(self):
        with patch.dict(os.environ,{'PASSWORD_SUFFIX':'changed'}):
            self.assertEqual(b.expand_env({'password':'pw$PASSWORD_SUFFIX','secret':'~abc'}),
                             {'password':'pw$PASSWORD_SUFFIX','secret':'~abc'})
            self.assertEqual(b.expand_env({'password':'${PASSWORD_SUFFIX}'})['password'],'changed')
    def test_csv_port(self):
        path=Path(self.tmp.name)/'devices.csv'
        path.write_text('name,ip,netmiko_device_type,port\na,192.0.2.1,huawei,2222\n')
        self.assertEqual(b.load_inventory_csv({},str(path))['devices']['a']['port'],2222)
    def test_ssh_modes(self):
        for mode, strict in [('compatible',False),('strict',True)]:
            c=self.collector(ssh_mode=mode)
            p=c._get_settings('192.0.2.1',None,None)
            self.assertEqual(p['ssh_strict'],strict)
            self.assertEqual(p['alt_host_keys'],strict)
    def test_key_and_encoding_options(self):
        c=self.collector(passphrase='test-only',encoding='latin1',disable_sha2_fix=True)
        p=c._get_settings('192.0.2.1',None,None)
        self.assertEqual(p['passphrase'],'test-only');self.assertEqual(p['encoding'],'latin1')
    def test_extra_pagers(self):
        for pager in ['<--- More --->','--- MORE ---']:
            self.assertTrue(b.ending_matches(b.PAGER_RE.pattern,pager))
    def test_parallel_preserves_connection_budget(self):
        c=self.collector();captured=[]
        def execute(**kw):
            captured.append(c._request.connection_timeouts);return {'ok':True}
        with patch.object(c,'execute',execute), c.request_budget(connection_timeouts={'auth_timeout':60}):
            self.assertTrue(c.parallel([{'target':'192.0.2.1','command':'show version'}])['ok'])
        self.assertEqual(captured,[{'auth_timeout':60}])
    def test_slow_lane_retries_at_most_once(self):
        c=self.collector(max_workers=2);attempts=[]
        def connect(**kw):
            attempts.append(1);raise TimeoutError('simulated TCP timeout')
        c._connect=connect
        result=scan.run_scan(c,[{'target':'192.0.2.1','device_type':'cisco_ios','lane':'slow'}],
                             Path(self.tmp.name)/'job',workers=2,slow_workers=1)
        self.assertEqual(len(attempts),2);self.assertEqual(result['failed'],1)
    def test_explicit_enable(self):
        conn=SimpleNamespace(find_prompt=lambda:'router#',disconnect=lambda:None)
        enabled=[];conn.enable=lambda:enabled.append(True)
        c=self.collector(auto_enable=True)
        c._connect=lambda **kw:conn
        with c.request_budget():
            p=c._get_settings('192.0.2.1','cisco_ios',None)
            c._open(p)
        self.assertEqual(enabled,[True])
    def test_batch_storage_failure_keeps_only_synchronized_session(self):
        for output, closed in [('valid data\nrouter#',False),('partial data',True)]:
            with self.subTest(output=output):
                conn=SimpleNamespace(closed=False,find_prompt=lambda:'router#',is_alive=lambda:True,
                                     send_command=lambda *a,**kw:output)
                conn.disconnect=lambda:setattr(conn,'closed',True)
                c=self.collector();c._connect=lambda **kw:conn
                with patch.object(c,'_save_output',side_effect=OSError('simulated disk error')):
                    with self.assertRaises(b.BatchError):
                        c.execute_many('192.0.2.1',['show version'],save_output=True)
                self.assertEqual(conn.closed,closed)
    def test_noc_aliases_and_filters(self):
        self.assertEqual(b.readonly_command('show run','cisco_ios'),'show running-config')
        self.assertEqual(b.readonly_command('display cu','huawei'),'display current-configuration')
        for cmd in ['show configuration | display inheritance no-comments',
                    'show interfaces | match "ge-0/0/0\\.[0-9]+"']:
            b.readonly_command(cmd,'juniper_junos')
        b.readonly_command('show tech-support','cisco_ios')
    def test_embedded_prompt_banner_waits_for_remaining_config(self):
        clock=VirtualClock()
        conn=TimelineChannel(clock,[(.01,'banner motd ^C\nrouter#'),(.2,'\n^C\nCOMPLETE\nend\nrouter#')])
        with patch.object(b,'time',SimpleNamespace(monotonic=clock.now,sleep=clock.sleep)):
            output,failure=b.read_cli_output(conn,'show running-config',1,r'(?m)^router#$')
        self.assertIsNone(failure);self.assertIn('COMPLETE',output)
    def test_unclosed_banner_is_incomplete(self):
        c=self.collector()
        self.assertFalse(c._result('a','show running-config','banner motd ^C\nrouter#',0)['ok'])
    def test_privilege_failure_is_not_success(self):
        c=self.collector()
        self.assertFalse(c._result('a','show version','Not enough privileges to perform this operation.\nrouter#',0)['ok'])
    def test_log_body_error_is_data(self):
        c=self.collector()
        self.assertTrue(c._result('a','show logging','Historical events\nError: old event\nrouter#',0)['ok'])

class LocalCompatibility(unittest.TestCase):
    setUpClass=classmethod(fixtures.RealSSHTests.setUpClass.__func__)
    setUp=fixtures.RealSSHTests.setUp
    collector=fixtures.RealSSHTests.collector
    def test_real_banner_prompt_collision(self):
        def output(ch):
            ch.sendall(b'banner motd ^C\r\nrouter#');time.sleep(.2)
            ch.sendall(b'\r\n^C\r\nCOMPLETE\r\nend\r\nrouter#')
        self.server.responses['show running-config']=output
        result=self.collector('cisco_ios').execute('local','show running-config')
        self.assertTrue(result['ok']);self.assertIn('COMPLETE',result['output'])
    def test_profile_read_timeout_and_quiet(self):
        c=self.collector();c.profiles['slow']={'read_timeout':3,'prompt_quiet_seconds':.15}
        captured=[]
        original=b.read_cli_output
        def read(*args,**kwargs):
            captured.append((args[2],kwargs.get('quiet')));return original(*args,**kwargs)
        with patch.object(b,'read_cli_output',read):
            result=c.execute('local','uname -s',profile='slow')
        self.assertTrue(result['ok']);self.assertEqual(captured[-1],(3,.15))
    def test_storage_failure_keeps_authenticated_session(self):
        c=self.collector()
        with patch.object(c,'_save_output',side_effect=OSError('simulated disk error')):
            with self.assertRaises(OSError):c.execute('local','uname -s',save_output=True)
        self.assertTrue(c.execute('local','uname -s')['ok'])
        self.assertEqual(self.server.auth_attempts,1)
    def test_parser_failure_keeps_raw_and_session(self):
        c=self.collector()
        with patch('netmiko.utilities.structured_data_converter',side_effect=ValueError('template')):
            result=c.execute('local','uname -s',use_textfsm=True)
        self.assertFalse(result['ok']);self.assertIn('Linux',result['output'])
        self.assertTrue(c.execute('local','uname -s')['ok']);self.assertEqual(self.server.auth_attempts,1)
    def test_interact_cli_error_keeps_session(self):
        c=self.collector();self.server.responses['hostname']='% Invalid command'
        self.assertFalse(c.interact('local',['hostname'])['ok'])
        self.assertTrue(c.execute('local','uname -s')['ok']);self.assertEqual(self.server.auth_attempts,1)
    def test_strict_rejects_unknown_key(self):
        c=self.collector();c.defaults['ssh_mode']='strict'
        with self.assertRaises(Exception):c.execute('local','uname -s')
        self.assertEqual(self.server.auth_attempts,0)
    def test_strict_accepts_known_and_rejects_changed_key(self):
        import paramiko
        c=self.collector();self.assertTrue(c.execute('local','uname -s')['ok']);c.shutdown()
        c=self.collector();c.defaults['ssh_mode']='strict'
        self.assertTrue(c.execute('local','uname -s')['ok']);c.shutdown()
        count=self.server.auth_attempts
        self.server.key=paramiko.RSAKey.generate(2048)
        c=self.collector();c.defaults['ssh_mode']='strict'
        with self.assertRaises(Exception):c.execute('local','uname -s')
        self.assertEqual(self.server.auth_attempts,count)
