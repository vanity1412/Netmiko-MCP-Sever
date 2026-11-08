"""Offline regressions for audit findings except redaction (out of scope)."""
import concurrent.futures
import threading
import time
import unittest
import test_collector as f
b=f.b
class AuditFixes(unittest.TestCase):
    setUp=f.Regression.setUp
    tearDown=f.Regression.tearDown
    def test_policy_additions(self):
        for p,c in [('juniper_junos','show configuration | display inheritance | display set'),('juniper_junos','show interfaces | match "up$"'),('cisco_ios','show controllers'),('cisco_ios','show etherchannel summary'),('cisco_ios','show policy-map interface Gi0/1'),('huawei','display eth-trunk'),('huawei','display bfd session all')]:
            self.assertEqual(b.readonly_command(c,p),c)
        with self.assertRaises(PermissionError):b.readonly_command('show version $x','juniper_junos')
    def test_wrong_final_prompt(self):
        fake=f.Fake();fake.send_command=lambda command,**kw:command+'\nMOCK>\nPARTIAL DONE'
        self.c._connect=lambda **kw:fake
        r=self.c.execute('MOCK','show version',expect_string='DONE$')
        self.assertFalse(r['ok']);self.assertFalse(r['output_complete'])
    def test_cli_errors_and_counter(self):
        for line in ['% Invalid interface type and number','% Bad IP address or host name']:
            self.assertFalse(self.c._result('MOCK','show interfaces','show interfaces\n'+line+'\nMOCK>',0)['cli_ok'])
        self.assertTrue(self.c._result('MOCK','show interfaces','show interfaces\nError counters: 0\nMOCK>',0)['ok'])
    def test_auth_not_repeated(self):
        from netmiko.exceptions import NetmikoAuthenticationException
        attempts=[]
        def connect(**kw):attempts.append(1);raise NetmikoAuthenticationException('MOCK')
        self.c._connect=connect
        self.c.parallel([{'target':'MOCK','command':'show version'}]*3)
        self.assertEqual(len(attempts),1)
    def test_identity_conflict(self):
        self.c.devices={'a':{'host':'192.0.2.1','device_type':'juniper_junos','username':'a'},'b':{'host':'192.0.2.1','device_type':'juniper_junos','username':'b'}}
        self.c._build_device_index()
        with self.assertRaises(ValueError):self.c._get_settings('192.0.2.1',None,None)
    def test_generic_uses_detection(self):
        class Detect:
            def autodetect(self):return 'juniper_junos'
        self.c._custom_detect=lambda **kw:Detect()
        params=self.c._get_settings('MOCK','generic_termserver',None)
        self.c._resolve_platform(params)
        self.assertEqual(params['device_type'],'juniper_junos')
    def test_close_respects_deadline(self):
        self.c.execute('MOCK','show version');entry=next(iter(self.c._sessions.values()))
        def close():
            self.c._request.context=(threading.Event(),time.monotonic()+.05)
            with self.assertRaises(TimeoutError):self.c.close('MOCK')
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            with entry['lock']:pool.submit(close).result(1)
        self.assertTrue(entry['conn'].alive)
    def test_same_host_waiters_leave_slots_available(self):
        self.c._ssh_slots=threading.BoundedSemaphore(1)
        self.c.execute('MOCK','show version');entry=next(iter(self.c._sessions.values()))
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            with entry['lock']:
                future=pool.submit(self.c.execute,'MOCK','show version')
                end=time.monotonic()+1
                while entry['borrowers']<1 and time.monotonic()<end:time.sleep(.005)
                self.c._request.context=(threading.Event(),time.monotonic()+.5)
                try:self.assertTrue(self.c.execute('other','show version')['ok'])
                finally:self.c._request.context=None
            self.assertTrue(future.result(1)['ok'])
    def test_regex_search_bounded(self):
        oid=self.c._save_output('a'*32+'!')
        with self.assertRaises(TimeoutError):self.c.search_output(oid,'(a+)+$',regex=True)
        self.assertTrue(self.c.execute('MOCK','show version')['ok'])
    def test_regex_search_normal(self):
        oid=self.c._save_output('CRC 12\nDROP 2\n')
        self.assertEqual(self.c.search_output(oid,'CRC|DROP',regex=True)['total_matches'],2)

    def test_fallback_enforces_policy_and_hostkeys(self):
        import sys
        from pathlib import Path
        from unittest.mock import patch
        sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
        import readonly_client
        with patch.object(readonly_client, 'Collector', return_value=self.c) as factory:
            wrapper=readonly_client.ReadOnlyConnection(host='MOCK',ssh_strict=False)
            defaults=factory.call_args.args[0]['defaults']
            self.assertTrue(defaults['ssh_strict']);self.assertTrue(defaults['alt_host_keys'])
            with self.assertRaises(PermissionError):wrapper.send_command('configure')
            self.assertIn('MOCK DATA',wrapper.send_command('show version'))
