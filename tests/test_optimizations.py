"""Performance options must preserve output and session isolation."""
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'mcp'))
import collector_backend as b
from test_ssh_reliability import FakeConnection

class OptimizationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
    def collector(self, **options):
        self.conn = FakeConnection(['DATA\nrouter#'] * 10)
        defaults = dict(output_dir=self.tmp.name, session_sweep_seconds=0, alt_key_file=str(Path(self.tmp.name)/'known_hosts'), **options)
        c = b.Collector({'defaults':defaults,'devices':{'test':{'host':'192.0.2.1','device_type':'cisco_ios'}}}, connect_factory=lambda **kw:self.conn)
        self.addCleanup(c.shutdown)
        return c
    def test_known_inventory_driver_skips_probe_and_can_be_overridden(self):
        c = self.collector()
        self.assertEqual(c._get_settings('test','autodetect',None)['device_type'],'cisco_ios')
        c.prefer_inventory_driver = False
        self.assertEqual(c._get_settings('test','autodetect',None)['device_type'],'autodetect')
    def test_health_probe_is_periodic(self):
        c = self.collector()
        probes=[]
        self.conn.is_alive=lambda:probes.append(1) or True
        for _ in range(3): self.assertTrue(c.execute('test','show version')['ok'])
        self.assertEqual(probes,[])
        next(iter(c._sessions.values()))['health_checked']=0
        self.assertTrue(c.execute('test','show version')['ok'])
        self.assertEqual(probes,[1])
    def test_dead_connection_is_not_reused_during_health_interval(self):
        c = self.collector()
        c.execute('test','show version')
        old=self.conn
        old.closed=True
        self.conn=FakeConnection(['DATA\nrouter#'])
        self.assertTrue(c.execute('test','show version')['ok'])
        self.assertEqual(c.status()['connections_opened'],2)
    def test_redaction_disabled_preserves_output_and_errors(self):
        c = self.collector(redaction_enabled=False)
        self.assertEqual(c.redact_output('password fixture-secret'),'password fixture-secret')
        self.assertIn('fixture-secret',c.scrub_error('password fixture-secret'))
        oid=c._save_output('password fixture-secret')
        self.assertEqual(c.read_output(oid)['text'],'password fixture-secret')
    def test_process_store_is_separate_from_shared_store(self):
        c = self.collector(host_key_store_mode='process')
        path=c._get_settings('test',None,None)['alt_key_file']
        self.assertTrue(path.endswith('known_hosts.'+str(os.getpid())))
        self.assertFalse(Path(path).exists())
    def test_successful_validation_is_cached(self):
        b.readonly_command.cache_clear()
        for _ in range(2):b.readonly_command('show version','cisco_ios')
        self.assertGreaterEqual(b.readonly_command.cache_info().hits,1)
    def test_invalid_options_are_rejected(self):
        for options in [dict(prompt_quiet_seconds=-1),dict(timing_quiet_seconds=3),dict(host_key_store_mode='invalid')]:
            with self.subTest(options=options),self.assertRaises(ValueError):self.collector(**options)
    def test_linear_backspace_cleaning_preserves_lines(self):
        self.assertEqual(b.clean_terminal('abc'+chr(8)*3+'xyz\nA'+chr(8)+'B'),'xyz\nB')

    def test_process_store_keeps_resume_identity_stable_across_pids(self):
        c = self.collector(host_key_store_mode='process')
        identities=[]
        paths=[]
        for pid in (123, 456):
            with patch.object(b.os, 'getpid', return_value=pid):
                params=c._get_settings('test',None,None)
                paths.append(params['alt_key_file'])
                identities.append(c._session_key(params))
        self.assertNotEqual(paths[0],paths[1])
        self.assertEqual(identities[0],identities[1])
