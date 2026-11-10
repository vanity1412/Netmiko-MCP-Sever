"""Storage accounting and persistent detection must survive collector restarts."""
import contextlib
import concurrent.futures
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'mcp'))
import collector_backend as b

class StorageDetectionTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
    def collector(self, **options):
        defaults=dict(output_dir=self.tmp.name,session_sweep_seconds=0,**options)
        c=b.Collector({'defaults':defaults},connect_factory=lambda **kw:None)
        self.addCleanup(c.shutdown)
        return c
    def test_exclusive_storage_does_not_glob_for_every_write(self):
        c=self.collector(output_storage_mode='exclusive')
        original=Path.glob
        calls=[]
        def glob(path, pattern):
            calls.append(pattern)
            return original(path,pattern)
        with patch.object(Path,'glob',glob):
            for i in range(100):c._save_output('sample-'+str(i))
        self.assertEqual(calls.count('*.txt'),1)
        self.assertEqual(c._output_total,sum(p.stat().st_size for p in Path(self.tmp.name).glob('*.txt')))
    def test_concurrent_writes_enforce_quota(self):
        c=self.collector(output_storage_mode='exclusive',output_quota_bytes=100)
        def save(_):
            try:c._save_output('x'*20);return True
            except ValueError:return False
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:successes=sum(pool.map(save,range(20)))
        self.assertEqual(successes,5)
        self.assertEqual(c._output_total,100)
    def test_shared_collectors_reconcile_external_files(self):
        a=self.collector(output_quota_bytes=10)
        other=self.collector(output_quota_bytes=10)
        oid=a._save_output('1234567890')
        # A new Collector must honor the creator's persisted retention pin.
        with self.assertRaises(ValueError):other._save_output('x')
    def test_external_deletion_notified_then_capacity_is_available(self):
        c=self.collector(output_storage_mode='exclusive',output_quota_bytes=10)
        oid=c._save_output('1234567890')
        (c.output_dir/(oid+'.txt')).unlink()
        c.forget_output(oid)
        self.assertEqual(c._output_total,0)
        c._save_output('1234567890')
    def test_restart_reconstructs_accounting(self):
        a=self.collector(output_storage_mode='exclusive')
        a._save_output('abc')
        other=self.collector(output_storage_mode='exclusive')
        other._save_output('de')
        self.assertEqual(other._output_total,5)
    def test_expired_active_output_survives_until_release(self):
        c=self.collector(output_storage_mode='exclusive',output_ttl_seconds=1)
        oid=c._save_output('abc');path=c.output_dir/(oid+'.txt')
        c._output_pins.clear();os.utime(path,(time.time()-10,time.time()-10))
        c._active_outputs[oid]=1
        c._cleanup_outputs()
        self.assertTrue(path.exists())
        c._active_outputs.clear();c._cleanup_outputs()
        self.assertFalse(path.exists())
    def params(self,password='fixture'):
        return dict(host='192.0.2.1',port=22,username='tester',password=password,device_type='autodetect')
    def detector(self,c,calls):
        class Detector:
            def autodetect(self):calls.append(1);return 'juniper_junos'
        c._custom_detect=lambda **kw:Detector()
    def test_driver_reused_by_new_collector_without_probe(self):
        cache=str(Path(self.tmp.name)/'drivers.sqlite3')
        calls=[]
        a=self.collector(autodetect_cache_file=cache);self.detector(a,calls)
        a._resolve_platform(self.params())
        other=self.collector(autodetect_cache_file=cache);self.detector(other,calls)
        params=self.params();other._resolve_platform(params)
        self.assertEqual(params['device_type'],'juniper_junos')
        self.assertEqual(len(calls),1)
        self.assertEqual(other._persistent_detection_hits,1)
        data=Path(cache).read_bytes()
        self.assertNotIn(b'fixture',data);self.assertNotIn(b'tester',data);self.assertNotIn(b'192.0.2.1',data)
    def test_changed_credentials_do_not_share_cached_driver(self):
        cache=str(Path(self.tmp.name)/'drivers.sqlite3');calls=[]
        a=self.collector(autodetect_cache_file=cache);self.detector(a,calls);a._resolve_platform(self.params())
        other=self.collector(autodetect_cache_file=cache);self.detector(other,calls);other._resolve_platform(self.params('changed'))
        self.assertEqual(len(calls),2)
    def test_expired_cache_requires_probe(self):
        cache=str(Path(self.tmp.name)/'drivers.sqlite3');calls=[]
        a=self.collector(autodetect_cache_file=cache);self.detector(a,calls);a._resolve_platform(self.params())
        with contextlib.closing(sqlite3.connect(cache)) as db, db:db.execute('UPDATE detection_v1 SET expires_at=0')
        other=self.collector(autodetect_cache_file=cache);self.detector(other,calls);other._resolve_platform(self.params())
        self.assertEqual(len(calls),2)
    def test_corrupt_cache_falls_back_to_live_probe(self):
        cache=Path(self.tmp.name)/'bad.sqlite3';cache.write_bytes(b'bad db')
        calls=[];c=self.collector(autodetect_cache_file=str(cache));self.detector(c,calls)
        params=self.params();c._resolve_platform(params)
        self.assertEqual(params['device_type'],'juniper_junos');self.assertEqual(len(calls),1)
    def test_failed_probe_is_not_cached(self):
        cache=str(Path(self.tmp.name)/'drivers.sqlite3');c=self.collector(autodetect_cache_file=cache)
        c._custom_detect=lambda **kw: (_ for _ in ()).throw(ValueError('probe failed'))
        with self.assertRaises(ValueError):c._resolve_platform(self.params())
        with contextlib.closing(sqlite3.connect(cache)) as db, db:self.assertEqual(db.execute('SELECT count(*) FROM detection_v1').fetchone()[0],0)

    def test_cache_reused_when_only_job_key_store_changes(self):
        cache=str(Path(self.tmp.name)/'drivers.sqlite3');calls=[]
        a=self.collector(autodetect_cache_file=cache);self.detector(a,calls)
        first=self.params();first['alt_key_file']='job-one/known_hosts.123'
        a._resolve_platform(first)
        other=self.collector(autodetect_cache_file=cache);self.detector(other,calls)
        second=self.params();second['alt_key_file']='job-two/known_hosts.456'
        other._resolve_platform(second)
        self.assertEqual(second['device_type'],'juniper_junos');self.assertEqual(len(calls),1)

    def test_disk_cache_is_reused_by_a_separate_python_process(self):
        program = """import sys,json
sys.path.insert(0,sys.argv[1])
import collector_backend as b
class Probe:
    def autodetect(self): return 'linux'
c=b.Collector({'defaults':{'output_dir':sys.argv[2],'session_sweep_seconds':0,'autodetect_cache_file':sys.argv[3]}},connect_factory=lambda **kw:None)
c._custom_detect=lambda **kw:Probe()
try:
    c._resolve_platform({'host':'192.0.2.2','port':22,'username':'fixture','password':'dummy','device_type':'autodetect'})
    print(json.dumps({'probes':c._detection_probes,'disk_hits':c._persistent_detection_hits}))
finally:c.shutdown()
"""
        args=[sys.executable,'-c',program,str(Path(b.__file__).parent),str(Path(self.tmp.name)/'out'),str(Path(self.tmp.name)/'drivers.sqlite3')]
        first=subprocess.run(args,capture_output=True,text=True,timeout=10,check=True)
        second=subprocess.run(args,capture_output=True,text=True,timeout=10,check=True)
        self.assertEqual(json.loads(first.stdout),{'probes':1,'disk_hits':0})
        self.assertEqual(json.loads(second.stdout),{'probes':0,'disk_hits':1})

    def test_disk_hit_does_not_restart_verification_ttl(self):
        cache=str(Path(self.tmp.name)/'drivers.sqlite3');calls=[]
        a=self.collector(autodetect_cache_file=cache);self.detector(a,calls);a._resolve_platform(self.params())
        with contextlib.closing(sqlite3.connect(cache)) as db, db:
            db.execute('UPDATE detection_v1 SET verified_at=?,expires_at=?',(time.time()-100,time.time()+1))
        other=self.collector(autodetect_cache_file=cache);self.detector(other,calls);other._resolve_platform(self.params())
        verified,_=next(iter(other._detect_cache.values()))
        remaining=other.detect_cache_ttl-(time.monotonic()-verified)
        self.assertGreater(remaining,0)
        self.assertLess(remaining,2)
        self.assertEqual(len(calls),1)
