"""Real subprocess contention on temporary evidence; no SSH or private config."""
import concurrent.futures
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

MCP = Path(__file__).resolve().parents[1] / 'mcp'
sys.path.insert(0, str(MCP))
import collector_backend as b
from output_storage import file_lock

CHILD = '''
import json, sys
sys.path.insert(0, sys.argv[1])
import collector_backend as b
c=b.Collector({'defaults':{'output_dir':sys.argv[2], 'output_quota_bytes':100,
    'session_sweep_seconds':0}}, connect_factory=lambda **kw:None)
try:
    if sys.argv[3]=='write':
        print('ready',flush=True);sys.stdin.readline()
        written=[]
        for i in range(10):
            try:written.append(c._save_output('x'*20))
            except ValueError:pass
        print(json.dumps(written),flush=True)
    else:
        with c._output_lease(sys.argv[4]) as path:
            with path.open('rb') as handle:
                print('ready',flush=True);sys.stdin.readline()
                print(handle.read().decode(),flush=True)
finally:c.shutdown()
'''


class SharedStorageTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def collector(self, **options):
        c = b.Collector({'defaults': {'output_dir': self.tmp.name,
            'session_sweep_seconds': 0, **options}}, connect_factory=lambda **kw: None)
        self.addCleanup(c.shutdown)
        return c

    def child(self, operation, oid=''):
        p = subprocess.Popen([sys.executable, '-u', '-c', CHILD, str(MCP),
            self.tmp.name, operation, oid], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, text=True, encoding='utf-8')
        def close():
            if p.poll() is None: p.kill()
            p.communicate(timeout=10)
        self.addCleanup(close)
        self.assertEqual(p.stdout.readline().strip(), 'ready')
        return p

    def expire(self, c, oid):
        c._output_pins.clear()
        with c._storage_transaction():
            c._shared_outputs.pin(oid, 0)
            old = time.time() - 10
            import os
            os.utime(c.output_dir / (oid + '.txt'), (old, old))

    def test_other_collector_honors_creation_pin(self):
        a = self.collector(output_quota_bytes=10)
        oid = a._save_output('0123456789')
        other = self.collector(output_quota_bytes=10)
        with self.assertRaises(ValueError): other._save_output('x')
        self.assertEqual(a.read_output(oid)['text'], '0123456789')

    def test_concurrent_process_writes_share_one_quota(self):
        processes = [self.child('write') for _ in range(4)]
        # Release every writer before waiting for any result.
        for p in processes:
            p.stdin.write('go\n'); p.stdin.flush()
        reports = []
        for p in processes:
            out, err = p.communicate(timeout=30)
            self.assertEqual(p.returncode, 0, err)
            reports.extend(json.loads(out))
        files = list(Path(self.tmp.name).glob('*.txt'))
        self.assertEqual(len(reports), 5)
        self.assertEqual(len(set(reports)), 5)
        self.assertEqual(sum(p.stat().st_size for p in files), 100)

    def test_live_reader_in_another_process_survives_expiry_and_pressure(self):
        c = self.collector(output_ttl_seconds=1, output_quota_bytes=10)
        oid = c._save_output('0123456789')
        self.expire(c, oid)
        p = self.child('read', oid)
        self.assertEqual(c._cleanup_outputs()['removed'], 0)
        self.assertFalse(c.retire_output(oid))
        with self.assertRaises(ValueError): c._save_output('x')
        out, err = p.communicate('go\n', timeout=10)
        self.assertEqual(p.returncode, 0, err)
        self.assertEqual(out.strip(), '0123456789')
        c._cleanup_outputs()
        self.assertFalse((c.output_dir / (oid + '.txt')).exists())

    def test_crashed_reader_releases_os_lease(self):
        c = self.collector(output_ttl_seconds=1)
        oid = c._save_output('abc')
        self.expire(c, oid)
        p = self.child('read', oid)
        self.assertEqual(c._cleanup_outputs()['removed'], 0)
        p.kill(); p.communicate(timeout=10)
        self.assertEqual(c._cleanup_outputs()['removed'], 1)

    def test_lock_timeout_is_storage_failure_without_publishing_output(self):
        c = self.collector()
        lock = c._shared_outputs.metadata / 'transaction.lock'
        with file_lock(lock):
            with patch.object(c._shared_outputs, 'transaction',
                              side_effect=lambda checkpoint: file_lock(lock, timeout=.03)):
                with self.assertRaises(TimeoutError) as caught: c._save_output('abc')
        result = c.failure_result(caught.exception)
        self.assertEqual(result['status'], 'STORAGE_ERROR')
        self.assertFalse(result['retryable'])
        self.assertEqual(list(c.output_dir.glob('*.txt')), [])

    def test_failed_publish_does_not_leave_partial_output(self):
        c = self.collector()
        with patch.object(Path, 'replace', side_effect=OSError('simulated disk error')):
            with self.assertRaises(OSError): c._save_output('abc')
        self.assertEqual(list(c.output_dir.glob('*.txt')), [])
        self.assertEqual(list(c._shared_outputs.metadata.glob('*.tmp')), [])
        # A failed publication must not consume quota in the following attempt.
        self.assertEqual(c.read_output(c._save_output('next'))['text'], 'next')

    def test_waiting_writer_obeys_request_budget(self):
        c = self.collector()
        lock = c._shared_outputs.metadata / 'transaction.lock'
        started = time.monotonic()
        with file_lock(lock), c.request_budget(timeout=.03):
            with self.assertRaises(TimeoutError): c._save_output('abc')
        self.assertLess(time.monotonic()-started, .5)
        self.assertEqual(list(c.output_dir.glob('*.txt')), [])


if __name__ == '__main__': unittest.main()
