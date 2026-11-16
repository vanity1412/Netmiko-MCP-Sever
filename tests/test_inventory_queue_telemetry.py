"""Additive metadata, concurrent queue accounting and scanner limits; no SSH."""
import concurrent.futures
from pathlib import Path
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'mcp'))
import collector_backend as b
from telemetry import WorkQueueMetrics


class InventoryQueueTests(unittest.TestCase):
    def collector(self, **config):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        defaults = {'output_dir': tmp.name, 'session_sweep_seconds': 0, 'max_workers': 1,
                    **config.pop('defaults', {})}
        c = b.Collector({'defaults': defaults, **config}, connect_factory=lambda **kw: None)
        self.addCleanup(c.shutdown)
        return c

    def test_inventory_port_matches_resolver_without_credentials(self):
        c = self.collector(defaults={'port': 2200}, profiles={
            'default': {'port': 2201}, 'noc': {'port': 2202, 'password': 'fixture-secret'}},
            devices={'a': {'host': '192.0.2.1'},
                     'b': {'host': '192.0.2.2', 'profile': 'noc'},
                     'c': {'host': '192.0.2.3', 'profile': 'noc', 'port': '2203'}})
        # Inventory must not invoke auth validation or mutate request options.
        with patch.object(c, '_get_settings', side_effect=AssertionError('auth resolution')):
            rows = c.inventory(limit=0)['devices']
        self.assertEqual([(r['profile'], r['port']) for r in rows],
                         [('default', 2201), ('noc', 2202), ('noc', 2203)])
        self.assertNotIn('fixture-secret', str(rows))
        self.assertEqual(c.inventory(offset=1, limit=1)['devices'], rows[1:2])
        self.assertEqual(c.inventory(summary_only=True)['devices'], [])
        self.assertEqual(self.collector(devices={'a': {}}).inventory()['devices'][0]['port'], 22)

    def test_parallel_queue_live_counts_waits_order_and_failure_cleanup(self):
        c = self.collector()
        entered, release = threading.Event(), threading.Event()
        def execute(**args):
            if args['target'] == 'first':
                entered.set()
                self.assertTrue(release.wait(5))
                return {'ok': True, 'target': 'first'}
            raise ValueError('fixture failure')
        with patch.object(c, 'execute', execute), concurrent.futures.ThreadPoolExecutor(1) as caller:
            future = caller.submit(c.parallel, [{'target': t, 'command': 'show version'} for t in ('first', 'second')])
            try:
                self.assertTrue(entered.wait(5))
                deadline = time.monotonic() + 5
                while c.status()['parallel_queue']['queued'] != 1 and time.monotonic() < deadline:
                    time.sleep(.001)
                snapshot = c.status()['parallel_queue']
                self.assertEqual((snapshot['queued'], snapshot['running']), (1, 1))
            finally:
                release.set()
            result = future.result(5)
        self.assertEqual([r['target'] for r in result['results']], ['first', 'second'])
        self.assertEqual(result['worker_telemetry']['effective_worker_limit'], 1)
        self.assertFalse(result['results'][1]['ok'])
        self.assertTrue(all(r['queue_wait_ms'] >= 0 for r in result['results']))
        snapshot = c.status()['parallel_queue']
        self.assertEqual((snapshot['queued'], snapshot['running'], snapshot['completed']), (0, 0, 2))
        self.assertEqual(snapshot['wait_metrics']['count'], 2)

    def test_expired_queued_task_is_not_executed(self):
        c = self.collector()
        release = threading.Event()
        blocked = c._task_pool.submit(release.wait, 5)
        timer = threading.Timer(.2, release.set)
        timer.start()
        try:
            with patch.object(c, '_connect', side_effect=AssertionError('unexpected SSH')), c.request_budget(timeout=.05):
                result = c.parallel([{'target': '192.0.2.1', 'command': 'show version'}])
        finally:
            release.set()
            timer.cancel()
            blocked.result(5)
        self.assertFalse(result['ok'])
        self.assertEqual(result['results'][0]['error_category'], 'deadline')
        self.assertEqual(c.status()['parallel_queue']['running'], 0)

    def test_cancel_and_rejected_submission_do_not_leak_queue_counts(self):
        metrics = WorkQueueMetrics()
        entered, release = threading.Event(), threading.Event()
        def blocking(queue_wait_ms):
            entered.set()
            release.wait(5)
        with concurrent.futures.ThreadPoolExecutor(1) as pool:
            first = metrics.submit(pool, blocking)
            try:
                self.assertTrue(entered.wait(5))
                second = metrics.submit(pool, blocking)
                self.assertTrue(second.cancel())
            finally:
                release.set()
            first.result(5)
        with self.assertRaises(RuntimeError):
            metrics.submit(pool, blocking)
        snapshot = metrics.snapshot()
        self.assertEqual((snapshot['queued'], snapshot['running'], snapshot['submitted'],
                          snapshot['completed'], snapshot['cancelled']), (0, 0, 2, 1, 1))
