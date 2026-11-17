"""Short soak harness regressions. Long runs are an explicit CLI operation."""
import os
from pathlib import Path
import socket
import sys
import tempfile
import unittest
from unittest.mock import patch

import soak_collector as soak


class SoakHarnessTests(unittest.TestCase):
    def test_mock_cycles_are_network_free_and_keep_evidence(self):
        with tempfile.TemporaryDirectory() as folder:
            with patch.object(socket.socket, 'connect', side_effect=AssertionError('No network in mock soak')):
                report = soak.run_mock(Path(folder), seconds=0, min_cycles=2, max_cycles=2)
            self.assertEqual(report['warm_connections'], 8)
            self.assertEqual(report['cycles'], 2)
            self.assertEqual(report['fault_attempts'], 11)
            self.assertEqual(report['sessions_after_shutdown'], 0)
            self.assertTrue(report['evidence']['all_hashes_reverified'])

    def test_mock_discovery_is_rejected_before_probe_spawn(self):
        with tempfile.TemporaryDirectory() as folder:
            c = soak.b.Collector({'defaults':{'output_dir':folder,'session_sweep_seconds':0}},
                connect_factory=lambda **kwargs: None, detect_factory=soak.reject_detection)
            try:
                with patch('probe_session.ProbeSession', side_effect=AssertionError('No live probe')) as probe:
                    with self.assertRaisesRegex(AssertionError, 'live discovery prohibited'):
                        c._resolve_platform(c._get_settings('192.0.2.99', 'autodetect', None))
                    probe.assert_not_called()
            finally:
                c.shutdown()

    def test_loopback_cycles_reap_probe_worker(self):
        original = socket.socket.connect
        def loopback_only(connection, address):
            self.assertEqual(address[0], '127.0.0.1')
            return original(connection, address)
        with tempfile.TemporaryDirectory() as folder:
            with patch.object(socket.socket, 'connect', loopback_only):
                report = soak.run_localhost(Path(folder), seconds=0, min_cycles=2, max_cycles=2)
            self.assertEqual(report['authentication_attempts'], 2)
            self.assertEqual(report['probe_workers_started'], 1)
            self.assertEqual(report['live_workers_after_shutdown'], 0)
            self.assertTrue(report['evidence']['all_hashes_reverified'])

    def test_owned_process_resource_sample(self):
        if os.name != 'nt' and not sys.platform.startswith('linux'):
            self.skipTest('Per-worker samples require Windows or Linux')
        sample = soak.worker_resources(os.getpid())
        self.assertIsNotNone(sample)
        self.assertGreater(sample['rss_bytes'], 0)
        self.assertGreaterEqual(sample['cpu_seconds'], 0)
