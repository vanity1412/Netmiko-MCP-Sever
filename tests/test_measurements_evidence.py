"""Generic CLI data fidelity, persistence failures and bounded phase metrics."""
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'mcp'))
import collector_backend as b
from telemetry import PhaseMetrics, time_connection_method

PAYLOAD = ('username fixture_user privilege 15 password fixture_password\n'
           'hash fixture_hash secret fixture_secret token fixture_token\nrouter#')


class Connection:
    device_type = 'cisco_ios'
    def find_prompt(self): return 'router#'
    def is_alive(self): return True
    def disconnect(self): pass
    def send_command(self, command, **kw): return PAYLOAD


class MeasurementsEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)

    def collector(self, **options):
        c = b.Collector({'defaults': {'output_dir': self.tmp.name,
            'device_type': 'cisco_ios', 'session_sweep_seconds': 0, **options}},
            connect_factory=lambda **kw: Connection())
        self.addCleanup(c.shutdown)
        return c

    def test_default_keeps_all_cli_fields_inline_file_structured_and_error(self):
        c = self.collector()
        result = c.execute('192.0.2.1', 'show custom data')
        self.assertEqual(result['output'], PAYLOAD)
        saved = c.execute('192.0.2.1', 'show custom data', save_output=True)
        self.assertEqual(c.read_output(saved['output_id'])['text'], PAYLOAD)
        structured = dict(username='fixture_user', password='fixture_password',
                          hash='fixture_hash', secret='fixture_secret', token='fixture_token')
        self.assertEqual(c.redact_structured(structured), structured)
        with patch('netmiko.utilities.structured_data_converter', return_value=structured):
            parsed = c.execute('192.0.2.1', 'show custom data', use_textfsm=True)
        self.assertEqual(parsed['structured_output'], structured)
        c.audit('ssh_execute', {'command': PAYLOAD}, True, 0)
        self.assertEqual(json.loads(c._audit_path.read_text())['command'], PAYLOAD)
        self.assertIn('fixture_secret', c.failure_result(ValueError('secret fixture_secret'))['message'])

    def test_explicit_redaction_remains_available_for_existing_deployments(self):
        c = self.collector(redaction_enabled=True)
        result = c.execute('192.0.2.1', 'show custom data')
        self.assertNotIn('fixture_password', result['output'])
        self.assertNotIn('fixture_secret', result['output'])

    def test_storage_failure_keeps_every_received_character_without_replaying(self):
        c = self.collector(output_quota_bytes=1, inline_max_chars=100)
        full = 'dữ liệu secret fixture_secret\n' * 1000 + 'router#'
        with patch.object(Connection, 'send_command', return_value=full) as send:
            with self.assertRaises(ValueError) as caught:
                c.execute('192.0.2.1', 'configure custom data', save_output=True)
        result = c.failure_result(caught.exception, '192.0.2.1', 'configure custom data')
        self.assertEqual(result['status'], 'STORAGE_ERROR')
        self.assertEqual(result['output'], full)
        self.assertFalse(result['output_truncated'])
        self.assertEqual(send.call_count, 1)
        self.assertEqual(c.status()['connections_opened'], 1)

    def test_twenty_commands_reuse_one_session_and_report_phases(self):
        c = self.collector()
        results = [c.execute('192.0.2.1', 'show custom data') for _ in range(20)]
        self.assertFalse(results[0]['session_reused'])
        self.assertTrue(all(r['session_reused'] for r in results[1:]))
        status = c.status()
        self.assertEqual(status['connections_opened'], 1)
        self.assertEqual(status['session_reuses'], 19)
        self.assertEqual(status['phase_metrics']['command']['count'], 20)
        self.assertEqual(status['phase_metrics']['connect_prepare']['count'], 1)
        self.assertNotIn('connect_prepare', results[-1]['timings_ms'])

    def test_metrics_window_is_bounded_and_failures_counted(self):
        metrics = PhaseMetrics()
        for i in range(1000): metrics.add('command', i, i % 2 == 0)
        report = metrics.snapshot()['command']
        self.assertEqual(report['count'], 1000)
        self.assertEqual(report['failures'], 500)
        self.assertEqual(report['sample_count'], 128)
        self.assertGreaterEqual(report['p95_ms'], report['p50_ms'])

    def test_close_releases_idle_registry_and_next_call_reconnects(self):
        c = self.collector()
        c.execute('192.0.2.1', 'show custom data')
        self.assertEqual(c.close()['closed'], 1)
        self.assertEqual(c.status()['sessions'], [])
        result = c.execute('192.0.2.1', 'show custom data')
        self.assertTrue(result['ok'])
        self.assertFalse(result['session_reused'])
        self.assertEqual(c.status()['connections_opened'], 2)

    def test_timing_preparation_wrapper_resolves_vendor_after_redispatch(self):
        class Generic:
            def _try_session_preparation(self): return self.session_preparation()
            def session_preparation(self): return 'generic'
        class Vendor(Generic):
            def session_preparation(self): return 'vendor'
        conn = Generic(); timings = {}
        time_connection_method(conn, '_try_session_preparation', 'preparation_ms', timings)
        conn.__class__ = Vendor
        self.assertEqual(conn._try_session_preparation(), 'vendor')
        self.assertIn('preparation_ms', timings)

    def test_parallel_recycled_worker_does_not_carry_previous_request_timings(self):
        c = self.collector(max_workers=1)
        task = {'target': '192.0.2.1', 'command': 'show custom data'}
        first, second = c.parallel([task, task])['results']
        self.assertIn('connect_prepare', first['timings_ms'])
        self.assertNotIn('connect_prepare', second['timings_ms'])
        self.assertTrue(second['session_reused'])


if __name__ == '__main__': unittest.main()
