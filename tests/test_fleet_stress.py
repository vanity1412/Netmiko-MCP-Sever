"""500 and 2,500 virtual devices through scanner, persistence and resume."""
import collections
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import threading
import unittest

from stress_resources import ResourceMonitor

import paramiko
from netmiko.exceptions import ReadTimeout

sys.path.insert(0, str((Path(__file__).resolve().parents[1] / 'mcp')))
import collector_backend as backend
import scan


class FleetStressTests(unittest.TestCase):
    def test_500_mixed_devices_with_faults_evidence_retry_and_resume(self):
        self.run_fleet(500)

    def test_2500_mixed_devices_with_resources_cleanup_and_resume(self):
        self.run_fleet(2500)

    def run_fleet(self, device_count):
        with tempfile.TemporaryDirectory(prefix='noc-stress-') as temporary:
            directory = Path(temporary) / 'job'
            calls = collections.Counter()
            lock = threading.Lock()
            resources = {'live_connections': 0, 'peak_connections': 0}
            devices = {f'fixture-{i:03}': {'host': f'198.18.{i // 250}.{i % 250 + 1}',
                                         'device_type': 'cisco_ios'} for i in range(device_count)}
            reverse = {v['host']: int(k.split('-')[-1]) for k, v in devices.items()}

            class Connection:
                closed = False
                def __init__(self, index, attempt):
                    self.index, self.attempt, self.sequence = index, attempt, 0
                    with lock:
                        resources['live_connections'] += 1
                        resources['peak_connections'] = max(resources['peak_connections'], resources['live_connections'])
                def find_prompt(self): return f'fixture-{self.index:03}#'
                def is_alive(self): return not self.closed
                def disconnect(self):
                    with lock:
                        if not self.closed:
                            self.closed = True
                            resources['live_connections'] -= 1
                def send_command(self, command, **kwargs):
                    self.sequence += 1
                    mode = self.index % 10
                    if mode == 2 and self.attempt == 1: raise ReadTimeout('simulated read timeout')
                    if mode == 4 and self.attempt == 1: raise EOFError('simulated transport EOF')
                    if mode == 5: return command + '\nINCOMPLETE DATA'
                    if mode == 9 or (mode == 1 and self.sequence == 2):
                        return f'% Invalid command\nfixture-{self.index:03}#'
                    body = f'fixture-tag={self.index:03} command={command}\n'
                    if mode == 8: body += 'interface-statistics 123456\n' * 1000
                    if mode == 7: body = command + '\n' + body
                    return body + f'fixture-{self.index:03}#'

            def factory(**params):
                index = reverse[params['host']]
                with lock:
                    calls[index] += 1
                    attempt = calls[index]
                if index % 10 == 0: raise paramiko.AuthenticationException('Authentication failed')
                if index % 10 == 3 and attempt == 1: raise paramiko.AuthenticationException('Authentication timeout')
                return Connection(index, attempt)

            collector = backend.Collector({'defaults': {'output_dir': str(directory / 'raw-output'),
                'max_workers': 16, 'max_sessions': 32, 'session_sweep_seconds': 0,
                'output_storage_mode': 'exclusive'}, 'devices': devices}, connect_factory=factory)
            try:
                tasks = [{'target': target, 'commands': ['show version', 'show interfaces description']} for target in devices]
                with ResourceMonitor(collector) as monitor:
                    result = scan.run_scan(collector, tasks, directory, workers=16, slow_workers=4)
                self.assertEqual((result['success'], result['partial'], result['failed'], result['unknown']), (device_count*6//10, device_count//10, device_count*3//10, 0))
                records = [json.loads(p.read_text(encoding='utf-8')) for p in (directory / 'results').glob('*.json')]
                self.assertEqual(len(records), device_count)
                proofs = 0
                for record in records:
                    index = int(record['target'].split('-')[-1])
                    expected_attempts = 2 if index % 10 in (2, 3, 4) else 1
                    self.assertEqual(len(record['attempts']), expected_attempts)
                    self.assertEqual(calls[index], expected_attempts)
                    for attempt in record['attempts']:
                        for proof in attempt['evidence']:
                            path = directory / proof['file']
                            payload = path.read_bytes()
                            self.assertEqual(hashlib.sha256(payload).hexdigest(), proof['sha256'])
                            if b'fixture-tag=' in payload:
                                self.assertIn(f'fixture-tag={index:03}'.encode(), payload)
                                self.assertNotIn(f'fixture-tag={(index+1)%device_count:03}'.encode(), payload)
                            proofs += 1
                        for command in attempt['result'].get('results', []):
                            if command['ok']: self.assertTrue(command['output_complete'])
                before = dict(calls)
                resumed = scan.run_scan(collector, tasks, directory, workers=16, slow_workers=4)
                self.assertEqual(resumed, result)
                self.assertEqual(dict(calls), before)
                proof = next(p for record in records for attempt in record['attempts'] for p in attempt['evidence'])
                with (directory / proof['file']).open('ab') as handle: handle.write(b'corrupted')
                with self.assertRaisesRegex(ValueError, 'evidence changed'):
                    scan.run_scan(collector, tasks, directory, workers=16, slow_workers=4)
                report = {'virtual_devices': device_count, 'success_expected_and_actual': result['success'],
                          'partial_expected_and_actual': result['partial'], 'failed_expected_and_actual': result['failed'],
                          'unexpected_states': 0, 'ssh_factory_calls': sum(calls.values()),
                          'evidence_files_hash_verified': proofs, 'cross_device_contamination': 0,
                          'resume_reopened_connections': 0, 'corrupted_evidence_rejected': True,
                          'resources': monitor.report(), 'peak_open_connections': resources['peak_connections'],
                          'phase_metrics': collector.status()['phase_metrics']}
                self.assertLessEqual(resources['peak_connections'], collector.max_sessions)
                self.assertLessEqual(monitor.peaks.get('sessions', 0), collector.max_sessions)
                self.assertTrue(all(not e.get('borrowers') for e in collector._sessions.values()))
                collector.shutdown()
                self.assertEqual(resources['live_connections'], 0)
                self.assertEqual(collector.status()['sessions'], [])
                self.assertTrue(all(not t.is_alive() for t in collector._task_pool._threads))
                report.update(sessions_after_shutdown=0, live_connections_after_shutdown=0,
                              resources_after_shutdown=__import__('stress_resources').process_resources())
                destination = os.environ.get('SSH_STRESS_REPORT')
                if destination:
                    path = Path(destination)
                    reports = json.loads(path.read_text(encoding='utf-8')) if path.exists() else {}
                    reports[str(device_count)] = report
                    path.write_text(json.dumps(reports, indent=2), encoding='utf-8')
            finally:
                collector.shutdown()


if __name__ == '__main__': unittest.main()
