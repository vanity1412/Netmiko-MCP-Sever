"""500 virtual devices through the real scanner, persistence and resume pipeline."""
import collections
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import threading
import unittest

import paramiko
from netmiko.exceptions import ReadTimeout

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import collector_backend as backend
import scan


class FleetStressTests(unittest.TestCase):
    def test_500_mixed_devices_with_faults_evidence_retry_and_resume(self):
        with tempfile.TemporaryDirectory(prefix='noc-stress-') as temporary:
            directory = Path(temporary) / 'job'
            calls = collections.Counter()
            lock = threading.Lock()
            devices = {f'fixture-{i:03}': {'host': f'198.18.{i // 250}.{i % 250 + 1}',
                                         'device_type': 'cisco_ios'} for i in range(500)}
            reverse = {v['host']: int(k.split('-')[-1]) for k, v in devices.items()}

            class Connection:
                closed = False
                def __init__(self, index, attempt): self.index, self.attempt, self.sequence = index, attempt, 0
                def find_prompt(self): return f'fixture-{self.index:03}#'
                def is_alive(self): return not self.closed
                def disconnect(self): self.closed = True
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
                'max_workers': 16, 'max_sessions': 32, 'session_sweep_seconds': 0}, 'devices': devices}, connect_factory=factory)
            try:
                tasks = [{'target': target, 'commands': ['show version', 'show interfaces description']} for target in devices]
                result = scan.run_scan(collector, tasks, directory, workers=16, slow_workers=4)
                self.assertEqual((result['success'], result['partial'], result['failed'], result['unknown']), (300, 50, 150, 0))
                records = [json.loads(p.read_text(encoding='utf-8')) for p in (directory / 'results').glob('*.json')]
                self.assertEqual(len(records), 500)
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
                                self.assertNotIn(f'fixture-tag={(index+1)%500:03}'.encode(), payload)
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
                report = {'virtual_devices': 500, 'success_expected_and_actual': 300,
                          'partial_expected_and_actual': 50, 'failed_expected_and_actual': 150,
                          'unexpected_states': 0, 'ssh_factory_calls': sum(calls.values()),
                          'evidence_files_hash_verified': proofs, 'cross_device_contamination': 0,
                          'resume_reopened_connections': 0, 'corrupted_evidence_rejected': True}
                destination = os.environ.get('SSH_STRESS_REPORT')
                if destination:
                    Path(destination).write_text(json.dumps(report, indent=2), encoding='utf-8')
            finally:
                collector.shutdown()


if __name__ == '__main__': unittest.main()
