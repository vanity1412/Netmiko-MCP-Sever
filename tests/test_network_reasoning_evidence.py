"""Replay synthetic reasoning inputs through real MCP/evidence APIs, never an LLM.

The reference engineering assessment lives in docs/NETWORK_REASONING.md.
Passing these tests verifies evidence delivery, not autonomous diagnosis quality.
"""
import collections
import hashlib
import json
from pathlib import Path
import socket
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'mcp'))
import collector_backend as b
from mcp_rpc import handle_rpc, make_tool_list

CASES = json.loads((ROOT / 'tests/network_reasoning_cases.json').read_text(encoding='utf-8'))['cases']


class NetworkReasoningEvidenceTests(unittest.TestCase):
    def replay(self, case):
        """Return actual results/raw keyed by source ID, preserving source order."""
        replies = collections.defaultdict(collections.deque)
        devices = {}
        for source in case['evidence']:
            target = source['target']
            host = target.lower() + '.invalid'
            devices[target] = dict(host=host, device_type=source['device_type'])
            replies[host, source['command']].append(source['raw'])
        sent = []

        class Connection:
            def __init__(self, host, driver):
                self.host, self.device_type, self.closed = host, driver, False
            def find_prompt(self):
                target = next(t for t, d in devices.items() if d['host'] == self.host)
                return target + ('>' if self.device_type == 'juniper_junos' else '#')
            def is_alive(self): return not self.closed
            def disconnect(self): self.closed = True
            def send_command(self, command, **options):
                sent.append((self.host, command))
                return replies[self.host, command].popleft()

        def connect(**params):
            self.assertIn(params['host'], {d['host'] for d in devices.values()})
            return Connection(params['host'], params['device_type'])

        actual = {}
        with tempfile.TemporaryDirectory() as folder, \
                patch.object(socket.socket, 'connect', side_effect=AssertionError('No network')), \
                patch.object(socket.socket, 'connect_ex', side_effect=AssertionError('No network')), \
                patch('probe_session.ProbeSession', side_effect=AssertionError('No discovery')):
            c = b.Collector({'defaults': {'execution_policy': 'read_write', 'output_dir': folder,
                                          'session_sweep_seconds': 0},
                             'devices': devices}, connect_factory=connect)
            try:
                for source in case['evidence']:
                    args = dict(target=source['target'], command=source['command'], save_output=True)
                    response = handle_rpc({'jsonrpc': '2.0', 'id': source['id'],
                        'method': 'tools/call', 'params': {'name': 'ssh_execute', 'arguments': args}}, c)
                    self.assertEqual(response['id'], source['id'])
                    result = json.loads(response['result']['content'][0]['text'])
                    self.assertEqual(result['status'], source['expected_status'])
                    self.assertEqual(response['result']['isError'], source['expected_status'] != 'SUCCESS')
                    self.assertEqual((result['target'], result['command']),
                                     (source['target'], source['command']))
                    path = Path(folder) / (result['output_id'] + '.txt')
                    expected = source['raw'].encode('utf-8')
                    self.assertEqual(path.read_bytes(), expected)
                    offset, parts = 0, []
                    while True:
                        chunk = c.read_output_bytes(result['output_id'], offset, 17)
                        parts.append(chunk['text'])
                        offset = chunk['next_byte_offset']
                        if not chunk['more']: break
                    raw = ''.join(parts)
                    self.assertEqual(hashlib.sha256(raw.encode()).digest(), hashlib.sha256(expected).digest())
                    actual[source['id']] = (result, raw)
                self.assertEqual(len(sent), len(case['evidence']))  # No replay/config/implicit probes.
                self.assertTrue(all(not pending for pending in replies.values()))
            finally:
                c.shutdown()
            self.assertEqual(c.status()['sessions'], [])
        return actual

    def test_all_eight_scenarios_deliver_original_scoped_evidence(self):
        self.assertEqual(len(CASES), 8)
        for case in CASES:
            with self.subTest(case=case['id']):
                self.replay(case)

    def test_wrong_vrf_and_healthy_default_are_different_successful_cli_data(self):
        scenarios = {}
        for case in CASES[:2]:
            actual = self.replay(case)
            self.assertTrue(all(result['ok'] for result, raw in actual.values()))
            scenarios[case['id']] = actual
        wrong = scenarios['wrong_vrf']
        self.assertIn('Network not in table', wrong['wrong_vrf-e3'][1])
        self.assertIn('203.0.113.2', wrong['wrong_vrf-e2'][1])
        self.assertIn('0.0.0.0/0', scenarios['healthy']['healthy-e1'][1])

    def test_zero_search_on_partial_does_not_upgrade_collection(self):
        case = next(c for c in CASES if c['id'] == 'missing')
        actual = self.replay(case)
        result, raw = actual['missing-e1']
        self.assertFalse(result['output_complete'])
        self.assertEqual(result['data_state'], 'PARTIAL')
        self.assertEqual(actual['missing-e2'][0]['error_reason'], 'permission_denied')
        with tempfile.TemporaryDirectory() as folder:
            c = b.Collector({'defaults': {'output_dir': folder, 'session_sweep_seconds': 0}},
                            connect_factory=lambda **kw: self.fail('Unexpected connection'))
            try:
                oid = c._save_output(raw)
                self.assertEqual(c.search_output(oid, 'vrf-target')['total_matches'], 0)
                self.assertFalse(result['output_complete'])
                self.assertEqual(c.read_output(oid)['text'], raw)
            finally:
                c.shutdown()


if __name__ == '__main__':
    unittest.main()
