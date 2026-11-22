"""Validate documented calls and evidence-reading contracts without SSH."""
import hashlib
import json
from pathlib import Path
import re
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'mcp'))
import collector_backend as b
from mcp_rpc import handle_rpc, make_tool_list


class WorkflowContractTests(unittest.TestCase):
    def test_documented_examples_validate_against_all_ten_tool_schemas(self):
        try:
            import jsonschema
        except ImportError:
            self.skipTest('Optional JSON Schema validator is not installed')
        text = (ROOT / 'docs/MCP_TOOL_GUIDE.md').read_text(encoding='utf-8')
        examples = [json.loads(block) for block in re.findall(r'```json\s*\n(.*?)\n```', text, re.S)]
        tools = {tool['name']: tool['inputSchema'] for tool in make_tool_list()}
        self.assertEqual(len(examples), 10)
        self.assertEqual({example['name'] for example in examples}, set(tools))
        for example in examples:
            with self.subTest(tool=example['name']):
                self.assertEqual(set(example), {'name', 'arguments'})
                jsonschema.validate(example['arguments'], tools[example['name']])
                if 'output_id' in example['arguments']:
                    b.safe_output_id(example['arguments']['output_id'])
                if example['name'] == 'ssh_parallel':
                    for task in example['arguments']['tasks']:
                        self.assertNotEqual('command' in task, 'commands' in task)

    def test_local_links_in_core_and_reference_documents_resolve(self):
        files = ['AGENTS.md', 'README.md', 'mcp/WORKFLOW.md', 'docs/EVIDENCE.md',
                 'docs/RECOVERY.md', 'docs/MCP_TOOL_GUIDE.md', 'docs/REPORTING.md',
                 'docs/NETWORK_REASONING.md']
        for filename in files:
            path = ROOT / filename
            text = re.sub(r'```.*?```', '', path.read_text(encoding='utf-8'), flags=re.S)
            for target in re.findall(r'\[[^\]]+\]\(([^)]+)\)', text):
                target = target.strip('<>').split('#', 1)[0]
                if not target or re.match(r'[a-z]+:', target, re.I):
                    continue
                with self.subTest(file=filename, target=target):
                    self.assertTrue((path.parent / target).is_file())

    def test_search_limits_and_byte_paging_preserve_full_raw(self):
        with tempfile.TemporaryDirectory() as directory:
            def no_ssh(**kwargs):
                raise AssertionError('Documentation checks must not open SSH')
            c = b.Collector({'defaults': {'output_dir': directory, 'session_sweep_seconds': 0}},
                            connect_factory=no_ssh)
            try:
                payload = 'route route\n' * 50 + 'mạng ' * 50000 + 'needle\n'
                oid = c._save_output(payload, already_redacted=True)
                raw_path = Path(directory) / (oid + '.txt')
                digest = hashlib.sha256(raw_path.read_bytes()).hexdigest()
                matches = c.search_output(oid, 'route', max_matches=1, context_lines=0)
                self.assertEqual(matches['total_matches'], 50)  # Matching lines, not 100 occurrences.
                self.assertEqual(matches['shown_matches'], 1)
                self.assertEqual(matches['excerpt'][0]['line'], 1)
                self.assertNotIn('more', matches)
                long_match = c.search_output(oid, 'needle', context_lines=0)
                self.assertEqual(long_match['total_matches'], 1)
                self.assertNotIn('needle', long_match['excerpt'][0]['text'])
                self.assertFalse(long_match['truncated'])  # Per-line truncation has no separate flag.
                row = c.read_output(oid, offset=50, limit=1)
                self.assertTrue(row['oversized_line'])
                self.assertEqual(row['next_offset'], 50)
                self.assertTrue(row['more'])
                offset, parts = 0, []
                while True:
                    chunk = c.read_output_bytes(oid, byte_offset=offset, length=64000)
                    parts.append(chunk['text'])
                    self.assertGreater(chunk['next_byte_offset'], offset)
                    offset = chunk['next_byte_offset']
                    if not chunk['more']:
                        break
                restored = ''.join(parts).encode('utf-8')
                self.assertEqual(hashlib.sha256(restored).hexdigest(), digest)
                self.assertEqual(restored, payload.encode('utf-8'))
                self.assertEqual(hashlib.sha256(raw_path.read_bytes()).hexdigest(), digest)
            finally:
                c.shutdown()
