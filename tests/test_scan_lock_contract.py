"""Scanner crash/contender regressions, using temporary files and no SSH."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

MCP = Path(__file__).resolve().parents[1] / 'mcp'
sys.path.insert(0, str(MCP))
import scan
import collector_backend as backend


class ScanLockTests(unittest.TestCase):
    def test_crash_releases_lock_and_contender_cannot_enter(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'scan.lock'
            child = subprocess.Popen([sys.executable, '-u', '-c',
                'import sys;sys.path.insert(0,sys.argv[1]);import scan;'
                '\nwith scan.scan_lock(sys.argv[2]):\n print("ready",flush=True);sys.stdin.readline()',
                str(MCP), str(path)], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, text=True)
            try:
                self.assertEqual(child.stdout.readline().strip(), 'ready')
                with self.assertRaises(TimeoutError):
                    with scan.scan_lock(path):
                        self.fail('Concurrent scanner entered')
                child.kill()
                child.communicate(timeout=10)
                self.assertTrue(path.exists())
                with scan.scan_lock(path):
                    pass
                with scan.scan_lock(path):
                    pass
            finally:
                if child.poll() is None:
                    child.kill()
                child.communicate(timeout=10)

    def test_legacy_lock_is_preserved(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'scan.lock'
            path.write_text('12345', encoding='ascii')
            with self.assertRaisesRegex(FileExistsError, 'Legacy'):
                with scan.scan_lock(path):
                    self.fail('Legacy lock bypassed')
            self.assertEqual(path.read_text(), '12345')

    def test_exception_releases_lock(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'scan.lock'
            with self.assertRaisesRegex(RuntimeError, 'fixture'):
                with scan.scan_lock(path):
                    raise RuntimeError('fixture')
            with scan.scan_lock(path):
                pass


class ToolContractTests(unittest.TestCase):
    def test_all_ten_schemas_match_reviewed_contract(self):
        actual = [{'name': t['name'], 'inputSchema': t['inputSchema']}
                  for t in backend.make_tool_list()]
        expected = json.loads((MCP.parent / 'tests/tool-schema-v1.json').read_text(encoding='utf-8'))
        self.assertEqual(len(actual), 10)
        self.assertEqual(actual, expected)
        tools = {t['name']: t['inputSchema'] for t in actual}
        task = tools['ssh_parallel']['properties']['tasks']['items']
        self.assertEqual(task['properties']['continue_on_error'], {'type': 'boolean'})
        self.assertNotIn('continue_on_error', task['required'])
        self.assertEqual(tools['ssh_interact']['properties']['steps']['items'], {'type': 'string'})

    def test_schema_examples_when_jsonschema_available(self):
        try:
            import jsonschema
        except ImportError:
            self.skipTest('Optional JSON Schema validator is not installed')
        tools = {t['name']: t['inputSchema'] for t in backend.make_tool_list()}
        examples = {
            'ssh_execute': {'target': 'fixture', 'command': 'show version'},
            'ssh_execute_many': {'target': 'fixture', 'commands': ['show version']},
            'ssh_interact': {'target': 'fixture', 'steps': ['configure', 'exit']},
            'ssh_parallel': {'tasks': [{'target': 'fixture', 'commands': ['show version'], 'continue_on_error': True}]},
            'ssh_inventory': {}, 'ssh_status': {}, 'ssh_close': {'target': 'fixture'},
            'ssh_read_output': {'output_id': 'fixture'},
            'ssh_read_output_bytes': {'output_id': 'fixture'},
            'ssh_search_output': {'output_id': 'fixture', 'query': 'version'},
        }
        for name, schema in tools.items():
            with self.subTest(name=name):
                jsonschema.Draft202012Validator.check_schema(schema)
                jsonschema.validate(examples[name], schema)
                with self.assertRaises(jsonschema.ValidationError):
                    jsonschema.validate({**examples[name], 'unknown_field': True}, schema)
        for bad in ('yes', 1, None):
            with self.assertRaises(jsonschema.ValidationError):
                jsonschema.validate({'tasks': [{'target': 'fixture', 'continue_on_error': bad}]}, tools['ssh_parallel'])
        with self.assertRaises(jsonschema.ValidationError):
            jsonschema.validate({'target': 'fixture', 'steps': [{'command': 'exit'}]}, tools['ssh_interact'])
