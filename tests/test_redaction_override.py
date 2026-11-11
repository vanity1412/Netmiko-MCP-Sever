"""Legacy one-argument overrides must not break CLI/preparation errors."""
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'mcp'))
import collector_backend as b


class LegacyOverrideTests(unittest.TestCase):
    def test_cli_and_preparation_error_accept_single_argument_override(self):
        class Legacy(b.Collector):
            def redact_output(self, message):
                return message
        with tempfile.TemporaryDirectory() as directory:
            c=Legacy({'defaults':{'output_dir':directory,'session_sweep_seconds':0}},
                     connect_factory=lambda **kw:None)
            try:
                result=c._result('fixture','show route','% Invalid command\nrouter#',0)
                self.assertEqual(result['status'],'CLI_ERROR')
                exc=b.CollectionError({'error_category':'read_timeout','error_stage':'preparation',
                    'output':'community 64500:123 secret fixture','preparation_command':'terminal width 511'})
                failed=c.failure_result(exc)
                self.assertEqual(failed['status'],'TIMEOUT')
                self.assertEqual(failed['output'],'community 64500:123 secret fixture')
            finally:c.shutdown()

    def test_disabled_redaction_preserves_routing_identifiers_and_credentials(self):
        text='community 64500:123\nroute-target import 64500:456\npolicy-statement community-policy\npassword fixture-secret'
        with tempfile.TemporaryDirectory() as directory:
            c=b.Collector({'defaults':{'output_dir':directory,'session_sweep_seconds':0}},connect_factory=lambda **kw:None)
            try:
                self.assertEqual(c.redact_output(text,force=True),text)
                self.assertEqual(c.read_output(c._save_output(text))['text'],text)
            finally:c.shutdown()
