"""A pending CLI question must be checked before probing the channel."""
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'mcp'))
from collector_backend import CollectionError, Collector


class PendingPromptGuardTests(unittest.TestCase):
    def test_pending_session_is_rejected_before_policy_or_prompt_probe(self):
        with tempfile.TemporaryDirectory() as folder:
            collector = Collector({'defaults': {'output_dir': folder, 'session_sweep_seconds': 0}},
                                  connect_factory=Mock())
            try:
                conn = Mock()
                conn._network_awaiting_input = True
                with patch.object(collector, 'validate_execution_commands') as validate:
                    with self.assertRaises(CollectionError) as failure:
                        collector._send(conn, 'show interfaces', 2)
                self.assertEqual(failure.exception.details['error_category'], 'awaiting_input')
                self.assertFalse(conn._network_command_sent)
                validate.assert_not_called()
                conn.find_prompt.assert_not_called()
                conn.write_channel.assert_not_called()
            finally:
                collector.shutdown()
