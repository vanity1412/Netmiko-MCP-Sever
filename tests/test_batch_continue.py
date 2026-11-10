"""Independent batch commands, explicit unsent results and session integrity."""
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'mcp'))
import collector_backend as b
from result_status import normalize_result
from test_collector import Fake
import test_execution_resume as resume_fixtures
import test_ssh_reliability as ssh_fixtures


class BatchContinueTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.conn = Fake(); self.opens = 0
        def connect(**kw):
            self.opens += 1
            return self.conn
        self.c = b.Collector({'defaults': {'device_type': 'juniper_junos',
            'output_dir': self.tmp.name, 'session_sweep_seconds': 0}}, connect_factory=connect)
        self.addCleanup(self.c.shutdown)

    def test_default_stops_marks_suffix_and_reuses_healthy_session(self):
        with self.assertRaises(b.BatchError) as caught:
            self.c.execute_many('fixture', ['show version', 'show system bad', 'show interfaces'])
        r = caught.exception.results
        self.assertEqual([x['status'] for x in r], ['SUCCESS', 'CLI_ERROR', 'SKIPPED'])
        self.assertEqual(r[-1]['execution_state'], 'NOT_SENT')
        self.assertFalse(r[-1]['command_sent'])
        self.assertEqual(r[-1]['blocked_by_command_index'], 1)
        self.assertNotIn('show interfaces', self.conn.commands)
        self.assertTrue(self.c.execute('fixture', 'show version')['ok'])
        self.assertEqual(self.opens, 1)

    def test_continue_cli_denial_runs_next_and_keeps_unredacted_evidence(self):
        r = self.c.execute_many('fixture', ['show version','show system bad','show interfaces'],
                                continue_on_error=True, save_output=True)
        self.assertEqual([x['status'] for x in r['results']], ['SUCCESS','CLI_ERROR','SUCCESS'])
        self.assertEqual(r['status'], 'PARTIAL'); self.assertFalse(r['ok'])
        self.assertEqual(r['successes'], 2)
        self.assertEqual(self.opens, 1)
        self.assertTrue(self.c.execute('fixture', 'show version')['session_reused'])

    def test_all_failed_cli_errors_never_report_success(self):
        r = self.c.execute_many('fixture', ['show system bad']*3, continue_on_error=True)
        self.assertEqual(r['status'], 'CLI_ERROR'); self.assertEqual(r['successes'], 0)
        self.assertEqual(len(self.conn.commands), 3)

    def test_incomplete_output_still_stops(self):
        with self.assertRaises(b.BatchError) as caught:
            self.c.execute_many('fixture', ['show system partial','show version'],continue_on_error=True)
        self.assertEqual(caught.exception.results[1]['status'], 'SKIPPED')
        self.assertFalse(caught.exception.results[0]['output_complete'])
        self.assertIn('PARTIAL', caught.exception.results[0]['output'])
        self.assertFalse(self.conn.alive)

    def test_confirmation_stops_without_sending_suffix_and_keeps_pending_session(self):
        with self.assertRaises(b.BatchError) as caught:
            self.c.execute_many('fixture', ['show system confirm','show version'],continue_on_error=True)
        self.assertEqual(caught.exception.results[0]['status'], 'AWAITING_INPUT')
        self.assertEqual(caught.exception.results[1]['status'], 'SKIPPED')
        self.assertEqual(self.conn.commands, ['show system confirm'])
        self.assertTrue(self.conn.alive)

    def test_timeout_and_disconnect_stop_even_when_continuation_requested(self):
        for failure in (TimeoutError('read timed out'), EOFError('lost transport')):
            with self.subTest(failure=type(failure).__name__):
                self.c.close(); self.conn = Fake()
                with patch.object(self.conn, 'send_command', side_effect=failure):
                    with self.assertRaises(b.BatchError) as caught:
                        self.c.execute_many('fixture', ['configure','show version'],continue_on_error=True)
                r = caught.exception.results
                self.assertEqual(r[0]['status'], 'UNKNOWN')
                self.assertIn(r[0]['fault_status'], ('TIMEOUT','CONNECT_ERROR'))
                self.assertEqual(r[1]['status'], 'SKIPPED')
                self.assertFalse(self.conn.alive)

    def test_storage_failure_keeps_output_and_skips_next(self):
        self.c.output_quota = 1
        with self.assertRaises(b.BatchError) as caught:
            self.c.execute_many('fixture', ['show version','show interfaces'],
                                continue_on_error=True, save_output=True)
        self.assertEqual(caught.exception.results[0]['status'], 'STORAGE_ERROR')
        self.assertIn('MOCK DATA', caught.exception.results[0]['output'])
        self.assertEqual(caught.exception.results[1]['status'], 'SKIPPED')

    def test_rpc_reports_partial_and_unsent_results(self):
        reply = b.handle_rpc({'jsonrpc':'2.0','id':1,'method':'tools/call','params':{
            'name':'ssh_execute_many','arguments':{'target':'fixture',
            'commands':['show system bad','show version']}}}, self.c)
        self.assertTrue(reply['result']['isError'])
        r = json.loads(reply['result']['content'][0]['text'])
        self.assertEqual(r['status'], 'CLI_ERROR')
        self.assertEqual(r['status_counts'], {'CLI_ERROR':1,'SKIPPED':1})

    def test_invalid_option_rejected_before_ssh(self):
        for option in ('true', 1, None):
            with self.assertRaises(ValueError):
                self.c.execute_many('fixture',['show version'],continue_on_error=option)
        self.assertEqual(self.opens, 0)

    def test_parallel_batch_task_forwards_continuation_flag(self):
        r=self.c.parallel([{'target':'fixture','commands':['show system bad','show version'],
                            'continue_on_error':True}])
        self.assertFalse(r['ok'])
        self.assertEqual([x['status'] for x in r['results'][0]['results']],['CLI_ERROR','SUCCESS'])

    def test_skipped_status_is_idempotent(self):
        r=normalize_result({'skipped':True,'ok':False})
        self.assertEqual(r['status'], 'SKIPPED')
        self.assertEqual(normalize_result(dict(r)), r)


class BatchResumeTests(resume_fixtures.ResumeTests):
    def test_skipped_blocker_index_is_rebased_after_resuming_prefix(self):
        tasks=[{'target':'bad','commands':['show version','show interfaces','show clock','show route']}]
        self.run_job(tasks)
        self.fail=False; self.c.close()
        connect=self.c._connect
        def factory(**kw):
            conn=connect(**kw); original=conn.send_command
            def send(command,**options):
                return '% Invalid command\nedge#' if command=='show clock' else original(command,**options)
            conn.send_command=send
            return conn
        self.c._connect=factory
        self.run_job(tasks,retry_statuses={'partial'})
        results=self.records()[0]['attempts'][-1]['result']['results']
        self.assertEqual([r['command_index'] for r in results],[1,2,3])
        self.assertEqual(results[-1]['status'],'SKIPPED')
        self.assertEqual(results[-1]['blocked_by_command_index'],2)

    def test_skipped_suffix_does_not_hide_failure_or_advance_resume(self):
        tasks=[{'target':'bad','commands':['show version','show interfaces','show clock']}]
        self.assertEqual(self.run_job(tasks)['partial'],1)
        record=self.records()[0]
        self.assertEqual(record['next_command_index'],1)
        self.assertEqual(record['attempts'][0]['error_category'],'cli_error')
        self.assertEqual(record['attempts'][0]['result']['results'][-1]['status'],'SKIPPED')
        self.fail=False
        self.assertTrue(self.run_job(tasks,retry_statuses={'partial'})['ok'])
        self.assertEqual(self.calls['192.0.2.2','show version'],1)
        self.assertEqual(self.calls['192.0.2.2','show clock'],1)


class LoopbackBatchTests(unittest.TestCase):
    setUpClass=classmethod(ssh_fixtures.RealSSHTests.setUpClass.__func__)
    setUp=ssh_fixtures.RealSSHTests.setUp
    collector=ssh_fixtures.RealSSHTests.collector

    def test_localhost_denial_continues_with_same_login(self):
        self.server.responses['show denied'] = '% Authorization failed.'
        c=self.collector('linux')
        r=c.execute_many('local',['show denied','uname -s'],continue_on_error=True)
        self.assertEqual([x['status'] for x in r['results']],['CLI_ERROR','SUCCESS'])
        self.assertEqual(self.server.auth_attempts,1)
        self.assertTrue(c.execute('local','uname -s')['ok'])
        self.assertEqual(self.server.auth_attempts,1)


if __name__ == '__main__': unittest.main()
