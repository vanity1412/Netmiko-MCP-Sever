"""Capacity waits, ambiguous prompt transcripts and shared scanner deadlines."""
import concurrent.futures
import json
from pathlib import Path
import sys
import tempfile
import threading
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'mcp'))
import collector_backend as b
import scan
from test_ssh_scenarios import TimelineChannel, VirtualClock
import test_execution_resume as resume
from test_collector import Fake

class ReaderCompletionTests(unittest.TestCase):
    def test_log_prompt_followed_by_channel_eof_can_complete(self):
        for command in ('show logging','show log messages','display logbuffer'):
            with self.subTest(command=command):
                clock=VirtualClock(); conn=TimelineChannel(clock,[(0,'row\nrouter#'),(.02,None)])
                with patch.object(b,'time',SimpleNamespace(monotonic=clock.now,sleep=clock.sleep)):
                    output,failure=b.read_cli_output(conn,command,2,r'(?m)^router#$')
                self.assertIsNone(failure)
                self.assertEqual(output,'row\nrouter#')
    def test_exact_prompt_in_log_with_point_seven_second_continuation_is_not_success(self):
        with tempfile.TemporaryDirectory() as directory:
            clock=VirtualClock()
            conn=TimelineChannel(clock,[(0,'log header\nrouter#'),(.7,'\nremaining log data\nrouter#')])
            c=b.Collector({'defaults':{'output_dir':directory,'session_sweep_seconds':0,
                                      'device_type':'cisco_ios'}},connect_factory=lambda **kw:conn)
            try:
                with patch.object(b,'time',SimpleNamespace(monotonic=clock.now,sleep=clock.sleep)):
                    result=c.execute('192.0.2.1','show logging',read_timeout=2)
                self.assertFalse(result['ok'])
                self.assertFalse(result['output_complete'])
                self.assertEqual(result['error_category'],'output_verification')
                self.assertEqual(result['data_state'],'PARTIAL')
                self.assertEqual(result['output'],'log header\nrouter#')
                self.assertEqual(conn.writes,['show logging\n'])
                self.assertTrue(conn.remote_conn.closed)
            finally:c.shutdown()
    def test_late_log_rows_retained_but_not_certified(self):
        clock=VirtualClock();conn=TimelineChannel(clock,[(0,'historical data\nrouter#'),(.2,'\nLATE DATA\nrouter#')])
        with patch.object(b,'time',SimpleNamespace(monotonic=clock.now,sleep=clock.sleep)):
            output,failure=b.read_cli_output(conn,'show version',2,r'(?m)^router#$')
        self.assertIn('LATE DATA',output)
        self.assertEqual(failure['error_category'],'output_verification')
        self.assertFalse(failure['retryable'])
        self.assertEqual(conn.writes,['show version\n'])
    def test_slow_log_timeout_keeps_partial_data(self):
        clock=VirtualClock();conn=TimelineChannel(clock,[(0,'row\nrouter#'),(.2,'\nmore rows')])
        with patch.object(b,'time',SimpleNamespace(monotonic=clock.now,sleep=clock.sleep)):
            output,failure=b.read_cli_output(conn,'display logbuffer',.5,r'(?m)^router#$')
        self.assertIn('more rows',output)
        self.assertEqual(failure['error_category'],'read_timeout')

class CapacityTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.c=b.Collector({'defaults':{'output_dir':self.tmp.name,'session_sweep_seconds':0},
                            'devices':{}},connect_factory=lambda **kw:Fake())
        self.c.max_sessions=1;self.addCleanup(self.c.shutdown)
    def test_waiter_does_not_hold_guard_and_only_evicts_after_release(self):
        entry,_,_=self.c._reserve_pool_entry('first')
        with concurrent.futures.ThreadPoolExecutor(1) as pool:
            future=pool.submit(self.c._reserve_pool_entry,'second')
            time.sleep(.06)
            self.assertFalse(future.done())
            with self.c._guard:
                self.assertIs(self.c._sessions['first'],entry)
                entry['borrowers']=0
            new,evicted,accepted=future.result(timeout=1)
        self.assertTrue(accepted);self.assertIs(evicted,entry)
        self.assertEqual(new['borrowers'],1)
    def test_capacity_wait_respects_request_deadline(self):
        self.c._reserve_pool_entry('first')
        with self.c.request_budget(timeout=.05):
            with self.assertRaises(TimeoutError):self.c._reserve_pool_entry('second')
        self.assertEqual(set(self.c._sessions),{'first'})
    def test_capacity_wait_observes_cancel(self):
        self.c._reserve_pool_entry('first');cancel=threading.Event()
        with concurrent.futures.ThreadPoolExecutor(1) as pool:
            def wait():
                with self.c.request_budget(timeout=1,cancel=cancel):self.c._reserve_pool_entry('second')
            future=pool.submit(wait);time.sleep(.03);cancel.set()
            with self.assertRaises(concurrent.futures.CancelledError):future.result(timeout=1)
    def test_probe_adoption_waits_for_capacity(self):
        entry,_,_=self.c._reserve_pool_entry('first')
        params={'host':'192.0.2.1','port':22,'device_type':'cisco_ios'};proxy=Fake()
        with concurrent.futures.ThreadPoolExecutor(1) as pool:
            future=pool.submit(self.c._adopt_probe,params,proxy);time.sleep(.04)
            self.assertFalse(future.done())
            with self.c._guard:entry['borrowers']=0
            future.result(timeout=1)
        self.assertIs(self.c._sessions[self.c._session_key(params)]['conn'],proxy)

    def test_probe_capacity_wait_releases_ssh_semaphore(self):
        self.c._ssh_slots=threading.BoundedSemaphore(1)
        entry,_,_=self.c._reserve_pool_entry('first')
        params={'host':'192.0.2.1','port':22,'device_type':'autodetect'}
        proxy=Fake();proxy.close=proxy.disconnect
        with patch('probe_session.ProbeSession',return_value=proxy):
            with concurrent.futures.ThreadPoolExecutor(1) as pool:
                future=pool.submit(self.c._resolve_platform_locked,params)
                try:
                    time.sleep(.05)
                    acquired=self.c._ssh_slots.acquire(timeout=.2)
                    if acquired:self.c._ssh_slots.release()
                    self.assertTrue(acquired,'Capacity wait must not occupy SSH slot')
                finally:
                    with self.c._guard:entry['borrowers']=0
                future.result(timeout=1)
        self.assertEqual(params['device_type'],'juniper_junos')

class DeviceBudgetTests(unittest.TestCase):
    setUp=resume.ResumeTests.setUp
    run_job=resume.ResumeTests.run_job
    records=resume.ResumeTests.records
    def attempt(self,clock,durations,deadlines):
        def fake(*args):
            deadlines.append(args[7][args[2]]['deadline']);clock.value+=durations[len(deadlines)-1]
            return dict(attempt=args[4],lane=args[2],status='failed',retryable=True,
                        error_category='read_timeout',next_command_index=0,result_status='TIMEOUT',
                        result={'ok':False},evidence=[],safe_to_retry=True)
        return fake
    def test_retry_receives_remaining_device_budget(self):
        clock=VirtualClock();deadlines=[]
        with patch.object(scan,'time',SimpleNamespace(monotonic=clock.now)),patch.object(scan,'_attempt',self.attempt(clock,[.6,.5],deadlines)):
            self.run_job([{'target':'good','commands':['show version']}],device_timeout=1)
        self.assertEqual(len(deadlines),2)
        self.assertAlmostEqual(deadlines[1],.4)
        self.assertTrue(self.records()[0]['attempts'][-1]['device_budget_exceeded'])
    def test_expired_device_never_receives_automatic_retry(self):
        clock=VirtualClock();deadlines=[]
        with patch.object(scan,'time',SimpleNamespace(monotonic=clock.now)),patch.object(scan,'_attempt',self.attempt(clock,[1.2],deadlines)):
            self.run_job([{'target':'good','commands':['show version']}],device_timeout=1)
        self.assertEqual(len(deadlines),1)
        self.assertEqual(len(self.records()[0]['attempts']),1)

    def test_resume_preserves_budget_and_completed_prefix(self):
        tasks=[{'target':'good','commands':['show version','show interfaces']}]
        clock=VirtualClock();deadlines=[]
        fake=self.attempt(clock,[.6],deadlines)
        def terminal(*args):
            result=fake(*args);result['retryable']=False;result['next_command_index']=1
            return result
        with patch.object(scan,'time',SimpleNamespace(monotonic=clock.now)),patch.object(scan,'_attempt',terminal):
            self.run_job(tasks,device_timeout=1)
        path=next((self.job/'results').glob('*.json'))
        record=json.loads(path.read_text());record['status']='retry_pending'
        path.write_text(json.dumps(record))
        deadlines=[]
        fake=self.attempt(clock,[.5],deadlines)
        def resumed(*args):
            self.assertEqual(args[8],1)
            return fake(*args)
        with patch.object(scan,'time',SimpleNamespace(monotonic=clock.now)),patch.object(scan,'_attempt',resumed):
            self.run_job(tasks,device_timeout=9)
        self.assertAlmostEqual(deadlines[0],.4)
        self.assertEqual(self.records()[0]['device_budget_seconds'],1)

if __name__=='__main__':unittest.main()
