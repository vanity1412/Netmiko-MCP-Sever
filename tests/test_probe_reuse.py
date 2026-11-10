"""Real SSH: one login for probe+collection, killable RPC and partial evidence."""
import concurrent.futures
import json
from pathlib import Path
import sys
import threading
import time
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'mcp'))
import collector_backend as b
import probe_session
import test_ssh_reliability as fixtures

import unittest
class ChannelEncodingTests(unittest.TestCase):
    def test_utf8_split_at_every_byte_is_preserved(self):
        from netmiko.channel import SSHChannel
        from types import SimpleNamespace
        from unittest.mock import Mock
        text='mạng-đường-truyền 日本語 😃\r\nrouter#'
        wire=text.encode('utf-8')
        for split in range(1,len(wire)):
            with self.subTest(split=split):
                remote=Mock()
                remote.recv_ready.return_value=True
                remote.recv.side_effect=[wire[:split],wire[split:]]
                channel=SSHChannel(conn=remote,encoding='utf-8')
                b.preserve_channel_encoding(SimpleNamespace(channel=channel))
                self.assertEqual(channel.read_buffer()+channel.read_buffer(),text)

class ReuseOnly(unittest.TestCase):
    setUpClass=classmethod(fixtures.RealSSHTests.setUpClass.__func__)
    setUp=fixtures.RealSSHTests.setUp
    collector=fixtures.RealSSHTests.collector
    def test_probe_and_commands_share_one_login(self):
        c=self.collector('autodetect')
        self.assertTrue(c.execute_many('local',['uname -s','uptime','ip route show'],read_timeout=3)['ok'])
        reused = c.execute('local','uname -s')
        self.assertTrue(reused['ok'])
        self.assertTrue(reused['session_reused'])
        self.assertIn('authentication_ms', reused['connection_timings_ms'])
        self.assertIn('ssh_connect_ms', reused['connection_timings_ms'])
        self.assertIn('preparation_ms', reused['connection_timings_ms'])
        self.assertNotIn('authentication', reused['timings_ms'])
        self.assertEqual(self.server.auth_attempts,1)
        self.assertEqual(c.status()['connections_opened'],1)
        self.assertEqual(c.status()['autodetect_probes'],1)
        proxy=next(iter(c._sessions.values()))['conn']
        c.shutdown()
        self.assertIsNotNone(proxy._process.poll())
    def test_request_deadline_kills_worker_and_keeps_partial(self):
        c=self.collector('autodetect')
        c.execute('local','uname -s')
        proxy=next(iter(c._sessions.values()))['conn']
        started=time.monotonic()
        with c.request_budget(timeout=.25):
            result=c.execute('local','hostname',read_timeout=10,save_output=True)
        self.assertFalse(result['ok'])
        # The command read budget is also clamped to the request budget.
        self.assertIn(result['error_category'], ('deadline', 'read_timeout'))
        saved=Path(self.tmp.name)/(result['output_id']+'.txt')
        self.assertIn('partial-hostname',saved.read_text())
        self.assertLess(time.monotonic()-started,2)
        self.assertIsNotNone(proxy._process.poll())
        self.assertNotIn('exit',self.server.commands)
        self.assertTrue(c.execute('local','uname -s')['ok'])
        self.assertEqual(self.server.auth_attempts,2)
    def test_cancellation_kills_worker_and_preserves_partial(self):
        c=self.collector('autodetect');c.execute('local','uname -s')
        event=threading.Event();timer=threading.Timer(.2,event.set)
        timer.start()
        try:
            with c.request_budget(cancel=event):result=c.execute('local','hostname',read_timeout=10)
        finally:timer.cancel()
        self.assertFalse(result['ok'])
        self.assertEqual(result['error_category'],'cancelled')
        self.assertIn('partial-hostname',result['output'])
        self.assertFalse(c.status()['sessions'])
    def test_probe_deadline_reaps_child(self):
        self.server.banner_delay=2
        c=self.collector('autodetect');workers=[]
        original=probe_session.subprocess.Popen
        def spawn(*args,**kwargs):
            child=original(*args,**kwargs);workers.append(child);return child
        started=time.monotonic()
        with patch.object(probe_session.subprocess,'Popen',spawn):
            with c.request_budget(autodetect_timeout=.3):
                with self.assertRaises(TimeoutError):c.execute('local','uname -s')
        self.assertLess(time.monotonic()-started,2)
        self.assertTrue(workers)
        self.assertTrue(all(p.poll() is not None for p in workers))
    def test_concurrent_same_target_does_not_probe_twice(self):
        c=self.collector('autodetect')
        with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
            results=list(pool.map(lambda _:c.execute('local','uname -s'),range(3)))
        self.assertTrue(all(r['ok'] for r in results))
        self.assertEqual(self.server.auth_attempts,1)

    def test_probe_replaces_idle_empty_pool_entry(self):
        c=self.collector('autodetect');c.max_sessions=1
        key=c._session_key(c._get_settings('local','linux',None))
        c._sessions[key]={'lock':threading.RLock(),'conn':None,'borrowers':0,
                          'used':time.monotonic(),'created':0}
        self.assertTrue(c.execute('local','uname -s')['ok'])
        self.assertEqual(self.server.auth_attempts,1)
        self.assertEqual(len(c._sessions),1)
    def test_confirmation_never_receives_cleanup_text(self):
        c=self.collector('autodetect');c.execute('local','uname -s')
        result=c.execute('local','date')
        self.assertFalse(result['ok'])
        self.assertFalse(result['output_complete'])
        self.assertNotIn('exit',self.server.commands)
    def test_child_exit_mid_command_is_not_success(self):
        c=self.collector('autodetect');c.execute('local','uname -s')
        proxy=next(iter(c._sessions.values()))['conn']
        timer=threading.Timer(.2,proxy._process.kill);timer.start()
        try:result=c.execute('local','hostname',read_timeout=10)
        finally:timer.cancel()
        self.assertFalse(result['ok'])
        self.assertEqual(result['recovery_attempts'],1)
        self.assertEqual(result['previous_attempt']['error_category'],'connection_lost')
        self.assertEqual(result['error_category'],'read_timeout')
        self.assertFalse(result['output_complete'])
        self.assertIn('partial-hostname',result['output'])
    def test_disk_cache_hit_opens_only_collection_session(self):
        c=self.collector('autodetect');c.execute('local','uname -s');c.shutdown()
        other=self.collector('autodetect');other.execute('local','uname -s')
        self.assertEqual(other.status()['autodetect_probes'],0)
        self.assertEqual(other.status()['persistent_autodetect_hits'],1)
        self.assertEqual(self.server.auth_attempts,2)

    def test_mcp_script_preserves_authentication_failure_category(self):
        c=self.collector('autodetect')
        config=dict(c.config,defaults=dict(c.defaults,password='wrong-local-test-password'))
        path=Path(self.tmp.name)/'config.json'
        path.write_text(json.dumps(config),encoding='utf-8')
        request={'jsonrpc':'2.0','id':1,'method':'tools/call',
                 'params':{'name':'ssh_execute','arguments':{'target':'local','command':'uname -s'}}}
        run=probe_session.subprocess.run([sys.executable,str(Path(b.__file__)),'--config',str(path)],
            input=json.dumps(request)+'\n',text=True,encoding='utf-8',capture_output=True,timeout=15)
        self.assertEqual(run.returncode,0)
        reply=json.loads(run.stdout)['result']
        self.assertTrue(reply['isError'])
        result=json.loads(reply['content'][0]['text'])
        self.assertEqual(result['error_category'],'authentication')
        self.assertEqual(result['error_stage'],'authentication')
        self.assertEqual(self.server.auth_attempts,1)

    def test_vendor_redispatch_reuses_authenticated_transport(self):
        vendors = [('cisco_ios', 'router#', 'show version', 'Cisco IOS Software'),
                   ('cisco_xr', 'RP/0/RP0/CPU0:router#', 'show version', 'Cisco IOS XR'),
                   ('cisco_nxos', 'router#', 'show version', 'Cisco Nexus NX-OS'),
                   ('huawei', '<router>', 'display version', 'Huawei VRP Software'),
                   ('juniper_junos', 'noc@router>', 'show version', 'Junos: 23.4R1')]
        for driver, prompt, command, response in vendors:
            with self.subTest(driver=driver):
                self.server.close()
                self.server = fixtures.LocalSSHServer(self.key)
                self.addCleanup(self.server.close)
                self.server.prompt = prompt
                self.server.responses[command] = response
                c = self.collector('autodetect')
                result = c.execute('local', command, read_timeout=3)
                self.assertTrue(result['ok'], result)
                self.assertIn(response, result['output'])
                self.assertEqual(next(iter(c._sessions.values()))['conn'].device_type, driver)
                self.assertEqual(self.server.auth_attempts, 1)
                c.shutdown()

    def test_large_unicode_output_and_timing_steps_are_complete(self):
        c=self.collector('autodetect');c.execute('local','uname -s')
        content=('interface mạng-đường-truyền IPv6 2001:db8::1\r\n' * 2500)
        self.server.responses['hostname'] = content
        result=c.execute('local','hostname',read_timeout=5,save_output=True)
        self.assertTrue(result['ok'], result)
        saved=Path(self.tmp.name)/(result['output_id']+'.txt')
        self.assertEqual(saved.read_text(encoding='utf-8').count('mạng-đường-truyền'),2500)
        result=c.interact('local',['uname -s','uptime'],read_timeout=3)
        self.assertTrue(result['ok'], result)
        self.assertEqual(self.server.auth_attempts,1)

    def test_read_timeout_stops_batch_and_reaps_worker(self):
        c=self.collector('autodetect');c.execute('local','uname -s')
        proxy=next(iter(c._sessions.values()))['conn']
        before=self.server.commands.count('uname -s')
        with self.assertRaises(b.BatchError) as caught:
            c.execute_many('local',['hostname','uname -s'],read_timeout=1)
        result=caught.exception.results[0]
        self.assertFalse(result['ok'])
        self.assertIn('partial-hostname', result['output'])
        self.assertEqual(self.server.commands.count('uname -s'),before)
        self.assertIsNotNone(proxy._process.poll())

    def test_hung_worker_is_killed_even_if_partial_contains_prompt(self):
        script = '''import json, sys, time
json.loads(sys.stdin.readline())
print(json.dumps({'device_type':'linux','prompt':'router#'}),flush=True)
json.loads(sys.stdin.readline())
print(json.dumps({'event':'data','data':'partial result\\nrouter#'}),flush=True)
time.sleep(60)
'''
        spawn=probe_session.subprocess.Popen
        def stub(*args, **kwargs):
            return spawn([sys.executable,'-u','-c',script], **kwargs)
        with patch.object(probe_session.subprocess,'Popen',stub):
            proxy=probe_session.ProbeSession({},lambda:None,3)
        self.addCleanup(proxy.close)
        start=time.monotonic()
        output,failure=proxy.collect_in_worker('hostname',.1,r'router#$',.03,lambda:None)
        self.assertLess(time.monotonic()-start,2)
        self.assertIn('partial result',output)
        self.assertEqual(failure['error_category'],'deadline')
        self.assertIsNotNone(proxy._process.poll())

    def test_idle_reaper_terminates_worker(self):
        c=self.collector('autodetect');c.execute('local','uname -s')
        entry=next(iter(c._sessions.values()));proxy=entry['conn']
        c.session_ttl=1;entry['used']=time.monotonic()-2
        self.assertEqual(c._reap_idle(),1)
        self.assertIsNotNone(proxy._process.poll())

    def test_verified_cli_error_keeps_session(self):
        c=self.collector('autodetect');c.execute('local','uname -s')
        self.server.responses['hostname']='% Invalid input'
        result=c.execute('local','hostname')
        self.assertFalse(result['ok'])
        self.assertEqual(result['error_category'],'cli_error')
        self.assertTrue(result['output_complete'])
        self.assertTrue(c.execute('local','uname -s')['ok'])
        self.assertEqual(self.server.auth_attempts,1)

    def test_redispatch_preparation_obeys_probe_deadline(self):
        self.server.responses['show version']='Cisco IOS Software'
        self.server.responses['terminal width 511']=lambda ch:ch.sendall(b'incomplete setup\r\n')
        c=self.collector('autodetect');workers=[]
        spawn=probe_session.subprocess.Popen
        def record(*args,**kwargs):
            child=spawn(*args,**kwargs);workers.append(child);return child
        start=time.monotonic()
        with patch.object(probe_session.subprocess,'Popen',record):
            with c.request_budget(autodetect_timeout=3):
                with self.assertRaises(TimeoutError):c.execute('local','show version')
        self.assertLess(time.monotonic()-start,5)
        self.assertIn('terminal width 511',self.server.commands)
        self.assertTrue(all(child.poll() is not None for child in workers))
        self.assertFalse(c.status()['sessions'])
