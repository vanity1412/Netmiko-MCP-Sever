"""Agent-controlled CLI and durable resume. No production connections."""
import collections
import json
from pathlib import Path
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'mcp'))
import collector_backend as b
import scan
import test_ssh_reliability as fixtures
from netmiko.exceptions import ReadTimeout
from test_ssh_scenarios import VirtualClock, TimelineChannel

class ReaderTests(unittest.TestCase):
    def read(self,command,events,expect=r'(?m)^router#$',prompt='router#'):
        clock=VirtualClock();conn=TimelineChannel(clock,events,prompt=prompt)
        conn._network_prompt_text=prompt
        conn._network_prompt_regex=r'(?m)^'+__import__('re').escape(prompt)+r'$'
        with patch.object(b,'time',SimpleNamespace(monotonic=clock.now,sleep=clock.sleep)):
            output,failure=b.read_cli_output(conn,command,1,conn._network_prompt_regex if expect is None else expect)
        return output,failure,conn
    def test_xml_prompt_inside_text_waits_for_closing_root(self):
        output,failure,_=self.read('show interfaces | display xml',
            [(0,'<rpc-reply><output>\nrouter#'),(.2,'\nFULL DATA</output></rpc-reply>\n{master}\nrouter#')])
        self.assertIsNone(failure);self.assertIn('FULL DATA',output)
    def test_incomplete_xml_is_not_completed_by_prompt(self):
        _,failure,_=self.read('show interfaces | display xml',[(0,'<rpc-reply>\nrouter#')])
        self.assertEqual(failure['error_category'],'read_timeout')
    def test_custom_expect_does_not_replace_device_identity(self):
        _,failure,conn=self.read('show version',[(0,'version data\nother-device#')],expect='other-device#')
        self.assertIsNone(failure)
        self.assertEqual(conn._network_prompt_text,'router#')
    def test_huawei_dirty_mode_with_hyphenated_hostname(self):
        output,failure,conn=self.read('system-view',[(0,'[~SW-HCM-01]')],
             expect=None,prompt='<SW-HCM-01>')
        self.assertIsNone(failure);self.assertEqual(conn._network_prompt_text,'[~SW-HCM-01]')
    def test_config_mode_does_not_accept_another_device_prompt(self):
        _,failure,_=self.read('configure terminal',[(0,'other-device(config)#')])
        self.assertEqual(failure['error_category'],'read_timeout')

class ResumeTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.job=Path(self.tmp.name)/'job';self.calls=collections.Counter();self.fail=True
        owner=self
        class Connection:
            device_type='cisco_ios'
            def __init__(self,host):self.host=host;self.closed=False
            def find_prompt(self):return 'edge#'
            def is_alive(self):return not self.closed
            def disconnect(self):self.closed=True
            def send_command(self,command,**kw):
                owner.calls[self.host,command]+=1
                if owner.fail and self.host=='192.0.2.2' and command=='show interfaces':
                    return '% Invalid command\nedge#'
                if owner.fail and command=='description new-uplink':
                    raise ReadTimeout('simulated timeout after possible write')
                return 'response\nedge#'
        self.c=b.Collector({'defaults':{'max_workers':4,'session_sweep_seconds':0,
             'output_dir':str(self.job/'raw-output'),'output_storage_mode':'exclusive'},
             'devices':{'good':{'host':'192.0.2.1','device_type':'cisco_ios'},
                        'bad':{'host':'192.0.2.2','device_type':'cisco_ios'}}},
             connect_factory=lambda **kw:Connection(kw['host']))
        self.addCleanup(self.c.shutdown)
    def run_job(self,tasks,**kw):
        return scan.run_scan(self.c,tasks,self.job,workers=4,slow_workers=1,**kw)
    def records(self):return [json.loads(p.read_text()) for p in (self.job/'results').glob('*.json')]
    def test_resume_skips_successful_devices_and_completed_prefix(self):
        tasks=[{'target':'good','commands':['show version']},
               {'target':'bad','commands':['show version','show interfaces']}]
        self.assertEqual(self.run_job(tasks)['partial'],1)
        original=dict(self.calls);self.fail=False
        self.assertEqual(self.run_job(tasks,retry_statuses={'failed','partial'})['success'],2)
        self.assertEqual(self.calls['192.0.2.1','show version'],original['192.0.2.1','show version'])
        self.assertEqual(self.calls['192.0.2.2','show version'],1)
        self.assertEqual(self.calls['192.0.2.2','show interfaces'],2)
        self.assertEqual(sum(len(r['attempts']) for r in self.records()),3)
        self.assertEqual(self.run_job(tasks)['success'],2)
    def test_configuration_is_allowed_but_not_automatically_replayed(self):
        tasks=[{'target':'bad','commands':['configure terminal','description new-uplink','end']}]
        self.assertEqual(self.run_job(tasks)['partial'],1)
        self.assertEqual(self.calls['192.0.2.2','description new-uplink'],1)
        before=dict(self.calls)
        self.assertEqual(self.run_job(tasks,retry_statuses={'partial'})['unknown'],1)
        self.assertEqual(dict(self.calls),before)
        self.fail=False
        self.assertEqual(self.run_job(tasks,retry_statuses={'unknown'},replay_uncertain=True)['success'],1)
        self.assertEqual(self.calls['192.0.2.2','configure terminal'],2)
    def test_transient_read_retry_skips_successful_prefix(self):
        original=self.c._connect
        def connect(**kw):
            conn=original(**kw);send=conn.send_command
            def command(text,**opts):
                if text=='show clock' and not self.calls['clock-failure']:
                    self.calls['clock-failure']+=1
                    raise ReadTimeout('simulated read timeout')
                return send(text,**opts)
            conn.send_command=command;return conn
        self.c._connect=connect
        self.assertTrue(self.run_job([{'target':'good','commands':['show version','show clock']}])['ok'])
        self.assertEqual(self.calls['192.0.2.1','show version'],1)
    def test_export_recovery_does_not_repeat_configuration(self):
        tasks=[{'target':'good','commands':['configure terminal','end']}]
        with patch.object(scan.shutil,'copyfile',side_effect=OSError('simulated archive error')):
            self.assertEqual(self.run_job(tasks)['unknown'],1)
        before=dict(self.calls)
        self.assertEqual(self.run_job(tasks,retry_statuses={'unknown'})['success'],1)
        self.assertEqual(dict(self.calls),before)
        latest=self.records()[0]['attempts'][-1]
        self.assertEqual(latest['result_status'],'SUCCESS')
        self.assertIsNone(latest['error_category'])
    def test_corrupt_evidence_is_rejected_even_for_selected_retry(self):
        tasks=[{'target':'good','commands':['show version']}];self.run_job(tasks)
        evidence=next((self.job/'bang-chung').glob('*.txt'));evidence.write_text('corrupt')
        with self.assertRaises(ValueError):self.run_job(tasks,retry_statuses={'failed','partial'})
    def test_larger_configuration_batch_is_not_limited_to_fifty(self):
        commands=['description fixture-'+str(i) for i in range(60)]
        self.assertTrue(self.c.execute_many('good',commands)['ok'])
        self.assertEqual(sum(self.calls.values()),60)
    def test_legacy_read_checkpoint_infers_completed_prefix(self):
        tasks=[{'target':'bad','commands':['show version','show interfaces']}]
        self.assertEqual(self.run_job(tasks)['partial'],1)
        path=next((self.job/'results').glob('*.json'))
        record=json.loads(path.read_text())
        record.pop('next_command_index',None)
        for attempt in record['attempts']:
            attempt.pop('safe_to_retry',None);attempt.pop('command_offset',None)
        path.write_text(json.dumps(record))
        self.fail=False
        self.assertTrue(self.run_job(tasks,retry_statuses={'partial'})['ok'])
        self.assertEqual(self.calls['192.0.2.2','show version'],1)

class RealConfigurationTests(unittest.TestCase):
    setUpClass=classmethod(fixtures.RealSSHTests.setUpClass.__func__)
    setUp=fixtures.RealSSHTests.setUp
    collector=fixtures.RealSSHTests.collector
    def configure_responses(self):
        def mode(prompt):
            def reply(channel):
                self.server.prompt=prompt;channel.sendall(('\r\n'+prompt).encode())
            return reply
        self.server.responses.update({'show version':'Cisco IOS Software',
            'configure terminal':mode('router(config)#'),
            'interface Gi0/1':mode('router(config-if)#'),
            'description uplink':mode('router(config-if)#'),
            'end':mode('router#'),'write memory':lambda ch:ch.sendall(b'[confirm]'),
            'yes':mode('router#'),
            'copy running-config startup-config':lambda ch:ch.sendall(b'Destination filename [startup-config]?')})
    def test_real_batch_configuration_modes_without_reconnect(self):
        self.configure_responses();c=self.collector('cisco_ios')
        commands=['configure terminal','interface Gi0/1','description uplink','end']
        result=c.execute_many('local',commands)
        self.assertTrue(result['ok'],result);self.assertEqual(self.server.auth_attempts,1)
        self.assertEqual(self.server.commands[-4:],commands)
    def test_probe_worker_supports_same_configuration_sequence(self):
        self.configure_responses();c=self.collector('autodetect')
        self.assertTrue(c.execute_many('local',['configure terminal','interface Gi0/1','end'])['ok'])
        self.assertEqual(self.server.auth_attempts,1)
    def test_confirmation_keeps_session_for_explicit_agent_response(self):
        self.configure_responses();c=self.collector('cisco_ios');c.health_check_interval=0
        result=c.execute('local','write memory')
        self.assertFalse(result['ok']);self.assertTrue(result['awaiting_input'])
        self.assertNotIn('yes',self.server.commands)
        self.assertTrue(c.execute('local','yes')['ok'])
        self.assertEqual(self.server.auth_attempts,1)
    def test_interact_supplies_only_explicit_responses(self):
        self.configure_responses();c=self.collector('cisco_ios')
        result=c.interact('local',['write memory','yes'])
        self.assertTrue(result['ok'],result)
        self.assertEqual(self.server.commands[-2:],['write memory','yes'])
    def test_filename_question_accepts_explicit_enter(self):
        self.configure_responses();c=self.collector('cisco_ios')
        result=c.interact('local',['copy running-config startup-config',''])
        self.assertTrue(result['ok'],result)
    def test_preceding_data_is_retained(self):
        self.configure_responses();c=self.collector('cisco_ios');c.execute('local','show version')
        self.server.responses['hostname']='new output'
        conn=next(iter(c._sessions.values()))['conn']
        # Place previously unassociated bytes into Netmiko's own read buffer.
        conn._read_buffer='late output from previous activity\n'
        result=c.execute('local','hostname')
        self.assertIn('late output',result['preceding_output'])
    def test_junos_configuration_mode_and_commit(self):
        self.server.prompt='noc@router>'
        def mode(prompt):
            def reply(ch):
                self.server.prompt=prompt;ch.sendall(('\r\n'+prompt).encode())
            return reply
        self.server.responses.update({'configure':mode('noc@router#'),
             'set interfaces ge-0/0/0 description uplink':mode('noc@router#'),
             'commit':mode('noc@router#'),'exit':mode('noc@router>')})
        c=self.collector('juniper_junos')
        self.assertTrue(c.execute_many('local',['configure','set interfaces ge-0/0/0 description uplink','commit','exit'])['ok'])
        self.assertEqual(self.server.auth_attempts,1)
    def test_huawei_configuration_modes(self):
        self.server.prompt='<SW-HCM-01>'
        def mode(prompt):
            def reply(ch):
                self.server.prompt=prompt;ch.sendall(('\r\n'+prompt).encode())
            return reply
        self.server.responses.update({'system-view':mode('[~SW-HCM-01]'),
             'interface GigabitEthernet0/0/1':mode('[*SW-HCM-01-GigabitEthernet0/0/1]'),
             'return':mode('<SW-HCM-01>')})
        c=self.collector('huawei')
        self.assertTrue(c.execute_many('local',['system-view','interface GigabitEthernet0/0/1','return'])['ok'])
        self.assertEqual(self.server.auth_attempts,1)

if __name__=='__main__':unittest.main()
