"""No production SSH: regression for error categories and durable scan lanes."""
import concurrent.futures
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch
import test_collector as f
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import collector_backend as b
import scan

class Performance(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.directory=Path(self.tmp.name);self.connections=[]
  def connect(**params):
   fake=f.Fake();self.connections.append((params,fake));return fake
  self.c=b.Collector({'defaults':{'device_type':'juniper_junos','output_dir':str(self.directory/'raw'),'max_workers':4,'session_sweep_seconds':0},'devices':{'MOCK':{'host':'mock-host','device_type':'juniper_junos'}}},connect_factory=connect)
 def tearDown(self):self.c.shutdown();self.tmp.cleanup()
 def test_tools_names_and_schemas_unchanged(self):
  baseline=json.loads(Path(__file__).with_name('tool-schema-v1.json').read_text(encoding='utf-8'))
  self.assertEqual(baseline,[{'name':t['name'],'inputSchema':t['inputSchema']} for t in b.make_tool_list()])
 def test_ip_only_outside_inventory_previews_autodetect(self):
  tasks,_=scan.prepare_tasks(self.c,[{'target':'192.0.2.10'}])
  self.assertEqual(tasks[0]['device_type'],'autodetect');self.assertFalse(self.connections)
 def test_profile_is_explicit_and_separate_identity(self):
  self.c.profiles.update(one={'username':'MOCK-ONE'},two={'username':'MOCK-TWO'})
  tasks,_=scan.prepare_tasks(self.c,[self.task(profile='one'),self.task(profile='two')])
  self.assertEqual(len(tasks),2)
 def test_duplicate_equivalent_profile_representation_is_deduped(self):
  tasks,_=scan.prepare_tasks(self.c,[self.task(),self.task(profile='default')])
  self.assertEqual(len(tasks),1)
 def test_unknown_driver_plan_cannot_hide_unsafe_command_map(self):
  with self.assertRaises(PermissionError):
   self.run_job([{'target':'192.0.2.10'}],command_map={'juniper_junos':['configure']})
  self.assertFalse(self.connections)
 def test_dns_and_banner_eof_are_not_silently_timeout(self):
  import socket,paramiko
  self.assertEqual(b.classify_error(socket.gaierror('MOCK DNS'),'connect')['error_category'],'dns_error')
  try:
   try:raise EOFError('MOCK EOF')
   except Exception:raise paramiko.SSHException('Error reading SSH protocol banner')
  except Exception as exc:
   self.assertEqual(b.classify_error(exc,'connect')['error_category'],'connection_lost')
   self.assertTrue(b.classify_error(exc,'connect')['retryable'])
 def test_banner_timeout_and_nested_detection_budget(self):
  import paramiko
  try:
   try:raise TimeoutError('MOCK timed out')
   except Exception:raise paramiko.SSHException('Error reading SSH protocol banner')
  except Exception as exc:self.assertEqual(b.classify_error(exc,'connect')['error_category'],'banner_timeout')
  with self.c.request_budget(autodetect_timeout=90):
   with self.c.request_budget():self.assertEqual(self.c._request.detection_timeout,90)
  self.assertIsNone(self.c._request.detection_timeout)
 def test_detection_worker_does_not_trust_banner_or_partial_output(self):
  fake=f.Fake()
  with patch('netmiko.ConnectHandler',return_value=fake),patch.object(b,'read_cli_output',return_value=('JUNOS login banner\nshow version\nPARTIAL',None)) as reader:
   result=b.detection_worker({'host':'MOCK'})
  self.assertEqual(result['error_category'],'output_verification')
  self.assertEqual(reader.call_args.args[1],'show version');self.assertFalse(fake.alive)
 def test_detection_worker_verified_response_and_slow_read_budget(self):
  with patch('netmiko.ConnectHandler',return_value=f.Fake()) as factory,patch.object(b,'read_cli_output',return_value=('show version\nJunos: 23.4R1\nMOCK>',None)) as reader:
   result=b.detection_worker({'host':'MOCK','_probe_read_timeout':30})
  self.assertEqual(result['device_type'],'juniper_junos');self.assertEqual(reader.call_args.args[2],30)
  self.assertNotIn('_probe_read_timeout',factory.call_args.kwargs)
 def test_wrapped_ssh_errors(self):
  import paramiko
  from netmiko.exceptions import NetmikoTimeoutException
  for underlying,expected in [(paramiko.SSHException('Server MOCK not found in known_hosts'),'host_key_unknown'),(paramiko.SSHException('Incompatible ssh peer (no acceptable kex algorithm)'),'algorithm_mismatch'),(paramiko.BadAuthenticationType('Bad authentication type',['keyboard-interactive']),'auth_method'),(paramiko.AuthenticationException('Authentication timeout.'),'auth_timeout')]:
   try:
    try:raise underlying
    except Exception:raise NetmikoTimeoutException('wrapped library error')
   except Exception as exc:
    result=b.classify_error(exc,'connect');self.assertEqual(result['error_category'],expected);self.assertEqual(result['retryable'], result['error_category']=='auth_timeout')
 def test_autodetect_worker_category_retained(self):
  result=b.classify_error(b.CollectionError({'error':'NetmikoTimeoutException','error_category':'host_key_unknown','error_stage':'host_key','retryable':False}))
  self.assertEqual(result['error_category'],'host_key_unknown')
 def test_global_slots_bound_probe_and_collection(self):
  self.c._ssh_slots=threading.BoundedSemaphore(2);guard=threading.Lock();active=[0,0]
  class Detector:
   def autodetect(inner):
    with guard:active[0]+=1;active[1]=max(active)
    time.sleep(.03)
    with guard:active[0]-=1
    return 'juniper_junos'
  self.c._custom_detect=lambda **kw:Detector()
  with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
   values=list(pool.map(lambda i:self.c.execute('mock-'+str(i),'show version',device_type='autodetect'),range(6)))
  self.assertTrue(all(v['ok'] for v in values));self.assertLessEqual(active[1],2)
 def test_auth_suppression_survives_lane_timeout_change(self):
  from netmiko.exceptions import NetmikoAuthenticationException
  attempts=[]
  def connect(**kw):attempts.append(1);raise NetmikoAuthenticationException('MOCK denied')
  self.c._connect=connect
  for timeout in [10,30]:
   with self.c.request_budget(connection_timeouts={'conn_timeout':timeout}):
    with self.assertRaises(Exception):self.c.execute('MOCK','show version')
  self.assertEqual(len(attempts),1)
 def test_cli_failure_keeps_verified_session(self):
  self.c.execute('MOCK','show version')
  with self.assertRaises(b.BatchError):self.c.execute_many('MOCK',['show system bad'])
  self.assertTrue(self.c.execute('MOCK','show version')['ok']);self.assertEqual(len(self.connections),1)
 def test_incomplete_batch_retires_session(self):
  with self.assertRaises(b.BatchError):self.c.execute_many('MOCK',['show system partial'])
  self.c.execute('MOCK','show version');self.assertEqual(len(self.connections),2)
 def test_bgp_history_is_data_not_health(self):
  for state in ['Established','Idle']:
   cmd='show bgp neighbor 192.0.2.1';out=cmd+"\nPeer: 192.0.2.1 AS 64500\nState: "+state+"\n  Error: 'Cease' Sent: 0 Recv: 5\nMOCK>"
   self.assertTrue(self.c._result('MOCK',cmd,out,0)['ok'])
   self.assertFalse(self.c._result('MOCK',cmd,out.replace('MOCK>','% Authorization failed\nMOCK>'),0)['ok'])
 def test_python_budget_is_cumulative(self):
  fake=f.Fake();original=fake.send_command
  def send(cmd,**kwargs):time.sleep(.04);return original(cmd,**kwargs)
  fake.send_command=send;self.c._connect=lambda **kw:fake
  with self.c.request_budget(timeout=.06):
   with self.assertRaises(b.BatchError) as caught:self.c.execute_many('MOCK',['show version','show interfaces','show system uptime'])
  self.assertEqual(caught.exception.results[-1]['error_category'],'deadline')
  self.assertNotIn('show system uptime',fake.commands)
  self.assertIsNone(getattr(self.c._request,'context',None))
 def task(self,target='MOCK',**kwargs):return dict(target=target,device_type='juniper_junos',commands=['show version'],**kwargs)
 def run_job(self,tasks,**kwargs):return scan.run_scan(self.c,tasks,self.directory/'job',workers=4,slow_workers=1,**kwargs)
 def records(self):return [json.loads(p.read_text(encoding='utf-8')) for p in (self.directory/'job/results').glob('*.json')]
 def test_scan_fast_timeout_recovered_slow(self):
  calls={}
  def connect(**params):
   host=params['host'];calls[host]=calls.get(host,0)+1
   if host=='slow-host' and params['conn_timeout']<30:raise TimeoutError('MOCK TCP timeout')
   return f.Fake()
  self.c._connect=connect
  result=self.run_job([self.task('slow-host'),self.task()])
  self.assertTrue(result['ok']);self.assertEqual(calls['slow-host'],2)
  record=next(r for r in self.records() if r['target']=='slow-host')
  self.assertEqual([a['lane'] for a in record['attempts']],['fast','slow'])
  self.assertEqual(record['attempts'][0]['error_category'],'connect_timeout')
 def test_auth_not_retried_in_slow_lane(self):
  from netmiko.exceptions import NetmikoAuthenticationException
  calls=[]
  def connect(**kw):calls.append(1);raise NetmikoAuthenticationException('MOCK denied')
  self.c._connect=connect
  result=self.run_job([self.task()]);self.assertFalse(result['ok']);self.assertEqual(len(calls),1)
  self.assertEqual(self.records()[0]['attempts'][0]['error_category'],'authentication')
 def test_known_slow_starts_slow_without_probe_retry(self):
  result=self.run_job([self.task(lane='slow')]);self.assertTrue(result['ok'])
  self.assertEqual(self.connections[0][0]['auth_timeout'],60)
  self.assertEqual(len(self.records()[0]['attempts']),1)
 def test_scan_dedup_and_resume(self):
  tasks=[self.task(),self.task('mock-host')]
  first=self.run_job(tasks);self.assertEqual(first['total'],1);self.assertEqual(first['duplicates_removed'],1)
  count=len(self.connections);again=self.run_job(tasks)
  self.assertTrue(again['ok']);self.assertEqual(len(self.connections),count)
 def test_scan_full_105_targets_not_limited_by_mcp100(self):
  result=self.run_job([self.task('mock-'+str(i)) for i in range(105)])
  self.assertEqual(result['success'],105);self.assertTrue(result['ok'])
  self.assertEqual(len(self.records()),105)
 def test_fast_results_saved_while_slow_busy(self):
  entered=threading.Event();release=threading.Event();fake=f.Fake()
  class Slow(f.Fake):
   def send_command(inner,cmd,**kw):entered.set();release.wait(3);return super().send_command(cmd,**kw)
  self.c._connect=lambda **kw:Slow() if kw['host']=='slow' else f.Fake()
  with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
   future=pool.submit(self.run_job,[self.task('slow',lane='slow'),self.task()])
   try:
    self.assertTrue(entered.wait(2));end=time.monotonic()+2
    while time.monotonic()<end and not any(r['status']=='success' for r in self.records()):time.sleep(.01)
    self.assertTrue(any(r['status']=='success' for r in self.records()),json.dumps(self.records()));self.assertFalse(future.done())
   finally:
    release.set();future.result(3)
   self.assertTrue(future.result(3)['ok'])
 def test_partial_evidence_and_flags(self):
  tasks=[dict(target='MOCK',commands=['show version','show system bad'])]
  result=self.run_job(tasks);self.assertEqual(result['partial'],1);self.assertFalse(result['ok'])
  attempt=self.records()[0]['attempts'][0]
  self.assertEqual(len(attempt['evidence']),2)
  for proof in attempt['evidence']:
   p=self.directory/'job'/proof['file'];self.assertEqual(hashlib.sha256(p.read_bytes()).hexdigest(),proof['sha256'])
 def test_resume_rejects_plan_or_evidence_change(self):
  self.run_job([self.task()])
  with self.assertRaises(ValueError):self.run_job([dict(target='MOCK',commands=['show interfaces'])])
  proof=self.records()[0]['attempts'][0]['evidence'][0]
  (self.directory/'job'/proof['file']).write_text('tampered')
  with self.assertRaises(ValueError):self.run_job([self.task()])
 def test_in_progress_resume_is_unknown_not_repeated_auth(self):
  tasks=[self.task()];self.run_job(tasks)
  path=next((self.directory/'job/results').glob('*.json'));record=json.loads(path.read_text(encoding='utf-8'));record['status']='running';scan.atomic_json(path,record)
  count=len(self.connections);result=self.run_job(tasks)
  self.assertEqual(result['unknown'],1);self.assertFalse(result['ok']);self.assertEqual(len(self.connections),count)
 def test_cancelled_job_keeps_every_target_accounted(self):
  cancel=threading.Event();cancel.set()
  result=self.run_job([self.task(),self.task('other')],cancel=cancel)
  self.assertEqual(result['pending'],2);self.assertFalse(result['ok']);self.assertFalse(self.connections)
 def test_invalid_plan_rejected_before_any_ssh(self):
  with self.assertRaises(PermissionError):self.run_job([self.task(),dict(target='other',commands=['configure'])])
  self.assertFalse(self.connections)
 def test_job_lock_and_malformed_checkpoint_fail_closed(self):
  directory=self.directory/'job';directory.mkdir();(directory/'scan.lock').write_text('MOCK')
  with self.assertRaises(FileExistsError):self.run_job([self.task()])
  (directory/'scan.lock').unlink();self.run_job([self.task()])
  next((directory/'results').glob('*.json')).write_text('{')
  with self.assertRaises(json.JSONDecodeError):self.run_job([self.task()])
 def test_runtime_export_error_never_reports_success(self):
  with patch.object(scan.shutil,'copyfile',side_effect=OSError('MOCK disk full')):
   result=self.run_job([self.task()])
  self.assertEqual(result['unknown'],1);self.assertFalse(result['ok'])
 def test_no_retry_for_wrapped_key_or_auth_timeout(self):
  from netmiko.exceptions import NetmikoTimeoutException
  for message in ['Server MOCK not found in known_hosts','Authentication timeout.','Incompatible ssh peer (no acceptable kex algorithm)']:
   with self.subTest(message=message):
    result=b.classify_error(NetmikoTimeoutException(message),'connect');self.assertEqual(result['retryable'], result['error_category']=='auth_timeout')

 def test_cli_private_raw_retired_only_after_archiving(self):
  original=self.c.output_dir
  private=self.directory/'job/raw-output';private.mkdir(parents=True)
  self.c.output_dir=private
  result=self.run_job([self.task()]);self.assertTrue(result['ok'])
  self.assertFalse(list(private.glob('*.txt')))
  self.assertTrue((self.directory/'job'/self.records()[0]['attempts'][0]['evidence'][0]['file']).is_file())
  self.assertTrue(original.exists())
 def test_shared_raw_outputs_never_deleted_by_scan(self):
  self.run_job([self.task()]);self.assertTrue(list(self.c.output_dir.glob('*.txt')))

class AtomicCheckpoint(unittest.TestCase):
 def test_transient_windows_lock_is_retried_without_repeating_ssh(self):
  with tempfile.TemporaryDirectory() as d:
   path=Path(d)/'record.json';original=scan.os.replace;calls=[]
   def replace(source,destination):
    calls.append(1)
    if len(calls)<3:raise PermissionError('MOCK file reader lock')
    return original(source,destination)
   with patch.object(scan.os,'replace',side_effect=replace):scan.atomic_json(path,{'status':'success'})
   self.assertEqual(len(calls),3);self.assertEqual(json.loads(path.read_text())['status'],'success')
 def test_persistent_replace_error_keeps_previous_checkpoint(self):
  with tempfile.TemporaryDirectory() as d:
   path=Path(d)/'record.json';path.write_text('{"status":"old"}')
   with patch.object(scan.os,'replace',side_effect=PermissionError('MOCK persistent lock')),patch.object(scan.time,'sleep'):
    with self.assertRaises(PermissionError):scan.atomic_json(path,{'status':'success'})
   self.assertEqual(json.loads(path.read_text())['status'],'old')
   self.assertFalse(list(Path(d).glob('*.tmp')))

if __name__=='__main__':unittest.main()
