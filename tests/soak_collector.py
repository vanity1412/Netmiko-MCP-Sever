"""Bounded mock/127.0.0.1 soak; never loads deployment inventory/credentials."""
import argparse
import collections
import ctypes
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import threading
import time
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'mcp'))
import collector_backend as b
import scan
from stress_resources import process_resources


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def reject_detection(**params):
    raise AssertionError('Mock fixtures require explicit drivers; live discovery prohibited')


def worker_resources(pid):
    """Owned worker only; CPU is cumulative, RSS is not unique physical RAM."""
    if os.name == 'nt':
        from ctypes import wintypes
        class Memory(ctypes.Structure):
            _fields_ = [('cb', wintypes.DWORD), ('faults', wintypes.DWORD)] + [
                (name, ctypes.c_size_t) for name in ('peak_rss', 'rss', 'peak_paged',
                'paged', 'peak_nonpaged', 'nonpaged', 'pagefile', 'peak_pagefile', 'private')]
        kernel = ctypes.WinDLL('kernel32', use_last_error=True)
        kernel.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        kernel.OpenProcess.restype = wintypes.HANDLE
        handle = kernel.OpenProcess(0x0400 | 0x0010, False, pid)
        if not handle: return None
        try:
            info = Memory(); info.cb = ctypes.sizeof(info)
            psapi = ctypes.WinDLL('psapi', use_last_error=True)
            psapi.GetProcessMemoryInfo.argtypes = [wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD]
            if not psapi.GetProcessMemoryInfo(handle, ctypes.byref(info), info.cb): return None
            times = [wintypes.FILETIME() for _ in range(4)]
            kernel.GetProcessTimes.argtypes = [wintypes.HANDLE] + [ctypes.POINTER(wintypes.FILETIME)]*4
            if not kernel.GetProcessTimes(handle, *(ctypes.byref(t) for t in times)): return None
            cpu = sum((t.dwHighDateTime << 32) + t.dwLowDateTime for t in times[2:]) / 10000000
            return {'rss_bytes': info.rss, 'private_bytes': info.private, 'cpu_seconds': cpu}
        finally:
            kernel.CloseHandle.argtypes = [wintypes.HANDLE]
            kernel.CloseHandle(handle)
    if sys.platform.startswith('linux'):
        try:
            folder = Path('/proc') / str(pid)
            status = dict(line.split(':', 1) for line in (folder/'status').read_text().splitlines())
            fields = (folder/'stat').read_text().rsplit(')', 1)[1].split()
            return {'rss_bytes': int(status['VmRSS'].split()[0])*1024,
                    'cpu_seconds': (int(fields[11])+int(fields[12])) / os.sysconf('SC_CLK_TCK')}
        except (OSError, KeyError, ValueError): return None
    return None


class SoakMonitor:
    def __init__(self, collectors, workers=None):
        self.collectors, self.workers = collectors, workers if workers is not None else []
        self.samples = collections.deque(maxlen=2000)
        self.peaks, self.worker_cpu = {}, {}
        self.stop = threading.Event()
        self.error = None
        self.unavailable_worker_samples = 0
        self.sample_count = 0
    def __enter__(self):
        self.before = process_resources()
        self.started, self.cpu_start = time.monotonic(), time.process_time()
        def sample():
            try:
                while not self.stop.wait(.2):
                    values = process_resources()
                    live_rss, live_workers, sessions, leased = 0, 0, 0, 0
                    for process in list(self.workers):
                        if process.poll() is not None: continue
                        live_workers += 1
                        result = worker_resources(process.pid)
                        if result is None:
                            self.unavailable_worker_samples += 1
                            continue
                        live_rss += result['rss_bytes']
                        self.worker_cpu[id(process)] = result['cpu_seconds']
                    for collector in list(self.collectors):
                        with collector._guard:
                            sessions += len(collector._sessions)
                            leased += sum(bool(e.get('borrowers')) for e in collector._sessions.values())
                    values.update(worker_rss_bytes=live_rss, worker_processes=live_workers,
                                  rss_sum_bytes=values.get('rss_bytes', 0)+live_rss,
                                  sessions=sessions, leased_sessions=leased)
                    for key, value in values.items(): self.peaks[key] = max(self.peaks.get(key, 0), value)
                    self.samples.append({'elapsed_seconds': round(time.monotonic()-self.started, 3), **values})
                    self.sample_count += 1
            except Exception as exc:
                self.error = exc
        self.thread = threading.Thread(target=sample, name='soak-resource-monitor')
        self.thread.start()
        return self
    def __exit__(self, *exc):
        self.stop.set(); self.thread.join(5)
        require(not self.thread.is_alive(), 'Resource monitor did not stop')
        self.elapsed = time.monotonic()-self.started
        self.cpu_seconds = time.process_time()-self.cpu_start
        self.after = process_resources()
        if self.error and exc[0] is None: raise self.error
    def report(self):
        return {'wall_seconds': round(self.elapsed, 3), 'parent_cpu_seconds': round(self.cpu_seconds, 3),
                'parent_cpu_percent_one_core': round(100*self.cpu_seconds/self.elapsed, 2),
                'worker_cpu_seconds_observed': round(sum(self.worker_cpu.values()), 3),
                'before': self.before, 'sampled_peaks': self.peaks, 'after': self.after,
                'samples': list(self.samples), 'sample_count': self.sample_count,
                'unavailable_worker_samples': self.unavailable_worker_samples,
                'scope': 'parent includes harness/server; worker CPU last observed before exit; RSS sum double-counts shared pages; 200 ms sampling'}


class Evidence:
    def __init__(self, root):
        self.root, self.count, self.bytes = root, 0, 0
        (root/'evidence').mkdir()
        self.index = root/'evidence.jsonl'
    def add(self, path, target, command, status, expected=None):
        payload = path.read_bytes()
        if expected is not None: require(payload == expected, 'Evidence content/identity mismatch')
        self.count += 1; self.bytes += len(payload)
        item = {'id': f'e{self.count:07}', 'path': str(path.relative_to(self.root)).replace('\\', '/'),
                'target': target, 'command': command, 'status': status,
                'sha256': hashlib.sha256(payload).hexdigest()}
        with self.index.open('a', encoding='utf-8') as handle:
            handle.write(json.dumps(item, ensure_ascii=False)+'\n')
    def save(self, collector, result, expected=None):
        oid = result.get('output_id')
        if oid:
            destination = self.root/'evidence'/f'e{self.count+1:07}.txt'
            with collector._output_lease(oid) as source: shutil.copyfile(source, destination)
            self.add(destination, result.get('target', 'fixture'), result.get('command', ''), result.get('status', ''), expected)
            require(collector.retire_output(oid), 'Scratch retirement failed after export')
        if result.get('previous_attempt'):
            self.save(collector, result['previous_attempt'])
    def finalize(self):
        count = 0
        with self.index.open(encoding='utf-8') as source, (self.root/'manifest.json').open('w', encoding='utf-8') as manifest:
            manifest.write('{"evidence":[')
            for line in source:
                item = json.loads(line)
                require(hashlib.sha256((self.root/item['path']).read_bytes()).hexdigest() == item['sha256'], 'Final evidence hash mismatch')
                if count: manifest.write(',')
                manifest.write(json.dumps(item, ensure_ascii=False))
                count += 1
            manifest.write(']}')
        require(count==self.count, 'Evidence manifest count changed')
        return {'files': self.count, 'bytes': self.bytes, 'all_hashes_reverified': True}


def body(index, username, command):
    size = 4096 if 'large' in command else 32
    return command+'\n'+f'identity={index} user={username}\n'+'dữ liệu αβγ\n'*size+f'fixture-{index}#'


def fault_cycle(root, evidence, serial):
    folder = root/f'job-{serial:04}'
    attempts, sent, live = collections.Counter(), collections.Counter(), {'count': 0, 'peak': 0}
    lock = threading.Lock()
    class Connection:
        def __init__(self, index, attempt):
            self.index, self.attempt, self.closed = index, attempt, False
            with lock:
                live['count'] += 1; live['peak'] = max(live['peak'], live['count'])
        def find_prompt(self): return f'fixture-{self.index}#'
        def is_alive(self): return not self.closed
        def disconnect(self):
            if not self.closed:
                self.closed = True
                with lock: live['count'] -= 1
        def send_command(self, command, **kwargs):
            with lock: sent[self.index, command] += 1
            if self.index == 6: raise EOFError('simulated uncertain configuration')
            if command == 'show second':
                if self.index == 2 and self.attempt == 1:
                    from netmiko.exceptions import ReadTimeout
                    raise ReadTimeout('simulated read timeout')
                if self.index == 3 and self.attempt == 1: raise EOFError('simulated EOF')
                if self.index == 4: return f'% Invalid command\nfixture-{self.index}#'
                if self.index == 5: return 'incomplete response'
            return body(self.index, 'fault-fixture', command)
        send_command_timing = send_command
    def connect(**params):
        index = int(params['host'].rsplit('.', 1)[1])-1
        with lock:
            attempts[index] += 1; attempt = attempts[index]
        if index == 1:
            import paramiko
            raise paramiko.AuthenticationException('Authentication failed')
        if index == 7 and attempt == 1: raise TimeoutError('simulated TCP timeout')
        return Connection(index, attempt)
    collector = b.Collector({'defaults': {'execution_policy': 'read_write', 'output_dir': str(folder/'raw-output'),
        'device_type': 'cisco_ios', 'max_workers': 4, 'max_sessions': 4,
        'output_storage_mode': 'exclusive', 'session_sweep_seconds': 0}}, connect_factory=connect, detect_factory=reject_detection)
    tasks = [{'target': f'192.0.2.{i+1}', 'device_type':'cisco_ios', 'commands': ['set fixture value'] if i == 6 else ['show first', 'show second']} for i in range(8)]
    try:
        result = scan.run_scan(collector, tasks, folder, workers=4, slow_workers=1)
        require((result['success'],result['partial'],result['failed'],result['unknown'])==(4,2,2,0), 'Unexpected fault distribution')
        records = [json.loads(p.read_text(encoding='utf-8')) for p in (folder/'results').glob('*.json')]
        require(len(records) == 8, 'Scanner lost targets')
        for record in records:
            i = int(record['target'].rsplit('.', 1)[1])-1
            require(len(record['attempts']) == (2 if i in (2,3,7) else 1), 'Unexpected retry count')
            if i in (2,3): require(sent[i, 'show first'] == 1 and sent[i, 'show second'] == 2, 'Completed prefix replayed')
            if i == 6:
                require(sent[i, 'set fixture value'] == 1, 'Uncertain configuration replayed')
                checked = record['attempts'][0]['result']['results'][0]
                require(checked['execution_state'] == 'UNCERTAIN', 'Uncertain write reported completed')
        before = dict(attempts), dict(sent)
        resumed = scan.run_scan(collector, tasks, folder, workers=4, slow_workers=1)
        require(resumed == result and before == (dict(attempts),dict(sent)), 'Resume repeated SSH/commands')
        proof = next(p for r in records for a in r['attempts'] for p in a['evidence'])
        path = folder/proof['file']; original = path.read_bytes()
        path.write_bytes(original+b'corrupted')
        try:
            try: scan.run_scan(collector, tasks, folder, workers=4, slow_workers=1)
            except ValueError as exc: require('evidence changed' in str(exc), 'Wrong corruption rejection')
            else: raise AssertionError('Corrupt evidence accepted')
        finally: path.write_bytes(original)
        require(before == (dict(attempts),dict(sent)), 'Corruption check opened SSH')
        for record in records:
            for attempt in record['attempts']:
                checked_outputs = [r for r in attempt['result'].get('results', []) if r.get('output_id')]
                require(len(checked_outputs) == len(attempt['evidence']), 'Evidence/result mapping lost')
                for proof, checked in zip(attempt['evidence'], checked_outputs):
                    path = folder/proof['file']
                    require(hashlib.sha256(path.read_bytes()).hexdigest() == proof['sha256'], 'Scanner evidence hash mismatch')
                    expected = body(int(record['target'].rsplit('.',1)[1])-1, 'fault-fixture', checked['command']).encode('utf-8') if checked['ok'] else None
                    evidence.add(path, record['target'], checked['command'], checked['status'], expected)
        require(live['peak'] <= 4 and len(collector._sessions) <= 4, 'Session bound exceeded')
        require(collector.status()['autodetect_probes']==0, 'Mock attempted discovery')
        return {'targets': 8, 'attempts': sum(attempts.values()), 'prefix_replays': 0,
                'uncertain_write_replays': 0, 'resume_connections': 0, 'corruption_rejected': True,
                'peak_connections': live['peak'], 'status': result}
    finally:
        collector.shutdown()
        require(live['count'] == 0 and collector.status()['sessions'] == [], 'Fault collector leaked sessions')


def run_mock(root, seconds=180, min_cycles=2, max_cycles=10000):
    evidence = Evidence(root)
    created, lock = collections.Counter(), threading.Lock()
    devices = {f'fixture-{i}': {'host': f'198.18.0.{i+1}' if i != 7 else '198.18.0.1',
                              'profile': f'p{i%2}'} for i in range(8)}
    lookup = {(v['host'], f'fixture-{i%2}'): i for i,v in enumerate(devices.values())}
    class Connection:
        def __init__(self, index, username): self.index, self.username, self.closed = index, username, False
        def find_prompt(self): return f'fixture-{self.index}#'
        def is_alive(self): return not self.closed
        def disconnect(self): self.closed = True
        def send_command(self, command, **kwargs): return body(self.index, self.username, command)
        send_command_timing = send_command
    def connect(**params):
        i = lookup[params['host'],params['username']]
        with lock: created[i] += 1
        return Connection(i,params['username'])
    collector = b.Collector({'defaults': {'output_dir': str(root/'scratch'), 'device_type':'cisco_ios',
        'max_workers':4, 'max_sessions':8, 'session_sweep_seconds':0}, 'devices':devices,
        'profiles':{f'p{i}':{'username':f'fixture-{i}','password':'synthetic-only'} for i in range(2)}}, connect_factory=connect, detect_factory=reject_detection)
    cycles, fault_jobs, fault_attempts, fault_peak = 0, 0, 0, 0
    last_progress = time.monotonic()
    try:
        with SoakMonitor([collector]) as monitor:
            while cycles < max_cycles and (cycles < min_cycles or time.monotonic()-monitor.started < seconds):
                commands = [f'show fixture {cycles}', f'show {"large " if cycles%16==0 else ""}second {cycles}']
                result = collector.parallel([{'target':name,'commands':commands,'save_output':True} for name in devices])
                require(result['ok'], 'Mock reuse batch failed')
                for i, task in enumerate(result['results']):
                    for checked in task['results']:
                        require(checked['output_complete'] and checked['status']=='SUCCESS', 'False/incomplete success')
                        if cycles: require(checked['session_reused'], 'Healthy session not reused')
                        evidence.save(collector, checked, body(i,f'fixture-{i%2}',checked['command']).encode('utf-8'))
                require(sum(created.values()) == 8, 'Unexpected reconnect or credential mix')
                status = collector.status()
                require(len(status['sessions']) <= 8 and not any(s['leased'] for s in status['sessions']), 'Session/lease leak')
                require(status['parallel_queue']['queued']==status['parallel_queue']['running']==0, 'Queue did not drain')
                if cycles%10==0:
                    fault = fault_cycle(root, evidence, fault_jobs)
                    fault_jobs += 1; fault_attempts += fault['attempts']
                    fault_peak = max(fault_peak, fault['peak_connections'])
                cycles += 1
                if time.monotonic()-last_progress >= 30:
                    progress = {'mode':'mock','cycles':cycles,'fault_jobs':fault_jobs,'evidence_files':evidence.count}
                    scan.atomic_json(root/'progress.json', progress)
                    print(json.dumps({'progress':progress}), flush=True)
                    last_progress = time.monotonic()
                time.sleep(.02)
        require(not list(collector.output_dir.glob('*.txt')), 'Scratch output was not retired')
        result = {'mode':'mock','cycles':cycles,'fault_jobs':fault_jobs,'warm_connections':sum(created.values()),
                  'fault_targets':fault_jobs*8,'fault_attempts':fault_attempts,'fault_peak_connections':fault_peak,
                  'session_reuse_and_credential_isolation':True,'resume_and_corruption_checks':True,
                  'resources':monitor.report(),'evidence':evidence.finalize(),
                  'collector':collector.status(),'duration_reached':monitor.elapsed>=seconds}
    finally:
        collector.shutdown()
    require(collector.status()['sessions']==[] and all(not t.is_alive() for t in collector._task_pool._threads), 'Shutdown leaked resources')
    result['after_shutdown'] = process_resources()
    result['sessions_after_shutdown'] = 0
    return result


def run_localhost(root, seconds=120, min_cycles=2, max_cycles=10000):
    import paramiko
    import probe_session
    from test_ssh_reliability import LocalSSHServer
    evidence = Evidence(root)
    server = LocalSSHServer(paramiko.RSAKey.generate(2048))
    require(server.listener.getsockname()[0] == '127.0.0.1', 'Fixture did not bind loopback')
    server.responses['uname -s'] = 'Linux'
    workers, collectors = [], []
    original_spawn = probe_session.subprocess.Popen
    def spawn(*args, **kwargs):
        process = original_spawn(*args, **kwargs)
        workers.append(process)
        return process
    for kind in ('linux', 'autodetect'):
        collectors.append(b.Collector({'defaults': {'execution_policy': 'read_write', 'username':'tester','password':'loopback-only',
            'output_dir':str(root/('scratch-'+kind)), 'session_sweep_seconds':0,
            'conn_timeout':3,'auth_timeout':3,'banner_timeout':3,
            'max_workers':2,'max_sessions':4,'alt_key_file':str(root/'known_hosts'),
            'autodetect_cache_file':str(root/'drivers.sqlite3')},
            'devices':{'local':{'host':'127.0.0.1','port':server.port,'device_type':kind}}}))
    cycles, recoveries, questions = 0, 0, 0
    last_progress = time.monotonic()
    def save_tree(collector, result):
        outputs = {}
        def visit(item):
            if item.get('output_id'): outputs[item['output_id']] = item
            for key in ('results','steps'):
                for child in item.get(key, []): visit(child)
            if item.get('previous_attempt'): visit(item['previous_attempt'])
        visit(result)
        # Save each unique raw once; previous_attempt is separately visited here.
        for item in outputs.values():
            evidence.save(collector, {k:v for k,v in item.items() if k!='previous_attempt'})
    try:
        with patch.object(probe_session.subprocess, 'Popen', spawn), SoakMonitor(collectors, workers) as monitor:
            while cycles < max_cycles and (cycles < min_cycles or time.monotonic()-monitor.started < seconds):
                payload = f'localhost-cycle={cycles}\n'+'dữ liệu đường truyền αβγ\n'*(4096 if cycles%16==0 else 32)
                server.responses['show fixture'] = payload
                for collector in collectors:
                    batch = collector.execute_many('local',['uname -s','show fixture'],read_timeout=10,save_output=True)
                    require(batch['ok'], 'Localhost collection failed')
                    for checked in batch['results']:
                        expected = ('Linux' if checked['command']=='uname -s' else payload)+'\r\nrouter#'
                        require(checked['output_complete'] and checked['status']=='SUCCESS', 'False localhost success')
                        evidence.save(collector,checked,b.clean_terminal(expected).encode('utf-8'))
                if cycles%10==0:
                    before_auth = server.auth_attempts
                    pending = collectors[0].execute('local','date',save_output=True)
                    require(pending['status']=='AWAITING_INPUT', 'Question was auto-answered')
                    save_tree(collectors[0],pending)
                    reply = collectors[0].interact('local',['\n'],save_output=True)
                    require(reply['ok'] and not reply.get('awaiting_input'), 'Explicit Enter did not clear question')
                    save_tree(collectors[0],reply)
                    require(server.auth_attempts == before_auth, 'Pending session reconnected')
                    questions += 1
                if cycles%15==14:
                    calls = []
                    def reset_once(channel):
                        calls.append(1)
                        if len(calls)==1:
                            channel.sendall(b'partial-recovery\r\n'); channel.close()
                        else: channel.sendall(b'recovered\r\nrouter#')
                    server.responses['hostname'] = reset_once
                    recovered = collectors[0].execute('local','hostname',read_timeout=5,save_output=True)
                    require(recovered['ok'] and recovered.get('recovery_attempts')==1 and len(calls)==2, 'Transport recovery was not bounded')
                    require('partial-recovery' in recovered['previous_attempt'].get('output','') or recovered['previous_attempt'].get('output_id'), 'Partial recovery evidence lost')
                    previous = recovered['previous_attempt']
                    if previous.get('output_id'):
                        with collectors[0]._output_lease(previous['output_id']) as path:
                            require(path.read_bytes()==b'partial-recovery\n', 'Partial recovery bytes changed')
                    else:
                        require(previous.get('output')=='partial-recovery\n', 'Partial recovery bytes changed')
                    save_tree(collectors[0],recovered)
                    recoveries += 1
                for collector in collectors:
                    status = collector.status()
                    require(len(status['sessions']) <= collector.max_sessions, 'Localhost pool exceeded limit')
                    require(not any(s['leased'] for s in status['sessions']), 'Localhost lease did not release')
                cycles += 1
                if time.monotonic()-last_progress >= 30:
                    progress = {'mode':'localhost','cycles':cycles,'recoveries':recoveries,'evidence_files':evidence.count}
                    scan.atomic_json(root/'progress.json', progress)
                    print(json.dumps({'progress':progress}), flush=True)
                    last_progress = time.monotonic()
        require(server.auth_attempts == 2+recoveries, 'Unexpected localhost authentication/reconnect')
        require(len(workers)==1, 'Unexpected probe spawn count')
        require(all(not list(c.output_dir.glob('*.txt')) for c in collectors), 'Localhost scratch remains')
        report = {'mode':'localhost','cycles':cycles,'recoveries':recoveries,'explicit_questions':questions,
                  'authentication_attempts':server.auth_attempts,'probe_workers_started':len(workers),
                  'duration_reached':monitor.elapsed>=seconds,'resources':monitor.report(),
                  'collectors':[c.status() for c in collectors],'evidence':evidence.finalize()}
    finally:
        for collector in collectors: collector.shutdown()
        server.close()
    require(all(p.poll() is not None for p in workers), 'Probe worker survived shutdown')
    require(all(not c.status()['sessions'] for c in collectors), 'Session survived shutdown')
    require(all(not t.is_alive() for c in collectors for t in c._task_pool._threads), 'Pool thread survived shutdown')
    require(not server.thread.is_alive() and all(not t.is_active() for t in server.transports), 'Local SSH server survived shutdown')
    report.update(sessions_after_shutdown=0,live_workers_after_shutdown=0,after_shutdown=process_resources())
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--mode',choices=['mock','localhost'],required=True)
    parser.add_argument('--seconds',type=float,default=180)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    if not 0 <= args.seconds <= 1800: parser.error('seconds must be 0..1800')
    if args.output.exists(): parser.error('output already exists')
    root=args.output.with_suffix('')
    root.mkdir(parents=True,exist_ok=False)
    try:
        report = run_mock(root,args.seconds) if args.mode=='mock' else run_localhost(root,args.seconds)
        require(report['duration_reached'], 'Cycle cap reached before requested soak duration')
        report.update(valid=True,artifact_root=str(root.resolve()),
                      git_revision=subprocess.check_output(['git','rev-parse','HEAD'],text=True).strip())
    except Exception as exc:
        args.output.write_text(json.dumps({'valid':False,'error':repr(exc),'artifact_root':str(root.resolve())}),encoding='utf-8')
        raise
    args.output.write_text(json.dumps(report,ensure_ascii=False,indent=2),encoding='utf-8')
    print(json.dumps({k:report[k] for k in ('mode','cycles','valid','evidence','sessions_after_shutdown')}))


if __name__=='__main__': main()
