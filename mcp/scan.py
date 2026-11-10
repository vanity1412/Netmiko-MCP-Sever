"""Bounded inventory scanner. Preview by default; --execute explicitly enables SSH.

One device per job, incremental evidence, fast/slow lanes, conservative resume.
This is a CLI/Python helper, not an additional MCP tool.
"""
from __future__ import annotations
import argparse
import collections
import concurrent.futures as futures
import contextlib
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import shutil
import threading
import time
import uuid
from result_status import normalize_result
from collector_backend import Collector, BatchError, safe_command, readonly_command, bounded_int, is_replay_safe, MAX_COMMANDS

DEFAULT_COMMANDS = {'juniper_junos':['show version'], 'cisco_ios':['show version'],
                    'cisco_xr':['show version'], 'cisco_nxos':['show version'],
                    'huawei':['display version'], 'linux':['uname -s']}

def stamp():
    return dt.datetime.now(dt.timezone.utc).isoformat()


def atomic_json(path, value):
    path = Path(path)
    temporary = path.with_name(path.name + '.' + uuid.uuid4().hex + '.tmp')
    try:
        with temporary.open('x', encoding='utf-8') as handle:
            json.dump(value, handle, ensure_ascii=False, indent=2)
            handle.flush(); os.fsync(handle.fileno())
        # Windows readers/antivirus may briefly deny replace. Preserve the old
        # checkpoint and retry only this local atomic operation, never SSH.
        for attempt in range(6):
            try:
                os.replace(temporary, path)
                break
            except PermissionError:
                if attempt == 5:
                    raise
                time.sleep(.01 * 2**attempt)
    finally:
        with contextlib.suppress(FileNotFoundError): temporary.unlink()


def prepare_tasks(collector, tasks, command_map=None):
    """Validate the entire known-driver plan before any SSH; hash identities only."""
    if not isinstance(tasks, list) or not tasks:
        raise ValueError('Plan must contain at least one task')
    command_map = DEFAULT_COMMANDS if command_map is None else command_map
    if not isinstance(command_map, dict):
        raise ValueError('Commands file must map device_type to arrays of commands')
    def commands(value):
        if not isinstance(value, list) or not 1 <= len(value) <= MAX_COMMANDS:
            raise ValueError('Each device needs 1..1000 commands')
        return [safe_command(c) for c in value]
    command_map = {dtype: commands(value) for dtype, value in command_map.items()}
    for dtype, values in command_map.items():
        for command in values:
            readonly_command(command, dtype)
    prepared = {}
    allowed = {'target','commands','device_type','profile','read_timeout','lane'}
    for raw in tasks:
        if not isinstance(raw, dict) or set(raw)-allowed or 'target' not in raw:
            raise ValueError('Invalid task fields')
        item = dict(raw)
        _, _, resolution = collector._resolve_target(item['target'])
        if resolution == 'dynamic' and not item.get('device_type'):
            item['device_type'] = 'autodetect'
        params = collector._get_settings(item['target'], item.get('device_type'), item.get('profile'))
        if item.get('lane', 'fast') not in {'fast','slow'}:
            raise ValueError('lane must be fast or slow')
        item['lane'] = item.get('lane','fast')
        if 'read_timeout' in item:
            item['read_timeout'] = bounded_int(item['read_timeout'],45,1,600)
        if 'commands' in item:
            item['commands'] = commands(item['commands'])
        elif params['device_type'] not in {'autodetect','generic_termserver'}:
            item['commands'] = commands(command_map.get(params['device_type']))
        public = {k:v for k,v in item.items() if k not in {'target','profile','device_type'}}
        token = [collector._session_key(params), public, command_map if 'commands' not in item else None]
        task_id = hashlib.sha256(json.dumps(token,sort_keys=True).encode()).hexdigest()
        prepared.setdefault(task_id, dict(item, task_id=task_id))
    return list(prepared.values()), command_map


def _proofs(collector, outcome, directory, task_id, attempt):
    proofs = []
    for index, result in enumerate(outcome.get('results', [])):
        oid = result.get('output_id')
        if not oid: continue
        destination = directory/'bang-chung'/f'{task_id}-{attempt}-{index}.txt'
        with collector._output_lease(oid) as source:
            shutil.copyfile(source, destination)
        digest = hashlib.sha256()
        with destination.open('rb') as handle:
            for block in iter(lambda:handle.read(1024*1024), b''): digest.update(block)
        proofs.append({'file':str(destination.relative_to(directory)).replace('\\','/'),
                       'sha256':digest.hexdigest()})
    return proofs


def _attempt(collector, task, lane, directory, number, command_map, cancel, budgets, command_offset=0):
    started = stamp(); clock = time.monotonic()
    budget = budgets[lane]
    outcome = None
    with collector.request_budget(timeout=budget['deadline'],cancel=cancel,
                                  connection_timeouts=budget['connection'],
                                  autodetect_timeout=min(budget['deadline'],120)):
        try:
            collector._request.stage = 'validation'
            params = collector._get_settings(task['target'],task.get('device_type'),task.get('profile'))
            collector._resolve_platform(params)
            commands = task.get('commands') or command_map.get(params['device_type'])
            if not commands:
                raise ValueError('No commands configured for the detected platform')
            outcome = collector.execute_many(task['target'],commands[command_offset:],device_type=params['device_type'],
                        profile=task.get('profile'),read_timeout=task.get('read_timeout',budget['read_timeout']),save_output=True)
        except BatchError as exc:
            outcome = {'ok':False,'results':exc.results}
        except Exception as exc:
            outcome = collector.failure_result(exc,task['target'])
    outcome = normalize_result(outcome)
    checked = outcome.get('results',[])
    next_command = command_offset
    for index, checked_result in enumerate(checked):
        checked_result['command_index'] = command_offset + index
        if checked_result.get('ok') and next_command == command_offset + index:
            next_command += 1
    command_sent = any(r.get('command_sent', True) for r in checked)
    retry_safe = all(not r.get('command_sent', True) or is_replay_safe(r.get('command','')) for r in checked)
    failure = next((r for r in reversed(checked) if not r.get('ok')), outcome)
    status = 'success' if outcome.get('ok') else ('partial' if any(r.get('ok') for r in checked) else 'failed')
    result = {'attempt':number,'lane':lane,'status':status,'started_at':started,'finished_at':stamp(),
              'elapsed_ms':round((time.monotonic()-clock)*1000,2),
              'error_category':failure.get('error_category',failure.get('error','cli_error')) if status!='success' else None,
              'retryable':bool(failure.get('retryable')) and retry_safe,
              'command_sent':command_sent,'safe_to_retry':retry_safe,'next_command_index':next_command,
              'command_offset':command_offset,'result_status':outcome['status'],'result':collector.redact_structured(outcome)}
    # Persistence failure is a job failure, never a false success.
    try:
        result['evidence'] = _proofs(collector,outcome,directory,task['task_id'],number)
    except Exception as exc:
        result.update(collection_status=status,status='unknown',result_status='STORAGE_ERROR',export_pending=True,evidence=[],
                      retryable=False,error_category='storage_error',export_error=type(exc).__name__)
    return result


def run_scan(collector, tasks, directory, *, workers=16, slow_workers=4, command_map=None,
             fast_timeout=90, slow_timeout=240, cancel=None, progress=None, retry_statuses=None, replay_uncertain=False, device_timeout=None):
    retry_statuses = set(retry_statuses or [])
    if retry_statuses - {'failed', 'partial', 'unknown'}:
        raise ValueError('retry_statuses must contain failed, partial or unknown')
    if collector.max_workers < 2:
        raise ValueError('Fast/slow scan needs max_workers >= 2 in collector configuration')
    workers = min(bounded_int(workers,16,2,32), collector.max_workers)
    slow_workers = min(bounded_int(slow_workers,4,1,31), workers-1)
    fast_timeout = bounded_int(fast_timeout,90,1,3600)
    slow_timeout = bounded_int(slow_timeout,240,fast_timeout,3600)
    device_timeout = bounded_int(device_timeout,slow_timeout,1,3600)
    prepared, command_map = prepare_tasks(collector,tasks,command_map)
    directory = Path(directory).resolve();directory.mkdir(parents=True,exist_ok=True)
    lock = directory/'scan.lock'
    with lock.open('x',encoding='utf-8') as handle:
        handle.write(str(os.getpid()));handle.flush();os.fsync(handle.fileno())
    try:
        return _run_locked(collector,prepared,command_map,directory,workers,slow_workers,
                           fast_timeout,slow_timeout,cancel or threading.Event(),progress,len(tasks)-len(prepared),retry_statuses,replay_uncertain,device_timeout)
    finally:
        lock.unlink()


def _run_locked(c, tasks, command_map, directory, workers, slow_workers, fast_timeout, slow_timeout, cancel, progress, duplicates, retry_statuses, replay_uncertain, device_timeout):
    manifest = directory/'scan-manifest.json'
    binding = {'version':1,'plan_hash':hashlib.sha256(json.dumps([tasks,command_map],sort_keys=True).encode()).hexdigest(),
               'total':len(tasks)}
    if manifest.exists():
        if json.loads(manifest.read_text(encoding='utf-8')) != binding:
            raise ValueError('Resume directory belongs to another plan/identity')
    else:
        if any(p.name!='scan.lock' and not (
                p.resolve() == c.output_dir.resolve() == directory/'raw-output' and
                p.is_dir() and not any(p.iterdir())) for p in directory.iterdir()):
            raise ValueError('New job output directory must be empty')
        atomic_json(manifest,binding)
    records_dir = directory/'results';records_dir.mkdir(exist_ok=True)
    (directory/'bang-chung').mkdir(exist_ok=True)
    states = {}; lanes = {'fast':collections.deque(), 'slow':collections.deque()}
    for task in tasks:
        path = records_dir/(task['task_id']+'.json')
        if path.exists():
            record = json.loads(path.read_text(encoding='utf-8'))
            if record.get('task_id') != task['task_id']:
                raise ValueError('Invalid checkpoint task identity')
            for attempt in record.get('attempts',[]):
                for proof in attempt.get('evidence',[]):
                    file = (directory/proof['file']).resolve()
                    if not file.is_relative_to(directory): raise ValueError('Invalid evidence path')
                    digest=hashlib.sha256()
                    with file.open('rb') as handle:
                        for block in iter(lambda:handle.read(1024*1024), b''):digest.update(block)
                    if digest.hexdigest()!=proof['sha256']:raise ValueError('Archived evidence changed')
            if record['status']=='running':
                record.update(status='unknown',interrupted=True,message='Interrupted attempt; reconcile before explicit replay')
                atomic_json(path,record)
            states[task['task_id']]=record
            if record['status'] in retry_statuses:
                latest = record.get('attempts', [])[-1] if record.get('attempts') else {}
                if latest.get('export_pending'):
                    try:
                        latest['evidence'] = _proofs(c,latest['result'],directory,task['task_id'],latest['attempt'])
                        latest['export_pending'] = False
                        record['status'] = latest['collection_status']
                        latest['status'] = record['status']
                        restored = normalize_result(latest['result'])
                        latest['result_status'] = restored['status']
                        failed = next((r for r in reversed(restored.get('results', [])) if not r.get('ok')), restored)
                        latest['error_category'] = failed.get('error_category') if not restored.get('ok') else None
                        atomic_json(path,record)
                    except Exception as exc:
                        record.update(status='unknown',message='Evidence export still pending: '+type(exc).__name__)
                        atomic_json(path,record)
                        continue
                    if record['status'] == 'success':
                        continue
                planned = task.get('commands')
                if planned is None:
                    planned = [command for values in command_map.values() for command in values]
                planned_reads = bool(planned) and all(is_replay_safe(command) for command in planned)
                # 1.6.x checkpoints lack replay metadata; infer only observational tasks.
                safe = bool(latest.get('safe_to_retry', planned_reads))
                if record.get('interrupted') and not planned_reads:
                    safe = False
                if 'next_command_index' not in record:
                    completed = latest.get('command_offset', 0)
                    for previous in latest.get('result', {}).get('results', []):
                        if not previous.get('ok'):
                            break
                        completed += 1
                    record['next_command_index'] = completed
                if not safe and not replay_uncertain:
                    record.update(status='unknown',needs_reconciliation=True,
                                  message='A command may have executed; inspect evidence or explicitly use --replay-uncertain')
                    atomic_json(path,record)
                else:
                    record.update(cycle_attempts=0,needs_reconciliation=False,replay_from_start=not safe,
                                  device_elapsed_seconds=0,device_budget_seconds=device_timeout)
                    if not safe:
                        record['next_command_index'] = 0
                    lanes['slow'].append(task)
            elif record['status']=='retry_pending':
                lanes['slow'].append(task)
        else:lanes[task['lane']].append(task)
    budgets = {
        'fast':{'deadline':fast_timeout,'connection':{'conn_timeout':10,'banner_timeout':15,'auth_timeout':30},'read_timeout':45},
        'slow':{'deadline':slow_timeout,'connection':{'conn_timeout':30,'banner_timeout':45,'auth_timeout':60},'read_timeout':120}}
    limits = {'fast':workers-slow_workers,'slow':slow_workers}
    active = {'fast':0,'slow':0};pending = {}
    device_clocks = {}
    def save(record):
        atomic_json(records_dir/(record['task_id']+'.json'),record);states[record['task_id']]=record
    def retire_owned_raw(attempt):
        # Only the CLI's private scratch directory, never shared MCP outputs.
        # Results and permanent evidence have already been committed above.
        if attempt.get('export_pending') or c.output_dir.resolve() != directory/'raw-output':
            return
        for result in attempt.get('result', {}).get('results', []):
            oid = result.get('output_id')
            if oid:
                c.retire_output(oid)
    def summary():
        counts=collections.Counter(r['status'] for r in states.values())
        return {'total':len(tasks),'duplicates_removed':duplicates,
                **{k:counts[k] for k in ['success','failed','partial','unknown','running','retry_pending']},
                'pending':len(tasks)-len(states),'cancelled':cancel.is_set(),
                'ok':counts['success']==len(tasks)}
    with futures.ThreadPoolExecutor(max_workers=limits['fast'],thread_name_prefix='scan-fast') as fast_pool, \
         futures.ThreadPoolExecutor(max_workers=limits['slow'],thread_name_prefix='scan-slow') as slow_pool:
        pools={'fast':fast_pool,'slow':slow_pool}
        while pending or (not cancel.is_set() and any(lanes.values())):
            for lane in ['fast','slow']:
                while not cancel.is_set() and lanes[lane] and active[lane]<limits[lane]:
                    task=lanes[lane].popleft();old=states.get(task['task_id'],{})
                    identity = task['task_id']
                    cap = min(device_timeout, old.get('device_budget_seconds', device_timeout))
                    if identity not in device_clocks:
                        device_clocks[identity] = (time.monotonic(), old.get('device_elapsed_seconds', 0))
                    cycle_start, prior_elapsed = device_clocks[identity]
                    elapsed = prior_elapsed + time.monotonic() - cycle_start
                    remaining = cap - elapsed
                    if remaining <= 0:
                        old.update(task_id=identity,target=task['target'],status='partial' if old.get('next_command_index',0) else 'failed',
                                   result_status='TIMEOUT',error_category='device_timeout',
                                   device_budget_seconds=cap,device_elapsed_seconds=elapsed,
                                   message='Total device time budget exhausted; no further SSH attempted')
                        save(old)
                        continue
                    attempt_budgets = {name:dict(value) for name,value in budgets.items()}
                    attempt_budgets[lane]['deadline'] = min(budgets[lane]['deadline'], remaining)
                    record={'task_id':task['task_id'],'target':task['target'],'status':'running',
                            'lane':lane,'started_at':stamp(),'attempts':old.get('attempts',[]),
                            'cycle_attempts':old.get('cycle_attempts',len(old.get('attempts',[])))+1,
                            'replay_from_start':old.get('replay_from_start',False),
                            'device_budget_seconds':cap,'device_elapsed_seconds':elapsed,
                            'next_command_index':old.get('next_command_index',0)}
                    save(record)
                    offset=old.get('next_command_index',0)
                    future=pools[lane].submit(_attempt,c,task,lane,directory,len(record['attempts'])+1,command_map,cancel,attempt_budgets,offset)
                    pending[future]=(task,lane);active[lane]+=1
            if not pending:break
            try:
                done,_=futures.wait(pending,timeout=.1,return_when=futures.FIRST_COMPLETED)
            except KeyboardInterrupt:
                cancel.set();continue
            for future in done:
                task,lane=pending.pop(future);active[lane]-=1
                record=states[task['task_id']]
                try:
                    attempt=future.result();record['attempts'].append(attempt)
                    record['next_command_index']=attempt['next_command_index']
                    cycle_start, prior_elapsed = device_clocks[task['task_id']]
                    record['device_elapsed_seconds'] = prior_elapsed + time.monotonic() - cycle_start
                    remaining = record['device_budget_seconds'] - record['device_elapsed_seconds']
                    attempt['device_budget_exceeded'] = remaining <= 0
                    retry=(remaining > 0 and record['cycle_attempts'] < 2 and attempt['retryable'] and attempt['error_category'] in
                           {'connect_timeout','banner_timeout','read_timeout','auth_timeout','connection_lost','handshake_incomplete'} and not cancel.is_set())
                    record['status']='retry_pending' if retry else attempt['status']
                    record['finished_at']=stamp();save(record)
                    retire_owned_raw(attempt)
                    if retry:lanes['slow'].append(task)
                except Exception as exc:
                    record.update(status='unknown',message='Collection/export incomplete: '+type(exc).__name__)
                    save(record)
                if progress:progress(summary())
    result=summary();atomic_json(directory/'scan-summary.json',result)
    return result


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    source=parser.add_mutually_exclusive_group(required=True)
    source.add_argument('--all',action='store_true',help='All inventory aliases')
    source.add_argument('--plan',type=Path,help='JSON task array: target, commands, device_type, profile, read_timeout, lane')
    parser.add_argument('--commands-file',type=Path,help='JSON device_type -> commands; defaults collect version only')
    parser.add_argument('--config',default='mcp/devices.json')
    parser.add_argument('--credentials-file',help='Shared credential JSON; relative to config directory')
    parser.add_argument('--inventory-csv',default='input/device.csv')
    parser.add_argument('--output',required=True,type=Path)
    parser.add_argument('--workers',type=int,default=16)
    parser.add_argument('--slow-workers',type=int,default=4)
    parser.add_argument('--fast-timeout',type=int,default=90)
    parser.add_argument('--slow-timeout',type=int,default=240)
    parser.add_argument('--device-timeout',type=int,default=None,help='Shared fast/retry device budget in seconds; defaults to slow-timeout')
    parser.add_argument('--retry-status', nargs='+', choices=['failed','partial','unknown'], help='Explicitly resume selected unsuccessful states, preserving successes and history')
    parser.add_argument('--replay-uncertain', action='store_true', help='Agent explicitly authorizes replay of an unsuccessful command whose effects are uncertain')
    parser.add_argument('--execute',action='store_true',help='Actually connect; default is preview only')
    args=parser.parse_args()
    from collector_backend import load_config,load_inventory_csv
    if args.execute:
        from bootstrap import prepare_environment
        prepare_environment()
    config=load_inventory_csv(load_config(args.config,args.credentials_file),args.inventory_csv)
    root=Path(__file__).resolve().parents[1]
    config.setdefault('defaults', {}).setdefault('autodetect_cache_file', str(root/'runtime/data/netmiko/autodetect.sqlite3'))
    raw_directory = args.output.resolve()/'raw-output' if args.execute else root/'runtime/data/netmiko/outputs'
    config.setdefault('defaults',{}).update(alt_host_keys=True,alt_key_file=str(root/'mcp/ssh/known_hosts'),
                                           output_dir=str(raw_directory), output_storage_mode='exclusive')
    collector=Collector(config)
    try:
        tasks=[{'target':alias} for alias in collector.devices] if args.all else json.loads(args.plan.read_text(encoding='utf-8-sig'))
        command_map=json.loads(args.commands_file.read_text(encoding='utf-8-sig')) if args.commands_file else None
        prepared,_=prepare_tasks(collector,tasks,command_map)
        if not args.execute:
            print(json.dumps({'preview':True,'total':len(tasks),'unique_tasks':len(prepared),'ssh_executed':False}));return 0
        result=run_scan(collector,tasks,args.output,workers=args.workers,slow_workers=args.slow_workers,
                        command_map=command_map,fast_timeout=args.fast_timeout,slow_timeout=args.slow_timeout,
                        retry_statuses=args.retry_status,replay_uncertain=args.replay_uncertain,device_timeout=args.device_timeout,
                        progress=lambda s:print(json.dumps({'progress':s}),flush=True))
        print(json.dumps(result));return 0 if result['ok'] else 2
    finally:collector.shutdown()

if __name__=='__main__':raise SystemExit(main())
