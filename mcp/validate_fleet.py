"""Repeatable fleet validation: TCP/banner census, then bounded read-only SSH pilot."""
from __future__ import annotations

import argparse
import collections
import concurrent.futures
import json
import logging
from pathlib import Path
import random
import socket
import time

from bootstrap import prepare_environment
from collector_backend import Collector, load_config, load_inventory_csv
from scan import atomic_json, run_scan

COMMANDS = {
    'juniper_junos': ['show version', 'show interfaces terse'],
    'cisco_ios': ['show version', 'show interfaces description'],
    'cisco_xr': ['show version', 'show interfaces description'],
    'cisco_nxos': ['show version', 'show interface brief'],
    'huawei': ['display version', 'display interface brief'],
    'linux': ['uname -a', 'ip -br address show'],
}


def probe_endpoint(host, port, timeout):
    started = time.monotonic()
    result = {'host': host, 'port': port, 'tcp_connected': False, 'ssh_banner': False}
    try:
        with socket.create_connection((host, port), timeout=timeout) as conn:
            result['tcp_connected'] = True
            deadline = time.monotonic() + timeout
            banner = b''
            while len(banner) < 4096:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                conn.settimeout(remaining)
                data = conn.recv(512)
                if not data:
                    break
                banner += data
                if any(line.startswith((b'SSH-2.0-', b'SSH-1.99-')) for line in banner.splitlines()):
                    result['ssh_banner'] = True
                    break
            if not result['ssh_banner']:
                result['error_category'] = 'banner_not_verified'
    except OSError as exc:
        result['error_category'] = ('banner_timeout' if result['tcp_connected'] else 'tcp_timeout') if isinstance(exc, TimeoutError) else type(exc).__name__
        result['errno'] = exc.errno
        result['winerror'] = getattr(exc, 'winerror', None)
    result['elapsed_ms'] = round((time.monotonic() - started) * 1000, 2)
    return result


def validate(config, directory, *, execute=False, timeout=2, probe_workers=64, ssh_limit=128, ssh_workers=8):
    directory = Path(directory).resolve()
    directory.mkdir(parents=True, exist_ok=True)
    if (directory / 'fleet-summary.json').exists():
        raise ValueError('Choose a new output directory for a fresh validation')
    config = dict(config, defaults=dict(config.get('defaults', {})))
    config['defaults'].setdefault('autodetect_cache_file', str(Path(__file__).resolve().parents[1]/'runtime/data/netmiko/autodetect.sqlite3'))
    config['defaults'].update(output_dir=str(directory / 'ssh-job' / 'raw-output'),
                              alt_key_file=str(directory / 'known_hosts'),
                              session_sweep_seconds=0, max_workers=ssh_workers, output_storage_mode='exclusive')
    collector = Collector(config)
    started = time.monotonic()
    try:
        endpoints, identities, invalid = {}, {}, []
        for alias in collector.devices:
            try:
                params = collector._get_settings(alias, None, None)
                key = (params['host'], params['port'])
                endpoints.setdefault(key, []).append(alias)
                identities.setdefault(collector._session_key(params), (alias, params))
            except Exception as exc:
                invalid.append({'target': alias, 'error': type(exc).__name__})
        results = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=probe_workers) as pool:
            pending = {pool.submit(probe_endpoint, host, port, timeout): (host, port) for host, port in endpoints}
            for future in concurrent.futures.as_completed(pending):
                result = future.result()
                result['aliases'] = endpoints[pending[future]]
                results.append(result)
                if len(results) % 250 == 0 or len(results) == len(pending):
                    atomic_json(directory / 'tcp-results.json', results)
                    print(json.dumps({'preflight_completed': len(results), 'total': len(pending),
                                      'tcp_connected': sum(r['tcp_connected'] for r in results)}), flush=True)
        atomic_json(directory / 'invalid-inventory.json', invalid)
        atomic_json(directory / 'tcp-results.json', results)
        reachable = {(r['host'], r['port']) for r in results if r['tcp_connected']}
        groups = collections.defaultdict(list)
        for alias, params in identities.values():
            if (params['host'], params['port']) in reachable:
                groups[params['device_type']].append(alias)
        rng = random.Random(20261109)
        for aliases in groups.values(): rng.shuffle(aliases)
        tasks = []
        while groups and len(tasks) < ssh_limit:
            for dtype in list(groups):
                tasks.append({'target': groups[dtype].pop(), 'read_timeout': 45})
                if not groups[dtype]: del groups[dtype]
                if len(tasks) >= ssh_limit: break
        atomic_json(directory / 'ssh-plan.json', tasks)
        summary = {'inventory_aliases': len(collector.devices), 'unique_identities': len(identities),
                   'invalid_inventory': len(invalid), 'unique_endpoints': len(endpoints),
                   'tcp_connected': len(reachable), 'ssh_banners': sum(r['ssh_banner'] for r in results),
                   'preflight_errors': dict(collections.Counter(r['error_category'] for r in results if 'error_category' in r)),
                   'ssh_selected': len(tasks), 'ssh_executed': bool(execute and tasks)}
        atomic_json(directory / 'fleet-summary.json', summary)
        if execute and tasks:
            try:
                summary['ssh'] = run_scan(collector, tasks, directory / 'ssh-job', workers=ssh_workers,
                                          slow_workers=max(1, ssh_workers // 4), command_map=COMMANDS,
                                          fast_timeout=90, slow_timeout=240,
                                          progress=lambda s: print(json.dumps({'ssh_progress': s}), flush=True))
            except Exception as exc:
                summary['ssh_job_error'] = collector.failure_result(exc)
                atomic_json(directory / 'fleet-summary.json', summary)
                raise
        summary['wall_seconds'] = round(time.monotonic() - started, 2)
        atomic_json(directory / 'fleet-summary.json', summary)
        return summary
    finally:
        collector.shutdown()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', default='mcp/devices.json')
    parser.add_argument('--credentials-file', help='Shared credential JSON; relative to config directory')
    parser.add_argument('--inventory-csv', default='input/device.csv')
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--execute', action='store_true', help='SSH into reachable sample; otherwise TCP/banner only')
    parser.add_argument('--tcp-timeout', type=float, default=2)
    parser.add_argument('--probe-workers', type=int, default=64)
    parser.add_argument('--ssh-workers', type=int, default=8)
    parser.add_argument('--ssh-limit', type=int, default=128)
    args = parser.parse_args()
    if not 0 < args.tcp_timeout <= 30 or not 1 <= args.probe_workers <= 128 or not 2 <= args.ssh_workers <= 32 or not 1 <= args.ssh_limit <= 4096:
        parser.error('Invalid timeout/worker/sample limits')
    prepare_environment()
    args.output.mkdir(parents=True, exist_ok=True)
    logging.basicConfig(filename=str(args.output / 'ssh-transport.log'), level=logging.WARNING)
    config = load_inventory_csv(load_config(args.config, args.credentials_file), args.inventory_csv)
    print(json.dumps(validate(config, args.output, execute=args.execute, timeout=args.tcp_timeout,
                              probe_workers=args.probe_workers, ssh_workers=args.ssh_workers, ssh_limit=args.ssh_limit)))


if __name__ == '__main__': main()
