"""Check the actual configured STDIO MCP without using a shared service port."""
import argparse
import json
import os
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--ssh', action='store_true', help='Also run read-only uptime on the test device')
    args = parser.parse_args()
    config = json.loads((ROOT / 'opencode.json').read_text(encoding='utf-8-sig'))
    server = config['mcp']['servers']['netmiko']
    command = server['command']
    environment = os.environ.copy()
    for key, value in server.get('environment', {}).items():
        if value.startswith('{env:') and value.endswith('}'):
            value = os.environ.get(value[5:-1], '')
        environment[key] = value
    requests = [
        {'jsonrpc': '2.0', 'id': 1, 'method': 'initialize', 'params': {'protocolVersion': '2025-11-25', 'capabilities': {}, 'clientInfo': {'name': 'network-check', 'version': '1'}}},
        {'jsonrpc': '2.0', 'method': 'notifications/initialized'},
        {'jsonrpc': '2.0', 'id': 2, 'method': 'tools/list'},
        {'jsonrpc': '2.0', 'id': 3, 'method': 'tools/call', 'params': {'name': 'ssh_inventory', 'arguments': {'summary_only': True}}},
    ]
    if args.ssh:
        requests.append({'jsonrpc': '2.0', 'id': 4, 'method': 'tools/call', 'params': {'name': 'ssh_execute', 'arguments': {'target': 'HNI-AggPE-07-02', 'command': 'show system uptime | no-more', 'expect_string': r'HNI-AggPE-07-02>\s*$', 'read_timeout': 30}}})
    process = subprocess.run(command, cwd=ROOT, env=environment, input=''.join(json.dumps(r) + '\n' for r in requests), capture_output=True, text=True, encoding='utf-8', timeout=75)
    if process.returncode:
        raise RuntimeError('MCP process failed; stderr withheld to protect local information')
    replies = {r['id']: r for r in map(json.loads, process.stdout.splitlines())}
    for request in requests:
        if 'id' not in request:
            continue
        reply = replies.get(request['id'], {})
        if 'error' in reply or 'result' not in reply or reply['result'].get('isError'):
            raise RuntimeError('MCP check failed at ' + request['method'])
    inventory = json.loads(replies[3]['result']['content'][0]['text'])
    summary = {'mcp_connected': True, 'tools': len(replies[2]['result']['tools']), 'devices': inventory['total'], 'profiles': inventory['profiles']}
    if args.ssh:
        result = json.loads(replies[4]['result']['content'][0]['text'])
        if not result.get('ok') or 'Current time:' not in result.get('output', ''):
            raise RuntimeError('SSH test did not return verified uptime')
        summary['ssh_readonly_verified'] = 'HNI-AggPE-07-02'
    print(json.dumps(summary))


if __name__ == '__main__':
    main()
