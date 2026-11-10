"""Verify startup and MCP framing/catalog without issuing any device SSH tool."""
import argparse
import json
from pathlib import Path
import subprocess
import sys


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', required=True)
    parser.add_argument('--inventory-csv')
    parser.add_argument('--credentials-file')
    args = parser.parse_args()
    command = [sys.executable, '-u', str(Path(__file__).with_name('bootstrap.py')),
               '--config', str(Path(args.config).resolve())]
    for option in ('inventory_csv', 'credentials_file'):
        value = getattr(args, option)
        if value:
            command += ['--' + option.replace('_', '-'), str(Path(value).resolve())]
    try:
        validation = subprocess.run(command + ['--check'], capture_output=True,
            text=True, encoding='utf-8', timeout=30)
        if validation.returncode or not json.loads(validation.stdout).get('ok'):
            raise ValueError('Configuration validation failed')
        requests = [
            {'jsonrpc': '2.0', 'id': 1, 'method': 'initialize', 'params': {
                'protocolVersion': '2025-11-25', 'capabilities': {},
                'clientInfo': {'name': 'install-check', 'version': '1'}}},
            {'jsonrpc': '2.0', 'method': 'notifications/initialized'},
            {'jsonrpc': '2.0', 'id': 2, 'method': 'tools/list'},
            {'jsonrpc': '2.0', 'id': 3, 'method': 'tools/call',
             'params': {'name': 'ssh_status', 'arguments': {}}},
        ]
        result = subprocess.run(command, input=''.join(json.dumps(r)+'\n' for r in requests),
            capture_output=True, text=True, encoding='utf-8', timeout=30)
        replies = {r['id']: r for r in map(json.loads, result.stdout.splitlines())}
        if result.returncode or set(replies) != {1, 2, 3} or any('error' in r for r in replies.values()):
            raise ValueError('MCP handshake failed')
        status_reply = replies[3]['result']
        if status_reply.get('isError'):
            raise ValueError('MCP status failed')
        status = json.loads(status_reply['content'][0]['text'])
        count = len(replies[2]['result']['tools'])
        if count != 10 or status['connections_opened'] != 0:
            raise ValueError('Unexpected catalog or connection activity')
        print(json.dumps({'ok': True, 'mcp_connected': True, 'tools': count,
            'version': status['version'], 'ssh_tested': False,
            'credential_validity_on_device': 'not_tested'}))
        return 0
    except (ValueError, KeyError, TypeError, subprocess.TimeoutExpired, OSError):
        # Do not echo library stderr/config values containing private credentials.
        print(json.dumps({'ok': False, 'mcp_connected': False, 'ssh_tested': False,
            'message': 'Install check failed. Check dependencies, paths and credential profiles; see docs/SETUP.md.'}))
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
