"""Start the existing collector with local, memory-only SSH credential profiles.

Credentials from the OpenCode MCP environment take priority.
Only if that pair is missing, use the local input/ssh.txt fallback.
"""
import argparse
import importlib.util
import json
import os
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BACKEND = ROOT / 'mcp' / 'collector_backend.py'


def prepare_environment(required=False):
    os.environ['NETWORK_MCP_DATA_DIR'] = str(ROOT / 'runtime' / 'data' / 'netmiko')
    if not (os.environ.get('NETWORK_SSH_USER') and os.environ.get('NETWORK_SSH_PASSWORD')):
        source = ROOT / 'input' / 'ssh.txt'
        credentials = re.findall(
            r'Username\s*:\s*([^;\r\n]+?)\s*;\s*Password\s*:\s*([^\r\n]+)',
            source.read_text(encoding='utf-8-sig') if source.is_file() else '', re.I,
        )
        if not credentials:
            if required:
                raise RuntimeError('Provide SSH credentials through profiles, environment or input/ssh.txt')
            return False
        os.environ['NETWORK_SSH_USER'], os.environ['NETWORK_SSH_PASSWORD'] = (value.strip() for value in credentials[0])
    return True


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--config', required=True)
    parser.add_argument('--inventory-csv', required=True)
    parser.add_argument('--credentials-file', help='Shared credential JSON; relative to config directory')
    parser.add_argument('--check', action='store_true')
    parser.add_argument('--output-dir', help='Optional isolated evidence directory; credentials/inventory unchanged')
    args = parser.parse_args()
    prepare_environment()
    spec = importlib.util.spec_from_file_location('goosenet_collector', BACKEND)
    backend = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(backend)
    config_path = Path(args.config)
    inventory_path = Path(args.inventory_csv)
    if not config_path.is_absolute():
        config_path = ROOT / config_path
    if not inventory_path.is_absolute():
        inventory_path = ROOT / inventory_path
    config = backend.load_inventory_csv(backend.load_config(str(config_path), credentials_file=args.credentials_file), str(inventory_path))
    config.setdefault('defaults', {})['alt_key_file'] = str(ROOT / 'mcp' / 'ssh' / 'known_hosts')
    config['defaults']['alt_host_keys'] = True
    config['defaults'].setdefault('autodetect_cache_file', str(ROOT / 'runtime/data/netmiko/autodetect.sqlite3'))
    if args.output_dir:
        output_path = Path(args.output_dir)
        config['defaults']['output_dir'] = str(output_path if output_path.is_absolute() else ROOT / output_path)
    profiles = config.setdefault('profiles', {})
    if args.check:
        collector = backend.Collector(config)
        try:
            missing = 0
            for target in collector.devices:
                settings = collector._get_settings(target, None, None)
                if not settings.get('username') or not any(settings.get(k) for k in ('password', 'use_keys', 'key_file', 'allow_agent')):
                    missing += 1
            print(json.dumps({'ok': missing == 0, 'devices': len(collector.devices), 'profiles': list(profiles),
                              'credentials_available': missing == 0, 'devices_missing_credentials': missing}))
        finally:
            collector.shutdown()
        return
    backend.run_stdio(backend.Collector(config))


if __name__ == '__main__':
    main()
