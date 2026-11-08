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


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--config', required=True)
    parser.add_argument('--inventory-csv', required=True)
    parser.add_argument('--check', action='store_true')
    parser.add_argument('--output-dir', help='Optional isolated evidence directory; credentials/inventory unchanged')
    args = parser.parse_args()
    os.environ['NETWORK_MCP_DATA_DIR'] = str(ROOT / 'runtime' / 'data' / 'netmiko')
    if not (os.environ.get('NETWORK_SSH_USER') and os.environ.get('NETWORK_SSH_PASSWORD')):
        source = ROOT / 'input' / 'ssh.txt'
        credentials = re.findall(
            r'Username\s*:\s*([^;\r\n]+?)\s*;\s*Password\s*:\s*([^\r\n]+)',
            source.read_text(encoding='utf-8-sig') if source.is_file() else '', re.I,
        )
        if not credentials:
            raise RuntimeError('Fill SSH environment fields in opencode.json or provide input/ssh.txt')
        os.environ['NETWORK_SSH_USER'], os.environ['NETWORK_SSH_PASSWORD'] = (value.strip() for value in credentials[0])
    spec = importlib.util.spec_from_file_location('goosenet_collector', BACKEND)
    backend = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(backend)
    config_path = Path(args.config)
    inventory_path = Path(args.inventory_csv)
    if not config_path.is_absolute():
        config_path = ROOT / config_path
    if not inventory_path.is_absolute():
        inventory_path = ROOT / inventory_path
    config = backend.load_inventory_csv(backend.load_config(str(config_path)), str(inventory_path))
    config.setdefault('defaults', {})['alt_key_file'] = str(ROOT / 'mcp' / 'ssh' / 'known_hosts')
    config['defaults']['alt_host_keys'] = True
    if args.output_dir:
        output_path = Path(args.output_dir)
        config['defaults']['output_dir'] = str(output_path if output_path.is_absolute() else ROOT / output_path)
    profiles = config.setdefault('profiles', {})
    if args.check:
        print(json.dumps({'ok': True, 'devices': len(config.get('devices', {})), 'profiles': list(profiles), 'credentials_available': True}))
        return
    backend.run_stdio(backend.Collector(config))


if __name__ == '__main__':
    main()
