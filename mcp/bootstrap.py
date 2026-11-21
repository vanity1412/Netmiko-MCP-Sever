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
    os.environ.setdefault('NETWORK_MCP_DATA_DIR', str(ROOT / 'runtime' / 'data' / 'netmiko'))
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


def load_deployment_config(backend, config_path, *, inventory_csv=None, credentials_file=None, output_dir=None):
    """Resolve the same deployment inputs for stdio and the Python client."""
    config = backend.load_config(str(ROOT / Path(config_path).expanduser()),
                                 credentials_file=os.fspath(credentials_file) if credentials_file is not None else None)
    if inventory_csv:
        config = backend.load_inventory_csv(config, str(ROOT / Path(inventory_csv).expanduser()))
    defaults = config.setdefault('defaults', {})
    defaults.setdefault('alt_key_file', str(ROOT / 'mcp' / 'ssh' / 'known_hosts'))
    defaults.setdefault('alt_host_keys', True)
    defaults.setdefault('autodetect_cache_file', str(ROOT / 'runtime/data/netmiko/autodetect.sqlite3'))
    if output_dir:
        defaults['output_dir'] = str(ROOT / Path(output_dir).expanduser())
    elif not defaults.get('output_dir'):
        data_dir = Path(os.environ.get('NETWORK_MCP_DATA_DIR') or ROOT / 'runtime/data/netmiko')
        defaults['output_dir'] = str(data_dir / 'outputs')
    return config


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--config', required=True)
    parser.add_argument('--inventory-csv', help='Optional CSV merged into devices declared in config')
    parser.add_argument('--credentials-file', help='Shared credential JSON; relative to config directory')
    parser.add_argument('--check', action='store_true')
    parser.add_argument('--output-dir', help='Optional isolated evidence directory; credentials/inventory unchanged')
    args = parser.parse_args()
    prepare_environment()
    spec = importlib.util.spec_from_file_location('goosenet_collector', BACKEND)
    backend = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(backend)
    config = load_deployment_config(backend, args.config, inventory_csv=args.inventory_csv,
                                    credentials_file=args.credentials_file, output_dir=args.output_dir)
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
