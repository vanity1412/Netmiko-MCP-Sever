"""Python CLI wrapper using the Collector's execution policy."""
from pathlib import Path
import re
import collector_backend as backend
from bootstrap import load_deployment_config, prepare_environment
from collector_backend import BatchError, Collector, KNOWN_KEYS, normalize_result


SINGLE_OPTIONS = {'read_timeout', 'expect_string', 'use_timing', 'save_output', 'use_textfsm'}
BATCH_OPTIONS = (SINGLE_OPTIONS - {'use_textfsm'}) | {'continue_on_error'}
LEGACY_CONNECTION_OPTIONS = KNOWN_KEYS | {
    'ssh_mode', 'host_key_store_mode', 'auto_enable', 'junos_minimal_recovery',
    'prompt_quiet_seconds', 'timing_quiet_seconds', 'read_timeout', 'request_timeout_seconds',
    'output_dir', 'session_sweep_seconds', 'inline_max_chars', 'execution_policy',
}


class CLIExecutionError(RuntimeError):
    """Compatibility error for send_command callers, with the complete tool result."""

    def __init__(self, result):
        self.result = result
        super().__init__(result.get('error') or 'Output verification failed')


def validate_options(options, supported):
    unknown = set(options) - supported
    if unknown:
        raise ValueError('Unsupported Python fallback options: ' + ', '.join(sorted(unknown)))


class ReadOnlyConnection:
    def __init__(self, *, device_type: str, **params):
        # This wrapper does not load inventory: never guess a Cisco driver.
        if not isinstance(device_type, str) or not re.fullmatch(r'[A-Za-z0-9_]+', device_type):
            raise ValueError('device_type must be supplied from the inventory netmiko_device_type field')
        root = Path(__file__).resolve().parents[1]
        target = params.pop('host')
        validate_options(params, LEGACY_CONNECTION_OPTIONS)
        defaults = dict(params, device_type=device_type)
        if defaults.get('ssh_strict') is True:
            defaults.setdefault('ssh_mode', 'strict')
        defaults.setdefault('ssh_strict', False)
        defaults.setdefault('alt_host_keys', False)
        defaults.setdefault('alt_key_file', str(root / 'mcp/ssh/known_hosts'))
        defaults.setdefault('session_sweep_seconds', 0)
        defaults.setdefault('output_dir', str(root / 'runtime/data/netmiko/outputs'))
        self._bind({'defaults': defaults}, target)

    @classmethod
    def from_config(cls, config_path, *, target, profile=None, device_type=None,
                    inventory_csv=None, credentials_file=None, output_dir=None):
        """Use the same configuration, inventory and target resolution as MCP stdio."""
        prepare_environment()
        config = load_deployment_config(backend, config_path, inventory_csv=inventory_csv,
                                        credentials_file=credentials_file, output_dir=output_dir)
        client = cls.__new__(cls)
        client._bind(config, target, profile=profile, device_type=device_type)
        return client

    def _bind(self, config, target, *, profile=None, device_type=None):
        self.target = target
        self.profile = profile
        self.device_type = device_type
        self.collector = Collector(config)

    def __enter__(self): return self
    def __exit__(self, *args): self.disconnect()
    def disconnect(self): self.collector.shutdown()

    def execute(self, command, **options):
        """Return the structured result, including transport and partial-output errors."""
        validate_options(options, SINGLE_OPTIONS)
        try:
            return self.collector.execute(self.target, command, device_type=self.device_type,
                                          profile=self.profile, **options)
        except Exception as exc:
            return self.collector.failure_result(exc, self.target, command if isinstance(command, str) else None)

    def execute_many(self, commands, **options):
        """Return the full batch result, including skipped commands and recovery evidence."""
        validate_options(options, BATCH_OPTIONS)
        try:
            return self.collector.execute_many(self.target, commands, device_type=self.device_type,
                                               profile=self.profile, **options)
        except BatchError as exc:
            return exc.summary or normalize_result({'ok': False, 'target': self.target, 'results': exc.results})
        except Exception as exc:
            return self.collector.failure_result(exc, self.target)

    def read_output_bytes(self, output_id, byte_offset=0, length=64000):
        return self.collector.read_output_bytes(output_id, byte_offset, length)

    def send_command(self, command, **options):
        result = self.execute(command, **options)
        if not result['ok']:
            raise CLIExecutionError(result)
        if result.get('saved'):
            chunks, offset = [], 0
            while True:
                part = self.read_output_bytes(result['output_id'], offset)
                chunks.append(part['text'])
                if not part['more']:
                    return ''.join(chunks)
                offset = part['next_byte_offset']
        return result['output']

# Keep both names available for existing callers.
CLIConnection = ReadOnlyConnection
