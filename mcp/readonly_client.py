"""Python CLI wrapper. Legacy ReadOnlyConnection name retained; content is not filtered."""
from pathlib import Path
import re
from collector_backend import Collector, KNOWN_KEYS

class ReadOnlyConnection:
    def __init__(self, *, device_type: str, **params):
        # This wrapper does not load inventory: never guess a Cisco driver.
        if not isinstance(device_type, str) or not re.fullmatch(r'[A-Za-z0-9_]+', device_type):
            raise ValueError('device_type must be supplied from the inventory netmiko_device_type field')
        params['device_type'] = device_type
        root = Path(__file__).resolve().parents[1]
        self.target = params.pop('host')
        defaults = {k:v for k,v in params.items() if k in KNOWN_KEYS}
        defaults.update(ssh_strict=False, alt_host_keys=False,
                        alt_key_file=str(root/'mcp/ssh/known_hosts'),
                        session_sweep_seconds=0,
                        output_dir=str(root/'runtime/data/netmiko/outputs'))
        self.collector = Collector({'defaults':defaults})
    def __enter__(self): return self
    def __exit__(self, *args): self.disconnect()
    def disconnect(self): self.collector.shutdown()
    def send_command(self, command, **options):
        allowed = {'read_timeout','expect_string','use_timing','save_output','use_textfsm'}
        if set(options)-allowed:
            raise ValueError('Unsupported fallback options; use MCP for other collection modes')
        result = self.collector.execute(self.target, command, **options)
        if not result['ok']:
            raise RuntimeError(result.get('error','Output verification failed'))
        if result.get('saved'):
            chunks=[]; offset=0
            while True:
                part=self.collector.read_output_bytes(result['output_id'],offset)
                chunks.append(part['text']);offset=part['next_byte_offset']
                if not part['more']:return ''.join(chunks)
        return result['output']

# New name reflects unrestricted CLI; old imports remain compatible.
CLIConnection = ReadOnlyConnection
