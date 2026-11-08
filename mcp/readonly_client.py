"""Same-policy Python fallback for local investigation scripts; no write API."""
from pathlib import Path
from collector_backend import Collector, KNOWN_KEYS

class ReadOnlyConnection:
    def __init__(self, **params):
        root = Path(__file__).resolve().parents[1]
        self.target = params.pop('host')
        defaults = {k:v for k,v in params.items() if k in KNOWN_KEYS}
        defaults.update(ssh_strict=True, alt_host_keys=True,
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
