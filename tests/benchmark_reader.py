"""Offline reader microbenchmark. Each measurement runs in a fresh process.

No sockets, device commands, credential files or backend behavior changes.
Accelerated clock skips requested sleeps but retains real processing time.
"""
import argparse
import codecs
from collections import deque
import contextlib
import cProfile
import hashlib
from importlib.metadata import version
import json
from pathlib import Path
import platform
import subprocess
import sys
import threading
import time
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'mcp'))
import collector_backend as backend
from stress_resources import ResourceMonitor


def fixture(size_bytes, kind):
    text = 'record mạng đường truyền alpha beta gamma 0123456789 ' * 8
    if kind == 'json':
        line = ('  "' + text + '",\n').encode('utf-8')
        body = line * max(1, size_bytes // len(line))
        return b'[\n' + body[:-2] + b'\n]\nrouter#', 'show data | display json'
    if kind in ('xml', 'xml_prompt'):
        line = ('<row>' + text + '</row>\n').encode('utf-8')
        if kind == 'xml_prompt':
            block = line * max(1, min(size_bytes, 65536) // len(line)) + b'router#\n'
            return b'<data>\n' + block * max(1, size_bytes // len(block)) + b'</data>\nrouter#', 'show data | display xml'
        return b'<data>\n' + line * max(1, size_bytes // len(line)) + b'</data>\nrouter#', 'show data | display xml'
    line = (text + '\n').encode('utf-8')
    body = line * max(1, size_bytes // len(line))
    if kind in ('fake_prompt', 'pager'):
        middle = len(body) // 2
        # Split only at a UTF-8 line boundary.
        middle = body.index(b'\n', middle) + 1
        marker = b'router#\n' if kind == 'fake_prompt' else b'--More--\n'
        return body[:middle] + marker + body[middle:] + b'router#', 'show data'
    if kind == 'banner':
        return b'banner motd ^C\n' + body + b'^C\nrouter#', 'show running-config'
    return body + b'router#', 'show data'


class Clock:
    def __init__(self, accelerated=True):
        self.accelerated = accelerated
        self.skipped = 0.
        self.requested = 0.
        self.calls = 0
    def monotonic(self): return time.monotonic() + self.skipped
    def sleep(self, seconds):
        self.calls += 1
        self.requested += seconds
        if self.accelerated:
            self.skipped += seconds
        else:
            time.sleep(seconds)


class Channel:
    def __init__(self, wire, chunk_bytes, split_at=None):
        self.wire, self.chunk_bytes = wire, chunk_bytes
        self.position = 0
        self.split_at = deque([split_at] if isinstance(split_at, int) else split_at or [])
        self.sent = False
        self.writes = []
        self.data_reads = 0
        self.decoder = codecs.getincrementaldecoder('utf-8')()
        self._network_prompt_text = 'router#'
        self._network_prompt_regex = r'(?m)^router#$'
        self.remote_conn = SimpleNamespace(closed=False, eof_received=False)
    def normalize_cmd(self, command): return command + '\n'
    def write_channel(self, command):
        self.writes.append(command)
        self.sent = True
    def read_channel(self):
        if not self.sent or self.position >= len(self.wire): return ''
        end = min(len(self.wire), self.position + self.chunk_bytes)
        while self.split_at and self.split_at[0] <= self.position:
            self.split_at.popleft()
        if self.split_at and self.split_at[0] < end:
            end = self.split_at[0]
        data = self.wire[self.position:end]
        self.position = end
        self.data_reads += 1
        return self.decoder.decode(data, final=end == len(self.wire))


def measure(size_bytes, chunk_bytes, kind, clock_mode='accelerated', profile_path=None):
    wire, command = fixture(size_bytes, kind)
    expected = wire.replace(b'--More--', b' ' * 8) if kind == 'pager' else wire
    expected_hash = hashlib.sha256(expected).hexdigest()
    split_at = None
    if kind in ('fake_prompt', 'pager'):
        marker = b'router#' if kind == 'fake_prompt' else b'--More--'
        split_at = wire.index(marker) + len(marker)
    elif kind == 'xml_prompt':
        split_at = []
        position = 0
        while (position := wire.find(b'router#', position)) != -1:
            position += len(b'router#')
            split_at.append(position)
    channel = Channel(wire, chunk_bytes, split_at)
    clock = Clock(clock_mode == 'accelerated')
    stats = {}
    def instrument(name, original):
        entry = stats.setdefault(name, {'calls': 0, 'input_chars': 0, 'large_calls': 0, 'inclusive_seconds': 0.})
        def wrapped(*args, **kwargs):
            started = time.perf_counter()
            try:
                result = original(*args, **kwargs)
                count = len(result) if name == 'buffer_value' else len(args[-1])
                entry['calls'] += 1
                entry['input_chars'] += count
                entry['large_calls'] += int(count > 16384)
                return result
            finally:
                entry['inclusive_seconds'] += time.perf_counter() - started
        return wrapped
    dummy = SimpleNamespace(_guard=threading.Lock(), _sessions={})
    profiler = cProfile.Profile() if profile_path else None
    with contextlib.ExitStack() as stack:
        stack.enter_context(patch.object(backend, 'time', clock))
        for name, owner, attribute in (
                ('buffer_value', backend.OutputBuffer, 'value'),
                ('clean_terminal', backend, 'clean_terminal'),
                ('container_check', backend, 'output_container_open'),
                ('banner_check', backend, 'config_banner_open')):
            stack.enter_context(patch.object(owner, attribute, instrument(name, getattr(owner, attribute))))
        with ResourceMonitor(dummy) as monitor:
            if profiler: profiler.enable()
            output, failure = backend.read_cli_output(channel, command, 1000000, channel._network_prompt_regex)
            if profiler: profiler.disable()
    if profiler:
        profiler.dump_stats(profile_path)
    output_hash = hashlib.sha256(output.encode('utf-8')).hexdigest()
    for entry in stats.values(): entry['inclusive_seconds'] = round(entry['inclusive_seconds'], 6)
    result = {'kind': kind, 'requested_bytes': size_bytes, 'wire_bytes': len(wire),
              'chunk_bytes': chunk_bytes, 'clock': clock_mode,
              'data_reads': channel.data_reads, 'output_chars': len(output),
              'sha256_expected': expected_hash, 'sha256_actual': output_hash,
              'integrity_ok': expected_hash == output_hash,
              'failure': failure, 'command_writes': len(channel.writes),
              'sleep_calls': clock.calls, 'requested_sleep_seconds': round(clock.requested, 6),
              'skipped_sleep_seconds': round(clock.skipped, 6),
              'buffer_read_amplification': round(stats['buffer_value']['input_chars'] / max(1, len(output)), 3),
              'functions': stats, 'resources': monitor.report()}
    result['resources']['scope'] = 'reader process; fixture allocated before baseline; sampled RSS, not guaranteed peak'
    expected_failure = 'prompt_candidate_continuation' if kind == 'fake_prompt' else None
    result['expected_error_reason'] = expected_failure
    failure_ok = (failure is None if expected_failure is None else
                  bool(failure and failure.get('error_category') == 'output_verification'
                       and failure.get('error_reason') == expected_failure))
    result['valid'] = (result['integrity_ok'] and failure_ok
                       and channel.writes == [command + '\n'] + ([' '] if kind == 'pager' else []))
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--sizes-mib', nargs='+', type=int, default=[1, 10, 100])
    parser.add_argument('--chunks', nargs='+', type=int, default=[4096, 65536, 1048576])
    parser.add_argument('--kinds', nargs='+', choices=['plain', 'json', 'xml', 'banner', 'fake_prompt', 'pager', 'xml_prompt'], default=['plain', 'json', 'xml', 'banner'])
    parser.add_argument('--repeats', type=int, default=1)
    parser.add_argument('--clock', choices=['accelerated', 'real'], default='accelerated')
    parser.add_argument('--case-timeout', type=int, default=300)
    parser.add_argument('--output', type=Path)
    parser.add_argument('--profile', type=Path)
    parser.add_argument('--child', action='store_true', help=argparse.SUPPRESS)
    args = parser.parse_args()
    if min(args.sizes_mib + args.chunks + [args.repeats, args.case_timeout]) <= 0:
        parser.error('sizes, chunks, repeats and timeout must be positive')
    if args.profile and (not args.child or len(args.sizes_mib) != 1 or len(args.chunks) != 1 or len(args.kinds) != 1):
        parser.error('--profile requires --child and exactly one case')
    if args.child:
        result = measure(args.sizes_mib[0]*1024*1024, args.chunks[0], args.kinds[0], args.clock, args.profile)
        print(json.dumps(result))
        return 0 if result['valid'] else 1
    if not args.output: parser.error('--output is required for matrix runs')
    if args.output.exists(): parser.error('output already exists; choose a new artifact path')
    report = {'environment': {'python': platform.python_version(), 'platform': platform.platform(),
                'netmiko': version('netmiko'),
                'reader_sha256': hashlib.sha256(Path(backend.__file__).read_bytes()).hexdigest(),
                'harness_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                'git_revision': subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=Path(__file__).resolve().parents[1], text=True).strip()},
              'scope': 'synthetic channel only; no SSH/network/AAA/worker IPC; instrumented reader',
              'cases': []}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2), encoding='utf-8')
    for size in args.sizes_mib:
        for kind in args.kinds:
            for chunk in args.chunks:
                for repeat in range(args.repeats):
                    command = [sys.executable, str(Path(__file__).resolve()), '--child', '--sizes-mib', str(size),
                               '--chunks', str(chunk), '--kinds', kind, '--clock', args.clock]
                    started = time.monotonic()
                    try:
                        child = subprocess.run(command, text=True, encoding='utf-8', capture_output=True, timeout=args.case_timeout)
                        case = json.loads(child.stdout)
                        case.update(repeat=repeat, child_returncode=child.returncode)
                    except (subprocess.TimeoutExpired, ValueError) as exc:
                        case = {'requested_mib': size, 'kind': kind, 'chunk_bytes': chunk, 'repeat': repeat,
                                'valid': False, 'error': type(exc).__name__}
                    case['child_wall_seconds'] = round(time.monotonic()-started, 3)
                    report['cases'].append(case)
                    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding='utf-8')
                    print(json.dumps({k: case[k] for k in ('kind', 'chunk_bytes', 'valid', 'child_wall_seconds')}), flush=True)
    return 0 if all(case['valid'] for case in report['cases']) else 1


if __name__ == '__main__':
    sys.exit(main())
