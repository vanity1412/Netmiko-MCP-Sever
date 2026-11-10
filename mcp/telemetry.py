"""Bounded, credential-free phase measurements; no extra SSH operations."""
import contextlib
from collections import deque
import functools
import threading
import time

_connection_context = threading.local()


@contextlib.contextmanager
def connection_measurements():
    previous = getattr(_connection_context, 'timings', None)
    timings = {}
    _connection_context.timings = timings
    try:
        yield timings
    finally:
        _connection_context.timings = previous


def current_connection_timings():
    timings = getattr(_connection_context, 'timings', None)
    return timings if timings is not None else {}


class PhaseMetrics:
    def __init__(self):
        self.lock = threading.Lock()
        self.phases = {}

    def add(self, phase, milliseconds, failed=False):
        with self.lock:
            entry = self.phases.setdefault(phase, {'count': 0, 'failures': 0, 'total_ms': 0., 'recent': deque(maxlen=128)})
            entry['count'] += 1
            entry['failures'] += int(failed)
            entry['total_ms'] += milliseconds
            entry['recent'].append(milliseconds)

    def snapshot(self):
        with self.lock:
            result = {}
            for phase, entry in self.phases.items():
                recent = sorted(entry['recent'])
                result[phase] = {k: round(v, 3) if isinstance(v, float) else v for k, v in entry.items() if k != 'recent'}
                result[phase].update(sample_count=len(recent),
                    p50_ms=round(recent[(len(recent)-1)//2], 3),
                    p95_ms=round(recent[min(len(recent)-1, (95*len(recent)+99)//100-1)], 3))
            return result


def measured_phase(phase):
    def decorate(method):
        @functools.wraps(method)
        def call(self, *args, **kwargs):
            with self._measure(phase):
                return method(self, *args, **kwargs)
        return call
    return decorate


def time_connection_method(owner, method, phase, timings):
    """Wrap an individual Netmiko/Paramiko instance, never a global auth hook."""
    original = getattr(owner, method)
    @functools.wraps(original)
    def call(*args, **kwargs):
        started = time.monotonic()
        try:
            return original(*args, **kwargs)
        except Exception as exc:
            exc._network_timings_ms = timings
            raise
        finally:
            timings[phase] = timings.get(phase, 0.) + (time.monotonic()-started)*1000
    setattr(owner, method, call)
