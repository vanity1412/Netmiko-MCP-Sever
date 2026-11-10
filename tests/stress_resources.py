"""Standard-library process samples for the offline fleet harness."""
import os
from pathlib import Path
import threading
import time


def process_resources():
    result = {'python_threads': threading.active_count()}
    if os.name == 'nt':
        import ctypes
        from ctypes import wintypes
        class Memory(ctypes.Structure):
            _fields_ = [('cb', wintypes.DWORD), ('faults', wintypes.DWORD),
                ('peak_rss', ctypes.c_size_t), ('rss', ctypes.c_size_t),
                ('peak_paged', ctypes.c_size_t), ('paged', ctypes.c_size_t),
                ('peak_nonpaged', ctypes.c_size_t), ('nonpaged', ctypes.c_size_t),
                ('pagefile', ctypes.c_size_t), ('peak_pagefile', ctypes.c_size_t),
                ('private', ctypes.c_size_t)]
        kernel = ctypes.WinDLL('kernel32', use_last_error=True)
        kernel.GetCurrentProcess.restype = wintypes.HANDLE
        handle = kernel.GetCurrentProcess()
        info = Memory(); info.cb = ctypes.sizeof(info)
        psapi = ctypes.WinDLL('psapi', use_last_error=True)
        psapi.GetProcessMemoryInfo.argtypes = [wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD]
        if not psapi.GetProcessMemoryInfo(handle, ctypes.byref(info), info.cb):
            raise ctypes.WinError(ctypes.get_last_error())
        result.update(rss_bytes=info.rss, private_bytes=info.private)
        count = wintypes.DWORD()
        kernel.GetProcessHandleCount.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
        if kernel.GetProcessHandleCount(handle, ctypes.byref(count)):
            result['os_handles'] = count.value
    elif Path('/proc/self/status').exists():
        fields = dict(line.split(':', 1) for line in Path('/proc/self/status').read_text().splitlines())
        result['rss_bytes'] = int(fields['VmRSS'].split()[0])*1024
        result['os_handles'] = len(list(Path('/proc/self/fd').iterdir()))
    else:
        import resource
        peak = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        result['peak_rss_bytes'] = peak if os.uname().sysname == 'Darwin' else peak*1024
    return result


class ResourceMonitor:
    def __init__(self, collector):
        self.collector = collector
        self.before = process_resources()
        self.peaks = dict(self.before)
        self.stop = threading.Event()
        self.error = None

    def __enter__(self):
        self.started = time.monotonic(); self.cpu = time.process_time()
        def sample():
            try:
                while not self.stop.wait(.025):
                    values = process_resources()
                    with self.collector._guard:
                        values['sessions'] = len(self.collector._sessions)
                        values['leased_sessions'] = sum(bool(e.get('borrowers')) for e in self.collector._sessions.values())
                    for key, value in values.items():
                        self.peaks[key] = max(self.peaks.get(key, 0), value)
            except Exception as exc:
                self.error = exc
        self.thread = threading.Thread(target=sample, name='offline-resource-monitor')
        self.thread.start()
        return self

    def __exit__(self, *exc):
        self.stop.set(); self.thread.join(timeout=2)
        self.elapsed = time.monotonic()-self.started
        self.cpu_seconds = time.process_time()-self.cpu
        self.after = process_resources()
        if self.error and exc[0] is None:
            raise self.error

    def report(self):
        return {'before': self.before, 'sampled_peaks': self.peaks, 'after': self.after,
            'wall_seconds': round(self.elapsed, 3), 'cpu_seconds': round(self.cpu_seconds, 3),
            'average_cpu_percent_one_core': round(100*self.cpu_seconds/self.elapsed, 2),
            'scope': 'current process; mocked SSH has no sockets or SSH child processes'}
