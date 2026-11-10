"""Bounded OS locks for shared output transactions and live readers.

Lock files have stable names and are never unlinked: removing an OS lock file
can let another process lock a different inode. A fixed set of stripes bounds
their count; collisions conservatively protect another output too.
"""
import contextlib
import os
import time
from pathlib import Path


@contextlib.contextmanager
def file_lock(path, timeout=5, checkpoint=None):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('a+b') as handle:
        if handle.seek(0, os.SEEK_END) == 0:
            handle.write(b'\0')
            handle.flush()
        deadline = time.monotonic() + timeout
        while True:
            try:
                handle.seek(0)
                if os.name == 'nt':
                    import msvcrt
                    msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
                else:
                    import fcntl
                    fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except OSError:
                # A free lock may publish partial evidence even after the SSH
                # deadline. Waiting for a busy lock must obey cancel/deadline.
                if checkpoint:
                    checkpoint()
                if time.monotonic() >= deadline:
                    error = TimeoutError('Output storage lock timed out')
                    error._network_error_stage = 'persistence'
                    raise error from None
                time.sleep(min(.01, max(0, deadline - time.monotonic())))
        try:
            yield
        finally:
            handle.seek(0)
            if os.name == 'nt':
                msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                fcntl.flock(handle, fcntl.LOCK_UN)


class SharedOutputStorage:
    def __init__(self, directory):
        self.directory = Path(directory)
        self.metadata = self.directory / '.storage'
        self.metadata.mkdir(exist_ok=True)

    def transaction(self, checkpoint):
        return file_lock(self.metadata / 'transaction.lock', checkpoint=checkpoint)

    def lease(self, oid, timeout=5, checkpoint=None):
        stripe = int(oid.rsplit('_', 1)[1], 16) % 64
        return file_lock(self.metadata / f'lease-{stripe:02}.lock', timeout, checkpoint)

    def pin(self, oid, expires):
        (self.metadata / (oid + '.pin')).write_text(str(expires), encoding='ascii')

    def pinned(self, oid, now):
        try:
            return float((self.metadata / (oid + '.pin')).read_text(encoding='ascii')) > now
        except FileNotFoundError:
            return False
        except (OSError, ValueError):
            # Unreadable metadata must never authorize deleting evidence.
            return True

    def forget(self, oid):
        (self.metadata / (oid + '.pin')).unlink(missing_ok=True)

    def clean_temporary(self):
        # Caller holds the transaction lock, so no live writer owns these files.
        for path in self.metadata.glob('*.tmp'):
            path.unlink(missing_ok=True)
        for pin in self.metadata.glob('*.pin'):
            if not (self.directory / (pin.stem + '.txt')).exists():
                pin.unlink(missing_ok=True)
