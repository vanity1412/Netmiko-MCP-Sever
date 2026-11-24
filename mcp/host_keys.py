#!/usr/bin/env python3
"""Host key persistence and Trust-On-First-Use (TOFU) policy for Netmiko SSH."""
from __future__ import annotations

import contextlib
import functools
import hashlib
import os
from pathlib import Path
import sys
import threading
import time
import uuid

_module_dir = str(Path(__file__).resolve().parent)
if _module_dir not in sys.path:
    sys.path.insert(0, _module_dir)

from config_utils import APP_HOME, stderr
from telemetry import current_connection_timings, time_connection_method

_TOFU_LOCK = threading.Lock()


@contextlib.contextmanager
def host_key_file_lock(path, timeout=0.5):
    """A bounded OS lock shared by scanner, MCP and detection processes."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.with_name(path.name + '.lock').open('a+b') as handle:
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
                if time.monotonic() >= deadline:
                    raise TimeoutError('Host key persistence lock timed out') from None
                time.sleep(.01)
        try:
            yield
        finally:
            handle.seek(0)
            if os.name == 'nt':
                msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                fcntl.flock(handle, fcntl.LOCK_UN)


def persist_host_key(path, hostname, key, *, lock_timeout=0.5):
    """Read/merge/replace under one process lock; retain other hosts and comments."""
    path = Path(path)
    temporary = path.with_name(path.name + '.' + uuid.uuid4().hex + '.tmp')
    with host_key_file_lock(path, timeout=lock_timeout):
        try:
            lines = path.read_text(encoding='utf-8').splitlines(keepends=True) if path.exists() else []
            replacement, matching = [], []
            for line in lines:
                fields = line.split()
                if len(fields) >= 3 and not line.lstrip().startswith('#') and hostname in fields[0].split(',') and fields[1] == key.get_name():
                    matching.append(fields[2])
                    remaining = [h for h in fields[0].split(',') if h != hostname]
                    if remaining:
                        replacement.append(','.join(remaining) + ' ' + ' '.join(fields[1:]) + '\n')
                else:
                    replacement.append(line)
            if matching and all(value == key.get_base64() for value in matching):
                return
            if matching:
                stderr('SSH host key changed; compatible policy accepted replacement fingerprint ' + hashlib.sha256(key.asbytes()).hexdigest()[:16])
            if replacement and not replacement[-1].endswith('\n'):
                replacement[-1] += '\n'
            replacement.append(f'{hostname} {key.get_name()} {key.get_base64()}\n')
            with temporary.open('x', encoding='utf-8', newline='\n') as handle:
                handle.writelines(replacement)
                handle.flush()
                os.fsync(handle.fileno())
            for attempt in range(4):
                try:
                    os.replace(temporary, path)
                    break
                except PermissionError:
                    if attempt == 3:
                        raise
                    time.sleep(.01 * 2**attempt)
        finally:
            with contextlib.suppress(OSError):
                temporary.unlink()


def install_tofu():
    """Attach a separate permissive persistence policy to each Netmiko client."""
    import paramiko
    from netmiko import BaseConnection
    with _TOFU_LOCK:
        if getattr(BaseConnection._build_ssh_client, '_goose_tofu', False):
            return
        original = BaseConnection._build_ssh_client

        class PersistingPolicy(paramiko.MissingHostKeyPolicy):
            def __init__(self, path):
                self.path = path

            def missing_host_key(self, client, hostname, key):
                client._host_keys.add(hostname, key.get_name(), key)
                try:
                    persist_host_key(self.path, hostname, key)
                    client._network_host_key_persisted = True
                except (OSError, UnicodeError):
                    # Connectivity is independent of optional on-disk persistence.
                    client._network_host_key_persisted = False
                    stderr('SSH host key accepted; known_hosts persistence failed')

        @functools.wraps(original)
        def build(conn):
            client = original(conn)
            timings = conn._network_timings_ms = current_connection_timings()
            time_connection_method(client, 'connect', 'ssh_connect_ms', timings)
            time_connection_method(client, '_auth', 'authentication_ms', timings)
            time_connection_method(conn, '_try_session_preparation', 'preparation_ms', timings)
            if conn.key_policy is paramiko.AutoAddPolicy or isinstance(conn.key_policy, paramiko.AutoAddPolicy):
                client.set_missing_host_key_policy(PersistingPolicy(conn.alt_key_file or APP_HOME / 'known_hosts'))
            return client

        build._goose_tofu = True
        BaseConnection._build_ssh_client = build
