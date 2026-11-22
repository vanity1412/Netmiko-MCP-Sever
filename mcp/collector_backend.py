#!/usr/bin/env python3
"""Goose Network Collector: generic Netmiko SSH MCP (stdio / JSON-RPC).

Independent implementation inspired by ideas in ntunes/netmiko-mcp-server,
ktbyers/netmiko_mcp, and the documented Netmiko API. No upstream code copied.
Python 3.10+; runtime dependency: netmiko==4.7.0.
"""
from __future__ import annotations

import argparse
import csv
import concurrent.futures
import contextlib
import datetime as dt
import hashlib
import functools
import json
import os
from pathlib import Path
import queue
import re
import shlex
import sys
import subprocess
import sqlite3
import threading
import time
import traceback
import uuid
from typing import Any, Callable
# File-based embedders load this backend without installing a package.
_module_dir = str(Path(__file__).resolve().parent)
if _module_dir not in sys.path:
    sys.path.insert(0, _module_dir)
from result_status import normalize_result
from output_storage import SharedOutputStorage
from telemetry import (PhaseMetrics, WorkQueueMetrics, measured_phase, time_connection_method,
                       connection_measurements, current_connection_timings)
import tempfile

VERSION = "1.9.1"
MCP_PROTOCOL_VERSIONS = ("2024-11-05", "2025-03-26", "2025-06-18", "2025-11-25")
# Local, backwards-compatible reader patch; public MCP tool schemas are unchanged.
JUNOS_READER_PATCH = "2026-11-19.1"
MAX_INLINE = 200_000
MAX_TASKS = 100
MAX_COMMANDS = 1000
APP_HOME = Path(os.environ.get("NETWORK_MCP_DATA_DIR") or ((Path(os.environ["LOCALAPPDATA"]) / "GooseNetworkCollector") if os.environ.get("LOCALAPPDATA") else (Path.home() / ".goose-network-collector")))
SENSITIVE_KEYS = ("password", "secret", "passphrase", "token", "private_key", "username")
ENV_RE = re.compile(r"^\$\{([A-Za-z_][A-Za-z0-9_]*)\}$")
KNOWN_KEYS = {"host", "port", "device_type", "username", "password", "secret", "use_keys", "key_file", "allow_agent", "ssh_strict", "system_host_keys", "alt_host_keys", "alt_key_file", "fast_cli", "conn_timeout", "auth_timeout", "banner_timeout", "global_delay_factor", "global_cmd_verify", "keepalive", "ssh_config_file", "disabled_algorithms", "passphrase", "encoding", "disable_sha2_fix", "blocking_timeout", "session_timeout"}


_TOFU_LOCK = threading.Lock()
_JUNOS_ECHO_INCOMPLETE = object()
_PREPARATION_CONTEXT = threading.local()
_JUNOS_TRACE_LOCK = threading.Lock()
_JUNOS_TRACE_QUEUE = None
_JUNOS_TRACE_THREAD = None
PAGER_RE = re.compile(r'(?i)(?:Press any key to continue \(Q to quit\)|--More-- or \(q\)uit|-- More --, next page: Space, next line: Enter, quit: Control-C|<--- More --->|--- MORE ---|---- More ----|---\(more[^\r\n)]*\)---|--\s*More\s*--(?:[ \t]*\(\d+%\))?)')
CONFIRM_RE = re.compile(r'(?i)(?:\[(?:yes/no|y/n|confirm)\]|\((?:yes/no|y/n)\))')


@contextlib.contextmanager
def host_key_file_lock(path, timeout=0.5):
    """A bounded OS lock shared by scanner, MCP and detection processes."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.with_name(path.name + '.lock').open('a+b') as handle:
        if handle.seek(0, os.SEEK_END) == 0:
            handle.write(b'\0'); handle.flush()
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
                handle.flush(); os.fsync(handle.fileno())
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


class CollectionError(Exception):
    """Bounded worker failures retain categories without copying library secrets."""
    def __init__(self, details):
        self.details = details
        super().__init__(details.get('error', 'CollectionError'))


def classify_error(exc, stage='unknown'):
    stage = getattr(exc, '_network_error_stage', stage)
    if isinstance(exc, CollectionError):
        return dict(exc.details)
    chain, seen, current = [], set(), exc
    while current is not None and id(current) not in seen:
        seen.add(id(current)); chain.append(current)
        current = current.__cause__ or current.__context__
    names = ' '.join(type(e).__name__ for e in chain).lower()
    message = ' '.join(str(e) for e in chain).lower()
    text = names + ' ' + message
    category, retry = 'unknown_error', False
    if 'cancelled' in names:
        category = 'cancelled'
    elif 'deadline exceeded' in message:
        category = 'deadline'
    elif stage == 'persistence':
        category = 'storage_error'
    elif 'badhostkey' in names or 'host key for server' in message:
        category, stage = 'host_key_changed', 'host_key'
    elif 'not found in known_hosts' in message or 'not in known_hosts' in message:
        category, stage = 'host_key_unknown', 'host_key'
    elif any(s in text for s in ('incompatiblepeer', 'no acceptable', 'no matching', 'incompatible ssh peer')):
        category, stage = 'algorithm_mismatch', 'key_exchange'
    elif 'no existing session' in message:
        category, stage, retry = 'handshake_incomplete', 'key_exchange', True
    elif any(s in names for s in ('eoferror', 'connectionreseterror', 'brokenpipeerror')) or 'transport shut down' in message:
        category, retry = 'connection_lost', True
    elif 'badauthenticationtype' in names or 'bad authentication type' in message:
        category, stage = 'auth_method', 'authentication'
    elif 'authentication timeout' in message or 'authentication timed out' in message:
        category, stage, retry = 'auth_timeout', 'authentication', True
    elif 'authentication' in text:
        category, stage = 'authentication', 'authentication'
    elif isinstance(exc, PermissionError):
        category = 'policy_denied'
    elif 'prompt could not be verified' in message:
        category, stage = 'output_verification', 'prompt'
    elif 'error reading ssh protocol banner' in message:
        timed_out = 'timeout' in names or 'timed out' in message
        category, stage, retry = ('banner_timeout' if timed_out else 'banner_error'), 'banner', timed_out
    elif 'readtimeout' in names or (isinstance(exc, TimeoutError) and stage == 'command'):
        category, retry = 'read_timeout', True
    elif 'connectionrefused' in names:
        category, stage = 'connection_refused', 'tcp'
    elif 'gaierror' in names or 'name or service not known' in message or 'dns failure' in message:
        category, stage = 'dns_error', 'dns'
    elif 'sshexception' in names:
        category = 'ssh_error'  # Netmiko may wrap SSH errors as TimeoutException.
    elif 'timeout' in names and stage in {'connect', 'autodetect'}:
        category, stage, retry = 'connect_timeout', 'tcp', True
    elif isinstance(exc, (TypeError, ValueError, FileNotFoundError)):
        category = 'invalid_input'
    return {'error': type(exc).__name__, 'error_category': category,
            'error_stage': stage, 'retryable': retry}


@contextlib.contextmanager
def preparation_request_context(checkpoint, *, minimal_junos=False):
    """Scope a caller's budget to synchronous Netmiko preparation only.

    Worker processes retain their existing parent-enforced budget. A nested
    connection must restore, never leak, the previous thread's callback.
    """
    previous = getattr(_PREPARATION_CONTEXT, 'checkpoint', None)
    previous_minimal = getattr(_PREPARATION_CONTEXT, 'minimal_junos', False)
    _PREPARATION_CONTEXT.checkpoint = checkpoint
    _PREPARATION_CONTEXT.minimal_junos = minimal_junos
    try:
        yield
    finally:
        _PREPARATION_CONTEXT.minimal_junos = previous_minimal
        if previous is None:
            with contextlib.suppress(AttributeError):
                del _PREPARATION_CONTEXT.checkpoint
        else:
            _PREPARATION_CONTEXT.checkpoint = previous


# Stable, machine-readable reasons for failures that are not CLI syntax errors.
# `cli_error` keeps its more specific value from the command result.
ERROR_REASON_BY_CATEGORY = {
    'read_timeout': 'read_timeout',
    'deadline': 'request_deadline',
    'connect_timeout': 'tcp_connect_timeout',
    'auth_timeout': 'authentication_timeout',
    'banner_timeout': 'banner_timeout',
    'output_verification': 'output_incomplete',
    'connection_lost': 'connection_lost',
    'authentication': 'authentication_failed',
    'auth_method': 'authentication_method',
    'storage_error': 'output_storage_failed',
    'parsing_error': 'parse_failed',
    'host_key_changed': 'host_key_changed',
    'host_key_unknown': 'host_key_unknown',
    'algorithm_mismatch': 'algorithm_mismatch',
    'dns_error': 'dns_error',
    'connection_refused': 'connection_refused',
    'policy_denied': 'policy_denied',
    'invalid_input': 'invalid_input',
    'cancelled': 'cancelled',
}


def bounded_request(method):
    @functools.wraps(method)
    def call(self, *args, **kwargs):
        with self.request_budget():
            previous_driver = getattr(self._request, 'resolved_driver', None)
            self._request.resolved_driver = None
            try:
                result = method(self, *args, **kwargs)
                if isinstance(result, dict):
                    result['timings_ms'] = dict(getattr(self._request, 'timings_ms', {}))
                return result
            except Exception as exc:
                exc._network_request_timings_ms = dict(getattr(self._request, 'timings_ms', {}))
                if not hasattr(exc, '_network_error_stage'):
                    exc._network_error_stage = getattr(self._request, 'stage', 'unknown')
                if exc._network_error_stage == 'command' and not hasattr(exc, '_network_command_sent'):
                    exc._network_command_sent = getattr(self._request, 'command_sent', None)
                if self._request.resolved_driver is not None:
                    exc._network_resolved_driver = self._request.resolved_driver
                raise
            finally:
                self._request.resolved_driver = previous_driver
    return call


def stderr(message: str) -> None:
    print(message, file=sys.stderr, flush=True)


def configure_stdio():
    """MCP and worker pipes are UTF-8, including on Windows legacy locales."""
    for stream in (sys.stdin, sys.stdout):
        if hasattr(stream, 'reconfigure'):
            stream.reconfigure(encoding='utf-8')


def expand_env(value: Any, field=None) -> Any:
    if isinstance(value, str):
        match = ENV_RE.fullmatch(value)
        if match:
            return os.environ.get(match.group(1), "")
        if field and any(k in field.lower() for k in SENSITIVE_KEYS):
            return value
        return os.path.expandvars(os.path.expanduser(value))
    if isinstance(value, dict):
        return {k: expand_env(v, k) for k, v in value.items()}
    if isinstance(value, list):
        return [expand_env(v) for v in value]
    return value


CREDENTIAL_FIELDS = {'username', 'password', 'secret', 'use_keys', 'key_file', 'allow_agent', 'passphrase'}


def load_config(path: str | None, credentials_file: str | None = None) -> dict[str, Any]:
    """Load connection settings and an optional client-independent credential file.

    Explicit argument > environment > config reference > sibling credentials.json.
    Relative references resolve against the config, never a client's working dir.
    Credential bundles replace inline auth atomically, retaining connection fields.
    """
    base = Path(path).expanduser().resolve().parent if path else Path(__file__).resolve().parent
    config = {}
    if path:
        with Path(path).expanduser().open('r', encoding='utf-8-sig') as handle:
            config = json.load(handle)
        if not isinstance(config, dict):
            raise ValueError('Configuration must be a JSON object')
        config = expand_env(config)
    reference = credentials_file or os.environ.get('NETWORK_MCP_CREDENTIALS_FILE') or config.get('credentials_file')
    if reference is not None and (not isinstance(reference, str) or not reference.strip()):
        raise ValueError('credentials_file must be a nonempty path string')
    source = Path(os.path.expandvars(os.path.expanduser(reference))) if reference else base/'credentials.json'
    if not source.is_absolute():
        source = base/source
    if not reference and not source.is_file():
        return config
    try:
        with source.open('r', encoding='utf-8-sig') as handle:
            private = json.load(handle)
    except json.JSONDecodeError:
        raise ValueError('Invalid credentials JSON; expected a profiles object') from None
    if not isinstance(private, dict) or set(private) != {'profiles'} or not isinstance(private['profiles'], dict):
        raise ValueError('Credential file must contain only a profiles object')
    profiles = config.setdefault('profiles', {})
    if not isinstance(profiles, dict):
        raise ValueError('profiles must be a JSON object')
    for name, raw in private['profiles'].items():
        if not isinstance(name, str) or not name.strip() or not isinstance(raw, dict):
            raise ValueError('Credential profile names and objects must be valid')
        if set(raw) - CREDENTIAL_FIELDS:
            raise ValueError(f'Credential profile {name} contains unsupported fields; put connection settings in devices.json')
        auth = expand_env(raw)
        for key, value in auth.items():
            expected = bool if key in {'allow_agent', 'use_keys'} else str
            if not isinstance(value, expected):
                raise ValueError(f'Invalid credential field type in profile {name}: {key}')
        if not auth.get('username') or not (auth.get('password') or auth.get('key_file') or auth.get('use_keys') or auth.get('allow_agent')):
            raise ValueError(f'Incomplete credential profile {name}: supply username plus password/key/agent')
        if auth.get('key_file'):
            key_path = Path(auth['key_file'])
            auth['key_file'] = str(key_path if key_path.is_absolute() else (source.parent/key_path).resolve())
        existing = profiles.get(name, {})
        if not isinstance(existing, dict):
            raise ValueError(f'Invalid connection profile {name}')
        merged = {key:value for key,value in existing.items() if key not in CREDENTIAL_FIELDS and key != 'inherit_credentials'}
        merged.update(auth)
        # An external bundle cannot accidentally inherit a legacy password or enable secret.
        merged.setdefault('password', '')
        merged.setdefault('secret', '')
        profiles[name] = merged
    return config


def load_inventory_csv(config: dict[str, Any], path: str | None) -> dict[str, Any]:
    """Merge device.csv rows into config devices without storing credentials.

    Rows are keyed by alias. Duplicate aliases never abort startup (that would
    take the whole collector offline) and never silently retarget an existing
    alias: identical duplicates are ignored, conflicting duplicates keep the
    first row and are reported through ``inventory_warnings``.
    """
    if not path:
        return config
    csv_path = Path(path).expanduser()
    if not csv_path.is_file():
        raise FileNotFoundError(f"Inventory CSV not found: {csv_path}")
    with csv_path.open("r", encoding="utf-8-sig", newline="") as handle:
        rows = list(csv.DictReader(handle))
    required = {"name", "ip"}
    if not rows or not required.issubset(rows[0]):
        raise ValueError("Inventory CSV requires name and ip columns; netmiko_device_type is optional")
    devices = dict(config.get("devices", {}))
    warnings = list(config.get("inventory_warnings") or [])
    for number, row in enumerate(rows, 2):
        name = (row.get("name") or "").strip()
        host = (row.get("ip") or "").strip()
        device_type = (row.get("netmiko_device_type") or "").strip() or "autodetect"
        profile = (row.get("profile") or "").strip() or "default"
        raw_port = (row.get("port") or "").strip()
        port = bounded_int(raw_port, 22, 1, 65535) if raw_port else None
        if not name or not host:
            raise ValueError(f"Invalid inventory CSV row {number}")
        if name in devices:
            existing = devices[name]
            if not isinstance(existing, dict):
                warnings.append(f"row {number}: alias '{name}' also defined in config - config entry kept")
                continue
            if (existing.get("host"), existing.get("device_type"), existing.get("profile") or "default", existing.get("port")) == (host, device_type, profile, port):
                warnings.append(f"row {number}: duplicate alias '{name}' identical to an earlier row - row ignored")
            else:
                warnings.append(
                    f"row {number}: duplicate alias '{name}' conflicts with an earlier row "
                    f"(host={existing.get('host')}, device_type={existing.get('device_type')}, "
                    f"port={existing.get('port', 'inherited')}; incoming port={port if port is not None else 'inherited'}) - "
                    "first row kept, row ignored; fix the CSV")
            continue
        devices[name] = {"host": host, "device_type": device_type, "profile": profile}
        if port is not None:
            devices[name]["port"] = port
    merged = dict(config)
    merged["devices"] = devices
    if warnings:
        merged["inventory_warnings"] = warnings
    return merged


def bounded_int(value: Any, default: int, low: int, high: int) -> int:
    result = default if value is None else int(value)
    if not low <= result <= high:
        raise ValueError(f"Value must be between {low} and {high}")
    return result


def safe_target(target: Any) -> str:
    if not isinstance(target, str) or not (1 <= len(target) <= 253):
        raise ValueError("target must be a hostname, IP address, or inventory alias")
    # No spaces, control characters, URLs, or CLI metacharacters in device targets.
    if not re.fullmatch(r"[A-Za-z0-9_.:\-\[\]]+", target):
        raise ValueError("Invalid target hostname/IP")
    if target.startswith("-"):
        raise ValueError("Invalid target hostname/IP")
    return target


def safe_output_id(output_id: str) -> str:
    if not isinstance(output_id, str) or not re.fullmatch(r"[0-9]{8}T[0-9]{6}Z_[a-f0-9]{32}", output_id):
        raise ValueError("Invalid output_id")
    return output_id


def safe_command(cmd: Any) -> str:
    if not isinstance(cmd, str) or not cmd.strip() or len(cmd) > 8192:
        raise ValueError("command must be a non-empty string up to 8192 characters")
    if any(ord(char) < 32 or ord(char) == 127 for char in cmd):
        raise ValueError("Commands must be single-line and contain no control characters")
    return cmd


def cli_pipeline(command: str) -> list[str]:
    """Split CLI pipes outside quotes; preserve quoted regular expressions."""
    parts, start, quote = [], 0, None
    for index, char in enumerate(command):
        if char in ('"', "'"):
            if quote is None:
                quote = char
            elif quote == char:
                quote = None
        elif char == '|' and quote is None:
            parts.append(command[start:index].strip())
            start = index + 1
    if quote:
        raise PermissionError("Unclosed CLI quote")
    parts.append(command[start:].strip())
    if any(not part for part in parts):
        raise PermissionError("Empty CLI pipeline")
    return parts


@functools.lru_cache(maxsize=4096)
def readonly_command(command: str, platform: str = '') -> str:
    """Legacy import name: validate framing only; never filter command content."""
    return safe_command(command)


def prepare_noc_command(command, platform):
    return safe_command(command)


def is_replay_safe(command):
    """Retry classification only. Never used to permit or reject execution."""
    if not isinstance(command, str) or re.search(r'[;&`><\n\r]', command):
        return False
    try:
        parts = cli_pipeline(command)
    except PermissionError:
        return False
    if any(not re.match(r'^(?:include|exclude|begin|section|match|except|find|count|last|no-more|display)\b', part, re.I) for part in parts[1:]):
        return False
    return bool(re.match(r'^(?:show|display)\s+', parts[0], re.I) or
                re.fullmatch(r'(?:uname(?: -[a-z]+)?|uptime|date|whoami|id|hostname|ip (?:-[a-z]+ )?(?:address|addr|link|route|neigh) show(?: .*)?|ss -[a-z]+)', parts[0], re.I))


def read_only_policy_allows(command, driver):
    """Recognize observational CLI forms for the supported device drivers."""
    if not command.isprintable() or re.search(r'[;&`<>$\\]', command):
        return False
    try:
        head, *filters = cli_pipeline(command)
    except PermissionError:
        return False
    # A quoted pipe is ambiguous across CLI parsers. Reject it rather than
    # treating a potential additional device-side stage as a filter argument.
    if any('|' in part for part in (head, *filters)):
        return False
    unresolved = driver in {'autodetect', 'generic_termserver'}
    if (unresolved or driver == 'linux') and not filters and re.fullmatch(
            r'(?:uname(?: -[asrvmnpo]+)?|uptime|date|whoami|id|hostname|'
            r'ip (?:-[46] )?(?:address|addr|link|route|neigh) show|ss -[a-z]+)', head):
        return True
    verbs = {'show', 'display'} if unresolved else (
        {'display'} if driver.startswith('huawei') else
        {'show'} if driver == 'juniper_junos' or driver.startswith('cisco_') else set())
    words = head.split(maxsplit=1)
    if len(words) != 2 or words[0].casefold() not in verbs:
        return False
    if words[0].casefold() == 'display' and 'diagnostic-information'.startswith(
            words[1].split()[0].casefold()):
        # VRP treats this as a bulk collection and can write a device file.
        return False
    return all(re.fullmatch(
        r'(?:(?:include|exclude|begin|section|match|except|find|last) +.+'
        r'|count|no-more|display (?:set(?: relative)?|xml|json|inheritance(?: no-comments)?|detail|omit))',
        part, re.I) for part in filters)


_LINUX_BLOCKED_PROGRAMS = frozenset('''
    sudo su doas pkexec rm mv cp dd truncate tee chmod chown chgrp ln touch mkdir rmdir
    vi vim nano ed install shred mount umount wipefs mkswap swapon swapoff service
    reboot shutdown poweroff halt init telinit kill killall pkill killproc
    iptables ip6tables nft ufw tc apt apt-get yum dnf pip pip3 dpkg rpm wget curl
    bash sh dash ash zsh ksh fish busybox perl ruby node php lua nc ncat netcat
    env command exec eval source . xargs awk gawk mawk timeout nohup nice ionice
    setsid screen tmux ssh telnet sftp scp ftp tftp rsync
'''.split())


def linux_operational_stage_allows(stage):
    words = shlex.split(stage)
    if not words or not re.fullmatch(r'[A-Za-z0-9_./+-]+', words[0]):
        return False
    program = words[0].rsplit('/', 1)[-1]
    if not program or program in _LINUX_BLOCKED_PROGRAMS or re.fullmatch(r'(?:python|pip|mkfs)[0-9.\w-]*', program):
        return False
    args = words[1:]
    if program == 'ss':
        return not any(arg == '--kill' or re.match(r'^-[a-zA-Z]*K', arg) for arg in args)
    if program in {'ping', 'ping6'}:
        return not any(re.match(r'^-[a-zA-Z]*[fl]', arg) for arg in args)
    if program == 'systemctl':
        return not set(args) & {'start', 'stop', 'restart', 'reload', 'enable', 'disable', 'mask',
                                'unmask', 'reboot', 'poweroff', 'halt', 'isolate', 'kill', 'set-property',
                                'edit', 'daemon-reload', 'link', 'preset', 'revert', 'try-restart',
                                'reload-or-restart', 'try-reload-or-restart'}
    if program in {'ip', 'nmcli'}:
        positionals = [arg for arg in args if not arg.startswith('-')]
        changes = {'set', 'add', 'delete', 'replace', 'change', 'append', 'flush', 'up', 'down',
                   'modify', 'connect', 'disconnect', 'exec', 'reload', 'load', 'edit', 'import',
                   'restore', 'attach', 'on', 'off', 'toggle'}
        return not any(arg == '-b' or arg.startswith('-ba') for arg in args) and not any(
            word and change.startswith(word) for word in positionals[1:] for change in changes)
    if program == 'ifconfig':
        return len(args) <= 1
    if program in {'sed', 'ethtool', 'find', 'crontab'}:
        for item in args:
            if program == 'sed' and (item.startswith(('--in-place', '--file')) or re.match(r'^-[a-zA-Z]*[if]', item)):
                return False
            if program == 'sed' and not item.startswith('-') and re.search(r'(?:^|[/;])\s*[ewW]\b', item):
                return False
            if program == 'ethtool' and (item.startswith(('--set', '--change', '--offload', '--features'))
                                         or re.match(r'^-[sKGCLAEXWNPH]', item)):
                return False
            if program == 'find' and item in {'-exec', '-execdir', '-ok', '-okdir', '-delete', '-fprint', '-fprintf', '-fls'}:
                return False
            if program == 'crontab' and item not in {'-l'}:
                return False
        if program == 'crontab' and args != ['-l']:
            return False
    return True


def operational_policy_allows(command, driver):
    """Screen known state-changing commands in the resolved operational CLI."""
    driver_rules = {
        'junos': {'edit', 'load', 'rollback', 'set', 'activate', 'deactivate',
                  'rename', 'replace', 'insert', 'annotate', 'wildcard', 'request system',
                  'request chassis', 'file copy', 'file delete', 'file rename', 'file archive',
                  'file make-directory', 'top', 'copy', 'protect', 'unprotect', 'monitor start',
                  'request routing-engine login', 'request support information', 'request message'},
        'cisco': {'conf', 'write', 'copy', 'replace', 'archive', 'config-register',
                  'interface', 'router', 'ip route', 'no', 'redundancy force-switchover',
                  'squeeze', 'rmdir', 'mkdir', 'rename', 'install', 'send',
                  'terminal monitor', 'terminal shell', 'tclsh', 'guestshell',
                  'event manager run', 'monitor capture'},
        'huawei': {'system-view', 'rollback', 'startup', 'copy', 'move', 'rename',
                   'configuration replace', 'undo', 'upgrade', 'interface', 'bgp', 'ospf',
                   'ip route-static', 'acl', 'mkdir', 'rmdir', 'undelete', 'ftp', 'tftp', 'sftp', 'scp',
                   'terminal debugging', 'display diagnostic-information'},
    }
    family = ('junos' if driver == 'juniper_junos' else 'cisco' if driver.startswith('cisco_')
              else 'huawei' if driver.startswith('huawei') else None)
    if family is None and driver not in {'autodetect', 'generic_termserver', 'linux'}:
        return False
    if not command.isprintable() or re.search(r'[;&`<>$\\]', command):
        return False
    try:
        head, *filters = cli_pipeline(command)
    except PermissionError:
        return False
    if driver == 'linux':
        return not re.search(r'[(){}!]', command) and all(
            linux_operational_stage_allows(stage) for stage in (head, *filters))
    if any('|' in part for part in (head, *filters)):
        return False
    if family is None and read_only_policy_allows(command, 'linux'):
        return True

    def matches_rule(text, rule):
        words = text.casefold().replace('"', '').replace("'", '').split()
        blocked = rule.split()
        return len(words) >= len(blocked) and all(
            full.startswith(word) for word, full in zip(words, blocked))

    common = {'configure', 'configuration', 'commit', 'save', 'enable', 'shell', 'start',
              'do', 'run', 'op', 'ssh', 'telnet', 'rlogin', 'python', 'reboot', 'reload',
              'restart', 'reset', 'halt', 'power-off', 'zeroize', 'delete', 'erase', 'format',
              'clear', 'debug', 'debugging', 'monitor traffic', 'test'}
    rules = common | (driver_rules[family] if family else set().union(*driver_rules.values()))
    allowed_head = not any(matches_rule(head, rule) for rule in rules)
    blocked_filters = {'save', 'redirect', 'append', 'tee', 'file', 'shell', 'execute', 'nohangup'}
    return allowed_head and not any(matches_rule(stage, rule) for stage in filters for rule in blocked_filters)


def execution_policy_error(message, policy='read_only'):
    return CollectionError({'error': 'ExecutionPolicyDenied', 'error_category': 'policy_denied',
                            'error_reason': f'execution_policy_{policy}', 'error_stage': 'validation',
                            'command_sent': False, 'retryable': False, 'message': message})


def command_prompt_pattern(conn, command, exact):
    """Accept mode transitions only within this device's prompt family."""
    old = getattr(conn, '_network_prompt_text', '')
    root = getattr(conn, '_network_prompt_root', old)
    if not root or is_replay_safe(command):
        return exact
    if root.startswith(('<', '[')) and root.endswith(('>', ']')):
        host = root[1:-1].lstrip('~*')
        return r'(?m)^(?:<' + re.escape(host) + r'>|\[[~*]?' + re.escape(host) + r'(?:-[^\]\r\n]+)?\])[ \t]*\r?$'
    if root[-1:] in '#>$%':
        stem = re.sub(r'\([^()]*\)$', '', root[:-1])
        pattern = r'(?m)^' + re.escape(stem) + r'(?:\([^()\r\n]*\))?[#>$%][ \t]*\r?$'
        rename = re.fullmatch(r'hostname\s+([A-Za-z0-9_.-]+)', command.strip(), re.I)
        if rename:
            pattern = r'(?m)^(?:' + re.escape(stem) + '|' + re.escape(rename[1]) + r')(?:\([^()\r\n]*\))?[#>][ \t]*\r?$'
        return pattern
    return exact


def cli_replay_context(conn, driver):
    """Return a verified, unchanged login context for an automatic replay."""
    prompt = getattr(conn, '_network_prompt_text', '')
    if (not prompt or prompt != getattr(conn, '_network_login_prompt', None)
            or getattr(conn, '_network_cli_context_changed', False)):
        return None
    return (driver, prompt) if is_operational_prompt(prompt, driver) else None


def is_operational_prompt(prompt, driver):
    if driver == 'juniper_junos':
        return prompt.endswith('>')
    if driver.startswith('huawei'):
        return prompt.startswith('<') and prompt.endswith('>')
    if driver.startswith('cisco_'):
        return prompt.endswith(('#', '>')) and '(' not in prompt
    return driver == 'linux' and prompt.endswith(('#', '$'))


# Used only on recognized CLI diagnostic lines, never as a command filter.
PERMISSION_DENIAL_RE = re.compile(
    r'\b(?:permission denied|access[ -]denied|command authorization failed|'
    r'authori[sz]ation (?:failed|denied)|not authori[sz]ed|operation not permitted|'
    r'insufficient (?:user )?(?:privileges?|permissions?|access)|not enough privileges|'
    r'(?:do|does) not have (?:the )?(?:required )?(?:permissions?|privileges?|access)|'
    r'no permission)\b', re.I)
CLI_SYNTAX_RE = re.compile(
    r'\b(?:invalid (?:input|command|interface)|unknown command|ambiguous command|'
    r'incomplete command|unrecognized command|syntax error|command not found)\b', re.I)


def clean_terminal(text: str) -> str:
    """Remove ANSI/control noise, including BEL, without dropping evidence lines."""
    text = re.sub(r"\x1b\][^\x07]*(?:\x07|\x1b\\)", "", text)
    text = re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", text)
    if '\x08' in text:
        terminal = []
        for char in text:
            if char == '\x08' and terminal and terminal[-1] != '\n':
                terminal.pop()
            else:
                terminal.append(char)
        text = ''.join(terminal)
    return re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", text).replace("\r\n", "\n").replace("\r", "\n")


def last_prompt(text: str) -> str | None:
    lines = clean_terminal(text).rstrip().splitlines()
    if not lines:
        return None
    line = lines[-1].strip()
    # Junos user@host>, IOS/XR/NXOS, VRP <host>/[host], and simple shell prompts.
    network = bool(re.fullmatch(r"[^\s]{1,220}[>#%$\]]", line))
    shell = bool(re.fullmatch(r"(?:\[[^\]\n]*@[^\]\n]+\][#$]|\[[^\]\n]+\][#$]|[^\s@]+@[^\n]{1,180}[#$>]|[>#%$])", line))
    if (network or shell) and line not in {"---(more)---", "[yes/no]"}:
        return line
    return None


def platform_from_version(text: str) -> str | None:
    text = clean_terminal(text)
    for pattern, platform in (
        (r"(?i)\b(?:JUNOS|Junos:)\b", "juniper_junos"),
        (r"(?i)Cisco IOS XR", "cisco_xr"),
        (r"(?i)(?:Cisco Nexus|NX-OS|NXOS:)", "cisco_nxos"),
        (r"(?i)Cisco IOS(?: XE)? Software", "cisco_ios"),
        (r"(?i)(?:Huawei.*(?:Versatile|VRP)|VRP.*Software|Versatile Routing Platform)", "huawei"),
        (r"(?m)^Linux(?:\s|$)", "linux"),
    ):
        if re.search(pattern, text):
            return platform
    return None


def redact_text(text: str, secrets: list[str] | None = None) -> str:
    """Best-effort sanitization; raw configuration access still requires AAA controls."""
    # Junos hierarchical login/SNMP syntax has no password keyword on this line.
    text = re.sub(r'(?im)(^\s*user\s+)\S+(?=\s*\{)', r'\1[user]', text)
    text = re.sub(r'(?im)(\b(?:authentication-key-chain|ssh-rsa|ssh-ed25519)\s+)[^\r\n]+', r'\1[redacted]', text)
    # Match complete credential suffixes before generic token redaction (type+hash,
    # Huawei cipher/simple, Junos quoted hashes and SNMPv3 key sequences).
    text = re.sub(r'(?im)(\b(?:encrypted-password|password|passwd|secret|community|authentication-key|pre-shared-key|cipher|simple|token|api[_-]?key|privacy-key|authentication-password|privacy-password|key-string|key|passphrase)\b[ \t]*(?:[:=][ \t]*|[ \t]+))[^\r\n]+', r'\1[redacted]', text)
    text = re.sub(r'(?im)(\b(?:username|user-name|local-user|login user)\s+)\S+', r'\1[user]', text)
    text = re.sub(r'(?im)(\bsnmp-agent (?:usm-user|community)\s+)[^\r\n]+', r'\1[redacted]', text)
    text = re.sub(r'(?im)(\bsnmp-server user\s+)[^\r\n]+', r'\1[redacted]', text)
    text = re.sub(r'(?i)(://)[^\s/@:]+:[^\s/@]+@', r'\1[redacted]@', text)
    text = re.sub(r'(?im)(Last configured:[^\n]*\bby\s+)\S+', r'\1[user]', text)
    for secret in sorted(set(secrets or []), key=len, reverse=True):
        if len(secret) >= 3:
            text = text.replace(secret, "[redacted]")
    text = re.sub(r"-----BEGIN [^-]*PRIVATE KEY-----.*?-----END [^-]*PRIVATE KEY-----", "[redacted private key]", text, flags=re.S)
    text = re.sub(r'(?i)("(?:password|passwd|secret|token|api[_-]?key|community|private[_-]?key)"\s*:\s*)"(?:\\.|[^"\\])*"', r'\1"[redacted]"', text)
    text = re.sub(r"(?im)(\b(?:encrypted-password|password|passwd|secret|token|api[_-]?key|community|authentication-key|pre-shared-key)\b[ \t]*(?:[:=][ \t]*|[ \t]+))(?:\"[^\"\n]*\"|'[^'\n]*'|[^\s;]+)", r"\1[redacted]", text)
    text = re.sub(r"(?im)(authorization:[ \t]*(?:bearer|basic)[ \t]+)\S+", r"\1[redacted]", text)
    text = re.sub(r"(?m)^(?:[^\s@]+)@(?=[^\s]+[>#%$]\s*$)", "[user]@", text)
    text = re.sub(r"(Current user: ')[^']+(' login: ')[^']+", r"\1[user]\2[user]", text)
    return text


def redact_data(value: Any, secrets: list[str] | None = None) -> Any:
    """Preserve JSON types/framing; never apply line regexes to serialized JSON."""
    if isinstance(value, dict):
        return {k: '[redacted]' if any(s in str(k).lower() for s in (*SENSITIVE_KEYS, 'community', 'api_key')) else redact_data(v, secrets) for k, v in value.items()}
    if isinstance(value, list):
        return [redact_data(v, secrets) for v in value]
    if isinstance(value, str):
        return redact_text(value, secrets)
    return value


def command_echo_line(command, output):
    normalized = ' '.join(command.split())
    for index, line in enumerate(output.splitlines()[:5]):
        line = ' '.join(line.split())
        if line == normalized or re.fullmatch(r'\S+[>#%$\]]\s*' + re.escape(normalized), line):
            return index
    return None


def ending_matches(pattern, text):
    ending = text.rstrip()
    match = None
    for match in re.finditer(pattern, ending):
        pass
    return bool(match and match.end() == len(ending))


def pending_interaction(text):
    """Distinguish a terminal question from a literal marker in configuration/logs."""
    lines = text.rstrip().splitlines()
    if not lines:
        return False
    line = lines[-1].strip()
    if re.match(r'(?i)^(?:destination|source)\s+file\s*name\b.*[?:]$', line):
        return True
    match = re.search(CONFIRM_RE.pattern + r'\s*[:?]?\s*$', line)
    if match:
        prefix = line[:match.start()].strip()
        if not prefix or prefix.endswith('?') or re.match(
                r'(?i)^(?:continue|proceed|confirm|are you sure|do you|would you|really|clear|overwrite|delete|reboot|reload|save|exit|quit|accept)\b', prefix):
            return True
    return bool(re.fullmatch(r'(?i)(?:(?:enter|retype|confirm)\s+)?(?:(?:old|new|current)\s+)?(?:password|passphrase)\s*:|press\s+(?:enter|return|any key)\s+to\s+continue[.:]?', line))


def _junos_trace_writer(pending):
    """Best-effort stderr only; a blocked diagnostic pipe never blocks SSH.

    Use the descriptor directly: a daemon must not hold Python's buffered
    stderr lock during interpreter shutdown. Never join/flush on a request.
    """
    while True:
        record = pending.get()
        try:
            wire = (json.dumps(record, ensure_ascii=True) + '\n').encode('ascii')
            while wire:
                written = os.write(2, wire)
                if written <= 0:
                    return
                wire = wire[written:]
        except Exception:
            return  # Diagnostics are optional; do not restart a failed sink.


def _junos_trace_enqueue(record):
    global _JUNOS_TRACE_QUEUE, _JUNOS_TRACE_THREAD
    try:
        with _JUNOS_TRACE_LOCK:
            if _JUNOS_TRACE_QUEUE is None:
                _JUNOS_TRACE_QUEUE = queue.Queue(maxsize=64)
                _JUNOS_TRACE_THREAD = threading.Thread(target=_junos_trace_writer,
                    args=(_JUNOS_TRACE_QUEUE,), name='junos-diagnostic-trace', daemon=True)
                _JUNOS_TRACE_THREAD.start()
            pending = _JUNOS_TRACE_QUEUE
            alive = _JUNOS_TRACE_THREAD is not None and _JUNOS_TRACE_THREAD.is_alive()
        if not alive:
            return False
        pending.put_nowait(record)
        return True
    except Exception:
        return False


def _junos_trace_event(conn, direction, data):
    """Record actual RX bytes / attempted TX bytes; never alter channel I/O.

    Opt-in traces may include command/output secrets. They are bounded and
    lossy on saturation; truncated/dropped records are not wire completeness.
    """
    state = getattr(conn, '_network_junos_trace', None)
    if state is None:
        return
    try:
        if not isinstance(data, bytes):
            return
        if state['events'] >= 256 or state['bytes'] >= 65536:
            return
        size = min(len(data), 2048, 65536 - state['bytes'])
        state['events'] += 1
        state['bytes'] += size
        record = {'trace': 'junos_channel', 'patch': JUNOS_READER_PATCH,
            'session_id': state['session_id'], 'event': state['events'],
            'command_index': state.get('command_index', 0),
            'phase': getattr(conn, '_network_junos_trace_phase', 'preparation'),
            'monotonic': round(time.monotonic(), 6), 'direction': direction,
            'length': len(data), 'data_repr': repr(data[:size]),
            'truncated': size < len(data),
            'budget_exhausted': state['events'] >= 256 or state['bytes'] >= 65536,
            'dropped_before': state['dropped']}
        if not _junos_trace_enqueue(record):
            state['dropped'] += 1
    except Exception:
        pass  # A diagnostic failure must never change command execution.


def _install_junos_trace(conn, channel):
    if getattr(conn, '_network_junos_trace_checked', False):
        return
    if not (str(getattr(conn, 'device_type', '')).startswith('juniper_junos')
            or getattr(conn, '_network_junos_preparing', False)):
        return
    conn._network_junos_trace_checked = True
    if os.environ.get('GOOSE_TRACE_JUNOS') != '1':
        return
    targets = {item.strip() for item in os.environ.get('GOOSE_TRACE_JUNOS_TARGET', '').split(',') if item.strip()}
    if targets and str(getattr(conn, 'host', '')) not in targets:
        return
    # Read the environment once per connection, not on every empty poll.
    try:
        from netmiko.channel import write_bytes
        original = channel.write_channel
        conn._network_junos_trace = {'session_id': uuid.uuid4().hex[:12],
            'events': 0, 'bytes': 0, 'dropped': 0, 'command_index': 0}

        def traced_write(data):
            try:
                _junos_trace_event(conn, 'TX_ATTEMPT', write_bytes(data, encoding=channel.encoding))
            except Exception:
                pass
            return original(data)  # Preserve send errors and partial-send uncertainty.

        channel.write_channel = traced_write
    except Exception:
        conn._network_junos_trace = None


def preserve_channel_encoding(conn):
    """Keep multibyte characters across SSH packets on this channel only."""
    channel = getattr(conn, 'channel', None)
    if channel is None:
        return
    from netmiko.channel import SSHChannel, MAX_BUFFER, ReadException
    if not isinstance(channel, SSHChannel):
        return
    _install_junos_trace(conn, channel)
    if getattr(channel, '_network_incremental_reader', False):
        return
    import codecs
    decoder = codecs.getincrementaldecoder(channel.encoding)(errors='ignore')

    def read_buffer():
        if channel.remote_conn is None:
            raise ReadException('Attempt to read, but there is no active channel.')
        if not channel.remote_conn.recv_ready():
            return ''
        data = channel.remote_conn.recv(MAX_BUFFER)
        if not data:
            raise ReadException('Channel stream closed by remote device.')
        if getattr(conn, '_network_junos_trace', None) is not None:
            _junos_trace_event(conn, 'RX', data)
        return decoder.decode(data)

    channel.read_buffer = read_buffer
    channel._network_incremental_reader = True


def config_banner_open(command, text):
    if not re.match(r'^show\s+(?:run(?:ning-config)?|startup-config)\b', command, re.I):
        return False
    delimiter = None
    for line in text.splitlines():
        if delimiter is not None:
            if delimiter in line:
                delimiter = None
        else:
            match = re.match(r'^\s*banner\s+\S+\s+(\^.|.)', line)
            if match:
                mark = match.group(1)
                if mark not in line[match.end():]:
                    delimiter = mark
    return delimiter is not None


def output_container_open(command, text):
    if config_banner_open(command, text):
        return True
    style = re.search(r'\|\s*(?:display\s+)?(json|xml)\b', command, re.I)
    if not style:
        return False
    lines = clean_terminal(text).splitlines()
    if lines and last_prompt(lines[-1]):
        lines = lines[:-1]
    body = '\n'.join(lines)
    if style[1].lower() == 'json':
        start = re.search(r'(?m)^\s*[\[{]', body)
        if start:
            try:
                json.JSONDecoder().raw_decode(body[start.start():].lstrip())
            except ValueError:
                return True
    else:
        start = re.search(r'(?m)^\s*<(?:\?xml|[A-Za-z_])', body)
        if start:
            import xml.etree.ElementTree as ET
            class RootState:
                depth = 0
                complete = False
                def start(self, tag, attrs): self.depth += 1
                def end(self, tag):
                    self.depth -= 1
                    if self.depth == 0: self.complete = True
                def data(self, data): pass
                def close(self): pass
            state = RootState()
            parser = ET.XMLParser(target=state)
            try:
                parser.feed(body[start.start():].strip())
                parser.close()
            except ET.ParseError:
                return not state.complete
            return not state.complete
    return False


class XMLPrefixGuard:
    """Prove an XML prefix is still open without rereading its transcript.

    This only supplies an open veto. Closed/unsupported cases still use the
    original whole-transcript verifier. Hold the last line because that verifier
    excludes a trailing CLI prompt, even if a newline has already arrived.
    """
    def __init__(self, command):
        style = re.search(r'\|\s*(?:display\s+)?(json|xml)\b', command, re.I)
        self.safe = bool(style and style[1].lower() == 'xml') and not bool(
            re.match(r'^show\s+(?:run(?:ning-config)?|startup-config)\b', command, re.I))
        self.pending = ''
        self.parser = None
        self.depth = 0
        self.complete = False
        self.failed = False

    def start(self, tag, attrs): self.depth += 1
    def end(self, tag):
        self.depth -= 1
        if self.depth == 0: self.complete = True
    def data(self, text): pass
    def close(self): pass

    def feed(self, data):
        if not self.safe: return
        # ANSI/backspaces/control normalization can change prior syntax. Fall
        # back instead of guessing. CRLF split across chunks is supported.
        if re.search(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f\x85\u2028\u2029]', data):
            self.safe = False
            self.pending = ''
            return
        parts = (self.pending + data).split('\n')
        if parts[-1] == '' and len(parts) > 1:
            self.pending = parts[-2] + '\n'
            lines = parts[:-2]
        else:
            self.pending = parts[-1]
            lines = parts[:-1]
        if len(self.pending) > 65536 or '\r' in self.pending.rstrip('\r\n'):
            self.safe = False
            self.pending = ''
            return
        for line in lines:
            if line.endswith('\r'): line = line[:-1]
            if '\r' in line:
                self.safe = False
                self.pending = ''
                return
            if self.failed: continue
            if self.parser is None:
                if not re.match(r'^\s*<(?:\?xml|[A-Za-z_])', line): continue
                import xml.etree.ElementTree as ET
                self.parser = ET.XMLParser(target=self)
                line = line.lstrip()
            try:
                self.parser.feed(line + '\n')
            except Exception as exc:
                import xml.etree.ElementTree as ET
                if isinstance(exc, ET.ParseError):
                    self.failed = True
                else:
                    # Optional acceleration must not introduce an earlier read
                    # failure. Let the legacy verifier handle unsupported input.
                    self.safe = False
                    self.parser = None
                    self.pending = ''
                    return

    def definitely_open(self):
        return bool(self.safe and self.parser is not None and not self.complete
                    and (not self.pending.strip() or last_prompt(self.pending)))


class OutputBuffer:
    def __init__(self):
        self.file = tempfile.SpooledTemporaryFile(max_size=1024*1024, mode='w+t', encoding='utf-8', newline='')
    def append(self, data):
        try: self.file.write(data)
        except OSError as exc:
            exc._network_error_stage = 'persistence'
            raise
    def value(self):
        try:
            self.file.seek(0)
            value = self.file.read()
            self.file.seek(0, 2)
            return value
        except OSError as exc:
            exc._network_error_stage = 'persistence'
            raise
    def close(self):
        with contextlib.suppress(OSError): self.file.close()


def strip_pager_spans(raw, spans):
    parts, previous = [], 0
    for start, end in sorted(spans):
        parts.extend((raw[previous:start], ' ' * (end-start)))
        previous = end
    parts.append(raw[previous:])
    return ''.join(parts)


def dead_session(conn):
    if conn is None: return True
    proc = getattr(conn, '_process', None)
    if proc is not None and proc.poll() is not None: return True
    channel = getattr(conn, 'remote_conn', None)
    transport = getattr(channel, 'transport', None)
    return bool(getattr(conn,'alive',True) is False or getattr(conn,'closed',False) is True or
                (channel is not None and (getattr(channel,'closed',False) or getattr(channel,'eof_received',False))) or
                (transport is not None and not transport.is_active()))


def junos_input_line(raw):
    """Render a small, known subset of Junos input repaint; reject other controls.

    This is only for the unsubmitted command, never for output normalization.
    Spaces (including quoted/repeated/trailing spaces) remain significant.
    """
    line, column, index = [], 0, 0
    while index < len(raw):
        char = raw[index]
        if char == '\x1b':
            rest = raw[index:]
            # SSH reads can end anywhere, including inside a supported CSI.
            # Missing bytes are not proof of a mismatched or unsupported echo.
            if re.fullmatch(r'\x1b(?:\[[0-9;]*)?', rest):
                return _JUNOS_ECHO_INCOMPLETE
            match = re.match(r'\x1b\[([0-9;]*)([mK])', rest)
            if not match:
                return None
            if match[2] == 'K':
                if match[1] not in {'', '0'}:
                    return None
                del line[column:]
            index += len(match[0])
            continue
        if char == '\r':
            column = 0
        elif char == '\x08':
            column = max(0, column - 1)
        elif char == '\n':
            # Wrapped/newline command echoes need a different verifier. Never
            # guess whether Enter was interpreted or an earlier line was lost.
            if line:
                return None
        elif char == '\x07':
            pass  # Junos may ring BEL during completion; compare final text.
        elif ord(char) < 32 or ord(char) == 127:
            return None
        else:
            if column == len(line):
                line.append(char)
            else:
                line[column] = char
            column += 1
        index += 1
    return ''.join(line)


def junos_verified_write(conn, command, deadline, checkpoint, on_data=None):
    """Type once, verify exact input before Enter; close on any uncertainty."""
    prompt = getattr(conn, '_network_prompt_text', '')
    raw, last_data = '', time.monotonic()
    conn.write_channel(command)  # No normalize_cmd/rstrip, and no Enter yet.
    while True:
        if checkpoint:
            try:
                checkpoint()
            except Exception as exc:
                exc._network_echo_output = raw
                raise
        if time.monotonic() >= deadline:
            return raw, 'junos_echo_timeout'
        try:
            data = conn.read_channel()
        except Exception as exc:
            exc._network_echo_output = raw
            raise
        if data:
            raw += data
            last_data = time.monotonic()
            if on_data:
                try:
                    on_data(data)
                except Exception as exc:
                    exc._network_echo_output = raw
                    raise
        if dead_session(conn):
            return raw, 'junos_echo_channel_closed'
        if time.monotonic() - last_data >= .3:
            line = junos_input_line(raw)
            if line is _JUNOS_ECHO_INCOMPLETE:
                time.sleep(min(.01, max(0, deadline - time.monotonic())))
                continue
            expected = {command, prompt + ' ' + command, prompt + command}
            if line not in expected and (not raw or (line is not None and any(
                    value.startswith(line) for value in expected))):
                # A slow, still valid prefix is not a mismatched command. Keep
                # receiving within the original deadline, without sending Enter.
                time.sleep(min(.01, max(0, deadline - time.monotonic())))
                continue
            if line not in expected:
                return raw, 'junos_echo_mismatch'
            if checkpoint:
                try:
                    checkpoint()
                except Exception as exc:
                    exc._network_echo_output = raw
                    raise
            if time.monotonic() >= deadline:
                return raw, 'junos_echo_timeout'
            conn._network_command_sent = True
            try:
                conn.write_channel(getattr(conn, 'RETURN', '\n'))
            except Exception as exc:
                exc._network_echo_output = raw
                raise
            return raw, None
        time.sleep(min(.01, max(0, deadline - time.monotonic())))


def read_cli_output(conn, command, timeout, pattern, checkpoint=None, quiet=.03, on_data=None):
    """Read one command without re-sending it; retain partial data on failure.

    Netmiko owns the transport, driver setup and channel normalization. Reading
    its channel directly avoids the mandatory echo wait and losing accumulated
    output when send_command raises ReadTimeout. The caller owns the session lease.
    """
    deadline = time.monotonic() + timeout
    chunks, tail, received = OutputBuffer(), '', 0
    xml_guard = XMLPrefixGuard(command)
    snapshot, snapshot_revision = None, -1
    container_revision, container_is_open = -1, False
    cleaned = None
    def current_raw():
        nonlocal snapshot, snapshot_revision
        if snapshot_revision != received:
            snapshot = chunks.value()
            snapshot_revision = received
        return snapshot
    def container_open():
        nonlocal container_revision, container_is_open
        if container_revision != received:
            container_is_open = xml_guard.definitely_open() or output_container_open(command, current_raw())
            container_revision = received
        return container_is_open
    # Log payloads can contain the exact prompt. Wait through the observed
    # 700 ms continuation case without extending the caller's deadline.
    log_output = bool(re.match(r'^\s*(?:show\s+log(?:ging)?|display\s+logbuffer)\b', command, re.I))
    quiet = max(quiet, .8 if log_output else .3)
    candidate = None
    candidate_echo_count = 0
    candidate_preamble_only = False
    echo_seen = 0
    prompt_only_completion = False
    handled_pagers = {}
    last_data = time.monotonic()
    failure = None
    next_checkpoint = 0.0
    conn._network_command_sent = False
    conn._network_preceding_output = ''
    if not getattr(conn, '_network_prompt_root', None) and getattr(conn, '_network_prompt_text', None):
        conn._network_prompt_root = conn._network_prompt_text
    actual_pattern = getattr(conn, '_network_prompt_regex', None) or pattern
    device_pattern = command_prompt_pattern(conn, command, actual_pattern)
    if pattern == actual_pattern:
        pattern = device_pattern
    try:
        preserve_channel_encoding(conn)
        trace_state = getattr(conn, '_network_junos_trace', None)
        trace_phase = 'preparation' if getattr(conn, '_network_junos_preparing', False) else 'command'
        if trace_state is not None:
            trace_state['command_index'] += 1
            conn._network_junos_trace_phase = trace_phase + '_drain'
        # Drop a buffered old prompt/login banner before sending this command.
        drained = False
        for _ in range(16):
            if checkpoint:
                checkpoint()
            if time.monotonic() >= deadline:
                raise TimeoutError('Command read timed out before send')
            stale = conn.read_channel()
            if not stale:
                drained = True
                break
            conn._network_preceding_output += stale
        if not drained:
            # Never attribute the next old chunk/prompt to the new command.
            # Preparation may attempt its one controlled resync; ordinary
            # callers will quarantine this connection through read_failure.
            raise CollectionError({'error': 'ChannelNotQuiescent',
                'error_category': 'output_verification', 'error_stage': 'command',
                'error_reason': 'pre_send_buffer_not_quiet', 'retryable': False,
                'command_sent': False, 'command_echo_verified': False})
        if getattr(conn, '_network_junos_verify_echo', False) and command.strip():
            if trace_state is not None:
                conn._network_junos_trace_phase = trace_phase + '_echo'
            # Netmiko normally turns a repaint CR into LF and may strip cursor
            # controls. Keep them only while verifying the unsubmitted input.
            preserved = {name: getattr(conn, name) for name in
                         ('disable_lf_normalization', 'ansi_escape_codes') if hasattr(conn, name)}
            try:
                if 'disable_lf_normalization' in preserved:
                    conn.disable_lf_normalization = True
                if 'ansi_escape_codes' in preserved:
                    conn.ansi_escape_codes = False
                echo, echo_failure = junos_verified_write(conn, command, deadline, checkpoint, on_data)
            finally:
                for name, value in preserved.items():
                    setattr(conn, name, value)
            chunks.append(echo)
            received += len(echo)
            if echo_failure:
                failure = {'error_category': 'output_verification', 'retryable': False,
                           'error_stage': 'command', 'error_reason': echo_failure,
                           'command_echo_verified': False,
                           'message': 'Junos input not verified; Enter was not sent'}
                output = clean_terminal(chunks.value())
                chunks.close()
                conn._network_pager_spans = []
                return output, failure
        else:
            if trace_state is not None:
                conn._network_junos_trace_phase = trace_phase + '_submit'
            conn._network_command_sent = True
            conn.write_channel(conn.normalize_cmd(command))
        if trace_state is not None:
            conn._network_junos_trace_phase = trace_phase + '_output'
        normalized_command = ' '.join(str(command).split())
        # Match the whole echoed line, never an arbitrary 60-character payload prefix.
        echo_body = r'[ \t]+'.join(re.escape(part) for part in normalized_command.split())
        echo_re = re.compile(r'^(?:\S+[>#%$\]]\s*)?' + echo_body + r'[ \t]*$') if echo_body else None
        repaint_command = bool(re.fullmatch(r'set cli screen-width \d+', normalized_command))
        width_preparation = repaint_command and getattr(conn, '_network_junos_preparing', False)
        width_ack = 'Screen width set to ' + normalized_command.split()[-1] if width_preparation else None
        candidate_has_width_ack = settling_width = False
        # Exact version queries must have a response body. Filtered commands may
        # legitimately produce no matches and keep their existing prompt rules.
        requires_payload = normalized_command.casefold() in {'show version', 'display version'}
        while True:
            now = time.monotonic()
            if checkpoint and now >= next_checkpoint:
                checkpoint()
                next_checkpoint = now + .05
            if now >= deadline and not settling_width:
                if (candidate is None or not candidate_has_width_ack
                        or not ending_matches(pattern, cleaned) or dead_session(conn)):
                    raise TimeoutError('Command read timed out')
                # ACK and prompt arrived within budget. Finish observing this
                # candidate only, still subject to the caller's deadline.
                settling_width = True
                deadline = last_data + quiet
            data = conn.read_channel()
            if data:
                # Invalidate before writes/callbacks: either may fail after
                # appending partial data, which still belongs in the evidence.
                snapshot, snapshot_revision = None, -1
                chunks.append(data)
                if on_data:
                    on_data(data)
                received += len(data)
                tail = (tail + data)[-16384:]
                last_data = time.monotonic()
                xml_guard.feed(data)
                if settling_width:
                    raise TimeoutError('Junos screen-width output continued past the read deadline')
            if data or cleaned is None:
                cleaned = clean_terminal(tail)
            # Echo is optional. Reset a provisional prompt only when the old
            # transcript contains no response body and a complete echo follows.
            # A version query still waiting for its required body can discard a
            # preamble-only candidate on any new data, including without echo.
            if data and echo_re:
                echo_seen = max(echo_seen, sum(bool(echo_re.fullmatch(line.strip()))
                                               for line in cleaned.splitlines()))
                if (candidate is not None and candidate_preamble_only
                        and (requires_payload or width_preparation or (echo_seen > candidate_echo_count
                             and (candidate_echo_count == 0 or repaint_command)))):
                    candidate = None
                    candidate_echo_count = 0
            if ending_matches(pattern, cleaned) and not container_open():
                if candidate is None:
                    candidate_echo_count = echo_seen
                    candidate_raw = current_raw()
                    if handled_pagers:
                        candidate_raw = strip_pager_spans(candidate_raw, list(handled_pagers.items()))
                    candidate_text = clean_terminal(candidate_raw)
                    if width_preparation:
                        candidate_has_width_ack = any(line.strip() == width_ack for line in candidate_text.splitlines())
                    candidate_preamble_only = all(
                        not line.strip() or ending_matches(device_pattern, line)
                        or (echo_re is not None and echo_re.fullmatch(line.strip()))
                        or re.fullmatch(r'\{(?:master|backup|primary|secondary)(?::\d+)?\}', line.strip())
                        for line in candidate_text.splitlines())
                    candidate = hashlib.sha256(candidate_text.rstrip().encode('utf-8')).digest()
                    del candidate_text
                    del candidate_raw
            if pending_interaction(cleaned) and not container_open():
                break
            pagers = list(PAGER_RE.finditer(tail))
            if pagers and ending_matches(PAGER_RE.pattern + r'[ \t]*', cleaned):
                pager = pagers[-1]
                marker_id = received - len(tail) + pager.start()
                if marker_id not in handled_pagers:
                    if checkpoint:
                        checkpoint()
                    if time.monotonic() >= deadline:
                        raise TimeoutError('Command read timed out')
                    handled_pagers[marker_id] = received - len(tail) + pager.end()
                    conn.write_channel(' ')
            elif (ending_matches(pattern, cleaned) and time.monotonic() - last_data >= quiet
                  and not container_open()
                  and not ((requires_payload or width_preparation) and candidate_preamble_only)):
                prompt_only_completion = True
                break
            if not data:
                channel = getattr(conn, 'remote_conn', None)
                if channel is not None and (getattr(channel, 'closed', False) or getattr(channel, 'eof_received', False)):
                    if (ending_matches(pattern, cleaned) and not container_open()
                            and not ((requires_payload or width_preparation) and candidate_preamble_only)):
                        break
                    raise EOFError('SSH channel closed before ending prompt')
            time.sleep(min(.01, max(0, deadline - time.monotonic())))
    except Exception as exc:
        if getattr(exc, '_network_echo_output', ''):
            snapshot, snapshot_revision = None, -1
            chunks.append(exc._network_echo_output)
        failure = classify_error(exc, 'command')
        failure['message'] = 'Command interrupted; partial output retained'
        failure.setdefault('error_reason', ERROR_REASON_BY_CATEGORY.get(failure.get('error_category'), 'command_read_interrupted'))
    raw = current_raw()
    chunks.close()
    xml_guard.parser = None  # Break the parser/target cycle after this command.
    conn._network_pager_spans = list(handled_pagers.items())
    if handled_pagers:
        raw = strip_pager_spans(raw, conn._network_pager_spans)
    output = clean_terminal(raw)
    if failure is None and prompt_only_completion:
        file_output = re.match(r'^\s*(?:more|file\s+show)\s+', command, re.I)
        if file_output or (log_output and candidate_preamble_only):
            failure = {'error_category': 'output_verification', 'retryable': False,
                       'message': 'Output may contain the device prompt; quiet time alone cannot verify completion',
                       'error_stage': 'command',
                       'error_reason': 'log_prompt_ambiguity' if log_output else 'file_prompt_ambiguity'}
    if failure is None and candidate is not None and candidate != hashlib.sha256(output.rstrip().encode('utf-8')).digest():
        failure = {'error_category': 'output_verification', 'retryable': False,
                   'message': 'Data continued after a prompt candidate; completion is uncertain',
                   'error_stage': 'command', 'error_reason': 'prompt_candidate_continuation'}
    if failure is None and ending_matches(device_pattern, output) and not (
            container_is_open if container_revision == received and output == snapshot else output_container_open(command, output)):
        prompt = last_prompt(output)
        if prompt:
            conn._network_prompt_text = prompt
            if re.match(r'^hostname\s+', command.strip(), re.I):
                conn._network_prompt_root = prompt
            conn._network_prompt_regex = r'(?m)^' + re.escape(prompt) + r'[ \t]*\r?$'
    if (hasattr(conn, '_network_junos_capabilities')
            and not getattr(conn, '_network_junos_preparing', False)
            and re.match(r'^\s*set\s+cli\b', command)):
        # Session-local preferences may have changed through an explicit user
        # command. Never retain a stale "autocomplete off" capability.
        conn._network_junos_capabilities = {}
        conn._network_junos_verify_echo = True
    return output, failure


def detection_worker(params: dict[str, Any], connection_sink=None) -> dict[str, Any]:
    """Small read-only probe set; parent process enforces a hard wall deadline."""
    from netmiko import ConnectHandler
    params = dict(params)
    probe_timeout = bounded_int(params.pop('_probe_read_timeout', 4),4,1,60)
    params.pop('_auto_enable', None)
    install_tofu()
    params.update(device_type="generic_termserver", read_timeout_override=probe_timeout)
    for field in ("conn_timeout", "auth_timeout", "banner_timeout"):
        params.setdefault(field, 8)
    conn = None
    retained = False
    try:
        with connection_measurements() as connection_timings:
            conn = ConnectHandler(**params)
        prompt = last_prompt(conn.find_prompt())
        if not prompt:
            return {'error': 'DetectionOutputVerificationError', 'error_category': 'output_verification',
                    'error_stage': 'autodetect', 'retryable': False}
        pattern = r'(?m)^' + re.escape(prompt) + r'[ \t]*\r?$'
        for command in ("show version", "display version", "uname -s"):
            output, failure = read_cli_output(conn, command, probe_timeout, pattern)
            if failure:
                return {**failure, 'error_stage': 'autodetect'}
            echo_line = command_echo_line(command, output)
            if not ending_matches(pattern, output) or pending_interaction(output):
                return {'error':'DetectionOutputVerificationError', 'error_category':'output_verification',
                        'error_stage':'autodetect', 'retryable':False,
                        'message':'Probe ending prompt could not be verified'}
            # Initial login banners are not the response to our probe command.
            platform = platform_from_version('\n'.join(output.splitlines()[(echo_line+1 if echo_line is not None else 0):-1]))
            if platform:
                if connection_sink:
                    try:
                        connection_sink(conn, platform)
                    except CollectionError as exc:
                        exc.details.setdefault('driver', platform)
                        raise
                    retained = True
                return {"device_type": platform, "probe_command": command}
        return {"error": "AutodetectUnknown", "message": "No supported version signature in bounded probes"}
    except Exception as exc:
        # Never put library exception text/credentials on the worker wire.
        return {**classify_error(exc, "autodetect"), "message": "Read-only detection probe failed",
                "connection_timings_ms": dict(locals().get('connection_timings', {}))}
    finally:
        if conn is not None and not retained:
            with contextlib.suppress(Exception):
                conn.remote_conn_pre.close()
            with contextlib.suppress(Exception):
                conn.disconnect()


def preparation_error(failure, output, command):
    """Keep setup evidence distinct from the caller's unsent business command."""
    error = CollectionError({**failure, 'error': failure.get('error', 'PreparationOutputVerificationError'),
                            'error_stage': 'preparation',
                            'output': output, 'preparation_command': command})
    if command.startswith('set cli ') or command == 'show cli':
        error._network_no_driver_refresh = True
    return error


def junos_resync_error(failure, reset_failure, output, command, reset_output, *, attempted=True):
    fatal_reset = reset_failure.get('error_category') in {'cancelled', 'deadline', 'storage_error'}
    error = preparation_error(reset_failure if fatal_reset else (failure or reset_failure), output, command)
    error.details['resync_output'] = reset_output
    error._network_junos_resync_failed = (
        attempted and reset_failure.get('error_reason') == 'junos_resync_failed'
        and error.details.get('error_category') in {'output_verification', 'read_timeout', 'connection_lost'})
    return error


def install_tolerant_width():
    """Handle Cisco preparation that waits for width-command echo before base_prompt exists."""
    from netmiko import BaseConnection
    if getattr(BaseConnection.set_terminal_width, '_goose_tolerant_width', False):
        return
    original = BaseConnection.set_terminal_width

    @functools.wraps(original)
    def set_width(conn, command='', delay_factor=None, cmd_verify=False, pattern=None):
        if conn.global_cmd_verify is not False or not command or not pattern:
            return original(conn, command=command, delay_factor=delay_factor, cmd_verify=cmd_verify, pattern=pattern)
        prompt = last_prompt(conn.find_prompt())
        if not prompt:
            raise ValueError('CLI prompt could not be verified before terminal setup')
        conn.base_prompt = prompt[:-1]
        output, failure = read_cli_output(conn, command, 5, r'(?m)^' + re.escape(prompt) + r'[ \t]*\r?$')
        if failure:
            raise preparation_error(failure, output, command)
        if not ending_matches(r'(?m)^' + re.escape(prompt) + r'[ \t]*\r?$', output):
            raise preparation_error({'error': 'PreparationPromptError', 'error_category': 'output_verification',
                                     'error_reason': 'terminal_width_prompt_not_verified',
                                     'retryable': False}, output, command)
        return output

    set_width._goose_tolerant_width = True
    BaseConnection.set_terminal_width = set_width


def junos_cli_capabilities(output, prompt):
    """Only complete, unambiguous show-cli fields establish capabilities."""
    fields = {'screen_width': [], 'screen_length': [], 'complete_on_space': []}
    ignored = {'', prompt, 'show cli', prompt + ' show cli', prompt + 'show cli'}
    for line in output.splitlines():
        line = line.strip()
        if line in ignored or re.fullmatch(r'\{(?:master|backup|primary|secondary)(?::\d+)?\}', line):
            continue
        if not line.startswith('CLI '):
            return {}
        # A malformed version of a known field must not be ignored beside a
        # contradictory, well-formed value that could disable the echo guard.
        recognized = False
        for label, pattern in (
                ('screen_width', r'CLI screen-width set to (\d{1,6})'),
                ('screen_length', r'CLI screen-length set to (\d{1,6})'),
                ('complete_on_space', r'CLI complete-on-space set to (on|off)')):
            match = re.fullmatch(pattern, line)
            if match:
                fields[label].append(match[1])
                recognized = True
        if not recognized and re.match(r'^CLI (?:screen-width|screen-length|complete-on-space)\b', line):
            return {}
    if not all(len(values) == 1 for values in fields.values()):
        return {}
    width, length = int(fields['screen_width'][0]), int(fields['screen_length'][0])
    if not (1 <= width <= 65535 and 0 <= length <= 65535):
        return {}
    return {'screen_width': width, 'screen_length': length,
            'complete_on_space': fields['complete_on_space'][0] == 'on',
            'paging_disabled': length == 0}


def junos_resync(conn, prompt, timeout=5, checkpoint=None):
    """One preparation-only Ctrl-C, never Enter, with positive cancel evidence."""
    deadline, last_data = time.monotonic() + timeout, time.monotonic()
    buffer, candidate = OutputBuffer(), None
    pattern = r'(?m)^' + re.escape(prompt) + r'[ \t]*\r?$'
    failure = {'error_category': 'output_verification', 'error_reason': 'junos_resync_failed',
               'error_stage': 'preparation', 'retryable': False}
    previous_phase = getattr(conn, '_network_junos_trace_phase', 'preparation')
    try:
        if checkpoint:
            deadline = min(deadline, time.monotonic() + checkpoint())
        if time.monotonic() >= deadline:
            return '', failure
        conn._network_junos_trace_phase = 'resync'
        conn.write_channel('\x03')
        while time.monotonic() < deadline:
            if checkpoint:
                checkpoint()
            data = conn.read_channel()
            if data:
                buffer.append(data)
                last_data = time.monotonic()
            if dead_session(conn):
                break
            if data or candidate is not None:
                text = clean_terminal(buffer.value())
                # A late old prompt alone is not evidence of cancellation.
                cancelled = bool(re.search(r'(?m)^(?:' + re.escape(prompt)
                    + r'[^\n]*)?\^C[ \t]*\r?$', text))
                if cancelled and ending_matches(pattern, text) and not any(pending_interaction(line) for line in text.splitlines()):
                    digest = hashlib.sha256(text.rstrip().encode('utf-8')).digest()
                    if candidate is None:
                        candidate = digest
                    if time.monotonic() - last_data >= .3:
                        if candidate == digest:
                            if checkpoint:
                                checkpoint()
                            if time.monotonic() >= deadline:
                                break
                            return text, None
                        break
            time.sleep(min(.01, max(0, deadline - time.monotonic())))
        if checkpoint:
            checkpoint()
        return clean_terminal(buffer.value()), failure
    except Exception as exc:
        details = classify_error(exc, 'preparation')
        category = details.get('error_category')
        details.update(error_stage='preparation', retryable=False,
            error_reason=ERROR_REASON_BY_CATEGORY.get(category, 'junos_resync_failed')
            if category in {'deadline', 'cancelled'} else 'junos_resync_failed')
        return clean_terminal(buffer.value()), details
    finally:
        conn._network_junos_trace_phase = previous_phase
        buffer.close()


def junos_initial_prompt(conn, checkpoint):
    """Keep Netmiko's mode handling and check the budget at each channel poll."""
    from netmiko.base_connection import BaseConnection

    if checkpoint is None or not isinstance(conn, BaseConnection):
        conn._test_channel_read(pattern=r"[%>$#]")
        conn.enter_cli_mode()
        return last_prompt(conn.find_prompt())

    read, write = conn.read_channel, conn.write_channel
    overrides = {name: conn.__dict__[name] for name in ('read_channel', 'write_channel')
                 if name in conn.__dict__}
    with contextlib.closing(OutputBuffer()) as evidence:
        def checked_read():
            checkpoint()
            data = read()
            if data:
                evidence.append(data)
            return data

        def checked_write(data):
            checkpoint()
            return write(data)

        conn.read_channel, conn.write_channel = checked_read, checked_write
        try:
            conn._test_channel_read(pattern=r"[%>$#]")
            conn.enter_cli_mode()
            while checked_read():
                pass
            checked_write(conn.RETURN)
            prompt = conn.read_until_pattern(
                pattern=r'^[^\r\n]*[>%$#][ \t]*\r?$', re_flags=re.MULTILINE)
            checkpoint()
            return last_prompt(prompt)
        except Exception as exc:
            failure = classify_error(exc, 'preparation')
            raise preparation_error(failure, clean_terminal(evidence.value()), '[initial prompt]') from exc
        finally:
            for name in ('read_channel', 'write_channel'):
                if name in overrides:
                    setattr(conn, name, overrides[name])
                else:
                    delattr(conn, name)


def junos_prepare_session(conn):
    """Keep the normal path; discover capabilities once after advisory failure."""
    checkpoint = getattr(_PREPARATION_CONTEXT, 'checkpoint', None)
    def remaining(limit=5):
        if checkpoint is None:
            return limit
        try:
            return min(limit, checkpoint())
        except Exception as exc:
            exc._network_error_stage = 'preparation'
            raise

    def reset_session(prompt):
        # Keep the legacy worker/fake connection call shape when no caller
        # budget is available; direct requests carry the real checkpoint.
        if checkpoint is None:
            return junos_resync(conn, prompt)
        return junos_resync(conn, prompt, checkpoint=checkpoint)

    def prep_read(command, pattern):
        # Autocomplete can delay the remainder of the echo by several seconds.
        # Leave room for both exact echo verification and the final prompt.
        limit = 10 if command == 'show cli' and conn._network_junos_verify_echo else 5
        if checkpoint is None:
            return read_cli_output(conn, command, limit, pattern)
        output = ''
        try:
            output, failure = read_cli_output(conn, command, remaining(limit), pattern, checkpoint=checkpoint)
            # The local read deadline can fire between checkpoint polls.
            checkpoint()
            return output, failure
        except (TimeoutError, concurrent.futures.CancelledError) as exc:
            failure = classify_error(exc, 'preparation')
            failure['error_reason'] = ERROR_REASON_BY_CATEGORY.get(failure['error_category'], 'command_read_interrupted')
            return output, failure

    remaining()
    if getattr(conn, '_network_junos_prepared', False) and not dead_session(conn):
        return
    if os.environ.get('GOOSE_TRACE_JUNOS') == '1':
        # Authentication is already complete here. Observe existing I/O only,
        # including initial prompt discovery; never open a second reader.
        preserve_channel_encoding(conn)
    prompt = junos_initial_prompt(conn, checkpoint)
    remaining()
    if not prompt or not prompt.endswith('>'):
        raise preparation_error({'error_category': 'output_verification',
            'error_reason': 'junos_preparation_not_operational', 'retryable': False}, '', '[initial prompt]')
    pattern = r'(?m)^' + re.escape(prompt) + r'[ \t]*\r?$'
    conn._network_prompt_text, conn._network_prompt_regex = prompt, pattern
    conn._network_junos_verify_echo = False
    conn._network_junos_capabilities = {}
    conn._network_junos_preparation = []
    conn._network_junos_preparing = True
    adaptive, probed, resynced = False, False, False
    steps = [('set cli screen-width 511', 'screen_width', 511, 'Screen width set to 511'),
             ('set cli complete-on-space off', 'complete_on_space', False, 'Disabling complete-on-space'),
             ('set cli screen-length 0', 'screen_length', 0, 'Screen length set to 0')]
    try:
        if getattr(_PREPARATION_CONTEXT, 'minimal_junos', False):
            if (dead_session(conn) or not callable(getattr(conn, 'read_channel', None))
                    or not callable(getattr(conn, 'write_channel', None))):
                raise preparation_error({'error_category': 'output_verification',
                    'error_reason': 'junos_minimal_channel_unavailable', 'retryable': False},
                    '', '[initial prompt]')
            conn._network_junos_verify_echo = True
            probe, failure = prep_read('show cli', pattern)
            if not failure and (not conn._network_command_sent or dead_session(conn)
                                or not junos_cli_capabilities(probe, prompt)):
                failure = {'error_category': 'output_verification',
                           'error_reason': 'junos_minimal_probe_unverified', 'retryable': False}
            if failure:
                raise preparation_error(failure, probe, 'show cli')
            conn._network_junos_preparation.append(
                {'command': 'show cli', 'output': probe, 'reason': 'minimal_preparation'})
            conn.base_prompt = prompt[:-1]
            conn._network_junos_prepared = True
            return

        for command, field, desired, ack in steps:
            caps = conn._network_junos_capabilities
            if adaptive:
                known = field in caps and caps[field] == desired
                conn._network_junos_preparation.append({'command': command, 'skipped': True,
                    'command_sent': False, 'reason': 'already_verified' if known else
                    'using_echo_guard' if field == 'complete_on_space' else 'using_reader_fallback'})
                continue
            # Existing three-command fast path: no extra probe or round-trip.
            verify_echo = conn._network_junos_verify_echo
            conn._network_junos_verify_echo = False
            try:
                reply, failure = prep_read(command, pattern)
            finally:
                conn._network_junos_verify_echo = verify_echo
            ignored = {'', prompt, command, prompt + ' ' + command, prompt + command}
            body = [line.strip() for line in reply.splitlines() if line.strip() not in ignored
                    and not re.fullmatch(r'\{(?:master|backup|primary|secondary)(?::\d+)?\}', line.strip())]
            if not failure and body == [ack]:
                caps[field] = desired
                if field == 'screen_length':
                    caps['paging_disabled'] = True
                if field == 'complete_on_space':
                    conn._network_junos_verify_echo = False
                continue
            caps.pop(field, None)
            if field == 'complete_on_space':
                conn._network_junos_verify_echo = True
            diagnostic = re.search(r'(?im)^\s*(?:error:|syntax error|unknown command|permission denied|access denied)[^\n]*', reply)
            reason = ('permission_denied' if diagnostic and PERMISSION_DENIAL_RE.search(diagnostic[0]) else
                      'syntax_error' if diagnostic and CLI_SYNTAX_RE.search(diagnostic[0]) else
                      (failure or {}).get('error_reason') or 'unconfirmed_response')
            record = {'command': command, 'output': reply, 'skipped': True, 'reason': reason}
            conn._network_junos_preparation.append(record)
            fatal = failure and failure.get('error_category') in {'cancelled', 'deadline', 'storage_error'}
            clean = ending_matches(pattern, reply) and not any(pending_interaction(line) for line in reply.splitlines()) and not dead_session(conn) and (
                failure is None or failure.get('error_reason') == 'prompt_candidate_continuation')
            if fatal:
                raise preparation_error(failure, reply, command)
            if not clean:
                resynced = True
                reset, reset_failure = reset_session(prompt)
                record['resync_output'] = reset
                if reset_failure:
                    raise junos_resync_error(failure, reset_failure, reply, command, reset)
            adaptive = True
            # Probe once on this SSH session, after a verified boundary. If the
            # probe cannot establish settings, the business echo guard stays on.
            if not probed:
                probed = True
                conn._network_junos_verify_echo = caps.get('complete_on_space') is not False
                probe, probe_failure = prep_read('show cli', pattern)
                probe_record = {'command': 'show cli', 'output': probe, 'reason': 'capability_probe'}
                conn._network_junos_preparation.append(probe_record)
                # A partial/contradictory probe must not preserve an earlier
                # autocomplete-off assumption from the preparation response.
                caps.clear()
                if probe_failure or not ending_matches(pattern, probe) or any(pending_interaction(line) for line in probe.splitlines()) or dead_session(conn):
                    can_resync = not resynced and (probe_failure or {}).get('error_category') not in {
                        'cancelled', 'deadline', 'storage_error'}
                    if not can_resync:
                        reset, reset_failure = '', probe_failure or {'error_category': 'output_verification',
                            'error_reason': 'junos_resync_failed', 'retryable': False}
                    else:
                        resynced = True
                        reset, reset_failure = reset_session(prompt)
                    probe_record['resync_output'] = reset
                    if reset_failure:
                        error = junos_resync_error(probe_failure, reset_failure, probe, 'show cli', reset,
                                                   attempted=can_resync)
                        error.details['junos_preparation'] = conn._network_junos_preparation
                        raise error
                else:
                    caps.update(junos_cli_capabilities(probe, prompt))
                conn._network_junos_verify_echo = caps.get('complete_on_space') is not False
        conn.base_prompt = prompt[:-1]
        conn._network_prompt_text, conn._network_prompt_regex = prompt, pattern
        conn._network_junos_prepared = True
    except Exception:
        conn._network_junos_capabilities = {}
        conn._network_junos_prepared = False
        raise
    finally:
        conn._network_junos_preparing = False


def install_tolerant_preparation():
    """Configure vendor preparation without allocating a Collector or storage."""
    install_tolerant_width()
    # Some Junos images suppress/localize Netmiko's expected acknowledgements.
    # Keep injected/fake Netmiko modules valid when they omit vendor packages.
    try:
        from netmiko.juniper.juniper import JuniperBase
    except (ImportError, ModuleNotFoundError):
        return
    if getattr(JuniperBase, '_goose_tolerant_prep', False):
        return

    def prepare(conn):
        try:
            junos_prepare_session(conn)
        except Exception:
            if getattr(_PREPARATION_CONTEXT, 'checkpoint', None) is not None:
                # Netmiko disconnects failed constructors. Skip its CLI
                # cleanup on this unusable session so it cannot send input
                # or wait for another prompt after a preparation failure.
                conn.cleanup = lambda: None
            raise

    JuniperBase.session_preparation = prepare
    JuniperBase._goose_tolerant_prep = True


def interaction_step(cmd: Any) -> str:
    if cmd in ("\n", "\r", ""):  # Enter/confirmation without a literal word
        return cmd or "\n"
    return safe_command(cmd)


class Collector:
    def __init__(self, config: dict[str, Any], connect_factory: Callable[..., Any] | None = None, detect_factory: Callable[..., Any] | None = None):
        self.config = config
        self.defaults = config.get("defaults", {})
        self.devices = config.get("devices", {})
        self.profiles = config.get("profiles", {})
        if not isinstance(self.defaults, dict) or not isinstance(self.devices, dict) or not isinstance(self.profiles, dict):
            raise ValueError("defaults, profiles and devices must be JSON objects")
        self.execution_policy_configured = 'execution_policy' in self.defaults
        self.execution_policy = self.defaults.get('execution_policy', 'read_only')
        if self.execution_policy not in ('read_only', 'operational', 'read_write'):
            raise ValueError('execution_policy must be read_only, operational or read_write')
        self.max_workers = bounded_int(self.defaults.get("max_workers"), 8, 1, 32)
        self.health_check_interval = bounded_int(self.defaults.get('health_check_interval_seconds'), 30, 0, 3600)
        self.auth_cooldown = bounded_int(self.defaults.get('auth_failure_cooldown_seconds'), 300, 0, 3600)
        self.redaction_enabled = bool(self.defaults.get('redaction_enabled', False))
        self.prefer_inventory_driver = bool(self.defaults.get('prefer_inventory_driver', True))
        self.host_key_store_mode = self.defaults.get('host_key_store_mode', 'shared')
        if self.host_key_store_mode not in {'shared', 'process'}:
            raise ValueError('host_key_store_mode must be shared or process')
        self.prompt_quiet = float(self.defaults.get('prompt_quiet_seconds', .03))
        self.timing_quiet = float(self.defaults.get('timing_quiet_seconds', .1))
        if not all(0 <= value <= 2 for value in (self.prompt_quiet, self.timing_quiet)):
            raise ValueError('Prompt quiet time must be between 0 and 2 seconds')
        self.inline_max_chars = bounded_int(self.defaults.get("inline_max_chars"), 12000, 100, MAX_INLINE)
        self.session_ttl = bounded_int(self.defaults.get("session_ttl_seconds"), 180, 0, 86400)
        self.session_max_age = bounded_int(self.defaults.get("session_max_age_seconds"), 43200, 0, 604800)
        self.max_sessions = bounded_int(self.defaults.get("max_sessions"), 64, 1, 1024)
        self.sweep_interval = bounded_int(self.defaults.get("session_sweep_seconds"), 60, 0, 3600)
        self.autodetect_timeout = bounded_int(self.defaults.get("autodetect_timeout_seconds"), 20, 1, 120)
        self.detect_cache_ttl = bounded_int(self.defaults.get("autodetect_cache_seconds"), 28800, 1, 604800)
        cache_file = self.defaults.get('autodetect_cache_file') or (APP_HOME / 'autodetect.sqlite3' if connect_factory is None else None)
        self.detection_cache_file = Path(cache_file).expanduser() if cache_file and self.defaults.get('autodetect_persistent_cache', True) else None
        self._persistent_detection_hits = 0
        self._driver_cache_refreshes = 0
        self._detect_cache: dict[tuple[Any, ...], tuple[float, str]] = {}
        self._detection_locks: dict[tuple[Any, ...], list[Any]] = {}
        self._detection_probes = 0
        self._detection_cache_hits = 0
        self._connection_failures = 0
        self._auth_failures: dict[tuple[Any, ...], float] = {}
        self._session_evictions = 0
        self._stop = threading.Event()
        self._request = threading.local()
        self._metrics = PhaseMetrics()
        self._parallel_queue = WorkQueueMetrics()
        self._ssh_slots = threading.BoundedSemaphore(self.max_workers)
        self._task_pool = concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers, thread_name_prefix='ssh-task')
        self.request_timeout = bounded_int(self.defaults.get('request_timeout_seconds'), 120, 1, 3600)
        self.read_timeout = bounded_int(self.defaults.get("read_timeout"), 40, 1, 600)
        self.output_dir = Path(self.defaults.get("output_dir") or APP_HOME / "outputs").expanduser()
        self.output_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.output_ttl = bounded_int(self.defaults.get("output_ttl_seconds"), 604800, 0, 31_536_000)
        self.output_quota = bounded_int(self.defaults.get("output_quota_bytes"), 1_073_741_824, 0, 1_099_511_627_776)
        self._output_lock = threading.RLock()
        self.output_storage_mode = self.defaults.get('output_storage_mode', 'shared')
        if self.output_storage_mode not in {'shared', 'exclusive'}:
            raise ValueError('output_storage_mode must be shared or exclusive')
        self._shared_outputs = SharedOutputStorage(self.output_dir) if self.output_storage_mode == 'shared' else None
        self._storage_context = threading.local()
        self.output_cleanup_interval = bounded_int(self.defaults.get('output_cleanup_interval_seconds'), 30, 1, 3600)
        self._output_index = None
        self._output_total = 0
        self._output_synced = 0.0
        self._output_cleaned = 0.0
        self._active_outputs: dict[str, int] = {}
        self._output_pins: dict[str, float] = {}
        self.audit_enabled = bool(self.defaults.get("audit_enabled", True))
        self._audit_path = self.output_dir / "collector_audit.jsonl"
        self._audit_lock = threading.Lock()
        self._sessions: dict[tuple[Any, ...], dict[str, Any]] = {}
        self._guard = threading.Lock()
        self._ambiguous_warned: set[str] = set()
        # Index inventory by alias and by host/IP so that "ALIAS" and "IP" resolve
        # to the same device entry, credential profile, device_type and session.
        self._build_device_index()
        # Observable counters prove whether MCP calls open or reuse SSH transports.
        self._connections_opened = 0
        self._session_reuses = 0
        if connect_factory is None:
            install_tolerant_preparation()
            from netmiko import ConnectHandler, SSHDetect
            connect_factory = ConnectHandler
            detect_factory = SSHDetect
        self._connect = connect_factory
        self._detect = detect_factory
        self._custom_detect = detect_factory if connect_factory is not None and detect_factory is not None and getattr(detect_factory, "__module__", "").split(".")[0] != "netmiko" else None
        self._sweeper = None
        if self.sweep_interval:
            self._sweeper = threading.Thread(target=self._reap_loop, name="netmiko-session-reaper", daemon=True)
            self._sweeper.start()

    @staticmethod
    def _device_signature(device: dict[str, Any]) -> tuple[Any, ...]:
        # Only the parameters that decide how a connection is built.
        keys = KNOWN_KEYS | {'profile', 'ssh_mode', 'auto_enable', 'inherit_credentials', 'junos_minimal_recovery'}
        return (json.dumps({k: v for k, v in device.items() if k in keys}, sort_keys=True),)

    def _build_device_index(self) -> None:
        """Index inventory by case-insensitive alias and by host/IP.

        Only unambiguous keys are indexed. When several aliases share one host,
        that host is indexed only if every alias agrees on device_type/profile/port
        (deterministic: first alias wins); otherwise the host is marked ambiguous,
        is left out of implicit resolution, and is reported as a warning.
        """
        self._alias_index: dict[str, str] = {}
        self._alias_conflicts: set[str] = set()
        self._host_index: dict[str, str] = {}
        self._host_conflicts: dict[str, list[str]] = {}
        alias_groups: dict[str, list[str]] = {}
        for alias, device in self.devices.items():
            if not isinstance(device, dict):
                continue
            alias_groups.setdefault(str(alias).casefold(), []).append(alias)
            host = str(device.get("host") or alias).strip().casefold()
            if not host:
                continue
            if host in self._host_conflicts:
                if alias not in self._host_conflicts[host]:
                    self._host_conflicts[host].append(alias)
            elif host in self._host_index:
                self._host_conflicts[host] = [self._host_index.pop(host), alias]
            else:
                self._host_index[host] = alias
        for folded, aliases in alias_groups.items():
            if len(aliases) == 1:
                self._alias_index[folded] = aliases[0]
            else:
                self._alias_conflicts.add(folded)
        self._index_warnings: list[str] = [str(w) for w in (self.config.get("inventory_warnings") or [])]
        self._shared_hosts: list[str] = []
        self._ambiguous_hosts: list[str] = []
        for host in sorted(self._host_conflicts):
            aliases = self._host_conflicts[host]
            signatures = {self._device_signature(self.devices[a]) for a in aliases if isinstance(self.devices.get(a), dict)}
            if len(signatures) == 1:
                # Same host and same connection parameters: share the first alias.
                self._host_index[host] = aliases[0]
                self._shared_hosts.append(host)
            else:
                self._ambiguous_hosts.append(host)
                self._index_warnings.append(
                    "ambiguous host '%s' shared by aliases with different parameters: %s - "
                    "pass device_type explicitly or fix the inventory" % (host, ", ".join(aliases)))
        self._shared_hosts_set = set(self._shared_hosts)

    def _resolve_target(self, target: str, device_type: str | None = None,
                        profile: str | None = None) -> tuple[str | None, dict[str, Any], str]:
        """Map an alias OR an inventory host/IP to the same device entry.

        For a host shared by conflicting inventory rows, an explicit device_type
        and/or profile may disambiguate it. The resolver selects a row only when
        all remaining candidates have the same connection signature; otherwise
        it deliberately falls back to dynamic resolution instead of guessing.

        Returns (alias, device_entry, mode) where mode is one of alias,
        alias_casefold, host, host_shared, host_disambiguated, host_ambiguous,
        or dynamic.
        """
        if not isinstance(target, str) or not 1 <= len(target) <= 253 or any(ord(c) < 32 for c in target):
            raise ValueError("Invalid inventory alias/target")
        if target in self.devices:
            device = self.devices[target]
            if not isinstance(device, dict):
                raise ValueError("Invalid device entry in inventory")
            return target, device, "alias"
        key = target.casefold()
        if key in self._alias_conflicts:
            raise ValueError("Inventory alias is ambiguous; use the exact case of an inventory alias")
        alias = self._alias_index.get(key)
        if alias is not None and isinstance(self.devices.get(alias), dict):
            return alias, self.devices[alias], "alias_casefold"
        safe_target(target)
        alias = self._host_index.get(key)
        if alias is not None and isinstance(self.devices.get(alias), dict):
            return alias, self.devices[alias], "host_shared" if key in self._shared_hosts_set else "host"
        if key in self._host_conflicts:
            aliases = self._host_conflicts[key]
            candidates = [a for a in aliases if isinstance(self.devices.get(a), dict)]
            if device_type:
                candidates = [a for a in candidates if self.devices[a].get("device_type") == device_type]
            if profile:
                candidates = [a for a in candidates if (self.devices[a].get("profile") or "default") == profile]
            signatures = {self._device_signature(self.devices[a]) for a in candidates}
            if candidates and len(signatures) == 1:
                alias = candidates[0]
                return alias, self.devices[alias], "host_disambiguated"
            self._warn_ambiguous(key)
            return None, {}, "host_ambiguous"
        return None, {}, "dynamic"

    def _warn_ambiguous(self, key: str) -> None:
        with self._guard:
            if key in self._ambiguous_warned:
                return
            self._ambiguous_warned.add(key)
        stderr("Inventory host '%s' matches several aliases with different parameters; "
               "explicit unique device_type/profile or inventory alias is required." % key)

    def scrub_error(self, message: str) -> str:
        return self.redact_output(message)[:400]

    def redact_output(self, message: str, *, force=False) -> str:
        if not self.redaction_enabled:
            return message
        secrets = [os.environ.get(x, "") for x in ("NETWORK_SSH_PASSWORD", "NETWORK_SSH_SECRET")]
        for section in [self.defaults, *self.profiles.values(), *self.devices.values()]:
            if isinstance(section, dict):
                for k, v in section.items():
                    if any(word in k.lower() for word in SENSITIVE_KEYS) and isinstance(v, str):
                        secrets.append(v)
        return redact_text(message, [x for x in secrets if isinstance(x, str)])

    def _audit_command(self, command: Any) -> str:
        if not self.redaction_enabled:
            return str(command)[:500]
        text = self.scrub_error(str(command))[:500]
        # Redact common inline CLI secret forms without trying to interpret vendor syntax.
        text = re.sub(r"(?i)\b(password|passwd|secret|token|community|passphrase)\b(\s+|\s*=\s*)\S+",
                      lambda m: m.group(1) + m.group(2) + "[redacted]", text)
        return text

    def redact_structured(self, value: Any) -> Any:
        if not self.redaction_enabled:
            return value
        if isinstance(value, dict):
            return {k: '[redacted]' if any(s in str(k).lower() for s in (*SENSITIVE_KEYS, 'community', 'api_key')) else self.redact_structured(v) for k, v in value.items()}
        if isinstance(value, list):
            return [self.redact_structured(v) for v in value]
        return self.redact_output(value) if isinstance(value, str) else value

    def audit(self, name: str, args: dict[str, Any], ok: bool, elapsed: float,
              error: str | None = None, result: dict[str, Any] | None = None,
              *, batch_id: str | None = None, task_index: int | None = None) -> None:
        """Write operational metadata only; never serialize profiles or credentials."""
        if not self.audit_enabled:
            return
        commands = args.get("commands") if isinstance(args.get("commands"), list) else None
        command = args.get("command") if isinstance(args.get("command"), str) else None
        steps = args.get("steps") if isinstance(args.get("steps"), list) else None
        tasks = args.get("tasks") if isinstance(args.get("tasks"), list) else None
        record: dict[str, Any] = {
            "timestamp": dt.datetime.now(dt.timezone.utc).isoformat(),
            "tool": name, "target": args.get("target"), "ok": bool(ok),
            "elapsed_ms": int(elapsed * 1000),
        }
        if command is not None:
            record["command"] = self._audit_command(command)
        if commands is not None:
            record["commands"] = [self._audit_command(x) for x in commands[:50]]
            record["command_count"] = len(commands)
        if steps is not None:
            # Interactive responses may contain secrets; record count only.
            record["interactive_step_count"] = len(steps)
        if tasks is not None:
            record["task_count"] = len(tasks)
            record["task_targets"] = []
            record["task_command_counts"] = []
            record["task_commands"] = []
            for task in tasks[:100]:
                if not isinstance(task, dict):
                    continue
                task_commands = task.get("commands")
                if isinstance(task.get("command"), str) and task["command"]:
                    task_commands = [task["command"]]
                if not isinstance(task_commands, list):
                    task_commands = []
                record["task_targets"].append(str(task.get("target"))[:255])
                record["task_command_counts"].append(len(task_commands))
                record["task_commands"].append([self._audit_command(c) for c in task_commands])
        if result is not None:
            # For a command batch, include diagnostics from the first real
            # failure alongside the aggregate status. Skip unsent placeholders.
            commands_result = result.get("results", []) if name != 'ssh_parallel' else []
            detail = next((item for item in commands_result if not item.get('ok') and not item.get('skipped')),
                          commands_result[0] if commands_result else {})
            details = {**detail, **result}
            for field in ('driver', 'status', 'error_category', 'error_stage', 'error_reason',
                          'execution_state', 'data_state'):
                value = details.get(field)
                if isinstance(value, str) and re.fullmatch(r'[A-Za-z0-9_-]{1,80}', value):
                    record[field] = value
            for field in ('command_sent', 'output_complete', 'retryable', 'ssh_authenticated', 'cli_ready'):
                if isinstance(details.get(field), bool):
                    record[field] = details[field]
            attempts = details.get('recovery_attempts')
            if type(attempts) is int and attempts in (0, 1):
                record['recovery_attempts'] = attempts
                previous = details.get('previous_attempt', {})
                for field in ('error_category', 'error_stage'):
                    key = 'previous_' + field
                    value = previous.get(field, details.get(key))
                    if isinstance(value, str) and re.fullmatch(r'[A-Za-z0-9_-]{1,80}', value):
                        record[key] = value
            for source, key in ((details, 'preparation_command'),
                                (details.get('previous_attempt', {}), 'previous_preparation_command')):
                prep = source.get('preparation_command')
                if isinstance(prep, str) and re.fullmatch(
                        r'(?:set cli (?:screen-(?:width|length) [0-9]{1,6}|complete-on-space off)'
                        r'|terminal width [0-9]{1,6}|show cli|\[initial prompt\])', prep):
                    record[key] = prep
            if type(result.get('failed_command_index')) is int:
                record['failed_command_index'] = result['failed_command_index']
            batch_id = batch_id or result.get('batch_id')
        if isinstance(batch_id, str) and re.fullmatch(r'[0-9a-f]{32}', batch_id):
            record['batch_id'] = batch_id
        if task_index is not None:
            record['task_index'] = task_index
        if error:
            record["error"] = self.scrub_error(str(error))
        try:
            with self._audit_lock:
                if self._audit_path.exists() and self._audit_path.stat().st_size > 10_000_000:
                    for index in (2, 1):
                        source = self._audit_path.with_suffix(f".jsonl.{index}")
                        if source.exists():
                            source.replace(self._audit_path.with_suffix(f".jsonl.{index + 1}"))
                    self._audit_path.replace(self._audit_path.with_suffix(".jsonl.1"))
                with self._audit_path.open("a", encoding="utf-8") as handle:
                    handle.write(json.dumps(record, ensure_ascii=False) + "\n")
        except OSError as exc:
            stderr("Audit write failed: " + type(exc).__name__)

    def _get_settings(self, target: str, device_type: str | None, profile: str | None) -> dict[str, Any]:
        # Alias or inventory host/IP both land on the same device entry, so both
        # produce identical settings (host, device_type, profile) -> identical
        # session key -> one shared SSH session.
        _alias, resolved, mode = self._resolve_target(target, device_type, profile)
        device = dict(resolved)
        if mode == "host_ambiguous":
            raise ValueError("Inventory host is ambiguous; pass a device_type/profile combination that uniquely identifies an entry, or use an inventory alias")
        name = profile or device.get("profile") or "default"
        prof = self.profiles.get(name, {})
        if not isinstance(prof, dict):
            raise ValueError("Invalid credential profile")
        if name != "default" and name not in self.profiles:
            raise ValueError(f"Unknown profile: {name}")
        effective = {**self.defaults, **prof, **device}
        self._request.cli_options = effective
        mode = effective.get('ssh_mode', 'compatible')
        if mode not in {'compatible', 'strict'}:
            raise ValueError('ssh_mode must be compatible or strict')
        # Do not pass generic app settings to ConnectHandler.
        settings = {k: v for k, v in self.defaults.items() if k in KNOWN_KEYS}
        settings.update({k: v for k, v in prof.items() if k in KNOWN_KEYS})
        settings.update({k: v for k, v in device.items() if k in KNOWN_KEYS})
        auth_keys = {'username','password','use_keys','key_file','allow_agent','passphrase'}
        for key in auth_keys:
            settings.pop(key, None)
        settings.update({k:v for k,v in self.defaults.items() if k in auth_keys})
        for source_label, source in ((f'profile {name}', prof), (f'device {_alias or target}', device)):
            if 'inherit_credentials' in source and not isinstance(source['inherit_credentials'], bool):
                raise ValueError(f'inherit_credentials must be a boolean in {source_label}')
            if not (auth_keys & source.keys()):
                continue
            if source.get('inherit_credentials', False):
                settings.update({k:v for k,v in source.items() if k in auth_keys})
                continue
            key_auth = bool(source.get('use_keys') or source.get('key_file') or source.get('allow_agent'))
            if not source.get('username') or not (source.get('password') or key_auth):
                raise ValueError(f'Incomplete SSH credential source in {source_label}: supply username plus password/key/agent, or explicitly set inherit_credentials=true')
            for key in auth_keys:
                settings.pop(key, None)
            settings.update({key:source[key] for key in auth_keys if key in source})
            settings.setdefault('password','')
        settings["host"] = safe_target(device.get("host") or target)
        if self.execution_policy in ('read_only', 'operational'):
            known_driver = settings.get('device_type') or 'autodetect'
            if device_type and device_type not in (known_driver, 'autodetect', 'generic_termserver'):
                raise execution_policy_error('Use the configured driver or autodetect', self.execution_policy)
            settings['device_type'] = known_driver
        elif device_type:
            known = device.get('device_type')
            settings['device_type'] = known if (self.prefer_inventory_driver and device_type in {'autodetect', 'generic_termserver'} and known and known not in {'autodetect', 'generic_termserver'}) else device_type
        settings.setdefault("device_type", "autodetect")
        settings.setdefault("port", 22)
        settings.setdefault("username", os.environ.get("NETWORK_SSH_USER", ""))
        settings.setdefault("password", os.environ.get("NETWORK_SSH_PASSWORD", ""))
        settings.setdefault("secret", os.environ.get("NETWORK_SSH_SECRET", ""))
        # Permissive host-key acceptance requested for this collector. Persistence
        # is per client and never turns a writable-disk problem into an SSH failure.
        if self.execution_policy == 'read_write' and effective.get('auto_enable', False):
            settings['_auto_enable'] = True
        settings['ssh_strict'] = mode == 'strict'
        settings['alt_host_keys'] = mode == 'strict'
        settings['system_host_keys'] = mode == 'strict'
        settings['alt_key_file'] = str(Path(settings.get('alt_key_file') or APP_HOME / 'known_hosts').expanduser().resolve())
        if self.host_key_store_mode == 'process' and mode != 'strict':
            store = Path(settings['alt_key_file'])
            settings['alt_key_file'] = str(store.with_name(store.name + '.' + str(os.getpid())))
        install_tofu()
        settings.setdefault("conn_timeout", 15)
        settings.setdefault("auth_timeout", 15)
        settings.setdefault("banner_timeout", 15)
        settings.setdefault("global_cmd_verify", False)
        settings.setdefault("keepalive", 30)
        if not isinstance(settings["device_type"], str) or not re.fullmatch(r"[A-Za-z0-9_]+", settings["device_type"]):
            raise ValueError("Invalid device_type")
        settings["port"] = bounded_int(settings["port"], 22, 1, 65535)
        settings.update(getattr(self._request, 'connection_timeouts', None) or {})
        return settings

    def _session_key(self, params: dict[str, Any]) -> tuple[Any, ...]:
        # Security/host-key/algorithm changes must not reuse a connection built under
        # different policy. Only the digest is retained in dictionary keys.
        identity = {k: v for k, v in params.items() if k not in {"host", "port", "device_type", "conn_timeout", "auth_timeout", "banner_timeout"}}
        if self.host_key_store_mode == 'process':
            # PID-specific persistence must not change task IDs across job resume.
            path = identity.get('alt_key_file', '')
            identity['alt_key_file'] = path.removesuffix('.' + str(os.getpid()))
        token = json.dumps(identity, ensure_ascii=False, sort_keys=True)
        fingerprint = hashlib.sha256(token.encode("utf-8")).hexdigest()
        return (params["host"], params["port"], params["device_type"], params.get("username"), params.get("key_file"), fingerprint)

    def _detect_key(self, params: dict[str, Any]) -> tuple[Any, ...]:
        key = self._session_key(params)
        return key[:2] + key[3:]

    def _resolve_platform(self, params: dict[str, Any]) -> None:
        if params["device_type"] == "generic_termserver":
            params["device_type"] = "autodetect"
        if params["device_type"] != "autodetect":
            self._request.driver_source = "explicit"
            return
        identity = self._detect_key(params)
        with self._guard:
            live = [(k,e) for k,e in self._sessions.items() if k[:2]+k[3:] == identity and not self._expired(e,time.monotonic()) and not dead_session(e.get("conn"))]
        if len(live) == 1:
            params["device_type"] = live[0][0][2]
            self._request.driver_source = "session"
            return
        # Serialize probes for the same identity only; a slow device must not
        # hold up detection of every other device. Reference counts bound state.
        key = self._detect_key(params)
        with self._guard:
            entry = self._detection_locks.setdefault(key, [threading.Lock(), 0])
            entry[1] += 1
        try:
            with self._entry_lock(entry[0]):
                if self._auth_failures.get(key, 0) > time.monotonic():
                    raise PermissionError('Authentication previously failed; credential identity is cooling down')
                try:
                    self._resolve_platform_locked(params)
                except Exception as exc:
                    if classify_error(exc, 'autodetect')['error_category'] in {'authentication', 'auth_method'}:
                        self._auth_failures[key] = time.monotonic() + self.auth_cooldown
                    raise
        finally:
            with self._guard:
                entry[1] -= 1
                if not entry[1]:
                    self._detection_locks.pop(key, None)

    def _disk_detection(self, params, driver=None, invalidate=False):
        if self.detection_cache_file is None:
            return None
        # Persistence-file location and command timeouts do not change the remote driver.
        identity = {k: params.get(k) for k in ('host','port','username','password','secret','use_keys','key_file','allow_agent','ssh_config_file','disabled_algorithms')}
        digest = hashlib.sha256(json.dumps(identity, sort_keys=True).encode('utf-8')).hexdigest()
        now = time.time()
        try:
            self.detection_cache_file.parent.mkdir(parents=True, exist_ok=True)
            with contextlib.closing(sqlite3.connect(str(self.detection_cache_file), timeout=.2)) as db, db:
                db.execute('CREATE TABLE IF NOT EXISTS detection_v1 (identity TEXT PRIMARY KEY, driver TEXT NOT NULL, verified_at REAL NOT NULL, expires_at REAL NOT NULL)')
                if invalidate:
                    db.execute('DELETE FROM detection_v1 WHERE identity=?', (digest,))
                    return None
                if driver is not None:
                    db.execute('DELETE FROM detection_v1 WHERE expires_at <= ?', (now,))
                    db.execute('INSERT OR REPLACE INTO detection_v1 VALUES (?, ?, ?, ?)', (digest, driver, now, now + self.detect_cache_ttl))
                    return None
                row = db.execute('SELECT driver, verified_at, expires_at FROM detection_v1 WHERE identity=?', (digest,)).fetchone()
                if row and row[1] <= now < min(row[2], row[1] + self.detect_cache_ttl) and row[0] in {'juniper_junos','cisco_ios','cisco_xr','cisco_nxos','huawei','linux'}:
                    return row[0], min(row[2], row[1] + self.detect_cache_ttl) - now
        except (OSError, sqlite3.Error):
            stderr('Autodetect disk cache unavailable; continuing with live detection')
        return None

    @measured_phase('autodetect')
    def _resolve_platform_locked(self, params: dict[str, Any]) -> None:
        key = self._detect_key(params)
        with self._guard:
            cached = self._detect_cache.get(key)
            if cached and not getattr(self._request, 'force_driver_probe', False) and time.monotonic() - cached[0] < self.detect_cache_ttl:
                params["device_type"] = cached[1]
                self._request.driver_source = "ram_cache"
                self._detection_cache_hits += 1
                return
        disk_entry = None if getattr(self._request, 'force_driver_probe', False) else self._disk_detection(params)
        if disk_entry:
            disk_driver, remaining_ttl = disk_entry
            with self._guard:
                self._detect_cache[key] = (time.monotonic() - (self.detect_cache_ttl - remaining_ttl), disk_driver)
                self._persistent_detection_hits += 1
            self._request.driver_source = 'disk_cache'
            params['device_type'] = disk_driver
            return
        with self._guard:
            self._request.driver_source = "probe"
            self._detection_probes += 1
        with self._entry_lock(self._ssh_slots):
            self._request.stage = 'autodetect'
            if self._custom_detect is not None:
                detector = self._custom_detect(**params)
                try:
                    guess = detector.autodetect()
                finally:
                    connection = getattr(detector, "connection", None)
                    if connection is not None:
                        with contextlib.suppress(Exception):
                            connection.disconnect()
            else:
                from probe_session import ProbeSession, ProbeFailure
                budget = min(getattr(self._request, 'detection_timeout', None) or self.autodetect_timeout, self._checkpoint())
                wire_params = dict(params)
                wire_params['_auto_enable'] = self.execution_policy == 'read_write' and bool(
                    getattr(self._request, 'cli_options', {}).get('auto_enable', False))
                overrides = getattr(self._request, 'connection_timeouts', None) or {}
                wire_params['_probe_read_timeout'] = min(30, overrides.get('banner_timeout', 4))
                try:
                    proxy = ProbeSession(wire_params, self._checkpoint, budget)
                except ProbeFailure as exc:
                    # Also works when this backend is the __main__ module.
                    self._connection_metrics(exc.details.get('connection_timings_ms', {}), failed=True)
                    raise CollectionError(exc.details) from None
                guess = proxy.device_type
                self._connection_metrics(getattr(proxy, '_network_timings_ms', {}))
                ready_params = dict(params, device_type=guess)
        if self._custom_detect is None:
            try:
                self._adopt_probe(ready_params, proxy)
            except Exception:
                proxy.close()
                raise
        if not guess or not re.fullmatch(r"[a-zA-Z0-9_]+", guess):
            raise ValueError("Autodetect could not verify a supported platform; specify device_type")
        params["device_type"] = guess
        with self._guard:
            if len(self._detect_cache) >= 256:
                self._detect_cache.pop(min(self._detect_cache, key=lambda k: self._detect_cache[k][0]))
            self._detect_cache[key] = (time.monotonic(), guess)
        self._disk_detection(params, guess)

    @measured_phase('pool_reservation')
    def _reserve_pool_entry(self, key, proxy=None):
        """Wait without holding global/session/SSH locks; reservation is atomic."""
        deadline = time.monotonic() + self._checkpoint()
        while True:
            self._request.stage = 'pool_wait'
            self._checkpoint()
            if time.monotonic() >= deadline:
                raise TimeoutError('Request deadline exceeded waiting for session pool capacity')
            evicted = None
            with self._guard:
                entry = self._sessions.get(key)
                accepted = proxy is None or entry is None or (entry.get('conn') is None and not entry.get('borrowers'))
                if proxy is not None and not accepted:
                    return entry, None, False
                if entry is None and len(self._sessions) >= self.max_sessions:
                    idle = [(k,e) for k,e in self._sessions.items() if not e.get('borrowers')]
                    if idle:
                        old_key, evicted = min(idle, key=lambda item:item[1]['used'])
                        self._sessions.pop(old_key)
                        self._session_evictions += 1
                    else:
                        accepted = False
                if accepted:
                    if entry is None or proxy is not None:
                        now = time.monotonic()
                        entry = {'lock':threading.RLock(), 'conn':proxy, 'used':now,
                                 'created':now if proxy is not None else 0, 'borrowers':0,
                                 'health_checked':now}
                        self._sessions[key] = entry
                    if proxy is None:
                        entry['borrowers'] += 1
                    else:
                        self._connections_opened += 1
                    return entry, evicted, True
            time.sleep(min(.02, max(0, deadline-time.monotonic())))

    def _adopt_probe(self, params, proxy):
        proxy._network_login_prompt = getattr(proxy, '_network_prompt_text', None)
        proxy._network_fresh_probe = True
        _, evicted, accepted = self._reserve_pool_entry(self._session_key(params), proxy)
        if not accepted:
            proxy.close()
        if evicted:
            self._disconnect_entry(evicted)

    @measured_phase('connect_prepare')
    def _open(self, params: dict[str, Any], *, minimal_junos=False) -> Any:
        remaining = self._checkpoint()
        params = dict(params)
        for field in ('conn_timeout', 'auth_timeout', 'banner_timeout'):
            params[field] = min(params.get(field, 15), remaining)
        self._request.stage = 'connect'
        started = time.monotonic()
        auto_enable = params.pop('_auto_enable', False)
        try:
            with preparation_request_context(self._checkpoint, minimal_junos=minimal_junos), connection_measurements() as connection_timings:
                conn = self._connect(**params)
        except Exception as exc:
            exc._network_timings_ms = dict(connection_timings)
            self._connection_metrics(connection_timings, failed=True)
            raise
        self._connection_metrics(getattr(conn, '_network_timings_ms', {}))
        try:
            if auto_enable and params['device_type'].startswith('cisco_'):
                conn.enable()
            self._request.stage = 'prompt'
            prompt = getattr(conn, "_network_prompt_text", None)
            if not prompt and hasattr(conn, "find_prompt"):
                prompt = last_prompt(conn.find_prompt())
            if not prompt:
                raise ValueError('CLI prompt could not be verified after connection')
            if prompt:
                conn._network_prompt_text = prompt
                conn._network_login_prompt = prompt
                conn._network_prompt_regex = r"(?m)^" + re.escape(prompt) + r"[ \t]*\r?$"
                conn.base_prompt = prompt[:-1]
            conn._network_connect_prepare_ms = int((time.monotonic()-started)*1000)
            self._checkpoint()
            return conn
        except Exception:
            self._disconnect_entry({'conn': conn}, graceful=False)
            raise

    def _expired(self, entry: dict[str, Any], now: float) -> bool:
        return bool((self.session_ttl and now - entry["used"] > self.session_ttl) or
                    (self.session_max_age and entry.get("created", 0) and now - entry["created"] > self.session_max_age))

    def _reap_idle(self) -> int:
        now = time.monotonic()
        with self._guard:
            expired = [(k, e) for k, e in self._sessions.items() if not e.get("borrowers") and self._expired(e, now)]
            for key, _entry in expired:
                self._sessions.pop(key, None)
            self._session_evictions += len(expired)
        for _key, entry in expired:
            self._disconnect_entry(entry)
        return len(expired)

    def _reap_loop(self) -> None:
        while not self._stop.wait(self.sweep_interval):
            self._reap_idle()

    def shutdown(self) -> None:
        self._stop.set()
        self._task_pool.shutdown(wait=True)
        if self._sweeper is not None:
            self._sweeper.join(timeout=2)
        self.close()

    @contextlib.contextmanager
    def _lease(self, target: str, device_type: str | None = None, profile: str | None = None,
               *, recover_junos=False, resolved_params=None):
        with self._lease_inner(target, device_type, profile, recover_junos=recover_junos,
                               resolved_params=resolved_params) as conn:
            yield conn

    @contextlib.contextmanager
    def _lease_inner(self, target, device_type=None, profile=None, *, recover_junos=False, resolved_params=None):
        yielded = False
        try:
            with self._lease_once(target, device_type, profile, recover_junos=recover_junos,
                                  resolved_params=resolved_params) as conn:
                yielded = True
                yield conn
        except Exception as exc:
            source = getattr(self._request, 'driver_source', 'explicit')
            category = classify_error(exc, getattr(exc, '_network_error_stage', 'connect'))['error_category']
            if yielded or getattr(exc, '_network_no_driver_refresh', False) or source not in {'ram_cache','disk_cache','session'} or category not in {'output_verification','read_timeout'}:
                raise
            params = self._get_settings(target, device_type, profile)
            with self._guard:
                self._detect_cache.pop(self._detect_key(params), None)
                self._driver_cache_refreshes += 1
            self._disk_detection(params, invalidate=True)
            self._checkpoint()
            old_force = getattr(self._request, 'force_driver_probe', False)
            self._request.force_driver_probe = True
            try:
                with self._lease_once(target, device_type, profile) as conn:
                    conn._network_driver_refreshed = True
                    yield conn
            finally:
                self._request.force_driver_probe = old_force

    @contextlib.contextmanager
    def _lease_once(self, target: str, device_type: str | None = None, profile: str | None = None,
                    *, recover_junos=False, resolved_params=None):
        self._checkpoint()
        params = (dict(resolved_params) if resolved_params is not None
                  else self._get_settings(target, device_type, profile))
        minimal_enabled = (params['device_type'] == 'juniper_junos'
                           and self._request.cli_options.get('junos_minimal_recovery') is True)
        self._resolve_platform(params)
        self._request.resolved_driver = params['device_type']
        key = self._session_key(params)
        if minimal_enabled:
            # Partition the pool without changing SSH identity or auth cooldown.
            key += ('junos_minimal_recovery',)
        entry, evicted, _ = self._reserve_pool_entry(key)
        if evicted is not None:
            self._disconnect_entry(evicted)
        try:
            with self._entry_lock(entry['lock']), self._entry_lock(self._ssh_slots):
                self._checkpoint()
                now = time.monotonic()
                if entry["conn"] is not None and self._expired(entry, now):
                    self._disconnect_entry(entry)
                if entry["conn"] is not None:
                    try:
                        channel = getattr(entry['conn'], 'remote_conn', None)
                        dead = dead_session(entry['conn'])
                        transport = getattr(channel, 'transport', None)
                        if transport is not None and not transport.is_active():
                            dead = True
                        due = now - entry.get('health_checked', 0) >= self.health_check_interval
                        if dead or (due and not getattr(entry['conn'], '_network_awaiting_input', False) and not entry['conn'].is_alive()):
                            self._disconnect_entry(entry)
                        elif due:
                            entry['health_checked'] = now
                    except Exception:
                        self._disconnect_entry(entry)
                if entry["conn"] is None:
                    self._request.session_reused = False
                    try:
                        if self._auth_failures.get(self._detect_key(params), 0) > time.monotonic():
                            raise PermissionError("Authentication previously failed; credential identity is cooling down")
                        entry["conn"] = (self._open_junos_batch_session(params, target)
                                         if recover_junos and minimal_enabled else self._open(params))
                    except Exception as exc:
                        with self._guard:
                            if classify_error(exc, 'connect')['error_category'] in {'authentication', 'auth_method'}:
                                now = time.monotonic()
                                self._auth_failures = {k: expiry for k, expiry in self._auth_failures.items() if expiry > now}
                                self._auth_failures[self._detect_key(params)] = now + self.auth_cooldown
                            self._connection_failures += 1
                        raise
                    entry["health_checked"] = time.monotonic()
                    entry["created"] = time.monotonic()
                    with self._guard:
                        self._connections_opened += 1
                else:
                    self._request.session_reused = not getattr(entry['conn'], '_network_fresh_probe', False)
                    entry['conn']._network_fresh_probe = False
                    with self._guard:
                        self._session_reuses += 1
                try:
                    yield entry["conn"]
                except Exception as exc:
                    verified_cli_failure = isinstance(exc, BatchError) and bool(exc.results) and exc.last_result.get('error_category') == 'cli_error' and all(
                        exc.last_result.get(k) for k in ('transport_ok', 'output_complete'))
                    keep = (bool(getattr(entry['conn'], '_network_awaiting_input', False)) or verified_cli_failure or getattr(exc, '_network_keep_session', False) or (isinstance(exc, BatchError) and bool(exc.results) and exc.last_result.get('session_reusable', False))) and not getattr(entry['conn'], '_network_read_failure', None)
                    if not keep:
                        self._disconnect_entry(entry, graceful=False)
                    raise
                finally:
                    entry["used"] = time.monotonic()
        finally:
            with self._guard:
                entry["borrowers"] -= 1
                if entry["conn"] is None and not entry["borrowers"] and self._sessions.get(key) is entry:
                    self._sessions.pop(key, None)

    @staticmethod
    def _disconnect_entry(entry: dict[str, Any], graceful=True) -> None:
        conn = entry.get("conn")
        entry["conn"] = None
        if conn is not None:
            if hasattr(conn, '_network_junos_capabilities'):
                conn._network_junos_capabilities = {}
                conn._network_junos_prepared = False
            if not graceful or getattr(conn, '_network_awaiting_input', False):
                # Driver cleanup may write "exit". Never send that as a reply
                # to an unfinished command, pager or confirmation question.
                client = getattr(conn, 'remote_conn_pre', None)
                if client is not None:
                    with contextlib.suppress(Exception):
                        client.close()
            with contextlib.suppress(Exception):
                conn.disconnect()

    @contextlib.contextmanager
    def request_budget(self, timeout=None, cancel=None, connection_timeouts=None, autodetect_timeout=None):
        previous = getattr(self._request, 'context', None)
        old_timeouts = getattr(self._request, 'connection_timeouts', None)
        old_stage = getattr(self._request, 'stage', 'queue')
        old_detection_timeout = getattr(self._request, 'detection_timeout', None)
        if timeout is not None and not 0 < timeout <= 3600:
            raise ValueError('Request budget must be 0..3600 seconds')
        if autodetect_timeout is not None and not 0 < autodetect_timeout <= 120:
            raise ValueError('Autodetect budget must be 0..120 seconds')
        overrides = connection_timeouts or {}
        if set(overrides) - {'conn_timeout', 'auth_timeout', 'banner_timeout'} or any(
                isinstance(v, bool) or not isinstance(v, (int, float)) or not 0 < v <= 600 for v in overrides.values()):
            raise ValueError('Invalid connection timeouts')
        if previous is None:
            self._request.context = (cancel or threading.Event(), time.monotonic() + (timeout or self.request_timeout))
            self._request.stage = 'queue'
            self._request.timings_ms = {}
            self._request.session_reused = False
        elif timeout is not None:
            self._request.context = (previous[0], min(previous[1], time.monotonic()+timeout))
        if connection_timeouts is not None:
            self._request.connection_timeouts = dict(overrides)
        if autodetect_timeout is not None:
            self._request.detection_timeout = autodetect_timeout
        try:
            self._checkpoint()
            yield
        finally:
            self._request.context = previous
            self._request.connection_timeouts = old_timeouts
            self._request.stage = old_stage
            self._request.detection_timeout = old_detection_timeout

    def failure_result(self, exc, target=None, command=None):
        details = classify_error(exc, getattr(self._request, 'stage', 'unknown'))
        previous = getattr(exc, '_network_command_result', {})
        details = {**previous, **details}
        recovery = getattr(exc, '_network_previous_attempt', None)
        if recovery is not None:
            details.update(recovery_attempts=getattr(exc, '_network_recovery_attempts', 1),
                           previous_attempt=recovery)
        driver = getattr(exc, '_network_resolved_driver', None) or getattr(self._request, 'resolved_driver', None)
        if driver is not None:
            details.setdefault('driver', driver)
        details['timings_ms'] = dict(getattr(exc, '_network_request_timings_ms', getattr(self._request, 'timings_ms', {})))
        if getattr(exc, '_network_timings_ms', None):
            details['connection_timings_ms'] = dict(exc._network_timings_ms)
        details.update(ok=False, transport_ok=bool(getattr(exc,'_network_keep_session',False)), cli_ok=previous.get('cli_ok'), output_complete=previous.get('output_complete',False),
                       message=self.scrub_error(details.get('message') or str(exc)))
        if not details.get('error_reason'):
            reason = ERROR_REASON_BY_CATEGORY.get(details.get('error_category'))
            if reason:
                details['error_reason'] = reason
        if hasattr(exc, '_network_keep_session'):
            details['session_reusable'] = bool(exc._network_keep_session)
        details['ssh_authenticated'] = True if details['error_stage'] in {'command', 'prompt', 'persistence', 'preparation'} else None
        details['cli_ready'] = False if details['error_stage'] == 'preparation' else (True if details['error_stage'] in {'command', 'persistence'} else None)
        if details['error_stage'] == 'preparation':
            details['output'] = self.redact_output(details.get('output', ''))
            details['preparation_command'] = self.redact_output(details.get('preparation_command', ''))
            if 'resync_output' in details:
                details['resync_output'] = self.redact_output(details['resync_output'])
            if 'junos_preparation' in details:
                details['junos_preparation'] = self.redact_structured(details['junos_preparation'])
        details['command_sent'] = getattr(exc, '_network_command_sent', True if getattr(exc,'_network_keep_session',False) else None) if details['error_stage'] in {'command','persistence','parsing'} else False
        if details.get('command'):
            details['replay_safe'] = is_replay_safe(details['command'])
        if getattr(exc, '_network_read_failure', None):
            details.update(transport_ok=False, read_error_category=exc._network_read_failure.get('error_category'))
        if command is not None:
            details['replay_safe'] = is_replay_safe(command)
        if target is not None:
            details['target'] = target
        if command is not None:
            details['command'] = self.redact_output(command)
        if hasattr(exc, '_network_interact_steps'):
            details['steps'] = exc._network_interact_steps
            if hasattr(exc, '_network_failed_step_index'):
                details['failed_step_index'] = exc._network_failed_step_index
        return normalize_result(details)

    def _checkpoint(self) -> float:
        context = getattr(self._request, 'context', None)
        if context is None:
            return float(self.request_timeout)
        event, deadline = context
        if event.is_set():
            raise concurrent.futures.CancelledError('Request cancelled')
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError('Request deadline exceeded')
        return remaining

    @contextlib.contextmanager
    def _measure(self, phase):
        started = time.monotonic()
        failed = False
        try:
            yield
        except Exception:
            failed = True
            raise
        finally:
            elapsed = (time.monotonic()-started)*1000
            self._metrics.add(phase, elapsed, failed)
            timings = getattr(self._request, 'timings_ms', None)
            if timings is not None:
                timings[phase] = round(timings.get(phase, 0.) + elapsed, 3)

    def _connection_metrics(self, timings, failed=False):
        for phase, elapsed in timings.items():
            self._metrics.add(phase.removesuffix('_ms'), elapsed, failed)
            request_timings = getattr(self._request, 'timings_ms', None)
            if request_timings is not None:
                name = phase.removesuffix('_ms')
                request_timings[name] = round(request_timings.get(name, 0.) + elapsed, 3)

    @contextlib.contextmanager
    def _entry_lock(self, lock):
        with self._measure('ssh_slot_wait' if lock is self._ssh_slots else 'session_lock_wait'):
            if not lock.acquire(blocking=False):
                while not lock.acquire(timeout=min(.1, self._checkpoint())):
                    pass
        try:
            self._checkpoint()
            yield
        finally:
            lock.release()

    def _preflight(self, target, commands, device_type=None, profile=None, *, resolved_params=None):
        self._request.stage = 'validation'
        params = resolved_params if resolved_params is not None else self._get_settings(target, device_type, profile)
        return self.validate_execution_commands(commands, params['device_type'])

    def validate_execution_commands(self, commands, driver):
        commands = [prepare_noc_command(command, driver) for command in commands]
        if self.execution_policy == 'read_only' and any(
                not read_only_policy_allows(command, driver) for command in commands):
            raise execution_policy_error('Command is outside the supported read_only CLI forms')
        if self.execution_policy == 'operational' and any(
                not operational_policy_allows(command, driver) for command in commands):
            raise execution_policy_error('Command denied by operational blacklist for this driver', 'operational')
        return commands

    @contextlib.contextmanager
    def _output_lease(self, output_id: str):
        output_id = safe_output_id(output_id)
        with self._output_lock:
            self._active_outputs[output_id] = self._active_outputs.get(output_id, 0) + 1
        try:
            # Regex workers are already protected by their parent's live lease.
            guard = self._shared_outputs.lease(output_id, checkpoint=self._checkpoint) if self._shared_outputs and not getattr(self, '_regex_worker', False) else contextlib.nullcontext()
            with guard:
                yield self.output_dir / (output_id + ".txt")
        finally:
            with self._output_lock:
                count = self._active_outputs.get(output_id, 1) - 1
                if count:
                    self._active_outputs[output_id] = count
                else:
                    self._active_outputs.pop(output_id, None)
            # A prior quota pass may have skipped this active file.
            # A cleanup failure must not replace output/a read error on exit.
            try:
                self._cleanup_outputs(force=False)
            except Exception:
                stderr('Output retention cleanup deferred; storage lock or filesystem unavailable')

    @contextlib.contextmanager
    def _storage_transaction(self):
        with self._output_lock:
            nested = getattr(self._storage_context, 'active', False)
            guard = self._shared_outputs.transaction(self._checkpoint) if self._shared_outputs and not nested else contextlib.nullcontext()
            with guard:
                self._storage_context.active = True
                try:
                    yield
                finally:
                    self._storage_context.active = nested

    def _sync_output_index(self, force=False):
        now = time.monotonic()
        if not force and self._output_index is not None and self.output_storage_mode == 'exclusive' and now - self._output_synced < self.output_cleanup_interval:
            return
        index = {}
        for path in self.output_dir.glob('*.txt'):
            if not re.fullmatch(r'[0-9]{8}T[0-9]{6}Z_[a-f0-9]{32}', path.stem):
                continue
            try:
                stat = path.stat()
            except FileNotFoundError:
                continue
            index[path.stem] = (stat.st_mtime, stat.st_size)
        self._output_index = index
        self._output_total = sum(size for _, size in index.values())
        self._output_synced = now

    def forget_output(self, output_id):
        """Notify exclusive storage accounting after the scanner retires scratch output."""
        with self._output_lock:
            if self._output_index is not None:
                removed = self._output_index.pop(output_id, None)
                if removed:
                    self._output_total -= removed[1]
            self._output_pins.pop(output_id, None)

    def retire_output(self, output_id):
        """Remove scanner-owned scratch only after evidence was committed."""
        oid = safe_output_id(output_id)
        with self._storage_transaction():
            if self._active_outputs.get(oid):
                return False
            guard = self._shared_outputs.lease(oid, timeout=0) if self._shared_outputs else contextlib.nullcontext()
            try:
                with guard:
                    (self.output_dir / (oid + '.txt')).unlink(missing_ok=True)
                    if self._shared_outputs:
                        self._shared_outputs.forget(oid)
                    self.forget_output(oid)
                return True
            except OSError:
                return False

    def _cleanup_outputs(self, reserve_bytes=0, *, force=True):
        now = time.time()
        removed = freed = 0
        with self._storage_transaction():
            if self._shared_outputs:
                self._shared_outputs.clean_temporary()
            self._sync_output_index(force=force)
            pressure = self.output_quota and self._output_total + reserve_bytes > self.output_quota
            if not force and not pressure and time.monotonic() - self._output_cleaned < self.output_cleanup_interval:
                return {'removed': 0, 'freed_bytes': 0}
            files = sorted((mtime, size, oid) for oid, (mtime, size) in self._output_index.items())
            for mtime, size, oid in files:
                expired = self.output_ttl and now - mtime > self.output_ttl
                pressure = self.output_quota and self._output_total + reserve_bytes > self.output_quota
                if not expired and not pressure:
                    continue
                if self._active_outputs.get(oid, 0) or self._output_pins.get(oid, 0) > now or (self._shared_outputs and self._shared_outputs.pinned(oid, now)):
                    continue
                try:
                    guard = self._shared_outputs.lease(oid, timeout=0) if self._shared_outputs else contextlib.nullcontext()
                    with guard:
                        (self.output_dir / (oid + '.txt')).unlink()
                        if self._shared_outputs:
                            self._shared_outputs.forget(oid)
                except FileNotFoundError:
                    pass
                except OSError:
                    continue
                self.forget_output(oid)
                removed += 1
                freed += size
            self._output_cleaned = time.monotonic()
        return {'removed': removed, 'freed_bytes': freed}

    @measured_phase('output_save')
    def _save_output(self, content, *, already_redacted=False):
        if not already_redacted:
            content = self.redact_output(content)
        size = len(content.encode('utf-8'))
        if self.output_quota and size > self.output_quota:
            raise ValueError('Output exceeds storage quota; no output_id was issued')
        stamp = dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%SZ')
        oid = stamp + '_' + uuid.uuid4().hex
        path = self.output_dir / (oid + '.txt')
        with self._storage_transaction():
            self._cleanup_outputs(size, force=False)
            if self.output_quota and self._output_total + size > self.output_quota:
                raise ValueError('Output storage full; export evidence or wait for retention cleanup')
            try:
                temporary = self._shared_outputs.metadata / (oid + '.tmp') if self._shared_outputs else path.with_suffix('.tmp')
                with temporary.open('x', encoding='utf-8', newline='\n') as handle:
                    handle.write(content)
                    handle.flush()
                if self._shared_outputs:
                    self._shared_outputs.pin(oid, time.time() + 300)
                temporary.replace(path)
            except Exception:
                self._output_index = None  # Reconcile even a partial write next time.
                if 'temporary' in locals():
                    with contextlib.suppress(OSError):
                        temporary.unlink(missing_ok=True)
                raise
            now = time.time()
            self._output_index[oid] = (now, size)
            self._output_total += size
            self._output_pins[oid] = now + 300
        return oid

    def _result(self, target: str, command: str, output: Any, elapsed: float, save_output: bool = False,
                prompt_pattern: str | None = None, interactive: bool = False, device_type: str = "") -> dict[str, Any]:
        if not isinstance(output, str):
            output = json.dumps(output, ensure_ascii=False)
        output = clean_terminal(output)
        prompt = last_prompt(output)
        ending = output.rstrip()
        complete = (ending_matches(prompt_pattern, ending) if prompt_pattern else bool(prompt)) and not output_container_open(command, output)
        # Match known error messages at line boundaries, not words in a config/route.
        errors = re.findall(r"(?im)^\s*(?:%\s*)?(?:Invalid (?:input|command|interface)|Bad IP address or host name|Unknown command|Error\s*:|Ambiguous command|Incomplete command|Unrecognized command|syntax error|permission denied|access denied|authorization (?:failed|denied)|command authorization failed|not authorized|insufficient (?:privilege|permission)|not enough privileges|command rejected|bash: .*: command not found)[^\n]*", output)
        errors += re.findall(
            r'(?im)^[ \t]*(?:%[ \t]*)?(?:Unrecognized host[^\n]*|Unknown host[^\n]*|'
            r'-?(?:bash|sh|zsh|ash|dash):[^\n]*(?:not found|permission denied|cannot execute)[^\n]*|'
            r'(?:ping|traceroute|tracert|tracepath|ip|ss|getent):[^\n]*(?:not found|unknown host|bad address|'
            r'name or service not known|temporary failure in name resolution|operation not permitted|'
            r'permission denied|invalid|unrecognized|cannot)[^\n]*|'
            r'usage:[ \t]*(?:ping|traceroute|tracert|tracepath|ip|ss|getent)\b[^\n]*)', output)
        # Common shell diagnostics and explicit device denial lines absent from
        # the legacy CLI list. Do not infer a denial from arbitrary output prose.
        errors += re.findall(
            r'(?im)^[ \t]*(?:%[ \t]*(?:This command is not authorized|Access denied)[^\n]*|'
            r'(?:-?(?:bash|sh|zsh|ash|dash)|cat|ls|grep|awk|sed|head|tail|find|sudo):'
            r'[^\n]*[ \t](?:Permission denied|Operation not permitted)[^\n]*)', output)
        vendor_patterns = {
            'juniper': r'(?im)^\s*(?:error:|syntax error|commit failed)[^\n]*',
            'huawei': r'(?im)^\s*(?:Error:|Failure:|Error\[\d+\]:)[^\n]*',
            'cisco': r'(?im)^\s*(?:% ?(?:Authorization|Permission|Command rejected|Invalid)|ERROR:)[^\n]*'}
        for family, vendor_pattern in vendor_patterns.items():
            if device_type.startswith(family):
                errors += re.findall(vendor_pattern, output)
        if '<rpc-error' in output and '<error-severity>error</error-severity>' in output:
            errors.append('RPC error response')
            for rpc in re.findall(r'<rpc-error\b[^>]*>(.*?)</rpc-error>', output, re.S):
                if '<error-severity>error</error-severity>' in rpc and re.search(r'<error-tag>access-denied</error-tag>', rpc):
                    errors.append('RPC access denied')
        if re.match(r'^(?:show logging|show log|display logbuffer|show configuration|show running-config|show startup-config|display current-configuration)\b', command, re.I):
            first = next((line.strip() for line in output.splitlines() if line.strip() and command not in line), '')
            errors = [line for line in errors if not (line.strip().lower().startswith('error:') and line.strip() != first)]
        if re.match(r'^show\s+bgp\s+neighbors?\b', command.strip(), re.I) and re.search(r'(?m)^Peer:\s+', output):
            errors = [line for line in errors if not re.fullmatch(
                r"\s*Error:\s+'[^'\n]+'\s+Sent:\s+\d+\s+Recv:\s+\d+\s*", line)]
        if ending_matches(PAGER_RE.pattern, output) or pending_interaction(output):
            complete = False
        echo = interactive or command_echo_line(command, output) is not None
        cli_ok = not bool(errors)
        denied = next((line for line in errors if PERMISSION_DENIAL_RE.search(line)), None)
        output = self.redact_output(output)
        size = len(output)
        data: dict[str, Any] = {"target": target, "command": self.redact_output(command), "ok": bool(cli_ok and complete), "transport_ok": True,
                                "cli_ok": cli_ok, "output_complete": complete, "command_echo_verified": bool(echo),
                                "validation": "heuristic", "characters": size, "lines": output.count("\n") + (1 if output and not output.endswith("\n") else 0), "elapsed_ms": int(elapsed * 1000)}
        if not data["ok"]:
            data["error"] = "CliError" if not cli_ok else "OutputVerificationError"
            data.update(error_category='cli_error' if not cli_ok else 'output_verification',
                        error_stage='cli' if not cli_ok else 'verification', retryable=False)
            if not cli_ok:
                data['error_reason'] = ('permission_denied' if denied else
                                        'syntax_error' if any(CLI_SYNTAX_RE.search(line) for line in errors) else 'command_failed')
            else:
                data['error_reason'] = ('pager_or_confirmation_pending'
                                        if ending_matches(PAGER_RE.pattern, output) or pending_interaction(output)
                                        else 'ending_prompt_not_verified')
            data["message"] = self.scrub_error(denied or errors[0]) if errors else "Ending prompt not verified or pager/confirmation remains; output is incomplete"
        if save_output or size > self.inline_max_chars:
            try:
                data["output_id"] = self._save_output(output, already_redacted=True)
            except Exception as exc:
                exc._network_command_result = dict(data, saved=False, output=output, output_truncated=False)
                exc._network_error_stage = 'persistence'
                exc._network_keep_session = bool(complete)
                raise
            data["preview"] = output[:min(self.inline_max_chars, 2000)]
            data["saved"] = True
            data["notice"] = "Full output saved. Use ssh_read_output or ssh_search_output with output_id."
        else:
            data["output"] = output
            data["saved"] = False
        return normalize_result(data)

    def _command_result(self, conn, target, command, output, elapsed, save_output, pattern):
        # Custom expectations may end a read early, but only the actual device
        # prompt can establish completion for every public execution method.
        failure = getattr(conn, '_network_read_failure', None)
        try:
            result = self._result(target, command, output, elapsed, save_output,
                                  getattr(conn, '_network_prompt_regex', None) or pattern, device_type=getattr(conn,'device_type',''))
        except Exception as exc:
            exc._network_command_sent = bool(getattr(conn, '_network_command_sent', True))
            if failure:
                exc._network_keep_session = False
                exc._network_read_failure = failure
                if hasattr(exc, '_network_command_result'):
                    exc._network_command_result['output_complete'] = False
            raise
        if failure:
            result.update(failure, ok=False, output_complete=False)
            if failure.get('error_category') == 'connection_lost':
                result['transport_ok'] = False
        result['command_sent'] = bool(getattr(conn, '_network_command_sent', True))
        result['replay_safe'] = is_replay_safe(command)
        driver = getattr(self._request, 'resolved_driver', None)
        if driver is not None:
            result['driver'] = driver
        awaiting = ((pending_interaction(clean_terminal(output)) and not output_container_open(command, output)) or (pattern and pattern != getattr(conn, '_network_prompt_regex', None) and ending_matches(pattern, clean_terminal(output)) and not result['output_complete'])) and not failure
        conn._network_awaiting_input = bool(awaiting)
        if awaiting:
            result.update(awaiting_input=True, session_reusable=True, retryable=False)
        preceding = getattr(conn, '_network_preceding_output', '')
        if preceding:
            preceding = self.redact_output(clean_terminal(preceding))
            if len(preceding) > self.inline_max_chars:
                try:
                    result['preceding_output_id'] = self._save_output(preceding, already_redacted=True)
                except Exception as exc:
                    exc._network_command_result = dict(result, preceding_output=preceding)
                    exc._network_error_stage = 'persistence'
                    exc._network_keep_session = bool(result['output_complete'] and not failure)
                    exc._network_command_sent = result['command_sent']
                    raise
            else:
                result['preceding_output'] = preceding
            result['preceding_output_association'] = 'unattributed; retained instead of discarded'
        client = getattr(conn, 'remote_conn_pre', None)
        if getattr(client, '_network_host_key_persisted', None) is False:
            result['warnings'] = ['SSH host key accepted; could not persist known_hosts']
        result.update(ssh_authenticated=True, cli_ready=True, driver_refreshed=bool(getattr(conn,"_network_driver_refreshed",False)))
        if getattr(conn, '_network_junos_preparation', None):
            result['junos_preparation'] = self.redact_structured(conn._network_junos_preparation)
        result['timings_ms'] = dict(getattr(self._request, 'timings_ms', {}))
        result['connection_timings_ms'] = {k: round(v, 3) for k, v in getattr(conn, '_network_timings_ms', {}).items()}
        result['session_reused'] = bool(getattr(self._request, 'session_reused', False))
        return normalize_result(result)

    @measured_phase('command')
    def _send(self, conn: Any, command: str, timeout: int, expect_string: str | None = None,
              use_timing: bool = False, *, allow_reply: bool = False) -> tuple[Any, str | None]:
        self._request.stage = 'command'
        self._request.command_sent = False
        conn._network_command_sent = False
        timeout = min(timeout, self._checkpoint())
        if getattr(conn, '_network_awaiting_input', False) and not allow_reply:
            error = CollectionError({'error': 'SessionAwaitingInput', 'error_category': 'awaiting_input',
                                     'error_stage': 'command', 'awaiting_input': True, 'retryable': False,
                                     'message': 'Session awaits an explicit reply via ssh_interact'})
            error._network_keep_session = True
            raise error
        if self.execution_policy in ('read_only', 'operational'):
            driver = getattr(self._request, 'resolved_driver', '') or ''
            try:
                self.validate_execution_commands([command], driver)
                if self.execution_policy == 'operational' and not is_operational_prompt(
                        getattr(conn, '_network_prompt_text', '') or '', driver):
                    raise execution_policy_error('Operational CLI prompt is not verified', 'operational')
            except CollectionError as exc:
                exc._network_keep_session = True
                raise
        pattern = expect_string or getattr(conn, "_network_prompt_regex", None)
        if pattern:
            if len(pattern) > 1000:
                raise ValueError("expect_string too long")
            re.compile(pattern)
        conn._network_read_failure = None
        options = getattr(self._request, 'cli_options', {})
        quiet = float(options.get('timing_quiet_seconds' if use_timing else 'prompt_quiet_seconds', self.timing_quiet if use_timing else self.prompt_quiet))
        if not 0 <= quiet <= 2:
            raise ValueError('Prompt quiet time must be between 0 and 2 seconds')
        if not is_replay_safe(command) or getattr(conn, '_network_awaiting_input', False):
            # A command or reply may change context without changing the prompt.
            conn._network_cli_context_changed = True
        if hasattr(conn, 'collect_in_worker'):
            output, failure = conn.collect_in_worker(command, timeout, pattern, quiet, self._checkpoint)
            conn._network_read_failure = failure
            return output, pattern
        if hasattr(conn, 'read_channel') and hasattr(conn, 'write_channel'):
            output, failure = read_cli_output(conn, command, timeout, pattern or r'(?!)',
                                             self._checkpoint, quiet=quiet)
            conn._network_read_failure = failure
            return output, pattern
        if getattr(conn, '_network_junos_verify_echo', False):
            raise CollectionError({'error_category': 'output_verification', 'error_stage': 'command',
                'error_reason': 'junos_echo_channel_unavailable', 'retryable': False})
        conn._network_command_sent = True
        self._request.command_sent = True
        if use_timing:
            output = conn.send_command_timing(command, read_timeout=timeout, strip_prompt=False, strip_command=False, cmd_verify=False)
        else:
            options = {"read_timeout": timeout, "strip_prompt": False, "strip_command": False, "cmd_verify": False}
            if pattern:
                options.update(expect_string=pattern, auto_find_prompt=False)
            output = conn.send_command(command, **options)
        self._checkpoint()
        return output, pattern

    @bounded_request
    def execute(self, target, command, device_type=None, profile=None, read_timeout=None,
                expect_string=None, use_timing=False, save_output=False, use_textfsm=False):
        options = dict(target=target,command=command,device_type=device_type,profile=profile,
                       read_timeout=read_timeout,expect_string=expect_string,use_timing=use_timing,
                       save_output=save_output,use_textfsm=use_textfsm)
        connection_failed = False
        try:
            result = self._execute_once(**options)
        except Exception as exc:
            failure = classify_error(exc)
            if (failure.get('retryable') is not True
                    or failure.get('error_stage') not in {'connect', 'autodetect', 'tcp', 'banner', 'key_exchange'}
                    or failure.get('error_category') not in {
                        'connect_timeout', 'banner_timeout', 'handshake_incomplete', 'connection_lost',
                    }
                    or not is_replay_safe(command)):
                raise
            result = self.failure_result(exc, target, command)
            if result['command_sent'] is not False:
                raise
            connection_failed = True
        replay_context = result.pop('_replay_context', None)
        category = result.get('error_category')
        transient = connection_failed or category == 'connection_lost' or (
            category == 'read_timeout' and result.get('retryable') is True)
        if transient and is_replay_safe(command) and not result.get('awaiting_input'):
            if not connection_failed and replay_context is None:
                result.update(retryable=False, recovery_attempts=0, recovery_skipped='cli_context_unverified')
                return normalize_result(result)
            previous = result
            try:
                self._checkpoint()
            except Exception as exc:
                failure = classify_error(exc, 'command')
                result.update(failure, error_reason=ERROR_REASON_BY_CATEGORY.get(failure['error_category']),
                              recovery_attempts=0, recovery_skipped='request budget or cancellation',
                              previous_error_category=category, previous_error_stage=previous.get('error_stage'))
                return normalize_result(result)
            try:
                result = self._execute_once(**options, expected_replay_context=replay_context)
            except Exception as exc:
                if connection_failed:
                    # Preserve the Collector exception contract; the MCP
                    # dispatcher still receives both attempts via failure_result.
                    exc._network_previous_attempt = previous
                    raise
                if getattr(exc, '_network_replay_context_changed', False):
                    previous.update(retryable=False, recovery_attempts=1, recovery_skipped='cli_context_changed')
                    return normalize_result(previous)
                result = self.failure_result(exc, target, command)
            result.pop('_replay_context', None)
            result.update(recovery_attempts=1,previous_attempt=previous)
        return normalize_result(result)

    @bounded_request
    def _execute_once(self, target: str, command: str, device_type: str | None = None, profile: str | None = None,
                read_timeout: int | None = None, expect_string: str | None = None, use_timing: bool = False,
                save_output: bool = False, use_textfsm: bool = False,
                *, expected_replay_context=None) -> dict[str, Any]:
        command = safe_command(command)
        command = self._preflight(target, [command], device_type, profile)[0]
        read_timeout = bounded_int(read_timeout, getattr(self._request, 'cli_options', {}).get('read_timeout', self.read_timeout), 1, 600)
        started = time.monotonic()
        with self._lease(target, device_type, profile) as conn:
            replay_context = cli_replay_context(conn, getattr(self._request, 'resolved_driver', '') or '')
            if expected_replay_context is not None and replay_context != expected_replay_context:
                error = CollectionError({'error': 'CLIReplayContextChanged', 'error_category': 'output_verification',
                                         'error_stage': 'command', 'retryable': False})
                error._network_replay_context_changed = True
                error._network_command_sent = False
                error._network_keep_session = True
                raise error
            out, pattern = self._send(conn, command, read_timeout, expect_string, use_timing)
            result = self._command_result(conn, target, command, out, time.monotonic() - started, bool(save_output), pattern)
            if not result['ok']:
                result['_replay_context'] = replay_context
            if (not result["output_complete"] and not result.get("awaiting_input")) or getattr(conn, '_network_read_failure', None):
                self._disconnect_connection(conn)
            if use_textfsm and result["ok"]:
                from netmiko.utilities import structured_data_converter
                try:
                    structured = structured_data_converter(raw_data=clean_terminal(out), command=command,
                                                          platform=getattr(conn, "device_type", device_type or ""), use_textfsm=True)
                except Exception as exc:
                    result.update(ok=False, error=type(exc).__name__, error_category='parsing_error',
                                  error_stage='parsing', retryable=False, message='Parsing failed; raw output retained')
                    return normalize_result(result)
                if not isinstance(structured, str):
                    result["structured_output"] = self.redact_structured(structured)
                    # Preserve the legacy JSON-string output representation for parsed results.
                    if not result["saved"]:
                        result["output"] = json.dumps(result["structured_output"], ensure_ascii=False)
        return result

    def _open_junos_batch_session(self, params, target):
        try:
            return self._open(params)
        except CollectionError as exc:
            if not getattr(exc, '_network_junos_resync_failed', False):
                raise
            previous = self.failure_result(exc, target)
            with self._guard:
                self._connection_failures += 1
        try:
            self._checkpoint()
        except Exception as exc:
            exc._network_previous_attempt = previous
            exc._network_recovery_attempts = 0
            raise
        # Netmiko closed the failed constructor. Reuse the exact resolved
        # connection parameters while the caller still owns the lease.
        try:
            conn = self._open(params, minimal_junos=True)
        except Exception as exc:
            exc._network_previous_attempt = previous
            raise
        conn._network_previous_preparation = previous
        return conn

    def _disconnect_connection(self, conn: Any) -> None:
        with self._guard:
            entries = [entry for entry in self._sessions.values() if entry.get("conn") is conn]
        for entry in entries:
            self._disconnect_entry(entry, graceful=False)

    @bounded_request
    def execute_many(self, target: str, commands: list[str], device_type: str | None = None, profile: str | None = None,
                     read_timeout: int | None = None, save_output: bool = False, use_timing: bool = False,
                     expect_string: str | None = None, continue_on_error: bool = False,
                     *, allow_junos_recovery: bool = True, _resolved_scan_params=None) -> dict[str, Any]:
        if not isinstance(continue_on_error, bool):
            raise ValueError("continue_on_error must be boolean")
        if not isinstance(commands, list) or not 1 <= len(commands) <= MAX_COMMANDS:
            raise ValueError("commands must be an array containing 1 to 1000 commands")
        commands = [safe_command(c) for c in commands]
        commands = self._preflight(target, commands, device_type, profile, resolved_params=_resolved_scan_params)
        timeout = bounded_int(read_timeout, getattr(self._request, 'cli_options', {}).get('read_timeout', self.read_timeout), 1, 600)
        results = []
        recovery = {}

        def stop(index):
            for skipped_index in range(index + 1, len(commands)):
                results.append(normalize_result({'target': target,
                    'command': self.redact_output(commands[skipped_index]),
                    'command_index': skipped_index, 'ok': False, 'skipped': True,
                    'command_sent': False, 'output_complete': False, 'retryable': False,
                    'skipped_reason': 'batch_stopped', 'blocked_by_command_index': index}))
            raise BatchError(results, {**batch_summary(target, len(commands), results, continue_on_error), **recovery})

        recover_junos = allow_junos_recovery and all(
            is_replay_safe(command) and re.match(r'^(?:show|display)\s', command, re.I)
            for command in commands)
        with self._lease(target, device_type, profile, recover_junos=recover_junos,
                         resolved_params=_resolved_scan_params) as conn:
            previous = getattr(conn, '_network_previous_preparation', None)
            if previous is not None:
                del conn._network_previous_preparation
                recovery.update(recovery_attempts=1, previous_attempt=previous)
            for index, cmd in enumerate(commands):
                start = time.monotonic()
                conn._network_command_sent = False
                try:
                    out, pattern = self._send(conn, cmd, timeout, expect_string, use_timing)
                    result = self._command_result(conn, target, cmd, out, time.monotonic()-start, save_output, pattern)
                except Exception as exc:
                    failed = self.failure_result(exc, target, cmd)
                    failed.update(command_index=index,
                        command_sent=bool(getattr(conn, '_network_command_sent', False)),
                        replay_safe=is_replay_safe(cmd))
                    results.append(normalize_result(failed))
                    stop(index)
                result['command_index'] = index
                results.append(result)
                if not result['ok']:
                    synchronized_cli_error = (result.get('error_category') == 'cli_error'
                        and result.get('transport_ok') is True and result.get('output_complete') is True
                        and not result.get('awaiting_input') and not getattr(conn, '_network_read_failure', None)
                        and not dead_session(conn))
                    if not (continue_on_error and synchronized_cli_error):
                        stop(index)
        return {**batch_summary(target, len(commands), results, continue_on_error), **recovery}

    @bounded_request
    def interact(self, target: str, steps: list[str], device_type: str | None = None, profile: str | None = None,
                 read_timeout: int | None = None, save_output: bool = False) -> dict[str, Any]:
        if self.execution_policy in ('read_only', 'operational'):
            raise execution_policy_error('ssh_interact requires read_write; use a command or batch', self.execution_policy)
        if not isinstance(steps, list) or not 1 <= len(steps) <= MAX_COMMANDS:
            raise ValueError("steps must be an array containing 1 to 1000 strings")
        # Every command or reply must be provided as an explicit step.
        steps = [interaction_step(step) for step in steps]
        self._get_settings(target, device_type, profile)
        timeout = bounded_int(read_timeout, getattr(self._request, 'cli_options', {}).get('read_timeout', self.read_timeout), 1, 600)
        started = time.monotonic()
        chunks = []
        results = []

        def stopped_steps(index):
            skipped = [normalize_result({'step_index': step_index, 'skipped': True,
                       'skipped_reason': 'interaction_stopped', 'blocked_by_step_index': index})
                       for step_index in range(index + 1, len(steps))]
            return results + skipped

        with self._lease(target, device_type, profile) as conn:
            for step_index, step in enumerate(steps):
                try:
                    out, pattern = self._send(conn, step, timeout, use_timing=True, allow_reply=True)
                    checked = self._command_result(conn, target, step, out, time.monotonic()-started, save_output, pattern)
                except Exception as exc:
                    exc._network_error_stage = getattr(exc, '_network_error_stage', 'command')
                    exc._network_command_sent = bool(getattr(conn, '_network_command_sent', False))
                    failed = self.failure_result(exc, target)
                    failed.update(step_index=step_index, replay_safe=is_replay_safe(step))
                    results.append(normalize_result(failed))
                    exc._network_interact_steps = stopped_steps(step_index)
                    exc._network_failed_step_index = step_index
                    raise
                chunks.append(out)
                checked['step_index'] = step_index
                results.append(checked)
                if not checked['ok']:
                    if checked.get('awaiting_input'):
                        if step_index + 1 < len(steps):
                            continue
                        return normalize_result({**checked, 'steps': results})
                    if not checked['output_complete'] or getattr(conn, '_network_read_failure', None):
                        self._disconnect_connection(conn)
                    return normalize_result({**checked, 'steps': stopped_steps(step_index),
                                             'failed_step_index': step_index})
            try:
                result = self._result(target, "[interactive: %d steps]" % len(steps), "\n".join(chunks), time.monotonic()-started,
                                      save_output, getattr(conn, "_network_prompt_regex", None), interactive=True)
            except Exception as exc:
                exc._network_interact_steps = results
                exc._network_command_sent = any(step.get('command_sent') for step in results)
                raise
            # Each step already applied its command-specific CLI checks (including
            # BGP notification counters). A synthetic aggregate is not a command.
            if result['output_complete'] and all(step['ok'] or step.get('awaiting_input') for step in results) and results[-1]['ok']:
                result.update(ok=True, cli_ok=True)
                for key in ('error', 'error_category', 'error_stage', 'retryable', 'message'):
                    result.pop(key, None)
            if not result["output_complete"]:
                self._disconnect_connection(conn)
            result['steps'] = results
        return normalize_result(result)

    @bounded_request
    def parallel(self, tasks: list[dict[str, Any]]) -> dict[str, Any]:
        if not isinstance(tasks, list) or not 1 <= len(tasks) <= MAX_TASKS:
            raise ValueError(f"tasks must contain 1 to {MAX_TASKS} items")
        # Some MCP clients materialize optional schema fields with empty values.
        # Normalize these before enforcing command XOR commands.
        normalized_tasks = []
        cli_tool_by_mode = {"command": "ssh_execute", "commands": "ssh_execute_many"}
        types = {"string": str, "integer": int, "boolean": bool, "array": list}
        for index, task in enumerate(tasks):
            if not isinstance(task, dict) or "target" not in task:
                raise ValueError("Each task needs a target and command or commands")
            task = dict(task)
            if task.get("command") in (None, ""):
                task.pop("command", None)
            if task.get("commands") in (None, []):
                task.pop("commands", None)
            if ("command" in task) == ("commands" in task):
                raise ValueError(f"tasks[{index}] needs exactly one of command or commands")
            mode = "command" if "command" in task else "commands"
            fields = TOOLS[cli_tool_by_mode[mode]]["schema"]
            unknown = task.keys() - fields.keys()
            if unknown:
                raise ValueError(f"tasks[{index}] unsupported for {mode}: {', '.join(sorted(unknown))}")
            for key, value in task.items():
                if type(value) is not types[fields[key]]:
                    raise ValueError(f"tasks[{index}].{key} must be {fields[key]}")
            if mode == "commands" and any(not isinstance(command, str) for command in task[mode]):
                raise ValueError(f"tasks[{index}].commands must contain strings")
            normalized_tasks.append(task)
        tasks = normalized_tasks
        context = getattr(self._request, 'context', None)
        connection_timeouts = getattr(self._request, 'connection_timeouts', None)
        detection_timeout = getattr(self._request, 'detection_timeout', None)
        def execute_task(item: dict[str, Any]) -> dict[str, Any]:
            self._request.context = context
            self._request.timings_ms = {}
            self._request.session_reused = False
            self._request.connection_timeouts = connection_timeouts
            self._request.detection_timeout = detection_timeout
            try:
                if "command" in item:
                    return self.execute(**item)
                return self.execute_many(**item)
            except BatchError as exc:
                return {**(getattr(exc, 'summary', None) or {"target": item.get("target"), "ok": False, "results": exc.results}),
                        "error": "Batch interrupted after command failure"}
            except Exception as exc:
                return self.failure_result(exc, item.get("target"))
            finally:
                self._request.context = None
                self._request.connection_timeouts = None
                self._request.detection_timeout = None
        def run_task(item, queue_wait_ms):
            result = execute_task(item)
            result['queue_wait_ms'] = queue_wait_ms
            return result
        submitted = [self._parallel_queue.submit(self._task_pool, run_task, item) for item in tasks]
        results = [future.result() for future in submitted]
        successes = sum(x.get("ok", False) is True for x in results)
        batch_id = uuid.uuid4().hex
        for index, (item, result) in enumerate(zip(tasks, results)):
            self.audit("ssh_parallel.task", item, bool(result.get("ok")), result.get("elapsed_ms", 0) / 1000,
                       result.get("error"), result, batch_id=batch_id, task_index=index)
        return normalize_result({"batch_id": batch_id, "total": len(results), "successes": successes, "failures": len(results)-successes,
                "ok": successes == len(results), "partial_failure": 0 < successes < len(results), "results": results,
                "worker_telemetry": {"tasks_requested": len(tasks), "worker_limit": self.max_workers,
                                     "effective_worker_limit": min(len(tasks), self.max_workers)}})

    def read_output(self, output_id: str, offset: int = 0, limit: int = 200) -> dict[str, Any]:
        offset = bounded_int(offset, 0, 0, 20_000_000)
        limit = bounded_int(limit, 200, 1, 1000)
        chunks = []
        used = 0
        consumed = 0
        oversized_line = False
        with self._output_lease(output_id) as path, path.open("r", encoding="utf-8") as handle:
            for _ in range(offset):
                if handle.readline() == "":
                    return {"output_id": output_id, "offset": offset, "next_offset": offset, "more": False, "text": ""}
            for _ in range(limit):
                line = handle.readline()
                if not line:
                    break
                if used + len(line) > MAX_INLINE:
                    oversized_line = True
                    # Never silently skip a truncated line. Use ssh_read_output_bytes.
                    break
                chunks.append(line)
                used += len(line)
                consumed += 1
            more = oversized_line or bool(handle.readline())
        return {"output_id": output_id, "offset": offset, "next_offset": offset + consumed,
                "more": more, "text": "".join(chunks), "oversized_line": oversized_line,
                "notice": "Use ssh_read_output_bytes for oversized lines." if oversized_line else ""}

    def read_output_bytes(self, output_id: str, byte_offset: int = 0, length: int = 64000) -> dict[str, Any]:
        """Read a UTF-8-safe chunk; offsets always describe actual consumed bytes."""
        byte_offset = bounded_int(byte_offset, 0, 0, 2_000_000_000)
        length = bounded_int(length, 64000, 1, 150000)
        with self._output_lease(output_id) as path, path.open("rb") as handle:
            handle.seek(0, os.SEEK_END)
            size = handle.tell()
            start = min(byte_offset, size)
            handle.seek(start)
            data = handle.read(length)
            # If the requested boundary splits a code point, consume enough
            # continuation bytes to return valid UTF-8 without dropping bytes.
            while data and start + len(data) < size:
                try:
                    text = data.decode("utf-8")
                    break
                except UnicodeDecodeError as exc:
                    if exc.reason == "unexpected end of data" and len(data) < length + 3:
                        extra = handle.read(1)
                        if extra:
                            data += extra
                            continue
                    text = data.decode("utf-8", errors="replace")
                    break
            else:
                text = data.decode("utf-8", errors="replace")
        next_offset = start + len(data)
        return {"output_id": output_id, "byte_offset": start, "next_byte_offset": next_offset,
                "total_bytes": size, "more": next_offset < size, "text": text}

    def search_output(self, output_id: str, query: str, regex: bool = False, ignore_case: bool = True, max_matches: int = 30, context_lines: int = 1) -> dict[str, Any]:
        if not isinstance(query, str) or not 1 <= len(query) <= 300:
            raise ValueError("query must be 1 to 300 characters")
        if regex and not getattr(self, '_regex_worker', False):
            payload = dict(output_dir=str(self.output_dir.resolve()), output_id=safe_output_id(output_id),
                           query=query, ignore_case=ignore_case, max_matches=max_matches, context_lines=context_lines)
            with self._output_lease(output_id):
                deadline = time.monotonic() + min(2, self._checkpoint())
                worker = subprocess.Popen([sys.executable, str(Path(__file__).resolve()), '--search-worker'],
                                          stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                          text=True, encoding='utf-8')
                wire = json.dumps(payload)
                try:
                    while True:
                        self._checkpoint()
                        if time.monotonic() >= deadline:
                            raise TimeoutError('Regex search exceeded 2 seconds; use a literal query')
                        try:
                            stdout, _ = worker.communicate(wire, timeout=min(.1, deadline-time.monotonic()))
                            result = json.loads(stdout)
                            if 'worker_error' in result:
                                raise ValueError(result['worker_error'])
                            return result
                        except subprocess.TimeoutExpired:
                            wire = None
                finally:
                    if worker.poll() is None:
                        worker.kill()
                    worker.communicate()
        max_matches = bounded_int(max_matches, 30, 1, 100)
        context_lines = bounded_int(context_lines, 1, 0, 5)
        flags = re.IGNORECASE if ignore_case else 0
        pattern = re.compile(query if regex else re.escape(query), flags)
        from collections import deque
        before: deque[tuple[int, str]] = deque(maxlen=context_lines)
        matches = 0
        post = 0
        excerpt = []
        seen: set[int] = set()
        max_excerpt_chars = 120_000
        used_chars = 0
        def emit(num: int, line: str) -> None:
            nonlocal used_chars
            if num in seen or used_chars >= max_excerpt_chars:
                return
            data = line[:3000].rstrip("\n")
            excerpt.append({"line": num, "text": data})
            seen.add(num)
            used_chars += len(data)
        with self._output_lease(output_id) as path, path.open("r", encoding="utf-8") as handle:
            for num, line in enumerate(handle, 1):
                self._checkpoint()
                found = bool(pattern.search(line))
                if found:
                    matches += 1
                    if matches <= max_matches:
                        for n, prev in before:
                            emit(n, prev)
                        emit(num, line)
                        post = context_lines
                elif post > 0:
                    emit(num, line)
                    post -= 1
                before.append((num, line))
        return {"output_id": output_id, "query": query, "total_matches": matches,
                "shown_matches": min(matches, max_matches), "excerpt": excerpt,
                "truncated": used_chars >= max_excerpt_chars}

    def inventory(self, query: str | None = None, device_type: str | None = None,
                  offset: int = 0, limit: int = 100, summary_only: bool = False) -> dict[str, Any]:
        """Search and page public inventory metadata. Use limit=0 for all matches."""
        query = (query or "").strip().casefold()
        if len(query) > 255:
            raise ValueError("query must be at most 255 characters")
        device_type = (device_type or "").strip()
        if device_type and not re.fullmatch(r"[A-Za-z0-9_]+", device_type):
            raise ValueError("Invalid device_type")
        offset = bounded_int(offset, 0, 0, 20_000_000)
        limit = bounded_int(limit, 100, 0, 10_000)
        matches = []
        type_counts: dict[str, int] = {}
        default_type = self.defaults.get("device_type", "autodetect")
        for name, value in self.devices.items():
            if not isinstance(value, dict):
                continue
            host = str(value.get("host", name))
            dtype = str(value.get("device_type", default_type))
            if query and query not in str(name).casefold() and query not in host.casefold():
                continue
            if device_type and dtype != device_type:
                continue
            type_counts[dtype] = type_counts.get(dtype, 0) + 1
            if not summary_only:
                profile = value.get('profile') or 'default'
                prof = self.profiles.get(profile, {})
                effective = {**self.defaults, **(prof if isinstance(prof, dict) else {}), **value}
                matches.append({"name": name, "host": host, "device_type": dtype, "tags": value.get("tags", []),
                                "profile": profile, "port": bounded_int(effective.get('port', 22), 22, 1, 65535)})
        total = sum(type_counts.values())
        page = [] if summary_only else (matches[offset:] if limit == 0 else matches[offset:offset + limit])
        returned = len(page)
        return {"devices": page, "total": total, "offset": offset, "limit": limit,
                "returned": returned, "more": False if summary_only or limit == 0 else offset + returned < total,
                "summary_only": bool(summary_only), "device_type_counts": dict(sorted(type_counts.items())),
                "profiles": list(self.profiles.keys()), "dynamic_hosts_allowed": True,
                "resolution": {"indexed_hosts": len(self._host_index), "shared_hosts": len(self._shared_hosts), "ambiguous_hosts": len(self._ambiguous_hosts)},
                "warnings": self._index_warnings[:20]}

    def status(self) -> dict[str, Any]:
        with self._guard:
            sessions = [{"host": k[0], "port": k[1], "device_type": k[2], "connected": not dead_session(v.get("conn")),
                         "leased": v.get("borrowers", 0), "awaiting_input": bool(getattr(v.get("conn"), "_network_awaiting_input", False)), "idle_seconds": round(time.monotonic()-v["used"], 2)} for k,v in self._sessions.items()]
        return {"version": VERSION, "mcp_protocol_versions": list(MCP_PROTOCOL_VERSIONS),
                "execution_policy": self.execution_policy,
                "execution_policy_configured": self.execution_policy_configured,
                "phase_metrics": self._metrics.snapshot(), "parallel_queue": self._parallel_queue.snapshot(), "driver_cache_refreshes": self._driver_cache_refreshes, "persistent_autodetect_hits": self._persistent_detection_hits, "output_storage_mode": self.output_storage_mode, "sessions": sessions, "connections_opened": self._connections_opened, "session_reuses": self._session_reuses,
                "connection_failures": self._connection_failures, "session_evictions": self._session_evictions,
                "max_sessions": self.max_sessions, "session_max_age_seconds": self.session_max_age,
                "autodetect_timeout_seconds": self.autodetect_timeout, "autodetect_probes": self._detection_probes,
                "autodetect_cache_hits": self._detection_cache_hits, "max_workers": self.max_workers, "inline_max_chars": self.inline_max_chars, "session_ttl_seconds": self.session_ttl, "output_dir": str(self.output_dir), "output_ttl_seconds": self.output_ttl, "output_quota_bytes": self.output_quota, "active_outputs": len(self._active_outputs), "inventory_index": {"aliases": len(self.devices), "indexed_hosts": len(self._host_index), "shared_hosts": len(self._shared_hosts), "ambiguous_hosts": len(self._ambiguous_hosts), "warnings": len(self._index_warnings)}}

    def close(self, target: str | None = None) -> dict[str, Any]:
        # Some MCP clients serialize an omitted optional target as an empty string.
        target = target or None
        if target is not None:
            # Closing by inventory host/IP must hit the same cached session as the alias.
            _alias, device, _mode = self._resolve_target(target)
            host = device.get("host", target)
        else:
            host = None
        count = 0
        with self._guard:
            matches = [(key, entry) for key, entry in self._sessions.items() if host is None or key[0] == host]
        for key, entry in matches:
            with self._entry_lock(entry["lock"]):
                if entry.get("conn") is not None:
                    self._disconnect_entry(entry)
                    count += 1
                with self._guard:
                    # Preserve reservations owned by callers waiting for this lock.
                    if not entry.get('borrowers') and self._sessions.get(key) is entry:
                        self._sessions.pop(key, None)
        return {"closed": count}


def batch_summary(target, command_count, results, continue_on_error):
    """One result shape for complete, partial, and stopped batches.

    Legacy fields (results/ok/total/successes/failures/continue_on_error) stay
    unchanged; the extra fields only describe the failure/skip state.
    """
    successes = sum(1 for item in results if item.get('ok') is True)
    failed = next((item for item in results if not item.get('ok') and not item.get('skipped')), {})
    return normalize_result({
        'target': target, 'results': results,
        'ok': successes == command_count,
        'total': command_count, 'successes': successes,
        'failures': command_count - successes,
        'continue_on_error': continue_on_error,
        'partial_failure': 0 < successes < command_count,
        'skipped_commands': sum(1 for item in results if item.get('skipped')),
        'failed_command_index': failed.get('command_index'),
        'failed_status': failed.get('status'),
        'failed_error_category': failed.get('error_category'),
        'failed_error_stage': failed.get('error_stage'),
        'failed_error_reason': failed.get('error_reason'),
    })


class BatchError(Exception):
    def __init__(self, results: list[dict[str, Any]], summary: dict[str, Any] | None = None):
        self.results = results
        self.summary = summary
        self.last_result = next((r for r in reversed(results) if not r.get("skipped")), {})
        super().__init__("A command failed during batch execution")


TOOLS: dict[str, dict[str, Any]] = {
    "ssh_execute": {"description": 'Execute one agent-selected CLI command on an alias/hostname/IP within user scope. Use device/VRF evidence for syntax and save_output for large raw. Check completeness/awaiting_input; SUCCESS is CLI collection, not network health.', "schema": {"target": "string", "command": "string", "device_type": "string", "profile": "string", "read_timeout": "integer", "expect_string": "string", "use_timing": "boolean", "save_output": "boolean", "use_textfsm": "boolean"}, "required": ["target", "command"], "method": "execute"},
    "ssh_execute_many": {"description": 'Execute commands (string array) in order on one session. Stops on failure; unsent suffix is SKIPPED. continue_on_error only continues complete synchronized CLI errors for independent commands. Inspect each result.', "schema": {"target": "string", "commands": "array", "device_type": "string", "profile": "string", "read_timeout": "integer", "save_output": "boolean", "use_timing": "boolean", "expect_string": "string", "continue_on_error": "boolean"}, "required": ["target", "commands"], "method": "execute_many"},
    "ssh_interact": {"description": 'Requires read_write. Send steps, including authorized configuration/replies, on the same target/profile/mode. Empty string/newline sends Enter; no implicit reply. Inspect each step and current awaiting_input.', "schema": {"target": "string", "steps": "array", "device_type": "string", "profile": "string", "read_timeout": "integer", "save_output": "boolean"}, "required": ["target", "steps"], "method": "interact"},
    "ssh_parallel": {"description": 'Run 1-100 independent tasks; each needs target and exactly one of command or commands. Output/result order retained per task. Inspect each result; task count is not SSH concurrency.', "schema": {"tasks": "array"}, "required": ["tasks"], "method": "parallel"},
    "ssh_read_output": {"description": 'Read saved text by output_id, zero-based line offset and limit. Follow next_offset while more=true; use byte reader if oversized_line prevents progress. A slice is not full configuration.', "schema": {"output_id": "string", "offset": "integer", "limit": "integer"}, "required": ["output_id"], "method": "read_output"},
    "ssh_read_output_bytes": {"description": 'Read saved output as best-effort UTF-8 text with byte offsets, including long lines. Start at zero, follow next_byte_offset (may extend length to finish UTF-8). For byte-exact export, copy/hash the source file.', "schema": {"output_id": "string", "byte_offset": "integer", "length": "integer"}, "required": ["output_id"], "method": "read_output_bytes"},
    "ssh_search_output": {"description": 'Search the entire saved file by query (literal/regex). total_matches counts lines; limited excerpts use one-based lines and may omit text even if truncated=false. Zero matches are not network absence; check collection scope/completeness/inheritance. Errors are not zero.', "schema": {"output_id": "string", "query": "string", "regex": "boolean", "ignore_case": "boolean", "max_matches": "integer", "context_lines": "integer"}, "required": ["output_id", "query"], "method": "search_output"},
    "ssh_inventory": {"description": 'Search configured alias/host IP by query and optional device_type. Returns profile/port and resolution warnings, not live topology/auth proof. Default 100 rows; limit=0 returns all matches; summary_only counts. Do not guess profiles.', "schema": {"query": "string", "device_type": "string", "offset": "integer", "limit": "integer", "summary_only": "boolean"}, "required": [], "method": "inventory"},
    "ssh_status": {"description": 'Inspect execution_policy, execution_policy_configured, and collector/session state. parallel_queue is process-local; running may await session/SSH slots. Metadata is not network health. No passwords returned.', "schema": {}, "required": [], "method": "status"},
    "ssh_close": {"description": 'Close all sessions for the resolved host, across profiles/ports; missing/empty target closes the entire pool. Use only when all affected sessions are in scope, not after every command.', "schema": {"target": "string"}, "required": [], "method": "close"},
}


def make_tool_list() -> list[dict[str, Any]]:
    descriptions = []
    for name, spec in TOOLS.items():
        fields = {}
        for key, value in spec["schema"].items():
            item = {"type": value}
            if value == "array":
                if key == "tasks":
                    task_fields = dict(TOOLS["ssh_execute"]["schema"])
                    task_fields["continue_on_error"] = "boolean"
                    item["items"] = {"type": "object", "properties": {name: {"type": kind} for name, kind in task_fields.items()}, "required": ["target"], "additionalProperties": False}
                    item["items"]["properties"]["commands"] = {"type": "array", "items": {"type": "string"}}
                else:
                    item["items"] = {"type": "string"}
            fields[key] = item
        descriptions.append({"name": name, "description": spec["description"], "inputSchema": {"type": "object", "properties": fields, "required": spec["required"], "additionalProperties": False}})
    return descriptions


def rpc_error(rid: Any, code: int, message: str) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": rid, "error": {"code": code, "message": message}}


def rpc_response(rid: Any, result: Any) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": rid, "result": result}


def handle_rpc(req: dict[str, Any], collector: Collector) -> dict[str, Any] | None:
    if not isinstance(req, dict):
        return rpc_error(None, -32600, "Invalid request")
    method = req.get("method")
    rid = req.get("id", None)
    if rid is None:
        # JSON-RPC notifications must never generate responses.
        return None
    try:
        if method == "initialize":
            requested = (req.get("params") or {}).get("protocolVersion", "2025-06-18")
            protocol = requested if requested in MCP_PROTOCOL_VERSIONS else MCP_PROTOCOL_VERSIONS[-1]
            return rpc_response(rid, {"protocolVersion": protocol, "capabilities": {"tools": {"listChanged": False}}, "serverInfo": {"name": "goose-network-collector", "version": VERSION}, "instructions": "Network CLI executor. Call ssh_status to check execution policy. Configuration changes require explicit user authorization and an explicitly configured read_write policy. Responses and completion are verified. Use credential profiles."})
        if method == "ping":
            return rpc_response(rid, {})
        if method == "tools/list":
            return rpc_response(rid, {"tools": make_tool_list()})
        if method == "tools/call":
            params = req.get("params") or {}
            name = params.get("name")
            tool = TOOLS.get(name)
            if tool is None:
                return rpc_error(rid, -32602, "Unknown tool")
            args = params.get("arguments", {})
            if not isinstance(args, dict):
                return rpc_error(rid, -32602, "Tool arguments must be an object")
            if name == "ssh_close" and "target" in args and not isinstance(args["target"], str):
                return rpc_error(rid, -32602, "ssh_close target must be a string")
            unknown = set(args) - set(tool["schema"])
            if unknown:
                return rpc_error(rid, -32602, "Unexpected tool arguments: " + ", ".join(sorted(unknown)))
            missing = set(tool["required"]) - set(args)
            if missing:
                return rpc_error(rid, -32602, "Missing arguments: " + ", ".join(sorted(missing)))
            started = time.monotonic()
            audit_error = None
            try:
                payload = getattr(collector, tool["method"])(**args)
                if payload.get("ok") is False:
                    audit_error = str(payload.get("error") or "One or more commands/tasks failed verification")
            except BatchError as exc:
                audit_error = type(exc).__name__ + ": " + str(exc)
                payload = getattr(exc, 'summary', None) or normalize_result({"ok": False, "results": exc.results})
            except Exception as exc:
                # Tool errors belong in tool result (not broken JSON-RPC). Never dump locals or tracebacks.
                audit_error = type(exc).__name__
                payload = collector.failure_result(exc, args.get("target"), args.get("command"))
            is_error = payload.get("ok") is False
            collector.audit(name, args, not is_error, time.monotonic() - started, audit_error, payload)
            result = {"content": [{"type": "text", "text": json.dumps(payload, ensure_ascii=False)}], "isError": is_error}
            return rpc_response(rid, result)
        return rpc_error(rid, -32601, "Method not found")
    except Exception:
        return rpc_error(rid, -32603, "Internal error")


def run_stdio(collector: Collector) -> None:
    """Bounded request workers; cancellation/deadlines are cooperative between IO.

    Never disconnect a transport from the dispatcher: its owner retains the lease
    until Netmiko returns or its bounded read timeout fires.
    """
    configure_stdio()
    write_lock = threading.Lock()
    pending_lock = threading.Lock()
    pending = {}
    slots = threading.BoundedSemaphore(collector.max_workers * 2)
    pool = concurrent.futures.ThreadPoolExecutor(max_workers=collector.max_workers)

    def emit(response):
        if response is not None:
            with write_lock:
                sys.stdout.write(json.dumps(response, ensure_ascii=False, separators=(',', ':')) + '\n')
                sys.stdout.flush()

    def run(message, event, deadline):
        collector._request.context = (event, deadline)
        collector._request.timings_ms = {}
        collector._request.session_reused = False
        try:
            collector._checkpoint()
            emit(handle_rpc(message, collector))
        except Exception as exc:
            emit(rpc_error(message.get('id'), -32000, type(exc).__name__))
        finally:
            collector._request.context = None
            with pending_lock:
                pending.pop(message.get('id'), None)
            slots.release()

    try:
        for line in sys.stdin:
            if not line.strip():
                continue
            try:
                message = json.loads(line)
            except json.JSONDecodeError:
                emit(rpc_error(None, -32700, "Invalid JSON"))
                continue
            else:
                if not isinstance(message, dict):
                    emit(rpc_error(None, -32600, 'Invalid request'))
                    continue
                rid = message.get('id')
                if rid is not None and (not isinstance(rid, (str, int)) or isinstance(rid, bool)):
                    emit(rpc_error(None, -32600, 'Invalid request id'))
                    continue
                if message.get('method') == 'notifications/cancelled':
                    params = message.get('params') or {}
                    cancelled = params.get('requestId') if isinstance(params, dict) else None
                    if isinstance(cancelled, (str, int)):
                        with pending_lock:
                            if cancelled in pending:
                                pending[cancelled].set()
                    continue
                # Fast control calls do not queue behind device IO.
                params = message.get('params') or {}
                slow = message.get('method') == 'tools/call' and isinstance(params, dict) and params.get('name') not in {'ssh_status', 'ssh_inventory'}
                if rid is None or not slow:
                    emit(handle_rpc(message, collector))
                    continue
                with pending_lock:
                    if rid in pending:
                        emit(rpc_error(rid, -32600, 'Duplicate in-flight request id'))
                        continue
                    if not slots.acquire(blocking=False):
                        emit(rpc_error(rid, -32000, 'Request capacity reached'))
                        continue
                    event = threading.Event()
                    pending[rid] = event
                pool.submit(run, message, event, time.monotonic() + collector.request_timeout)
    finally:
        pool.shutdown(wait=True)
        collector.shutdown()


def main() -> int:
    configure_stdio()
    if "--search-worker" in sys.argv:
        try:
            args = json.loads(sys.stdin.read())
            collector = Collector({'defaults': {'output_dir': args.pop('output_dir'), 'session_sweep_seconds': 0}}, connect_factory=lambda **kw: None)
            collector._regex_worker = True
            collector._cleanup_outputs = lambda *a, **kw: {}
            try:
                result = collector.search_output(regex=True, **args)
            finally:
                collector.shutdown()
        except Exception as exc:
            result = {'worker_error': type(exc).__name__}
        print(json.dumps(result), flush=True)
        return 0
    if "--detect-worker" in sys.argv:
        try:
            result = detection_worker(json.loads(sys.stdin.read()))
        except Exception:
            result = {"error": "DetectionWorkerError"}
        print(json.dumps(result), flush=True)
        return 0
    parser = argparse.ArgumentParser(description="Generic Netmiko SSH MCP collector for Goose")
    parser.add_argument("--config", default=os.environ.get("NETWORK_MCP_CONFIG"))
    parser.add_argument("--credentials-file", help="Shared SSH credential JSON; relative to config directory")
    parser.add_argument("--inventory-csv", default=os.environ.get("NETWORK_MCP_INVENTORY_CSV"))
    parser.add_argument("--check", action="store_true", help="Check Python and Netmiko dependency")
    parser.add_argument("--version", action="store_true")
    args = parser.parse_args()
    if args.config is None:
        candidate = Path(sys.executable if getattr(sys, "frozen", False) else __file__).resolve().parent / "devices.json"
        if candidate.is_file():
            args.config = str(candidate)
    if args.version:
        print(VERSION)
        return 0
    if args.check:
        try:
            import netmiko
            print(json.dumps({"ok": True, "python": sys.version.split()[0], "netmiko": netmiko.__version__, "version": VERSION}))
            return 0
        except ImportError:
            print(json.dumps({"ok": False, "message": "netmiko missing", "python": sys.version.split()[0]}))
            return 2
    try:
        config = load_config(args.config, args.credentials_file)
        config = load_inventory_csv(config, args.inventory_csv)
        collector = Collector(config)
        run_stdio(collector)
        return 0
    except Exception as exc:
        stderr("Collector startup failed: " + type(exc).__name__ + ": " + str(exc)[:250])
        return 1


if __name__ == "__main__":
    sys.exit(main())
