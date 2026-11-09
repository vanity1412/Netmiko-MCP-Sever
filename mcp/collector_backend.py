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
import re
import sys
import subprocess
import threading
import time
import traceback
import uuid
from typing import Any, Callable

VERSION = "1.3.3"
MAX_INLINE = 200_000
MAX_TASKS = 100
APP_HOME = Path(os.environ.get("NETWORK_MCP_DATA_DIR") or ((Path(os.environ["LOCALAPPDATA"]) / "GooseNetworkCollector") if os.environ.get("LOCALAPPDATA") else (Path.home() / ".goose-network-collector")))
SENSITIVE_KEYS = ("password", "secret", "passphrase", "token", "private_key", "username")
ENV_RE = re.compile(r"^\$\{([A-Za-z_][A-Za-z0-9_]*)\}$")
KNOWN_KEYS = {"host", "port", "device_type", "username", "password", "secret", "use_keys", "key_file", "allow_agent", "ssh_strict", "system_host_keys", "alt_host_keys", "alt_key_file", "fast_cli", "conn_timeout", "auth_timeout", "banner_timeout", "global_delay_factor", "global_cmd_verify", "keepalive", "ssh_config_file", "disabled_algorithms"}


_TOFU_LOCK = threading.Lock()
PAGER_RE = re.compile(r'(?i)(?:---- More ----|---\(more[^\r\n)]*\)---|--\s*More\s*--(?:[ \t]*\(\d+%\))?)')
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


def bounded_request(method):
    @functools.wraps(method)
    def call(self, *args, **kwargs):
        with self.request_budget():
            try:
                return method(self, *args, **kwargs)
            except Exception as exc:
                if not hasattr(exc, '_network_error_stage'):
                    exc._network_error_stage = getattr(self._request, 'stage', 'unknown')
                raise
    return call


def stderr(message: str) -> None:
    print(message, file=sys.stderr, flush=True)


def configure_stdio():
    """MCP and worker pipes are UTF-8, including on Windows legacy locales."""
    for stream in (sys.stdin, sys.stdout):
        if hasattr(stream, 'reconfigure'):
            stream.reconfigure(encoding='utf-8')


def expand_env(value: Any) -> Any:
    if isinstance(value, str):
        match = ENV_RE.fullmatch(value)
        if match:
            return os.environ.get(match.group(1), "")
        return os.path.expandvars(os.path.expanduser(value))
    if isinstance(value, dict):
        return {k: expand_env(v) for k, v in value.items()}
    if isinstance(value, list):
        return [expand_env(v) for v in value]
    return value


def load_config(path: str | None) -> dict[str, Any]:
    if path and Path(path).is_file():
        with open(path, "r", encoding="utf-8-sig") as file:
            config = json.load(file)
        if not isinstance(config, dict):
            raise ValueError("Configuration must be a JSON object")
        return expand_env(config)
    if path and not Path(path).is_file():
        raise FileNotFoundError(f"Config file not found: {path}")
    return {}


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
    required = {"name", "ip", "netmiko_device_type"}
    if not rows or not required.issubset(rows[0]):
        raise ValueError("Inventory CSV requires name, ip and netmiko_device_type columns")
    devices = dict(config.get("devices", {}))
    warnings = list(config.get("inventory_warnings") or [])
    for number, row in enumerate(rows, 2):
        name = (row.get("name") or "").strip()
        host = (row.get("ip") or "").strip()
        device_type = (row.get("netmiko_device_type") or "").strip()
        profile = (row.get("profile") or "").strip() or "default"
        if not name or not host or not device_type:
            raise ValueError(f"Invalid inventory CSV row {number}")
        if name in devices:
            existing = devices[name]
            if not isinstance(existing, dict):
                warnings.append(f"row {number}: alias '{name}' also defined in config - config entry kept")
                continue
            if (existing.get("host"), existing.get("device_type"), existing.get("profile") or "default") == (host, device_type, profile):
                warnings.append(f"row {number}: duplicate alias '{name}' identical to an earlier row - row ignored")
            else:
                warnings.append(
                    f"row {number}: duplicate alias '{name}' conflicts with an earlier row "
                    f"(host={existing.get('host')}, device_type={existing.get('device_type')}) - "
                    "first row kept, row ignored; fix the CSV")
            continue
        devices[name] = {"host": host, "device_type": device_type, "profile": profile}
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


def readonly_command(command: str, platform: str) -> str:
    """Conservative grammar, not a substitute for device-side AAA authorization."""
    command = safe_command(command).strip()
    if any(x in command for x in (';', '&', '`', '\\', '<', '>')):
        raise PermissionError("CLI operators/redirection are not permitted")
    parts = cli_pipeline(command)
    quote = None
    for char in command:
        if char in ('\"', "'"):
            quote = None if quote == char else (char if quote is None else quote)
        if char == '$' and quote is None:
            raise PermissionError('Dollar signs are allowed only in quoted CLI filters')
    base = parts[0].lower()
    diagnostic = bool(re.fullmatch(r'(?:ping|traceroute|tracert|tracepath)\s+[a-z0-9_.:%/\[\] =\-]+', base))
    if platform.startswith('juniper'):
        allowed = diagnostic or bool(re.match(r'^show\s+(?:version|system|interfaces|route|bgp|ospf|isis|ldp|mpls|rsvp|bfd|pim|igmp|multicast|vpls|l2circuit|configuration|chassis|lacp|lldp|ethernet-switching|vlans|arp|cli|log|ntp|services|security|class-of-service|bridge|evpn|task|snmp|firewall)\b', base))
        filters = r'(?:no-more|count|last(?:\s+\d+)?|(?:match|except|find)\s+.+|display\s+(?:set|json|xml|detail|inheritance))'
    elif platform.startswith(('cisco_', 'arista_', 'dell_', 'hp_')):
        allowed = diagnostic or bool(re.match(r'^show\s+(?:controllers|etherchannel|policy-map|version|clock|running-config|startup-config|interfaces?|ip|ipv6|route|bgp|ospf|isis|mpls|lacp|lldp|cdp|vlan|arp|inventory|environment|processes|users|privilege|aaa|tacacs|radius|logging|platform|ntp|vrf|mac|mac-address-table|spanning-tree|standby|vrrp|track|access-lists|snmp|tcp|udp|ssh|license|hardware|module|power|switch|stack|diagnostic|bfd|evpn|segment-routing)\b', base))
        filters = r'(?:count|(?:include|exclude|begin|section)\s+.+)'
    elif platform.startswith('huawei'):
        allowed = diagnostic or bool(re.match(r'^display\s+(?:eth-trunk|lacp|bfd|version|clock|current-configuration|saved-configuration|interface|ip|ipv6|bgp|ospf|isis|mpls|lldp|vlan|arp|device|cpu-usage|memory-usage|aaa|users|logbuffer|transceiver|ntp-service|ntp|stp|mac-address|traffic|alarm|elabel|esn|license|optical-module|port|dhcp|dns|temperature|fan|power|stack|ssh|tcp|udp|vpn-instance)\b', base))
        filters = r'(?:count|no-more|(?:include|exclude|begin)\s+.+)'
    elif platform == 'linux':
        # No general shell, interpreters, arbitrary paths or options with side effects.
        allowed = diagnostic or bool(re.fullmatch(r'(?:uname(?: -[asrnmvpio]+)?|uptime|date|whoami|id|hostname|ip (?:(?:-br|-s) )?(?:address|addr|link|route|neigh) show(?: [a-z0-9_.:/ \-]+)?|ip (?:-6 )?route get [a-z0-9_.:%]+|ss -[tulnapoei]+|getent (?:hosts|ahosts) [a-z0-9_.:\-]+)', base))
        filters = r'(?!)'
    else:
        raise PermissionError("No reviewed read-only grammar for this platform")
    if not allowed or re.search(r'\b(?:save|redirect|append|delete|erase|reset|clear|reload|reboot|configure|commit|copy|write|install|request|activate|deactivate|test|start|stop|file|url|flash|bootflash)\b', base):
        raise PermissionError("Command is outside the read-only policy")
    if diagnostic:
        if len(parts) != 1:
            raise PermissionError('Diagnostic commands do not accept CLI pipelines')
        counts = re.findall(r'(?:\bcount\s+|\brepeat\s+|(?<!\S)-c\s*)(\d+)\b', base)
        if any(not 1 <= int(value) <= 20 for value in counts):
            raise ValueError('Diagnostic packet count must be between 1 and 20')
        if re.search(r'(?<!\S)-(?:f|l)(?:\s|$)', base):
            raise PermissionError('Flood/preload diagnostic options are not supported')
    if any(not re.fullmatch(filters, p, re.I) for p in parts[1:]):
        raise PermissionError("CLI pipeline is outside the read-only policy")
    return command


def prepare_noc_command(command, platform):
    command = readonly_command(command, platform)
    if re.match(r'^ping\s', command, re.I):
        if platform.startswith('juniper') and not re.search(r'\bcount\s+\d+\b', command, re.I):
            command += ' count 5'
        elif platform == 'linux' and not re.search(r'(?<!\S)-c\s*\d+\b', command):
            command += ' -c 5'
    return command


def clean_terminal(text: str) -> str:
    """Remove ANSI/control noise, including BEL, without dropping evidence lines."""
    text = re.sub(r"\x1b\][^\x07]*(?:\x07|\x1b\\)", "", text)
    text = re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", text)
    while re.search(r"[^\n]\x08", text):
        text = re.sub(r"[^\n]\x08", "", text)
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
    match = re.search(CONFIRM_RE.pattern + r'\s*[:?]?\s*$', line)
    if match:
        prefix = line[:match.start()].strip()
        if not prefix or prefix.endswith('?') or re.match(
                r'(?i)^(?:continue|proceed|confirm|are you sure|do you|would you|really|clear|overwrite|delete|reboot|reload|save|exit|quit|accept)\b', prefix):
            return True
    return bool(re.fullmatch(r'(?i)(?:(?:enter|retype|confirm)\s+)?(?:(?:old|new|current)\s+)?(?:password|passphrase)\s*:|press\s+(?:enter|return|any key)\s+to\s+continue[.:]?', line))


def read_cli_output(conn, command, timeout, pattern, checkpoint=None, quiet=.08):
    """Read one command without re-sending it; retain partial data on failure.

    Netmiko owns the transport, driver setup and channel normalization. Reading
    its channel directly avoids the mandatory echo wait and losing accumulated
    output when send_command raises ReadTimeout. The caller owns the session lease.
    """
    deadline = time.monotonic() + timeout
    chunks, tail, received = [], '', 0
    handled_pagers = {}
    last_data = time.monotonic()
    failure = None
    try:
        # Drop a buffered old prompt/login banner before sending this command.
        for _ in range(16):
            if checkpoint:
                checkpoint()
            if time.monotonic() >= deadline:
                raise TimeoutError('Command read timed out before send')
            if not conn.read_channel():
                break
        conn.write_channel(conn.normalize_cmd(command))
        while True:
            if checkpoint:
                checkpoint()
            now = time.monotonic()
            if now >= deadline:
                raise TimeoutError('Command read timed out')
            data = conn.read_channel()
            if data:
                chunks.append(data)
                received += len(data)
                tail = (tail + data)[-16384:]
                last_data = time.monotonic()
            cleaned = clean_terminal(tail)
            if pending_interaction(cleaned):
                break
            pagers = list(PAGER_RE.finditer(tail))
            if pagers and ending_matches(PAGER_RE.pattern + r'[ \t]*', cleaned):
                pager = pagers[-1]
                marker_id = received - len(tail) + pager.start()
                if marker_id not in handled_pagers:
                    handled_pagers[marker_id] = received - len(tail) + pager.end()
                    conn.write_channel(' ')
            elif ending_matches(pattern, cleaned) and time.monotonic() - last_data >= quiet:
                break
            if not data:
                channel = getattr(conn, 'remote_conn', None)
                if channel is not None and (getattr(channel, 'closed', False) or getattr(channel, 'eof_received', False)):
                    if ending_matches(pattern, cleaned):
                        break
                    raise EOFError('SSH channel closed before ending prompt')
            time.sleep(min(.02, max(0, deadline - time.monotonic())))
    except Exception as exc:
        failure = classify_error(exc, 'command')
        failure['message'] = 'Command interrupted; partial output retained'
    raw = ''.join(chunks)
    if handled_pagers:
        # Blank only the actual footer spans. Equal-width blanks preserve terminal
        # backspace erasure without deleting literal --More-- text in real data.
        parts, previous = [], 0
        for start, end in sorted(handled_pagers.items()):
            parts.extend((raw[previous:start], ' ' * (end - start)))
            previous = end
        parts.append(raw[previous:])
        raw = ''.join(parts)
    output = clean_terminal(raw)
    return output, failure


def detection_worker(params: dict[str, Any]) -> dict[str, Any]:
    """Small read-only probe set; parent process enforces a hard wall deadline."""
    from netmiko import ConnectHandler
    params = dict(params)
    probe_timeout = bounded_int(params.pop('_probe_read_timeout', 4),4,1,60)
    install_tofu()
    params.update(device_type="generic_termserver", read_timeout_override=probe_timeout,
                  ssh_strict=False, alt_host_keys=False, system_host_keys=False)
    for field in ("conn_timeout", "auth_timeout", "banner_timeout"):
        params.setdefault(field, 8)
    conn = None
    try:
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
                return {"device_type": platform, "probe_command": command}
        return {"error": "AutodetectUnknown", "message": "No supported version signature in bounded probes"}
    except Exception as exc:
        # Never put library exception text/credentials on the worker wire.
        return {**classify_error(exc, "autodetect"), "message": "Read-only detection probe failed"}
    finally:
        if conn is not None:
            with contextlib.suppress(Exception):
                conn.disconnect()


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
            raise CollectionError(failure)
        if not ending_matches(r'(?m)^' + re.escape(prompt) + r'[ \t]*\r?$', output):
            raise ValueError('CLI prompt could not be verified after terminal setup')
        return output

    set_width._goose_tolerant_width = True
    BaseConnection.set_terminal_width = set_width


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
        self.max_workers = bounded_int(self.defaults.get("max_workers"), 8, 1, 32)
        self.inline_max_chars = bounded_int(self.defaults.get("inline_max_chars"), 12000, 100, MAX_INLINE)
        self.session_ttl = bounded_int(self.defaults.get("session_ttl_seconds"), 180, 0, 86400)
        self.session_max_age = bounded_int(self.defaults.get("session_max_age_seconds"), 43200, 0, 604800)
        self.max_sessions = bounded_int(self.defaults.get("max_sessions"), 64, 1, 1024)
        self.sweep_interval = bounded_int(self.defaults.get("session_sweep_seconds"), 60, 0, 3600)
        self.autodetect_timeout = bounded_int(self.defaults.get("autodetect_timeout_seconds"), 20, 1, 120)
        self.detect_cache_ttl = bounded_int(self.defaults.get("autodetect_cache_seconds"), 28800, 1, 604800)
        self._detect_cache: dict[tuple[Any, ...], tuple[float, str]] = {}
        self._detection_locks: dict[tuple[Any, ...], list[Any]] = {}
        self._detection_probes = 0
        self._detection_cache_hits = 0
        self._connection_failures = 0
        self._auth_failures: dict[tuple[Any, ...], float] = {}
        self._session_evictions = 0
        self._stop = threading.Event()
        self._request = threading.local()
        self._ssh_slots = threading.BoundedSemaphore(self.max_workers)
        self._task_pool = concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers, thread_name_prefix='ssh-task')
        self.request_timeout = bounded_int(self.defaults.get('request_timeout_seconds'), 120, 1, 3600)
        self.read_timeout = bounded_int(self.defaults.get("read_timeout"), 40, 1, 600)
        self.output_dir = Path(self.defaults.get("output_dir") or APP_HOME / "outputs").expanduser()
        self.output_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.output_ttl = bounded_int(self.defaults.get("output_ttl_seconds"), 604800, 0, 31_536_000)
        self.output_quota = bounded_int(self.defaults.get("output_quota_bytes"), 1_073_741_824, 0, 1_099_511_627_776)
        self._output_lock = threading.RLock()
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
            install_tolerant_width()
            # Some Junos images localize/suppress the English acknowledgements
            # expected by Netmiko (for example, "Screen width set to").
            # Consume those setup replies by timing instead of matching text.
            # Patch Junos only when the installed Netmiko exposes its real package.
            # Lightweight injected/fake Netmiko modules used by protocol tests need
            # only ConnectHandler/SSHDetect and must remain valid dependencies.
            try:
                from netmiko.juniper.juniper import JuniperBase
            except (ImportError, ModuleNotFoundError):
                JuniperBase = None

            if JuniperBase is not None and not getattr(JuniperBase, "_goose_tolerant_prep", False):
                def tolerant_session_preparation(conn: Any) -> None:
                    conn._test_channel_read(pattern=r"[%>$#]")
                    conn.enter_cli_mode()
                    prompt = None
                    for command in (
                        "set cli screen-width 511",
                        "set cli complete-on-space off",
                        "set cli screen-length 0",
                    ):
                        conn.write_channel(conn.normalize_cmd(command))
                        reply = conn.read_channel_timing(last_read=0.5, read_timeout=5)
                        prompt = last_prompt(reply) or prompt
                    conn.clear_buffer()
                    if not prompt:
                        conn.write_channel(conn.RETURN)
                        prompt = last_prompt(conn.read_channel_timing(last_read=0.5, read_timeout=5))
                    if not prompt:
                        raise ValueError("Junos did not return a valid CLI prompt after setup")
                    conn.base_prompt = prompt[:-1]
                    conn._network_prompt_text = prompt
                    conn._network_prompt_regex = r"(?m)^" + re.escape(prompt) + r"\s*$"

                JuniperBase.session_preparation = tolerant_session_preparation
                JuniperBase._goose_tolerant_prep = True

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
        return (json.dumps({k: v for k, v in device.items() if k in KNOWN_KEYS or k == "profile"}, sort_keys=True),)

    def _build_device_index(self) -> None:
        """Index inventory by case-insensitive alias and by host/IP.

        Only unambiguous keys are indexed. When several aliases share one host,
        that host is indexed only if every alias agrees on device_type/profile/port
        (deterministic: first alias wins); otherwise the host is marked ambiguous,
        is left out of implicit resolution, and is reported as a warning.
        """
        self._alias_index: dict[str, str] = {}
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

    def redact_output(self, message: str) -> str:
        secrets = [os.environ.get(x, "") for x in ("NETWORK_SSH_PASSWORD", "NETWORK_SSH_SECRET")]
        for section in [self.defaults, *self.profiles.values(), *self.devices.values()]:
            if isinstance(section, dict):
                for k, v in section.items():
                    if any(word in k.lower() for word in SENSITIVE_KEYS) and isinstance(v, str):
                        secrets.append(v)
        return redact_text(message, [x for x in secrets if isinstance(x, str)])

    def _audit_command(self, command: Any) -> str:
        text = self.scrub_error(str(command))[:500]
        # Redact common inline CLI secret forms without trying to interpret vendor syntax.
        text = re.sub(r"(?i)\b(password|passwd|secret|token|community|passphrase)\b(\s+|\s*=\s*)\S+",
                      lambda m: m.group(1) + m.group(2) + "[redacted]", text)
        return text

    def redact_structured(self, value: Any) -> Any:
        if isinstance(value, dict):
            return {k: '[redacted]' if any(s in str(k).lower() for s in (*SENSITIVE_KEYS, 'community', 'api_key')) else self.redact_structured(v) for k, v in value.items()}
        if isinstance(value, list):
            return [self.redact_structured(v) for v in value]
        return self.redact_output(value) if isinstance(value, str) else value

    def audit(self, name: str, args: dict[str, Any], ok: bool, elapsed: float,
              error: str | None = None) -> None:
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
            record["task_targets"] = [str(x.get("target"))[:255] for x in tasks[:100] if isinstance(x, dict)]
            record["task_command_counts"] = [1 if x.get("command") else len(x.get("commands") or []) for x in tasks[:100] if isinstance(x, dict)]
            record["task_commands"] = [[self._audit_command(c) for c in ([x["command"]] if x.get("command") else x.get("commands", []))] for x in tasks[:100] if isinstance(x, dict)]
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
        # Do not pass generic app settings to ConnectHandler.
        settings = {k: v for k, v in self.defaults.items() if k in KNOWN_KEYS}
        settings.update({k: v for k, v in prof.items() if k in KNOWN_KEYS})
        settings.update({k: v for k, v in device.items() if k in KNOWN_KEYS})
        settings["host"] = safe_target(device.get("host") or target)
        if device_type:
            settings["device_type"] = device_type
        settings.setdefault("device_type", "cisco_ios")
        settings.setdefault("port", 22)
        settings.setdefault("username", os.environ.get("NETWORK_SSH_USER", ""))
        settings.setdefault("password", os.environ.get("NETWORK_SSH_PASSWORD", ""))
        settings.setdefault("secret", os.environ.get("NETWORK_SSH_SECRET", ""))
        # Permissive host-key acceptance requested for this collector. Persistence
        # is per client and never turns a writable-disk problem into an SSH failure.
        settings['ssh_strict'] = False
        settings['alt_host_keys'] = False
        settings['system_host_keys'] = False
        settings['alt_key_file'] = str(Path(settings.get('alt_key_file') or APP_HOME / 'known_hosts').expanduser().resolve())
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
        token = json.dumps({k: v for k, v in params.items() if k not in {"host", "port", "device_type", "conn_timeout", "auth_timeout", "banner_timeout"}}, ensure_ascii=False, sort_keys=True)
        fingerprint = hashlib.sha256(token.encode("utf-8")).hexdigest()
        return (params["host"], params["port"], params["device_type"], params.get("username"), params.get("key_file"), fingerprint)

    def _detect_key(self, params: dict[str, Any]) -> tuple[Any, ...]:
        key = self._session_key(params)
        return key[:2] + key[3:]

    def _resolve_platform(self, params: dict[str, Any]) -> None:
        if params["device_type"] == "generic_termserver":
            params["device_type"] = "autodetect"
        if params["device_type"] != "autodetect":
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
                    raise PermissionError('Authentication previously failed; suppressed for 5 minutes')
                try:
                    self._resolve_platform_locked(params)
                except Exception as exc:
                    if classify_error(exc, 'autodetect')['error_category'] in {'authentication', 'auth_method'}:
                        self._auth_failures[key] = time.monotonic() + 300
                    raise
        finally:
            with self._guard:
                entry[1] -= 1
                if not entry[1]:
                    self._detection_locks.pop(key, None)

    def _resolve_platform_locked(self, params: dict[str, Any]) -> None:
        key = self._detect_key(params)
        with self._guard:
            cached = self._detect_cache.get(key)
            if cached and time.monotonic() - cached[0] < self.detect_cache_ttl:
                params["device_type"] = cached[1]
                self._detection_cache_hits += 1
                return
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
                # Killable process, not a timed-out thread left sending more probes.
                self._checkpoint()
                probe_deadline = time.monotonic() + min(
                    getattr(self._request, 'detection_timeout', None) or self.autodetect_timeout, self._checkpoint())
                worker = subprocess.Popen([sys.executable, "-u", str(Path(__file__).resolve()), "--detect-worker"],
                                          stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                          text=True, encoding="utf-8")
                wire_params = dict(params)
                overrides = getattr(self._request, 'connection_timeouts', None) or {}
                wire_params['_probe_read_timeout'] = min(30, overrides.get('banner_timeout', 4))
                wire = json.dumps(wire_params)
                try:
                    while True:
                        self._checkpoint()
                        left = probe_deadline - time.monotonic()
                        if left <= 0:
                            raise TimeoutError('Autodetect deadline exceeded')
                        try:
                            stdout, _stderr = worker.communicate(wire, timeout=min(.1, left))
                            break
                        except subprocess.TimeoutExpired:
                            wire = None
                finally:
                    if worker.poll() is None:
                        worker.kill()
                    worker.communicate()
                try:
                    result = json.loads(stdout)
                except (ValueError, TypeError):
                    raise ValueError("Autodetect worker returned invalid output") from None
                if result.get("error"):
                    raise CollectionError(result)
                guess = result.get("device_type")
        if not guess or not re.fullmatch(r"[a-zA-Z0-9_]+", guess):
            raise ValueError("Autodetect could not verify a supported platform; specify device_type")
        params["device_type"] = guess
        with self._guard:
            if len(self._detect_cache) >= 256:
                self._detect_cache.pop(min(self._detect_cache, key=lambda k: self._detect_cache[k][0]))
            self._detect_cache[key] = (time.monotonic(), guess)

    def _open(self, params: dict[str, Any]) -> Any:
        remaining = self._checkpoint()
        params = dict(params)
        for field in ('conn_timeout', 'auth_timeout', 'banner_timeout'):
            params[field] = min(params.get(field, 15), remaining)
        self._request.stage = 'connect'
        started = time.monotonic()
        conn = self._connect(**params)
        try:
            self._request.stage = 'prompt'
            prompt = getattr(conn, "_network_prompt_text", None)
            if not prompt and hasattr(conn, "find_prompt"):
                prompt = last_prompt(conn.find_prompt())
            if not prompt:
                raise ValueError('CLI prompt could not be verified after connection')
            if prompt:
                conn._network_prompt_text = prompt
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
    def _lease(self, target: str, device_type: str | None = None, profile: str | None = None):
        with self._lease_inner(target, device_type, profile) as conn:
            yield conn

    @contextlib.contextmanager
    def _lease_inner(self, target: str, device_type: str | None = None, profile: str | None = None):
        self._checkpoint()
        params = self._get_settings(target, device_type, profile)
        self._resolve_platform(params)
        key = self._session_key(params)
        evicted = None
        with self._guard:
            entry = self._sessions.get(key)
            if entry is None:
                if len(self._sessions) >= self.max_sessions:
                    idle = [(k, e) for k, e in self._sessions.items() if not e.get("borrowers")]
                    if not idle:
                        raise RuntimeError("Session pool is at capacity; all sessions are leased")
                    old_key, evicted = min(idle, key=lambda item: item[1]["used"])
                    self._sessions.pop(old_key)
                    self._session_evictions += 1
                entry = {"lock": threading.RLock(), "conn": None, "used": time.monotonic(), "created": 0.0, "borrowers": 0}
                self._sessions[key] = entry
            entry["borrowers"] += 1
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
                        if not entry["conn"].is_alive():
                            self._disconnect_entry(entry)
                    except Exception:
                        self._disconnect_entry(entry)
                if entry["conn"] is None:
                    try:
                        if self._auth_failures.get(self._detect_key(params), 0) > time.monotonic():
                            raise PermissionError("Authentication previously failed; suppressed for 5 minutes")
                        entry["conn"] = self._open(params)
                    except Exception as exc:
                        with self._guard:
                            if classify_error(exc, 'connect')['error_category'] in {'authentication', 'auth_method'}:
                                now = time.monotonic()
                                self._auth_failures = {k: expiry for k, expiry in self._auth_failures.items() if expiry > now}
                                self._auth_failures[self._detect_key(params)] = now + 300
                            self._connection_failures += 1
                        raise
                    entry["created"] = time.monotonic()
                    with self._guard:
                        self._connections_opened += 1
                else:
                    with self._guard:
                        self._session_reuses += 1
                try:
                    yield entry["conn"]
                except Exception as exc:
                    verified_cli_failure = isinstance(exc, BatchError) and bool(exc.results) and exc.results[-1].get('error_category') == 'cli_error' and all(
                        exc.results[-1].get(k) for k in ('transport_ok', 'output_complete'))
                    if not verified_cli_failure:
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
            if not graceful:
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
        details.update(ok=False, transport_ok=False, cli_ok=None, output_complete=False,
                       message=self.scrub_error(str(exc)))
        details['ssh_authenticated'] = True if details['error_stage'] in {'command', 'prompt', 'persistence'} else None
        details['cli_ready'] = True if details['error_stage'] in {'command', 'persistence'} else None
        if target is not None:
            details['target'] = target
        if command is not None:
            details['command'] = self.redact_output(command)
        return details

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
    def _entry_lock(self, lock):
        while not lock.acquire(timeout=min(.1, self._checkpoint())):
            pass
        try:
            self._checkpoint()
            yield
        finally:
            lock.release()

    def _preflight(self, target, commands, device_type=None, profile=None):
        self._request.stage = 'validation'
        params = self._get_settings(target, device_type, profile)
        # Autodetect must complete before choosing a platform-specific policy.
        self._resolve_platform(params)
        return [prepare_noc_command(command, params['device_type']) for command in commands]

    @contextlib.contextmanager
    def _output_lease(self, output_id: str):
        output_id = safe_output_id(output_id)
        with self._output_lock:
            self._active_outputs[output_id] = self._active_outputs.get(output_id, 0) + 1
        try:
            yield self.output_dir / (output_id + ".txt")
        finally:
            with self._output_lock:
                count = self._active_outputs.get(output_id, 1) - 1
                if count:
                    self._active_outputs[output_id] = count
                else:
                    self._active_outputs.pop(output_id, None)
            # A prior quota pass may have skipped this active file.
            self._cleanup_outputs()

    def _cleanup_outputs(self, reserve_bytes: int = 0) -> dict[str, int]:
        """Delete expired files first, then oldest files over quota; skip active files."""
        now = time.time()
        removed = 0
        freed = 0
        with self._output_lock:
            files = []
            for path in self.output_dir.glob("*.txt"):
                output_id = path.stem
                if not re.fullmatch(r"[0-9]{8}T[0-9]{6}Z_[a-f0-9]{32}", output_id):
                    continue
                try:
                    stat = path.stat()
                except OSError:
                    continue
                files.append((stat.st_mtime, stat.st_size, output_id, path))
            total = sum(item[1] for item in files)
            for mtime, size, output_id, path in sorted(files):
                expired = bool(self.output_ttl and now - mtime > self.output_ttl)
                over_quota = bool(self.output_quota and total + reserve_bytes > self.output_quota)
                if not expired and not over_quota:
                    continue
                if self._active_outputs.get(output_id, 0) or self._output_pins.get(output_id, 0) > now:
                    continue
                try:
                    path.unlink()
                    self._output_pins.pop(output_id, None)
                    total -= size
                    removed += 1
                    freed += size
                except OSError:
                    pass
        return {"removed": removed, "freed_bytes": freed}

    def _save_output(self, content: str) -> str:
        content = self.redact_output(content)
        content_bytes = len(content.encode("utf-8"))
        if self.output_quota and content_bytes > self.output_quota:
            raise ValueError("Output exceeds storage quota; no output_id was issued")
        self._cleanup_outputs(content_bytes)
        stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        output_id = stamp + "_" + uuid.uuid4().hex
        path = self.output_dir / (output_id + ".txt")
        with self._output_lock:
            # Fail clearly instead of issuing an ID that cleanup immediately removes.
            total = sum(p.stat().st_size for p in self.output_dir.glob("*.txt") if re.fullmatch(r"[0-9]{8}T[0-9]{6}Z_[a-f0-9]{32}", p.stem))
            if self.output_quota and total + content_bytes > self.output_quota:
                raise ValueError("Output storage full; export evidence or wait for retention cleanup")
            with open(path, "x", encoding="utf-8", newline="\n") as handle:
                handle.write(content)
            self._output_pins[output_id] = time.time() + 300
        self._cleanup_outputs()
        return output_id

    def _result(self, target: str, command: str, output: Any, elapsed: float, save_output: bool = False,
                prompt_pattern: str | None = None, interactive: bool = False) -> dict[str, Any]:
        if not isinstance(output, str):
            output = json.dumps(output, ensure_ascii=False)
        output = clean_terminal(output)
        prompt = last_prompt(output)
        ending = output.rstrip()
        complete = ending_matches(prompt_pattern, ending) if prompt_pattern else bool(prompt)
        # Match known error messages at line boundaries, not words in a config/route.
        errors = re.findall(r"(?im)^\s*(?:%\s*)?(?:Invalid (?:input|command|interface)|Bad IP address or host name|Unknown command|Error\s*:|Ambiguous command|Incomplete command|Unrecognized command|syntax error|permission denied|access denied|authorization (?:failed|denied)|command authorization failed|not authorized|insufficient (?:privilege|permission)|bash: .*: command not found)[^\n]*", output)
        errors += re.findall(
            r'(?im)^[ \t]*(?:%[ \t]*)?(?:Unrecognized host[^\n]*|Unknown host[^\n]*|'
            r'-?(?:bash|sh|zsh|ash|dash):[^\n]*(?:not found|permission denied|cannot execute)[^\n]*|'
            r'(?:ping|traceroute|tracert|tracepath|ip|ss|getent):[^\n]*(?:not found|unknown host|bad address|'
            r'name or service not known|temporary failure in name resolution|operation not permitted|'
            r'permission denied|invalid|unrecognized|cannot)[^\n]*|'
            r'usage:[ \t]*(?:ping|traceroute|tracert|tracepath|ip|ss|getent)\b[^\n]*)', output)
        if re.match(r'^show\s+bgp\s+neighbors?\b', command.strip(), re.I) and re.search(r'(?m)^Peer:\s+', output):
            errors = [line for line in errors if not re.fullmatch(
                r"\s*Error:\s+'[^'\n]+'\s+Sent:\s+\d+\s+Recv:\s+\d+\s*", line)]
        if ending_matches(PAGER_RE.pattern, output) or pending_interaction(output):
            complete = False
        echo = interactive or command_echo_line(command, output) is not None
        cli_ok = not bool(errors)
        output = self.redact_output(output)
        size = len(output)
        data: dict[str, Any] = {"target": target, "command": self.redact_output(command), "ok": bool(cli_ok and complete), "transport_ok": True,
                                "cli_ok": cli_ok, "output_complete": complete, "command_echo_verified": bool(echo),
                                "validation": "heuristic", "characters": size, "lines": output.count("\n") + (1 if output and not output.endswith("\n") else 0), "elapsed_ms": int(elapsed * 1000)}
        if not data["ok"]:
            data["error"] = "CliError" if not cli_ok else "OutputVerificationError"
            data.update(error_category='cli_error' if not cli_ok else 'output_verification',
                        error_stage='cli' if not cli_ok else 'verification', retryable=False)
            data["message"] = self.scrub_error(errors[0]) if errors else "Ending prompt not verified or pager/confirmation remains; output is incomplete"
        if save_output or size > self.inline_max_chars:
            try:
                data["output_id"] = self._save_output(output)
            except Exception as exc:
                exc._network_error_stage = 'persistence'
                raise
            data["preview"] = output[:min(self.inline_max_chars, 2000)]
            data["saved"] = True
            data["notice"] = "Full output saved. Use ssh_read_output or ssh_search_output with output_id."
        else:
            data["output"] = output
            data["saved"] = False
        return data

    def _command_result(self, conn, target, command, output, elapsed, save_output, pattern):
        # Custom expectations may end a read early, but only the actual device
        # prompt can establish completion for every public execution method.
        result = self._result(target, command, output, elapsed, save_output,
                              getattr(conn, '_network_prompt_regex', None) or pattern)
        failure = getattr(conn, '_network_read_failure', None)
        if failure:
            result.update(failure, ok=False)
            if failure.get('error_category') == 'connection_lost':
                result['transport_ok'] = False
        client = getattr(conn, 'remote_conn_pre', None)
        if getattr(client, '_network_host_key_persisted', None) is False:
            result['warnings'] = ['SSH host key accepted; could not persist known_hosts']
        return result

    def _send(self, conn: Any, command: str, timeout: int, expect_string: str | None = None,
              use_timing: bool = False) -> tuple[Any, str | None]:
        timeout = min(timeout, self._checkpoint())
        self._request.stage = 'command'
        pattern = expect_string or getattr(conn, "_network_prompt_regex", None)
        if pattern:
            if len(pattern) > 1000:
                raise ValueError("expect_string too long")
            re.compile(pattern)
        conn._network_read_failure = None
        if hasattr(conn, 'read_channel') and hasattr(conn, 'write_channel'):
            output, failure = read_cli_output(conn, command, timeout, pattern or r'(?!)',
                                             self._checkpoint, quiet=.5 if use_timing else .08)
            conn._network_read_failure = failure
            return output, pattern
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
    def execute(self, target: str, command: str, device_type: str | None = None, profile: str | None = None,
                read_timeout: int | None = None, expect_string: str | None = None, use_timing: bool = False,
                save_output: bool = False, use_textfsm: bool = False) -> dict[str, Any]:
        command = safe_command(command)
        command = self._preflight(target, [command], device_type, profile)[0]
        read_timeout = bounded_int(read_timeout, self.read_timeout, 1, 600)
        started = time.monotonic()
        with self._lease(target, device_type, profile) as conn:
            out, pattern = self._send(conn, command, read_timeout, expect_string, use_timing)
            result = self._command_result(conn, target, command, out, time.monotonic() - started, bool(save_output), pattern)
            if not result["output_complete"] or getattr(conn, '_network_read_failure', None):
                self._disconnect_connection(conn)
            if use_textfsm and result["ok"]:
                from netmiko.utilities import structured_data_converter
                structured = structured_data_converter(raw_data=clean_terminal(out), command=command,
                                                      platform=getattr(conn, "device_type", device_type or ""), use_textfsm=True)
                if not isinstance(structured, str):
                    result["structured_output"] = self.redact_structured(structured)
                    # Preserve the legacy JSON-string output representation for parsed results.
                    if not result["saved"]:
                        result["output"] = json.dumps(result["structured_output"], ensure_ascii=False)
        return result

    def _disconnect_connection(self, conn: Any) -> None:
        with self._guard:
            entries = [entry for entry in self._sessions.values() if entry.get("conn") is conn]
        for entry in entries:
            self._disconnect_entry(entry, graceful=False)

    @bounded_request
    def execute_many(self, target: str, commands: list[str], device_type: str | None = None, profile: str | None = None,
                     read_timeout: int | None = None, save_output: bool = False, use_timing: bool = False,
                     expect_string: str | None = None) -> dict[str, Any]:
        if not isinstance(commands, list) or not 1 <= len(commands) <= 50:
            raise ValueError("commands must be an array containing 1 to 50 commands")
        commands = [safe_command(c) for c in commands]
        commands = self._preflight(target, commands, device_type, profile)
        timeout = bounded_int(read_timeout, self.read_timeout, 1, 600)
        results = []
        with self._lease(target, device_type, profile) as conn:
            for cmd in commands:
                start = time.monotonic()
                try:
                    out, pattern = self._send(conn, cmd, timeout, expect_string, use_timing)
                    result = self._command_result(conn, target, cmd, out, time.monotonic()-start, save_output, pattern)
                    results.append(result)
                    if not result["ok"]:
                        raise BatchError(results)
                except BatchError:
                    raise
                except Exception as exc:
                    # The connection is potentially out of sync; do not continue blindly.
                    results.append(self.failure_result(exc, target, cmd))
                    raise BatchError(results)
        return {"target": target, "results": results, "ok": True, "total": len(commands), "successes": len(results)}

    @bounded_request
    def interact(self, target: str, steps: list[str], device_type: str | None = None, profile: str | None = None,
                 read_timeout: int | None = None, save_output: bool = False) -> dict[str, Any]:
        if not isinstance(steps, list) or not 1 <= len(steps) <= 20:
            raise ValueError("steps must be an array containing 1 to 20 strings")
        # No blind confirmations, passwords, shell escapes or arbitrary replies.
        # Each step is an independently reviewed read-only command.
        steps = [safe_command(step) for step in steps]
        steps = self._preflight(target, steps, device_type, profile)
        timeout = bounded_int(read_timeout, self.read_timeout, 1, 600)
        started = time.monotonic()
        chunks = []
        results = []
        with self._lease(target, device_type, profile) as conn:
            for step in steps:
                out, pattern = self._send(conn, step, timeout, use_timing=True)
                checked = self._command_result(conn, target, step, out, time.monotonic()-started, save_output, pattern)
                chunks.append(out)
                results.append(checked)
                if not checked['ok']:
                    self._disconnect_connection(conn)
                    return {**checked, 'steps': results}
            result = self._result(target, "[interactive: %d steps]" % len(steps), "\n".join(chunks), time.monotonic()-started,
                                  save_output, getattr(conn, "_network_prompt_regex", None), interactive=True)
            # Each step already applied its command-specific CLI checks (including
            # BGP notification counters). A synthetic aggregate is not a command.
            if result['output_complete'] and all(step['ok'] for step in results):
                result.update(ok=True, cli_ok=True)
                for key in ('error', 'error_category', 'error_stage', 'retryable', 'message'):
                    result.pop(key, None)
            if not result["output_complete"]:
                self._disconnect_connection(conn)
            result['steps'] = results
        return result

    @bounded_request
    def parallel(self, tasks: list[dict[str, Any]]) -> dict[str, Any]:
        if not isinstance(tasks, list) or not 1 <= len(tasks) <= MAX_TASKS:
            raise ValueError(f"tasks must contain 1 to {MAX_TASKS} items")
        # Some MCP clients materialize optional schema fields with empty values.
        # Normalize these before enforcing command XOR commands.
        normalized_tasks = []
        for task in tasks:
            if not isinstance(task, dict) or "target" not in task:
                raise ValueError("Each task needs a target and command or commands")
            task = dict(task)
            if not task.get("command"):
                task.pop("command", None)
            if not task.get("commands"):
                task.pop("commands", None)
            if ("command" in task) == ("commands" in task):
                raise ValueError("Each task needs exactly one of command or commands")
            normalized_tasks.append(task)
        tasks = normalized_tasks
        context = getattr(self._request, 'context', None)
        def run_task(item: dict[str, Any]) -> dict[str, Any]:
            self._request.context = context
            try:
                if "command" in item:
                    return self.execute(**{k: v for k,v in item.items() if k in {"target","command","device_type","profile","read_timeout","expect_string","use_timing","save_output","use_textfsm"}})
                return self.execute_many(**{k: v for k,v in item.items() if k in {"target","commands","device_type","profile","read_timeout","use_timing","save_output","expect_string"}})
            except BatchError as exc:
                return {"target": item.get("target"), "ok": False, "results": exc.results, "error": "Batch interrupted after command failure"}
            except Exception as exc:
                return self.failure_result(exc, item.get("target"))
            finally:
                self._request.context = None
        results = list(self._task_pool.map(run_task, tasks))
        successes = sum(x.get("ok", False) is True for x in results)
        for item, result in zip(tasks, results):
            self.audit("ssh_parallel.task", item, bool(result.get("ok")), result.get("elapsed_ms", 0) / 1000, result.get("error"))
        return {"total": len(results), "successes": successes, "failures": len(results)-successes,
                "ok": successes == len(results), "partial_failure": 0 < successes < len(results), "results": results}

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
        default_type = self.defaults.get("device_type", "cisco_ios")
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
                matches.append({"name": name, "host": host, "device_type": dtype, "tags": value.get("tags", [])})
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
            sessions = [{"host": k[0], "port": k[1], "device_type": k[2], "connected": v.get("conn") is not None,
                         "leased": v.get("borrowers", 0), "idle_seconds": round(time.monotonic()-v["used"], 2)} for k,v in self._sessions.items()]
        return {"version": VERSION, "sessions": sessions, "connections_opened": self._connections_opened, "session_reuses": self._session_reuses,
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
        return {"closed": count}


class BatchError(Exception):
    def __init__(self, results: list[dict[str, Any]]):
        self.results = results
        super().__init__("A command failed during batch execution")


TOOLS: dict[str, dict[str, Any]] = {
    "ssh_execute": {"description": "Execute a reviewed read-only CLI command over Netmiko SSH on a device alias, hostname or IP. Device type can be specified at call time; raw output is retained. State-changing commands are always rejected.", "schema": {"target": "string", "command": "string", "device_type": "string", "profile": "string", "read_timeout": "integer", "expect_string": "string", "use_timing": "boolean", "save_output": "boolean", "use_textfsm": "boolean"}, "required": ["target", "command"], "method": "execute"},
    "ssh_execute_many": {"description": "Run a sequence of reviewed read-only CLI commands on one device using the same SSH session. Stops if one command fails.", "schema": {"target": "string", "commands": "array", "device_type": "string", "profile": "string", "read_timeout": "integer", "save_output": "boolean", "use_timing": "boolean", "expect_string": "string"}, "required": ["target", "commands"], "method": "execute_many"},
    "ssh_interact": {"description": "Run independent read-only commands with timing reads and verify every step. No confirmations, yes/Enter responses or configuration mode. Prefer ssh_execute_many for ordinary collection.", "schema": {"target": "string", "steps": "array", "device_type": "string", "profile": "string", "read_timeout": "integer", "save_output": "boolean"}, "required": ["target", "steps"], "method": "interact"},
    "ssh_parallel": {"description": "Run independent SSH collections concurrently on many devices. Each task can have a DIFFERENT target, command or list of commands, optional vendor and profile. Output kept per task.", "schema": {"tasks": "array"}, "required": ["tasks"], "method": "parallel"},
    "ssh_read_output": {"description": "Read a slice of a saved CLI output by opaque output_id, offset (0-based LINE number), and limit (max lines). Useful for huge configs.", "schema": {"output_id": "string", "offset": "integer", "limit": "integer"}, "required": ["output_id"], "method": "read_output"},
    "ssh_read_output_bytes": {"description": "Read exact bytes of any saved raw output, including very long single lines, with byte offset and length. UTF-8 text is decoded best-effort.", "schema": {"output_id": "string", "byte_offset": "integer", "length": "integer"}, "required": ["output_id"], "method": "read_output_bytes"},
    "ssh_search_output": {"description": "Search entire saved CLI output for a substring or regular expression, returning matching lines with configurable context.", "schema": {"output_id": "string", "query": "string", "regex": "boolean", "ignore_case": "boolean", "max_matches": "integer", "context_lines": "integer"}, "required": ["output_id", "query"], "method": "search_output"},
    "ssh_inventory": {"description": "Search and page configured aliases by hostname/IP and device type. Defaults to 100 devices; use limit=0 to explicitly return all matches. summary_only returns counts without devices.", "schema": {"query": "string", "device_type": "string", "offset": "integer", "limit": "integer", "summary_only": "boolean"}, "required": [], "method": "inventory"},
    "ssh_status": {"description": "View active connection cache and collector limits. No passwords are returned.", "schema": {}, "required": [], "method": "status"},
    "ssh_close": {"description": "Disconnect all cached sessions or only those matching target/alias.", "schema": {"target": "string"}, "required": [], "method": "close"},
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
            protocol = requested if requested in {"2024-11-05", "2025-03-26", "2025-06-18", "2025-11-25", "2026-07-28"} else "2025-06-18"
            return rpc_response(rid, {"protocolVersion": protocol, "capabilities": {"tools": {"listChanged": False}}, "serverInfo": {"name": "goose-network-collector", "version": VERSION}, "instructions": "Generic network CLI collector. Choose your own commands and targets. Never send secrets in tool arguments; use credential profiles and SSH access with read-only permissions."})
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
            args = params.get("arguments") or {}
            if not isinstance(args, dict):
                return rpc_error(rid, -32602, "Tool arguments must be an object")
            unknown = set(args) - set(tool["schema"])
            if unknown:
                return rpc_error(rid, -32602, "Unexpected tool arguments: " + ", ".join(sorted(unknown)))
            missing = set(tool["required"]) - set(args)
            if missing:
                return rpc_error(rid, -32602, "Missing arguments: " + ", ".join(sorted(missing)))
            started = time.monotonic()
            audit_error = None
            try:
                output = getattr(collector, tool["method"])(**args)
                result = {"content": [{"type": "text", "text": json.dumps(output, ensure_ascii=False)}], "isError": output.get("ok") is False}
                if result["isError"]:
                    audit_error = str(output.get("error") or "One or more commands/tasks failed verification")
            except BatchError as exc:
                audit_error = type(exc).__name__ + ": " + str(exc)
                result = {"content": [{"type": "text", "text": json.dumps({"ok": False, "results": exc.results}, ensure_ascii=False)}], "isError": True}
            except Exception as exc:
                # Tool errors belong in tool result (not broken JSON-RPC). Never dump locals or tracebacks.
                msg = collector.scrub_error(str(exc))
                audit_error = type(exc).__name__ + ": " + msg
                result = {"content": [{"type": "text", "text": json.dumps(collector.failure_result(exc, args.get("target")), ensure_ascii=False)}], "isError": True}
            collector.audit(name, args, not result["isError"], time.monotonic() - started, audit_error)
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
        config = load_config(args.config)
        config = load_inventory_csv(config, args.inventory_csv)
        collector = Collector(config)
        run_stdio(collector)
        return 0
    except Exception as exc:
        stderr("Collector startup failed: " + type(exc).__name__ + ": " + str(exc)[:250])
        return 1


if __name__ == "__main__":
    sys.exit(main())
