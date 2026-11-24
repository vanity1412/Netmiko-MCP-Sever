#!/usr/bin/env python3
"""Configuration loading, environment expansion, and parameter validation utilities."""
from __future__ import annotations

import csv
import functools
import json
import os
from pathlib import Path
import re
import sys
from typing import Any

_module_dir = str(Path(__file__).resolve().parent)
if _module_dir not in sys.path:
    sys.path.insert(0, _module_dir)

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
CREDENTIAL_FIELDS = {'username', 'password', 'secret', 'use_keys', 'key_file', 'allow_agent', 'passphrase'}


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
