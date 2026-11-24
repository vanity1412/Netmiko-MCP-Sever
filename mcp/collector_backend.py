#!/usr/bin/env python3
"""Goose Network Collector: generic Netmiko SSH MCP (stdio / JSON-RPC).

Independent implementation inspired by ideas in ntunes/netmiko-mcp-server,
ktbyers/netmiko_mcp, and the documented Netmiko API. No upstream code copied.
Python 3.10+; runtime dependency: netmiko==4.7.0.
"""
from __future__ import annotations

import argparse
import concurrent.futures
import contextlib
import datetime as dt
import functools
import hashlib
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
from collections import deque
from typing import Any, Callable

# File-based embedders load this backend without installing a package.
_module_dir = str(Path(__file__).resolve().parent)
if _module_dir not in sys.path:
    sys.path.insert(0, _module_dir)

from result_status import normalize_result
from output_storage import SharedOutputStorage
from telemetry import (
    PhaseMetrics, WorkQueueMetrics, measured_phase, time_connection_method,
    connection_measurements, current_connection_timings
)
from policy import (
    CollectionError, _LINUX_BLOCKED_PROGRAMS, cli_pipeline, cli_replay_context,
    canonical_operational_command, command_prompt_pattern, execution_policy_error, is_operational_prompt,
    is_replay_safe, linux_operational_stage_allows, operational_policy_allows,
    prepare_noc_command, readonly_command, safe_command
)

# Re-exported modular components for 100% backwards compatibility
from config_utils import (
    VERSION, MCP_PROTOCOL_VERSIONS, JUNOS_READER_PATCH, MAX_INLINE, MAX_TASKS,
    MAX_COMMANDS, APP_HOME, SENSITIVE_KEYS, ENV_RE, KNOWN_KEYS, CREDENTIAL_FIELDS,
    stderr, configure_stdio, expand_env, load_config, load_inventory_csv,
    bounded_int, safe_target, safe_output_id, bounded_request
)
from host_keys import (
    _TOFU_LOCK, host_key_file_lock, persist_host_key, install_tofu
)
from diagnostics import (
    _PREPARATION_CONTEXT, ERROR_REASON_BY_CATEGORY, classify_error,
    preparation_request_context, preparation_error, junos_resync_error
)
from terminal_utils import (
    PAGER_RE, CONFIRM_RE, PERMISSION_DENIAL_RE, CLI_SYNTAX_RE,
    clean_terminal, last_prompt, platform_from_version, redact_text, redact_data,
    command_echo_line, ending_matches, pending_interaction, config_banner_open,
    output_container_open, XMLPrefixGuard, OutputBuffer, strip_pager_spans,
    dead_session
)
from junos_prep import (
    _JUNOS_ECHO_INCOMPLETE, _JUNOS_TRACE_LOCK, _JUNOS_TRACE_QUEUE, _JUNOS_TRACE_THREAD,
    _junos_trace_writer, _junos_trace_enqueue, _junos_trace_event, _install_junos_trace,
    preserve_channel_encoding, junos_input_line, junos_verified_write,
    install_tolerant_width, junos_cli_capabilities, junos_resync,
    junos_initial_prompt, junos_prepare_session, install_tolerant_preparation
)
from cli_reader import read_cli_output
from detection import detection_worker
from batch_utils import interaction_step, batch_summary, BatchError, TOOLS


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
            raise ValueError('execution_policy must be read_only or read_write')
        # operational is a legacy alias: one blacklist policy, named read_only.
        if self.execution_policy == 'operational':
            self.execution_policy = 'read_only'
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
        # read_only and operational share the same blacklist; the label only
        # marks the policy name in results and audit.
        if self.execution_policy == 'read_only' and any(
                not operational_policy_allows(command, driver) for command in commands):
            raise execution_policy_error('Command denied by blacklist for this driver', self.execution_policy)
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
        driver = getattr(self._request, 'resolved_driver', None)
        sent_command = canonical_operational_command(command, driver or '') if self.execution_policy == 'read_only' else command
        try:
            result = self._result(target, sent_command, output, elapsed, save_output,
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
        if sent_command != command:
            result['command'] = self.redact_output(command)
            if result['command_sent']:
                result['sent_command'] = self.redact_output(sent_command)
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
                # The cached login prompt goes stale after a mode change; ask the device.
                if hasattr(conn, 'find_prompt') and not hasattr(conn, 'collect_in_worker'):
                    live = last_prompt(conn.find_prompt() or '')
                    if not live:
                        raise execution_policy_error('Operational CLI prompt is not verified', self.execution_policy)
                    conn._network_prompt_text = live
                    conn._network_prompt_regex = r'(?m)^' + re.escape(live) + r'[ \t]*\r?$'
                if not is_operational_prompt(getattr(conn, '_network_prompt_text', '') or '', driver):
                    raise execution_policy_error('Operational CLI prompt is not verified', self.execution_policy)
            except CollectionError as exc:
                exc._network_keep_session = True
                raise
            command = canonical_operational_command(command, driver)
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
                textfsm_command = command
                if self.execution_policy == 'read_only':
                    textfsm_command = canonical_operational_command(command, result.get('driver') or '')
                try:
                    structured = structured_data_converter(raw_data=clean_terminal(out), command=textfsm_command,
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
        # With continue_on_error, a blacklisted command is reported as denied
        # and not sent; the other commands still run. Without it, the whole
        # batch is rejected before any SSH activity (fail-closed).
        denied = {}
        if continue_on_error and self.execution_policy == 'read_only':
            params = _resolved_scan_params or self._get_settings(target, device_type, profile)
            for index, cmd in enumerate(commands):
                try:
                    self.validate_execution_commands([cmd], params['device_type'])
                except CollectionError as exc:
                    denied[index] = exc.details
            allowed = [cmd for index, cmd in enumerate(commands) if index not in denied]
            if allowed:
                self._preflight(target, allowed, device_type, profile, resolved_params=_resolved_scan_params)
        else:
            self._preflight(target, commands, device_type, profile, resolved_params=_resolved_scan_params)
        timeout = bounded_int(read_timeout, getattr(self._request, 'cli_options', {}).get('read_timeout', self.read_timeout), 1, 600)
        results = []
        recovery = {}

        def denied_result(index):
            return normalize_result({**denied[index], 'target': target,
                'command': self.redact_output(commands[index]), 'command_index': index,
                'ok': False, 'command_sent': False, 'output_complete': False})

        if len(denied) == len(commands):
            return batch_summary(target, len(commands), [denied_result(i) for i in range(len(commands))],
                                 continue_on_error)

        def stop(index):
            for skipped_index in range(index + 1, len(commands)):
                results.append(normalize_result({'target': target,
                    'command': self.redact_output(commands[skipped_index]),
                    'command_index': skipped_index, 'ok': False, 'skipped': True,
                    'command_sent': False, 'output_complete': False, 'retryable': False,
                    'skipped_reason': 'batch_stopped', 'blocked_by_command_index': index}))
            raise BatchError(results, {**batch_summary(target, len(commands), results, continue_on_error), **recovery})

        if continue_on_error and denied and len(denied) == len(commands):
            # Nothing is left to send: report the denials without opening a session.
            results = [normalize_result({'target': target, 'command': self.redact_output(cmd),
                'command_index': index, 'ok': False, 'command_sent': False, 'output_complete': False,
                'retryable': False, 'error': 'ExecutionPolicyDenied', 'error_category': 'policy_denied',
                'error_reason': 'execution_policy_read_only', 'error_stage': 'validation',
                'message': 'Command denied by blacklist; not sent'}) for index, cmd in enumerate(commands)]
            return {**batch_summary(target, len(commands), results, continue_on_error)}
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
                if index in denied:
                    results.append(denied_result(index))
                    continue
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
        from mcp_rpc import run_stdio
        run_stdio(collector)
        return 0
    except Exception as exc:
        stderr("Collector startup failed: " + type(exc).__name__ + ": " + str(exc)[:250])
        return 1


if __name__ == "__main__":
    sys.exit(main())
