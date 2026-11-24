#!/usr/bin/env python3
"""Isolated autodetect probe worker for platform version detection."""
from __future__ import annotations

import contextlib
from pathlib import Path
import re
import sys
from typing import Any

_module_dir = str(Path(__file__).resolve().parent)
if _module_dir not in sys.path:
    sys.path.insert(0, _module_dir)

from config_utils import bounded_int
from host_keys import install_tofu
from telemetry import connection_measurements
from terminal_utils import (
    last_prompt, command_echo_line, ending_matches, pending_interaction, platform_from_version
)
from cli_reader import read_cli_output
from diagnostics import classify_error
from policy import CollectionError


def detection_worker(params: dict[str, Any], connection_sink=None) -> dict[str, Any]:
    """Small read-only probe set; parent process enforces a hard wall deadline."""
    from netmiko import ConnectHandler
    params = dict(params)
    probe_timeout = bounded_int(params.pop('_probe_read_timeout', 4), 4, 1, 60)
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
            output, failure = read_cli_output(conn, command, probe_timeout, pattern, observe_prompt=False)
            if failure:
                return {**failure, 'error_stage': 'autodetect'}
            echo_line = command_echo_line(command, output)
            if not ending_matches(pattern, output) or pending_interaction(output):
                return {'error': 'DetectionOutputVerificationError', 'error_category': 'output_verification',
                        'error_stage': 'autodetect', 'retryable': False,
                        'message': 'Probe ending prompt could not be verified'}
            # Initial login banners are not the response to our probe command.
            platform = platform_from_version('\n'.join(output.splitlines()[(echo_line + 1 if echo_line is not None else 0):-1]))
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
