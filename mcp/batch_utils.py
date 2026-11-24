#!/usr/bin/env python3
"""Batch execution summaries, error types, and interaction step validation."""
from __future__ import annotations

from pathlib import Path
import sys
from typing import Any

_module_dir = str(Path(__file__).resolve().parent)
if _module_dir not in sys.path:
    sys.path.insert(0, _module_dir)

from policy import safe_command
from result_status import normalize_result


def interaction_step(cmd: Any) -> str:
    if cmd in ("\n", "\r", ""):  # Enter/confirmation without a literal word
        return cmd or "\n"
    return safe_command(cmd)


def batch_summary(target: str, command_count: int, results: list[dict[str, Any]], continue_on_error: bool) -> dict[str, Any]:
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
    "ssh_execute_many": {"description": 'Execute commands (string array) in order on one session. Stops on failure; unsent suffix is SKIPPED. For independent commands, continue_on_error skips commands denied at preflight and continues after complete synchronized CLI errors. Inspect each result.', "schema": {"target": "string", "commands": "array", "device_type": "string", "profile": "string", "read_timeout": "integer", "save_output": "boolean", "use_timing": "boolean", "expect_string": "string", "continue_on_error": "boolean"}, "required": ["target", "commands"], "method": "execute_many"},
    "ssh_interact": {"description": 'Requires read_write. Send steps, including authorized configuration/replies, on the same target/profile/mode. Empty string/newline sends Enter; no implicit reply. Inspect each step and current awaiting_input.', "schema": {"target": "string", "steps": "array", "device_type": "string", "profile": "string", "read_timeout": "integer", "save_output": "boolean"}, "required": ["target", "steps"], "method": "interact"},
    "ssh_parallel": {"description": 'Run 1-100 independent tasks; each needs target and exactly one of command or commands. Output/result order retained per task. Inspect each result; task count is not SSH concurrency.', "schema": {"tasks": "array"}, "required": ["tasks"], "method": "parallel"},
    "ssh_read_output": {"description": 'Read saved text by output_id, zero-based line offset and limit. Follow next_offset while more=true; use byte reader if oversized_line prevents progress. A slice is not full configuration.', "schema": {"output_id": "string", "offset": "integer", "limit": "integer"}, "required": ["output_id"], "method": "read_output"},
    "ssh_read_output_bytes": {"description": 'Read saved output as best-effort UTF-8 text with byte offsets, including long lines. Start at zero, follow next_byte_offset (may extend length to finish UTF-8). For byte-exact export, copy/hash the source file.', "schema": {"output_id": "string", "byte_offset": "integer", "length": "integer"}, "required": ["output_id"], "method": "read_output_bytes"},
    "ssh_search_output": {"description": 'Search the entire saved file by query (literal/regex). total_matches counts lines; limited excerpts use one-based lines and may omit text even if truncated=false. Zero matches are not network absence; check collection scope/completeness/inheritance. Errors are not zero.', "schema": {"output_id": "string", "query": "string", "regex": "boolean", "ignore_case": "boolean", "max_matches": "integer", "context_lines": "integer"}, "required": ["output_id", "query"], "method": "search_output"},
    "ssh_inventory": {"description": 'Search configured alias/host IP by query and optional device_type. Returns profile/port and resolution warnings, not live topology/auth proof. Default 100 rows; limit=0 returns all matches; summary_only counts. Do not guess profiles.', "schema": {"query": "string", "device_type": "string", "offset": "integer", "limit": "integer", "summary_only": "boolean"}, "required": [], "method": "inventory"},
    "ssh_status": {"description": 'Inspect execution_policy, execution_policy_configured, and collector/session state. parallel_queue is process-local; running may await session/SSH slots. Metadata is not network health. No passwords returned.', "schema": {}, "required": [], "method": "status"},
    "ssh_close": {"description": 'Close all sessions for the resolved host, across profiles/ports; missing/empty target closes the entire pool. Use only when all affected sessions are in scope, not after every command.', "schema": {"target": "string"}, "required": [], "method": "close"},
}
