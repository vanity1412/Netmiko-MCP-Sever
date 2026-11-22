"""MCP JSON-RPC stdio server for the Collector."""
from __future__ import annotations

import concurrent.futures
import json
import sys
import threading
import time
from typing import Any

from result_status import normalize_result
from collector_backend import (Collector, MCP_PROTOCOL_VERSIONS, TOOLS, VERSION,
                               configure_stdio)


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
            except Exception as exc:
                # Match BatchError by name, not identity: the module may be loaded
                # under another name (tests, worker processes). Tool errors belong
                # in the tool result; never dump locals or tracebacks.
                if type(exc).__name__ == 'BatchError' and hasattr(exc, 'results'):
                    audit_error = type(exc).__name__ + ": " + str(exc)
                    payload = getattr(exc, 'summary', None) or normalize_result({"ok": False, "results": exc.results})
                else:
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
