#!/usr/bin/env python3
"""Error classification, diagnostic mapping, and preparation request context."""
from __future__ import annotations

import contextlib
from pathlib import Path
import sys
import threading
from typing import Any

_module_dir = str(Path(__file__).resolve().parent)
if _module_dir not in sys.path:
    sys.path.insert(0, _module_dir)

from policy import CollectionError

_PREPARATION_CONTEXT = threading.local()

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


def classify_error(exc: Exception, stage: str = 'unknown') -> dict[str, Any]:
    stage = getattr(exc, '_network_error_stage', stage)
    if isinstance(exc, CollectionError):
        return dict(exc.details)
    chain, seen, current = [], set(), exc
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        chain.append(current)
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


def preparation_error(failure: dict[str, Any], output: str, command: str) -> CollectionError:
    """Keep setup evidence distinct from the caller's unsent business command."""
    error = CollectionError({**failure, 'error': failure.get('error', 'PreparationOutputVerificationError'),
                            'error_stage': 'preparation',
                            'output': output, 'preparation_command': command})
    if command.startswith('set cli ') or command == 'show cli':
        error._network_no_driver_refresh = True
    return error


def junos_resync_error(failure: dict[str, Any] | None, reset_failure: dict[str, Any],
                       output: str, command: str, reset_output: str, *, attempted=True) -> CollectionError:
    fatal_reset = reset_failure.get('error_category') in {'cancelled', 'deadline', 'storage_error'}
    error = preparation_error(reset_failure if fatal_reset else (failure or reset_failure), output, command)
    error.details['resync_output'] = reset_output
    error._network_junos_resync_failed = (
        attempted and reset_failure.get('error_reason') == 'junos_resync_failed'
        and error.details.get('error_category') in {'output_verification', 'read_timeout', 'connection_lost'})
    return error
