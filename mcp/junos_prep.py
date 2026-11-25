#!/usr/bin/env python3
"""Juniper Junos preparation, CLI capability discovery, resynchronization, and input echo verification."""
from __future__ import annotations

import concurrent.futures
import contextlib
import functools
import hashlib
import json
import os
from pathlib import Path
import queue
import re
import sys
import threading
import time
from typing import Any
import uuid

_module_dir = str(Path(__file__).resolve().parent)
if _module_dir not in sys.path:
    sys.path.insert(0, _module_dir)

def read_cli_output(*args, **kwargs):
    from cli_reader import read_cli_output as _read
    return _read(*args, **kwargs)

from config_utils import JUNOS_READER_PATCH
from diagnostics import _PREPARATION_CONTEXT, ERROR_REASON_BY_CATEGORY, classify_error, preparation_error, junos_resync_error
from terminal_utils import (
    clean_terminal, last_prompt, ending_matches, pending_interaction,
    dead_session, OutputBuffer, PERMISSION_DENIAL_RE, CLI_SYNTAX_RE
)

_JUNOS_ECHO_INCOMPLETE = object()
_JUNOS_TRACE_LOCK = threading.Lock()
_JUNOS_TRACE_QUEUE = None
_JUNOS_TRACE_THREAD = None


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
                _JUNOS_TRACE_THREAD = threading.Thread(
                    target=_junos_trace_writer,
                    args=(_JUNOS_TRACE_QUEUE,),
                    name='junos-diagnostic-trace',
                    daemon=True
                )
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
        record = {
            'trace': 'junos_channel', 'patch': JUNOS_READER_PATCH,
            'session_id': state['session_id'], 'event': state['events'],
            'command_index': state.get('command_index', 0),
            'phase': getattr(conn, '_network_junos_trace_phase', 'preparation'),
            'monotonic': round(time.monotonic(), 6), 'direction': direction,
            'length': len(data), 'data_repr': repr(data[:size]),
            'truncated': size < len(data),
            'budget_exhausted': state['events'] >= 256 or state['bytes'] >= 65536,
            'dropped_before': state['dropped']
        }
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
        conn._network_junos_trace = {
            'session_id': uuid.uuid4().hex[:12],
            'events': 0, 'bytes': 0, 'dropped': 0, 'command_index': 0
        }

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


def junos_input_line(raw: str) -> str | None | object:
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


def junos_verified_write(conn, command: str, deadline: float, checkpoint=None, on_data=None):
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
        from cli_reader import read_cli_output
        output, failure = read_cli_output(conn, command, 5, r'(?m)^' + re.escape(prompt) + r'[ \t]*\r?$',
                                          observe_prompt=False)
        if failure:
            raise preparation_error(failure, output, command)
        if not ending_matches(r'(?m)^' + re.escape(prompt) + r'[ \t]*\r?$', output):
            raise preparation_error({'error': 'PreparationPromptError', 'error_category': 'output_verification',
                                     'error_reason': 'terminal_width_prompt_not_verified',
                                     'retryable': False}, output, command)
        return output

    set_width._goose_tolerant_width = True
    BaseConnection.set_terminal_width = set_width


def junos_cli_capabilities(output: str, prompt: str) -> dict[str, Any]:
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


def junos_resync(conn, prompt: str, timeout: float = 5, checkpoint=None):
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
        # Budget echo verification separately from the existing setup reply
        # window, while keeping the combined wait inside the request budget.
        verify_echo = conn._network_junos_verify_echo
        limit = 10 if verify_echo else 5
        options = {'reply_timeout': 5} if verify_echo and command != 'show cli' else {}
        if checkpoint is None:
            return read_cli_output(conn, command, limit, pattern, **options)
        output = ''
        try:
            output, failure = read_cli_output(conn, command, remaining(limit), pattern, checkpoint=checkpoint, **options)
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
    conn._network_junos_verify_echo = True
    skip_cli_setup = os.environ.get('NETMIKO_JUNOS_SKIP_CLI_SETUP', '').strip().lower() in {
        '1', 'true', 'yes', 'on'}
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
            if skip_cli_setup:
                conn._network_junos_preparation.append({'command': command, 'skipped': True,
                    'command_sent': False, 'reason': 'skipped_by_policy'})
                continue
            caps = conn._network_junos_capabilities
            if adaptive:
                known = field in caps and caps[field] == desired
                conn._network_junos_preparation.append({'command': command, 'skipped': True,
                    'command_sent': False, 'reason': 'already_verified' if known else
                    'using_echo_guard' if field == 'complete_on_space' else 'using_reader_fallback'})
                continue
            # With autocomplete still unknown, check the typed input before
            # Enter. Once disabling autocomplete is acknowledged, use one write.
            reply, failure = prep_read(command, pattern)
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
            if not conn._network_command_sent:
                record['command_sent'] = False
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
