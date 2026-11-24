#!/usr/bin/env python3
"""CLI reading engine: stream reads from Netmiko SSH channels with paging, prompt detection, and error recovery."""
from __future__ import annotations

import hashlib
from pathlib import Path
import re
import sys
import time

_module_dir = str(Path(__file__).resolve().parent)
if _module_dir not in sys.path:
    sys.path.insert(0, _module_dir)

from diagnostics import classify_error, ERROR_REASON_BY_CATEGORY
from policy import CollectionError, command_prompt_pattern
from terminal_utils import (
    OutputBuffer, XMLPrefixGuard, output_container_open, strip_pager_spans,
    clean_terminal, ending_matches, pending_interaction, dead_session,
    last_prompt, PAGER_RE
)
from junos_prep import preserve_channel_encoding, junos_verified_write


_DEVICE_PROMPT_OBSERVATION_SECONDS = 1.1


def read_cli_output(conn, command, timeout, pattern, checkpoint=None, quiet=.03, on_data=None,
                    *, reply_timeout=None, observe_prompt=True):
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

    # A text payload can contain the exact prompt. Observe a provisional
    # business-command prompt through the reported one-second gap.
    log_output = bool(re.match(r'^\s*(?:show\s+log(?:ging)?|display\s+logbuffer)\b', command, re.I))
    quiet = max(quiet, .3)
    candidate = None
    candidate_since = 0.0
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
    observe_device_prompt = (observe_prompt and bool(command.strip())
                             and not getattr(conn, '_network_junos_preparing', False))
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
        if reply_timeout is not None:
            deadline = min(deadline, time.monotonic() + reply_timeout)
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
                    candidate_since = last_data
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
                  and not ((requires_payload or width_preparation) and candidate_preamble_only)
                  and (not observe_device_prompt or not ending_matches(device_pattern, cleaned)
                       or time.monotonic() - candidate_since >= _DEVICE_PROMPT_OBSERVATION_SECONDS)):
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
