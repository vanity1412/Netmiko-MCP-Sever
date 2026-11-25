#!/usr/bin/env python3
"""Terminal output cleaning, prompt detection, redaction, and buffer management."""
from __future__ import annotations

import contextlib
import functools
import json
from pathlib import Path
import re
import sys
import tempfile
from typing import Any

_module_dir = str(Path(__file__).resolve().parent)
if _module_dir not in sys.path:
    sys.path.insert(0, _module_dir)

from config_utils import SENSITIVE_KEYS
from policy import cli_pipeline

PAGER_RE = re.compile(
    r'(?i)(?:Press any key to continue \(Q to quit\)|--More-- or \(q\)uit|'
    r'-- More --, next page: Space, next line: Enter, quit: Control-C|'
    r'<--- More --->|--- MORE ---|---- More ----|---\(more[^\r\n)]*\)---|'
    r'--\s*More\s*--(?:[ \t]*\(\d+%\))?)'
)
CONFIRM_RE = re.compile(r'(?i)(?:\[(?:yes/no|y/n|confirm)\]|\((?:yes/no|y/n)\))')
PERMISSION_DENIAL_RE = re.compile(
    r'\b(?:permission denied|access[ -]denied|command authorization failed|'
    r'authori[sz]ation (?:failed|denied)|not authori[sz]ed|operation not permitted|'
    r'insufficient (?:user )?(?:privileges?|permissions?|access)|not enough privileges|'
    r'(?:do|does) not have (?:the )?(?:required )?(?:permissions?|privileges?|access)|'
    r'no permission)\b', re.I
)
CLI_SYNTAX_RE = re.compile(
    r'\b(?:invalid (?:input|command|interface)|unknown command|ambiguous command|'
    r'incomplete command|unrecognized command|syntax error|command not found)\b', re.I
)


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
    # Junos user@host>, IOS/XR/NXOS, VRP <host>/[host], simple shell prompts,
    # and Vertiv ACS8000 console prompt '--:- / cli->'.
    network = bool(re.fullmatch(r"[^\s]{1,220}[>#%$\]]", line)) or line == '--:- / cli->'
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


def command_echo_line(command: str, output: str) -> int | None:
    normalized = ' '.join(command.split())
    for index, line in enumerate(output.splitlines()[:5]):
        line = ' '.join(line.split())
        if line == normalized or re.fullmatch(r'\S+[>#%$\]]\s*' + re.escape(normalized), line):
            return index
    return None


def ending_matches(pattern: str, text: str) -> bool:
    ending = text.rstrip()
    match = None
    for match in re.finditer(pattern, ending):
        pass
    return bool(match and match.end() == len(ending))


def pending_interaction(text: str) -> bool:
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


def config_banner_open(command: str, text: str) -> bool:
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


@functools.lru_cache(maxsize=256)
def _output_style(command: str) -> str | None:
    try:
        stages = cli_pipeline(command)
    except PermissionError:
        return None
    for stage in stages[1:]:
        match = re.match(r'(?:display\s+)?(json|xml)\b', stage, re.I)
        if match:
            return match[1].lower()
    return None


def output_container_open(command: str, text: str) -> bool:
    if config_banner_open(command, text):
        return True
    style = _output_style(command)
    if not style:
        return False
    lines = clean_terminal(text).splitlines()
    if lines and last_prompt(lines[-1]):
        lines = lines[:-1]
    body = '\n'.join(lines)
    if style == 'json':
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
    def __init__(self, command: str):
        self.safe = _output_style(command) == 'xml' and not bool(
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

    def feed(self, data: str):
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

    def definitely_open(self) -> bool:
        return bool(self.safe and self.parser is not None and not self.complete
                    and (not self.pending.strip() or last_prompt(self.pending)))


class OutputBuffer:
    def __init__(self):
        self.file = tempfile.SpooledTemporaryFile(max_size=1024*1024, mode='w+t', encoding='utf-8', newline='')

    def append(self, data: str):
        try:
            self.file.write(data)
        except OSError as exc:
            exc._network_error_stage = 'persistence'
            raise

    def value(self) -> str:
        try:
            self.file.seek(0)
            value = self.file.read()
            self.file.seek(0, 2)
            return value
        except OSError as exc:
            exc._network_error_stage = 'persistence'
            raise

    def close(self):
        with contextlib.suppress(OSError):
            self.file.close()


def strip_pager_spans(raw: str, spans: list[tuple[int, int]]) -> str:
    parts, previous = [], 0
    for start, end in sorted(spans):
        parts.extend((raw[previous:start], ' ' * (end - start)))
        previous = end
    parts.append(raw[previous:])
    return ''.join(parts)


def dead_session(conn: Any) -> bool:
    if conn is None:
        return True
    proc = getattr(conn, '_process', None)
    if proc is not None and proc.poll() is not None:
        return True
    channel = getattr(conn, 'remote_conn', None)
    transport = getattr(channel, 'transport', None)
    return bool(getattr(conn, 'alive', True) is False or getattr(conn, 'closed', False) is True or
                (channel is not None and (getattr(channel, 'closed', False) or getattr(channel, 'eof_received', False))) or
                (transport is not None and not transport.is_active()))
