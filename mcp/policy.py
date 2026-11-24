"""Execution policy: command framing, blacklist decisions, prompt gating."""
from __future__ import annotations

import functools
import re
import shlex
from typing import Any


class CollectionError(Exception):
    """Bounded worker failures retain categories without copying library secrets."""
    def __init__(self, details):
        self.details = details
        super().__init__(details.get('error', 'CollectionError'))



def safe_command(cmd: Any) -> str:
    if not isinstance(cmd, str) or not cmd.strip() or len(cmd) > 8192:
        raise ValueError("command must be a non-empty string up to 8192 characters")
    if any(ord(char) < 32 or ord(char) == 127 for char in cmd):
        raise ValueError("Commands must be single-line and contain no control characters")
    return cmd


def cli_pipeline(command: str) -> list[str]:
    """Split unquoted, unescaped pipes while retaining the original CLI text."""
    parts, start, quote = [], 0, None
    escaped = False
    for index, char in enumerate(command):
        if escaped:
            escaped = False
        elif char == '\\' and quote != "'":
            escaped = True
        elif char in ('"', "'"):
            if quote is None:
                quote = char
            elif quote == char:
                quote = None
        elif char == '|' and quote is None:
            parts.append(command[start:index].strip())
            start = index + 1
    if quote:
        raise PermissionError("Unclosed CLI quote")
    if escaped:
        raise PermissionError("Incomplete CLI escape")
    parts.append(command[start:].strip())
    if any(not part for part in parts):
        raise PermissionError("Empty CLI pipeline")
    return parts


@functools.lru_cache(maxsize=4096)
def readonly_command(command: str, platform: str = '') -> str:
    """Legacy import name: validate framing only; never filter command content."""
    return safe_command(command)


def prepare_noc_command(command, platform):
    return safe_command(command)


def is_replay_safe(command):
    """Retry classification only. Never used to permit or reject execution."""
    if not isinstance(command, str) or re.search(r'[;&`><\n\r]', command):
        return False
    try:
        parts = cli_pipeline(command)
    except PermissionError:
        return False
    if any(not re.match(r'^(?:include|exclude|begin|section|match|except|find|count|last|no-more|display)\b', part, re.I) for part in parts[1:]):
        return False
    return bool(re.match(r'^(?:show|display)\s+', parts[0], re.I) or
                re.fullmatch(r'(?:uname(?: -[a-z]+)?|uptime|date|whoami|id|hostname|ip (?:-[a-z]+ )?(?:address|addr|link|route|neigh) show(?: .*)?|ss -[a-z]+)', parts[0], re.I))


_LINUX_BLOCKED_PROGRAMS = frozenset('''
    sudo su doas pkexec rm mv cp dd truncate tee chmod chown chgrp ln touch mkdir rmdir
    vi vim nano ed install shred mount umount wipefs mkswap swapon swapoff service
    reboot shutdown poweroff halt init telinit kill killall pkill killproc
    iptables ip6tables nft ufw tc apt apt-get yum dnf pip pip3 dpkg rpm wget curl
    bash sh dash ash zsh ksh fish busybox perl ruby node php lua nc ncat netcat
    env command exec eval source . xargs awk gawk mawk timeout nohup nice ionice
    setsid screen tmux ssh telnet sftp scp ftp tftp rsync
'''.split())
_CLI_SEPARATORS = re.compile(r'[;&`]')
_JUNOS_REGEX_STAGE = re.compile(
    r'''(?:mat(?:ch?)?|exc(?:e(?:pt?)?)?|find?)\s+(?:(?P<quoted>"(?:[^"\\]|\\.)*")|[^\s"']+)''', re.I)


def canonical_operational_command(command, driver):
    """Use the full Cisco read verb so an abbreviated alias is never sent."""
    if driver.startswith('cisco_') or driver == 'autodetect':
        return re.sub(r'^(\s*)sho?(?=\s+\S)', r'\1show', command, count=1, flags=re.I)
    return command


def linux_operational_stage_allows(stage):
    words = shlex.split(stage)
    if not words or not re.fullmatch(r'[A-Za-z0-9_./+-]+', words[0]):
        return False
    program = words[0].rsplit('/', 1)[-1]
    if not program or program in _LINUX_BLOCKED_PROGRAMS or re.fullmatch(r'(?:python|pip|mkfs)[0-9.\w-]*', program):
        return False
    args = words[1:]
    if program == 'ss':
        return not any(arg == '--kill' or re.match(r'^-[a-zA-Z]*K', arg) for arg in args)
    if program in {'ping', 'ping6'}:
        return not any(re.match(r'^-[a-zA-Z]*[fl]', arg) for arg in args)
    if program == 'systemctl':
        return not set(args) & {'start', 'stop', 'restart', 'reload', 'enable', 'disable', 'mask',
                                'unmask', 'reboot', 'poweroff', 'halt', 'isolate', 'kill', 'set-property',
                                'edit', 'daemon-reload', 'link', 'preset', 'revert', 'try-restart',
                                'reload-or-restart', 'try-reload-or-restart'}
    if program in {'ip', 'nmcli'}:
        positionals = [arg for arg in args if not arg.startswith('-')]
        changes = {'set', 'add', 'delete', 'replace', 'change', 'append', 'flush', 'up', 'down',
                   'modify', 'connect', 'disconnect', 'exec', 'reload', 'load', 'edit', 'import',
                   'restore', 'attach', 'on', 'off', 'toggle'}
        return not any(arg == '-b' or arg.startswith('-ba') for arg in args) and not any(
            word and change.startswith(word) for word in positionals[1:] for change in changes)
    if program == 'ifconfig':
        return len(args) <= 1
    if program in {'sed', 'ethtool', 'find', 'crontab'}:
        for item in args:
            if program == 'sed' and (item.startswith(('--in-place', '--file')) or re.match(r'^-[a-zA-Z]*[if]', item)):
                return False
            if program == 'sed' and not item.startswith('-') and re.search(r'(?:^|[/;])\s*[ewW]\b', item):
                return False
            if program == 'ethtool' and (item.startswith(('--set', '--change', '--offload', '--features'))
                                         or re.match(r'^-[sKGCLAEXWNPH]', item)):
                return False
            if program == 'find' and item in {'-exec', '-execdir', '-ok', '-okdir', '-delete', '-fprint', '-fprintf', '-fls'}:
                return False
            if program == 'crontab' and item not in {'-l'}:
                return False
        if program == 'crontab' and args != ['-l']:
            return False
    return True


def operational_policy_allows(command, driver):
    """Screen known state-changing commands in the resolved operational CLI."""
    driver_rules = {
        'junos': {'edit', 'load', 'rollback', 'set', 'activate', 'deactivate',
                  'rename', 'replace', 'insert', 'annotate', 'wildcard', 'request system',
                  'request chassis', 'file copy', 'file delete', 'file rename', 'file archive',
                  'file make-directory', 'top', 'copy', 'protect', 'unprotect', 'monitor start',
                  'request routing-engine login', 'request support information', 'request message'},
        'cisco': {'conf', 'write', 'copy', 'replace', 'archive', 'config-register',
                  'interface', 'router', 'ip route', 'no', 'redundancy force-switchover',
                  'squeeze', 'rmdir', 'mkdir', 'rename', 'install', 'send',
                  'terminal monitor', 'terminal shell', 'tclsh', 'guestshell',
                  'event manager run', 'monitor capture'},
        'huawei': {'system-view', 'rollback', 'startup', 'copy', 'move', 'rename',
                   'configuration replace', 'undo', 'upgrade', 'interface', 'bgp', 'ospf',
                   'ip route-static', 'acl', 'mkdir', 'rmdir', 'undelete', 'ftp', 'tftp', 'sftp', 'scp',
                   'terminal debugging', 'display diagnostic-information'},
    }
    family = ('junos' if driver == 'juniper_junos' else 'cisco' if driver.startswith('cisco_')
              else 'huawei' if driver.startswith('huawei') else None)
    if family is None and driver not in {'autodetect', 'generic_termserver', 'linux'}:
        return False
    if not command.isprintable():
        return False
    try:
        head, *filters = cli_pipeline(canonical_operational_command(command, driver))
    except PermissionError:
        return False
    if driver == 'linux':
        # Redirections write files; they are not blacklisted by program name.
        return not re.search(r'[(){}!<>;&`]', command) and all(
            linux_operational_stage_allows(stage) for stage in (head, *filters))
    if '|' in head or _CLI_SEPARATORS.search(head):
        return False
    for stage in filters:
        regex = _JUNOS_REGEX_STAGE.fullmatch(stage) if driver in {'juniper_junos', 'autodetect'} else None
        if '|' in stage and not regex:
            return False
        if _CLI_SEPARATORS.search(stage) and (not regex or not regex['quoted']):
            return False

    def matches_rule(text, rule):
        words = text.casefold().replace('"', '').replace("'", '').split()
        blocked = rule.split()
        return len(words) >= len(blocked) and all(
            full.startswith(word) for word, full in zip(words, blocked))

    common = {'configure', 'configuration', 'commit', 'save', 'enable', 'shell', 'start',
              'do', 'run', 'op', 'ssh', 'telnet', 'rlogin', 'python', 'reboot', 'reload',
              'restart', 'reset', 'halt', 'power-off', 'zeroize', 'delete', 'erase', 'format',
              'clear', 'debug', 'debugging', 'monitor traffic', 'test'}
    rules = common | (driver_rules[family] if family else set().union(*driver_rules.values()))
    allowed_head = not any(matches_rule(head, rule) for rule in rules)
    blocked_filters = {'save', 'redirect', 'append', 'tee', 'file', 'shell', 'execute', 'nohangup'}
    return allowed_head and not any(matches_rule(stage, rule) for stage in filters for rule in blocked_filters)


def execution_policy_error(message, policy='read_only'):
    return CollectionError({'error': 'ExecutionPolicyDenied', 'error_category': 'policy_denied',
                            'error_reason': f'execution_policy_{policy}', 'error_stage': 'validation',
                            'command_sent': False, 'retryable': False, 'message': message})


def command_prompt_pattern(conn, command, exact):
    """Accept mode transitions only within this device's prompt family."""
    old = getattr(conn, '_network_prompt_text', '')
    root = getattr(conn, '_network_prompt_root', old)
    if not root or is_replay_safe(command):
        return exact
    if root.startswith(('<', '[')) and root.endswith(('>', ']')):
        host = root[1:-1].lstrip('~*')
        return r'(?m)^(?:<' + re.escape(host) + r'>|\[[~*]?' + re.escape(host) + r'(?:-[^\]\r\n]+)?\])[ \t]*\r?$'
    if root[-1:] in '#>$%':
        stem = re.sub(r'\([^()]*\)$', '', root[:-1])
        pattern = r'(?m)^' + re.escape(stem) + r'(?:\([^()\r\n]*\))?[#>$%][ \t]*\r?$'
        rename = re.fullmatch(r'hostname\s+([A-Za-z0-9_.-]+)', command.strip(), re.I)
        if rename:
            pattern = r'(?m)^(?:' + re.escape(stem) + '|' + re.escape(rename[1]) + r')(?:\([^()\r\n]*\))?[#>][ \t]*\r?$'
        return pattern
    return exact


def cli_replay_context(conn, driver):
    """Return a verified, unchanged login context for an automatic replay."""
    prompt = getattr(conn, '_network_prompt_text', '')
    if (not prompt or prompt != getattr(conn, '_network_login_prompt', None)
            or getattr(conn, '_network_cli_context_changed', False)):
        return None
    return (driver, prompt) if is_operational_prompt(prompt, driver) else None


def is_operational_prompt(prompt, driver):
    if driver == 'juniper_junos':
        return prompt.endswith('>')
    if driver.startswith('huawei'):
        return prompt.startswith('<') and prompt.endswith('>')
    if driver.startswith('cisco_'):
        return prompt.endswith(('#', '>')) and '(' not in prompt
    return driver == 'linux' and prompt.endswith(('#', '$'))


# Used only on recognized CLI diagnostic lines, never as a command filter.
