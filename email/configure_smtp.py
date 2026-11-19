"""Configure SMTP credentials interactively; never sends an email."""
import argparse
import getpass
import json
import sys
import warnings

from send_report import public_settings
from smtp_credentials import read_password, write_password


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true', help='Check credential presence without displaying it')
    args = parser.parse_args()
    settings = public_settings()
    host, username = settings.get('host'), settings.get('username')
    if not host or not username:
        raise ValueError('Configure host and username in smtp-settings.json first')
    if args.check:
        present = bool(read_password(host, username))
        print(json.dumps({'credential_present': present, 'email_sent': False}))
        return 0 if present else 1
    if not sys.stdin.isatty():
        raise ValueError('Run in your local interactive terminal; do not pipe a password')
    print('Enter a NEW Google app password. Input is hidden; nothing is written to project files.')
    with warnings.catch_warnings():
        warnings.simplefilter('error', getpass.GetPassWarning)
        password = getpass.getpass('New app password: ').replace(' ', '')
        confirm = getpass.getpass('Confirm app password: ').replace(' ', '')
    if not password or password != confirm:
        raise ValueError('Empty password or confirmation mismatch')
    if any(ord(c) < 32 or ord(c) == 127 for c in password):
        print('Invalid hidden/control character detected. Type the new app password manually; nothing was saved.')
        return 1
    write_password(host, username, password)
    print(json.dumps({'credential_saved': True, 'email_sent': False}))
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(json.dumps({'status': 'error', 'error_type': type(exc).__name__, 'email_sent': False}))
        raise SystemExit(1)
