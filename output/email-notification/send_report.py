"""Full-body Markdown report mailer. Dry-run is offline; no attachments/CC.

SMTP settings come from environment/non-secret JSON; passwords from environment
or Windows Credential Manager only. A durable outbox prevents concurrent
duplicates and blocks ambiguous deliveries instead of blindly retrying DATA.
"""
from __future__ import annotations
import argparse
import contextlib
import datetime as dt
from email import policy
from email.message import EmailMessage
from email.utils import formatdate, parseaddr
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import smtplib
import sqlite3
import ssl
import time

ROOT = Path(__file__).resolve().parents[2]
RECIPIENT = "[redacted-email]"
SETTINGS_PATH = Path(__file__).with_name("smtp-settings.json")


def html_report(body: str, report_id: str) -> str:
    spec = importlib.util.spec_from_file_location("opencode_report_html", Path(__file__).with_name("report_html.py"))
    renderer = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(renderer)
    return renderer.render_report(body, report_id)


def credential_store():
    spec = importlib.util.spec_from_file_location("opencode_smtp_credentials", Path(__file__).with_name("smtp_credentials.py"))
    store = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(store)
    return store


def public_settings() -> dict:
    settings = json.loads(SETTINGS_PATH.read_text(encoding="utf-8-sig")) if SETTINGS_PATH.is_file() else {}
    if not isinstance(settings, dict) or set(settings) - {"host", "port", "security", "sender", "username", "require_auth"}:
        raise ValueError("SMTP settings may contain only approved non-secret fields")
    return settings


def sanitized_report(path: Path) -> str:
    spec = importlib.util.spec_from_file_location("report_redaction", ROOT / "mcp/collector_backend.py")
    backend = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(backend)
    secrets = [value for name, value in os.environ.items()
               if any(word in name.upper() for word in ("PASSWORD", "SECRET", "TOKEN", "API_KEY")) and len(value) >= 3]
    return backend.redact_text(path.read_text(encoding="utf-8-sig"), secrets)


def build_message(path: Path, sender: str = "opencode@localhost") -> tuple[EmailMessage, str]:
    body = sanitized_report(path)
    subject = "[OpenCode Network] " + path.parent.name
    key = hashlib.sha256(json.dumps([RECIPIENT, subject, body], ensure_ascii=False).encode("utf-8")).hexdigest()
    message = EmailMessage(policy=policy.SMTP)
    message["From"] = sender
    message["To"] = RECIPIENT
    message["Subject"] = subject
    message["Date"] = formatdate(localtime=False)
    message["Message-ID"] = "<" + key + "@opencode.local>"
    message.set_content(body, charset="utf-8")
    message.add_alternative(html_report(body, path.parent.name), subtype="html", charset="utf-8")
    return message, key


def connect_state(path: Path) -> sqlite3.Connection:
    path.parent.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(path, timeout=10, isolation_level=None)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA journal_mode=WAL")
    db.execute("PRAGMA synchronous=FULL")
    db.execute("""CREATE TABLE IF NOT EXISTS delivery (
        delivery_key TEXT PRIMARY KEY, status TEXT NOT NULL, attempts INTEGER NOT NULL,
        updated REAL NOT NULL, next_retry REAL NOT NULL, error_type TEXT, smtp_code INTEGER)""")
    return db


def reserve(db: sqlite3.Connection, key: str, now: float, max_attempts: int) -> dict:
    db.execute("BEGIN IMMEDIATE")
    try:
        row = db.execute("SELECT * FROM delivery WHERE delivery_key=?", (key,)).fetchone()
        if row:
            state = dict(row)
            if state["status"] in {"accepted", "unknown", "sending", "permanent_failure", "exhausted"}:
                db.execute("COMMIT")
                return {"reserved": False, **state}
            if state["next_retry"] > now:
                db.execute("COMMIT")
                return {"reserved": False, **state}
            if state["attempts"] >= max_attempts:
                db.execute("UPDATE delivery SET status='exhausted',updated=? WHERE delivery_key=?", (now, key))
                db.execute("COMMIT")
                return {"reserved": False, "status": "exhausted", "attempts": state["attempts"]}
            attempt = state["attempts"] + 1
            db.execute("UPDATE delivery SET status='sending',attempts=?,updated=?,next_retry=0 WHERE delivery_key=?", (attempt, now, key))
        else:
            attempt = 1
            db.execute("INSERT INTO delivery VALUES (?,?,?,?,?,?,?)", (key, "sending", attempt, now, 0, None, None))
        db.execute("COMMIT")
        return {"reserved": True, "status": "sending", "attempts": attempt}
    except Exception:
        db.execute("ROLLBACK")
        raise


def update_state(db: sqlite3.Connection, key: str, status: str, now: float,
                 next_retry: float = 0, error: str | None = None, code: int | None = None) -> None:
    db.execute("UPDATE delivery SET status=?,updated=?,next_retry=?,error_type=?,smtp_code=? WHERE delivery_key=?",
               (status, now, next_retry, error, code, key))


def smtp_delivery(message: EmailMessage, settings: dict, factory=None) -> dict:
    smtp = None
    during_data = False
    try:
        security = settings["security"]
        context = ssl.create_default_context()
        creator = factory or (smtplib.SMTP_SSL if security == "ssl" else smtplib.SMTP)
        kwargs = {"host": settings["host"], "port": settings["port"], "timeout": settings.get("timeout", 20)}
        if security == "ssl":
            kwargs["context"] = context
        smtp = creator(**kwargs)
        smtp.ehlo()
        if security == "starttls":
            smtp.starttls(context=context)
            smtp.ehlo()
        elif security != "ssl":
            raise ValueError("Only starttls or ssl transport is allowed")
        if settings.get("username"):
            smtp.login(settings["username"], settings["password"])
        for code, response in (smtp.mail(parseaddr(str(message["From"]))[1]),):
            if not 200 <= code < 300:
                raise smtplib.SMTPSenderRefused(code, response, "[sender]")
        code, response = smtp.rcpt(RECIPIENT)
        if not 200 <= code < 300:
            raise smtplib.SMTPResponseException(code, response)
        during_data = True
        code, response = smtp.data(message.as_bytes())
        if not 200 <= code < 300:
            raise smtplib.SMTPDataError(code, response)
        return {"status": "accepted", "smtp_code": code}
    except smtplib.SMTPResponseException as exc:
        code = int(exc.smtp_code)
        permanent = isinstance(exc, smtplib.SMTPAuthenticationError) or not 400 <= code < 500
        return {"status": "permanent_failure" if permanent else "retryable", "smtp_code": code, "error_type": type(exc).__name__}
    except (ssl.SSLError, ValueError, smtplib.SMTPNotSupportedError) as exc:
        return {"status": "permanent_failure", "error_type": type(exc).__name__}
    except (OSError, smtplib.SMTPException) as exc:
        return {"status": "unknown" if during_data else "retryable", "error_type": type(exc).__name__}
    finally:
        if smtp is not None:
            # QUIT failure must not undo an accepted DATA or trigger a duplicate.
            with contextlib.suppress(Exception):
                smtp.close()


def deliver(message: EmailMessage, key: str, state_path: Path, settings: dict,
            max_attempts: int = 3, backoff: float = 5, factory=None, clock=time.time, sleep=time.sleep) -> dict:
    db = connect_state(state_path)
    try:
        while True:
            state = reserve(db, key, clock(), max_attempts)
            if not state["reserved"]:
                return {"delivery_key": key, "status": state["status"], "attempts": state["attempts"],
                        "duplicate_suppressed": state["status"] == "accepted", "sent_this_call": False}
            outcome = smtp_delivery(message, settings, factory)
            status = outcome["status"]
            if status == "retryable" and state["attempts"] >= max_attempts:
                status = "exhausted"
            delay = min(backoff * 2 ** (state["attempts"] - 1), 300) if status == "retryable" else 0
            try:
                update_state(db, key, status, clock(), clock()+delay if delay else 0,
                             outcome.get("error_type"), outcome.get("smtp_code"))
            except sqlite3.Error:
                # Reservation remains 'sending', blocking duplicates after a crash/disk error.
                return {"delivery_key": key, "status": "unknown", "smtp_accepted": outcome["status"] == "accepted",
                        "state_write_failed": True, "attempts": state["attempts"], "sent_this_call": None}
            if status != "retryable":
                return {"delivery_key": key, **outcome, "status": status, "attempts": state["attempts"],
                        "sent_this_call": status == "accepted"}
            sleep(delay)
    finally:
        db.close()


def settings_from_env() -> dict:
    defaults = public_settings()
    host = os.environ.get("SMTP_HOST", defaults.get("host", ""))
    # Never carry an identity/security policy over to a different SMTP endpoint.
    if host.casefold() != str(defaults.get("host", "")).casefold():
        defaults = {}
    sender = os.environ.get("SMTP_FROM", defaults.get("sender", ""))
    security = os.environ.get("SMTP_SECURITY", defaults.get("security", "starttls"))
    username = os.environ.get("SMTP_USERNAME", defaults.get("username", ""))
    password = os.environ.get("SMTP_PASSWORD", "")
    if not host or not sender or parseaddr(sender)[1] != sender or "\n" in sender or "\r" in sender or "@" not in sender:
        raise ValueError("SMTP_HOST and a valid SMTP_FROM are required; use --dry-run for offline preview")
    if username and not password and os.name == "nt":
        password = credential_store().read_password(host, username) or ""
    if bool(username) != bool(password) or security not in {"starttls", "ssl"} or (defaults.get("require_auth") and not username):
        raise ValueError("Supply a complete SMTP credential pair and starttls/ssl transport")
    configured_port = defaults.get("port") if security == defaults.get("security") else None
    port = int(os.environ.get("SMTP_PORT", str(configured_port or (465 if security == "ssl" else 587))))
    if not 1 <= port <= 65535:
        raise ValueError("SMTP_PORT out of range")
    return {"host": host, "sender": sender, "security": security, "port": port,
            "username": username, "password": password}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report", type=Path)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--preview", type=Path)
    parser.add_argument("--html-preview", type=Path, help="HTML preview path for --dry-run; never sends mail")
    parser.add_argument("--state-dir", type=Path, default=ROOT / "runtime/data/email-notification")
    parser.add_argument("--max-attempts", type=int, default=3)
    args = parser.parse_args()
    try:
        if not 1 <= args.max_attempts <= 5:
            raise ValueError("max-attempts must be 1..5")
        if args.dry_run:
            preview_sender = os.environ.get("SMTP_FROM", public_settings().get("sender", "opencode@localhost"))
            message, key = build_message(args.report, preview_sender)
            message["X-Unsent"] = "1"
            preview = args.preview or args.report.parent / "email-preview.eml"
            html_preview = args.html_preview or args.report.parent / "email-preview.html"
            if (preview.resolve() == args.report.resolve() or html_preview.resolve() == args.report.resolve()
                    or preview.resolve() == html_preview.resolve()):
                raise ValueError("Preview must not overwrite the report")
            preview.parent.mkdir(parents=True, exist_ok=True)
            html_preview.parent.mkdir(parents=True, exist_ok=True)
            preview.write_bytes(message.as_bytes())
            html_preview.write_text(message.get_body(preferencelist=("html",)).get_content(), encoding="utf-8")
            print(json.dumps({"status": "preview", "email_sent": False, "delivery_key": key, "preview": str(preview), "html_preview": str(html_preview), "recipient": RECIPIENT}))
            return 0
        settings = settings_from_env()
        message, key = build_message(args.report, settings["sender"])
        result = deliver(message, key, args.state_dir / "outbox.sqlite3", settings, args.max_attempts)
        print(json.dumps(result))
        return 0 if result["status"] == "accepted" else 2
    except Exception as exc:
        # No exception text: SMTP/OS/library messages may contain authentication data.
        print(json.dumps({"status": "error", "email_sent": False, "error_type": type(exc).__name__}))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
