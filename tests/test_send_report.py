"""Offline sender regressions. SMTP clients and credentials are synthetic."""
import contextlib
from email import policy
from email.parser import BytesParser
import importlib.util
import io
import json
import os
from pathlib import Path
import smtplib
import sys
import tempfile
import unittest
from unittest.mock import patch

from test_report_bundle import bundle

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('test_report_sender', ROOT / 'email/send_report.py')
sender = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sender)


class FakeSMTP:
    def __init__(self, payloads, response=None):
        self.payloads = payloads
        self.response = response or (250, b'fixture accepted')

    def ehlo(self):
        return 250, b'fixture'

    def starttls(self, *, context):
        return 220, b'fixture ready'

    def mail(self, sender_address):
        return 250, b'fixture sender'

    def rcpt(self, recipient):
        return 250, b'fixture recipient'

    def data(self, message):
        self.payloads.append(message)
        if isinstance(self.response, Exception):
            raise self.response
        return self.response

    def close(self):
        pass


class SenderTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        output = self.root / 'bundle'
        self.report = output / 'report.md'
        self.raw = 'Junos: 23.4R2\nDữ liệu mô phỏng\n'
        (self.root / 'raw.txt').write_text(self.raw, encoding='utf-8')
        summary = self.root / 'analysis.md'
        summary.write_text('# Báo cáo LAB\n\n## Kết luận\nĐã kiểm tra fixture.\n', encoding='utf-8')
        manifest = self.root / 'manifest.json'
        manifest.write_text(json.dumps({'evidence': [{'id': 'e1', 'path': 'raw.txt',
            'target': 'LAB', 'command': 'show version', 'status': 'SUCCESS'}]}), encoding='utf-8')
        bundle.build(summary, manifest, output)

    def dry_run(self, *options):
        captured = io.StringIO()
        with patch.object(sys, 'argv', ['send_report.py', str(self.report), '--dry-run', *options]), \
                patch.dict(os.environ, {}, clear=True), patch.object(sender, 'public_settings', return_value={}), \
                patch.object(sender.smtplib, 'SMTP') as smtp, patch.object(sender.smtplib, 'SMTP_SSL') as smtp_ssl, \
                contextlib.redirect_stdout(captured):
            code = sender.main()
        smtp.assert_not_called()
        smtp_ssl.assert_not_called()
        return code, json.loads(captured.getvalue())

    def test_dry_run_rejects_all_bundle_members_before_writing_either_preview(self):
        for name in ('report.md', 'report.html', 'summary.md', 'bundle.json',
                     'source_manifest.json', 'evidence/e1.txt'):
            with self.subTest(name=name):
                member = self.report.parent / name
                original = member.read_bytes()
                eml = self.root / 'preview.eml'
                code, result = self.dry_run('--preview', str(eml), '--html-preview', str(member))
                self.assertEqual(code, 2)
                self.assertFalse(result['email_sent'])
                self.assertFalse(eml.exists())
                self.assertEqual(member.read_bytes(), original)
        bundle.verified_html(self.report)

    def test_dry_run_rejects_a_hard_link_to_bundle_evidence(self):
        evidence = self.report.parent / 'evidence/e1.txt'
        alias = self.root / 'alias.html'
        os.link(evidence, alias)
        code, result = self.dry_run('--html-preview', str(alias))
        self.assertEqual(code, 2)
        self.assertFalse(result['email_sent'])
        self.assertFalse((self.report.parent / 'email-preview.eml').exists())
        bundle.verified_html(self.report)

    def test_dry_run_creates_utf8_previews_and_preserves_bundle(self):
        for _ in range(2):
            code, result = self.dry_run()
            self.assertEqual(code, 0, result)
            self.assertEqual(result['status'], 'preview')
            self.assertFalse(result['email_sent'])
        message = BytesParser(policy=policy.default).parsebytes(Path(result['preview']).read_bytes())
        self.assertEqual(message['X-Unsent'], '1')
        self.assertIn(self.raw, message.get_body(preferencelist=('plain',)).get_content().replace('\r\n', '\n'))
        self.assertIn('Dữ liệu mô phỏng', Path(result['html_preview']).read_text(encoding='utf-8'))
        self.assertEqual(list(message.iter_attachments()), [])
        bundle.verified_html(self.report)

    def test_fake_smtp_retry_acceptance_dedup_and_ambiguous_data(self):
        message, key = sender.build_message(self.report, 'sender@example.invalid', 'preview@example.invalid')
        settings = {'host': 'smtp-fixture.invalid', 'port': 587, 'security': 'starttls'}
        payloads = []
        responses = iter(((451, b'try again'), (250, b'accepted')))
        state = self.root / 'outbox.sqlite3'

        def accept(**_):
            return FakeSMTP(payloads, next(responses))

        accepted = sender.deliver(message, key, state, settings, backoff=0, factory=accept)
        self.assertEqual((accepted['status'], accepted['attempts']), ('accepted', 2))
        repeated = sender.deliver(message, key, state, settings, factory=accept)
        self.assertTrue(repeated['duplicate_suppressed'])
        self.assertFalse(repeated['sent_this_call'])
        self.assertEqual(len(payloads), 2)
        delivered = BytesParser(policy=policy.default).parsebytes(payloads[-1])
        self.assertIn(self.raw, delivered.get_body(preferencelist=('plain',)).get_content().replace('\r\n', '\n'))
        self.assertEqual(delivered['To'], 'preview@example.invalid')
        self.assertEqual(list(delivered.iter_attachments()), [])

        unknown_state = self.root / 'unknown-outbox.sqlite3'
        unknown_payloads = []

        def disconnect(**_):
            return FakeSMTP(unknown_payloads, smtplib.SMTPServerDisconnected('fixture DATA disconnect'))

        unknown = sender.deliver(message, key, unknown_state, settings, backoff=0, factory=disconnect)
        repeat_unknown = sender.deliver(message, key, unknown_state, settings, factory=disconnect)
        self.assertEqual((unknown['status'], repeat_unknown['status']), ('unknown', 'unknown'))
        self.assertEqual(unknown['attempts'], 1)
        self.assertEqual(len(unknown_payloads), 1)
