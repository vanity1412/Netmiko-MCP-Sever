"""Offline tests only: never connect to SMTP or read real credentials."""
import hashlib
import importlib.util
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch


BASE = Path(__file__).resolve().parents[1]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


renderer = load('test_report_html', BASE / 'report_html.py')
sender = load('test_html_sender', BASE / 'send_report.py')


class HtmlEmailTests(unittest.TestCase):
    def test_headings_tables_lists_quotes_and_code(self):
        body = '# Kết luận\n\n**Tải cao**\n\n| Cổng | Tải |\n|---|---:|\n| `et-0/0/39` | 85,3% |\n\n- Up\n\n> Chưa xác nhận mất gói\n\n```text\nshow x | match "<peer>"\n```'
        result = renderer.render_report(body, 'SC07112601316')
        for expected in ['<h1 ', '<strong>Tải cao</strong>', 'scope="col"', '85,3%', '<ul ', '<li ', '<pre ', '&lt;peer&gt;', 'Chưa xác nhận mất gói']:
            self.assertIn(expected, result)

    def test_code_pipe_is_not_a_table_separator(self):
        self.assertEqual(renderer.table_cells('| `show x | match y` | Up |'), ['`show x | match y`', 'Up'])

    def test_raw_html_and_unsafe_links_cannot_execute(self):
        result = renderer.render_report('<script>alert(1)</script>\n\n[x](javascript:alert)\n\n[x](file:///C:/secret)\n\n[web](https://example.com?a=1&b=2)')
        self.assertNotIn('<script>', result)
        self.assertNotIn('href="javascript:', result)
        self.assertNotIn('href="file:', result)
        self.assertIn('&lt;script&gt;', result)
        self.assertIn('href="https://example.com?a=1&amp;b=2"', result)

    def test_unclosed_code_is_preserved(self):
        self.assertIn('&lt;raw&gt;', renderer.render_report('```\n<raw>'))

    def test_multipart_alternative_and_existing_dedup_key(self):
        body = '# Kết luận\n\nDữ liệu đã che bí mật.\n'
        path = Path('output/SC07112601316/bao-cao.md')
        with patch.object(sender, 'sanitized_report', return_value=body):
            message, key = sender.build_message(path, 'sender@example.com')
        self.assertEqual(message.get_content_type(), 'multipart/alternative')
        self.assertEqual(message.get_body(preferencelist=('plain',)).get_content(), body)
        self.assertIn('Dữ liệu đã che bí mật.', message.get_body(preferencelist=('html',)).get_content())
        self.assertEqual(list(message.iter_attachments()), [])
        self.assertIsNone(message['Cc'])
        self.assertIsNone(message['Bcc'])
        self.assertEqual(str(message['To']), '[redacted-email]')
        old_key = hashlib.sha256(json.dumps([sender.RECIPIENT, str(message['Subject']), body], ensure_ascii=False).encode('utf-8')).hexdigest()
        self.assertEqual(key, old_key)

    def test_html_does_not_bypass_sending_or_unknown_state(self):
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory) / 'outbox.sqlite3'
            db = sender.connect_state(state)
            for key, status in [('a', 'sending'), ('b', 'unknown'), ('c', 'accepted')]:
                db.execute('INSERT INTO delivery VALUES (?,?,?,?,?,?,?)', (key, status, 1, 1, 0, None, None))
            db.close()
            for key, status in [('a', 'sending'), ('b', 'unknown'), ('c', 'accepted')]:
                with patch.object(sender, 'smtp_delivery') as smtp:
                    result = sender.deliver(None, key, state, {})
                self.assertEqual(result['status'], status)
                smtp.assert_not_called()


if __name__ == '__main__':
    unittest.main()
