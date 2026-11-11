"""Full-byte evidence assembly, HTML safety and refusal to fabricate completeness."""
import hashlib
import html
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
import zipfile
from unittest.mock import patch

spec=importlib.util.spec_from_file_location('report_bundle',Path(__file__).resolve().parents[1]/'scripts/report_bundle.py')
bundle=importlib.util.module_from_spec(spec);spec.loader.exec_module(bundle)


class BundleTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name)
        self.raw=('dữ liệu 日本語 😃\r\n```\n<script>raw</script>\npassword fixture token fixture\n'*100).encode()
        (self.root/'raw.txt').write_bytes(self.raw)
        (self.root/'brief.md').write_text('## Kết luận\nChưa xác minh vì TIMEOUT; e1 là PARTIAL.\n',encoding='utf-8')
        self.entry={'id':'e1','path':'raw.txt','target':'LAB','command':'show interfaces','status':'PARTIAL','sha256':hashlib.sha256(self.raw).hexdigest()}
        self.plan=self.root/'manifest.json';self.output=self.root/'bundle'
        self.plan.write_text(json.dumps({'evidence':[self.entry]}))

    def build(self):return bundle.build(self.root/'brief.md',self.plan,self.output)

    def test_raw_exact_and_html_escaped_without_data_loss(self):
        self.build()
        self.assertEqual((self.output/'evidence/e1.txt').read_bytes(),self.raw)
        self.assertEqual((self.root/'raw.txt').read_bytes(),self.raw)
        self.assertIn(self.raw,(self.output/'report.md').read_bytes())
        rendered=(self.output/'report.html').read_bytes().decode()
        self.assertNotIn('<script>',rendered)
        self.assertIn(self.raw.decode(),html.unescape(rendered))
        self.assertIn('````text',(self.output/'report.md').read_bytes().decode())
        self.assertEqual(json.loads((self.output/'bundle.json').read_text())['evidence'][0]['status'],'PARTIAL')

    def test_stable_artifacts_for_same_input(self):
        self.build();other=self.root/'second'
        bundle.build(self.root/'brief.md',self.plan,other)
        for file in ('report.md','report.html','bundle.json'):
            self.assertEqual((self.output/file).read_bytes(),(other/file).read_bytes())

    def test_sender_verifies_html_markdown_and_raw(self):
        self.build()
        self.assertEqual(bundle.verified_html(self.output/'report.md'),(self.output/'report.html').read_bytes().decode())
        for filename in ('summary.md','report.md','report.html','evidence/e1.txt'):
            path=self.output/filename;original=path.read_bytes();path.write_bytes(original+b'changed')
            with self.subTest(filename=filename),self.assertRaises(ValueError):
                bundle.verified_html(self.output/'report.md')
            path.write_bytes(original)

    def test_checksum_failure_refuses_to_publish(self):
        (self.root/'raw.txt').write_bytes(b'changed')
        with self.assertRaises(ValueError):self.build()
        self.assertFalse(self.output.exists())

    def test_missing_source_refuses_to_publish(self):
        (self.root/'raw.txt').unlink()
        with self.assertRaises(FileNotFoundError):self.build()
        self.assertFalse(self.output.exists())

    def test_existing_destination_is_not_overwritten(self):
        self.output.mkdir();marker=self.output/'keep';marker.write_bytes(b'keep')
        with self.assertRaises(ValueError):self.build()
        self.assertEqual(marker.read_bytes(),b'keep')

    def test_duplicate_ids_and_traversal_are_rejected(self):
        for records in ([self.entry,self.entry],[dict(self.entry,id='../escape')]):
            with self.subTest(records=records):
                self.plan.write_text(json.dumps({'evidence':records}))
                with self.assertRaises(ValueError):self.build()
                self.assertFalse(self.output.exists())

    def test_invalid_encoding_does_not_silently_replace_bytes(self):
        raw=b'\xff\xfe\x00';(self.root/'raw.txt').write_bytes(raw)
        self.entry['sha256']=hashlib.sha256(raw).hexdigest()
        self.plan.write_text(json.dumps({'evidence':[self.entry]}))
        with self.assertRaises(UnicodeError):self.build()
        self.assertEqual((self.root/'raw.txt').read_bytes(),raw)

    def test_summary_streams_binary_and_generates_hash_without_inline_raw(self):
        raw=b'\xff\x00'+b'RAW-MARKER'*300000
        (self.root/'raw.txt').write_bytes(raw)
        self.entry.pop('sha256')
        self.plan.write_text(json.dumps({'evidence':[self.entry]}))
        original=Path.read_bytes
        def read(path):
            if path==self.root/'raw.txt':raise AssertionError('Raw must stream')
            return original(path)
        with patch.object(Path,'read_bytes',read):
            bundle.build(self.root/'brief.md',self.plan,self.output,mode='SUMMARY')
        self.assertNotIn(b'RAW-MARKER',(self.output/'report.md').read_bytes())
        self.assertFalse((self.output/'evidence').exists())
        with zipfile.ZipFile(self.output/'evidence.zip') as archive:
            self.assertEqual(archive.read('evidence/e1.raw'),raw)
            record=json.loads(archive.read('manifest.json'))['evidence'][0]
            self.assertEqual(record['sha256'],hashlib.sha256(raw).hexdigest())
            self.assertEqual(record['status'],'PARTIAL')
        self.assertIn('Chưa xác minh',bundle.verified_html(self.output/'report.md'))

    def test_summary_tampered_zip_refuses_verification(self):
        bundle.build(self.root/'brief.md',self.plan,self.output,mode='SUMMARY')
        p=self.output/'evidence.zip';p.write_bytes(p.read_bytes()+b'changed')
        with self.assertRaises(ValueError):bundle.verified_html(self.output/'report.md')

    def test_summary_wrong_hash_cleans_staging_without_publishing(self):
        self.entry['sha256']='wrong';self.plan.write_text(json.dumps({'evidence':[self.entry]}))
        with self.assertRaises(ValueError):bundle.build(self.root/'brief.md',self.plan,self.output,mode='SUMMARY')
        self.assertFalse(self.output.exists())
        self.assertFalse(list(self.root.glob('.report-bundle-*')))

    def test_summary_keeps_logs_configs_and_completion_metadata(self):
        entries=[]
        for ident,raw in [('cli',b'cli\r\n'),('log',b'log\x00'),('config',b'secret unchanged')]:
            (self.root/ident).write_bytes(raw)
            entries.append(dict(self.entry,id=ident,path=ident,sha256=hashlib.sha256(raw).hexdigest(),
                                kind=ident,output_complete=False))
        self.plan.write_text(json.dumps({'evidence':entries}))
        bundle.build(self.root/'brief.md',self.plan,self.output,mode='SUMMARY')
        bundle.verified_html(self.output/'report.md')
        with zipfile.ZipFile(self.output/'evidence.zip') as archive:
            for entry in entries:
                self.assertEqual(archive.read('evidence/'+entry['id']+'.raw'),(self.root/entry['id']).read_bytes())
            self.assertTrue(all(not x['output_complete'] for x in json.loads(archive.read('manifest.json'))['evidence']))

    def test_summary_duplicate_ids_leave_sources_intact(self):
        self.plan.write_text(json.dumps({'evidence':[self.entry,self.entry]}))
        before=(self.root/'raw.txt').read_bytes()
        with self.assertRaises(ValueError):bundle.build(self.root/'brief.md',self.plan,self.output,mode='SUMMARY')
        self.assertFalse(self.output.exists())
        self.assertEqual((self.root/'raw.txt').read_bytes(),before)
