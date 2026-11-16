"""Small correctness checks for the offline benchmark, not speed thresholds."""
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

import benchmark_reader as benchmark


class ReaderBenchmarkTests(unittest.TestCase):
    def test_all_fixture_types_have_complete_verified_utf8(self):
        for kind in ('plain', 'json', 'xml', 'banner', 'xml_prompt'):
            with self.subTest(kind=kind):
                result = benchmark.measure(4096, 257, kind)
                self.assertTrue(result['valid'], result)
                self.assertEqual(result['command_writes'], 1)
                self.assertEqual(result['sha256_expected'], result['sha256_actual'])
                self.assertGreater(result['functions']['buffer_value']['calls'], 0)
                self.assertGreater(result['requested_sleep_seconds'], 0)

    def test_wire_chunks_split_utf8_without_corruption(self):
        wire = 'đường truyền 日本語 😃'.encode('utf-8')
        for size in (1, 2, 3, 4, 7):
            channel = benchmark.Channel(wire, size)
            self.assertEqual(channel.read_channel(), '')
            channel.write_channel('show data\n')
            parts = []
            while channel.position < len(wire):
                parts.append(channel.read_channel())
            self.assertEqual(hashlib.sha256(''.join(parts).encode('utf-8')).digest(), hashlib.sha256(wire).digest())

    def test_prompt_ambiguity_and_pager_keep_complete_evidence(self):
        ambiguous = benchmark.measure(4096, 257, 'fake_prompt')
        self.assertTrue(ambiguous['valid'], ambiguous)
        self.assertEqual(ambiguous['failure']['error_category'], 'output_verification')
        pager = benchmark.measure(4096, 257, 'pager')
        self.assertTrue(pager['valid'], pager)
        self.assertEqual(pager['command_writes'], 2)

    def test_json_fixture_is_well_formed_and_profile_is_written(self):
        wire, _ = benchmark.fixture(4096, 'json')
        self.assertTrue(json.loads(wire.decode('utf-8').removesuffix('\nrouter#')))
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'reader.prof'
            self.assertTrue(benchmark.measure(4096, 1024, 'json', profile_path=path)['valid'])
            self.assertGreater(path.stat().st_size, 0)
