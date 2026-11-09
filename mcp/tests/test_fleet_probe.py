"""Loopback checks for the fleet TCP/banner census; never contact inventory devices."""
import contextlib
import json
from pathlib import Path
import socket
import sys
import tempfile
import threading
import time
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from collector_backend import readonly_command
from validate_fleet import COMMANDS, probe_endpoint, validate


@contextlib.contextmanager
def tcp_server(chunks):
    listener = socket.socket()
    listener.bind(('127.0.0.1', 0))
    listener.listen(1)
    listener.settimeout(2)
    port = listener.getsockname()[1]
    def serve():
        try:
            client, _ = listener.accept()
            with client:
                for delay, payload in chunks:
                    time.sleep(delay)
                    client.sendall(payload)
        except OSError:
            pass
    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    try: yield port
    finally:
        listener.close()
        thread.join(3)


class FleetProbeTests(unittest.TestCase):
    def test_fragmented_banner_after_login_notice_is_detected(self):
        with tcp_server([(0, b'Authorized use only\r\n'), (.02, b'SS'), (.02, b'H-2.0-fixture\r\n')]) as port:
            result = probe_endpoint('127.0.0.1', port, 1)
        self.assertTrue(result['tcp_connected'])
        self.assertTrue(result['ssh_banner'])

    def test_open_http_service_is_not_reported_as_ssh(self):
        with tcp_server([(0, b'HTTP/1.1 200 OK\r\n\r\n')]) as port:
            result = probe_endpoint('127.0.0.1', port, .2)
        self.assertTrue(result['tcp_connected'])
        self.assertFalse(result['ssh_banner'])
        self.assertEqual(result['error_category'], 'banner_not_verified')

    def test_silent_listener_is_banner_timeout_not_success(self):
        with tcp_server([(.3, b'')]) as port:
            result = probe_endpoint('127.0.0.1', port, .1)
        self.assertTrue(result['tcp_connected'])
        self.assertFalse(result['ssh_banner'])
        self.assertEqual(result['error_category'], 'banner_timeout')

    def test_census_deduplicates_endpoints_and_validates_command_map(self):
        for dtype, commands in COMMANDS.items():
            for command in commands: readonly_command(command, dtype)
        with tempfile.TemporaryDirectory() as tmp:
            with tcp_server([(0, b'SSH-2.0-fixture\r\n')]) as port:
                device = {'host': '127.0.0.1', 'port': port, 'device_type': 'linux'}
                result = validate({'devices': {'one': device, 'two': dict(device)}}, tmp,
                                  execute=False, timeout=.5, probe_workers=2, ssh_workers=2)
            self.assertEqual(result['inventory_aliases'], 2)
            self.assertEqual(result['unique_endpoints'], 1)
            self.assertEqual(result['unique_identities'], 1)
            self.assertEqual(result['tcp_connected'], 1)
            self.assertEqual(result['ssh_banners'], 1)
            self.assertFalse(result['ssh_executed'])
            self.assertEqual(json.loads((Path(tmp) / 'fleet-summary.json').read_text()), result)
            with self.assertRaises(ValueError): validate({}, tmp)


if __name__ == '__main__': unittest.main()
