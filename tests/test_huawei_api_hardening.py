"""Hardening tests for the direct client's absolute HTTP budget.

A local raw-socket peer drips one byte before every per-recv timeout; a small
loopback HTTP peer counts the logout. No real router or credential is used.
"""

import importlib.util
import json
import socket
import sys
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

WEBROOT = Path(__file__).resolve().parents[1]
_WEBDIR = str(WEBROOT / 'webcol')
if _WEBDIR not in sys.path:
    sys.path.insert(0, _WEBDIR)
_spec = importlib.util.spec_from_file_location(
    'huawei_api_hard', WEBROOT / 'webcol' / 'huawei_api.py')
assert _spec is not None and _spec.loader is not None
huawei_api = importlib.util.module_from_spec(_spec)
sys.modules['huawei_api_hard'] = huawei_api
_spec.loader.exec_module(huawei_api)


class DripServer:
    """Accepts one connection and drips bytes forever under a huge Content-Length."""

    def __init__(self):
        self._stop = False
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(('127.0.0.1', 0))
        self._sock.listen(5)
        self.port = self._sock.getsockname()[1]
        threading.Thread(target=self._accept, daemon=True).start()

    def _accept(self):
        while not self._stop:
            try:
                conn, _ = self._sock.accept()
            except OSError:
                return
            threading.Thread(target=self._drip, args=(conn,), daemon=True).start()

    def _drip(self, conn):
        try:
            conn.recv(65536)
            conn.sendall(b'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n'
                         b'Content-Length: 100000000\r\n\r\n')
            while not self._stop:
                conn.sendall(b'x')
                time.sleep(0.05)
        except OSError:
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass

    def close(self):
        self._stop = True
        try:
            self._sock.close()
        except OSError:
            pass


class LogoutCounter(BaseHTTPRequestHandler):
    hits = []

    def log_message(self, fmt, *args):
        pass

    def do_POST(self):
        LogoutCounter.hits.append(self.path)
        length = int(self.headers.get('Content-Length', '0') or 0)
        self.rfile.read(min(length, 1 << 16))
        body = json.dumps({'err': 0}).encode()
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class AbsoluteBudgetTests(unittest.TestCase):
    def test_slow_drip_cannot_hold_the_thread(self):
        server = DripServer()
        self.addCleanup(server.close)
        client = huawei_api.HuaweiDirectClient(
            'http://127.0.0.1:%d' % server.port, 'placeholder-pw', request_timeout=0.4)
        outcome = {}

        def run():
            start = time.monotonic()
            try:
                client._request('GET', 'api/x')
                outcome['result'] = ('returned', time.monotonic() - start)
            except Exception as exc:  # noqa: BLE001 - which typed error is asserted below
                outcome['result'] = (type(exc).__name__, time.monotonic() - start)

        worker = threading.Thread(target=run, daemon=True)
        worker.start()
        worker.join(timeout=6)
        self.assertFalse(worker.is_alive(), 'read loop did not terminate')
        name, elapsed = outcome['result']
        self.assertIn(name, ('BudgetExceeded', 'TimeoutError', 'timeout', 'socket.timeout'))
        self.assertLess(elapsed, 5.0)

    def test_oversized_body_still_capped(self):
        body_bytes = 1 << 16

        class BigHandler(BaseHTTPRequestHandler):
            def log_message(self, fmt, *args):
                pass

            def do_GET(self):
                payload = b'x' * body_bytes
                self.send_response(200)
                self.send_header('Content-Length', str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

        server = ThreadingHTTPServer(('127.0.0.1', 0), BigHandler)
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        client = huawei_api.HuaweiDirectClient(
            'http://127.0.0.1:%d' % server.server_address[1], 'placeholder-pw',
            request_timeout=5.0, max_response=1024)
        with self.assertRaises(huawei_api.ResponseTooLarge):
            client._request('GET', 'api/x')


class LogoutBudgetTests(unittest.TestCase):
    server: ThreadingHTTPServer
    base: str

    def setUp(self):
        LogoutCounter.hits = []
        self.server = ThreadingHTTPServer(('127.0.0.1', 0), LogoutCounter)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.base = 'http://127.0.0.1:%d' % self.server.server_address[1]

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()

    def test_logout_attempted_after_budget_exhausted(self):
        client = huawei_api.HuaweiDirectClient(self.base, 'placeholder-pw', request_timeout=5.0)
        client.logged_in = True
        client.csrf = {'csrf_param': 'p', 'csrf_token': 't'}
        client._deadline = time.monotonic() - 1.0
        self.assertEqual(client.logout(), 'ok')
        self.assertTrue(any('user_logout' in path for path in LogoutCounter.hits))
        self.assertFalse(client.logged_in)

    def test_logout_failure_never_leaves_logged_in(self):
        probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        probe.bind(('127.0.0.1', 0))
        port = probe.getsockname()[1]
        probe.close()
        client = huawei_api.HuaweiDirectClient(
            'http://127.0.0.1:%d' % port, 'placeholder-pw', request_timeout=0.5)
        client.logged_in = True
        client.csrf = {'csrf_param': 'p', 'csrf_token': 't'}
        self.assertEqual(client.logout(), 'failed')
        self.assertFalse(client.logged_in)


if __name__ == '__main__':
    unittest.main()
