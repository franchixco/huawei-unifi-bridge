"""Offline tests for the read-only controller-native metrics probe tool."""

import importlib.util
import json
import os
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location(
    'ucg_metrics_probe', ROOT / 'tools' / 'ucg_metrics_probe.py')
assert _spec is not None and _spec.loader is not None
probe_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(probe_mod)


class Forbidden(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass

    def _deny(self):
        length = int(self.headers.get('Content-Length', '0') or 0)
        if length:
            self.rfile.read(min(length, 65536))
        self.send_response(403)
        self.send_header('Content-Length', '0')
        self.end_headers()

    do_GET = _deny
    do_POST = _deny


class ProbeSummarizeTests(unittest.TestCase):
    def test_empty_series_does_not_establish_history_disabled(self):
        summary = probe_mod.summarize_series([])
        self.assertEqual(summary['buckets'], 0)
        self.assertIn('history', summary['note'])
        self.assertIn('does not establish', summary['note'])

    def test_buckets_are_summarized_without_fabrication(self):
        summary = probe_mod.summarize_series([{'series': [
            {'timestamp': 1, 'rxBytes': 0, 'txBytes': 5},
            {'timestamp': 2, 'rxBytes': None, 'txBytes': 7}]}])
        self.assertEqual(summary['buckets'], 2)
        self.assertEqual(summary['fields']['txBytes']['nonzero'], 2)
        self.assertEqual(summary['fields']['rxBytes']['zero'], 1)
        self.assertEqual(summary['fields']['rxBytes']['null'], 1)

    def test_non_list_series_is_not_a_shape_claim(self):
        self.assertEqual(probe_mod.summarize_series({'data': []})['shape'], 'non-list')


class ProbeHttpTests(unittest.TestCase):
    def test_forbidden_is_reported_not_treated_as_success(self):
        server = ThreadingHTTPServer(('127.0.0.1', 0), Forbidden)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.shutdown)
        self.addCleanup(server.server_close)
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        creds = os.path.join(directory.name, 'ro.json')
        with open(creds, 'w', encoding='utf-8') as handle:
            json.dump({'username': 'readonly', 'password': 'placeholder'}, handle)
        probe = probe_mod.Probe('http://127.0.0.1:%d' % server.server_address[1], creds)
        status, csrf = probe.login()
        self.assertEqual(status, 403)
        self.assertFalse(csrf)
        status, devices = probe.stat_device()
        self.assertEqual(status, 403)
        self.assertEqual(devices, [])


if __name__ == '__main__':
    unittest.main()
