"""End-to-end admin API test: real HTTP server + real session transport.

A local ThreadingHTTPServer serves the admin routes; a RecordingClient stands in
for the authenticated CPE and captures the exact wire DTO, action extra field
and headers the real HuaweiSession sends. No real router, credential or network
beyond the in-process admin listener.
"""

import asyncio
import http.client
import importlib.util
import json
import os
import sys
import tempfile
import threading
import time
import unittest
import unittest.mock
from concurrent.futures import ThreadPoolExecutor
from http.server import ThreadingHTTPServer
from pathlib import Path
from typing import Any

WEBROOT = Path(__file__).resolve().parents[1]
_WEBDIR = str(WEBROOT / 'webcol')
if _WEBDIR not in sys.path:
    sys.path.insert(0, _WEBDIR)


def _load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


ops = _load('operations', WEBROOT / 'webcol' / 'operations.py')
svc = _load('operation_service', WEBROOT / 'webcol' / 'operation_service.py')
huawei_api = _load('huawei_api', WEBROOT / 'webcol' / 'huawei_api.py')
_spec = importlib.util.spec_from_file_location('webcol_e2e', WEBROOT / 'webcol' / 'webcol.py')
assert _spec is not None and _spec.loader is not None
webcol = importlib.util.module_from_spec(_spec)
sys.modules['webcol_e2e'] = webcol
_spec.loader.exec_module(webcol)

HOST = 'https://192.0.2.9'
RID = '192.0.2.9'
TOKEN = 'e2e-admin-token'
SERIAL = 'SYNTH-SERIAL-0001'

WLAN_PATH = 'api/ntwk/WlanGuideBasic?type=notshowpassall'
GUEST_PATH = 'api/ntwk/guest_network?type=notshowpassall'
DEVICE_PATH = 'api/system/deviceinfo'


def wlanguide(dot11r=False):
    return {"WifiConfig": [
        {"ID": "1", "FrequencyBand": "2.4GHz", "WifiSsid": "main", "WifiEnable": True,
         "Dot11REnable": dot11r, "TWTEnable": dot11r},
        {"ID": "2", "FrequencyBand": "5GHz", "WifiSsid": "main5", "WifiEnable": True,
         "Dot11REnable": dot11r, "TWTEnable": dot11r},
    ]}


def guest():
    return [
        {"ID": "g2", "FrequencyBand": "2.4GHz", "EnableFrequency": True,
         "CanEnableFrequency": True, "SecOpt": "tkip", "WifiSsid": "G"},
        {"ID": "g5", "FrequencyBand": "5GHz", "EnableFrequency": True,
         "CanEnableFrequency": True, "SecOpt": "tkip", "WifiSsid": "G"},
    ]


class RecordingClient:
    def __init__(self, *, reads=None, on_post=None, post_reply=None, post_error=None):
        self.csrf = {'csrf_param': 'csrf_param', 'csrf_token': 'tok0'}
        self.public_key = {'rsan': 'ab' * 256, 'rsae': '10001'}
        self.public_key_verified = True
        self.logged_in = False
        self.reads = dict(reads or {})
        self.requests = []
        self.posts = []
        self.on_post = on_post
        self.post_reply = post_reply
        self.post_error = post_error

    def login(self):
        self.logged_in = True
        return {'public_key_verified': True}

    def logout(self):
        self.logged_in = False
        return 'ok'

    def classify_error(self, data):
        raise AssertionError('HuaweiSession must use the module classify_error')

    def _get_json(self, path, stage):
        if path == DEVICE_PATH:
            return {'SerialNumber': SERIAL, 'SoftwareVersion': 'fw'}
        if path in self.reads:
            return self.reads[path]
        raise huawei_api.CollectionError(stage)

    def _request(self, method, path, body=None, timeout=None, headers=None):
        entry = {'method': method, 'path': path, 'body': body,
                 'headers': dict(headers or {})}
        self.requests.append(entry)
        if method == 'POST':
            self.posts.append(entry)
            if self.on_post is not None:
                self.on_post(self, path, body)
            if self.post_error is not None:
                raise self.post_error
        self.csrf = {'csrf_param': 'csrf_param', 'csrf_token': 'tok' + str(len(self.requests))}
        reply = self.post_reply if (method == 'POST' and self.post_reply is not None) else {}
        return 200, json.dumps(reply).encode()

    def _json(self, raw):
        data = json.loads(raw.decode('utf-8'))
        if isinstance(data, dict) and isinstance(data.get('csrf_param'), str) \
                and isinstance(data.get('csrf_token'), str):
            self.csrf = {'csrf_param': data['csrf_param'], 'csrf_token': data['csrf_token']}
        return data


class E2EFixture(unittest.TestCase):
    def _service(self, tmp, client, *, allow, master=True, unverified=False, serial=SERIAL):
        registry = {RID: svc.RouterBinding(RID, HOST, 'pw', expected_serial=serial)}
        return svc.OperationsService(
            registry, token=TOKEN, writes_master=master, enabled_operations=frozenset(allow),
            unverified_writes=unverified, state_path=os.path.join(tmp, 'ops.json'),
            session_factory=lambda b: svc.HuaweiSession(client, b),
            executor=ThreadPoolExecutor(max_workers=2))

    def _serve(self, service):
        loop = asyncio.new_event_loop()
        thread = threading.Thread(target=loop.run_forever, daemon=True)
        thread.start()
        service.set_loop(loop)
        server = ThreadingHTTPServer(
            ('127.0.0.1', 0), webcol.handler(webcol.Collector(), service, loop))
        server.daemon_threads = True
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.shutdown)
        self.addCleanup(server.server_close)

        def _stop_loop():
            loop.call_soon_threadsafe(loop.stop)
            thread.join(timeout=5)
            loop.close()

        self.addCleanup(_stop_loop)
        return server

    def _http(self, server, method, path, body=None, headers=None):
        connection = http.client.HTTPConnection('127.0.0.1', server.server_address[1], timeout=10)
        payload = None if body is None else json.dumps(body).encode()
        connection.request(method, path, body=payload, headers=headers or {})
        response = connection.getresponse()
        raw = response.read()
        connection.close()
        data: Any = None
        try:
            data = json.loads(raw.decode('utf-8'))
        except ValueError:
            pass
        return response.status, data

    def _auth(self, extra=None):
        headers = {'Authorization': 'Bearer ' + TOKEN, 'Content-Type': 'application/json'}
        headers.update(extra or {})
        return headers


class WireTransportTests(E2EFixture):
    def test_plan_dry_run_never_posts(self):
        with tempfile.TemporaryDirectory() as tmp:
            client = RecordingClient(reads={WLAN_PATH: wlanguide(False)})
            service = self._service(tmp, client, allow=('wifi.80211r',))
            server = self._serve(service)
            status, body = self._http(server, 'POST', '/operations/plan', {
                'router': RID, 'operation': 'wifi.80211r',
                'target': {'vap_id': '1'}, 'fields': {'enabled': True}}, self._auth())
        self.assertEqual(status, 200)
        self.assertEqual(body['status'], 'ok')
        self.assertEqual(client.posts, [])

    def test_execute_sends_nested_dto_and_action_extra(self):
        with tempfile.TemporaryDirectory() as tmp:
            reads = {WLAN_PATH: wlanguide(False)}

            def on_post(client, path, body):
                reads[WLAN_PATH]['WifiConfig'][0]['Dot11REnable'] = True

            client = RecordingClient(reads=reads, on_post=on_post)
            service = self._service(tmp, client, allow=('wifi.80211r',))
            server = self._serve(service)
            status, body = self._http(server, 'POST', '/operations', {
                'router': RID, 'operation': 'wifi.80211r', 'operation_id': 'e2e-11r',
                'target': {'vap_id': '1'}, 'fields': {'enabled': True}}, self._auth())
        self.assertEqual(status, 200)
        self.assertEqual(body['outcome'], 'verified_changed')
        post = client.posts[-1]
        self.assertEqual(post['path'], ops.URL_WLAN_GUIDE)
        self.assertEqual(post['body']['data'], {'Dot11REnable': True})
        self.assertEqual(post['body']['action'], '11rSetting')
        self.assertEqual(post['body']['csrf']['csrf_token'], 'tok0')
        self.assertNotEqual(client.csrf['csrf_token'], 'tok0')

    def test_guest_uses_enp_content_type(self):
        with tempfile.TemporaryDirectory() as tmp:
            client = RecordingClient(reads={GUEST_PATH: guest()})
            service = self._service(tmp, client, allow=('wifi.guest.set',))
            server = self._serve(service)
            status, body = self._http(server, 'POST', '/operations', {
                'router': RID, 'operation': 'wifi.guest.set', 'operation_id': 'e2e-guest',
                'fields': {'enabled': True, 'ssid': 'G', 'security': 'open'}}, self._auth())
        self.assertEqual(status, 200)
        self.assertIn(body['outcome'], ('verified_changed', 'uncertain'))
        self.assertEqual(
            client.posts[-1]['headers'].get('Content-Type'),
            'application/json;charset=UTF-8;enp')

    def test_csrf_error_is_uncertain_and_not_resent(self):
        with tempfile.TemporaryDirectory() as tmp:
            client = RecordingClient(
                reads={WLAN_PATH: wlanguide(False)},
                post_reply={'errcode': 1, 'csrf': 'Menu.csrf_err'})
            service = self._service(tmp, client, allow=('wifi.80211r',))
            server = self._serve(service)
            status, body = self._http(server, 'POST', '/operations', {
                'router': RID, 'operation': 'wifi.80211r',
                'target': {'vap_id': '1'}, 'fields': {'enabled': True}}, self._auth())
        self.assertEqual(status, 200)
        self.assertEqual(body['outcome'], 'uncertain')
        self.assertEqual(len(client.posts), 1)

    def test_non_object_reply_is_uncertain(self):
        with tempfile.TemporaryDirectory() as tmp:
            client = RecordingClient(
                reads={WLAN_PATH: wlanguide(False)}, post_reply=[1, 2, 3])
            service = self._service(tmp, client, allow=('wifi.80211r',))
            server = self._serve(service)
            status, body = self._http(server, 'POST', '/operations', {
                'router': RID, 'operation': 'wifi.80211r',
                'target': {'vap_id': '1'}, 'fields': {'enabled': True}}, self._auth())
        self.assertEqual(status, 200)
        self.assertEqual(body['outcome'], 'uncertain')


class HttpBoundaryTests(E2EFixture):
    def test_main_from_env_path_serves_not_503(self):
        with tempfile.TemporaryDirectory() as tmp:
            env = {'HW_OPERATIONS_TOKEN': TOKEN, 'HW_ROUTER_SERIALS': HOST + '=' + SERIAL}
            with unittest.mock.patch.dict(os.environ, env, clear=False):
                service = svc.OperationsService.from_env(
                    [(HOST, 'pw')], state_path=os.path.join(tmp, 'ops.json'))
            server = self._serve(service)
            status, caps = self._http(server, 'GET', '/capabilities',
                                      headers={'Host': '127.0.0.1'})
            self.assertEqual(status, 200)
            self.assertIn('operations', caps)
            status, _ = self._http(server, 'POST', '/operations/plan',
                                   {'router': RID}, {'Content-Type': 'application/json'})
            self.assertEqual(status, 401)

    def test_host_origin_and_token_boundary(self):
        with tempfile.TemporaryDirectory() as tmp:
            client = RecordingClient(reads={WLAN_PATH: wlanguide(False)})
            service = self._service(tmp, client, allow=('wifi.80211r',))
            server = self._serve(service)

            status, _ = self._http(server, 'GET', '/capabilities',
                                   headers={'Host': 'evil.example'})
            self.assertEqual(status, 400)

            status, _ = self._http(server, 'GET', '/capabilities',
                                      headers={'Host': '192.0.2.9'})
            self.assertEqual(status, 400)

            status, caps = self._http(server, 'GET', '/capabilities',
                                      headers={'Host': '127.0.0.1'})
            self.assertEqual(status, 200)
            self.assertIn('operations', caps)

            status, _ = self._http(server, 'POST', '/operations/plan', {
                'router': RID, 'operation': 'wifi.80211r',
                'target': {'vap_id': '1'}, 'fields': {'enabled': True}},
                self._auth({'Origin': 'https://evil.example'}))
            self.assertEqual(status, 403)

            status, _ = self._http(server, 'POST', '/operations/plan', {
                'router': RID, 'operation': 'wifi.80211r',
                'target': {'vap_id': '1'}, 'fields': {'enabled': True}},
                {'Content-Type': 'application/json'})
            self.assertEqual(status, 401)

            status, _ = self._http(server, 'GET', '/operations/unknown-id')
            self.assertEqual(status, 401)


if __name__ == '__main__':
    unittest.main()
