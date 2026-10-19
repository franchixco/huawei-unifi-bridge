"""Offline tests for the admin operations service and its HTTP routes.

Everything synthetic: a fake session, throwaway temp state dir and a placeholder
token/password that exist only here. No real router, credential or network.
"""

import asyncio
import importlib.util
import json
import os
import sys
import tempfile
import threading
import time
import unittest
import unittest.mock
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from http.server import ThreadingHTTPServer
from pathlib import Path

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

_spec = importlib.util.spec_from_file_location('webcol_svc_test', WEBROOT / 'webcol' / 'webcol.py')
assert _spec is not None and _spec.loader is not None
webcol = importlib.util.module_from_spec(_spec)
sys.modules['webcol_svc_test'] = webcol
_spec.loader.exec_module(webcol)

HOST = 'https://192.0.2.9'
RID = '192.0.2.9'
TOKEN = 'unit-test-admin-token'
PLACEHOLDER = 'synthetic-placeholder-only'
SERIAL = 'SYNTH-SERIAL-0001'


def wlanguide(dot11r=False):
    return {"WifiConfig": [
        {"ID": "1", "FrequencyBand": "2.4GHz", "WifiSsid": "main",
         "WifiEnable": True, "Dot11REnable": dot11r, "TWTEnable": dot11r},
        {"ID": "2", "FrequencyBand": "5GHz", "WifiSsid": "main5",
         "WifiEnable": True, "Dot11REnable": dot11r, "TWTEnable": dot11r},
    ]}


def deviceinfo():
    return {"SerialNumber": SERIAL, "SoftwareVersion": "4.2.0.53SP1C1555"}


class FakeSession:
    def __init__(self, data=None, *, device=None, fail_open=False, post_error=None,
                 store_path=None, mutate=None, expected_serial=None):
        self.data = dict(data or {})
        self.device = device if device is not None else deviceinfo()
        self.fail_open = fail_open
        self.post_error = post_error
        self.store_path = store_path
        self.mutate = mutate
        self.expected_serial = expected_serial
        self.posts = []
        self.opened = False
        self.closed = False
        self.pending_seen_before_post = None

    def open(self):
        if self.fail_open:
            raise svc.SessionIdentityError('credentials')
        serial = self.device.get("SerialNumber")
        if self.expected_serial and serial != self.expected_serial:
            raise svc.SessionIdentityError('serial-mismatch')
        self.opened = True
        return {"router_id": RID, "serial": serial,
                "software": self.device.get("SoftwareVersion"),
                "public_key_verified": True}

    def read(self, path):
        if path == 'api/system/deviceinfo':
            return self.device
        if path in self.data:
            return self.data[path]
        raise ops.TransportError('missing_fixture', 'read')

    def public_key(self):
        return {"rsan": "ab" * 256, "rsae": "10001"}

    def post(self, path, payload, *, extra=None, headers=None):
        self.posts.append({"path": path, "payload": payload, "extra": extra, "headers": headers})
        if self.store_path:
            try:
                with open(self.store_path, 'r', encoding='utf-8') as handle:
                    blob = json.load(handle)
                records = blob.get('records', {}) if isinstance(blob, dict) else {}
                self.pending_seen_before_post = any(
                    r.get('state') == 'pending' for r in records.values())
            except Exception:
                self.pending_seen_before_post = False
        if self.mutate:
            self.mutate(self.data, path, payload)
        if self.post_error is not None:
            raise self.post_error
        return {}

    def close(self):
        self.closed = True


def make_service(tmp, *, sessions, master=True, allow=frozenset({'wifi.80211r'}),
                 unverified=False, reboot=False, resolve=False, token=TOKEN,
                 gate=None, budget=5.0, lock_wait=1.0, serial: str | None = SERIAL,
                 state_name='ops_state.json'):
    queue = list(sessions)

    def factory(binding):
        return queue.pop(0)

    registry = {RID: svc.RouterBinding(RID, HOST, 'placeholder-pw', expected_serial=serial)}
    return svc.OperationsService(
        registry, token=token, writes_master=master, enabled_operations=allow,
        unverified_writes=unverified, reboot_approved=reboot, resolve_enabled=resolve,
        state_path=os.path.join(tmp, state_name), gate=gate,
        session_factory=factory, executor=__import__('concurrent.futures',
                                                      fromlist=['ThreadPoolExecutor'])
        .ThreadPoolExecutor(max_workers=2), ops_budget=budget, lock_wait=lock_wait,
    )


def run(coro):
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


class TokenAndRegistryTests(unittest.TestCase):
    def test_token_constant_time_and_empty(self):
        self.assertTrue(svc.token_ok('abc', 'abc'))
        self.assertFalse(svc.token_ok('abc', 'abd'))
        self.assertFalse(svc.token_ok('', 'abc'))
        self.assertFalse(svc.token_ok('abc', None))
        self.assertFalse(svc.token_ok(None, 'abc'))

    def test_registry_from_config_only(self):
        registry = svc.build_registry([(HOST, 'pw')], {HOST: SERIAL})
        self.assertEqual(set(registry), {RID})
        self.assertEqual(registry[RID].expected_serial, SERIAL)
        self.assertEqual(registry[RID].password, 'pw')

    def test_serial_map_parsing(self):
        parsed = svc._parse_serial_map('https://a=1,bad,https://b=2')
        self.assertEqual(parsed, {'https://a': '1', 'https://b': '2'})

    def test_capabilities_have_no_secrets(self):
        with tempfile.TemporaryDirectory() as tmp:
            service = make_service(tmp, sessions=[], master=False)
            blob = json.dumps(service.capabilities())
            self.assertFalse(service.capabilities()['writes_enabled'])
            self.assertTrue(service.capabilities()['token_required'])
        self.assertNotIn(PLACEHOLDER, blob)


class PersistentStoreTests(unittest.TestCase):
    def test_pending_persisted_before_post(self):
        with tempfile.TemporaryDirectory() as tmp:
            state_path = os.path.join(tmp, 'ops_state.json')
            session = FakeSession(
                data={'api/ntwk/WlanGuideBasic?type=notshowpassall': wlanguide(False)},
                store_path=state_path)
            service = make_service(tmp, sessions=[session])
            result = run(service.execute({
                'router': RID, 'operation': 'wifi.80211r', 'operation_id': 'op-a',
                'target': {'vap_id': '1'}, 'fields': {'enabled': True},
            }))
            self.assertEqual(session.pending_seen_before_post, True)
            self.assertIn(result['outcome'], ('verified_changed', 'uncertain', 'applied_unverified'))

    def test_reload_preserves_unresolved_and_resolution(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, 'ops_state.json')
            store = svc.PersistentTransactionStore(path)
            store.begin(ops.TransactionRecord(
                operation_id='op-x', operation='wifi.80211r', payload_hash='p',
                preimage_hash='q', state=ops.Outcome.UNCERTAIN, target={'router_id': RID}))
            reloaded = svc.PersistentTransactionStore(path)
            self.assertIsNotNone(reloaded.unresolved_for(RID, 'wifi.80211r'))
            reloaded.mark_resolved('op-x', 'operator')
            again = svc.PersistentTransactionStore(path)
            self.assertIsNone(again.unresolved_for(RID, 'wifi.80211r'))

    def test_store_file_is_redacted_and_private(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, 'ops_state.json')
            store = svc.PersistentTransactionStore(path)
            store.begin(ops.TransactionRecord(
                operation_id='op-y', operation='wifi.guest.set', payload_hash='h',
                preimage_hash='q', state=ops.Outcome.PENDING, target={'router_id': RID},
                evidence={'readback': {'Enable': True}}))
            with open(path, encoding='utf-8') as handle:
                blob = handle.read()
            self.assertNotIn(PLACEHOLDER, blob)
            self.assertNotIn('password', blob)
            self.assertEqual(oct(os.stat(path).st_mode & 0o777), '0o600')

    def test_corrupt_store_never_blocks_startup(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, 'ops_state.json')
            with open(path, 'w', encoding='utf-8') as handle:
                handle.write('{not json')
            store = svc.PersistentTransactionStore(path)
            self.assertEqual(store.as_dict(), {})


class ValidationTests(unittest.TestCase):
    def _service(self, tmp, **kwargs):
        return make_service(tmp, sessions=[FakeSession()], **kwargs)

    def test_unknown_router(self):
        with tempfile.TemporaryDirectory() as tmp:
            service = self._service(tmp)
            result = run(service.plan({'router': 'nope', 'operation': 'wifi.80211r'}))
        self.assertEqual(result['status'], 'denied')
        self.assertEqual(result['reason'], 'unknown_router')

    def test_unknown_operation(self):
        with tempfile.TemporaryDirectory() as tmp:
            service = self._service(tmp)
            result = run(service.plan({'router': RID, 'operation': 'wifi.magic'}))
        self.assertEqual(result['reason'], 'unknown_operation')

    def test_unknown_top_level_and_field_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            service = self._service(tmp)
            extra = run(service.plan({'router': RID, 'operation': 'wifi.80211r', 'x': 1}))
            badfield = run(service.plan({
                'router': RID, 'operation': 'wifi.80211r',
                'target': {'vap_id': '1'}, 'fields': {'nope': 1}}))
        self.assertEqual(extra['reason'], 'unknown_field')
        self.assertEqual(badfield['reason'], 'unknown_field')

    def test_invalid_operation_id(self):
        with tempfile.TemporaryDirectory() as tmp:
            service = self._service(tmp)
            result = run(service.plan({
                'router': RID, 'operation': 'wifi.80211r', 'operation_id': '',
                'target': {'vap_id': '1'}, 'fields': {'enabled': True}}))
        self.assertEqual(result['reason'], 'invalid_payload')


class PlanDryRunTests(unittest.TestCase):
    def test_plan_never_posts(self):
        with tempfile.TemporaryDirectory() as tmp:
            session = FakeSession(
                data={'api/ntwk/WlanGuideBasic?type=notshowpassall': wlanguide(False)})
            service = make_service(tmp, sessions=[session])
            result = run(service.plan({
                'router': RID, 'operation': 'wifi.80211r',
                'target': {'vap_id': '1'}, 'fields': {'enabled': True}}))
            self.assertEqual(result['status'], 'ok')
            self.assertFalse(result['no_op'])
            self.assertEqual(session.posts, [])
            self.assertTrue(session.closed)

    def test_plan_noop_when_already_desired(self):
        with tempfile.TemporaryDirectory() as tmp:
            session = FakeSession(
                data={'api/ntwk/WlanGuideBasic?type=notshowpassall': wlanguide(True)})
            service = make_service(tmp, sessions=[session])
            result = run(service.plan({
                'router': RID, 'operation': 'wifi.80211r',
                'target': {'vap_id': '1'}, 'fields': {'enabled': True}}))
        self.assertTrue(result['no_op'])

    def test_plan_without_crypto_still_plans_guest(self):
        with tempfile.TemporaryDirectory() as tmp:
            session = FakeSession(data={
                'api/ntwk/guest_network?type=notshowpassall': [
                    {"ID": "g2", "FrequencyBand": "2.4GHz", "EnableFrequency": False,
                     "CanEnableFrequency": True, "SecOpt": "tkip", "WifiSsid": "G"},
                    {"ID": "g5", "FrequencyBand": "5GHz", "EnableFrequency": False,
                     "CanEnableFrequency": True, "SecOpt": "tkip", "WifiSsid": "G"},
                ]})
            service = make_service(tmp, sessions=[session], allow=frozenset({'wifi.guest.set'}))
            result = run(service.plan({
                'router': RID, 'operation': 'wifi.guest.set',
                'fields': {'enabled': True, 'ssid': 'Guest', 'security': 'open'}}))
        self.assertEqual(result['status'], 'ok')
        self.assertFalse(result['secret_involved'])


class ExecuteGateTests(unittest.TestCase):
    def test_default_writes_off(self):
        with tempfile.TemporaryDirectory() as tmp:
            session = FakeSession(
                data={'api/ntwk/WlanGuideBasic?type=notshowpassall': wlanguide(False)})
            service = make_service(tmp, sessions=[session], master=False)
            result = run(service.execute({
                'router': RID, 'operation': 'wifi.80211r',
                'target': {'vap_id': '1'}, 'fields': {'enabled': True}}))
        self.assertEqual(result['outcome'], 'rejected')
        self.assertEqual(result['reason'], 'writes_disabled')
        self.assertEqual(session.posts, [])

    def test_allowlisted_write_posts_exact_dto(self):
        with tempfile.TemporaryDirectory() as tmp:
            data = {'api/ntwk/WlanGuideBasic?type=notshowpassall': wlanguide(False)}

            def mutate(store, path, payload):
                store['api/ntwk/WlanGuideBasic?type=notshowpassall']['WifiConfig'][0][
                    'Dot11REnable'] = True

            session = FakeSession(data=data, mutate=mutate)
            service = make_service(tmp, sessions=[session], master=True)
            result = run(service.execute({
                'router': RID, 'operation': 'wifi.80211r', 'operation_id': 'op-11r',
                'target': {'vap_id': '1'}, 'fields': {'enabled': True}}))
        self.assertEqual(result['outcome'], 'verified_changed')
        post = session.posts[-1]
        self.assertEqual(post['path'], ops.URL_WLAN_GUIDE)
        self.assertEqual(post['payload'], {'Dot11REnable': True})
        self.assertEqual(post['extra'], {'action': '11rSetting'})

    def test_guest_unverified_write_disabled_by_default(self):
        with tempfile.TemporaryDirectory() as tmp:
            session = FakeSession(data={
                'api/ntwk/guest_network?type=notshowpassall': [
                    {"ID": "g2", "FrequencyBand": "2.4GHz", "EnableFrequency": True,
                     "CanEnableFrequency": True, "SecOpt": "tkip", "WifiSsid": "G"},
                    {"ID": "g5", "FrequencyBand": "5GHz", "EnableFrequency": True,
                     "CanEnableFrequency": True, "SecOpt": "tkip", "WifiSsid": "G"},
                ]})
            service = make_service(tmp, sessions=[session], master=True,
                                   allow=frozenset({'wifi.guest.set'}), unverified=False)
            result = run(service.execute({
                'router': RID, 'operation': 'wifi.guest.set',
                'fields': {'enabled': True, 'ssid': 'G', 'security': 'psk',
                           'password': PLACEHOLDER}}))
        self.assertEqual(result['outcome'], 'rejected')
        self.assertEqual(result['reason'], 'unverified_write_disabled')

    def test_login_failure_is_code_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            session = FakeSession(fail_open=True)
            service = make_service(tmp, sessions=[session])
            result = run(service.execute({
                'router': RID, 'operation': 'wifi.80211r',
                'target': {'vap_id': '1'}, 'fields': {'enabled': True}}))
        self.assertEqual(result['status'], 'denied')
        self.assertTrue(result['reason'].startswith('login_'))
        self.assertNotIn(PLACEHOLDER, json.dumps(result))

    def test_cross_operation_lock_survives_new_ids(self):
        with tempfile.TemporaryDirectory() as tmp:
            data = {'api/ntwk/WlanGuideBasic?type=notshowpassall': wlanguide(False)}
            first = FakeSession(data=data,
                                post_error=ops.TransportError('timeout', 'post_send'))
            second = FakeSession(data=data)
            service = make_service(tmp, sessions=[first, second], master=True)
            payload = {'router': RID, 'operation': 'wifi.80211r',
                       'target': {'vap_id': '1'}, 'fields': {'enabled': True}}
            a = run(service.execute(dict(payload, operation_id='id-1')))
            self.assertEqual(a['outcome'], 'uncertain')
            b = run(service.execute(dict(payload, operation_id='id-2')))
            self.assertEqual(b['outcome'], 'rejected')
            self.assertEqual(b['reason'], 'router_operation_locked')
            self.assertEqual(second.posts, [])


class SerializationTests(unittest.TestCase):
    class Pending:
        def done(self):
            return False

    def test_active_session_denies_busy(self):
        with tempfile.TemporaryDirectory() as tmp:
            collector = webcol.Collector()
            collector.ops_pending[HOST] = self.Pending()
            session = FakeSession(
                data={'api/ntwk/WlanGuideBasic?type=notshowpassall': wlanguide(False)})
            service = make_service(tmp, sessions=[session], gate=collector)
            result = run(service.plan({
                'router': RID, 'operation': 'wifi.80211r',
                'target': {'vap_id': '1'}, 'fields': {'enabled': True}}))
        self.assertEqual(result['status'], 'denied')
        self.assertEqual(result['reason'], 'router_busy')

    def test_collector_session_active_covers_ops(self):
        collector = webcol.Collector()
        self.assertFalse(collector.session_active(HOST))
        collector.ops_pending[HOST] = self.Pending()
        self.assertTrue(collector.session_active(HOST))


class ResolveTests(unittest.TestCase):
    def test_resolve_disabled_by_default(self):
        with tempfile.TemporaryDirectory() as tmp:
            service = make_service(tmp, sessions=[])
            result = service.resolve('op-x')
        self.assertEqual(result['reason'], 'resolve_disabled')

    def test_resolve_unlocks(self):
        with tempfile.TemporaryDirectory() as tmp:
            data = {'api/ntwk/WlanGuideBasic?type=notshowpassall': wlanguide(False)}
            first = FakeSession(data=data,
                                post_error=ops.TransportError('timeout', 'post_send'))
            second = FakeSession(data=data)
            service = make_service(tmp, sessions=[first, second], master=True, resolve=True)
            payload = {'router': RID, 'operation': 'wifi.80211r',
                       'target': {'vap_id': '1'}, 'fields': {'enabled': True}}
            run(service.execute(dict(payload, operation_id='id-1')))
            self.assertEqual(service.resolve('id-1')['status'], 'ok')
            result = run(service.execute(dict(payload, operation_id='id-2')))
            self.assertNotEqual(result.get('reason'), 'router_operation_locked')


class SerialBindingTests(unittest.TestCase):
    def test_write_requires_bound_serial_before_login(self):
        with tempfile.TemporaryDirectory() as tmp:
            session = FakeSession(
                data={'api/ntwk/WlanGuideBasic?type=notshowpassall': wlanguide(False)})
            service = make_service(tmp, sessions=[session], master=True, serial=None)
            result = run(service.execute({
                'router': RID, 'operation': 'wifi.80211r',
                'target': {'vap_id': '1'}, 'fields': {'enabled': True}}))
        self.assertEqual(result['status'], 'denied')
        self.assertEqual(result['reason'], 'missing_serial')
        self.assertFalse(session.opened)
        self.assertEqual(session.posts, [])

    def test_dry_run_allowed_without_serial_but_not_eligible(self):
        with tempfile.TemporaryDirectory() as tmp:
            session = FakeSession(
                data={'api/ntwk/WlanGuideBasic?type=notshowpassall': wlanguide(False)})
            service = make_service(tmp, sessions=[session], master=True, serial=None)
            result = run(service.plan({
                'router': RID, 'operation': 'wifi.80211r',
                'target': {'vap_id': '1'}, 'fields': {'enabled': True}}))
        self.assertEqual(result['status'], 'ok')
        self.assertFalse(result['write_eligible'])
        self.assertEqual(session.posts, [])
        self.assertTrue(session.opened)

    def test_write_eligible_with_serial(self):
        with tempfile.TemporaryDirectory() as tmp:
            session = FakeSession(
                data={'api/ntwk/WlanGuideBasic?type=notshowpassall': wlanguide(False)})
            service = make_service(tmp, sessions=[session], master=True)
            result = run(service.plan({
                'router': RID, 'operation': 'wifi.80211r',
                'target': {'vap_id': '1'}, 'fields': {'enabled': True}}))
        self.assertTrue(result['write_eligible'])

    def test_wrong_serial_is_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            session = FakeSession(
                data={}, device={"SerialNumber": "OTHER-SERIAL", "SoftwareVersion": "x"},
                expected_serial=SERIAL)
            service = make_service(tmp, sessions=[session], master=True)
            result = run(service.execute({
                'router': RID, 'operation': 'wifi.80211r',
                'target': {'vap_id': '1'}, 'fields': {'enabled': True}}))
        self.assertEqual(result['status'], 'denied')
        self.assertEqual(result['reason'], 'login_serial-mismatch')
        self.assertEqual(session.posts, [])

    def test_huawei_session_serial_mismatch_closes(self):
        class FakeClient:
            def __init__(self, serial):
                self.serial = serial
                self.logged_in = False
                self.public_key = {"rsan": "ab", "rsae": "10001"}
                self.public_key_verified = True

            def login(self):
                self.logged_in = True

            def _get_json(self, path, stage):
                return {"SerialNumber": self.serial, "SoftwareVersion": "fw"}

            def logout(self):
                self.logged_in = False
                return "ok"

        binding = svc.RouterBinding(RID, HOST, 'pw', expected_serial=SERIAL)
        good = FakeClient(SERIAL)
        session = svc.HuaweiSession(good, binding)
        identity = session.open()
        self.assertEqual(identity['serial'], SERIAL)
        self.assertEqual(session.close(), "ok")

        wrong = FakeClient("OTHER-SERIAL")
        bad = svc.HuaweiSession(wrong, binding)
        with self.assertRaises(svc.SessionIdentityError):
            bad.open()
        self.assertFalse(wrong.logged_in)

    def test_real_client_is_built_with_serial_bound(self):
        # A real HuaweiDirectClient path must not be reachable for a write
        # without a bound serial; the guard runs before session construction.
        with tempfile.TemporaryDirectory() as tmp:
            service = make_service(tmp, sessions=[], master=True, serial=None)
            self.assertFalse(service._write_eligible(
                svc.RouterBinding(RID, HOST, 'pw'), 'wifi.80211r', {'enabled': True}))
            self.assertTrue(service._write_eligible(
                svc.RouterBinding(RID, HOST, 'pw', expected_serial=SERIAL),
                'wifi.80211r', {'enabled': True}))


GUEST_DATA = {
    'api/ntwk/guest_network?type=notshowpassall': [
        {"ID": "g2", "FrequencyBand": "2.4GHz", "EnableFrequency": True,
         "CanEnableFrequency": True, "SecOpt": "tkip", "WifiSsid": "G"},
        {"ID": "g5", "FrequencyBand": "5GHz", "EnableFrequency": True,
         "CanEnableFrequency": True, "SecOpt": "tkip", "WifiSsid": "G"},
    ]
}


class RouterWideLockTests(unittest.TestCase):
    def test_unresolved_guest_blocks_twt_across_restart(self):
        with tempfile.TemporaryDirectory() as tmp:
            guest = FakeSession(data=dict(GUEST_DATA),
                                post_error=ops.TransportError('timeout', 'post_send'))
            first = make_service(tmp, sessions=[guest], master=True,
                                 allow=frozenset({'wifi.guest.set'}), unverified=True)
            r1 = run(first.execute({
                'router': RID, 'operation': 'wifi.guest.set', 'operation_id': 'g1',
                'fields': {'enabled': True, 'ssid': 'G', 'security': 'psk',
                           'password': PLACEHOLDER}}))
            self.assertEqual(r1['outcome'], 'uncertain')

            twt = FakeSession(data={'api/ntwk/WlanGuideBasic?type=notshowpassall': wlanguide(False)})
            restarted = make_service(tmp, sessions=[twt], master=True,
                                     allow=frozenset({'wifi.twt'}))
            r2 = run(restarted.execute({
                'router': RID, 'operation': 'wifi.twt', 'operation_id': 't1',
                'target': {'vap_id': '1'}, 'fields': {'enabled': True}}))
        self.assertEqual(r2['outcome'], 'rejected')
        self.assertEqual(r2['reason'], 'router_operation_locked')
        self.assertEqual(twt.posts, [])

    def test_unresolved_twt_blocks_guest(self):
        with tempfile.TemporaryDirectory() as tmp:
            twt = FakeSession(
                data={'api/ntwk/WlanGuideBasic?type=notshowpassall': wlanguide(False)},
                post_error=ops.TransportError('timeout', 'post_send'))
            first = make_service(tmp, sessions=[twt], master=True,
                                 allow=frozenset({'wifi.twt'}))
            r1 = run(first.execute({
                'router': RID, 'operation': 'wifi.twt', 'operation_id': 't1',
                'target': {'vap_id': '1'}, 'fields': {'enabled': True}}))
            self.assertEqual(r1['outcome'], 'uncertain')

            guest = FakeSession(data=dict(GUEST_DATA))
            second = make_service(tmp, sessions=[guest], master=True,
                                  allow=frozenset({'wifi.guest.set'}), unverified=True)
            r2 = run(second.execute({
                'router': RID, 'operation': 'wifi.guest.set', 'operation_id': 'g1',
                'fields': {'enabled': True, 'ssid': 'G', 'security': 'open'}}))
        self.assertEqual(r2['reason'], 'router_operation_locked')
        self.assertEqual(guest.posts, [])

    def test_resolve_clears_router_wide_lock(self):
        with tempfile.TemporaryDirectory() as tmp:
            guest = FakeSession(data=dict(GUEST_DATA),
                                post_error=ops.TransportError('timeout', 'post_send'))
            service = make_service(tmp, sessions=[guest, FakeSession(
                data={'api/ntwk/WlanGuideBasic?type=notshowpassall': wlanguide(False)})],
                master=True, allow=frozenset({'wifi.guest.set', 'wifi.twt'}),
                unverified=True, resolve=True)
            run(service.execute({
                'router': RID, 'operation': 'wifi.guest.set', 'operation_id': 'g1',
                'fields': {'enabled': True, 'ssid': 'G', 'security': 'psk',
                           'password': PLACEHOLDER}}))
            self.assertEqual(service.resolve('g1')['status'], 'ok')
            result = run(service.execute({
                'router': RID, 'operation': 'wifi.twt', 'operation_id': 't1',
                'target': {'vap_id': '1'}, 'fields': {'enabled': True}}))
        self.assertNotEqual(result.get('reason'), 'router_operation_locked')


class StartupAndLedgerTests(unittest.TestCase):
    def test_from_env_explicit_state_path_no_duplicate(self):
        with tempfile.TemporaryDirectory() as tmp:
            env = {'HW_ROUTER_SERIALS': HOST + '=' + SERIAL, 'HW_OPERATIONS_TOKEN': TOKEN}
            with unittest.mock.patch.dict(os.environ, env, clear=False):
                service = svc.OperationsService.from_env(
                    [(HOST, 'pw')], state_path=os.path.join(tmp, 's.json'))
        self.assertEqual(service.token, TOKEN)
        self.assertTrue(service.store.healthy)
        self.assertEqual(set(service.registry), {RID})

    def test_from_env_uses_env_state_when_not_passed(self):
        with tempfile.TemporaryDirectory() as tmp:
            env = {'HW_OPERATIONS_STATE': os.path.join(tmp, 'env.json')}
            with unittest.mock.patch.dict(os.environ, env, clear=False):
                service = svc.OperationsService.from_env([(HOST, 'pw')])
        self.assertIsInstance(service.store, svc.PersistentTransactionStore)

    def test_unreadable_ledger_blocks_writes_but_serves_reads(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, 'ops_state.json')
            with open(path, 'w', encoding='utf-8') as handle:
                handle.write('{truncated')
            session = FakeSession(
                data={'api/ntwk/WlanGuideBasic?type=notshowpassall': wlanguide(False)})
            service = make_service(tmp, sessions=[session], master=True)
        self.assertFalse(service.store.healthy)
        self.assertFalse(service.capabilities()['ledger_healthy'])
        self.assertEqual(service.capabilities()['schema_version'], 1)

    def test_bad_record_is_atomic_no_partial_load(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, 'ops_state.json')
            payload = {
                "schema_version": 1,
                "records": {
                    "good": {"operation": "wifi.twt", "state": "uncertain",
                             "payload_hash": "p", "preimage_hash": "q",
                             "target": {}, "evidence": {}},
                    "bad": {"operation": "x"},
                },
                "approvals": {},
            }
            with open(path, 'w', encoding='utf-8') as handle:
                json.dump(payload, handle)
            store = svc.PersistentTransactionStore(path)
        self.assertFalse(store.healthy)
        self.assertEqual(store.as_dict(), {})

    def test_missing_file_is_healthy_first_boot(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = svc.PersistentTransactionStore(os.path.join(tmp, 'new.json'))
        self.assertTrue(store.healthy)
        self.assertEqual(store.as_dict(), {})

    def test_persist_failure_aborts_before_post(self):
        with tempfile.TemporaryDirectory() as tmp:
            session = FakeSession(
                data={'api/ntwk/WlanGuideBasic?type=notshowpassall': wlanguide(False)})
            service = make_service(tmp, sessions=[session], master=True)

            def boom():
                raise ops.LedgerError('ledger_write')

            service.store._flush = boom
            result = run(service.execute({
                'router': RID, 'operation': 'wifi.80211r',
                'target': {'vap_id': '1'}, 'fields': {'enabled': True}}))
        self.assertEqual(result['reason'], 'ledger_invalid')
        self.assertEqual(session.posts, [])

    def test_final_persist_failure_degrades_to_uncertain(self):
        with tempfile.TemporaryDirectory() as tmp:
            data = {'api/ntwk/WlanGuideBasic?type=notshowpassall': wlanguide(False)}

            def mutate(store, path, payload):
                store['api/ntwk/WlanGuideBasic?type=notshowpassall']['WifiConfig'][0][
                    'Dot11REnable'] = True

            session = FakeSession(data=data, mutate=mutate)
            service = make_service(tmp, sessions=[session], master=True)
            real_flush = service.store._flush
            calls = {'n': 0}

            def flaky():
                calls['n'] += 1
                if calls['n'] >= 2:
                    raise ops.LedgerError('ledger_write')
                return real_flush()

            service.store._flush = flaky
            result = run(service.execute({
                'router': RID, 'operation': 'wifi.80211r', 'operation_id': 'deg',
                'target': {'vap_id': '1'}, 'fields': {'enabled': True}}))
        self.assertEqual(result['outcome'], 'uncertain')
        self.assertEqual(len(session.posts), 1)


class RebootApprovalTests(unittest.TestCase):
    def test_one_use_survives_restart(self):
        with tempfile.TemporaryDirectory() as tmp:
            session = FakeSession(data={})
            service = make_service(tmp, sessions=[session], master=True,
                                   allow=frozenset({'system.reboot'}), reboot=True)
            issued = service.issue_reboot_approval(RID, ttl_seconds=100)
            self.assertEqual(issued['status'], 'ok')
            approval = issued['approval_id']
            first = run(service.execute({
                'router': RID, 'operation': 'system.reboot', 'approval_id': approval}))
            self.assertIn(first['outcome'], ('uncertain', 'verified_changed', 'failed'))

            restart_session = FakeSession(data={})
            restarted = make_service(tmp, sessions=[restart_session], master=True,
                                     allow=frozenset({'system.reboot'}), reboot=True)
            second = run(restarted.execute({
                'router': RID, 'operation': 'system.reboot', 'approval_id': approval}))
        self.assertEqual(second['reason'], 'reboot_approval_required')
        self.assertEqual(restart_session.posts, [])

    def test_approval_required_when_not_approved(self):
        with tempfile.TemporaryDirectory() as tmp:
            session = FakeSession(data={})
            service = make_service(tmp, sessions=[session], master=True,
                                   allow=frozenset({'system.reboot'}), reboot=False)
            issued = service.issue_reboot_approval(RID)
            result = run(service.execute({
                'router': RID, 'operation': 'system.reboot', 'approval_id': 'x'}))
        self.assertEqual(issued['reason'], 'reboot_approval_disabled')
        self.assertEqual(result['reason'], 'reboot_approval_required')
        self.assertEqual(session.posts, [])

    def test_approvals_bound_per_router(self):
        with tempfile.TemporaryDirectory() as tmp:
            registry = {
                'r1': svc.RouterBinding('r1', HOST, 'pw', expected_serial=SERIAL),
            'r2': svc.RouterBinding('r2', 'https://192.0.2.10', 'pw', expected_serial='S2'),
            }
            service = svc.OperationsService(
                registry, token=TOKEN, writes_master=True,
                enabled_operations=frozenset({'system.reboot'}), reboot_approved=True,
                state_path=os.path.join(tmp, 'ops.json'),
                session_factory=lambda b: FakeSession(data={}),
                executor=ThreadPoolExecutor(max_workers=2))
            a1 = service.issue_reboot_approval('r1')['approval_id']
            a2 = service.issue_reboot_approval('r2')['approval_id']
            now = time.time()
            self.assertTrue(service.store.reserve_approval(a1, 'r1', 'system.reboot', now))
            self.assertFalse(service.store.reserve_approval(a1, 'r2', 'system.reboot', now))
            self.assertTrue(service.store.reserve_approval(a2, 'r2', 'system.reboot', now))


class DependencyGateTests(unittest.TestCase):
    def test_guest_secret_not_eligible_without_rsa(self):
        with tempfile.TemporaryDirectory() as tmp:
            service = make_service(tmp, sessions=[], master=True,
                                   allow=frozenset({'wifi.guest.set'}), unverified=True)
            binding = service.registry[RID]
            with unittest.mock.patch.object(svc.operations, 'crypto_available',
                                            lambda: False):
                secret_ok = service._write_eligible(
                    binding, 'wifi.guest.set', {'security': 'psk'})
                open_ok = service._write_eligible(
                    binding, 'wifi.guest.set', {'security': 'open'})
                caps = service.capabilities()
        self.assertFalse(secret_ok)
        self.assertTrue(open_ok)
        self.assertFalse(caps['rsa_backend_available'])
        self.assertTrue(caps['write_eligible_requires_serial'])


class DurableStoreGateTests(unittest.TestCase):
    def test_volatile_store_rejects_writes_but_allows_dry_run(self):
        session = FakeSession(
            data={'api/ntwk/WlanGuideBasic?type=notshowpassall': wlanguide(False)})
        registry = {RID: svc.RouterBinding(RID, HOST, 'pw', expected_serial=SERIAL)}
        service = svc.OperationsService(
            registry, token=TOKEN, writes_master=True,
            enabled_operations=frozenset({'wifi.80211r'}),
            session_factory=lambda b: session,
            executor=ThreadPoolExecutor(max_workers=2))
        self.assertFalse(service.store.durable)
        write = run(service.execute({
            'router': RID, 'operation': 'wifi.80211r',
            'target': {'vap_id': '1'}, 'fields': {'enabled': True}}))
        self.assertEqual(write['reason'], 'ledger_not_durable')
        self.assertFalse(session.opened)
        plan = run(service.plan({
            'router': RID, 'operation': 'wifi.80211r',
            'target': {'vap_id': '1'}, 'fields': {'enabled': True}}))
        self.assertEqual(plan['status'], 'ok')
        self.assertFalse(plan['write_eligible'])
        self.assertEqual(plan['write_blocked_reason'], 'ledger_not_durable')

    def test_absent_state_dir_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            blocker = os.path.join(tmp, 'not-a-dir')
            with open(blocker, 'w', encoding='utf-8') as handle:
                handle.write('x')
            session = FakeSession(
                data={'api/ntwk/WlanGuideBasic?type=notshowpassall': wlanguide(False)})
            service = make_service(tmp, sessions=[session], master=True,
                                   state_name=os.path.join('not-a-dir', 'ops.json'))
            write = run(service.execute({
                'router': RID, 'operation': 'wifi.80211r',
                'target': {'vap_id': '1'}, 'fields': {'enabled': True}}))
        self.assertFalse(service.store.healthy)
        self.assertEqual(write['reason'], 'ledger_invalid')
        self.assertFalse(session.opened)


class _FakeGate:
    def __init__(self):
        self.blocked = set()
        self.failures = []
        self.active = set()

    def lock(self, host):
        return asyncio.Lock()

    def session_active(self, host):
        return host in self.active

    def credential_blocked(self, host):
        return host in self.blocked

    def record_credential_failure(self, host):
        self.failures.append(host)

    def register_ops_future(self, host, future):
        pass

    def clear_ops_future(self, host, future):
        pass


class CredentialCircuitTests(unittest.TestCase):
    def test_blocked_gate_denies_plan_before_login(self):
        with tempfile.TemporaryDirectory() as tmp:
            gate = _FakeGate()
            gate.blocked.add(HOST)
            session = FakeSession(
                data={'api/ntwk/WlanGuideBasic?type=notshowpassall': wlanguide(False)})
            service = make_service(tmp, sessions=[session], master=True, gate=gate)
            plan = run(service.plan({
                'router': RID, 'operation': 'wifi.80211r',
                'target': {'vap_id': '1'}, 'fields': {'enabled': True}}))
            self.assertEqual(plan['status'], 'denied')
            self.assertEqual(plan['reason'], 'credential_blocked')
            self.assertFalse(session.opened)

    def test_login_failure_opens_circuit_once(self):
        with tempfile.TemporaryDirectory() as tmp:
            gate = _FakeGate()
            session = FakeSession(fail_open=True)
            service = make_service(tmp, sessions=[session], master=True, gate=gate)
            first = run(service.plan({
                'router': RID, 'operation': 'wifi.80211r',
                'target': {'vap_id': '1'}, 'fields': {'enabled': True}}))
            self.assertEqual(first['reason'], 'login_credentials')
            self.assertNotIn('_login_blocking', first)
            self.assertEqual(gate.failures, [HOST])
            gate.blocked.add(HOST)
            again = run(service.plan({
                'router': RID, 'operation': 'wifi.80211r',
                'target': {'vap_id': '1'}, 'fields': {'enabled': True}}))
            self.assertEqual(again['reason'], 'credential_blocked')
            self.assertEqual(gate.failures, [HOST])

    def test_other_router_not_blocked(self):
        with tempfile.TemporaryDirectory() as tmp:
            gate = _FakeGate()
            gate.blocked.add(HOST)
            r2 = 'r2'
            registry = {
                RID: svc.RouterBinding(RID, HOST, 'pw', expected_serial=SERIAL),
            r2: svc.RouterBinding(r2, 'https://192.0.2.10', 'pw', expected_serial='S2'),
            }
            session = FakeSession(
                data={'api/ntwk/WlanGuideBasic?type=notshowpassall': wlanguide(False)})
            service = svc.OperationsService(
                registry, token=TOKEN, writes_master=True,
                enabled_operations=frozenset({'wifi.80211r'}), gate=gate,
                state_path=os.path.join(tmp, 'ops.json'),
                session_factory=lambda b: session,
                executor=ThreadPoolExecutor(max_workers=2))
            blocked = run(service.plan({
                'router': RID, 'operation': 'wifi.80211r',
                'target': {'vap_id': '1'}, 'fields': {'enabled': True}}))
            allowed = run(service.plan({
                'router': r2, 'operation': 'wifi.80211r',
                'target': {'vap_id': '1'}, 'fields': {'enabled': True}}))
        self.assertEqual(blocked['reason'], 'credential_blocked')
        self.assertNotEqual(allowed.get('reason'), 'credential_blocked')
        self.assertTrue(session.opened)


class HttpRoutingTests(unittest.TestCase):
    def _serve(self, service):
        loop = asyncio.new_event_loop()
        thread = threading.Thread(target=loop.run_forever, daemon=True)
        thread.start()
        service.set_loop(loop)
        collector = webcol.Collector()
        server = ThreadingHTTPServer(('127.0.0.1', 0), webcol.handler(collector, service, loop))
        server.daemon_threads = True
        server_thread = threading.Thread(target=server.serve_forever, daemon=True)
        server_thread.start()
        return server, loop, thread

    def _request(self, server, method, path, body=None, token=None, content_type='application/json'):
        url = 'http://127.0.0.1:%d%s' % (server.server_address[1], path)
        data = None if body is None else json.dumps(body).encode()
        request = urllib.request.Request(url, data=data, method=method)
        if content_type is not None:
            request.add_header('Content-Type', content_type)
        if token is not None:
            request.add_header('Authorization', 'Bearer ' + token)
        try:
            with urllib.request.urlopen(request, timeout=10) as response:
                return response.status, json.loads(response.read().decode())
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read().decode())

    def test_http_endpoints(self):
        with tempfile.TemporaryDirectory() as tmp:
            session = FakeSession(
                data={'api/ntwk/WlanGuideBasic?type=notshowpassall': wlanguide(False)})
            service = make_service(tmp, sessions=[session, FakeSession(
                data={'api/ntwk/WlanGuideBasic?type=notshowpassall': wlanguide(False)})],
                master=False)
            server, loop, thread = self._serve(service)
            try:
                status, caps = self._request(server, 'GET', '/capabilities')
                self.assertEqual(status, 200)
                self.assertIn('operations', caps)

                status, _ = self._request(server, 'GET', '/health')
                self.assertIn(status, (200, 503))

                status, body = self._request(server, 'POST', '/operations', {
                    'router': RID, 'operation': 'wifi.80211r',
                    'target': {'vap_id': '1'}, 'fields': {'enabled': True}})
                self.assertEqual(status, 401)

                status, body = self._request(server, 'POST', '/operations/plan', {
                    'router': RID, 'operation': 'wifi.80211r',
                    'target': {'vap_id': '1'}, 'fields': {'enabled': True}},
                    token=TOKEN)
                self.assertEqual(status, 200)
                self.assertEqual(body['status'], 'ok')

                status, body = self._request(server, 'POST', '/operations', {
                    'router': RID, 'operation': 'wifi.80211r',
                    'target': {'vap_id': '1'}, 'fields': {'enabled': True}},
                    token=TOKEN)
                self.assertEqual(status, 403)
                self.assertEqual(body['outcome'], 'rejected')

                status, body = self._request(server, 'POST', '/operations/plan',
                                             {'router': RID, 'bogus': 1}, token=TOKEN)
                self.assertEqual(status, 400)
                self.assertEqual(body['reason'], 'unknown_field')

                status, _ = self._request(server, 'POST', '/operations/plan',
                                          {'router': RID}, token=TOKEN,
                                          content_type='text/plain')
                self.assertEqual(status, 400)

                status, _ = self._request(server, 'GET', '/operations/unknown-id')
                self.assertEqual(status, 401)

                status, body = self._request(server, 'GET', '/operations/unknown-id',
                                             token=TOKEN)
                self.assertEqual(status, 404)
            finally:
                server.shutdown()
                server.server_close()
                loop.call_soon_threadsafe(loop.stop)
                thread.join(timeout=5)
                loop.close()


if __name__ == '__main__':
    unittest.main()
