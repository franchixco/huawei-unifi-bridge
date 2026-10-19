"""Local integration checks: config contracts, optional-helper isolation, locks."""

import json
import os
import re
import shutil
import tempfile
import threading
import time
import unittest
import unittest.mock
from pathlib import Path
from types import SimpleNamespace

from huawei_bridge.__main__ import Application
from huawei_bridge.metrics import CounterTracker

WEBROOT = Path(__file__).resolve().parents[1]


class ConfigContractTests(unittest.TestCase):
    def test_compose_forwards_operations_env_with_safe_defaults(self):
        compose = (WEBROOT / 'compose.yml').read_text()
        for expected in ('HW_OPERATIONS_TOKEN: "${HW_OPERATIONS_TOKEN:-}"',
                         'HW_OPERATIONS_WRITES: "${HW_OPERATIONS_WRITES:-0}"',
                         'HW_OPERATIONS_ALLOW: "${HW_OPERATIONS_ALLOW:-}"',
                         'HW_OPERATIONS_UNVERIFIED_WRITES: "${HW_OPERATIONS_UNVERIFIED_WRITES:-0}"',
                         'HW_OPERATIONS_REBOOT_APPROVED: "${HW_OPERATIONS_REBOOT_APPROVED:-0}"',
                         'HW_OPERATIONS_RESOLVE: "${HW_OPERATIONS_RESOLVE:-0}"',
                         'HW_OPERATIONS_STATE: "/data/operations_state.json"',
                         'HW_ROUTER_SERIALS: "${HW_ROUTER_SERIALS:-}"'):
            self.assertIn(expected, compose)
        self.assertIn('WEBENRICH_VERIFY_TLS: "${WEBENRICH_VERIFY_TLS:-true}"', compose)
        self.assertIn('webcol-data:/data', compose)

    def test_env_example_is_placeholder_only_and_fail_closed(self):
        example = (WEBROOT / '.env.example').read_text()
        self.assertRegex(example, r'(?m)^HW_OPERATIONS_TOKEN=$')
        self.assertRegex(example, r'(?m)^HW_OPERATIONS_WRITES=0$')
        self.assertRegex(example, r'(?m)^HW_OPERATIONS_REBOOT_APPROVED=0$')
        self.assertRegex(example, r'(?m)^HW_OPERATIONS_RESOLVE=0$')
        self.assertRegex(example, r'(?m)^HW_OPERATIONS_UNVERIFIED_WRITES=0$')
        self.assertRegex(example, r'(?m)^HUAWEI_CONTROL_IP=$')
        self.assertNotIn('never-persist', example)
        self.assertIsNone(re.search(r'(?m)^HW_OPERATIONS_TOKEN=\S', example))

    def test_no_secret_looking_values_in_public_configs(self):
        for name in ('.env.example', 'compose.yml'):
            text = (WEBROOT / name).read_text()
            for pattern in (r'(?i)password=\S', r'sk-[A-Za-z0-9]{8}', r'(?i)secret=\S'):
                self.assertIsNone(re.search(pattern, text), name)


def app_in_tempdir(testcase):
    directory = tempfile.TemporaryDirectory()
    testcase.addCleanup(directory.cleanup)
    patcher = unittest.mock.patch.dict(os.environ, {'STATE_DIR': directory.name,
                                                    'UNIFI_WLAN_MAP': '{}',
                                                    'HUAWEI_CONTROL_IP': ''}, clear=False)
    patcher.start()
    testcase.addCleanup(patcher.stop)
    app = Application()
    testcase.addCleanup(app.close)
    return app


class OptionalHelperIsolationTests(unittest.TestCase):
    app: Application
    calls: list

    def setUp(self):
        self.app = app_in_tempdir(self)
        self.calls = []

    def _http(self, payload=None, fail=False):
        calls = self.calls
        class Response:
            def __init__(self, body):
                self._body = body
            def read(self, size=-1):
                return self._body
            def __enter__(self):
                return self
            def __exit__(self, *args):
                return False
        def open_request(request, timeout=None):
            calls.append(request.full_url)
            if fail:
                raise OSError('helper down')
            return Response(json.dumps(payload).encode())
        return SimpleNamespace(open=open_request)

    def test_failing_helper_backs_off_instead_of_hitting_every_snapshot(self):
        setattr(self.app, 'http', self._http(fail=True))
        self.assertIsNone(self.app.web_enrichment())
        self.assertEqual(len(self.calls), 1)
        self.assertIsNone(self.app.web_enrichment())
        self.assertEqual(len(self.calls), 1)
        self.assertIn('/enrich', self.app.web_backoff)

    def test_success_is_cached_for_the_ttl(self):
        setattr(self.app, 'http', self._http(payload={'by_mac': {}}))
        self.assertEqual(self.app.web_enrichment(), {'by_mac': {}})
        self.assertEqual(self.app.web_enrichment(), {'by_mac': {}})
        self.assertEqual(len(self.calls), 1)

    def test_failing_helpers_do_not_break_snapshot_or_inform_state(self):
        setattr(self.app, 'http', self._http(fail=True))
        snapshot = self.app.snapshot()
        self.assertIn('aps', snapshot)
        self.assertEqual(snapshot['identity_contract']['trust'], 'ip+serial')
        self.assertEqual(self.app.unifi.status, {})

    def test_operations_absence_is_isolated_from_telemetry(self):
        self.assertEqual(getattr(self.app, 'service', None), None)
        snapshot = self.app.snapshot()
        self.assertIsInstance(snapshot.get('warnings'), list)


class CounterTrackerConcurrencyTests(unittest.TestCase):
    def test_shared_tracker_is_monotonic_under_threads(self):
        tracker = CounterTracker()
        errors = []

        def worker(seed):
            try:
                for tick in range(300):
                    tracker.update('mac-%d' % (seed % 4), 'tx_kb', tick, float(tick))
                    tracker.annotate({'mac': 'mac-%d' % (seed % 4), 'tx_kb': tick}, float(tick))
            except Exception as exc:  # noqa: BLE001 - asserted below
                errors.append(exc)

        threads = [threading.Thread(target=worker, args=(index,)) for index in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(errors, [])
        for key, entry in tracker._last.items():
            self.assertGreaterEqual(entry['value'], 0)
            self.assertGreaterEqual(entry['resets'], 0)


class WebcolProvenanceContractTests(unittest.TestCase):
    def test_router_and_client_expose_observed_timestamp_and_serial(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location('webcol_mod', WEBROOT / 'webcol' / 'webcol.py')
        webcol = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(webcol)
        result = {'ok': True, 'version': 'V', 'transport': 'direct',
                  'device': {'serial_number': 'SER-1', 'model': 'WUKUN-BE32-40'},
                  'clients': [{'mac': 'aa:bb:cc:dd:ee:01'}],
                  'ssids': [{'band': '5g', 'ssid': 'ExampleSSID'}], 'inventory': {'profiles': []}}
        with unittest.mock.patch.object(webcol, 'routers', return_value=[]):
            webcol.merge_into_data('https://192.0.2.11', result)
        view = webcol.snapshot()['routers']['https://192.0.2.11']
        self.assertEqual(view['serial'], 'SER-1')
        self.assertIsNotNone(view['observed_at'])
        self.assertEqual(webcol.snapshot()['by_mac']['AA:BB:CC:DD:EE:01']['_serial'], 'SER-1')


class ConcurrentRegistryTests(unittest.TestCase):
    def _device(self, extra_radios=()):
        wlans = {'1': {'SSID': {'_value': 'A'}, 'Channel': {'_value': 1}, 'Enable': {'_value': True},
                       'BSSID': {'_value': '02:00:00:00:00:13'}, 'AssociatedDevice': {}}}
        for index, path in enumerate(extra_radios):
            wlans[path] = {'SSID': {'_value': 'X%d' % index}, 'Channel': {'_value': 6},
                           'Enable': {'_value': True}, 'BSSID': {'_value': '02:00:00:00:00:14'},
                           'AssociatedDevice': {}}
        return {'_id': 'SYNTH-AP-1',
                '_deviceId': {'_Manufacturer': 'Huawei', '_ProductClass': 'WUKUN-BE32'},
                '_lastInform': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
                'InternetGatewayDevice': {
                    'ManagementServer': {'ConnectionRequestURL': {'_value': 'https://192.0.2.11:7547/cb'}},
                    'DeviceInfo': {'SoftwareVersion': {'_value': '4.2.0.53'}},
                    'LANDevice': {'1': {'WLANConfiguration': wlans}}}}

    def test_concurrent_snapshots_do_not_lose_registry_slots(self):
        directory = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, directory, ignore_errors=True)
        with unittest.mock.patch.dict(os.environ, {'STATE_DIR': directory,
                                                   'UNIFI_WLAN_MAP': '{}',
                                                   'HUAWEI_CONTROL_IP': ''}, clear=False):
            app = Application()
            self.addCleanup(app.close)
            app.devices = [self._device(('3', '4'))]
            app.web_enrichment = lambda: None
            app.web_inventory = lambda: None
            results = []

            def worker():
                results.append(app.snapshot())

            threads = [threading.Thread(target=worker) for _ in range(6)]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join()
            self.assertEqual(len(results), 6)
            slots = app.registry['aps']['SYNTH-AP-1']['slots']
            self.assertEqual(sorted(int(key) for key in slots), [0, 1, 2])
            for result in results:
                self.assertEqual(result['inventory']['schema_version'], 2)


def _load(name, filename):
    import importlib.util
    spec = importlib.util.spec_from_file_location(name, WEBROOT / 'webcol' / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class BrowserlessNormalizationTests(unittest.TestCase):
    SERIAL = 'SYNTHSN0001'

    def raw(self, **overrides):
        payload = {
            'deviceinfo': {'SoftwareVersion': '4.2.0.53', 'DeviceName': 'Huawei',
                           'ModelName': 'WUKUN-BE32', 'SerialNumber': self.SERIAL,
                           'UpTime': 42407},
            'hostinfo': [{'Active': True, 'phyMode': '802.11ax',
                          'MACAddress': 'aa:bb:cc:dd:ee:01', 'IPAddress': '192.0.2.50',
                          'HostName': 'laptop', 'Frequency': '5GHz', 'Layer2Interface': 'SSID1',
                          'staRssi': -50, 'rate': 866.7, 'TxKBytes': 5, 'RxKBytes': 9}],
            'wifi': {'WifiConfig': [
                {'FrequencyBand': '2.4G', 'WifiSsid': 'ExampleSSID', 'WifiEnable': True,
                 'Channel': 1, 'WMMEnable': True, 'WifiType': 'primary', 'ID': 1,
                 'TransmitPower': '100%', 'WlanStandard': 'b/g/n/ax'}]},
            'guest': [{'WifiSsid': 'GuestExample'}],
        }
        payload.update(overrides)
        return payload

    def test_fallback_produces_direct_schema_and_survives_bridge_trust(self):
        webcol = _load('webcol_mod_norm', 'webcol.py')
        inventory_bridge = __import__('huawei_bridge.inventory', fromlist=['*'])
        normalized = webcol.normalize_browserless(self.raw())
        self.assertIsNotNone(normalized)
        self.assertEqual(normalized['device']['serial_number'], self.SERIAL)
        self.assertEqual(normalized['version'], '4.2.0.53')
        self.assertEqual(normalized['clients'][0]['negotiated_rate'], 866.7)
        self.assertTrue(normalized['inventory']['profiles'][0]['native_id'])
        self.assertTrue(webcol.valid_fallback(normalized))
        with unittest.mock.patch.object(webcol, 'routers', return_value=[]):
            webcol.merge_into_data('https://192.0.2.11', normalized)
        view = webcol.snapshot()['routers']['https://192.0.2.11']
        self.assertEqual(view['serial'], self.SERIAL)
        self.assertIsNotNone(view['observed_at'])
        ap = {'id': 'OEM-WUKUN-BE32-' + self.SERIAL, 'ip': '192.0.2.11', 'online': True, 'radios': []}
        trusted = inventory_bridge.filter_inventory([ap], {'routers': {view['router_ip']: view}},
                                                    now=view['observed_at'])
        self.assertIn('192.0.2.11', trusted['routers'])
        kept = inventory_bridge.filter_enrichment([ap], webcol.snapshot(), now=view['observed_at'])
        self.assertIn('AA:BB:CC:DD:EE:01', kept['by_mac'])

    def test_malformed_raw_is_never_a_valid_collection(self):
        webcol = _load('webcol_mod_norm2', 'webcol.py')
        for raw in (None, {}, {'deviceinfo': {}, 'hostinfo': [], 'wifi': {}},
                    self.raw(hostinfo='x'), self.raw(wifi={'WifiConfig': 'x'}),
                    self.raw(deviceinfo={'SoftwareVersion': 'V'})):
            self.assertIsNone(webcol.normalize_browserless(raw))
        empty_ok = self.raw(hostinfo=[])
        empty_ok['hostinfo'] = []
        normalized = webcol.normalize_browserless(empty_ok)
        self.assertIsNotNone(normalized)  # A valid empty HostInfo array is legitimate.
        self.assertEqual(normalized['clients'], [])

    def test_fallback_inventory_is_built_once_without_losing_radio_settings(self):
        webcol = _load('webcol_mod_norm_settings', 'webcol.py')
        normalized = webcol.normalize_browserless(self.raw())
        collector = webcol.Collector()
        with unittest.mock.patch.object(webcol.inventory, 'load_state', return_value=None), \
                unittest.mock.patch.object(webcol.inventory, 'save_state', return_value=True):
            result = collector.build_inventory(normalized)
        profile = result['inventory']['profiles'][0]
        self.assertEqual(profile['channel']['configured'], 1)
        self.assertFalse(profile['channel']['configured_is_auto'])
        self.assertEqual(profile['power']['reported'], 100)
        self.assertEqual(profile['power']['unit'], 'percent')
        self.assertTrue(profile['native_id'])


if __name__ == '__main__':
    unittest.main()
