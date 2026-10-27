"""Offline tests for the read-only WEB-ONLY provider (Huawei AX3 / WS7200)."""

import contextlib
import importlib.util
import json
import os
import shutil
import tempfile
import time
import unittest
import unittest.mock
from pathlib import Path

from huawei_bridge import webonly
from huawei_bridge.collector import normalize, virtual_mac
from huawei_bridge.control import Control
from huawei_bridge.unifi import payload

ROOT = Path(__file__).resolve().parent.parent
NOW = 1792184400.0
ACS_ID = '00E0FC-WUKUN-BE32-SYNTH0000002'
ACS_SERIAL = 'SYNTH0000002'
WEB_SERIAL = 'SYNTHAX30001'
WEB_ORIGIN = 'https://192.168.3.1'
STAMP = '2026-10-16T21:00:00Z'
PINS = {WEB_ORIGIN: WEB_SERIAL}


def merge(result, records, registry, now=None, publish=True):
    return webonly.merge(result, records, registry, now=now, publish=publish, pins=PINS)


def load_webcol_module(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / 'webcol' / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def profile(band, ssid, native_id, standard, channel=0, usage='primary', enabled=True):
    return {'band': band, 'ssid': ssid, 'native_id': native_id, 'standard': standard,
            'channel_configured': channel, 'usage': usage, 'enabled': enabled}


def record(**overrides):
    rec = {
        'router_ip': '192.168.3.1',
        'origin': WEB_ORIGIN,
        'serial': WEB_SERIAL,
        'source_type': 'web-api-only',
        'device': {'software_version': '11.0.5.6', 'model': 'WS7200',
                   'hardware_version': 'VER.A', 'uptime_seconds': 70815},
        'clients': [{'mac': 'aa:bb:cc:dd:ee:01', 'ip': '192.168.3.50', 'hostname': 'laptop',
                     'band': '5GHz', 'band_norm': '5g', 'interface_id': 'SSID1'}],
        'inventory': {
            'radios': [{'band': '2.4g', 'profile_count': 1}, {'band': '5g', 'profile_count': 1}],
            'profiles': [
                profile('2.4g', 'ExampleWifi', 'InternetGatewayDevice.X_Config.Wifi.Radio.1.Ssid.1',
                        'b/g/n/ax', channel=0),
                profile('5g', 'ExampleWifi', 'InternetGatewayDevice.X_Config.Wifi.Radio.2.Ssid.1',
                        'a/n/ac/ax', channel=36)]},
        'stats': {'cpu_percent': 0, 'mem_percent': 22}, 'stats_reason': None,
        'device_observed_at': NOW,
        'stats_observed_at': NOW, 'transport': 'direct', 'observed_at': NOW, 'fresh': True,
    }
    rec.update(overrides)
    return rec


def acs_ap(serial=ACS_SERIAL, ip='192.0.2.11'):
    return {'id': '00E0FC-WUKUN-BE32-' + serial, 'serial': serial, 'ip': ip, 'online': True,
            'virtual_mac': '02:00:00:00:00:0b', 'name': 'WUKUN-BE32', 'radios': []}


def snapshot_with_acs(serial=ACS_SERIAL):
    return {'updated_at': NOW, 'aps': [acs_ap(serial=serial)], 'clients': [], 'warnings': []}


class IdentityTests(unittest.TestCase):
    def test_source_id_and_virtual_mac_are_stable_and_shared(self):
        self.assertEqual(webonly.source_id(WEB_SERIAL), webonly.source_id(WEB_SERIAL))
        self.assertTrue(webonly.source_id(WEB_SERIAL).startswith('webonly-'))
        registry = webonly.sanitize_registry(None)
        identifier, mac, _entry = webonly.ensure_source(registry, WEB_SERIAL)
        self.assertEqual(identifier, webonly.source_id(WEB_SERIAL))
        self.assertEqual(mac, virtual_mac(identifier))
        self.assertTrue(webonly._valid_mac(mac))
        self.assertEqual(webonly.ensure_source(registry, WEB_SERIAL)[:2], (identifier, mac))
        self.assertNotIn(WEB_SERIAL, json.dumps(registry))  # serial stored as a hash

    def test_registry_roundtrip_survives_restart_and_rename(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, 'webonly_v1.json')
            registry, ok = webonly.load_registry(path)
            self.assertTrue(ok)
            webonly.ensure_source(registry, WEB_SERIAL)
            self.assertTrue(webonly.save_registry(path, registry))
            reloaded, ok = webonly.load_registry(path)
            self.assertTrue(ok)
            renamed = record(inventory={'profiles': [profile(
                '5g', 'Renamed', 'n-5', 'a/n/ac/ax', channel=36)]})
            result, registry2, _ = merge(snapshot_with_acs(), {'h': renamed}, reloaded, now=NOW)
            self.assertEqual(result['aps'][1]['id'], webonly.source_id(WEB_SERIAL))

    def test_malformed_registry_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, 'webonly_v1.json')
            with open(path, 'w', encoding='utf-8') as handle:
                handle.write('{not json')
            _, ok = webonly.load_registry(path)
            self.assertFalse(ok)
            with open(path, 'w', encoding='utf-8') as handle:
                json.dump({'schema_version': 99, 'sources': {}}, handle)
            _, ok = webonly.load_registry(path)
            self.assertFalse(ok)


class BuildTests(unittest.TestCase):
    def test_merge_adds_a_third_virtual_ap_with_both_bands(self):
        result, registry, warnings = merge(
            snapshot_with_acs(), {'https://192.168.3.1': record()}, {}, now=NOW)
        self.assertEqual(warnings, [])
        self.assertEqual(len(result['aps']), 2)
        ap = result['aps'][1]
        self.assertTrue(ap['web_only'])
        self.assertEqual(ap['source_kind'], 'web-api-only')
        self.assertIsNone(ap['last_inform'])
        self.assertEqual(ap['last_seen'], NOW)
        self.assertTrue(ap['online'])
        self.assertEqual({r['band'] for r in ap['radios']}, {'2.4g', '5g'})
        self.assertEqual(ap['device_truth']['model'], 'WS7200')
        self.assertEqual(ap['device_stats']['uptime_seconds'], 70815)
        self.assertEqual(ap['device_stats']['mem_percent'], 22)
        self.assertEqual(len(result['clients']), 1)
        client = result['clients'][0]
        self.assertEqual(client['ap_id'], ap['id'])
        self.assertEqual(client['band'], '5g')
        self.assertEqual(client['radio_id'], ap['radios'][1]['id'])
        self.assertNotIn('phy_mode', client)  # Never fabricated; AX3 reports none.

    def test_browserless_or_unpinned_or_bad_model_records_are_rejected_before_registration(self):
        for rec, pins in ((record(transport='browserless'), PINS),
                          (record(), {}),
                          (record(device={'model': 'ARBITRARY'}), PINS),
                          (record(observed_at=float('inf')), PINS)):
            result, registry, warnings = webonly.merge(
                dict(aps=[], clients=[], warnings=[]), {'h': rec}, {}, now=NOW, pins=pins)
            self.assertEqual(result['aps'], [])
            self.assertEqual(registry['sources'], {})
            self.assertTrue(any('admisión' in w for w in warnings))

    def test_acs_serial_collision_suppresses_the_web_ap(self):
        result, _, warnings = merge(
            snapshot_with_acs(WEB_SERIAL), {'h': record()}, {}, now=NOW)
        self.assertEqual(len(result['aps']), 1)
        self.assertTrue(any('colisión de identidad' in w for w in warnings))

    def test_stale_record_is_offline_and_clients_are_stale(self):
        result, _, _ = merge(
            snapshot_with_acs(), {'h': record(observed_at=NOW - 7200)}, {}, now=NOW)
        ap = result['aps'][1]
        self.assertFalse(ap['online'])
        self.assertTrue(all(r['stale'] for r in ap['radios']))
        self.assertTrue(result['clients'][0]['stale'])

    def test_configured_channel_is_always_omitted_without_a_verified_source(self):
        result, _, _ = merge(snapshot_with_acs(), {'h': record()}, {}, now=NOW)
        radios = {r['band']: r for r in result['aps'][1]['radios']}
        self.assertNotIn('channel', radios['2.4g'])
        self.assertNotIn('channel', radios['5g'])
        configured = record(inventory={'profiles': [
            profile('5g', 'ExampleWifi', 'n-5', 'a/n/ac/ax', channel=36)]})
        result2, _, _ = merge(snapshot_with_acs(), {'h': configured}, {}, now=NOW)
        self.assertNotIn('channel', result2['aps'][1]['radios'][0])

    def test_client_without_band_is_kept_but_not_attached(self):
        rec = record(clients=[{'mac': 'aa:bb:cc:dd:ee:09', 'hostname': 'x'}])
        result, _, _ = merge(snapshot_with_acs(), {'h': rec}, {}, now=NOW)
        client = [c for c in result['clients'] if c['mac'] == 'aa:bb:cc:dd:ee:09'][0]
        self.assertIsNone(client['radio_id'])

    def test_guest_client_with_only_a_primary_profile_is_unbound(self):
        rec = record(clients=[{'mac': 'aa:bb:cc:dd:ee:0a', 'band_norm': '5g', 'guest': True}])
        result, _, _ = merge(snapshot_with_acs(), {'h': rec}, {}, now=NOW)
        client = [c for c in result['clients'] if c['mac'] == 'aa:bb:cc:dd:ee:0a'][0]
        self.assertIsNone(client['radio_id'])
        self.assertEqual(result['aps'][1]['unbound_client_count'], 1)

    def test_two_primary_profiles_on_one_band_are_ambiguous(self):
        rec = record(clients=[{'mac': 'aa:bb:cc:dd:ee:0b', 'band_norm': '5g'}])
        rec['inventory']['profiles'] = [
            profile('5g', 'A', 'n-a', 'ax', usage='primary'),
            profile('5g', 'B', 'n-b', 'ax', usage='primary')]
        result, _, _ = merge(snapshot_with_acs(), {'h': rec}, {}, now=NOW)
        self.assertIsNone(result['clients'][0]['radio_id'])
        self.assertEqual(result['aps'][1]['unbound_client_count'], 1)


class SlotStabilityTests(unittest.TestCase):
    def rec(self, profiles):
        return record(inventory={'profiles': profiles})

    def wire_names(self, result):
        ap = result['aps'][1]
        body = payload(ap, {'clients': result['clients'], 'aps': result['aps']}, {},
                       'http://unifi.test/inform', 1.0,
                       {r['ssid']: 'w' * 24 for r in ap['radios']})
        return {v['name'] for v in body['vap_table']}

    def test_native_profile_usage_change_keeps_id_and_slot(self):
        registry = {}
        first, registry, _ = merge(
            snapshot_with_acs(), {'h': self.rec([profile('5g', 'A', 'n-a', 'ax')])}, registry, now=NOW)
        before = {r['native_id']: (r['id'], r['slot']) for r in first['aps'][1]['radios']}
        second, registry, _ = merge(
            snapshot_with_acs(), {'h': self.rec([
                profile('5g', 'Renamed', 'n-a', 'ax', usage='guest')])}, registry, now=NOW)
        after = {r['native_id']: (r['id'], r['slot']) for r in second['aps'][1]['radios']}
        self.assertEqual(before['n-a'], after['n-a'])

    def test_absent_then_new_then_return_keeps_slot_and_wire_bssid(self):
        registry = {}
        a = [profile('2.4g', 'A', 'n-a', 'ax')]
        first, registry, _ = merge(snapshot_with_acs(), {'h': self.rec(a)}, registry, now=NOW)
        slot_a = first['aps'][1]['radios'][0]['slot']
        names_a = self.wire_names(first)
        second, registry, _ = merge(
            snapshot_with_acs(), {'h': self.rec([profile('5g', 'B', 'n-b', 'ax')])}, registry, now=NOW)
        self.assertGreater(second['aps'][1]['radios'][0]['slot'], slot_a)  # A stays reserved
        third, registry, _ = merge(snapshot_with_acs(), {'h': self.rec(a)}, registry, now=NOW)
        self.assertEqual(third['aps'][1]['radios'][0]['slot'], slot_a)
        self.assertEqual(self.wire_names(third), names_a)


class RegistryStrictnessTests(unittest.TestCase):
    def seed(self, **overrides):
        key = webonly.source_key(WEB_SERIAL)
        entry = {'id': 'webonly-' + key, 'mac': virtual_mac('webonly-' + key),
                 'serial_hash': key}
        entry.update(overrides)
        return key, {'schema_version': 1, 'sources': {key: entry}}

    def write(self, path, payload):
        with open(path, 'w', encoding='utf-8') as handle:
            json.dump(payload, handle)

    def test_old_source_without_slots_is_a_valid_migration_seed(self):
        key, payload = self.seed()
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, 'webonly_v1.json')
            self.write(path, payload)
            registry, ok = webonly.load_registry(path)
            self.assertTrue(ok)
            self.assertEqual(registry['sources'][key]['slots'], {})

    def test_bad_entry_is_rejected_and_the_file_is_preserved(self):
        key, payload = self.seed(mac='02:00:00:00:00:01')
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, 'webonly_v1.json')
            self.write(path, payload)
            registry, ok = webonly.load_registry(path)
            self.assertFalse(ok)
            self.assertEqual(registry['sources'], {})
            with open(path, 'r', encoding='utf-8') as handle:
                self.assertEqual(json.load(handle), payload)

    def test_deeply_nested_json_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, 'webonly_v1.json')
            with open(path, 'w', encoding='utf-8') as handle:
                handle.write('[' * 200000 + ']' * 200000)
            self.assertFalse(webonly.load_registry(path)[1])

    def test_duplicate_slot_and_bad_cursor_fail_closed_without_touching_the_file(self):
        key = webonly.source_key(WEB_SERIAL)
        identifier = 'webonly-' + key
        for slots, cursor in ({'a': 0, 'b': 0}, 1), ({'a': 0, 'b': 2}, 1):
            payload = {'schema_version': 1, 'sources': {key: {
                'id': identifier, 'mac': virtual_mac(identifier), 'serial_hash': key,
                'slots': slots, 'next_slot': cursor}}}
            with tempfile.TemporaryDirectory() as directory:
                path = os.path.join(directory, 'webonly_v1.json')
                with open(path, 'w', encoding='utf-8') as handle:
                    json.dump(payload, handle)
                self.assertFalse(webonly.load_registry(path)[1])
                with open(path, 'r', encoding='utf-8') as handle:
                    self.assertEqual(json.load(handle), payload)

    def test_non_integer_slots_fail_closed_and_preserve_original_registry(self):
        for invalid in ([], {}, '0', None, True):
            with self.subTest(slot=invalid):
                _, payload = self.seed(slots={'native-a': invalid}, next_slot=1)
                with tempfile.TemporaryDirectory() as directory:
                    path = os.path.join(directory, 'webonly_v1.json')
                    self.write(path, payload)
                    registry, ok = webonly.load_registry(path)
                    self.assertFalse(ok)
                    self.assertEqual(registry['sources'], {})
                    with open(path, 'r', encoding='utf-8') as handle:
                        self.assertEqual(json.load(handle), payload)

    def test_slot_cap_blocks_a_new_slot_without_history_loss(self):
        key = webonly.source_key(WEB_SERIAL)
        identifier = 'webonly-' + key
        payload = {'schema_version': 1, 'sources': {key: {
            'id': identifier, 'mac': virtual_mac(identifier), 'serial_hash': key,
            'slots': {'n%d' % i: i for i in range(512)}, 'next_slot': 512}}}
        self.assertTrue(webonly._validate_registry(payload))
        registry = webonly.sanitize_registry(payload)
        result, registry, warnings = merge(
            {'aps': [], 'clients': [], 'warnings': []},
            {'h': record(inventory={'profiles': [profile('5g', 'S', 'n512', 'ax')]})},
            registry, now=NOW)
        self.assertEqual(result['aps'], [])
        self.assertTrue(any('límite' in w for w in warnings))
        self.assertEqual(len(registry['sources'][key]['slots']), 512)

    def test_duplicate_mac_across_sources_is_rejected(self):
        key = webonly.source_key(WEB_SERIAL)
        other = '0123456789abcdef'
        mac = virtual_mac('webonly-' + key)
        payload = {'schema_version': 1, 'sources': {
            key: {'id': 'webonly-' + key, 'mac': mac, 'serial_hash': key},
            other: {'id': 'webonly-' + other, 'mac': mac, 'serial_hash': other}}}
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, 'webonly_v1.json')
            self.write(path, payload)
            self.assertFalse(webonly.load_registry(path)[1])


class StatsTests(unittest.TestCase):
    def ap_stats(self, rec, now):
        return merge(snapshot_with_acs(), {'h': rec}, {}, now=now)[0]['aps'][1]['device_stats']

    def test_old_gauge_expires_even_if_the_record_is_fresh(self):
        stats = self.ap_stats(record(observed_at=NOW, stats_observed_at=NOW - 1000,
                                     stats={'cpu_percent': 5, 'mem_percent': 10}), NOW)
        self.assertIsNone(stats['cpu_percent'])
        self.assertIsNone(stats['mem_percent'])
        self.assertIsNone(stats['observed_at'])

    def test_bad_gauge_and_timestamp_values_never_wire(self):
        for gauge in ({'cpu_percent': float('nan')}, {'cpu_percent': float('inf')},
                      {'cpu_percent': True}, {'mem_percent': 101}, {'mem_percent': -1}):
            stats = self.ap_stats(record(observed_at=NOW, stats_observed_at=NOW, stats=gauge), NOW)
            self.assertIsNone(stats['cpu_percent'] if 'cpu_percent' in gauge else stats['mem_percent'])
        for seen in (NOW + 100, float('inf'), True, None, 'x'):
            stats = self.ap_stats(record(observed_at=NOW, stats_observed_at=seen,
                                         stats={'cpu_percent': 5, 'mem_percent': 10}), NOW)
            self.assertIsNone(stats['cpu_percent'])

    def test_ttl_is_clamped_so_a_huge_value_cannot_extend_freshness(self):
        rec = record(observed_at=NOW - 1000, stats_observed_at=NOW - 1000,
                     ttl_seconds=float('inf'))
        result = merge(snapshot_with_acs(), {'h': rec}, {}, now=NOW)[0]
        self.assertFalse(result['aps'][1]['online'])


class PayloadTests(unittest.TestCase):
    def build(self, rec=None):
        result, _, _ = merge(snapshot_with_acs(), {'h': rec or record()}, {}, now=NOW)
        ap = result['aps'][1]
        snapshot = {'clients': result['clients'], 'aps': result['aps']}
        return ap, payload(ap, snapshot, {}, 'http://unifi.test/inform', 1.0,
                           {r['ssid']: 'w' * 24 for r in ap['radios']})

    def test_web_only_wire_has_no_be_no_6ghz_no_160(self):
        ap, body = self.build()
        self.assertEqual({r['name'] for r in body['radio_table']}, {'wifi0', 'wifi1'})
        for radio in body['radio_table']:
            self.assertFalse(radio['is_11be'])
            self.assertFalse(radio['has_ht160'])
        self.assertNotIn('channel', body['radio_table'][0])
        self.assertIn('web API only', body['model_display'])
        self.assertEqual(sum(v['num_sta'] for v in body['vap_table']), 1)
        self.assertNotIn('channel', body['vap_table'][0])

    def test_ax3_model_truth_is_separate_from_the_virtual_profile(self):
        ap, body = self.build()
        self.assertEqual(body['model'], 'U7PRO')
        self.assertEqual(ap['device_truth']['model'], 'WS7200')
        self.assertEqual(body['model_display'], 'Huawei WS7200 (web API only)')


class ControlGateTests(unittest.TestCase):
    def test_web_only_is_never_controllable_even_if_ip_is_allowlisted(self):
        with tempfile.TemporaryDirectory() as directory:
            control = Control(directory, lambda *a: {}, allowed_ip='192.168.3.1')
            self.assertIn('192.168.3.1', control.allowed_ips)
            ap = merge(snapshot_with_acs(), {'h': record()}, {}, now=NOW)[0]['aps'][1]
            self.assertIs(control.receive(ap, {'system_cfg': {'x': 1}}, {}, {}), None)
            plan = control.plan(ap, {'system_cfg': {'x': 1}}, {}, {})
            self.assertFalse(plan['ok'])
            self.assertEqual(plan['blocked_reason'], 'cwmp-unsupported-web-source')
            self.assertFalse(control.public(ap)['enabled'])
            self.assertFalse(os.path.exists(os.path.join(
                directory, ap['virtual_mac'].replace(':', '') + '.json')))

    def test_acs_refresh_never_sees_a_web_only_ap(self):
        devices = [{'_id': ACS_ID, '_deviceId': {'_Manufacturer': 'Huawei',
                    '_ProductClass': 'WUKUN-BE32'}, '_lastInform': STAMP,
                    'InternetGatewayDevice': {'DeviceInfo': {'SoftwareVersion': {'_value': 'v'}}}}]
        self.assertEqual([ap['id'] for ap in normalize(devices, NOW)['aps']], [ACS_ID])
        self.assertFalse(ACS_ID.startswith('webonly-'))

    def test_device_lookup_and_cwmp_plan_are_never_used_for_web_only(self):
        from types import SimpleNamespace
        from huawei_bridge import unifi as unifi_module
        from huawei_bridge.unifi import UniFi

        lookup_calls = []

        class FakeControl:
            allowed_ips = {'192.168.3.1'}

            def record(self, ap):
                return {}

            def plan(self, *args, **kwargs):
                raise AssertionError('control.plan must not run for web-only')

            def receive(self, *args, **kwargs):
                raise AssertionError('control.receive must not run for web-only')

            def reset(self, ap):
                raise AssertionError('control.reset must not run for web-only')

            def public(self, ap):
                return {'enabled': False}

            def ack(self, ap):
                return None

            def mapping(self, ap, mapping):
                raise AssertionError('control.mapping must not run for web-only')

        ap = merge(snapshot_with_acs(), {'h': record()}, {}, now=NOW)[0]['aps'][1]
        decoded = SimpleNamespace(mac=ap['virtual_mac'], mode='cbc',
                                  body={'_type': 'setparam', 'system_cfg': {'x': 1},
                                        'cfgversion': 'v1'})

        class Response:
            def read(self, limit):
                return b''

            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

        with tempfile.TemporaryDirectory() as directory:
            unifi = UniFi(directory, 'http://127.0.0.1:9/inform', {}, FakeControl(),
                          lambda identity: lookup_calls.append(identity) or {})
            unifi.http = SimpleNamespace(open=lambda *a, **k: Response())
            with unittest.mock.patch.object(unifi_module, 'encode', return_value=b'x'), \
                    unittest.mock.patch.object(unifi_module, 'decode', return_value=decoded), \
                    unittest.mock.patch.object(
                        unifi_module, 'apply_response',
                        side_effect=lambda state, body: state.update(cfgversion='v1') or 0):
                unifi.exchange(ap, {'clients': [], 'aps': [ap]})
        self.assertEqual(lookup_calls, [])
        self.assertEqual(unifi.status[ap['virtual_mac']]['plan']['reason'],
                         'cwmp-unsupported-web-source')


class WebcolSourceTests(unittest.TestCase):
    def test_config_parsing_and_pin_resolution(self):
        module = load_webcol_module('webcol_webonly_cfg', 'webcol.py')
        wo = module.webonly
        hosts = wo.webonly_routers(
            'https://192.168.3.1=secret, bad-entry, https://router.lan=pw, http://user@192.0.2.1=pw')
        self.assertEqual(hosts, [('https://192.168.3.1', 'secret')])
        self.assertEqual(wo.expected_serial('https://192.168.3.1', 'https://192.168.3.1=SERIAL1'),
                         'SERIAL1')
        self.assertIsNone(wo.expected_serial('https://192.168.3.1', 'SERIAL1'))
        self.assertIsNone(wo.expected_serial('https://192.168.3.1', ''))
        self.assertIsNone(wo.expected_serial('https://192.168.3.2',
                                             'https://192.168.3.1=SERIAL1'))

    def test_build_record_requires_the_pinned_serial(self):
        module = load_webcol_module('webcol_webonly_build', 'webcol.py')
        result = {'ok': True, 'transport': 'direct',
                  'server_signature_verified': True, 'public_key_verified': True,
                  'device': {'serial_number': WEB_SERIAL, 'model': 'WS7200',
                             'software_version': '11.0.5.6', 'uptime_seconds': 10},
                  'clients': [{'mac': 'aa:bb:cc:dd:ee:01', 'band_norm': '5g', 'secret': 'x'}],
                  'inventory': {'profiles': [{'band': '5g', 'native_id': 'n', 'password': 'p',
                                              'standard': 'ax'}]},
                  'stats': {'cpu_percent': 0, 'password': 'p'}}
        self.assertIsNone(module.webonly.build_record(
            'https://192.168.3.1', result, 'WRONG', now=NOW))
        built = module.webonly.build_record('https://192.168.3.1', result, WEB_SERIAL, now=NOW)
        self.assertEqual(built['serial'], WEB_SERIAL)
        self.assertEqual(built['origin'], 'https://192.168.3.1')
        self.assertEqual(built['source_type'], 'web-api-only')
        self.assertEqual(built['clients'][0]['mac'], 'aa:bb:cc:dd:ee:01')
        self.assertNotIn('secret', json.dumps(built))
        self.assertNotIn('password', json.dumps(built))

    def test_webonly_endpoint_shape(self):
        module = load_webcol_module('webcol_webonly_endpoint', 'webcol.py')
        with module.LOCK:
            module.DATA['webonly'] = {}
            module.DATA['webonly_at'] = None
        module.merge_webonly('https://192.168.3.1', record(), now=NOW)
        view = module.snapshot_webonly(now=NOW)
        self.assertEqual(view['schema_version'], 1)
        state = view['routers']['https://192.168.3.1']
        self.assertTrue(state['fresh'])
        self.assertEqual(state['source_type'], 'web-api-only')
        self.assertEqual(state['last_seen'], NOW)
        stale = module.snapshot_webonly(now=NOW + module.TTL_SECONDS + 1)
        self.assertFalse(stale['routers']['https://192.168.3.1']['fresh'])


class ApplicationIntegrationTests(unittest.TestCase):
    def device(self, last_inform=None):
        return {'_id': ACS_ID, '_deviceId': {'_Manufacturer': 'Huawei',
                '_ProductClass': 'WUKUN-BE32'},
                '_lastInform': last_inform or time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
                'InternetGatewayDevice': {
                    'ManagementServer': {'ConnectionRequestURL': {'_value': 'https://192.0.2.11:7547/cb'}},
                    'DeviceInfo': {'SoftwareVersion': {'_value': '4.2.0.53'}},
                    'LANDevice': {'1': {'WLANConfiguration': {'1': {
                        'SSID': {'_value': 'ExampleSSID'}, 'Channel': {'_value': 128},
                        'Enable': {'_value': True}, 'BSSID': {'_value': '02:00:00:00:00:13'},
                        'AssociatedDevice': {}}}}}}}

    def app(self, directory):
        from huawei_bridge.__main__ import Application
        app = Application()
        self.addCleanup(app.close)
        app.web_enrichment = lambda: None
        app.web_inventory = lambda: {'routers': {}}
        return app

    def live_record(self):
        return record(observed_at=time.time() - 5, stats_observed_at=time.time() - 5)

    def durable_snapshot(self, app):
        app.snapshot()
        app.web_registry_saved_generation = app.web_registry_generation
        return app.snapshot()

    def env(self, directory):
        return unittest.mock.patch.dict(os.environ, {
            'STATE_DIR': directory, 'UNIFI_WLAN_MAP': '{}', 'HUAWEI_CONTROL_IP': '',
            'WEB_ONLY_SERIALS': '%s=%s' % (WEB_ORIGIN, WEB_SERIAL)}, clear=False)

    @contextlib.contextmanager
    def workdir(self):
        directory = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, directory, ignore_errors=True)
        yield directory

    def test_first_mint_is_suppressed_until_durable(self):
        with self.workdir() as directory, self.env(directory):
            app = self.app(directory)
            app.devices = [self.device()]
            app.web_only = lambda: {'routers': {'https://192.168.3.1': self.live_record()}}
            first = app.snapshot()
            self.assertEqual(len(first['aps']), 1)
            self.assertTrue(any('aun no persistidos' in w for w in first['warnings']))
            app.web_registry_saved_generation = app.web_registry_generation
            second = app.snapshot()
            self.assertEqual(len(second['aps']), 2)
            web = [ap for ap in second['aps'] if ap.get('web_only')][0]
            self.assertTrue(web['online'])
            self.assertIsNotNone(web['inventory']['slot_by_radio'])

    def test_failed_save_never_emits(self):
        from huawei_bridge.writer import JsonRegistryWriter

        def failing(path, data):
            raise OSError('ENOSPC')

        with self.workdir() as directory, self.env(directory):
            app = self.app(directory)
            app.writer.close()
            app.writer = JsonRegistryWriter(
                {'vap': app.registry_path, 'webonly': app.web_registry_path},
                on_saved=app._on_saved, write=failing, join_timeout=0.2)
            self.addCleanup(app.writer.close)
            app.devices = [self.device()]
            app.web_only = lambda: {'routers': {'https://192.168.3.1': self.live_record()}}
            for _ in range(3):
                self.assertEqual(len(app.snapshot()['aps']), 1)
            self.assertGreater(app.web_registry_generation, app.web_registry_saved_generation)

    def test_zero_acs_devices_still_publishes_a_valid_ax3(self):
        with self.workdir() as directory, self.env(directory):
            app = self.app(directory)
            app.devices = []
            app.web_only = lambda: {'routers': {'https://192.168.3.1': self.live_record()}}
            snap = self.durable_snapshot(app)
            self.assertEqual(len(snap['aps']), 1)
            web = snap['aps'][0]
            self.assertTrue(web['web_only'])
            self.assertTrue(web['online'])
            self.assertGreaterEqual(web['client_count'], 1)
            self.assertTrue(any(c['ap_id'] == web['id'] and c['radio_id'] for c in snap['clients']))

    def test_all_acs_offline_still_publishes_online_ax3(self):
        with self.workdir() as directory, self.env(directory):
            app = self.app(directory)
            app.devices = [self.device('2020-01-01T00:00:00Z')]
            app.web_only = lambda: {'routers': {'https://192.168.3.1': self.live_record()}}
            snap = self.durable_snapshot(app)
            self.assertFalse(any(ap.get('web_only') is not True and ap.get('online') for ap in snap['aps']))
            web = [ap for ap in snap['aps'] if ap.get('web_only')][0]
            self.assertTrue(web['online'])

    def test_losing_ax3_does_not_affect_be3(self):
        with self.workdir() as directory, self.env(directory):
            app = self.app(directory)
            app.devices = [self.device()]
            app.web_only = lambda: {'routers': {}}
            snap = app.snapshot()
            self.assertEqual(len(snap['aps']), 1)
            self.assertEqual(snap['aps'][0]['id'], ACS_ID)
            self.assertEqual(snap['aps'][0]['virtual_mac'], virtual_mac(ACS_ID))

    def test_bad_web_registry_fails_web_only_only(self):
        with self.workdir() as directory, self.env(directory):
            app = self.app(directory)
            app.web_registry_ok = False
            app.devices = [self.device()]
            app.web_only = lambda: {'routers': {'https://192.168.3.1': self.live_record()}}
            snap = app.snapshot()
            self.assertEqual(len(snap['aps']), 1)
            self.assertFalse(any(ap.get('web_only') for ap in snap['aps']))
            self.assertTrue(any('web-only' in w for w in snap['warnings']))


if __name__ == '__main__':
    unittest.main()
