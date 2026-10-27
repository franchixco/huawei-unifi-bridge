"""Synthetic uptime/restart regression checks; no CPE or controller connections."""

import copy
import io
import json
import tempfile
import unittest
import urllib.error
from pathlib import Path
from unittest.mock import Mock, patch

from huawei_bridge import inventory, uptime, webonly
from huawei_bridge.protocol import ProtocolError, decode, encode
from huawei_bridge.unifi import UniFi, atomic_json, read_auth_state
from test_webonly import NOW, PINS, WEB_ORIGIN, record


class ProjectionTests(unittest.TestCase):
    def stats(self, raw=10000, seen=NOW, ttl=60):
        return uptime.sample({'uptime_seconds': raw}, seen, NOW, ttl)

    def test_repeated_sample_informs_advance_without_refreshing_sample(self):
        stats = self.stats()
        for elapsed in (0, 10, 20, 60):
            diagnostic = uptime.project(stats, NOW + elapsed)
            self.assertEqual(diagnostic['reported_seconds'], 10000)
            self.assertEqual(diagnostic['estimated_seconds'], 10000 + elapsed)
            self.assertEqual(diagnostic['observed_at'], NOW)

    def test_projection_stops_at_ttl(self):
        diagnostic = uptime.project(self.stats(), NOW + 60.001)
        self.assertIsNone(diagnostic['estimated_seconds'])
        self.assertEqual(diagnostic['unavailable_reason'], 'expired-sample')

    def test_fractional_observation_uses_native_utc_second_rounding(self):
        seen = NOW + 0.75
        stats = uptime.sample({'uptime_seconds': 10000}, seen, seen, 60)
        for now in (seen, NOW + 1.1, NOW + 1.75, NOW + 10.2):
            projected = uptime.project(stats, now)['estimated_seconds']
            self.assertEqual(int(now) - projected, int(seen) - 10000)
            self.assertLess(abs(projected - (10000 + now - seen)), 1)

    def test_fresh_lower_sample_is_never_clamped(self):
        self.assertEqual(uptime.project(self.stats(), NOW + 10)['estimated_seconds'], 10010)
        lower = uptime.sample({'uptime_seconds': 3}, NOW + 10, NOW + 10, 60)
        self.assertEqual(uptime.project(lower, NOW + 10)['estimated_seconds'], 3)
        self.assertEqual(uptime.project(lower, NOW + 20)['estimated_seconds'], 13)

    def test_invalid_uptime_numbers_are_bounded_before_float_conversion(self):
        for raw in (None, True, False, -1, '10', float('nan'), float('inf'),
                    -float('inf'), 10 ** 10000, uptime.MAX_UPTIME + 1):
            with self.subTest(kind=type(raw).__name__):
                stats = self.stats(raw=raw)
                self.assertIsNone(uptime.project(stats, NOW)['estimated_seconds'])
                json.dumps(stats, allow_nan=False)

    def test_invalid_or_unproven_timestamps_never_project(self):
        for seen in (None, True, False, '10', float('nan'), float('inf'),
                     10 ** 10000, -1, NOW + 0.001, NOW - 61):
            with self.subTest(kind=type(seen).__name__):
                stats = self.stats(seen=seen)
                self.assertIsNone(uptime.project(stats, NOW)['estimated_seconds'])
                json.dumps(stats, allow_nan=False)

    def test_invalid_ttl_and_now_are_rejected(self):
        for value in (None, True, -1, 0, float('inf'), 10 ** 10000, '60'):
            self.assertIsNone(uptime.project(self.stats(ttl=value), NOW)['estimated_seconds'])
        for now in (None, True, float('inf'), 10 ** 10000, '10'):
            self.assertIsNone(uptime.project(self.stats(), now)['estimated_seconds'])

    def test_zero_is_only_allowed_as_a_real_fresh_hardware_sample(self):
        self.assertEqual(uptime.project(self.stats(raw=0), NOW)['estimated_seconds'], 0)
        self.assertIsNone(uptime.project({}, NOW)['estimated_seconds'])

    def test_cpu_timestamp_is_not_uptime_timestamp_in_both_providers(self):
        source = record(device_observed_at=NOW - 20, stats_observed_at=NOW)
        device = source['device']
        for stats in (inventory.device_stats(source, device, now=NOW),
                      webonly._stats(source, device, NOW)):
            self.assertEqual(stats['observed_at'], NOW)
            self.assertEqual(stats['uptime_observed_at'], NOW - 20)
            self.assertEqual(stats['uptime_seconds'], 70815)
            self.assertEqual(uptime.project(stats, NOW)['estimated_seconds'], 70835)

    def test_fresh_cpu_or_router_timestamp_cannot_rescue_expired_deviceinfo(self):
        for seen in (None, NOW - 601, NOW + 1, True, float('inf'), 10 ** 10000):
            source = record(device_observed_at=seen)
            for stats in (inventory.device_stats(source, source['device'], now=NOW),
                          webonly._stats(source, source['device'], NOW)):
                self.assertEqual(stats['mem_percent'], 22)
                self.assertIsNone(stats['uptime_seconds'])
                self.assertIsNone(uptime.project(stats, NOW)['estimated_seconds'])

    def test_uptime_respects_source_ttl_without_changing_cpu_freshness(self):
        source = record(device_observed_at=NOW - 61, ttl_seconds=60)
        for stats in (inventory.device_stats(source, source['device'], now=NOW),
                      webonly._stats(source, source['device'], NOW)):
            self.assertEqual(stats['mem_percent'], 22)
            self.assertIsNone(stats['uptime_seconds'])
        source['device_observed_at'] = NOW
        source['ttl_seconds'] = 10000
        stats = inventory.device_stats(source, source['device'], now=NOW)
        self.assertEqual(stats['uptime_ttl_seconds'], uptime.MAX_TTL)
        for value in (True, float('inf'), 10 ** 10000):
            source['ttl_seconds'] = value
            for stats in (inventory.device_stats(source, source['device'], now=NOW),
                          webonly._stats(source, source['device'], NOW)):
                self.assertIsNone(stats['uptime_seconds'])


class ContinuityTests(unittest.TestCase):
    def setUp(self):
        # Retain synthetic artifacts: this test adds no delete/cleanup operation.
        self.directory = Path(tempfile.mkdtemp(prefix='uptime-regression-'))
        self.registry_path = self.directory / 'webonly_v1.json'
        result, registry, warnings = webonly.merge(
            {'aps': [], 'clients': [], 'warnings': []},
            {WEB_ORIGIN: record()}, {}, now=NOW, pins=PINS)
        self.assertFalse(warnings)
        self.assertTrue(webonly.save_registry(self.registry_path, registry))
        self.ap, self.snapshot = result['aps'][0], result
        self.url = 'http://127.0.0.1:8080/inform'
        self.key = bytes.fromhex('11223344556677889900aabbccddeeff')
        self.path = self.directory / (self.ap['virtual_mac'].replace(':', '') + '.json')
        self.state = {'phase': 'exchanging', 'authkey': self.key.hex(), 'encryption': 'gcm',
                      'cfgversion': 'synthetic-v1', 'controller_url': self.url,
                      'virtual_mac': self.ap['virtual_mac'], 'adoption_marker': 'preserve'}
        atomic_json(self.path, self.state)
        self.mapping = {'ExampleWifi': '11111111-2222-4333-8444-555555555555'}
        self.sent = []

    def peer(self, request, timeout):
        packet = decode(request.data, self.key)
        self.sent.append(packet)
        return io.BytesIO(encode({'_type': 'noop'}, packet.mac, self.key, mode='gcm'))

    def instance(self):
        instance = UniFi(self.directory, self.url, self.mapping)
        instance.http = Mock()
        instance.http.open.side_effect = self.peer
        return instance

    def exchange(self, instance, now):
        with patch('huawei_bridge.unifi.inform_url', return_value=self.url), \
                patch('huawei_bridge.unifi.time.time', return_value=now):
            instance.exchange(self.ap, self.snapshot)
        return self.sent[-1].body

    def test_unifi_restart_preserves_hardware_uptime_auth_profile_and_identity(self):
        first_instance = self.instance()
        first_instance.started -= 1000000
        first = self.exchange(first_instance, NOW)
        restarted = self.instance()
        second = self.exchange(restarted, NOW + 10)
        self.assertEqual((first['uptime'], second['uptime']), (70815, 70825))
        self.assertEqual(second['system-stats']['uptime'], '70825')
        for key in ('mac', 'serial', 'model', 'version', 'cfgversion', 'vap_table'):
            self.assertEqual(first[key], second[key])
        self.assertFalse(second['default'])
        self.assertEqual(self.sent[-1].mode, 'gcm')
        persisted = read_auth_state(self.path)
        for key in self.state:
            self.assertEqual(persisted[key], self.state[key])
        diagnostic = restarted.status[self.ap['virtual_mac']]['uptime']
        self.assertEqual(diagnostic['reported_seconds'], 70815)
        self.assertEqual(diagnostic['estimated_seconds'], 70825)
        self.assertEqual(diagnostic['sent_seconds'], 70825)

    def test_native_utc_time_minus_uptime_has_stable_boot_estimate(self):
        instance = self.instance()
        estimates = []
        for elapsed in (0, 10, 20, 50, 60):
            body = self.exchange(instance, NOW + elapsed)
            self.assertEqual(body['time'], int(NOW + elapsed))
            estimates.append(body['time'] - body['uptime'])
        self.assertEqual(len(set(estimates)), 1)
        self.assertEqual(estimates[0], NOW - 70815)

    def test_reboot_lower_sample_replaces_old_uptime_and_boot_estimate(self):
        instance = self.instance()
        old = self.exchange(instance, NOW)
        self.ap['device_stats'] = webonly._stats(
            record(device_observed_at=NOW + 10), {'uptime_seconds': 2}, NOW + 10)
        new = self.exchange(instance, NOW + 10)
        self.assertEqual(new['uptime'], 2)
        self.assertGreater(new['time'] - new['uptime'], old['time'] - old['uptime'])
        self.assertEqual(new['mac'], old['mac'])
        self.assertFalse(new['default'])

    def test_missing_undated_or_expired_sample_omits_uptime_without_readoption(self):
        for stats in (None, {}, {'uptime_seconds': 123},
                      uptime.sample({'uptime_seconds': 50}, NOW - 601, NOW, 600)):
            self.ap['device_stats'] = stats
            body = self.exchange(self.instance(), NOW)
            self.assertNotIn('uptime', body)
            self.assertNotIn('uptime', body.get('system-stats', {}))
            self.assertFalse(body['default'])
            self.assertEqual(body['state'], 2)
            self.assertEqual(read_auth_state(self.path)['authkey'], self.key.hex())

    def test_snapshot_replay_expires_at_send_time_without_zero_or_auth_reset(self):
        body = self.exchange(self.instance(), NOW + 601)
        self.assertNotIn('uptime', body)
        self.assertNotIn('uptime', body.get('system-stats', {}))
        self.assertFalse(body['default'])
        self.assertEqual(read_auth_state(self.path)['authkey'], self.key.hex())

    def test_transient_exceptions_never_apply_response_or_rewrite_auth_state(self):
        original = self.path.read_bytes()
        for error in (urllib.error.URLError('synthetic'), TimeoutError(),
                      ProtocolError('synthetic'), OSError('synthetic')):
            instance = self.instance()
            instance.http.open.side_effect = error
            with patch('huawei_bridge.unifi.inform_url', return_value=self.url), \
                    patch('huawei_bridge.unifi.apply_response') as apply:
                instance.tick(self.snapshot)
            apply.assert_not_called()
            self.assertEqual(instance.status[self.ap['virtual_mac']]['phase'], 'error')
            self.assertEqual(self.path.read_bytes(), original)

    def test_malformed_or_wrong_identity_reply_does_not_reset_adoption(self):
        original = self.path.read_bytes()
        replies = (b'invalid', encode({'_type': 'setdefault'}, '02:00:00:00:00:ff',
                                      self.key, mode='gcm'))
        for reply in replies:
            instance = self.instance()
            instance.http.open.side_effect = lambda *a, **kw: io.BytesIO(reply)
            with patch('huawei_bridge.unifi.inform_url', return_value=self.url), \
                    patch('huawei_bridge.unifi.apply_response') as apply:
                instance.tick(self.snapshot)
            apply.assert_not_called()
            self.assertEqual(self.path.read_bytes(), original)

    def test_explicit_valid_controller_setdefault_keeps_intended_reset_semantics(self):
        instance = self.instance()
        instance.http.open.side_effect = lambda *a, **kw: io.BytesIO(encode(
            {'_type': 'setdefault'}, self.ap['virtual_mac'], self.key, mode='gcm'))
        with patch('huawei_bridge.unifi.inform_url', return_value=self.url):
            instance.exchange(self.ap, self.snapshot)
        state = read_auth_state(self.path)
        self.assertIsNone(state['authkey'])
        self.assertEqual(state['phase'], 'factory')

    def test_collector_restart_preserves_registry_slots_bssids_and_auth_file(self):
        original = self.path.read_bytes()
        before = self.exchange(self.instance(), NOW)
        registry, ok = webonly.load_registry(self.registry_path)
        self.assertTrue(ok)
        source = record(device_observed_at=NOW + 60, observed_at=NOW + 60)
        source['device']['uptime_seconds'] += 60
        source['inventory']['profiles'].reverse()
        result, registry, warnings = webonly.merge(
            {'aps': [], 'clients': [], 'warnings': []}, {WEB_ORIGIN: source}, registry,
            now=NOW + 60, pins=PINS)
        self.assertFalse(warnings)
        self.assertTrue(webonly.save_registry(self.registry_path, registry))
        self.ap, self.snapshot = result['aps'][0], result
        after = self.exchange(self.instance(), NOW + 60)
        for key in ('mac', 'serial', 'model', 'version', 'vap_table'):
            self.assertEqual(before[key], after[key])
        self.assertEqual(after['uptime'], 70875)
        self.assertEqual(read_auth_state(self.path)['authkey'], self.key.hex())
        self.assertEqual(json.loads(original)['adoption_marker'],
                         read_auth_state(self.path)['adoption_marker'])

    def test_missing_collector_record_does_not_mutate_registry_or_adoption(self):
        registry, _ = webonly.load_registry(self.registry_path)
        saved = copy.deepcopy(registry)
        original = self.path.read_bytes()
        result, registry, _ = webonly.merge(
            {'aps': [], 'clients': [], 'warnings': []}, {}, registry, now=NOW, pins=PINS)
        self.assertEqual(registry, saved)
        self.assertEqual(result['aps'], [])
        self.assertEqual(self.path.read_bytes(), original)


class TimestampPipelineTests(unittest.TestCase):
    def test_direct_deviceinfo_time_is_captured_before_later_cpu_sample(self):
        from test_huawei_api import huawei_api

        client = huawei_api.HuaweiDirectClient('http://127.0.0.1', 'synthetic-only')
        with patch.object(client, 'login'), patch.object(client, '_get_json', return_value={}), \
                patch.object(client, '_read_optional', return_value=None), \
                patch.object(client, '_read_stats', return_value=({'cpu_percent': 1}, None)), \
                patch.object(huawei_api, 'parse_deviceinfo', return_value={'uptime_seconds': 100}), \
                patch.object(huawei_api, 'parse_hostinfo', return_value=[]), \
                patch.object(huawei_api, 'parse_wlanguide', return_value={'profiles': []}), \
                patch.object(huawei_api.time, 'time', side_effect=[NOW - 5, NOW]):
            result = client.collect()
        self.assertTrue(result['ok'])
        self.assertEqual(result['device_observed_at'], NOW - 5)
        self.assertEqual(result['stats_observed_at'], NOW)

    def test_webcol_publishers_preserve_device_timestamp_not_merge_or_fetch_time(self):
        from test_webcol import webcol

        result = {'ok': True, 'transport': 'direct', 'clients': [], 'ssids': [],
                  'server_signature_verified': True, 'public_key_verified': True,
                  'device': {'serial_number': 'SYNTHAX30001', 'model': 'WS7200',
                             'uptime_seconds': 100}, 'inventory': {'profiles': []},
                  'device_observed_at': NOW - 5, 'stats': {'cpu_percent': 1},
                  'stats_observed_at': NOW}
        with patch.object(webcol, 'DATA', {'routers': {}, 'updated_at': None}):
            webcol.merge_into_data(WEB_ORIGIN, result, now=NOW + 5)
            published = webcol.snapshot(now=NOW + 10)['routers'][WEB_ORIGIN]
            handler = webcol.handler(Mock())
            request = object.__new__(handler)
            request.path, request.send = '/inventory', Mock()
            with patch.object(webcol.time, 'time', return_value=NOW + 10):
                handler.do_GET(request)
            api_record = request.send.call_args.args[1]['routers'][WEB_ORIGIN]
            self.assertEqual(api_record['device_observed_at'], NOW - 5)
            self.assertEqual(api_record['ttl_seconds'], webcol.TTL_SECONDS)
        self.assertEqual(published['device_observed_at'], NOW - 5)
        self.assertEqual(published['stats_observed_at'], NOW)
        self.assertEqual(published['observed_at'], NOW + 5)
        normalized = webcol.webonly.build_record(WEB_ORIGIN, result, 'SYNTHAX30001', now=NOW + 5)
        self.assertEqual(normalized['device_observed_at'], NOW - 5)
