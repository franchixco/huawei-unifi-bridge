"""Offline tests for the bridge TR-098 <-> webcol inventory crosswalk."""

import json
import os
import shutil
import tempfile
import time
import unittest
import unittest.mock

from huawei_bridge import inventory
from huawei_bridge.__main__ import Application

NOW = time.time()
AP_ID = '00E0FC-WUKUN-BE32-SYNTH0000002'
SERIAL = 'SYNTH0000002'
PATH_24 = 'InternetGatewayDevice.LANDevice.1.WLANConfiguration.1'
PATH_5 = 'InternetGatewayDevice.LANDevice.1.WLANConfiguration.2'


def radio(path, band, ssid, channel, enabled=True, native=None):
    entry = {'id': path, 'band': band, 'ssid': ssid, 'channel': channel,
             'bssid': None, 'enabled': enabled, 'standards': ['ax'],
             'updated_at': NOW, 'stale': False}
    if native:
        entry['native_id'] = native
    return entry


def ap(radios, ip='192.0.2.11', ap_id=AP_ID):
    return {'id': ap_id, 'ip': ip, 'radios': radios, 'online': True}


def profile(band, ssid, native_id, usage='primary', enabled=True, channel=0):
    return {'band': band, 'ssid': ssid, 'native_id': native_id, 'usage': usage,
            'enabled': enabled, 'channel': {'configured': channel},
            'power': {'reported': 100}, 'wmm': True, 'standard': 'b/g/n/ax'}


def web_router(profiles, ip='192.0.2.11', serial=SERIAL, fresh=True, updated_at=NOW,
               observed_at=NOW, model='WUKUN-BE32-40'):
    return {'router_ip': ip, 'fresh': fresh, 'updated_at': updated_at, 'observed_at': observed_at,
            'device_observed_at': observed_at,
            'serial': serial,
            'device': {'serial_number': serial, 'model': model},
            'inventory': {'profiles': profiles}}


def web(router, url='https://192.0.2.11'):
    items = router if isinstance(router, (list, tuple)) else [router]
    return {'routers': {('%s#%d' % (url, index)): item for index, item in enumerate(items)}}


def result_with(aps):
    return {'updated_at': NOW, 'aps': aps, 'clients': [], 'warnings': []}


class TrustTests(unittest.TestCase):
    def test_requires_ip_and_serial(self):
        a = ap([radio(PATH_5, '5g', 'ExampleSSID', 128)])
        self.assertEqual(inventory.trust(a, web_router([], ip='192.0.2.11'))[0], True)
        self.assertEqual(inventory.trust(a, web_router([], ip='192.0.2.99'))[1], 'ip-mismatch')
        self.assertEqual(inventory.trust(a, web_router([], serial='OTHER'))[1], 'serial-mismatch')

    def test_serial_from_acs_id(self):
        self.assertEqual(inventory.ap_serial({'id': AP_ID}), SERIAL)

    def test_dhcp_change_is_not_misattributed(self):
        a = ap([radio(PATH_5, '5g', 'ExampleSSID', 128)], ip='192.0.2.50')
        trusted, reason = inventory.trust(a, web_router([], ip='192.0.2.11'))
        self.assertFalse(trusted)
        self.assertEqual(reason, 'ip-mismatch')


class ProfileClassificationTests(unittest.TestCase):
    def test_enabled_requires_explicit_true(self):
        profiles = [profile('2.4g', 'A', 'n1'), profile('5g', 'B', 'n2', enabled=False)]
        classified = inventory.classify_profiles(web_router(profiles), now=NOW)
        self.assertTrue(classified['fresh'])
        self.assertEqual([p['ssid'] for p in classified['active']], ['A'])
        self.assertEqual([p['ssid'] for p in classified['observed']], ['B'])

    def test_missing_enable_is_observed_not_disabled(self):
        entry = profile('5g', 'C', 'n3')
        del entry['enabled']
        classified = inventory.classify_profiles(web_router([entry]), now=NOW)
        self.assertEqual(classified['active'], [])
        self.assertEqual(classified['observed'][0]['ssid'], 'C')

    def test_stale_web_is_observed(self):
        classified = inventory.classify_profiles(
            web_router([profile('5g', 'D', 'n4')], fresh=True, observed_at=NOW - 7200), now=NOW)
        self.assertFalse(classified['fresh'])
        self.assertEqual(classified['active'], [])


class CrosswalkTests(unittest.TestCase):
    def test_ambiguous_candidates_are_not_selected(self):
        radios = [radio(PATH_5, '5g', 'ExampleSSID', 36), radio(PATH_24, '5g', 'ExampleSSID', 44)]
        matches, ambiguous, ghosts = inventory.crosswalk_band(
            radios, [profile('5g', 'ExampleSSID', 'n1')])
        self.assertEqual(matches, {})
        self.assertEqual(len(ambiguous), 2)
        self.assertEqual(ghosts, [])

    def test_unmatched_active_profile_is_a_ghost(self):
        matches, _, ghosts = inventory.crosswalk_band(
            [radio(PATH_24, '2.4g', 'ExampleSSID', 1)], [profile('5g', 'Guest5', 'n9', usage='guest')])
        self.assertEqual(matches, {})
        self.assertEqual(ghosts[0]['ssid'], 'Guest5')


class ApplyTests(unittest.TestCase):
    def test_trusted_apply_sets_native_id_and_effective_channel(self):
        radios = [radio(PATH_24, '2.4g', 'ExampleSSID', 1), radio(PATH_5, '5g', 'ExampleSSID', 128)]
        result = result_with([ap(radios)])
        applied, registry = inventory.apply(
            result, web([web_router([profile('2.4g', 'ExampleSSID', 'nr1'),
                                     profile('5g', 'ExampleSSID', 'nr2')])]), {}, now=NOW)
        radio_24, radio_5 = applied['aps'][0]['radios']
        self.assertEqual(radio_24['native_id'], 'nr1')
        self.assertEqual(radio_24['effective_channel'], 1)
        self.assertEqual(radio_24['channel_source'], 'tr098')
        self.assertTrue(applied['aps'][0]['inventory']['trusted'])
        self.assertEqual(applied['inventory']['routers'][AP_ID]['identity'], 'trusted')
        self.assertEqual(registry['aps'][AP_ID]['slots'][0]['native_id'], 'nr1')

    def test_rename_keeps_the_same_slot(self):
        before = result_with([ap([radio(PATH_24, '2.4g', 'ExampleSSID', 1)])])
        _, registry = inventory.apply(
            before, web([web_router([profile('2.4g', 'ExampleSSID', 'nr1')])]), {}, now=NOW)
        after = result_with([ap([radio(PATH_24, '2.4g', 'Renamed', 1)])])
        applied, registry2 = inventory.apply(
            after, web([web_router([profile('2.4g', 'Renamed', 'nr1')])]), registry, now=NOW)
        self.assertEqual(registry2['aps'][AP_ID]['slots'][0]['identity'], '2.4g|nid|nr1')
        self.assertEqual(applied['aps'][0]['inventory']['slots']['0']['ssid'], 'Renamed')

    def test_reorder_and_ap_isolation(self):
        first = result_with([ap([radio(PATH_24, '2.4g', 'A', 1), radio(PATH_5, '5g', 'B', 36)])])
        _, registry = inventory.apply(
            first, web([web_router([profile('2.4g', 'A', 'a1'), profile('5g', 'B', 'b1')])]),
            {}, now=NOW)
        second = result_with([ap([radio(PATH_5, '5g', 'B', 36), radio(PATH_24, '2.4g', 'A', 1)])])
        applied, registry2 = inventory.apply(
            second, web([web_router([profile('5g', 'B', 'b1'), profile('2.4g', 'A', 'a1')])]),
            registry, now=NOW)
        slots = {info['identity']: slot for slot, info in registry2['aps'][AP_ID]['slots'].items()}
        self.assertEqual(slots['2.4g|nid|a1'], 0)
        self.assertEqual(slots['5g|nid|b1'], 1)
        self.assertEqual(applied['aps'][0]['inventory']['slots']['1']['ssid'], 'B')

    def test_web_unavailable_falls_back_to_tr098(self):
        radios = [radio(PATH_5, '5g', 'ExampleSSID', 128)]
        applied, registry = inventory.apply(result_with([ap(radios)]), {}, {}, now=NOW)
        self.assertNotIn('native_id', applied['aps'][0]['radios'][0])
        self.assertEqual(applied['aps'][0]['radios'][0]['channel_source'], 'tr098')
        self.assertIsNone(applied['aps'][0]['device_truth'])
        self.assertEqual(registry['aps'][AP_ID]['slots'][0]['identity'],
                         '5g|path|' + PATH_5)

    def test_channel_conflict_flags_uncertainty_and_represents_deterministically(self):
        radios = [radio(PATH_5, '5g', 'A', 44), radio(PATH_5 + '0', '5g', 'B', 36)]
        applied, _ = inventory.apply(result_with([ap(radios)]), {}, {}, now=NOW)
        summary = applied['aps'][0]['inventory']
        self.assertTrue(summary['channel_uncertain']['5g'])
        self.assertEqual(summary['representative_channel']['5g'], 36)

    def test_ghost_profile_is_observed_without_channel(self):
        radios = [radio(PATH_24, '2.4g', 'ExampleSSID', 1)]
        applied, _ = inventory.apply(
            result_with([ap(radios)]),
            web([web_router([profile('2.4g', 'ExampleSSID', 'n1'),
                             profile('5g', 'Guest5', 'n9', usage='guest')])]), {}, now=NOW)
        ghosts = applied['aps'][0]['inventory']['observed_unmanaged']
        self.assertEqual([g['ssid'] for g in ghosts], ['Guest5'])
        self.assertIsNone(ghosts[0]['channel'])
        self.assertEqual(ghosts[0]['reason'], 'no-tr098-match')

    def test_unknown_enabled_never_disables_a_radio(self):
        radios = [radio(PATH_5, '5g', 'ExampleSSID', 128, enabled=True)]
        entry = profile('5g', 'ExampleSSID', 'n2')
        del entry['enabled']
        applied, _ = inventory.apply(result_with([ap(radios)]),
                                     web([web_router([entry])]), {}, now=NOW)
        self.assertIs(applied['aps'][0]['radios'][0]['enabled'], True)
        self.assertNotIn('web_enabled', applied['aps'][0]['radios'][0])

    def test_device_truth_is_separate_from_virtual_identity(self):
        radios = [radio(PATH_5, '5g', 'ExampleSSID', 128)]
        applied, _ = inventory.apply(
            result_with([ap(radios)]), web([web_router([profile('5g', 'ExampleSSID', 'n2')])]),
            {}, now=NOW)
        truth = applied['aps'][0]['device_truth']
        self.assertEqual(truth['model'], 'WUKUN-BE32-40')
        self.assertEqual(truth['serial_number'], SERIAL)
        self.assertNotEqual(applied['aps'][0]['id'], truth['serial_number'])

    def test_optional_inventory_failure_is_tolerated(self):
        radios = [radio(PATH_5, '5g', 'ExampleSSID', 128)]
        applied, registry = inventory.apply(result_with([ap(radios)]), 'not-a-dict', None, now=NOW)
        self.assertTrue(applied['aps'][0]['inventory'])


class RegistryTests(unittest.TestCase):
    def test_v1_migration_by_band_and_ssid(self):
        migrated = inventory.migrate_v1({'ap': {'schema_version': 1, 'slots': {
            '0': {'band': '2.4g', 'ssid': 'Legacy'}}}})
        self.assertEqual(migrated['schema_version'], 2)
        self.assertEqual(migrated['aps']['ap']['slots'][0]['identity'], '2.4g|ssid|Legacy')

    def test_sanitize_rejects_unknown_shapes(self):
        self.assertEqual(inventory.sanitize_registry(None)['aps'], {})
        self.assertEqual(inventory.sanitize_registry({'schema_version': 1})['aps'], {})

    def test_atomic_roundtrip_and_failure_is_non_fatal(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, 'inventory', 'vap_map_v2.json')
            state = {'schema_version': 2, 'aps': {'ap': {'slots': {
                0: {'band': '2.4g', 'ssid': 'A', 'native_id': 'n1', 'identity': '2.4g|nid|n1'}}}}}
            self.assertTrue(inventory.save_registry(path, state))
            self.assertEqual(inventory.load_registry(path), inventory.sanitize_registry(state))
            self.assertFalse(inventory.save_registry('/proc/nope/vap_map.json', state))


class ApplicationSnapshotTests(unittest.TestCase):
    def _device(self):
        return {'_id': AP_ID, '_deviceId': {'_Manufacturer': 'Huawei', '_ProductClass': 'WUKUN-BE32'},
                '_lastInform': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
                'InternetGatewayDevice': {
                    'ManagementServer': {'ConnectionRequestURL': {'_value': 'https://192.0.2.11:7547/cb'}},
                    'DeviceInfo': {'SoftwareVersion': {'_value': '4.2.0.53'}},
                    'LANDevice': {'1': {'WLANConfiguration': {'1': {
                        'SSID': {'_value': 'ExampleSSID'}, 'Channel': {'_value': 128},
                        'Enable': {'_value': True}, 'BSSID': {'_value': '02:00:00:00:00:13'},
                        'AssociatedDevice': {}}}}}}}

    def test_snapshot_exposes_inventory_and_device_truth(self):
        directory = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, directory, ignore_errors=True)
        with unittest.mock.patch.dict(os.environ, {'STATE_DIR': directory,
                                                   'UNIFI_WLAN_MAP': '{}',
                                                   'HUAWEI_CONTROL_IP': ''}, clear=False):
            app = Application()
            self.addCleanup(app.close)
            app.devices = [self._device()]
            app.web_enrichment = lambda: None
            app.web_inventory = lambda: web([web_router(
                [profile('5g', 'ExampleSSID', 'n1')], ip='192.0.2.11',
                serial=AP_ID.rsplit('-', 1)[-1])])
            snap = app.snapshot()
            self.assertEqual(snap['inventory']['schema_version'], 2)
            ap_view = snap['aps'][0]
            self.assertTrue(ap_view['inventory']['trusted'])
            self.assertEqual(ap_view['device_truth']['model'], 'WUKUN-BE32-40')
            self.assertEqual(snap['identity_contract']['trust'], 'ip+serial')
            self.assertIsNotNone(app.registry_pending)

    def test_snapshot_survives_broken_web_inventory(self):
        directory = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, directory, ignore_errors=True)
        with unittest.mock.patch.dict(os.environ, {'STATE_DIR': directory,
                                                   'UNIFI_WLAN_MAP': '{}',
                                                   'HUAWEI_CONTROL_IP': ''}, clear=False):
            app = Application()
            self.addCleanup(app.close)
            app.devices = [self._device()]
            app.web_enrichment = lambda: None

            def broken():
                raise RuntimeError('webcol down')

            app.web_inventory = broken
            snap = app.snapshot()
            self.assertEqual(len(snap['aps']), 1)


def bridge_payload(result):
    from huawei_bridge.unifi import payload
    ap = result['aps'][0]
    ap.setdefault('virtual_mac', '02:00:00:00:00:0b')
    ap.setdefault('name', 'WUKUN-BE32-40')
    ap.setdefault('firmware', '4.2.0.53')
    ap.setdefault('hardware', 'VER.A')
    for radio in ap['radios']:
        radio.setdefault('standards', ['ax'])
        radio.setdefault('bssid', '02:00:00:00:00:13')
        radio.setdefault('effective_channel', radio.get('channel'))
    snapshot = {'clients': [], 'aps': [ap]}
    state = {'authkey': None, 'encryption': 'cbc'}
    return payload(ap, snapshot, state, 'http://unifi.test/inform', 1.0, {r['ssid']: 'w' * 24 for r in ap['radios']})


class SlotAliasStabilityTests(unittest.TestCase):
    """BSSID (ath{slot}) must not churn across upgrade, reorder, rename or web loss."""

    def pairs(self):
        return [radio(PATH_24, '2.4g', 'ExampleSSID', 1, native='n-24'),
                radio(PATH_5, '5g', 'ExampleSSID', 128, native='n-5')]

    def names(self, result):
        body = bridge_payload(result)
        ap_view = result['aps'][0]
        by_path = {r['id']: r['native_id'] for r in ap_view['radios']}
        slots = ap_view['inventory']['slot_by_radio']
        expected = {by_path[path]: 'ath%s' % slot for path, slot in slots.items()}
        self.assertEqual({v['name'] for v in body['vap_table']}, set(expected.values()))
        return expected

    def test_legacy_registry_upgrade_keeps_published_slots(self):
        legacy = {'aps': {AP_ID: {'slots': {0: {'band': '2.4g', 'ssid': 'ExampleSSID', 'identity': '2.4g|ssid|ExampleSSID'}}}},
                  'schema_version': 2}
        result = result_with([ap(self.pairs())])
        applied, registry = inventory.apply(result, None, legacy, now=NOW)
        names = self.names(applied)
        self.assertEqual(names['n-24'], 'ath0')
        self.assertEqual(registry['aps'][AP_ID]['slots'][0]['identity'], '2.4g|nid|n-24')

    def test_reorder_rename_and_web_loss_keep_same_bssids(self):
        first = result_with([ap(self.pairs())])
        applied, registry = inventory.apply(
            first, web([web_router([profile('2.4g', 'ExampleSSID', 'n-24'),
                                    profile('5g', 'ExampleSSID', 'n-5')])]), {}, now=NOW)
        baseline = self.names(applied)
        reordered = result_with([ap(list(reversed(self.pairs())))])
        applied2, registry2 = inventory.apply(
            reordered, web([web_router([profile('5g', 'Renamed5', 'n-5'),
                                        profile('2.4g', 'Renamed', 'n-24')])]), registry, now=NOW)
        self.assertEqual(self.names(applied2), baseline)
        offline = result_with([ap([radio(PATH_5, '5g', 'Renamed5', 128, native='n-5'),
                                   radio(PATH_24, '2.4g', 'Renamed', 1, native='n-24')])])
        applied3, _ = inventory.apply(offline, None, registry2, now=NOW)
        self.assertEqual(self.names(applied3), baseline)

    def test_hidden_slot_is_reserved_for_a_later_join(self):
        ab = [radio(PATH_24, '2.4g', 'A', 1, native='n-a'),
              radio(PATH_5, '5g', 'B', 36, native='n-b')]
        applied, registry = inventory.apply(result_with([ap(ab)]), None, {}, now=NOW)
        first = self.names(applied)
        self.assertEqual(first['n-a'], 'ath0')
        self.assertEqual(first['n-b'], 'ath1')
        hidden = result_with([ap([radio(PATH_5, '5g', 'B', 36, native='n-b')])])
        applied2, registry2 = inventory.apply(hidden, None, registry, now=NOW)
        self.assertEqual(self.names(applied2), {'n-b': 'ath1'})
        path_c = PATH_24.rsplit('.', 1)[0] + '.3'
        joined = result_with([ap([radio(PATH_5, '5g', 'B', 36, native='n-b'),
                                  radio(path_c, '2.4g', 'C', 6, native='n-c')])])
        applied3, registry3 = inventory.apply(joined, None, registry2, now=NOW)
        self.assertEqual(self.names(applied3), {'n-b': 'ath1', 'n-c': 'ath2'})
        returned = result_with([ap(ab)])
        applied4, _ = inventory.apply(returned, None, registry3, now=NOW)
        self.assertEqual(self.names(applied4), {'n-a': 'ath0', 'n-b': 'ath1'})
        self.assertIn(0, registry3['aps'][AP_ID]['slots'])


class TrustFilterTests(unittest.TestCase):
    def test_expired_observed_at_is_not_trusted_even_when_fresh_flag_true(self):
        aps = [ap([radio(PATH_5, '5g', 'ExampleSSID', 128)])]
        router = web_router([], fresh=True, observed_at=NOW - 7200)
        self.assertEqual(inventory.filter_inventory(aps, web([router]), now=NOW)['routers'], {})
        self.assertFalse(inventory._fresh(router, NOW, 600))
        result = result_with(aps)
        applied, _ = inventory.apply(result, web([router]), {}, now=NOW)
        self.assertFalse(applied['aps'][0]['inventory']['fresh'])
        self.assertNotIn('native_id', applied['aps'][0]['radios'][0])

    def test_dhcp_ip_reused_by_another_serial_is_refused(self):
        aps = [ap([radio(PATH_5, '5g', 'ExampleSSID', 128)])]
        router = web_router([], serial='DIFFERENT-SERIAL', observed_at=NOW)
        self.assertEqual(inventory.filter_inventory(aps, web([router]), now=NOW)['routers'], {})

    def test_missing_ip_or_serial_refuses_merge(self):
        aps = [ap([radio(PATH_5, '5g', 'ExampleSSID', 128)])]
        no_ip = ap([radio(PATH_5, '5g', 'ExampleSSID', 128)], ip=None)
        self.assertEqual(inventory.trust(no_ip, web_router([]))[1], 'ap-ip-missing')
        self.assertEqual(inventory.trust(aps[0], web_router([], serial=None))[1], 'serial-missing')

    def test_clients_from_another_serial_are_filtered(self):
        aps = [ap([radio(PATH_5, '5g', 'ExampleSSID', 128)])]
        payload = {'by_mac': {'AA:BB:CC:DD:EE:01': {'router_ip': '192.0.2.11', '_serial': SERIAL,
                                                    '_ts': NOW},
                              'AA:BB:CC:DD:EE:02': {'router_ip': '192.0.2.11', '_serial': 'OTHER',
                                                    '_ts': NOW}}}
        filtered = inventory.filter_enrichment(aps, payload, now=NOW)
        self.assertEqual(list(filtered['by_mac']), ['AA:BB:CC:DD:EE:01'])

    def test_untrusted_inventory_leaves_tr098_identity(self):
        result = result_with([ap([radio(PATH_5, '5g', 'ExampleSSID', 128)])])
        router = web_router([profile('5g', 'ExampleSSID', 'n-5')], serial='OTHER')
        applied, registry = inventory.apply(result, web([router]), {}, now=NOW)
        self.assertFalse(applied['aps'][0]['inventory']['trusted'])
        self.assertNotIn('native_id', applied['aps'][0]['radios'][0])
        self.assertEqual(registry['aps'][AP_ID]['slots'][0]['identity'], '5g|path|' + PATH_5)


class DeviceStatsCrosswalkTests(unittest.TestCase):
    def apply_router(self, router):
        result = result_with([ap([radio(PATH_5, '5g', 'X', 36)])])
        applied, _ = inventory.apply(result, web([router]), {}, now=NOW)
        return applied['aps'][0]

    def test_trusted_fresh_gauges_reach_the_ap_and_inventory(self):
        router = web_router([])
        router['device']['uptime_seconds'] = 4321
        router['stats'] = {'cpu_percent': 5, 'mem_percent': 36}
        router['stats_observed_at'] = NOW
        ap_view = self.apply_router(router)
        stats = ap_view['device_stats']
        self.assertEqual((stats['cpu_percent'], stats['mem_percent']), (5, 36))
        self.assertEqual(stats['uptime_seconds'], 4321)
        self.assertEqual(ap_view['inventory']['device_stats']['cpu_percent'], 5)

    def test_stale_stats_keep_uptime_but_drop_percent(self):
        router = web_router([])
        router['device']['uptime_seconds'] = 4321
        router['stats'] = {'cpu_percent': 5, 'mem_percent': 36}
        router['stats_observed_at'] = NOW - 7200
        stats = self.apply_router(router)['device_stats']
        self.assertIsNone(stats['cpu_percent'])
        self.assertIsNone(stats['mem_percent'])
        self.assertEqual(stats['uptime_seconds'], 4321)
        self.assertIn('unavailable', stats['unavailable_reason'])

    def test_untrusted_router_yields_no_stats(self):
        router = web_router([], serial='OTHER')
        router['stats'] = {'cpu_percent': 5, 'mem_percent': 36}
        self.assertIsNone(self.apply_router(router)['device_stats'])

    def test_absent_gauges_are_reported_with_a_reason(self):
        stats = self.apply_router(web_router([]))['device_stats']
        self.assertIsNone(stats['cpu_percent'])
        self.assertEqual(stats['unavailable_reason'], 'unavailable_in_observed_sources')
        self.assertEqual(stats['source'], 'huawei-web')


class SnapshotMetricWiringTests(unittest.TestCase):
    def _device(self):
        stamp = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())

        def c(value):
            return {'_value': value, '_timestamp': stamp, '_type': 'xsd:unsignedInt'}

        def wlan(ssid, channel, bssid, sent):
            return {'SSID': {'_value': ssid}, 'Channel': {'_value': channel},
                    'Enable': {'_value': True}, 'BSSID': {'_value': bssid},
                    'TotalBytesSent': c(sent), 'TotalBytesReceived': c(196737964),
                    'AssociatedDevice': {}}

        return {'_id': AP_ID, '_deviceId': {'_Manufacturer': 'Huawei', '_ProductClass': 'WUKUN-BE32'},
                '_lastInform': stamp,
                'InternetGatewayDevice': {
                    'ManagementServer': {'ConnectionRequestURL': {'_value': 'https://192.0.2.11:7547/cb'}},
                    'DeviceInfo': {'SoftwareVersion': {'_value': '4.2.0.53'}},
                    'LANDevice': {'1': {'WLANConfiguration': {
                        '1': wlan('ExampleSSID', 128, '02:00:00:00:00:13', 2744285448),
                        '2': wlan('Other', 6, '02:00:00:00:00:14', 2744285576)}}}}}

    def _router(self):
        router = web_router([profile('5g', 'ExampleSSID', 'n-5')])
        router['device'] = {'serial_number': SERIAL, 'model': 'WUKUN-BE32-40',
                            'uptime_seconds': 500000}
        router['stats'] = {'cpu_percent': 5, 'mem_percent': 36}
        router['stats_observed_at'] = NOW
        return router

    def test_snapshot_wires_stats_counters_and_capabilities(self):
        directory = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, directory, ignore_errors=True)
        with unittest.mock.patch.dict(os.environ, {'STATE_DIR': directory,
                                                   'UNIFI_WLAN_MAP': '{}',
                                                   'HUAWEI_CONTROL_IP': ''}, clear=False):
            app = Application()
            self.addCleanup(app.close)
            app.devices = [self._device()]
            app.web_enrichment = lambda: None
            app.web_inventory = lambda: web([self._router()])
            snap = app.snapshot()
            ap_view = snap['aps'][0]
            self.assertEqual(ap_view['device_stats']['cpu_percent'], 5)
            self.assertEqual(ap_view['device_stats']['uptime_seconds'], 500000)
            caps = ap_view['metric_capabilities']
            self.assertEqual(caps['available']['uptime_seconds']['value'], 500000)
            self.assertIn('total_bytes_sent', caps['blocked'])
            self.assertTrue(snap['counter_observations'])
            self.assertTrue(snap['metric_capabilities']['counter_state']['persistence_enabled'])

            # Persistence is asynchronous: snapshot only signals the bounded
            # background writer, which must flush without blocking the snapshot.
            app.counters.start_writer()
            state_path = os.path.join(directory, 'metrics', 'counters_v1.json')
            deadline = time.time() + 3
            while not os.path.exists(state_path) and time.time() < deadline:
                time.sleep(0.02)
            self.assertTrue(os.path.exists(state_path))

            from huawei_bridge.unifi import payload
            with unittest.mock.patch('huawei_bridge.unifi.time.time', return_value=NOW):
                body = payload(ap_view, snap, {}, 'http://unifi.test/inform', 3)
            self.assertEqual(body['system-stats']['cpu'], '5')
            self.assertEqual(body['uptime'], 500000)
            self.assertNotIn('tx_bytes', json.dumps(body))
            self.assertNotIn('2744285448', json.dumps(body))


if __name__ == '__main__':
    unittest.main()
