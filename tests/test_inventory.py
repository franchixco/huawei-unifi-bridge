"""Offline tests for the pure WLAN inventory model (webcol/inventory.py)."""

import importlib.util
import json
import os
import tempfile
import unittest
from pathlib import Path

WEBROOT = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location('inventory_under_test',
                                               WEBROOT / 'webcol' / 'inventory.py')
inventory = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(inventory)


def web_profile(band, ssid, native_id=None, usage='primary', **overrides):
    profile = {'band': band, 'ssid': ssid, 'native_id': native_id, 'usage': usage,
               'enabled': True, 'channel_configured': 0, 'power': '100%',
               'wmm': True, 'standard': 'b/g/n/ax'}
    profile.update(overrides)
    return profile


def web_inventory(profiles, radios=()):
    return {'radios': list(radios), 'profiles': list(profiles)}


def tr098_radio(path, band, ssid, channel, bssid=None):
    return {'id': path, 'band': band, 'ssid': ssid, 'channel': channel,
            'bssid': bssid, 'enabled': True, 'standards': ['ax'], 'stale': False}


class BandAndSlotTests(unittest.TestCase):
    def test_normalize_band(self):
        self.assertEqual(inventory.normalize_band('2.4GHz'), '2.4g')
        self.assertEqual(inventory.normalize_band('5G'), '5g')
        self.assertIsNone(inventory.normalize_band('6G'))
        self.assertIsNone(inventory.normalize_band(None))

    def test_slots_are_stable_under_ssid_rename_with_native_id(self):
        before = [web_profile('2.4g', 'ExampleSSID', native_id=1),
                  web_profile('5g', 'ExampleSSID', native_id=2)]
        _, state = inventory.assign_slots(before)
        after = [web_profile('5g', 'ExampleSSID-5G', native_id=2),
                 web_profile('2.4g', 'ExampleSSID-2G', native_id=1)]
        assignment, _ = inventory.assign_slots(after, state)
        self.assertEqual(assignment[0], state['slots'] and
                         {v['identity']: k for k, v in state['slots'].items()}['5g|nid|2'])
        self.assertEqual(assignment[1], {v['identity']: k for k, v in
                                         state['slots'].items()}['2.4g|nid|1'])

    def test_slots_are_reorder_independent(self):
        profiles = [web_profile('5g', 'B', native_id=2),
                    web_profile('2.4g', 'A', native_id=1),
                    web_profile('5g', 'C', native_id=3)]
        shuffled = [profiles[2], profiles[0], profiles[1]]
        first, _ = inventory.assign_slots(profiles)
        second, _ = inventory.assign_slots(shuffled)
        first_by_identity = {inventory.profile_identity(p)[1:]: s
                             for p, s in zip(profiles, [first[i] for i in range(3)])}
        second_by_identity = {inventory.profile_identity(p)[1:]: s
                              for p, s in zip(shuffled, [second[i] for i in range(3)])}
        self.assertEqual(first_by_identity, second_by_identity)

    def test_slots_fall_back_to_band_and_ssid(self):
        profiles = [web_profile('5g', 'Zeta'), web_profile('2.4g', 'Alpha')]
        assignment, state = inventory.assign_slots(profiles)
        self.assertEqual(assignment[0], 1)
        self.assertEqual(assignment[1], 0)
        self.assertIn('2.4g|ssid|Alpha', {v['identity'] for v in state['slots'].values()})

    def test_sanitize_state_rejects_unknown_or_malformed(self):
        self.assertEqual(inventory.sanitize_state(None)['slots'], {})
        self.assertEqual(inventory.sanitize_state({'schema_version': 99})['slots'], {})
        self.assertEqual(inventory.sanitize_state(
            {'schema_version': 1, 'slots': {'x': {'identity': 'a'}}})['slots'], {})
        good = {'schema_version': 1, 'slots': {'3': {'identity': '2.4g|nid|1', 'band': '2.4g'}}}
        self.assertEqual(set(inventory.sanitize_state(good)['slots']), {3})


class CrosswalkTests(unittest.TestCase):
    def test_primary_matches_by_band_and_ssid_leaving_tr098_extras(self):
        profiles = [web_profile('2.4g', 'ExampleSSID', native_id=1),
                    web_profile('5g', 'ExampleSSID', native_id=2)]
        radios = [tr098_radio('...WLANConfiguration.1', '2.4g', 'ExampleSSID', 1, 'aa:aa:aa:aa:aa:01'),
                  tr098_radio('...WLANConfiguration.2', '5g', 'ExampleSSID', 128),
                  tr098_radio('...WLANConfiguration.3', '2.4g', 'IoT', 6),
                  tr098_radio('...WLANConfiguration.4', '5g', 'Guest', 0)]
        crosswalk = inventory.crosswalk_primary(profiles, radios)
        self.assertEqual(len(crosswalk['matches']), 2)
        self.assertEqual(crosswalk['matches'][0]['tr098_id'], '...WLANConfiguration.1')
        self.assertEqual(crosswalk['matches'][0]['channel_effective'], 1)
        self.assertEqual(crosswalk['matches'][0]['bssid_observed'], 'aa:aa:aa:aa:aa:01')
        self.assertEqual(len(crosswalk['unmatched_tr098']), 2)
        self.assertEqual(crosswalk['ambiguous'], [])

    def test_ambiguous_candidates_are_never_selected(self):
        profiles = [web_profile('5g', 'ExampleSSID', native_id=2)]
        radios = [tr098_radio('a', '5g', 'ExampleSSID', 1),
                  tr098_radio('b', '5g', 'ExampleSSID', 1)]
        crosswalk = inventory.crosswalk_primary(profiles, radios)
        self.assertEqual(crosswalk['matches'], [])
        self.assertEqual(len(crosswalk['ambiguous']), 1)
        self.assertEqual(sorted(crosswalk['ambiguous'][0]['candidates']), ['a', 'b'])

    def test_non_primary_profiles_are_not_crosswalked(self):
        profiles = [web_profile('5g', 'Guest5', native_id=3, usage='guest')]
        radios = [tr098_radio('a', '5g', 'Guest5', 1)]
        crosswalk = inventory.crosswalk_primary(profiles, radios)
        self.assertEqual(crosswalk['matches'], [])
        self.assertEqual(len(crosswalk['unmatched_tr098']), 1)


class BuildInventoryTests(unittest.TestCase):
    def test_channel_auto_and_effective_are_distinguished(self):
        result = inventory.build_inventory(
            web_inventory([web_profile('5g', 'ExampleSSID', native_id=2,
                                       channel_configured=0)]),
            [tr098_radio('...2', '5g', 'ExampleSSID', 128)])
        profile = result['profiles'][0]
        self.assertEqual(profile['channel']['configured'], 0)
        self.assertTrue(profile['channel']['configured_is_auto'])
        self.assertEqual(profile['channel']['effective'], 128)
        self.assertEqual(profile['channel']['effective_source'], 'tr098')

    def test_power_is_percent_and_never_dbm(self):
        result = inventory.build_inventory(
            web_inventory([web_profile('2.4g', 'A', native_id=1, power='80%'),
                           web_profile('5g', 'B', native_id=2, power=100)]))
        first = result['profiles'][0]['power']
        self.assertEqual(first['unit'], 'percent')
        self.assertEqual(first['reported'], 80)
        self.assertEqual(first['raw'], '80%')
        self.assertNotIn('dbm', json.dumps(result).lower())

    def test_unknown_usage_and_guest_activity_are_not_inferred(self):
        result = inventory.build_inventory(web_inventory([
            web_profile('5g', 'Whatever-Guest', native_id=9, usage='unknown', enabled=False),
            web_profile('5g', 'Guest5', native_id=10, usage='guest', enabled=True)]))
        by_ssid = {p['ssid']: p for p in result['profiles']}
        self.assertEqual(by_ssid['Whatever-Guest']['usage'], 'unknown')
        self.assertFalse(by_ssid['Whatever-Guest']['enabled'])
        self.assertEqual(by_ssid['Guest5']['usage'], 'guest')
        self.assertTrue(by_ssid['Guest5']['enabled'])

    def test_hardware_prefers_real_model_over_virtual_profile(self):
        real = inventory.build_inventory(web_inventory([]), device={
            'model': 'WUKUN-BE32', 'model_cust': 'WUKUN-BE32', 'software_version': '4.2.0.53',
            'serial_number': 'SN', 'uptime_seconds': 10})
        self.assertEqual(real['hardware']['model'], 'WUKUN-BE32')
        self.assertIsNone(real['hardware']['virtual_profile'])
        virtual = inventory.build_inventory(web_inventory([]), device={'model': 'U7PRO'})
        self.assertEqual(virtual['hardware']['model'], None)
        self.assertEqual(virtual['hardware']['virtual_profile'], 'U7PRO')

    def test_model_carries_no_secret_material(self):
        result = inventory.build_inventory(
            web_inventory([web_profile('5g', 'ExampleSSID', native_id=2)]),
            [tr098_radio('...2', '5g', 'ExampleSSID', 128)])
        blob = json.dumps(result).lower()
        for secret in ('password', 'cookie', 'csrf', 'clientproof', 'serversignature',
                       'nonce', 'salt'):
            self.assertNotIn(secret, blob)

    def test_counts_and_registry_are_emitted(self):
        result = inventory.build_inventory(web_inventory([
            web_profile('2.4g', 'ExampleSSID', native_id=1, usage='primary'),
            web_profile('5g', 'ExampleSSID', native_id=2, usage='primary'),
            web_profile('5g', 'Guest5', native_id=3, usage='guest')]))
        self.assertEqual(result['counts'], {'primary': 2, 'guest': 1, 'unknown': 0})
        self.assertEqual(result['registry']['schema_version'], 1)
        self.assertEqual(sorted(p['slot'] for p in result['profiles']), [0, 1, 2])

    def test_missing_web_inventory_is_tolerated(self):
        result = inventory.build_inventory(None)
        self.assertEqual(result['profiles'], [])
        self.assertEqual(result['counts'], {'primary': 0, 'guest': 0, 'unknown': 0})


class StateIoTests(unittest.TestCase):
    def test_state_roundtrip_and_atomic_write(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, 'nested', 'inventory_state.json')
            _, state = inventory.assign_slots([web_profile('5g', 'X', native_id=2)])
            self.assertTrue(inventory.save_state(path, state))
            self.assertEqual(inventory.load_state(path)['slots'], state['slots'])
            with open(path) as handle:
                self.assertEqual(json.load(handle)['schema_version'], 1)

    def test_load_state_tolerates_corrupt_or_missing(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, 'missing.json')
            self.assertEqual(inventory.load_state(path)['slots'], {})
            bad = os.path.join(directory, 'bad.json')
            with open(bad, 'w') as handle:
                handle.write('{not json')
            self.assertEqual(inventory.load_state(bad)['slots'], {})

    def test_save_state_failure_is_non_fatal(self):
        self.assertFalse(inventory.save_state('/proc/definitely/not/writable.json', {}))


if __name__ == '__main__':
    unittest.main()
