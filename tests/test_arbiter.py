"""Offline tests for the global station association arbiter and bounded state read."""

import json
import os
import tempfile
import time
import unittest
from pathlib import Path

from huawei_bridge import webonly
from huawei_bridge.collector import arbitrate, normalize
from huawei_bridge.unifi import payload, read_auth_state

NOW = time.time()
STRONG = 'strong-authenticated'
REPORTED = 'reported'
WEAK = 'weak'


def client(mac, ap_id, confidence, stale=False):
    return {'mac': mac, 'ap_id': ap_id, 'radio_id': ap_id + ':r', 'band': '5g', 'ssid': 'S',
            'stale': stale, 'updated_at': NOW, 'association_confidence': confidence,
            'association_source': 'test'}


def ap(ap_id, radio_id=None, ip='192.0.2.11', name='WUKUN-BE32', web_only=False, count=0):
    return {'id': ap_id, 'ip': ip, 'online': True, 'virtual_mac': '02:00:00:00:00:0b',
            'name': name, 'web_only': web_only, 'client_count': count,
            'radios': [{'id': radio_id or ap_id + ':r', 'band': '5g', 'ssid': 'S',
                        'channel': 36, 'enabled': True, 'standards': ['ax'],
                        'stale': False, 'native_id': 'n-5', 'slot': 0}],
            'inventory': {'slot_by_radio': {(radio_id or ap_id + ':r'): 0},
                          'representative_channel': {}}}


def result(aps, clients):
    return {'updated_at': NOW, 'aps': aps, 'clients': clients, 'warnings': []}


class ArbiterTests(unittest.TestCase):
    def kept(self, snap):
        return [c for c in snap['clients'] if not c.get('stale')]

    def test_strong_authenticated_beats_weak_hostinfo(self):
        mac = 'aa:bb:cc:dd:ee:01'
        snap = arbitrate(result([ap('be3'), ap('ax3', web_only=True)],
                                [client(mac, 'be3', STRONG), client(mac, 'ax3', WEAK)]), now=NOW)
        kept = self.kept(snap)
        self.assertEqual([c['ap_id'] for c in kept], ['be3'])
        self.assertEqual(snap['aps'][0]['client_count'], 1)
        self.assertEqual(snap['aps'][1]['client_count'], 0)
        self.assertEqual(snap['aps'][1]['reported_client_count'], 0)

    def test_two_equally_strong_native_candidates_are_both_suppressed(self):
        mac = 'aa:bb:cc:dd:ee:02'
        snap = arbitrate(result([ap('be3a'), ap('be3b')],
                                [client(mac, 'be3a', REPORTED), client(mac, 'be3b', REPORTED)]), now=NOW)
        self.assertEqual(self.kept(snap), [])
        self.assertTrue(any('ambigua' in w for w in snap['warnings']))
        self.assertNotIn(mac, json.dumps(snap['warnings']))  # hashed, never plaintext

    def test_two_weak_candidates_are_both_suppressed(self):
        mac = 'aa:bb:cc:dd:ee:03'
        snap = arbitrate(result([ap('ax3a', web_only=True), ap('ax3b', web_only=True)],
                                [client(mac, 'ax3a', WEAK), client(mac, 'ax3b', WEAK)]), now=NOW)
        self.assertEqual(self.kept(snap), [])

    def test_stale_native_expires_and_the_fresh_weak_candidate_emits(self):
        mac = 'aa:bb:cc:dd:ee:04'
        snap = arbitrate(result([ap('be3'), ap('ax3', web_only=True)],
                                [client(mac, 'be3', STRONG, stale=True),
                                 client(mac, 'ax3', WEAK)]), now=NOW)
        kept = self.kept(snap)
        self.assertEqual([c['ap_id'] for c in kept], ['ax3'])

    def test_unique_mac_from_one_cpe_emits(self):
        mac = 'aa:bb:cc:dd:ee:05'
        snap = arbitrate(result([ap('be3')], [client(mac, 'be3', REPORTED)]), now=NOW)
        self.assertEqual(len(self.kept(snap)), 1)

    def test_payload_sta_tables_never_duplicate_a_mac_across_providers(self):
        mac = 'aa:bb:cc:dd:ee:06'
        be3, ax3 = ap('be3'), ap('ax3', ip='192.168.3.1', name='WS7200 (web API)', web_only=True)
        snap = arbitrate(result([be3, ax3], [client(mac, 'be3', STRONG), client(mac, 'ax3', WEAK)]),
                         now=NOW)
        seen = []
        for device in snap['aps']:
            body = payload(device, snap, {}, 'http://unifi.test/inform', 1.0,
                           {r['ssid']: 'w' * 24 for r in device['radios']})
            for vap in body['vap_table']:
                seen.extend(station.get('mac') for station in vap['sta_table'])
        self.assertEqual(len(seen), len(set(seen)))
        self.assertLessEqual(len(seen), 1)


class NegativeAssociationTests(unittest.TestCase):
    def be3_device(self, serial, mac, auth):
        return {'_id': '00E0FC-WUKUN-BE32-' + serial,
                '_deviceId': {'_Manufacturer': 'Huawei', '_ProductClass': 'WUKUN-BE32'},
                '_lastInform': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
                'InternetGatewayDevice': {
                    'DeviceInfo': {'SoftwareVersion': {'_value': 'v'},
                                   'SerialNumber': {'_value': serial}},
                    'LANDevice': {'1': {'WLANConfiguration': {'1': {
                        'SSID': {'_value': 'ExampleSSID'}, 'Channel': {'_value': 128},
                        'Enable': {'_value': True}, 'BSSID': {'_value': '02:00:00:00:00:13'},
                        'AssociatedDevice': {'1': {
                            'AssociatedDeviceMACAddress': {
                                '_value': mac,
                                '_timestamp': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())},
                            'AuthenticationState': {'_value': auth}}}}}}}}}

    def test_false_auth_row_is_excluded_and_the_ax3_client_emits(self):
        mac = 'aa:bb:cc:dd:ee:21'
        pins = {'https://192.168.3.1': 'SYNTHAX30001'}
        now = time.time()
        result = normalize([self.be3_device('SYNTH0000003', mac, False)], now=now)
        self.assertEqual(result['clients'], [])  # explicit negative auth is not "reported"
        rec = {'origin': 'https://192.168.3.1', 'serial': 'SYNTHAX30001',
               'source_type': 'web-api-only', 'transport': 'direct', 'router_ip': '192.168.3.1',
               'device': {'model': 'WS7200'}, 'clients': [{'mac': mac, 'band_norm': '5g'}],
               'inventory': {'profiles': [{'band': '5g', 'ssid': 'ExampleWifi', 'native_id': 'n-5',
                                           'usage': 'primary', 'standard': 'a/n/ac/ax',
                                           'enabled': True}]},
               'observed_at': now}
        result, _, _ = webonly.merge(result, {'h': rec}, {}, now=now, pins=pins)
        arbitrate(result, now=now)
        kept = [c for c in result['clients'] if not c['stale']]
        self.assertEqual(len(kept), 1)
        self.assertTrue(kept[0]['ap_id'].startswith('webonly-'))
        ax3 = [ap for ap in result['aps'] if ap.get('web_only')][0]
        be3 = [ap for ap in result['aps'] if not ap.get('web_only')][0]
        ax3_body = payload(ax3, result, {}, 'http://unifi.test/inform', 1.0, {'ExampleWifi': 'w' * 24})
        be3_body = payload(be3, result, {}, 'http://unifi.test/inform', 1.0, {'ExampleSSID': 'w' * 24})
        self.assertEqual(sum(len(v['sta_table']) for v in ax3_body['vap_table']), 1)
        self.assertEqual(sum(len(v['sta_table']) for v in be3_body['vap_table']), 0)

    def test_positive_auth_row_still_wins_over_a_weak_web_row(self):
        mac = 'aa:bb:cc:dd:ee:22'
        pins = {'https://192.168.3.1': 'SYNTHAX30001'}
        now = time.time()
        result = normalize([self.be3_device('SYNTH0000003', mac, True)], now=now)
        rec = {'origin': 'https://192.168.3.1', 'serial': 'SYNTHAX30001',
               'source_type': 'web-api-only', 'transport': 'direct', 'router_ip': '192.168.3.1',
               'device': {'model': 'WS7200'}, 'clients': [{'mac': mac, 'band_norm': '5g'}],
               'inventory': {'profiles': [{'band': '5g', 'ssid': 'ExampleWifi', 'native_id': 'n-5',
                                           'usage': 'primary', 'standard': 'a/n/ac/ax',
                                           'enabled': True}]},
               'observed_at': now}
        result, _, _ = webonly.merge(result, {'h': rec}, {}, now=now, pins=pins)
        arbitrate(result, now=now)
        kept = [c for c in result['clients'] if not c['stale']]
        self.assertEqual(len(kept), 1)
        self.assertFalse(kept[0]['ap_id'].startswith('webonly-'))


class BoundedStateTests(unittest.TestCase):
    def test_missing_file_is_a_factory_state(self):
        with tempfile.TemporaryDirectory() as directory:
            self.assertEqual(read_auth_state(Path(directory) / 'none.json'), {'phase': 'factory'})

    def test_oversize_and_malformed_files_fail_closed_without_deleting(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'big.json'
            path.write_bytes(b'x' * (1024 * 1024 + 1))
            with self.assertRaises(ValueError):
                read_auth_state(path)
            self.assertTrue(path.exists())
            bad = Path(directory) / 'bad.json'
            bad.write_text('{not json')
            with self.assertRaises(ValueError):
                read_auth_state(bad)
            self.assertEqual(bad.read_text(), '{not json')


if __name__ == '__main__':
    unittest.main()
