import copy
import json
import os
import tempfile
import threading
import time
import unittest
import unittest.mock
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace

from huawei_bridge.__main__ import Application, handler
from huawei_bridge.collector import (enrich, mac, metric_capabilities, normalize, signal,
                                     virtual_mac)
from huawei_bridge.protocol import BOOTSTRAP_KEY, ProtocolError, decode, encode
from huawei_bridge.unifi import UniFi, apply_response, payload, validate_wlan_map

NOW = 1792184400
STAMP = '2026-10-16T21:00:00Z'
UUID = '11111111-2222-4333-8444-555555555555'


def field(value):
    return {'_value': value, '_timestamp': STAMP}


def fixture():
    wlan = {'SSID': field('Test <SSID>'), 'Channel': field(36), 'Enable': field(True),
            'BSSID': field('00:11:22:33:44:50'), 'AssociatedDevice': {'1': {
                'AssociatedDeviceMACAddress': field('00:11:22:33:44:66'),
                'AssociatedDeviceIPAddress': field('192.0.2.10'),
                'AssociatedDeviceRssi': field(55)}}}
    return [{'_id': 'test-ap', '_deviceId': {'_Manufacturer': 'Huawei Device Co., Ltd.',
            '_ProductClass': 'TestAP'}, '_lastInform': STAMP, 'InternetGatewayDevice': {
            'ManagementServer': {'ConnectionRequestURL': field('https://192.0.2.2:7547/callback')},
            'DeviceInfo': {'SoftwareVersion': field('test')},
            'LANDevice': {'1': {'WLANConfiguration': {'2': wlan}, 'Hosts': {'Host': {'1': {
                'MACAddress': field('00:11:22:33:44:66'), 'HostName': field('Client'),
                'IPAddress': field('192.0.2.10')}}}}}}}]


class CollectorTests(unittest.TestCase):
    def test_real_fields_and_identity(self):
        result = normalize(fixture(), NOW)
        ap, client = result['aps'][0], result['clients'][0]
        self.assertTrue(ap['online'])
        self.assertEqual(ap['ip'], '192.0.2.2')
        self.assertEqual(ap['client_count'], 1)
        self.assertEqual(client['signal'], -55)
        self.assertEqual(client['hostname'], 'Client')
        self.assertEqual(client['radio_id'], ap['radios'][0]['id'])
        self.assertEqual(ap['virtual_mac'], virtual_mac('test-ap'))
        self.assertEqual(int(ap['virtual_mac'][:2], 16) & 3, 2)

    def test_old_values_are_not_online(self):
        result = normalize(fixture(), NOW + 181)
        self.assertFalse(result['aps'][0]['online'])
        self.assertTrue(result['clients'][0]['stale'])
        self.assertEqual(result['aps'][0]['client_count'], 0)

    def test_deduplicate_and_disabled_radio(self):
        devices = fixture()
        radios = devices[0]['InternetGatewayDevice']['LANDevice']['1']['WLANConfiguration']
        radios['3'] = copy.deepcopy(radios['2'])
        self.assertEqual(len(normalize(devices, NOW)['clients']), 1)
        radios['2']['Enable'] = field(False)
        radios['3']['Enable'] = field(False)
        self.assertEqual(normalize(devices, NOW)['clients'], [])

    def test_unknown_signal_and_other_manufacturer(self):
        self.assertIsNone(signal(0))
        self.assertIsNone(signal(True))
        self.assertIsNone(signal(float('nan')))
        self.assertIsNone(mac('ff:ff:ff:ff:ff:ff'))
        devices = fixture()
        devices[0]['_deviceId']['_Manufacturer'] = 'Other'
        self.assertEqual(normalize(devices, NOW)['aps'], [])


class EnrichTests(unittest.TestCase):
    def snapshot(self):
        return normalize(fixture(), NOW)

    def web_entry(self, **overrides):
        entry = {'mac': '00:11:22:33:44:66', 'phy_mode': '802.11ax', 'rate_mbps': 864,
                 'rssi_dbm': -50, 'tx_kb': 1024, 'rx_kb': 2048, '_serial': 'test-ap',
                 'router_ip': '192.0.2.2', '_ts': NOW - 10}
        entry.update(overrides)
        return entry

    def test_fresh_matching_router_evidence_merges(self):
        snapshot = self.snapshot()
        enrich(snapshot, {'by_mac': {'00:11:22:33:44:66': self.web_entry()},
                          'ttl_seconds': 600}, now=NOW)
        client = snapshot['clients'][0]
        self.assertEqual(client['phy_mode'], '802.11ax')
        self.assertEqual(client['radio_proto'], 'ax')
        self.assertEqual(client['rate_mbps'], 864.0)
        self.assertEqual(client['signal'], -50)
        self.assertEqual(client['tx_kb'], 1024)
        self.assertEqual(client['rx_kb'], 2048)

    def test_stale_evidence_never_merges(self):
        snapshot = self.snapshot()
        enrich(snapshot, {'by_mac': {'00:11:22:33:44:66': self.web_entry(_ts=NOW - 601)}}, now=NOW)
        client = snapshot['clients'][0]
        for key in ('phy_mode', 'radio_proto', 'rate_mbps', 'tx_kb', 'rx_kb'):
            self.assertNotIn(key, client)
        self.assertEqual(client['signal'], -55)  # TR-069 value untouched.

    def test_ttl_from_publisher_is_honored(self):
        snapshot = self.snapshot()
        enrich(snapshot, {'by_mac': {'00:11:22:33:44:66': self.web_entry(_ts=NOW - 31)},
                          'ttl_seconds': 30}, now=NOW)
        self.assertNotIn('phy_mode', snapshot['clients'][0])
        enrich(snapshot, {'by_mac': {'00:11:22:33:44:66': self.web_entry(_ts=NOW - 31)},
                          'ttl_seconds': 600}, now=NOW)
        self.assertIn('phy_mode', snapshot['clients'][0])

    def test_evidence_from_another_router_is_rejected(self):
        snapshot = self.snapshot()
        enrich(snapshot, {'by_mac': {'00:11:22:33:44:66':
                                     self.web_entry(router_ip='192.0.2.99')}}, now=NOW)
        for key in ('phy_mode', 'rate_mbps', 'tx_kb'):
            self.assertNotIn(key, snapshot['clients'][0])

    def test_ambiguous_rate_never_fabricates_directional_tx_rate(self):
        snapshot = self.snapshot()
        enrich(snapshot, {'by_mac': {'00:11:22:33:44:66': self.web_entry()}}, now=NOW)
        client = snapshot['clients'][0]
        self.assertIn('rate_mbps', client)
        self.assertNotIn('tx_rate', client)
        self.assertNotIn('rx_rate', client)

    def test_zero_is_unknown_for_rate_and_rssi_but_real_for_traffic(self):
        snapshot = self.snapshot()
        enrich(snapshot, {'by_mac': {'00:11:22:33:44:66': self.web_entry(
            rate_mbps=0, rssi_dbm=0, tx_kb=0, rx_kb=None)}}, now=NOW)
        client = snapshot['clients'][0]
        self.assertNotIn('rate_mbps', client)   # Zero negotiated rate is unknown.
        self.assertNotIn('rssi_dbm', client)
        self.assertEqual(client['signal'], -55)  # TR-069 signal kept.
        self.assertEqual(client['tx_kb'], 0)     # Zero traffic is a real reading.
        self.assertNotIn('rx_kb', client)        # Missing stays absent.

    def test_missing_or_malformed_web_payload_is_ignored(self):
        snapshot = self.snapshot()
        for web in (None, 'x', 42, {}, {'by_mac': None}, {'by_mac': 'x'},
                    {'by_mac': {'00:11:22:33:44:66': 'x'}}, {'by_mac': {None: self.web_entry()}}):
            enrich(snapshot, web, now=NOW)
        client = snapshot['clients'][0]
        self.assertNotIn('phy_mode', client)
        self.assertEqual(client['signal'], -55)

    def test_missing_router_ip_or_serial_or_future_ts_never_merges(self):
        for overrides in ({'router_ip': None}, {'_serial': None}, {'_serial': 'other-cpe'},
                          {'_ts': NOW + 60}):
            snapshot = self.snapshot()
            enrich(snapshot, {'by_mac': {'00:11:22:33:44:66': self.web_entry(**overrides)}},
                   now=NOW)
            client = snapshot['clients'][0]
            self.assertNotIn('phy_mode', client)
            self.assertEqual(client['signal'], -55)


class WlanMapTests(unittest.TestCase):
    def test_valid_uuid_and_24hex_accepted_and_normalized(self):
        mapping = validate_wlan_map({'ExampleSSID': UUID.upper()})
        self.assertEqual(mapping['ExampleSSID'], UUID)
        mapping = validate_wlan_map({'ExampleSSID': UUID.upper()})
        self.assertEqual(mapping['ExampleSSID'], UUID)
        mapping = validate_wlan_map({'ExampleSSID': ' ' + UUID + ' '})
        self.assertEqual(mapping['ExampleSSID'], UUID)
        mapping = validate_wlan_map({'Legacy': '0123456789ABCDEF01234567'})
        self.assertEqual(mapping['Legacy'], '0123456789abcdef01234567')

    def test_invalid_wlan_ids_are_rejected(self):
        for invalid in ('11111111-2222-4333-8444-55555555555',      # truncated UUID
                        '11111111_2222-4333-8444-555555555555',     # wrong separator
                        'g1fbd724-2068-43c5-8ac2-58a679052996',     # non-hex character
                        '11111111-2222-4333-8444-5555555555550',    # too long
                        '11111111222243338444555555555555',         # 32 hex without dashes
                        '{' + UUID + '}',                           # braced
                        '0123456789abcdef0123456',                  # 23 hex
                        '0123456789abcdef012345678',                # 25 hex
                        ''):
            with self.subTest(invalid=invalid):
                with self.assertRaises(ValueError):
                    validate_wlan_map({'ExampleSSID': invalid})
        for bad_map in ([], {'SSID': 'fake'}, {'': UUID}, {'SSID': None},
                        {'x' * 33: UUID}, {5: UUID}, {'ExampleSSID': 12345}):
            with self.assertRaises(ValueError):
                validate_wlan_map(bad_map)

    def test_uuid_reaches_vap_table_id(self):
        snapshot = normalize(fixture(), NOW)
        body = payload(snapshot['aps'][0], snapshot, {}, 'http://192.0.2.1:8080/inform', 12,
                       {'Test <SSID>': UUID})
        self.assertEqual(body['vap_table'][0]['id'], UUID)
        self.assertEqual(body['vap_table'][0]['essid'], 'Test <SSID>')


class ProtocolTests(unittest.TestCase):
    def test_radio_capabilities_are_not_client_generations_or_measured_width(self):
        raw = fixture()
        wlan = raw[0]['InternetGatewayDevice']['LANDevice']['1']['WLANConfiguration']['2']
        wlan['Standard'] = field('a/n/ac/ax/be')
        raw[0]['_deviceId']['_ProductClass'] = 'WUKUN-BE32'
        snapshot = normalize(raw, NOW)
        body = payload(snapshot['aps'][0], snapshot, {}, 'http://192.0.2.1:8080/inform', 12,
                       {'Test <SSID>': '0123456789abcdef01234567'})
        radio = body['radio_table'][0]
        self.assertTrue(radio['has_ht160'])
        self.assertTrue(radio['is_11ac'] and radio['is_11ax'] and radio['is_11be'])
        self.assertNotIn('bw', body['radio_table_stats'][0])
        self.assertEqual(body['radio_table_stats'][0]['channel'], 36)
        self.assertNotIn('is_11be', body['vap_table'][0]['sta_table'][0])
        wlan['Standard'] = field('b/g/n/ax')
        wlan['Channel'] = field(1)
        snapshot = normalize(raw, NOW)
        radio = payload(snapshot['aps'][0], snapshot, {}, 'http://192.0.2.1:8080/inform', 12)['radio_table'][0]
        self.assertTrue(radio['is_11ax'])
        self.assertFalse(radio['is_11be'] or radio['is_11ac'] or radio['has_ht160'])

    def test_invalid_wlan_map_is_rejected(self):
        for invalid in ([], {'SSID': 'fake'}, {'': '0123456789abcdef01234567'},
                        {'SSID': None}, {'x' * 33: '0123456789abcdef01234567'}):
            with self.assertRaises(ValueError):
                validate_wlan_map(invalid)

    def test_wlan_id_uses_controller_mapping(self):
        snapshot = normalize(fixture(), NOW)
        wlan_id = '0123456789abcdef01234567'
        body = payload(snapshot['aps'][0], snapshot, {}, 'http://192.0.2.1:8080/inform', 12,
                       {'Test <SSID>': wlan_id})
        self.assertEqual(body['vap_table'][0]['id'], wlan_id)
        self.assertEqual(body['vap_table'][0]['essid'], 'Test <SSID>')
        self.assertEqual(body['vap_table'][0]['num_sta'], 1)
        self.assertEqual(body['model'], 'U7PRO')
        self.assertEqual(body['required_version'], '8.0.28')
        self.assertEqual({r['radio'] for r in body['radio_table']}, {'na'})
        self.assertNotIn('channel_width', body['radio_table'][0])

    def test_unmapped_wlan_is_not_exported(self):
        snapshot = normalize(fixture(), NOW)
        body = payload(snapshot['aps'][0], snapshot, {}, 'http://192.0.2.1:8080/inform', 12)
        self.assertEqual(body['vap_table'], [])
        self.assertEqual(len(body['radio_table']), 1)

    def test_crypto_and_tamper(self):
        for mode in ('cbc', 'gcm'):
            raw = encode({'_type': 'noop'}, '02:00:00:00:00:01', mode=mode)
            self.assertEqual(decode(raw).body, {'_type': 'noop'})
            with self.assertRaises(ProtocolError):
                decode(raw[:-1])

    def test_commands_do_not_apply(self):
        state = {'phase': 'factory'}
        for kind in ('reboot', 'upgrade', 'cmd'):
            apply_response(state, {'_type': kind, 'command': 'touch /tmp/never'})
        self.assertEqual(state, {'phase': 'factory'})
        with self.assertRaises(ProtocolError):
            apply_response(state, {'_type': 'setparam', 'mgmt_cfg': 'authkey=invalid'})

    def test_payload_observed_clients_only(self):
        snapshot = normalize(fixture(), NOW)
        ap = snapshot['aps'][0]
        body = payload(ap, snapshot, {}, 'http://192.0.2.1:8080/inform', 12,
                       {'Test <SSID>': '0123456789abcdef01234567'})
        self.assertEqual(body['vap_table'][0]['num_sta'], 1)
        self.assertEqual(body['vap_table'][0]['sta_table'][0]['signal'], -55)
        self.assertEqual(len(body['vap_table'][0]['id']), 24)
        self.assertEqual(body['vap_table'][0]['sta_table'][0]['essid'], 'Test <SSID>')
        self.assertNotIn('tx_bytes', body['vap_table'][0])
        self.assertNotEqual(body['mac'], ap['radios'][0]['bssid'])

    def test_directional_fields_propagate_only_when_explicit(self):
        snapshot = normalize(fixture(), NOW)
        snapshot['clients'][0]['tx_rate'] = 864000
        snapshot['clients'][0]['radio_proto'] = 'ax'
        body = payload(snapshot['aps'][0], snapshot, {}, 'http://192.0.2.1:8080/inform', 12,
                       {'Test <SSID>': '0123456789abcdef01234567'})
        station = body['vap_table'][0]['sta_table'][0]
        self.assertEqual(station['tx_rate'], 864000)
        self.assertEqual(station['radio_proto'], 'ax')
        self.assertNotIn('rate_mbps', station)   # Internal unit never leaks to UniFi.
        del snapshot['clients'][0]['tx_rate']
        body = payload(snapshot['aps'][0], snapshot, {}, 'http://192.0.2.1:8080/inform', 12,
                       {'Test <SSID>': '0123456789abcdef01234567'})
        self.assertNotIn('tx_rate', body['vap_table'][0]['sta_table'][0])

    def test_live_peer_adoption_and_restart(self):
        private_key = bytes.fromhex('11223344556677889900aabbccddeeff')
        received = []

        class Peer(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_POST(self):
                key = BOOTSTRAP_KEY if not received else private_key
                packet = decode(self.rfile.read(int(self.headers['Content-Length'])), key)
                received.append(packet)
                response = {'_type': 'setparam', 'mgmt_cfg': 'authkey=' + private_key.hex() + '\nuse_aes_gcm=true'} if len(received) == 1 else {'_type': 'noop'}
                raw = encode(response, packet.mac, key, mode=packet.mode)
                self.send_response(200)
                self.end_headers()
                self.wfile.write(raw)

        peer = ThreadingHTTPServer(('127.0.0.1', 0), Peer)
        thread = threading.Thread(target=peer.serve_forever, daemon=True)
        thread.start()
        try:
            with tempfile.TemporaryDirectory() as tmp:
                url = f'http://127.0.0.1:{peer.server_port}/inform'
                snapshot = normalize(fixture(), NOW)
                ap = snapshot['aps'][0]
                mapping = {'Test <SSID>': UUID}
                UniFi(tmp, url, mapping).exchange(ap, snapshot)
                restarted = UniFi(tmp, url, mapping)
                restarted.exchange(ap, snapshot)
                self.assertEqual(restarted.status[ap['virtual_mac']]['phase'], 'exchanging')
                self.assertEqual(received[1].mode, 'gcm')
                self.assertEqual(received[1].body['vap_table'][0]['id'], UUID)
                self.assertEqual(restarted.status[ap['virtual_mac']]['stations_sent'], 1)
                statefile = next(Path(tmp).glob('*.json'))
                self.assertEqual(statefile.stat().st_mode & 0o777, 0o600)
                with self.assertRaises(ValueError):
                    UniFi(tmp, 'http://127.0.0.2:8080/inform').exchange(ap, snapshot)
        finally:
            peer.shutdown()
            peer.server_close()


class AllowlistedControlStub:
    allowed_ips = {'192.0.2.2'}

    def mapping(self, ap, original):
        return dict(original)

    def ack(self, ap):
        return None

    def receive(self, ap, response, device, mapping):
        pass

    def reject(self, ap, error):
        pass

    def reset(self, ap):
        pass

    def public(self, ap):
        return {'enabled': ap.get('ip') in self.allowed_ips}


class RejectingControlStub(AllowlistedControlStub):
    def receive(self, ap, response, device, mapping):
        raise ValueError('Multiple VAPs on one Huawei radio are not supported')

    def reject(self, ap, error):
        self.last_reject = str(error)

    def public(self, ap):
        return {'enabled': True, 'phase': 'rejected', 'error': getattr(self, 'last_reject', None)}


class StaleAckControlStub(AllowlistedControlStub):
    def ack(self, ap):
        return 'stale-cpe-ack'

    def public(self, ap):
        return {'enabled': True, 'phase': 'baseline'}


class ExchangeControlTests(unittest.TestCase):
    def test_reporting_echoes_controller_revision_not_stale_cpe_ack(self):
        provision_revision = 'new-rev-0002'
        informed = []

        class Peer(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_POST(self):
                packet = decode(self.rfile.read(int(self.headers['Content-Length'])), BOOTSTRAP_KEY)
                informed.append(packet.body.get('cfgversion', ''))
                response = {'_type': 'setparam', 'cfgversion': provision_revision,
                            'system_cfg': 'radio.1.phyname=wifi0\nradio.1.status=enabled\n'}
                raw = encode(response, packet.mac, BOOTSTRAP_KEY, mode=packet.mode)
                self.send_response(200)
                self.end_headers()
                self.wfile.write(raw)

        peer = ThreadingHTTPServer(('127.0.0.1', 0), Peer)
        threading.Thread(target=peer.serve_forever, daemon=True).start()
        try:
            with tempfile.TemporaryDirectory() as tmp:
                url = f'http://127.0.0.1:{peer.server_port}/inform'
                snapshot = normalize(fixture(), NOW)
                unifi = UniFi(tmp, url, {'Test <SSID>': UUID}, control=StaleAckControlStub(),
                              device_lookup=lambda _id: {})
                unifi.exchange(snapshot['aps'][0], snapshot)
                unifi.exchange(snapshot['aps'][0], snapshot)
                # First inform carries the CPE ack; once the controller announces
                # its own revision the device must echo THAT, never the stale ack.
                self.assertEqual(informed[1], provision_revision)
                statefile = json.loads(next(Path(tmp).glob('*.json')).read_text())
                self.assertEqual(statefile['cfgversion'], provision_revision)
        finally:
            peer.shutdown()
            peer.server_close()

    def test_cpe_rejection_never_stalls_controller_provision_ack(self):
        provision_revision = 'prov-rev-0001'
        informed = []

        class Peer(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_POST(self):
                packet = decode(self.rfile.read(int(self.headers['Content-Length'])), BOOTSTRAP_KEY)
                informed.append(packet.body.get('cfgversion', ''))
                response = {'_type': 'setparam', 'cfgversion': provision_revision,
                            'system_cfg': 'radio.1.phyname=wifi0\nradio.1.channel=auto\n'
                                          'wireless.1.parent=wifi0\nwireless.1.ssid=Lab\n'
                                          'wireless.2.parent=wifi0\nwireless.2.ssid=Guest\n'}
                raw = encode(response, packet.mac, BOOTSTRAP_KEY, mode=packet.mode)
                self.send_response(200)
                self.end_headers()
                self.wfile.write(raw)

        peer = ThreadingHTTPServer(('127.0.0.1', 0), Peer)
        threading.Thread(target=peer.serve_forever, daemon=True).start()
        try:
            with tempfile.TemporaryDirectory() as tmp:
                url = f'http://127.0.0.1:{peer.server_port}/inform'
                snapshot = normalize(fixture(), NOW)
                control = RejectingControlStub()
                unifi = UniFi(tmp, url, {'Test <SSID>': UUID}, control=control,
                              device_lookup=lambda _id: {})
                unifi.exchange(snapshot['aps'][0], snapshot)
                # First inform requests the baseline with an empty cfgversion.
                self.assertEqual(informed[0], '')
                unifi.exchange(snapshot['aps'][0], snapshot)
                # The CPE translation was rejected, but the device must still echo
                # the controller's revision: a stalled ack keeps the UCG in state=5
                # with num_sta=0.
                self.assertEqual(informed[1], provision_revision)
                statefile = json.loads(next(Path(tmp).glob('*.json')).read_text())
                self.assertEqual(statefile['cfgversion'], provision_revision)
                # The rejection stays visible in status reporting.
                self.assertEqual(unifi.status[snapshot['aps'][0]['virtual_mac']]['configuration'],
                                 {'enabled': True, 'phase': 'rejected',
                                  'error': 'Multiple VAPs on one Huawei radio are not supported'})
        finally:
            peer.shutdown()
            peer.server_close()

    def test_exchange_with_allowlist_set_control_never_attribute_errors(self):
        private_key = bytes.fromhex('aabbccddeeff00112345678900aabbcc')
        state = {'round': 0}

        class Peer(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_POST(self):
                state['round'] += 1
                packet = decode(self.rfile.read(int(self.headers['Content-Length'])), BOOTSTRAP_KEY)
                response = {'_type': 'setparam', 'mgmt_cfg': 'authkey=' + private_key.hex()}
                raw = encode(response, packet.mac, BOOTSTRAP_KEY, mode=packet.mode)
                self.send_response(200)
                self.end_headers()
                self.wfile.write(raw)

        peer = ThreadingHTTPServer(('127.0.0.1', 0), Peer)
        threading.Thread(target=peer.serve_forever, daemon=True).start()
        try:
            with tempfile.TemporaryDirectory() as tmp:
                url = f'http://127.0.0.1:{peer.server_port}/inform'
                snapshot = normalize(fixture(), NOW)
                unifi = UniFi(tmp, url, {'Test <SSID>': UUID}, control=AllowlistedControlStub())
                # Pre-2212 builds compared self.control.allowed_ip and crashed with
                # AttributeError; membership against the set must keep working.
                unifi.exchange(snapshot['aps'][0], snapshot)
                self.assertEqual(unifi.status[snapshot['aps'][0]['virtual_mac']]['phase'], 'key-received')
                self.assertEqual(unifi.status[snapshot['aps'][0]['virtual_mac']]['configuration'],
                                 {'enabled': True})
        finally:
            peer.shutdown()
            peer.server_close()


class ApplicationTests(unittest.TestCase):
    def setUp(self):
        self._env = {}
        self.tmp = tempfile.TemporaryDirectory()
        for key, value in [('STATE_DIR', self.tmp.name),
                           ('GENIEACS_URL', 'http://127.0.0.1:59999'),
                           ('WEBENRICH_URL', 'http://127.0.0.1:59998'),
                           ('UNIFI_INFORM_URL', ''),
                           ('UNIFI_WLAN_MAP', '{}'),
                           ('HUAWEI_CONTROL_IP', ''),
                           ('PUBLIC_URL', 'http://127.0.0.1:8090')]:
            self._env[key] = os.environ.get(key)
            os.environ[key] = value

    def tearDown(self):
        self.tmp.cleanup()
        for key, value in self._env.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value

    def test_broken_webcol_does_not_break_snapshot_or_informs(self):
        app = Application()
        self.addCleanup(app.close)
        app.devices = fixture()
        snapshot = app.snapshot()
        self.assertEqual(len(snapshot['aps']), 1)
        self.assertEqual(len(snapshot['clients']), 1)
        self.assertNotIn('phy_mode', snapshot['clients'][0])  # Enrichment absent, data intact.
        # The inform worker path must stay a no-op success when UniFi is disabled.
        app.unifi.tick(snapshot)
        self.assertEqual(app.unifi.status, {})
        # Health stays truthful about ACS, independent of webcol.
        self.assertIsNone(snapshot['acs_last_collection'])
        self.assertIsNone(snapshot['acs_error'])

    def test_snapshot_surfaces_control_rejections_as_warnings(self):
        app = Application()
        self.addCleanup(app.close)
        app.devices = fixture()
        app.unifi.status = {'02:00:00:00:00:fa': {'phase': 'exchanging', 'experimental': True,
                                                  'configuration': {'phase': 'rejected',
                                                                    'error': 'Multiple VAPs on one Huawei radio are not supported'}}}
        snapshot = app.snapshot()
        self.assertTrue(any('Provisión CPE' in warning for warning in snapshot['warnings']))
        app.unifi.status = {'02:00:00:00:00:fa': {'phase': 'exchanging', 'experimental': True,
                                                  'configuration': {'phase': 'baseline', 'error': None}}}
        snapshot = app.snapshot()
        self.assertFalse(any('Provisión CPE' in warning for warning in snapshot['warnings']))

    def test_snapshot_uses_cached_enrichment_within_ttl(self):
        payloads = []

        class EnrichPeer(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_GET(self):
                if self.path.split('?', 1)[0] == '/enrich':
                    payloads.append(1)
                body = json.dumps({'by_mac': {}, 'ttl_seconds': 600}).encode()
                self.send_response(200)
                self.send_header('Content-Length', str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        peer = ThreadingHTTPServer(('127.0.0.1', 0), EnrichPeer)
        threading.Thread(target=peer.serve_forever, daemon=True).start()
        try:
            os.environ['WEBENRICH_URL'] = f'http://127.0.0.1:{peer.server_port}'
            app = Application()
            self.addCleanup(app.close)
            app.devices = fixture()
            app.snapshot()
            app.snapshot()
            app.snapshot()
            self.assertEqual(len(payloads), 1)  # Throttled: cache reused within the window.
        finally:
            peer.shutdown()
            peer.server_close()


class WebTests(unittest.TestCase):
    def test_host_and_origin_boundary(self):
        app = SimpleNamespace(allowed_hosts={'127.0.0.1:8090'}, public_url='http://127.0.0.1:8090',
                              snapshot=lambda: {'aps': []}, unifi=SimpleNamespace(status={}),
                              last_collection=time.time(), last_error=None)
        server = ThreadingHTTPServer(('127.0.0.1', 0), handler(app))
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        url = f'http://127.0.0.1:{server.server_port}/api/snapshot'
        try:
            req = urllib.request.Request(url, headers={'Host': '127.0.0.1:8090'})
            with urllib.request.urlopen(req) as response:
                self.assertEqual(json.load(response), {'aps': []})
            req.add_header('Origin', 'https://attacker.example')
            with self.assertRaises(urllib.error.HTTPError) as error:
                urllib.request.urlopen(req)
            self.assertEqual(error.exception.code, 403)
            error.exception.close()
            health = urllib.request.Request(f'http://127.0.0.1:{server.server_port}/health',
                                            headers={'Host': '127.0.0.1:8090'})
            with urllib.request.urlopen(health) as response:
                body = json.load(response)
            self.assertIn('unifi_errors', body)
        finally:
            server.shutdown()
            server.server_close()


def counter(value, stamp=STAMP, field_type='xsd:unsignedInt'):
    return {'_value': value, '_timestamp': stamp, '_type': field_type}


def ap_with_counters():
    return {'id': 'ap-bytes', 'ip': '192.0.2.11', 'online': True,
            'virtual_mac': '02:00:00:00:00:0b', 'name': 'WUKUN-BE32',
            'inventory': {'trusted': True, 'identity': 'trusted', 'fresh': True,
                          'observed_at': NOW},
            'radios': [{'id': 'p1', 'band': '5g', 'ssid': 'Test <SSID>', 'channel': 36,
                        'enabled': True, 'standards': ['ax'], 'stale': False,
                        'bssid': '00:11:22:33:44:50'}]}


class SystemStatsPayloadTests(unittest.TestCase):
    def ap_with_stats(self, **stats):
        ap = ap_with_counters()
        ap['device_stats'] = stats
        return ap

    def build(self, ap):
        snapshot = {'clients': [], 'aps': [ap]}
        return payload(ap, snapshot, {}, 'http://unifi.test/inform', 99)

    def test_system_stats_carry_real_cpu_mem_and_uptime(self):
        body = self.build(self.ap_with_stats(cpu_percent=5, mem_percent=36, uptime_seconds=12345))
        self.assertEqual(body['system-stats'], {'cpu': '5', 'mem': '36', 'uptime': '12345'})
        self.assertEqual(body['uptime'], 12345)

    def test_float_percent_is_preserved(self):
        body = self.build(self.ap_with_stats(cpu_percent=7.5, mem_percent=36.25,
                                             uptime_seconds=8))
        self.assertEqual(body['system-stats'], {'cpu': '7.5', 'mem': '36.25', 'uptime': '8'})

    def test_bridge_session_uptime_is_never_published_as_device_uptime(self):
        body = self.build(ap_with_counters())
        self.assertNotIn('uptime', body)
        self.assertNotIn('system-stats', body)

    def test_missing_uptime_omits_only_the_uptime_field(self):
        body = self.build(self.ap_with_stats(cpu_percent=5, mem_percent=36))
        self.assertEqual(body['system-stats'], {'cpu': '5', 'mem': '36'})
        self.assertNotIn('uptime', body)

    def test_absolute_memory_bytes_are_never_invented(self):
        body = self.build(self.ap_with_stats(cpu_percent=5, mem_percent=36, uptime_seconds=1))
        self.assertNotIn('sys_stats', body)
        self.assertNotIn('mem_total', json.dumps(body))
        self.assertNotIn('mem_used', json.dumps(body))


class WlanCounterObservationTests(unittest.TestCase):
    def devices(self):
        def wlan(ssid, channel, bssid, sent):
            return {'SSID': field(ssid), 'Channel': field(channel), 'Enable': field(True),
                    'BSSID': field(bssid), 'TotalBytesSent': counter(sent),
                    'TotalBytesReceived': counter(196737964),
                    'Stats': {'ErrorsSent': counter(0)}, 'AssociatedDevice': {}}
        lan = {'WLANConfiguration': {'2': wlan('A', 36, 'aa:bb:cc:dd:ee:01', 2744285448),
                                     '3': wlan('B', 6, 'aa:bb:cc:dd:ee:02', 2744285576)},
               'Hosts': {'Host': {}}}
        return [{'_id': 'ap-x', '_deviceId': {'_Manufacturer': 'Huawei Device Co., Ltd.',
                 '_ProductClass': 'X'}, '_lastInform': STAMP,
                 'InternetGatewayDevice': {'ManagementServer': {},
                                           'DeviceInfo': {'SoftwareVersion': field('v')},
                                           'LANDevice': {'1': lan}}}]

    def test_observations_keep_leaf_timestamp_unit_and_unverified_scope(self):
        ap = normalize(self.devices(), NOW)['aps'][0]
        obs = [o for o in ap['wlan_counters'] if o['metric'] == 'total_bytes_sent']
        self.assertEqual(len(obs), 2)
        first = obs[0]
        self.assertEqual(first['unit'], 'bytes')
        self.assertEqual(first['direction'], 'tx')
        self.assertEqual(first['scope'], 'interface-unverified')
        self.assertEqual(first['observed_at'], 1792184400.0)
        self.assertEqual(first['field_type'], 'xsd:unsignedInt')
        self.assertTrue(first['interface'].endswith('WLANConfiguration.2'))
        self.assertEqual(first['cpe'], 'ap-x')

    def test_near_identical_interfaces_are_flagged_shared_not_summed(self):
        ap = normalize(self.devices(), NOW)['aps'][0]
        bytes_obs = [o for o in ap['wlan_counters'] if o['metric'] == 'total_bytes_sent']
        self.assertTrue(all(o['group'] == 'shared_or_mirrored_unverified' for o in bytes_obs))
        self.assertNotIn('tx_bytes', json.dumps({k: v for k, v in ap.items()
                                                 if k != 'wlan_counters'}))

    def test_metric_capabilities_blocks_unverified_counters(self):
        ap = normalize(self.devices(), NOW)['aps'][0]
        ap['device_stats'] = {'cpu_percent': 5, 'mem_percent': 36, 'uptime_seconds': 12345,
                              'observed_at': NOW, 'source': 'huawei-web',
                              'unavailable_reason': None}
        caps = metric_capabilities(ap, now=NOW)
        self.assertEqual(caps['available']['cpu_percent']['value'], 5)
        self.assertEqual(caps['available']['uptime_seconds']['unit'], 'seconds')
        self.assertEqual(caps['blocked']['total_bytes_sent']['reason'],
                         'shared_or_mirrored_unverified')
        self.assertIn('tx_retries', caps['unavailable_in_observed_sources'])
        self.assertEqual(caps['client_per_station_traffic'], 'client_per_station_traffic_unusable')

    def test_capability_reports_absent_metrics_with_a_source_reason(self):
        ap = normalize(self.devices(), NOW)['aps'][0]
        caps = metric_capabilities(ap, now=NOW)
        self.assertEqual(caps['available'], {})
        self.assertIn('cpu_percent', caps['unavailable'])


class ApplicationCounterStateTests(unittest.TestCase):
    def app_in(self, directory):
        patcher = unittest.mock.patch.dict(
            os.environ, {'STATE_DIR': directory, 'UNIFI_WLAN_MAP': '{}',
                         'HUAWEI_CONTROL_IP': ''}, clear=False)
        patcher.start()
        self.addCleanup(patcher.stop)
        app = Application()
        self.addCleanup(app.close)
        app.web_enrichment = lambda: None
        app.web_inventory = lambda: None
        return app

    def test_corrupt_counter_state_does_not_break_startup_or_snapshot(self):
        with tempfile.TemporaryDirectory() as directory:
            metrics_dir = os.path.join(directory, 'metrics')
            os.makedirs(metrics_dir)
            state_path = os.path.join(metrics_dir, 'counters_v1.json')
            with open(state_path, 'w') as handle:
                handle.write('{"schema_version": 1, "entries": {"k": {"value": 1, '
                             '"samples": "invalid"}}}')
            app = self.app_in(directory)
            snap = app.snapshot()
            counter_state = snap['metric_capabilities']['counter_state']
            self.assertFalse(counter_state['persistence_enabled'])
            self.assertEqual(counter_state['degraded_reason'], 'state-entry-invalid')
            self.assertTrue(any('degradado' in warning for warning in snap['warnings']))
            self.assertEqual(len(snap['aps']), 0)
            self.assertEqual(app.last_error, None)

    def test_snapshot_never_calls_blocking_save_inline(self):
        with tempfile.TemporaryDirectory() as directory:
            app = self.app_in(directory)
            app.devices = fixture()
            app.counters.save = unittest.mock.Mock(
                side_effect=AssertionError('inline save on the snapshot path'))
            snap = app.snapshot()
            self.assertIn('counter_observations', snap)
            app.counters.save.assert_not_called()

    def test_extreme_counter_integer_does_not_prevent_application_startup(self):
        with tempfile.TemporaryDirectory() as directory:
            metrics_dir = os.path.join(directory, 'metrics')
            os.makedirs(metrics_dir)
            state_path = os.path.join(metrics_dir, 'counters_v1.json')
            with open(state_path, 'w') as handle:
                json.dump({'schema_version': 1, 'entries': {
                    'k': {'value': 10 ** 400, 'samples': 1, 'resets': 0}}}, handle)
            app = self.app_in(directory)
            snap = app.snapshot()
            self.assertFalse(snap['metric_capabilities']['counter_state']['persistence_enabled'])
            self.assertEqual(app.last_error, None)


if __name__ == '__main__':
    unittest.main()
