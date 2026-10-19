"""Offline tests for the direct Huawei web API client (webcol/huawei_api.py).

Everything here is synthetic: fixed salts, nonces, RSA modulus and a password
that exist only in this file. No real router credential, salt, proof, cookie
or public key is ever written into the test suite. Known vectors are hardcoded
from the documented upstream/CryptoJS SCRAM algorithm and recomputed by an
independent inline reference implementation so a regression in either
direction is caught.
"""

import hashlib
import hmac
import importlib.util
import json
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

WEBROOT = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location('huawei_api_under_test',
                                               WEBROOT / 'webcol' / 'huawei_api.py')
huawei_api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(huawei_api)

SYNTH_PASSWORD = 'unit-test-only-password'
SYNTH_SALT = '0011223344'
SYNTH_ITERATIONS = 1000
SYNTH_FIRST = 'firstnonce-a'
SYNTH_SERVER = 'servernonce-b'
SYNTH_RSAN = 'ab' * 32
SYNTH_RSAE = '10001'
# Computed offline from the router CryptoJS SCRAM source, whose HMAC helper is
# HmacSHA256(message, key): clientproof = clientKey XOR HMAC(key=auth,
# msg=storedKey); serversig = HMAC(key=auth, msg=serverKey); rsapubkeysig =
# HMAC(key=serverKey, msg=fromhex(rsan)).
SYNTH_PROOF = '501430be70c7785191db49c4e5e96e60b8c228928e8e83ed7c2e70e7fecdb5d5'
SYNTH_SERVERSIG = '073e0cd66699d376e7ca3d4eb47fdf7a49cfd3f69507c03d356e7e3736075c5a'
SYNTH_RSASIG = '8cd5ce80f078dde6cb00b51db4ac2d30ef46c3fe41970cadafb031b68ac9c988'


def _salted(password, salt_hex, iterations):
    return hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'),
                               bytes.fromhex(salt_hex), int(iterations), 32)


def reference_proof(password, salt_hex, iterations, first_nonce, server_nonce):
    auth = f'{first_nonce},{server_nonce},{server_nonce}'.encode('utf-8')
    salted = _salted(password, salt_hex, iterations)
    client_key = hmac.new(b'Client Key', salted, hashlib.sha256).digest()
    stored_key = hashlib.sha256(client_key).digest()
    signature = hmac.new(auth, stored_key, hashlib.sha256).digest()
    return bytes(k ^ s for k, s in zip(client_key, signature)).hex()


def reference_server_signature(password, salt_hex, iterations, first_nonce, server_nonce):
    auth = f'{first_nonce},{server_nonce},{server_nonce}'.encode('utf-8')
    server_key = hmac.new(b'Server Key', _salted(password, salt_hex, iterations),
                          hashlib.sha256).digest()
    return hmac.new(auth, server_key, hashlib.sha256).hexdigest()


def reference_rsa_signature(password, salt_hex, iterations, rsan_hex):
    server_key = hmac.new(b'Server Key', _salted(password, salt_hex, iterations),
                          hashlib.sha256).digest()
    return hmac.new(server_key, bytes.fromhex(rsan_hex), hashlib.sha256).hexdigest()


class ClientProofTests(unittest.TestCase):
    def test_synthetic_known_vector_matches_reference(self):
        computed = huawei_api.client_proof(SYNTH_PASSWORD, SYNTH_SALT,
                                           SYNTH_ITERATIONS, SYNTH_FIRST, SYNTH_SERVER)
        self.assertEqual(computed, reference_proof(SYNTH_PASSWORD, SYNTH_SALT,
                                                   SYNTH_ITERATIONS, SYNTH_FIRST, SYNTH_SERVER))
        self.assertEqual(computed, SYNTH_PROOF)

    def test_server_and_rsa_signatures_match_reference_and_vectors(self):
        server_sig = huawei_api.server_signature(SYNTH_PASSWORD, SYNTH_SALT,
                                                 SYNTH_ITERATIONS, SYNTH_FIRST, SYNTH_SERVER)
        self.assertEqual(server_sig, reference_server_signature(
            SYNTH_PASSWORD, SYNTH_SALT, SYNTH_ITERATIONS, SYNTH_FIRST, SYNTH_SERVER))
        self.assertEqual(server_sig, SYNTH_SERVERSIG)
        _, _, server_key = huawei_api.derive_scram_keys(SYNTH_PASSWORD, SYNTH_SALT,
                                                        SYNTH_ITERATIONS)
        rsa_sig = huawei_api.rsa_key_signature(server_key, SYNTH_RSAN)
        self.assertEqual(rsa_sig, reference_rsa_signature(
            SYNTH_PASSWORD, SYNTH_SALT, SYNTH_ITERATIONS, SYNTH_RSAN))
        self.assertEqual(rsa_sig, SYNTH_RSASIG)

    def test_proof_is_deterministic_hex64_and_input_sensitive(self):
        base = huawei_api.client_proof(SYNTH_PASSWORD, SYNTH_SALT, 1000, 'n1', 'n2')
        self.assertEqual(len(base), 64)
        int(base, 16)
        self.assertEqual(base, huawei_api.client_proof(SYNTH_PASSWORD, SYNTH_SALT, 1000, 'n1', 'n2'))
        for changed in ((SYNTH_PASSWORD + 'x', SYNTH_SALT, 1000, 'n1', 'n2'),
                        (SYNTH_PASSWORD, SYNTH_SALT, 1000, 'n2', 'n1'),
                        (SYNTH_PASSWORD, 'ff' + SYNTH_SALT[:-2], 1000, 'n1', 'n2')):
            self.assertNotEqual(base, huawei_api.client_proof(*changed))

    def test_kdf_parameters_are_bounded(self):
        # A hostile reply must not be able to demand unbounded PBKDF2 work.
        for salt, iterations in ((SYNTH_SALT, 0), (SYNTH_SALT, -1),
                                 (SYNTH_SALT, huawei_api.MAX_KDF_ITERATIONS + 1),
                                 (SYNTH_SALT, 10 ** 9), (SYNTH_SALT, '1000'),
                                 (SYNTH_SALT, True), ('zz', 1000), ('abc', 1000),
                                 ('', 1000), ('00' * (huawei_api.MAX_SALT_HEX // 2 + 1), 1000)):
            with self.subTest(salt=salt, iterations=iterations):
                with self.assertRaises(ValueError):
                    huawei_api.derive_scram_keys(SYNTH_PASSWORD, salt, iterations)

    def test_bounded_nonce_rejects_oversize_and_separators(self):
        self.assertIsNone(huawei_api._bounded_nonce(''))
        self.assertIsNone(huawei_api._bounded_nonce('x' * (huawei_api.MAX_NONCE_LEN + 1)))
        self.assertIsNone(huawei_api._bounded_nonce('a,b'))
        self.assertIsNone(huawei_api._bounded_nonce(1234))
        self.assertEqual(huawei_api._bounded_nonce('abc'), 'abc')


class ErrorClassificationTests(unittest.TestCase):
    def test_categories_map_to_policy_reasons(self):
        cases = [
            ({'err': 1, 'errorCategory': 'user_pass_err'}, huawei_api.R_CREDENTIALS),
            ({'err': 1, 'errorCategory': 'Too_Many_user'}, huawei_api.R_LOCKED),
            ({'err': 1, 'errorCategory': 'Three_time_err_multi'}, huawei_api.R_LOCKED),
            ({'err': 1, 'errorCategory': 'csrf_error'}, huawei_api.R_CSRF),
            ({'err': 1, 'errorCategory': 'unauthorized'}, huawei_api.R_UNAUTHORIZED),
            ({'err': 1, 'errorCategory': 'request_error'}, huawei_api.R_GENERIC),
            ({'err': 1, 'csrf': 'Menu.csrf_err'}, huawei_api.R_CSRF),
            ({'errcode': -2, 'csrf': 'Menu.csrf_err'}, huawei_api.R_CSRF),
            ({'errcode': -2}, huawei_api.R_UNAUTHORIZED),
            ({'errcode': -3}, huawei_api.R_GENERIC),
            ({'errorcode': -2}, huawei_api.R_UNAUTHORIZED),
            ({'errorcode': 7}, huawei_api.R_GENERIC),
            ({'err': 0}, None),
            ({'err': False}, None),
            ({}, None),
            ('not-a-dict', None),
            (None, None),
            ([], None),
        ]
        for payload, expected in cases:
            with self.subTest(payload=payload):
                self.assertEqual(huawei_api.classify_error(payload), expected)

    def test_zero_errcode_variants_are_success(self):
        for zero in (0, '0', None):
            self.assertIsNone(huawei_api.classify_error({'err': zero, 'errcode': zero}))

    def test_explicit_success_requires_a_zero_flag(self):
        self.assertTrue(huawei_api._explicit_success({'err': 0}))
        self.assertTrue(huawei_api._explicit_success({'errcode': '0'}))
        self.assertFalse(huawei_api._explicit_success({}))
        self.assertFalse(huawei_api._explicit_success('x'))
        self.assertFalse(huawei_api._explicit_success({'errorCategory': 'user_pass_err'}))


class ParseDeviceinfoTests(unittest.TestCase):
    def test_software_version_is_required(self):
        self.assertIsNone(huawei_api.parse_deviceinfo(None))
        self.assertIsNone(huawei_api.parse_deviceinfo([]))
        self.assertIsNone(huawei_api.parse_deviceinfo({'DeviceName': 'X'}))
        self.assertIsNone(huawei_api.parse_deviceinfo({'SoftwareVersion': ''}))
        self.assertIsNone(huawei_api.parse_deviceinfo({'SoftwareVersion': '   '}))

    def test_bounded_scalar_fields_only(self):
        info = huawei_api.parse_deviceinfo({
            'SoftwareVersion': 'V1.0', 'DeviceName': 'Huawei', 'ModelName': 'BE3-Pro',
            'SerialNumber': 'SN123', 'HardwareVersion': 'HW1', 'UpTime': 120,
            'custinfo': {'CustDeviceName': 'WUKUN-BE32'},
            'HugeBlob': {'nested': 'x' * 10000}, 'TelnetEnable': 1})
        self.assertEqual(info, {'software_version': 'V1.0', 'model': 'WUKUN-BE32',
                                'model_cust': 'WUKUN-BE32', 'serial_number': 'SN123',
                                'hardware_version': 'HW1', 'uptime_seconds': 120})

    def test_model_falls_back_to_model_name_then_device_name(self):
        self.assertEqual(huawei_api.parse_deviceinfo(
            {'SoftwareVersion': 'V1', 'ModelName': 'BE3-Pro',
             'DeviceName': 'Huawei'})['model'], 'BE3-Pro')
        self.assertEqual(huawei_api.parse_deviceinfo(
            {'SoftwareVersion': 'V1', 'DeviceName': 'Huawei'})['model'], 'Huawei')

    def test_placeholder_and_invalid_values_are_dropped(self):
        info = huawei_api.parse_deviceinfo({'SoftwareVersion': 'V1', 'DeviceName': '-',
                                            'SerialNumber': '', 'UpTime': -5})
        self.assertEqual(info, {'software_version': 'V1'})
        self.assertEqual(huawei_api.parse_deviceinfo(
            {'SoftwareVersion': 'V1', 'UpTime': '3600'})['uptime_seconds'], 3600)
        self.assertNotIn('uptime_seconds', huawei_api.parse_deviceinfo(
            {'SoftwareVersion': 'V1', 'UpTime': float('inf')}))


class ParseProcessStatusTests(unittest.TestCase):
    def test_total_row_only_carries_cpu_and_memory(self):
        parsed = huawei_api.parse_processstatus([
            {'Name': 'Total', 'CpuUsage': 5, 'MemUsage': 36, 'Icon': 'x'},
            {'Name': 'wifi', 'CpuUsage': 1, 'MemUsage': 10, 'Icon': 'y'}])
        self.assertEqual(parsed, {'cpu_percent': 5, 'mem_percent': 36})

    def test_zero_is_a_valid_reading(self):
        self.assertEqual(huawei_api.parse_processstatus(
            [{'Name': 'Total', 'CpuUsage': 0, 'MemUsage': 0}]),
            {'cpu_percent': 0, 'mem_percent': 0})

    def test_wrong_or_unknown_first_row_is_unavailable(self):
        for data in ([{'Name': 'wifi', 'CpuUsage': 1, 'MemUsage': 2}],
                     [{'CpuUsage': 1, 'MemUsage': 2}],
                     [{'Name': 'total', 'CpuUsage': 1, 'MemUsage': 2}],
                     [{'Name': 'Total', 'CpuUsage': 1}],
                     [{'Name': 'Total', 'MemUsage': 2}]):
            with self.subTest(data=data):
                self.assertIsNone(huawei_api.parse_processstatus(data))

    def test_bool_and_out_of_range_and_non_finite_are_rejected(self):
        for cpu, mem in ((True, 36), (5, False), (-1, 36), (5, 101), (5, 101.5),
                         ('x', 36), (5, float('nan')), (5, float('inf'))):
            with self.subTest(cpu=cpu, mem=mem):
                self.assertIsNone(huawei_api.parse_processstatus(
                    [{'Name': 'Total', 'CpuUsage': cpu, 'MemUsage': mem}]))

    def test_numeric_strings_are_accepted(self):
        self.assertEqual(huawei_api.parse_processstatus(
            [{'Name': 'Total', 'CpuUsage': '5', 'MemUsage': '36.5'}]),
            {'cpu_percent': 5, 'mem_percent': 36.5})

    def test_malformed_payloads_are_rejected(self):
        for data in (None, {}, 'x', [], [None], ['Total'], 5):
            with self.subTest(data=data):
                self.assertIsNone(huawei_api.parse_processstatus(data))


class ParseHostinfoTests(unittest.TestCase):
    def active_host(self, **overrides):
        host = {'Active': True, 'phyMode': '802.11ax', 'MACAddress': 'aa:bb:cc:dd:ee:01',
             'IPAddress': '192.0.2.50', 'HostName': 'laptop', 'Frequency': '5GHz',
                'Layer2Interface': 'SSID2', 'staRssi': -55, 'rate': 866.7,
                'TxKBytes': 12, 'RxKBytes': 0}
        host.update(overrides)
        return host

    def test_active_client_uses_camelcase_phy_mode(self):
        # Regression: phyMode is read from the same key that gates the row.
        clients = huawei_api.parse_hostinfo([self.active_host()])
        self.assertEqual(len(clients), 1)
        client = clients[0]
        self.assertEqual(client['mac'], 'aa:bb:cc:dd:ee:01')
        self.assertEqual(client['phy_mode'], '802.11ax')
        self.assertEqual(client['negotiated_rate'], 866.7)
        self.assertEqual(client['rssi_dbm'], -55)
        self.assertEqual(client['tx_kb'], 12)
        self.assertEqual(client['rx_kb'], 0)
        self.assertEqual(client['hostname'], 'laptop')
        self.assertEqual(client['band'], '5GHz')
        self.assertEqual(client['ssid'], '2')
        self.assertEqual(client['ip'], '192.0.2.50')

    def test_inactive_or_malformed_rows_are_skipped(self):
        clients = huawei_api.parse_hostinfo([
            self.active_host(Active=False),
            self.active_host(Active=0),
            self.active_host(Active='true'),
            self.active_host(Active='1'),
            self.active_host(Active=None),
            self.active_host(MACAddress='bad'),
            self.active_host(MACAddress='aa:bb:cc:dd:ee'),
            self.active_host(MACAddress=123456),
            'not-a-dict', None])
        self.assertEqual(clients, [])

    def test_phy_mode_is_optional_and_never_required_to_keep_a_client(self):
        # Regression: the AX3 reports no phyMode on any row; clients must survive.
        kept = huawei_api.parse_hostinfo([
            self.active_host(phyMode=''),
            self.active_host(phyMode={'x': 1}),
            self.active_host(phyMode=None)])
        self.assertEqual(len(kept), 3)
        for client in kept:
            self.assertNotIn('phy_mode', client)
            self.assertEqual(client['band_norm'], '5g')

    def test_wired_rows_are_excluded_even_with_a_stale_phy_mode(self):
        self.assertEqual(huawei_api.parse_hostinfo([
            self.active_host(InterfaceType='LAN', Frequency=None, Layer2Interface=None),
            self.active_host(InterfaceType='Ethernet', Frequency=None, Layer2Interface=None)]), [])

    def test_live_lan1_row_with_a_stale_wireless_label_is_wired(self):
        # Observed on the real AX3: LAN1 interface but a stale 5GHz label.
        self.assertEqual(huawei_api.parse_hostinfo([{
            'Active': True, 'MACAddress': 'aa:bb:cc:dd:ee:11', 'Layer2Interface': 'LAN1',
            'InterfaceType': '5GHz', 'Frequency': '', 'phyMode': '802.11ax'}]), [])

    def test_live_wireless_ssid_row_survives_default_false_wlanactive(self):
        rows = huawei_api.parse_hostinfo([{
            'Active': True, 'MACAddress': 'aa:bb:cc:dd:ee:12', 'Layer2Interface': 'SSID1',
            'InterfaceType': '2.4GHz', 'Frequency': '2.4GHz', 'IsGuest': False,
            'WlanActive': False, 'CouldRate': None}])
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]['interface_id'], 'SSID1')
        self.assertNotIn('phy_mode', rows[0])
        self.assertIs(rows[0]['guest'], False)
        self.assertEqual(rows[0]['band_norm'], '2.4g')

    def test_native_interface_and_guest_flag_are_reported_verbatim(self):
        native = 'InternetGatewayDevice.X_Config.Wifi.Radio.2.Ssid.1'
        client = huawei_api.parse_hostinfo([self.active_host(
            Layer2Interface=native, IsGuest=True)])[0]
        self.assertEqual(client['interface_id'], native)
        self.assertEqual(client['ssid'], native[:32])
        self.assertIs(client['guest'], True)
        self.assertNotIn('guest', huawei_api.parse_hostinfo([self.active_host()])[0])

    def test_counters_and_numbers_are_validated(self):
        client = huawei_api.parse_hostinfo([self.active_host(
            TxKBytes=0, RxKBytes=-1, rate='866.7', UpRate=3.5, DownRate='-2',
            staRssi='-42', IPAddress='not-an-ip', MACAddress='AA:BB:CC:DD:EE:0A')])[0]
        self.assertEqual(client['tx_kb'], 0)
        self.assertNotIn('rx_kb', client)
        self.assertEqual(client['negotiated_rate'], 866.7)
        self.assertEqual(client['up_rate'], 3.5)
        self.assertNotIn('down_rate', client)
        self.assertEqual(client['rssi_dbm'], -42)
        self.assertNotIn('ip', client)
        self.assertEqual(client['mac'], 'aa:bb:cc:dd:ee:0a')

    def test_non_finite_and_boolean_numbers_are_rejected(self):
        client = huawei_api.parse_hostinfo([self.active_host(
            rate=float('nan'), UpRate=True, DownRate=float('inf'), staRssi=100,
            TxKBytes='abc')])[0]
        for key in ('negotiated_rate', 'up_rate', 'down_rate', 'rssi_dbm', 'tx_kb'):
            self.assertNotIn(key, client)

    def test_absent_updown_rate_keys_stay_absent(self):
        client = huawei_api.parse_hostinfo([self.active_host()])[0]
        self.assertNotIn('up_rate', client)
        self.assertNotIn('down_rate', client)
        client = huawei_api.parse_hostinfo([self.active_host(UpRate=1, DownRate=2)])[0]
        self.assertEqual(client['up_rate'], 1)
        self.assertEqual(client['down_rate'], 2)

    def test_client_list_is_capped(self):
        many = [self.active_host(MACAddress=f'aa:bb:cc:{i >> 8:02x}:{i & 0xff:02x}:10')
                for i in range(huawei_api.MAX_CLIENTS + 5)]
        self.assertEqual(len(huawei_api.parse_hostinfo(many)), huawei_api.MAX_CLIENTS)

    def test_non_list_payload_is_rejected(self):
        self.assertIsNone(huawei_api.parse_hostinfo({}))
        self.assertIsNone(huawei_api.parse_hostinfo(None))
        self.assertIsNone(huawei_api.parse_hostinfo('x'))


class ParseWlanGuideTests(unittest.TestCase):
    def guide(self, configs):
        return {'WifiConfig': configs}

    def test_radios_are_physical_bands_and_profiles_keep_native_ids(self):
        parsed = huawei_api.parse_wlanguide(self.guide([
            {'FrequencyBand': '2.4G', 'WifiSsid': 'Home', 'WifiEnable': True, 'Channel': 6,
             'WlanStandard': 'b/g/n/ax', 'TransmitPower': '80%', 'WMMEnable': True,
             'WifiType': 'primary', 'ID': 1},
            {'FrequencyBand': '5G', 'WifiSsid': 'Home', 'WifiEnable': True, 'Channel': 0,
             'WlanStandard': 'a/n/ac/ax/be', 'TransmitPower': '100%', 'WMMEnable': False,
             'WifiType': 'user', 'ID': 2},
            {'FrequencyBand': '5G', 'WifiSsid': 'Home-Guest', 'WifiEnable': False,
             'Channel': 36, 'WMMEnable': True, 'WifiType': 'guest', 'ID': 'iot-7'}]))
        self.assertEqual(parsed['radios'], [{'band': '2.4g', 'profile_count': 1},
                                            {'band': '5g', 'profile_count': 2}])
        self.assertEqual([p['usage'] for p in parsed['profiles']],
                         ['primary', 'primary', 'guest'])
        self.assertEqual([p['native_id'] for p in parsed['profiles']], ['1', '2', 'iot-7'])
        self.assertEqual(parsed['profiles'][1]['channel_configured'], 0)
        self.assertIs(parsed['profiles'][1]['enabled'], True)
        self.assertIs(parsed['profiles'][2]['enabled'], False)
        self.assertIs(parsed['profiles'][1]['wmm'], False)
        self.assertEqual(parsed['profiles'][0]['power'], '80%')

    def test_numeric_booleans_and_bad_channels_are_normalised(self):
        parsed = huawei_api.parse_wlanguide(self.guide([
            {'FrequencyBand': '2.4G', 'WifiSsid': 'X', 'WifiEnable': 1, 'WMMEnable': 0,
             'Channel': '11', 'ID': True},
            {'FrequencyBand': '2.4G', 'WifiSsid': 'Y', 'Channel': -1, 'ID': 4}]))
        self.assertIs(parsed['profiles'][0]['enabled'], True)
        self.assertIs(parsed['profiles'][0]['wmm'], False)
        self.assertEqual(parsed['profiles'][0]['channel_configured'], 11)
        self.assertIsNone(parsed['profiles'][0]['native_id'])
        self.assertIsNone(parsed['profiles'][1]['channel_configured'])

    def test_unknown_usage_is_never_inferred_from_names(self):
        parsed = huawei_api.parse_wlanguide(self.guide([
            {'FrequencyBand': '5G', 'WifiSsid': 'Whatever-Guest', 'ID': 3}]))
        self.assertEqual(parsed['profiles'][0]['usage'], 'unknown')

    def test_malformed_payloads_are_rejected(self):
        self.assertIsNone(huawei_api.parse_wlanguide(None))
        self.assertIsNone(huawei_api.parse_wlanguide([]))
        self.assertIsNone(huawei_api.parse_wlanguide({}))
        self.assertIsNone(huawei_api.parse_wlanguide({'WifiConfig': 'x'}))
        self.assertIsNone(huawei_api.parse_wlanguide({'WifiConfig': {'a': 1}}))

    def test_unknown_band_entries_are_flagged_not_dropped(self):
        parsed = huawei_api.parse_wlanguide(self.guide([
            {'FrequencyBand': '6G', 'WifiSsid': 'x', 'ID': 9},
            {'FrequencyBand': '2.4G', 'WifiSsid': 'ok', 'ID': 10}]))
        self.assertEqual(parsed['radios'], [{'band': '2.4g', 'profile_count': 1}])
        self.assertEqual([(p['band'], p['ssid']) for p in parsed['profiles']],
                         [(None, 'x'), ('2.4g', 'ok')])

    def test_guest_ssids_and_normalization_helpers(self):
        self.assertEqual(huawei_api.parse_guest_ssids([{'WifiSsid': 'G'}]), {'G'})
        self.assertIsNone(huawei_api.parse_guest_ssids(None))
        self.assertIsNone(huawei_api.parse_guest_ssids('x'))
        self.assertIsNone(huawei_api.parse_guest_ssids({'err': 0}))
        self.assertEqual(huawei_api.normalize_band('5GHz'), '5g')
        self.assertEqual(huawei_api.normalize_band('2.4g'), '2.4g')
        self.assertIsNone(huawei_api.normalize_band('60g'))


class BaseUrlTests(unittest.TestCase):
    def test_origin_and_lan_host_are_required(self):
        for bad in ('ftp://192.0.2.1', 'http://', 'not a url',
                    'http://8.8.8.8', 'http://user:pw@192.0.2.1', 'http://user@192.0.2.1',
                    'http://@192.0.2.1', 'http://:@192.0.2.1', 'http://192.0.2.1:99999',
                    'http://192.0.2.1?x=1', 'http://192.0.2.1#f', 'http://192.0.2.1/api',
                    'http://evil.example.com', 'http://192.0.2.1\n', ''):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    huawei_api.HuaweiDirectClient(bad, 'pw')
        for good in ('http://127.0.0.1', 'http://192.0.2.1', 'http://192.168.1.10:8443',
                     'https://192.0.2.11/', 'http://localhost', 'http://router.lan',
                     'http://be3.local'):
            with self.subTest(good=good):
                client = huawei_api.HuaweiDirectClient(good, 'pw')
                self.assertFalse(client.base_url.endswith('/'))

    def test_origin_is_canonicalised(self):
        self.assertEqual(huawei_api.validate_base_url('HTTPS://192.0.2.1:443/'), 'https://192.0.2.1')
        self.assertEqual(huawei_api.validate_base_url('http://192.0.2.1:80'), 'http://192.0.2.1')
        self.assertEqual(huawei_api.validate_base_url('http://192.0.2.1:8443'), 'http://192.0.2.1:8443')

    def test_non_string_password_is_rejected(self):
        with self.assertRaises(ValueError):
            huawei_api.HuaweiDirectClient('http://192.0.2.1', b'pw')

    def test_tls_verification_is_on_by_default_and_opt_in_only(self):
        secure = huawei_api.HuaweiDirectClient('https://192.0.2.11', 'pw')
        self.assertTrue(secure.verify_tls)
        insecure = huawei_api.HuaweiDirectClient('https://192.0.2.11', 'pw', verify_tls=False)
        self.assertFalse(insecure.verify_tls)


class FakeRouterHandler(BaseHTTPRequestHandler):
    """Synthetic router that verifies the exact proof it taught."""

    server_version = 'FakeRouter/1'
    password = SYNTH_PASSWORD
    iterations = SYNTH_ITERATIONS
    salt = SYNTH_SALT
    proof_error_category = None
    nonce_attempts = 0
    proof_attempts = 0
    logout_attempts = 0
    nonce_reject_csrf_first = 0
    logout_rejected = False
    deviceinfo_mode = 'ok'
    hostinfo_mode = 'ok'
    wifi_mode = 'ok'
    guest_mode = 'list'
    topology_mode = 'notfound'
    processstatus_mode = 'notfound'
    serversignature_mode = 'ok'
    rsa_mode = 'ok'
    slow_paths = ()
    max_response_bytes = None
    current_csrf_token = 'token-init'
    hit_paths = []
    post_bodies = []
    seen_username = None
    seen_first_nonce = None

    def log_message(self, fmt, *args):
        pass

    def _rotate(self):
        session = 'rotated-session-%d' % (self.__class__.proof_attempts
                                          + self.__class__.nonce_attempts)
        token = 'token-' + session
        self.__class__.current_csrf_token = token
        return token, 'SessionID_R3=' + session

    def _send_json(self, payload, status=200, extra_headers=()):
        body = json.dumps(payload).encode()
        if self.__class__.max_response_bytes and len(body) < self.__class__.max_response_bytes:
            if self.path.startswith('/api/system/deviceinfo'):
                body = body + b' ' * (self.__class__.max_response_bytes + 64)
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        for name, value in extra_headers:
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(body)

    def _send_html(self, html='<html><body>login required</body></html>'):
        body = html.encode()
        self.send_response(200)
        self.send_header('Content-Type', 'text/html')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _authorized(self, body):
        data = json.loads(body.decode())
        if data.get('csrf', {}).get('csrf_token') != self.__class__.current_csrf_token:
            return {'errcode': 125004, 'csrf': 'Menu.csrf_err'}, False
        return data, True

    def _maybe_slow(self):
        for prefix in self.__class__.slow_paths:
            if self.path.startswith(prefix):
                time.sleep(1.0)
                return

    def do_GET(self):
        self.__class__.hit_paths.append(self.path)
        self._maybe_slow()
        if self.path.startswith('/html/index.html'):
            self.__class__.current_csrf_token = 'token-init'
            self._send_html('<html><head>'
                            '<meta name="csrf_param" content="hd"/>'
                            '<meta name="csrf_token" content="token-init"/>'
                            '</head><body></body></html>')
        elif self.path.startswith('/api/system/deviceinfo'):
            mode = self.__class__.deviceinfo_mode
            if mode == 'html':
                self._send_html()
            elif mode == 'redirect':
                self.send_response(302)
                self.send_header('Location', 'http://10.255.255.1/steal')
                self.send_header('Content-Length', '0')
                self.end_headers()
            elif mode == 'application_error':
                self._send_json({'err': 1, 'errorCategory': 'request_error'})
            elif mode == 'unauthorized':
                self._send_json({'err': 0, 'errcode': -2})
            elif mode == 'missing_sw':
                self._send_json({'DeviceName': 'X'})
            else:
                self._send_json({'SoftwareVersion': 'VTEST', 'DeviceName': 'BE3-Test',
                                 'UpTime': 60})
        elif self.path.startswith('/api/system/HostInfo'):
            if self.__class__.hostinfo_mode == 'dict':
                self._send_json({'not': 'a list'})
            elif self.__class__.hostinfo_mode == 'html':
                self._send_html()
            else:
                hosts = [{'Active': True, 'phyMode': '802.11ax', 'MACAddress': 'aa:bb:cc:dd:ee:01',
             'IPAddress': '192.0.2.50', 'HostName': 'laptop', 'Frequency': '5GHz',
                          'Layer2Interface': 'SSID1', 'staRssi': -50, 'rate': 866.7,
                          'TxKBytes': 5, 'RxKBytes': 9},
                         {'Active': False, 'phyMode': '802.11n', 'MACAddress': 'aa:bb:cc:dd:ee:02'}]
                self._send_json(hosts, extra_headers=[
                    ('Set-Cookie', 'SessionID_R3=rotated-client-cookie')])
        elif self.path.startswith('/api/ntwk/WlanGuideBasic'):
            if self.__class__.wifi_mode == 'notlist':
                self._send_json({'WifiConfig': 'x'})
            else:
                self._send_json({'WifiConfig': [
                    {'FrequencyBand': '2.4G', 'WifiSsid': 'Main', 'WifiEnable': True, 'Channel': 1,
                     'WMMEnable': True, 'WifiType': 'primary', 'ID': 1},
                    {'FrequencyBand': '5G', 'WifiSsid': 'Guest5', 'WifiEnable': True, 'Channel': 0,
                     'WMMEnable': True, 'WifiType': 'unknown-typo', 'ID': 2}]},
                    extra_headers=[('Set-Cookie', 'SessionID_R3S=rotated-https-session')])
        elif self.path.startswith('/api/ntwk/guest_network'):
            if self.__class__.guest_mode == 'list':
                self._send_json([{'WifiSsid': 'Guest5'}])
            elif self.__class__.guest_mode == 'error':
                self._send_json({'err': 1, 'errorCategory': 'request_error'})
            elif self.__class__.guest_mode == 'html':
                self._send_html()
            else:
                self.send_response(404)
                self.send_header('Content-Length', '0')
                self.end_headers()
        elif self.path.startswith('/api/device/'):
            mode = self.__class__.topology_mode
            if mode == 'dict':
                self._send_json({'topo': [{'MACAddress': 'aa:bb:cc:dd:ee:01'}]})
            elif mode == 'error':
                self._send_json({'errcode': -2, 'errorCategory': 'unauthorized'})
            else:
                self.send_response(404)
                self.send_header('Content-Length', '0')
                self.end_headers()
        elif self.path.startswith('/api/system/processstatus'):
            mode = self.__class__.processstatus_mode
            if mode == 'ok':
                self._send_json([{'Name': 'Total', 'CpuUsage': 5, 'MemUsage': 36, 'Icon': ''},
                                 {'Name': 'wifi', 'CpuUsage': 1, 'MemUsage': 9, 'Icon': 'w'}])
            elif mode == 'wrong_first':
                self._send_json([{'Name': 'wifi', 'CpuUsage': 1, 'MemUsage': 9}])
            elif mode == 'schema':
                self._send_json({'not': 'a list'})
            elif mode == 'error':
                self._send_json({'err': 1, 'errorCategory': 'request_error'})
            else:
                self.send_response(404)
                self.send_header('Content-Length', '0')
                self.end_headers()
        else:
            self.send_response(404)
            self.send_header('Content-Length', '0')
            self.end_headers()

    def do_POST(self):
        self.__class__.hit_paths.append(self.path)
        self._maybe_slow()
        length = int(self.headers.get('Content-Length', '0') or 0)
        body = self.rfile.read(min(length, 1 << 20))
        try:
            self.__class__.post_bodies.append(json.loads(body.decode()))
        except ValueError:
            self.__class__.post_bodies.append(None)
        if self.path.startswith('/api/system/user_login_nonce'):
            self.__class__.nonce_attempts += 1
            if self.__class__.nonce_reject_csrf_first and self.__class__.nonce_attempts == 1:
                token, cookie = self._rotate()
                self._send_json({'errcode': 125004, 'csrf': 'Menu.csrf_err',
                                 'csrf_param': 'hd', 'csrf_token': token},
                                extra_headers=[('Set-Cookie', cookie)])
                return
            data, ok = self._authorized(body)
            if not ok:
                self._send_json(data)
                return
            request = data.get('data', {})
            self.__class__.seen_username = request.get('username')
            self.__class__.seen_first_nonce = request.get('firstnonce')
            token, cookie = self._rotate()
            self._send_json({'err': 0, 'servernonce': SYNTH_SERVER,
                             'iterations': self.__class__.iterations,
                             'salt': self.__class__.salt, 'csrf_param': 'hd',
                             'csrf_token': token},
                            extra_headers=[('Set-Cookie', cookie)])
        elif self.path.startswith('/api/system/user_login_proof'):
            self.__class__.proof_attempts += 1
            data, ok = self._authorized(body)
            if not ok:
                self._send_json(data)
                return
            if self.__class__.proof_error_category:
                self._send_json({'err': 1, 'errorCategory': self.__class__.proof_error_category})
                return
            proof = data.get('data', {}).get('clientproof', '')
            expected = reference_proof(self.__class__.password, self.__class__.salt,
                                       self.__class__.iterations,
                                       self.__class__.seen_first_nonce, SYNTH_SERVER)
            if proof != expected:
                self._send_json({'err': 1, 'errorCategory': 'user_pass_err'})
                return
            token, cookie = self._rotate()
            payload = {'err': 0, 'level': 2, 'csrf_param': 'hd', 'csrf_token': token}
            if self.__class__.serversignature_mode == 'ok':
                payload['serversignature'] = reference_server_signature(
                    self.__class__.password, self.__class__.salt, self.__class__.iterations,
                    self.__class__.seen_first_nonce, SYNTH_SERVER)
            elif self.__class__.serversignature_mode == 'bad':
                payload['serversignature'] = '00' * 32
            if self.__class__.rsa_mode == 'ok':
                payload.update({'rsan': SYNTH_RSAN, 'rsae': SYNTH_RSAE,
                                'rsapubkeysignature': reference_rsa_signature(
                                    self.__class__.password, self.__class__.salt,
                                    self.__class__.iterations, SYNTH_RSAN)})
            elif self.__class__.rsa_mode == 'bad':
                payload.update({'rsan': SYNTH_RSAN, 'rsae': SYNTH_RSAE,
                                'rsapubkeysignature': '11' * 32})
            self._send_json(payload, extra_headers=[('Set-Cookie', cookie)])
        elif self.path.startswith('/api/system/user_logout'):
            self.__class__.logout_attempts += 1
            if self.__class__.logout_rejected:
                self._send_json({'err': 1, 'errorCategory': 'request_error'})
            else:
                self._send_json({'err': 0},
                                extra_headers=[('Set-Cookie', 'SessionID_R3=; Max-Age=0')])
        else:
            self.send_response(404)
            self.send_header('Content-Length', '0')
            self.end_headers()


class DirectSessionTests(unittest.TestCase):
    """Bounded live-loopback sessions against the synthetic router."""

    def setUp(self):
        defaults = (('password', SYNTH_PASSWORD), ('iterations', SYNTH_ITERATIONS),
                    ('salt', SYNTH_SALT), ('proof_error_category', None),
                    ('nonce_attempts', 0), ('proof_attempts', 0), ('logout_attempts', 0),
                    ('nonce_reject_csrf_first', 0), ('logout_rejected', False),
                    ('deviceinfo_mode', 'ok'), ('hostinfo_mode', 'ok'), ('wifi_mode', 'ok'),
                    ('guest_mode', 'list'), ('topology_mode', 'notfound'),
                    ('processstatus_mode', 'notfound'),
                    ('serversignature_mode', 'ok'), ('rsa_mode', 'ok'), ('slow_paths', ()),
                    ('max_response_bytes', None), ('current_csrf_token', 'token-init'),
                    ('hit_paths', []), ('post_bodies', []), ('seen_username', None),
                    ('seen_first_nonce', None))
        for name, value in defaults:
            setattr(FakeRouterHandler, name, value)
        self.server = ThreadingHTTPServer(('127.0.0.1', 0), FakeRouterHandler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.base = 'http://127.0.0.1:%d' % self.server.server_address[1]

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)

    def client(self, password=SYNTH_PASSWORD, **kwargs):
        kwargs.setdefault('request_timeout', 5.0)
        return huawei_api.HuaweiDirectClient(self.base, password, **kwargs)

    def test_full_collection_is_read_only_and_faithful(self):
        result = self.client().collect()
        self.assertTrue(result['ok'], result)
        self.assertEqual(result['transport'], 'direct')
        self.assertEqual(result['version'], 'VTEST')
        self.assertEqual(result['device']['model'], 'BE3-Test')
        self.assertEqual(len(result['clients']), 1)
        self.assertEqual(result['clients'][0]['mac'], 'aa:bb:cc:dd:ee:01')
        self.assertEqual(result['clients'][0]['phy_mode'], '802.11ax')
        self.assertEqual(result['clients'][0]['negotiated_rate'], 866.7)
        self.assertEqual(result['clients'][0]['tx_kb'], 5)
        self.assertEqual(result['clients'][0]['rx_kb'], 9)
        ssids = result['ssids']
        self.assertEqual([s['channel_configured'] for s in ssids], [1, 0])
        self.assertEqual(ssids[1]['usage'], 'guest')
        self.assertFalse(result['topology_supported'])
        self.assertTrue(result['guest_api_supported'])
        self.assertTrue(result['server_signature_verified'])
        self.assertTrue(result['public_key_verified'])
        self.assertEqual(result['logout'], 'ok')
        paths = [p.split('?')[0] for p in FakeRouterHandler.hit_paths]
        self.assertNotIn('/api/system/system_cfg', paths)
        for path in paths:
            self.assertTrue(path.startswith(('/html/', '/api/system/', '/api/ntwk/',
                                             '/api/device/')), path)
        self.assertEqual(FakeRouterHandler.seen_username, 'admin')

    def test_private_request_normalises_a_leading_slash(self):
        data = self.client()._get_json('/api/system/deviceinfo', 'deviceinfo-schema')
        self.assertEqual(data.get('SoftwareVersion'), 'VTEST')

    def test_result_never_contains_auth_material(self):
        result = self.client().collect()
        blob = repr(result)
        for secret in (SYNTH_PASSWORD, SYNTH_SALT, SYNTH_PROOF, SYNTH_SERVERSIG,
                       SYNTH_SERVER, 'clientproof', 'firstnonce', 'servernonce',
                       'rotated-session', 'rotated-client-cookie'):
            self.assertNotIn(secret, blob)
        self.assertNotIn('rsan', blob)
        self.assertNotIn('Cookie', blob)

    def test_cookies_and_csrf_rotate_every_response(self):
        client = self.client()
        client.login()
        self.assertEqual(client.cookies.get('SessionID_R3'), 'rotated-session-2')
        self.assertTrue(str(client.csrf['csrf_token']).startswith('token-rotated-session'))
        client.logout()
        self.assertIsNone(client.cookies.get('SessionID_R3'))

    def test_login_post_bodies_use_data_and_csrf_envelope(self):
        self.client().collect()
        nonce_body = FakeRouterHandler.post_bodies[0]
        self.assertEqual(set(nonce_body), {'csrf', 'data'})
        self.assertEqual(nonce_body['data']['username'], 'admin')
        self.assertEqual(len(nonce_body['data']['firstnonce']), 64)
        proof_body = FakeRouterHandler.post_bodies[1]
        self.assertEqual(set(proof_body['data']), {'clientproof', 'finalnonce'})
        self.assertEqual(len(proof_body['data']['clientproof']), 64)
        self.assertEqual(proof_body['data']['finalnonce'], SYNTH_SERVER)

    def test_wrong_password_rejects_once_without_retry(self):
        result = self.client(password='deliberately-wrong').collect()
        self.assertFalse(result['ok'])
        self.assertEqual(result['reason'], huawei_api.R_CREDENTIALS)
        self.assertTrue(result['login_rejected'])
        self.assertFalse(result['logged_in'])
        self.assertEqual(FakeRouterHandler.nonce_attempts, 1)
        self.assertEqual(FakeRouterHandler.proof_attempts, 1)
        self.assertNotIn('logout', result)

    def test_lockout_category_is_rejected_as_locked(self):
        FakeRouterHandler.proof_error_category = 'Three_time_err_multi'
        result = self.client().collect()
        self.assertFalse(result['ok'])
        self.assertEqual(result['reason'], huawei_api.R_LOCKED)
        self.assertTrue(result['login_rejected'])
        self.assertTrue(result['locked'])
        self.assertEqual(FakeRouterHandler.proof_attempts, 1)

    def test_csrf_challenge_is_retried_bounded_with_fresh_nonce(self):
        FakeRouterHandler.nonce_reject_csrf_first = 1
        result = self.client().collect()
        self.assertTrue(result['ok'], result)
        self.assertEqual(FakeRouterHandler.nonce_attempts, 2)

    def test_redirects_are_refused_not_followed(self):
        FakeRouterHandler.deviceinfo_mode = 'redirect'
        result = self.client().collect()
        self.assertFalse(result['ok'])
        self.assertEqual(result['stage'], 'network:HTTPError')
        paths = FakeRouterHandler.hit_paths
        self.assertEqual(paths.count('/api/system/deviceinfo'), 1)
        self.assertTrue(all('10.255.255.1' not in p for p in paths))

    def test_non_json_html_is_never_fresh(self):
        FakeRouterHandler.hostinfo_mode = 'html'
        result = self.client().collect()
        self.assertFalse(result['ok'])
        self.assertEqual(result['stage'], 'parse')
        self.assertNotIn('clients', result)

    def test_application_error_is_not_a_schema_stage(self):
        FakeRouterHandler.deviceinfo_mode = 'application_error'
        result = self.client().collect()
        self.assertFalse(result['ok'])
        self.assertEqual(result['stage'], 'application:generic')

    def test_unauthorized_is_session_expired_without_relogin(self):
        FakeRouterHandler.deviceinfo_mode = 'unauthorized'
        result = self.client().collect()
        self.assertFalse(result['ok'])
        self.assertEqual(result['stage'], 'session-expired')
        self.assertEqual(FakeRouterHandler.nonce_attempts, 1)

    def test_malformed_schemas_are_staged_and_logged_out(self):
        for attr, value, stage in (('deviceinfo_mode', 'missing_sw', 'deviceinfo-schema'),
                                   ('hostinfo_mode', 'dict', 'hostinfo-schema'),
                                   ('wifi_mode', 'notlist', 'wifi-schema')):
            with self.subTest(stage=stage):
                FakeRouterHandler.deviceinfo_mode = 'ok'
                FakeRouterHandler.hostinfo_mode = 'ok'
                FakeRouterHandler.wifi_mode = 'ok'
                setattr(FakeRouterHandler, attr, value)
                result = self.client().collect()
                self.assertFalse(result['ok'])
                self.assertEqual(result['stage'], stage)
                self.assertEqual(result.get('logout'), 'ok')

    def test_bad_server_signature_is_rejected(self):
        FakeRouterHandler.serversignature_mode = 'bad'
        result = self.client().collect()
        self.assertFalse(result['ok'])
        self.assertEqual(result['reason'], huawei_api.R_SERVER_PROOF)
        self.assertNotIn('clients', result)
        self.assertEqual(result.get('logout'), 'ok')

    def test_bad_rsa_key_signature_is_rejected(self):
        FakeRouterHandler.rsa_mode = 'bad'
        result = self.client().collect()
        self.assertFalse(result['ok'])
        self.assertEqual(result['reason'], huawei_api.R_SERVER_PROOF)

    def test_missing_server_signature_is_collected_but_flagged(self):
        FakeRouterHandler.serversignature_mode = 'absent'
        result = self.client().collect()
        self.assertTrue(result['ok'], result)
        self.assertFalse(result['server_signature_verified'])

    def test_malicious_kdf_parameters_never_reach_pbkdf2(self):
        for iterations, salt in ((10 ** 9, SYNTH_SALT), (0, SYNTH_SALT),
                                 (SYNTH_ITERATIONS, 'zz'), (SYNTH_ITERATIONS, '00' * 100)):
            with self.subTest(iterations=iterations, salt=salt):
                FakeRouterHandler.iterations = iterations
                FakeRouterHandler.salt = salt
                FakeRouterHandler.nonce_attempts = 0
                FakeRouterHandler.proof_attempts = 0
                result = self.client().collect()
                self.assertFalse(result['ok'])
                self.assertEqual(result['reason'], huawei_api.R_PARSE)
                self.assertEqual(FakeRouterHandler.proof_attempts, 0)
                self.assertEqual(FakeRouterHandler.nonce_attempts, 1)

    def test_logout_rejected_is_invalid_and_single_attempt(self):
        FakeRouterHandler.logout_rejected = True
        result = self.client().collect()
        self.assertTrue(result['ok'], result)
        self.assertEqual(result['logout'], 'invalid')
        self.assertEqual(FakeRouterHandler.logout_attempts, 1)

    def test_optional_errors_never_mark_support(self):
        for guest, topology, guest_ok, topo_ok in (
                ('error', 'notfound', False, False),
                ('html', 'dict', False, True),
                ('notfound', 'error', False, False)):
            with self.subTest(guest=guest, topology=topology):
                FakeRouterHandler.guest_mode = guest
                FakeRouterHandler.topology_mode = topology
                result = self.client().collect()
                self.assertTrue(result['ok'], result)
                self.assertEqual(result['guest_api_supported'], guest_ok)
                self.assertEqual(result['topology_supported'], topo_ok)

    def test_process_status_is_parsed_from_the_total_row(self):
        FakeRouterHandler.processstatus_mode = 'ok'
        result = self.client().collect()
        self.assertTrue(result['ok'], result)
        self.assertEqual(result['stats'], {'cpu_percent': 5, 'mem_percent': 36})
        self.assertIsNone(result['stats_reason'])
        self.assertIsInstance(result['stats_observed_at'], float)

    def test_unsupported_process_status_never_blocks_core(self):
        for mode, reason in (('notfound', 'unsupported'), ('schema', 'schema'),
                             ('wrong_first', 'schema'), ('error', 'unsupported')):
            with self.subTest(mode=mode):
                FakeRouterHandler.processstatus_mode = mode
                result = self.client().collect()
                self.assertTrue(result['ok'], result)
                self.assertIsNone(result['stats'])
                self.assertEqual(result['stats_reason'], reason)
                self.assertIsNone(result['stats_observed_at'])
                self.assertEqual(len(result['clients']), 1)
                self.assertEqual(result['logout'], 'ok')
        paths = [p.split('?')[0] for p in FakeRouterHandler.hit_paths]
        self.assertIn('/api/system/processstatus', paths)

    def test_request_timeout_is_bounded(self):
        FakeRouterHandler.slow_paths = ('/api/system/HostInfo',)
        result = self.client(request_timeout=0.25).collect()
        self.assertFalse(result['ok'])
        self.assertIn('timeout', result['stage'].lower())

    def test_total_budget_stops_the_session(self):
        result = self.client(total_budget=0.001).collect()
        self.assertFalse(result['ok'])
        self.assertEqual(result['stage'], 'budget')
        self.assertEqual(FakeRouterHandler.nonce_attempts, 0)

    def test_oversized_response_is_capped(self):
        FakeRouterHandler.deviceinfo_mode = 'too_large'
        FakeRouterHandler.max_response_bytes = 512
        result = self.client(max_response=512).collect()
        self.assertFalse(result['ok'])
        self.assertEqual(result['stage'], 'response-too-large')

    def test_csrf_meta_parsing(self):
        html = '<meta name="csrf_param" content="p"/><meta name="csrf_token" content="t"/>'
        self.assertEqual(huawei_api.parse_csrf_meta(html), {'csrf_param': 'p', 'csrf_token': 't'})
        reversed_attrs = '<meta content="p" name="csrf_param"><meta content="t" name="csrf_token">'
        self.assertEqual(huawei_api.parse_csrf_meta(reversed_attrs),
                         {'csrf_param': 'p', 'csrf_token': 't'})
        self.assertIsNone(huawei_api.parse_csrf_meta('<html></html>'))


if __name__ == '__main__':
    unittest.main()
