import copy
import tempfile
import unittest
from unittest.mock import patch

from huawei_bridge.control import Control, allowed_ip_set, translate

PATH = 'InternetGatewayDevice.LANDevice.1.WLANConfiguration.1'
CONFIG = '''radio.1.phyname=wifi0
radio.1.channel=6
radio.1.status=enabled
wireless.1.parent=wifi0
wireless.1.devname=ath0
wireless.1.ssid=Lab
wireless.1.status=enabled
wireless.1.wmm=enabled
wireless.1.security=wpapsk
aaa.1.wpa.psk=never-persist-this
users.1.password=never-persist-this
ebtables.1.cmd=never-execute-this
'''
BINDINGS = {'wifi0': {'path': PATH, 'wlan_id': '0123456789abcdef01234567'}}


def device(stamp='2026-10-16T21:00:00Z', channel=1):
    fields = {'SSID': 'Lab', 'Channel': channel, 'AutoChannelEnable': False,
              'Enable': True, 'WMMEnable': True, 'PossibleChannels': '1,6,11'}
    wlan = {k: {'_value': v, '_writable': k != 'PossibleChannels', '_timestamp': stamp}
            for k, v in fields.items()}
    return {'_id': 'cpe', 'InternetGatewayDevice': {'LANDevice': {'1': {'WLANConfiguration': {'1': wlan}}}}}


class TranslationTests(unittest.TestCase):
    def test_allowlist_and_explicit_radio_binding(self):
        desired = translate(CONFIG, BINDINGS, device())
        self.assertEqual(desired, {PATH + '.SSID': ['Lab', 'xsd:string'],
            PATH + '.Channel': [6, 'xsd:unsignedInt'], PATH + '.AutoChannelEnable': [False, 'xsd:boolean'],
            PATH + '.Enable': [True, 'xsd:boolean'], PATH + '.WMMEnable': [True, 'xsd:boolean']})
        self.assertNotIn('never-persist-this', str(desired))

    def test_auto_does_not_translate_channel_zero(self):
        result = translate(CONFIG.replace('channel=6', 'channel=auto'), BINDINGS, device())
        self.assertEqual(result[PATH + '.AutoChannelEnable'][0], True)
        self.assertNotIn(PATH + '.Channel', result)

    def test_rejects_invalid_nonwritable_and_ambiguous_values(self):
        for config in (CONFIG.replace('channel=6', 'channel=13'),
                       CONFIG.replace('status=enabled', 'status=bad'),
                       CONFIG + 'radio.1.channel=11\n',
                       CONFIG.replace('ssid=Lab', 'ssid=')):
            with self.assertRaises(ValueError):
                translate(config, BINDINGS, device())
        raw = device()
        raw['InternetGatewayDevice']['LANDevice']['1']['WLANConfiguration']['1']['Channel']['_writable'] = False
        with self.assertRaises(ValueError):
            translate(CONFIG, BINDINGS, raw)

    def test_missing_radio_does_not_disable_it(self):
        self.assertEqual(translate('', BINDINGS, device()), {})


class AllowedIpSetTests(unittest.TestCase):
    def test_empty_disables_writes(self):
        self.assertEqual(allowed_ip_set(''), set())
        self.assertEqual(allowed_ip_set('   '), set())
        self.assertEqual(allowed_ip_set(None), set())

    def test_multi_ip_parsed_and_normalized(self):
        result = allowed_ip_set('192.0.2.11, 192.0.2.12\n192.0.2.13')
        self.assertEqual(result, {'192.0.2.11', '192.0.2.12', '192.0.2.13'})

    def test_invalid_entries_are_rejected_not_dropped(self):
        for bad in ('192.0.2.11,300.1.1.1', 'not-an-ip', '192.0.2.11/32',
                    '192.0.2.11,192.0.2.12,banana', '0300.0.0.1'):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    allowed_ip_set(bad)


class ControlTests(unittest.TestCase):
    def test_baseline_then_task_readback_and_restart(self):
        calls = []
        def request(path, data=None):
            calls.append((path, data))
            if data:
                return {'_id': 'task1'}
            return []
        ap = {'id': 'cpe', 'ip': '192.0.2.2', 'virtual_mac': '02:00:00:00:00:01',
              'radios': [{'id': PATH, 'ssid': 'Lab', 'band': '2.4g'}]}
        mapping = {'Lab': '0123456789abcdef01234567'}
        with tempfile.TemporaryDirectory() as tmp:
            control = Control(tmp, request, '192.0.2.2', legacy_bindings=True)
            control.receive(ap, {'system_cfg': CONFIG.replace('channel=6', 'channel=1'), 'cfgversion': 'a'}, device(), mapping)
            self.assertEqual(calls, [])
            self.assertEqual(control.public(ap)['phase'], 'baseline')
            control.receive(ap, {'system_cfg': CONFIG, 'cfgversion': 'b'}, device(), mapping)
            self.assertEqual(control.public(ap)['phase'], 'queued')
            self.assertEqual(len(calls), 1)
            self.assertIn('setParameterValues', calls[0][1].decode())
            control.receive(ap, {'system_cfg': CONFIG, 'cfgversion': 'b'}, device(), mapping)
            self.assertEqual(len(calls), 1)
            restarted = Control(tmp, request, '192.0.2.2', legacy_bindings=True)
            restarted.record(ap)
            restarted.reconcile([device(channel=1)])
            self.assertEqual(restarted.public(ap)['phase'], 'reading')
            self.assertEqual(restarted.ack(ap), 'a')
            restarted.reconcile([device('2099-01-01T00:00:00Z', channel=6)])
            self.assertEqual(restarted.public(ap)['phase'], 'confirmed')
            self.assertEqual(restarted.ack(ap), 'b')
            restarted.reset(ap)
            self.assertIsNone(restarted.ack(ap))
            calls.clear()
            restarted.receive(ap, {'system_cfg': CONFIG.replace('channel=6', 'channel=11'), 'cfgversion': 'new-controller'}, device(), mapping)
            self.assertEqual(restarted.public(ap)['phase'], 'baseline')
            self.assertEqual(calls, [])

    def test_fault_timeout_and_unknown_submission_never_ack_or_retry(self):
        ap = {'id': 'cpe', 'ip': '192.0.2.2', 'virtual_mac': '02:00:00:00:00:01',
              'radios': [{'id': PATH, 'ssid': 'Lab', 'band': '2.4g'}]}
        for outcome in ('fault', 'timeout', 'unknown'):
            calls = []
            def request(path, data=None):
                calls.append((path, data))
                if data:
                    if outcome == 'unknown':
                        raise TimeoutError()
                    return {'_id': 'task1'}
                return [{'channel': 'task_task1'}] if path.startswith('/faults') and outcome == 'fault' else []
            with self.subTest(outcome=outcome), tempfile.TemporaryDirectory() as tmp:
                control = Control(tmp, request, '192.0.2.2', legacy_bindings=True)
                control.receive(ap, {'system_cfg': CONFIG, 'cfgversion': 'a'}, device(), {'Lab': BINDINGS['wifi0']['wlan_id']})
                control.receive(ap, {'system_cfg': CONFIG.replace('channel=6', 'channel=11'), 'cfgversion': 'b'}, device(), {})
                with patch('huawei_bridge.control.time.time', return_value=control.record(ap)['requested_at'] + 301):
                    control.reconcile([device()])
                self.assertEqual(control.public(ap)['phase'], 'uncertain' if outcome == 'unknown' else 'failed')
                self.assertEqual(control.ack(ap), 'a')
                control.reconcile([device()])
                self.assertEqual(sum(data is not None for _, data in calls), 1)

    def test_wrong_device_never_writes(self):
        calls = []
        with tempfile.TemporaryDirectory() as tmp:
            control = Control(tmp, lambda *args: calls.append(args), '192.0.2.2')
            ap = {'id': 'other', 'ip': '192.0.2.99', 'virtual_mac': '02:00:00:00:00:02'}
            control.receive(ap, {'system_cfg': CONFIG, 'cfgversion': 'a'}, device(), {})
            self.assertEqual(calls, [])

    def test_multi_ip_membership_gates_writes(self):
        calls = []
        def request(path, data=None):
            calls.append((path, data))
            if data:
                return {'_id': 'task1'}
            return []
        with tempfile.TemporaryDirectory() as tmp:
            control = Control(tmp, request, '192.0.2.11,192.0.2.12', legacy_bindings=True)
            self.assertEqual(control.allowed_ips, {'192.0.2.11', '192.0.2.12'})
            allowed = {'id': 'cpe-a', 'ip': '192.0.2.11', 'virtual_mac': '02:00:00:00:00:0b',
                       'radios': [{'id': PATH, 'ssid': 'Lab', 'band': '2.4g'}]}
            denied = {'id': 'cpe-b', 'ip': '192.0.2.99', 'virtual_mac': '02:00:00:00:00:63',
                      'radios': [{'id': PATH, 'ssid': 'Lab', 'band': '2.4g'}]}
            self.assertTrue(control.public(allowed)['enabled'])
            self.assertFalse(control.public(denied)['enabled'])
            control.receive(allowed, {'system_cfg': CONFIG.replace('channel=6', 'channel=1'), 'cfgversion': 'a'}, device(), {'Lab': BINDINGS['wifi0']['wlan_id']})
            control.receive(allowed, {'system_cfg': CONFIG, 'cfgversion': 'b'}, device(), {'Lab': BINDINGS['wifi0']['wlan_id']})
            control.receive(denied, {'system_cfg': CONFIG, 'cfgversion': 'a'}, device(), {'Lab': BINDINGS['wifi0']['wlan_id']})
            self.assertEqual(len(calls), 1)  # Only the allowlisted CPE got a task.
            self.assertEqual(control.public(denied).get('phase'), None)

    def test_invalid_allowlist_entry_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(ValueError):
                Control(tmp, lambda *args: None, '192.0.2.11,banana', legacy_bindings=True)

    def test_reject_never_downgrades_in_flight_or_failed_phases(self):
        with tempfile.TemporaryDirectory() as tmp:
            control = Control(tmp, lambda *args: None, '', legacy_bindings=True)
            ap = {'id': 'cpe', 'ip': '192.0.2.11', 'virtual_mac': '02:00:00:00:00:0b'}
            for phase in ('queued', 'reading', 'submitting', 'uncertain', 'failed'):
                control.records[ap['virtual_mac']] = {'device': ap['id'], 'phase': phase,
                                                      'error': None, 'task_id': 'task1'}
                control.reject(ap, 'late CPE-side complaint')
                self.assertEqual(control.record(ap)['phase'], phase)
                self.assertEqual(control.record(ap)['task_id'], 'task1')
                self.assertIsNone(control.record(ap)['error'])
            control.records[ap['virtual_mac']] = {'device': ap['id'], 'phase': 'baseline'}
            control.reject(ap, 'translation failed')
            self.assertEqual(control.record(ap)['phase'], 'rejected')
            self.assertEqual(control.record(ap)['error'], 'translation failed')

    def test_invalid_revision_cannot_unlock_failed_state(self):
        calls = []
        def request(path, data=None):
            calls.append((path, data))
            if data:
                return {'_id': 'task1'}
            return []
        with tempfile.TemporaryDirectory() as tmp:
            control = Control(tmp, request, '192.0.2.11', legacy_bindings=True)
            ap = {'id': 'cpe', 'ip': '192.0.2.11', 'virtual_mac': '02:00:00:00:00:0b',
                  'radios': [{'id': PATH, 'ssid': 'Lab', 'band': '2.4g'}]}
            control.records[ap['virtual_mac']] = {'device': ap['id'], 'phase': 'failed',
                                                  'error': 'Readback timeout'}
            # The phase guard runs before revision validation: nothing raises,
            # nothing is consumed, and reject() never flips failed -> rejected.
            control.receive(ap, {'system_cfg': CONFIG, 'cfgversion': ''}, device(), {})
            self.assertEqual(control.record(ap)['phase'], 'failed')
            self.assertEqual(control.record(ap)['error'], 'Readback timeout')
            # A later valid revision stays locked out: no blind write after fail.
            control.receive(ap, {'system_cfg': CONFIG, 'cfgversion': 'valid-rev'}, device(), {})
            self.assertEqual(calls, [])
            self.assertEqual(control.record(ap)['phase'], 'failed')

    def test_failed_writeback_never_blindly_retries(self):
        calls = []
        def request(path, data=None):
            calls.append((path, data))
            if data:
                return {'_id': 'task1'}
            return []
        with tempfile.TemporaryDirectory() as tmp:
            control = Control(tmp, request, '192.0.2.11', legacy_bindings=True)
            ap = {'id': 'cpe', 'ip': '192.0.2.11', 'virtual_mac': '02:00:00:00:00:0b',
                  'radios': [{'id': PATH, 'ssid': 'Lab', 'band': '2.4g'}]}
            control.receive(ap, {'system_cfg': CONFIG.replace('channel=6', 'channel=1'), 'cfgversion': 'a'}, device(), {'Lab': BINDINGS['wifi0']['wlan_id']})
            control.receive(ap, {'system_cfg': CONFIG, 'cfgversion': 'b'}, device(), {})
            self.assertEqual(control.public(ap)['phase'], 'queued')
            control.records[ap['virtual_mac']]['phase'] = 'failed'
            before = len(calls)
            for phase in ('failed', 'uncertain', 'submitting', 'reading'):
                control.records[ap['virtual_mac']]['phase'] = phase
                control.receive(ap, {'system_cfg': CONFIG.replace('channel=6', 'channel=11'), 'cfgversion': 'c'}, device(), {})
                self.assertEqual(len(calls), before)  # No new write without definitive fault.


if __name__ == '__main__':
    unittest.main()
