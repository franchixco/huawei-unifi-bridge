"""Offline tests for multi-VAP TR-098 provisioning (stable bindings)."""

import json
import tempfile
import threading
import unittest

from huawei_bridge.control import (Control, analyze, sanitize_bindings, translate)

P1 = 'InternetGatewayDevice.LANDevice.1.WLANConfiguration.1'
P2 = 'InternetGatewayDevice.LANDevice.1.WLANConfiguration.2'
P3 = 'InternetGatewayDevice.LANDevice.1.WLANConfiguration.3'
P4 = 'InternetGatewayDevice.LANDevice.1.WLANConfiguration.4'
STAMP = '2026-10-16T21:00:00Z'


def wlan(ssid='Lab', channel=1, possible='1,6,11,36', enabled_value=True, wmm=True):
    fields = {'SSID': ssid, 'Channel': channel, 'AutoChannelEnable': False,
              'Enable': enabled_value, 'WMMEnable': wmm, 'PossibleChannels': possible}
    return {k: {'_value': v, '_writable': k != 'PossibleChannels',
                '_type': 'xsd:unsignedInt' if k == 'Channel' else 'xsd:string',
                '_timestamp': STAMP} for k, v in fields.items()}


def device(paths=('1', '2', '3', '4')):
    table = {pid: wlan(ssid='Lab' + pid, channel=int(pid)) for pid in paths}
    return {'_id': 'cpe', 'InternetGatewayDevice': {'LANDevice': {'1': {
        'WLANConfiguration': table}}}}


def mkbindings(radios, vaps):
    return {'schema_version': 2, 'radios': radios, 'vaps': vaps}


def two_band_bindings():
    return mkbindings(
        {'wifi0': {'path': P1, 'native_id': 'n-24', 'slot': 0},
         'wifi1': {'path': P2, 'native_id': 'n-5', 'slot': 1}},
        {'n-24': {'phy': 'wifi0', 'path': P1, 'wlan_id': 'a' * 24, 'native_id': 'n-24',
                  'ssid': 'Lab1'},
         'n-5': {'phy': 'wifi1', 'path': P2, 'wlan_id': 'b' * 24, 'native_id': 'n-5',
                 'ssid': 'Lab2'}})


class MultiVapTranslateTests(unittest.TestCase):
    def test_two_vaps_on_one_radio_translate_independently(self):
        config = ('radio.1.phyname=wifi0\nradio.1.channel=6\n'
                  'wireless.1.parent=wifi0\nwireless.1.devname=ath1\nwireless.1.ssid=Lab1\n'
                  'wireless.1.status=enabled\nwireless.1.wmm=enabled\n'
                  'wireless.2.parent=wifi0\nwireless.2.devname=ath2\nwireless.2.ssid=Lab2\n'
                  'wireless.2.status=disabled\nwireless.2.wmm=disabled\n')
        bindings = mkbindings(
            {'wifi0': {'path': P1, 'native_id': 'n-24'}},
            {'n-24': {'phy': 'wifi0', 'path': P1, 'wlan_id': 'a' * 24, 'ssid': 'Lab1',
                      'aliases': ['ath1', 'n-24', P1]},
             'ath2': {'phy': 'wifi0', 'path': P2, 'wlan_id': 'b' * 24, 'native_id': 'n-24b',
                      'ssid': 'Lab2', 'aliases': ['ath2', 'n-24b', P2]}})
        desired = translate(config, bindings, device())
        self.assertEqual(desired[P1 + '.SSID'], ['Lab1', 'xsd:string'])
        self.assertEqual(desired[P2 + '.SSID'], ['Lab2', 'xsd:string'])
        self.assertEqual(desired[P1 + '.Channel'], [6, 'xsd:unsignedInt'])
        self.assertNotIn(P2 + '.Channel', desired)
        self.assertEqual(desired[P2 + '.Enable'][0], False)

    def test_two_bands_each_two_vaps(self):
        config = ('radio.1.phyname=wifi0\nradio.1.channel=1\n'
                  'radio.2.phyname=wifi1\nradio.2.channel=36\n'
                  'wireless.1.parent=wifi0\nwireless.1.devname=ath1\nwireless.1.ssid=A\n'
                  'wireless.2.parent=wifi0\nwireless.2.devname=ath2\nwireless.2.ssid=B\n'
                  'wireless.3.parent=wifi1\nwireless.3.devname=ath3\nwireless.3.ssid=C\n'
                  'wireless.4.parent=wifi1\nwireless.4.devname=ath4\nwireless.4.ssid=D\n')
        bindings = mkbindings(
            {'wifi0': {'path': P1}, 'wifi1': {'path': P3}},
            {'ath1': {'phy': 'wifi0', 'path': P1, 'ssid': 'A'},
             'ath2': {'phy': 'wifi0', 'path': P2, 'ssid': 'B'},
             'ath3': {'phy': 'wifi1', 'path': P3, 'ssid': 'C'},
             'ath4': {'phy': 'wifi1', 'path': P4, 'ssid': 'D'}})
        desired = translate(config, bindings, device())
        for path, ssid in ((P1, 'A'), (P2, 'B'), (P3, 'C'), (P4, 'D')):
            self.assertEqual(desired[path + '.SSID'], [ssid, 'xsd:string'])
        self.assertEqual(desired[P1 + '.Channel'], [1, 'xsd:unsignedInt'])
        self.assertEqual(desired[P3 + '.Channel'], [36, 'xsd:unsignedInt'])
        self.assertNotIn(P2 + '.Channel', desired)
        self.assertNotIn(P4 + '.Channel', desired)

    def test_reorder_by_prefix_is_identity_based(self):
        ordered = ('wireless.1.parent=wifi0\nwireless.1.devname=ath1\nwireless.1.ssid=A\n'
                   'wireless.2.parent=wifi0\nwireless.2.devname=ath2\nwireless.2.ssid=B\n')
        reordered = ('wireless.2.parent=wifi0\nwireless.2.devname=ath2\nwireless.2.ssid=B\n'
                     'wireless.1.parent=wifi0\nwireless.1.devname=ath1\nwireless.1.ssid=A\n')
        bindings = mkbindings({'wifi0': {'path': P1}},
                            {'ath1': {'phy': 'wifi0', 'path': P1, 'ssid': 'A'},
                             'ath2': {'phy': 'wifi0', 'path': P2, 'ssid': 'B'}})
        first = translate(ordered, bindings, device())
        second = translate(reordered, bindings, device())
        self.assertEqual(first[P1 + '.SSID'], ['A', 'xsd:string'])
        self.assertEqual(second[P1 + '.SSID'], ['A', 'xsd:string'])
        self.assertEqual(second[P2 + '.SSID'], ['B', 'xsd:string'])

    def test_unbound_extra_ssid_rejects_the_whole_plan(self):
        config = ('wireless.1.parent=wifi0\nwireless.1.devname=ath1\nwireless.1.ssid=A\n'
                  'wireless.2.parent=wifi0\nwireless.2.devname=guest\nwireless.2.ssid=Guest\n')
        bindings = mkbindings({'wifi0': {'path': P1}},
                            {'ath1': {'phy': 'wifi0', 'path': P1, 'ssid': 'A'}})
        with self.assertRaises(ValueError):
            translate(config, bindings, device())

    def test_ambiguous_vaps_reject_instead_of_first(self):
        config = 'wireless.1.parent=wifi0\nwireless.1.devname=unknown\nwireless.1.ssid=X\n'
        bindings = mkbindings({'wifi0': {'path': P1}},
                            {'a': {'phy': 'wifi0', 'path': P1},
                             'b': {'phy': 'wifi0', 'path': P2}})
        with self.assertRaises(ValueError):
            translate(config, bindings, device())

    def test_unknown_phy_rejects(self):
        config = 'wireless.1.parent=wifi9\nwireless.1.ssid=X\n'
        with self.assertRaises(ValueError):
            translate(config, mkbindings({'wifi0': {'path': P1}}, {}), device())

    def test_duplicate_phy_binding_rejects(self):
        config = 'radio.1.phyname=wifi0\nradio.1.channel=1\nradio.2.phyname=wifi0\n'
        with self.assertRaises(ValueError):
            translate(config, mkbindings({'wifi0': {'path': P1}}, {}), device())

    def test_rename_resolves_by_identity(self):
        config = 'wireless.1.parent=wifi0\nwireless.1.devname=ath1\nwireless.1.ssid=Renamed\n'
        bindings = mkbindings({'wifi0': {'path': P1}},
                            {'ath1': {'phy': 'wifi0', 'path': P1, 'ssid': 'Old'}})
        desired = translate(config, bindings, device())
        self.assertEqual(desired[P1 + '.SSID'], ['Renamed', 'xsd:string'])

    def test_ssid_change_with_two_candidates_is_ambiguous(self):
        config = 'wireless.1.parent=wifi0\nwireless.1.ssid=Unseen\n'
        bindings = mkbindings({'wifi0': {'path': P1}},
                            {'a': {'phy': 'wifi0', 'path': P1, 'ssid': 'One'},
                             'b': {'phy': 'wifi0', 'path': P2, 'ssid': 'Two'}})
        with self.assertRaises(ValueError):
            translate(config, bindings, device())

    def test_ssid_bounds_and_boolean_types(self):
        config = ('wireless.1.parent=wifi0\nwireless.1.devname=a\n'
                  + 'wireless.1.ssid=' + 'x' * 33 + '\n')
        bindings = mkbindings({'wifi0': {'path': P1}}, {'a': {'phy': 'wifi0', 'path': P1}})
        with self.assertRaises(ValueError):
            translate(config, bindings, device())
        bad = 'wireless.1.parent=wifi0\nwireless.1.devname=a\nwireless.1.status=maybe\n'
        with self.assertRaises(ValueError):
            translate(bad, bindings, device())

    def test_strict_unsupported_rejects_entire_plan(self):
        config = ('wireless.1.parent=wifi0\nwireless.1.devname=a\nwireless.1.ssid=A\n'
                  'wireless.1.security=wpapsk\naaa.1.wpa.psk=secret-not-persisted\n'
                  'wireless.1.vlan=7\n')
        bindings = mkbindings({'wifi0': {'path': P1}}, {'a': {'phy': 'wifi0', 'path': P1}})
        with self.assertRaises(ValueError):
            translate(config, bindings, device(), strict_unsupported=True)

    def test_unsupported_diagnostics_never_carry_values(self):
        config = ('wireless.1.parent=wifi0\nwireless.1.devname=a\nwireless.1.ssid=A\n'
                  'wireless.1.security=wpapsk\naaa.1.wpa.psk=secret-not-persisted\n')
        bindings = mkbindings({'wifi0': {'path': P1}}, {'a': {'phy': 'wifi0', 'path': P1}})
        desired, diagnostics = analyze(config, bindings, device())
        self.assertIn('security', diagnostics['unsupported'])
        self.assertNotIn('never', json.dumps(diagnostics).lower())
        self.assertEqual(desired[P1 + '.SSID'], ['A', 'xsd:string'])

    def test_channel_must_be_advertised_and_primary_scoped(self):
        config = 'radio.1.phyname=wifi0\nradio.1.channel=7\n'
        with self.assertRaises(ValueError):
            translate(config, mkbindings({'wifi0': {'path': P1}}, {}), device())


class BindingsMigrationTests(unittest.TestCase):
    def test_legacy_bindings_upgrade_to_v2(self):
        legacy = {'wifi0': {'path': P1, 'wlan_id': 'c' * 24}}
        upgraded = sanitize_bindings(legacy)
        self.assertEqual(upgraded['schema_version'], 2)
        self.assertEqual(upgraded['radios']['wifi0']['path'], P1)
        self.assertEqual(upgraded['vaps'][P1]['wlan_id'], 'c' * 24)

    def test_untrusted_inventory_fails_closed(self):
        ap = {'id': 'cpe', 'ip': '192.0.2.11', 'virtual_mac': '02:00:00:00:00:0b', 'radios': [
            {'id': P1, 'band': '2.4g', 'ssid': 'Lab', 'native_id': 'n'}],
            'inventory': {'trusted': False, 'slot_by_radio': {P1: 0}}}
        for control in (Control(tempfile.mkdtemp(), lambda *a: None, '192.0.2.11'),
                        Control(tempfile.mkdtemp(), lambda *a: None, '192.0.2.11',
                                legacy_bindings=True)):
            with self.assertRaises(ValueError):
                control.build_bindings(ap, {})
        control = Control(tempfile.mkdtemp(), lambda *a: None, '192.0.2.11')
        plan = control.plan(ap, {'system_cfg': 'wireless.1.parent=wifi0\nwireless.1.ssid=Lab\n',
                                 'cfgversion': 'a'}, device(('1',)), {'Lab': 'a' * 24})
        self.assertFalse(plan['ok'])
        self.assertIn('Untrusted', plan['error'])

    def test_missing_inventory_is_opt_in_only(self):
        ap = {'id': 'cpe', 'ip': '192.0.2.11', 'radios': [
            {'id': P1, 'band': '2.4g', 'ssid': 'Lab'}]}
        with self.assertRaises(ValueError):
            Control(tempfile.mkdtemp(), lambda *a: None, '192.0.2.11').build_bindings(
                ap, {'Lab': 'a' * 24})
        legacy = Control(tempfile.mkdtemp(), lambda *a: None, '192.0.2.11', legacy_bindings=True)
        self.assertEqual(legacy.build_bindings(ap, {'Lab': 'a' * 24})['radios']['wifi0']['path'], P1)

    def test_trusted_inventory_binds_native_id_and_lowest_slot(self):
        control = Control(tempfile.mkdtemp(), lambda *a: None, '192.0.2.11')
        ap = {'id': 'cpe', 'ip': '192.0.2.11', 'radios': [
            {'id': P2, 'band': '5g', 'ssid': 'B', 'native_id': 'n-b'},
            {'id': P1, 'band': '5g', 'ssid': 'A', 'native_id': 'n-a'}],
            'inventory': {'trusted': True, 'slot_by_radio': {P2: 3, P1: 1}}}
        result = control.build_bindings(ap, {'A': 'a' * 24, 'B': 'b' * 24})
        self.assertEqual(result['radios']['wifi1']['path'], P1)
        self.assertEqual(sorted(result['vaps']), ['n-a', 'n-b'])


class ControlMultiVapStateTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.calls = []

        def request(path, data=None):
            self.calls.append((path, data))
            if data:
                return {'_id': 'task1'}
            return []

        self.request = request
        self.control = Control(self.tmp, request, '192.0.2.11', legacy_bindings=True)
        self.ap = {'id': 'cpe', 'ip': '192.0.2.11', 'virtual_mac': '02:00:00:00:00:0b',
                   'radios': [{'id': P1, 'ssid': 'Lab1', 'band': '2.4g', 'native_id': 'n-24'}],
                   'inventory': {'trusted': True, 'slot_by_radio': {P1: 1}}}
        self.mapping = {'Lab1': 'a' * 24}
        self.config = ('radio.1.phyname=wifi0\nradio.1.channel=6\n'
                       'wireless.1.parent=wifi0\nwireless.1.devname=ath1\n'
                       'wireless.1.ssid=Lab1\n')

    def receive(self, config, revision='a', dev=None):
        self.control.receive(self.ap, {'system_cfg': config, 'cfgversion': revision},
                             dev or device(('1',)), self.mapping)

    def test_baseline_records_receipt_but_not_hardware_confirmation(self):
        self.receive(self.config, 'a')
        record = self.control.record(self.ap)
        self.assertEqual(record['phase'], 'baseline')
        self.assertEqual(record['ack_version'], 'a')
        self.assertIsNone(record['confirmed_version'])
        self.assertEqual(self.calls, [])

    def matched_device(self, channel=6, wmm=True):
        dev = device(('1',))
        wlan = dev['InternetGatewayDevice']['LANDevice']['1']['WLANConfiguration']['1']
        wlan['Channel']['_value'] = channel
        wlan['WMMEnable']['_value'] = wmm
        return dev

    def test_noop_same_desired_and_matching_cpe_is_confirmed(self):
        self.receive(self.config, 'a', self.matched_device(channel=6))
        self.receive(self.config, 'b', self.matched_device(channel=6))
        record = self.control.record(self.ap)
        self.assertEqual(record['phase'], 'confirmed')
        self.assertEqual(record['confirmed_version'], 'b')
        self.assertIsNone(record.get('task_id'))
        self.assertEqual(self.calls, [])

    def test_baseline_intent_unchanged_with_hardware_drift_is_not_written(self):
        self.receive(self.config, 'a')  # controller wants channel 6; CPE reports 1
        self.receive(self.config, 'b')
        record = self.control.record(self.ap)
        self.assertEqual(record['phase'], 'drift')
        self.assertEqual(record['drift'], [P1 + '.Channel'])
        self.assertIsNone(record.get('confirmed_version'))
        self.assertEqual(self.calls, [])
        self.assertIn('drift', self.control.public(self.ap))

    def test_new_controller_intent_is_written_after_gates(self):
        self.receive(self.config, 'a')
        self.receive(self.config.replace('channel=6', 'channel=11'), 'b')
        record = self.control.record(self.ap)
        self.assertEqual(record['phase'], 'queued')
        self.assertEqual(list(record['changes']), [P1 + '.Channel'])
        self.assertEqual(sum(data is not None for _, data in self.calls), 1)

    def test_partial_readback_does_not_confirm_or_retry(self):
        self.receive(self.config, 'a')
        two = self.config.replace('channel=6', 'channel=11') + 'wireless.1.wmm=disabled\n'
        self.receive(two, 'b')
        self.assertEqual(self.control.public(self.ap)['phase'], 'queued')
        before = len(self.calls)
        partial = device(('1',))
        partial['InternetGatewayDevice']['LANDevice']['1']['WLANConfiguration']['1']['Channel']['_value'] = 6
        self.control.reconcile([partial])
        self.assertEqual(self.control.public(self.ap)['phase'], 'reading')
        self.assertEqual(sum(data is not None for _, data in self.calls), before + 1)

    def test_duplicate_revision_never_double_submits(self):
        self.receive(self.config, 'a')
        self.receive(self.config.replace('channel=6', 'channel=11'), 'b')
        self.receive(self.config.replace('channel=6', 'channel=11'), 'b')
        self.assertEqual(sum(data is not None for _, data in self.calls), 1)

    def test_concurrent_receive_single_submission(self):
        self.receive(self.config, 'a')
        config = self.config.replace('channel=6', 'channel=11')

        def worker():
            self.control.receive(self.ap, {'system_cfg': config, 'cfgversion': 'b'},
                                 device(('1',)), self.mapping)

        threads = [threading.Thread(target=worker) for _ in range(4)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(sum(data is not None for _, data in self.calls), 1)

    def test_plan_is_read_only_and_reports_blocked_when_disabled(self):
        disabled = Control(self.tmp, self.request, '', legacy_bindings=True)
        before = len(self.calls)
        plan = disabled.plan(self.ap, {'system_cfg': self.config, 'cfgversion': 'a'},
                             device(('1',)), self.mapping)
        self.assertTrue(plan['ok'])
        self.assertFalse(plan['writes_enabled'])
        self.assertEqual(plan['blocked_reason'], 'writes-disabled')
        self.assertIn(P1 + '.Channel', plan['targets'])
        self.assertEqual(self.calls, self.calls[:before])

    def test_plan_surfaces_unresolved_binding_without_writing(self):
        config = 'wireless.2.parent=wifi0\nwireless.2.devname=ghost\nwireless.2.ssid=Ghost\n'
        plan = self.control.plan(self.ap, {'system_cfg': config, 'cfgversion': 'x'},
                                 device(('1',)), self.mapping)
        self.assertFalse(plan['ok'])
        self.assertIn('Unknown VAP identity', plan['error'])
        self.assertEqual(self.calls, [])

    def test_capabilities_report_writable_and_channels(self):
        self.receive(self.config, 'a')
        caps = self.control.capabilities(self.ap, device(('1',)))
        self.assertTrue(caps['writes_enabled'])
        self.assertEqual(caps['bound_radios']['wifi0'], P1)
        self.assertTrue(caps['writable']['wifi0']['ssid_writable'])
        self.assertEqual(caps['writable']['wifi0']['possible_channels'], '1,6,11,36')

    def test_stored_binding_is_revalidated_every_send(self):
        self.receive(self.config, 'a')
        record = self.control.record(self.ap)
        record['bindings']['vaps']['n-24']['path'] = P4
        self.control.save(self.ap)
        plan = self.control.plan(self.ap, {'system_cfg': self.config.replace('channel=6', 'channel=11'),
                                           'cfgversion': 'b'}, device(('1',)), self.mapping)
        self.assertFalse(plan['ok'])
        self.assertIn('no longer present', plan['error'])
        with self.assertRaises(ValueError):
            self.receive(self.config.replace('channel=6', 'channel=11'), 'b')

    def test_explicit_identity_never_falls_back_to_ssid(self):
        config = 'wireless.1.parent=wifi0\nwireless.1.devname=ath9\nwireless.1.ssid=Lab1\n'
        bindings = mkbindings({'wifi0': {'path': P1}},
                              {'ath1': {'phy': 'wifi0', 'path': P1, 'ssid': 'Lab1'}})
        with self.assertRaises(ValueError):
            translate(config, bindings, device(('1',)))

    def test_radio_disable_with_multiple_vaps_is_rejected(self):
        config = ('radio.1.phyname=wifi0\nradio.1.status=disabled\n'
                  'wireless.1.parent=wifi0\nwireless.1.devname=ath1\nwireless.1.ssid=A\n'
                  'wireless.2.parent=wifi0\nwireless.2.devname=ath2\nwireless.2.ssid=B\n')
        bindings = mkbindings({'wifi0': {'path': P1}},
                              {'ath1': {'phy': 'wifi0', 'path': P1, 'ssid': 'A'},
                               'ath2': {'phy': 'wifi0', 'path': P2, 'ssid': 'B'}})
        with self.assertRaises(ValueError):
            translate(config, bindings, device(('1',)))

    def test_ath_slot_alias_maps_system_cfg_to_native_path(self):
        config = ('radio.1.phyname=wifi0\nradio.1.channel=6\n'
                  'wireless.1.parent=wifi0\nwireless.1.devname=ath0\nwireless.1.ssid=Renamed\n')
        bindings = mkbindings({'wifi0': {'path': P1}},
                              {'n-24': {'phy': 'wifi0', 'path': P1, 'ssid': 'Old',
                                        'native_id': 'n-24',
                                        'aliases': ['n-24', P1, 'ath0']}})
        desired = translate(config, bindings, device(('1',)))
        self.assertEqual(desired[P1 + '.SSID'], ['Renamed', 'xsd:string'])
        self.assertEqual(desired[P1 + '.Channel'], [6, 'xsd:unsignedInt'])

    def test_persisted_bindings_without_inventory_fail_closed(self):
        self.receive(self.config, 'a')
        bare = {'id': 'cpe', 'ip': '192.0.2.11', 'virtual_mac': '02:00:00:00:00:0b',
                'radios': [{'id': P1, 'ssid': 'Lab1', 'band': '2.4g', 'native_id': 'n-24'}]}
        strict = Control(self.tmp, self.request, '192.0.2.11')
        strict.records[self.ap['virtual_mac']] = dict(self.control.record(self.ap))
        plan = strict.plan(bare, {'system_cfg': self.config.replace('channel=6', 'channel=11'),
                                  'cfgversion': 'b'}, device(('1',)), self.mapping)
        self.assertFalse(plan['ok'])
        self.assertIn('Inventory required', plan['error'])
        self.assertEqual(sum(data is not None for _, data in self.calls), 0)
        legacy = Control(self.tmp, self.request, '192.0.2.11', legacy_bindings=True)
        legacy.records[self.ap['virtual_mac']] = dict(self.control.record(self.ap))
        self.assertTrue(legacy.plan(bare, {'system_cfg': self.config.replace('channel=6', 'channel=11'),
                                           'cfgversion': 'b'}, device(('1',)), self.mapping)['ok'])


if __name__ == '__main__':
    unittest.main()
