"""Offline tests for the bounded background registry writer."""

import contextlib
import os
import shutil
import tempfile
import threading
import time
import unittest
import unittest.mock
from pathlib import Path

from huawei_bridge.writer import JsonRegistryWriter

ROOT = Path(__file__).resolve().parent.parent


def wait_for(predicate, timeout=3.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.01)
    return predicate()


class WriterUnitTests(unittest.TestCase):
    @contextlib.contextmanager
    def workdir(self):
        directory = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, directory, ignore_errors=True)
        yield Path(directory)

    def test_submit_returns_immediately_and_never_fsyncs_inline(self):
        with self.workdir() as directory:
            gate = threading.Event()
            writer = JsonRegistryWriter({'ns': directory / 'x.json'},
                                        write=lambda path, data: gate.wait(2.0),
                                        join_timeout=0.2)
            self.addCleanup(writer.close)
            started = time.monotonic()
            writer.submit('ns', {'a': 1}, 1)
            self.assertLess(time.monotonic() - started, 0.2)
            self.assertEqual(writer.saved('ns'), 0)
            gate.set()

    def test_ack_is_per_generation_and_partial_until_written(self):
        with self.workdir() as directory:
            first = threading.Event()
            release = threading.Event()
            written = []

            def write(path, data):
                written.append(data)
                if data == 'g1' and not first.is_set():
                    first.set()
                    release.wait(3.0)

            writer = JsonRegistryWriter({'ns': directory / 'x.json'}, write=write,
                                        join_timeout=0.5)
            self.addCleanup(writer.close)
            writer.submit('ns', 'g1', 1)
            self.assertTrue(first.wait(2.0))
            writer.submit('ns', 'g2', 2)
            self.assertEqual(writer.saved('ns'), 0)  # g1 not yet durable
            release.set()
            self.assertTrue(wait_for(lambda: writer.saved('ns') == 2))
            self.assertEqual(written, ['g1', 'g2'])

    def test_only_the_newest_pending_survives_a_burst(self):
        with self.workdir() as directory:
            first = threading.Event()
            release = threading.Event()
            written = []

            def write(path, data):
                written.append(data)
                if len(written) == 1:
                    first.set()
                    release.wait(3.0)

            writer = JsonRegistryWriter({'ns': directory / 'x.json'}, write=write,
                                        join_timeout=0.5)
            self.addCleanup(writer.close)
            writer.submit('ns', 'g1', 1)
            self.assertTrue(first.wait(2.0))
            writer.submit('ns', 'g2', 2)
            writer.submit('ns', 'g3', 3)
            release.set()
            self.assertTrue(wait_for(lambda: writer.saved('ns') == 3))
            self.assertEqual(written, ['g1', 'g3'])

    def test_a_failing_namespace_backs_off_without_starving_the_other(self):
        with self.workdir() as directory:
            good = directory / 'good.json'

            def write(path, data):
                if str(path).endswith('bad.json'):
                    raise OSError('ENOSPC')

            writer = JsonRegistryWriter({'bad': directory / 'bad.json', 'good': good},
                                        write=write, min_backoff=0.05, max_backoff=0.1,
                                        join_timeout=0.5)
            self.addCleanup(writer.close)
            writer.submit('bad', {'x': 1}, 1)
            writer.submit('good', {'y': 1}, 1)
            self.assertTrue(wait_for(lambda: writer.saved('good') == 1))
            self.assertEqual(writer.saved('bad'), 0)
            self.assertIn('bad', writer.errors())


class ApplicationWriterTests(unittest.TestCase):
    @contextlib.contextmanager
    def workdir(self):
        directory = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, directory, ignore_errors=True)
        yield directory

    def env(self, directory, pins='https://192.168.3.1=SYNTHAX30001', inform=''):
        return unittest.mock.patch.dict(os.environ, {'STATE_DIR': directory,
                                                     'UNIFI_WLAN_MAP': '{}',
                                                     'HUAWEI_CONTROL_IP': '',
                                                     'UNIFI_INFORM_URL': inform,
                                                     'WEB_ONLY_SERIALS': pins}, clear=False)

    def device(self, serial='SYNTH0000002'):
        return {'_id': '00E0FC-WUKUN-BE32-' + serial,
                '_deviceId': {'_Manufacturer': 'Huawei', '_ProductClass': 'WUKUN-BE32'},
                '_lastInform': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
                'InternetGatewayDevice': {
                    'ManagementServer': {'ConnectionRequestURL': {'_value': 'https://192.0.2.11:7547/cb'}},
                    'DeviceInfo': {'SoftwareVersion': {'_value': '4.2.0.53'},
                                   'SerialNumber': {'_value': serial}},
                    'LANDevice': {'1': {'WLANConfiguration': {'1': {
                        'SSID': {'_value': 'ExampleSSID'}, 'Channel': {'_value': 128},
                        'Enable': {'_value': True}, 'BSSID': {'_value': '02:00:00:00:00:13'},
                        'AssociatedDevice': {}}}}}}}

    def test_stuck_writer_does_not_block_snapshot_or_tick(self):
        from huawei_bridge.__main__ import Application
        with self.workdir() as directory, self.env(directory, inform='http://127.0.0.1:9/inform'):
            app = Application()
            self.addCleanup(app.close)
            app.writer.close()
            entered = threading.Event()
            release = threading.Event()

            def blocked(path, data):
                entered.set()
                release.wait(3.0)

            app.writer = JsonRegistryWriter(
                {'vap': app.registry_path, 'webonly': app.web_registry_path},
                on_saved=app._on_saved, write=blocked, join_timeout=0.2)
            self.addCleanup(app.writer.close)
            app.web_enrichment = lambda: None
            app.web_inventory = lambda: {'routers': {}}
            app.web_only = lambda: {'routers': {}}
            app.devices = [self.device()]
            started = time.monotonic()
            snapshot = app.snapshot()  # submits the VAP registry -> the writer blocks
            self.assertTrue(entered.wait(2.0))
            calls = []

            def spy(ap, snap):
                calls.append(ap['id'])
                app.unifi.next_send[ap['virtual_mac']] = time.monotonic() + 1

            app.unifi.exchange = spy
            before = dict(app.unifi.next_send)
            app.unifi.tick(snapshot)
            self.assertTrue(calls)  # the BE3 inform path still advances
            self.assertNotEqual(before, app.unifi.next_send)
            self.assertLess(time.monotonic() - started, 0.5)
            release.set()

    def test_close_is_bounded_and_idempotent(self):
        from huawei_bridge.__main__ import Application
        with self.workdir() as directory, self.env(directory):
            app = Application()
            app.close()
            app.close()
            self.assertFalse(app.writer._thread.is_alive())

    def test_concurrent_registry_candidates_are_both_kept(self):
        from huawei_bridge.__main__ import Application

        pins = 'https://192.168.3.1=SYNTHAX30001,https://192.168.3.2=SYNTHAX30002'
        with self.workdir() as directory, self.env(directory, pins=pins):
            app = Application()
            self.addCleanup(app.close)
            app.web_enrichment = lambda: None
            app.web_inventory = lambda: {'routers': {}}
            app.devices = []
            local = threading.local()
            profiles = [{'band': '5g', 'ssid': 'ExampleWifi', 'native_id': 'n-5', 'usage': 'primary',
                         'standard': 'a/n/ac/ax', 'enabled': True, 'channel_configured': 0}]

            def web_only():
                origin = getattr(local, 'origin', 'https://192.168.3.1')
                serial = getattr(local, 'serial', 'SYNTHAX30001')
                mac = getattr(local, 'mac', 'aa:bb:cc:dd:ee:01')
                rec = {'router_ip': origin[8:], 'origin': origin, 'serial': serial,
                       'source_type': 'web-api-only', 'transport': 'direct',
                       'device': {'model': 'WS7200'}, 'clients': [{'mac': mac, 'band_norm': '5g'}],
                       'inventory': {'profiles': profiles}, 'observed_at': time.time() - 5}
                return {'routers': {origin: rec}}

            app.web_only = web_only

            def run(origin, serial, mac):
                local.origin, local.serial, local.mac = origin, serial, mac
                app.snapshot()

            threads = [threading.Thread(target=run, args=('https://192.168.3.1', 'SYNTHAX30001', 'aa:bb:cc:dd:ee:01')),
                       threading.Thread(target=run, args=('https://192.168.3.2', 'SYNTHAX30002', 'aa:bb:cc:dd:ee:02'))]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join(5)
            self.assertEqual(len(app.web_registry['sources']), 2)


class IdentityCollisionTests(unittest.TestCase):
    @contextlib.contextmanager
    def workdir(self):
        directory = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, directory, ignore_errors=True)
        yield directory

    def env(self, directory):
        return unittest.mock.patch.dict(os.environ, {
            'STATE_DIR': directory, 'UNIFI_WLAN_MAP': '{}', 'HUAWEI_CONTROL_IP': '',
            'WEB_ONLY_SERIALS': 'https://192.168.3.1=SYNTHAX30001'}, clear=False)

    def device(self, serial):
        return {'_id': '00E0FC-WUKUN-BE32-' + serial,
                '_deviceId': {'_Manufacturer': 'Huawei', '_ProductClass': 'WUKUN-BE32'},
                '_lastInform': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
                'InternetGatewayDevice': {
                    'ManagementServer': {'ConnectionRequestURL': {'_value': 'https://192.0.2.11:7547/cb'}},
                    'DeviceInfo': {'SoftwareVersion': {'_value': '4.2.0.53'},
                                   'SerialNumber': {'_value': serial}},
                    'LANDevice': {'1': {'WLANConfiguration': {'1': {
                        'SSID': {'_value': 'ExampleSSID'}, 'Channel': {'_value': 128},
                        'Enable': {'_value': True}, 'BSSID': {'_value': '02:00:00:00:00:13'},
                        'AssociatedDevice': {}}}}}}}

    def record(self, serial):
        return {'origin': 'https://192.168.3.1', 'router_ip': '192.168.3.1', 'serial': serial,
                'source_type': 'web-api-only', 'transport': 'direct',
                'device': {'model': 'WS7200'}, 'clients': [],
                'inventory': {'profiles': [{'band': '5g', 'ssid': 'M', 'native_id': 'n',
                                            'usage': 'primary', 'standard': 'ax', 'enabled': True}]},
                'observed_at': time.time() - 5}

    def test_future_acs_same_serial_is_quarantined_with_and_without_a_web_record(self):
        from huawei_bridge.__main__ import Application
        from huawei_bridge import webonly
        with self.workdir() as directory, self.env(directory):
            app = Application()
            self.addCleanup(app.close)
            webonly.ensure_source(app.web_registry, 'SYNTHAX30001')  # known web source
            app.web_registry_saved_generation = app.web_registry_generation
            app.web_enrichment = lambda: None
            app.web_inventory = lambda: {'routers': {}}
            app.devices = [self.device('SYNTHAX30001')]
            app.web_only = lambda: {'routers': {'https://192.168.3.1': self.record('SYNTHAX30001')}}
            snap = app.snapshot()
            acs = [ap for ap in snap['aps'] if not ap.get('web_only')]
            self.assertTrue(acs)
            self.assertTrue(acs[0]['quarantined_identity'])
            self.assertFalse(acs[0]['online'])
            self.assertLessEqual(len([ap for ap in snap['aps']]), 1)  # no duplicate physical unit
            app.web_only = lambda: {'routers': {}}
            snap2 = app.snapshot()
            acs2 = [ap for ap in snap2['aps'] if not ap.get('web_only')]
            self.assertTrue(acs2 and acs2[0]['quarantined_identity'])  # registry is persistent

    def test_no_acs_refresh_task_for_a_colliding_identity(self):
        from huawei_bridge.__main__ import Application
        from huawei_bridge import webonly
        with self.workdir() as directory, self.env(directory):
            app = Application()
            self.addCleanup(app.close)
            webonly.ensure_source(app.web_registry, 'SYNTHAX30001')
            paths = []

            def request(path, data=None):
                paths.append(path)
                if path == '/devices':
                    return [self.device('SYNTHAX30001')]
                return []

            app.request = request
            app.control.reconcile = lambda devices: None
            app.last_refresh = 0
            app.devices = [self.device('SYNTHAX30001')]
            app.collect()
            self.assertFalse(any('/tasks' in path and 'SYNTHAX30001' in path for path in paths))


if __name__ == '__main__':
    unittest.main()
