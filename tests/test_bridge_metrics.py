"""Offline tests for reported-counter bookkeeping (no unit conversion)."""

import json
import os
import tempfile
import threading
import time
import unittest

from huawei_bridge import metrics


class StepTests(unittest.TestCase):
    def test_first_and_monotonic_transitions(self):
        self.assertEqual(metrics.step(None, 5), (None, False))
        self.assertEqual(metrics.step(5, None), (None, False))
        self.assertEqual(metrics.step(5, 9), (4, False))

    def test_decrease_is_a_reset(self):
        delta, reset = metrics.step(100, 7)
        self.assertEqual(delta, 7)
        self.assertTrue(reset)

    def test_no_throughput_is_derived(self):
        entry = metrics.CounterTracker().update('aa:bb:cc:dd:ee:01', 'tx_kb', 1024, 10.0)
        self.assertNotIn('bytes', entry)
        self.assertNotIn('per_second', entry)
        self.assertEqual(entry['unit'], 'KB-reported')


class TrackerTests(unittest.TestCase):
    def test_delta_and_reset_counting(self):
        tracker = metrics.CounterTracker()
        tracker.update('m', 'rx_kb', 100, 1.0)
        second = tracker.update('m', 'rx_kb', 150, 2.0)
        self.assertEqual(second['delta'], 50)
        self.assertEqual(second['resets'], 0)
        third = tracker.update('m', 'rx_kb', 10, 3.0)
        self.assertEqual(third['delta'], 10)
        self.assertEqual(third['resets'], 1)
        self.assertEqual(third['first_seen'], 1.0)

    def test_annotate_labels_units_and_skips_unknowns(self):
        client = {'mac': 'aa:bb:cc:dd:ee:01', 'tx_kb': 5, 'up_rate': 9,
                  'negotiated_rate': 866, 'bogus': 1}
        metrics.CounterTracker().annotate(client, 10.0)
        self.assertEqual(client['metrics']['tx_kb']['unit'], 'KB-reported')
        self.assertEqual(client['metrics']['up_rate']['unit'], 'unknown')
        self.assertEqual(client['metrics']['negotiated_rate']['unit'], 'unknown')
        self.assertNotIn('bogus', client['metrics'])

    def test_booleans_and_non_numbers_are_ignored(self):
        tracker = metrics.CounterTracker()
        self.assertIsNone(tracker.update('m', 'tx_kb', True, 1.0))
        self.assertIsNone(tracker.update('m', 'tx_kb', 'x', 1.0))


class CounterStoreTests(unittest.TestCase):
    def store(self, **kwargs):
        self._directory = tempfile.TemporaryDirectory()
        self.addCleanup(self._directory.cleanup)
        path = os.path.join(self._directory.name, 'counters_v1.json')
        return metrics.CounterStore(path, **kwargs)

    def test_first_sample_has_no_delta(self):
        entry = self.store().observe(('ap', 'path', 'total_bytes_sent', 'tr098-nbi'),
                                     100, 10.0, 'bytes', direction='tx')
        self.assertIsNone(entry['delta'])
        self.assertEqual(entry['samples'], 1)
        self.assertFalse(entry['replay'])

    def test_newer_observation_produces_the_delta(self):
        store = self.store()
        store.observe(('ap', 'p', 'm', 's'), 100, 10.0, 'bytes')
        entry = store.observe(('ap', 'p', 'm', 's'), 160, 20.0, 'bytes')
        self.assertEqual(entry['delta'], 60)
        self.assertEqual(entry['samples'], 2)

    def test_replay_and_reorder_never_advance_or_repeat_delta(self):
        store = self.store()
        first = store.observe(('ap', 'p', 'm', 's'), 100, 10.0, 'bytes')
        store.observe(('ap', 'p', 'm', 's'), 160, 20.0, 'bytes')
        replay = store.observe(('ap', 'p', 'm', 's'), 160, 20.0, 'bytes')
        self.assertTrue(replay['replay'])
        self.assertIsNone(replay['delta'])
        reorder = store.observe(('ap', 'p', 'm', 's'), 120, 15.0, 'bytes')
        self.assertTrue(reorder['replay'])
        self.assertIsNone(reorder['delta'])
        self.assertEqual(reorder['first_seen'], first['first_seen'])
        self.assertEqual(store.view()[next(iter(store.view()))]['value'], 160)

    def test_stale_gap_invalidates_the_interval(self):
        store = self.store(stale_after=100)
        store.observe(('ap', 'p', 'm', 's'), 100, 10.0, 'bytes')
        entry = store.observe(('ap', 'p', 'm', 's'), 900, 200.0, 'bytes')
        self.assertIsNone(entry['delta'])
        self.assertFalse(entry['reset'])

    def test_decrease_is_a_reset_never_a_guessed_wrap(self):
        store = self.store()
        store.observe(('ap', 'p', 'm', 's'), 4000, 10.0, 'packets')
        entry = store.observe(('ap', 'p', 'm', 's'), 12, 20.0, 'packets')
        self.assertTrue(entry['reset'])
        self.assertIsNone(entry['delta'])
        self.assertEqual(entry['resets'], 1)

    def test_explicit_width_contract_handles_the_wrap(self):
        store = self.store()
        store.observe(('ap', 'p', 'm', 's'), 2 ** 32 - 10, 10.0, 'packets')
        entry = store.observe(('ap', 'p', 'm', 's'), 5, 20.0, 'packets', wrap_width=32)
        self.assertFalse(entry['reset'])
        self.assertEqual(entry['delta'], 15)

    def test_invalid_samples_are_rejected(self):
        store = self.store()
        for value in (True, -1, 'x', float('inf'), None):
            with self.subTest(value=value):
                self.assertIsNone(store.observe(('ap', 'p', 'm', 's'), value, 1.0, 'bytes'))
        self.assertEqual(len(store), 0)

    def test_state_persists_and_reloads(self):
        store = self.store()
        store.observe(('ap', 'p', 'm', 's'), 100, 10.0, 'bytes', direction='tx',
                      scope='interface-unverified', verification='unverified', source='tr098-nbi')
        self.assertTrue(store.save())
        self.assertTrue(os.path.exists(store.path))
        reloaded = metrics.CounterStore(store.path)
        entry = reloaded.view()['ap|p|m|s']
        self.assertEqual(entry['value'], 100)
        self.assertEqual(entry['direction'], 'tx')
        self.assertEqual(entry['scope'], 'interface-unverified')

    def test_restart_epoch_resets_without_a_great_delta(self):
        store = self.store()
        store.observe(('ap', 'p', 'm', 's'), 5_000_000, 10.0, 'bytes')
        store.save()
        reloaded = metrics.CounterStore(store.path)
        entry = reloaded.observe(('ap', 'p', 'm', 's'), 3, 20.0, 'bytes')
        self.assertTrue(entry['reset'])
        self.assertIsNone(entry['delta'])

    def test_identical_values_across_interfaces_stay_separate_keys(self):
        store = self.store()
        a = store.observe(('ap', 'p1', 'total_bytes_sent', 'tr098-nbi'), 42, 10.0, 'bytes')
        b = store.observe(('ap', 'p2', 'total_bytes_sent', 'tr098-nbi'), 42, 10.0, 'bytes')
        self.assertNotEqual(a['key'], b['key'])
        self.assertEqual(len(store), 2)

    def test_missing_timestamp_is_diagnostic_and_never_becomes_a_watermark(self):
        store = self.store()
        for bad in (None, float('nan'), True, 'x'):
            with self.subTest(timestamp=bad):
                entry = store.observe(('ap', 'p', 'm', 's'), 10, bad, 'bytes')
                self.assertTrue(entry['missing_time'])
                self.assertFalse(entry['accepted'])
                self.assertIsNone(entry['delta'])
        self.assertEqual(len(store), 0)

    def test_missing_timestamp_does_not_corrupt_an_accepted_watermark(self):
        store = self.store()
        store.observe(('ap', 'p', 'm', 's'), 100, 20.0, 'bytes')
        gap = store.observe(('ap', 'p', 'm', 's'), 150, None, 'bytes')
        self.assertTrue(gap['missing_time'])
        self.assertIsNone(gap['delta'])
        self.assertEqual(gap['accepted_value'], 100)
        stored = store.view()['ap|p|m|s']
        self.assertEqual(stored['value'], 100)
        self.assertEqual(stored['observed_at'], 20.0)
        reorder = store.observe(('ap', 'p', 'm', 's'), 120, 15.0, 'bytes')
        self.assertTrue(reorder['replay'])
        self.assertIsNone(reorder['delta'])
        nxt = store.observe(('ap', 'p', 'm', 's'), 160, 25.0, 'bytes')
        self.assertEqual(nxt['delta'], 60)
        self.assertTrue(nxt['accepted'])

    def test_an_undated_record_is_upgraded_without_a_delta(self):
        store = self.store()
        store.observe(('ap', 'p', 'm', 's'), 50, None, 'bytes')
        first_dated = store.observe(('ap', 'p', 'm', 's'), 80, 10.0, 'bytes')
        self.assertTrue(first_dated['accepted'])
        self.assertIsNone(first_dated['delta'])
        self.assertEqual(first_dated['samples'], 1)
        store.observe(('ap', 'p', 'm', 's'), 90, 20.0, 'bytes')
        entry = store.observe(('ap', 'p', 'm', 's'), 95, 30.0, 'bytes')
        self.assertEqual(entry['delta'], 5)

    def test_decline_is_never_wrapped_without_an_explicit_contract(self):
        store = self.store()
        store.observe(('ap', 'p', 'm', 's'), 4_000_000_000, 10.0, 'packets')
        entry = store.observe(('ap', 'p', 'm', 's'), 3, 20.0, 'packets')
        self.assertTrue(entry['reset'])
        self.assertIsNone(entry['delta'])

    def test_entry_cap_prunes_the_least_recent(self):
        store = self.store(max_entries=2)
        store.observe(('ap', 'a', 'm', 's'), 1, 1.0, 'bytes')
        store.observe(('ap', 'b', 'm', 's'), 1, 2.0, 'bytes')
        store.observe(('ap', 'c', 'm', 's'), 1, 3.0, 'bytes')
        self.assertEqual(len(store), 2)
        self.assertNotIn('ap|a|m|s', store.view())

    def test_corrupt_state_file_fails_open_and_preserves_the_original(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, 'counters_v1.json')
            with open(path, 'w') as handle:
                handle.write('{not json')
            store = metrics.CounterStore(path)
            self.assertEqual(len(store), 0)
            self.assertFalse(store.status()['persistence_enabled'])
            self.assertEqual(store.status()['degraded_reason'], 'state-unreadable')
            self.assertFalse(store.save())
            self.assertEqual(store.observe(('ap', 'p', 'm', 's'), 1, 1.0, 'bytes')['value'], 1)
            self.assertFalse(store.save())
            with open(path) as handle:
                self.assertEqual(handle.read(), '{not json')

    def test_save_without_path_is_a_noop(self):
        store = metrics.CounterStore(None)
        self.assertIsNone(store.observe(('ap', 'p', 'm', 's'), 1, 1.0, 'bytes')['delta'])
        self.assertFalse(store.save())

    def test_persisted_shape_is_schema_versioned(self):
        store = self.store()
        store.observe(('ap', 'p', 'm', 's'), 1, 1.0, 'bytes')
        store.save()
        with open(store.path) as handle:
            payload = json.load(handle)
        self.assertEqual(payload['schema_version'], metrics.COUNTERS_SCHEMA)
        self.assertIn('ap|p|m|s', payload['entries'])


class CounterStoreLoadTests(unittest.TestCase):
    def build(self, payload_text):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        path = os.path.join(directory.name, 'counters_v1.json')
        with open(path, 'w') as handle:
            handle.write(payload_text)
        return path, metrics.CounterStore(path)

    def state(self, entries_json):
        return '{"schema_version": 1, "entries": %s}' % entries_json

    def test_bad_samples_metadata_never_raises_and_keeps_the_file(self):
        raw = self.state('{"k": {"value": 1, "samples": "invalid"}}')
        path, store = self.build(raw)
        self.assertEqual(len(store), 0)
        self.assertFalse(store.status()['persistence_enabled'])
        self.assertEqual(store.status()['degraded_reason'], 'state-entry-invalid')
        self.assertFalse(store.save())
        with open(path) as handle:
            self.assertEqual(handle.read(), raw)

    def test_extreme_json_integer_never_raises_or_overwrites_state(self):
        raw = json.dumps({'schema_version': 1, 'entries': {
            'k': {'value': 10 ** 400, 'samples': 1, 'resets': 0}}})
        path, store = self.build(raw)
        self.assertEqual(len(store), 0)
        self.assertEqual(store.status()['degraded_reason'], 'state-entry-invalid')
        self.assertFalse(store.save())
        with open(path) as handle:
            self.assertEqual(handle.read(), raw)

    def test_malformed_numeric_and_metadata_entries_are_dropped(self):
        raw = self.state('{"ok": {"value": 5, "samples": 2, "resets": 0},'
                         ' "bool": {"value": true},'
                         ' "nan": {"value": NaN},'
                         ' "cnt": {"value": 1, "samples": 1.5},'
                         ' "neg": {"value": -3},'
                         ' "list": {"value": 1, "resets": [1]},'
                         ' "badts": {"value": 1, "observed_at": "soon"}}')
        _, store = self.build(raw)
        self.assertEqual(list(store.view()), ['ok'])
        self.assertFalse(store.status()['persistence_enabled'])

    def test_over_cap_entry_count_degrades(self):
        entries = ','.join('"k%d": {"value": %d, "samples": 1, "resets": 0}' % (i, i)
                           for i in range(5))
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        path = os.path.join(directory.name, 'counters_v1.json')
        with open(path, 'w') as handle:
            handle.write(self.state('{%s}' % entries))
        store = metrics.CounterStore(path, max_entries=2)
        self.assertEqual(len(store), 2)
        self.assertEqual(store.status()['degraded_reason'], 'state-over-cap')

    def test_oversized_file_is_rejected_before_decode(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        path = os.path.join(directory.name, 'counters_v1.json')
        with open(path, 'wb') as handle:
            handle.write(b'x' * (metrics.MAX_STATE_BYTES + 1))
        store = metrics.CounterStore(path)
        self.assertEqual(store.status()['degraded_reason'], 'state-too-large')
        self.assertFalse(store.save())

    def test_wrong_top_level_shape_degrades(self):
        _, store = self.build('{"schema_version": 2, "entries": {}}')
        self.assertEqual(store.status()['degraded_reason'], 'state-shape')
        _, store = self.build('{"schema_version": 1, "entries": []}')
        self.assertEqual(store.status()['degraded_reason'], 'state-shape')

    def test_over_long_key_is_dropped_and_degrades(self):
        long_key = 'x' * (metrics.MAX_KEY_LEN + 1)
        _, store = self.build(self.state('{"%s": {"value": 1, "samples": 1}}' % long_key))
        self.assertEqual(len(store), 0)
        self.assertEqual(store.status()['degraded_reason'], 'state-entry-invalid')

    def test_missing_file_is_a_fresh_enabled_store(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        store = metrics.CounterStore(os.path.join(directory.name, 'counters_v1.json'))
        self.assertTrue(store.status()['persistence_enabled'])
        self.assertIsNone(store.status()['degraded_reason'])

    def test_over_long_metadata_string_is_sanitized_not_crashing(self):
        raw = self.state('{"k": {"value": 1, "samples": 1, "unit": "%s"}}' %
                         ('u' * (metrics.MAX_META_LEN + 5)))
        _, store = self.build(raw)
        self.assertEqual(store.view()['k']['unit'], 'unknown')


class CounterStoreWriterTests(unittest.TestCase):
    def store(self, writer, **kwargs):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        path = os.path.join(directory.name, 'counters_v1.json')
        store = metrics.CounterStore(path, writer=writer, **kwargs)
        self.addCleanup(store.close)
        return store

    def wait_saved(self, store, timeout=3.0):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            status = store.status()
            if status['generation'] <= status['saved_generation']:
                return True
            time.sleep(0.02)
        return store.status()['generation'] <= store.status()['saved_generation']

    def test_observe_never_blocks_on_a_stuck_writer(self):
        entered, release = threading.Event(), threading.Event()

        def writer(path, payload):
            entered.set()
            release.wait(5)
            return True

        store = self.store(writer)
        store.start_writer()
        start = time.monotonic()
        for index in range(300):
            store.observe(('ap', 'p', 'm', 's'), index, float(index + 1), 'bytes')
        elapsed = time.monotonic() - start
        self.assertLess(elapsed, 1.0)
        self.assertTrue(entered.wait(2.0))
        release.set()
        self.assertTrue(self.wait_saved(store))

    def test_updates_during_io_are_not_lost(self):
        written = []

        def writer(path, payload):
            written.append(payload)
            return True

        store = self.store(writer)
        store.start_writer()
        for index in range(1, 61):
            store.observe(('ap', 'p', 'm', 's'), index, float(index), 'bytes')
        self.assertTrue(self.wait_saved(store))
        self.assertEqual(store.status()['saved_generation'], store.status()['generation'])
        self.assertEqual(written[-1]['entries']['ap|p|m|s']['value'], 60)

    def test_failed_write_backs_off_without_repeated_io(self):
        attempts = []

        def writer(path, payload):
            attempts.append(time.monotonic())
            return False

        store = self.store(writer)
        store.start_writer()
        store.observe(('ap', 'p', 'm', 's'), 1, 1.0, 'bytes')
        deadline = time.monotonic() + 2.0
        while not attempts and time.monotonic() < deadline:
            time.sleep(0.02)
        self.assertEqual(len(attempts), 1)
        store.request_save()
        store.request_save()
        time.sleep(0.3)
        self.assertEqual(len(attempts), 1)
        self.assertGreaterEqual(store.status()['failures'], 1)

    def test_close_is_bounded_with_a_stuck_writer(self):
        entered, release = threading.Event(), threading.Event()

        def writer(path, payload):
            entered.set()
            release.wait(5)
            return True

        store = self.store(writer)
        store.start_writer()
        store.observe(('ap', 'p', 'm', 's'), 1, 1.0, 'bytes')
        self.assertTrue(entered.wait(2.0))
        start = time.monotonic()
        closed = store.close(timeout=0.2)
        self.assertLess(time.monotonic() - start, 1.5)
        self.assertFalse(closed)
        release.set()
        self.assertTrue(store.close(timeout=5.0))
        self.assertFalse(store.status()['writer_running'])

    def test_status_reports_no_secret_payload(self):
        store = self.store(lambda path, payload: True)
        store.observe(('ap', 'p', 'm', 's'), 1, 1.0, 'bytes')
        self.assertIn('persistence_enabled', store.status())
        self.assertIn('degraded_reason', store.status())


if __name__ == '__main__':
    unittest.main()
