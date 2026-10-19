#!/usr/bin/env python3
"""Counter bookkeeping for reported router metrics (no unit conversion).

Tracks per-client raw counters across polls, detects resets (a decrease means
the router rebooted or the counter wrapped) and labels each value with its
source unit. Throughput is never derived: directional counters stay as
reported until their unit and direction are proven.

``CounterStore`` persists interface-level counter observations keyed by
``CPE id + native TR-098 interface path + metric + source``. Its step is driven
by the observation timestamp carried by each sample, never by the bridge's poll
time, so a replayed or reordered controller snapshot cannot fabricate a delta.
"""

import json
import math
import threading
import time
from pathlib import Path
from typing import Any

# The firmware contract for rate units is not verified, so every rate is
# labelled 'unknown'; no reported rate is ever presented as Mbps or converted
# into directional tx/rx. Flip only with an explicit verified contract.
UNITS = {
    'tx_kb': 'KB-reported',
    'rx_kb': 'KB-reported',
    'up_rate': 'unknown',
    'down_rate': 'unknown',
    'negotiated_rate': 'unknown',
    'rate_mbps': 'unknown',
}


def step(previous, current):
    if current is None:
        return None, False
    if previous is None:
        return None, False
    if current < previous:
        return current, True
    return current - previous, False


COUNTERS_SCHEMA = 1
COUNTERS_FILENAME = 'counters_v1.json'
DEFAULT_STALE_AFTER = 900.0
DEFAULT_MAX_ENTRIES = 4096
MAX_STATE_BYTES = 2 * 1024 * 1024
MAX_LOAD_ENTRIES = 16384
MAX_KEY_LEN = 512
MAX_META_LEN = 64
MAX_COUNT_VALUE = 2 ** 53
DEFAULT_WRITE_BACKOFF = 1.0
MAX_WRITE_BACKOFF = 60.0


def _finite(value):
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    try:
        return value if math.isfinite(value) else None
    except OverflowError:
        return None


def _counter_key(key):
    if isinstance(key, (tuple, list)):
        return '|'.join('' if part is None else str(part) for part in key)
    return str(key)


def _atomic_write(path, payload):
    from .unifi import atomic_json
    atomic_json(path, payload)
    return True


class CounterStore:
    """Bounded, fail-open persistence of interface counter observations.

    Entries keyed by CPE/interface/metric/source hold the last accepted dated
    sample. A sample whose timestamp is not newer than the stored one is a
    replay/reorder: it neither advances state nor repeats a delta. A sample
    without a usable timestamp is diagnostic only and never advances the
    accepted watermark nor produces a delta. A gap wider than ``stale_after``
    invalidates the interval, and a decrease is a reset (never a guessed wrap)
    unless the caller supplies an explicit width contract.

    Callers never perform I/O: ``observe`` mutates under a short lock and
    signals an optional single background daemon writer that persists outside
    the lock. A corrupt state file disables persistence without crashing the
    caller or overwriting the file.
    """

    def __init__(self, path=None, max_entries=DEFAULT_MAX_ENTRIES,
                 stale_after=DEFAULT_STALE_AFTER, writer=None):
        self.path = Path(path) if path is not None else None
        self.max_entries = max(1, int(max_entries))
        self.stale_after = float(stale_after)
        self._writer_fn = writer or _atomic_write
        self._entries: dict[str, Any] = {}
        self._lock = threading.RLock()
        self._gen = 0
        self._saved_gen = 0
        self._persistence_disabled = path is None
        self._degraded_reason = None if path is not None else 'no-path'
        self._warnings: list[str] = []
        self._writer: threading.Thread | None = None
        self._wake = threading.Event()
        self._stop = threading.Event()
        self._next_attempt = 0.0
        self._write_successes = 0
        self._write_failures = 0
        self._last_success = None
        self._last_error = None
        self.load()

    def load(self):
        self._entries = {}
        if self.path is None:
            return
        try:
            with open(self.path, 'rb') as handle:
                data = handle.read(MAX_STATE_BYTES + 1)
        except FileNotFoundError:
            return
        except OSError:
            self._degrade('state-unreadable')
            return
        if len(data) > MAX_STATE_BYTES:
            self._degrade('state-too-large')
            return
        try:
            raw = json.loads(data.decode('utf-8'))
        except (ValueError, UnicodeDecodeError):
            self._degrade('state-unreadable')
            return
        if not isinstance(raw, dict) or raw.get('schema_version') != COUNTERS_SCHEMA:
            self._degrade('state-shape')
            return
        entries = raw.get('entries')
        if not isinstance(entries, dict):
            self._degrade('state-shape')
            return
        clean: dict[str, Any] = {}
        anomalies = 0
        for key, entry in entries.items():
            if len(clean) >= self.max_entries:
                self._degrade('state-over-cap')
                break
            parsed = self._parse_entry(key, entry)
            if parsed is None:
                anomalies += 1
                continue
            parsed_key, value = parsed
            clean[parsed_key] = value
        self._entries = clean
        if anomalies:
            self._degrade('state-entry-invalid')

    def _degrade(self, reason):
        self._persistence_disabled = True
        self._degraded_reason = reason
        if reason not in self._warnings:
            self._warnings.append(reason)

    @staticmethod
    def _bounded_count(value):
        if value is None:
            return 0
        if isinstance(value, bool):
            return None
        if isinstance(value, int):
            count = value
        elif isinstance(value, float) and value.is_integer():
            count = int(value)
        else:
            return None
        return count if 0 <= count <= MAX_COUNT_VALUE else None

    @staticmethod
    def _optional_number(value):
        if value is None:
            return True, None
        number = _finite(value)
        return (number is not None), number

    def _parse_entry(self, key, entry):
        if not isinstance(key, str) or not key or len(key) > MAX_KEY_LEN:
            return None
        if not isinstance(entry, dict):
            return None
        value = _finite(entry.get('value'))
        if value is None or value < 0:
            return None
        samples = self._bounded_count(entry.get('samples'))
        resets = self._bounded_count(entry.get('resets'))
        if samples is None or resets is None:
            return None
        fields = {}
        for name in ('observed_at', 'first_seen', 'last_seen'):
            ok, number = self._optional_number(entry.get(name))
            if not ok:
                return None
            fields[name] = number
        meta = {}
        for name, default in (('unit', 'unknown'), ('direction', None), ('scope', None),
                              ('verification', 'unverified'), ('source', None)):
            raw = entry.get(name)
            meta[name] = raw if isinstance(raw, str) and len(raw) <= MAX_META_LEN else default
        return key, {'value': value, 'samples': samples, 'resets': resets, **fields, **meta}

    @property
    def persistence_enabled(self):
        return self.path is not None and not self._persistence_disabled

    def _write_payload(self, entries):
        return bool(self._writer_fn(self.path, {'schema_version': COUNTERS_SCHEMA,
                                                'updated_at': time.time(), 'entries': entries}))

    def save(self, force=False):
        with self._lock:
            if not self.persistence_enabled:
                return False
            if not force and self._gen <= self._saved_gen:
                return False
            generation = self._gen
            entries = {key: dict(entry) for key, entry in self._entries.items()}
        try:
            ok = self._write_payload(entries)
        except Exception as exc:  # noqa: BLE001 - explicit API only; never crash the caller
            ok, error = False, type(exc).__name__
        else:
            error = None if ok else 'write-failed'
        with self._lock:
            if not ok:
                self._write_failures += 1
                self._last_error = error
                return False
            self._saved_gen = max(self._saved_gen, generation)
            self._write_successes += 1
            self._last_success = time.time()
            self._last_error = None
        return True

    def _prune(self):
        overflow = len(self._entries) - self.max_entries
        if overflow <= 0:
            return
        ordered = sorted(self._entries.items(),
                         key=lambda item: item[1].get('last_seen') or 0)
        for key, _ in ordered[:overflow]:
            self._entries.pop(key, None)

    def _advance(self):
        self._gen += 1
        if self._writer is not None:
            self._wake.set()

    def observe(self, key, value, observed_at, unit, direction=None, scope=None,
                verification='unverified', source=None, wrap_width=None):
        """Record one counter sample under a short lock; no I/O, no blocking.

        Returns ``None`` for a rejected sample (non-numeric, negative or
        non-finite). A missing or invalid timestamp yields a diagnostic with
        no delta and no accepted-watermark change (``missing_time`` true), so a
        fabricated interval is never emitted.
        """
        value = _finite(value)
        if value is None or value < 0:
            return None
        observed_at = _finite(observed_at)
        with self._lock:
            return self._observe(_counter_key(key), value, observed_at, unit, direction,
                                 scope, verification, source, wrap_width)

    def _observe(self, key, value, observed_at, unit, direction, scope, verification,
                 source, wrap_width):
        prev = self._entries.get(key)
        if observed_at is None:
            # No usable timestamp: diagnostic only. Never advance the accepted
            # watermark (a later dated sample must step from the last dated
            # point, not from this unverified one) and never emit a delta.
            return self._view(key, prev, value, delta=None, reset=False, replay=False,
                              accepted=False, missing_time=True)
        if prev is None:
            entry = {'value': value, 'observed_at': observed_at, 'first_seen': observed_at,
                     'last_seen': observed_at, 'samples': 1, 'resets': 0, 'unit': unit,
                     'direction': direction, 'scope': scope, 'verification': verification,
                     'source': source}
            self._entries[key] = entry
            self._prune()
            self._advance()
            return self._view(key, entry, value, delta=None, reset=False, replay=False,
                              accepted=True, missing_time=False)

        prev_at = prev.get('observed_at')
        if prev_at is None:
            prev.update(value=value, observed_at=observed_at, first_seen=observed_at,
                        last_seen=observed_at, samples=prev.get('samples', 0) + 1,
                        unit=unit, direction=direction, scope=scope,
                        verification=verification, source=source)
            self._advance()
            return self._view(key, prev, value, delta=None, reset=False, replay=False,
                              accepted=True, missing_time=False)
        if observed_at <= prev_at:
            # A replay/reordered snapshot must not advance state or overwrite
            # the accepted sample; the previous delta is never repeated.
            return self._view(key, prev, prev['value'], delta=None, reset=False,
                              replay=True, accepted=False, missing_time=False)

        delta, reset = None, False
        gap = observed_at - prev_at
        if gap > self.stale_after:
            delta = None
        elif value < prev['value']:
            if wrap_width is not None and 0 <= prev['value'] < 2 ** wrap_width:
                delta = (2 ** wrap_width - prev['value']) + value
            else:
                reset, delta = True, None
        else:
            delta = value - prev['value']

        prev.update(value=value, observed_at=observed_at, last_seen=observed_at,
                    samples=prev.get('samples', 0) + 1,
                    resets=prev.get('resets', 0) + (1 if reset else 0),
                    unit=unit, direction=direction, scope=scope,
                    verification=verification, source=source)
        self._prune()
        self._advance()
        return self._view(key, prev, value, delta=delta, reset=reset, replay=False,
                          accepted=True, missing_time=False)

    @staticmethod
    def _view(key, stored, value, delta, reset, replay, accepted, missing_time):
        stored = stored if isinstance(stored, dict) else {}
        view = {'key': key, 'value': value, 'delta': delta, 'reset': reset,
                'replay': replay, 'accepted': accepted, 'missing_time': missing_time,
                'samples': stored.get('samples'), 'resets': stored.get('resets'),
                'first_seen': stored.get('first_seen'), 'observed_at': stored.get('observed_at'),
                'last_seen': stored.get('last_seen'), 'unit': stored.get('unit'),
                'direction': stored.get('direction'), 'scope': stored.get('scope'),
                'verification': stored.get('verification'), 'source': stored.get('source')}
        if not accepted:
            view['accepted_value'] = stored.get('value')
        return view

    def view(self):
        with self._lock:
            return {key: dict(entry) for key, entry in self._entries.items()}

    def __len__(self):
        with self._lock:
            return len(self._entries)

    def start_writer(self):
        with self._lock:
            if self._writer is not None and self._writer.is_alive():
                return False
            self._stop.clear()
            self._writer = threading.Thread(target=self._writer_loop,
                                            name='counter-writer', daemon=True)
            self._writer.start()
            return True

    def request_save(self):
        if self._writer is not None:
            self._wake.set()

    def _writer_loop(self):
        backoff = DEFAULT_WRITE_BACKOFF
        while not self._stop.is_set():
            self._wake.wait(timeout=2.0)
            self._wake.clear()
            if self._stop.is_set():
                break
            now = time.monotonic()
            with self._lock:
                if self._gen <= self._saved_gen or self._persistence_disabled:
                    continue
                if now < self._next_attempt:
                    continue
                generation = self._gen
                entries = {key: dict(entry) for key, entry in self._entries.items()}
            try:
                ok, error = self._write_payload(entries), None
            except Exception as exc:  # noqa: BLE001 - fail open; never crash the writer
                ok, error = False, type(exc).__name__
            with self._lock:
                if ok:
                    # A mutation during the write bumped _gen past the generation
                    # captured here, so the store stays dirty and is rewritten.
                    self._saved_gen = max(self._saved_gen, generation)
                    self._write_successes += 1
                    self._last_success = time.time()
                    self._last_error = None
                    self._next_attempt = 0.0
                    backoff = DEFAULT_WRITE_BACKOFF
                else:
                    self._write_failures += 1
                    self._last_error = error or 'write-failed'
                    self._next_attempt = time.monotonic() + backoff
                    backoff = min(backoff * 2, MAX_WRITE_BACKOFF)

    def close(self, timeout=2.0):
        self._stop.set()
        self._wake.set()
        writer = self._writer
        if writer is not None and writer.is_alive() and writer is not threading.current_thread():
            writer.join(timeout)
        self._writer = None
        return not (writer is not None and writer.is_alive())

    def status(self):
        with self._lock:
            writer = self._writer
            return {'persistence_enabled': self.persistence_enabled,
                    'degraded_reason': self._degraded_reason,
                    'warnings': list(self._warnings), 'entries': len(self._entries),
                    'generation': self._gen, 'saved_generation': self._saved_gen,
                    'pending': self._gen > self._saved_gen,
                    'writer_running': bool(writer is not None and writer.is_alive()),
                    'saves': self._write_successes, 'failures': self._write_failures,
                    'last_success': self._last_success, 'last_error': self._last_error}


class CounterTracker:
    def __init__(self):
        self._last = {}
        self._lock = threading.RLock()

    def update(self, client_mac, key, value, now):
        with self._lock:
            return self._update(client_mac, key, value, now)

    def _update(self, client_mac, key, value, now):
        if not isinstance(value, (int, float)) or isinstance(value, bool):
            return None
        previous = self._last.get((client_mac, key))
        delta, reset = step(previous.get('value') if previous else None, value)
        entry = {
            'value': value,
            'unit': UNITS.get(key, 'unknown'),
            'source': 'reported',
            'delta': delta,
            'resets': (previous.get('resets', 0) if previous else 0) + (1 if reset else 0),
            'first_seen': previous.get('first_seen', now) if previous else now,
            'last_seen': now,
        }
        self._last[(client_mac, key)] = {'value': value, 'resets': entry['resets'],
                                         'first_seen': entry['first_seen']}
        return entry

    def annotate(self, client, now):
        mac = client.get('mac')
        if not isinstance(mac, str):
            return client
        with self._lock:
            seen = {}
            for key in UNITS:
                if key in client:
                    entry = self._update(mac, key, client[key], now)
                    if entry is not None:
                        seen[key] = entry
            if seen:
                client['metrics'] = seen
            return client
