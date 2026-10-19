#!/usr/bin/env python3
"""Bounded background JSON writer for the bridge registries.

The inform/snapshot thread must never fsync. It captures an immutable copy plus a
monotonic generation under its own quick lock and only enqueues in memory; one
daemon thread performs every durable write outside all caller locks and reports
the persisted generation back through a quick callback. At most one pending
payload per namespace is kept, so a burst of updates collapses to the newest one
without ever marking an unwritten generation as saved.
"""

import copy
import threading
import time

DEFAULT_MIN_BACKOFF = 1.0
DEFAULT_MAX_BACKOFF = 60.0
DEFAULT_JOIN_TIMEOUT = 5.0
IDLE_WAIT = 0.5


class JsonRegistryWriter:
    def __init__(self, paths, on_saved=None, write=None, min_backoff=DEFAULT_MIN_BACKOFF,
                 max_backoff=DEFAULT_MAX_BACKOFF, join_timeout=DEFAULT_JOIN_TIMEOUT):
        self._paths = dict(paths)
        self._on_saved = on_saved
        if write is None:
            from .unifi import atomic_json
            write = atomic_json
        self._write = write
        self._lock = threading.Lock()
        self._pending = {}
        self._saved = {name: 0 for name in self._paths}
        self._errors = {}
        self._inflight = set()
        self._next_attempt = {}
        self._backoff = {}
        self._wake = threading.Event()
        self._stop = threading.Event()
        self._min_backoff = min_backoff
        self._max_backoff = max_backoff
        self._join_timeout = join_timeout
        self._thread = threading.Thread(target=self._run, name='bridge-json-writer', daemon=True)
        self._thread.start()

    def submit(self, name, payload, generation):
        with self._lock:
            current = self._pending.get(name)
            if current is None or generation >= current[0]:
                self._pending[name] = (int(generation), copy.deepcopy(payload))
        self._wake.set()

    def saved(self, name):
        with self._lock:
            return self._saved.get(name, 0)

    def errors(self):
        with self._lock:
            return dict(self._errors)

    def _claim(self):
        now = time.monotonic()
        with self._lock:
            ready = [name for name in self._pending
                     if name not in self._inflight and self._next_attempt.get(name, 0.0) <= now]
            if not ready:
                return None
            name = min(ready, key=lambda key: self._pending[key][0])
            generation, payload = self._pending.pop(name)
            self._inflight.add(name)
            return name, generation, payload

    def _waited(self):
        with self._lock:
            upcoming = [self._next_attempt[name] for name in self._pending
                        if name not in self._inflight and name in self._next_attempt]
        if not upcoming:
            return IDLE_WAIT
        return max(0.01, min(IDLE_WAIT, min(upcoming) - time.monotonic()))

    def _ack(self, name, generation, ok):
        with self._lock:
            self._inflight.discard(name)
            if ok:
                self._next_attempt.pop(name, None)
                self._backoff.pop(name, None)
                if generation > self._saved.get(name, 0):
                    self._saved[name] = generation
        if ok and self._on_saved is not None:
            self._on_saved(name, generation)

    def _fail(self, name, generation, payload):
        with self._lock:
            current = self._pending.get(name)
            if current is None or generation >= current[0]:
                self._pending[name] = (generation, payload)
            delay = min(self._backoff.get(name, self._min_backoff) * 2, self._max_backoff)
            self._backoff[name] = delay
            self._next_attempt[name] = time.monotonic() + delay
            self._inflight.discard(name)

    def _run(self):
        while not self._stop.is_set():
            claimed = self._claim()
            if claimed is None:
                self._wake.wait(timeout=self._waited())
                self._wake.clear()
                continue
            name, generation, payload = claimed
            try:
                self._write(self._paths[name], payload)
            except OSError as exc:
                with self._lock:
                    self._errors[name] = type(exc).__name__
                self._fail(name, generation, payload)
                continue
            with self._lock:
                self._errors.pop(name, None)
            self._ack(name, generation, True)

    def close(self, timeout=None):
        self._stop.set()
        self._wake.set()
        if self._thread.is_alive():
            self._thread.join(self._join_timeout if timeout is None else timeout)
