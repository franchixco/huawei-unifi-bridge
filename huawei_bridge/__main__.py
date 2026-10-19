import fcntl
import json
import logging
import os
import signal
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import quote, urlsplit

from . import inventory, metrics, webonly
from .collector import arbitrate, enrich, metric_capabilities, normalize
from .control import Control
from .unifi import UniFi
from .writer import JsonRegistryWriter

LOG = logging.getLogger('huawei-bridge')
STATIC = Path(__file__).parent / 'static'
MAX_BODY = 16 * 1024 * 1024
MAX_ENRICH_BODY = 1024 * 1024
MAX_WEB_ROUTERS = 32
WEBENRICH_MAX_AGE = 5.0
WEBENRICH_FAILURE_BACKOFF = 20.0
INVENTORY_FILE = ('inventory', 'vap_map_v2.json')
WEBONLY_FILE = ('inventory', 'webonly_v1.json')


class Application:
    def __init__(self):
        self.directory = Path(os.environ.get('STATE_DIR', '.state'))
        self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.lockfile = (self.directory / '.lock').open('a')
        fcntl.flock(self.lockfile, fcntl.LOCK_EX | fcntl.LOCK_NB)
        self.nbi = os.environ.get('GENIEACS_URL', 'http://127.0.0.1:7557').rstrip('/')
        self.webenrich = os.environ.get('WEBENRICH_URL', 'http://webcol:7560').rstrip('/')
        self.public_url = os.environ.get('PUBLIC_URL', 'http://127.0.0.1:8090').rstrip('/')
        self.allowed_hosts = {urlsplit(self.public_url).netloc, 'localhost:8090', '127.0.0.1:8090'}
        self.devices = []
        self.last_collection = None
        self.last_error = None
        self.last_refresh = 0
        self.web_snapshot = None
        self.web_fetched = 0.0
        self.web_inventory_data = None
        self.web_inventory_fetched = 0.0
        self.web_only_data = None
        self.web_only_fetched = 0.0
        self.web_backoff = {}
        self.registry = inventory.load_registry(self.directory.joinpath(*INVENTORY_FILE))
        self.registry_path = self.directory.joinpath(*INVENTORY_FILE)
        self.registry_pending = None
        self.web_registry_path = self.directory.joinpath(*WEBONLY_FILE)
        self.web_registry, self.web_registry_ok = webonly.load_registry(self.web_registry_path)
        self.web_registry_generation = 0
        self.web_registry_saved_generation = 0
        self.web_registry_pending = None
        self.web_pins = webonly.pins_from_env()
        self.registry_generation = 0
        self.registry_saved_generation = 0
        self.metrics = metrics.CounterTracker()
        self.counters = metrics.CounterStore(self.directory / 'metrics' / metrics.COUNTERS_FILENAME)
        self.mutex = threading.RLock()
        self.writer = JsonRegistryWriter(
            {'vap': self.registry_path, 'webonly': self.web_registry_path},
            on_saved=self._on_saved)
        self.control = Control(self.directory / 'control', self.request,
                               os.environ.get('HUAWEI_CONTROL_IP', ''))
        self.unifi = UniFi(self.directory / 'unifi', os.environ.get('UNIFI_INFORM_URL', ''),
                           json.loads(os.environ.get('UNIFI_WLAN_MAP') or '{}'),
                           self.control, self.device_lookup)
        self.http = urllib.request.build_opener(urllib.request.ProxyHandler({}))

    def device_lookup(self, identity):
        return next((d for d in self.devices if d.get('_id') == identity), {})

    def _known_source_hashes(self):
        return set((self.web_registry or {}).get('sources', {}) or {})

    def _quarantine_identity(self, result):
        known = self._known_source_hashes()
        if not known:
            return
        for ap in result.get('aps', []):
            serial = ap.get('serial')
            if isinstance(serial, str) and serial and webonly.source_key(serial) in known:
                ap['quarantined_identity'] = True
                ap['online'] = False
        quarantined = {ap['id'] for ap in result.get('aps', []) if ap.get('quarantined_identity')}
        if quarantined:
            result['clients'] = [c for c in result.get('clients', [])
                                 if c.get('ap_id') not in quarantined]
            result.setdefault('warnings', []).append(
                'Identidad ACS coincide con una fuente web conocida; AP en cuarentena '
                '(reconciliación manual, sin adopción automática)')

    def _on_saved(self, name, generation):
        with self.mutex:
            if name == 'vap' and generation > self.registry_saved_generation:
                self.registry_saved_generation = generation
            elif name == 'webonly' and generation > self.web_registry_saved_generation:
                self.web_registry_saved_generation = generation

    def close(self):
        self.writer.close()
        self.counters.close()
        self.lockfile.close()

    def request(self, path, data=None):
        req = urllib.request.Request(self.nbi + path, data=data,
                                     headers={'Content-Type': 'application/json'})
        with self.http.open(req, timeout=8) as response:
            raw = response.read(MAX_BODY + 1)
        if len(raw) > MAX_BODY:
            raise ValueError('ACS response too large')
        return json.loads(raw)

    def collect(self):
        devices = self.request('/devices')
        if not isinstance(devices, list):
            raise ValueError('Invalid ACS response')
        with self.mutex:
            self.devices = devices
            self.last_collection = time.time()
            self.last_error = None
        self.control.reconcile(devices)
        if time.time() - self.last_refresh >= 60:
            # Periodic telemetry reads are independent of explicit controller provisioning.
            tasks = self.request('/tasks')
            queued = {(task.get('device'), task.get('objectName')) for task in tasks}
            known = self._known_source_hashes()
            for device in normalize(devices)['aps']:
                identity = device['id']
                if device.get('web_only'):
                    continue  # Web-only APs have no NBI device and are never refreshed.
                serial = device.get('serial')
                if isinstance(serial, str) and serial and webonly.source_key(serial) in known:
                    continue  # Colliding ACS identity: quarantine, no refresh task.
                if (identity, 'InternetGatewayDevice.LANDevice') in queued:
                    continue
                self.request('/devices/' + quote(identity, safe='') + '/tasks',
                             json.dumps({'name': 'refreshObject', 'objectName': 'InternetGatewayDevice.LANDevice'}).encode())
            self.last_refresh = time.time()

    def _fetch_web(self, endpoint):
        # Throttled, bounded, fail-open: telemetry must never delay or break informs.
        now = time.monotonic()
        if endpoint == '/enrich':
            cached, fetched = self.web_snapshot, self.web_fetched
        elif endpoint == '/webonly':
            cached, fetched = self.web_only_data, self.web_only_fetched
        else:
            cached, fetched = self.web_inventory_data, self.web_inventory_fetched
        with self.mutex:
            if cached is not None and now - fetched < WEBENRICH_MAX_AGE:
                return cached
            if now < self.web_backoff.get(endpoint, 0):
                return cached
        try:
            with self.http.open(urllib.request.Request(self.webenrich + endpoint), timeout=2) as response:
                raw = response.read(MAX_ENRICH_BODY + 1)
            data = json.loads(raw) if len(raw) <= MAX_ENRICH_BODY else None
        except Exception:
            data = None
        with self.mutex:
            if data is not None:
                if endpoint == '/enrich':
                    self.web_snapshot, self.web_fetched = data, now
                elif endpoint == '/webonly':
                    self.web_only_data, self.web_only_fetched = data, now
                else:
                    self.web_inventory_data, self.web_inventory_fetched = data, now
                self.web_backoff.pop(endpoint, None)
            else:
                # A failing optional helper backs off instead of costing 2 s on
                # every snapshot (the worker calls this once per second).
                self.web_backoff[endpoint] = now + WEBENRICH_FAILURE_BACKOFF
            return cached if data is None else data

    def web_enrichment(self):
        return self._fetch_web('/enrich')

    def web_inventory(self):
        return self._fetch_web('/inventory')

    def web_only(self):
        return self._fetch_web('/webonly')

    def _record_counters(self, result):
        # Diagnostic only: observations never enter the device/VAP wire. This
        # path holds no lock across I/O; the CounterStore signals its own
        # background writer, so a snapshot or inform never blocks on disk.
        observations = []
        try:
            for ap in result.get('aps', []):
                for obs in ap.get('wlan_counters') or []:
                    entry = self.counters.observe(
                        (obs['cpe'], obs['interface'], obs['metric'], obs['source']),
                        obs['value'], obs.get('observed_at'), obs['unit'],
                        direction=obs.get('direction'), scope=obs.get('scope'),
                        verification=obs.get('verification'), source=obs.get('source'))
                    if entry is not None:
                        entry['group'] = obs.get('group')
                        entry['field_type'] = obs.get('field_type')
                        observations.append(entry)
        except Exception as exc:  # noqa: BLE001 - metric bookkeeping never breaks the snapshot
            result.setdefault('warnings', []).append(
                'Contadores no registrados: ' + type(exc).__name__)
        result['counter_observations'] = observations

    def snapshot(self):
        with self.mutex:
            devices = self.devices
            last_collection, last_error = self.last_collection, self.last_error
        result = normalize(devices)
        now = time.time()
        self._quarantine_identity(result)
        web = self.web_enrichment()
        if web is not None:
            enrich(result, inventory.filter_enrichment(result.get('aps', []), web, now=now))
        webonly_data = self.web_only()
        web_records = webonly_data.get('routers') if isinstance(webonly_data, dict) else None
        if web_records and not self.web_registry_ok:
            result.setdefault('warnings', []).append(
                'web-only: registro de identidad invalido; proveedor omitido (APs ACS intactos)')
        elif web_records:
            try:
                with self.mutex:
                    _, candidate, _ = webonly.merge(result, web_records, self.web_registry,
                                                    now=now, publish=False, pins=self.web_pins)
                    if candidate != self.web_registry:
                        if webonly._validate_registry(candidate):
                            self.web_registry = candidate
                            self.web_registry_generation += 1
                            self.writer.submit('webonly', candidate, self.web_registry_generation)
                        else:
                            result.setdefault('warnings', []).append(
                                'web-only: candidato de registro invalido descartado; sin cambios')
                    durable = self.web_registry_saved_generation >= self.web_registry_generation
                    registry_now = self.web_registry
                if durable:
                    result, _, _ = webonly.merge(result, web_records, registry_now, now=now,
                                                 pins=self.web_pins)
                else:
                    result.setdefault('warnings', []).append(
                        'web-only: identidad/slots aun no persistidos; se publicara tras guardar')
            except Exception as exc:
                result.setdefault('warnings', []).append(
                    'web-only no aplicado: ' + type(exc).__name__)
        online = any(ap.get('online') for ap in result.get('aps', []))
        if online:
            try:
                trusted_inventory = inventory.filter_inventory(
                    result.get('aps', []), self.web_inventory(), now=now)
                with self.mutex:
                    result, registry = inventory.apply(result, trusted_inventory,
                                                       self.registry, now=now)
                    if registry != self.registry:
                        self.registry = registry
                        self.registry_pending = registry
                        self.registry_generation += 1
                        self.writer.submit('vap', registry, self.registry_generation)
            except Exception as exc:
                result.setdefault('warnings', []).append(
                    'Inventario web no aplicado: ' + type(exc).__name__)
        arbitrate(result, now=now)
        for client in result.get('clients', []):
            self.metrics.annotate(client, time.time())
        self._record_counters(result)
        for ap in result.get('aps', []):
            ap['metric_capabilities'] = metric_capabilities(ap, now=now)
        counter_status = self.counters.status()
        result['metric_capabilities'] = {
            'schema_version': 1,
            'counter_state': {'path': 'metrics/' + metrics.COUNTERS_FILENAME,
                              'stale_after': self.counters.stale_after, **counter_status}}
        if not counter_status['persistence_enabled'] and counter_status['degraded_reason'] not in (
                None, 'no-path'):
            result['warnings'].append(
                'Estado de contadores degradado (memoria solamente): '
                + str(counter_status['degraded_reason']))
        result['identity_contract'] = {'trust': 'ip+serial',
                                       'radio_proto': 'reported-unverified',
                                       'counters': 'reported-raw',
                                       'inventory_schema': inventory.SCHEMA_VERSION}
        result.update(acs_last_collection=last_collection, acs_error=last_error,
                      unifi_enabled=bool(self.unifi.url), unifi=dict(self.unifi.status))
        if last_error:
            result['warnings'].append('No se pudo actualizar GenieACS: ' + last_error)
        unmapped = sorted({ssid for status in result['unifi'].values()
                           for ssid in status.get('unmapped_ssids', [])})
        if unmapped:
            result['warnings'].append('SSID sin vínculo WLAN en UniFi: ' + ', '.join(unmapped))
        control_errors = sorted({status['configuration']['error'] for status in result['unifi'].values()
                                 if isinstance(status.get('configuration'), dict) and status['configuration'].get('error')})
        if control_errors:
            result['warnings'].append('Provisión CPE con rechazos (telemetría no afectada): ' + '; '.join(control_errors))
        return result

    def worker(self):
        next_collect = 0
        while True:
            if time.monotonic() >= next_collect:
                try:
                    self.collect()
                except Exception as exc:
                    with self.mutex:
                        self.last_error = type(exc).__name__
                    LOG.warning('Fallo al consultar ACS: %s', type(exc).__name__)
                next_collect = time.monotonic() + 10
            self.unifi.tick(self.snapshot())
            time.sleep(1)


def handler(app):
    class Handler(BaseHTTPRequestHandler):
        def setup(self):
            super().setup()
            self.connection.settimeout(10)

        def log_message(self, format, *args):
            pass

        def allowed(self):
            origin = self.headers.get('Origin')
            return self.headers.get('Host') in app.allowed_hosts and (
                not origin or origin in {app.public_url, 'http://localhost:8090'})

        def send(self, status, data, content_type='application/json'):
            if not isinstance(data, bytes):
                data = json.dumps(data, allow_nan=False).encode()
            self.send_response(status)
            self.send_header('Content-Type', content_type)
            self.send_header('Content-Length', str(len(data)))
            self.send_header('Cache-Control', 'no-store')
            self.send_header('X-Content-Type-Options', 'nosniff')
            self.send_header('Referrer-Policy', 'no-referrer')
            self.send_header('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self'; object-src 'none'; frame-ancestors 'none'")
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self):
            if not self.allowed():
                return self.send(403, {'error': 'Origin or Host rejected'})
            path = urlsplit(self.path).path
            if path == '/api/snapshot':
                return self.send(200, app.snapshot())
            if path == '/api/inventory':
                snap = app.snapshot()
                inventory_view = snap.get('inventory') if isinstance(snap.get('inventory'), dict) else {}
                return self.send(200, {
                    'schema_version': inventory_view.get('schema_version'),
                    'updated_at': snap.get('updated_at'),
                    'identity_contract': snap.get('identity_contract'),
                    'warnings': inventory_view.get('warnings', []),
                    'routers': {ap['id']: {'virtual_mac': ap.get('virtual_mac'),
                                           'ip': ap.get('ip'), 'online': ap.get('online'),
                                           'inventory': ap.get('inventory'),
                                           'device_truth': ap.get('device_truth'),
                                           'device_stats': ap.get('device_stats'),
                                           'metric_capabilities': ap.get('metric_capabilities')}
                                for ap in snap.get('aps', [])}})
            if path == '/health':
                healthy = bool(app.last_collection) and time.time() - app.last_collection < 60 and not app.last_error
                unifi_errors = sum(1 for status in app.unifi.status.values() if status.get('phase') == 'error')
                return self.send(200 if healthy else 503,
                                 {'acs': bool(app.last_collection), 'error': app.last_error,
                                  'unifi_errors': unifi_errors})
            files = {'/': ('index.html', 'text/html'), '/app.js': ('app.js', 'text/javascript'),
                     '/style.css': ('style.css', 'text/css')}
            if path in files:
                filename, kind = files[path]
                return self.send(200, (STATIC / filename).read_bytes(), kind + '; charset=utf-8')
            return self.send(404, {'error': 'Not found'})
    return Handler


def main():
    logging.basicConfig(level=logging.INFO, format='%(asctime)s %(message)s')
    app = Application()
    # Runtime-only: the counter state is persisted by one bounded background
    # daemon. Construction stays side-effect free for offline callers/tests.
    app.counters.start_writer()
    thread = threading.Thread(target=app.worker, daemon=True)
    thread.start()
    server = ThreadingHTTPServer((os.environ.get('LISTEN_HOST', '127.0.0.1'), int(os.environ.get('PORT', '8090'))), handler(app))
    server.daemon_threads = True
    LOG.info('Huawei Bridge disponible en %s', app.public_url)

    def stop(signum, frame):
        raise KeyboardInterrupt

    try:
        signal.signal(signal.SIGTERM, stop)
    except (ValueError, OSError):
        pass
    # Bounded, best-effort shutdown: a pending persistence write may be dropped,
    # which is safe because a web-only AP is never published before its identity
    # is durable. Never call shutdown() from this thread (deadlock).
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        LOG.info('Deteniendo Huawei Bridge')
    finally:
        server.server_close()
        app.close()


if __name__ == '__main__':
    main()
