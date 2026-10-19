"""Experimental AP reporting and allowlisted optional provisioning."""

import ipaddress
import json
import math
import os
import re
import socket
import tempfile
import time
import urllib.request
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from .protocol import BOOTSTRAP_KEY, MAX_PAYLOAD, ProtocolError, decode, encode

MODEL = 'U7PRO'
VERSION = '8.7.11.19419'

# Controller WLAN identifiers: legacy 24-character hex _id or RFC 4122 UUID.
WLAN_ID_PATTERN = re.compile(
    r'(?:[0-9a-f]{24}|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})')


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


AUTH_STATE_MAX_BYTES = 1024 * 1024


def read_auth_state(path):
    """Bounded read of a CPE auth/session state file.

    A missing file is a fresh factory state. An over-large or malformed file
    fails closed for that one AP (the caller reports the error) and the original
    file is never rewritten or deleted.
    """
    try:
        raw = path.read_bytes() if path.exists() else None
    except OSError as exc:
        raise ValueError('Unreadable controller state') from exc
    if raw is None:
        return {'phase': 'factory'}
    if len(raw) > AUTH_STATE_MAX_BYTES:
        raise ValueError('Controller state too large')
    try:
        state = json.loads(raw)
    except (ValueError, UnicodeDecodeError, RecursionError) as exc:
        raise ValueError('Malformed controller state') from exc
    if not isinstance(state, dict):
        raise ValueError('Malformed controller state')
    return state


def atomic_json(path, data):
    path = Path(path)
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(dir=path.parent, prefix='.tmp-')
    try:
        with os.fdopen(fd, 'w') as handle:
            json.dump(data, handle, allow_nan=False)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(name, path)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def inform_url(url):
    parsed = urlsplit(url)
    if parsed.scheme not in ('http', 'https') or not parsed.hostname or parsed.username or parsed.password:
        raise ValueError('Invalid inform URL')
    if parsed.path != '/inform' or parsed.query or parsed.fragment:
        raise ValueError('Expected /inform URL without query or fragment')
    address = socket.gethostbyname(parsed.hostname)
    ipaddress.IPv4Address(address)
    return urlunsplit((parsed.scheme, address + (f':{parsed.port}' if parsed.port else ''), '/inform', '', ''))


def validate_wlan_map(mapping):
    if not isinstance(mapping, dict) or any(
        not isinstance(ssid, str) or not ssid or len(ssid.encode('utf-8')) > 32
        or not isinstance(wlan_id, str) or not WLAN_ID_PATTERN.fullmatch(wlan_id.strip().lower())
        for ssid, wlan_id in mapping.items()
    ):
        raise ValueError(
            'UNIFI_WLAN_MAP must map SSIDs to 24-character lowercase WLAN IDs or lowercase UUIDs')
    # UUIDs are case-insensitive; normalize so controller lookups never fail on case.
    return {ssid: wlan_id.strip().lower() for ssid, wlan_id in mapping.items()}


def _is_number(value):
    return (isinstance(value, (int, float)) and not isinstance(value, bool)
            and math.isfinite(value))


def _percent_text(value):
    return str(int(value)) if float(value).is_integer() else str(float(value))


def payload(ap: dict[str, Any], snapshot: dict[str, Any], state: dict[str, Any],
            url, _session_uptime, wlan_map=None) -> dict[str, Any]:
    vm = ap['virtual_mac']
    body: dict[str, Any] = {'model': MODEL,
            'model_display': ap.get('model_display') or 'Huawei BE3 bridge (virtual U7 Pro)',
            'version': VERSION, 'required_version': '8.0.28',
            'mac': vm, 'serial': vm.replace(':', '').upper(),
            'hostname': ap.get('hostname') or 'Huawei-' + vm.replace(':', '')[-6:],
            'ip': ap['ip'] or '0.0.0.0', 'inform_url': url,
            'default': not state.get('authkey'), 'state': 2 if state.get('authkey') else 0,
            'cfgversion': state.get('cfgversion', ''), 'time': int(time.time()),
            'discovery_response': False, 'isolated': False, 'locating': False,
            'radio_table': [], 'radio_table_stats': [], 'vap_table': []}
    # CPU/memory/uptime are emitted only from trusted, fresh hardware evidence.
    # The bridge's own session uptime is never published as device uptime: with
    # no hardware source the wire fields are simply absent.
    device_stats = ap.get('device_stats') if isinstance(ap.get('device_stats'), dict) else None
    system_stats: dict[str, str] = {}
    uptime_seconds = None
    if device_stats:
        cpu, mem = device_stats.get('cpu_percent'), device_stats.get('mem_percent')
        if _is_number(cpu) and cpu >= 0:
            system_stats['cpu'] = _percent_text(cpu)
        if _is_number(mem) and mem >= 0:
            system_stats['mem'] = _percent_text(mem)
        raw_uptime = device_stats.get('uptime_seconds')
        if _is_number(raw_uptime) and raw_uptime >= 0:
            uptime_seconds = int(raw_uptime)
    if uptime_seconds is not None:
        body['uptime'] = uptime_seconds
        system_stats['uptime'] = str(uptime_seconds)
    if system_stats:
        body['system-stats'] = system_stats
    raw_inventory = ap.get('inventory')
    inventory: dict[str, Any] = raw_inventory if isinstance(raw_inventory, dict) else {}
    slot_by_radio = inventory.get('slot_by_radio') or {}
    representative = inventory.get('representative_channel') or {}
    ordered = sorted(enumerate(ap['radios']),
                     key=lambda item: (0 if item[1]['band'] == '2.4g' else 1, str(item[1]['id'])))
    bands: dict[str, dict[str, Any]] = {}
    for index, radio in ordered:
        if radio.get('enabled') is False or radio.get('stale'):
            continue
        band = radio['band']
        name = 'wifi0' if band == '2.4g' else 'wifi1'
        kind = 'ng' if band == '2.4g' else 'na'
        slot = slot_by_radio.get(str(radio['id']))
        slot = radio.get('slot') if slot is None else slot
        slot = index if slot is None else slot
        if name not in bands:
            channel = representative.get(band)
            if not channel:
                observed = [r['channel'] for r in ap['radios']
                            if r['band'] == band and r.get('enabled') is not False
                            and not r.get('stale') and r.get('channel')]
                channel = min(observed) if observed else None
            standards = radio.get('standards', [])
            entry = {'name': name, 'radio': kind,
                     'is_11ac': 'ac' in standards, 'is_11ax': 'ax' in standards,
                     'is_11be': 'be' in standards,
                     'has_ht160': str(ap.get('name', '')).startswith('WUKUN-BE32') and band == '5g'}
            if channel:
                entry['channel'] = channel
            if radio.get('native_id'):
                entry['native_id'] = radio['native_id']
            bands[name] = entry
        wlan_id = (wlan_map or {}).get(radio['ssid'])
        if not wlan_id:
            continue
        station_channel = radio.get('effective_channel') or radio.get('channel') or representative.get(band)
        stations: list[dict[str, Any]] = []
        for client in snapshot['clients']:
            if client['ap_id'] != ap['id'] or client['radio_id'] != radio['id'] or client['stale']:
                continue
            station = {'mac': client['mac'], 'radio': kind, 'essid': radio['ssid'],
                       'bssid': virtual_bssid(vm, slot)}
            if station_channel:
                station['channel'] = station_channel
            for src, dst in [('ip', 'ip'), ('hostname', 'hostname'), ('signal', 'signal'),
                             ('tx_rate', 'tx_rate'), ('radio_proto', 'radio_proto')]:
                if client.get(src) is not None:
                    station[dst] = client[src]
            stations.append(station)
        vap: dict[str, Any] = {'id': wlan_id, 'name': f'ath{slot}', 'radio': kind,
               'bssid': virtual_bssid(vm, slot), 'essid': radio['ssid'],
               'up': True, 'state': 'RUN', 'usage': 'user',
               'num_sta': len(stations), 'sta_table': stations}
        if station_channel:
            vap['channel'] = station_channel
        if radio.get('native_id'):
            vap['native_id'] = radio['native_id']
        body['vap_table'].append(vap)
    body['radio_table'] = list(bands.values())
    body['radio_table_stats'] = [{'name': r['name'], 'radio': r['radio'],
                                  'state': 'RUN', **({'channel': r['channel']} if r.get('channel') else {})}
                                 for r in bands.values()]
    return body


def virtual_bssid(address, index):
    raw = bytearray.fromhex(address.replace(':', ''))
    raw[-1] = (raw[-1] + index + 1) % 256
    return ':'.join(f'{part:02x}' for part in raw)


def apply_response(state, response):
    kind = response.get('_type')
    if kind == 'setparam':
        mgmt = response.get('mgmt_cfg', '')
        if not isinstance(mgmt, str):
            raise ProtocolError('Invalid management metadata')
        values = dict(line.split('=', 1) for line in mgmt.splitlines() if '=' in line)
        key = values.get('authkey')
        if key is not None:
            try:
                if len(key) != 32 or len(bytes.fromhex(key)) != 16 or bytes.fromhex(key) == BOOTSTRAP_KEY:
                    raise ValueError
            except ValueError:
                raise ProtocolError('Invalid private key') from None
        mode = values.get('use_aes_gcm')
        if mode not in (None, 'true', 'false', '1', '0'):
            raise ProtocolError('Invalid encryption mode')
        cfg = response.get('cfgversion', values.get('cfgversion', state.get('cfgversion', '')))
        if not isinstance(cfg, str) or len(cfg) > 256:
            raise ProtocolError('Invalid configuration version')
        if key:
            state['authkey'] = key
            state['phase'] = 'key-received'
        state['cfgversion'] = cfg
        if mode is not None:
            state['encryption'] = 'gcm' if mode in ('true', '1') else 'cbc'
    elif kind == 'noop' and state.get('authkey'):
        state['phase'] = 'exchanging'
    elif kind == 'setdefault' and state.get('authkey'):
        state.update(authkey=None, phase='factory', cfgversion='', encryption='cbc')
    # Raw system_cfg is handled separately by the allowlisted translator; commands are ignored.
    delay = response.get('interval', 10)
    return min(60, max(1, delay)) if isinstance(delay, (int, float)) and not isinstance(delay, bool) else 10


class UniFi:
    def __init__(self, directory, url='', wlan_map=None, control=None, device_lookup=None):
        self.directory = Path(directory)
        self.url = url
        self.wlan_map = validate_wlan_map(wlan_map if wlan_map is not None else {})
        self.control, self.device_lookup = control, device_lookup
        self.status = {}
        self.started = time.monotonic()
        self.next_send = {}
        self.http = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())

    def exchange(self, ap, snapshot):
        identity = ap['virtual_mac']
        path = self.directory / (identity.replace(':', '') + '.json')
        state: dict[str, Any] = read_auth_state(path)
        if state.get('controller_url', self.url) != self.url:
            raise ValueError('State belongs to another controller')
        state['controller_url'] = self.url
        state['virtual_mac'] = identity
        mapping = self.wlan_map
        # Membership in the allowlist set; never a bare attribute compare. A
        # web-only AP is never controllable: no CWMP/TR-069 path exists for it,
        # even if its management IP is present in HUAWEI_CONTROL_IP.
        controlled = bool(self.control and not ap.get('web_only')
                          and ap.get('ip') in getattr(self.control, 'allowed_ips', set()))
        if self.control and not ap.get('web_only'):
            mapping = self.control.mapping(ap, mapping)
            # The wire version always echoes what the controller last announced
            # (persisted below): an empty one asks for the provision baseline.
            # Pushing a CPE ack here instead would override that echo with a
            # stale revision and keep the UCG provisioning (state=5) forever.
            # The ack stays internal bookkeeping for the CPE write path.
        key = bytes.fromhex(state['authkey']) if state.get('authkey') else BOOTSTRAP_KEY
        mode = state.get('encryption', 'cbc')
        session_uptime = time.monotonic() - self.started
        data = payload(ap, snapshot, state, inform_url(self.url), session_uptime, mapping)
        packet = encode(data, identity, key, mode=mode)
        request = urllib.request.Request(self.url, packet, headers={'Content-Type': 'application/x-binary',
                                          'User-Agent': 'AirControl Agent v1.0', 'Accept-Encoding': 'identity'})
        with self.http.open(request, timeout=8) as response:
            raw = response.read(MAX_PAYLOAD + 41)
        decoded = decode(raw, key)
        if decoded.mac != identity or (mode == 'gcm' and decoded.mode != 'gcm'):
            raise ProtocolError('Response identity or encryption mismatch')
        previous_cfg = state.get('cfgversion', '')
        delay = apply_response(state, decoded.body)
        if controlled and self.control is not None and decoded.body.get('_type') == 'setdefault':
            self.control.reset(ap)
        if (controlled and self.control is not None and self.device_lookup is not None
                and decoded.body.get('_type') == 'setparam' and 'system_cfg' in decoded.body):
            provision_cfg = decoded.body.get('cfgversion')
            try:
                self.control.receive(ap, decoded.body, self.device_lookup(ap['id']), mapping)
            except ValueError as exc:
                self.control.reject(ap, exc)
            # Reporting always echoes the controller's newest revision, whether
            # or not the CPE write path produced an ack: a stale CPE ack echoed
            # back would keep the UCG provisioning (state=5) forever. This is a
            # provisioning echo, never presented as a Huawei-confirmed value.
            state['cfgversion'] = str(provision_cfg) if isinstance(provision_cfg, str) and provision_cfg else str(
                self.control.ack(ap) or previous_cfg or '')
        state['last_success'] = time.time()
        atomic_json(path, state)
        plan_summary, confirmed_version = None, None
        if self.control is not None:
            record_fn: Any = getattr(self.control, 'record', None)
            if callable(record_fn):
                try:
                    record = record_fn(ap)
                    if isinstance(record, dict):
                        confirmed_version = record.get('confirmed_version')
                except ValueError:
                    confirmed_version = None
            plan_fn: Any = getattr(self.control, 'plan', None)
            if ap.get('web_only') and 'system_cfg' in decoded.body:
                plan_summary = {'ok': False, 'reason': 'cwmp-unsupported-web-source',
                                'no_op': False, 'fields': [], 'unsupported': ['cwmp'],
                                'writes_enabled': False}
            elif ('system_cfg' in decoded.body and not ap.get('web_only')
                  and self.device_lookup is not None and callable(plan_fn)):
                try:
                    plan = plan_fn(ap, decoded.body, self.device_lookup(ap['id']), mapping)
                    if not isinstance(plan, dict):
                        raise ValueError('Invalid provisioning plan result')
                    plan_summary = {'ok': plan.get('ok'),
                                    'reason': plan.get('error') or plan.get('blocked_reason'),
                                    'no_op': bool(plan.get('ok')) and not plan.get('changes'),
                                    'fields': sorted(plan.get('targets', {})) if plan.get('ok') else [],
                                    'unsupported': plan.get('unsupported', []),
                                    'writes_enabled': plan.get('writes_enabled')}
                except Exception as exc:
                    plan_summary = {'ok': False, 'reason': type(exc).__name__,
                                    'fields': [], 'unsupported': []}
        self.status[identity] = {'phase': state['phase'], 'last_success': state['last_success'],
                                  'model': MODEL, 'experimental': True,
                                  # Bridge-local diagnostic only: never the wire uptime.
                                  'virtual_session_uptime': int(session_uptime),
                                  'device_stats': dict(ap['device_stats'])
                                  if isinstance(ap.get('device_stats'), dict) else None,
                                  'stations_sent': sum(len(v['sta_table']) for v in data['vap_table']),
                                  'cfgversion_echo': state['cfgversion'],
                                  'confirmed_version': confirmed_version,
                                  'plan': plan_summary,
                                  'unmapped_ssids': sorted({r['ssid'] for r in ap['radios']
                                      if r.get('enabled') is not False and not r.get('stale')
                                      and r['ssid'] not in mapping})}
        if self.control:
            self.status[identity]['configuration'] = self.control.public(ap)
        self.next_send[identity] = time.monotonic() + delay

    def tick(self, snapshot):
        if not self.url:
            return
        for ap in snapshot['aps']:
            if not ap['online'] or time.monotonic() < self.next_send.get(ap['virtual_mac'], 0):
                continue
            try:
                self.exchange(ap, snapshot)
            except Exception as exc:
                # HTTP/library messages may contain credentials or response bodies.
                self.status[ap['virtual_mac']] = {'phase': 'error', 'error': type(exc).__name__,
                    'http_status': getattr(exc, 'code', None), 'experimental': True}
                self.next_send[ap['virtual_mac']] = time.monotonic() + 30
