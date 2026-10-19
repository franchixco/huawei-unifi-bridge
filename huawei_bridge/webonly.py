#!/usr/bin/env python3
"""Read-only WEB-ONLY provider: an extra virtual AP with no TR-069 behind it.

Consumes the webcol ``/webonly`` records (a CPE reachable only through its
authenticated web API) and emits canonical AP/client dicts into the existing
inventory -> virtual-AP pipeline. It never impersonates an ACS device, never
queues an ACS task, and is never controllable: its writes stay off even when its
management IP appears in ``HUAWEI_CONTROL_IP``.

Identity and slots are serial/native-id derived and persisted in a private
registry (mode 0600) *before* an AP may be published. A missing file is a clean
first boot; any other malformation fails the whole web-only source closed while
the healthy ACS APs keep working.
"""

import hashlib
import json
import math
import os
import re
import time
from collections import Counter
from typing import Any
from urllib.parse import urlsplit

from .collector import virtual_mac

SCHEMA_VERSION = 1
SOURCE_KIND = 'web-api-only'
DEFAULT_TTL = 600.0
MAX_TTL = 600.0
MAX_REGISTRY_BYTES = 1024 * 1024
MAX_SOURCES = 64
MAX_SLOTS = 512
MAX_SLOT = 4096
MAX_UPTIME = 10 * 365 * 24 * 3600
MAX_PROFILES = 64
MAX_CLIENTS = 256
MAX_NATIVE_ID = 256
KEY_PATTERN = re.compile(r'^[0-9a-f]{16}$')
MAC_PATTERN = re.compile(r'^[0-9a-f]{2}(:[0-9a-f]{2}){5}$')
MODEL_PATTERN = re.compile(r'^WS(?:7100|7200)(?:-[0-9A-Z]{1,8})?$')
SERIAL_PATTERN = re.compile(r'^[0-9A-Za-z]{4,64}$')
BAND_ORDER = {'2.4g': 0, '5g': 1}
STANDARD_ORDER = ('a', 'b', 'g', 'n', 'ac', 'ax', 'be')
PROFILE_FIELDS = ('band', 'ssid', 'enabled', 'standard', 'native_id', 'usage',
                  'endpoint_role', 'channel_configured', 'wmm', 'power')
STATS_FIELDS = ('cpu_percent', 'mem_percent')
_BAND_ALIASES = {'2.4g': '2.4g', '2.4ghz': '2.4g', '2g': '2.4g', '5g': '5g', '5ghz': '5g'}


class RegistryCapacity(ValueError):
    """A bounded registry limit would be exceeded; nothing is mutated."""


def _norm_band(value):
    return _BAND_ALIASES.get(str(value).strip().lower()) if value is not None else None


def _as_dict(value):
    return value if isinstance(value, dict) else {}


def _finite(value):
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    try:
        return value if math.isfinite(value) else None
    except OverflowError:
        return None


def _clamp_ttl(value):
    ttl = _finite(value)
    return DEFAULT_TTL if ttl is None or ttl <= 0 else min(ttl, MAX_TTL)


def _short(value, limit=24):
    text = ''.join(ch for ch in str(value) if ch.isprintable())
    return text[:limit]


def source_key(serial):
    return hashlib.sha256(('webonly:' + str(serial).strip().upper()).encode()).hexdigest()[:16]


def source_id(serial):
    return 'webonly-' + source_key(serial)


def canonical_origin(value):
    """Return a canonical ``scheme://host[:port]`` origin, or None if invalid."""
    if not isinstance(value, str) or not value or len(value) > 255:
        return None
    try:
        parsed = urlsplit(value.strip())
    except ValueError:
        return None
    if parsed.scheme not in ('http', 'https') or not parsed.hostname:
        return None
    if parsed.username is not None or parsed.password is not None or '@' in parsed.netloc:
        return None
    if parsed.query or parsed.fragment or parsed.path not in ('', '/'):
        return None
    try:
        port = parsed.port
    except ValueError:
        return None
    default = (parsed.scheme == 'http' and port == 80) or (parsed.scheme == 'https' and port == 443)
    host = parsed.hostname.lower()
    netloc = host if port is None or default else '%s:%d' % (host, port)
    return '%s://%s' % (parsed.scheme, netloc)


def pins_from_env(raw=None):
    """Independent pin authority for the bridge: ``origin=serial`` only.

    Passwords never reach the bridge and a bare or ambiguous serial is refused,
    so the bridge never trusts a producer-supplied pin flag.
    """
    raw = os.environ.get('WEB_ONLY_SERIALS', '') if raw is None else raw
    pins = {}
    for item in raw.split(','):
        item = item.strip()
        if not item:
            continue
        host, sep, serial = item.rpartition('=')
        serial = serial.strip()
        if not sep or not SERIAL_PATTERN.fullmatch(serial):
            continue
        origin = canonical_origin(host)
        if origin is not None:
            pins[origin] = serial
    return pins


def _valid_mac(mac):
    if not isinstance(mac, str) or not MAC_PATTERN.fullmatch(mac):
        return False
    first = int(mac[:2], 16)
    return first & 0x01 == 0 and first & 0x02 == 0x02  # unicast + locally administered


def _valid_source(key, entry):
    if not isinstance(key, str) or not KEY_PATTERN.fullmatch(key):
        return False
    if not isinstance(entry, dict):
        return False
    identifier, mac, serial_hash = entry.get('id'), entry.get('mac'), entry.get('serial_hash')
    if identifier != 'webonly-' + key or serial_hash != key:
        return False
    if not _valid_mac(mac) or mac != virtual_mac(identifier):
        return False
    slots = entry.get('slots', {})
    if not isinstance(slots, dict) or len(slots) > MAX_SLOTS:
        return False
    for native_id, slot in slots.items():
        if not isinstance(native_id, str) or not native_id or len(native_id) > MAX_NATIVE_ID:
            return False
        if not isinstance(slot, int) or isinstance(slot, bool) or not 0 <= slot <= MAX_SLOT:
            return False
    values = list(slots.values())
    if len(values) != len(set(values)):  # two native ids sharing a slot
        return False
    next_slot = entry.get('next_slot', 0)
    if not isinstance(next_slot, int) or isinstance(next_slot, bool):
        return False
    floor = (max(values) + 1) if values else 0
    return floor <= next_slot <= MAX_SLOT + 1


def _validate_registry(raw):
    if not isinstance(raw, dict) or raw.get('schema_version') != SCHEMA_VERSION:
        return False
    sources = raw.get('sources')
    if not isinstance(sources, dict) or len(sources) > MAX_SOURCES:
        return False
    ids, macs = set(), set()
    for key, entry in sources.items():
        if not _valid_source(key, entry):
            return False
        if entry['id'] in ids or entry['mac'] in macs:
            return False
        ids.add(entry['id'])
        macs.add(entry['mac'])
    return True


def sanitize_registry(raw):
    """Deep copy of a validated registry; an invalid one becomes empty."""
    clean: dict[str, Any] = {'schema_version': SCHEMA_VERSION, 'sources': {}}
    if not _validate_registry(raw):
        return clean
    for key, entry in raw.get('sources', {}).items():
        slots = {str(k): int(v) for k, v in (entry.get('slots') or {}).items()}
        next_slot = entry.get('next_slot')
        if not isinstance(next_slot, int) or isinstance(next_slot, bool):
            next_slot = max(slots.values()) + 1 if slots else 0
        clean['sources'][key] = {'id': entry['id'], 'mac': entry['mac'],
                                 'serial_hash': key, 'slots': slots, 'next_slot': next_slot}
    return clean


def load_registry(path):
    """Return ``(registry, ok)``. Only a missing file is a clean first boot."""
    try:
        with open(path, 'rb') as handle:
            raw = handle.read(MAX_REGISTRY_BYTES + 1)
    except FileNotFoundError:
        return sanitize_registry(None), True
    except OSError:
        return sanitize_registry(None), False
    if len(raw) > MAX_REGISTRY_BYTES:
        return sanitize_registry(None), False
    try:
        data = json.loads(raw)
    except (ValueError, UnicodeDecodeError, RecursionError):
        return sanitize_registry(None), False
    if not _validate_registry(data):
        return sanitize_registry(None), False
    return sanitize_registry(data), True


def save_registry(path, registry) -> bool:
    from .unifi import atomic_json
    try:
        atomic_json(path, sanitize_registry(registry))
        return True
    except OSError:
        return False


def ensure_source(registry, serial):
    """Return ``(source_id, virtual_mac, entry)`` for a serial, minting once."""
    key = source_key(serial)
    sources = registry.setdefault('sources', {})
    entry = sources.get(key)
    if not isinstance(entry, dict):
        if len(sources) >= MAX_SOURCES:
            raise RegistryCapacity('sources')
        identifier = 'webonly-' + key
        entry = {'id': identifier, 'mac': virtual_mac(identifier),
                 'serial_hash': key, 'slots': {}, 'next_slot': 0}
        sources[key] = entry
    return entry['id'], entry['mac'], entry


def _assign_slots(entry, native_ids):
    for native_id in native_ids:
        if not isinstance(native_id, str) or not native_id or len(native_id) > MAX_NATIVE_ID:
            raise RegistryCapacity('native-id')
    slots = entry.get('slots')
    if not isinstance(slots, dict):
        raise RegistryCapacity('slots-shape')
    next_slot = entry.get('next_slot')
    if not isinstance(next_slot, int) or isinstance(next_slot, bool) or next_slot < 0:
        next_slot = (max(slots.values()) + 1) if slots else 0
    pending = [n for n in dict.fromkeys(native_ids) if n not in slots]
    if len(slots) + len(pending) > MAX_SLOTS:
        raise RegistryCapacity('slots')
    used = set(slots.values())
    cursor = next_slot
    assigned = {}
    for native_id in pending:
        while cursor in used:
            cursor += 1
        if cursor > MAX_SLOT:
            raise RegistryCapacity('slot-range')
        assigned[native_id] = cursor
        used.add(cursor)
        cursor += 1
    for native_id in native_ids:
        if native_id not in assigned:
            assigned[native_id] = slots[native_id]
    slots.update({n: assigned[n] for n in pending})
    entry['next_slot'] = cursor
    return assigned


def _standard_letters(raw):
    if not isinstance(raw, str):
        return []
    text = raw.strip().lower().replace('802.11', '').replace('11', '')
    return [part for part in re.split(r'[^a-z0-9]+', text) if part in STANDARD_ORDER]


def _clean_profile(profile):
    return {key: profile[key] for key in PROFILE_FIELDS if key in profile}


def _profiles(record):
    inventory = _as_dict(record.get('inventory'))
    raw = [p for p in inventory.get('profiles', [])[:MAX_PROFILES] if isinstance(p, dict)]
    counts = Counter(p.get('native_id') for p in raw
                     if isinstance(p.get('native_id'), str) and p.get('native_id'))
    valid = [p for p in raw
             if isinstance(p.get('native_id'), str) and p.get('native_id')
             and counts[p['native_id']] == 1 and _norm_band(p.get('band')) is not None]
    valid.sort(key=lambda p: (BAND_ORDER.get(_norm_band(p.get('band')) or '', 99),
                              p['native_id']))
    return [_clean_profile(p) for p in valid]


def _associate(client, radios):
    by_native = {r['native_id']: r for r in radios}
    iface = client.get('interface_id')
    if isinstance(iface, str) and iface in by_native:
        return by_native[iface], 'native-interface'
    band = _norm_band(client.get('band_norm') or client.get('band'))
    candidates = [r for r in radios if r['band'] == band]
    wanted = 'guest' if client.get('guest') is True else 'primary'
    matches = [r for r in candidates if r['web_usage'] == wanted]
    return (matches[0], 'band-role') if len(matches) == 1 else (None, None)


def _stats(record, device, now):
    raw = _as_dict(record.get('stats'))
    stats_seen = _finite(record.get('stats_observed_at'))
    fresh = stats_seen is not None and 0 <= now - stats_seen <= _clamp_ttl(record.get('ttl_seconds'))

    def gauge(key):
        value = raw.get(key)
        if not fresh:
            return None
        value = _finite(value)
        return value if value is not None and 0 <= value <= 100 else None

    cpu, mem = gauge('cpu_percent'), gauge('mem_percent')
    uptime = device.get('uptime_seconds')
    uptime = (int(uptime) if isinstance(uptime, int) and not isinstance(uptime, bool)
              and 0 <= uptime <= MAX_UPTIME else None)
    reason = record.get('stats_reason') if isinstance(record.get('stats_reason'), str) else None
    if (cpu is None or mem is None) and reason is None:
        reason = 'unavailable_in_observed_sources'
    return {'cpu_percent': cpu, 'mem_percent': mem, 'uptime_seconds': uptime,
            'observed_at': stats_seen if (cpu is not None or mem is not None) else None,
            'source': 'huawei-web', 'unavailable_reason': reason}


def _build_ap(identifier, mac, entry, record, profiles, seen, fresh, now):
    assignments = _assign_slots(entry, [p['native_id'] for p in profiles])
    device = _as_dict(record.get('device'))
    model = device.get('model') or device.get('model_cust') or 'Huawei AX3'
    radios = []
    for profile in profiles:
        native_id = profile['native_id']
        role = profile.get('endpoint_role')
        if role not in ('primary', 'guest'):
            role = profile.get('usage') if profile.get('usage') in ('primary', 'guest') else 'unknown'
        standards = {letter for letter in _standard_letters(profile.get('standard'))}
        radios.append({
            'id': '%s:%s' % (identifier, native_id),
            'band': _norm_band(profile.get('band')),
            'ssid': profile.get('ssid') if isinstance(profile.get('ssid'), str) else '',
            'enabled': profile.get('enabled') is True,
            'standards': sorted(standards, key=STANDARD_ORDER.index),
            'bssid': None,
            'native_id': native_id,
            'web_usage': role,
            'slot': assignments[native_id],
            'stale': not fresh,
            'updated_at': seen if isinstance(seen, (int, float)) else None,
        })
    clients, unbound = [], 0
    for client in record.get('clients') or []:
        if not isinstance(client, dict):
            continue
        address = client.get('mac')
        if not isinstance(address, str) or not address:
            continue
        radio, method = _associate(client, radios)
        if radio is None:
            unbound += 1
        item: dict[str, Any] = {
            'mac': address, 'ap_id': identifier,
            'radio_id': radio['id'] if radio else None,
            'band': _norm_band(client.get('band_norm') or client.get('band')),
            'ssid': radio['ssid'] if radio else '',
            'association_confidence': 'weak',
            'association_source': 'web-hostinfo',
            'association_method': method or 'unbound',
            'authentication_state': None,
            'stale': not fresh, 'updated_at': seen if isinstance(seen, (int, float)) else None}
        for key in ('ip', 'hostname', 'phy_mode'):
            if isinstance(client.get(key), str):
                item[key] = client[key]
        if isinstance(client.get('phy_mode'), str):
            proto = client['phy_mode'].replace('802.11', '').strip().lower()
            if proto in STANDARD_ORDER:
                item['radio_proto'] = proto
        rssi = _finite(client.get('rssi_dbm'))
        if rssi is not None and -200 <= rssi <= 0:
            item['signal'] = rssi
        for key in ('tx_kb', 'rx_kb', 'negotiated_rate', 'up_rate', 'down_rate'):
            value = _finite(client.get(key))
            if value is not None:
                item[key] = value
        clients.append(item)
    emitted = sum(1 for c in clients if not c['stale'] and c['radio_id'] is not None)
    ap = {
        'id': identifier,
        'virtual_mac': mac,
        'name': '%s (web API)' % model,
        'model_display': 'Huawei %s (web API only)' % model,
        'hostname': 'Huawei-' + mac.replace(':', '')[-6:],
        'ip': record.get('router_ip'),
        'firmware': device.get('software_version'),
        'hardware': device.get('hardware_version'),
        'last_inform': None,
        'last_seen': seen,
        'source_kind': SOURCE_KIND,
        'web_only': True,
        'online': bool(fresh),
        'radios': radios,
        'wlan_counters': [],
        'client_count': emitted,
        'unbound_client_count': unbound,
        'device_stats': _stats(record, device, now),
        'device_truth': dict(device),
        'inventory': {
            'schema_version': 1, 'trusted': False, 'identity': 'web-api-only',
            'fresh': bool(fresh), 'observed_at': seen, 'source_kind': SOURCE_KIND,
            'slot_by_radio': {str(r['id']): r['slot'] for r in radios},
            'representative_channel': {},
        },
    }
    return ap, clients


def _acs_serial(ap):
    identity = str(ap.get('id') or '')
    parts = identity.split('-')
    return parts[-1].strip().upper() if len(parts) >= 3 and parts[-1].strip() else identity.upper()


def _record_admitted(record, pins):
    if record.get('source_type') != SOURCE_KIND or record.get('transport') != 'direct':
        return False
    serial = record.get('serial')
    if not isinstance(serial, str) or not SERIAL_PATTERN.fullmatch(serial):
        return False
    device = _as_dict(record.get('device'))
    model = device.get('model') or device.get('model_cust')
    if not isinstance(model, str) or not MODEL_PATTERN.fullmatch(model.strip().upper()):
        return False
    if _finite(record.get('observed_at')) is None:
        return False
    if not isinstance(pins, dict):
        return False
    origin = record.get('origin')
    expected = pins.get(origin) if isinstance(origin, str) else None
    return isinstance(expected, str) and serial.upper() == expected.upper()


def _capacity(registry, serial, profiles):
    source = registry.get('sources', {}).get(source_key(serial))
    existing = set(source['slots']) if isinstance(source, dict) and isinstance(source.get('slots'), dict) else set()
    needed = [n for n in dict.fromkeys(p['native_id'] for p in profiles) if n not in existing]
    if len(existing) + len(needed) > MAX_SLOTS:
        return 'slots'
    if not isinstance(source, dict) and len(registry.get('sources', {})) >= MAX_SOURCES:
        return 'sources'
    return None


def build(records, registry, acs_serials, now=None, pins=None):
    now = time.time() if now is None else now
    aps, clients, warnings = [], [], []
    if not isinstance(records, dict):
        return aps, clients, warnings
    for host, record in sorted(records.items()):
        if not isinstance(record, dict):
            continue
        if not _record_admitted(record, pins):
            warnings.append('web-only: record rechazado por admisión (origen/serial/prueba); %s'
                            % _short(host))
            continue
        serial = record['serial']
        profiles = _profiles(record)
        if not profiles:
            continue
        if serial.upper() in acs_serials:
            warnings.append('web-only: AP web suprimido por colisión de identidad con un CPE de ACS; '
                            'se requiere reconciliación manual (%s)' % _short(host))
            continue
        if _capacity(registry, serial, profiles) is not None:
            warnings.append('web-only: límite de registro alcanzado; sin cambios (%s)' % _short(host))
            continue
        seen = record.get('observed_at')
        ttl = _clamp_ttl(record.get('ttl_seconds'))
        fresh = isinstance(seen, (int, float)) and not isinstance(seen, bool) and 0 <= now - seen <= ttl
        try:
            identifier, mac, entry = ensure_source(registry, serial)
            ap, ap_clients = _build_ap(identifier, mac, entry, record, profiles, seen, fresh, now)
        except RegistryCapacity as exc:
            warnings.append('web-only: límite de registro alcanzado (%s); sin cambios' % exc)
            continue
        aps.append(ap)
        clients.extend(ap_clients)
    return aps, clients, warnings


def merge(result, records, registry, now=None, publish=True, pins=None):
    """Merge web-only APs into a normalized snapshot.

    Returns ``(result, registry, warnings)``. With ``publish=False`` the result is
    left untouched (used to compute the registry before durable persistence).
    """
    if registry is None or registry == {}:
        registry = sanitize_registry(None)
    elif not _validate_registry(registry):
        return result, registry, ['web-only: registro de identidad invalido; sin cambios ni remint']
    else:
        registry = sanitize_registry(registry)
    acs_serials = {(ap.get('serial') or _acs_serial(ap)).upper()
                   for ap in result.get('aps', []) if isinstance(ap, dict)}
    aps, clients, warnings = build(records, registry, acs_serials, now=now, pins=pins)
    if publish:
        result.setdefault('aps', []).extend(aps)
        result.setdefault('clients', []).extend(clients)
        result.setdefault('warnings', []).extend(warnings)
    return result, registry, warnings
