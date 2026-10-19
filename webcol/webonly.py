#!/usr/bin/env python3
"""Read-only WEB-ONLY collection for a CPE without usable TR-069 (Huawei AX3).

Collected with the same bounded direct client as every other web source and
normalized with the shared huawei_api parsers, but kept in its own store and its
own endpoint: a web-only CPE is never an ACS device, gets no synthetic
lastInform, no CWMP identity and no journal entry. A record is published only
when the fresh deviceinfo serial matches the pinned allowlist entry for that
host; without a pin nothing is published (fail closed).
"""

import importlib
import ipaddress
import logging
import os
import re
import sys
from pathlib import Path
from urllib.parse import urlsplit

_SELF = str(Path(__file__).resolve().parent)
if _SELF not in sys.path:
    sys.path.insert(0, _SELF)
huawei_api = importlib.import_module('huawei_api')

LOG = logging.getLogger('webcol.webonly')

SCHEMA_VERSION = 1
SOURCE_TYPE = 'web-api-only'
MAX_CLIENTS = 256
MAX_PROFILES = 64
MODEL_PATTERN = re.compile(r'^WS(?:7100|7200)(?:-[0-9A-Z]{1,8})?$')
_CLIENT_FIELDS = ('mac', 'ip', 'hostname', 'band', 'band_norm', 'interface_id', 'guest',
                  'phy_mode', 'rssi_dbm', 'negotiated_rate', 'up_rate', 'down_rate',
                  'tx_kb', 'rx_kb')
_DEVICE_FIELDS = ('software_version', 'model', 'model_cust', 'hardware_version',
                  'uptime_seconds')
_PROFILE_FIELDS = ('band', 'ssid', 'native_id', 'standard', 'enabled', 'channel_configured',
                   'usage', 'endpoint_role', 'wmm', 'power')
_STATS_FIELDS = ('cpu_percent', 'mem_percent')


def _clean_profile(profile):
    return {key: profile.get(key) for key in _PROFILE_FIELDS if profile.get(key) is not None}


def _clean_stats(stats):
    raw = _as_dict(stats)
    clean = {}
    for key in _STATS_FIELDS:
        value = raw.get(key)
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            clean[key] = value
    return clean



def _invalid(message):
    # Never echo a credential-bearing URL; only a fixed code is logged.
    LOG.warning('%s', message)


def _literal_private(host):
    """A web-only source must be a literal private/loopback IP, never a name."""
    try:
        address = ipaddress.ip_address(urlsplit(host).hostname or '')
    except ValueError:
        return False
    return address.is_private or address.is_loopback or address.is_link_local


def _canonical_origin(value):
    try:
        canonical = huawei_api.validate_base_url(value)
    except ValueError:
        return None
    return canonical if _literal_private(canonical) else None


def webonly_routers(config=None):
    raw = os.environ.get('WEB_ONLY_ROUTERS', '') if config is None else config
    result = []
    for item in raw.split(','):
        item = item.strip()
        if not item:
            continue
        host, sep, password = item.rpartition('=')
        if not sep or not password:
            _invalid('WEB_ONLY_ROUTERS: entrada invalida ignorada')
            continue
        canonical = _canonical_origin(host.strip())
        if canonical is None:
            _invalid('WEB_ONLY_ROUTERS: URL no es IP privada literal valida ignorada')
            continue
        result.append((canonical, password))
    return result


def pinned_serials(config=None):
    """Pinned serial allowlist: ``origin=serial`` per host (no bare serial)."""
    raw = os.environ.get('WEB_ONLY_SERIALS', '') if config is None else config
    by_host = {}
    for item in raw.split(','):
        item = item.strip()
        if not item:
            continue
        host, sep, serial = item.rpartition('=')
        serial = serial.strip()
        if not sep or not serial:
            _invalid('WEB_ONLY_SERIALS: entrada sin origen ignorada')
            continue
        if not serial.isalnum():
            _invalid('WEB_ONLY_SERIALS: serial invalido ignorado')
            continue
        canonical = _canonical_origin(host.strip())
        if canonical is None:
            _invalid('WEB_ONLY_SERIALS: host no es IP privada literal valida ignorado')
            continue
        by_host[canonical] = serial
    return by_host, []


def expected_serial(host, serials=None, routers_config=None):
    """Resolve the pinned serial for a host, or None when absent/ambiguous.

    Pins are keyed by an explicit canonical origin, so a bare or shared serial is
    never honored and a missing pin fails closed.
    """
    by_host, _ = pinned_serials(serials)
    return by_host.get(host)


def router_ip(host):
    try:
        return str(ipaddress.ip_address(urlsplit(host).hostname))
    except (ValueError, TypeError):
        return None


def _as_dict(value):
    return value if isinstance(value, dict) else {}


def build_record(host, result, pin, now=None):
    """One publishable web-only record, or None when it must stay unpublished."""
    if not isinstance(result, dict) or not result.get('ok'):
        return None
    if result.get('transport') != 'direct':
        _invalid('WEB_ONLY: transporte no directo; no publicado')
        return None
    if (result.get('server_signature_verified') is not True
            or result.get('public_key_verified') is not True):
        _invalid('WEB_ONLY: sesion sin prueba criptografica; no publicado')
        return None
    device = _as_dict(result.get('device'))
    model = device.get('model') or device.get('model_cust')
    if not isinstance(model, str) or not MODEL_PATTERN.fullmatch(model.strip().upper()):
        _invalid('WEB_ONLY: modelo fuera de allowlist WS7100/WS7200; no publicado')
        return None
    serial = device.get('serial_number')
    if not isinstance(serial, str) or not serial:
        return None
    if not isinstance(pin, str) or not pin or serial.upper() != pin.upper():
        _invalid('WEB_ONLY: serial no coincide con el allowlist fijado')
        return None
    inventory = _as_dict(result.get('inventory'))
    raw_clients = result.get('clients')
    if not isinstance(raw_clients, list):
        return None
    profiles = [p for p in inventory.get('profiles', [])[:MAX_PROFILES] if isinstance(p, dict)]
    clients = []
    for client in raw_clients[:MAX_CLIENTS]:
        if not isinstance(client, dict):
            continue
        clients.append({key: client.get(key) for key in _CLIENT_FIELDS if client.get(key) is not None})
    return {
        'router_ip': router_ip(host),
        'origin': host,
        'serial': serial,
        'source_type': SOURCE_TYPE,
        'device': {key: device.get(key) for key in _DEVICE_FIELDS},
        'clients': clients,
        'inventory': {'profiles': [_clean_profile(p) for p in profiles]},
        'stats': _clean_stats(result.get('stats')),
        'stats_reason': result.get('stats_reason'),
        'stats_observed_at': result.get('stats_observed_at'),
        'transport': result.get('transport'),
        'observed_at': now,
        'fresh': True,
    }
