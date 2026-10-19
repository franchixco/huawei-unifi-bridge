"""Normalize Huawei TR-098 telemetry received by GenieACS."""

import hashlib
import ipaddress
import re
import time
from datetime import datetime
from typing import Any
from urllib.parse import urlsplit


def mac(value):
    if not isinstance(value, str):
        return None
    value = value.lower().replace('-', ':')
    if not re.fullmatch(r'(?:[0-9a-f]{2}:){5}[0-9a-f]{2}', value):
        return None
    raw = bytes.fromhex(value.replace(':', ''))
    return value if any(raw) and not raw[0] & 1 else None


def ip(value):
    try:
        return str(ipaddress.ip_address(value)) if value else None
    except (ValueError, TypeError):
        return None


def val(obj, name, default=None):
    field = obj.get(name, {}) if isinstance(obj, dict) else {}
    return field.get('_value', default) if isinstance(field, dict) else default


def rows(obj):
    if not isinstance(obj, dict):
        return []
    return sorted(((key, value) for key, value in obj.items() if key.isdigit() and isinstance(value, dict)),
                  key=lambda item: int(item[0]))


def timestamp(value):
    try:
        return datetime.fromisoformat(value.replace('Z', '+00:00')).timestamp()
    except (AttributeError, TypeError, ValueError):
        return None


def number(value):
    if isinstance(value, bool):
        return None
    try:
        result = float(value)
        return result if abs(result) < 1e16 else None
    except (TypeError, ValueError):
        return None


def signal(value):
    value = number(value)
    # Huawei reports either negative dBm or its positive magnitude; zero is unknown.
    return -abs(value) if value is not None and 1 <= abs(value) <= 127 else None


def virtual_mac(identity):
    data = bytearray(hashlib.sha256(('huawei-bridge:' + identity).encode()).digest()[:6])
    data[0] = (data[0] | 2) & 254
    return ':'.join(f'{part:02x}' for part in data)


# TR-098 WLANConfiguration cumulative counters. The two interfaces on this CPE
# report near-identical totals, so the scope is unverified and the values are
# kept as diagnostic observations only: they are never summed, deduplicated or
# exported as a device/VAP aggregate.
WLAN_COUNTER_FIELDS = (
    ('TotalBytesSent', 'total_bytes_sent', 'bytes', 'tx'),
    ('TotalBytesReceived', 'total_bytes_received', 'bytes', 'rx'),
    ('TotalPacketsSent', 'total_packets_sent', 'packets', 'tx'),
    ('TotalPacketsReceived', 'total_packets_received', 'packets', 'rx'),
)
WLAN_STATS_FIELDS = (
    ('ErrorsSent', 'errors_sent', 'packets', 'tx'),
    ('ErrorsReceived', 'errors_received', 'packets', 'rx'),
    ('DiscardsSent', 'discards_sent', 'packets', 'tx'),
    ('DiscardsReceived', 'discards_received', 'packets', 'rx'),
)
OBSERVED_COUNTER_METRICS = tuple(metric for _, metric, _, _ in WLAN_COUNTER_FIELDS + WLAN_STATS_FIELDS)
SHARED_OR_MIRRORED = 'shared_or_mirrored_unverified'
PER_INTERFACE = 'per_interface_unverified'
# Source-level metrics no observed endpoint provides: reported as absent from
# the observed sources, never as physically impossible on the device.
UNAVAILABLE_IN_OBSERVED_SOURCES = ('tx_retries', 'airtime', 'satisfaction')
CLIENT_TRAFFIC_UNUSABLE = 'client_per_station_traffic_unusable'


def _counter_leaf(field) -> dict[str, Any] | None:
    if not isinstance(field, dict):
        return None
    value = number(field.get('_value'))
    if value is None or value < 0 or value != int(value):
        return None
    declared = field.get('_type')
    return {'value': int(value), 'observed_at': timestamp(field.get('_timestamp')),
            'field_type': str(declared)[:48] if declared else None}


def _observation(cpe: str, path: str, metric: str, unit: str, direction: str,
                 leaf: dict[str, Any]) -> dict[str, Any]:
    return {'cpe': cpe, 'interface': path, 'metric': metric, 'value': leaf['value'],
            'unit': unit, 'direction': direction, 'scope': 'interface-unverified',
            'source': 'tr098-nbi', 'verification': 'unverified',
            'observed_at': leaf['observed_at'], 'field_type': leaf['field_type']}


def wlan_counter_observations(cpe: str, path: str, wlan) -> list[dict[str, Any]]:
    """Per-interface counter observations, each stamped by its own leaf time."""
    if not isinstance(wlan, dict):
        return []
    raw_stats: Any = wlan.get('Stats')
    stats: dict[str, Any] = raw_stats if isinstance(raw_stats, dict) else {}
    out = []
    for source, metric, unit, direction in WLAN_COUNTER_FIELDS:
        leaf = _counter_leaf(wlan.get(source))
        if leaf:
            out.append(_observation(cpe, path, metric, unit, direction, leaf))
    for source, metric, unit, direction in WLAN_STATS_FIELDS:
        leaf = _counter_leaf(stats.get(source))
        if leaf:
            out.append(_observation(cpe, path, metric, unit, direction, leaf))
    return out


def fingerprint_observations(observations: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Label each metric's interfaces as shared/mirrored or per-interface.

    Near-identical values across interfaces mean the totals cannot be trusted
    as independent per-interface scopes; the label is a diagnostic inference,
    never a claim that they are a guaranteed aggregate.
    """
    groups = {}
    for obs in observations:
        groups.setdefault((obs['metric'], obs['direction']), []).append(obs)
    for items in groups.values():
        if len({item['interface'] for item in items}) < 2:
            group = PER_INTERFACE
        else:
            high = max(item['value'] for item in items)
            group = (SHARED_OR_MIRRORED
                     if high - min(item['value'] for item in items) <= max(256, 0.01 * high)
                     else PER_INTERFACE)
        for item in items:
            item['group'] = group
    return observations


def metric_capabilities(ap: dict[str, Any], now=None) -> dict[str, Any]:
    """Per-AP table of proven, blocked and unavailable native metrics.

    Proven metrics carry their exact source and unit. Blocked counters name the
    reason they are withheld from the device/VAP wire (unverified shared scope),
    and metrics no observed endpoint provides are reported as absent from the
    observed sources, never as impossible on the hardware.
    """
    raw_stats: Any = ap.get('device_stats')
    stats: dict[str, Any] = raw_stats if isinstance(raw_stats, dict) else {}
    raw_inventory: Any = ap.get('inventory')
    inventory_view: dict[str, Any] = raw_inventory if isinstance(raw_inventory, dict) else {}
    available: dict[str, Any] = {}
    unavailable: dict[str, Any] = {}
    for metric, source, unit in (
            ('cpu_percent', 'api/system/processstatus[0].CpuUsage', 'percent'),
            ('mem_percent', 'api/system/processstatus[0].MemUsage', 'percent'),
            ('uptime_seconds', 'api/system/deviceinfo.UpTime', 'seconds')):
        value = stats.get(metric)
        if isinstance(value, (int, float)) and not isinstance(value, bool) and value >= 0:
            available[metric] = {'unit': unit, 'source': source, 'value': value}
        else:
            unavailable[metric] = {
                'unit': unit, 'source': source,
                'reason': stats.get('unavailable_reason') or 'unavailable_in_observed_sources'}
    blocked = {}
    for obs in ap.get('wlan_counters') or []:
        entry = blocked.setdefault(obs['metric'], {
            'reason': obs.get('group') or SHARED_OR_MIRRORED, 'scope': obs['scope'],
            'unit': obs['unit'], 'direction': obs['direction'],
            'provenance': 'TR-098 WLANConfiguration %.N.' + obs['metric'], 'interfaces': []})
        if obs['interface'] not in entry['interfaces']:
            entry['interfaces'].append(obs['interface'])
    observed = stats.get('observed_at') or inventory_view.get('observed_at')
    return {'schema_version': 1,
            'trust': inventory_view.get('identity'),
            'fresh': inventory_view.get('fresh'),
            'observed_at': observed,
            'age': (round(now - observed) if now is not None and isinstance(observed, (int, float))
                    else None),
            'available': available, 'unavailable': unavailable, 'blocked': blocked,
            'unavailable_in_observed_sources': list(UNAVAILABLE_IN_OBSERVED_SOURCES),
            'client_per_station_traffic': CLIENT_TRAFFIC_UNUSABLE,
            'sources': {'cpu_memory': 'api/system/processstatus',
                        'uptime': 'api/system/deviceinfo.UpTime',
                        'counters': 'tr098-nbi'}}


def normalize(devices, now=None) -> dict[str, Any]:
    now = now if now is not None else time.time()
    aps, clients = [], []
    for device in devices:
        root = device.get('InternetGatewayDevice', {})
        identity = device.get('_id')
        info = device.get('_deviceId', {})
        if not isinstance(root, dict) or not isinstance(identity, str):
            continue
        if 'huawei' not in str(info.get('_Manufacturer', '')).lower():
            continue
        last = timestamp(device.get('_lastInform'))
        hosts = {}
        for _, lan in rows(root.get('LANDevice')):
            for _, host in rows(lan.get('Hosts', {}).get('Host')):
                address = mac(val(host, 'MACAddress'))
                if address:
                    hosts[address] = {'hostname': str(val(host, 'HostName', ''))[:128],
                                      'ip': ip(val(host, 'IPAddress'))}
        radios, stations, counters = [], {}, []
        for lid, lan in rows(root.get('LANDevice')):
            for wid, wlan in rows(lan.get('WLANConfiguration')):
                path = f'InternetGatewayDevice.LANDevice.{lid}.WLANConfiguration.{wid}'
                counters.extend(wlan_counter_observations(identity, path, wlan))
                channel = number(val(wlan, 'Channel'))
                if channel is None or channel < 1 or channel > 196:
                    continue
                band = '2.4g' if channel <= 14 else '5g'
                radio: dict[str, Any] = {'id': path, 'ssid': str(val(wlan, 'SSID', ''))[:128],
                         'channel': int(channel), 'band': band, 'bssid': mac(val(wlan, 'BSSID')),
                         'enabled': val(wlan, 'Enable'),
                         'standards': [s for s in str(val(wlan, 'Standard', '')).split('/')
                                       if s in ('a', 'b', 'g', 'n', 'ac', 'ax', 'be')],
                         'updated_at': timestamp(wlan.get('Channel', {}).get('_timestamp'))}
                radio['stale'] = radio['updated_at'] is None or now - radio['updated_at'] > 180
                radios.append(radio)
                if radio['enabled'] is False:
                    continue
                for _, station in rows(wlan.get('AssociatedDevice')):
                    address = mac(val(station, 'AssociatedDeviceMACAddress'))
                    if not address:
                        continue
                    observed = timestamp(station.get('AssociatedDeviceMACAddress', {}).get('_timestamp'))
                    auth_value = val(station, 'AuthenticationState')
                    if isinstance(auth_value, bool):
                        auth_state = auth_value
                    elif isinstance(auth_value, int):
                        auth_state = bool(auth_value)
                    elif (isinstance(auth_value, str)
                          and auth_value.strip().lower() in ('true', 'false', '1', '0')):
                        auth_state = auth_value.strip().lower() in ('true', '1')
                    else:
                        auth_state = None
                    if auth_state is False:
                        continue
                    candidate = {'mac': address, 'ip': ip(val(station, 'AssociatedDeviceIPAddress')),
                                 'signal': signal(val(station, 'AssociatedDeviceRssi')),
                                 'band': band, 'radio_id': path, 'ssid': radio['ssid'],
                                 'ap_id': identity, 'updated_at': observed,
                                 'stale': observed is None or now - observed > 180,
                                 'association_confidence':
                                     'strong-authenticated' if auth_state is True else 'reported',
                                 'association_source': 'tr069-associated-device',
                                 'authentication_state': auth_state}
                    # Prefer the newest observation if stale rows remain after a roam.
                    previous = stations.get(address)
                    if previous is None or (observed or 0) > (previous['updated_at'] or 0):
                        stations[address] = candidate
        callback = val(root.get('ManagementServer'), 'ConnectionRequestURL', '')
        try:
            device_ip = ip(urlsplit(callback).hostname)
        except (TypeError, ValueError):
            device_ip = None
        native_serial = val(root.get('DeviceInfo'), 'SerialNumber')
        serial = native_serial.strip() if isinstance(native_serial, str) and native_serial.strip() else None
        if serial is None:
            parts = identity.rsplit('-', 1)
            serial = parts[-1] if len(parts) == 2 and parts[-1] else identity
        online = bool(last and 0 <= now - last < 180)
        ap = {'id': identity, 'serial': serial, 'virtual_mac': virtual_mac(identity),
              'name': info.get('_ProductClass', 'Huawei AP'), 'ip': device_ip,
              'firmware': val(root.get('DeviceInfo'), 'SoftwareVersion'),
              'hardware': val(root.get('DeviceInfo'), 'HardwareVersion'),
              'last_inform': last, 'online': online, 'radios': radios,
              'wlan_counters': fingerprint_observations(counters),
              'client_count': sum(not c['stale'] and online for c in stations.values())}
        aps.append(ap)
        for address, client in stations.items():
            host = hosts.get(address, {})
            client['hostname'] = host.get('hostname', '')
            client['ip'] = client['ip'] or host.get('ip')
            client['stale'] = client['stale'] or not online
            clients.append(client)
    return {'updated_at': now, 'aps': aps, 'clients': clients, 'warnings': []}


ENRICH_DEFAULT_TTL = 600


def enrich(snapshot, web, now=None) -> dict[str, Any]:
    now = time.time() if now is None else now
    if not isinstance(web, dict):
        return snapshot
    by_mac = web.get('by_mac')
    if not isinstance(by_mac, dict):
        return snapshot
    ttl = number(web.get('ttl_seconds'))
    ttl = ENRICH_DEFAULT_TTL if ttl is None else min(max(ttl, 30), 3600)
    ap_ip = {ap.get('id'): ap.get('ip') for ap in snapshot.get('aps', []) if isinstance(ap, dict)}
    ap_online = {ap.get('id') for ap in snapshot.get('aps', [])
                 if isinstance(ap, dict) and ap.get('online')}
    ap_serial = {}
    for ap in snapshot.get('aps', []):
        identity = str(ap.get('id') or '')
        parts = identity.split('-')
        ap_serial[ap.get('id')] = parts[-1] if len(parts) >= 3 else identity
    for client in snapshot.get('clients', []):
        if client.get('ap_id') not in ap_online:
            continue  # Web telemetry never revives a client whose CPE is offline.
        extra = by_mac.get((client.get('mac') or '').upper())
        if not isinstance(extra, dict):
            continue
        seen = number(extra.get('_ts'))
        if seen is None or seen < 0 or seen > now or now - seen > ttl:
            continue  # Expired or future-dated router evidence is never merged.
        router_ip = extra.get('router_ip')
        if not router_ip or router_ip != ap_ip.get(client.get('ap_id')):
            continue  # Missing or other-router origin: a MAC alone can roam or be reused.
        expected_serial = ap_serial.get(client.get('ap_id'))
        got_serial = extra.get('_serial') or extra.get('serial')
        if not expected_serial or not got_serial or str(got_serial).upper() != expected_serial.upper():
            continue  # Serial must match the CPE that owns this management IP.
        merged = []
        if extra.get('phy_mode'):
            client['phy_mode'] = str(extra['phy_mode'])
            merged.append('phy_mode')
            proto = str(extra['phy_mode']).replace('802.11', '').strip().lower()
            if proto in ('a', 'b', 'g', 'n', 'ac', 'ax', 'be'):
                client['radio_proto'] = proto
        rate = number(extra.get('rate_mbps'))
        if rate and rate > 0:
            # Huawei's negotiated rate has no reliable direction: keep the neutral
            # field and never fabricate directional tx_rate/rx_rate from it.
            client['rate_mbps'] = rate
            merged.append('rate_mbps')
        negotiated = number(extra.get('negotiated_rate'))
        if negotiated and negotiated > 0:
            client['negotiated_rate'] = negotiated
            merged.append('negotiated_rate')
        # Explicit directional rates only when the router itself reported them;
        # units stay as reported (unverified), never relabelled as Mbps.
        for key in ('up_rate', 'down_rate'):
            value = number(extra.get(key))
            if value is not None and value >= 0:
                client[key] = value
                merged.append(key)
        rssi = number(extra.get('rssi_dbm'))
        if rssi is not None and -90 <= rssi <= -20:
            client['signal'] = rssi
            merged.append('signal')
        for key in ('tx_kb', 'rx_kb'):
            value = number(extra.get(key))
            if value is not None and value >= 0:
                client[key] = value  # A zero reading is real data; absence stays absent.
                merged.append(key)
        if extra.get('tx_kb') == 0 and extra.get('rx_kb') == 0:
            # Two zero readings on a field the router also uses as a PHY rate
            # mean the per-station traffic counter is unusable, not that the
            # client is idle; the raw zeros are preserved without reinterpretation.
            client['traffic_capability'] = CLIENT_TRAFFIC_UNUSABLE
            merged.append('traffic_capability')
        if merged:
            client['provenance'] = {'source': extra.get('_source') or 'huawei-web',
                                    'router_ip': router_ip, 'observed_at': seen,
                                    'fields': merged, 'schema_version': 2}
    return snapshot


VAP_MAP_SCHEMA = 1
BAND_ORDER = {'2.4g': 0, '5g': 1}


def sanitize_vap_map(stored):
    if not isinstance(stored, dict):
        return {}
    result = {}
    for ap_id, state in stored.items():
        if not isinstance(ap_id, str) or not isinstance(state, dict):
            continue
        slots = state.get('slots')
        if not isinstance(slots, dict):
            continue
        clean = {}
        for slot, info in slots.items():
            if not str(slot).isdigit() or not isinstance(info, dict):
                continue
            clean[str(int(slot))] = {'band': info.get('band'), 'ssid': info.get('ssid')}
        if clean:
            result[ap_id] = {'schema_version': VAP_MAP_SCHEMA, 'slots': clean}
    return result


def assign_vap_slots(aps, stored):
    """Bind each TR-069 WLANConfiguration to a stable virtual VAP slot.

    Identity is the physical band plus the persisted (band, ssid) map, never
    the enumeration index: reorders, renames and restarts keep the same slots,
    so virtual BSSIDs and ath names never move. A band with multiple VAPs is
    only resolved by exact persisted entries; anything ambiguous keeps its
    previous slots and exports nothing new. Returns (updated_map, warnings).
    """
    stored = sanitize_vap_map(stored)
    warnings = []
    for ap in aps:
        ap_id = ap.get('id')
        if not isinstance(ap_id, str):
            continue
        slots = dict(stored.get(ap_id, {}).get('slots', {}))
        bands = {}
        for radio in ap.get('radios', []):
            bands.setdefault(radio.get('band'), []).append(radio)
        used = set()

        def free_slot():
            slot = 0
            while str(slot) in slots or slot in used:
                slot += 1
            return slot

        for band in sorted(bands, key=lambda item: (BAND_ORDER.get(item, 99), str(item))):
            group = bands[band]
            if len(group) > 1:
                matched = []
                for radio in group:
                    candidates = [slot for slot, info in slots.items()
                                  if info.get('band') == band and info.get('ssid') == radio.get('ssid')
                                  and int(slot) not in used]
                    if len(candidates) == 1:
                        matched.append((radio, candidates[0]))
                if len(matched) != len(group):
                    for radio in group:
                        radio['slot'] = None
                    warnings.append(f'{ap_id}: banda {band} tiene {len(group)} perfiles sin '
                                    'mapeo inequívoco; slots previos conservados, sin reasignación')
                    continue
                for radio, slot in matched:
                    radio['slot'] = int(slot)
                    used.add(int(slot))
                    slots[slot] = {'band': band, 'ssid': radio.get('ssid')}
            else:
                radio = group[0]
                existing = [slot for slot, info in slots.items() if info.get('band') == band]
                slot = int(existing[0]) if len(existing) == 1 else free_slot()
                radio['slot'] = slot
                used.add(slot)
                slots[str(slot)] = {'band': band, 'ssid': radio.get('ssid')}
        ap['vap_slots'] = {radio['id']: radio['slot'] for radio in ap.get('radios', [])
                           if radio.get('slot') is not None}
        stored[ap_id] = {'schema_version': VAP_MAP_SCHEMA, 'slots': slots}
    return stored, warnings


ARBITRATION_TIERS = {'strong-authenticated': 3, 'reported': 2, 'weak': 1}


def _mac_hash(value):
    return hashlib.sha256(str(value).encode()).hexdigest()[:12]


def arbitrate(result, now=None):
    """Pick one source per client MAC before the UniFi wire.

    Fresh candidates are grouped by MAC and the strongest evidence tier wins.
    A tie inside the winning tier is ambiguous and suppresses every candidate
    for that MAC, never resolved by poll timestamp, so a duplicate or roaming
    client cannot flap between ACS CPEs and a web-only AP. Stale candidates are
    excluded because age describes the source, not a roam decision.
    """
    reported = {}
    for ap in result.get('aps', []):
        count = ap.get('client_count')
        if isinstance(count, int) and not isinstance(count, bool):
            reported[ap.get('id')] = count
    groups, stale = {}, []
    for client in result.get('clients') or []:
        if not isinstance(client, dict):
            continue
        if client.get('stale'):
            stale.append(client)
            continue
        groups.setdefault(client.get('mac'), []).append(client)
    winners, warnings = [], []
    for address, candidates in groups.items():
        strongest = max(ARBITRATION_TIERS.get(c.get('association_confidence'), 0)
                        for c in candidates)
        top = [c for c in candidates
               if ARBITRATION_TIERS.get(c.get('association_confidence'), 0) == strongest]
        if len(top) == 1:
            winners.append(top[0])
        else:
            warnings.append('Cliente con asociación ambigua suprimido del wire (%s)'
                            % _mac_hash(address))
    result['clients'] = winners + stale
    publishable = {}
    for client in winners:
        if client.get('radio_id') is not None:
            publishable[client.get('ap_id')] = publishable.get(client.get('ap_id'), 0) + 1
    for ap in result.get('aps', []):
        identifier = ap.get('id')
        if identifier in reported:
            ap['reported_client_count'] = reported[identifier]
            ap['client_count'] = publishable.get(identifier, 0)
    result.setdefault('warnings', []).extend(warnings)
    return result
