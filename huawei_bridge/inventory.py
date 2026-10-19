#!/usr/bin/env python3
"""Bridge-side crosswalk between TR-098 radios and the webcol inventory.

Pure, additive helpers consumed by __main__.snapshot(); they never write to a
CPE and never fabricate router state. Trust requires BOTH the management IP and
the hardware serial to match the ACS identity, so a DHCP change can never bind
web evidence to the wrong CPE. Everything is bounded and fails open.
"""

import json
import os
from typing import Any

SCHEMA_VERSION = 2
BAND_ORDER = {'2.4g': 0, '5g': 1}
DEFAULT_WEB_TTL = 600.0
MAX_WEB_TTL = 3600.0


def band_rank(band):
    return BAND_ORDER.get(band, len(BAND_ORDER))


def _text(value, limit=128):
    if not isinstance(value, str):
        return None
    value = value.strip()
    return value[:limit] if value else None


def ap_serial(ap):
    """Serial from the ACS ``_id`` (``OUI-ProductClass-Serial``) or identity."""
    identity = str(ap.get('id') or '')
    parts = identity.split('-')
    if len(parts) >= 3 and parts[-1].strip():
        return parts[-1].strip()
    return identity or None


def trust(ap: dict[str, Any], web_router: dict[str, Any] | None) -> tuple[bool, str]:
    """True only when IP AND serial both match an ACS-known CPE."""
    if not isinstance(ap, dict):
        return False, 'no-web'
    if not isinstance(web_router, dict):
        return False, 'no-web'
    if not ap.get('ip'):
        return False, 'ap-ip-missing'
    if web_router.get('router_ip') != ap.get('ip'):
        return False, 'ip-mismatch'
    serial = ap_serial(ap)
    raw_device = web_router.get('device')
    device: dict[str, Any] = raw_device if isinstance(raw_device, dict) else {}
    web_serial = _text(device.get('serial_number') or web_router.get('serial'), 64)
    if not serial or not web_serial:
        return False, 'serial-missing'
    if serial.upper() != web_serial.upper():
        return False, 'serial-mismatch'
    return True, 'trusted'


def observed_at(web_router):
    """Per-CPE observation timestamp, never the bridge's own fetch time."""
    for key in ('observed_at', 'updated_at'):
        value = web_router.get(key) if isinstance(web_router, dict) else None
        if isinstance(value, (int, float)):
            return value
    return None


def _fresh(web_router, now, ttl):
    """Fresh only from an observed timestamp; the ``fresh`` flag is never trusted."""
    generated = observed_at(web_router)
    if generated is None or now is None:
        return False
    age = now - generated
    return 0 <= age <= ttl


def _numeric(value):
    return value if isinstance(value, (int, float)) and not isinstance(value, bool) else None


def device_stats(web_router, device, now=None, ttl=DEFAULT_WEB_TTL):
    """Proven hardware gauges (CPU/memory percent, uptime) or explicit absence.

    CPU and memory come only from the router's own process-status gauge and
    uptime only from the hardware device-info, so each field is either a real
    reading or None with a reason: no absolute memory bytes and no bridge
    process uptime are ever substituted here.
    """
    router = web_router if isinstance(web_router, dict) else {}
    raw_stats: Any = router.get('stats')
    stats: dict[str, Any] = raw_stats if isinstance(raw_stats, dict) else {}
    seen = router.get('stats_observed_at')
    if not isinstance(seen, (int, float)) or isinstance(seen, bool):
        seen = observed_at(router)
    fresh = seen is not None and now is not None and 0 <= now - seen <= min(max(ttl or DEFAULT_WEB_TTL,
                                                                              30.0), MAX_WEB_TTL)
    cpu = _numeric(stats.get('cpu_percent')) if fresh else None
    mem = _numeric(stats.get('mem_percent')) if fresh else None
    raw_device = device if isinstance(device, dict) else {}
    uptime = _numeric(raw_device.get('uptime_seconds'))
    uptime = int(uptime) if uptime is not None and uptime >= 0 else None
    reason = None
    if cpu is None or mem is None:
        reason = router.get('stats_reason') if isinstance(router.get('stats_reason'), str) \
            else 'unavailable_in_observed_sources'
    return {'cpu_percent': cpu, 'mem_percent': mem, 'uptime_seconds': uptime,
            'observed_at': seen if (cpu is not None or mem is not None) else None,
            'source': 'huawei-web', 'unavailable_reason': reason}


def classify_profiles(web_router, ttl=DEFAULT_WEB_TTL, now=None) -> dict[str, Any]:
    """Split web profiles into fresh-active and observed-but-not-published.

    A missing/unknown enable flag is never read as disabled, and a profile the
    web API did not report as active is kept as observed metadata only.
    """
    ttl = min(max(ttl or DEFAULT_WEB_TTL, 30.0), MAX_WEB_TTL)
    inventory = web_router.get('inventory') if isinstance(web_router, dict) else None
    inventory = inventory if isinstance(inventory, dict) else {}
    profiles = [p for p in inventory.get('profiles', []) if isinstance(p, dict)]
    fresh = _fresh(web_router, now, ttl)
    active, observed = [], []
    for profile in profiles:
        entry = {
            'band': profile.get('band'),
            'ssid': _text(profile.get('ssid'), 128),
            'native_id': _text(profile.get('native_id'), 160),
            'usage': profile.get('usage') if profile.get('usage') in ('primary', 'guest') else 'unknown',
            'enabled': profile.get('enabled') is True,
            'channel_configured': (profile.get('channel') or {}).get('configured'),
            'power': profile.get('power'),
            'wmm': profile.get('wmm') is True,
            'standard': _text(profile.get('standard'), 32),
        }
        if fresh and entry['enabled'] and entry['ssid']:
            active.append(entry)
        else:
            observed.append(entry)
    return {'fresh': fresh, 'active': active, 'observed': observed}


def _group_by_band(radios):
    groups = {}
    for radio in radios:
        groups.setdefault(radio.get('band'), []).append(radio)
    return groups


def crosswalk_band(radios, active_profiles):
    """Match radios of one band to active web profiles by exact SSID.

    Ambiguous matches (2+ candidates on either side) are reported, never
    resolved by arbitrary selection.
    """
    matches, ambiguous, hits = {}, [], {}
    for radio in radios:
        candidates = [p for p in active_profiles
                      if p.get('band') == radio.get('band') and p.get('ssid') == radio.get('ssid')]
        if len(candidates) == 1:
            matches[radio.get('id')] = candidates[0]
            hits.setdefault(id(candidates[0]), []).append(radio.get('id'))
        elif len(candidates) > 1:
            ambiguous.append({'radio_id': radio.get('id'), 'band': radio.get('band'),
                              'ssid': radio.get('ssid'), 'candidates': len(candidates)})
    contested = {pid for pid, radio_ids in hits.items() if len(radio_ids) > 1}
    for radio_id, profile in list(matches.items()):
        if id(profile) in contested:
            ambiguous.append({'radio_id': radio_id, 'band': profile.get('band'),
                              'ssid': profile.get('ssid'),
                              'candidates': len(hits[id(profile)])})
            matches.pop(radio_id)
    ghosts = [p for p in active_profiles if id(p) not in hits]
    return matches, ambiguous, ghosts


def _identity(band, native_id, radio_id, ssid):
    if native_id:
        return '%s|nid|%s' % (band, native_id)
    if radio_id:
        return '%s|path|%s' % (band, radio_id)
    return '%s|ssid|%s' % (band, ssid)


def _aliases(band, native_id, radio_id, ssid):
    """Every identity that must resolve to the same slot/BSSID."""
    out = []
    if native_id:
        out.append('%s|nid|%s' % (band, native_id))
    if radio_id:
        out.append('%s|path|%s' % (band, radio_id))
    if ssid:
        out.append('%s|ssid|%s' % (band, ssid))
    return sorted(set(out))


def sanitize_registry(registry):
    """Accept only the v2 shape; v1 slots migrate by (band, ssid) identity."""
    if not isinstance(registry, dict) or registry.get('schema_version') != SCHEMA_VERSION:
        return {'schema_version': SCHEMA_VERSION, 'aps': {}}
    aps = registry.get('aps')
    if not isinstance(aps, dict):
        return {'schema_version': SCHEMA_VERSION, 'aps': {}}
    clean = {}
    for ap_id, state in aps.items():
        if not isinstance(ap_id, str) or not isinstance(state, dict):
            continue
        slots = state.get('slots')
        if not isinstance(slots, dict):
            continue
        kept = {}
        for slot, info in slots.items():
            try:
                slot = int(slot)
            except (TypeError, ValueError):
                continue
            if slot < 0 or not isinstance(info, dict) or not info.get('identity'):
                continue
            aliases = info.get('aliases')
            aliases = sorted({str(a) for a in aliases if isinstance(a, str)}) \
                if isinstance(aliases, list) else []
            kept[slot] = {'band': info.get('band'), 'ssid': info.get('ssid'),
                          'native_id': info.get('native_id'), 'identity': str(info['identity']),
                          'aliases': aliases or [str(info['identity'])]}
        clean[ap_id] = {'slots': kept}
    return {'schema_version': SCHEMA_VERSION, 'aps': clean}


def migrate_v1(registry_v1):
    """Convert the legacy {ap: {schema_version:1, slots:{slot:{band,ssid}}}} map."""
    if not isinstance(registry_v1, dict):
        return sanitize_registry(None)
    aps = {}
    for ap_id, state in registry_v1.items():
        slots = state.get('slots') if isinstance(state, dict) else None
        if not isinstance(ap_id, str) or not isinstance(slots, dict):
            continue
        kept = {}
        for slot, info in slots.items():
            try:
                slot = int(slot)
            except (TypeError, ValueError):
                continue
            if slot < 0 or not isinstance(info, dict):
                continue
            band, ssid = info.get('band'), info.get('ssid')
            identity = _identity(band, None, None, ssid)
            kept[slot] = {'band': band, 'ssid': ssid, 'native_id': None,
                          'identity': identity,
                          'aliases': _aliases(band, None, None, ssid)}
        aps[ap_id] = {'slots': kept}
    return {'schema_version': SCHEMA_VERSION, 'aps': aps}


def _stable_slots(ap_id, entries, previous):
    """Deterministic slots keyed by alias sets, seeded by published order.

    Any alias of a previous slot (native_id, TR-098 path, legacy band+SSID)
    resolves to that slot, so an SSID rename, a row reorder or a v1 upgrade
    never changes the published BSSID. An empty registry seeds slot = published
    order index, matching the enumeration already advertised.
    """
    prev_slots = previous.get('aps', {}).get(ap_id, {}).get('slots', {})
    by_alias = {}
    for slot, info in prev_slots.items():
        for alias in (info.get('aliases') or [info['identity']]):
            by_alias[alias] = slot
    reserved = set(prev_slots)
    seeded = bool(prev_slots)
    claimed = {}
    duplicates = []
    assignment = {}
    slots = {slot: dict(info) for slot, info in prev_slots.items()}
    ordered = sorted(entries, key=lambda e: (band_rank(e['band']), e['order']))
    for entry in ordered:
        slot = None
        for alias in entry['aliases']:
            if alias in by_alias:
                slot = by_alias[alias]
                break
        if slot is not None and slot in claimed and claimed[slot] != entry['identity']:
            slot = None
            duplicates.append({'band': entry['band'], 'ssid': entry['ssid'],
                               'reason': 'slot-claimed-by'})
        if slot is None:
            if not seeded:
                slot = entry['order']
            else:
                candidate = 0
                while candidate in reserved or candidate in set(claimed):
                    candidate += 1
                slot = candidate
            reserved.add(slot)
        for alias in entry['aliases']:
            by_alias[alias] = slot
        claimed[slot] = entry['identity']
        assignment[entry['identity']] = slot
        slots[slot] = {'band': entry['band'], 'ssid': entry['ssid'],
                       'native_id': entry['native_id'], 'identity': entry['identity'],
                       'aliases': list(entry['aliases'])}
    return assignment, slots, duplicates


def apply(result, web_inventory, registry, now=None) -> tuple[dict[str, Any], dict[str, Any]]:
    """Enrich normalized APs with trusted web evidence; return (result, registry).

    Additive only: TR-098 keys and existing slot assignments are preserved.
    """
    registry = sanitize_registry(registry)
    web_routers = {}
    if isinstance(web_inventory, dict):
        for router in (web_inventory.get('routers') or {}).values():
            if isinstance(router, dict) and router.get('router_ip'):
                web_routers[router['router_ip']] = router
    warnings = []
    summary = {}
    new_aps = {}
    for ap in result.get('aps', []):
        if ap.get('web_only') is True:
            # The web-only provider owns its identity, slots and inventory summary.
            continue
        ap_id = ap.get('id')
        web_router = web_routers.get(ap.get('ip'))
        trusted, reason = trust(ap, web_router)
        classified = classify_profiles(web_router or {}, now=now)
        use_web = trusted and classified['fresh']
        radios = ap.get('radios', [])
        band_profiles = {}
        for profile in classified['active']:
            band_profiles.setdefault(profile.get('band'), []).append(profile)
        matches, ambiguous, ghosts = {}, [], []
        grouped = _group_by_band(radios)
        for band in set(grouped) | set(band_profiles):
            band_matches, band_ambiguous, band_ghosts = crosswalk_band(
                grouped.get(band, []), band_profiles.get(band, []))
            matches.update(band_matches)
            ambiguous.extend(band_ambiguous)
            ghosts.extend(band_ghosts)
        for issue in ambiguous:
            warnings.append('%s: match ambiguo %s/%s (%s radios)' % (
                ap_id, issue.get('band'), issue.get('ssid'), issue.get('candidates')))
        entries, channels = [], {}
        for order, radio in enumerate(radios):
            radio['trusted_web'] = trusted
            profile = matches.get(radio.get('id')) if use_web else None
            if profile:
                radio['native_id'] = profile['native_id']
                radio['web_usage'] = profile['usage']
                radio['web_enabled'] = profile['enabled']
                radio['web_channel_configured'] = profile['channel_configured']
            radio['effective_channel'] = radio.get('channel')
            radio['channel_source'] = 'tr098'
            native_id = radio.get('native_id')
            aliases = _aliases(radio.get('band'), native_id, radio.get('id'), radio.get('ssid'))
            entries.append({'band': radio.get('band'), 'ssid': radio.get('ssid'),
                            'native_id': native_id, 'radio_id': radio.get('id'),
                            'order': order, 'aliases': aliases,
                            'identity': aliases[0] if aliases else _identity(
                                radio.get('band'), native_id, radio.get('id'), radio.get('ssid'))})
            if radio.get('enabled') is not False and not radio.get('stale'):
                channels.setdefault(radio.get('band'), []).append(
                    (radio.get('channel'), str(radio.get('id'))))
        representative, uncertainty = {}, {}
        for band, observed in channels.items():
            distinct = {value for value, _ in observed}
            uncertainty[band] = len(distinct) > 1
            if len(distinct) > 1:
                warnings.append('%s: canal observado conflictivo en %s: %s' % (
                    ap_id, band, sorted(distinct)))
            representative[band] = min(observed, key=lambda item: (item[0] or 0, item[1]))[0]
        assignment, slots, duplicates = _stable_slots(ap_id, entries, registry)
        for issue in duplicates:
            warnings.append('%s: slots duplicados %s/%s' % (
                ap_id, issue.get('band'), issue.get('ssid')))
        new_aps[ap_id] = {'slots': slots}
        device = (web_router or {}).get('device') if use_web else None
        stats_view = device_stats(web_router or {}, device, now=now) if use_web else None
        web_only = ap.get('web_only') is True
        if not web_only:
            ap['device_stats'] = dict(stats_view) if isinstance(stats_view, dict) else None
            ap['device_truth'] = dict(device) if isinstance(device, dict) else None
        device_summary = dict(device) if isinstance(device, dict) else (
            dict(ap['device_truth']) if web_only and isinstance(ap.get('device_truth'), dict) else None)
        stats_summary = dict(stats_view) if isinstance(stats_view, dict) else (
            dict(ap['device_stats']) if web_only and isinstance(ap.get('device_stats'), dict) else None)
        summary[ap_id] = {
            'schema_version': SCHEMA_VERSION,
            'trusted': trusted,
            'identity': 'web-api-only' if web_only else reason,
            'fresh': bool(ap.get('online')) if web_only else classified['fresh'],
            'observed_at': ap.get('last_seen') if web_only else observed_at(web_router or {}),
            'serial': ap_serial(ap),
            'active_profiles': classified['active'],
            'observed_unmanaged': classified['observed'] + [
                {'band': g.get('band'), 'ssid': g.get('ssid'), 'native_id': g.get('native_id'),
                 'usage': g.get('usage'), 'enabled': g.get('enabled'),
                 'channel_configured': g.get('channel_configured'), 'channel': None,
                 'reason': 'no-tr098-match'} for g in ghosts],
            'slots': {str(slot): dict(info) for slot, info in slots.items()},
            'slot_by_radio': {str(e['radio_id']): assignment.get(e['identity'])
                              for e in entries},
            'representative_channel': representative,
            'channel_uncertain': uncertainty,
            'ambiguous': ambiguous,
            'device': device_summary,
            'device_stats': stats_summary,
        }
        ap['inventory'] = summary[ap_id]
    result['inventory'] = {'schema_version': SCHEMA_VERSION, 'routers': summary,
                           'warnings': warnings}
    result.setdefault('warnings', []).extend(warnings)
    return result, {'schema_version': SCHEMA_VERSION, 'aps': new_aps}


def _bounded_ttl(ttl):
    return min(max(ttl or DEFAULT_WEB_TTL, 30.0), MAX_WEB_TTL)


def trusted_routers(aps, web_inventory, now=None, ttl=DEFAULT_WEB_TTL):
    """{router_ip: web_router} for CPEs that pass IP+serial identity AND have a
    per-CPE observed timestamp that is neither future nor expired."""
    ttl = _bounded_ttl(ttl)
    routers = web_inventory.get('routers') if isinstance(web_inventory, dict) else None
    if not isinstance(routers, dict):
        return {}
    by_ip = {}
    for router in routers.values():
        if isinstance(router, dict) and router.get('router_ip'):
            by_ip[router['router_ip']] = router
    out = {}
    for ap in aps or []:
        router = by_ip.get(ap.get('ip'))
        trusted, _ = trust(ap, router)
        if trusted and _fresh(router, now, ttl):
            out[ap['ip']] = router
    return out


def filter_inventory(aps, web_inventory, now=None, ttl=DEFAULT_WEB_TTL):
    return {'routers': dict(trusted_routers(aps, web_inventory, now, ttl))}


def filter_enrichment(aps, enrichment, now=None, ttl=DEFAULT_WEB_TTL):
    """Drop client evidence that is not from a trusted, fresh, same-CPE source."""
    if not isinstance(enrichment, dict):
        return enrichment
    by_mac = enrichment.get('by_mac')
    if not isinstance(by_mac, dict):
        return enrichment
    ttl = _bounded_ttl(ttl)
    serial_by_ip = {ap.get('ip'): ap_serial(ap) for ap in aps or [] if ap.get('ip')}
    kept = {}
    for mac, extra in by_mac.items():
        if not isinstance(extra, dict):
            continue
        router_ip = extra.get('router_ip')
        expected = serial_by_ip.get(router_ip)
        if not expected:
            continue
        got = _text(extra.get('_serial') or extra.get('serial'), 64)
        if not got or got.upper() != expected.upper():
            continue
        seen = extra.get('_ts')
        if not isinstance(seen, (int, float)) or now is None:
            continue
        if seen > now or now - seen > ttl:
            continue
        kept[mac] = extra
    out = dict(enrichment)
    out['by_mac'] = kept
    return out


def load_registry(path) -> dict[str, Any]:
    try:
        with open(path, 'r', encoding='utf-8') as handle:
            data = json.load(handle)
    except (OSError, ValueError):
        return sanitize_registry(None)
    if isinstance(data, dict) and data.get('schema_version') == SCHEMA_VERSION:
        return sanitize_registry(data)
    return migrate_v1(data)


def save_registry(path, registry) -> bool:
    """Atomic best-effort write; never raises to the caller."""
    from .unifi import atomic_json
    try:
        atomic_json(path, sanitize_registry(registry))
        return True
    except OSError:
        return False
