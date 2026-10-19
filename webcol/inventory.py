#!/usr/bin/env python3
"""Stable WLAN inventory model for webcol (pure functions).

Crosswalks the Huawei web WLAN inventory (huawei_api.parse_wlanguide output)
with optional TR-098 radios (huawei_bridge.collector.normalize output) and
assigns a persisted, SSID-independent slot registry.

Security/contract notes:
- Safe by construction: only whitelisted fields are copied, so credentials,
  cookies, CSRF pairs, nonces and proofs can never leak into the model.
- The registry is metadata only: it never writes a BSSID or changes radio
  state. An observed router BSSID is carried read-only for review.
- Ambiguous multi-candidate crosswalks are reported, never resolved by
  arbitrary selection.
"""

import json
import os

SCHEMA_VERSION = 1
BAND_ORDER = {'2.4g': 0, '5g': 1}
RESULTS = ('primary', 'guest', 'unknown')


def normalize_band(value):
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in ('2.4g', '2.4ghz', '2g'):
            return '2.4g'
        if lowered in ('5g', '5ghz'):
            return '5g'
    return None


def band_rank(band):
    return BAND_ORDER.get(band, len(BAND_ORDER))


def profile_identity(profile):
    """Return (band, kind, value). native_id wins over SSID for stability."""
    band = normalize_band(profile.get('band')) if isinstance(profile, dict) else None
    native_id = profile.get('native_id') if isinstance(profile, dict) else None
    if isinstance(native_id, (str, int)) and str(native_id):
        return band, 'nid', str(native_id)
    ssid = profile.get('ssid') if isinstance(profile, dict) else None
    return band, 'ssid', ssid if isinstance(ssid, str) else ''


def _identity_key(identity):
    return '%s|%s|%s' % (identity[0], identity[1], identity[2])


def sanitize_state(state):
    """Accept only the known registry shape; unknown/migrated shapes yield {}."""
    if not isinstance(state, dict) or state.get('schema_version') != SCHEMA_VERSION:
        return {'schema_version': SCHEMA_VERSION, 'slots': {}}
    slots = state.get('slots')
    if not isinstance(slots, dict):
        return {'schema_version': SCHEMA_VERSION, 'slots': {}}
    clean = {}
    for key, meta in slots.items():
        try:
            slot = int(key)
        except (TypeError, ValueError):
            continue
        if slot < 0 or not isinstance(meta, dict):
            continue
        identity = meta.get('identity')
        if not isinstance(identity, str) or not identity:
            continue
        clean[slot] = {'band': meta.get('band'), 'ssid': meta.get('ssid'),
                       'native_id': meta.get('native_id'), 'identity': identity}
    return {'schema_version': SCHEMA_VERSION, 'slots': clean}


def assign_slots(profiles, previous_state=None):
    """Assign deterministic global slots, reusing previous identities.

    Slots are keyed on native_id when present so an SSID rename or a reorder
    keeps the same slot; otherwise they fall back to (band, ssid).
    """
    previous = sanitize_state(previous_state)
    by_identity = {meta['identity']: slot for slot, meta in previous['slots'].items()}
    used = set(previous['slots'])
    next_free = 0
    assignment, slots = {}, {}

    def sort_key(item):
        index, profile = item
        identity = profile_identity(profile)
        return (band_rank(identity[0]), identity[1], identity[2], index)

    for index, profile in sorted(enumerate(profiles), key=sort_key):
        identity = profile_identity(profile)
        key = _identity_key(identity)
        slot = by_identity.get(key)
        if slot is None:
            while next_free in used:
                next_free += 1
            slot = next_free
            used.add(slot)
            next_free += 1
        assignment[index] = slot
        slots[slot] = {'band': identity[0], 'ssid': profile.get('ssid'),
                       'native_id': profile.get('native_id'), 'identity': key}
    return assignment, {'schema_version': SCHEMA_VERSION, 'slots': slots}


def crosswalk_primary(web_profiles, tr098_radios=None):
    """Match primary web profiles to TR-098 radios by exact (band, ssid).

    Returns matches, ambiguous groups (2+ candidates, never auto-resolved) and
    unmatched entries on both sides.
    """
    radios = [r for r in (tr098_radios or []) if isinstance(r, dict)]
    matches, ambiguous, matched_ids = [], [], set()

    def candidate_band(radio):
        band = normalize_band(radio.get('band'))
        return band if band is not None else None

    for profile in web_profiles or []:
        if not isinstance(profile, dict) or profile.get('usage') != 'primary':
            continue
        band = normalize_band(profile.get('band'))
        ssid = profile.get('ssid')
        if band is None or not isinstance(ssid, str) or not ssid:
            continue
        candidates = [r for r in radios
                      if candidate_band(r) == band and r.get('ssid') == ssid]
        if len(candidates) == 1:
            radio = candidates[0]
            matched_ids.add(radio.get('id'))
            matches.append({'band': band, 'ssid': ssid, 'tr098_id': radio.get('id'),
                            'match': 'band+ssid',
                            'channel_effective': radio.get('channel'),
                            'bssid_observed': radio.get('bssid')})
        elif len(candidates) > 1:
            ambiguous.append({'band': band, 'ssid': ssid,
                              'candidates': [r.get('id') for r in candidates]})

    matched_bands = {(m['band'], m['ssid']) for m in matches}
    unmatched_web = [{'band': normalize_band(p.get('band')), 'ssid': p.get('ssid')}
                     for p in (web_profiles or [])
                     if isinstance(p, dict) and p.get('usage') == 'primary'
                     and (normalize_band(p.get('band')), p.get('ssid')) not in matched_bands]
    unmatched_tr098 = [{'id': r.get('id'), 'band': candidate_band(r), 'ssid': r.get('ssid')}
                       for r in radios if r.get('id') not in matched_ids]
    return {'matches': matches, 'ambiguous': ambiguous,
            'unmatched_web': unmatched_web, 'unmatched_tr098': unmatched_tr098}


def _channel(value):
    configured = None
    if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
        configured = value
    elif isinstance(value, str) and value.strip().isdigit():
        configured = int(value.strip())
    return {'configured': configured, 'configured_is_auto': configured == 0,
            'effective': None, 'effective_source': None}


def _power(value):
    if isinstance(value, bool) or value is None:
        return {'reported': None, 'unit': None, 'raw': None}
    if isinstance(value, str):
        text = value.strip()
        if text.endswith('%'):
            number = _number(text[:-1])
            return {'reported': number, 'unit': 'percent', 'raw': value}
        number = _number(text)
        return {'reported': number, 'unit': 'percent' if number is not None else None,
                'raw': value}
    if isinstance(value, (int, float)):
        return {'reported': value, 'unit': 'percent' if value <= 100 else None,
                'raw': value}
    return {'reported': None, 'unit': None, 'raw': None}


def _number(text):
    try:
        number = float(text)
    except (TypeError, ValueError):
        return None
    return int(number) if number.is_integer() else number


def _hardware(device):
    device = device if isinstance(device, dict) else {}
    model = device.get('model') or device.get('model_cust')
    virtual = None
    if isinstance(model, str) and model.replace(' ', '').upper() in ('U7PRO',):
        virtual, model = model, device.get('model_cust')
    return {'model': model, 'model_cust': device.get('model_cust'),
            'software_version': device.get('software_version'),
            'hardware_version': device.get('hardware_version'),
            'serial_number': device.get('serial_number'),
            'uptime_seconds': device.get('uptime_seconds'),
            'virtual_profile': virtual}


def build_inventory(web_inventory, tr098_radios=None, device=None,
                    previous_state=None, now=None):
    """Build the structured, slot-stable inventory model."""
    web_inventory = web_inventory if isinstance(web_inventory, dict) else {}
    profiles = [p for p in web_inventory.get('profiles', []) if isinstance(p, dict)]
    crosswalk = crosswalk_primary(profiles, tr098_radios)
    effective = {(m['band'], m['ssid']): m for m in crosswalk['matches']}
    assignment, state = assign_slots(profiles, previous_state)

    output = []
    for index, profile in enumerate(profiles):
        band = normalize_band(profile.get('band'))
        ssid = profile.get('ssid') if isinstance(profile.get('ssid'), str) else ''
        channel = _channel(profile.get('channel_configured'))
        match = effective.get((band, ssid))
        if match and match.get('channel_effective') is not None:
            channel['effective'] = match['channel_effective']
            channel['effective_source'] = 'tr098'
        usage = profile.get('usage')
        output.append({
            'slot': assignment[index],
            'slot_key': '%s:slot-%s' % (band or 'unknown', assignment[index]),
            'band': band,
            'ssid': ssid,
            'native_id': profile.get('native_id'),
            'usage': usage if usage in RESULTS else 'unknown',
            'enabled': profile.get('enabled') is True,
            'channel': channel,
            'power': _power(profile.get('power')),
            'wmm': profile.get('wmm') is True,
            'standard': profile.get('standard'),
            'tr098_id': match.get('tr098_id') if match else None,
            'match': match.get('match') if match else None,
            'bssid_observed': match.get('bssid_observed') if match else None,
            'provenance': {'source': 'huawei-web:WlanGuideBasic',
                           'schema_version': SCHEMA_VERSION,
                           'observed_at': now},
        })
    output.sort(key=lambda p: (band_rank(p['band']), p['slot']))
    counts = {name: sum(1 for p in output if p['usage'] == name)
              for name in RESULTS}
    return {
        'schema_version': SCHEMA_VERSION,
        'generated_at': now,
        'hardware': _hardware(device),
        'radios': web_inventory.get('radios', []),
        'profiles': output,
        'counts': counts,
        'crosswalk': crosswalk,
        'registry': state,
    }


def load_state(path):
    try:
        with open(path, 'r', encoding='utf-8') as handle:
            return sanitize_state(json.load(handle))
    except (OSError, ValueError):
        return sanitize_state(None)


def save_state(path, state):
    """Best-effort atomic write of the registry; never raises to the caller."""
    try:
        directory = os.path.dirname(path)
        if directory:
            os.makedirs(directory, exist_ok=True)
        temp = path + '.tmp'
        with open(temp, 'w', encoding='utf-8') as handle:
            json.dump(sanitize_state(state), handle, sort_keys=True)
        os.replace(temp, path)
        return True
    except OSError:
        return False
