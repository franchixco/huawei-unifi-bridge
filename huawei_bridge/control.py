"""Allowlisted UniFi Wi-Fi provisioning, with ACS task and readback confirmation."""

import json
import re
import threading
import time
from pathlib import Path
from typing import Any
from urllib.parse import quote, urlencode

from .collector import ip, timestamp, val

BINDING_SCHEMA = 2
RADIO_PATH = re.compile(r'InternetGatewayDevice\.LANDevice\.\d+\.WLANConfiguration\.\d+')
WIRELESS_KEY = re.compile(r'wireless\.\d+\.(parent|ssid|status|wmm|devname|name|id)')
RADIO_KEY = re.compile(r'radio\.\d+\.(phyname|channel|status)')
CONTROLLED_KEY = re.compile(r'(?:radio|wireless)\.\d+\.([a-z_0-9]+)')
IGNORED_FIELDS = {'phyname', 'parent', 'ssid', 'status', 'wmm', 'devname', 'name', 'id',
                  'channel'}
FINITE_BOOL = ('enabled', 'disabled')


def field(device, path):
    result = device
    for key in path.split('.'):
        result = result.get(key, {}) if isinstance(result, dict) else {}
    return result if isinstance(result, dict) else {}


def enabled(value):
    if value not in FINITE_BOOL:
        raise ValueError('Invalid enabled/disabled value')
    return value == 'enabled'


def sanitize_bindings(raw) -> dict[str, Any]:
    """Normalize legacy ``{phy: {path, wlan_id}}`` and v2 bindings.

    v2 shape: ``{'schema_version': 2, 'radios': {phy: {path, native_id}},
    'vaps': {identity: {phy, path, wlan_id, native_id, ssid}}}``.
    """
    if not isinstance(raw, dict):
        return {'schema_version': BINDING_SCHEMA, 'radios': {}, 'vaps': {}}

    def clean_radio(entry):
        if not isinstance(entry, dict) or not isinstance(entry.get('path'), str):
            return None
        if not RADIO_PATH.fullmatch(entry['path']):
            return None
        return {'path': entry['path'], 'native_id': entry.get('native_id'),
                'slot': entry.get('slot')}

    def clean_vap(key, entry):
        if not isinstance(entry, dict) or not isinstance(entry.get('path'), str):
            return None
        if not RADIO_PATH.fullmatch(entry['path']):
            return None
        aliases = entry.get('aliases')
        aliases = sorted({str(a) for a in aliases if isinstance(a, str)}) \
            if isinstance(aliases, list) else []
        if not aliases:
            aliases = [str(entry.get('identity') or key), entry['path']]
        return {'phy': entry.get('phy'), 'path': entry['path'],
                'wlan_id': entry.get('wlan_id'), 'native_id': entry.get('native_id'),
                'ssid': entry.get('ssid'), 'identity': entry.get('identity') or key,
                'aliases': aliases}

    if raw.get('schema_version') == BINDING_SCHEMA:
        radios = {}
        for phy, entry in (raw.get('radios') or {}).items():
            cleaned = clean_radio(entry)
            if isinstance(phy, str) and cleaned:
                radios[phy] = cleaned
        vaps = {}
        for key, entry in (raw.get('vaps') or {}).items():
            cleaned = clean_vap(key, entry)
            if isinstance(key, str) and cleaned:
                vaps[key] = cleaned
        return {'schema_version': BINDING_SCHEMA, 'radios': radios, 'vaps': vaps}

    radios, vaps = {}, {}
    for phy, entry in raw.items():
        cleaned = clean_radio(entry)
        if not isinstance(phy, str) or not cleaned:
            continue
        radios[phy] = cleaned
        aliases: list[str] = [str(cleaned['native_id'] or cleaned['path']), str(cleaned['path'])]
        aliases.append('ath0' if phy == 'wifi0' else 'ath1' if phy == 'wifi1' else str(phy))
        vaps[cleaned['path']] = {'phy': phy, 'path': cleaned['path'],
                                 'wlan_id': entry.get('wlan_id'),
                                 'native_id': cleaned['native_id'], 'ssid': entry.get('ssid'),
                                 'identity': cleaned['native_id'] or cleaned['path'],
                                 'aliases': sorted(set(aliases))}
    return {'schema_version': BINDING_SCHEMA, 'radios': radios, 'vaps': vaps}


def _resolve_vap(bindings, phy, identity, ssid):
    vaps = bindings['vaps']
    candidates = [v for v in vaps.values() if v.get('phy') == phy]
    if identity:
        by_identity = [v for v in vaps.values()
                       if identity in (v.get('aliases') or [])
                       or identity == v.get('identity') or identity == v.get('native_id')
                       or identity == v.get('path')]
        if len(by_identity) == 1:
            if by_identity[0].get('phy') != phy:
                raise ValueError('Explicit VAP identity belongs to another radio: ' + phy)
            return by_identity[0]
        if len(by_identity) > 1:
            raise ValueError('Ambiguous VAP identity for ' + phy)
        # An explicit identity that matches nothing is never resolved by SSID:
        # falling back could bind the wrong profile on a rename or typo.
        raise ValueError('Unknown VAP identity for ' + phy)
    if ssid:
        by_ssid = [v for v in candidates if v.get('ssid') == ssid]
        if len(by_ssid) == 1:
            return by_ssid[0]
        if len(by_ssid) > 1:
            raise ValueError('Ambiguous VAP binding for ' + phy)
    if len(candidates) == 1:
        only = candidates[0]
        if not ssid or not only.get('ssid') or only.get('ssid') == ssid:
            return only
        return None
    if not candidates:
        return None
    raise ValueError('Ambiguous VAP binding for ' + phy)


def analyze(config, bindings, device, strict_unsupported=False):
    """Return (desired, diagnostics). Never mutates the device or the record."""
    if not isinstance(config, str) or len(config) > 1024 * 1024:
        raise ValueError('Invalid provisioning text')
    bindings = sanitize_bindings(bindings)
    values, unsupported = {}, []
    for line in config.splitlines():
        if '=' not in line:
            continue
        key, value = line.split('=', 1)
        match = CONTROLLED_KEY.fullmatch(key)
        if not match:
            continue
        name = match.group(1)
        if name not in IGNORED_FIELDS:
            if name not in unsupported:
                unsupported.append(name)
            continue
        if not (WIRELESS_KEY.fullmatch(key) or RADIO_KEY.fullmatch(key)):
            continue
        if key in values or '\x00' in value:
            raise ValueError('Duplicate or invalid provisioning field')
        values[key] = value
    if strict_unsupported and unsupported:
        raise ValueError('Unsupported controlled Wi-Fi fields present: '
                         + ','.join(sorted(unsupported)))

    desired: dict[str, list[Any]] = {}

    def put(path, param, pair):
        key = path + '.' + param
        if key in desired and desired[key] != pair:
            raise ValueError('Conflicting provisioning targets for ' + param)
        desired[key] = pair

    seen_phys = set()
    radio_status_by_phy = {}
    for key, phy in values.items():
        if not (key.startswith('radio.') and key.endswith('.phyname')):
            continue
        if phy not in bindings['radios']:
            raise ValueError('Unknown radio binding for ' + phy)
        if phy in seen_phys:
            raise ValueError('Ambiguous radio binding')
        seen_phys.add(phy)
        prefix = key.rsplit('.', 1)[0]
        radio_status_by_phy[phy] = values.get(prefix + '.status')
        path = bindings['radios'][phy]['path']
        wlan = field(device, path)
        channel = values.get(prefix + '.channel')
        if channel == 'auto':
            put(path, 'AutoChannelEnable', [True, 'xsd:boolean'])
        elif channel is not None:
            allowed = str(val(wlan, 'PossibleChannels', '')).split(',')
            if not channel.isdigit() or channel not in allowed:
                raise ValueError('Channel not advertised by CPE')
            put(path, 'AutoChannelEnable', [False, 'xsd:boolean'])
            put(path, 'Channel', [int(channel), 'xsd:unsignedInt'])
        status = values.get(prefix + '.status')
        if status is not None:
            put(path, 'Enable', [enabled(status), 'xsd:boolean'])

    for key, phy in values.items():
        if not (key.startswith('wireless.') and key.endswith('.parent')):
            continue
        if phy not in bindings['radios']:
            raise ValueError('Unknown radio binding for ' + phy)
        prefix = key.rsplit('.', 1)[0]
        identity = (values.get(prefix + '.devname') or values.get(prefix + '.name')
                    or values.get(prefix + '.id'))
        binding = _resolve_vap(bindings, phy, identity, values.get(prefix + '.ssid'))
        if binding is None:
            raise ValueError('Unresolved VAP binding for ' + phy)
        path = binding['path']
        radio_status = radio_status_by_phy.get(phy)
        managed_vaps = [v for v in bindings['vaps'].values() if v.get('phy') == phy]
        if radio_status == 'disabled' and len(managed_vaps) > 1:
            raise ValueError('Radio disable with multiple VAPs is not supported')
        ssid = values.get(prefix + '.ssid')
        if ssid is not None:
            if not ssid or len(ssid.encode('utf-8')) > 32:
                raise ValueError('Invalid SSID')
            put(path, 'SSID', [ssid, 'xsd:string'])
        if prefix + '.status' in values:
            put(path, 'Enable', [enabled(values[prefix + '.status']) and
                                 (enabled(radio_status) if radio_status is not None else True),
                                 'xsd:boolean'])
        if prefix + '.wmm' in values:
            put(path, 'WMMEnable', [enabled(values[prefix + '.wmm']), 'xsd:boolean'])

    for path, pair in desired.items():
        current = field(device, path)
        if not current or (current.get('_value') != pair[0] and current.get('_writable') is not True):
            raise ValueError('CPE field is absent or not writable')
        if path.endswith('.Channel') and current.get('_type') in ('xsd:int', 'xsd:unsignedInt'):
            pair[1] = current['_type']
    return desired, {'unsupported': sorted(set(unsupported))}


def translate(config, bindings, device, strict_unsupported=False):
    desired, _ = analyze(config, bindings, device, strict_unsupported=strict_unsupported)
    return desired


def allowed_ip_set(allowed_ip):
    # A malformed entry must fail loudly: silently dropping it would widen or
    # narrow the write allowlist without anyone noticing.
    entries = [item for item in re.split(r'[,\s]+', allowed_ip or '') if item]
    if not entries:
        return set()
    result = set()
    for item in entries:
        parsed = ip(item)
        if parsed is None:
            raise ValueError('Invalid HUAWEI_CONTROL_IP entry')
        result.add(parsed)
    return result


class Control:
    def __init__(self, directory, request, allowed_ip='', inventory=None,
                 legacy_bindings=False, enforce_drift=False):
        self.directory = Path(directory)
        self.request = request
        self.allowed_ips = allowed_ip_set(allowed_ip)
        self.inventory = inventory
        self.legacy_bindings = legacy_bindings
        self.enforce_drift = enforce_drift
        self.records = {}
        self._lock = threading.RLock()

    def _inventory_for(self, ap):
        if callable(self.inventory):
            return self.inventory(ap)
        return ap.get('inventory')

    def build_bindings(self, ap, mapping):
        """Trusted inventory bindings; legacy bands only when explicitly opted in.

        An inventory that is present but untrusted (or a configured provider
        that raises/returns nothing) fails closed, so a DHCP or serial change
        never degrades into the ambiguous legacy band map.
        """
        inventory = self._inventory_for(ap)
        if inventory is not None:
            if not (isinstance(inventory, dict) and inventory.get('trusted') is True):
                raise ValueError('Untrusted inventory: writes refused')
        elif not self.legacy_bindings:
            raise ValueError('Inventory required: legacy bindings are opt-in only')
        radios, vaps = {}, {}
        if inventory is not None:
            slot_by_radio = inventory.get('slot_by_radio') or {}
            for radio in ap.get('radios', []):
                band = radio.get('band')
                phy = 'wifi0' if band == '2.4g' else 'wifi1' if band == '5g' else None
                native = radio.get('native_id')
                if phy is None or not native:
                    continue
                slot = slot_by_radio.get(str(radio.get('id')))
                wlan_id = mapping.get(radio.get('ssid'))
                aliases = [str(native), str(radio.get('id'))]
                if slot is not None:
                    aliases.append('ath%s' % slot)
                vaps[str(native)] = {'phy': phy, 'path': radio.get('id'), 'wlan_id': wlan_id,
                                     'native_id': native, 'ssid': radio.get('ssid'),
                                     'identity': str(native), 'aliases': aliases}
                if wlan_id is None:
                    continue
                current = radios.get(phy)
                if current is None or (slot is not None and slot < current.get('slot', 10 ** 9)):
                    radios[phy] = {'path': radio.get('id'), 'native_id': native, 'slot': slot}
            return sanitize_bindings({'schema_version': BINDING_SCHEMA,
                                      'radios': radios, 'vaps': vaps})
        for index, radio in enumerate(ap.get('radios', [])):
            band = radio.get('band')
            phy = 'wifi0' if band == '2.4g' else 'wifi1' if band == '5g' else None
            if phy is None or radio.get('ssid') not in mapping:
                continue
            if phy in radios:
                raise ValueError('Ambiguous Huawei radio')
            slot = radio.get('slot')
            slot = index if slot is None else slot
            native = radio.get('native_id') or radio['id']
            radios[phy] = {'path': radio['id'], 'native_id': radio.get('native_id')}
            vaps[str(native)] = {'phy': phy, 'path': radio['id'],
                                 'wlan_id': mapping[radio['ssid']],
                                 'native_id': radio.get('native_id'),
                                 'ssid': radio['ssid'], 'identity': str(native),
                                 'aliases': [str(native), str(radio['id']), 'ath%s' % slot]}
        return sanitize_bindings({'schema_version': BINDING_SCHEMA,
                                  'radios': radios, 'vaps': vaps})

    def revalidate_bindings(self, ap, bindings):
        """Every stored path must still map to the same CPE, phy and native id."""
        inventory = self._inventory_for(ap)
        if inventory is None:
            if not self.legacy_bindings:
                raise ValueError('Inventory required: legacy bindings are opt-in only')
        elif not (isinstance(inventory, dict) and inventory.get('trusted') is True):
            raise ValueError('Untrusted inventory: writes refused')
        radios_by_path = {r.get('id'): r for r in ap.get('radios', [])}
        for binding in bindings['vaps'].values():
            radio = radios_by_path.get(binding['path'])
            if radio is None:
                raise ValueError('Stored VAP path is no longer present on this CPE')
            band = radio.get('band')
            phy = 'wifi0' if band == '2.4g' else 'wifi1' if band == '5g' else None
            if binding.get('phy') != phy:
                raise ValueError('Stored VAP binding radio mismatch')
            native = radio.get('native_id')
            stored = binding.get('native_id')
            if not self.legacy_bindings:
                if not stored or not native:
                    raise ValueError('Stored VAP native id missing on this CPE')
                if str(stored) != str(native):
                    raise ValueError('Stored VAP native id changed on this CPE')
            elif stored and native and str(stored) != str(native):
                raise ValueError('Stored VAP native id changed on this CPE')
        for phy, radio_binding in bindings['radios'].items():
            radio = radios_by_path.get(radio_binding['path'])
            if radio is None:
                raise ValueError('Stored radio path is no longer present on this CPE')
            band = radio.get('band')
            expected = 'wifi0' if band == '2.4g' else 'wifi1' if band == '5g' else None
            if expected != phy:
                raise ValueError('Stored radio binding phy mismatch')
        return bindings

    def record(self, ap):
        identity = ap['virtual_mac']
        if identity not in self.records:
            path = self.directory / (identity.replace(':', '') + '.json')
            self.records[identity] = json.loads(path.read_text()) if path.exists() else {}
        record = self.records[identity]
        if record.get('device', ap['id']) != ap['id']:
            raise ValueError('Provisioning identity binding mismatch')
        if 'bindings' in record:
            record['bindings'] = sanitize_bindings(record['bindings'])
        return record

    def save(self, ap):
        from .unifi import atomic_json
        atomic_json(self.directory / (ap['virtual_mac'].replace(':', '') + '.json'), self.record(ap))

    def capabilities(self, ap, device=None):
        if ap.get('web_only'):
            return {'writes_enabled': False, 'bound_radios': {}, 'bound_vaps': {},
                    'unsupported': ['cwmp-web-source']}
        record = self.record(ap)
        bindings = sanitize_bindings(record.get('bindings') or {})
        report = {'writes_enabled': bool(self.allowed_ips and ap.get('ip') in self.allowed_ips),
                  'bound_radios': {phy: entry['path'] for phy, entry in bindings['radios'].items()},
                  'bound_vaps': {key: entry['path'] for key, entry in bindings['vaps'].items()},
                  'unsupported': sorted(record.get('unsupported', []))}
        if isinstance(device, dict):
            writable = {}
            for phy, entry in bindings['radios'].items():
                wlan = field(device, entry['path'])
                writable[phy] = {'possible_channels': str(val(wlan, 'PossibleChannels', '')),
                                 'ssid_writable': bool(field(device, entry['path'] + '.SSID').get('_writable')),
                                 'channel_writable': bool(field(device, entry['path'] + '.Channel').get('_writable')),
                                 'enable_writable': bool(field(device, entry['path'] + '.Enable').get('_writable')),
                                 'wmm_writable': bool(field(device, entry['path'] + '.WMMEnable').get('_writable'))}
            report['writable'] = writable
        return report

    def plan(self, ap, response, device, mapping=None):
        """Read-only plan: resolves bindings and targets without writing."""
        mapping = mapping or {}
        if ap.get('web_only'):
            return {'ok': False, 'error': 'cwmp-unsupported-web-source',
                    'blocked_reason': 'cwmp-unsupported-web-source', 'writes_enabled': False,
                    'bindings': {'schema_version': BINDING_SCHEMA, 'radios': {}, 'vaps': {}},
                    'targets': {}, 'changes': {}, 'unsupported': ['cwmp']}
        record = self.record(ap)
        try:
            bindings = sanitize_bindings(record.get('bindings') or {})
            if not bindings['radios'] and not bindings['vaps']:
                bindings = self.build_bindings(ap, mapping)
            else:
                self.revalidate_bindings(ap, bindings)
            system_cfg = (response or {}).get('system_cfg')
            desired, diagnostics = analyze(system_cfg, bindings, device) \
                if system_cfg is not None else ({}, {'unsupported': []})
        except ValueError as exc:
            return {'ok': False, 'error': str(exc), 'writes_enabled':
                    bool(self.allowed_ips and ap.get('ip') in self.allowed_ips)}
        return {'ok': True,
                'writes_enabled': bool(self.allowed_ips and ap.get('ip') in self.allowed_ips),
                'blocked_reason': None if self.allowed_ips and ap.get('ip') in self.allowed_ips
                else 'writes-disabled',
                'phase': record.get('phase'),
                'bindings': bindings,
                'targets': desired,
                'changes': {p: v for p, v in desired.items()
                            if field(device, p).get('_value') != v[0]},
                'unsupported': diagnostics['unsupported']}

    def public(self, ap):
        if ap.get('web_only'):
            return {'enabled': False, 'blocked_reason': 'cwmp-unsupported-web-source',
                    'phase': 'unsupported', 'parameters': [], 'drift': [],
                    'unsupported': ['cwmp'], 'bound_radios': {}, 'bound_vaps': {},
                    'confirmed_version': None, 'request_id': None}
        record = self.record(ap)
        bindings = sanitize_bindings(record.get('bindings') or {})
        return {key: record[key] for key in ('phase', 'error', 'requested_at', 'confirmed_at', 'task_id') if key in record} | {
            'enabled': bool(self.allowed_ips and ap.get('ip') in self.allowed_ips),
            'parameters': sorted(record.get('changes', {})),
            'confirmed_version': record.get('confirmed_version'),
            'drift': sorted(record.get('drift', [])),
            'request_id': record.get('request_id'),
            'unsupported': sorted(record.get('unsupported', [])),
            'bound_radios': {phy: entry['path'] for phy, entry in bindings['radios'].items()},
            'bound_vaps': {key: entry['path'] for key, entry in bindings['vaps'].items()}}

    def mapping(self, ap, original):
        result = dict(original)
        for binding in self.record(ap).get('bindings', {}).get('vaps', {}).values():
            for radio in ap.get('radios', []):
                if radio['id'] == binding['path'] and binding.get('wlan_id'):
                    result[radio['ssid']] = binding['wlan_id']
        return result

    def ack(self, ap):
        return self.record(ap).get('ack_version')

    def reset(self, ap):
        if ap.get('web_only'):
            return
        with self._lock:
            record = self.record(ap)
            if record.get('phase') in ('queued', 'reading', 'submitting', 'uncertain'):
                record.update(phase='uncertain', error='Controller reset while ACS task pending; inspect before retry')
            else:
                for key in ('desired', 'revision', 'ack_version', 'changes', 'error',
                            'task_id', 'refresh_id', 'request_id', 'confirmed_version',
                            'unsupported', 'bindings'):
                    record.pop(key, None)
                record['phase'] = 'awaiting-baseline'
            self.save(ap)

    def reject(self, ap, error):
        with self._lock:
            record = self.record(ap)
            if record.get('phase') in ('queued', 'reading', 'submitting', 'uncertain', 'failed'):
                # Unresolved task outcomes and failed writebacks are authoritative:
                # a later rejection must never erase them or unlock a fresh write.
                return
            record.update(phase='rejected', error=str(error))
            self.save(ap)

    def receive(self, ap, response, device, mapping):
        if ap.get('web_only'):
            return  # No CWMP/TR-069 write path exists for a web-only AP.
        if not self.allowed_ips or ap.get('ip') not in self.allowed_ips or response.get('system_cfg') is None:
            return
        with self._lock:
            record = self.record(ap)
            # Guard the phase before anything else: validating the revision first
            # could raise and hand a failed record to reject(), which would flip it
            # to rejected and let a later revision start a fresh write.
            if record.get('phase') in ('queued', 'reading', 'submitting', 'uncertain', 'failed'):
                # In-flight tasks must finish, and a failed writeback requires manual
                # inspection: consuming a new revision here would be a blind retry
                # with no definitive fault.
                return
            revision = response.get('cfgversion')
            if not isinstance(revision, str) or not revision or len(revision) > 256:
                raise ValueError('Invalid provisioning revision')
            if revision == record.get('revision'):
                return
            bindings = sanitize_bindings(record.get('bindings') or {})
            if not bindings['radios'] and not bindings['vaps']:
                bindings = self.build_bindings(ap, mapping)
            else:
                self.revalidate_bindings(ap, bindings)
            desired, diagnostics = analyze(response['system_cfg'], bindings, device)
            if not desired:
                raise ValueError('No supported fields matched the bound radios')
            now = time.time()
            hardware_diff = {p: v for p, v in desired.items()
                             if field(device, p).get('_value') != v[0]}
            if 'desired' not in record:
                record.update(device=ap['id'], ip=ap['ip'], bindings=bindings, desired=desired,
                              baseline=dict(desired), revision=revision, ack_version=revision,
                              received_version=revision, received_at=now, confirmed_version=None,
                              unsupported=diagnostics['unsupported'], drift=sorted(hardware_diff),
                              phase='baseline', error=None)
                self.save(ap)
                return  # Existing controller defaults are not silently imposed on the router.
            baseline = record.get('baseline') or record.get('desired') or {}
            intent = {p: v for p, v in desired.items() if baseline.get(p) != v}
            drift = sorted(hardware_diff)
            record.update(revision=revision, desired=desired, error=None, drift=drift,
                          unsupported=diagnostics['unsupported'], received_version=revision,
                          received_at=now, bindings=bindings)
            if not intent:
                # The controller still wants the baseline: hardware drift alone is
                # never written (enforcement is a separate explicit policy).
                if drift and self.enforce_drift:
                    record.update(changes={p: desired[p] for p in drift})
                else:
                    record.update(changes={}, phase='confirmed' if not drift else 'drift',
                                  ack_version=revision, confirmed_version=revision if not drift else None,
                                  confirmed_at=now if not drift else None,
                                  requested_at=now, error=None)
                    self.save(ap)
                    return
            changes = {p: v for p, v in intent.items() if hardware_diff.get(p) is not None
                       or field(device, p).get('_value') != v[0]}
            record.update(changes=changes)
            if not changes:
                record.update(phase='confirmed', ack_version=revision, confirmed_version=revision,
                              confirmed_at=now, requested_at=now, error=None)
                self.save(ap)
                return
            record.update(phase='submitting', requested_at=now, task_id=None, refresh_id=None)
            self.save(ap)
            try:
                task = self.request('/devices/' + quote(ap['id'], safe='') + '/tasks', json.dumps({
                    'name': 'setParameterValues', 'parameterValues': [[p, *v] for p, v in changes.items()]}).encode())
                if not isinstance(task.get('_id'), str):
                    raise ValueError('ACS omitted task ID')
                record.update(phase='queued', task_id=task['_id'],
                              request_id=revision + ':' + str(int(now)))
            except Exception as exc:  # noqa: BLE001 - any submit failure is an unknown outcome
                record.update(phase='uncertain', error=type(exc).__name__)
            self.save(ap)

    def reconcile(self, devices):
        with self._lock:
            for device in devices:
                ap = next(({'id': device['_id'], 'virtual_mac': k} for k, r in self.records.items()
                           if r.get('device') == device.get('_id')), None)
                if not ap:
                    continue
                record = self.record(ap)
                if record.get('phase') not in ('queued', 'reading', 'submitting', 'uncertain'):
                    continue
                if record['phase'] in ('submitting', 'uncertain'):
                    record.update(phase='uncertain', error='Submission outcome unknown; no automatic retry')
                    self.save(ap)
                    continue
                changes = record['changes']
                requested_at = record.get('requested_at') or 0
                if all(field(device, p).get('_value') == v[0] and
                       (timestamp(field(device, p).get('_timestamp')) or 0) >= requested_at
                       for p, v in changes.items()):
                    record.update(phase='confirmed', ack_version=record['revision'],
                                  confirmed_version=record['revision'], confirmed_at=time.time(),
                                  error=None)
                    self.save(ap)
                    continue
                query = urlencode({'query': json.dumps({'device': ap['id']})})
                faults = self.request('/faults?' + query)
                ids = {record.get('task_id'), record.get('refresh_id')} - {None}
                if any(any(str(f.get('channel', '')).endswith(task) for task in ids) for f in faults):
                    record.update(phase='failed', error='ACS task fault')
                elif time.time() - record['requested_at'] > 300:
                    record.update(phase='failed', error='Readback timeout')
                else:
                    tasks = self.request('/tasks?' + query)
                    if not any(t.get('_id') in ids for t in tasks) and not record.get('refresh_id'):
                        result = self.request('/devices/' + quote(ap['id'], safe='') + '/tasks', json.dumps({
                            'name': 'getParameterValues', 'parameterNames': sorted(changes)}).encode())
                        record.update(phase='reading', refresh_id=result.get('_id'))
                self.save(ap)
