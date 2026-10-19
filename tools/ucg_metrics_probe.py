#!/usr/bin/env python3
"""Read-only UCG/UniFi probe for Network 11.x native metrics (stat_series + stat/device).

Reusable CLI; no credentials or device IDs are embedded. Intended for before/after
comparison of controller-native AP metrics. Makes GET requests only, plus one login.
"""
import argparse
import base64
import http.cookiejar
import json
import re
import ssl
import sys
import time
from typing import Any
import urllib.error
import urllib.parse
import urllib.request

AP_TRAFFIC = [
    'rxBytes', 'txBytes', 'rxPackets', 'txPackets', 'rxDroppedPackets', 'txDroppedPackets',
    'rxErrorPackets', 'txErrorPackets', 'wifiTxRetryPackets', 'wifiTxAttemptPackets',
    'wifiTxDroppedPackets', 'maxWifiTxRetryPct', 'avgTotalCuPct', 'avgRxSelfCuPct',
    'avgTxSelfCuPct', 'avgInterfCuPct', 'distinctClientCount', 'avgClientSignalDbm',
]
SYSTEM_HINTS = ('cpu', 'mem', 'uptime', 'load', 'temp')
DEFAULT_SCHEMAS = ['wirelessBySiteByDevice', 'wirelessTrafficBySiteByDevice',
                   'wirelessAnalyticsBySiteByDevice', 'systemBySiteByDevice']


class Probe:
    def __init__(self, base, creds_path, site='default', timeout=45, sleep=1.0, insecure=True):
        self.base = base.rstrip('/')
        self.site = site
        self.timeout = timeout
        self.sleep = sleep
        self.n = 0
        self._last = 0.0
        self.engine = None
        ctx = ssl.create_default_context()
        if insecure:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        self.jar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(self.jar),
            urllib.request.ProxyHandler({}),
            urllib.request.HTTPSHandler(context=ctx))
        with open(creds_path, 'r', encoding='utf-8') as handle:
            self._creds: dict[str, Any] = json.load(handle)
        self.csrf: str | None = None

    def call(self, path, method='GET', body=None):
        gap = self.sleep - (time.time() - self._last)
        if self.n and gap > 0:
            time.sleep(gap)
        self._last = time.time()
        self.n += 1
        headers = {'Content-Type': 'application/json', 'User-Agent': 'Mozilla/5.0'}
        if self.csrf and method != 'GET':
            headers['x-csrf-token'] = self.csrf
        req = urllib.request.Request(self.base + path, method=method, data=body, headers=headers)
        try:
            with self.opener.open(req, timeout=self.timeout) as r:
                raw = r.read().decode()
                return r.status, (json.loads(raw) if raw.strip() else None)
        except urllib.error.HTTPError as e:
            return e.code, None
        except Exception:
            return -1, None

    def login(self):
        body = json.dumps({'username': self._creds['username'],
                           'password': self._creds['password']}).encode()
        st, _ = self.call('/api/auth/login', 'POST', body)
        for c in self.jar:
            if c.name == 'TOKEN':
                parts = (c.value or '').split('.')
                try:
                    payload = json.loads(base64.urlsafe_b64decode(parts[1] + '==' * (-len(parts[1]) % 4)))
                    self.csrf = payload.get('csrfToken')
                except Exception:
                    self.csrf = None
        return st, bool(self.csrf)

    def proxy(self, path):
        return '/proxy/network' + path

    def stat_device(self):
        st, d = self.call(self.proxy('/api/s/%s/stat/device' % self.site))
        return st, (d.get('data') if isinstance(d, dict) else d) or []

    def schemas(self):
        st, d = self.call(self.proxy('/v2/api/stats/schemas'))
        data = d if isinstance(d, list) else (d.get('data') if isinstance(d, dict) else None)
        return st, (data or [])

    def series(self, schema, period, end_ms, filt=None, projection=None, no_gaps=False):
        q = {'schema': schema, 'period': period, 'end': end_ms}
        if filt:
            q['filter'] = filt
        if projection:
            q['projection'] = projection
        if no_gaps:
            q['noGaps'] = 'true'
        st, d = self.call(self.proxy('/v2/api/stats/recent/series?' + urllib.parse.urlencode(q)))
        return st, (d if isinstance(d, list) else (d.get('data') if isinstance(d, dict) else None))


def flatten(obj, prefix='', out=None):
    if out is None:
        out = {}
    if isinstance(obj, dict):
        for k, v in obj.items():
            flatten(v, (prefix + '.' + k) if prefix else k, out)
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            flatten(v, prefix, out)
    else:
        out.setdefault(prefix, []).append(obj)
    return out


def summarize_series(d):
    if not isinstance(d, list):
        return {'shape': 'non-list'}
    nkeys = len(d)
    buckets = 0
    ts = []
    stats = {}
    for o in d:
        ser = o.get('series') if isinstance(o, dict) else None
        if not isinstance(ser, list):
            continue
        for b in ser:
            if not isinstance(b, dict):
                continue
            buckets += 1
            if isinstance(b.get('timestamp'), (int, float)):
                ts.append(b['timestamp'])
            flat = flatten({k: v for k, v in b.items() if k not in ('timestamp', 'duration')})
            for path, vals in flat.items():
                s = stats.setdefault(path, {'present': 0, 'null': 0, 'zero': 0, 'nonzero': 0, 'sample': None})
                for v in vals:
                    s['present'] += 1
                    if v is None:
                        s['null'] += 1
                    elif isinstance(v, (int, float)):
                        if v == 0:
                            s['zero'] += 1
                        else:
                            s['nonzero'] += 1
                            if s['sample'] is None:
                                s['sample'] = v
                    else:
                        s['nonzero'] += 1
    out = {'key_objects': nkeys, 'buckets': buckets,
           'ts_min': min(ts) if ts else None, 'ts_max': max(ts) if ts else None,
           'fields': stats}
    if buckets == 0:
        out['note'] = ('no buckets returned for this window/filter; this does not '
                       'establish whether history is enabled. No data is backfilled '
                       'or fabricated by this probe')
    return out


def build_projection(schema_obj, desired):
    values = schema_obj.get('values') or []
    top = [f for f in desired if f in values]
    parts = []
    if top:
        parts.append('values(' + ','.join(top) + ')')
    for grp in schema_obj.get('nested') or []:
        gname = grp.get('name') if isinstance(grp, dict) else None
        gvals = grp.get('values') or [] if isinstance(grp, dict) else []
        gtop = [f for f in desired if f in gvals]
        if gname and gtop:
            parts.append('nested(%s(values(%s)))' % (gname, ','.join(gtop)))
    return ','.join(parts)


def main():
    ap = argparse.ArgumentParser(description='Read-only UCG Network 11.x native metrics probe')
    ap.add_argument('--base', required=True, help='controller base URI, e.g. https://192.0.2.1')
    ap.add_argument('--credentials', required=True, help='path to JSON {username,password}')
    ap.add_argument('--site', default='default')
    ap.add_argument('--device-mac', action='append', default=[], help='AP device MAC (repeatable)')
    ap.add_argument('--period', default='HOUR', choices=['HOUR', 'DAY', 'WEEK', 'MONTH'])
    ap.add_argument('--schemas', default=','.join(DEFAULT_SCHEMAS))
    ap.add_argument('--no-gaps', action='store_true')
    ap.add_argument('--sleep', type=float, default=1.0)
    ap.add_argument('--json', action='store_true', help='emit JSON instead of text')
    args = ap.parse_args()

    p = Probe(args.base, args.credentials, args.site, sleep=args.sleep)
    out: dict[str, Any] = {'requests': []}
    st, csrf = p.login()
    out['login'] = {'status': st, 'csrf_derived': csrf}
    if st == 403:
        out['login']['note'] = 'HTTP 403: read-only role or rejected login; never treated as success'

    st, devs = p.stat_device()
    out['requests'].append({'path': '/stat/device', 'status': st})
    if st == 403:
        out['requests'][-1]['note'] = ('HTTP 403: read-only role or missing CSRF token; '
                                       'never treated as success')
    want = [m.lower() for m in args.device_mac]
    aps = []
    for d in devs:
        if not isinstance(d, dict):
            continue
        is_ap = str(d.get('type', '')).startswith('uap') or 'radio_table' in d
        if not is_ap:
            continue
        mac = (d.get('mac') or '').lower()
        if want and mac not in want:
            continue
        flat = flatten({k: d.get(k) for k in ('system-stats', 'sys_stats') if k in d})
        aps.append({
            'index': len(aps), 'matched_requested_mac': mac in want if want else None,
            'model': d.get('model'), 'state': d.get('state'), 'version': d.get('version'),
            'uptime_seconds': d.get('uptime'),
            'has_system_stats': 'system-stats' in d, 'has_sys_stats': 'sys_stats' in d,
            'device_stats_leaf_count': len(flat),
            'hardware_leaves': {k: v[:1] for k, v in flat.items()
                                if any(h in k.lower() for h in SYSTEM_HINTS)},
            'note': 'sys/system-stats = controller-reported, derived (not raw physical sensor); verify in UI',
        })
    out['aps'] = aps
    out['ap_count'] = len(aps)
    out['ap_states'] = sorted(a['state'] for a in aps)

    st, sch = p.schemas()
    out['requests'].append({'path': '/v2/api/stats/schemas', 'status': st})
    by_name = {s.get('name'): s for s in sch if isinstance(s, dict)}
    out['schema_count'] = len(sch)

    end = int(time.time() * 1000)
    filt = None
    if args.device_mac:
        filt = 'deviceMac.in(' + ','.join("'%s'" % m.lower() for m in args.device_mac) + ')'
    for name in [s.strip() for s in args.schemas.split(',') if s.strip()]:
        obj = by_name.get(name)
        if not obj:
            out.setdefault('series', {})[name] = {'status': 'schema-not-declared'}
            continue
        desired = AP_TRAFFIC if 'system' not in name else list(AP_TRAFFIC)
        if 'system' in name:
            declared = obj.get('values') or []
            desired = [f for f in declared if any(h in f.lower() for h in SYSTEM_HINTS)]
        proj = build_projection(obj, desired)
        st, d = p.series(name, args.period, end, filt, proj, args.no_gaps)
        out['requests'].append({'path': '/v2/api/stats/recent/series', 'schema': name, 'status': st})
        entry = {'status': st, 'projection': proj,
                 'note': ('HTTP 403: read-only role or missing CSRF token; never treated as success'
                          if st == 403 else None),
                 'declared_values': obj.get('values'),
                 'declared_nested': [g.get('name') for g in (obj.get('nested') or []) if isinstance(g, dict)]}
        if st == 200:
            entry.update(summarize_series(d))
            entry['native_metric_note'] = (
                'Controller-native series; verify source scope, units and UI separately. '
                'Field presence alone does not establish a physical AP measurement.')
        out.setdefault('series', {})[name] = entry

    out['requests_total'] = p.n
    if args.json:
        print(json.dumps(out, ensure_ascii=False, indent=2))
    else:
        print(json.dumps(out, ensure_ascii=False))


if __name__ == '__main__':
    main()
