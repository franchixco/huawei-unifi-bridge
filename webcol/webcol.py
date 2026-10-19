#!/usr/bin/env python3
"""Huawei telemetry collector with a direct API and optional browser fallback."""

import asyncio
import importlib
import ipaddress
import json
import logging
import os
import re
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeout
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

# huawei_api and inventory live next to this file, which is not on sys.path
# when the test suite imports webcol from the project root.
_SELF_DIR = str(Path(__file__).resolve().parent)
if _SELF_DIR not in sys.path:
    sys.path.insert(0, _SELF_DIR)
huawei_api = importlib.import_module('huawei_api')
inventory = importlib.import_module('inventory')
webonly = importlib.import_module('webonly')
operation_service = importlib.import_module('operation_service')

LOG = logging.getLogger('webcol')

BROWSERLESS_URL = os.environ.get('BROWSERLESS_URL', 'ws://127.0.0.1:3000?stealth=1')
INTERVAL = int(os.environ.get('INTERVAL_SECONDS', '60'))
PORT = int(os.environ.get('PORT', '7560'))
TTL_SECONDS = int(os.environ.get('WEBENRICH_TTL', '600'))
MAX_BACKOFF = int(os.environ.get('WEBENRICH_MAX_BACKOFF', '900'))
LOGIN_BACKOFF = int(os.environ.get('WEBENRICH_LOGIN_BACKOFF', '300'))
# Hard bound waiting for the direct session to finish. The client also carries
# its own monotonic total budget (DIRECT_TOTAL_SECONDS), so a healthy session
# ends before this bound and no thread is abandoned mid-authentication.
DIRECT_BUDGET_SECONDS = float(os.environ.get('WEBENRICH_DIRECT_BUDGET', '30'))
DIRECT_TOTAL_SECONDS = float(os.environ.get('WEBENRICH_DIRECT_TOTAL', '25'))
DIRECT_ONLY = os.environ.get('WEBENRICH_DIRECT_ONLY', '').strip().lower() in ('1', 'true', 'yes', 'on')
# Explicit local opt-in only: the deployed CPE UI serves a self-signed
# certificate, so deployment sets WEBENRICH_VERIFY_TLS=false. Default is to
# verify; this never becomes a global default.
DIRECT_VERIFY_TLS = os.environ.get('WEBENRICH_VERIFY_TLS', '').strip().lower() not in (
    '0', 'false', 'no', 'off')
HTTP_TIMEOUT_SECONDS = float(os.environ.get('WEBENRICH_HTTP_TIMEOUT', '8'))
STATE_DIR = os.environ.get('WEBCOL_STATE_DIR', '/data')
INVENTORY_STATE_FILE = os.path.join(STATE_DIR, 'inventory_state.json')
ROUTER_BUDGET_SECONDS = 60.0
CLEANUP_SECONDS = 5.0
ROUTER_GAP_SECONDS = 3.0
UA = ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/152.0.0.0 Safari/537.36")

MAC_PATTERN = re.compile(r'(?:[0-9a-f]{2}:){5}[0-9a-f]{2}', re.IGNORECASE)

# Failure stages that mean the router UI refused or challenged the login.
# Retrying these every interval can lock the account out, so they back off hard.
LOGIN_STAGES = frozenset({'no-input', 'no-button', 'login-ui', 'nonce', 'proof',
                          'no-csrf', 'credentials', 'locked'})

# Direct stages eligible for the browserless fallback: transient API
# incompatibilities only. Transport failures, timeouts, credential rejections
# and lockouts never open a second login path.
FALLBACK_ELIGIBLE = frozenset({'deviceinfo-schema', 'hostinfo-schema', 'wifi-schema',
                               'parse', 'extract-error', 'csrf-retry-exhausted',
                               'response-too-large', 'schema-invalid'})

# Direct outcomes that mean the router refused or could not prove authenticity:
# never open a second login path, always take the >= LOGIN_BACKOFF window.
BLOCKED_LOGIN_REASONS = frozenset({'credentials', 'locked', 'server-proof'})
SKIP_STAGES = frozenset({'direct-active', 'circuit-open'})

LOCK = threading.Lock()
DATA: dict[str, Any] = {'routers': {}, 'updated_at': None, 'webonly': {}, 'webonly_at': None}

OPERATIONS_MAX_BODY = 65536
ADMIN_TIMEOUT_SECONDS = float(os.environ.get('WEBCOL_ADMIN_TIMEOUT', '40'))
GATE_DENY_REASONS = frozenset({
    'writes_disabled', 'destructive_approval_required', 'destructive_approval_reused',
    'capability_unverified', 'unverified_write_disabled', 'operation_not_allowlisted',
    'resolve_disabled', 'target_not_allowlisted', 'unauthorized',
})
BUSY_REASONS = frozenset({
    'router_busy', 'router_operation_locked', 'replay_conflict', 'stale_snapshot',
})

LISTEN_HOST = (os.environ.get('WEBCOL_LISTEN_HOST') or '127.0.0.1').strip() or '127.0.0.1'


def _allowed_host_names():
    names = {'localhost', '127.0.0.1', '::1'}
    if LISTEN_HOST not in ('0.0.0.0', '::'):
        names.add(LISTEN_HOST.strip('[]').lower())
    for item in (os.environ.get('WEBCOL_ALLOWED_HOSTS') or '').split(','):
        item = item.strip().lower()
        if item:
            names.add(item)
    return frozenset(names)


ALLOWED_HOSTS = _allowed_host_names()
ALLOWED_ORIGINS = frozenset(
    item.strip() for item in (os.environ.get('WEBCOL_ALLOWED_ORIGINS') or '').split(',')
    if item.strip()
)


def service_http_status(result):
    if not isinstance(result, dict):
        return 500
    status = result.get('status')
    if status == 'ok' and result.get('outcome') == 'rejected':
        reason = result.get('reason')
        if reason in BUSY_REASONS:
            return 409
        if reason in GATE_DENY_REASONS:
            return 403
        return 400
    if status in ('ok', 'uncertain'):
        return 200
    if status == 'busy':
        return 409
    if status == 'missing':
        return 404
    if status == 'denied':
        reason = result.get('reason')
        if reason in BUSY_REASONS:
            return 409
        if reason in GATE_DENY_REASONS:
            return 403
        return 400
    return 500


def routers(config=None):
    result = []
    raw = os.environ.get('WEBROUTERS', '') if config is None else config
    for item in raw.split(','):
        item = item.strip()
        if not item:
            continue
        host, sep, password = item.rpartition('=')
        host = host.strip()
        hostname = urlsplit(host).hostname if sep else None
        if host.startswith('http') and password and hostname and '=' not in hostname:
            result.append((host, password))
        else:
            LOG.warning('WEBROUTERS: entrada invalida ignorada')
    return result


def router_ip(host):
    try:
        return str(ipaddress.ip_address(urlsplit(host).hostname))
    except (ValueError, TypeError):
        return None


def failure_delay(failures, login_failure):
    delay = min(INTERVAL * (2 ** max(0, failures - 1)), MAX_BACKOFF)
    return max(delay, LOGIN_BACKOFF) if login_failure else delay


def normalize_browserless(raw, now=None):
    """Normalize raw browser payloads into the direct API's published schema.

    Reuses huawei_api parsers so a fallback collection has the same device,
    native profile ids, per-client fields, counters and inventory shape as the
    direct transport; a malformed payload never becomes a valid collection.
    """
    if not isinstance(raw, dict):
        return None
    device = huawei_api.parse_deviceinfo(raw.get('deviceinfo'))
    clients = huawei_api.parse_hostinfo(raw.get('hostinfo'))
    wlan = huawei_api.parse_wlanguide(raw.get('wifi'))
    if device is None or clients is None or wlan is None:
        return None
    if not device.get('serial_number'):
        return None
    now = time.time() if now is None else now
    guest = huawei_api.parse_guest_ssids(raw.get('guest'))
    stats = huawei_api.parse_processstatus(raw.get('processstatus'))
    profiles = wlan.get('profiles', [])
    ssids = [{'band': p.get('band'), 'ssid': p.get('ssid'),
              'channel_configured': p.get('channel_configured'), 'enabled': p.get('enabled'),
              'power': p.get('power'), 'wmm': p.get('wmm'), 'standard': p.get('standard'),
              'usage': p.get('usage')} for p in profiles]
    return {'ok': True, 'transport': 'browserless', 'logged_in': True,
            'clients': clients, 'ssids': ssids, 'device': device,
            'inventory': wlan,
            'version': device.get('software_version'),
            'stats': stats, 'stats_reason': None if stats is not None else 'unsupported',
            'stats_observed_at': now if stats is not None else None,
            'topology_supported': None,
            'guest_api_supported': guest is not None}


def valid_fallback(result):
    """A fallback success must carry the CPE serial and a real profile inventory."""
    if not valid_collection(result):
        return False
    device = result.get('device')
    inventory_view = result.get('inventory')
    if not isinstance(device, dict) or not device.get('serial_number'):
        return False
    if not isinstance(inventory_view, dict) or not inventory_view.get('profiles'):
        return False
    return True


def valid_collection(result):
    # Publisher-side schema gate: "fresh" is only claimed for well-formed
    # collections. A zero client list from a valid array is legitimate; a
    # malformed HostInfo/WifiConfig/deviceinfo never is.
    if not isinstance(result, dict) or not result.get('ok'):
        return False
    if not isinstance(result.get('clients'), list) or not isinstance(result.get('ssids'), list):
        return False
    return all(isinstance(c, dict) and MAC_PATTERN.fullmatch(str(c.get('mac') or ''))
               for c in result['clients'])


def merge_into_data(host, result, now=None):
    now = time.time() if now is None else now
    serial = (result.get('device') or {}).get('serial_number')
    clients = {}
    for client in result.get('clients', []):
        address = (client.get('mac') or '').upper()
        if address:
            clients[address] = {**client, 'mac': address, '_ts': now, '_serial': serial,
                                '_source': 'huawei-web:HostInfo'}
    entry = {'updated_at': now, 'observed_at': now, 'serial': serial,
             'version': result.get('version'),
             'router_ip': router_ip(host), 'ssids': result.get('ssids', []),
             'clients': clients, 'transport': result.get('transport'),
             'device': result.get('device'), 'inventory': result.get('inventory'),
             'stats': result.get('stats'), 'stats_reason': result.get('stats_reason'),
             'stats_observed_at': result.get('stats_observed_at') if result.get('stats') else None,
             'topology_supported': result.get('topology_supported'),
             'guest_api_supported': result.get('guest_api_supported')}
    with LOCK:
        DATA['routers'][host] = entry
        DATA['updated_at'] = now


def register_routers(hosts, now=None):
    # Every configured router appears in /health even before its first success,
    # so an unreachable router can never look healthy by absence.
    now = time.time() if now is None else now
    with LOCK:
        for host in hosts:
            if host not in DATA['routers']:
                DATA['routers'][host] = {'updated_at': None, 'observed_at': None, 'serial': None,
                                         'version': None,
                                         'router_ip': router_ip(host), 'ssids': [],
                                         'clients': {}, 'transport': None,
                                         'device': None, 'inventory': None,
                                         'stats': None, 'stats_reason': None,
                                         'stats_observed_at': None,
                                         'topology_supported': None,
                                         'guest_api_supported': None}


def register_webonly_routers(hosts, now=None):
    now = time.time() if now is None else now
    with LOCK:
        for host in hosts:
            if host not in DATA['webonly']:
                DATA['webonly'][host] = {
                    'observed_at': None, 'serial': None, 'device': None, 'clients': [],
                    'inventory': None, 'stats': None, 'stats_reason': None,
                    'stats_observed_at': None, 'router_ip': webonly.router_ip(host),
                    'transport': None, 'source_type': webonly.SOURCE_TYPE, 'fresh': False}


def merge_webonly(host, record, now=None):
    now = time.time() if now is None else now
    with LOCK:
        DATA['webonly'][host] = dict(record, observed_at=now)
        DATA['webonly_at'] = now


def snapshot_webonly(now=None) -> dict[str, Any]:
    now = time.time() if now is None else now
    with LOCK:
        entries = {host: dict(entry) for host, entry in (DATA.get('webonly') or {}).items()}
        updated_at = DATA.get('webonly_at')
    routers = {}
    for host, entry in entries.items():
        seen = entry.get('observed_at')
        routers[host] = {**entry, 'last_seen': seen, 'source_type': entry.get('source_type'),
                         'fresh': bool(seen) and 0 <= now - seen <= TTL_SECONDS}
    return {'schema_version': webonly.SCHEMA_VERSION, 'updated_at': updated_at,
            'ttl_seconds': TTL_SECONDS, 'routers': routers}


def snapshot(now=None) -> dict[str, Any]:
    # Built entirely under the lock into a private copy: HTTP readers never see
    # a torn view and never mutate shared state.
    now = time.time() if now is None else now
    with LOCK:
        entries = {host: dict(entry) for host, entry in DATA['routers'].items()}
        updated_at = DATA['updated_at']
    by_mac = {}
    view = {}
    for host, entry in entries.items():
        refreshed = entry.get('updated_at', 0)
        clients = entry.get('clients') or {}
        stats_at = entry.get('stats_observed_at')
        view[host] = {'updated_at': refreshed, 'observed_at': refreshed,
                      'serial': entry.get('serial'),
                      'router_ip': entry.get('router_ip'),
                      'version': entry.get('version'), 'clients': len(clients),
                      'ssids': entry.get('ssids', []),
                      'transport': entry.get('transport'),
                      'device': entry.get('device'),
                      'inventory': entry.get('inventory'),
                      'stats': entry.get('stats'), 'stats_reason': entry.get('stats_reason'),
                      'stats_observed_at': stats_at,
                      'stats_fresh': bool(entry.get('stats')) and isinstance(stats_at, (int, float))
                      and 0 <= now - stats_at <= TTL_SECONDS,
                      'topology_supported': entry.get('topology_supported'),
                      'guest_api_supported': entry.get('guest_api_supported'),
                      'last_success_age': round(now - refreshed) if refreshed else None,
                      'fresh': bool(refreshed) and now - refreshed <= TTL_SECONDS}
        for address, client in clients.items():
            seen = client.get('_ts', 0)
            if now - seen > TTL_SECONDS:
                continue
            current = {**client, 'router': host, 'router_ip': entry.get('router_ip'), '_ts': seen}
            previous = by_mac.get(address)
            if previous is None or seen > previous['_ts']:
                by_mac[address] = current
    return {'updated_at': updated_at, 'ttl_seconds': TTL_SECONDS, 'schema_version': 2,
            'routers': view, 'by_mac': by_mac}


# Bounds the response body read, not just the headers: the AbortController
# timer is still armed while `response.json()` is awaited, so a peer that sends
# headers fast and then stalls the body cannot hang the whole session. Shared by
# the login/extract and logout scripts, and executed directly by the offline
# node test, so both paths are covered by one definition.
JS_FETCH_JSON_HELPER = r"""
    const fetchJson = async (p, options = {}, ms = 5000, remaining = null) => {
        const budget = remaining ? Math.min(ms, remaining()) : ms;
        if (budget <= 0) throw new Error("budget");
        const ctrl = new AbortController();
        const timer = setTimeout(() => ctrl.abort(), budget);
        try {
            const response = await fetch(p, {...options, signal: ctrl.signal});
            return await response.json();
        } finally { clearTimeout(timer); }
    };
"""

LOGIN_AND_EXTRACT = (
    r"""async ([password]) => {
    const hex = (buf) => Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, "0")).join("");
    const startedAt = Date.now();
    const TOTAL_MS = 45000;
    const remaining = () => Math.max(0, TOTAL_MS - (Date.now() - startedAt));
"""
    + JS_FETCH_JSON_HELPER
    + r"""
    const jget = (p, ms = 5000) => fetchJson(
        p, {headers: {"_ResponseFormat": "JSON"}, credentials: "same-origin"}, ms, remaining);
    const wait = (ms) => new Promise(resolve => setTimeout(resolve, ms));

    document.location.hash = "#/login";
    await wait(600);
    const input = document.querySelector('input[name="password"], input[type="password"]');
    if (!input) return {ok: false, stage: "no-input"};

    const setter = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, "value").set;
    setter.call(input, password);
    input.dispatchEvent(new Event("input", {bubbles: true}));
    await wait(400);
    // Single verified submit: clicking the located button only. No synthetic
    // Enter fallback: a double submit is how accounts get locked out.
    const btn = Array.from(document.querySelectorAll("div,button,span")).find(el =>
        el.children.length === 0 && /^(Log In|Iniciar sesión|Login)$/i.test(el.textContent.trim()));
    if (!btn) return {ok: false, stage: "no-button"};
    btn.click();
    await wait(2500);
    if (!document.location.hash.includes("#/home")) {
        await wait(4000);
        if (!document.location.hash.includes("#/home")) {
            return {ok: false, stage: "login-ui", hash: document.location.hash};
        }
    }

    const di = await jget("/api/system/deviceinfo");
    if (!di || typeof di !== "object" || Array.isArray(di) ||
        typeof di.SoftwareVersion !== "string" || !di.SoftwareVersion) {
        return {ok: false, stage: "deviceinfo-schema", logged_in: true};
    }
    let hostinfo, wifi;
    try {
        hostinfo = await jget("/api/system/HostInfo");
        wifi = await jget("/api/ntwk/WlanGuideBasic?type=notshowpassall");
    } catch (e) {
        return {ok: false, stage: "extract-error", logged_in: true};
    }
    if (!Array.isArray(hostinfo)) return {ok: false, stage: "hostinfo-schema", logged_in: true};
    if (!wifi || typeof wifi !== "object" || Array.isArray(wifi) || !Array.isArray(wifi.WifiConfig)) {
        return {ok: false, stage: "wifi-schema", logged_in: true};
    }
    let guest = null;
    try { guest = await jget("/api/ntwk/guest_network?type=notshowpassall", 4000); } catch (e) { guest = null; }
    // The optional gauge gets its own small budget and never discards the valid
    // core: if the body stalls, fetchJson aborts (timer still armed through the
    // body parse), the error is swallowed here, and stats stays null.
    let processstatus = null;
    try { processstatus = await jget("/api/system/processstatus", 2500); } catch (e) { processstatus = null; }
    // Raw payloads only: Python normalizes them with the same shared parsers as
    // the direct API. The WiFi config may contain masked keys and is never
    // stored or logged; nothing here is published verbatim.
    // Logout runs as a separate bounded evaluate afterwards; failing here must
    // still report the extraction and leave the session for that cleanup.
    return {ok: true, logged_in: true,
            raw: {deviceinfo: di, hostinfo, wifi, guest, processstatus}};
}"""
)

LOGOUT_SCRIPT = r"""async () => {
    const fetchJson = async (p, options = {}, ms = 4000) => {
        const ctrl = new AbortController();
        const timer = setTimeout(() => ctrl.abort(), ms);
        try {
            const r = await fetch(p, {...options, signal: ctrl.signal});
            let body = null;
            try { body = await r.json(); } catch (e) { body = null; }
            return {ok: r.ok, status: r.status, body: body};
        } finally { clearTimeout(timer); }
    };
    try {
        const di = (await fetchJson("/api/system/deviceinfo",
            {headers: {"_ResponseFormat": "JSON"}, credentials: "same-origin"})).body;
        const csrf = (di && di.csrf_param && di.csrf_token)
            ? {csrf_param: di.csrf_param, csrf_token: di.csrf_token} : null;
        const r = await fetchJson("/api/system/user_logout", {method: "POST", credentials: "same-origin",
            headers: {"Content-Type": "application/json; charset=UTF-8", "_ResponseFormat": "JSON"},
            body: JSON.stringify(csrf ? {data: {}, csrf: csrf} : {})});
        // HTTP 200 alone is not success: an application rejection carries a
        // non-zero err/errcode/errorcode even with a 200 status.
        const body = r.body;
        const rejected = body && typeof body === "object" &&
            ((body.err !== undefined && body.err !== 0) ||
             (body.errcode !== undefined && body.errcode !== 0) ||
             (body.errorcode !== undefined && body.errorcode !== 0));
        return {ok: r.ok && !rejected, status: r.status};
    } catch (e) {
        return {ok: false};
    }
}"""


async def close_quietly(ctx):
    try:
        await asyncio.wait_for(ctx.close(), timeout=CLEANUP_SECONDS)
    except Exception:
        pass


async def attempt_logout(page, result):
    # Bounded, separate evaluation: even a failed extraction or a budget
    # timeout must not leave an authenticated router session open.
    try:
        outcome = await asyncio.wait_for(page.evaluate(LOGOUT_SCRIPT), timeout=CLEANUP_SECONDS)
        result['logout'] = 'ok' if isinstance(outcome, dict) and outcome.get('ok') else 'invalid'
    except Exception:
        result['logout'] = 'failed'


async def collect_router(browser, host, password):
    result = {"ok": False, "stage": "unknown"}
    ctx = None
    page = None

    async def session():
        # Setup and extraction share one total budget: a pending CDP call in
        # new_context/new_page/add_init_script must never stall the cycle.
        nonlocal ctx, page
        expected = urlsplit(host)
        expected_origin = (expected.scheme, expected.netloc)

        async def same_origin_only(route):
            target = urlsplit(route.request.url)
            if (target.scheme, target.netloc) == expected_origin:
                await route.continue_()
            else:
                await route.abort()

        ctx = await browser.new_context(
            ignore_https_errors=True, viewport={"width": 1366, "height": 850},
            user_agent=UA, locale="en-US",
        )
        try:
            await ctx.route('**/*', same_origin_only)
        except (AttributeError, TypeError):
            pass  # A test double without routing still gets the landed-origin gate.
        page = await ctx.new_page()
        await ctx.add_init_script(
            "Object.defineProperty(navigator, 'webdriver', {get: () => undefined});"
        )
        await page.goto(host + "/html/index.html", timeout=30000, wait_until="domcontentloaded")
        await page.wait_for_timeout(1200)
        landed = urlsplit(getattr(page, 'url', '') or host)
        if (landed.scheme, landed.netloc) != expected_origin:
            raise RuntimeError('origin-mismatch')
        return await page.evaluate(LOGIN_AND_EXTRACT, [password])

    try:
        result = await asyncio.wait_for(session(), timeout=ROUTER_BUDGET_SECONDS)
        if not isinstance(result, dict):
            result = {"ok": False, "stage": "invalid-result"}
        elif result.get('ok') and isinstance(result.get('raw'), dict):
            normalized = normalize_browserless(result['raw'])
            if normalized is None:
                result = {"ok": False, "stage": "normalize-error", "logged_in": True}
            else:
                result = normalized
    except asyncio.TimeoutError:
        # Login state is unknowable at the deadline: attempt the bounded
        # logout rather than risk an open session.
        result = {"ok": False, "stage": "timeout", "logged_in": True}
    except Exception as exc:
        # Never echo exception text: playwright errors can embed evaluated
        # arguments, and the password is one of them. Authentication state is
        # uncertain after any failure once a page exists.
        result = {"ok": False, "stage": "exception:" + type(exc).__name__}
    finally:
        if page is not None:
            await attempt_logout(page, result)
        if ctx is not None:
            await close_quietly(ctx)
    return result


class Collector:
    def __init__(self, direct_factory=None, direct_verify_tls=None):
        self.playwright = None
        self.browser = None
        self.failures = {}
        self.next_attempt = {}
        self.last_stage = {}
        self.host_locks = {}
        self.credential_failures = {}
        self.credential_block = {}
        self.transport_counts = {}
        self.last_success = {}
        self.direct_factory = direct_factory
        self.direct_verify_tls = DIRECT_VERIFY_TLS if direct_verify_tls is None else bool(direct_verify_tls)
        self._direct_executor = None
        self.direct_pending = {}
        self.ops_pending = {}
        # Global bound: at most two collection sessions at once. Normal CPEs and
        # web-only CPEs are dispatched on separate tasks so one slow/failing
        # web-only poll can never hold the normal CPE poll beyond its own budget.
        self.poll_semaphore = asyncio.Semaphore(2)

    async def ensure_browser(self):
        if self.browser is not None:
            if self.browser.is_connected():
                return
            try:
                await self.browser.close()
            except Exception:
                pass
            self.browser = None
        if self.playwright is None:
            browser_api = importlib.import_module('playwright.async_api')
            self.playwright = await browser_api.async_playwright().start()
        self.browser = await self.playwright.chromium.connect_over_cdp(BROWSERLESS_URL, timeout=15000)

    def due(self, host, now=None):
        return (time.monotonic() if now is None else now) >= self.next_attempt.get(host, 0)

    def lock(self, host):
        return self.host_locks.setdefault(host, asyncio.Lock())

    def credential_blocked(self, host, now=None):
        return (time.monotonic() if now is None else now) < self.credential_block.get(host, 0.0)

    def record_credential_failure(self, host, now=None):
        # Circuit breaker: credential rejections grow the lockout window
        # geometrically (300 s floor, 900 s cap). The router already said no.
        now = time.monotonic() if now is None else now
        count = self.credential_failures.get(host, 0) + 1
        self.credential_failures[host] = count
        delay = min(LOGIN_BACKOFF * 2 ** max(0, count - 1), MAX_BACKOFF)
        self.credential_block[host] = now + delay
        return delay

    def record_failure(self, host, stage, now=None):
        now = time.monotonic() if now is None else now
        count = self.failures.get(host, 0) + 1
        self.failures[host] = count
        self.last_stage[host] = stage
        delay = failure_delay(count, stage in LOGIN_STAGES)
        self.next_attempt[host] = now + delay
        LOG.warning('%s FAIL (%s): reintento en %ss', host, stage, delay)

    def record_success(self, host):
        self.failures[host] = 0
        self.next_attempt[host] = 0
        self.last_stage.pop(host, None)
        self.credential_failures.pop(host, None)
        self.credential_block.pop(host, None)

    def state_view(self, now=None):
        now = time.monotonic() if now is None else now
        with LOCK:
            keys = set(self.failures) | set(self.next_attempt) | set(self.last_stage) \
                | set(self.credential_block)
            return {host: {'failures': self.failures.get(host, 0),
                           'retry_in': max(0, round(self.next_attempt.get(host, 0) - now)),
                           'last_stage': self.last_stage.get(host),
                           'credential_block_in': max(0, round(self.credential_block.get(host, 0) - now)),
                           'credential_failures': self.credential_failures.get(host, 0)}
                    for host in keys}

    def transport_view(self):
        return {host: dict(counts) for host, counts in self.transport_counts.items()}

    def last_success_view(self, now=None):
        with LOCK:
            successes = dict(self.last_success)
        return {host: (round(time.time() - at) if at else None)
                for host, at in successes.items()}

    def _build_direct_client(self, host, password):
        if self.direct_factory is not None:
            return self.direct_factory(host, password)
        return huawei_api.HuaweiDirectClient(
            host, password, request_timeout=HTTP_TIMEOUT_SECONDS,
            total_budget=DIRECT_TOTAL_SECONDS, verify_tls=self.direct_verify_tls)

    def _direct_worker(self, host, password):
        try:
            result = self._build_direct_client(host, password).collect()
        except Exception as exc:
            result = {'ok': False, 'stage': 'exception:' + type(exc).__name__}
        if not isinstance(result, dict):
            result = {'ok': False, 'stage': 'exception:InvalidResult'}
        result.setdefault('transport', 'direct')
        return result

    def direct_active(self, host):
        future = self.direct_pending.get(host)
        if future is None:
            return False
        if future.done():
            self.direct_pending.pop(host, None)
            return False
        return True

    def session_active(self, host):
        # A collection session and an admin operation for the same host never
        # overlap: either pending future marks the host busy.
        for pending in (self.direct_pending, self.ops_pending):
            future = pending.get(host)
            if future is None:
                continue
            if future.done():
                pending.pop(host, None)
                continue
            return True
        return False

    def register_ops_future(self, host, future):
        self.ops_pending[host] = future

    def clear_ops_future(self, host, future):
        if self.ops_pending.get(host) is future:
            self.ops_pending.pop(host, None)

    async def collect_direct(self, host, password):
        # A dedicated worker plus a shield means a slow router never leaves a
        # live session running while a second transport starts: on timeout the
        # host is reported busy and skipped until the client's own bounded
        # deadline ends the session.
        loop = asyncio.get_running_loop()
        if self._direct_executor is None:
            self._direct_executor = ThreadPoolExecutor(max_workers=2,
                                                       thread_name_prefix='webcol-direct')
        future = loop.run_in_executor(self._direct_executor, self._direct_worker, host, password)
        self.direct_pending[host] = future
        try:
            return await asyncio.wait_for(asyncio.shield(future), timeout=DIRECT_BUDGET_SECONDS)
        except asyncio.TimeoutError:
            return {'ok': False, 'stage': 'direct-active', 'transport': 'direct', 'active': True}
        finally:
            if future.done():
                self.direct_pending.pop(host, None)

    def build_inventory(self, result):
        state = inventory.load_state(INVENTORY_STATE_FILE)
        built = inventory.build_inventory(result.get('inventory'), tr098_radios=None,
                                          device=result.get('device'), previous_state=state,
                                          now=time.time())
        persisted = inventory.save_state(INVENTORY_STATE_FILE, built.get('registry'))
        result = dict(result)
        result['inventory'] = built
        result['inventory_persisted'] = persisted
        return result

    async def collect_host(self, ensure_browser, host, password, direct_only=False) -> dict[str, Any]:
        # Whole per-CPE session under one lock: the direct transport and the
        # browserless fallback never run concurrently for the same router.
        async with self.lock(host):
            now = time.monotonic()
            if self.session_active(host):
                return {'ok': False, 'stage': 'direct-active', 'transport': 'direct'}
            if self.credential_blocked(host, now):
                return {'ok': False, 'stage': 'circuit-open',
                        'credential_block_in': round(self.credential_block[host] - now)}
            try:
                direct = await self.collect_direct(host, password)
            except Exception as exc:
                direct = {'ok': False, 'stage': 'exception:' + type(exc).__name__,
                          'transport': 'direct'}
            if direct.get('stage') == 'direct-active':
                return direct
            direct.setdefault('transport', 'direct')
            if direct.get('ok') and valid_collection(direct):
                self.transport_counts.setdefault(host, {'direct': 0, 'browserless': 0})['direct'] += 1
                return direct
            reason = direct.get('reason')
            if direct.get('login_rejected') or reason in BLOCKED_LOGIN_REASONS:
                delay = self.record_credential_failure(host)
                LOG.warning('%s login rechazado por el router: sin reintento ni fallback por %ss',
                            host, delay)
                return direct
            stage = 'schema-invalid' if direct.get('ok') else str(direct.get('stage'))
            if direct_only:
                # A web-only CPE is never allowed to open a browser session, not
                # even after a network or schema error: the fallback would fill
                # the admin password into whatever page the browser lands on.
                result = dict(direct)
                result.setdefault('transport', 'direct')
                result['browserless_unavailable'] = True
                result['browserless_skipped'] = 'webonly-direct-only'
                return result
            if DIRECT_ONLY or stage not in FALLBACK_ELIGIBLE:
                return direct
            try:
                await ensure_browser()
            except Exception as exc:
                LOG.warning('browserless no disponible para fallback: %s', type(exc).__name__)
                self.browser = None
                direct = dict(direct)
                direct['browserless_unavailable'] = True
                return direct
            try:
                result = await collect_router(self.browser, host, password)
            except Exception as exc:
                result = {'ok': False, 'stage': 'exception:' + type(exc).__name__}
            result['transport'] = 'browserless'
            result['direct_stage'] = stage
            if result.get('ok') and valid_fallback(result):
                self.transport_counts.setdefault(host, {'direct': 0, 'browserless': 0})['browserless'] += 1
            return result

    async def cycle(self):
        register_routers([host for host, _ in routers()])
        register_webonly_routers([host for host, _ in webonly.webonly_routers()])
        # Normal and web-only polls run as independent tasks (bounded by the
        # shared semaphore): a slow web-only poll overlaps instead of delaying
        # the normal CPE refresh.
        await asyncio.gather(self.cycle_normal(), self.cycle_webonly())

    async def collect_bounded(self, host, password, direct_only=False):
        async with self.poll_semaphore:
            return await self.collect_host(self.ensure_browser, host, password,
                                           direct_only=direct_only)

    async def cycle_normal(self):
        for host, password in routers():
            if not self.due(host):
                continue
            try:
                result = await self.collect_bounded(host, password)
            except Exception as exc:
                self.record_failure(host, 'exception:' + type(exc).__name__)
                continue
            if result.get('stage') in SKIP_STAGES:
                continue
            if result.get('login_rejected'):
                continue  # Credential circuit breaker already recorded its window.
            if result.get('ok') and valid_collection(result):
                try:
                    result = self.build_inventory(result)
                except Exception as exc:
                    LOG.warning('%s inventario no construido: %s', host, type(exc).__name__)
                merge_into_data(host, result)
                self.record_success(host)
                self.last_success[host] = time.time()
                LOG.info('%s OK via %s: %s clientes, %s SSIDs, logout %s', host,
                         result.get('transport', 'n/a'), len(result.get('clients', [])),
                         len(result.get('ssids', [])), result.get('logout', 'n/a'))
            elif result.get('browserless_unavailable'):
                self.next_attempt[host] = time.monotonic() + INTERVAL
                LOG.warning('%s sin fallback browserless: %s', host, result.get('stage'))
            elif result.get('ok'):
                self.record_failure(host, 'schema-invalid')
            else:
                self.record_failure(host, str(result.get('stage', 'unknown')))
            await asyncio.sleep(ROUTER_GAP_SECONDS)

    async def cycle_webonly(self):
        for host, password in webonly.webonly_routers():
            if not self.due(host):
                continue
            try:
                result = await self.collect_bounded(host, password, direct_only=True)
            except Exception as exc:
                self.record_failure(host, 'exception:' + type(exc).__name__)
                continue
            if result.get('stage') in SKIP_STAGES:
                continue
            if result.get('login_rejected'):
                continue
            if result.get('ok') and valid_collection(result):
                record = webonly.build_record(host, result, webonly.expected_serial(host))
                if record is None:
                    self.record_failure(host, 'identity-pin')
                else:
                    merge_webonly(host, record)
                    self.record_success(host)
                    self.last_success[host] = time.time()
                    LOG.info('%s OK web-only via %s: %s clientes', host,
                             result.get('transport', 'n/a'), len(record['clients']))
            elif result.get('browserless_unavailable'):
                self.next_attempt[host] = time.monotonic() + INTERVAL
                LOG.warning('%s web-only sin fallback browserless: %s', host, result.get('stage'))
            elif result.get('ok'):
                self.record_failure(host, 'schema-invalid')
            else:
                self.record_failure(host, str(result.get('stage', 'unknown')))
            await asyncio.sleep(ROUTER_GAP_SECONDS)

    async def worker(self):
        while True:
            try:
                await self.cycle()
            except Exception as exc:
                LOG.warning('Ciclo falló: %s', type(exc).__name__)
                self.browser = None
            await asyncio.sleep(INTERVAL)


def handler(collector, service=None, loop=None, service_error=None):
    class Handler(BaseHTTPRequestHandler):
        def setup(self):
            super().setup()
            self.connection.settimeout(10)

        def log_message(self, format, *args):
            pass

        def host_allowed(self):
            host = self.headers.get('Host')
            if not host:
                return False
            if host.startswith('['):
                end = host.find(']')
                name = host[1:end] if end > 0 else host
            else:
                name = host.split(':', 1)[0]
            return name.strip().lower() in ALLOWED_HOSTS

        def origin_allowed(self):
            origin = self.headers.get('Origin')
            return origin is None or origin in ALLOWED_ORIGINS

        def guard_admin(self):
            if not self.host_allowed():
                self.send(400, {'error': 'bad-host'})
                return False
            if not self.origin_allowed():
                self.send(403, {'error': 'bad-origin'})
                return False
            return True

        def unavailable(self):
            return self.send(503, {'error': 'operations unavailable',
                                   'reason': service_error or 'unavailable'})

        def send(self, status, data):
            if not isinstance(data, bytes):
                data = json.dumps(data, allow_nan=False).encode()
            self.send_response(status)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(data)))
            self.send_header('Cache-Control', 'no-store')
            self.end_headers()
            self.wfile.write(data)

        def authorized(self):
            if service is None:
                return False
            header = self.headers.get('Authorization') or ''
            if not header.startswith('Bearer '):
                return False
            return service.verify_token(header[7:].strip())

        def read_json(self, max_body=OPERATIONS_MAX_BODY):
            raw_length = self.headers.get('Content-Length')
            if raw_length is None:
                raise ValueError('content-length')
            try:
                length = int(raw_length)
            except (TypeError, ValueError):
                raise ValueError('content-length') from None
            if length <= 0 or length > max_body:
                raise ValueError('content-length')
            ctype = (self.headers.get('Content-Type') or '').split(';', 1)[0].strip().lower()
            if ctype != 'application/json':
                raise ValueError('content-type')
            raw = self.rfile.read(length)
            if len(raw) != length:
                raise ValueError('short-body')
            try:
                return json.loads(raw.decode('utf-8'))
            except (ValueError, UnicodeDecodeError):
                raise ValueError('invalid-json') from None

        def call(self, coro):
            if loop is None:
                return {'status': 'denied', 'reason': 'service_error'}
            future = asyncio.run_coroutine_threadsafe(coro, loop)
            try:
                return future.result(timeout=ADMIN_TIMEOUT_SECONDS)
            except FuturesTimeout:
                return {'status': 'uncertain', 'reason': 'admin_timeout'}
            except Exception:  # noqa: BLE001 - never surface internal text
                return {'status': 'denied', 'reason': 'service_error'}

        def do_GET(self):
            path = self.path.split('?')[0]
            if path == '/enrich':
                return self.send(200, snapshot())
            if path == '/webonly':
                return self.send(200, snapshot_webonly())
            if path == '/health':
                view = snapshot()
                states = view['routers']
                all_fresh = bool(states) and all(item['fresh'] for item in states.values())
                return self.send(200 if all_fresh else 503, {
                    'ok': all_fresh, 'updated_at': view['updated_at'],
                    'ttl_seconds': view['ttl_seconds'], 'routers': states,
                    'transports': collector.transport_view(),
                    'policy': collector.state_view()})
            if path == '/inventory':
                view = snapshot()
                return self.send(200, {'schema_version': view['schema_version'],
                                       'updated_at': view['updated_at'],
                                       'routers': {host: {'router_ip': state['router_ip'],
                                                          'fresh': state['fresh'],
                                                          'observed_at': state['observed_at'],
                                                          'serial': state['serial'],
                                                          'transport': state['transport'],
                                                          'device': state['device'],
                                                          'inventory': state['inventory'],
                                                          'stats': state['stats'],
                                                          'stats_reason': state['stats_reason'],
                                                          'stats_observed_at': state['stats_observed_at'],
                                                          'stats_fresh': state['stats_fresh'],
                                                          'topology_supported': state['topology_supported'],
                                                          'guest_api_supported': state['guest_api_supported']}
                                                   for host, state in view['routers'].items()}})
            if path == '/capabilities':
                if not self.guard_admin():
                    return
                if service is None:
                    return self.unavailable()
                return self.send(200, service.capabilities())
            if path.startswith('/operations/'):
                if not self.guard_admin():
                    return
                if service is None:
                    return self.unavailable()
                if not self.authorized():
                    return self.send(401, {'error': 'unauthorized'})
                operation_id = path[len('/operations/'):].strip('/')
                result = service.status(operation_id)
                return self.send(service_http_status(result), result)
            return self.send(404, {'error': 'Not found'})

        def do_POST(self):
            path = self.path.split('?', 1)[0]
            if not path.startswith('/operations'):
                return self.send(404, {'error': 'Not found'})
            if not self.guard_admin():
                return
            if service is None or loop is None:
                return self.unavailable()
            if not self.authorized():
                return self.send(401, {'error': 'unauthorized'})
            try:
                body = self.read_json()
            except ValueError as exc:
                return self.send(400, {'error': str(exc)})
            if not isinstance(body, dict):
                return self.send(400, {'error': 'invalid-body'})
            if path == '/operations/plan':
                result = self.call(service.plan(body))
            elif path == '/operations':
                result = self.call(service.execute(body))
            elif path.startswith('/operations/') and path.endswith('/resolve'):
                operation_id = path[len('/operations/'):-len('/resolve')].strip('/')
                note = body.get('note')
                result = service.resolve(operation_id, note if isinstance(note, str) else None)
            else:
                return self.send(404, {'error': 'Not found'})
            return self.send(service_http_status(result), result)
    return Handler


async def main_async():
    logging.basicConfig(level=logging.INFO, format='%(asctime)s webcol %(message)s')
    collector = Collector()
    state_path = (os.path.join(STATE_DIR, 'operations_state.json')
                  if os.path.isdir(STATE_DIR) else None)
    service_error = None
    try:
        service = operation_service.OperationsService.from_env(
            routers(), gate=collector, state_path=state_path)
    except Exception as exc:  # noqa: BLE001 - never block collection, but report why
        service_error = type(exc).__name__
        LOG.error('operations service no disponible (%s)', service_error)
        service = None
    loop = asyncio.get_running_loop()
    if service is not None:
        service.set_loop(loop)
    server = ThreadingHTTPServer((LISTEN_HOST, PORT),
                                 handler(collector, service, loop, service_error))
    server.daemon_threads = True
    thread = loop.run_in_executor(None, server.serve_forever)
    LOG.info('webcol publicando en %s:%s | browserless: %s | routers: %s | write control: %s',
             LISTEN_HOST, PORT, BROWSERLESS_URL.split('?')[0], [h for h, _ in routers()],
             bool(service and service.writes_master))
    await collector.worker()


if __name__ == '__main__':
    asyncio.run(main_async())
