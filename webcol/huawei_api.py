#!/usr/bin/env python3
"""Direct Huawei web API client: authentication and read-only collection.

API-primary transport for webcol. Implements the SCRAM-like proof order taken
from the router's own web bundle (CryptoJS SCRAM, cat_enc_121.js) and from
vmakeev/huawei_mesh_router (client/crypto.py):

    salted = pbkdf2_hmac('sha256', password, fromhex(salt), iterations, 32)
    client_key = HMAC(key=b'Client Key', msg=salted)
    server_key = HMAC(key=b'Server Key', msg=salted)
    stored_key = sha256(client_key)
    auth_msg   = first_nonce + ',' + server_nonce + ',' + server_nonce
    client_sig = HMAC(key=auth_msg, msg=stored_key)      # inverted vs RFC 5802
    client_proof = client_key XOR client_sig
    server_sig = HMAC(key=auth_msg, msg=server_key)      # value in 'serversignature'
    rsa_sig    = HMAC(key=server_key, msg=fromhex(rsan)) # value in 'rsapubkeysignature'

The router's CryptoJS helper is ``HmacSHA256(message, key)``, so every argument
order above is deliberate. Do not "fix" it to the RFC ordering.

Safety model (mirrors HARDENING.md):
- Login attempts are bounded: only CSRF errors may be retried (finite, with a
  fresh nonce after re-initialising CSRF). Credential rejections, lockouts and
  "Three_time_err_multi" raise immediately; callers back off >= 300 s and never
  try alternate passwords.
- Cookies (SessionID_R3 / SessionID_R3S) and the CSRF pair are rotated from
  every JSON response that carries them; empty or malformed values delete the
  cookie instead of being replayed.
- Timeouts are layered: per-request (connect + headers), a total monotonic
  session budget across every request, and a hard response-body size cap.
- KDF work is bounded: iterations, salt and nonces coming from the router are
  validated before any PBKDF2/HMAC is computed.
- Redirects are refused so session cookies are never replayed to a third party,
  and the base URL must be a loopback/private LAN origin without userinfo,
  query or fragment.
- Never log raw responses or exception text: they can embed auth material.

Read-only collection only: deviceinfo, HostInfo, WlanGuideBasic, and optional
probes (guest network names, l2topo topology support). Nothing here writes to
the router.
"""

import hashlib
import hmac
import ipaddress
import json
import logging
import math
import re
import secrets
import socket
import ssl
import time
import urllib.error
import urllib.request
from urllib.parse import urlsplit

LOG = logging.getLogger('webcol.direct')

USERNAME = 'admin'
SESSION_COOKIE_HTTP = 'SessionID_R3'
SESSION_COOKIE_HTTPS = 'SessionID_R3S'

CSRF_ERR_MARKER = 'Menu.csrf_err'
CAT_CREDENTIALS = 'user_pass_err'
CAT_CSRF = 'csrf_error'
CAT_TOO_MANY_USERS = 'Too_Many_user'
CAT_THREE_TIME_LOCK = 'Three_time_err_multi'
CAT_UNAUTHORIZED = 'unauthorized'

PATH_INDEX = 'html/index.html'
PATH_LOGIN_NONCE = 'api/system/user_login_nonce'
PATH_LOGIN_PROOF = 'api/system/user_login_proof'
PATH_LOGOUT = 'api/system/user_logout'
PATH_DEVICE_INFO = 'api/system/deviceinfo'
PATH_HOST_INFO = 'api/system/HostInfo'
PATH_WLAN_GUIDE = 'api/ntwk/WlanGuideBasic?type=notshowpassall'
PATH_GUEST_NETWORK = 'api/ntwk/guest_network?type=notshowpassall'
PATH_TOPOLOGY = ('api/device/l2topo', 'api/device/topology')
# Optional router-wide CPU/memory gauge. Reading it must never gate the core
# collection: an unsupported or malformed reply only drops the gauge.
PATH_PROCESS_STATUS = 'api/system/processstatus'

MAX_PROFILES = 16
MAX_CLIENTS = 256

MAX_KDF_ITERATIONS = 200000
MAX_SALT_HEX = 128
MAX_NONCE_LEN = 256
MAX_HEX_KEY_LEN = 4096
MAX_COOKIE_LEN = 512
MAX_TEXT = 128

MIN_REQUEST_SECONDS = 0.2
DEFAULT_REQUEST_TIMEOUT = 8.0
DEFAULT_TOTAL_BUDGET = 25.0
DEFAULT_MAX_RESPONSE = 4 * 1024 * 1024
# Logout runs on its own small budget so a session whose main deadline is spent
# can still close cleanly without ever re-logging-in or retrying a write.
CLEANUP_BUDGET_SECONDS = 3.0
READ_CHUNK = 65536

MAC_RE = re.compile(r'^[0-9a-f]{2}(:[0-9a-f]{2}){5}$')
HEX_RE = re.compile(r'^[0-9a-fA-F]+$')
# Explicit wired interface markers. A wired row is never a wireless client even
# if a stale phyMode field is present. Anything not listed here is judged by the
# band/interface evidence below, never assumed wired.
WIRED_INTERFACE_TYPES = frozenset({'lan', 'ethernet', 'wired', 'eth'})
WIRED_INTERFACE_PREFIXES = ('lan', 'eth')


def _looks_wired_interface(value):
    """A native LAN/ethernet interface id outweighs a stale wireless label."""
    if not isinstance(value, str):
        return False
    text = value.strip().lower()
    return any(text.startswith(prefix) for prefix in WIRED_INTERFACE_PREFIXES)
# Only LAN origins are valid: an operator typo or hostile config must never
# send the admin password to a public host.
LAN_NAME_SUFFIXES = ('.local', '.lan', '.home', '.internal', '.localdomain')
PLACEHOLDER_VALUES = frozenset({'-', '--', 'unknown', 'n/a', 'null', 'none'})

# Callers may request only a stricter/looser JSON content type per endpoint;
# Cookie, Host, Authorization and any other header are never overridable.
ALLOWED_REQUEST_HEADERS = frozenset({'Content-Type'})
ALLOWED_CONTENT_TYPES = frozenset({
    'application/json; charset=UTF-8',
    'application/json;charset=UTF-8;enp',
})


def _encode_body(body):
    return None if body is None else json.dumps(body).encode('utf-8')


class ResponseTooLarge(Exception):
    """Router response exceeded the hard size cap."""


class BudgetExceeded(Exception):
    """The monotonic session budget was exhausted before this request."""


class NoRedirect(urllib.request.HTTPRedirectHandler):
    # A redirect to a hostile URL would replay the Cookie header (session or
    # CSRF material) to a third party: redirects are refused, never followed.
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        try:
            fp.close()
        except Exception:  # noqa: BLE001 - best-effort socket release
            pass
        raise urllib.error.HTTPError(newurl, code, 'redirect refused', headers, None)


# Reason codes on LoginRejected: callers route them into backoff policy.
R_CREDENTIALS = 'credentials'
R_LOCKED = 'locked'
R_CSRF = 'csrf'
R_UNAUTHORIZED = 'unauthorized'
R_HTTP = 'http'
R_PARSE = 'parse'
R_SERVER_PROOF = 'server-proof'
R_GENERIC = 'generic'

# Login-stage reason codes that must never open a second transport path.
BLOCKING_LOGIN_REASONS = frozenset({R_CREDENTIALS, R_LOCKED})


class LoginRejected(Exception):
    """The router refused the login; no retry may occur without backoff."""

    def __init__(self, stage, reason):
        super().__init__(stage)
        self.stage = stage
        self.reason = reason


class CollectionError(Exception):
    def __init__(self, stage):
        super().__init__(stage)
        self.stage = stage


def bounded_text(value, limit=MAX_TEXT):
    """Return a printable, stripped, bounded string or None."""
    if not isinstance(value, str):
        return None
    cleaned = ''.join(ch for ch in value if ch.isprintable())
    cleaned = cleaned.strip()
    if not cleaned or cleaned.lower() in PLACEHOLDER_VALUES:
        return None
    return cleaned[:limit]


def finite_number(value, minimum=None, maximum=None):
    """Return a finite int/float (numeric strings accepted) or None.

    Booleans are never numbers here: ``True``/``False`` from a malformed
    payload must not become 1/0 counters.
    """
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        number = value
    elif isinstance(value, float):
        number = value
    elif isinstance(value, str):
        try:
            number = float(value.strip())
        except (TypeError, ValueError):
            return None
        if number.is_integer():
            number = int(number)
    else:
        return None
    if not math.isfinite(number):
        return None
    if minimum is not None and number < minimum:
        return None
    if maximum is not None and number > maximum:
        return None
    return number


def _as_bool(value):
    return value is True or (value == 1 and not isinstance(value, bool))


def _bounded_hex(value, max_hex):
    if not isinstance(value, str) or not value or len(value) > max_hex:
        return None
    if len(value) % 2 or not HEX_RE.fullmatch(value):
        return None
    return value


def _bounded_hex_int(value, max_hex):
    if not isinstance(value, str) or not value or len(value) > max_hex:
        return None
    if not HEX_RE.fullmatch(value):
        return None
    return value


def _bounded_nonce(value):
    if not isinstance(value, str) or not value or len(value) > MAX_NONCE_LEN:
        return None
    if ',' in value or not value.isprintable():
        return None
    return value


def derive_scram_keys(password, salt_hex, iterations):
    """Validate router-provided KDF parameters and derive the SCRAM keys.

    Raises ValueError when the parameters are outside the accepted bounds so a
    hostile reply cannot demand unbounded PBKDF2 work.
    """
    if not isinstance(iterations, int) or isinstance(iterations, bool):
        raise ValueError('iterations')
    if not 1 <= iterations <= MAX_KDF_ITERATIONS:
        raise ValueError('iterations')
    if not _bounded_hex(salt_hex, MAX_SALT_HEX):
        raise ValueError('salt')
    salted = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'),
                                 bytes.fromhex(salt_hex), iterations, dklen=32)
    client_key = hmac.new(b'Client Key', salted, hashlib.sha256).digest()
    server_key = hmac.new(b'Server Key', salted, hashlib.sha256).digest()
    stored_key = hashlib.sha256(client_key).digest()
    return client_key, stored_key, server_key


def auth_message(first_nonce, server_nonce):
    return f'{first_nonce},{server_nonce},{server_nonce}'.encode('utf-8')


def client_proof(password, salt_hex, iterations, first_nonce, server_nonce):
    """Compute the client proof with the upstream (non-RFC) argument order."""
    client_key, stored_key, _ = derive_scram_keys(password, salt_hex, iterations)
    signature = hmac.new(auth_message(first_nonce, server_nonce), stored_key,
                         hashlib.sha256).digest()
    return bytes(k ^ s for k, s in zip(client_key, signature)).hex()


def server_signature(password, salt_hex, iterations, first_nonce, server_nonce):
    """Expected value of the router's 'serversignature' field."""
    _, _, server_key = derive_scram_keys(password, salt_hex, iterations)
    return hmac.new(auth_message(first_nonce, server_nonce), server_key,
                    hashlib.sha256).hexdigest()


def rsa_key_signature(server_key, rsan_hex):
    """Expected value of 'rsapubkeysignature' for the given server key/modulus."""
    return hmac.new(server_key, bytes.fromhex(rsan_hex), hashlib.sha256).hexdigest()


def parse_csrf_meta(html):
    def meta(name):
        pattern = (r'<meta[^>]*name="%s"[^>]*content="([^"]+)"' % re.escape(name))
        match = re.search(pattern, html, re.IGNORECASE)
        if not match:
            pattern = (r'<meta[^>]*content="([^"]+)"[^>]*name="%s"' % re.escape(name))
            match = re.search(pattern, html, re.IGNORECASE)
        return match.group(1) if match else None
    param, token = meta('csrf_param'), meta('csrf_token')
    if not param or not token:
        return None
    return {'csrf_param': param, 'csrf_token': token}


def classify_error(data):
    """Map an API error payload to a policy reason (None means no error).

    A missing error field is success; an explicit non-zero one is an error.
    The returned code never carries router text, only a policy reason.
    """
    if not isinstance(data, dict):
        return None
    if data.get('err') not in (None, 0, '0', False):
        category = data.get('errorCategory')
        if category == CAT_CREDENTIALS:
            return R_CREDENTIALS
        if category in (CAT_TOO_MANY_USERS, CAT_THREE_TIME_LOCK):
            return R_LOCKED
        if category == CAT_CSRF or data.get('csrf') == CSRF_ERR_MARKER:
            return R_CSRF
        if category == CAT_UNAUTHORIZED:
            return R_UNAUTHORIZED
        return R_GENERIC
    if data.get('errcode') not in (None, 0, '0', False):
        if data.get('csrf') == CSRF_ERR_MARKER:
            return R_CSRF
        if data.get('errcode') == -2 or data.get('errorCategory') == CAT_UNAUTHORIZED:
            return R_UNAUTHORIZED
        return R_GENERIC
    if data.get('errorcode') not in (None, 0, '0', False):
        if data.get('errorcode') == -2:
            return R_UNAUTHORIZED
        return R_GENERIC
    return None


def application_rejected(body):
    return classify_error(body) is not None


def _explicit_success(data):
    """True only when the reply explicitly reports success (err/errcode zero)."""
    if not isinstance(data, dict):
        return False
    for key in ('err', 'errcode', 'errorcode'):
        if data.get(key) in (0, '0'):
            return True
    return False


def scalar(value, limit=256):
    """Return a bounded JSON scalar as-is; compound values are never copied."""
    if isinstance(value, str):
        return value[:limit]
    if value is None or isinstance(value, (int, float, bool)):
        return value
    return None


def parse_deviceinfo(data):
    """Extract bounded hardware metadata, only scalar fields as reported."""
    if not isinstance(data, dict):
        return None
    software = bounded_text(data.get('SoftwareVersion'), 64)
    if not software:
        return None
    info: dict[str, object] = {'software_version': software}
    cust_data = data.get('custinfo')
    cust = cust_data if isinstance(cust_data, dict) else {}
    # The product model is custinfo.CustDeviceName first (upstream contract);
    # DeviceName alone is the generic vendor string ("Huawei") on this CPE.
    model = (bounded_text(cust.get('CustDeviceName')) or bounded_text(data.get('ModelName'))
             or bounded_text(data.get('DeviceName')))
    if model:
        info['model'] = model
    cust_model = bounded_text(cust.get('CustDeviceName'))
    if cust_model:
        info['model_cust'] = cust_model
    serial = bounded_text(data.get('SerialNumber'))
    if serial:
        info['serial_number'] = serial
    hardware = bounded_text(data.get('HardwareVersion'), 64)
    if hardware:
        info['hardware_version'] = hardware
    uptime = finite_number(data.get('UpTime'), minimum=0)
    if uptime is not None:
        info['uptime_seconds'] = int(uptime)
    return info


def parse_processstatus(data):
    """Router-wide CPU/memory percent from the first process row only.

    The router's own bundle reads ``processstatus[0].CpuUsage``/``MemUsage``
    gated by ``isSupportShowCpuMemoryStatus`` and labels that row ``Total``.
    Only the first row is used: per-process rows are never summed or averaged,
    and no per-process name ever leaves this function. A missing/unknown name,
    a bool, a non-finite value or one outside 0..100 makes the gauge
    unavailable rather than guessed. Zero is a real reading (unlike an unset
    RSSI), so it is preserved.
    """
    if not isinstance(data, list) or not data:
        return None
    first = data[0]
    if not isinstance(first, dict) or bounded_text(first.get('Name'), 32) != 'Total':
        return None
    cpu = finite_number(first.get('CpuUsage'), minimum=0, maximum=100)
    mem = finite_number(first.get('MemUsage'), minimum=0, maximum=100)
    if cpu is None or mem is None:
        return None
    return {'cpu_percent': cpu, 'mem_percent': mem}


def _wireless_band(host):
    """Return the wireless band (or None) when the row is a proven wireless client.

    ``False`` means the row is wired or carries no wireless evidence. A wired
    ``InterfaceType`` (LAN/Ethernet) disqualifies the row even when a stale
    phyMode is present. A wireless row is proven by an explicit band-bearing
    Frequency/InterfaceType or by a native Layer2Interface; the PHY mode is
    optional and is never required to keep a client.
    """
    interface_type = bounded_text(host.get('InterfaceType'), 32)
    if interface_type and interface_type.strip().lower() in WIRED_INTERFACE_TYPES:
        return False
    if _looks_wired_interface(host.get('Layer2Interface')):
        return False
    band = normalize_band(interface_type) if interface_type else None
    if band is None:
        band = normalize_band(host.get('Frequency'))
    if band is not None:
        return band
    if interface_type:
        return None  # Non-wired, e.g. "Wireless", but no explicit band.
    interface = host.get('Layer2Interface')
    if isinstance(interface, str) and interface.strip():
        return None
    return False


def _parse_client(host):
    address = host.get('MACAddress')
    if not isinstance(address, str) or not MAC_RE.fullmatch(address.strip().lower()):
        return None
    if _wireless_band(host) is False:
        return None
    client: dict[str, object] = {'mac': address.strip().lower()}
    phy_mode = bounded_text(host.get('phyMode'), 64)
    if phy_mode is not None:
        client['phy_mode'] = phy_mode
    ip_value = host.get('IPAddress')
    if isinstance(ip_value, str):
        try:
            ipaddress.ip_address(ip_value.strip())
            client['ip'] = ip_value.strip()
        except ValueError:
            pass
    hostname = bounded_text(host.get('HostName'))
    if hostname:
        client['hostname'] = hostname
    band = bounded_text(host.get('Frequency'), 16)
    if band:
        client['band'] = band
    normalized = normalize_band(host.get('InterfaceType')) or normalize_band(band)
    if normalized:
        client['band_norm'] = normalized
    interface = host.get('Layer2Interface')
    if isinstance(interface, str) and interface.strip():
        raw_interface = interface.strip()[:64]
        # RAW native interface id, plus the legacy truncated SSID alias. An
        # interface id is never asserted to be an SSID.
        client['interface_id'] = raw_interface
        client['ssid'] = re.sub(r'^SSID', '', raw_interface, flags=re.IGNORECASE)[:32]
    guest = host.get('IsGuest')
    if isinstance(guest, bool):
        client['guest'] = guest  # Explicit source only; never guessed False.
    rssi = finite_number(host.get('staRssi'), minimum=-200, maximum=0)
    if rssi is not None:
        client['rssi_dbm'] = rssi
    # Neutral negotiated link rate, raw as reported. Direction is unknown:
    # never present it as TX or RX.
    rate = finite_number(host.get('rate'), minimum=0)
    if rate is not None:
        client['negotiated_rate'] = rate
    # Directional rates keep their router-provided field names and raw values;
    # they are never relabelled as the neutral rate, and no unit is asserted.
    for key, source in (('up_rate', 'UpRate'), ('down_rate', 'DownRate')):
        value = finite_number(host.get(source), minimum=0)
        if value is not None:
            client[key] = value
    for key, source in (('tx_kb', 'TxKBytes'), ('rx_kb', 'RxKBytes')):
        value = finite_number(host.get(source), minimum=0)
        if value is not None:
            client[key] = value  # A zero counter is a real reading.
    return client


def _strict_active(value):
    """True only for a boolean True or the integer 1; strings never count."""
    return value is True or (isinstance(value, int) and not isinstance(value, bool) and value == 1)


def parse_hostinfo(data):
    """Extract active wireless clients; units stay as reported by the router."""
    if not isinstance(data, list):
        return None
    clients = []
    for host in data[:MAX_CLIENTS]:
        if not isinstance(host, dict) or not _strict_active(host.get('Active')):
            continue
        client = _parse_client(host)
        if client is not None:
            clients.append(client)
    return clients


def usage_from_config(entry):
    """Explicit router-provided usage only; SSID prefixes are never trusted."""
    for key in ('WifiType', 'Type', 'Usage', 'WifiUsage'):
        value = entry.get(key)
        if isinstance(value, str):
            lowered = value.strip().lower()
            if lowered == 'guest':
                return 'guest'
            if lowered in ('primary', 'main', 'normal', 'user'):
                return 'primary'
    return 'unknown'


def normalize_band(raw):
    if isinstance(raw, str):
        lowered = raw.strip().lower()
        if lowered in ('2.4g', '2.4ghz', '2g'):
            return '2.4g'
        if lowered in ('5g', '5ghz'):
            return '5g'
    return None


def _configured_channel(value):
    if isinstance(value, bool):
        return None
    if isinstance(value, int) and value >= 0:
        return value  # 0 stays 0: it means automatic, not an effective channel.
    if isinstance(value, str) and value.strip().isdigit():
        return int(value.strip())
    return None


def parse_wlanguide(data):
    """Extract the web-side WiFi inventory: physical radios and SSID profiles.

    One physical radio per reported band (BE3 reports exactly two). Every
    WifiConfig entry is an SSID profile with its native router identifier.
    Usage is only 'guest' when the router says so explicitly; unknown stays
    unknown and inactive is never inferred from a name prefix. Transmit power
    is kept exactly as reported (percent, not dBm) and channel 0 is preserved
    as the configured/automatic value, never as an effective channel.
    """
    if not isinstance(data, dict) or not isinstance(data.get('WifiConfig'), list):
        return None
    profiles, band_order = [], []
    for entry in data['WifiConfig'][:MAX_PROFILES]:
        if not isinstance(entry, dict):
            continue
        band = normalize_band(entry.get('FrequencyBand'))
        if band is not None and band not in band_order:
            band_order.append(band)
        native_id = entry.get('ID')
        if isinstance(native_id, bool) or not isinstance(native_id, (str, int)):
            native_id = None
        profile = {'band': band, 'ssid': '' if entry.get('WifiSsid') is None
                   else str(entry.get('WifiSsid'))[:32],
                   'enabled': _as_bool(entry.get('WifiEnable')),
                   'channel_configured': _configured_channel(entry.get('Channel')),
                   'standard': scalar(entry.get('WlanStandard')),
                   'power': scalar(entry.get('TransmitPower')),
                   'wmm': _as_bool(entry.get('WMMEnable')),
                   'usage': usage_from_config(entry),
                   'native_id': str(native_id) if native_id is not None else None,
                   'endpoint_role': 'primary'}
        profiles.append(profile)
    radios = [{'band': band, 'profile_count': sum(1 for p in profiles if p['band'] == band)}
              for band in band_order]
    return {'radios': radios, 'profiles': profiles}


def parse_guest_ssids(data):
    """SSID names the router's guest API lists; None when unsupported."""
    if not isinstance(data, list):
        return None
    names = set()
    for entry in data[:MAX_PROFILES]:
        if isinstance(entry, dict):
            ssid = bounded_text(entry.get('WifiSsid'), 32)
            if ssid:
                names.add(ssid)
    return names


def _lan_host_allowed(hostname):
    try:
        address = ipaddress.ip_address(hostname)
    except ValueError:
        lowered = hostname.lower()
        return (lowered == 'localhost' or '.' not in lowered
                or lowered.endswith(LAN_NAME_SUFFIXES))
    if address.version == 4:
        return (address.is_private or address.is_loopback or address.is_link_local)
    return address.is_private or address.is_loopback or address.is_link_local


def validate_base_url(base_url):
    """Return the normalised origin or raise ValueError.

    Rejects userinfo, query, fragment, non-origin paths, public hosts and
    control characters so the admin password can only reach a LAN device.
    """
    if not isinstance(base_url, str) or not base_url or len(base_url) > 255:
        raise ValueError('Invalid router base URL')
    if any(ch.isspace() or ord(ch) < 0x20 for ch in base_url):
        raise ValueError('Invalid router base URL')
    parsed = urlsplit(base_url)
    if parsed.scheme not in ('http', 'https'):
        raise ValueError('Invalid router base URL')
    if (parsed.username is not None or parsed.password is not None
            or '@' in parsed.netloc):
        raise ValueError('Router base URL must be a bare origin')
    if parsed.query or parsed.fragment:
        raise ValueError('Router base URL must be a bare origin')
    if parsed.path not in ('', '/'):
        raise ValueError('Router base URL must not contain a path')
    hostname = parsed.hostname
    if not hostname or not _lan_host_allowed(hostname):
        raise ValueError('Router base URL must be a loopback/private LAN host')
    try:
        port = parsed.port
    except ValueError:
        raise ValueError('Invalid router base URL') from None
    if port is not None and not 1 <= port <= 65535:
        raise ValueError('Invalid router base URL')
    default = (parsed.scheme == 'http' and port == 80) or (parsed.scheme == 'https' and port == 443)
    netloc = hostname.lower() if port is None or default else '%s:%d' % (hostname.lower(), port)
    return '%s://%s' % (parsed.scheme, netloc)


def _response_socket(response):
    fp = getattr(response, 'fp', None)
    raw = getattr(fp, 'raw', None)
    return getattr(raw, '_sock', None)


def _read_bounded(response, max_bytes, deadline, path):
    """Read the body under an absolute deadline, never the whole block.

    Each chunk tightens the socket timeout to the time left, so a peer that
    drips one byte before every per-recv timeout cannot extend the read past the
    deadline; ``read1`` returns as soon as any data is available. ``read`` is
    used only as a fallback for a response object without ``read1``.
    """
    read1 = getattr(response, 'read1', None) or response.read
    sock = _response_socket(response)
    chunks = []
    total = 0
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise BudgetExceeded(path)
        if sock is not None:
            try:
                sock.settimeout(remaining)
            except OSError:
                pass
        want = min(READ_CHUNK, max_bytes + 1 - total)
        if want <= 0:
            raise ResponseTooLarge(path)
        piece = read1(want)
        if not piece:
            break
        total += len(piece)
        if total > max_bytes:
            raise ResponseTooLarge(path)
        chunks.append(piece)
    return b''.join(chunks)


def _tls_context(verify_tls):
    context = ssl.create_default_context()
    try:
        context.minimum_version = ssl.TLSVersion.TLSv1_2
    except AttributeError:  # pragma: no cover - very old OpenSSL
        pass
    if not verify_tls:
        # Explicit local opt-in only: the router UI serves a self-signed
        # certificate and the base URL is already constrained to the LAN.
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    return context


class HuaweiDirectClient:
    """One bounded direct session against a single router."""

    def __init__(self, base_url, password, request_timeout=DEFAULT_REQUEST_TIMEOUT,
                 max_response=DEFAULT_MAX_RESPONSE, total_budget=DEFAULT_TOTAL_BUDGET,
                 verify_tls=True):
        self.base_url = validate_base_url(base_url)
        if not isinstance(password, str):
            raise ValueError('password must be a string')
        self.password = password
        self.request_timeout = float(request_timeout)
        self.max_response = int(max_response)
        self.total_budget = float(total_budget) if total_budget else None
        self.verify_tls = bool(verify_tls)
        parsed = urlsplit(self.base_url)
        self.https = parsed.scheme == 'https'
        self.cookies = {}
        self.csrf = None
        self.public_key = None
        self.server_signature_verified = False
        self.public_key_verified = False
        self.logged_in = False
        self._deadline = None
        if self.https:
            context = _tls_context(self.verify_tls)
            https_handler = urllib.request.HTTPSHandler(context=context)
        else:
            https_handler = urllib.request.HTTPHandler()
        self.opener = urllib.request.build_opener(
            NoRedirect(),
            urllib.request.ProxyHandler({}),
            https_handler)

    def _start_budget(self):
        if self.total_budget:
            self._deadline = time.monotonic() + self.total_budget

    def _remaining(self):
        if self._deadline is None:
            return None
        return self._deadline - time.monotonic()

    def _absorb_cookies(self, headers):
        for header in headers.get_all('Set-Cookie') or ():
            first = header.split(';', 1)[0]
            name, sep, value = first.partition('=')
            name = name.strip()
            if not sep or name not in (SESSION_COOKIE_HTTP, SESSION_COOKIE_HTTPS):
                continue
            value = value.strip().strip('"')
            if (not value or len(value) > MAX_COOKIE_LEN
                    or any(ord(ch) < 0x21 or ord(ch) > 0x7e or ch in ';,' for ch in value)):
                self.cookies.pop(name, None)  # deletion header / hostile value
                continue
            self.cookies[name] = value

    def _request(self, method, path, body=None, timeout=None, headers=None,
                 ignore_session_budget=False):
        remaining = None if ignore_session_budget else self._remaining()
        if remaining is not None and remaining < MIN_REQUEST_SECONDS:
            raise BudgetExceeded(path)
        effective_timeout = timeout or self.request_timeout
        if remaining is not None:
            effective_timeout = min(effective_timeout, remaining)
        deadline = time.monotonic() + effective_timeout
        url = self.base_url + '/' + path.lstrip('/')
        request_headers = {'_ResponseFormat': 'JSON', 'Referer': self.base_url + '/' + PATH_INDEX}
        if self.cookies:
            request_headers['Cookie'] = '; '.join(
                f'{name}={value}' for name, value in self.cookies.items())
        if body is not None:
            request_headers['Content-Type'] = 'application/json; charset=UTF-8'
        if headers:
            for name, value in headers.items():
                if name not in ALLOWED_REQUEST_HEADERS:
                    continue
                if name == 'Content-Type' and value in ALLOWED_CONTENT_TYPES:
                    request_headers['Content-Type'] = value
        request = urllib.request.Request(
            url, data=_encode_body(body), headers=request_headers, method=method)
        # Timeout layer 1: connect + response headers per request.
        with self.opener.open(request, timeout=effective_timeout) as response:
            self._absorb_cookies(response.headers)
            # Timeout layer 2: the body read is hard-capped and bounded by the
            # absolute deadline, so a slow-drip peer cannot hold the thread.
            status = response.status
            raw = _read_bounded(response, self.max_response, deadline, path)
        return status, raw

    def _json(self, raw):
        try:
            data = json.loads(raw.decode('utf-8'))
        except (ValueError, UnicodeDecodeError):
            raise CollectionError('parse') from None
        # CSRF rotation: every JSON response may carry a new pair. Non-JSON
        # HTML (a sanitized login page or proxy error) is never treated as
        # data, so it can never be published as a fresh collection.
        if isinstance(data, dict) and isinstance(data.get('csrf_param'), str) \
                and isinstance(data.get('csrf_token'), str):
            self.csrf = {'csrf_param': data['csrf_param'], 'csrf_token': data['csrf_token']}
        return data

    def _post_login_json(self, path, payload, stage):
        status, raw = self._request('POST', path, payload)
        if status != 200:
            raise LoginRejected(stage, R_HTTP)
        return self._json(raw)

    def _get_json(self, path, stage):
        status, raw = self._request('GET', path)
        if status != 200:
            raise CollectionError(stage)
        data = self._json(raw)
        reason = classify_error(data)
        if reason in (R_UNAUTHORIZED, R_CSRF):
            # The session was refused or expired: never re-login inside a
            # collection; the caller applies backoff.
            raise CollectionError('session-expired')
        if reason:
            raise CollectionError('application:' + reason)
        return data

    def _init_csrf(self):
        status, raw = self._request('GET', PATH_INDEX)
        if status != 200:
            return False
        self.csrf = parse_csrf_meta(raw.decode('utf-8', 'ignore'))
        return self.csrf is not None

    def login(self, max_csrf_retries=2):
        """Authenticate once. Retries ONLY csrf errors, always with a fresh
        nonce after re-initialising CSRF. Credential/lockout rejections raise
        immediately: the caller must back off, never alternate passwords."""
        self._start_budget()
        attempts = 0
        while True:
            attempts += 1
            if not self._init_csrf():
                raise LoginRejected('no-csrf', R_HTTP)
            first_nonce = secrets.token_hex(32)
            result = self._post_login_json(
                PATH_LOGIN_NONCE,
                {'csrf': self.csrf,
                 'data': {'username': USERNAME, 'firstnonce': first_nonce}},
                'nonce')
            reason = classify_error(result)
            if reason == R_CSRF and attempts < max_csrf_retries:
                continue
            if reason:
                raise LoginRejected('nonce', reason)
            if not _explicit_success(result):
                raise LoginRejected('nonce', R_PARSE)
            try:
                server_nonce = _bounded_nonce(result['servernonce'])
                salt = result['salt']
                iterations = int(result['iterations'])
                if server_nonce is None:
                    raise ValueError('servernonce')
                client_key, stored_key, server_key = derive_scram_keys(
                    self.password, salt, iterations)
            except (KeyError, TypeError, ValueError):
                raise LoginRejected('nonce', R_PARSE) from None

            message = auth_message(first_nonce, server_nonce)
            signature = hmac.new(message, stored_key, hashlib.sha256).digest()
            proof = bytes(k ^ s for k, s in zip(client_key, signature)).hex()
            result = self._post_login_json(
                PATH_LOGIN_PROOF,
                {'csrf': self.csrf,
                 'data': {'clientproof': proof, 'finalnonce': server_nonce}},
                'proof')
            reason = classify_error(result)
            if reason == R_CSRF and attempts < max_csrf_retries:
                continue
            if reason:
                raise LoginRejected('proof', reason)
            if not _explicit_success(result):
                raise LoginRejected('proof', R_PARSE)
            self.logged_in = True

            # Server authenticity: the router proves it knows the salted
            # password by signing the same auth message with the Server Key.
            expected = hmac.new(message, server_key, hashlib.sha256).hexdigest()
            provided = result.get('serversignature')
            if isinstance(provided, str) and provided:
                if not hmac.compare_digest(provided.lower(), expected):
                    raise LoginRejected('proof', R_SERVER_PROOF)
                self.server_signature_verified = True
            # The RSA public key carries its own proof; only a complete,
            # self-consistent set is accepted, and raw key material is never
            # exposed through collect().
            rsan = result.get('rsan')
            rsae = result.get('rsae')
            rsa_sig = result.get('rsapubkeysignature')
            if rsan or rsae or rsa_sig:
                if (_bounded_hex(rsan, MAX_HEX_KEY_LEN)
                        and _bounded_hex_int(rsae, MAX_HEX_KEY_LEN)
                        and isinstance(rsa_sig, str) and rsa_sig):
                    expected_sig = rsa_key_signature(server_key, rsan)
                    if not hmac.compare_digest(rsa_sig.lower(), expected_sig):
                        raise LoginRejected('proof', R_SERVER_PROOF)
                    self.public_key = {'rsan': rsan, 'rsae': rsae}
                    self.public_key_verified = True
            return {'server_signature_verified': self.server_signature_verified,
                    'public_key_verified': self.public_key_verified}

    def logout(self, max_csrf_retries=2):
        """Bounded logout with application-level validation."""
        try:
            attempts = 0
            while True:
                attempts += 1
                try:
                    status, raw = self._request(
                        'POST', PATH_LOGOUT, {'data': {}, 'csrf': self.csrf},
                        timeout=CLEANUP_BUDGET_SECONDS, ignore_session_budget=True)
                except (BudgetExceeded, urllib.error.URLError, socket.timeout, OSError):
                    return 'failed'
                if status != 200:
                    return 'invalid'
                body = self._json(raw)
                reason = classify_error(body)
                if reason == R_CSRF and attempts < max_csrf_retries and self._init_csrf():
                    continue
                return 'invalid' if reason else 'ok'
        except Exception:  # noqa: BLE001 - logout never raises
            return 'failed'
        finally:
            self.logged_in = False

    def _read_optional(self, paths, expected_type):
        """Probe an optional endpoint: parsed JSON of the expected type or None.

        A 404, an application error or a malformed payload all mean "not
        supported" and never mark support.
        """
        for path in paths:
            try:
                status, raw = self._request('GET', path)
            except (urllib.error.URLError, socket.timeout, OSError,
                    ResponseTooLarge, BudgetExceeded):
                return None
            if status != 200:
                continue
            try:
                data = self._json(raw)
            except CollectionError:
                continue
            if classify_error(data) is not None:
                continue
            if not isinstance(data, expected_type):
                continue
            return data
        return None

    def _read_stats(self):
        """One bounded optional read of the router CPU/memory gauge.

        Returns ``(stats, reason)``. The session deadline still bounds it, but
        any failure (404, timeout, malformed row, exhausted budget) only yields
        ``(None, reason)``: the gauge is never allowed to gate the core
        collection, and an unsupported router is never retried or re-authed.
        """
        try:
            status, raw = self._request('GET', PATH_PROCESS_STATUS)
        except urllib.error.HTTPError as exc:
            return None, 'unsupported' if getattr(exc, 'code', None) == 404 else 'transport'
        except BudgetExceeded:
            return None, 'budget'
        except (urllib.error.URLError, socket.timeout, OSError, ResponseTooLarge):
            return None, 'transport'
        if status != 200:
            return None, 'unsupported'
        try:
            data = self._json(raw)
        except CollectionError:
            return None, 'parse'
        if classify_error(data) is not None:
            return None, 'unsupported'
        stats = parse_processstatus(data)
        if stats is None:
            return None, 'schema'
        return stats, None

    def collect(self):
        """One read-only collection session. Never raises; every failure is a
        structured stage so callers can apply transport policy without seeing
        raw router responses."""
        self._start_budget()
        result = {'ok': False, 'transport': 'direct', 'stage': 'unknown'}
        try:
            self.login()
            deviceinfo = parse_deviceinfo(self._get_json(PATH_DEVICE_INFO, 'deviceinfo'))
            device_observed_at = time.time()
            if deviceinfo is None:
                raise CollectionError('deviceinfo-schema')
            hostinfo = parse_hostinfo(self._get_json(PATH_HOST_INFO, 'hostinfo'))
            if hostinfo is None:
                raise CollectionError('hostinfo-schema')
            wlanguide = parse_wlanguide(self._get_json(PATH_WLAN_GUIDE, 'wifi'))
            if wlanguide is None:
                raise CollectionError('wifi-schema')
            guest_data = self._read_optional((PATH_GUEST_NETWORK,), list)
            guest_ssids = parse_guest_ssids(guest_data) if guest_data is not None else None
            for profile in wlanguide['profiles']:
                if guest_ssids and profile['ssid'] in guest_ssids and profile['usage'] == 'unknown':
                    profile['usage'] = 'guest'  # Confirmed by the router's own API.
                    profile['endpoint_role'] = 'guest'
            topology = self._read_optional(PATH_TOPOLOGY, dict)
            # Read the optional gauge last so it can never starve the core
            # endpoints of the shared session budget.
            stats, stats_reason = self._read_stats()
            result = {'ok': True, 'transport': 'direct', 'clients': hostinfo,
                      'ssids': [{'band': p['band'], 'ssid': p['ssid'],
                                 'channel_configured': p['channel_configured'],
                                 'enabled': p['enabled'], 'power': p['power'], 'wmm': p['wmm'],
                                 'standard': p['standard'], 'usage': p['usage']}
                                for p in wlanguide['profiles']],
                      'inventory': wlanguide, 'device': deviceinfo,
                      'device_observed_at': device_observed_at,
                      'version': deviceinfo.get('software_version'),
                      'stats': stats, 'stats_reason': stats_reason,
                      'stats_observed_at': time.time() if stats is not None else None,
                      'server_signature_verified': self.server_signature_verified,
                      'public_key_verified': self.public_key_verified,
                      'topology_supported': topology is not None,
                      'guest_api_supported': guest_ssids is not None}
        except LoginRejected as exc:
            result = {'ok': False, 'transport': 'direct', 'stage': exc.stage,
                      'reason': exc.reason, 'logged_in': self.logged_in}
            if exc.reason in BLOCKING_LOGIN_REASONS:
                result['login_rejected'] = True
                result['locked'] = exc.reason == R_LOCKED
        except CollectionError as exc:
            result = {'ok': False, 'transport': 'direct', 'stage': exc.stage,
                      'logged_in': self.logged_in}
        except ResponseTooLarge:
            result = {'ok': False, 'transport': 'direct', 'stage': 'response-too-large',
                      'logged_in': self.logged_in}
        except BudgetExceeded:
            result = {'ok': False, 'transport': 'direct', 'stage': 'budget',
                      'logged_in': self.logged_in}
        except (urllib.error.URLError, socket.timeout, OSError) as exc:
            # Transport-level failure: never includes router response text.
            result = {'ok': False, 'transport': 'direct',
                      'stage': 'network:' + type(exc).__name__, 'logged_in': self.logged_in}
        except Exception as exc:  # noqa: BLE001 - stage names only, never str(exc)
            result = {'ok': False, 'transport': 'direct',
                      'stage': 'exception:' + type(exc).__name__, 'logged_in': self.logged_in}
        finally:
            if self.logged_in:
                result['logout'] = self.logout()
        return result
