"""Isolated, gated Huawei control-operation adapters and transactional engine.

This module is a pure library: it opens no socket, performs no authentication
and starts no server. Every side effect goes through an injected ``Transport``.
Real writes stay OFF until an explicit :class:`Policy` enables them per
operation; a destructive operation (reboot) additionally needs a one-use
approval flag AND an observed down/up cycle -- HTTP success alone is never
treated as a verified change.

Design constraints (mirrored from a verified read-only client and the upstream
``vmakeev/huawei_mesh_router`` web client):

- Capability is declared per operation: ``available`` (endpoint + readback
  contract known and verifiable), ``implemented_unverified`` (write implemented
  from the upstream contract but the changed field cannot always be observed)
  or ``unsupported`` (no endpoint is invented; the request is rejected).
- Outcomes are honest: ``rejected`` / ``verified_noop`` / ``verified_changed`` /
  ``applied_unverified`` / ``uncertain`` / ``failed`` (+ ``pending``).
- Guest-network passwords are encrypted with the upstream RSA-OAEP pattern
  (base64 of the secret, encrypted in ``modulus_bytes - 42`` byte chunks and
  hex-concatenated). The chunk size is derived from the modulus, not hardcoded.
  The router returns a masked password, so a password write can never be
  reported as ``verified_changed``: at best ``applied_unverified``.
- No password, raw payload, cookie or full response is stored or logged: the
  operation history keeps hashes and a redacted projection only.
- Readback is interpreted only through explicit resolvers keyed by router
  identity and native IDs (VAP/radio ``ID``), never by SSID or hostname.

The authentication boundary is the caller: only the trusted coordinator, after
it has validated the bearer token, may build the injected
:class:`RouterIdentity` / :class:`Snapshot` / :class:`Policy` and present a
:class:`CoordinatorGrant` naming the same allowlisted router.
"""

from __future__ import annotations

import base64
import hashlib
import importlib.util
import json
import math
import re
import secrets
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Mapping, Protocol, runtime_checkable

__all__ = [
    "Capability",
    "Outcome",
    "OperationRejected",
    "TransportError",
    "BudgetExhausted",
    "RsaUnavailable",
    "RouterIdentity",
    "Snapshot",
    "Policy",
    "CoordinatorGrant",
    "Target",
    "OperationRequest",
    "Plan",
    "Result",
    "TransactionStore",
    "TransactionRecord",
    "OperationEngine",
    "ReadOnlyTransport",
    "Transport",
    "MANIFEST",
    "default_policy",
    "capability_manifest",
    "normalize_mac",
    "normalize_band",
    "oaep_chunk_size",
    "rsa_oaep_encode",
    "crypto_available",
]


URL_WLAN_GUIDE = "api/ntwk/WlanGuideBasic?type=notshowpassall"
URL_GUEST_NETWORK = "api/ntwk/guest_network?type=notshowpassall"
URL_WLAN_FILTER = "api/ntwk/wlanfilterenhance"
URL_REBOOT = "api/service/reboot.cgi"
URL_DEVICE_INFO = "api/system/deviceinfo"

# Upstream WIFI_SECURITY_* constants. "tkip" is the router's own name for the
# single encrypted guest profile; no other WPA enum is guessed.
SEC_OPEN = "none"
SEC_ENCRYPTED = "tkip"

# Upstream FilterMode. Only BLACKLIST is safe for a whole-state write here.
FILTER_BLACKLIST = 0
FILTER_WHITELIST = 1

GUEST_DURATIONS = frozenset({1, 2, 3})  # FOUR_HOURS / ONE_DAY / UNLIMITED
GUEST_HEADERS = {"Content-Type": "application/json;charset=UTF-8;enp"}

MAC_RE = re.compile(r"^[0-9a-f]{2}(:[0-9a-f]{2}){5}$")
SSID_MAX = 32
PASSWORD_MAX = 128
MAX_READBACK_ENTRIES = 64


class Capability(str, Enum):
    AVAILABLE = "available"
    IMPLEMENTED_UNVERIFIED = "implemented_unverified"
    UNSUPPORTED = "unsupported"


class Outcome(str, Enum):
    PENDING = "pending"
    REJECTED = "rejected"
    VERIFIED_NOOP = "verified_noop"
    VERIFIED_CHANGED = "verified_changed"
    APPLIED_UNVERIFIED = "applied_unverified"
    UNCERTAIN = "uncertain"
    FAILED = "failed"


TERMINAL_OUTCOMES = frozenset(
    {
        Outcome.REJECTED,
        Outcome.VERIFIED_NOOP,
        Outcome.VERIFIED_CHANGED,
        Outcome.APPLIED_UNVERIFIED,
        Outcome.UNCERTAIN,
        Outcome.FAILED,
    }
)

# States that keep a per-router/operation lock: a later operation_id for the
# same router+operation is refused until an operator explicitly resolves it.
UNRESOLVED_STATES = frozenset({Outcome.PENDING, Outcome.UNCERTAIN, Outcome.FAILED})


class OperationRejected(Exception):
    """The request was refused before any write. ``reason`` is a policy code."""

    def __init__(self, reason: str, detail: str | None = None) -> None:
        super().__init__(reason)
        self.reason = reason
        self.detail = detail


class TransportError(Exception):
    """A transport-level failure. ``phase`` distinguishes pre/post send."""

    def __init__(self, reason: str, phase: str) -> None:
        super().__init__(reason)
        self.reason = reason
        self.phase = phase


class BudgetExhausted(Exception):
    """The bounded call/deadline budget was exceeded."""


class LedgerError(Exception):
    """The transactional ledger could not be read or durably written.

    Fail-closed: raises before a POST when persisting the pending record, and
    demotes a post-send result to ``uncertain`` when the final write fails.
    """

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


class RsaUnavailable(Exception):
    """The optional ``cryptography`` backend is not importable."""


_RSA_OAEP_SHA1_LEN = 20  # OAEP with SHA-1: 2 * hLen
_OAEP_OVERHEAD = 2 * _RSA_OAEP_SHA1_LEN + 2  # + 2 separator bytes


def crypto_available() -> bool:
    """True when the RSA-OAEP backend needed for guest passwords is present."""
    return importlib.util.find_spec("cryptography") is not None


def _bounded_hex(value: Any, max_hex: int = 4096) -> str | None:
    if not isinstance(value, str) or not value or len(value) > max_hex:
        return None
    if len(value) % 2 or not re.fullmatch(r"[0-9a-fA-F]+", value):
        return None
    return value


def _bounded_exp(value: Any, max_hex: int = 64) -> str | None:
    # The RSA exponent may have an odd hex length (0x10001); only the modulus
    # must be byte-aligned.
    if not isinstance(value, str) or not value or len(value) > max_hex:
        return None
    if not re.fullmatch(r"[0-9a-fA-F]+", value):
        return None
    return value


def oaep_chunk_size(modulus_hex: str) -> int:
    """Plaintext chunk for OAEP/SHA-1 derived from the modulus size.

    Mirrors the upstream ``_RSA_CHUNK_SIZE = 214`` which is exactly
    ``256 - 2*20 - 2`` for a 2048-bit modulus; deriving it keeps larger or
    smaller keys correct instead of silently truncating.
    """
    if not _bounded_hex(modulus_hex):
        raise ValueError("invalid modulus")
    key_bytes = len(modulus_hex) // 2
    chunk = key_bytes - _OAEP_OVERHEAD
    if chunk < 1:
        raise ValueError("modulus too small for OAEP")
    return chunk


def rsa_oaep_encode(data: str, modulus_hex: str, exponent_hex: str) -> str:
    """Encrypt ``data`` exactly like the upstream ``crypto.rsa_encode``.

    base64 -> split into ``oaep_chunk_size`` chunks -> RSA-OAEP(SHA-1) ->
    hex-concatenate. Raises :class:`RsaUnavailable` when ``cryptography`` is
    missing so callers can gate the operation instead of inventing a scheme.
    """
    if not crypto_available():
        raise RsaUnavailable("cryptography backend not available")
    if not isinstance(data, str):
        raise ValueError("data must be a string")
    modulus = _bounded_hex(modulus_hex)
    exponent = _bounded_exp(exponent_hex)
    if modulus is None or exponent is None:
        raise ValueError("invalid RSA key")
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding, rsa

    chunk_size = oaep_chunk_size(modulus)
    public_numbers = rsa.RSAPublicNumbers(int(exponent, 16), int(modulus, 16))
    public_key = public_numbers.public_key()
    oaep_padding = padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA1()),
        algorithm=hashes.SHA1(),
        label=None,
    )
    encoded = base64.b64encode(data.encode("utf-8"))
    parts = []
    for index in range(0, len(encoded), chunk_size):
        chunk = encoded[index:index + chunk_size]
        parts.append(public_key.encrypt(chunk, oaep_padding).hex())
    return "".join(parts)


def normalize_mac(value: Any) -> str:
    """Return a canonical lowercase ``aa:bb:..`` MAC or raise."""
    if not isinstance(value, str):
        raise OperationRejected("invalid_mac")
    candidate = value.strip().lower().replace("-", ":")
    if not MAC_RE.fullmatch(candidate):
        raise OperationRejected("invalid_mac")
    return candidate


def normalize_band(value: Any) -> str | None:
    """'2.4GHz'/'5GHz' (and variants) -> '2.4g'/'5g' or None."""
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in ("2.4g", "2.4ghz", "2g"):
            return "2.4g"
        if lowered in ("5g", "5ghz"):
            return "5g"
    return None


def _as_bool(value: Any) -> bool | None:
    """Strict boolean: ``True``/``1`` (not ``True``), else None."""
    if value is True or (value == 1 and not isinstance(value, bool)):
        return True
    if value is False or (value == 0 and not isinstance(value, bool)):
        return False
    return None


def _bounded_text(value: Any, limit: int) -> str | None:
    if not isinstance(value, str):
        return None
    cleaned = "".join(ch for ch in value if ch.isprintable()).strip()
    if not cleaned or len(cleaned) > limit:
        return None
    return cleaned


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)


@dataclass(frozen=True)
class RouterIdentity:
    """The single allowlisted CPE the engine is bound to."""

    router_id: str
    label: str = ""


@dataclass(frozen=True)
class Snapshot:
    """Coordinator-provided readback image with an injected age.

    ``data`` is a redacted mapping keyed by endpoint role, e.g.::

        {
          "wlanguide": {"WifiConfig": [...]},
          "wlan_filter": [ {...2.4GHz...}, {...5GHz...} ],
          "guest_network": [ {...2.4GHz...}, {...5GHz...} ],
          "deviceinfo": {...},
          "rsa_public_key": {"rsan": "...", "rsae": "..."},
        }
    """

    router_id: str
    age_seconds: float
    data: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class Policy:
    """Explicit, fail-closed authorization for control operations."""

    writes_enabled: bool = False
    enabled_operations: frozenset[str] = frozenset()
    allowlisted_router_ids: frozenset[str] = frozenset()
    reboot_approved: bool = False
    allow_unverified_writes: bool = False
    max_transport_calls: int = 16
    callback_timeout_seconds: float = 10.0
    snapshot_max_age_seconds: float = 60.0
    reboot_max_reads: int = 6


def default_policy() -> Policy:
    """Writes OFF, nothing allowlisted: safe default for integration."""
    return Policy()


@dataclass(frozen=True)
class CoordinatorGrant:
    """Proof the trusted coordinator already validated the bearer token.

    The engine never verifies tokens; it only enforces that the grant names the
    same allowlisted router and does not widen the operation scope.
    """

    subject: str
    router_id: str
    operations: frozenset[str] = frozenset()


@dataclass(frozen=True)
class Target:
    """Explicit binding: router identity plus radio/VAP native id."""

    router_id: str
    band: str | None = None
    vap_id: str | None = None


@dataclass(frozen=True)
class OperationRequest:
    operation_id: str
    operation: str
    target: Target
    fields: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class Plan:
    request: OperationRequest
    capability: Capability
    path: str
    payload: Mapping[str, Any]
    extra: Mapping[str, Any] | None
    headers: Mapping[str, str] | None
    current_projection: Mapping[str, Any]
    target_projection: Mapping[str, Any]
    secret_involved: bool
    destructive: bool
    payload_hash: str
    preimage_hash: str
    unifi_mapping: None = None


@dataclass(frozen=True)
class Result:
    operation_id: str
    operation: str
    outcome: Outcome
    reason: str | None = None
    evidence: Mapping[str, Any] = field(default_factory=dict)
    transport_calls: int = 0
    requires_operator_confirmation: bool = False

    @property
    def ok(self) -> bool:
        return self.outcome in (Outcome.VERIFIED_NOOP, Outcome.VERIFIED_CHANGED)


@runtime_checkable
class Transport(Protocol):
    """Injected transport. The engine calls only these two methods."""

    def read(self, path: str) -> Any: ...

    def post(
        self,
        path: str,
        payload: Mapping[str, Any],
        *,
        extra: Mapping[str, Any] | None = None,
        headers: Mapping[str, str] | None = None,
    ) -> Any: ...


class ReadOnlyTransport:
    """Adapts an injected reader (e.g. a bound ``HuaweiDirectClient`` method).

    ``post`` always refuses: this is the production default until the
    coordinator explicitly swaps in a write-capable transport with writes
    enabled by policy.
    """

    def __init__(self, reader: Callable[[str], Any]) -> None:
        self._reader = reader

    def read(self, path: str) -> Any:
        return self._reader(path)

    def post(self, path: str, payload: Mapping[str, Any], **_: Any) -> Any:
        raise TransportError("read_only_transport", "pre_send")


@dataclass
class TransactionRecord:
    operation_id: str
    operation: str
    payload_hash: str
    preimage_hash: str
    state: Outcome
    target: Mapping[str, Any]
    evidence: Mapping[str, Any] = field(default_factory=dict)
    reason: str | None = None
    attempts: int = 0
    revision: int = 1
    resolved: bool = False
    resolution: str | None = None


class TransactionStore:
    """Idempotency ledger keyed by ``operation_id``.

    Stores no raw payload and no secret: only hashes and a redacted evidence
    projection. In-flight and uncertain records are preserved so a repeat
    request is answered from the ledger instead of resending a write.
    """

    def __init__(self) -> None:
        self._records: dict[str, TransactionRecord] = {}
        self._approvals: dict[str, dict[str, Any]] = {}
        self.healthy = True
        # An in-memory ledger is not durable across a restart; production writes
        # require a persistent store (the service enforces this before a login).
        self.durable = False

    def get(self, operation_id: str) -> TransactionRecord | None:
        return self._records.get(operation_id)

    def begin(self, record: TransactionRecord) -> TransactionRecord:
        existing = self._records.get(record.operation_id)
        if existing is None:
            self._records[record.operation_id] = record
            return record
        return existing

    def finish(
        self,
        operation_id: str,
        state: Outcome,
        *,
        reason: str | None = None,
        evidence: Mapping[str, Any] | None = None,
    ) -> TransactionRecord | None:
        record = self._records.get(operation_id)
        if record is None:
            return None
        record.state = state
        record.reason = reason
        record.attempts += 1
        if evidence is not None:
            record.evidence = dict(evidence)
        self._records[operation_id] = record
        return record

    def as_dict(self) -> dict[str, dict[str, Any]]:
        return {
            key: {
                "operation": r.operation,
                "state": r.state.value,
                "reason": r.reason,
                "payload_hash": r.payload_hash,
                "preimage_hash": r.preimage_hash,
                "target": dict(r.target),
                "evidence": dict(r.evidence),
                "attempts": r.attempts,
                "resolved": r.resolved,
                "resolution": r.resolution,
            }
            for key, r in self._records.items()
        }

    def unresolved_for(
        self, router_id: str, operation: str | None = None
    ) -> TransactionRecord | None:
        """First unresolved record for this router, any operation_id.

        The lock is router-wide by default (``operation=None``): an unresolved
        guest write blocks a later 11r/TWT write on the same physical router,
        because the safe assumption is that a half-applied change may affect any
        subsequent write. Passing an ``operation`` narrows the query only for
        read-only reporting.
        """
        for record in self._records.values():
            if record.resolved:
                continue
            if record.target.get("router_id") != router_id:
                continue
            if operation is not None and record.operation != operation:
                continue
            if record.state in UNRESOLVED_STATES:
                return record
        return None

    def mark_resolved(
        self, operation_id: str, note: str | None = None
    ) -> TransactionRecord | None:
        """Clear a lock by marking (never deleting) the record as resolved."""
        record = self._records.get(operation_id)
        if record is None:
            return None
        record.resolved = True
        record.resolution = note or "operator"
        return record

    def issue_approval(
        self, approval_id: str, router_id: str, operation: str, expires_at: float
    ) -> bool:
        if not approval_id or approval_id in self._approvals:
            return False
        self._approvals[approval_id] = {
            "router_id": router_id,
            "operation": operation,
            "expires_at": float(expires_at),
            "used": False,
        }
        return True

    def reserve_approval(
        self, approval_id: str, router_id: str, operation: str, now: float
    ) -> bool:
        """Atomically consume a one-use approval, or return False.

        Bound to the exact router and operation and to an expiry; a consumed or
        expired or mismatched approval never authorizes a destructive write.
        """
        record = self._approvals.get(approval_id)
        if record is None or record.get("used"):
            return False
        if record.get("router_id") != router_id or record.get("operation") != operation:
            return False
        expires = record.get("expires_at")
        if not isinstance(expires, (int, float)) or isinstance(expires, bool):
            return False
        if now > expires:
            return False
        record["used"] = True
        return True

    def approvals_view(self) -> dict[str, dict[str, Any]]:
        return {key: dict(value) for key, value in self._approvals.items()}


@dataclass(frozen=True)
class OperationSpec:
    operation: str
    capability: Capability
    destructive: bool = False
    requires_password: bool = False
    band_scoped: bool = False
    vap_scoped: bool = False
    notes: str = ""
    fields: frozenset[str] = frozenset()
    implemented: bool = False
    firmware_advertised: bool | None = None
    # Never claim hardware verification without a real write on the firmware.
    hardware_write_verified: bool = False
    # No native UniFi button is claimed until a real contract is known.
    unifi_mapping: None = None


def _specs() -> tuple[OperationSpec, ...]:
    available = Capability.AVAILABLE
    unverified = Capability.IMPLEMENTED_UNVERIFIED
    unsupported = Capability.UNSUPPORTED
    fw = True  # firmware advertises the field; no hardware write verified.
    return (
        OperationSpec(
            "wifi.80211r", available, vap_scoped=True,
            fields=frozenset({"enabled"}), implemented=True, firmware_advertised=fw,
            notes="Dot11REnable via WlanGuideBasic action=11rSetting.",
        ),
        OperationSpec(
            "wifi.twt", available, vap_scoped=True,
            fields=frozenset({"enabled"}), implemented=True, firmware_advertised=fw,
            notes="TWTEnable via WlanGuideBasic action=TWTSetting.",
        ),
        OperationSpec(
            "wifi.mac_filter.block", unverified, band_scoped=False,
            fields=frozenset({"mac", "name"}), implemented=True, firmware_advertised=fw,
            notes="Whole 2-band wlanfilterenhance state; blacklist mode only.",
        ),
        OperationSpec(
            "wifi.mac_filter.unblock", unverified, band_scoped=False,
            fields=frozenset({"mac"}), implemented=True, firmware_advertised=fw,
            notes="Removes one MAC from the blacklist, preserving the rest.",
        ),
        OperationSpec(
            "wifi.guest.set", unverified, band_scoped=False,
            requires_password=True,
            fields=frozenset({"enabled", "ssid", "security", "password", "duration"}),
            implemented=True, firmware_advertised=fw,
            notes="Guest enable/SSID/security; password readback is masked.",
        ),
        OperationSpec(
            "system.reboot", unverified, destructive=True,
            implemented=True, firmware_advertised=fw,
            notes="Destructive: one-use approval plus observed down/up.",
        ),
        OperationSpec(
            "wifi.primary.ssid", unsupported,
            notes="Primary SSID is handled by the TR-069 control path.",
        ),
        OperationSpec(
            "wifi.primary.channel", unsupported,
            notes="Channel is handled by the TR-069 control path.",
        ),
        OperationSpec(
            "wifi.primary.wmm", unsupported,
            notes="WMM is handled by the TR-069 control path.",
        ),
        OperationSpec(
            "client.disconnect", unsupported,
            notes="Temporary disconnect != block; no safe endpoint.",
        ),
        OperationSpec(
            "wifi.channel_width", unsupported,
            notes="No verified endpoint; width is never invented.",
        ),
        OperationSpec(
            "wifi.transmit_power", unsupported,
            notes="No verified endpoint; power is never invented.",
        ),
        OperationSpec(
            "wifi.primary.security", unsupported,
            notes="Primary security/password readback is masked.",
        ),
        OperationSpec(
            "network.vlan", unsupported,
            notes="Guest isolation is not VLAN; no VLAN endpoint exists.",
        ),
        OperationSpec(
            "system.firmware", unsupported, notes="Firmware update is out of scope.",
        ),
        OperationSpec(
            "system.factory_reset", unsupported, destructive=True,
            notes="Factory reset is never exposed.",
        ),
    )


MANIFEST: Mapping[str, OperationSpec] = {s.operation: s for s in _specs()}


def capability_manifest() -> list[dict[str, Any]]:
    """Structured manifest for integration/UI consumption (no secrets)."""
    return [
        {
            "operation": s.operation,
            "capability": s.capability.value,
            "implemented": s.implemented,
            "firmware_advertised": s.firmware_advertised,
            "hardware_write_verified": s.hardware_write_verified,
            "destructive": s.destructive,
            "requires_password": s.requires_password,
            "band_scoped": s.band_scoped,
            "vap_scoped": s.vap_scoped,
            "fields": sorted(s.fields),
            "unifi_mapping": s.unifi_mapping,
            "notes": s.notes,
        }
        for s in MANIFEST.values()
    ]


def allowed_fields(operation: str) -> frozenset[str]:
    spec = MANIFEST.get(operation)
    return spec.fields if spec else frozenset()


def operation_read_endpoint(operation: str) -> tuple[str | None, str | None]:
    handler = _HANDLERS.get(operation)
    if handler is None:
        return None, None
    return handler.read_source or None, handler.read_path or None


def _config_entries(data: Any) -> list[Mapping[str, Any]]:
    if isinstance(data, Mapping):
        entries = data.get("WifiConfig")
        if isinstance(entries, list):
            return [e for e in entries[:MAX_READBACK_ENTRIES] if isinstance(e, Mapping)]
        return []
    if isinstance(data, list):
        return [e for e in data[:MAX_READBACK_ENTRIES] if isinstance(e, Mapping)]
    return []


def resolve_wifi_entry(data: Any, vap_id: Any) -> Mapping[str, Any]:
    """Locate one WifiConfig entry by native ``ID``; ambiguous -> reject."""
    entries = _config_entries(data)
    if vap_id is None or vap_id == "":
        raise OperationRejected("ambiguous_binding", "vap_id-required")
    matches = [e for e in entries if str(e.get("ID")) == str(vap_id)]
    if len(matches) != 1:
        raise OperationRejected(
            "ambiguous_binding", "vap-not-found" if not matches else "vap-duplicate"
        )
    return matches[0]


def resolve_band_pair(data: Any) -> dict[str, Mapping[str, Any]]:
    """Return both band entries for a whole-state 2-band write."""
    entries = _config_entries(data)
    found: dict[str, Mapping[str, Any]] = {}
    for entry in entries:
        band = normalize_band(entry.get("FrequencyBand"))
        if band is not None and band not in found:
            found[band] = entry
    if "2.4g" not in found or "5g" not in found:
        raise OperationRejected("ambiguous_binding", "band-pair-incomplete")
    return found


def resolve_band_entry(data: Any, band: str) -> Mapping[str, Any]:
    return resolve_band_pair(data)[band]


@dataclass(frozen=True)
class BuiltCall:
    path: str
    payload: Mapping[str, Any]
    extra: Mapping[str, Any] | None
    headers: Mapping[str, str] | None
    secret_involved: bool


def _validate_ssid(value: Any) -> str:
    ssid = _bounded_text(value, SSID_MAX)
    if ssid is None:
        raise OperationRejected("invalid_payload", "ssid")
    return ssid


def _validate_password(value: Any) -> str:
    if not isinstance(value, str) or not value:
        raise OperationRejected("secret_required", "password")
    if len(value) > PASSWORD_MAX or any(not ch.isprintable() for ch in value):
        raise OperationRejected("invalid_payload", "password")
    return value


def _validate_duration(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise OperationRejected("invalid_payload", "duration")
    if value not in GUEST_DURATIONS:
        raise OperationRejected("invalid_payload", "duration")
    return value


def _resolve_security(value: Any) -> tuple[str, bool]:
    """Closed security map: only the two verified router enums are accepted."""
    if value is None:
        raise OperationRejected("security_unknown")
    lowered = str(value).strip().lower()
    if lowered in ("open", "none"):
        return SEC_OPEN, False
    if lowered in ("psk", "secure", "encrypted", "tkip"):
        return SEC_ENCRYPTED, True
    raise OperationRejected("security_unknown", lowered[:16])


def _build_switch(request: OperationRequest, data: Any) -> tuple[
    Mapping[str, Any], Mapping[str, Any], Mapping[str, Any]
]:
    state = request.fields.get("enabled")
    enabled = _as_bool(state)
    if enabled is None:
        raise OperationRejected("invalid_payload", "enabled")
    entry = resolve_wifi_entry(data, request.target.vap_id)
    field_name = "Dot11REnable" if request.operation == "wifi.80211r" else "TWTEnable"
    current = _as_bool(entry.get(field_name))
    if current is None:
        raise OperationRejected("unknown_field", field_name)
    current_projection = {field_name: current}
    target_projection = {field_name: enabled}
    payload = {field_name: enabled}
    return payload, current_projection, target_projection


def _build_11r(request: OperationRequest, data: Any) -> BuiltCall:
    payload, _, _ = _build_switch(request, data)
    return BuiltCall(URL_WLAN_GUIDE, payload, {"action": "11rSetting"}, None, False)


def _build_twt(request: OperationRequest, data: Any) -> BuiltCall:
    payload, _, _ = _build_switch(request, data)
    return BuiltCall(URL_WLAN_GUIDE, payload, {"action": "TWTSetting"}, None, False)


def _project_11r(request: OperationRequest, data: Any) -> Mapping[str, Any]:
    _, current, _ = _build_switch(request, data)
    return dict(current)


def _project_11r_target(request: OperationRequest, data: Any) -> Mapping[str, Any]:
    _, _, target = _build_switch(request, data)
    return dict(target)


def _project_twt(request: OperationRequest, data: Any) -> Mapping[str, Any]:
    return _project_11r(request, data)


def _project_twt_target(request: OperationRequest, data: Any) -> Mapping[str, Any]:
    return _project_11r_target(request, data)


def _mac_entries(state: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    raw = state.get("BMacAddresses")
    if raw is None:
        raw = state.get("BMacFilters")
    if not isinstance(raw, list):
        return []
    return [e for e in raw if isinstance(e, Mapping)]


def _mac_list(state: Mapping[str, Any]) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for entry in _mac_entries(state):
        mac = entry.get("MACAddress")
        if isinstance(mac, str) and MAC_RE.fullmatch(mac.strip().lower()):
            item: dict[str, Any] = {"MACAddress": mac.strip().lower()}
            hostname = _bounded_text(entry.get("HostName"), 64)
            if hostname:
                item["HostName"] = hostname
            result.append(item)
    return result


def _mac_filter_context(
    request: OperationRequest, data: Any
) -> tuple[dict[str, Mapping[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    bands = resolve_band_pair(data)
    state_2g = bands["2.4g"]
    state_5g = bands["5g"]
    for state in (state_2g, state_5g):
        if _as_bool(state.get("MACAddressControlEnabled")) is not True:
            raise OperationRejected("filtering_disabled")
        policy = state.get("MacFilterPolicy")
        if isinstance(policy, bool) or policy != FILTER_BLACKLIST:
            if request.operation == "wifi.mac_filter.block":
                raise OperationRejected("whitelist_mode_unsupported")
    return bands, _mac_list(state_2g), _mac_list(state_5g)


def _build_mac_filter(request: OperationRequest, data: Any) -> BuiltCall:
    bands, black_2g, black_5g = _mac_filter_context(request, data)
    mac = normalize_mac(request.fields.get("mac"))
    blocking = request.operation == "wifi.mac_filter.block"

    def apply_to(blacklist: list[dict[str, Any]]) -> list[dict[str, Any]]:
        present = any(item.get("MACAddress") == mac for item in blacklist)
        if blocking:
            if present:
                return blacklist
            item: dict[str, Any] = {"MACAddress": mac}
            hostname = _bounded_text(request.fields.get("name"), 64)
            if hostname:
                item["HostName"] = hostname
            return blacklist + [item]
        return [i for i in blacklist if i.get("MACAddress") != mac]

    def config(state: Mapping[str, Any], blacklist: list[dict[str, Any]]) -> dict[str, Any]:
        return {
            "MACAddressControlEnabled": True,
            "WMacFilters": state.get("WMacAddresses") or [],
            "ID": state.get("ID"),
            "MacFilterPolicy": state.get("MacFilterPolicy"),
            "BMacFilters": blacklist,
            "FrequencyBand": state.get("FrequencyBand"),
        }

    payload = {
        "config2g": config(bands["2.4g"], apply_to(black_2g)),
        "config5g": config(bands["5g"], apply_to(black_5g)),
    }
    return BuiltCall(URL_WLAN_FILTER, payload, None, None, False)


def _mac_projection(
    request: OperationRequest, black_2g: list[dict[str, Any]],
    black_5g: list[dict[str, Any]],
) -> Mapping[str, Any]:
    return {
        "mac": normalize_mac(request.fields.get("mac")),
        "blocking": request.operation == "wifi.mac_filter.block",
        "2.4g": sorted(i.get("MACAddress", "") for i in black_2g),
        "5g": sorted(i.get("MACAddress", "") for i in black_5g),
    }


def _project_mac_current(request: OperationRequest, data: Any) -> Mapping[str, Any]:
    _, black_2g, black_5g = _mac_filter_context(request, data)
    return _mac_projection(request, black_2g, black_5g)


def _project_mac_target(request: OperationRequest, data: Any) -> Mapping[str, Any]:
    _, black_2g, black_5g = _mac_filter_context(request, data)
    mac = normalize_mac(request.fields.get("mac"))
    blocking = request.operation == "wifi.mac_filter.block"

    def apply_to(blacklist: list[dict[str, Any]]) -> list[dict[str, Any]]:
        present = any(item.get("MACAddress") == mac for item in blacklist)
        if blocking:
            return blacklist if present else blacklist + [{"MACAddress": mac}]
        return [i for i in blacklist if i.get("MACAddress") != mac]

    return _mac_projection(request, apply_to(black_2g), apply_to(black_5g))


def _guest_entry(bands: Mapping[str, Mapping[str, Any]], band: str) -> Mapping[str, Any]:
    entry = bands[band]
    for key in ("ID", "EnableFrequency", "SecOpt"):
        if key not in entry:
            raise OperationRejected("unknown_field", key)
    return entry


def _guest_projection(
    bands: Mapping[str, Mapping[str, Any]], enabled: bool, ssid: str, sec: str
) -> dict[str, Any]:
    projection: dict[str, Any] = {}
    for band in ("2.4g", "5g"):
        entry = bands[band]
        projection[band] = {
            "id": str(entry.get("ID")),
            "Enable": enabled and _as_bool(entry.get("EnableFrequency")) is True,
            "WifiSsid": ssid,
            "SecOpt": sec,
        }
    return projection


def _current_guest_projection(bands: Mapping[str, Mapping[str, Any]]) -> dict[str, Any]:
    projection: dict[str, Any] = {}
    for band in ("2.4g", "5g"):
        entry = bands[band]
        projection[band] = {
            "id": str(entry.get("ID")),
            "Enable": entry.get("EnableFrequency") is True,
            "WifiSsid": entry.get("WifiSsid"),
            "SecOpt": entry.get("SecOpt"),
        }
    return projection


def _guest_desired(request: OperationRequest) -> tuple[bool, str, str, bool, str | None, int]:
    fields = request.fields
    enabled = _as_bool(fields.get("enabled"))
    if enabled is None:
        raise OperationRejected("invalid_payload", "enabled")
    ssid = _validate_ssid(fields.get("ssid"))
    sec, secure = _resolve_security(fields.get("security"))
    duration = _validate_duration(fields.get("duration", 3))
    password: str | None = None
    if secure:
        password = _validate_password(fields.get("password"))
    return enabled, ssid, sec, secure, password, duration


def _build_guest(request: OperationRequest, data: Any, rsa_public_key: Mapping[str, Any] | None) -> BuiltCall:
    bands = resolve_band_pair(data)
    enabled, ssid, sec, secure, password, duration = _guest_desired(request)

    def config(band: str) -> dict[str, Any]:
        entry = _guest_entry(bands, band)
        key_value = ""
        if secure:
            if not crypto_available():
                raise RsaUnavailable("cryptography backend not available")
            if not isinstance(rsa_public_key, Mapping):
                raise OperationRejected("secret_required", "rsa_public_key")
            rsan = rsa_public_key.get("rsan")
            rsae = rsa_public_key.get("rsae")
            try:
                key_value = rsa_oaep_encode(password or "", str(rsan), str(rsae))
            except (ValueError, RsaUnavailable) as exc:
                raise OperationRejected("invalid_payload", "rsa_key") from exc
        return {
            "ID": entry.get("ID"),
            "Enable": enabled and _as_bool(entry.get("EnableFrequency")) is True,
            "WifiSsid": ssid,
            "ValidTime": duration,
            "SecOpt": sec,
            "WpaPreSharedKey": key_value,
        }

    payload = {"config5g": config("5g"), "config2g": config("2.4g")}
    return BuiltCall(URL_GUEST_NETWORK, payload, None, dict(GUEST_HEADERS), secure)


def _project_guest_current(request: OperationRequest, data: Any) -> Mapping[str, Any]:
    return _current_guest_projection(resolve_band_pair(data))


def _project_guest_target(request: OperationRequest, data: Any) -> Mapping[str, Any]:
    bands = resolve_band_pair(data)
    enabled, ssid, sec, _, _, _ = _guest_desired(request)
    return _guest_projection(bands, enabled, ssid, sec)


def _build_reboot(request: OperationRequest, data: Any) -> BuiltCall:
    return BuiltCall(URL_REBOOT, {}, None, None, False)


@dataclass(frozen=True)
class _Handler:
    build: Callable[..., BuiltCall]
    current: Callable[[OperationRequest, Any], Mapping[str, Any]]
    target: Callable[[OperationRequest, Any], Mapping[str, Any]]
    read_source: str
    read_path: str
    needs_rsa: bool = False


_HANDLERS: Mapping[str, _Handler] = {
    "wifi.80211r": _Handler(
        _build_11r, _project_11r, _project_11r_target, "wlanguide", URL_WLAN_GUIDE
    ),
    "wifi.twt": _Handler(
        _build_twt, _project_twt, _project_twt_target, "wlanguide", URL_WLAN_GUIDE
    ),
    "wifi.mac_filter.block": _Handler(
        _build_mac_filter, _project_mac_current, _project_mac_target,
        "wlan_filter", URL_WLAN_FILTER,
    ),
    "wifi.mac_filter.unblock": _Handler(
        _build_mac_filter, _project_mac_current, _project_mac_target,
        "wlan_filter", URL_WLAN_FILTER,
    ),
    "wifi.guest.set": _Handler(
        _build_guest, _project_guest_current, _project_guest_target,
        "guest_network", URL_GUEST_NETWORK, True,
    ),
    "system.reboot": _Handler(
        _build_reboot, lambda r, d: {}, lambda r, d: {}, "", ""
    ),
}


class _Budget:
    def __init__(self, max_calls: int, deadline: float | None, clock: Callable[[], float]):
        self._remaining = max_calls
        self._deadline = deadline
        self._clock = clock
        self.calls = 0

    def spend(self) -> None:
        if self._deadline is not None and self._clock() > self._deadline:
            raise BudgetExhausted("deadline")
        if self._remaining <= 0:
            raise BudgetExhausted("call-limit")
        self._remaining -= 1
        self.calls += 1


class OperationEngine:
    """Plan/apply/readback engine bound to one router identity.

    All side effects are delegated to the injected ``transport``. The engine is
    fail-closed: writes are refused unless ``policy.writes_enabled`` is set and
    the operation is explicitly allowlisted.
    """

    def __init__(
        self,
        transport: Transport,
        *,
        identity: RouterIdentity,
        policy: Policy | None = None,
        store: TransactionStore | None = None,
        clock: Callable[[], float] | None = None,
    ) -> None:
        self.transport = transport
        self.identity = identity
        self.policy = policy or default_policy()
        self.store = store or TransactionStore()
        self._clock = clock
        self._destructive_used: set[str] = set()
        # Per-engine salt so secret digests cannot be brute-forced off-line.
        self._secret_salt = secrets.token_bytes(16)

    def _now(self) -> float:
        if self._clock is not None:
            return self._clock()
        import time  # local import keeps module import side-effect free

        return time.monotonic()

    def _secret_digest(self, value: str) -> str:
        return hashlib.blake2b(
            value.encode("utf-8"), key=self._secret_salt, digest_size=16
        ).hexdigest()

    def _hash(self, value: Any) -> str:
        return hashlib.sha256(_canonical(value).encode("utf-8")).hexdigest()

    def _validate_grant(self, grant: CoordinatorGrant) -> None:
        if not isinstance(grant, CoordinatorGrant):
            raise OperationRejected("unauthorized")
        if grant.router_id != self.identity.router_id:
            raise OperationRejected("target_not_allowlisted", "grant-router-mismatch")
        if not isinstance(grant.subject, str) or not grant.subject:
            raise OperationRejected("unauthorized")

    def _validate_request(self, request: OperationRequest, grant: CoordinatorGrant) -> OperationSpec:
        if not isinstance(request.operation_id, str) or not request.operation_id:
            raise OperationRejected("invalid_payload", "operation_id")
        spec = MANIFEST.get(request.operation)
        if spec is None:
            raise OperationRejected("unknown_operation")
        grant_scope = grant.operations or self.policy.enabled_operations
        if request.operation not in grant_scope:
            raise OperationRejected("operation_not_allowlisted")
        target = request.target
        if target.router_id != self.identity.router_id:
            raise OperationRejected("target_not_allowlisted")
        if self.policy.allowlisted_router_ids and (
            target.router_id not in self.policy.allowlisted_router_ids
        ):
            raise OperationRejected("target_not_allowlisted")
        if spec.band_scoped:
            if normalize_band(target.band) is None and target.band not in ("2.4g", "5g"):
                raise OperationRejected("invalid_target", "band")
        if spec.vap_scoped and (target.vap_id is None or target.vap_id == ""):
            raise OperationRejected("invalid_target", "vap_id")
        return spec

    def _gate_capability(self, spec: OperationSpec) -> None:
        if spec.capability is Capability.UNSUPPORTED:
            raise OperationRejected("capability_unsupported")
        if not self.policy.writes_enabled:
            raise OperationRejected("writes_disabled")
        if spec.capability is Capability.IMPLEMENTED_UNVERIFIED:
            if spec.operation not in self.policy.enabled_operations:
                raise OperationRejected("capability_unverified", "not-explicitly-enabled")

    def _gate_destructive(self, spec: OperationSpec, *, consume: bool) -> None:
        if not spec.destructive:
            return
        if not self.policy.reboot_approved:
            raise OperationRejected("destructive_approval_required")
        if spec.operation in self._destructive_used:
            raise OperationRejected("destructive_approval_reused")
        if consume:
            self._destructive_used.add(spec.operation)

    def _snapshot_data(self, snapshot: Snapshot) -> Mapping[str, Any]:
        if snapshot.router_id != self.identity.router_id:
            raise OperationRejected("target_not_allowlisted", "snapshot-router-mismatch")
        max_age = self.policy.snapshot_max_age_seconds
        age = snapshot.age_seconds
        if isinstance(age, bool) or not isinstance(age, (int, float)):
            raise OperationRejected("stale_snapshot")
        # NaN passes both "< 0" and "> max": reject any non-finite age explicitly.
        if not math.isfinite(age) or age < 0 or age > max_age:
            raise OperationRejected("stale_snapshot")
        return snapshot.data

    def _read(self, path: str, budget: _Budget) -> Any:
        budget.spend()
        try:
            return self.transport.read(path)
        except TransportError:
            raise
        except BudgetExhausted:
            raise
        except Exception as exc:  # noqa: BLE001 - normalise to a typed failure
            raise TransportError(type(exc).__name__, "read") from exc

    def plan(
        self, request: OperationRequest, snapshot: Snapshot, grant: CoordinatorGrant
    ) -> Plan:
        self._validate_grant(grant)
        spec = self._validate_request(request, grant)
        self._gate_capability(spec)
        self._gate_destructive(spec, consume=False)

        data = self._snapshot_data(snapshot)
        handler = _HANDLERS[request.operation]
        source = data.get(handler.read_source) if handler.read_source else None
        if handler.read_source and source is None:
            raise OperationRejected("stale_snapshot", "missing-" + handler.read_source)

        rsa_key = data.get("rsa_public_key")
        if handler.needs_rsa:
            built = handler.build(request, source, rsa_key)
            current = dict(handler.current(request, source))
            target = dict(handler.target(request, source))
        else:
            built = handler.build(request, source)
            current = dict(handler.current(request, source))
            target = dict(handler.target(request, source))

        if built.secret_involved and not self.policy.allow_unverified_writes:
            # A masked secret can never be read back, so the write could not be
            # verified; it stays disabled unless policy explicitly opts in.
            raise OperationRejected("unverified_write_disabled")

        projection = {
            "operation": request.operation,
            "target": {"router_id": target_router(request), "band": request.target.band,
                       "vap_id": request.target.vap_id},
            "fields": self._redacted_fields(request, built.secret_involved),
        }
        payload_hash = self._hash([projection, built.payload])
        preimage_hash = self._hash(current)
        return Plan(
            request=request,
            capability=spec.capability,
            path=built.path,
            payload=built.payload,
            extra=built.extra,
            headers=built.headers,
            current_projection=current,
            target_projection=target,
            secret_involved=built.secret_involved,
            destructive=spec.destructive,
            payload_hash=payload_hash,
            preimage_hash=preimage_hash,
        )

    def _redacted_fields(self, request: OperationRequest, secret_involved: bool) -> dict[str, Any]:
        fields = dict(request.fields)
        if "password" in fields:
            password = fields.pop("password")
            # Only a salted digest is ever folded into the hash; the value
            # itself is dropped here and never stored.
            fields["password"] = (
                self._secret_digest(password) if isinstance(password, str) else "<invalid>"
            )
        # A stable marker keeps hash comparisons meaningful without the secret.
        if secret_involved:
            fields["_secret"] = True
        return fields

    def readback(self, plan: Plan, grant: CoordinatorGrant) -> Result:
        self._validate_grant(grant)
        handler = _HANDLERS[plan.request.operation]
        if not handler.read_source:
            return Result(
                plan.request.operation_id, plan.request.operation, Outcome.UNCERTAIN,
                reason="no_readback_contract", requires_operator_confirmation=True,
            )
        budget = _Budget(self.policy.max_transport_calls, self._deadline(), self._now)
        try:
            source = self._read(handler.read_path, budget) if handler.read_path else {}
        except (TransportError, BudgetExhausted) as exc:
            return Result(
                plan.request.operation_id, plan.request.operation, Outcome.FAILED,
                reason=self._reason(exc), transport_calls=budget.calls,
            )
        current = dict(handler.current(plan.request, source))
        evidence = {"readback": current, "target": plan.target_projection}
        if self._matches(current, plan.target_projection):
            outcome = Outcome.VERIFIED_CHANGED
        else:
            outcome = Outcome.UNCERTAIN
        return Result(
            plan.request.operation_id, plan.request.operation, outcome,
            evidence=evidence, transport_calls=budget.calls,
        )

    def apply(self, plan: Plan, grant: CoordinatorGrant) -> Result:
        self._validate_grant(grant)
        spec = MANIFEST[plan.request.operation]
        request = plan.request
        target_key = {
            "router_id": request.target.router_id,
            "band": request.target.band,
            "vap_id": request.target.vap_id,
        }

        # Idempotency: answer from the ledger before touching the transport.
        existing = self.store.get(request.operation_id)
        if existing is not None:
            if existing.payload_hash != plan.payload_hash:
                return Result(
                    request.operation_id, request.operation, Outcome.REJECTED,
                    reason="replay_conflict",
                )
            if existing.state in TERMINAL_OUTCOMES:
                return Result(
                    request.operation_id, request.operation, existing.state,
                    reason="duplicate_terminal", evidence=existing.evidence,
                )
            # In-flight (pending/uncertain): never resend.
            return Result(
                request.operation_id, request.operation, existing.state,
                reason="inflight_no_resend", evidence=existing.evidence,
            )

        blocking = self.store.unresolved_for(request.target.router_id)
        if blocking is not None:
            # Router-wide lock: an unresolved record (any type) blocks every new
            # operation for this physical router, across operation_ids. It is
            # checked before the destructive gate so a blocked request never
            # burns the one-use reboot approval.
            return Result(
                request.operation_id, request.operation, Outcome.REJECTED,
                reason="router_operation_locked",
                evidence={"blocking_operation_id": blocking.operation_id,
                          "blocking_operation": blocking.operation,
                          "blocking_state": blocking.state.value},
            )

        # Destructive approval is consumed at apply time.
        try:
            self._gate_destructive(spec, consume=True)
        except OperationRejected as exc:
            return self._record_failure(request, target_key, Outcome.REJECTED,
                                        exc.reason, plan)

        record = TransactionRecord(
            operation_id=request.operation_id,
            operation=request.operation,
            payload_hash=plan.payload_hash,
            preimage_hash=plan.preimage_hash,
            state=Outcome.PENDING,
            target=target_key,
        )
        try:
            self.store.begin(record)
        except LedgerError as exc:
            # The pending record must be durable before any POST; if it cannot
            # be persisted, refuse the write instead of risking a duplicate.
            return Result(
                request.operation_id, request.operation, Outcome.REJECTED,
                reason="ledger_invalid", evidence={"detail": exc.reason},
            )

        if spec.destructive:
            return self._apply_reboot(plan, target_key)

        budget = _Budget(self.policy.max_transport_calls, self._deadline(), self._now)
        handler = _HANDLERS[request.operation]

        # Fresh preimage read (definitive failure if it faults: nothing sent).
        try:
            fresh_source = self._read(handler.read_path, budget) if handler.read_path else {}
            fresh_current = dict(handler.current(request, fresh_source))
        except (TransportError, BudgetExhausted) as exc:
            return self._finalise(
                request, target_key, Outcome.FAILED, self._reason(exc),
                {"phase": "preflight"}, budget.calls,
            )

        # Truthful no-op: desired already present, no write performed.
        if not plan.secret_involved and self._matches(fresh_current, plan.target_projection):
            return self._finalise(
                request, target_key, Outcome.VERIFIED_NOOP, "already_applied",
                {"phase": "preflight", "readback": fresh_current}, budget.calls,
            )

        # Precondition fingerprint: the fresh preimage must still match the
        # planned baseline, or a concurrent change (e.g. another MAC added to
        # the whole-list write) would be silently overwritten. This holds even
        # for secret-bearing requests (guest password): the compared projections
        # carry only observable fields (never the masked password), so a
        # concurrent SSID/enabled change blocks the write instead of being
        # overwritten. Replan required.
        if self._hash(fresh_current) != plan.preimage_hash:
            return self._finalise(
                request, target_key, Outcome.REJECTED, "precondition_changed",
                {"phase": "preflight", "baseline": plan.preimage_hash,
                 "fresh": self._hash(fresh_current)}, budget.calls,
            )

        try:
            budget.spend()
            self.transport.post(
                plan.path, plan.payload, extra=plan.extra, headers=plan.headers
            )
        except BudgetExhausted as exc:
            return self._finalise(request, target_key, Outcome.FAILED, self._reason(exc),
                                  {"phase": "write"}, budget.calls)
        except TransportError as exc:
            outcome = Outcome.FAILED if exc.phase in ("pre_send", "send", "read") else Outcome.UNCERTAIN
            return self._finalise(request, target_key, outcome, exc.reason,
                                  {"phase": exc.phase}, budget.calls)
        except Exception as exc:  # noqa: BLE001 - unknown post-send state
            return self._finalise(request, target_key, Outcome.UNCERTAIN,
                                  type(exc).__name__, {"phase": "write"}, budget.calls)

        try:
            post_source = self._read(handler.read_path, budget) if handler.read_path else {}
            post_current = dict(handler.current(request, post_source))
        except (TransportError, BudgetExhausted) as exc:
            return self._finalise(request, target_key, Outcome.UNCERTAIN,
                                  "readback_" + self._reason(exc),
                                  {"phase": "readback"}, budget.calls)

        evidence = {"readback": post_current, "target": plan.target_projection}
        if self._matches(post_current, plan.target_projection):
            outcome = Outcome.APPLIED_UNVERIFIED if plan.secret_involved else Outcome.VERIFIED_CHANGED
            reason = "password_masked" if plan.secret_involved else None
        else:
            outcome = Outcome.UNCERTAIN
            reason = "readback_mismatch"
        return self._finalise(request, target_key, outcome, reason, evidence, budget.calls)

    def _apply_reboot(self, plan: Plan, target_key: Mapping[str, Any]) -> Result:
        request = plan.request
        budget = _Budget(self.policy.max_transport_calls, self._deadline(), self._now)
        try:
            budget.spend()
            self.transport.post(plan.path, plan.payload, extra=plan.extra, headers=plan.headers)
        except BudgetExhausted as exc:
            return self._finalise(request, target_key, Outcome.FAILED, self._reason(exc),
                                  {"phase": "write"}, budget.calls)
        except TransportError as exc:
            outcome = Outcome.FAILED if exc.phase in ("pre_send", "send") else Outcome.UNCERTAIN
            return self._finalise(request, target_key, outcome, exc.reason,
                                  {"phase": exc.phase}, budget.calls)
        except Exception as exc:  # noqa: BLE001
            return self._finalise(request, target_key, Outcome.UNCERTAIN,
                                  type(exc).__name__, {"phase": "write"}, budget.calls)

        # HTTP 200 is not a verified reboot: only an observed down/up cycle is.
        saw_down = False
        reads = 0
        while reads < self.policy.reboot_max_reads and budget.calls < self.policy.max_transport_calls:
            reads += 1
            try:
                budget.spend()
                self.transport.read(URL_DEVICE_INFO)
                if saw_down:
                    return self._finalise(
                        request, target_key, Outcome.VERIFIED_CHANGED, "observed_down_up",
                        {"phase": "observe", "down": True, "up": True}, budget.calls,
                    )
            except TransportError:
                saw_down = True
            except BudgetExhausted:
                break
            except Exception:  # noqa: BLE001 - any read fault counts as down
                saw_down = True
            self._sleep(0.0)
        return self._finalise(
            request, target_key, Outcome.UNCERTAIN,
            "down_up_not_observed" if not saw_down else "up_not_observed",
            {"phase": "observe", "down": saw_down,
             "requires_operator_confirmation": True},
            budget.calls,
        )

    def _sleep(self, seconds: float) -> None:
        if self._clock is not None:
            return
        import time

        if seconds > 0:
            time.sleep(seconds)

    def execute(
        self, request: OperationRequest, snapshot: Snapshot, grant: CoordinatorGrant
    ) -> Result:
        """Plan then apply. Rejections are returned, never raised for policy."""
        try:
            plan = self.plan(request, snapshot, grant)
        except OperationRejected as exc:
            return Result(
                request.operation_id, request.operation, Outcome.REJECTED,
                reason=exc.reason,
            )
        except RsaUnavailable as exc:
            return Result(
                request.operation_id, request.operation, Outcome.REJECTED,
                reason="capability_unsupported", evidence={"detail": str(exc)},
            )
        return self.apply(plan, grant)

    def _deadline(self) -> float | None:
        timeout = self.policy.callback_timeout_seconds
        if timeout is None or timeout <= 0:
            return None
        return self._now() + float(timeout)

    @staticmethod
    def _matches(observed: Mapping[str, Any], target: Mapping[str, Any]) -> bool:
        return _canonical(observed) == _canonical(target)

    @staticmethod
    def _reason(exc: Exception) -> str:
        if isinstance(exc, BudgetExhausted):
            return "budget:" + str(exc)
        if isinstance(exc, TransportError):
            return exc.reason
        return type(exc).__name__

    def _finalise(
        self,
        request: OperationRequest,
        target_key: Mapping[str, Any],
        outcome: Outcome,
        reason: str | None,
        evidence: Mapping[str, Any],
        calls: int,
    ) -> Result:
        requires_confirmation = bool(evidence.get("requires_operator_confirmation"))
        evidence = dict(evidence)
        try:
            self.store.finish(
                request.operation_id, outcome, reason=reason, evidence=evidence
            )
        except LedgerError:
            # A post-send result that cannot be persisted is never reported as
            # verified: it degrades to uncertain and the write gate closes.
            outcome = Outcome.UNCERTAIN
            reason = reason or "ledger_degraded"
            evidence["persisted"] = False
            requires_confirmation = True
        return Result(
            request.operation_id, request.operation, outcome,
            reason=reason, evidence=evidence, transport_calls=calls,
            requires_operator_confirmation=requires_confirmation,
        )

    def _record_failure(
        self,
        request: OperationRequest,
        target_key: Mapping[str, Any],
        outcome: Outcome,
        reason: str,
        plan: Plan,
    ) -> Result:
        record = TransactionRecord(
            operation_id=request.operation_id,
            operation=request.operation,
            payload_hash=plan.payload_hash,
            preimage_hash=plan.preimage_hash,
            state=outcome,
            target=target_key,
            reason=reason,
        )
        try:
            self.store.begin(record)
        except LedgerError:
            pass
        return Result(request.operation_id, request.operation, outcome, reason=reason)


def target_router(request: OperationRequest) -> str:
    return request.target.router_id
