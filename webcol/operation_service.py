"""Admin control service: token-gated, serialized operations over one CPE.

Pure stdlib plus the existing read-only direct client. The service owns no
socket, no HTTP server and no background thread: administrative work is
scheduled per host onto the caller's event loop and never overlaps a collection
session. Writes stay OFF unless env explicitly enables them and allowlists the
operation; destructive reboot additionally needs a one-use approval.

The transport used here is the real direct session: it performs the upstream
nested POST DTO (``{"data": ...}`` + extra ``action`` + headers + CSRF), never
retries a write automatically, and turns a post-send ambiguity into an
``uncertain`` result instead of a false success or a duplicate write.
"""

from __future__ import annotations

import asyncio
import hmac
import importlib
import json
import logging
import os
import sys
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, Callable, Mapping

_HERE = str(Path(__file__).resolve().parent)
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

operations = importlib.import_module('operations')
huawei_api = importlib.import_module('huawei_api')

LOG = logging.getLogger('webcol.operations')

MAX_BODY_FIELDS = 64
SNAPSHOT_TTL_DEFAULT = 180.0
OPS_BUDGET_DEFAULT = 20.0
LOCK_WAIT_DEFAULT = 5.0
ENGINE_TIMEOUT_DEFAULT = 12.0
MAX_CALLS_DEFAULT = 16

GET_PATHS = frozenset({
    'api/system/deviceinfo',
    'api/system/HostInfo',
    'api/ntwk/WlanGuideBasic?type=notshowpassall',
    'api/ntwk/guest_network?type=notshowpassall',
    'api/ntwk/wlanfilterenhance',
})
WRITE_PATHS = frozenset({
    operations.URL_WLAN_GUIDE,
    operations.URL_GUEST_NETWORK,
    operations.URL_WLAN_FILTER,
    operations.URL_REBOOT,
})
REQUEST_KEYS = frozenset({'router', 'operation', 'operation_id', 'target', 'fields', 'approval_id'})
TARGET_KEYS = frozenset({'band', 'vap_id'})
ENV_WRITES = 'HW_OPERATIONS_WRITES'
ENV_ALLOW = 'HW_OPERATIONS_ALLOW'
ENV_UNVERIFIED = 'HW_OPERATIONS_UNVERIFIED_WRITES'
ENV_REBOOT = 'HW_OPERATIONS_REBOOT_APPROVED'
ENV_TOKEN = 'HW_OPERATIONS_TOKEN'
ENV_RESOLVE = 'HW_OPERATIONS_RESOLVE'
ENV_STATE = 'HW_OPERATIONS_STATE'

# Login reasons that must open the shared credential circuit (backoff), never
# retried and never falling back to another transport.
BLOCKING_LOGIN_REASONS = frozenset({'credentials', 'locked'})


def _truthy(value: str | None) -> bool:
    return bool(value) and value.strip().lower() in ('1', 'true', 'yes', 'on')


def token_ok(provided: Any, expected: str | None) -> bool:
    """Constant-time bearer comparison; an empty expected token never passes."""
    if not expected or not isinstance(provided, str) or not provided:
        return False
    return hmac.compare_digest(provided.encode('utf-8'), expected.encode('utf-8'))


def redact(text: Any, limit: int = 200) -> str:
    """Return a bounded, printable code-only string (no router text/secrets)."""
    if not isinstance(text, str):
        text = type(text).__name__
    cleaned = ''.join(ch for ch in text if ch.isprintable())[:limit]
    return cleaned


@dataclass(frozen=True)
class RouterBinding:
    router_id: str
    host: str
    password: str
    expected_serial: str | None = None


def build_registry(
    routers: list[tuple[str, str]], serials: Mapping[str, str] | None = None
) -> dict[str, RouterBinding]:
    """Validated registry built only from config; callers cannot forge it."""
    serials = serials or {}
    registry: dict[str, RouterBinding] = {}
    for host, password in routers:
        router_id = _router_id(host)
        if not router_id or router_id in registry:
            continue
        registry[router_id] = RouterBinding(
            router_id=router_id, host=host, password=password,
            expected_serial=serials.get(host) or serials.get(router_id) or None,
        )
    return registry


def _router_id(host: str) -> str:
    from urllib.parse import urlsplit
    try:
        hostname = urlsplit(host).hostname
    except ValueError:
        return ''
    return hostname or ''


class SessionIdentityError(Exception):
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


class DirectSessionTransport:
    """Engine Transport over one authenticated :class:`HuaweiSession`."""

    def __init__(self, session: 'HuaweiSession') -> None:
        self._session = session

    def read(self, path: str) -> Any:
        return self._session.read(path)

    def post(
        self,
        path: str,
        payload: Mapping[str, Any],
        *,
        extra: Mapping[str, Any] | None = None,
        headers: Mapping[str, str] | None = None,
    ) -> Any:
        return self._session.post(path, payload, extra=extra, headers=headers)


class HuaweiSession:
    """One bounded authenticated direct session bound to a validated identity."""

    def __init__(
        self,
        client: Any,
        binding: RouterBinding,
        *,
        log: logging.Logger | None = None,
    ) -> None:
        self._client = client
        self._binding = binding
        self._log = log or LOG
        self._open = False
        self.serial: str | None = None
        self.software: str | None = None

    def open(self) -> dict[str, Any]:
        try:
            self._client.login()
        except Exception as exc:  # noqa: BLE001 - code-only classification
            raise SessionIdentityError(self._login_reason(exc)) from None
        self._open = True
        try:
            deviceinfo = self.read("api/system/deviceinfo")
        except Exception:  # noqa: BLE001
            self.close()
            raise SessionIdentityError("deviceinfo") from None
        serial = deviceinfo.get("SerialNumber") if isinstance(deviceinfo, Mapping) else None
        serial = serial.strip()[:64] if isinstance(serial, str) else None
        expected = self._binding.expected_serial
        if expected and serial != expected:
            self.close()
            raise SessionIdentityError("serial-mismatch")
        self.serial = serial or None
        software = deviceinfo.get("SoftwareVersion") if isinstance(deviceinfo, Mapping) else None
        self.software = software.strip()[:64] if isinstance(software, str) else None
        return {
            "router_id": self._binding.router_id,
            "serial": self.serial,
            "software": self.software,
            "public_key_verified": bool(getattr(self._client, "public_key_verified", False)),
        }

    @staticmethod
    def _login_reason(exc: Exception) -> str:
        reason = getattr(exc, "reason", None)
        if isinstance(reason, str) and reason:
            return reason
        return "login:" + type(exc).__name__

    def public_key(self) -> dict[str, str] | None:
        if not getattr(self._client, "public_key_verified", False):
            return None
        key = getattr(self._client, "public_key", None)
        if not isinstance(key, Mapping):
            return None
        rsan = key.get("rsan")
        rsae = key.get("rsae")
        if not isinstance(rsan, str) or not isinstance(rsae, str):
            return None
        return {"rsan": rsan, "rsae": rsae}

    def read(self, path: str) -> Any:
        if path not in GET_PATHS:
            raise operations.TransportError("path_not_allowed", "read")
        if not self._open:
            raise operations.TransportError("session_closed", "read")
        try:
            return self._client._get_json(path, "ops")
        except operations.TransportError:
            raise
        except Exception as exc:  # noqa: BLE001
            raise operations.TransportError("read:" + type(exc).__name__, "read") from None

    def post(
        self,
        path: str,
        payload: Mapping[str, Any],
        *,
        extra: Mapping[str, Any] | None = None,
        headers: Mapping[str, str] | None = None,
    ) -> Any:
        if path not in WRITE_PATHS:
            raise operations.TransportError("path_not_allowed", "pre_send")
        if not self._open:
            raise operations.TransportError("session_closed", "pre_send")
        csrf = getattr(self._client, "csrf", None)
        if not isinstance(csrf, Mapping):
            raise operations.TransportError("no_csrf", "pre_send")
        body: dict[str, Any] = {"data": dict(payload), "csrf": dict(csrf)}
        if extra:
            for key, value in extra.items():
                body[key] = value
        try:
            status, raw = self._client._request(
                "POST", path, body, timeout=None, headers=headers
            )
        except operations.BudgetExhausted:
            raise
        except operations.TransportError:
            raise
        except Exception as exc:  # noqa: BLE001 - ambiguous after send
            raise operations.TransportError(
                "post:" + type(exc).__name__, "post_send"
            ) from None
        try:
            data = self._client._json(raw)
        except Exception:  # noqa: BLE001
            raise operations.TransportError("post_parse", "post_send") from None
        if status != 200:
            raise operations.TransportError("http_" + str(status), "post_send")
        if not isinstance(data, Mapping):
            # A non-object body is not a valid API reply; never treated as ok.
            raise operations.TransportError("post_schema", "post_send")
        reason = huawei_api.classify_error(data)
        if reason:
            # Application-level rejection happened after send: never retried,
            # reported as uncertain so no duplicate write is attempted.
            raise operations.TransportError("application:" + redact(reason, 32), "post_send")
        return data

    def close(self) -> str:
        self._open = False
        try:
            return self._client.logout()
        except Exception:  # noqa: BLE001
            return "failed"


PDL_SCHEMA = 1


class PersistentTransactionStore(operations.TransactionStore):
    """Atomic, secret-redacted ledger that survives a restart.

    Fail-closed: a missing file is a genuine first boot (healthy, empty); an
    existing file that is malformed, truncated, incomplete or carries any bad
    record makes the whole store unhealthy and read-only, so every write is
    refused instead of losing an unresolved lock. Records are only written or
    marked resolved; nothing is deleted and no secret is stored.
    """

    def __init__(self, path: str) -> None:
        super().__init__()
        self._path = path
        self._lock = threading.Lock()
        self._error = "ledger_invalid"
        self.durable = True
        self._load()

    def _mark_unhealthy(self, reason: str) -> None:
        self.healthy = False
        self._error = reason
        LOG.warning("operations ledger invalido (%s): escrituras bloqueadas", reason)

    def _load(self) -> None:
        try:
            with open(self._path, "r", encoding="utf-8") as handle:
                raw = json.load(handle)
        except FileNotFoundError:
            self._error = "ledger_invalid"
            return
        except Exception:  # noqa: BLE001 - unreadable existing file is not a first boot
            self._mark_unhealthy("ledger_unreadable")
            return
        if not isinstance(raw, dict) or raw.get("schema_version") != PDL_SCHEMA:
            self._mark_unhealthy("ledger_schema")
            return
        records = raw.get("records")
        approvals = raw.get("approvals")
        if not isinstance(records, dict) or not isinstance(approvals, dict):
            self._mark_unhealthy("ledger_schema")
            return
        staged: dict[str, Any] = {}
        for key, item in records.items():
            record = self._to_record(key, item)
            if record is None or record.operation_id in staged:
                self._mark_unhealthy("ledger_record")
                return
            staged[record.operation_id] = record
        staged_approvals: dict[str, dict[str, Any]] = {}
        for key, item in approvals.items():
            approval = self._to_approval(key, item)
            if approval is None:
                self._mark_unhealthy("ledger_approval")
                return
            staged_approvals[key] = approval
        self._records = staged
        self._approvals = staged_approvals

    def _to_record(self, key: Any, item: Any) -> Any:
        if not isinstance(key, str) or not key or not isinstance(item, Mapping):
            return None
        try:
            state = operations.Outcome(str(item.get("state")))
        except ValueError:
            return None
        operation = item.get("operation")
        payload_hash = item.get("payload_hash")
        preimage_hash = item.get("preimage_hash")
        if not isinstance(operation, str) or not operation:
            return None
        if not isinstance(payload_hash, str) or not isinstance(preimage_hash, str):
            return None
        if not isinstance(item.get("target"), Mapping) or not isinstance(item.get("evidence"), Mapping):
            return None
        reason = item.get("reason")
        resolution = item.get("resolution")
        attempts = item.get("attempts")
        return operations.TransactionRecord(
            operation_id=key,
            operation=operation,
            payload_hash=payload_hash,
            preimage_hash=preimage_hash,
            state=state,
            target=_dict_of(item.get("target")),
            evidence=_dict_of(item.get("evidence")),
            reason=reason if isinstance(reason, str) else None,
            attempts=attempts if isinstance(attempts, int) and not isinstance(attempts, bool) else 0,
            resolved=bool(item.get("resolved")),
            resolution=resolution if isinstance(resolution, str) else None,
        )

    def _to_approval(self, key: Any, item: Any) -> dict[str, Any] | None:
        if not isinstance(key, str) or not key or not isinstance(item, Mapping):
            return None
        router_id = item.get("router_id")
        operation = item.get("operation")
        expires = item.get("expires_at")
        if not isinstance(router_id, str) or not router_id or not isinstance(operation, str):
            return None
        if isinstance(expires, bool) or not isinstance(expires, (int, float)):
            return None
        return {"router_id": router_id, "operation": operation,
                "expires_at": float(expires), "used": bool(item.get("used"))}

    def _flush(self) -> None:
        payload = {
            "schema_version": PDL_SCHEMA,
            "records": {
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
            },
            "approvals": {key: dict(value) for key, value in self._approvals.items()},
        }
        directory = os.path.dirname(self._path) or "."
        data = json.dumps(payload, sort_keys=True, default=str).encode("utf-8")
        tmp = self._path + "." + str(os.getpid()) + ".tmp"
        try:
            os.makedirs(directory, exist_ok=True)
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            try:
                written = 0
                while written < len(data):
                    written += os.write(fd, data[written:])
                os.fsync(fd)
            finally:
                os.close(fd)
            os.chmod(tmp, 0o600)
            os.replace(tmp, self._path)
            dir_fd = os.open(directory, os.O_RDONLY)
            try:
                os.fsync(dir_fd)
            finally:
                os.close(dir_fd)
        except OSError as exc:
            raise operations.LedgerError("ledger_write") from exc

    def begin(self, record: Any) -> Any:
        with self._lock:
            if not self.healthy:
                raise operations.LedgerError(self._error)
            existing = self._records.get(record.operation_id)
            if existing is not None:
                return existing
            self._records[record.operation_id] = record
            try:
                self._flush()
            except operations.LedgerError:
                self._records.pop(record.operation_id, None)
                raise
            return record

    def finish(self, operation_id, state, *, reason=None, evidence=None):
        with self._lock:
            result = super().finish(operation_id, state, reason=reason, evidence=evidence)
            if result is None:
                return None
            try:
                self._flush()
            except operations.LedgerError:
                self._mark_unhealthy("ledger_degraded")
                raise
            return result

    def mark_resolved(self, operation_id, note=None):
        with self._lock:
            if not self.healthy:
                raise operations.LedgerError(self._error)
            record = self._records.get(operation_id)
            if record is None:
                return None
            previous = (record.resolved, record.resolution)
            result = super().mark_resolved(operation_id, note)
            try:
                self._flush()
            except operations.LedgerError:
                record.resolved, record.resolution = previous
                raise
            return result

    def issue_approval(self, approval_id, router_id, operation, expires_at):
        with self._lock:
            if not self.healthy:
                raise operations.LedgerError(self._error)
            if not super().issue_approval(approval_id, router_id, operation, expires_at):
                return False
            try:
                self._flush()
            except operations.LedgerError:
                self._approvals.pop(approval_id, None)
                raise
            return True

    def reserve_approval(self, approval_id, router_id, operation, now):
        with self._lock:
            if not self.healthy:
                raise operations.LedgerError(self._error)
            record = self._approvals.get(approval_id)
            previous_used = record.get("used") if record is not None else None
            if not super().reserve_approval(approval_id, router_id, operation, now):
                return False
            try:
                self._flush()
            except operations.LedgerError:
                if record is not None:
                    record["used"] = previous_used
                raise
            return True


class OperationsService:
    """Coordinates admin operations with per-CPE serialization and gating."""

    def __init__(
        self,
        registry: Mapping[str, RouterBinding],
        *,
        token: str | None = None,
        writes_master: bool = False,
        enabled_operations: frozenset[str] = frozenset(),
        unverified_writes: bool = False,
        reboot_approved: bool = False,
        resolve_enabled: bool = False,
        state_path: str | None = None,
        gate: Any | None = None,
        session_factory: Callable[[RouterBinding], HuaweiSession] | None = None,
        executor: ThreadPoolExecutor | None = None,
        ops_budget: float = OPS_BUDGET_DEFAULT,
        lock_wait: float = LOCK_WAIT_DEFAULT,
        engine_timeout: float = ENGINE_TIMEOUT_DEFAULT,
        snapshot_ttl: float = SNAPSHOT_TTL_DEFAULT,
        max_calls: int = MAX_CALLS_DEFAULT,
    ) -> None:
        self.registry = dict(registry)
        self.token = token or None
        self.writes_master = bool(writes_master)
        self.enabled_operations = frozenset(enabled_operations)
        self.unverified_writes = bool(unverified_writes)
        self._reboot_approved = bool(reboot_approved)
        self.resolve_enabled = bool(resolve_enabled)
        self.gate = gate
        self._session_factory = session_factory
        self._executor = executor or ThreadPoolExecutor(
            max_workers=2, thread_name_prefix="webcol-ops"
        )
        self.ops_budget = float(ops_budget)
        self.lock_wait = float(lock_wait)
        self.engine_timeout = float(engine_timeout)
        self.snapshot_ttl = float(snapshot_ttl)
        self.max_calls = int(max_calls)
        self.store = (
            PersistentTransactionStore(state_path) if state_path
            else operations.TransactionStore()
        )
        self._local_locks: dict[str, asyncio.Lock] = {}
        self.loop: asyncio.AbstractEventLoop | None = None

    def set_loop(self, loop: asyncio.AbstractEventLoop) -> None:
        self.loop = loop

    @classmethod
    def from_env(cls, routers: list[tuple[str, str]], **kwargs: Any) -> 'OperationsService':
        serials = _parse_serial_map(os.environ.get('HW_ROUTER_SERIALS', ''))
        allow = frozenset(
            item.strip() for item in os.environ.get(ENV_ALLOW, '').split(',') if item.strip()
        )
        # An explicit state_path (e.g. from webcol main) wins; otherwise the env
        # var is honoured, and both empty means a volatile store (writes refused).
        if not kwargs.get('state_path'):
            kwargs['state_path'] = os.environ.get(ENV_STATE) or None
        return cls(
            build_registry(routers, serials),
            token=os.environ.get(ENV_TOKEN) or None,
            writes_master=_truthy(os.environ.get(ENV_WRITES)),
            enabled_operations=allow,
            unverified_writes=_truthy(os.environ.get(ENV_UNVERIFIED)),
            reboot_approved=_truthy(os.environ.get(ENV_REBOOT)),
            resolve_enabled=_truthy(os.environ.get(ENV_RESOLVE)),
            **kwargs,
        )

    def capabilities(self) -> dict[str, Any]:
        """Unauthenticated, secret-free capability view."""
        return {
            "schema_version": 1,
            "operations": operations.capability_manifest(),
            "writes_enabled": bool(self.writes_master),
            "enabled_operations": sorted(self.enabled_operations),
            "unverified_writes_enabled": bool(self.unverified_writes),
            "reboot_approved": bool(self._reboot_approved),
            "reboot_approvals_issuable": bool(self._reboot_approved and self.store.healthy),
            "token_required": bool(self.token),
            "router_count": len(self.registry),
            "serial_bound_router_count": sum(
                1 for b in self.registry.values() if b.expected_serial),
            "ledger_healthy": bool(self.store.healthy),
            "ledger_durable": bool(self.store.durable),
            "rsa_backend_available": operations.crypto_available(),
            "write_eligible_requires_serial": True,
        }

    def _write_block_reason(
        self, binding: RouterBinding, operation: str, fields: Mapping[str, Any]
    ) -> str | None:
        """First gate that blocks a real write, or None when fully eligible."""
        if not self.store.durable:
            return "ledger_not_durable"
        if not self.store.healthy:
            return "ledger_invalid"
        if not binding.expected_serial:
            return "missing_serial"
        if not self.writes_master or operation not in self.enabled_operations:
            return "writes_disabled"
        spec = operations.MANIFEST.get(operation)
        if spec is None or not spec.implemented:
            return "capability_unsupported"
        if spec.destructive and not self._reboot_approved:
            return "reboot_approval_required"
        if spec.requires_password:
            security = str(fields.get("security", "")).strip().lower()
            if security in ("psk", "secure", "encrypted", "tkip"):
                if not self.unverified_writes:
                    return "unverified_write_disabled"
                if not operations.crypto_available():
                    return "capability_unsupported"
        return None

    def _write_eligible(
        self, binding: RouterBinding, operation: str, fields: Mapping[str, Any]
    ) -> bool:
        return self._write_block_reason(binding, operation, fields) is None

    def issue_reboot_approval(
        self, router_id: str, ttl_seconds: float = 300.0
    ) -> dict[str, Any]:
        """Issue a persisted, one-use, router+operation-bound approval id."""
        if not self._reboot_approved:
            return {"status": "denied", "reason": "reboot_approval_disabled"}
        if router_id not in self.registry:
            return {"status": "denied", "reason": "unknown_router"}
        if not self.store.healthy:
            return {"status": "denied", "reason": "ledger_invalid"}
        approval_id = uuid.uuid4().hex
        try:
            created = self.store.issue_approval(
                approval_id, router_id, "system.reboot",
                time.time() + float(ttl_seconds))
        except operations.LedgerError:
            return {"status": "denied", "reason": "ledger_invalid"}
        if not created:
            return {"status": "denied", "reason": "approval_exists"}
        return {"status": "ok", "approval_id": approval_id,
                "expires_in": float(ttl_seconds)}

    def verify_token(self, provided: Any) -> bool:
        return token_ok(provided, self.token)

    def _lock(self, host: str) -> asyncio.Lock:
        if self.gate is not None:
            return self.gate.lock(host)
        lock = self._local_locks.get(host)
        if lock is None:
            lock = asyncio.Lock()
            self._local_locks[host] = lock
        return lock

    def _session_active(self, host: str) -> bool:
        if self.gate is None:
            return False
        checker = getattr(self.gate, 'session_active', None)
        if callable(checker):
            return bool(checker(host))
        return bool(self.gate.direct_active(host))

    def _credential_blocked(self, host: str) -> bool:
        if self.gate is None:
            return False
        checker = getattr(self.gate, 'credential_blocked', None)
        return bool(checker(host)) if callable(checker) else False

    def _record_credential_failure(self, host: str) -> None:
        if self.gate is None:
            return
        recorder = getattr(self.gate, 'record_credential_failure', None)
        if callable(recorder):
            recorder(host)

    def _policy(self, operation: str) -> Any:
        allowed = operation in self.enabled_operations
        return operations.Policy(
            writes_enabled=bool(self.writes_master and allowed),
            enabled_operations=frozenset({operation}) if allowed else frozenset(),
            allowlisted_router_ids=frozenset(self.registry),
            reboot_approved=False,
            allow_unverified_writes=bool(self.unverified_writes),
            callback_timeout_seconds=self.engine_timeout,
            snapshot_max_age_seconds=self.snapshot_ttl,
            max_transport_calls=self.max_calls,
        )

    def _planning_policy(self, operation: str) -> Any:
        return replace(
            self._policy(operation),
            writes_enabled=True,
            allow_unverified_writes=True,
            reboot_approved=True,
        )

    def _engine(self, transport: Any, binding: RouterBinding, operation: str,
                planning: bool, destructive: bool = False) -> Any:
        if planning:
            policy = self._planning_policy(operation)
        else:
            policy = self._policy(operation)
            if destructive:
                policy = replace(policy, reboot_approved=True)
        return operations.OperationEngine(
            transport,
            identity=operations.RouterIdentity(binding.router_id, ""),
            policy=policy,
            store=self.store,
            clock=time.monotonic,
        )

    def _grant(self, binding: RouterBinding, operation: str) -> Any:
        return operations.CoordinatorGrant(
            subject="admin", router_id=binding.router_id,
            operations=frozenset({operation}),
        )

    def _validate_request(
        self, payload: Mapping[str, Any]
    ) -> tuple[RouterBinding, str, dict[str, Any], str | None, Any]:
        if not isinstance(payload, Mapping):
            raise operations.OperationRejected("invalid_body")
        unknown = set(payload) - REQUEST_KEYS
        if unknown:
            raise operations.OperationRejected("unknown_field")
        router_id = payload.get("router")
        if not isinstance(router_id, str) or router_id not in self.registry:
            raise operations.OperationRejected("unknown_router")
        binding = self.registry[router_id]
        operation = payload.get("operation")
        if not isinstance(operation, str) or operation not in operations.MANIFEST:
            raise operations.OperationRejected("unknown_operation")
        operation_id = payload.get("operation_id")
        if operation_id is not None and (
            not isinstance(operation_id, str) or not operation_id or len(operation_id) > 64
        ):
            raise operations.OperationRejected("invalid_payload", "operation_id")
        target = payload.get("target") or {}
        if not isinstance(target, Mapping) or set(target) - TARGET_KEYS:
            raise operations.OperationRejected("unknown_field", "target")
        fields = payload.get("fields") or {}
        if not isinstance(fields, Mapping) or len(fields) > MAX_BODY_FIELDS:
            raise operations.OperationRejected("invalid_payload", "fields")
        unknown_fields = {str(k) for k in fields} - set(operations.allowed_fields(operation))
        if unknown_fields:
            raise operations.OperationRejected("unknown_field")
        target_ref = operations.Target(
            router_id=router_id,
            band=target.get("band"),
            vap_id=target.get("vap_id"),
        )
        return binding, operation, dict(fields), operation_id, target_ref

    async def plan(self, payload: Mapping[str, Any]) -> dict[str, Any]:
        try:
            binding, operation, fields, operation_id, target = self._validate_request(payload)
        except operations.OperationRejected as exc:
            return _denied(exc.reason)
        return await self._dispatch(
            binding, lambda: self._plan_sync(binding, operation, fields, operation_id, target)
        )

    async def execute(self, payload: Mapping[str, Any]) -> dict[str, Any]:
        if not self.store.durable:
            return _denied("ledger_not_durable")
        if not self.store.healthy:
            return _denied("ledger_invalid")
        try:
            binding, operation, fields, operation_id, target = self._validate_request(payload)
        except operations.OperationRejected as exc:
            return _denied(exc.reason)
        if not binding.expected_serial:
            # An actual write requires a bound expected serial, not just the
            # registry host: refuse before any login or transport use.
            return _denied("missing_serial", router=binding.router_id)
        spec = operations.MANIFEST[operation]
        destructive = spec.destructive
        if destructive:
            approval_id = payload.get("approval_id")
            if not self._reboot_approved or not isinstance(approval_id, str) or not approval_id:
                return _denied("reboot_approval_required", router=binding.router_id)
            try:
                reserved = self.store.reserve_approval(
                    approval_id, binding.router_id, operation, time.time())
            except operations.LedgerError:
                return _denied("ledger_invalid", router=binding.router_id)
            if not reserved:
                return _denied("reboot_approval_required", router=binding.router_id)
        operation_id = operation_id or uuid.uuid4().hex
        return await self._dispatch(
            binding,
            lambda: self._execute_sync(
                binding, operation, fields, operation_id, target, destructive=destructive),
        )

    def status(self, operation_id: str) -> dict[str, Any]:
        record = self.store.get(operation_id)
        if record is None:
            return {"status": "missing", "reason": "unknown_operation_id"}
        return {
            "status": "ok",
            "operation_id": record.operation_id,
            "operation": record.operation,
            "state": record.state.value,
            "reason": record.reason,
            "target": dict(record.target),
            "evidence": dict(record.evidence),
            "attempts": record.attempts,
            "resolved": record.resolved,
            "resolution": record.resolution,
        }

    def resolve(self, operation_id: str, note: str | None = None) -> dict[str, Any]:
        if not self.resolve_enabled:
            return {"status": "denied", "reason": "resolve_disabled"}
        try:
            record = self.store.mark_resolved(operation_id, redact(note or "operator", 64))
        except operations.LedgerError:
            return {"status": "denied", "reason": "ledger_invalid"}
        if record is None:
            return {"status": "missing", "reason": "unknown_operation_id"}
        return {"status": "ok", "operation_id": operation_id, "state": record.state.value}

    async def _dispatch(
        self, binding: RouterBinding, fn: Callable[[], dict[str, Any]]
    ) -> dict[str, Any]:
        host = binding.host
        if self._session_active(host):
            return _denied("router_busy")
        lock = self._lock(host)
        try:
            await asyncio.wait_for(lock.acquire(), timeout=self.lock_wait)
        except asyncio.TimeoutError:
            return _denied("router_busy")
        try:
            if self._session_active(host):
                return _denied("router_busy")
            if self._credential_blocked(host):
                # Never attempt a login (even a dry-run) while the circuit is open.
                return _denied("credential_blocked")
            loop = asyncio.get_running_loop()
            future = loop.run_in_executor(self._executor, fn)
            if self.gate is not None:
                self.gate.register_ops_future(host, future)
            try:
                outcome = await asyncio.wait_for(asyncio.shield(future), timeout=self.ops_budget)
            except asyncio.TimeoutError:
                # The worker keeps running and stays registered as active, so no
                # second session is started; the ledger holds the pending state.
                return {"status": "uncertain", "reason": "ops_timeout",
                        "router": binding.router_id}
            finally:
                if future.done() and self.gate is not None:
                    self.gate.clear_ops_future(host, future)
        finally:
            lock.release()
        if isinstance(outcome, dict) and outcome.pop("_login_blocking", False):
            # Mutated on the event loop, exactly once, never from the worker.
            self._record_credential_failure(host)
        return outcome

    def _build_snapshot(
        self, session: HuaweiSession, binding: RouterBinding, operation: str
    ) -> Any:
        captured = time.time()
        role, path = operations.operation_read_endpoint(operation)
        data: dict[str, Any] = {}
        deviceinfo = session.read("api/system/deviceinfo")
        data["deviceinfo"] = deviceinfo
        if role and path:
            data[role] = session.read(path)
        public_key = session.public_key()
        if public_key is not None:
            data["rsa_public_key"] = public_key
        age = max(0.0, time.time() - captured)
        if age > self.snapshot_ttl:
            raise operations.OperationRejected("stale_snapshot")
        return operations.Snapshot(router_id=binding.router_id, age_seconds=age, data=data)

    def _make_session(self, binding: RouterBinding) -> HuaweiSession:
        if self._session_factory is not None:
            return self._session_factory(binding)
        client = huawei_api.HuaweiDirectClient(
            binding.host, binding.password,
            request_timeout=8.0,
            total_budget=self.ops_budget + 8.0,
            verify_tls=_verify_tls_from_env(),
        )
        return HuaweiSession(client, binding)

    def _plan_sync(self, binding, operation, fields, operation_id, target) -> dict[str, Any]:
        session = self._make_session(binding)
        try:
            try:
                identity = session.open()
            except SessionIdentityError as exc:
                result = _denied("login_" + exc.reason, router=binding.router_id)
                if exc.reason in BLOCKING_LOGIN_REASONS:
                    result["_login_blocking"] = True
                return result
            snapshot = self._build_snapshot(session, binding, operation)
            engine = self._engine(DirectSessionTransport(session), binding, operation,
                                  planning=True)
            request = operations.OperationRequest(
                operation_id=operation_id or "plan-" + uuid.uuid4().hex,
                operation=operation, target=target, fields=fields,
            )
            plan = engine.plan(request, snapshot, self._grant(binding, operation))
            return self._plan_summary(binding, identity, plan)
        except operations.OperationRejected as exc:
            return _denied(exc.reason, router=binding.router_id)
        except operations.RsaUnavailable:
            return _denied("capability_unsupported", router=binding.router_id)
        except Exception as exc:  # noqa: BLE001
            return _denied("plan:" + type(exc).__name__, router=binding.router_id)
        finally:
            session.close()

    def _execute_sync(self, binding, operation, fields, operation_id, target,
                      destructive: bool = False) -> dict[str, Any]:
        session = self._make_session(binding)
        try:
            try:
                identity = session.open()
            except SessionIdentityError as exc:
                result = _denied("login_" + exc.reason, router=binding.router_id)
                if exc.reason in BLOCKING_LOGIN_REASONS:
                    result["_login_blocking"] = True
                return result
            snapshot = self._build_snapshot(session, binding, operation)
            engine = self._engine(DirectSessionTransport(session), binding, operation,
                                  planning=False, destructive=destructive)
            request = operations.OperationRequest(
                operation_id=operation_id, operation=operation, target=target, fields=fields,
            )
            result = engine.execute(request, snapshot, self._grant(binding, operation))
            return self._result_summary(binding, result)
        except operations.RsaUnavailable:
            return _denied("capability_unsupported", router=binding.router_id)
        except Exception as exc:  # noqa: BLE001
            return _denied("execute:" + type(exc).__name__, router=binding.router_id)
        finally:
            session.close()

    def _plan_summary(self, binding, identity, plan: Any) -> dict[str, Any]:
        no_op = (
            not plan.secret_involved
            and dict(plan.current_projection) == dict(plan.target_projection)
        )
        return {
            "status": "ok",
            "router": binding.router_id,
            "serial": identity.get("serial"),
            "operation": plan.request.operation,
            "operation_id": plan.request.operation_id,
            "capability": plan.capability.value,
            "destructive": plan.destructive,
            "secret_involved": plan.secret_involved,
            "path": plan.path,
            "payload_hash": plan.payload_hash,
            "preimage_hash": plan.preimage_hash,
            "current": dict(plan.current_projection),
            "target": dict(plan.target_projection),
            "no_op": bool(no_op),
            "write_eligible": self._write_block_reason(
                binding, plan.request.operation, plan.request.fields) is None,
            "write_blocked_reason": self._write_block_reason(
                binding, plan.request.operation, plan.request.fields),
            "writes_enabled": bool(self.writes_master),
            "unverified_writes_enabled": bool(self.unverified_writes),
        }

    def _result_summary(self, binding, result: Any) -> dict[str, Any]:
        return {
            "status": "ok",
            "router": binding.router_id,
            "operation": result.operation,
            "operation_id": result.operation_id,
            "outcome": result.outcome.value,
            "reason": result.reason,
            "evidence": dict(result.evidence),
            "transport_calls": result.transport_calls,
            "requires_operator_confirmation": result.requires_operator_confirmation,
        }


def _denied(reason: str, *, router: str | None = None) -> dict[str, Any]:
    payload: dict[str, Any] = {"status": "denied", "reason": redact(reason, 64)}
    if router:
        payload["router"] = router
    return payload


def _dict_of(value: Any) -> dict[str, Any]:
    if isinstance(value, Mapping):
        return {str(k): v for k, v in value.items()}
    return {}


def _parse_serial_map(raw: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for item in raw.split(','):
        item = item.strip()
        if not item or '=' not in item:
            continue
        key, _, value = item.partition('=')
        key, value = key.strip(), value.strip()
        if key and value:
            result[key] = value
    return result


def _verify_tls_from_env() -> bool:
    value = os.environ.get('WEBENRICH_VERIFY_TLS', '').strip().lower()
    return value not in ('0', 'false', 'no', 'off')
