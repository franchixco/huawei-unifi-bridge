# Control operations engine (`webcol/operations.py`)

Design and safety contract for the isolated Huawei control adapters. The module
is a pure library: no socket, no authentication, no HTTP server of its own. It
owns only the new `webcol/operations.py` and `tests/test_operations.py`; the
existing transport, collector and router configuration are untouched.

## Authentication boundary

The engine performs no authentication. Only the trusted coordinator, after it
has validated the bearer token, may:

1. build the injected `RouterIdentity` (the single allowlisted CPE),
2. provide a fresh `Snapshot` (a redacted readback image with an injected age),
3. provide the explicit `Policy`, and
4. present a `CoordinatorGrant` naming the same allowlisted router.

The engine enforces that the grant router, the snapshot router and the request
target all match the bound identity, and that the operation is inside the
grant's scope. A token is never seen, stored or logged here. There is no
unauthenticated HTTP surface: integration wires the authenticated coordinator to
`OperationEngine.execute()`.

## Transport

All side effects go through the injected `Transport` protocol (`read`, `post`).
`ReadOnlyTransport` adapts a read-only reader such as a bound
`HuaweiDirectClient` method and refuses every `post`, so the production default
cannot write.

The admin service uses a real session transport
(`operation_service.HuaweiSession`), which:

- reads only an allowlisted set of GET endpoints (deviceinfo, HostInfo,
  WlanGuideBasic, guest network, wlan filter) — never an arbitrary path;
- builds the upstream nested POST DTO `{"data": payload, "csrf": ...}` plus the
  `action` extra field and per-operation headers, and relies on the client's
  CSRF rotation. The only header a caller may set is `Content-Type`, and only to
  an allowlisted value (`...;charset=UTF-8;enp` for the guest endpoint); Cookie,
  Host and Authorization are never overridable;
- classifies the reply with the module-level `classify_error` (never a client
  attribute), rejects a non-object body, and performs **no automatic retry** of a
  write: a deterministic pre-send problem (no session, no CSRF, disallowed path)
  raises `failed`, while anything after the request was sent (HTTP error,
  timeout, application rejection) raises `uncertain` so no duplicate write is
  ever attempted;
- reads the body under an **absolute deadline**, not the whole block: each chunk
  tightens the socket timeout to the time left (`read1`), so a peer that drips
  one byte before every per-recv timeout cannot hold the worker thread; the body
  is still hard size-capped. A session whose main deadline is spent closes with
  its own bounded cleanup budget (`CLEANUP_BUDGET_SECONDS`) that never
  re-logs-in or retries a write, and the session always clears `logged_in`;
- requires the validated server public key (`public_key_verified`) before guest
  password encryption, and refuses with `secret_required` otherwise.

## Integration (webcol admin API)

The HTTP surface is token-bearing and loopback/internal only; it never accepts a
token in the query string and adds no CORS headers. The admin routes reject a
`Host` outside the configured allowlist (loopback plus `WEBCOL_ALLOWED_HOSTS`)
with `400 bad-host`, and reject any supplied `Origin` not in
`WEBCOL_ALLOWED_ORIGINS` with `403 bad-origin` — a missing `Origin` never
bypasses the token. The server binds `WEBCOL_LISTEN_HOST` (default `127.0.0.1`);
the compose deployment sets `0.0.0.0` explicitly with the port mapped to
loopback.

| Route | Auth | Purpose |
|---|---|---|
| `GET /capabilities` | none | secret-free capability manifest + gate flags |
| `POST /operations/plan` | bearer | read-only dry run: exact DTO, preimage/target projections, `no_op`; never POSTs |
| `POST /operations` | bearer | gated write; refused unless `HW_OPERATIONS_WRITES` and the operation allowlist match |
| `GET /operations/<id>` | bearer | redacted transactional status |
| `POST /operations/<id>/resolve` | bearer | clear a lock (disabled unless `HW_OPERATIONS_RESOLVE`) |

`POST` bodies must be `application/json`, strictly positive `Content-Length`
<= 64 kB, with an allowlisted top-level key set (`router`, `operation`,
`operation_id`, `target`, `fields`); unknown fields are rejected. The body
references a router by registry id only — the caller cannot supply a URL or
forged identity. A write is refused with `writes_disabled` /
`destructive_approval_required` / `unverified_write_disabled` otherwise.

Serialization: an operation runs under the same per-host asyncio lock as
collection and is refused (`router_busy`) if a collection or admin session is
already active for that host; a timed-out worker stays registered so no second
session is opened. The direct client keeps its own finite budget and logs out in
a bounded way; the service never re-authenticates on an unknown outcome.

Persistent idempotency: the ledger is written atomically (0600, never deleted)
to `HW_OPERATIONS_STATE` on the existing webcol-data volume: a checked write
loop, `fsync` on the file, atomic `os.replace` and a parent-directory `fsync`. A
`pending` record is persisted **before** the POST; if that write cannot be made
durable the write is refused (`ledger_invalid`) rather than risking a duplicate,
and a post-send persistence failure degrades the result to `uncertain`. **Any
actual write requires a durable persistent store**: a volatile in-memory ledger
(no `state_path`) lets dry-runs and the read-only manifest run, but refuses every
write with `ledger_not_durable` before any login (`write_eligible:false`). A
missing file is a genuine first boot (healthy, empty); an existing file that is
malformed, truncated, incomplete or carries any bad record makes the whole store
unhealthy and read-only — all writes are refused with `ledger_invalid` while the
read-only manifest still responds. Unresolved records (`pending` / `uncertain` /
`failed`) keep a **router-wide** lock across restarts **and across new operation
ids and types**: a later write for the same router is refused with
`router_operation_locked` until an operator resolves it. Validation rejections
never clear a lock, and nothing resumes automatically.

Fresh-preimage precondition: immediately before the POST the engine re-reads the
target and compares a fingerprint of the current state with the planned
baseline; if they differ (e.g. another MAC was added to the whole-list write)
the write is refused with `precondition_changed` and a replan is required, so a
concurrent change is never silently overwritten. This holds **even for
secret-bearing requests** (a guest password): the compared projections carry only
observable fields (never the masked password), so a concurrent SSID/enabled
change blocks the request instead of being overwritten, while an unchanged state
still posts and returns `applied_unverified`.

Credential circuit: every admin call — dry-run included — is refused with
`credential_blocked` while the shared gate reports the host as blocked, before
any login. A blocking login rejection (`credentials`/`locked`) is propagated as
`login_*` and opens the circuit via the gate's `record_credential_failure`
exactly once, called on the event loop (never from the worker thread); the admin
path never falls back to the browserless transport.

Destructive reboot: the env flag alone is not sufficient. A token-authenticated
operator issues a persisted, one-use approval bound to the exact router,
operation and expiry; it is reserved atomically **before** the POST and stays
consumed across a restart even if the outcome is `failed`/`uncertain`. There is
no global boolean that re-arms on restart.

## Capability manifest

Per operation: `available` (endpoint + readback contract known and verifiable),
`implemented_unverified` (write implemented from the upstream contract but the
changed field cannot always be observed), or `unsupported` (no endpoint is
invented; the request is rejected). Each entry also states `implemented`,
`firmware_advertised` and `hardware_write_verified` — the last is **false** for
every operation: nothing here has been write-verified on real firmware.

| Operation | Capability | Notes |
|---|---|---|
| `wifi.80211r` | available | `Dot11REnable`, action `11rSetting` |
| `wifi.twt` | available | `TWTEnable`, action `TWTSetting` |
| `wifi.mac_filter.block` | implemented_unverified | whole 2-band state, blacklist only |
| `wifi.mac_filter.unblock` | implemented_unverified | removes one MAC, preserves the rest |
| `wifi.guest.set` | implemented_unverified | enable/SSID/security; password masked |
| `system.reboot` | implemented_unverified | destructive, one-use approval |
| `wifi.primary.ssid` / `.channel` / `.wmm` | unsupported | owned by the TR-069 control path |
| `client.disconnect` | unsupported | temporary disconnect != block |
| `wifi.channel_width` / `wifi.transmit_power` / `wifi.primary.security` | unsupported | no verified endpoint |
| `network.vlan` | unsupported | guest isolation is not VLAN |
| `system.firmware` / `system.factory_reset` | unsupported | out of scope |

No native UniFi button is claimed: `unifi_mapping` is `None` for every
operation until a real contract is known.

## Outcomes

`pending` · `rejected` · `verified_noop` · `verified_changed` ·
`applied_unverified` · `uncertain` · `failed`.

- **verified_noop** — fresh readback already matched the desired state, so no
  write was performed (truthful: nothing changed).
- **verified_changed** — a write happened and a fresh readback matched.
- **applied_unverified** — the write was accepted but the changed field is not
  observable (guest password is returned masked).
- **uncertain** — post was attempted but the result cannot be established
  (timeout after send, readback mismatch, reboot not observed down/up).
- **failed** — a fault before any write, or a budget/deadline exhaustion.

## Operation details

- **11r / TWT** — `POST api/ntwk/WlanGuideBasic?type=notshowpassall` with
  `dot11REnable`/`TWTEnable` and the upstream `action` extra field. The VAP is
  selected by native `ID`, never by SSID; a missing/duplicate ID is rejected.
- **MAC filter** — `POST api/ntwk/wlanfilterenhance` writing both `config2g`
  and `config5g` from a fresh preimage, preserving other entries. Blocking
  requires blacklist mode and filtering enabled; whitelist mode fails closed.
  Unblock removes only the target and never wipes other entries. MACs are
  validated and canonicalised.
- **Guest network** — `POST api/ntwk/guest_network?type=notshowpassall` with the
  upstream `...;enp` content type. Only the two verified security enums are
  accepted (`none`/`tkip`); anything else (WPA3, enterprise, VLAN, captive
  portal, isolated) is rejected as `security_unknown`. Passwords are encrypted
  with the upstream RSA-OAEP pattern: base64 of the secret, split into
  `modulus_bytes - 42` byte chunks (214 for a 2048-bit key) and hex-concatenated.
  Because the router returns the password masked, a password write is never
  `verified_changed` — at best `applied_unverified`.
- **Reboot** — destructive. Requires `policy.reboot_approved` AND a one-use
  consumption; a later reboot is rejected as `destructive_approval_reused`.
  HTTP 200 alone is never verified: the engine must observe the router going
  down and back up, otherwise the result is `uncertain` with
  `requires_operator_confirmation`.

## Transactional guarantees

The `TransactionStore` is keyed by `operation_id` and keeps only hashes and a
redacted evidence projection — never a payload, password, cookie or raw
response.

- A repeat with the same `operation_id` and payload never resends: terminal
  states are returned as `duplicate_terminal`, in-flight states as
  `inflight_no_resend`.
- A repeat with the same `operation_id` but a different payload is rejected as
  `replay_conflict`.
- A new `operation_id` for the same router is refused while an unresolved
  record exists (`router_operation_locked`). The lock is **router-wide**: an
  unresolved guest write blocks a later 11r/TWT write on the same physical
  router, and vice versa, because a half-applied change may affect any
  subsequent write. It survives a restart because the ledger is persisted
  before the POST, and a rejected request never clears another record's lock.
- Pre-write faults are `failed`; post-send timeouts are `uncertain`; both are
  preserved across new requests.
- Every read and write spends a bounded budget (call count + deadline); no
  unbounded loop or busy wait.

## Session identity and freshness

Any **actual write** requires a bound expected serial
(`HW_ROUTER_SERIALS`), not just a registry host: without it the request is
refused with `missing_serial` *before* any login or transport use. A read-only
dry run (`POST /operations/plan`) is still allowed without a serial, but its
reply carries `write_eligible: false` so it cannot be mistaken for a writable
target. A session logs in once, reads `deviceinfo`, and compares the native
serial against the expectation; a mismatch closes the session and is refused
(`login_serial-mismatch`). The snapshot is captured at session open and its age
is bounded by the policy TTL (default 60 s, service 180 s); a non-finite
(`NaN`/`inf`), negative or stale age is rejected — the freshness check is
`finite and 0 <= age <= max`. Callers cannot inject a router URL or identity;
the registry comes only from configured routers, and the serial only from the
protected runtime map (never hardcoded).

`tests/test_huawei_api_hardening.py` runs 4 tests for the absolute HTTP budget: a
raw-socket peer that drips a byte before every per-recv timeout cannot hold the
worker (bounded error under the deadline), the body stays size-capped, and a
session whose deadline is spent still attempts a bounded logout while never
leaving `logged_in` set. No real credential or network is used.

## Python compatibility

The engine uses `class X(str, Enum)` (not `StrEnum`) so it imports on Python
3.10 while behaving identically on 3.11+/3.12 in the deployed image.

## Limitations and open items (unverified)

1. **No hardware write verification.** Direct authentication and telemetry
   collection are verified on both BE3 routers. The deployed admin service has
   also completed an authenticated, read-only plan against a live CPE. No
   configuration-changing operation has been executed on the routers.
2. **Guest password** can never be confirmed by readback; it is capped at
   `applied_unverified`.
3. **MAC filter** whole-state writes are `implemented_unverified`: the upstream
   contract is followed, but no live run has confirmed end-to-end preservation.
4. **11r/TWT readback** follows the upstream `WifiConfig` shape. One live 11r
   plan returned a no-op; this does not verify changing 11r or TWT on hardware.
5. **Reboot down/up** observation depends on the transport surfacing connection
   failures; a graceful but slow reboot may need a larger `reboot_max_reads`.
6. **Session/CSRF** wrapping (`{"data": payload, "csrf": ...}` plus the `action`
   extra field) is the transport's responsibility; the engine builds the
   semantic payload, extra field and headers only.
7. **No UniFi equivalence** is promised: primary SSID/channel/WMM remain under
   the TR-069 control path, and no AP setting is claimed as reflected without a
   known contract.
8. **Integration status.** Telemetry, inventory, and token-authenticated admin
   planning are deployed with all write gates disabled. Write DTOs
   (`data`/`csrf`/`action`/headers) are tested with local fake CPEs, not by
   changing production router settings. AX3 integration and its overlapping
   Docker network remain deferred at the owner's request; this service does
   not modify that network.
9. **No real changes claimed.** Every write path here was tested with a fake
   transport; no real CPE change is verified, and `hardware_write_verified` is
   false for all operations.

## Changed files (this integration)

`webcol/operations.py` (review fixes: 3.10 enum compat, honest manifest flags,
unverified-write gate, cross-operation locked records), new
`webcol/operation_service.py`, `webcol/webcol.py` (routes + collector
serialization), `webcol/Dockerfile` (source COPY), `.env.example`,
`tests/test_operations.py`, new `tests/test_operation_service.py`, this doc.
Bridge inventory, reporting, and native TR-069 provisioning are documented
separately in `README.md`, `CONTROL.md`, and `HARDENING.md`.

## Tests

`tests/test_operations.py` runs 61 offline engine tests with a `FakeTransport`
that asserts exact endpoint/body DTO, token-scope gating, wrong-device/stale/
ambiguous/VAP-binding/unknown-field/MAC-validation/duplicate/replay/precondition
paths, no-op vs changed vs unverified vs uncertain vs failed outcomes,
one-use reboot approval with observed down/up, secret non-persistence, and the
RSA-OAEP round-trip against a throwaway key.

`tests/test_operation_e2e.py` runs 7 end-to-end tests over a real in-process
HTTP server and the real session transport with a recording fake CPE: exact
nested DTO + `action` extra + CSRF-before/after, the guest `...;enp` content
type, CSRF-error and non-object replies as `uncertain` with no resend, the
`from_env` startup path serving `200`/`401` (not `503`), and the Host/Origin/
token boundary. No real router, credential or network is used.

`tests/test_operation_service.py` runs 50 offline service/ledger/HTTP tests:
constant-time token, config-only registry, secret-free capabilities, durable
redaction and 0600 perms, pending-persisted-before-POST, router-wide locked
records surviving reload and blocking a different operation type, `missing_serial`
refusal before login with dry-run `write_eligible:false`, serial-mismatch
refusal, per-CPE busy refusal, dry-run that never POSTs, exact DTO through the
session, `unverified_write_disabled` default, and the HTTP routes
(401/403/400/404/409/200). No real credential or network is used.
