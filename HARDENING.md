# Hardening notes and operational runbook

Scope: the deployed stack on this host. Source of truth is this working tree.
Status: UniFi reporting, ACS collection and web telemetry are active (phase 1
deployed). Both CPE write paths are disabled by default: native UniFi
provisioning is off because `HUAWEI_CONTROL_IP` is empty, and the admin sidecar
has authenticated planning available but writes off because
`HW_OPERATIONS_WRITES=0`. The
inventory reconciliation, multi-VAP provisioning and admin sidecar are deployed
with writes OFF (safe-OFF release): `HUAWEI_CONTROL_IP` empty,
`HW_OPERATIONS_WRITES=0`, serial expectations bound 2/2, and verified live
`/capabilities` 200, unauthenticated admin `401`, `<id>` read `401` without token,
dry-run plan OK and write `403 writes_disabled` before any CPE configuration POST.
Two direct cycles per CPE were observed (browserless 0, failures 0) and the UCG
`cfgversion`, VAP BSSIDs and CPE WLAN settings were unchanged afterwards, so no
hardware write occurred and `hardware_write_verified` stays false. Residual risk
kept: the GenieACS UI JWT secret, the CWMP bind allowlist and the network
shadow/AX3 integration are unchanged and deferred to the owner; the command token
is stored only in the protected `.env` (600).

The native metrics release is deployed. Local verification passed 421 tests;
the server ran 421 with 419 passing and two JavaScript-runtime tests skipped
because that host has no JS test engine. Those two tests passed locally.
Controller `stat/device` now stores hardware CPU/memory percentages and router
uptime. The MODERN `systemBySiteByDevice` series contains CPU and memory samples;
read-only UI verification confirmed Memory Usage and Uptime on both APs. CPU
is present in the API/history but absent from the tested U7 Pro detail view.
Wireless traffic, retries and airtime panels remain unsupported where no
verified source exists; UI zeros must not be interpreted as measured zeros.
The diagnostic counter writer is asynchronous, bounded and fail-open, with
its state at `bridge-data/metrics/counters_v1.json` (0600).
All physical-write gates remain OFF. Native settings, adoption keys, virtual
MACs, BSSIDs and the owner's deferred AX3/Docker network are unchanged.

## Published ports

| Service | Bind | Notes |
| --- | --- | --- |
| bridge dashboard | `127.0.0.1:8091` | loopback only |
| webcol | `127.0.0.1:7560` | loopback only |
| GenieACS NBI | `127.0.0.1:7557` | loopback only |
| GenieACS UI | `127.0.0.1:3002` | loopback only, test JWT secret |
| CWMP (TR-069) | `<host-lan-ip>:7547` | see residual risk below |

## CWMP residual risk

TR-069 CWMP here is plain HTTP and the GenieACS configuration does not enforce
ACS credentials. Binding to a single LAN address (compose.yml) removes exposure
on other interfaces; within that LAN the endpoint stays unauthenticated. This
is a lab posture: it is not Internet-safe and not production-hardened. Add a
firewall allowlist (source IPs of the CPEs) as the next step; that change is
deliberately out of scope here.

## Secrets handling

- `.env` is mode 600 and holds router passwords and integration endpoints.
  Never paste it into tickets, logs or chats.
- Logs never contain router passwords: webcol logs stages and exception types
  only, because Playwright exception text can embed evaluated arguments.
- The optional UniFi controller probe (`/root/ucg_probe.py`) reads credentials
  from `/root/.ucg-ro.json` (0600) and performs read-only GETs only.
- `.env.example` carries placeholders only.

## webcol collection safety

- The direct Huawei web API (`huawei_api.py`) is the primary transport. The
  browserless CDP path is an optional fallback, connected lazily and only for
  explicit transient/incompatibility stages (`FALLBACK_ELIGIBLE`). Credential,
  lockout and unverified-proof outcomes never open a second login path and take
  the >= 300 s credential circuit breaker. `WEBENRICH_DIRECT_ONLY=1` disables
  the fallback entirely.
- One session per router at a time. The direct client runs in a dedicated
  bounded worker with its own monotonic total budget (`WEBENRICH_DIRECT_TOTAL`,
  default 25 s) inside a hard wait bound (`WEBENRICH_DIRECT_BUDGET`, default
  30 s). On a stall the host is reported `direct-active` and skipped until the
  session ends; a second transport never starts while one is live.
- TLS verification is on by default. `WEBENRICH_VERIFY_TLS=false` is an
  explicit opt-in for these LAN CPEs, whose UI serves a self-signed
  certificate; it is never a global default.
- Every in-page fetch keeps its AbortController timer armed through the response
  **body** parse (not just the headers), so a peer that sends headers fast and
  then stalls cannot hang the session. Optional gauges (guest SSIDs, process
  status) get their own smaller budget and never discard a valid core: if they
  stall the error is swallowed and the field stays absent. The whole per-router
  browserless session has a 60 s budget (`ROUTER_BUDGET_SECONDS`) and cleanup
  is bounded. Login submits once (button click only); logout is a validated,
  CSRF-paired POST.
- Extraction is validated against a schema before "fresh" is claimed:
  `deviceinfo` object with string `SoftwareVersion`, `HostInfo` must be an
  array, `WifiConfig` must be an array, client MACs must be well formed. A
  valid empty client list is legitimate; malformed payloads are not published.
  A non-JSON (sanitized HTML) response is never published as fresh data.
- `/health` exposes per-router transport, freshness age, failure count and
  retry window, and transport counters, without credentials. `/inventory`
  serves the structured WLAN inventory (stable slots, raw vs effective channel,
  power as a percentage) plus real device metadata; the registry is metadata
  only and never changes a BSSID or radio state.
- Login-stage failures (bad password, UI changes) back off exponentially with a
  300 s floor and 900 s cap so per-minute retries cannot lock the account.
  Non-auth failures (timeouts, schema) use generic backoff and never retry
  authentication faster.

## Inventory and telemetry reconciliation (phase 2)

- The bridge reconciles its TR-098 radios with the webcol inventory
  (`huawei_bridge/inventory.py`). Web evidence is trusted for a CPE only when
  **both** the management IP and the hardware serial match the ACS identity, so
  a DHCP change can never bind telemetry to the wrong device.
- Slots are stable and persisted with atomic writes at
  `STATE_DIR/inventory/vap_map_v2.json` (v1 maps migrate by band+SSID). The
  identity is the web `native_id` (TR-098 SSID path) or, when absent, the
  TR-098 path, so SSID renames and row reorders keep the same virtual BSSID.
  Radio keys and existing adopted identities are never rewritten.
- Only profiles the web API reports as fresh and explicitly enabled are
  published. A profile without a TR-098 radio (or without an explicit enable
  flag) is kept as `observed_unmanaged` metadata with **no** channel; it is
  never read as disabled and no ghost BSSID is fabricated.
- `radio_table` has one deterministic entry per physical band (2.4/5 GHz),
  using the representative observed channel; conflicting observed channels on
  one band are flagged as uncertain rather than overwritten by the last value.
  A configured `channel 0` (automatic) is never sent as a physical channel.
- Real device metadata (WUKUN-BE32 model, firmware, serial, uptime) is exposed
  separately as `device_truth`; the virtual inform keeps the U7PRO profile and
  its own session uptime, so identity stays compatible and nothing is
  mispresented. `/api/inventory` and `/api/snapshot` carry it read-only.
- Reported counters are annotated with their source unit and delta/reset
  detection (`huawei_bridge/metrics.py`): no throughput is derived and
  directional rates stay as reported until unit and direction are proven.
  `radio_proto` is advertised only as `reported-unverified`.
- Inventory is optional and fails open: a webcol outage degrades the
  reconciliation but never breaks ACS collection or `/api/snapshot`. An offline
  CPE is never revived by web telemetry and keeps its honest stale/offline state.

## Provisioning write state machine (currently OFF)

`HUAWEI_CONTROL_IP` is empty, so the native `Control.receive` path never acts.
The separate admin sidecar (`webcol`) is also off: an empty `HW_OPERATIONS_TOKEN`
refuses every admin request, and its own `HW_OPERATIONS_WRITES` master switch
defaults to `0`. When the native path is re-enabled:

- In-flight phases (`queued`, `reading`, `submitting`, `uncertain`) are
  authoritative: `reject` cannot downgrade them and `receive` will not consume
  a new revision until they resolve.
- `failed` (task fault or readback timeout) requires manual inspection; the
  bridge never blindly retries a writeback without a definitive fault.
- UniFi reporting always echoes the controller's newest provision revision,
  independent of any stale CPE ack; it is a provisioning echo, never presented
  as a Huawei-confirmed value.
- Multiple VAPs per physical radio are supported through stable persisted
  bindings (web `native_id`/TR-098 path, with legacy migration). Bindings are
  only accepted from a trusted inventory (management IP AND serial matched);
  an unknown, ambiguous or untrusted binding fails closed instead of falling
  back to a legacy band map, so a DHCP change cannot misfire a write.
- The physical channel is applied to the deterministic primary radio of each
  band; per-VAP channels are not written. `cfgversion` is always an echo of the
  controller revision, kept distinct from `confirmed_version`, which is set only
  after a fresh readback; a rejected plan never fabricates an acknowledgement.
- Admin sidecar operations are a distinct path from native UniFi provisioning
  (see OPERATIONS.md): loopback-only, token-gated, with per-risk opt-ins for
  unverified writes and a one-use destructive reboot approval. Secrets (guest
  passwords) are never read back and are reported `applied_unverified`.

## Verification runbook (read-only)

```sh
/root/bridge-test-venv/bin/python -m unittest discover -s tests   # from the stack dir
docker compose config --quiet                                     # no secrets printed
curl -s http://127.0.0.1:8091/api/snapshot | python3 -m json.tool # bridge view
curl -s http://127.0.0.1:7560/health                              # per-router freshness
python3 /root/ucg_probe.py                                        # UCG stat/device + stat/sta
python3 tools/ucg_metrics_probe.py --base https://<ucg-ip> \
  --credentials <ro-creds.json> --period HOUR --json              # read-only native metrics
```

Controller truth: both virtual APs must show `state: 1`, `known_cfgversion`
equal to `cfgversion`, `num_sta` matching attributed clients in `stat/sta`.
A healthy bridge exchange alone does not prove controller-side visibility.
