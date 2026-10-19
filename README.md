# Huawei UniFi Bridge — API + TR-069 fork

This is the maintained `huawei-api-bridge` variant of
[RodrigoChang/TR-069-Unifi-Simulator](https://github.com/RodrigoChang/TR-069-Unifi-Simulator).
It preserves the original project's history, MIT license and acknowledgements.
The fork adds a direct Huawei API collector, explicitly pinned web-only devices,
durable radio/VAP identities, association conflict handling and guarded
administrative operations. See [FORK_NOTES.md](FORK_NOTES.md) for the branch
relationship, validation evidence, AI disclosure and limitations.

An experimental, self-hosted bridge that collects Huawei router telemetry through
GenieACS and/or the authenticated Huawei web API, displays it in a local dashboard,
and reports observed radios and Wi-Fi clients to UniFi Network as a virtual access
point. Web-only routers do not need to impersonate or register as ACS devices.

This independent project is based on the virtual AP simulation approach of
[MartinDejmal/unifi-simulator](https://github.com/MartinDejmal/unifi-simulator).
It does not install or depend on that repository. The adapted TNBU codec and its
MIT attribution are documented in [THIRD_PARTY_LICENSES.md](THIRD_PARTY_LICENSES.md).

**This does not turn a Huawei router into a native UniFi device.** The virtual AP
provides visibility and limited configuration translation, not full UniFi
management. Missing measurements are not fabricated.

## Acknowledgements and attribution

Special thanks to **MartinDejmal and the unifi-simulator contributors** for
[unifi-simulator](https://github.com/MartinDejmal/unifi-simulator), the original
project that provided the foundation for this bridge's UniFi AP simulation work.
Their work on reporting non-UniFi hardware to UniFi made this Huawei adaptation
possible.

This fork also acknowledges **Rodrigo Chang** for the original Huawei TR-069
bridge and **Vladimir Makeev** for the Huawei API client on which the adapted
authentication and operation contracts are based. Their copyright and license
notices are preserved in `LICENSE` and `THIRD_PARTY_LICENSES.md`.

The TNBU codec in `huawei_bridge/protocol.py` is adapted from upstream revision
[`adef72ae011837b07f7406a2932bc153febf84d9`](https://github.com/MartinDejmal/unifi-simulator/tree/adef72ae011837b07f7406a2932bc153febf84d9).
The upstream MIT copyright notice and license are preserved in
[THIRD_PARTY_LICENSES.md](THIRD_PARTY_LICENSES.md).

The Huawei TR-069 collection, local dashboard and allowlisted provisioning are
implemented in this separate project. This attribution does not imply endorsement
by the upstream authors, Huawei or Ubiquiti.

## AI development disclosure

**This project was developed with substantial generative AI assistance**, including
code implementation, test development, documentation and troubleshooting.
AI-assisted work can contain errors; this disclosure is not proof of correctness,
security, hardware compatibility or production readiness. Contributors and
maintainers remain responsible for reviewing changes and validating their claims.

AI-assisted and non-AI contributions are both welcome. **Every contribution and
pull request must explicitly declare whether AI was used (Yes or No)** and
describe its scope, tools and verification as required by
[CONTRIBUTING.md](CONTRIBUTING.md). Use the
[PR template](.github/pull_request_template.md) when submitting changes.

This statement describes work on this project; it does not make claims about
AI use by the upstream unifi-simulator authors. It is not an endorsement or
certification by an AI provider, Huawei, Ubiquiti or the upstream maintainers.

## Features and compatibility

- A local dashboard and JSON snapshot of directly registered Huawei CPEs.
- Observed SSIDs, channels, radio capabilities, client MAC/IP addresses and RSSI.
- Stable virtual identities, encrypted inform exchange and persisted adoption.
- Explicit mapping from Huawei SSIDs to existing UniFi WLAN IDs.
- Optional SSID, channel, enable/disable and WMM changes through GenieACS.

Upstream reference hardware is Huawei BE3 (`WUKUN-BE32`), firmware
`4.2.0.53(SP1C1555)`, with UniFi Network `10.6.106` as reported by upstream.
This fork has additionally been exercised with Network `11.0.89`, BE3 telemetry
and adopted virtual identities, and AX3 (`WS7200-30`) API-only collection and
virtual-device discovery. These observations do not certify other firmware,
physical write operations or full UniFi equivalence. The dashboard currently uses
Spanish labels.

```text
Huawei CPE -- TR-069/CWMP --> GenieACS -- NBI --+
                                             +--> Bridge -- inform --> UniFi
Huawei web API ---------> webcol --------------+       |
                                                Local dashboard
```

The default mode only reads telemetry. Optional provisioning follows the reverse
path: UniFi configuration → validated translation → ACS task → Huawei → fresh
readback confirmation.

## Requirements

- Docker Engine/Desktop running, with Docker Compose v2.
- `make` for convenience commands, or use Docker Compose directly.
- Either a Huawei router with configurable TR-069 and TR-098 WLAN data, or an
  explicitly configured API-only router with its own pinned serial.
- For TR-069 devices: connectivity to the Docker host's CWMP listener. For
  API-only devices: a persistent management route from the Docker host to the
  router. The collector does not configure host routes or IP aliases.
- For UniFi reporting: a reachable Network inform endpoint and an existing WLAN.
- Internet access for the initial image and dependency downloads.

Replace all `<PLACEHOLDERS>` with your own values. Example SSIDs and IDs are
synthetic. No deployment-specific LAN addresses are required in public files;
`127.0.0.1` below refers to the local Docker host.

## Quick start

From the project directory:

```sh
make up
```

Without `make`:

```sh
docker compose up -d --build
```

No `.env` is required for local monitoring. Without it, UniFi reporting and
both provisioning write paths are disabled by default. Startup never replaces an
existing `.env` or deletes data volumes.

| Service | Docker host address (application default) |
| --- | --- |
| Bridge dashboard / snapshot | <http://127.0.0.1:8091> (`8090` inside the container) |
| Inventory reconciliation | <http://127.0.0.1:8091/api/inventory> |
| Bridge health | <http://127.0.0.1:8091/health> |
| Web collection + admin sidecar | <http://127.0.0.1:7560> (`/health`, `/inventory`, `/capabilities`, `/operations`) |
| GenieACS UI | <http://127.0.0.1:3002> (container `3000`) |
| GenieACS NBI | `127.0.0.1:7557` |
| CWMP listener | TCP `7547`, bound to the single LAN address configured in `compose.yml` (owner-set `CWMP_BIND_IP`, loopback by default in examples) |

Running the bridge directly (outside Docker) keeps its own defaults:
`127.0.0.1:8090` with `STATE_DIR=.state/`.

### Control paths and phase status

There are two independent, separately gated write paths; a default install
writes nothing on either:

- **Native UniFi provisioning** (`HUAWEI_CONTROL_IP`): the bridge translates
  allowlisted `system_cfg` fields (SSID, fixed/automatic channel, enable, WMM)
  for multiple bound VAPs, and requires an unambiguous, trusted binding. With
  the variable empty it never writes.
- **Admin operations sidecar** (`HW_OPERATIONS_TOKEN` + `HW_OPERATIONS_WRITES`):
  loopback-only HTTP endpoints in the `webcol` service for 802.11r, TWT, MAC
  filtering, guest network and reboot plans. An empty token refuses every admin
  request; each destructive or unverified action has its own opt-in flag.

Read-only capability/plan status is exposed without enabling writes. Deployment
status: the reviewed bridge + webcol source (the full offline test suite) is deployed with
both write paths explicitly OFF and observed live:

- `HUAWEI_CONTROL_IP` empty and `HW_OPERATIONS_WRITES=0`; the admin write endpoint
  returns `403 writes_disabled` before any CPE configuration POST, and an
  unauthenticated admin request returns `401`. The command token lives only in the
  protected `.env` (mode 600) and is read manually by the owner, never from chat
  or docs.
- Direct API collection is primary on both CPEs (2 cycles each, browserless 0,
  failures 0) and `/inventory` reports both routers fresh with trusted identity.
- Controller-side projections are unchanged after deployment: both virtual APs
  stay `state 1`, the same `cfgversion` and VAP BSSIDs, and the CPE WLAN settings
  (SSID/channel/enable/WMM) are untouched — only login/logout were issued, never
  a configuration write.

Endpoint kinds, precisely: the native UniFi path implements an SSID/channel/WMM
planner but is not enabled; the extra Huawei admin operations (`wifi.80211r`,
`wifi.twt`, MAC filter, guest network, reboot) are **not** native UniFi buttons.
Reported client rates carry an unverified unit: they are shown as source values
only, never converted into directional TX/RX.

Allow a few seconds for startup, then check:

```sh
docker compose ps
curl --fail http://127.0.0.1:8091/health
```

Health confirms recent ACS collection, not AP adoption or client visibility.
Check those separately in the dashboard and UniFi.

### Configure the Huawei ACS connection

In the router's TR-069 settings:

| Setting | Value |
| --- | --- |
| ACS URL | `http://<DOCKER_HOST_LAN_IP>:7547/` |
| Periodic Inform | Enabled |
| Inform interval | `60` seconds |
| ACS username/password | Local test values if required by the router |

Use the Docker host's LAN address, **not** loopback, a container address or the
UniFi gateway address unless that gateway actually hosts this stack. Reserve the
host address in DHCP or keep it static. Wait for an Inform and confirm the CPE
appears in GenieACS and the dashboard.

**Lab security:** the supplied GenieACS configuration does not enforce the ACS
credentials sent by the CPE. Entering them in the router does not enable
server-side authentication. CWMP uses HTTP, and Compose includes a test UI JWT
secret. The CWMP port is published only on the single LAN address configured in
`compose.yml`; within that LAN the endpoint remains unauthenticated, so add a
firewall allowlist for the CPEs as defense in depth. Do not expose this stack
directly to the Internet or treat these defaults as production-hardened.

## Enable UniFi reporting

Copy the template without overwriting an existing local file:

```sh
cp -n .env.example .env
```

Edit `.env` using your own inform address and a real WLAN ID:

```ini
UNIFI_INFORM_URL=http://<UNIFI_HOST>:8080/inform
UNIFI_WLAN_MAP={"ExampleSSID":"0123456789abcdef01234567"}
HUAWEI_CONTROL_IP=
```

The example ID is not usable for your controller. The hostname must resolve from
the bridge container, and TCP `8080` must be reachable; see Ubiquiti's
[Layer 3 adoption guidance](https://help.ui.com/hc/en-us/articles/204909754-Remote-Adoption-Layer-3).
Leave `HUAWEI_CONTROL_IP` empty to keep the native UniFi path read-only (the
admin sidecar has its own `HW_OPERATIONS_WRITES` switch). Apply `.env` edits by
recreating the bridge:

```sh
docker compose up -d --build bridge
make logs
```

### How to obtain the WLAN ID

The bridge needs the existing Wi-Fi network's **internal `_id`**, normally a
24-character lowercase hexadecimal string. It is not the SSID, BSSID, AP MAC,
VLAN ID, wired network ID or site ID. SSIDs must match exactly, including case.
Create the Wi-Fi network in the intended UniFi site first; this bridge does not
create WLANs.

This lookup uses UniFi Network's internal web API, verified on `10.6.106`, not
the [official Integration API](https://help.ui.com/hc/en-us/articles/30076656117655-Getting-Started-with-the-Official-UniFi-API).
Internal paths may change between versions. Do not assume IDs from other API
resources are interchangeable with the WLAN `_id` expected here.

#### Option A: read-only browser query

1. Sign in to your controller's **local UniFi Network web interface** and select
   the site containing the Wi-Fi network. Do not run this from the bridge
   dashboard or the cloud Site Manager page.
2. Open Developer Tools → **Console**.
3. Set `site` to the internal site key. `default` is common for single-site
   installations, but is not guaranteed. Use the key in the local Network URL
   or its network requests, not the site's display name.
4. Use `/proxy/network` for UniFi OS consoles. For standalone Network
   applications serving `/api/s/...` directly, set `prefix` to an empty string.
5. Review and run this GET-only query. It uses your signed-in session and prints
   only Wi-Fi names and IDs, without exporting cookies or requiring an API key:

```javascript
(async () => {
  const site = 'default';
  const prefix = '/proxy/network'; // Use '' for a standalone Network application.
  const response = await fetch(
    `${prefix}/api/s/${encodeURIComponent(site)}/rest/wlanconf`,
    { method: 'GET', credentials: 'same-origin', cache: 'no-store' }
  );
  if (!response.ok) throw new Error(`WLAN lookup failed: HTTP ${response.status}`);
  const result = await response.json();
  if (!Array.isArray(result.data)) throw new Error('Unexpected WLAN response');
  console.table(result.data.map(({ name, _id }) => ({ ssid: name, wlan_id: _id })));
})().catch(error => console.error(error.message));
```

Locate your SSID in the table and copy its `wlan_id` into `UNIFI_WLAN_MAP`. If
the browser blocks pasted console code, use the Network inspector below instead
of disabling browser safeguards.

#### Option B: Network inspector

1. While signed in to local UniFi Network, open Developer Tools → **Network**
   and filter requests by `wlanconf`.
2. Open or reload the Wi-Fi settings page. If your version uses this endpoint,
   select its successful GET request and inspect the JSON response.
3. In `data`, find the object whose `name` matches your SSID and copy only its
   `_id`. The request URL also identifies the API prefix and site key.

**Never share the full WLAN response or publish a HAR export.** It may contain
Wi-Fi passwords and other secrets, even though Option A only prints names and
IDs. If the request is absent, use Option A with the appropriate path or inspect
your version's request format; do not invent an ID.

Example mapping for two Wi-Fi networks, using synthetic IDs:

```ini
UNIFI_WLAN_MAP={"ExampleSSID":"0123456789abcdef01234567","GuestSSID":"89abcdef0123456789abcdef"}
```

Replace each value with an ID from the site where the virtual AP is adopted.
Without a valid mapping, the bridge still reports identity and radios, but omits
the corresponding virtual WLAN interfaces and clients. The dashboard warns about
unmapped SSIDs. If you delete and recreate a WLAN, obtain its new ID and update
the mapping.

### Adopt the virtual AP

In UniFi Devices, adopt the pending AP whose **virtual MAC** matches the bridge
dashboard. Do not use the physical Huawei MAC or run UniFi firmware/SSH commands
on the Huawei router.

The compatibility profile is `U7PRO` (U7 Pro), with emulated firmware version
`8.7.11.19419`. The dashboard retains the actual Huawei model and firmware.
The [U7 Pro profile supports Wi-Fi 7 and 160 MHz](https://techspecs.ui.com/unifi/wifi/u7-pro),
but only radios actually observed on the Huawei are published:

- The tested BE3 reports 2.4/5 GHz, not 6 GHz.
- Radio AC/AX/BE capability flags come from TR-098 `Standard`.
- `has_ht160` is limited to the 5 GHz radio of the BE3 `WUKUN-BE32`.
- Supporting 160 MHz does not mean the active channel width is 160 MHz.
- Selecting a width in UniFi does not currently apply it to the Huawei.

`key-received` means an adoption key was received; `exchanging` means encrypted
exchange succeeded. Neither alone proves the AP is Online or its clients are
visible. Verify those results in UniFi. SSH adoption and UDP discovery are not
implemented.

### Inventory reconciliation (read-only)

The bridge reconciles the Huawei web WLAN inventory (collected by `webcol` over
the direct API) with TR-098 radios. A router's web evidence is applied only when
its management IP **and** hardware serial match the ACS identity, so a DHCP
change is never attributed to the wrong device. Only fresh, explicitly enabled
profiles are published; a profile without a TR-098 radio is retained as
`observed_unmanaged` metadata with no channel. `radio_table` keeps one
deterministic entry per physical band and flags conflicting observed channels as
uncertain instead of guessing; a configured `channel 0` (automatic) is never
sent as a physical channel. Stable virtual slots persist under `bridge-data`
(`inventory/vap_map_v2.json`) and keep the same virtual BSSID across SSID
renames and row reorders. Real model, firmware, serial and uptime appear as
read-only `device_truth`, while the inform keeps the virtual U7PRO identity and
publishes uptime only from fresh, trusted router evidence. The bridge session
uptime remains local diagnostic metadata. Reported counters carry their source unit and reset
detection; no throughput is derived. `/api/inventory` exposes this view and
never writes to a router.

### Read-only WEB-ONLY CPE (no TR-069)

Some Huawei CPEs (for example the AX3/WS7200 class) expose no usable TR-069
endpoint and never register with GenieACS. They can still be reported as an extra
virtual AP over their authenticated web API, without impersonating an ACS device:

- `WEB_ONLY_ROUTERS` lists `https://<router-ip>=<password>` pairs (protected
  `.env` only, empty by default; each URL must be a literal private/loopback IP
  with no userinfo and is never logged). `WEB_ONLY_SERIALS` pins
  `origin=serial` (an explicit canonical origin, no bare/ambiguous serial); webcol
  re-checks it on every poll and the bridge enforces its own independent
  origin-to-serial map (no password ever reaches the bridge). A non-direct
  transport or a session without the verified server signature/public key is
  refused, and only the WS7100/WS7200 model family is admitted. A CPE whose fresh
  serial does not match is never published.
- The provider consumes the webcol `/webonly` records and reuses the same
  bounded direct client and parsers. It is collected independently of ACS: a
  zero-device or all-offline ACS state never hides a healthy AX3, and losing the
  AX3 never changes the BE3 identity. Clients without a PHY mode are kept (the
  AX3 reports none); a native `LAN*`/`eth*` interface is treated as wired even
  when a stale wireless label is present, and `WlanActive=false` alone does not
  drop a row.
- Identity is serial-derived and stable: a private registry under `bridge-data`
  (`inventory/webonly_v1.json`, mode 0600) maps a hash of the pinned serial to an
  explicit source id and virtual MAC. The registry is strictly validated
  (bounded size, scheme/sources shape, id/MAC/hash consistency, no duplicate
  MAC/id); any malformed entry fails the whole web-only source closed and the
  file is never rewritten. **Identity and slots are persisted before the first
  AP is published**: if the background save has not completed (or fails, e.g.
  ENOSPC), the AX3 stays suppressed until durable state exists, while the BE3
  path is never blocked. A missing file is the only clean first boot. If a CPE
  with the same serial appears in ACS (even while the web source itself is
  offline, because the registry key is persistent), the new ACS AP and its
  clients are quarantined before the wire and before any ACS refresh/control; no
  new pending identity derived from that ACS unit is emitted, and a manual
  reconciliation is required (no automatic migration or re-adoption).
- Radios are one VAP per actual profile `native_id` (not per usage label), with
  the physical 2.4/5 GHz table deduplicated as before. Virtual slots are reserved
  historically by `native_id`, so a reorder, SSID rename, usage-flag change, a
  profile disappearing and later returning keep the same slot and wire BSSID.
  A profile without a `native_id`, or with a duplicated one, is rejected rather
  than guessed. Clients attach by exact native interface id, otherwise only by
  an unambiguous band plus the WlanGuideBasic `primary` role; a guest client is
  never mapped onto a primary-only band, and unbound clients are counted
  separately from the native client count. Only `WlanGuideBasic` profiles become
  primary VAPs; guest SSIDs are never inferred from names.
- The virtual AP keeps the U7PRO profile but advertises only the observed
  radios: no 6 GHz, no `be`, no fabricated 160 MHz. No effective channel is
  claimed (the read-only `wlanradio` getter does not expose current channel
  fields), so a configured channel—including automatic `0` and a configured
  `36`—is never sent as the effective one. CPU/memory gauges are published only
  when the stats timestamp is fresh (bounded TTL) and the values are finite
  percentages; an absent/old/bogus gauge is omitted, never freshened by the
  record timestamp.
- It is never controllable: `device_lookup` and any CWMP plan/ACS task are
  skipped for web-only (`cwmp-unsupported-web-source` is reported as an explicit
  reason, not an error), and native writes stay off even if its management IP is
  added to `HUAWEI_CONTROL_IP`.

This is an **external, temporary network dependency**: the AX3 is reachable only
while a LAN management route/alias to its `192.168.3.1` address exists. That route
does not survive a host reboot until the owner persists it (or the CPE's LAN
management IP is changed), so the web-only AP is not reported as permanent. The
provider never adds a privileged service, proxy MAC or network-admin container;
it fails only the AX3 when the route is lost and leaves everything else intact.

### Station association, persistence and poll isolation

- A single global arbiter runs before the UniFi wire for every provider. Fresh
  clients are grouped by MAC and the strongest evidence wins: `TR-069
  AssociatedDevice` with `AuthenticationState=true` is `strong-authenticated`
  (source confidence, not a hardware crypto claim); a native associated MAC
  without that flag is `reported`; `HostInfo` rows are `weak` (ARP/IP presence,
  not association proof). A tie inside the winning tier is ambiguous and every
  candidate for that MAC is suppressed, never resolved by poll timestamp, so a
  duplicate or roaming client cannot flap between the ACS CPEs and the web-only
  AP. Stale observations are excluded from arbitration (age describes the
  source, not a roam decision). An explicit negative `AuthenticationState`
  (false/0/`'false'`/`'0'`) excludes the row entirely rather than treating it as
  a weak candidate. `client_count` is the publishable count; the
  reported count and unbound web clients are kept separately.
- Registry persistence runs on one bounded background writer, never in the
  snapshot/inform thread: the state is copied under a quick lock, at most one
  pending payload per namespace is queued, and a generation is acknowledged only
  after it is durably written. A stuck or failed save (for example ENOSPC) backs
  off without starving the other registry and suppresses the AX3 rather than
  blocking the BE3. Identity and VAP slots are therefore durable before a new
  web-only AP is ever published. Shutdown is bounded and best-effort: a pending
  write may be dropped, which is safe because an AP is never published before its
  identity is durable.
- Diagnostics use hashed, non-plaintext client and identity identifiers (MAC and
  serial are never logged in clear). The bootstrap identity file
  (`/root/ax3-api-bootstrap-*/identity.json`, mode 0600) is private operator data
  and must never be copied into public fixtures or documentation.
- The `webcol` cycle dispatches normal CPEs and web-only CPEs as separate tasks
  under a shared semaphore of two, one poll per host: a slow or failing web-only
  poll overlaps instead of delaying the normal CPE refresh.

## Optional configuration from UniFi

To enable writes for one directly registered CPE, set its management/callback IP
in `.env` and recreate the bridge. This is disabled by default.

```ini
HUAWEI_CONTROL_IP=<HUAWEI_MANAGEMENT_IP>
```

| UniFi field | Huawei TR-098 parameter |
| --- | --- |
| `wireless.N.ssid` | Bound WLAN's `SSID` |
| `radio.N.channel` | `Channel` + `AutoChannelEnable`; `auto` only enables automatic selection |
| `radio.N.status` / `wireless.N.status` | Bound WLAN's `Enable` |
| `wireless.N.wmm` | Bound WLAN's `WMMEnable` |

Radios bind through `phyname`/`parent` and observed TR-098 paths, not row position.
Multiple VAPs per physical radio are supported through stable, persisted
bindings (keyed by the web `native_id`/TR-098 path, never by SSID or row order),
with legacy single-binding records migrated automatically. An unknown, ambiguous
or untrusted binding is rejected rather than guessed; channels must be advertised
in `PossibleChannels`, and changed parameters must exist and be writable.

The first configuration establishes a baseline **without writing controller
defaults to the router**. Later supported changes generate `setParameterValues`
tasks. A task ID is not success: matching values with fresh readback timestamps
are required before acknowledging the revision. Allow for the router's Inform
interval before expecting results.

The dashboard distinguishes baseline, queued, reading, confirmed, rejected,
failed and uncertain states. Faults or 300 seconds without confirmation fail the
change. Writes are not automatically resent. For an unknown submission outcome,
inspect GenieACS tasks, faults and current values before intervening; do not
delete state or blindly repeat a write. After resolving a failed revision,
generate a new revision in UniFi to retry. State and WLAN bindings persist across
restarts and SSID changes.

A controller-requested virtual reset requires a new baseline. If an ACS task
was already pending, further writes remain blocked for manual inspection.

**Not translated:** passwords, WPA security, VLANs, channel widths, transmit
power, firmware, reboots, SSH and shell commands. An acknowledgement covers only
allowlisted fields, not the entire UniFi configuration. Supported Wi-Fi changes
can still temporarily disconnect clients. GenieACS presets are independent and
may provision a router outside this bridge's allowlist.

## Telemetry and limitations

The collector reads `InternetGatewayDevice.LANDevice.*.WLANConfiguration.*`,
refreshes LAN data every 60 seconds without duplicating pending refreshes, and
marks observations older than 180 seconds as stale. Stale clients are excluded
from UniFi reporting. Duplicate associations are reduced to the newest record.
Client names come from the Hosts table when available. Zero RSSI is unknown;
Huawei's positive RSSI magnitude is converted to negative dBm.

No traffic counters, client speeds, noise, transmit power or connection duration
are fabricated. Band mapping targets the tested 2.4/5 GHz device; 6 GHz hardware
requires additional handling. Controller defaults are not Huawei measurements.

### Native CPU, memory and uptime

When the web `direct` transport succeeds, the bridge reads the router's own
`GET /api/system/processstatus` once per cycle and uses **only** the first row
(`Name: "Total"`) as the router-wide CPU/memory gauge. This matches the router's
bundled UI, which renders `processstatus[0].CpuUsage`/`MemUsage` as percentages
when the `isSupportShowCpuMemoryStatus` capability is set; no per-process row is
ever summed, and no per-process name is published. Values are exported to the
UniFi inform as the native `system-stats` object (`cpu`, `mem` as percentage
strings) plus `uptime` in seconds, and only while the CPE is trusted (management
IP **and** serial matched) and the observation is fresh. Uptime comes from the
router's **web** `GET /api/system/deviceinfo` `UpTime` field — not from the
TR-098 `InternetGatewayDevice.DeviceInfo.UpTime` parameter, which this firmware
does not expose here. The bridge never publishes its own process uptime as
device uptime, and when no hardware reading exists the field is omitted.
Absolute memory bytes (`sys_stats.mem_total`/`mem_used`), load averages,
temperature and air/retry/satisfaction metrics are never invented.

The deployed Network 11.0.89 controller has accepted `system-stats.cpu`,
`system-stats.mem`, and router uptime in `stat/device`. Its native
`systemBySiteByDevice` history now contains `avgCpuUtilizationPct` and
`avgMemoryUtilizationPct` samples. A read-only browser check confirmed Memory
Usage and router Uptime in both AP detail panels. The tested U7 Pro detail view
does not display a CPU gauge, even though CPU is available in the controller
API and history. This is not a claim that every UniFi panel is supported.

The native `wirelessTrafficBySiteByDevice` query still returns no byte values
for the selected APs. Air Stats displays zero/default values, not independently
measured zero traffic or zero retries. Retries, airtime, satisfaction and the
unverified shared interface byte counters remain unsupported by the observed
sources and are never invented or exported to the device/VAP wire.

Per-interface TR-098 counters (`TotalBytesSent`/`Received`,
`TotalPacketsSent`/`Received`, `Stats.Errors*`/`Discards*`) are recorded as
**diagnostic observations only**. On the tested firmware the two
`WLANConfiguration` interfaces report near-identical totals, so their scope is
marked `shared_or_mirrored_unverified` and they are never summed, deduplicated
or written to the device/VAP wire. Each observation keeps its own
`_timestamp`/`_type` leaf metadata and the counter state is persisted to
`bridge-data` under `metrics/counters_v1.json`; replay/reordered snapshots never
advance state or repeat a delta, a wider-than-threshold gap invalidates the
interval, and a decrease is treated as a reset (never a guessed wrap). Metrics
no observed endpoint provides (retries, airtime, satisfaction) are reported as
`unavailable_in_observed_sources`, and per-station `HostInfo` bytes are labelled
`client_per_station_traffic_unusable`. The snapshot exposes a per-AP
`metric_capabilities` table with the exact source, unit and reason for every
proven, blocked or unavailable metric.

### Wi-Fi generation per client

The tested BE3 exposes MAC, IP and RSSI through TR-069 `AssociatedDevice`, and
`Standard` describes the radio's capabilities rather than a client's mode.

The `webcol` service now collects Huawei's authenticated `GET /api/system/HostInfo`
automatically over the direct web API using credentials stored only in the
protected `.env`, and the bridge merges per-client `phyMode` into a neutral
`radio_proto` when the evidence is fresh. It is advertised as
`reported-unverified`: it is what the router reports, not a controller-confirmed
mode. Clients without fresh web evidence simply omit it, and no browser cookie
or web session is exported.

### EasyMesh satellites

EasyMesh collection is not implemented. Each CPE currently needs to register
directly with GenieACS. The primary Huawei's authenticated
`GET /api/device/l2topo` was observed to expose controller/agent relationships,
but agent client lists can be empty. This is a possible future source, not proof
of complete per-node telemetry or an existing project feature.

## Operation and persistence

```sh
make logs                              # Follow bridge logs; Ctrl+C stops following.
make stop                              # Stop services without deleting data.
docker compose up -d --build bridge     # Rebuild only the bridge.
docker compose stop bridge             # Stop the bridge; leave GenieACS running.
```

`mongo-data` holds GenieACS data. `bridge-data` holds private adoption keys,
stable identities, WLAN bindings, provisioning state and the bounded interface
counter state (`metrics/counters_v1.json`, written atomically and fail-open so a
metric failure never affects the inform). **Do not delete these
volumes or run `docker compose down -v` as an update step.** Backups contain
sensitive data and must be stored securely.

Forgetting a virtual AP can discard controller history/settings. Readoption may
also need an explicit reset of local adoption credentials; an HTTP error alone
does not prove or authorize that action. Coordinate both ends and preserve the
virtual identity. Never factory-reset the physical Huawei to recover a virtual AP.

## Troubleshooting

| Symptom | Checks |
| --- | --- |
| No Huawei appears | Docker host LAN address in ACS URL, reachable TCP 7547, enabled Inform and CPE present in GenieACS. |
| Clients appear locally but not in UniFi | Exact SSID, real 24-character WLAN `_id`, correct site and recreated bridge after `.env` changes. |
| Pending adoption / offline virtual AP | Inform URL, container-to-controller TCP 8080 connectivity, controller version and persisted adoption state. |
| WLAN lookup returns HTTP 401/403 | Sign in to local Network with appropriate read access; check site and API prefix. Do not export cookies. |
| WLAN lookup returns HTTP 404 | Check UniFi OS versus standalone prefix, site key and Network version. |
| Dashboard returns HTTP 403 | Use the documented loopback URL; Host and Origin headers are validated. |
| Provisioning stays queued/reading | Wait for the next Inform; inspect its task and faults in GenieACS. |
| Wrong client generation or channel width | These may be controller defaults; see telemetry limitations. |

## Development and validation

For local execution and tests, use Python 3.11+:

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements.txt
make test
python -m huawei_bridge
```

Local execution defaults to NBI at `http://127.0.0.1:7557` and `.state/` for
persistence. Export environment variables when running Python directly: `.env`
is consumed by Compose, not automatically loaded by the application. Do not run
a second emitter against the same virtual AP while the Docker bridge is active.
Tests use synthetic fixtures/local HTTP peers, not the real router; HTTP tests
require permission to bind loopback sockets.

The test suite covers normalization,
encryption/adoption, WLAN mapping, HTTP boundaries, translation, persistence,
readback, faults and uncertain outcomes. Hardware validation included adoption,
restart persistence, client visibility, 160 MHz capability display and an
idempotent WMM write followed by fresh ACS readback. Disruptive SSID/channel
changes have not been validated against the physical router.

### Controller-native metrics probe

`tools/ucg_metrics_probe.py` is a read-only, credential-file-driven CLI used to
verify what the UCG/Network controller reports natively for the APs (the
`stat/device` `system-stats`/`sys_stats` blocks and the modern
`/v2/api/stats/recent/series` schemas). It makes GET requests plus one login,
never writes, and its output distinguishes a genuinely empty series (controller
history/analytics disabled for that range) from a 403 (read-only role or a
missing CSRF token, never treated as success). It reports only current
observations — no backfill or synthetic history is fabricated — and the recent
series may legitimately include buckets from the recent past. Example:

```sh
python3 tools/ucg_metrics_probe.py \
  --base https://<controller-ip> --credentials <ro-creds.json> \
  --device-mac <ap-mac> --period HOUR --json
```

Credentials stay in a separate `0600` JSON file and are never embedded in the
tool, output or repository.

| Variable | Purpose / default |
| --- | --- |
| `UNIFI_INFORM_URL` | Empty disables the emitter. |
| `UNIFI_WLAN_MAP` | JSON mapping of exact SSIDs to real WLAN IDs; empty means no mapped WLANs. |
| `HUAWEI_CONTROL_IP` | Empty disables native UniFi provisioning; otherwise restricts it to listed management IPs (comma separated). |
| `WEBROUTERS` | `https://<ip>=<password>` telemetry sources for the `webcol` direct API collector. |
| `HW_OPERATIONS_TOKEN` | Empty refuses every admin sidecar request. |
| `HW_OPERATIONS_WRITES` / `HW_OPERATIONS_ALLOW` | Master write switch (default `0`) and comma-separated write allowlist. |
| `HW_OPERATIONS_UNVERIFIED_WRITES` / `HW_OPERATIONS_REBOOT_APPROVED` / `HW_OPERATIONS_RESOLVE` | Per-risk opt-ins (default `0`). |
| `HW_OPERATIONS_STATE` | Redacted sidecar ledger, e.g. `/data/operations_state.json`. |
| `HW_ROUTER_SERIALS` | Optional `host=serial` expectations; the fresh deviceinfo serial must match before a session is trusted. |
| `GENIEACS_URL` | NBI URL; local default `http://127.0.0.1:7557`. |
| `STATE_DIR` | Local default `.state/`; Docker uses `/data`. |
| `PUBLIC_URL` | Default `http://127.0.0.1:8090`; participates in request validation. |
| `LISTEN_HOST` / `PORT` | Local defaults `127.0.0.1` / `8090`; Docker listens internally on `0.0.0.0`. |

See [AGENTS.md](AGENTS.md) for contributor/agent constraints and
[compose.yml](compose.yml) for Docker settings.

## Before publishing to Git

- Keep deployment addresses, actual SSIDs, WLAN IDs and credentials in ignored
  `.env`, not public examples. The template leaves integrations disabled.
- Do not commit state, volume exports, keys, HAR/packet captures, raw ACS/WLAN
  responses or screenshots containing client information.
- `.gitignore` does not untrack files or scrub history. If a secret was committed,
  remove it from publication and rotate it; ignoring it afterward is insufficient.
- Review the exact files and diff being published. Preserve third-party
  attribution. `THIRD_PARTY_LICENSES.md` covers the adapted codec; do not assume
  that it grants a license for every other project file.

The dashboard, NBI and GenieACS UI bind to loopback in the supplied stack. Do not
publish their APIs without authentication and transport/access controls. This is
an experimental LAN integration, not an officially supported Huawei/Ubiquiti
management solution.
