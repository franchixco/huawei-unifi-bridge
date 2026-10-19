# Agent instructions

## Purpose and scope

An independent Huawei TR-069 → GenieACS → local dashboard / virtual UniFi AP
project, based on the AP simulation approach of
[MartinDejmal/unifi-simulator](https://github.com/MartinDejmal/unifi-simulator).
Do not modify or integrate this code into the upstream repository. Preserve the
acknowledgements and the adapted TNBU codec's MIT attribution in
`THIRD_PARTY_LICENSES.md`.

Respond to the owner in Spanish unless requested otherwise. Keep public project
documentation in English. Distinguish verified results from limitations and
hypotheses. Prefer small changes without new dependencies when the standard
library or existing components are sufficient.

## Project map

- `huawei_bridge/collector.py`: normalizes TR-098 radios, clients and data age.
- `huawei_bridge/protocol.py`: TNBU codec, CBC/GCM and packet validation.
- `huawei_bridge/unifi.py`: virtual profile, inform, adoption and WLAN mapping.
- `huawei_bridge/control.py`: allowlisted translation and ACS task confirmation.
- `huawei_bridge/__main__.py`: ACS collection, worker, HTTP API and dashboard.
- `huawei_bridge/static/`: dashboard without a framework or additional build step.
- `tools/ucg_metrics_probe.py`: read-only CLI probing controller-native AP
  metrics (`stat/device` system stats and `/v2` recent series); GET-only, no
  writes, credentials from a separate file.
- `tests/`: `unittest` tests with synthetic fixtures and local HTTP peers.
- `compose.yml`, `Dockerfile*`: GenieACS/MongoDB/bridge lab stack.

## Startup and tests

From the project root, with Docker Engine/Desktop running and Compose v2:

```sh
make up
make logs
make stop
```

`make up` rebuilds and starts services without replacing `.env` or deleting
volumes. `make stop` stops services without deleting data. Under Compose the
bridge dashboard is at `http://127.0.0.1:8091` (container `8090`), the `webcol`
telemetry/admin sidecar at `http://127.0.0.1:7560`, GenieACS UI at
`http://127.0.0.1:3002`, and bridge health at `/health`. Running the bridge
directly keeps its own `127.0.0.1:8090` default. The first build requires image
and package downloads.

Run tests with Python 3.11+ and `requirements.txt` installed, preferably in an
activated `.venv`:

```sh
make test
```

HTTP tests need permission to bind loopback sockets; a sandbox denying that
operation does not mean the application is broken. Do not skip those tests and
claim the full suite passed. Verify Makefile changes using `make -n`; do not
execute `stop` merely to test it against the active lab.

## Configuration and persistent data

- Consult `.env.example` and README for variables. Do not print or overwrite an
  existing `.env`. Without `.env`, Compose disables the emitter and write control.
- `UNIFI_WLAN_MAP` must use real IDs of existing WLANs. Never fabricate IDs.
- An empty `HUAWEI_CONTROL_IP` means observation only. Enabling it technically
  allows the bridge to write to one CPE; it does not authorize the agent to
  expand the scope of changes.
- Preserve `mongo-data` and `bridge-data`: they hold inventory, keys, adopted
  identity, WLAN bindings and provisioning state.
- Do not run `docker compose down -v`, remove volumes, forget APs, reset keys or
  readopt without explicit owner authorization. Readoption must affect only the
  virtual AP, never factory-reset the physical Huawei.

## Contracts to preserve

- The current profile is a virtual U7 Pro (`U7PRO`), not the Huawei's actual
  model or firmware. Keep the virtual MAC stable and the identity persistent.
- Publish only observed radios. The verified BE3 uses 2.4/5 GHz; do not add
  6 GHz merely because the profile is a U7 Pro.
- `Standard` describes radio capabilities, not each client's mode. Radio
  AC/AX/BE flags come from that field; `has_ht160` is limited to the 5 GHz radio
  of the BE3 `WUKUN-BE32`. A 160 MHz capability is not the active channel width.
- Do not infer missing generation, speeds, traffic, RSSI or topology. Exclude
  stale observations from reporting according to the collector's rules.
- The `webcol` service collects per-client `phyMode` automatically over
  Huawei's authenticated web API, using credentials kept only in the protected
  `.env`; the bridge merges it into a neutral, `reported-unverified` `radio_proto`
  when the evidence is fresh. Never export browser cookies or session material,
  and never present `reported-unverified` data as controller-confirmed.
- EasyMesh is not implemented. The primary router exposes topology through
  `/api/device/l2topo`; its agent client lists can be empty, so it is reported as
  support metadata only, never as complete agent metrics.

## Writes and security

- Native UniFi translation covers SSID, fixed/automatic channel, enable/disable
  and WMM for multiple VAPs per radio through stable, trusted bindings. Preserve
  the allowlist, unambiguous/trusted binding (fail closed on untrusted or
  ambiguous inventory), channel validation and writable-field checks.
- The admin sidecar (see OPERATIONS.md) is a separate, loopback-only, token-gated
  path: empty token refuses every request, writes and unverified/destructive
  actions each need their own opt-in, and secrets are never read back. Keep it
  distinct from the native inform path.
- The first configuration establishes a baseline without writes. Never impose
  UniFi defaults on the Huawei during startup or readoption.
- An ACS task ID does not confirm a write. Require matching readback values
  timestamped after the request. Preserve fault handling, timeouts, persistence
  and uncertain outcomes without automatic write retries.
- Do not translate passwords, WPA, VLANs, firmware, reboots, SSH, commands,
  transmit power or channel width without additional design and authorization.
- Never save full `system_cfg`, Wi-Fi keys, cookies or authkeys in logs, fixtures,
  public captures or documentation. Project only necessary fields when inspecting
  ACS/UniFi responses; they may contain secrets.
- Do not expose the dashboard, NBI or UI beyond loopback. Lab CWMP uses HTTP on
  port 7547 and must remain restricted to the LAN. GenieACS test authentication
  settings and the UI JWT secret are not a production configuration.
- Keep deployment-specific addresses and identifiers out of public files;
  preserve generic placeholders and disabled defaults in `.env.example`.

## Before handing off changes

Follow `CONTRIBUTING.md` and `.github/pull_request_template.md`. Every contribution
or PR must explicitly disclose AI assistance as Yes or No, including AI used for
code, tests, documentation, translations, incorporated suggestions and PR text.
For AI-assisted work, name the tools and describe their scope and actual review
and verification. Never claim No for agent-generated work. Keep disclosures
accurate during revisions without exposing private prompts, secrets or deployment
data. Preserve the project's AI development disclosure and upstream attribution.

Update tests and README when contracts, operation or limitations change. Run
relevant checks and report actual results, distinguishing automated tests from
hardware/controller validation. For new operational commands, verify that `.env`,
volumes and adoption state are preserved.

This directory may not be initialized in Git. Do not run `git init`, create
commits or publish the project unless the owner requests it.
