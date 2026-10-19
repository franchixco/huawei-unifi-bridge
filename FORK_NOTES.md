# Fork scope and provenance

## Branch relationship

This repository is a fork of
[RodrigoChang/TR-069-Unifi-Simulator](https://github.com/RodrigoChang/TR-069-Unifi-Simulator).
The `huawei-api-bridge` branch is the maintained variant. The fork's `main`
branch preserves the upstream snapshot and is not rewritten by the variant.

The variant is based on upstream commit `5cf246a`, whose tree is identical to the
initial bridge snapshot used during development. Upstream subsequently added
hardening and optional web/mesh inventory through `e72fa0b7`; those commits are
not automatically merged into this branch. Similar features in the two lines
are not, by themselves, evidence that a correction is missing upstream.

Future contributions should compare behavior against the current upstream HEAD,
start from an appropriate upstream-based branch, and discuss substantial API,
device or write-access changes before proposing a PR. This publication does not
open a PR or imply endorsement by upstream, Huawei or Ubiquiti.

## Variant capabilities

- An API-primary Huawei collector with checked SCRAM server/public-key proofs,
  rotating session/CSRF state, bounded requests and lockout-aware retry policy.
- The original GenieACS/TR-098 source alongside explicitly configured web-only
  WS7100/WS7200 sources, without inserting synthetic devices into GenieACS.
- Serial-pinned identities, stable native-profile/VAP slots, fail-closed state
  validation and generation-confirmed asynchronous registry persistence.
- Global client-association conflict handling, without choosing a roaming AP
  merely by which source was polled last.
- Hardware CPU/memory percentages and uptime when observed and trusted, with a
  controller-native metrics probe for Network 11.
- Multi-VAP TR-069 planning and a separate token-gated administrative API.
  Configuration writes, unverifiable secret changes and destructive operations
  require their own opt-ins and remain disabled in the reference deployment.

## Limits that remain explicit

The emulated UniFi profile is a compatibility identity, not a hardware upgrade.
Missing PHY generation, RSSI, effective channels, traffic, retries, airtime or
radio width must not be inferred from that profile. Ambiguous shared interface
counters are retained for diagnostics rather than summed or duplicated into
native throughput graphs. Existing history is queried, not fabricated or
retroactively backfilled.

AX3 collection and virtual-device discovery were checked on a real router. Its
firmware did not provide a usable TR-069 endpoint, and some client fields were
absent. Discovery is not proof that a device has been adopted by every target
controller. API-only routers never become native CWMP provisioning targets.

Each API-only router needs a durable host management route. A temporary alias
used during diagnostics is not a persistent network configuration. This project
does not install a privileged route service, create a network-admin container,
or depend on a user's laptop as a permanent proxy.

The sample stack is a private-LAN lab setup. Loopback-bound management endpoints,
disabled write gates and example authentication settings do not make unauthenticated
HTTP CWMP safe to expose to untrusted networks.

## Validation and AI disclosure

AI assistance: **Yes**.

Tools/models included OpenCode with oh-my-openagent, OpenAI GPT-6.1-sol and
DeepSeek V4.1 Flash. Assistance covered architecture, implementation, regression
tests, documentation, diagnosis, review and publication preparation. This does
not constitute a human audit or vendor certification.

The development snapshot was checked with 488 local unit tests, including fake
HTTP peers and synthetic failure cases. The reference server ran the same 488
tests with two JavaScript-runtime tests skipped because that host lacked the
test engine; those tests passed locally. The publication copy is tested again
after replacing deployment-specific fixtures with synthetic data.

Real checks included BE3 API/CWMP telemetry, adopted virtual-device continuity,
AX3 API-only discovery, and controller API/history/UI observations for supported
hardware gauges. These checks do not verify all physical configuration writes.
The hardware compatibility and native-panel limitations in the README still
apply.

Secrets, adoption keys, cookies, runtime state, screenshots and laboratory
backups are not part of the source export. Fixtures use synthetic values.
The original MIT license and all third-party copyright notices are retained;
this fork does not claim the original authors' work as its own.
