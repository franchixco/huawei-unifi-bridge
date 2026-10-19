# Huawei provisioning control path

`huawei_bridge/control.py` translates an allowlisted subset of the UniFi
`system_cfg` into TR-098 `setParameterValues` tasks and confirms them by
readback. It is the only UniFi→Huawei control path. Writes stay disabled unless
`HUAWEI_CONTROL_IP` (or the `allowed_ip` argument) names the CPE; with an empty
allowlist every method is read-only.

## Supported commands

Only these fields are translated; everything else is ignored and reported as a
diagnostic (names only, never values):

| UniFi field | TR-098 parameter |
| --- | --- |
| `radio.N.phyname` | selects the bound physical radio |
| `radio.N.channel` (`auto` or an advertised number) | `AutoChannelEnable` + `Channel` |
| `radio.N.status` / `wireless.N.status` | `Enable` |
| `wireless.N.parent` | selects the bound virtual AP |
| `wireless.N.ssid` | `SSID` (UTF-8, ≤ 32 bytes) |
| `wireless.N.wmm` | `WMMEnable` |
| `wireless.N.devname` / `name` / `id` | stable VAP identity (not a write target) |

Security, PSK, VLAN, width, transmit power and similar fields are never
translated, never persisted and never logged. `strict_unsupported=True` rejects
the whole plan when any of them is present, so a partially supported plan is
never half-applied.

## Bindings schema

Bindings are persisted per virtual AP identity and migrate automatically from
the legacy `{phy: {path, wlan_id}}` shape.

```json
{
  "schema_version": 2,
  "radios": {"wifi0": {"path": "...WLANConfiguration.1", "native_id": "..."}},
  "vaps": {
    "<identity>": {"phy": "wifi0", "path": "...WLANConfiguration.1",
                   "wlan_id": "0123456789abcdef01234567",
                   "native_id": "...", "ssid": "Lab"}
  }
}
```

Resolution order for each `wireless.N`: explicit identity (`devname`/`name`/`id`),
then a unique `(phy, ssid)` match, then the single candidate for that physical
radio. Two candidates for the same identity, SSID or physical radio raise
`Ambiguous VAP binding`; an unknown `parent` or a `wireless.N` without a binding
raises `Unresolved VAP binding`. Nothing is guessed and no extra VAP is
fabricated to satisfy a controller SSID that the router never reported.

`Control.build_bindings(ap, mapping)` derives bindings from a trusted inventory
(IP **and** serial matched upstream). Untrusted or unmatched radios are skipped,
falling back to the legacy band mapping only for a unique observed SSID.

## Read-only planning

- `analyze(config, bindings, device, strict_unsupported=False)` →
  `(desired, diagnostics)`; pure, no writes.
- `translate(...)` → `desired` only (legacy-compatible).
- `Control.plan(ap, response, device, mapping)` → resolved bindings, targets and
  the current diff, plus `blocked_reason` (`writes-disabled`) when the CPE is not
  allowlisted. Never writes.
- `Control.capabilities(ap, device)` → bound radios/VAPs, advertised channels
  and per-field writability.

## State machine and confirmation

`baseline` records the first controller revision without writing: existing
controller defaults are never imposed on the router. Later revisions produce a
`setParameterValues` task only for parameters whose live value differs from the
desired value (drift under an unchanged revision still triggers a change).
`ack_version` is the controller-revision echo; `confirmed_version` is set only
after the CPE reports the value with a readback timestamp at or after the
request, so a historical acknowledgement is never presented as hardware
confirmation. A verified no-op (desired equals the live value) is reported as
`confirmed` with no task.

Faults, readback timeouts, unknown submissions and failed writebacks never
retry automatically; `reject()` never downgrades an in-flight or failed record.
`reconcile()` drives `queued → reading → confirmed|failed` and requires fresh
timestamps. Each submission records a `request_id`; a duplicate revision does
not submit twice, and record access is guarded by a re-entrant lock.

## Integration

`Control(directory, request, allowed_ip='', inventory=None)`. The optional
`inventory` may be a per-CPE provider (callable or mapping) returning the
phase-2 inventory dict; when omitted, `ap['inventory']` is used, which is how
`__main__`/`unifi` currently supply it (no explicit provider argument is passed).
Bindings are accepted only when that inventory reports `trusted is True`
(management IP AND serial matched); an untrusted or incomplete inventory raises
instead of falling back to the legacy band map, so a DHCP change cannot misfire a
write. The legacy `{phy: {path, wlan_id}}` path is used only when no inventory is
present at all (older records/tests). `plan()` returns that refusal as `ok: false`
with the reason, without writing.

## Limitations

- Multi-VAP translation and reconciliation are validated offline only; no live
  Huawei/controller multi-VAP write has been executed in this phase.
- The physical channel is applied to the deterministic primary radio of each
  band; per-VAP channels are not written.
- UniFi radio status maps to the per-SSID `Enable` of the bound WLAN(s); the
  behaviour of a radio-level disable with multiple VAPs is reported, not forced.
