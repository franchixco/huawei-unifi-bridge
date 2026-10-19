"""Offline tests for the gated control-operation engine (webcol/operations.py).

Everything is synthetic: fake transports, synthetic router IDs, a generated
throwaway RSA key and a placeholder password that exists only here. No real
router credential, key, cookie or response is used, and no socket is opened.
"""

import importlib.util
import json
import sys
import unittest
from copy import deepcopy
from pathlib import Path

WEBROOT = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location(
    "operations_under_test", WEBROOT / "webcol" / "operations.py"
)
assert _spec is not None and _spec.loader is not None
ops = importlib.util.module_from_spec(_spec)
sys.modules["operations_under_test"] = ops
_spec.loader.exec_module(ops)

RID = "be3-lab"
OTHER = "other-router"
PLACEHOLDER_PASSWORD = "synthetic-placeholder-only"

_CRYPTO = ops.crypto_available()
if _CRYPTO:  # pragma: no cover - exercised in every RSA test below
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding, rsa

    _KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    _NUMBERS = _KEY.public_key().public_numbers()
    RSA_KEY = {"rsan": format(_NUMBERS.n, "x"), "rsae": format(_NUMBERS.e, "x")}


def wlanguide(dot11r=False, twt=False, ids=("1", "2")):
    return {
        "WifiConfig": [
            {"ID": ids[0], "FrequencyBand": "2.4GHz", "WifiSsid": "main",
             "WifiEnable": True, "Dot11REnable": dot11r, "TWTEnable": twt},
            {"ID": ids[1], "FrequencyBand": "5GHz", "WifiSsid": "main5",
             "WifiEnable": True, "Dot11REnable": dot11r, "TWTEnable": twt},
        ]
    }


def wlan_filter(mode=0, enabled=True, black_2g=(), black_5g=()):
    def state(item_id, band, blacklist):
        return {
            "ID": item_id,
            "FrequencyBand": band,
            "MACAddressControlEnabled": enabled,
            "MacFilterPolicy": mode,
            "WMacAddresses": [],
            "BMacAddresses": [dict(b) for b in blacklist],
        }

    return [state("f2", "2.4GHz", black_2g), state("f5", "5GHz", black_5g)]


def guest(enabled=False, ssid="Guest", sec="tkip", can=True):
    def item(item_id, band):
        return {
            "ID": item_id,
            "FrequencyBand": band,
            "EnableFrequency": enabled,
            "CanEnableFrequency": can,
            "SecOpt": sec,
            "WifiSsid": ssid,
            "WpaPreSharedKey": "",
            "ValidTime": 3,
        }

    return [item("g2", "2.4GHz"), item("g5", "5GHz")]


class FakeTransport:
    def __init__(self):
        self.read_handlers = {}
        self.post_results = []
        self.post_effects = {}
        self.calls = []

    def read(self, path):
        self.calls.append({"method": "GET", "path": path})
        handler = self.read_handlers.get(path)
        if handler is None:
            raise ops.TransportError("unknown_path", "read")
        if isinstance(handler, Exception):
            raise handler
        if callable(handler):
            return handler()
        return handler

    def post(self, path, payload, *, extra=None, headers=None):
        self.calls.append(
            {"method": "POST", "path": path, "payload": deepcopy(payload),
             "extra": extra, "headers": headers}
        )
        effect = self.post_effects.get(path)
        if effect is not None:
            effect(payload, extra, headers)
        result = self.post_results.pop(0) if self.post_results else {}
        if isinstance(result, Exception):
            raise result
        return result

    def posts(self):
        return [c for c in self.calls if c["method"] == "POST"]


def policy(operation, *, writes=True, reboot=False, max_calls=16, allow_unverified=False, **kwargs):
    return ops.Policy(
        writes_enabled=writes,
        enabled_operations=frozenset({operation}),
        allowlisted_router_ids=frozenset({RID}),
        reboot_approved=reboot,
        allow_unverified_writes=allow_unverified,
        max_transport_calls=max_calls,
        **kwargs,
    )


def grant(operation, router=RID):
    return ops.CoordinatorGrant("trusted-coordinator", router, frozenset({operation}))


def request(operation, fields, *, band=None, vap=None, oid="op-1", router=RID):
    return ops.OperationRequest(oid, operation, ops.Target(router, band, vap), fields)


def snapshot(data, *, age=0.0, router=RID):
    return ops.Snapshot(router, age, data)


def engine(transport, operation, *, snap, **kwargs):
    return ops.OperationEngine(
        transport, identity=ops.RouterIdentity(RID, "lab"), policy=policy(operation, **kwargs)
    ), snap


class ManifestTests(unittest.TestCase):
    def test_capabilities(self):
        manifest = {entry["operation"]: entry for entry in ops.capability_manifest()}
        self.assertEqual(manifest["wifi.80211r"]["capability"], "available")
        self.assertEqual(manifest["wifi.twt"]["capability"], "available")
        self.assertEqual(manifest["wifi.mac_filter.block"]["capability"], "implemented_unverified")
        self.assertEqual(manifest["wifi.guest.set"]["capability"], "implemented_unverified")
        self.assertEqual(manifest["system.reboot"]["capability"], "implemented_unverified")
        for name in ("wifi.primary.ssid", "wifi.primary.channel", "wifi.primary.wmm",
                     "client.disconnect", "wifi.channel_width", "wifi.transmit_power",
                     "wifi.primary.security", "network.vlan", "system.firmware",
                     "system.factory_reset"):
            self.assertEqual(manifest[name]["capability"], "unsupported", name)

    def test_no_false_unifi_mapping(self):
        for entry in ops.capability_manifest():
            self.assertIsNone(entry["unifi_mapping"])

    def test_default_policy_is_off(self):
        default = ops.default_policy()
        self.assertFalse(default.writes_enabled)
        self.assertEqual(default.enabled_operations, frozenset())


class AuthBoundaryTests(unittest.TestCase):
    def test_grant_router_mismatch(self):
        transport = FakeTransport()
        engine = ops.OperationEngine(transport, identity=ops.RouterIdentity(RID))
        result = engine.execute(
            request("wifi.80211r", {"enabled": True}, vap="1"),
            snapshot({"wlanguide": wlanguide()}),
            grant("wifi.80211r", router=OTHER),
        )
        self.assertEqual(result.outcome, ops.Outcome.REJECTED)
        self.assertEqual(result.reason, "target_not_allowlisted")

    def test_unauthorized_subject(self):
        transport = FakeTransport()
        engine = ops.OperationEngine(
            transport, identity=ops.RouterIdentity(RID), policy=policy("wifi.80211r")
        )
        bad = ops.CoordinatorGrant("", RID, frozenset({"wifi.80211r"}))
        result = engine.execute(
            request("wifi.80211r", {"enabled": True}, vap="1"),
            snapshot({"wlanguide": wlanguide()}), bad,
        )
        self.assertEqual(result.outcome, ops.Outcome.REJECTED)

    def test_operation_not_allowlisted(self):
        transport = FakeTransport()
        engine = ops.OperationEngine(
            transport, identity=ops.RouterIdentity(RID),
            policy=policy("wifi.80211r"),
        )
        result = engine.execute(
            request("wifi.twt", {"enabled": True}, vap="1"),
            snapshot({"wlanguide": wlanguide()}), grant("wifi.80211r"),
        )
        self.assertEqual(result.reason, "operation_not_allowlisted")

    def test_writes_default_off(self):
        transport = FakeTransport()
        engine = ops.OperationEngine(transport, identity=ops.RouterIdentity(RID))
        result = engine.execute(
            request("wifi.80211r", {"enabled": True}, vap="1"),
            snapshot({"wlanguide": wlanguide()}), grant("wifi.80211r"),
        )
        self.assertEqual(result.reason, "writes_disabled")
        self.assertEqual(transport.calls, [])

    def test_unknown_operation(self):
        transport = FakeTransport()
        engine = ops.OperationEngine(
            transport, identity=ops.RouterIdentity(RID), policy=policy("does.not.exist")
        )
        result = engine.execute(
            request("does.not.exist", {}), snapshot({}), grant("does.not.exist")
        )
        self.assertEqual(result.reason, "unknown_operation")

    def test_unsupported_capability(self):
        transport = FakeTransport()
        engine = ops.OperationEngine(
            transport, identity=ops.RouterIdentity(RID), policy=policy("wifi.channel_width")
        )
        result = engine.execute(
            request("wifi.channel_width", {}), snapshot({}), grant("wifi.channel_width")
        )
        self.assertEqual(result.reason, "capability_unsupported")

    def test_unverified_requires_explicit_enable(self):
        transport = FakeTransport()
        engine = ops.OperationEngine(
            transport, identity=ops.RouterIdentity(RID),
            policy=ops.Policy(writes_enabled=True, allowlisted_router_ids=frozenset({RID})),
        )
        result = engine.execute(
            request("wifi.mac_filter.block", {"mac": "aa:bb:cc:dd:ee:ff"}),
            snapshot({"wlan_filter": wlan_filter()}),
            ops.CoordinatorGrant("trusted-coordinator", RID, frozenset({"wifi.mac_filter.block"})),
        )
        self.assertEqual(result.reason, "capability_unverified")


class PreconditionTests(unittest.TestCase):
    def test_stale_snapshot(self):
        transport = FakeTransport()
        engine = ops.OperationEngine(
            transport, identity=ops.RouterIdentity(RID), policy=policy("wifi.80211r")
        )
        result = engine.execute(
            request("wifi.80211r", {"enabled": True}, vap="1"),
            snapshot({"wlanguide": wlanguide()}, age=9999), grant("wifi.80211r"),
        )
        self.assertEqual(result.reason, "stale_snapshot")

    def test_wrong_device_snapshot(self):
        transport = FakeTransport()
        engine = ops.OperationEngine(
            transport, identity=ops.RouterIdentity(RID), policy=policy("wifi.80211r")
        )
        result = engine.execute(
            request("wifi.80211r", {"enabled": True}, vap="1"),
            snapshot({"wlanguide": wlanguide()}, router=OTHER), grant("wifi.80211r"),
        )
        self.assertEqual(result.reason, "target_not_allowlisted")

    def test_ambiguous_vap_binding(self):
        transport = FakeTransport()
        engine = ops.OperationEngine(
            transport, identity=ops.RouterIdentity(RID), policy=policy("wifi.80211r")
        )
        missing = engine.execute(
            request("wifi.80211r", {"enabled": True}, vap=None),
            snapshot({"wlanguide": wlanguide()}), grant("wifi.80211r"),
        )
        self.assertEqual(missing.reason, "invalid_target")
        duplicated = wlanguide(ids=("1", "1"))
        ambiguous = engine.execute(
            request("wifi.80211r", {"enabled": True}, vap="1"),
            snapshot({"wlanguide": duplicated}), grant("wifi.80211r"),
        )
        self.assertEqual(ambiguous.reason, "ambiguous_binding")

    def test_vap_identity_not_ssid(self):
        transport = FakeTransport()
        engine = ops.OperationEngine(
            transport, identity=ops.RouterIdentity(RID), policy=policy("wifi.80211r")
        )
        result = engine.execute(
            request("wifi.80211r", {"enabled": True}, vap="main"),
            snapshot({"wlanguide": wlanguide()}), grant("wifi.80211r"),
        )
        self.assertEqual(result.reason, "ambiguous_binding")

    def test_unknown_field(self):
        transport = FakeTransport()
        broken = {"WifiConfig": [{"ID": "1", "FrequencyBand": "2.4GHz", "WifiSsid": "main"}]}
        engine = ops.OperationEngine(
            transport, identity=ops.RouterIdentity(RID), policy=policy("wifi.80211r")
        )
        result = engine.execute(
            request("wifi.80211r", {"enabled": True}, vap="1"),
            snapshot({"wlanguide": broken}), grant("wifi.80211r"),
        )
        self.assertEqual(result.reason, "unknown_field")


class SwitchOperationTests(unittest.TestCase):
    def _run(self, transport, operation, snapshot_data, fields, action, field_name):
        engine = ops.OperationEngine(
            transport, identity=ops.RouterIdentity(RID), policy=policy(operation)
        )
        return engine, engine.execute(
            request(operation, fields, vap="1"),
            snapshot({"wlanguide": snapshot_data}), grant(operation),
        )

    def test_11r_exact_dto_and_verified(self):
        transport = FakeTransport()
        state = {"wlanguide": wlanguide(dot11r=False)}

        def effect(payload, extra, headers):
            state["wlanguide"]["WifiConfig"][0]["Dot11REnable"] = True

        transport.read_handlers[ops.URL_WLAN_GUIDE] = lambda: deepcopy(state["wlanguide"])
        transport.post_effects[ops.URL_WLAN_GUIDE] = effect
        _, result = self._run(transport, "wifi.80211r", deepcopy(state["wlanguide"]),
                              {"enabled": True}, "11rSetting", "Dot11REnable")
        self.assertEqual(result.outcome, ops.Outcome.VERIFIED_CHANGED)
        post = transport.posts()[-1]
        self.assertEqual(post["path"], ops.URL_WLAN_GUIDE)
        self.assertEqual(post["payload"], {"Dot11REnable": True})
        self.assertEqual(post["extra"], {"action": "11rSetting"})
        self.assertIsNone(post["headers"])

    def test_twt_exact_dto(self):
        transport = FakeTransport()
        transport.read_handlers[ops.URL_WLAN_GUIDE] = lambda: wlanguide(twt=True)
        _, result = self._run(transport, "wifi.twt", wlanguide(), {"enabled": True},
                              "TWTSetting", "TWTEnable")
        self.assertEqual(result.outcome, ops.Outcome.VERIFIED_NOOP)
        self.assertEqual(transport.posts(), [])

    def test_twt_writes(self):
        transport = FakeTransport()
        state = {"wlanguide": wlanguide(twt=False)}

        def effect(payload, extra, headers):
            state["wlanguide"]["WifiConfig"][0]["TWTEnable"] = payload["TWTEnable"]

        transport.read_handlers[ops.URL_WLAN_GUIDE] = lambda: deepcopy(state["wlanguide"])
        transport.post_effects[ops.URL_WLAN_GUIDE] = effect
        _, result = self._run(transport, "wifi.twt", deepcopy(state["wlanguide"]),
                              {"enabled": True}, "TWTSetting", "TWTEnable")
        self.assertEqual(result.outcome, ops.Outcome.VERIFIED_CHANGED)
        self.assertEqual(transport.posts()[-1]["extra"], {"action": "TWTSetting"})

    def test_invalid_enabled_value(self):
        transport = FakeTransport()
        engine = ops.OperationEngine(
            transport, identity=ops.RouterIdentity(RID), policy=policy("wifi.80211r")
        )
        result = engine.execute(
            request("wifi.80211r", {"enabled": "yes"}, vap="1"),
            snapshot({"wlanguide": wlanguide()}), grant("wifi.80211r"),
        )
        self.assertEqual(result.reason, "invalid_payload")


class OutcomeTests(unittest.TestCase):
    def _engine_11r(self, transport, *, max_calls=16):
        return ops.OperationEngine(
            transport, identity=ops.RouterIdentity(RID),
            policy=policy("wifi.80211r", max_calls=max_calls),
        )

    def test_verified_noop_no_write(self):
        transport = FakeTransport()
        transport.read_handlers[ops.URL_WLAN_GUIDE] = lambda: wlanguide(dot11r=True)
        engine = self._engine_11r(transport)
        result = engine.execute(
            request("wifi.80211r", {"enabled": True}, vap="1"),
            snapshot({"wlanguide": wlanguide(dot11r=True)}), grant("wifi.80211r"),
        )
        self.assertEqual(result.outcome, ops.Outcome.VERIFIED_NOOP)
        self.assertEqual(transport.posts(), [])

    def test_readback_mismatch_is_uncertain(self):
        transport = FakeTransport()
        transport.read_handlers[ops.URL_WLAN_GUIDE] = lambda: wlanguide(dot11r=False)
        engine = self._engine_11r(transport)
        result = engine.execute(
            request("wifi.80211r", {"enabled": True}, vap="1"),
            snapshot({"wlanguide": wlanguide()}), grant("wifi.80211r"),
        )
        self.assertEqual(result.outcome, ops.Outcome.UNCERTAIN)
        self.assertEqual(result.reason, "readback_mismatch")

    def test_fault_before_post_is_failed(self):
        transport = FakeTransport()
        transport.read_handlers[ops.URL_WLAN_GUIDE] = lambda: wlanguide()
        transport.post_results.append(ops.TransportError("boom", "pre_send"))
        engine = self._engine_11r(transport)
        result = engine.execute(
            request("wifi.80211r", {"enabled": True}, vap="1"),
            snapshot({"wlanguide": wlanguide()}), grant("wifi.80211r"),
        )
        self.assertEqual(result.outcome, ops.Outcome.FAILED)

    def test_timeout_after_post_is_uncertain_and_not_resent(self):
        transport = FakeTransport()
        transport.read_handlers[ops.URL_WLAN_GUIDE] = lambda: wlanguide()
        transport.post_results.append(ops.TransportError("timeout", "timeout"))
        engine = self._engine_11r(transport)
        first = engine.execute(
            request("wifi.80211r", {"enabled": True}, vap="1", oid="replay-1"),
            snapshot({"wlanguide": wlanguide()}), grant("wifi.80211r"),
        )
        self.assertEqual(first.outcome, ops.Outcome.UNCERTAIN)
        posts_before = len(transport.posts())
        second = engine.execute(
            request("wifi.80211r", {"enabled": True}, vap="1", oid="replay-1"),
            snapshot({"wlanguide": wlanguide()}), grant("wifi.80211r"),
        )
        self.assertEqual(second.outcome, ops.Outcome.UNCERTAIN)
        self.assertEqual(len(transport.posts()), posts_before)

    def test_duplicate_terminal_no_resend(self):
        transport = FakeTransport()
        state = {"wlanguide": wlanguide()}
        transport.read_handlers[ops.URL_WLAN_GUIDE] = lambda: deepcopy(state["wlanguide"])

        def effect(payload, extra, headers):
            state["wlanguide"]["WifiConfig"][0]["Dot11REnable"] = True

        transport.post_effects[ops.URL_WLAN_GUIDE] = effect
        engine = self._engine_11r(transport)
        first = engine.execute(
            request("wifi.80211r", {"enabled": True}, vap="1", oid="once"),
            snapshot({"wlanguide": wlanguide()}), grant("wifi.80211r"),
        )
        self.assertEqual(first.outcome, ops.Outcome.VERIFIED_CHANGED)
        posts_before = len(transport.posts())
        second = engine.execute(
            request("wifi.80211r", {"enabled": True}, vap="1", oid="once"),
            snapshot({"wlanguide": wlanguide()}), grant("wifi.80211r"),
        )
        self.assertEqual(second.reason, "duplicate_terminal")
        self.assertEqual(len(transport.posts()), posts_before)

    def test_replay_conflict(self):
        transport = FakeTransport()
        transport.read_handlers[ops.URL_WLAN_GUIDE] = lambda: wlanguide(dot11r=True)
        engine = self._engine_11r(transport)
        engine.execute(
            request("wifi.80211r", {"enabled": True}, vap="1", oid="conflict"),
            snapshot({"wlanguide": wlanguide(dot11r=True)}), grant("wifi.80211r"),
        )
        result = engine.execute(
            request("wifi.80211r", {"enabled": False}, vap="1", oid="conflict"),
            snapshot({"wlanguide": wlanguide(dot11r=True)}), grant("wifi.80211r"),
        )
        self.assertEqual(result.outcome, ops.Outcome.REJECTED)
        self.assertEqual(result.reason, "replay_conflict")

    def test_budget_is_bounded(self):
        transport = FakeTransport()
        transport.read_handlers[ops.URL_WLAN_GUIDE] = lambda: wlanguide()
        engine = self._engine_11r(transport, max_calls=1)
        result = engine.execute(
            request("wifi.80211r", {"enabled": True}, vap="1"),
            snapshot({"wlanguide": wlanguide()}), grant("wifi.80211r"),
        )
        self.assertEqual(result.outcome, ops.Outcome.FAILED)
        self.assertTrue(result.reason.startswith("budget:"))

    def test_readback_method_reports_fresh_state(self):
        transport = FakeTransport()
        transport.read_handlers[ops.URL_WLAN_GUIDE] = lambda: wlanguide(dot11r=True)
        engine = self._engine_11r(transport)
        plan = engine.plan(
            request("wifi.80211r", {"enabled": True}, vap="1"),
            snapshot({"wlanguide": wlanguide()}), grant("wifi.80211r"),
        )
        result = engine.readback(plan, grant("wifi.80211r"))
        self.assertEqual(result.outcome, ops.Outcome.VERIFIED_CHANGED)


class MacFilterTests(unittest.TestCase):
    MAC = "aa:bb:cc:dd:ee:ff"
    OTHER_MAC = "11:22:33:44:55:66"

    def _engine(self, transport, operation):
        return ops.OperationEngine(
            transport, identity=ops.RouterIdentity(RID), policy=policy(operation)
        )

    def test_block_preserves_existing_and_whole_two_bands(self):
        transport = FakeTransport()
        state = {"f": wlan_filter(mode=0, black_2g=[{"MACAddress": self.OTHER_MAC}])}

        def effect(payload, extra, headers):
            state["f"][0]["BMacAddresses"] = payload["config2g"]["BMacFilters"]
            state["f"][1]["BMacAddresses"] = payload["config5g"]["BMacFilters"]

        transport.read_handlers[ops.URL_WLAN_FILTER] = lambda: deepcopy(state["f"])
        transport.post_effects[ops.URL_WLAN_FILTER] = effect
        engine = self._engine(transport, "wifi.mac_filter.block")
        result = engine.execute(
            request("wifi.mac_filter.block", {"mac": self.MAC, "name": "phone"}),
            snapshot({"wlan_filter": deepcopy(state["f"])}),
            grant("wifi.mac_filter.block"),
        )
        self.assertEqual(result.outcome, ops.Outcome.VERIFIED_CHANGED)
        post = transport.posts()[-1]
        self.assertEqual(post["path"], ops.URL_WLAN_FILTER)
        self.assertEqual(set(post["payload"]), {"config2g", "config5g"})
        for band in ("config2g", "config5g"):
            macs = {i["MACAddress"] for i in post["payload"][band]["BMacFilters"]}
            self.assertIn(self.MAC, macs)
            self.assertTrue(post["payload"][band]["MACAddressControlEnabled"])
            self.assertEqual(post["payload"][band]["MacFilterPolicy"], 0)
        self.assertEqual(
            {i["MACAddress"] for i in post["payload"]["config2g"]["BMacFilters"]},
            {self.MAC, self.OTHER_MAC},
        )

    def test_unblock_removes_only_target(self):
        transport = FakeTransport()
        state = {"f": wlan_filter(
            mode=0, black_2g=[{"MACAddress": self.MAC}, {"MACAddress": self.OTHER_MAC}])}

        def effect(payload, extra, headers):
            state["f"][0]["BMacAddresses"] = payload["config2g"]["BMacFilters"]
            state["f"][1]["BMacAddresses"] = payload["config5g"]["BMacFilters"]

        transport.read_handlers[ops.URL_WLAN_FILTER] = lambda: deepcopy(state["f"])
        transport.post_effects[ops.URL_WLAN_FILTER] = effect
        engine = self._engine(transport, "wifi.mac_filter.unblock")
        result = engine.execute(
            request("wifi.mac_filter.unblock", {"mac": self.MAC}),
            snapshot({"wlan_filter": deepcopy(state["f"])}),
            grant("wifi.mac_filter.unblock"),
        )
        self.assertEqual(result.outcome, ops.Outcome.VERIFIED_CHANGED)
        payload = transport.posts()[-1]["payload"]
        self.assertEqual(
            [i["MACAddress"] for i in payload["config2g"]["BMacFilters"]], [self.OTHER_MAC]
        )
        self.assertEqual(payload["config5g"]["BMacFilters"], [])

    def test_block_rejects_whitelist_mode(self):
        transport = FakeTransport()
        transport.read_handlers[ops.URL_WLAN_FILTER] = lambda: wlan_filter(mode=1)
        engine = self._engine(transport, "wifi.mac_filter.block")
        result = engine.execute(
            request("wifi.mac_filter.block", {"mac": self.MAC}),
            snapshot({"wlan_filter": wlan_filter(mode=1)}),
            grant("wifi.mac_filter.block"),
        )
        self.assertEqual(result.outcome, ops.Outcome.REJECTED)
        self.assertEqual(result.reason, "whitelist_mode_unsupported")

    def test_unblock_in_whitelist_without_entry_is_noop(self):
        transport = FakeTransport()
        transport.read_handlers[ops.URL_WLAN_FILTER] = lambda: wlan_filter(mode=1)
        engine = self._engine(transport, "wifi.mac_filter.unblock")
        result = engine.execute(
            request("wifi.mac_filter.unblock", {"mac": self.MAC}),
            snapshot({"wlan_filter": wlan_filter(mode=1)}),
            grant("wifi.mac_filter.unblock"),
        )
        self.assertEqual(result.outcome, ops.Outcome.VERIFIED_NOOP)
        self.assertEqual(transport.posts(), [])

    def test_block_rejects_when_filtering_disabled(self):
        transport = FakeTransport()
        transport.read_handlers[ops.URL_WLAN_FILTER] = lambda: wlan_filter(enabled=False)
        engine = self._engine(transport, "wifi.mac_filter.block")
        result = engine.execute(
            request("wifi.mac_filter.block", {"mac": self.MAC}),
            snapshot({"wlan_filter": wlan_filter(enabled=False)}),
            grant("wifi.mac_filter.block"),
        )
        self.assertEqual(result.reason, "filtering_disabled")

    def test_invalid_mac_rejected(self):
        transport = FakeTransport()
        transport.read_handlers[ops.URL_WLAN_FILTER] = lambda: wlan_filter()
        engine = self._engine(transport, "wifi.mac_filter.block")
        result = engine.execute(
            request("wifi.mac_filter.block", {"mac": "not-a-mac"}),
            snapshot({"wlan_filter": wlan_filter()}),
            grant("wifi.mac_filter.block"),
        )
        self.assertEqual(result.reason, "invalid_mac")


class GuestNetworkTests(unittest.TestCase):
    def _engine(self, transport):
        return ops.OperationEngine(
            transport, identity=ops.RouterIdentity(RID),
            policy=policy("wifi.guest.set", allow_unverified=True),
        )

    def test_open_ssid_verified(self):
        transport = FakeTransport()
        state = {"g": guest(enabled=False, ssid="GuestOld", sec="tkip")}

        def effect(payload, extra, headers):
            for index, band in ((0, "config2g"), (1, "config5g")):
                cfg = payload[band]
                state["g"][index]["EnableFrequency"] = cfg["Enable"]
                state["g"][index]["WifiSsid"] = cfg["WifiSsid"]
                state["g"][index]["SecOpt"] = cfg["SecOpt"]

        transport.read_handlers[ops.URL_GUEST_NETWORK] = lambda: deepcopy(state["g"])
        transport.post_effects[ops.URL_GUEST_NETWORK] = effect
        engine = self._engine(transport)
        result = engine.execute(
            request("wifi.guest.set", {"enabled": True, "ssid": "GuestNew",
                                       "security": "open", "duration": 3}),
            snapshot({"guest_network": deepcopy(state["g"])}),
            grant("wifi.guest.set"),
        )
        self.assertEqual(result.outcome, ops.Outcome.VERIFIED_CHANGED)
        post = transport.posts()[-1]
        self.assertEqual(post["path"], ops.URL_GUEST_NETWORK)
        self.assertEqual(post["headers"], ops.GUEST_HEADERS)
        self.assertEqual(post["payload"]["config2g"]["SecOpt"], "none")
        self.assertEqual(post["payload"]["config2g"]["WpaPreSharedKey"], "")

    def test_password_is_encrypted_and_applied_unverified(self):
        transport = FakeTransport()
        state = {"g": guest(enabled=False, ssid="GuestOld", sec="tkip")}

        def effect(payload, extra, headers):
            for index, band in ((0, "config2g"), (1, "config5g")):
                cfg = payload[band]
                state["g"][index]["EnableFrequency"] = cfg["Enable"]
                state["g"][index]["WifiSsid"] = cfg["WifiSsid"]
                state["g"][index]["SecOpt"] = cfg["SecOpt"]

        transport.read_handlers[ops.URL_GUEST_NETWORK] = lambda: deepcopy(state["g"])
        transport.post_effects[ops.URL_GUEST_NETWORK] = effect
        engine = self._engine(transport)
        snapshot_data = {"guest_network": deepcopy(state["g"]), "rsa_public_key": RSA_KEY}
        result = engine.execute(
            request("wifi.guest.set", {"enabled": True, "ssid": "GuestNew",
                                       "security": "psk", "password": PLACEHOLDER_PASSWORD}),
            snapshot(snapshot_data), grant("wifi.guest.set"),
        )
        self.assertEqual(result.outcome, ops.Outcome.APPLIED_UNVERIFIED)
        self.assertEqual(result.reason, "password_masked")
        ciphertext = transport.posts()[-1]["payload"]["config2g"]["WpaPreSharedKey"]
        self.assertNotEqual(ciphertext, "")
        self.assertNotIn(PLACEHOLDER_PASSWORD, ciphertext)
        self.assertNotIn(PLACEHOLDER_PASSWORD, json.dumps(result.evidence))

    def test_secrets_not_persisted_in_store(self):
        transport = FakeTransport()
        state = {"g": guest(enabled=True, ssid="Guest", sec="tkip")}
        transport.read_handlers[ops.URL_GUEST_NETWORK] = lambda: deepcopy(state["g"])
        engine = self._engine(transport)
        snapshot_data = {"guest_network": deepcopy(state["g"]), "rsa_public_key": RSA_KEY}
        engine.execute(
            request("wifi.guest.set", {"enabled": True, "ssid": "Guest",
                                       "security": "psk", "password": PLACEHOLDER_PASSWORD}),
            snapshot(snapshot_data), grant("wifi.guest.set"),
        )
        blob = json.dumps(engine.store.as_dict(), default=str)
        self.assertNotIn(PLACEHOLDER_PASSWORD, blob)

    def test_unknown_security_rejected(self):
        transport = FakeTransport()
        transport.read_handlers[ops.URL_GUEST_NETWORK] = lambda: guest()
        engine = self._engine(transport)
        for security in ("wpa3", "enterprise", "vlan", "isolated", None):
            result = engine.execute(
                request("wifi.guest.set", {"enabled": True, "ssid": "G",
                                           "security": security}, oid=f"sec-{security}"),
                snapshot({"guest_network": guest(), "rsa_public_key": RSA_KEY}),
                grant("wifi.guest.set"),
            )
            self.assertEqual(result.reason, "security_unknown", security)

    def test_vlan_operation_unsupported(self):
        transport = FakeTransport()
        engine = ops.OperationEngine(
            transport, identity=ops.RouterIdentity(RID), policy=policy("network.vlan")
        )
        result = engine.execute(
            request("network.vlan", {"vlan": 20}), snapshot({}), grant("network.vlan")
        )
        self.assertEqual(result.reason, "capability_unsupported")

    def test_missing_rsa_key_rejected(self):
        if not _CRYPTO:
            self.skipTest("cryptography backend not installed")
        transport = FakeTransport()
        transport.read_handlers[ops.URL_GUEST_NETWORK] = lambda: guest()
        engine = self._engine(transport)
        result = engine.execute(
            request("wifi.guest.set", {"enabled": True, "ssid": "G",
                                       "security": "psk", "password": PLACEHOLDER_PASSWORD}),
            snapshot({"guest_network": guest()}), grant("wifi.guest.set"),
        )
        self.assertEqual(result.reason, "secret_required")

    def test_password_required_when_secure(self):
        transport = FakeTransport()
        transport.read_handlers[ops.URL_GUEST_NETWORK] = lambda: guest()
        engine = self._engine(transport)
        result = engine.execute(
            request("wifi.guest.set", {"enabled": True, "ssid": "G", "security": "psk"}),
            snapshot({"guest_network": guest(), "rsa_public_key": RSA_KEY}),
            grant("wifi.guest.set"),
        )
        self.assertEqual(result.reason, "secret_required")


class RebootTests(unittest.TestCase):
    def _engine(self, transport, *, approved=True, **kwargs):
        return ops.OperationEngine(
            transport, identity=ops.RouterIdentity(RID),
            policy=policy("system.reboot", reboot=approved, **kwargs),
        )

    def test_transport_error_uses_plain_name(self):
        self.assertEqual(ops.OperationEngine._reason(ops.TransportError("x", "pre_send")), "x")

    def test_requires_approval(self):
        transport = FakeTransport()
        engine = self._engine(transport, approved=False)
        result = engine.execute(
            request("system.reboot", {}), snapshot({}), grant("system.reboot")
        )
        self.assertEqual(result.outcome, ops.Outcome.REJECTED)
        self.assertEqual(result.reason, "destructive_approval_required")
        self.assertEqual(transport.posts(), [])

    def test_http_success_alone_is_uncertain(self):
        transport = FakeTransport()
        transport.read_handlers[ops.URL_DEVICE_INFO] = lambda: {"UpTime": 100}
        engine = self._engine(transport)
        result = engine.execute(
            request("system.reboot", {}), snapshot({}), grant("system.reboot")
        )
        self.assertEqual(result.outcome, ops.Outcome.UNCERTAIN)
        self.assertTrue(result.requires_operator_confirmation)

    def test_observed_down_up_is_verified(self):
        transport = FakeTransport()
        calls = {"n": 0}

        def reader():
            calls["n"] += 1
            if calls["n"] <= 2:
                raise ops.TransportError("offline", "read")
            return {"UpTime": 1}

        transport.read_handlers[ops.URL_DEVICE_INFO] = reader
        engine = self._engine(transport)
        result = engine.execute(
            request("system.reboot", {}), snapshot({}), grant("system.reboot")
        )
        self.assertEqual(result.outcome, ops.Outcome.VERIFIED_CHANGED)
        self.assertEqual(result.reason, "observed_down_up")
        self.assertEqual(transport.posts()[-1]["path"], ops.URL_REBOOT)
        self.assertEqual(transport.posts()[-1]["payload"], {})

    def test_approval_is_one_use(self):
        transport = FakeTransport()
        transport.read_handlers[ops.URL_DEVICE_INFO] = lambda: {"UpTime": 1}
        engine = self._engine(transport)
        engine.execute(
            request("system.reboot", {}, oid="rb-1"), snapshot({}), grant("system.reboot")
        )
        second = engine.execute(
            request("system.reboot", {}, oid="rb-2"), snapshot({}), grant("system.reboot")
        )
        self.assertEqual(second.reason, "destructive_approval_reused")


class RsaTests(unittest.TestCase):
    def test_chunk_size_matches_upstream_constant(self):
        modulus_2048 = "ab" * 256
        self.assertEqual(ops.oaep_chunk_size(modulus_2048), 214)

    def test_invalid_modulus_rejected(self):
        with self.assertRaises(ValueError):
            ops.oaep_chunk_size("zz")
        with self.assertRaises(ValueError):
            ops.oaep_chunk_size("abab")

    @unittest.skipUnless(_CRYPTO, "cryptography backend not installed")
    def test_roundtrip_matches_upstream_pattern(self):
        modulus_hex = format(_NUMBERS.n, "x")
        encoded = ops.rsa_oaep_encode(PLACEHOLDER_PASSWORD, modulus_hex, format(_NUMBERS.e, "x"))
        chunk = ops.oaep_chunk_size(modulus_hex)
        key_bytes = len(modulus_hex) // 2
        self.assertEqual(len(encoded) % (key_bytes * 2), 0)
        raw = bytes.fromhex(encoded)
        plaintext = b""
        for index in range(0, len(raw), key_bytes):
            plaintext += _KEY.decrypt(
                raw[index:index + key_bytes],
                padding.OAEP(mgf=padding.MGF1(hashes.SHA1()), algorithm=hashes.SHA1(), label=None),
            )
        import base64 as _b64

        self.assertEqual(_b64.b64decode(plaintext).decode("utf-8"), PLACEHOLDER_PASSWORD)
        self.assertGreater(chunk, 0)


class HardeningTests(unittest.TestCase):
    def _engine(self, transport, ops_allowed=('wifi.80211r',)):
        return ops.OperationEngine(
            transport, identity=ops.RouterIdentity(RID),
            policy=ops.Policy(writes_enabled=True,
                              enabled_operations=frozenset(ops_allowed),
                              allowlisted_router_ids=frozenset({RID})),
        )

    def test_router_wide_lock_blocks_other_type(self):
        transport = FakeTransport()
        transport.read_handlers[ops.URL_WLAN_GUIDE] = lambda: wlanguide()
        transport.post_results.append(ops.TransportError("timeout", "post_send"))
        engine = self._engine(transport, ("wifi.80211r", "wifi.twt"))
        first = engine.execute(
            request("wifi.80211r", {"enabled": True}, vap="1", oid="a"),
            snapshot({"wlanguide": wlanguide()}), grant("wifi.80211r"))
        self.assertEqual(first.outcome, ops.Outcome.UNCERTAIN)
        second = engine.execute(
            request("wifi.twt", {"enabled": True}, vap="1", oid="b"),
            snapshot({"wlanguide": wlanguide()}), grant("wifi.twt"))
        self.assertEqual(second.outcome, ops.Outcome.REJECTED)
        self.assertEqual(second.reason, "router_operation_locked")
        self.assertEqual(
            second.evidence.get("blocking_operation"), "wifi.80211r")

    def test_rejected_request_does_not_clear_lock(self):
        transport = FakeTransport()
        transport.read_handlers[ops.URL_WLAN_GUIDE] = lambda: wlanguide()
        transport.post_results.append(ops.TransportError("timeout", "post_send"))
        engine = self._engine(transport, ("wifi.80211r", "wifi.twt"))
        engine.execute(request("wifi.80211r", {"enabled": True}, vap="1", oid="a"),
                       snapshot({"wlanguide": wlanguide()}), grant("wifi.80211r"))
        rejected = engine.execute(
            request("wifi.twt", {"enabled": True}, vap=None, oid="c"),
            snapshot({"wlanguide": wlanguide()}), grant("wifi.twt"))
        self.assertEqual(rejected.outcome, ops.Outcome.REJECTED)
        self.assertIsNotNone(engine.store.unresolved_for(RID))

    def test_unresolved_for_router_wide_and_narrow(self):
        store = ops.TransactionStore()
        store.begin(ops.TransactionRecord(
            operation_id="g", operation="wifi.guest.set", payload_hash="p",
            preimage_hash="q", state=ops.Outcome.UNCERTAIN, target={"router_id": RID}))
        self.assertIsNotNone(store.unresolved_for(RID))
        self.assertIsNotNone(store.unresolved_for(RID, "wifi.guest.set"))
        self.assertIsNone(store.unresolved_for(RID, "wifi.twt"))
        self.assertIsNone(store.unresolved_for(OTHER))

    def test_nonfinite_and_future_snapshot_age_rejected(self):
        transport = FakeTransport()
        transport.read_handlers[ops.URL_WLAN_GUIDE] = lambda: wlanguide()
        engine = self._engine(transport)
        for age in (float("nan"), float("inf"), -1.0):
            result = engine.execute(
                request("wifi.80211r", {"enabled": True}, vap="1"),
                snapshot({"wlanguide": wlanguide()}, age=age), grant("wifi.80211r"),
            )
            self.assertEqual(result.reason, "stale_snapshot", age)

    def test_pending_persisted_before_post_still_holds(self):
        transport = FakeTransport()
        state = {"wlanguide": wlanguide()}

        def effect(payload, extra, headers):
            state["wlanguide"]["WifiConfig"][0]["Dot11REnable"] = True

        transport.read_handlers[ops.URL_WLAN_GUIDE] = lambda: deepcopy(state["wlanguide"])
        transport.post_effects[ops.URL_WLAN_GUIDE] = effect
        engine = self._engine(transport)
        result = engine.execute(
            request("wifi.80211r", {"enabled": True}, vap="1", oid="pend"),
            snapshot({"wlanguide": wlanguide()}), grant("wifi.80211r"))
        self.assertEqual(result.outcome, ops.Outcome.VERIFIED_CHANGED)


class PreconditionDriftTests(unittest.TestCase):
    MAC_A = "aa:aa:aa:aa:aa:aa"
    MAC_B = "bb:bb:bb:bb:bb:bb"
    MAC_C = "cc:cc:cc:cc:cc:cc"

    def _engine(self, transport):
        return ops.OperationEngine(
            transport, identity=ops.RouterIdentity(RID),
            policy=ops.Policy(writes_enabled=True,
                              enabled_operations=frozenset({"wifi.mac_filter.block"}),
                              allowlisted_router_ids=frozenset({RID})),
        )

    def test_concurrent_mac_addition_blocks_write(self):
        baseline = wlan_filter(mode=0, black_2g=[{"MACAddress": self.MAC_A}])
        drifted = wlan_filter(mode=0, black_2g=[
            {"MACAddress": self.MAC_A}, {"MACAddress": self.MAC_B}])
        transport = FakeTransport()
        transport.read_handlers[ops.URL_WLAN_FILTER] = lambda: deepcopy(drifted)
        engine = self._engine(transport)
        result = engine.execute(
            request("wifi.mac_filter.block", {"mac": self.MAC_C}),
            snapshot({"wlan_filter": baseline}), grant("wifi.mac_filter.block"))
        self.assertEqual(result.outcome, ops.Outcome.REJECTED)
        self.assertEqual(result.reason, "precondition_changed")
        self.assertEqual(transport.posts(), [])

    def test_unchanged_baseline_proceeds(self):
        baseline = wlan_filter(mode=0, black_2g=[{"MACAddress": self.MAC_A}])
        state = {"f": deepcopy(baseline)}

        def effect(payload, extra, headers):
            state["f"][0]["BMacAddresses"] = payload["config2g"]["BMacFilters"]
            state["f"][1]["BMacAddresses"] = payload["config5g"]["BMacFilters"]

        transport = FakeTransport()
        transport.read_handlers[ops.URL_WLAN_FILTER] = lambda: deepcopy(state["f"])
        transport.post_effects[ops.URL_WLAN_FILTER] = effect
        engine = self._engine(transport)
        result = engine.execute(
            request("wifi.mac_filter.block", {"mac": self.MAC_C}),
            snapshot({"wlan_filter": deepcopy(baseline)}), grant("wifi.mac_filter.block"))
        self.assertEqual(result.outcome, ops.Outcome.VERIFIED_CHANGED)


class ApprovalLedgerTests(unittest.TestCase):
    def test_one_use_binding_and_expiry(self):
        store = ops.TransactionStore()
        self.assertTrue(store.issue_approval("a1", "r1", "system.reboot", 1000.0))
        self.assertFalse(store.issue_approval("a1", "r1", "system.reboot", 1000.0))
        self.assertTrue(store.reserve_approval("a1", "r1", "system.reboot", 500.0))
        self.assertFalse(store.reserve_approval("a1", "r1", "system.reboot", 500.0))
        store.issue_approval("a2", "r1", "system.reboot", 1000.0)
        self.assertFalse(store.reserve_approval("a2", "r2", "system.reboot", 500.0))
        self.assertFalse(store.reserve_approval("a2", "r1", "wifi.twt", 500.0))
        self.assertTrue(store.reserve_approval("a2", "r1", "system.reboot", 500.0))
        store.issue_approval("a3", "r1", "system.reboot", 1000.0)
        self.assertFalse(store.reserve_approval("a3", "r1", "system.reboot", 2000.0))
        self.assertFalse(store.reserve_approval("missing", "r1", "system.reboot", 1.0))

    def test_ledger_error_is_fail_closed_in_engine(self):
        class BrokenStore(ops.TransactionStore):
            def begin(self, record):
                raise ops.LedgerError("ledger_write")

        transport = FakeTransport()
        transport.read_handlers[ops.URL_WLAN_GUIDE] = lambda: wlanguide()
        engine = ops.OperationEngine(
            transport, identity=ops.RouterIdentity(RID),
            policy=ops.Policy(writes_enabled=True,
                              enabled_operations=frozenset({"wifi.80211r"}),
                              allowlisted_router_ids=frozenset({RID})),
            store=BrokenStore(),
        )
        result = engine.execute(
            request("wifi.80211r", {"enabled": True}, vap="1"),
            snapshot({"wlanguide": wlanguide()}), grant("wifi.80211r"))
        self.assertEqual(result.outcome, ops.Outcome.REJECTED)
        self.assertEqual(result.reason, "ledger_invalid")
        self.assertEqual(transport.posts(), [])


class SecretPreconditionTests(unittest.TestCase):
    def _engine(self, transport, *, allow_unverified=True):
        return ops.OperationEngine(
            transport, identity=ops.RouterIdentity(RID),
            policy=ops.Policy(writes_enabled=True,
                              enabled_operations=frozenset({"wifi.guest.set"}),
                              allowlisted_router_ids=frozenset({RID}),
                              allow_unverified_writes=allow_unverified))

    def _request(self):
        return request("wifi.guest.set", {
            "enabled": True, "ssid": "G", "security": "psk",
            "password": PLACEHOLDER_PASSWORD})

    def test_secret_request_blocks_on_observable_drift(self):
        if not _CRYPTO:
            self.skipTest("cryptography backend not installed")
        baseline = guest(enabled=True, ssid="G", sec="tkip")
        drifted = guest(enabled=True, ssid="H", sec="tkip")
        transport = FakeTransport()
        transport.read_handlers[ops.URL_GUEST_NETWORK] = lambda: deepcopy(drifted)
        engine = self._engine(transport)
        result = engine.execute(
            self._request(),
            snapshot({"guest_network": deepcopy(baseline), "rsa_public_key": RSA_KEY}),
            grant("wifi.guest.set"))
        self.assertEqual(result.outcome, ops.Outcome.REJECTED)
        self.assertEqual(result.reason, "precondition_changed")
        self.assertEqual(transport.posts(), [])

    def test_password_on_unchanged_state_is_applied_unverified(self):
        if not _CRYPTO:
            self.skipTest("cryptography backend not installed")
        state = guest(enabled=True, ssid="G", sec="tkip")
        transport = FakeTransport()
        transport.read_handlers[ops.URL_GUEST_NETWORK] = lambda: deepcopy(state)
        engine = self._engine(transport)
        result = engine.execute(
            self._request(),
            snapshot({"guest_network": deepcopy(state), "rsa_public_key": RSA_KEY}),
            grant("wifi.guest.set"))
        self.assertEqual(result.outcome, ops.Outcome.APPLIED_UNVERIFIED)
        self.assertEqual(len(transport.posts()), 1)

    def test_password_blocked_when_unverified_disabled(self):
        if not _CRYPTO:
            self.skipTest("cryptography backend not installed")
        state = guest(enabled=True, ssid="G", sec="tkip")
        transport = FakeTransport()
        transport.read_handlers[ops.URL_GUEST_NETWORK] = lambda: deepcopy(state)
        engine = self._engine(transport, allow_unverified=False)
        result = engine.execute(
            self._request(),
            snapshot({"guest_network": deepcopy(state), "rsa_public_key": RSA_KEY}),
            grant("wifi.guest.set"))
        self.assertEqual(result.reason, "unverified_write_disabled")
        self.assertEqual(transport.posts(), [])


class ReadOnlyTransportTests(unittest.TestCase):
    def test_post_is_refused(self):
        transport = ops.ReadOnlyTransport(lambda path: {})
        with self.assertRaises(ops.TransportError):
            transport.post("api/x", {})


if __name__ == "__main__":
    unittest.main()
