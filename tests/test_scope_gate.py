import base64
import json
import unittest
from datetime import datetime, timedelta, timezone

from secassess.core.hitl import ApprovalQueue
from secassess.core.scope_gate import (ScopeGate, ScopePolicy, ScopeViolation, TimeWindow, build_action,
                                       target_host)
from secassess.models import IntrusiveLevel, RateLimit, ScanRequest


class FakeClock:
    def __init__(self, now=datetime(2026, 3, 4, 10, 0, tzinfo=timezone.utc)):  # 周三
        self.now = now

    def __call__(self):
        return self.now


def policy(**overrides):
    data = dict(project_id="p1", authorization_ref="AUTH-2026-001",
                allowed_cidrs=["192.0.2.0/24", "198.51.100.0/24"], allowed_domains=["*.example.com"],
                excluded=["192.0.2.200", "198.51.100.128/25", "legacy.example.com"],
                valid_from="2026-01-01T00:00:00Z", valid_until="2026-12-31T00:00:00Z")
    data.update(overrides)
    return ScopePolicy(**data)


def action(targets, **overrides):
    kw = dict(project_id="p1", targets=targets, scan_type="port_discovery", adapter="mock-nmap",
              intrusive_level=IntrusiveLevel.SAFE)
    kw.update(overrides)
    return build_action(**kw)


class ScopeGateTest(unittest.TestCase):
    def setUp(self):
        self.clock = FakeClock()
        self.gate = ScopeGate(b"k" * 32, approvals=ApprovalQueue(clock=self.clock), clock=self.clock)
        self.gate.set_policy(policy())

    def authorize(self, act, approval_id=None):
        return self.gate.authorize(act, requested_by="alice", approval_id=approval_id)

    # —— 范围判定 ——
    def test_in_scope_targets_are_allowed_with_token(self):
        for targets in (["192.0.2.10"], ["192.0.2.0/26"], ["www.example.com"], ["https://api.example.com/v1"],
                        ["example.com:443"], ["192.0.2.10:22", "198.51.100.5"]):
            with self.subTest(targets=targets):
                d = self.authorize(action(targets))
                self.assertEqual(d.state, "allowed", d.denials)
                self.assertTrue(d.token)

    def test_any_out_of_scope_target_denies_whole_action(self):
        d = self.authorize(action(["192.0.2.10", "203.0.113.5"]))
        self.assertEqual(d.state, "denied")
        self.assertIsNone(d.token)
        self.assertTrue(any("203.0.113.5" in r for r in d.denials))
        self.assertEqual(self.authorize(action(["evil.com"])).state, "denied")
        self.assertEqual(self.authorize(action(["notexample.com"])).state, "denied")
        # 比授权网段更大的 CIDR 不算在范围内
        self.assertEqual(self.authorize(action(["192.0.0.0/16"])).state, "denied")

    def test_exclusion_takes_priority(self):
        self.assertEqual(self.authorize(action(["192.0.2.200"])).state, "denied")
        self.assertEqual(self.authorize(action(["legacy.example.com"])).state, "denied")
        # CIDR 目标与免扫段只要部分重叠即拒绝
        d = self.authorize(action(["198.51.100.0/24"]))
        self.assertEqual(d.state, "denied")
        self.assertTrue(any("免扫" in r for r in d.denials))
        self.assertEqual(self.authorize(action(["192.0.2.192/28"])).state, "denied")
        self.assertEqual(self.authorize(action(["198.51.100.0/25"])).state, "allowed")

    def test_out_of_scope_can_route_to_hitl_by_policy(self):
        self.gate.set_policy(policy(out_of_scope_action="hitl"))
        d = self.authorize(action(["203.0.113.5"]))
        self.assertEqual(d.state, "pending_approval")
        self.assertEqual(self.authorize(action(["192.0.2.200"])).state, "denied")  # 免扫清单仍硬拒绝

    def test_missing_policy_and_validity_and_roe(self):
        self.assertEqual(self.authorize(action(["192.0.2.1"], project_id="unknown")).state, "denied")
        self.clock.now = datetime(2027, 1, 2, tzinfo=timezone.utc)
        self.assertIn("授权已过期", self.authorize(action(["192.0.2.1"])).denials)
        self.clock.now = datetime(2025, 6, 1, tzinfo=timezone.utc)
        self.assertIn("授权尚未生效", self.authorize(action(["192.0.2.1"])).denials)
        self.clock.now = datetime(2026, 3, 4, 10, 0, tzinfo=timezone.utc)
        self.gate.set_policy(policy(allowed_scan_types=["port_discovery"]))
        self.assertEqual(self.authorize(action(["192.0.2.1"], scan_type="vuln")).state, "denied")

    # —— HITL 触发 ——
    def test_hitl_triggers(self):
        cases = {
            "deep 扫描": action(["192.0.2.1"], options={"profile": "deep"}),
            "侵入式动作": action(["192.0.2.1"], intrusive_level=IntrusiveLevel.INTRUSIVE),
            "对外动作": action(["192.0.2.1"], intrusive_level=IntrusiveLevel.EXTERNAL),
            "超出约定速率": action(["192.0.2.1"], rate_limit=RateLimit(pps=5000)),
        }
        for reason, act in cases.items():
            with self.subTest(reason=reason):
                d = self.authorize(act)
                self.assertEqual(d.state, "pending_approval")
                self.assertIn(reason, d.hitl_reasons)
                self.assertIsNone(d.token)

    def test_hitl_for_fragile_window_and_elevated_credentials(self):
        self.gate.set_policy(policy(fragile_assets=["192.0.2.50"], elevated_credentials=["vault://mem/root"],
                                    windows=[TimeWindow(days=[5, 6], start="22:00", end="06:00")]))
        d = self.authorize(action(["192.0.2.50"], credential_ref="vault://mem/root"))
        self.assertEqual(d.state, "pending_approval")
        self.assertEqual(set(d.hitl_reasons), {"脆弱/OT 资产主动探测: 192.0.2.50", "维护窗口外执行", "使用高权限凭证"})

    def test_time_window_overnight(self):
        w = TimeWindow(days=[0], start="22:00", end="06:00", tz="Asia/Shanghai")
        self.assertTrue(w.contains(datetime(2026, 3, 2, 23, 0, tzinfo=timezone(timedelta(hours=8)))))  # 周一夜
        self.assertTrue(w.contains(datetime(2026, 3, 3, 5, 0, tzinfo=timezone(timedelta(hours=8)))))   # 周二凌晨
        self.assertFalse(w.contains(datetime(2026, 3, 3, 23, 0, tzinfo=timezone(timedelta(hours=8)))))  # 周二夜

    def test_approval_flow_issues_token_once(self):
        act = action(["192.0.2.1"], options={"profile": "deep"})
        pending = self.authorize(act)
        self.gate.approvals.approve(pending.approval_id, "bob")
        allowed = self.authorize(act, approval_id=pending.approval_id)
        self.assertEqual(allowed.state, "allowed")
        self.assertTrue(allowed.token)
        self.assertEqual(self.authorize(act, approval_id=pending.approval_id).state, "denied")  # 不能复用
        other = self.authorize(act)
        self.gate.approvals.approve(other.approval_id, "bob")
        changed = action(["192.0.2.1", "192.0.2.2"], options={"profile": "deep"})
        self.assertEqual(self.authorize(changed, approval_id=other.approval_id).state, "denied")

    # —— 令牌校验 ——
    def _token(self, targets=("192.0.2.1", "192.0.2.2")):
        return self.authorize(action(list(targets))).token

    def _request(self, token, targets=("192.0.2.1",), **kw):
        return ScanRequest(targets=list(targets), scan_type=kw.pop("scan_type", "port_discovery"),
                           scope_token=token, project_id=kw.pop("project_id", "p1"))

    def test_verify_accepts_subset_of_authorized_targets(self):
        claims = self.gate.verify(self._token(), self._request(self._token()))
        self.assertEqual(claims["pid"], "p1")

    def test_verify_rejects_bad_tokens(self):
        token = self._token()
        body, sig = token.rsplit(".", 1)
        claims = json.loads(base64.urlsafe_b64decode(body + "=" * (-len(body) % 4)))
        claims["tg"].append("203.0.113.9")
        forged_body = base64.urlsafe_b64encode(json.dumps(claims, sort_keys=True).encode()).decode().rstrip("=")
        cases = {
            "tampered": (f"{forged_body}.{sig}", {}),
            "garbage": ("not-a-token", {}),
            "other-key": (ScopeGate(b"x" * 32, clock=self.clock).issue_token(action(["192.0.2.1"])), {}),
            "extra-target": (token, {"targets": ("192.0.2.1", "192.0.2.3")}),
            "project": (token, {"project_id": "p2"}),
            "scan-type": (token, {"scan_type": "vuln"}),
        }
        for name, (tok, kw) in cases.items():
            with self.subTest(name), self.assertRaises(ScopeViolation):
                self.gate.verify(tok, self._request(tok, **kw))

    def test_verify_rejects_expired_and_revoked(self):
        token = self._token()
        self.gate.revoke(token)
        with self.assertRaises(ScopeViolation):
            self.gate.verify(token, self._request(token))
        token = self._token()
        self.clock.now += timedelta(hours=2)
        with self.assertRaises(ScopeViolation):
            self.gate.verify(token, self._request(token))

    def test_verify_rechecks_exclusions_and_policy_removal(self):
        token = self._token()
        self.gate.set_policy(policy(excluded=["192.0.2.1"]))
        with self.assertRaises(ScopeViolation):
            self.gate.verify(token, self._request(token))
        self.gate.remove_policy("p1")
        with self.assertRaises(ScopeViolation):
            self.gate.verify(token, self._request(token, targets=("192.0.2.2",)))

    def test_target_host_normalization(self):
        self.assertEqual(target_host("192.0.2.0/24"), "192.0.2.0/24")
        self.assertEqual(target_host("192.0.2.5:8080"), "192.0.2.5")
        self.assertEqual(target_host("https://WWW.Example.com./x"), "www.example.com")
        self.assertEqual(target_host("user@corp.example.com"), "corp.example.com")
        self.assertEqual(target_host("[2001:db8::1]:443"), "2001:db8::1")

    def test_policy_validation(self):
        with self.assertRaises(ValueError):
            policy(authorization_ref="")
        with self.assertRaises(ValueError):
            policy(allowed_cidrs=["not-a-cidr"])
        with self.assertRaises(ValueError):
            policy(out_of_scope_action="allow")
        self.assertEqual(ScopePolicy.from_dict(policy().to_dict()).to_dict(), policy().to_dict())


if __name__ == "__main__":
    unittest.main()
