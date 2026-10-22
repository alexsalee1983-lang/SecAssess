import unittest
from datetime import datetime, timedelta, timezone

from secassess.core.ctem import CTEMEngine, TriggerKind
from secassess.core.scope_gate import ScopeGate, ScopePolicy, build_action


class Clock:
    def __init__(self):
        self.now = datetime(2026, 6, 1, tzinfo=timezone.utc)

    def __call__(self):
        return self.now

    def tick(self, **kw):
        self.now += timedelta(**kw)


class CTEMTest(unittest.TestCase):
    def setUp(self):
        self.clock = Clock()
        self.engine = CTEMEngine(project_id="p1", cooldown=timedelta(hours=6), period=timedelta(days=7),
                                 clock=self.clock)

    def test_all_trigger_kinds(self):
        self.assertEqual(self.engine.on_new_assets(["192.0.2.1"])[0].kind, TriggerKind.NEW_ASSET)
        self.assertEqual(self.engine.on_config_drift(["192.0.2.2"])[0].kind, TriggerKind.CONFIG_DRIFT)
        self.assertEqual(self.engine.on_new_intel(["192.0.2.3"], "CVE-2024-1")[0].kind, TriggerKind.NEW_INTEL)
        periodic = self.engine.tick(["192.0.2.4"])
        self.assertEqual(periodic[0].kind, TriggerKind.PERIODIC)

    def test_cooldown_prevents_repeat(self):
        first = self.engine.on_config_drift(["192.0.2.1"])
        self.assertEqual(len(first), 1)
        self.assertEqual(self.engine.on_config_drift(["192.0.2.1"]), [])  # 冷却期内
        self.clock.tick(hours=7)
        again = self.engine.on_config_drift(["192.0.2.1"])
        self.assertEqual(len(again), 1)

    def test_periodic_respects_period(self):
        self.assertTrue(self.engine.tick(["192.0.2.1"]))     # 首次
        self.clock.tick(days=1)
        self.assertEqual(self.engine.tick(["192.0.2.1"]), [])  # 未到周期（且冷却）
        self.clock.tick(days=7)
        self.assertTrue(self.engine.tick(["192.0.2.9"]))     # 到期，新目标

    def test_reassess_requests_still_pass_through_scope_gate(self):
        gate = ScopeGate(b"k" * 32)
        gate.set_policy(ScopePolicy(project_id="p1", authorization_ref="A", allowed_cidrs=["192.0.2.0/24"]))
        req = self.engine.on_new_assets(["203.0.113.5"])[0]  # 越界新资产
        action = build_action(project_id="p1", targets=req.targets, scan_type="port_discovery",
                              adapter="mock-nmap", intrusive_level="safe")
        decision = gate.authorize(action, requested_by="system")
        self.assertEqual(decision.state, "denied")  # 持续触发不绕过授权


if __name__ == "__main__":
    unittest.main()
