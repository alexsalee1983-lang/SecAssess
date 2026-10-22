import unittest
from datetime import datetime, timedelta, timezone

from secassess.core.lifecycle import LifecycleError, LifecycleManager
from secassess.data.evidence import EvidenceStore
from secassess.inputs.scope_loader import Readiness
from secassess.models import Category, Confidence, FindingSource, FindingStatus, NormalizedFinding, Severity


class Clock:
    def __init__(self):
        self.now = datetime(2026, 5, 1, tzinfo=timezone.utc)

    def __call__(self):
        return self.now

    def tick(self, **kw):
        self.now += timedelta(**kw)


def vuln(target, rule, collected_at, status=FindingStatus.OPEN):
    return NormalizedFinding(scan_id="s", project_id="p1", source=FindingSource("a", "e"), target=target,
                             category=Category.VULNERABILITY, title=rule, severity=Severity.HIGH,
                             confidence=Confidence.FIRM, status=status, collected_at=collected_at,
                             details={"rule_id": rule})


class LifecycleTest(unittest.TestCase):
    def setUp(self):
        self.clock = Clock()
        self.evidence = EvidenceStore()
        self.mgr = LifecycleManager(self.evidence, clock=self.clock)
        self.a = self.mgr.create("p1")

    def test_valid_and_invalid_transitions(self):
        ready = Readiness(ready=True)
        self.mgr.transition(self.a.assessment_id, "scoped")
        self.mgr.transition(self.a.assessment_id, "active", readiness=ready)
        self.mgr.transition(self.a.assessment_id, "review")
        self.assertEqual(self.a.state, "review")
        with self.assertRaises(LifecycleError):
            self.mgr.transition(self.a.assessment_id, "closed")  # review 不能直接 closed

    def test_active_requires_readiness(self):
        self.mgr.transition(self.a.assessment_id, "scoped")
        with self.assertRaises(LifecycleError):
            self.mgr.transition(self.a.assessment_id, "active", readiness=Readiness(ready=False, missing=["①"]))
        with self.assertRaises(LifecycleError):
            self.mgr.transition(self.a.assessment_id, "active")  # 未提供就绪检查

    def _to_reported(self):
        ready = Readiness(ready=True)
        for state, kw in (("scoped", {}), ("active", {"readiness": ready}), ("review", {}), ("reported", {})):
            self.mgr.transition(self.a.assessment_id, state, **kw)

    def test_retest_closes_fixed_regresses_reappeared_keeps_untouched(self):
        t0 = self.clock.now
        self.evidence.add_findings([vuln("192.0.2.1:80", "FIXED", t0),      # 覆盖且不再出现 → 修复
                                    vuln("192.0.2.1:443", "STILL", t0),     # 覆盖且仍出现
                                    vuln("192.0.2.9:80", "OTHER", t0)])     # 未覆盖 → 不变
        self._to_reported()
        self.clock.tick(days=7)
        self.mgr.begin_retest(self.a.assessment_id)
        self.clock.tick(minutes=1)
        # 复测重新扫描覆盖目标：STILL 再次出现（last_seen 更新），FIXED 未出现
        self.evidence.add_findings([vuln("192.0.2.1:443", "STILL", self.clock.now)])
        stats = self.mgr.conclude_retest(self.a.assessment_id, ["192.0.2.1:80", "192.0.2.1:443"])
        self.assertEqual(len(stats["verified_fixed"]), 1)
        self.assertEqual(stats["untouched_count"], 1)
        statuses = {f.title: f.status for f in self.evidence.query("p1")}
        self.assertIs(statuses["FIXED"], FindingStatus.VERIFIED_FIXED)
        self.assertIs(statuses["STILL"], FindingStatus.OPEN)
        self.assertIs(statuses["OTHER"], FindingStatus.OPEN)

    def test_regression_detected_on_second_retest(self):
        t0 = self.clock.now
        self.evidence.add_findings([vuln("192.0.2.1:80", "X", t0)])
        self._to_reported()
        self.clock.tick(days=1)
        self.mgr.begin_retest(self.a.assessment_id)
        self.clock.tick(minutes=1)
        self.mgr.conclude_retest(self.a.assessment_id, ["192.0.2.1:80"])  # 未再出现 → verified_fixed
        self.assertIs(self.evidence.query("p1")[0].status, FindingStatus.VERIFIED_FIXED)
        # 第二次复测，问题又出现了
        self.clock.tick(days=30)
        self.mgr.begin_retest(self.a.assessment_id)
        self.clock.tick(minutes=1)
        self.evidence.add_findings([vuln("192.0.2.1:80", "X", self.clock.now)])
        stats = self.mgr.conclude_retest(self.a.assessment_id, ["192.0.2.1:80"])
        self.assertEqual(len(stats["regressed"]), 1)
        f = self.evidence.query("p1")[0]
        self.assertIs(f.status, FindingStatus.OPEN)
        self.assertTrue(f.details.get("regressed"))

    def test_retest_requires_begin(self):
        self._to_reported()
        with self.assertRaises(LifecycleError):
            self.mgr.conclude_retest(self.a.assessment_id, ["192.0.2.1:80"])


if __name__ == "__main__":
    unittest.main()
