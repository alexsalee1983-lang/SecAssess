import unittest

from secassess.core.metrics import MetricsRegistry, collect
from secassess.data.asset_graph import AssetGraph
from secassess.data.evidence import EvidenceStore
from secassess.data.facts import FactStore
from secassess.models import Category, FindingSource, NormalizedFinding, Severity


class _Jobs:
    def list(self, pid=None):
        rows = [{"project_id": "p1", "state": "done"}, {"project_id": "p1", "state": "failed"},
                {"project_id": "p2", "state": "done"}]
        return [r for r in rows if pid in (None, r["project_id"])]


class _Approvals:
    def list(self, pid):
        return []


class _Gate:
    def __init__(self):
        self.approvals = _Approvals()


class _Tickets:
    def list(self, pid):
        return []


class _Registry:
    def describe(self):
        return [{"available": True}, {"available": False}]


class _Audit:
    def verify_chain(self):
        return True


class Stub:
    def __init__(self, evidence):
        self.evidence = evidence
        self.jobs = _Jobs()
        self.gate = _Gate()
        self.tickets = _Tickets()
        self.registry = _Registry()
        self.audit = _Audit()
        self.metrics = MetricsRegistry()


class MetricsTest(unittest.TestCase):
    def setUp(self):
        self.evidence = EvidenceStore()
        FactStore(self.evidence, AssetGraph()).add_findings([
            NormalizedFinding(scan_id="s", project_id="p1", source=FindingSource("a", "e"),
                              target="192.0.2.1:443", category=Category.VULNERABILITY, title="v",
                              severity=Severity.CRITICAL, details={"rule_id": "R1"}),
            NormalizedFinding(scan_id="s", project_id="p1", source=FindingSource("a", "e"),
                              target="192.0.2.2:80", category=Category.MISCONFIG, title="m",
                              severity=Severity.LOW, details={"rule_id": "R2"})])
        self.platform = Stub(self.evidence)

    def test_registry_counter(self):
        reg = MetricsRegistry()
        reg.incr("scan.submitted")
        reg.incr("scan.submitted", 2)
        self.assertEqual(reg.snapshot()["scan.submitted"], 3)

    def test_collect_single_project(self):
        m = collect(self.platform, ["p1"], single="p1")
        self.assertEqual(m["findings"]["total"], 2)
        self.assertEqual(m["findings"]["by_severity"]["critical"], 1)
        self.assertEqual(m["jobs"]["by_state"], {"done": 1, "failed": 1})
        self.assertEqual(m["adapters_available"], 1)
        self.assertTrue(m["audit_chain_valid"])

    def test_collect_multi_project_filters_jobs(self):
        m = collect(self.platform, ["p1"])  # 不含 p2 的 job
        self.assertEqual(m["jobs"]["total"], 2)


if __name__ == "__main__":
    unittest.main()
