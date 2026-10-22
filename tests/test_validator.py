import unittest

from secassess.core.validator import ExploitabilityValidator, Hypothesis
from secassess.data.asset_graph import AssetGraph
from secassess.data.evidence import EvidenceStore
from secassess.data.facts import FactStore
from secassess.models import Category, Confidence, FindingSource, NormalizedFinding, Severity


def vuln(version=None, **extra):
    details = {"rule_id": "V1"}
    if version:
        details["version"] = version
    details.update(extra)
    return NormalizedFinding(scan_id="s", project_id="p1", source=FindingSource("a", "e"),
                             target="192.0.2.7:22", category=Category.VULNERABILITY, title="SSH 漏洞",
                             severity=Severity.HIGH, confidence=Confidence.TENTATIVE, details=details)


class ValidatorTest(unittest.TestCase):
    def setUp(self):
        self.evidence = EvidenceStore()
        self.facts = FactStore(self.evidence, AssetGraph())
        self.validator = ExploitabilityValidator(self.evidence)

    def store(self, finding):
        return self.facts.add_findings([finding])[0]

    def test_intrusive_requires_hitl(self):
        f = self.store(vuln(version="7.4"))
        r = self.validator.validate(Hypothesis(f.finding_id, "version_range", {"fixed_version": "7.8"},
                                               intrusive=True))
        self.assertEqual(r.verdict, "needs_hitl")
        self.assertIs(self.evidence.get(f.finding_id).confidence, Confidence.TENTATIVE)  # 未提升

    def test_version_range_confirms_and_writes_back(self):
        f = self.store(vuln(version="OpenSSH 7.4"))
        r = self.validator.validate(Hypothesis(f.finding_id, "version_range", {"fixed_version": "7.8"}))
        self.assertEqual(r.verdict, "confirmed")
        self.assertIsNotNone(r.evidence_ref)
        updated = self.evidence.get(f.finding_id)
        self.assertIs(updated.confidence, Confidence.CONFIRMED)
        self.assertEqual(updated.details["validated"]["method"], "deterministic")

    def test_version_not_in_range_does_not_promote(self):
        f = self.store(vuln(version="8.0"))
        r = self.validator.validate(Hypothesis(f.finding_id, "version_range", {"fixed_version": "7.8"}))
        self.assertEqual(r.verdict, "not_confirmed")
        self.assertIs(self.evidence.get(f.finding_id).confidence, Confidence.TENTATIVE)

    def test_reachability_uses_fact_source_only(self):
        # 事实源中有该服务开放端口的证据
        self.facts.add_findings([NormalizedFinding(
            scan_id="s", project_id="p1", source=FindingSource("nmap", "nmap"), target="192.0.2.7:22",
            category=Category.ASSET, title="open 22", severity=Severity.INFO,
            details={"host": "192.0.2.7", "port": 22, "state": "open"})])
        f = self.store(vuln())
        r = self.validator.validate(Hypothesis(f.finding_id, "service_reachable", {"port": 22}))
        self.assertEqual(r.verdict, "confirmed")
        # 没有端口证据的服务
        f2 = self.store(vuln(host="192.0.2.8"))
        f2.target = "192.0.2.8:22"
        self.evidence.update(f2)
        r2 = self.validator.validate(Hypothesis(f2.finding_id, "service_reachable", {"port": 9999}))
        self.assertEqual(r2.verdict, "not_confirmed")

    def test_unknown_finding_and_kind(self):
        self.assertEqual(self.validator.validate(Hypothesis("fnd_missing", "version_range", {})).verdict, "error")
        f = self.store(vuln(version="1.0"))
        self.assertEqual(self.validator.validate(Hypothesis(f.finding_id, "magic", {})).verdict, "error")


if __name__ == "__main__":
    unittest.main()
