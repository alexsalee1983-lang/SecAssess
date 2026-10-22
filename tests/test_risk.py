import unittest

from secassess.core.risk import RiskScorer, ThreatIntel
from secassess.data.asset_graph import AssetGraph
from secassess.data.evidence import EvidenceStore
from secassess.data.facts import FactStore
from secassess.inputs.threat_intel import load_threat_intel
from secassess.models import Category, Confidence, FindingSource, NormalizedFinding, Severity


def finding(**kw):
    data = dict(scan_id="s1", project_id="p1", source=FindingSource("a", "e"), target="192.0.2.7:443",
                category=Category.VULNERABILITY, title="x", severity=Severity.HIGH, confidence=Confidence.FIRM)
    data.update(kw)
    return NormalizedFinding(**data)


class RiskScorerTest(unittest.TestCase):
    def setUp(self):
        self.scorer = RiskScorer()

    def test_bounds_and_asset_zero(self):
        self.assertEqual(self.scorer.score(finding(category=Category.ASSET, severity=Severity.INFO)), 0.0)
        s = self.scorer.score(finding(severity=Severity.CRITICAL), criticality=5, internet_facing=True)
        self.assertLessEqual(s, 100.0)
        self.assertGreater(s, 0)

    def test_monotonic_in_severity(self):
        lo = self.scorer.score(finding(severity=Severity.LOW))
        hi = self.scorer.score(finding(severity=Severity.CRITICAL))
        self.assertGreater(hi, lo)

    def test_monotonic_in_criticality_and_exposure(self):
        base = self.scorer.score(finding(), criticality=1)
        self.assertGreater(self.scorer.score(finding(), criticality=5), base)
        self.assertGreater(self.scorer.score(finding(), internet_facing=True), base)

    def test_confidence_lowers_score(self):
        firm = self.scorer.score(finding(confidence=Confidence.FIRM))
        tentative = self.scorer.score(finding(confidence=Confidence.TENTATIVE))
        self.assertGreater(firm, tentative)

    def test_threat_intel_raises_score(self):
        intel = ThreatIntel(kev={"CVE-2021-44228"}, epss={"CVE-2021-44228": 1.0})
        scorer = RiskScorer(intel)
        plain = scorer.score(finding(severity=Severity.MEDIUM))
        known = scorer.score(finding(severity=Severity.MEDIUM, cve=["CVE-2021-44228"]))
        self.assertGreater(known, plain + 25)

    def test_priority_buckets(self):
        self.assertEqual(RiskScorer.priority(80), "P1")
        self.assertEqual(RiskScorer.priority(60), "P2")
        self.assertEqual(RiskScorer.priority(30), "P3")
        self.assertEqual(RiskScorer.priority(10), "P4")

    def test_load_threat_intel(self):
        intel = load_threat_intel({"kev": ["cve-2021-44228"], "epss": {"cve-2021-44228": 0.9}})
        self.assertIn("CVE-2021-44228", intel.kev)
        self.assertEqual(intel.epss["CVE-2021-44228"], 0.9)


class FactStoreScoringTest(unittest.TestCase):
    def test_findings_get_scored_and_sorted(self):
        graph = AssetGraph()
        graph.upsert_node("p1", "asset", "192.0.2.7", {"criticality": 5, "internet_facing": True})
        facts = FactStore(EvidenceStore(), graph, RiskScorer(ThreatIntel(kev={"CVE-2000-1"})))
        facts.add_findings([
            finding(title="low issue", severity=Severity.LOW, details={"rule_id": "R1"}),
            finding(title="kev crit", severity=Severity.CRITICAL, cve=["CVE-2000-1"], details={"rule_id": "R2"}),
        ])
        rows = facts.evidence.query("p1")
        self.assertTrue(all(f.risk_score is not None for f in rows))
        self.assertEqual(rows[0].title, "kev crit")  # 最高风险排最前
        self.assertGreater(rows[0].risk_score, rows[1].risk_score)


if __name__ == "__main__":
    unittest.main()
