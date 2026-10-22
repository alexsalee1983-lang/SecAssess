import unittest

from secassess.agents.compliance import ComplianceAgent
from secassess.compliance.frameworks import controls_for_category, known_frameworks
from secassess.compliance.mapper import build_matrix
from secassess.data.asset_graph import AssetGraph
from secassess.data.evidence import EvidenceStore
from secassess.data.facts import FactStore
from secassess.models import Category, FindingSource, FindingStatus, NormalizedFinding, Severity
from secassess.reports.engine import build_report, render_html, render_markdown


def finding(category, title, rule, status=FindingStatus.OPEN, severity=Severity.HIGH):
    return NormalizedFinding(scan_id="s1", project_id="p1", source=FindingSource("a", "e"),
                             target="192.0.2.7:443", category=category, title=title, severity=severity,
                             status=status, details={"rule_id": rule})


class ComplianceMapperTest(unittest.TestCase):
    def setUp(self):
        self.evidence = EvidenceStore()

    def control(self, matrix, framework, cid):
        return next(c for c in matrix.controls if c.framework == framework and c.control_id == cid)

    def test_open_finding_marks_gap(self):
        self.evidence.add_findings([finding(Category.VULNERABILITY, "漏洞 A", "SIM-VULN-1")])
        m = build_matrix(self.evidence, "p1")
        self.assertEqual(self.control(m, "CIS-v8", "7").status, "gap")
        self.assertEqual(self.control(m, "ISO27001-2022", "A.8.8").status, "gap")
        self.assertEqual(self.control(m, "CIS-v8", "4").status, "no_evidence")  # 无 misconfig

    def test_closed_findings_are_covered_not_gap(self):
        self.evidence.add_findings([finding(Category.MISCONFIG, "配置 A", "SIM-CFG-1",
                                            status=FindingStatus.FALSE_POSITIVE)])
        self.evidence.add_findings([finding(Category.VULNERABILITY, "漏洞 B", "SIM-VULN-2",
                                            status=FindingStatus.ACCEPTED)])
        m = build_matrix(self.evidence, "p1")
        self.assertEqual(self.control(m, "CIS-v8", "4").status, "covered")   # misconfig 都是误报
        self.assertEqual(self.control(m, "CIS-v8", "7").status, "covered")   # vuln 已接受

    def test_asset_findings_cover_inventory_not_gap(self):
        facts = FactStore(self.evidence, AssetGraph())
        facts.add_findings([NormalizedFinding(scan_id="s1", project_id="p1", source=FindingSource("nmap", "nmap"),
                                              target="192.0.2.7:22", category=Category.ASSET, title="open 22",
                                              severity=Severity.INFO,
                                              details={"host": "192.0.2.7", "port": 22})])
        m = build_matrix(self.evidence, "p1")
        self.assertEqual(self.control(m, "CIS-v8", "1").status, "covered")  # 资产清单有证据，但资产发现不算 gap

    def test_manual_evidence_covers_control(self):
        m = build_matrix(self.evidence, "p1", manual_evidence={"CIS-v8|14": "已完成年度安全意识培训"})
        c = self.control(m, "CIS-v8", "14")
        self.assertEqual(c.status, "covered")
        self.assertEqual(c.manual_evidence, "已完成年度安全意识培训")

    def test_framework_filter_and_summary(self):
        self.evidence.add_findings([finding(Category.VULNERABILITY, "漏洞", "SIM-VULN-3")])
        m = build_matrix(self.evidence, "p1", frameworks=["CIS-v8"])
        self.assertTrue(all(c.framework == "CIS-v8" for c in m.controls))
        self.assertEqual(sum(m.summary().values()), len(m.controls))

    def test_agent_and_frameworks_helpers(self):
        agent = ComplianceAgent(self.evidence)
        self.assertIn("CIS-v8", known_frameworks())
        self.assertEqual(controls_for_category(Category.MISCONFIG, "CIS-v8"), ["4"])
        self.assertIsNotNone(agent.assess("p1").summary())


class ComplianceReportTest(unittest.TestCase):
    def test_report_includes_matrix(self):
        evidence, graph = EvidenceStore(), AssetGraph()
        evidence.add_findings([finding(Category.VULNERABILITY, "漏洞 X", "SIM-VULN-9")])
        matrix = build_matrix(evidence, "p1").to_dict()
        model = build_report("p1", evidence, graph, compliance=matrix)
        md, html_page = render_markdown(model), render_html(model)
        self.assertIn("## 合规矩阵", md)
        self.assertIn("持续漏洞管理", md)
        self.assertIn("合规矩阵", html_page)
        self.assertIn("c-gap", html_page)


if __name__ == "__main__":
    unittest.main()
