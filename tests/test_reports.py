import os
import tempfile
import unittest

from secassess.core.scope_gate import ScopePolicy
from secassess.data.asset_graph import AssetGraph
from secassess.data.evidence import EvidenceStore
from secassess.data.facts import FactStore
from secassess.models import Category, FindingSource, FindingStatus, NormalizedFinding, Severity
from secassess.reports.engine import build_report, render_docx, render_html, render_markdown

try:
    import docx  # noqa: F401
    HAS_DOCX = True
except ImportError:
    HAS_DOCX = False


def seed():
    evidence, graph = EvidenceStore(), AssetGraph()
    facts = FactStore(evidence, graph)
    raw = evidence.put_raw("p1", "raw tool output")
    facts.add_findings([
        NormalizedFinding(scan_id="s1", project_id="p1", source=FindingSource("mock-nmap", "nmap"),
                          target="192.0.2.7:22", category=Category.ASSET, title="open 22", severity=Severity.INFO,
                          details={"host": "192.0.2.7", "port": 22, "service": "ssh"}),
        NormalizedFinding(scan_id="s2", project_id="p1", source=FindingSource("fake-mcp", "engine-x", "1.2"),
                          target="192.0.2.7:22", category=Category.VULNERABILITY,
                          title="<script>alert(1)</script> SIM-VULN-001", severity=Severity.HIGH,
                          raw_ref=raw, remediation="升级组件 | 关闭端口", details={"rule_id": "SIM-VULN-001"}),
        NormalizedFinding(scan_id="s3", project_id="p1", source=FindingSource("mock-cfg", "cfg"),
                          target="192.0.2.7", category=Category.MISCONFIG, title="SIM-CFG-002",
                          severity=Severity.LOW, details={"rule_id": "SIM-CFG-002"}),
    ])
    fp = facts.add_findings([NormalizedFinding(
        scan_id="s3", project_id="p1", source=FindingSource("mock-cfg", "cfg"), target="192.0.2.7",
        category=Category.MISCONFIG, title="SIM-CFG-003", severity=Severity.MEDIUM,
        details={"rule_id": "SIM-CFG-003"})])[0]
    fp.status = FindingStatus.FALSE_POSITIVE
    evidence.update(fp)
    policy = ScopePolicy(project_id="p1", authorization_ref="AUTH-2026-007", allowed_cidrs=["192.0.2.0/24"])
    return build_report("p1", evidence, graph, policy), raw


class ReportTest(unittest.TestCase):
    def test_model_counts(self):
        report, _ = seed()
        self.assertEqual(len(report.assets), 1)
        self.assertEqual(len(report.findings), 2)  # 资产发现与误报不计入问题
        self.assertEqual(report.severity_counts["high"], 1)
        self.assertEqual(report.severity_counts["medium"], 0)

    def test_markdown_contents(self):
        report, raw = seed()
        md = render_markdown(report)
        for expected in ("p1", "AUTH-2026-007", "资产数：1", "| high | 1 |", "192.0.2.7", "SIM-CFG-002",
                         "active_scan → fake-mcp/engine-x@1.2", f"原始证据 {raw}", "资产节点 asset:192.0.2.7",
                         "升级组件 \\| 关闭端口"):
            self.assertIn(expected, md)

    def test_html_escapes_untrusted_text(self):
        report, _ = seed()
        page = render_html(report)
        self.assertNotIn("<script>alert(1)</script>", page)
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", page)
        self.assertIn("AUTH-2026-007", page)
        self.assertIn("资产节点 asset:192.0.2.7", page)

    @unittest.skipUnless(HAS_DOCX, "python-docx 未安装")
    def test_docx_roundtrip(self):
        import docx
        report, _ = seed()
        with tempfile.TemporaryDirectory() as tmp:
            path = render_docx(report, os.path.join(tmp, "report.docx"))
            text = "\n".join(p.text for p in docx.Document(path).paragraphs)
            self.assertIn("AUTH-2026-007", text)
            self.assertIn("SIM-CFG-002", text)


if __name__ == "__main__":
    unittest.main()
