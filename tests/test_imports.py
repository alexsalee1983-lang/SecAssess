import os
import tempfile
import unittest

from secassess.core.scope_gate import ScopePolicy
from secassess.data.asset_graph import AssetGraph
from secassess.data.evidence import EvidenceStore
from secassess.data.facts import FactStore
from secassess.inputs.importers import (ImportError_, import_cmdb, import_nessus, import_passive)
from secassess.models import Category, Channel, FindingSource, NormalizedFinding, Severity

POLICY = ScopePolicy(project_id="p1", authorization_ref="A", allowed_cidrs=["192.0.2.0/24"])

NESSUS = """<?xml version="1.0"?>
<NessusClientData_v2><Report name="r">
  <ReportHost name="192.0.2.7">
    <ReportItem port="443" severity="3" pluginID="12345" pluginName="TLS 过期证书">
      <cve>CVE-2020-1234</cve>
    </ReportItem>
    <ReportItem port="22" severity="2" pluginID="22222" pluginName="SSH 弱算法"/>
  </ReportHost>
  <ReportHost name="203.0.113.9">
    <ReportItem port="80" severity="4" pluginID="33333" pluginName="越界主机的发现"/>
  </ReportHost>
</Report></NessusClientData_v2>"""

XXE = """<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<NessusClientData_v2><Report><ReportHost name="192.0.2.7"/></Report></NessusClientData_v2>"""


class ImportTest(unittest.TestCase):
    def setUp(self):
        self.evidence, self.graph = EvidenceStore(), AssetGraph()
        self.facts = FactStore(self.evidence, self.graph)

    def test_cmdb_sets_asset_attrs_and_filters_scope(self):
        rows = [{"host": "192.0.2.10", "criticality": "5", "owner": "ops", "internet_facing": "true"},
                {"host": "203.0.113.5", "criticality": "3"}]
        result = import_cmdb(self.facts, "p1", rows, policy=POLICY)
        self.assertEqual(result.imported, 1)
        self.assertEqual(result.skipped, [{"value": "203.0.113.5", "reason": "out_of_scope"}])
        node = self.graph.nodes("p1", "asset")[0]
        self.assertEqual(node["attrs"]["criticality"], 5)
        self.assertEqual(node["attrs"]["owner"], "ops")
        self.assertTrue(node["attrs"]["internet_facing"])

    def test_passive_discovers_assets(self):
        rows = [{"host": "192.0.2.20", "source": "dns", "port": "53", "service": "dns"},
                {"host": "203.0.113.1", "source": "netflow"}]
        result = import_passive(self.facts, "p1", rows, policy=POLICY)
        self.assertEqual(result.imported, 1)
        f = self.evidence.query("p1")[0]
        self.assertIs(f.source.channel, Channel.PASSIVE)
        self.assertEqual(len(result.skipped), 1)

    def test_nessus_import_channel_and_merge(self):
        # 先有一条主动扫描的同问题（同 host:port + 同 rule_id）
        self.facts.add_findings([NormalizedFinding(
            scan_id="active", project_id="p1", source=FindingSource("nuclei", "nuclei"),
            target="192.0.2.7:443", category=Category.VULNERABILITY, title="TLS 过期证书",
            severity=Severity.MEDIUM, details={"rule_id": "nessus-12345", "port": 443})])
        result = import_nessus(self.facts, "p1", NESSUS, policy=POLICY)
        self.assertEqual(result.skipped, [{"value": "203.0.113.9", "reason": "out_of_scope"}])
        merged = self.evidence.query("p1", target="192.0.2.7:443")[0]
        channels = {s.channel for s in merged.sources}
        self.assertIn(Channel.IMPORT, channels)
        self.assertIn(Channel.ACTIVE_SCAN, channels)
        self.assertIs(merged.severity, Severity.HIGH)  # 取较高严重性
        self.assertIn("CVE-2020-1234", merged.cve)

    def test_nessus_rejects_xxe(self):
        with self.assertRaises(ImportError_):
            import_nessus(self.facts, "p1", XXE, policy=POLICY)

    def test_import_from_csv_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "cmdb.csv")
            with open(path, "w", encoding="utf-8") as fh:
                fh.write("host,criticality\n192.0.2.30,4\n")
            result = import_cmdb(self.facts, "p1", path, policy=POLICY)
            self.assertEqual(result.imported, 1)


if __name__ == "__main__":
    unittest.main()
