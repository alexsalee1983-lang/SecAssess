import os
import tempfile
import unittest

from secassess.data.asset_graph import AssetGraph
from secassess.data.evidence import EvidenceStore
from secassess.data.facts import FactStore
from secassess.models import Category, FindingSource, NormalizedFinding, Severity


class AssetGraphTest(unittest.TestCase):
    def test_identity_merging(self):
        g = AssetGraph()
        a = g.upsert_node("p1", "asset", "Host.Example.com.", {"criticality": 3})
        b = g.upsert_node("p1", "asset", "https://host.example.com/login", {"owner": "ops"})
        self.assertEqual(a, b)
        self.assertEqual(len(g.nodes("p1", "asset")), 1)
        self.assertEqual(g.get_node(a)["attrs"], {"criticality": 3, "owner": "ops"})
        self.assertNotEqual(a, g.upsert_node("p2", "asset", "host.example.com"))  # 项目隔离

    def test_edges_and_validation(self):
        g = AssetGraph()
        h = g.upsert_node("p1", "asset", "192.0.2.1")
        s = g.upsert_node("p1", "service", "192.0.2.1:22")
        g.add_edge("p1", h, s, "hosts")
        g.add_edge("p1", h, s, "hosts")  # 幂等
        self.assertEqual(g.edges("p1"), [{"src": h, "dst": s, "kind": "hosts", "attrs": {}}])
        with self.assertRaises(ValueError):
            g.upsert_node("p1", "router", "x")
        with self.assertRaises(ValueError):
            g.add_edge("p1", h, s, "owns")

    def test_file_backed_graph_persists(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "graph.db")
            nid = AssetGraph(path).upsert_node("p1", "asset", "192.0.2.1")
            self.assertIsNotNone(AssetGraph(path).get_node(nid))


class FactStoreTest(unittest.TestCase):
    def test_findings_are_attached_to_graph(self):
        graph, evidence = AssetGraph(), EvidenceStore()
        facts = FactStore(evidence, graph)
        src = FindingSource("mock-nmap", "nmap")
        port = NormalizedFinding(scan_id="s1", project_id="p1", source=src, target="192.0.2.7:22",
                                 category=Category.ASSET, title="open 22", severity=Severity.INFO,
                                 details={"host": "192.0.2.7", "port": 22, "protocol": "tcp", "service": "ssh"})
        vuln = NormalizedFinding(scan_id="s2", project_id="p1", source=FindingSource("mock-vuln", "v"),
                                 target="192.0.2.7:22", category=Category.VULNERABILITY, title="SIM",
                                 severity=Severity.HIGH, details={"rule_id": "SIM-VULN-001"})
        stored = facts.add_findings([port, vuln])
        services = graph.nodes("p1", "service")
        assets = graph.nodes("p1", "asset")
        self.assertEqual([n["key"] for n in services], ["192.0.2.7:22"])
        self.assertEqual(services[0]["attrs"]["service"], "ssh")
        self.assertEqual([n["key"] for n in assets], ["192.0.2.7"])
        self.assertEqual(stored[0].asset_ref, services[0]["id"])
        self.assertEqual(stored[1].asset_ref, assets[0]["id"])
        self.assertEqual(graph.edges("p1", "hosts")[0]["dst"], services[0]["id"])
        self.assertEqual(len(facts.findings_for_scan("s1")), 1)


if __name__ == "__main__":
    unittest.main()
