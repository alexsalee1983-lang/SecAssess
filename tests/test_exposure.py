import unittest

from secassess.core.exposure import add_exploit_edges, attack_paths, choke_points
from secassess.data.asset_graph import AssetGraph
from secassess.data.evidence import EvidenceStore
from secassess.data.facts import FactStore
from secassess.models import Category, Confidence, FindingSource, NormalizedFinding, Severity


class ExposureTest(unittest.TestCase):
    def setUp(self):
        self.g = AssetGraph()
        # entry → a → b → jewel，另有一条更长的旁路 entry → c → jewel
        self.nodes = {k: self.g.upsert_node("p1", "asset", k) for k in ("entry", "a", "b", "jewel", "c")}
        self.g.add_edge("p1", self.nodes["entry"], self.nodes["a"], "reachable_to")
        self.g.add_edge("p1", self.nodes["a"], self.nodes["b"], "reachable_to")
        self.g.add_edge("p1", self.nodes["b"], self.nodes["jewel"], "has_privilege")
        self.g.add_edge("p1", self.nodes["entry"], self.nodes["c"], "trusts")
        self.g.add_edge("p1", self.nodes["c"], self.nodes["jewel"], "reachable_to")

    def test_shortest_path_by_weight(self):
        paths = attack_paths(self.g, "p1", [self.nodes["entry"]], [self.nodes["jewel"]])
        self.assertEqual(len(paths), 1)
        best = paths[0]
        # entry→a→b→jewel = 1.0+1.0+0.5 = 2.5；entry→c→jewel = 0.8+1.0 = 1.8 → 选旁路
        self.assertEqual(best["nodes"], [self.nodes["entry"], self.nodes["c"], self.nodes["jewel"]])
        self.assertAlmostEqual(best["cost"], 1.8)

    def test_no_path_and_unknown_nodes(self):
        isolated = self.g.upsert_node("p1", "asset", "island")
        self.assertEqual(attack_paths(self.g, "p1", [isolated], [self.nodes["jewel"]]), [])
        self.assertEqual(attack_paths(self.g, "p1", ["asset:doesnotexist"], [self.nodes["jewel"]]), [])

    def test_choke_points_ranking(self):
        # 两个入口都必须经过 b 到达 jewel（移除旁路）
        g = AssetGraph()
        n = {k: g.upsert_node("p1", "asset", k) for k in ("e1", "e2", "b", "jewel")}
        g.add_edge("p1", n["e1"], n["b"], "reachable_to")
        g.add_edge("p1", n["e2"], n["b"], "reachable_to")
        g.add_edge("p1", n["b"], n["jewel"], "reachable_to")
        paths = attack_paths(g, "p1", [n["e1"], n["e2"]], [n["jewel"]])
        self.assertEqual(len(paths), 2)
        choke = choke_points(paths)
        self.assertEqual(choke[0]["node"], n["b"])
        self.assertEqual(choke[0]["paths"], 2)
        self.assertEqual(choke[0]["score"], 1.0)

    def test_exploit_edges_from_findings(self):
        g = AssetGraph()
        facts = FactStore(EvidenceStore(), g)
        facts.add_findings([NormalizedFinding(
            scan_id="s", project_id="p1", source=FindingSource("nmap", "nmap"), target="192.0.2.7:443",
            category=Category.ASSET, title="open", severity=Severity.INFO,
            details={"host": "192.0.2.7", "port": 443, "service": "https"})])
        facts.add_findings([NormalizedFinding(
            scan_id="s2", project_id="p1", source=FindingSource("nuclei", "nuclei"), target="192.0.2.7:443",
            category=Category.VULNERABILITY, title="RCE", severity=Severity.CRITICAL,
            confidence=Confidence.CONFIRMED, details={"rule_id": "X", "host": "192.0.2.7", "port": 443})])
        added = add_exploit_edges(g, facts.evidence, "p1")
        self.assertEqual(added, 1)
        self.assertTrue(any(e["kind"] == "exploitable_via" for e in g.edges("p1")))
        # 低危不生成
        self.assertEqual(add_exploit_edges(g, facts.evidence, "p1", min_severity=Severity.CRITICAL), 1)


if __name__ == "__main__":
    unittest.main()
