import os
import unittest

from secassess.adapters.base import AdapterRegistry, ScannerAdapter
from secassess.adapters.mock_nmap import MockNmapAdapter
from secassess.adapters.mock_placeholder import PlaceholderAdapter
from secassess.agents.asset import AssetDiscoveryAgent
from secassess.agents.baseline import BaselineAgent
from secassess.agents.vuln import VulnScanAgent
from secassess.core.scope_gate import ScopeGate, ScopePolicy
from secassess.data.asset_graph import AssetGraph
from secassess.data.vault import Vault
from secassess.inputs.scope_loader import load_policy, readiness
from secassess.models import Capability, IntrusiveLevel, ScanType

EXAMPLE_SCOPE = os.path.join(os.path.dirname(__file__), "..", "examples", "scope.json")


class RealVulnAdapter(ScannerAdapter):
    name = "real-vuln"

    def __init__(self, available=True):
        self._available = available

    def capability(self):
        return Capability(engine="real", scan_types=frozenset({ScanType.VULN}))

    def available(self):
        return self._available

    async def scan(self, request, on_progress):
        return []


class AgentTest(unittest.TestCase):
    def setUp(self):
        self.registry = AdapterRegistry()
        self.registry.register(MockNmapAdapter())
        self.registry.register(PlaceholderAdapter(ScanType.VULN))
        self.registry.register(PlaceholderAdapter(ScanType.CONFIG_BASELINE))
        self.graph = AssetGraph()

    def test_real_adapter_preferred_over_mock(self):
        self.registry.register(RealVulnAdapter())
        self.assertEqual(VulnScanAgent(self.registry, self.graph).pick_adapter().name, "real-vuln")

    def test_unavailable_real_adapter_falls_back_to_mock(self):
        self.registry.register(RealVulnAdapter(available=False))
        self.assertEqual(VulnScanAgent(self.registry, self.graph).pick_adapter().name, "mock-vuln")

    def test_explicit_adapter_must_support_scan_type(self):
        with self.assertRaises(ValueError):
            VulnScanAgent(self.registry, self.graph).pick_adapter("mock-nmap")
        with self.assertRaises(LookupError):
            VulnScanAgent(AdapterRegistry(), self.graph).pick_adapter()

    def test_asset_agent_requires_explicit_targets(self):
        agent = AssetDiscoveryAgent(self.registry, self.graph)
        with self.assertRaises(ValueError):
            agent.prepare("p1")
        plan = agent.prepare("p1", ["192.0.2.0/28"])
        self.assertEqual((plan.adapter.name, plan.targets, plan.options), ("mock-nmap", ["192.0.2.0/28"],
                                                                           {"profile": "default"}))

    def test_vuln_agent_defaults_to_graph_services(self):
        host = self.graph.upsert_node("p1", "asset", "192.0.2.5")
        for port in (22, 443):
            self.graph.add_edge("p1", host, self.graph.upsert_node("p1", "service", f"192.0.2.5:{port}"), "hosts")
        plan = VulnScanAgent(self.registry, self.graph).prepare("p1")
        self.assertEqual(sorted(plan.targets), ["192.0.2.5:22", "192.0.2.5:443"])
        self.assertEqual(VulnScanAgent(self.registry, self.graph).prepare("p1", ["192.0.2.9:80"]).targets,
                         ["192.0.2.9:80"])
        with self.assertRaises(ValueError):
            VulnScanAgent(self.registry, self.graph).prepare("empty-project")

    def test_baseline_agent_requires_credential(self):
        self.graph.upsert_node("p1", "asset", "192.0.2.5")
        agent = BaselineAgent(self.registry, self.graph)
        with self.assertRaises(ValueError):
            agent.prepare("p1")
        plan = agent.prepare("p1", credential_ref="vault://mem/ssh")
        self.assertEqual((plan.targets, plan.credential_ref), (["192.0.2.5"], "vault://mem/ssh"))

    def test_deep_profile_is_intrusive(self):
        agent = AssetDiscoveryAgent(self.registry, self.graph)
        self.assertIs(agent.prepare("p1", ["192.0.2.1"]).intrusive_level, IntrusiveLevel.SAFE)
        self.assertIs(agent.prepare("p1", ["192.0.2.1"], options={"profile": "deep"}).intrusive_level,
                      IntrusiveLevel.INTRUSIVE)

    def test_observe_returns_summary_only(self):
        summary = AssetDiscoveryAgent(self.registry, self.graph).observe([])
        self.assertEqual(summary, {"agent": "asset", "count": 0, "by_severity": {}})


class ScopeLoaderTest(unittest.TestCase):
    def test_load_example_scope(self):
        policy = load_policy(EXAMPLE_SCOPE)
        self.assertEqual(policy.project_id, "demo")
        self.assertTrue(policy.in_scope("192.0.2.10"))
        self.assertTrue(policy.is_excluded("198.51.100.200"))

    def test_readiness(self):
        gate, vault = ScopeGate(), Vault()
        r = readiness(gate, vault, "demo")
        self.assertFalse(r.ready)
        self.assertIn("① 授权与交战规则未录入", r.missing)
        gate.set_policy(load_policy(EXAMPLE_SCOPE))
        self.assertTrue(readiness(gate, vault, "demo").ready)
        r = readiness(gate, vault, "demo", credential_ref="vault://mem/missing")
        self.assertFalse(r.ready)
        self.assertTrue(any("②" in m for m in r.missing))
        self.assertTrue(readiness(gate, vault, "demo", credential_ref=vault.put("ssh", "k")).ready)
        gate.set_policy(ScopePolicy(project_id="old", authorization_ref="A", allowed_cidrs=["192.0.2.0/24"],
                                    valid_until="2020-01-01T00:00:00Z"))
        self.assertIn("① 授权已过期", readiness(gate, vault, "old").missing)


if __name__ == "__main__":
    unittest.main()
