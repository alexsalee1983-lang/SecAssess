import unittest

from secassess.adapters.base import AdapterRegistry
from secassess.adapters.mock_nmap import MockNmapAdapter
from secassess.adapters.mock_placeholder import PlaceholderAdapter
from secassess.core.audit import AuditLog
from secassess.core.hitl import ApprovalError
from secassess.core.jobs import JobManager
from secassess.core.orchestrator import Orchestrator
from secassess.core.rbac import PermissionDenied, Principal, Role
from secassess.core.scope_gate import ScopeGate, ScopePolicy
from secassess.data.asset_graph import AssetGraph
from secassess.data.evidence import EvidenceStore
from secassess.data.facts import FactStore
from secassess.data.vault import Vault
from secassess.models import ScanType

ALICE = Principal("alice", Role.ASSESSOR)
BOB = Principal("bob", Role.APPROVER)


class OrchestratorTest(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        registry = AdapterRegistry()
        registry.register(MockNmapAdapter(delay=0))
        registry.register(PlaceholderAdapter(ScanType.VULN, delay=0))
        registry.register(PlaceholderAdapter(ScanType.CONFIG_BASELINE, delay=0))
        self.gate = ScopeGate(b"k" * 32)
        self.gate.set_policy(ScopePolicy(project_id="p1", authorization_ref="AUTH-1",
                                         allowed_cidrs=["192.0.2.0/24"], excluded=["192.0.2.254"]))
        self.evidence, self.graph = EvidenceStore(), AssetGraph()
        self.facts = FactStore(self.evidence, self.graph)
        self.audit, self.vault = AuditLog(), Vault()
        self.jobs = JobManager(sink=self.facts, verifier=self.gate)
        self.orch = Orchestrator(registry=registry, gate=self.gate, jobs=self.jobs, facts=self.facts,
                                 audit=self.audit, vault=self.vault)

    async def asyncTearDown(self):
        await self.jobs.shutdown()

    async def test_pipeline_runs_asset_vuln_baseline_into_one_fact_source(self):
        cred = self.vault.put("ssh", "key-material")
        run = await self.orch.run_pipeline("p1", ["192.0.2.0/28"], ALICE, credential_ref=cred)
        self.assertEqual(run["state"], "done", run)
        self.assertEqual([s["agent"] for s in run["steps"]], ["asset", "vuln", "baseline"])
        categories = {f.category.value for f in self.evidence.query("p1")}
        self.assertEqual(categories, {"asset", "vulnerability", "misconfig"})
        node_ids = {n["id"] for n in self.graph.nodes("p1")}
        self.assertTrue(all(f.asset_ref in node_ids for f in self.evidence.query("p1")))
        self.assertTrue(all("summary" in s for s in run["steps"]))
        self.assertTrue(self.audit.verify_chain())

    async def test_pipeline_followups_limited_to_seed_range(self):
        other = self.orch.execute("asset", "p1", ALICE, targets=["192.0.2.64/28"])
        await self.jobs.wait(other["job_id"], timeout=5)
        run = await self.orch.run_pipeline("p1", ["192.0.2.0/28"], ALICE)
        vuln_job = next(s for s in run["steps"] if s["agent"] == "vuln")["job_id"]
        targets = self.jobs.get(vuln_job).request.targets
        self.assertTrue(targets)
        self.assertTrue(all(int(t.split(":")[0].rsplit(".", 1)[1]) < 16 for t in targets), targets)

    async def test_pipeline_without_credential_skips_baseline(self):
        run = await self.orch.run_pipeline("p1", ["192.0.2.0/29"], ALICE)
        self.assertEqual(run["state"], "done")
        self.assertEqual(run["steps"][-1], {"agent": "baseline", "state": "skipped", "reason": "未提供凭证引用"})

    async def test_pipeline_stops_when_seed_out_of_scope(self):
        run = await self.orch.run_pipeline("p1", ["203.0.113.0/28"], ALICE)
        self.assertEqual(run["state"], "stopped")
        self.assertEqual(run["steps"][0]["state"], "denied")
        self.assertEqual(self.jobs.list(), [])

    async def test_deep_scan_requires_approval_then_resumes(self):
        outcome = self.orch.execute("asset", "p1", ALICE, targets=["192.0.2.1"], options={"profile": "deep"})
        self.assertEqual(outcome["state"], "pending_approval")
        self.assertEqual(self.jobs.list(), [])
        approval_id = outcome["approval_id"]
        with self.assertRaises(PermissionDenied):
            self.orch.approve(approval_id, ALICE)  # 评估员无审批权
        with self.assertRaises(ApprovalError):
            self.orch.approve(approval_id, Principal("alice", Role.LEAD))  # 申请人不能自批
        early = self.orch.resume(approval_id, ALICE)  # 未批准不能执行
        self.assertEqual(early["state"], "denied")
        self.assertEqual(self.jobs.list(), [])
        self.orch.approve(approval_id, BOB, "ok")
        submitted = self.orch.resume(approval_id, ALICE)
        self.assertEqual(submitted["state"], "submitted")
        self.assertEqual((await self.jobs.wait(submitted["job_id"], timeout=5))["state"], "done")
        with self.assertRaises(ApprovalError):
            self.orch.resume(approval_id, ALICE)  # 一次性
        actions = [e["action"] for e in reversed(self.audit.entries("p1"))]
        self.assertEqual(actions, ["scan.pending_approval", "scan.denied", "approval.approve", "scan.submitted"])
        self.assertTrue(self.audit.verify_chain())

    async def test_rejected_approval_cannot_resume(self):
        outcome = self.orch.execute("asset", "p1", ALICE, targets=["192.0.2.1"], options={"profile": "deep"})
        self.orch.reject(outcome["approval_id"], BOB, "not now")
        with self.assertRaises(ApprovalError):
            self.orch.resume(outcome["approval_id"], ALICE)

    async def test_out_of_scope_and_excluded_targets_denied(self):
        for targets in (["203.0.113.5"], ["192.0.2.1", "192.0.2.254"]):
            with self.subTest(targets=targets):
                outcome = self.orch.execute("asset", "p1", ALICE, targets=targets)
                self.assertEqual(outcome["state"], "denied")
        self.assertEqual(self.jobs.list(), [])
        self.assertEqual(self.audit.entries("p1")[0]["action"], "scan.denied")

    async def test_roles_without_scan_permission_are_rejected(self):
        for role in (Role.CLIENT, Role.APPROVER):
            with self.subTest(role=role), self.assertRaises(PermissionDenied):
                self.orch.execute("asset", "p1", Principal("u", role), targets=["192.0.2.1"])
        with self.assertRaises(PermissionDenied):
            self.orch.execute("asset", "p1", Principal("a", Role.ASSESSOR, frozenset({"p2"})), targets=["192.0.2.1"])

    async def test_readiness_and_credential_checks(self):
        self.assertEqual(self.orch.execute("asset", "no-policy", ALICE, targets=["192.0.2.1"])["state"], "denied")
        self.graph.upsert_node("p1", "asset", "192.0.2.1")
        missing_cred = self.orch.execute("baseline", "p1", ALICE)
        self.assertEqual(missing_cred["state"], "denied")
        self.assertTrue(any("credential_ref" in r for r in missing_cred["reasons"]))
        bad_cred = self.orch.execute("baseline", "p1", ALICE, credential_ref="vault://mem/nope")
        self.assertEqual(bad_cred["state"], "denied")
        with self.assertRaises(KeyError):
            self.orch.execute("phishing", "p1", ALICE, targets=["192.0.2.1"])


if __name__ == "__main__":
    unittest.main()
