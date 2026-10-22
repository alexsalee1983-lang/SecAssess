import unittest

from secassess.adapters.base import AdapterRegistry
from secassess.adapters.mock_nmap import MockNmapAdapter
from secassess.adapters.mock_placeholder import PlaceholderAdapter
from secassess.copilot.harness import CopilotHarness, run_to_completion
from secassess.copilot.planner import Plan, PlanContext, PlannedStep
from secassess.copilot.qa import answer
from secassess.core.audit import AuditLog
from secassess.core.jobs import JobManager
from secassess.core.orchestrator import Orchestrator
from secassess.core.rbac import Principal, Role
from secassess.core.scope_gate import ScopeGate, ScopePolicy
from secassess.data.asset_graph import AssetGraph
from secassess.data.evidence import EvidenceStore
from secassess.data.facts import FactStore
from secassess.data.vault import Vault
from secassess.models import ScanType

ALICE = Principal("alice", Role.ASSESSOR)
BOB = Principal("bob", Role.APPROVER)


class StubPlanner:
    """固定计划，用于验证 harness 对越界/审批的处理，不依赖关键字解析。"""
    name = "stub"

    def __init__(self, batches):
        self.batches = batches
        self.calls = 0

    async def next_steps(self, ctx: PlanContext) -> Plan:
        if self.calls >= len(self.batches):
            return Plan([], [], self.name)
        steps = self.batches[self.calls]
        self.calls += 1
        return Plan(steps, [], self.name)


class CopilotTest(unittest.IsolatedAsyncioTestCase):
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
        self.audit = AuditLog()
        self.jobs = JobManager(sink=self.facts, verifier=self.gate)
        self.orch = Orchestrator(registry=registry, gate=self.gate, jobs=self.jobs, facts=self.facts,
                                 audit=self.audit, vault=Vault())

    async def asyncTearDown(self):
        await self.jobs.shutdown()

    async def test_natural_language_full_assessment(self):
        harness = CopilotHarness(self.orch)
        self.orch.vault.put("ssh", "key")
        cred = "vault://mem/ssh"
        run = harness.start("p1", "对 192.0.2.0/28 做全面评估", ALICE, credential_ref=cred)
        run = await harness.drive(run, ALICE)
        self.assertEqual(run.state, "done", run.view())
        categories = {f.category.value for f in self.evidence.query("p1")}
        self.assertEqual(categories, {"asset", "vulnerability", "misconfig"})
        agents = [s["agent"] for s in run.steps if s.get("state") == "done"]
        self.assertEqual(set(agents), {"asset", "vuln", "baseline"})

    async def test_deep_scan_pauses_then_continues(self):
        harness = CopilotHarness(self.orch, StubPlanner([[PlannedStep("asset", ["192.0.2.3"], {"profile": "deep"})]]))
        run = harness.start("p1", "深度扫描 192.0.2.3", ALICE)
        run = await harness.drive(run, ALICE)
        self.assertEqual(run.state, "waiting_approval")
        self.assertEqual(len(run.pending_approvals), 1)
        # 只有发起人能推进
        with self.assertRaises(PermissionError):
            await harness.drive(run, BOB)
        self.orch.approve(run.pending_approvals[0]["approval_id"], BOB, "ok")
        run = await harness.continue_run(run.run_id, ALICE)
        self.assertEqual(run.state, "done", run.view())
        self.assertTrue(self.evidence.query("p1"))

    async def test_rejected_approval_does_not_execute(self):
        harness = CopilotHarness(self.orch, StubPlanner([[PlannedStep("asset", ["192.0.2.3"], {"profile": "deep"})]]))
        run = harness.start("p1", "深度扫描 192.0.2.3", ALICE)
        await harness.drive(run, ALICE)
        self.orch.reject(run.pending_approvals[0]["approval_id"], BOB, "no")
        run = await harness.continue_run(run.run_id, ALICE)
        self.assertEqual(run.state, "done")
        self.assertEqual(self.evidence.query("p1"), [])
        self.assertTrue(any("rejected" in n for n in run.notes))

    async def test_out_of_scope_is_reported_not_retried(self):
        harness = CopilotHarness(self.orch, StubPlanner([[PlannedStep("asset", ["203.0.113.9"])]]))
        run = harness.start("p1", "scan 203.0.113.9", ALICE)
        run = await harness.drive(run, ALICE)
        self.assertEqual(run.state, "done")
        self.assertTrue(any(s.get("state") == "denied" for s in run.steps))
        self.assertEqual(self.jobs.list(), [])

    async def test_no_targets_stops(self):
        harness = CopilotHarness(self.orch)
        run = harness.start("p1", "帮我做个评估", ALICE)
        run = await harness.drive(run, ALICE)
        self.assertEqual(run.state, "stopped")

    async def test_iteration_cap(self):
        # 规划器每轮都返回一个 asset 步骤，但第一次之后 asset 已完成，仍强行返回 → 验证不会无限循环
        batches = [[PlannedStep("asset", ["192.0.2.1"])] for _ in range(20)]
        harness = CopilotHarness(self.orch, StubPlanner(batches), max_iterations=3)
        run = harness.start("p1", "repeat", ALICE)
        run = await harness.drive(run, ALICE)
        self.assertLessEqual(run.iterations, 3)
        self.assertIn(run.state, ("done", "stopped"))

    async def test_run_to_completion_helper_auto_approves(self):
        harness = CopilotHarness(self.orch)
        self.orch.vault.put("ssh", "key")
        run = harness.start("p1", "对 192.0.2.0/28 做深度全面评估", ALICE, credential_ref="vault://mem/ssh")
        run = await run_to_completion(harness, run, ALICE, auto_approver=BOB)
        self.assertEqual(run.state, "done", run.view())

    async def test_qa_cites_findings(self):
        harness = CopilotHarness(self.orch)
        run = harness.start("p1", "对 192.0.2.0/28 做资产测绘和漏洞扫描", ALICE)
        await harness.drive(run, ALICE)
        result = answer(self.evidence, "p1", "有哪些高危漏洞？")
        self.assertEqual(result["filters"]["category"], "vulnerability")
        self.assertEqual(result["filters"]["min_severity"], "high")
        self.assertEqual(result["count"], len(result["references"]) if result["count"] <= 50 else 50)
        for ref in result["references"]:
            self.assertIn(ref["severity"], ("high", "critical"))
            self.assertTrue(ref["finding_id"].startswith("fnd_"))
        empty = answer(self.evidence, "p1", "有没有 203.0.113.1 的发现？")
        self.assertEqual(empty["count"], 0)
        self.assertIn("没有匹配", empty["answer"])


if __name__ == "__main__":
    unittest.main()
