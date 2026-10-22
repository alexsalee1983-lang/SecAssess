import unittest

from secassess.copilot.planner import (MAX_TARGETS, PlanContext, PlannedStep, RuleBasedPlanner, detect_intent,
                                       extract_targets, sanitize_steps)


class ExtractTargetsTest(unittest.TestCase):
    def test_mixed_chinese_and_english(self):
        text = "请对192.0.2.0/28和198.51.100.7:8443做漏洞扫描，另外看看 www.example.com 与 https://api.example.com/v1。"
        self.assertEqual(extract_targets(text),
                         ["https://api.example.com/v1", "192.0.2.0/28", "198.51.100.7:8443", "www.example.com"])

    def test_rejects_invalid_ips_and_dedups(self):
        self.assertEqual(extract_targets("scan 999.1.1.1 and 192.0.2.1, 192.0.2.1"), ["192.0.2.1"])
        self.assertEqual(extract_targets("没有目标的指令"), [])

    def test_email_is_not_a_domain_target(self):
        self.assertEqual(extract_targets("联系 soc@example.com 后扫描 192.0.2.9"), ["192.0.2.9"])


class IntentTest(unittest.TestCase):
    def test_keywords(self):
        self.assertEqual(detect_intent("对 192.0.2.0/24 做资产测绘"), ({"asset"}, False))
        self.assertEqual(detect_intent("scan for vulns")[0], {"vuln"})
        self.assertEqual(detect_intent("做一次 CIS 基线核查")[0], {"baseline"})
        self.assertEqual(detect_intent("对它做全面评估")[0], {"asset", "vuln", "baseline"})
        self.assertEqual(detect_intent("comprehensive assessment please")[0], {"asset", "vuln", "baseline"})
        self.assertTrue(detect_intent("深度端口扫描")[1])
        self.assertEqual(detect_intent("看一下 192.0.2.1")[0], {"asset"})


class RuleBasedPlannerTest(unittest.IsolatedAsyncioTestCase):
    async def run_plan(self, instruction, **kw):
        ctx = PlanContext(instruction=instruction, project_id="p1", seeds=extract_targets(instruction), **kw)
        return await RuleBasedPlanner().next_steps(ctx)

    async def test_full_assessment_iterates(self):
        text = "对 192.0.2.0/28 做全面评估"
        first = await self.run_plan(text, credential_ref="vault://mem/ssh")
        self.assertEqual([s.agent for s in first.steps], ["asset"])
        self.assertEqual(first.steps[0].targets, ["192.0.2.0/28"])
        second = await self.run_plan(text, credential_ref="vault://mem/ssh", completed=[{"agent": "asset"}],
                                     discovered={"asset": 3, "service": 5})
        self.assertEqual([s.agent for s in second.steps], ["vuln", "baseline"])
        self.assertTrue(all(s.targets is None for s in second.steps))
        done = await self.run_plan(text, credential_ref="vault://mem/ssh",
                                   completed=[{"agent": "asset"}, {"agent": "vuln"}, {"agent": "baseline"}],
                                   discovered={"asset": 3, "service": 5})
        self.assertEqual(done.steps, [])

    async def test_baseline_without_credential_is_skipped_with_note(self):
        plan = await self.run_plan("全面评估 192.0.2.0/28", completed=[{"agent": "asset"}],
                                   discovered={"asset": 1, "service": 1})
        self.assertEqual([s.agent for s in plan.steps], ["vuln"])
        self.assertTrue(any("凭证" in n for n in plan.notes))

    async def test_deep_option_and_vuln_needs_discovery_first(self):
        plan = await self.run_plan("对 192.0.2.5 做深度漏洞扫描")
        self.assertEqual([(s.agent, s.options) for s in plan.steps], [("asset", {"profile": "deep"})])

    async def test_no_targets(self):
        plan = await self.run_plan("帮我做个全面评估")
        self.assertEqual(plan.steps, [])
        self.assertTrue(plan.notes)


class SanitizeTest(unittest.TestCase):
    def test_whitelist(self):
        steps = [PlannedStep("asset", ["192.0.2.1"]), PlannedStep("exploit", ["192.0.2.1"]),
                 PlannedStep("asset", ["192.0.2.1"], {"profile": "insane"}),
                 PlannedStep("asset", ["192.0.2.1"], {"shell": "x"}),
                 PlannedStep("vuln", [f"192.0.2.{i}" for i in range(MAX_TARGETS + 1)]),
                 PlannedStep("vuln", []), PlannedStep("baseline", None, {"profile": "deep"})]
        clean, dropped = sanitize_steps(steps)
        self.assertEqual([s.agent for s in clean], ["asset", "baseline"])
        self.assertEqual(len(dropped), 5)


if __name__ == "__main__":
    unittest.main()
