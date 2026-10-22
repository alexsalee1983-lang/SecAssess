"""端到端演示（只用 mock 适配器与 RFC 5737 文档网段，不产生任何真实网络流量）。

展示：提交即返回 → 并发进度轮询 → HITL 拦截 deep 扫描并审批 → 越界拒绝 → 主干流水线 → 报告。
"""
from __future__ import annotations

import asyncio
import time
from pathlib import Path

from .core.rbac import Principal, Role
from .platform import Platform
from .copilot.harness import run_to_completion
from .copilot.qa import answer as qa_answer
from .reports.engine import build_report, render_html, render_markdown

SCOPE = {
    "project_id": "demo", "authorization_ref": "AUTH-DEMO-2026-001",
    "allowed_cidrs": ["192.0.2.0/24", "198.51.100.0/24"], "excluded": ["192.0.2.254"],
    "allowed_scan_types": ["port_discovery", "vuln", "config_baseline"],
}
ALICE = Principal("alice", Role.ASSESSOR, frozenset({"demo"}))
BOB = Principal("bob", Role.APPROVER, frozenset({"demo"}))


class DemoFailure(AssertionError):
    pass


def check(condition: bool, message: str) -> None:
    if not condition:
        raise DemoFailure(message)


async def _demo(out_dir: Path) -> None:
    platform = Platform.create({"mock_delay": 0.02, "max_concurrent": 2, "scopes": [SCOPE]})
    orch, jobs = platform.orchestrator, platform.jobs

    print("== 1. 提交即返回 + 并发（max_concurrent=2）==")
    job_ids = []
    for cidr in ("192.0.2.0/28", "192.0.2.16/28", "198.51.100.0/28"):
        start = time.perf_counter()
        outcome = orch.execute("asset", "demo", ALICE, targets=[cidr])
        elapsed_ms = (time.perf_counter() - start) * 1000
        check(outcome["state"] == "submitted", f"提交失败: {outcome}")
        check(elapsed_ms < 50, f"submit 耗时 {elapsed_ms:.1f}ms，超过 50ms")
        print(f"  submit {cidr:<16} -> {outcome['job_id']}  耗时 {elapsed_ms:.2f}ms")
        job_ids.append(outcome["job_id"])
    while True:
        views = [jobs.status(j) for j in job_ids]
        print("  进度: " + "  ".join(f"{v['state']:<9}{v['progress']:>5.0%}" for v in views))
        if all(v["state"] in ("done", "failed", "cancelled") for v in views):
            break
        await asyncio.sleep(0.1)
    check(all(v["state"] == "done" for v in views), "端口发现任务未全部完成")

    print("== 2. HITL：deep 扫描需审批 ==")
    pending = orch.execute("asset", "demo", ALICE, targets=["192.0.2.5"], options={"profile": "deep"})
    check(pending["state"] == "pending_approval", f"deep 扫描未被拦截: {pending}")
    print(f"  pending_approval {pending['approval_id']}  原因: {pending['reasons']}")
    orch.approve(pending["approval_id"], BOB, "维护窗口内执行")
    print("  bob 已批准")
    resumed = orch.resume(pending["approval_id"], ALICE)
    view = await jobs.wait(resumed["job_id"], timeout=30)
    check(view["state"] == "done", f"审批后任务未完成: {view}")
    print(f"  resume -> {resumed['job_id']} {view['state']}")

    print("== 3. 越界目标被拒绝（fail-closed）==")
    denied = orch.execute("asset", "demo", ALICE, targets=["192.0.2.1", "203.0.113.10"])
    check(denied["state"] == "denied", "越界目标未被拒绝")
    print(f"  denied: {denied['reasons']}")

    print("== 4. 主干流水线：资产 → 漏洞 + 基线 ==")
    credential = platform.vault.put("demo.ssh", "demo-key-material")
    run = await orch.run_pipeline("demo", ["198.51.100.16/28"], ALICE, credential_ref=credential)
    for step in run["steps"]:
        print(f"  {step['agent']:<9} {step['state']:<9} findings={step.get('finding_count', '-')}")
    check(run["state"] == "done", f"流水线未完成: {run}")
    categories = {f.category.value for f in platform.evidence.query("demo")}
    check(categories == {"asset", "vulnerability", "misconfig"}, f"事实源类别不完整: {categories}")

    print("== 5. 自然语言 Copilot（plan → gate → act → observe）==")
    run = platform.copilot.start("demo", "对 198.51.100.32/28 做全面评估", ALICE, credential_ref=credential)
    run = await run_to_completion(platform.copilot, run, ALICE, auto_approver=BOB)
    check(run.state == "done", f"Copilot 回路未完成: {run.view()}")
    print(f"  指令: {run.instruction}")
    for step in run.steps:
        if step.get("state") == "done":
            print(f"  [{step['iteration']}] {step['agent']:<9} findings={step['finding_count']}  {step['rationale']}")
    ask = qa_answer(platform.evidence, "demo", "有哪些高危漏洞？")
    print(f"  问答: {ask['answer']}")
    check(ask["filters"]["min_severity"] == "high", "问答未按高危过滤")

    print("== 6. 报告 ==")
    out_dir.mkdir(parents=True, exist_ok=True)
    model = build_report("demo", platform.evidence, platform.graph, platform.gate.policy("demo"))
    md_path, html_path = out_dir / "demo-report.md", out_dir / "demo-report.html"
    md_path.write_text(render_markdown(model), encoding="utf-8")
    html_path.write_text(render_html(model), encoding="utf-8")
    print(f"  资产 {len(model.assets)}，问题 {len(model.findings)}，严重性 {model.severity_counts}")
    print(f"  报告: {md_path}")
    print(f"  报告: {html_path}")
    check(platform.audit.verify_chain(), "审计哈希链校验失败")
    print(f"  审计日志 {len(platform.audit.entries('demo'))} 条，哈希链完整")
    await jobs.shutdown()


def run_demo(out_dir: str = "reports_out") -> int:
    try:
        asyncio.run(_demo(Path(out_dir)))
    except DemoFailure as exc:
        print(f"演示失败: {exc}")
        return 1
    print("演示完成")
    return 0
