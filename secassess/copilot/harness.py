"""Copilot Harness（L2）：自然语言 → plan → gate → act → observe 回路。

- 规划器只产出提议，每一步都经 Orchestrator.execute 过 Scope Gate / HITL（硬闸门，回路不可绕过）；
- 高敏动作在闸门处暂停为 waiting_approval，审批后用 continue_run 继续；
- 事实源是外部记忆：observe 阶段只回传 Asset Graph 的计数与各步摘要，不把全部发现塞回上下文；
- 回路有迭代上限，越界被拒会如实记录且不重试绕过。
"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from datetime import datetime

from ..core.jobs import JobState
from ..core.orchestrator import Orchestrator
from ..core.rbac import Permission, Principal
from ..models import new_id, utcnow
from .planner import PlanContext, Planner, RuleBasedPlanner, extract_targets, sanitize_steps

MAX_ITERATIONS = 8


@dataclass
class CopilotRun:
    run_id: str
    project_id: str
    instruction: str
    seeds: list[str]
    requested_by: str
    credential_ref: str | None = None
    state: str = "running"  # running | waiting_approval | done | stopped | failed
    steps: list[dict] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    pending_approvals: list[dict] = field(default_factory=list)
    completed: list[dict] = field(default_factory=list)
    iterations: int = 0
    error: str | None = None
    created_at: datetime = field(default_factory=utcnow)
    finished_at: datetime | None = None

    def view(self) -> dict:
        return {"run_id": self.run_id, "project_id": self.project_id, "instruction": self.instruction,
                "seeds": list(self.seeds), "requested_by": self.requested_by, "state": self.state,
                "steps": list(self.steps), "notes": list(self.notes),
                "pending_approvals": list(self.pending_approvals), "iterations": self.iterations,
                "error": self.error, "created_at": self.created_at.isoformat(),
                "finished_at": self.finished_at.isoformat() if self.finished_at else None}


class CopilotHarness:
    def __init__(self, orchestrator: Orchestrator, planner: Planner | None = None, *,
                 max_iterations: int = MAX_ITERATIONS) -> None:
        self.orch = orchestrator
        self.planner = planner or RuleBasedPlanner()
        self.max_iterations = max_iterations
        self._runs: dict[str, CopilotRun] = {}

    def start(self, project_id: str, instruction: str, principal: Principal, *,
              credential_ref: str | None = None) -> CopilotRun:
        principal.require(Permission.SCAN, project_id)
        run = CopilotRun(run_id=new_id("cop"), project_id=project_id, instruction=instruction,
                         seeds=extract_targets(instruction), requested_by=principal.user,
                         credential_ref=credential_ref)
        self._runs[run.run_id] = run
        return run

    def get(self, run_id: str) -> CopilotRun:
        if run_id not in self._runs:
            raise KeyError(f"未知 copilot run: {run_id}")
        return self._runs[run_id]

    async def drive(self, run: CopilotRun, principal: Principal) -> CopilotRun:
        """推进回路，直到结束、暂停审批或触达迭代上限。principal 必须与发起人一致。"""
        if run.requested_by != principal.user:
            raise PermissionError("只有发起人可以推进该 Copilot 回路")
        if run.state not in ("running", "waiting_approval"):
            return run
        run.state = "running"
        run.pending_approvals = []
        if not run.seeds:
            return self._finish(run, "stopped", "指令中没有识别到授权目标")
        try:
            while run.iterations < self.max_iterations:
                run.iterations += 1
                ctx = PlanContext(instruction=run.instruction, project_id=run.project_id, seeds=run.seeds,
                                  credential_ref=run.credential_ref, completed=list(run.completed),
                                  discovered=self._discovered(run))
                plan = await self.planner.next_steps(ctx)
                run.notes += [n for n in plan.notes if n not in run.notes]
                steps, dropped = sanitize_steps(plan.steps)
                run.notes += dropped
                if not steps:
                    return self._finish(run, "done")
                paused = await self._run_steps(run, steps, principal)
                if paused:
                    run.state = "waiting_approval"
                    return run
            run.notes.append(f"达到迭代上限 {self.max_iterations}")
            return self._finish(run, "done")
        except Exception as exc:  # 回路失败只影响本次运行
            return self._finish(run, "failed", f"{type(exc).__name__}: {exc}")

    async def _run_steps(self, run: CopilotRun, steps, principal: Principal) -> bool:
        paused = False
        for step in steps:
            outcome = self.orch.execute(step.agent, run.project_id, principal, targets=step.targets,
                                        options=step.options, credential_ref=run.credential_ref)
            record = {"iteration": run.iterations, "agent": step.agent, "rationale": step.rationale, **outcome}
            if outcome["state"] == "submitted":
                view = await self.orch.jobs.wait(outcome["job_id"])
                summary = self.orch.agents[step.agent].observe(self.orch.jobs.results(outcome["job_id"]))
                record.update(state=view["state"], finding_count=view["finding_count"], summary=summary)
                run.completed.append({"agent": step.agent, "state": view["state"], "summary": summary})
                if view["state"] != JobState.DONE:
                    run.steps.append(record)
                    self._finish(run, "stopped", f"{step.agent} 执行失败: {view['error']}")
                    return False
            elif outcome["state"] == "pending_approval":
                run.pending_approvals.append({"agent": step.agent, "approval_id": outcome["approval_id"],
                                              "reasons": outcome["reasons"]})
                paused = True
            else:  # denied —— 如实记录，不重试绕过
                run.completed.append({"agent": step.agent, "state": "denied", "summary": {}})
                run.notes.append(f"{step.agent} 被拒绝: {'; '.join(outcome.get('reasons', []))}")
            run.steps.append(record)
        return paused

    async def continue_run(self, run_id: str, principal: Principal) -> CopilotRun:
        """审批（批准/拒绝）后继续回路。已被批准的 pending 动作先 resume，再重新规划。"""
        run = self.get(run_id)
        if run.requested_by != principal.user:
            raise PermissionError("只有发起人可以继续该 Copilot 回路")
        if run.state != "waiting_approval":
            return run
        for pending in run.steps:
            if pending.get("state") == "pending_approval":
                approval = self.orch.gate.approvals.get(pending["approval_id"])
                if approval.state == "approved":
                    resumed = self.orch.resume(pending["approval_id"], principal)
                    pending["state"] = resumed["state"]
                    if resumed["state"] == "submitted":
                        view = await self.orch.jobs.wait(resumed["job_id"])
                        agent = pending["agent"]
                        summary = self.orch.agents[agent].observe(self.orch.jobs.results(resumed["job_id"]))
                        pending.update(state=view["state"], finding_count=view["finding_count"], summary=summary)
                        run.completed.append({"agent": agent, "state": view["state"], "summary": summary})
                elif approval.state in ("rejected", "expired"):
                    pending["state"] = approval.state
                    run.notes.append(f"{pending['agent']} 的审批被{approval.state}，跳过")
                    run.completed.append({"agent": pending["agent"], "state": approval.state, "summary": {}})
        if any(p.get("state") == "pending_approval" for p in run.steps):
            run.pending_approvals = [{"agent": p["agent"], "approval_id": p["approval_id"],
                                      "reasons": p.get("reasons", [])}
                                     for p in run.steps if p.get("state") == "pending_approval"]
            return run  # 仍有未决审批
        return await self.drive(run, principal)

    def _discovered(self, run: CopilotRun) -> dict[str, int]:
        return {kind: len(self.orch.discovered(run.project_id, kind, run.seeds)) for kind in ("asset", "service")}

    def _finish(self, run: CopilotRun, state: str, error: str | None = None) -> CopilotRun:
        run.state, run.error, run.finished_at = state, error, utcnow()
        run.pending_approvals = []
        self.orch.audit.record(actor=run.requested_by, action="copilot.finish", project_id=run.project_id,
                               target=",".join(run.seeds),
                               detail={"run_id": run.run_id, "state": state, "iterations": run.iterations})
        return run


async def run_to_completion(harness: CopilotHarness, run: CopilotRun, principal: Principal,
                            auto_approver: Principal | None = None) -> CopilotRun:
    """测试/演示辅助：驱动回路，若提供 auto_approver 则自动批准暂停的审批后继续。"""
    await harness.drive(run, principal)
    while run.state == "waiting_approval" and auto_approver is not None:
        for pending in list(run.pending_approvals):
            harness.orch.approve(pending["approval_id"], auto_approver, "auto-approved for run")
        await harness.continue_run(run.run_id, principal)
        await asyncio.sleep(0)
    return run
