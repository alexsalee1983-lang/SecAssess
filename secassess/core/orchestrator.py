"""编排器（M0/M1）：确定性的 plan → gate → act → observe 回路。

单步：RBAC → L0 就绪检查 → Agent.prepare → Scope Gate → JobManager.submit，每一步写审计。
主干流水线：资产测绘 →（观察 Asset Graph）→ 漏洞扫描 + 配置基线并行。
M2 会在此之上加 LLM Harness；Scope Gate 与 HITL 仍是不可跳过的硬闸门。
"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from datetime import datetime

from ..adapters.base import AdapterRegistry
from ..agents.asset import AssetDiscoveryAgent
from ..agents.base import AgentPlan, BusinessAgent
from ..agents.baseline import BaselineAgent
from ..agents.vuln import VulnScanAgent
from ..data.facts import FactStore
from ..data.vault import Vault
from ..inputs.scope_loader import readiness
from ..models import ScanRequest, new_id, utcnow
from .audit import AuditLog
from .hitl import ApprovalError
from .jobs import JobManager, JobState
from .rbac import Permission, Principal
from .scope_gate import ScopeGate, build_action, within_targets


@dataclass
class PendingAction:
    plan: AgentPlan
    action: dict
    project_id: str
    requested_by: str


@dataclass
class PipelineRun:
    pipeline_id: str
    project_id: str
    seeds: list[str]
    requested_by: str
    state: str = "running"  # running | done | stopped | failed
    steps: list[dict] = field(default_factory=list)
    error: str | None = None
    created_at: datetime = field(default_factory=utcnow)
    finished_at: datetime | None = None

    def view(self) -> dict:
        return {"pipeline_id": self.pipeline_id, "project_id": self.project_id, "seeds": list(self.seeds),
                "requested_by": self.requested_by, "state": self.state, "steps": list(self.steps),
                "error": self.error, "created_at": self.created_at.isoformat(),
                "finished_at": self.finished_at.isoformat() if self.finished_at else None}


class Orchestrator:
    def __init__(self, *, registry: AdapterRegistry, gate: ScopeGate, jobs: JobManager, facts: FactStore,
                 audit: AuditLog, vault: Vault) -> None:
        self.registry, self.gate, self.jobs = registry, gate, jobs
        self.facts, self.audit, self.vault = facts, audit, vault
        self.agents: dict[str, BusinessAgent] = {
            cls.name: cls(registry, facts.graph) for cls in (AssetDiscoveryAgent, VulnScanAgent, BaselineAgent)}
        self._pending: dict[str, PendingAction] = {}
        self._pipelines: dict[str, PipelineRun] = {}
        self._pipeline_tasks: dict[str, asyncio.Task] = {}

    # —— 单步 ——
    def execute(self, agent: str, project_id: str, principal: Principal, *, targets: list[str] | None = None,
                options: dict | None = None, credential_ref: str | None = None,
                adapter: str | None = None) -> dict:
        principal.require(Permission.SCAN, project_id)
        if agent not in self.agents:
            raise KeyError(f"未知 agent: {agent}")
        ready = readiness(self.gate, self.vault, project_id, credential_ref)
        if not ready.ready:
            return self._deny(principal, project_id, agent, targets, ready.missing)
        try:
            plan = self.agents[agent].prepare(project_id, targets, adapter=adapter, options=options,
                                              credential_ref=credential_ref)
        except (ValueError, LookupError, KeyError) as exc:
            return self._deny(principal, project_id, agent, targets, [str(exc)])
        action = build_action(project_id=project_id, targets=plan.targets, scan_type=plan.scan_type,
                              adapter=plan.adapter.name, intrusive_level=plan.intrusive_level, options=plan.options,
                              credential_ref=plan.credential_ref, rate_limit=plan.rate_limit)
        decision = self.gate.authorize(action, requested_by=principal.user)
        if decision.state == "denied":
            return self._deny(principal, project_id, agent, plan.targets, decision.denials)
        if decision.state == "pending_approval":
            self._pending[decision.approval_id] = PendingAction(plan, action, project_id, principal.user)
            self.audit.record(actor=principal.user, action="scan.pending_approval", project_id=project_id,
                              target=",".join(action["targets"]),
                              detail={"agent": agent, "approval_id": decision.approval_id,
                                      "reasons": decision.hitl_reasons})
            return {"state": "pending_approval", "approval_id": decision.approval_id,
                    "reasons": decision.hitl_reasons}
        return self._submit(plan, decision.token, principal, project_id)

    def approve(self, approval_id: str, principal: Principal, comment: str = "") -> dict:
        item = self.gate.approvals.get(approval_id)
        principal.require(Permission.APPROVE, item.project_id)
        item = self.gate.approvals.approve(approval_id, principal.user, comment)
        self.audit.record(actor=principal.user, action="approval.approve", project_id=item.project_id,
                          target=",".join(item.action.get("targets", [])),
                          detail={"approval_id": approval_id, "comment": comment}, basis=", ".join(item.reasons))
        return item.view()

    def reject(self, approval_id: str, principal: Principal, comment: str = "") -> dict:
        item = self.gate.approvals.get(approval_id)
        principal.require(Permission.APPROVE, item.project_id)
        item = self.gate.approvals.reject(approval_id, principal.user, comment)
        self._pending.pop(approval_id, None)
        self.audit.record(actor=principal.user, action="approval.reject", project_id=item.project_id,
                          detail={"approval_id": approval_id, "comment": comment})
        return item.view()

    def resume(self, approval_id: str, principal: Principal) -> dict:
        """审批通过后重放原动作；动作必须与审批时一致（由 Gate 校验指纹）。"""
        pending = self._pending.get(approval_id)
        if pending is None:
            raise ApprovalError(f"没有待恢复的动作: {approval_id}")
        principal.require(Permission.SCAN, pending.project_id)
        decision = self.gate.authorize(pending.action, requested_by=pending.requested_by, approval_id=approval_id)
        if decision.state != "allowed":
            return self._deny(principal, pending.project_id, pending.plan.agent, pending.plan.targets,
                              decision.denials)
        del self._pending[approval_id]
        return self._submit(pending.plan, decision.token, principal, pending.project_id, approval_id)

    # —— 主干流水线 ——
    def start_pipeline(self, project_id: str, seeds: list[str], principal: Principal, *,
                       credential_ref: str | None = None, options: dict | None = None) -> str:
        """非阻塞：立即返回 pipeline_id，流水线在后台运行。"""
        principal.require(Permission.SCAN, project_id)
        run = PipelineRun(pipeline_id=new_id("pipe"), project_id=project_id, seeds=list(seeds),
                          requested_by=principal.user)
        self._pipelines[run.pipeline_id] = run
        self._pipeline_tasks[run.pipeline_id] = asyncio.get_running_loop().create_task(
            self._run_pipeline(run, principal, credential_ref, options or {}))
        return run.pipeline_id

    async def run_pipeline(self, project_id: str, seeds: list[str], principal: Principal, *,
                           credential_ref: str | None = None, options: dict | None = None) -> dict:
        pipeline_id = self.start_pipeline(project_id, seeds, principal, credential_ref=credential_ref,
                                          options=options)
        await self._pipeline_tasks[pipeline_id]
        return self.pipeline(pipeline_id)

    async def wait_pipeline(self, pipeline_id: str, timeout: float | None = None) -> dict:
        """等待流水线结束（或超时），返回当前状态；不会取消流水线。"""
        task = self._pipeline_tasks.get(pipeline_id)
        if task is None:
            raise KeyError(f"未知 pipeline: {pipeline_id}")
        await asyncio.wait({task}, timeout=timeout)
        return self.pipeline(pipeline_id)

    def pipeline(self, pipeline_id: str) -> dict:
        if pipeline_id not in self._pipelines:
            raise KeyError(f"未知 pipeline: {pipeline_id}")
        return self._pipelines[pipeline_id].view()

    async def _run_pipeline(self, run: PipelineRun, principal: Principal, credential_ref: str | None,
                            options: dict) -> None:
        self.audit.record(actor=principal.user, action="pipeline.start", project_id=run.project_id,
                          target=",".join(run.seeds), detail={"pipeline_id": run.pipeline_id})
        try:
            asset = await self._step(run, "asset", principal, targets=run.seeds, options=options)
            if asset["state"] != JobState.DONE:
                run.state = "stopped"
                return
            # observe：后续步骤只针对本次种子范围内发现的资产（而非项目图谱中的全部节点）
            services = self.discovered(run.project_id, "service", run.seeds)
            hosts = self.discovered(run.project_id, "asset", run.seeds)
            followups, skipped = [], []
            if services:
                followups.append(self._step(run, "vuln", principal, targets=services))
            else:
                skipped.append({"agent": "vuln", "state": "skipped", "reason": "种子范围内未发现服务"})
            if not credential_ref:
                skipped.append({"agent": "baseline", "state": "skipped", "reason": "未提供凭证引用"})
            elif hosts:
                followups.append(self._step(run, "baseline", principal, targets=hosts, credential_ref=credential_ref))
            else:
                skipped.append({"agent": "baseline", "state": "skipped", "reason": "种子范围内未发现主机"})
            results = await asyncio.gather(*followups)
            run.steps.extend(skipped)
            run.state = "done" if all(r["state"] == JobState.DONE for r in results) else "stopped"
        except Exception as exc:  # 流水线失败只影响本次运行
            run.state, run.error = "failed", f"{type(exc).__name__}: {exc}"
        finally:
            run.finished_at = utcnow()
            self.audit.record(actor=principal.user, action="pipeline.finish", project_id=run.project_id,
                              detail={"pipeline_id": run.pipeline_id, "state": run.state})

    async def _step(self, run: PipelineRun, agent: str, principal: Principal, **kwargs) -> dict:
        outcome = self.execute(agent, run.project_id, principal, **kwargs)
        step = {"agent": agent, **outcome}
        run.steps.append(step)  # 并行步骤按提交顺序记录（同步段内追加，顺序确定）
        if outcome["state"] != "submitted":
            return step
        view = await self.jobs.wait(outcome["job_id"])
        step.update(state=view["state"], finding_count=view["finding_count"], error=view["error"],
                    summary=self.agents[agent].observe(self.jobs.results(outcome["job_id"])))
        return step

    # —— 内部 ——
    def discovered(self, project_id: str, kind: str, seeds: list[str]) -> list[str]:
        """Asset Graph 中落在 seeds 范围内的节点（observe 阶段的外部记忆检索）。"""
        return [n["key"] for n in self.facts.graph.nodes(project_id, kind) if within_targets(n["key"], seeds)]

    def _submit(self, plan: AgentPlan, token: str, principal: Principal, project_id: str,
                approval_id: str | None = None) -> dict:
        request = ScanRequest(targets=plan.targets, scan_type=plan.scan_type, scope_token=token,
                              credential_ref=plan.credential_ref, options=plan.options, rate_limit=plan.rate_limit,
                              project_id=project_id)
        job_id = self.jobs.submit(plan.adapter, request)
        policy = self.gate.policy(project_id)
        self.audit.record(actor=principal.user, action="scan.submitted", project_id=project_id,
                          target=",".join(plan.targets),
                          detail={"agent": plan.agent, "adapter": plan.adapter.name, "job_id": job_id,
                                  "scan_id": request.scan_id, "approval_id": approval_id},
                          basis=policy.authorization_ref if policy else "")
        return {"state": "submitted", "job_id": job_id, "scan_id": request.scan_id}

    def _deny(self, principal: Principal, project_id: str, agent: str, targets, reasons: list[str]) -> dict:
        self.audit.record(actor=principal.user, action="scan.denied", project_id=project_id,
                          target=",".join(targets or []), detail={"agent": agent, "reasons": reasons})
        return {"state": "denied", "reasons": list(reasons)}
