"""非阻塞 REST + SSE 接口（FastAPI，可选依赖：pip install 'secassess[api]'）。

认证：请求头 X-API-Key → Principal（RBAC + 项目隔离）。长动作一律 202 + 轮询/SSE。
"""
from __future__ import annotations

import json
from contextlib import asynccontextmanager
from typing import Any

from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, Response, StreamingResponse
from pydantic import BaseModel, Field

from ..core.hitl import ApprovalError
from ..core.rbac import Permission, PermissionDenied, Principal
from ..core.scope_gate import ScopePolicy
from ..core.validator import Hypothesis
from ..remediation.tickets import TicketError
from ..data.vault import VaultError
from ..models import FindingStatus, Severity
from ..platform import Platform
from ..compliance.mapper import build_matrix
from ..core.exposure import add_exploit_edges, attack_paths, choke_points
from ..core.lifecycle import LifecycleError
from ..inputs.importers import ImportError_, import_cmdb, import_nessus, import_passive
from ..inputs.scope_loader import readiness
from ..copilot.qa import answer as qa_answer
from ..reports.engine import build_report, evidence_chain, render_docx, render_html, render_markdown


class ScanBody(BaseModel):
    project_id: str
    agent: str = Field(description="asset | vuln | baseline")
    targets: list[str] | None = None
    options: dict[str, Any] = Field(default_factory=dict)
    credential_ref: str | None = None
    adapter: str | None = None


class PipelineBody(BaseModel):
    project_id: str
    seeds: list[str]
    credential_ref: str | None = None
    options: dict[str, Any] = Field(default_factory=dict)


class CopilotBody(BaseModel):
    project_id: str
    instruction: str
    credential_ref: str | None = None


class AskBody(BaseModel):
    project_id: str
    question: str


class ImportBody(BaseModel):
    rows: list[dict] = Field(default_factory=list)
    xml: str | None = None


class TransitionBody(BaseModel):
    target: str
    credential_ref: str | None = None


class RetestBody(BaseModel):
    covered_targets: list[str] = Field(default_factory=list)


class ExposureBody(BaseModel):
    entries: list[str] = Field(default_factory=list)
    crown_jewels: list[str] = Field(default_factory=list)


class ValidateBody(BaseModel):
    kind: str
    params: dict = Field(default_factory=dict)
    intrusive: bool = False


class TicketOpenBody(BaseModel):
    assignee: str | None = None


class TicketUpdateBody(BaseModel):
    status: str
    note: str = ""


class DecisionBody(BaseModel):
    comment: str = ""


class ReviewBody(BaseModel):
    status: FindingStatus
    comment: str = ""


class CredentialBody(BaseModel):
    name: str
    value: str


def create_app(platform: Platform) -> FastAPI:
    # 所有路由都是 async：JobManager 的任务必须在同一个事件循环里创建和取消（不能在线程池里调用）。
    @asynccontextmanager
    async def lifespan(_app: FastAPI):
        yield
        await platform.jobs.shutdown()

    app = FastAPI(title="SecAssess", version="0.3.0", lifespan=lifespan)
    orch = platform.orchestrator

    def principal(x_api_key: str | None = Header(default=None)) -> Principal:
        user = platform.api_keys.get(x_api_key or "")
        if user is None:
            raise HTTPException(401, "缺少或无效的 X-API-Key")
        return user

    def need(p: Principal, perm: Permission, project_id: str | None = None) -> None:
        try:
            if project_id is not None:
                platform.tenants.require_access(p, project_id)  # 跨租户硬隔离，先于 RBAC
            p.require(perm, project_id)
        except PermissionDenied as exc:
            raise HTTPException(403, str(exc)) from None

    def job_project(job_id: str) -> str:
        try:
            return platform.jobs.get(job_id).request.project_id
        except KeyError:
            raise HTTPException(404, "job 不存在") from None

    @app.exception_handler(PermissionDenied)
    async def _denied(_req: Request, exc: PermissionDenied):
        return JSONResponse({"detail": str(exc)}, status_code=403)

    @app.exception_handler(ApprovalError)
    async def _approval(_req: Request, exc: ApprovalError):
        return JSONResponse({"detail": str(exc)}, status_code=409)

    @app.get("/health")
    async def health() -> dict:
        return {"status": "ok"}

    # —— L0 输入 ——
    @app.put("/projects/{project_id}/scope")
    async def set_scope(project_id: str, body: dict, p: Principal = Depends(principal)) -> dict:
        if not platform.tenants.is_registered(project_id):
            platform.tenants.set_project_tenant(project_id, p.tenant)  # 新项目归属创建者所在租户
        need(p, Permission.INTEGRATE, project_id)
        try:
            policy = ScopePolicy.from_dict({**body, "project_id": project_id})
        except (TypeError, ValueError) as exc:
            raise HTTPException(400, f"授权策略无效: {exc}") from None
        platform.gate.set_policy(policy)
        platform.audit.record(actor=p.user, action="scope.set", project_id=project_id,
                              detail=policy.to_dict(), basis=policy.authorization_ref)
        return policy.to_dict()

    @app.get("/projects/{project_id}/scope")
    async def get_scope(project_id: str, p: Principal = Depends(principal)) -> dict:
        need(p, Permission.VIEW, project_id)
        policy = platform.gate.policy(project_id)
        if policy is None:
            raise HTTPException(404, "未配置授权范围")
        return policy.to_dict()

    @app.post("/projects/{project_id}/credentials", status_code=201)
    async def add_credential(project_id: str, body: CredentialBody, p: Principal = Depends(principal)) -> dict:
        need(p, Permission.INTEGRATE, project_id)
        try:
            ref = platform.vault.put(f"{project_id}.{body.name}", body.value)
        except VaultError as exc:
            raise HTTPException(400, str(exc)) from None
        platform.audit.record(actor=p.user, action="credential.add", project_id=project_id, detail={"ref": ref})
        return {"credential_ref": ref}

    @app.get("/adapters")
    async def adapters(p: Principal = Depends(principal)) -> list[dict]:
        need(p, Permission.VIEW)
        return platform.registry.describe()

    # —— 扫描（非阻塞）——
    @app.post("/scans", status_code=202)
    async def submit_scan(body: ScanBody, p: Principal = Depends(principal)):
        try:
            outcome = orch.execute(body.agent, body.project_id, p, targets=body.targets, options=body.options,
                                   credential_ref=body.credential_ref, adapter=body.adapter)
        except KeyError as exc:
            raise HTTPException(404, str(exc)) from None
        if outcome["state"] == "denied":
            return JSONResponse(outcome, status_code=403)
        return outcome

    @app.get("/scans")
    async def list_scans(project_id: str, p: Principal = Depends(principal)) -> list[dict]:
        need(p, Permission.VIEW, project_id)
        return platform.jobs.list(project_id)

    @app.get("/scans/{job_id}")
    async def scan_status(job_id: str, p: Principal = Depends(principal)) -> dict:
        need(p, Permission.VIEW, job_project(job_id))
        return platform.jobs.status(job_id)

    @app.get("/scans/{job_id}/results")
    async def scan_results(job_id: str, p: Principal = Depends(principal)) -> list[dict]:
        need(p, Permission.VIEW, job_project(job_id))
        return [f.to_dict() for f in platform.jobs.results(job_id)]

    @app.get("/scans/{job_id}/stream")
    async def scan_stream(job_id: str, p: Principal = Depends(principal)) -> StreamingResponse:
        need(p, Permission.VIEW, job_project(job_id))

        async def events():
            async for view in platform.jobs.stream(job_id):
                yield f"event: status\ndata: {json.dumps(view, ensure_ascii=False)}\n\n"

        return StreamingResponse(events(), media_type="text/event-stream",
                                 headers={"Cache-Control": "no-cache"})

    @app.post("/scans/{job_id}/cancel")
    async def scan_cancel(job_id: str, p: Principal = Depends(principal)) -> dict:
        project_id = job_project(job_id)
        need(p, Permission.SCAN, project_id)
        cancelled = platform.jobs.cancel(job_id)
        platform.audit.record(actor=p.user, action="scan.cancel", project_id=project_id,
                              detail={"job_id": job_id, "cancelled": cancelled})
        return {"job_id": job_id, "cancelled": cancelled}

    # —— HITL ——
    @app.get("/approvals")
    async def approvals(project_id: str, state: str | None = None, p: Principal = Depends(principal)) -> list[dict]:
        need(p, Permission.VIEW, project_id)
        return [a.view() for a in platform.gate.approvals.list(project_id, state)]

    @app.post("/approvals/{approval_id}/approve")
    async def approve(approval_id: str, body: DecisionBody, p: Principal = Depends(principal)) -> dict:
        return orch.approve(approval_id, p, body.comment)

    @app.post("/approvals/{approval_id}/reject")
    async def reject(approval_id: str, body: DecisionBody, p: Principal = Depends(principal)) -> dict:
        return orch.reject(approval_id, p, body.comment)

    @app.post("/approvals/{approval_id}/resume", status_code=202)
    async def resume(approval_id: str, p: Principal = Depends(principal)):
        outcome = orch.resume(approval_id, p)
        return JSONResponse(outcome, status_code=403) if outcome["state"] == "denied" else outcome

    # —— 主干流水线 ——
    @app.post("/pipelines", status_code=202)
    async def start_pipeline(body: PipelineBody, p: Principal = Depends(principal)) -> dict:
        pipeline_id = orch.start_pipeline(body.project_id, body.seeds, p, credential_ref=body.credential_ref,
                                          options=body.options)
        return {"pipeline_id": pipeline_id}

    @app.get("/pipelines/{pipeline_id}")
    async def pipeline(pipeline_id: str, wait: float = 0, p: Principal = Depends(principal)) -> dict:
        """wait>0 时长轮询：最多等待 wait 秒（上限 60）直到流水线结束。"""
        try:
            view = orch.pipeline(pipeline_id)
        except KeyError:
            raise HTTPException(404, "pipeline 不存在") from None
        need(p, Permission.VIEW, view["project_id"])
        if wait > 0 and view["state"] == "running":
            view = await orch.wait_pipeline(pipeline_id, timeout=min(wait, 60.0))
        return view

    # —— Copilot（自然语言驱动）——
    @app.post("/copilot/runs", status_code=202)
    async def copilot_start(body: CopilotBody, p: Principal = Depends(principal)) -> dict:
        run = platform.copilot.start(body.project_id, body.instruction, p, credential_ref=body.credential_ref)
        await platform.copilot.drive(run, p)
        return run.view()

    @app.get("/copilot/runs/{run_id}")
    async def copilot_get(run_id: str, p: Principal = Depends(principal)) -> dict:
        try:
            run = platform.copilot.get(run_id)
        except KeyError:
            raise HTTPException(404, "copilot run 不存在") from None
        need(p, Permission.VIEW, run.project_id)
        return run.view()

    @app.post("/copilot/runs/{run_id}/continue", status_code=202)
    async def copilot_continue(run_id: str, p: Principal = Depends(principal)) -> dict:
        try:
            platform.copilot.get(run_id)
        except KeyError:
            raise HTTPException(404, "copilot run 不存在") from None
        return (await platform.copilot.continue_run(run_id, p)).view()

    @app.post("/copilot/ask")
    async def copilot_ask(body: AskBody, p: Principal = Depends(principal)) -> dict:
        need(p, Permission.VIEW, body.project_id)
        return qa_answer(platform.evidence, body.project_id, body.question)

    # —— 事实源 ——
    @app.get("/findings")
    async def findings(project_id: str, category: str | None = None, status: str | None = None,
                 min_severity: str | None = None, p: Principal = Depends(principal)) -> list[dict]:
        need(p, Permission.VIEW, project_id)
        return [f.to_dict() for f in platform.evidence.query(project_id, category=category, status=status,
                                                             min_severity=min_severity)]

    @app.patch("/findings/{finding_id}")
    async def review_finding(finding_id: str, body: ReviewBody, p: Principal = Depends(principal)) -> dict:
        finding = platform.evidence.get(finding_id)
        if finding is None:
            raise HTTPException(404, "发现不存在")
        need(p, Permission.SCAN, finding.project_id)
        if body.status == FindingStatus.ACCEPTED and finding.severity.rank >= Severity.HIGH.rank:
            need(p, Permission.APPROVE, finding.project_id)  # 高危风险接受属于 HITL 范畴
        previous = finding.status
        finding.status = body.status
        finding.details["review"] = {"by": p.user, "comment": body.comment, "previous": previous.value}
        platform.evidence.update(finding)
        platform.audit.record(actor=p.user, action="finding.review", project_id=finding.project_id,
                              target=finding.target, detail={"finding_id": finding_id, "from": previous.value,
                                                             "to": body.status.value, "comment": body.comment})
        return finding.to_dict()

    @app.get("/assets")
    async def assets(project_id: str, kind: str | None = None, p: Principal = Depends(principal)) -> list[dict]:
        need(p, Permission.VIEW, project_id)
        return platform.graph.nodes(project_id, kind)

    @app.get("/findings/{finding_id}/evidence")
    async def finding_evidence(finding_id: str, p: Principal = Depends(principal)) -> dict:
        finding = platform.evidence.get(finding_id)
        if finding is None:
            raise HTTPException(404, "发现不存在")
        need(p, Permission.VIEW, finding.project_id)
        raw_ok = None
        if finding.raw_ref:
            try:
                raw_ok = platform.evidence.get_raw(finding.raw_ref) is not None
            except ValueError:
                raw_ok = False
        return {"finding_id": finding_id, "chain": evidence_chain(finding, platform.graph),
                "raw_ref": finding.raw_ref, "raw_integrity_ok": raw_ok}

    # —— L0 数据导入 ——
    @app.post("/projects/{project_id}/imports/{kind}", status_code=202)
    async def do_import(project_id: str, kind: str, body: ImportBody, p: Principal = Depends(principal)) -> dict:
        need(p, Permission.INTEGRATE, project_id)
        policy = platform.gate.policy(project_id)
        try:
            if kind == "cmdb":
                result = import_cmdb(platform.facts, project_id, body.rows, policy=policy)
            elif kind == "passive":
                result = import_passive(platform.facts, project_id, body.rows, policy=policy)
            elif kind == "nessus":
                if not body.xml:
                    raise HTTPException(400, "nessus 导入需要 xml 字段")
                result = import_nessus(platform.facts, project_id, body.xml, policy=policy)
            else:
                raise HTTPException(404, f"未知导入类型: {kind}")
        except ImportError_ as exc:
            raise HTTPException(400, str(exc)) from None
        platform.audit.record(actor=p.user, action="data.import", project_id=project_id,
                              detail={"kind": kind, **result.to_dict()})
        return result.to_dict()

    # —— 评估生命周期 ——
    @app.post("/assessments", status_code=201)
    async def create_assessment(project_id: str, p: Principal = Depends(principal)) -> dict:
        need(p, Permission.SCAN, project_id)
        return platform.lifecycle.create(project_id).view()

    @app.get("/assessments/{assessment_id}")
    async def get_assessment(assessment_id: str, p: Principal = Depends(principal)) -> dict:
        try:
            a = platform.lifecycle.get(assessment_id)
        except LifecycleError:
            raise HTTPException(404, "评估不存在") from None
        need(p, Permission.VIEW, a.project_id)
        return a.view()

    @app.post("/assessments/{assessment_id}/transition")
    async def transition_assessment(assessment_id: str, body: TransitionBody,
                                    p: Principal = Depends(principal)) -> dict:
        try:
            a = platform.lifecycle.get(assessment_id)
            need(p, Permission.SCAN, a.project_id)
            ready = readiness(platform.gate, platform.vault, a.project_id, body.credential_ref) \
                if body.target == "active" else None
            return platform.lifecycle.transition(assessment_id, body.target, readiness=ready, actor=p.user).view()
        except LifecycleError as exc:
            raise HTTPException(409, str(exc)) from None

    @app.post("/assessments/{assessment_id}/retest")
    async def retest_assessment(assessment_id: str, body: RetestBody,
                                p: Principal = Depends(principal)) -> dict:
        try:
            a = platform.lifecycle.get(assessment_id)
            need(p, Permission.SCAN, a.project_id)
            platform.lifecycle.begin_retest(assessment_id, actor=p.user)
            return platform.lifecycle.conclude_retest(assessment_id, body.covered_targets)
        except LifecycleError as exc:
            raise HTTPException(409, str(exc)) from None

    # —— 输出 ——
    @app.get("/reports/{project_id}")
    async def report(project_id: str, format: str = "md", compliance: bool = True,
                     p: Principal = Depends(principal)) -> Response:
        need(p, Permission.REPORT, project_id)
        matrix = build_matrix(platform.evidence, project_id).to_dict() if compliance else None
        model = build_report(project_id, platform.evidence, platform.graph, platform.gate.policy(project_id),
                             compliance=matrix)
        platform.audit.record(actor=p.user, action="report.generate", project_id=project_id, detail={"format": format})
        if format == "md":
            return PlainTextResponse(render_markdown(model), media_type="text/markdown; charset=utf-8")
        if format == "html":
            return HTMLResponse(render_html(model))
        if format == "docx":
            import tempfile
            with tempfile.TemporaryDirectory() as tmp:
                try:
                    path = render_docx(model, f"{tmp}/report.docx")
                except ImportError:
                    raise HTTPException(501, "未安装 python-docx") from None
                data = open(path, "rb").read()
            return Response(data, media_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document")
        raise HTTPException(400, "format 只能是 md | html | docx")

    @app.get("/compliance/{project_id}")
    async def compliance(project_id: str, p: Principal = Depends(principal)) -> dict:
        need(p, Permission.VIEW, project_id)
        return build_matrix(platform.evidence, project_id).to_dict()

    @app.post("/exposure/{project_id}")
    async def exposure(project_id: str, body: ExposureBody, p: Principal = Depends(principal)) -> dict:
        need(p, Permission.VIEW, project_id)
        add_exploit_edges(platform.graph, platform.evidence, project_id)
        paths = attack_paths(platform.graph, project_id, body.entries, body.crown_jewels)
        return {"paths": paths, "choke_points": choke_points(paths)}

    @app.post("/findings/{finding_id}/validate")
    async def validate_finding(finding_id: str, body: ValidateBody, p: Principal = Depends(principal)) -> dict:
        finding = platform.evidence.get(finding_id)
        if finding is None:
            raise HTTPException(404, "发现不存在")
        need(p, Permission.SCAN, finding.project_id)
        result = platform.validator.validate(
            Hypothesis(finding_id, body.kind, body.params, intrusive=body.intrusive))
        platform.audit.record(actor=p.user, action="finding.validate", project_id=finding.project_id,
                              target=finding.target, detail=result.to_dict())
        return result.to_dict()

    # —— 整改工单 ——
    @app.post("/findings/{finding_id}/ticket", status_code=201)
    async def open_ticket(finding_id: str, body: TicketOpenBody, p: Principal = Depends(principal)) -> dict:
        finding = platform.evidence.get(finding_id)
        if finding is None:
            raise HTTPException(404, "发现不存在")
        need(p, Permission.SCAN, finding.project_id)
        ticket = platform.tickets.open_from_finding(finding, assignee=body.assignee)
        platform.audit.record(actor=p.user, action="ticket.open", project_id=finding.project_id,
                              target=finding.target, detail={"ticket_id": ticket.ticket_id})
        return ticket.to_dict()

    @app.get("/tickets")
    async def list_tickets(project_id: str, status: str | None = None,
                           p: Principal = Depends(principal)) -> list[dict]:
        need(p, Permission.VIEW, project_id)
        return [t.to_dict() for t in platform.tickets.list(project_id, status=status)]

    @app.patch("/tickets/{ticket_id}")
    async def update_ticket(ticket_id: str, body: TicketUpdateBody, p: Principal = Depends(principal)) -> dict:
        ticket = platform.tickets.get(ticket_id)
        if ticket is None:
            raise HTTPException(404, "工单不存在")
        need(p, Permission.SCAN, ticket.project_id)
        try:
            ticket = platform.tickets.transition(ticket_id, body.status, actor=p.user, note=body.note)
        except TicketError as exc:
            raise HTTPException(409, str(exc)) from None
        platform.audit.record(actor=p.user, action="ticket.update", project_id=ticket.project_id,
                              detail={"ticket_id": ticket_id, "status": ticket.status.value})
        return ticket.to_dict()

    @app.get("/audit")
    async def audit(project_id: str, limit: int = 200, p: Principal = Depends(principal)) -> dict:
        need(p, Permission.VIEW, project_id)
        return {"chain_valid": platform.audit.verify_chain(), "entries": platform.audit.entries(project_id, limit)}

    return app
