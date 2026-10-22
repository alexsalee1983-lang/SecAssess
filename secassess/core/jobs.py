"""★ 异步非阻塞 JobManager（§11）。

- submit 校验令牌后立即返回 job_id，执行在后台 asyncio 任务中；
- 信号量限制同时运行的任务数，超额排队；
- 支持协作式取消与超时；任何异常只影响本 job；
- 发现写入外部 sink（事实源），状态可轮询或流式订阅。
"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from datetime import datetime
from typing import AsyncIterator, Callable, Protocol

from ..adapters.base import ScannerAdapter
from ..models import NormalizedFinding, ScanRequest, new_id, utcnow


class JobState:
    QUEUED = "queued"
    RUNNING = "running"
    DONE = "done"
    FAILED = "failed"
    CANCELLED = "cancelled"
    TERMINAL = frozenset({"done", "failed", "cancelled"})


class FindingSink(Protocol):
    def add_findings(self, findings: list[NormalizedFinding]) -> list[NormalizedFinding]: ...

    def findings_for_scan(self, scan_id: str) -> list[NormalizedFinding]: ...


class TokenVerifier(Protocol):
    def verify(self, token: str, request: ScanRequest) -> dict: ...


@dataclass
class Job:
    job_id: str
    adapter: str
    request: ScanRequest
    state: str = JobState.QUEUED
    progress: float = 0.0
    message: str = "queued"
    error: str | None = None
    finding_count: int = 0
    created_at: datetime = field(default_factory=utcnow)
    started_at: datetime | None = None
    finished_at: datetime | None = None
    version: int = 0

    def view(self) -> dict:
        return {
            "job_id": self.job_id, "scan_id": self.request.scan_id, "project_id": self.request.project_id,
            "adapter": self.adapter, "scan_type": self.request.scan_type.value,
            "targets": list(self.request.targets), "state": self.state, "progress": round(self.progress, 4),
            "message": self.message, "error": self.error, "finding_count": self.finding_count,
            "created_at": self.created_at.isoformat(),
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "finished_at": self.finished_at.isoformat() if self.finished_at else None,
        }


OnComplete = Callable[[Job, list[NormalizedFinding]], None]


class JobManager:
    def __init__(self, *, sink: FindingSink, verifier: TokenVerifier | None, max_concurrent: int = 4,
                 default_timeout: float = 3600.0, on_complete: OnComplete | None = None) -> None:
        if max_concurrent < 1:
            raise ValueError("max_concurrent 必须 >= 1")
        self.sink, self.verifier = sink, verifier
        self.max_concurrent, self.default_timeout = max_concurrent, default_timeout
        self.on_complete = on_complete
        self._sem: asyncio.Semaphore | None = None
        self._jobs: dict[str, Job] = {}
        self._tasks: dict[str, asyncio.Task] = {}
        self._changed: dict[str, asyncio.Event] = {}

    # —— §11 契约 ——
    def submit(self, adapter: ScannerAdapter, request: ScanRequest, *, timeout: float | None = None) -> str:
        """非阻塞。令牌缺失/非法、适配器不匹配时同步抛异常，且不创建任务（fail-closed）。"""
        if self.verifier is None:
            raise RuntimeError("未配置令牌校验器，拒绝执行")
        self.verifier.verify(request.scope_token, request)
        if not adapter.supports(request.scan_type):
            raise ValueError(f"{adapter.name} 不支持 {request.scan_type.value}")
        loop = asyncio.get_running_loop()
        if self._sem is None:
            self._sem = asyncio.Semaphore(self.max_concurrent)
        job = Job(job_id=new_id("job"), adapter=adapter.name, request=request)
        self._jobs[job.job_id] = job
        self._changed[job.job_id] = asyncio.Event()
        self._tasks[job.job_id] = loop.create_task(self._run(job, adapter, timeout or self.default_timeout),
                                                   name=job.job_id)
        return job.job_id

    def status(self, job_id: str) -> dict:
        return self._job(job_id).view()

    def results(self, job_id: str) -> list[NormalizedFinding]:
        return self.sink.findings_for_scan(self._job(job_id).request.scan_id)

    def cancel(self, job_id: str) -> bool:
        job = self._job(job_id)
        if job.state in JobState.TERMINAL:
            return False
        self._tasks[job_id].cancel()
        return True

    async def stream(self, job_id: str) -> AsyncIterator[dict]:
        """每次状态变化产出一个快照，以终态结束。"""
        job = self._job(job_id)
        seen = -1
        while True:
            event = self._changed[job_id]
            if job.version != seen:
                seen = job.version
                snapshot = job.view()
                yield snapshot
                if snapshot["state"] in JobState.TERMINAL:
                    return
            await event.wait()

    async def wait(self, job_id: str, timeout: float | None = None) -> dict:
        await asyncio.wait({self._tasks[job_id]}, timeout=timeout)
        return self.status(job_id)

    def list(self, project_id: str | None = None) -> list[dict]:
        return [j.view() for j in self._jobs.values() if project_id in (None, j.request.project_id)]

    def get(self, job_id: str) -> Job:
        return self._job(job_id)

    async def shutdown(self) -> None:
        for task in self._tasks.values():
            task.cancel()
        await asyncio.gather(*self._tasks.values(), return_exceptions=True)

    # —— 内部 ——
    def _job(self, job_id: str) -> Job:
        if job_id not in self._jobs:
            raise KeyError(f"未知 job: {job_id}")
        return self._jobs[job_id]

    def _update(self, job: Job, **changes) -> None:
        for key, value in changes.items():
            setattr(job, key, value)
        job.version += 1
        event, self._changed[job.job_id] = self._changed[job.job_id], asyncio.Event()
        event.set()

    async def _run(self, job: Job, adapter: ScannerAdapter, timeout: float) -> None:
        def on_progress(fraction: float, message: str) -> None:
            if job.state == JobState.RUNNING:
                value = max(job.progress, min(1.0, max(0.0, float(fraction))))
                self._update(job, progress=value, message=str(message)[:500])

        assert self._sem is not None
        try:
            async with self._sem:
                self._update(job, state=JobState.RUNNING, started_at=utcnow(), message="running")
                findings = await asyncio.wait_for(adapter.scan(job.request, on_progress), timeout)
            for f in findings:  # 结果必须归属本次扫描与项目
                f.scan_id, f.project_id = job.request.scan_id, job.request.project_id
            stored = self.sink.add_findings(findings)
            if self.on_complete is not None:
                self.on_complete(job, stored)
            self._update(job, state=JobState.DONE, progress=1.0, finding_count=len(stored),
                         message=f"{len(stored)} findings", finished_at=utcnow())
        except asyncio.CancelledError:
            self._update(job, state=JobState.CANCELLED, message="cancelled", finished_at=utcnow())
        except asyncio.TimeoutError:
            self._update(job, state=JobState.FAILED, error=f"timeout after {timeout}s", message="timeout",
                         finished_at=utcnow())
        except Exception as exc:  # 边界兜底：错误进 job，不拖垮平台
            self._update(job, state=JobState.FAILED, error=f"{type(exc).__name__}: {exc}", message="failed",
                         finished_at=utcnow())
