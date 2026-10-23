"""平台可观测性（缺口⑫）：从各事实源与内核状态汇总快照指标。

快照式（按需计算），不侵入业务路径；也提供一个轻量累计计数器供事件流水使用。
"""
from __future__ import annotations

import threading
from collections import Counter

from ..models import Severity


class MetricsRegistry:
    """进程内累计计数器（线程安全），用于记录事件发生次数。"""

    def __init__(self) -> None:
        self._counts: Counter = Counter()
        self._lock = threading.Lock()

    def incr(self, name: str, n: int = 1) -> None:
        with self._lock:
            self._counts[name] += n

    def snapshot(self) -> dict[str, int]:
        with self._lock:
            return dict(self._counts)


def _finding_breakdown(evidence, project_ids) -> dict:
    by_sev: Counter = Counter()
    by_cat: Counter = Counter()
    by_status: Counter = Counter()
    total = 0
    for pid in project_ids:
        for f in evidence.query(pid):
            total += 1
            by_sev[f.severity.value] += 1
            by_cat[f.category.value] += 1
            by_status[f.status.value] += 1
    return {"total": total, "by_severity": {s.value: by_sev.get(s.value, 0) for s in Severity},
            "by_category": dict(by_cat), "by_status": dict(by_status)}


def collect(platform, project_ids: list[str], *, single: str | None = None) -> dict:
    """汇总给定项目集合的快照指标（调用方负责按租户/权限筛选 project_ids）。"""
    jobs = platform.jobs.list(single) if single else [j for j in platform.jobs.list()
                                                      if j["project_id"] in set(project_ids)]
    job_states: Counter = Counter(j["state"] for j in jobs)
    approvals = []
    for pid in project_ids:
        approvals += platform.gate.approvals.list(pid)
    tickets = []
    for pid in project_ids:
        tickets += platform.tickets.list(pid)
    return {
        "projects": len(project_ids),
        "jobs": {"total": len(jobs), "by_state": dict(job_states)},
        "findings": _finding_breakdown(platform.evidence, project_ids),
        "approvals": {"pending": sum(1 for a in approvals if a.state == "pending"),
                      "total": len(approvals)},
        "tickets": {"open": sum(1 for t in tickets if not t.status.is_terminal), "total": len(tickets)},
        "adapters_available": sum(1 for a in platform.registry.describe() if a["available"]),
        "audit_chain_valid": platform.audit.verify_chain(),
        "counters": platform.metrics.snapshot(),
    }
