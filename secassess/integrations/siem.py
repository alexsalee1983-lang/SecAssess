"""SIEM 事件导出接口（缺口⑩）：把发现与审计记录归一化为事件，供外部 SIEM 消费。

本地实现 InMemoryExporter / JsonlFileExporter，不接真实 SIEM。对接 Splunk/ELK/QRadar 时实现
SIEMExporter.emit 即可。事件为结构化 JSON（含最小 CEF 风格字段），按 project 隔离。
"""
from __future__ import annotations

import abc
import json
from pathlib import Path

from ..data.evidence import EvidenceStore
from ..models import NormalizedFinding, utcnow

_SEVERITY_NUM = {"critical": 10, "high": 8, "medium": 5, "low": 3, "info": 1}


def finding_event(f: NormalizedFinding) -> dict:
    return {"ts": utcnow().isoformat(), "type": "finding", "project_id": f.project_id,
            "finding_id": f.finding_id, "category": f.category.value, "severity": f.severity.value,
            "severity_num": _SEVERITY_NUM.get(f.severity.value, 0), "name": f.title, "target": f.target,
            "risk_score": f.risk_score, "status": f.status.value, "cve": list(f.cve),
            "source": f.source.adapter}


def audit_event(entry: dict) -> dict:
    return {"ts": entry.get("ts"), "type": "audit", "project_id": entry.get("project_id"),
            "actor": entry.get("actor"), "action": entry.get("action"), "target": entry.get("target"),
            "seq": entry.get("seq")}


class SIEMExporter(abc.ABC):
    @abc.abstractmethod
    def emit(self, events: list[dict]) -> int:
        """投递事件，返回成功投递数。"""


class InMemoryExporter(SIEMExporter):
    def __init__(self) -> None:
        self.events: list[dict] = []

    def emit(self, events: list[dict]) -> int:
        self.events.extend(events)
        return len(events)


class JsonlFileExporter(SIEMExporter):
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)

    def emit(self, events: list[dict]) -> int:
        with self.path.open("a", encoding="utf-8") as fh:
            for e in events:
                fh.write(json.dumps(e, ensure_ascii=False, sort_keys=True) + "\n")
        return len(events)


def collect_events(evidence: EvidenceStore, project_id: str, audit_entries: list[dict] | None = None) -> list[dict]:
    events = [finding_event(f) for f in evidence.query(project_id)]
    events += [audit_event(e) for e in (audit_entries or [])]
    return events


def export_project(exporter: SIEMExporter, evidence: EvidenceStore, project_id: str,
                   audit_entries: list[dict] | None = None) -> int:
    return exporter.emit(collect_events(evidence, project_id, audit_entries))
