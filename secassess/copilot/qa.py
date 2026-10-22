"""结果问答（L1）：只从单一事实源检索并回答，每条结论都带 finding_id 引用。

不是 LLM：用确定性的关键字/过滤检索，保证答案可溯源、不臆造。
"""
from __future__ import annotations

import re

from ..data.evidence import EvidenceStore
from ..models import Category, Severity

_SEVERITY_WORDS = {"critical": "critical", "严重": "critical", "high": "high", "高危": "high", "高风险": "high",
                   "medium": "medium", "中危": "medium", "low": "low", "低危": "low", "info": "info"}
_CATEGORY_WORDS = {"漏洞": Category.VULNERABILITY, "vuln": Category.VULNERABILITY,
                   "配置": Category.MISCONFIG, "基线": Category.MISCONFIG, "misconfig": Category.MISCONFIG,
                   "资产": Category.ASSET, "端口": Category.ASSET, "asset": Category.ASSET}


def answer(evidence: EvidenceStore, project_id: str, question: str) -> dict:
    """返回 {answer, count, references:[{finding_id, title, severity, target}], filters}。"""
    q = question.lower()
    min_sev = next((v for k, v in _SEVERITY_WORDS.items() if k in q), None)
    category = next((v for k, v in _CATEGORY_WORDS.items() if k in q), None)
    target = next(iter(re.findall(r"\d{1,3}(?:\.\d{1,3}){3}", question)), None)

    findings = evidence.query(project_id, category=category.value if category else None,
                              min_severity=min_sev, target=target)
    terms = [t for t in re.findall(r"[\w一-鿿.-]+", q) if len(t) > 1]
    if terms and not (min_sev or category or target):
        findings = [f for f in findings if any(t in f.to_json().lower() for t in terms)] or findings

    refs = [{"finding_id": f.finding_id, "title": f.title, "severity": f.severity.value,
             "target": f.target, "category": f.category.value} for f in findings[:50]]
    filters = {"min_severity": min_sev, "category": category.value if category else None, "target": target}
    by_sev = {s.value: sum(1 for f in findings if f.severity == s) for s in Severity}
    text = _summarize(project_id, len(findings), filters, by_sev)
    return {"answer": text, "count": len(findings), "references": refs, "filters": filters}


def _summarize(project_id: str, count: int, filters: dict, by_sev: dict) -> str:
    scope = []
    if filters["min_severity"]:
        scope.append(f"严重性 ≥ {filters['min_severity']}")
    if filters["category"]:
        scope.append(f"类别 {filters['category']}")
    if filters["target"]:
        scope.append(f"目标 {filters['target']}")
    where = ("（" + "，".join(scope) + "）") if scope else ""
    if count == 0:
        return f"项目 {project_id}{where} 在事实源中没有匹配的发现。"
    dist = "，".join(f"{s}:{n}" for s, n in by_sev.items() if n)
    return f"项目 {project_id}{where} 共 {count} 条发现（{dist}）。详见引用的 finding_id。"
