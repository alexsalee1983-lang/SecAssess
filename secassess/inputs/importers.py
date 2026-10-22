"""L0 数据导入：② CMDB（CSV）、④ 被动采集（CSV）、⑤ 既有扫描结果（.nessus XML）。

统一入口把记录写入单一事实源（资产图 / Evidence Store），并做授权范围过滤：
授权范围外的记录被标记为 out_of_scope、不进入扫描目标，只在结果里列出。
XML 解析拒绝 DOCTYPE / 实体定义，防 XXE 与实体膨胀。
"""
from __future__ import annotations

import csv
import io
from dataclasses import dataclass, field
from pathlib import Path

from ..core.scope_gate import ScopePolicy
from ..data.facts import FactStore
from ..models import (Category, Channel, Confidence, FindingSource, NormalizedFinding, Severity, new_id,
                      utcnow)


class ImportError_(ValueError):
    pass


@dataclass
class ImportResult:
    channel: str
    imported: int = 0
    assets: int = 0
    skipped: list[dict] = field(default_factory=list)  # [{value, reason}]
    finding_ids: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {"channel": self.channel, "imported": self.imported, "assets": self.assets,
                "skipped": list(self.skipped), "finding_ids": list(self.finding_ids)}


def _rows(source: str | Path | list[dict]) -> list[dict]:
    """source 可以是 list[dict]、CSV 文本（含换行）或 CSV 文件路径。"""
    if isinstance(source, list):
        return source
    text = str(source) if (isinstance(source, str) and "\n" in source) else Path(source).read_text(encoding="utf-8")
    return list(csv.DictReader(io.StringIO(text)))


def _in_scope(policy: ScopePolicy | None, value: str) -> bool:
    return policy is None or policy.in_scope(value)


def import_cmdb(facts: FactStore, project_id: str, source, *, policy: ScopePolicy | None = None) -> ImportResult:
    """CSV 列：host, criticality(1-5), owner, internet_facing(true/false), data_class。"""
    result = ImportResult(channel="cmdb")
    for row in _rows(source):
        host = (row.get("host") or row.get("ip") or "").strip()
        if not host:
            continue
        if not _in_scope(policy, host):
            result.skipped.append({"value": host, "reason": "out_of_scope"})
            continue
        attrs = {"source": "cmdb"}
        if row.get("criticality"):
            attrs["criticality"] = int(row["criticality"])
        if row.get("owner"):
            attrs["owner"] = row["owner"].strip()
        if row.get("internet_facing"):
            attrs["internet_facing"] = row["internet_facing"].strip().lower() in ("1", "true", "yes", "y")
        if row.get("data_class"):
            attrs["data_class"] = row["data_class"].strip()
        facts.graph.upsert_node(project_id, "asset", host, attrs)
        result.assets += 1
        result.imported += 1
    return result


def import_passive(facts: FactStore, project_id: str, source, *, policy: ScopePolicy | None = None) -> ImportResult:
    """被动采集 CSV 列：host, source(dns/netflow/dhcp), service(optional), port(optional)。"""
    result = ImportResult(channel="passive")
    findings = []
    for row in _rows(source):
        host = (row.get("host") or row.get("ip") or "").strip()
        if not host:
            continue
        if not _in_scope(policy, host):
            result.skipped.append({"value": host, "reason": "out_of_scope"})
            continue
        port = row.get("port", "").strip()
        target = f"{host}:{port}" if port else host
        details = {"host": host, "origin": row.get("source", "passive").strip(), "simulated": False}
        if port:
            details["port"] = int(port)
        if row.get("service"):
            details["service"] = row["service"].strip()
        findings.append(NormalizedFinding(
            scan_id=new_id("import"), project_id=project_id,
            source=FindingSource("passive-import", row.get("source", "passive").strip(), channel=Channel.PASSIVE),
            target=target, category=Category.ASSET, title=f"被动发现资产 {target}", severity=Severity.INFO,
            confidence=Confidence.FIRM, collected_at=utcnow(), details=details))
    stored = facts.add_findings(findings)
    result.imported = len(stored)
    result.assets = len({f.details.get("host") for f in stored})
    result.finding_ids = [f.finding_id for f in stored]
    return result


# —— .nessus 导入 ——
def _severity_from_nessus(num: str) -> Severity:
    return {"0": Severity.INFO, "1": Severity.LOW, "2": Severity.MEDIUM, "3": Severity.HIGH,
            "4": Severity.CRITICAL}.get(str(num).strip(), Severity.INFO)


def _safe_parse(xml_text: str):
    if "<!DOCTYPE" in xml_text or "<!ENTITY" in xml_text:
        raise ImportError_("出于安全考虑拒绝包含 DOCTYPE / ENTITY 的 XML（防 XXE / 实体膨胀）")
    try:
        from defusedxml.ElementTree import fromstring  # noqa: PLC0415
    except ImportError:  # 回退：标准库解析器对已过滤 DOCTYPE 的文本（上面已拦截实体）
        from xml.etree.ElementTree import fromstring  # noqa: PLC0415, S405
    return fromstring(xml_text)


def import_nessus(facts: FactStore, project_id: str, source, *, policy: ScopePolicy | None = None) -> ImportResult:
    """解析 .nessus (Nessus v2) 报告，导入为 channel=import 的发现，与主动扫描同一问题合并。"""
    xml_text = source if isinstance(source, str) and source.lstrip().startswith("<") \
        else Path(source).read_text(encoding="utf-8")
    root = _safe_parse(xml_text)
    result = ImportResult(channel="import")
    scan_id = new_id("import")
    findings = []
    for host_node in root.iter("ReportHost"):
        host = host_node.get("name", "").strip()
        if not host:
            continue
        if not _in_scope(policy, host):
            result.skipped.append({"value": host, "reason": "out_of_scope"})
            continue
        for item in host_node.iter("ReportItem"):
            sev = _severity_from_nessus(item.get("severity", "0"))
            port = item.get("port", "0")
            plugin = item.get("pluginID", "")
            name = item.get("pluginName", "finding")
            cves = [e.text.strip().upper() for e in item.iter("cve") if e.text]
            target = f"{host}:{port}" if port and port != "0" else host
            findings.append(NormalizedFinding(
                scan_id=scan_id, project_id=project_id,
                source=FindingSource("nessus-import", "nessus", channel=Channel.IMPORT),
                target=target, category=Category.VULNERABILITY if sev.rank > 0 else Category.ASSET,
                title=name, severity=sev, confidence=Confidence.FIRM, cve=cves, collected_at=utcnow(),
                details={"rule_id": f"nessus-{plugin}", "port": int(port) if port.isdigit() else 0,
                         "host": host, "imported": True}))
    stored = facts.add_findings(findings)
    result.imported = len(stored)
    result.finding_ids = [f.finding_id for f in stored]
    return result
