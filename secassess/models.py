"""核心契约（§6）：ScanRequest / NormalizedFinding —— 单一事实源。

所有主动动作的入参是 ScanRequest；所有适配器输出归一化为 NormalizedFinding。仅依赖标准库。
"""
from __future__ import annotations

import enum
import hashlib
import json
import re
import uuid
from dataclasses import dataclass, field, fields
from datetime import datetime, timezone
from typing import Any


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def new_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:16]}"


def to_datetime(value: Any) -> datetime | None:
    if value is None or isinstance(value, datetime):
        return value
    dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


class ScanType(str, enum.Enum):
    PORT_DISCOVERY = "port_discovery"
    VULN = "vuln"
    CONFIG_BASELINE = "config_baseline"
    EXPOSURE = "exposure"
    WEB = "web"
    PHISHING = "phishing"


class Category(str, enum.Enum):
    ASSET = "asset"
    VULNERABILITY = "vulnerability"
    MISCONFIG = "misconfig"
    EXPOSURE = "exposure"
    COMPLIANCE = "compliance"


class Severity(str, enum.Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def rank(self) -> int:
        return ["info", "low", "medium", "high", "critical"].index(self.value)


class Confidence(str, enum.Enum):
    CONFIRMED = "confirmed"
    FIRM = "firm"
    TENTATIVE = "tentative"

    @property
    def rank(self) -> int:
        return ["tentative", "firm", "confirmed"].index(self.value)


class Channel(str, enum.Enum):
    ACTIVE_SCAN = "active_scan"
    CMDB = "cmdb"
    CLOUD_API = "cloud_api"
    PASSIVE = "passive"
    MANUAL = "manual"
    IMPORT = "import"  # ⑤ 既有安全数据导入（历史扫描结果、SBOM 等）


class IntrusiveLevel(str, enum.Enum):
    """动作侵入等级，Scope Gate 据此决定是否需要 HITL。"""
    READONLY = "readonly"
    SAFE = "safe"
    INTRUSIVE = "intrusive"
    EXTERNAL = "external"

    @property
    def rank(self) -> int:
        return ["readonly", "safe", "intrusive", "external"].index(self.value)


class FindingStatus(str, enum.Enum):
    """L0 ⑥ 人工复核闭环。"""
    OPEN = "open"
    FALSE_POSITIVE = "false_positive"
    ACCEPTED = "accepted"
    REMEDIATED = "remediated"           # 声称已整改，待复测
    VERIFIED_FIXED = "verified_fixed"   # 复测确认已修复


@dataclass(frozen=True)
class RateLimit:
    pps: int = 1000
    concurrency: int = 50

    def to_dict(self) -> dict:
        return {"pps": self.pps, "concurrency": self.concurrency}

    @classmethod
    def from_dict(cls, data: dict | None) -> "RateLimit":
        data = data or {}
        return cls(pps=int(data.get("pps", 1000)), concurrency=int(data.get("concurrency", 50)))


_BAD_TARGET = re.compile(r"[\s;|&`$<>\\'\"]")


@dataclass
class ScanRequest:
    """统一入参（§6.2）。"""
    targets: list[str]
    scan_type: ScanType
    scope_token: str
    credential_ref: str | None = None
    options: dict = field(default_factory=dict)
    rate_limit: RateLimit = field(default_factory=RateLimit)
    scan_id: str = field(default_factory=lambda: new_id("scan"))
    project_id: str = "default"

    def __post_init__(self) -> None:
        self.scan_type = ScanType(self.scan_type)
        if isinstance(self.rate_limit, dict):
            self.rate_limit = RateLimit.from_dict(self.rate_limit)
        self.targets = [str(t).strip() for t in self.targets if str(t).strip()]
        if not self.targets:
            raise ValueError("targets 不能为空")
        for t in self.targets:
            # 目标会被传给外部引擎：拒绝可能被解析为参数或 shell 片段的值
            if t.startswith("-") or _BAD_TARGET.search(t):
                raise ValueError(f"非法目标: {t!r}")
        if not self.scope_token:
            raise ValueError("scope_token 必填：无令牌不执行")
        if self.credential_ref is not None and not self.credential_ref.startswith("vault://"):
            raise ValueError("credential_ref 只能是 vault:// 引用，禁止传递明文凭证")


@dataclass
class FindingSource:
    adapter: str
    engine: str
    engine_version: str = "unknown"
    channel: Channel = Channel.ACTIVE_SCAN

    def __post_init__(self) -> None:
        self.channel = Channel(self.channel)

    def to_dict(self) -> dict:
        return {"adapter": self.adapter, "engine": self.engine,
                "engine_version": self.engine_version, "channel": self.channel.value}


@dataclass
class CVSS:
    version: str
    score: float
    vector: str = ""


@dataclass
class NormalizedFinding:
    """单一事实源契约（§6.3）。"""
    scan_id: str
    source: FindingSource
    target: str
    category: Category
    title: str
    severity: Severity
    asset_ref: str | None = None
    cvss: CVSS | None = None
    cve: list[str] = field(default_factory=list)
    confidence: Confidence = Confidence.TENTATIVE
    evidence_ref: str | None = None
    collected_at: datetime = field(default_factory=utcnow)
    raw_ref: str | None = None
    remediation: str | None = None
    # 扩展字段：去重、复核与追溯
    finding_id: str = field(default_factory=lambda: new_id("fnd"))
    project_id: str = "default"
    details: dict = field(default_factory=dict)
    status: FindingStatus = FindingStatus.OPEN
    risk_score: float | None = None  # 0-100，由风险评分模型计算
    sources: list[FindingSource] = field(default_factory=list)  # 佐证来源（多源合并后累积）
    first_seen: datetime | None = None
    last_seen: datetime | None = None

    def __post_init__(self) -> None:
        if isinstance(self.source, dict):
            self.source = FindingSource(**self.source)
        if isinstance(self.cvss, dict):
            self.cvss = CVSS(**self.cvss)
        self.category = Category(self.category)
        self.severity = Severity(self.severity)
        self.confidence = Confidence(self.confidence)
        self.status = FindingStatus(self.status)
        self.collected_at = to_datetime(self.collected_at) or utcnow()
        self.first_seen = to_datetime(self.first_seen) or self.collected_at
        self.last_seen = to_datetime(self.last_seen) or self.collected_at
        self.sources = [FindingSource(**s) if isinstance(s, dict) else s for s in self.sources] or [self.source]
        self.cve = sorted({c.upper() for c in self.cve})

    @property
    def fingerprint(self) -> str:
        """同一资产上的同一问题，与引擎无关。"""
        rule = self.details.get("rule_id") or ",".join(self.cve) or self.title.strip().lower()
        material = "|".join([self.project_id, self.target.strip().lower(), self.category.value,
                             str(self.details.get("port", "")), str(rule)])
        return hashlib.sha256(material.encode()).hexdigest()[:24]

    def to_dict(self) -> dict:
        return {
            "finding_id": self.finding_id, "scan_id": self.scan_id, "project_id": self.project_id,
            "source": self.source.to_dict(), "asset_ref": self.asset_ref, "target": self.target,
            "category": self.category.value, "title": self.title, "severity": self.severity.value,
            "cvss": vars(self.cvss) if self.cvss else None, "cve": list(self.cve),
            "confidence": self.confidence.value, "evidence_ref": self.evidence_ref,
            "collected_at": self.collected_at.isoformat(), "raw_ref": self.raw_ref,
            "remediation": self.remediation, "details": self.details, "status": self.status.value,
            "risk_score": self.risk_score,
            "sources": [s.to_dict() for s in self.sources], "fingerprint": self.fingerprint,
            "first_seen": self.first_seen.isoformat(), "last_seen": self.last_seen.isoformat(),
        }

    @classmethod
    def from_dict(cls, data: dict) -> "NormalizedFinding":
        names = {f.name for f in fields(cls)}
        return cls(**{k: v for k, v in data.items() if k in names})

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False, sort_keys=True)


@dataclass(frozen=True)
class Capability:
    engine: str
    scan_types: frozenset
    needs_credential: bool = False
    intrusive_level: IntrusiveLevel = IntrusiveLevel.SAFE
    engine_version: str = "unknown"

    def to_dict(self) -> dict:
        return {"engine": self.engine, "scan_types": sorted(s.value for s in self.scan_types),
                "needs_credential": self.needs_credential,
                "intrusive_level": self.intrusive_level.value, "engine_version": self.engine_version}
