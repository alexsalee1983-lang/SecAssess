"""内容更新流水线（缺口⑪）：引擎模板 / 合规框架 / MCP 封装等内容包的版本固定与上线审查。

对标架构供应链底线：开源引擎→自研封装，固定版本、过 CIS MCP Server Benchmark 审查后上线。
内容包必须 pin 到具体版本（禁止 latest），带 sha256 与来源；经审查闸门通过才标记 approved 可用。
"""
from __future__ import annotations

import abc
import enum
from dataclasses import dataclass, field

from ..models import utcnow


class PackKind(str, enum.Enum):
    TEMPLATES = "templates"       # 如 nuclei 模板集
    FRAMEWORK = "framework"       # 合规框架版本
    MCP_ADAPTER = "mcp_adapter"   # 引擎的 MCP 封装


class PackStatus(str, enum.Enum):
    CANDIDATE = "candidate"
    APPROVED = "approved"
    REJECTED = "rejected"


@dataclass
class ContentPack:
    name: str
    version: str
    kind: PackKind
    sha256: str
    source: str
    status: PackStatus = PackStatus.CANDIDATE
    review: dict | None = None
    registered_at: str = field(default_factory=lambda: utcnow().isoformat())

    @property
    def key(self) -> str:
        return f"{self.name}@{self.version}"

    def to_dict(self) -> dict:
        return {"name": self.name, "version": self.version, "kind": self.kind.value, "sha256": self.sha256,
                "source": self.source, "status": self.status.value, "review": self.review,
                "registered_at": self.registered_at}


@dataclass
class ReviewResult:
    passed: bool
    checks: list[dict]  # [{name, ok, detail}]

    def to_dict(self) -> dict:
        return {"passed": self.passed, "checks": list(self.checks)}


class ReviewGate(abc.ABC):
    @abc.abstractmethod
    def review(self, pack: ContentPack) -> ReviewResult: ...


class BenchmarkReviewGate(ReviewGate):
    """CIS MCP Server Benchmark 审查闸门的占位实现：做可离线判定的基线检查。

    真实基准接入后替换本类；上层通过 ReviewGate 接口调用，不受影响。
    """

    def review(self, pack: ContentPack) -> ReviewResult:
        checks = [
            {"name": "version_pinned", "ok": bool(pack.version) and pack.version.lower() != "latest",
             "detail": "版本必须固定，禁止 latest"},
            {"name": "sha256_present", "ok": len(pack.sha256) == 64,
             "detail": "必须提供 sha256 完整性校验值"},
            {"name": "source_declared", "ok": bool(pack.source),
             "detail": "必须声明来源（仓库/URL）"},
        ]
        return ReviewResult(passed=all(c["ok"] for c in checks), checks=checks)


class ContentRegistryError(RuntimeError):
    pass


class ContentRegistry:
    def __init__(self, gate: ReviewGate | None = None) -> None:
        self.gate = gate or BenchmarkReviewGate()
        self._packs: dict[str, ContentPack] = {}

    def register(self, pack: ContentPack) -> ContentPack:
        """登记候选内容包（幂等：同 name@version 覆盖候选，已 approved 的不可被候选覆盖）。"""
        existing = self._packs.get(pack.key)
        if existing and existing.status == PackStatus.APPROVED:
            raise ContentRegistryError(f"{pack.key} 已上线，不能重新登记为候选（请发新版本）")
        self._packs[pack.key] = pack
        return pack

    def submit_review(self, key: str) -> ContentPack:
        pack = self._get(key)
        result = self.gate.review(pack)
        pack.review = result.to_dict()
        pack.status = PackStatus.APPROVED if result.passed else PackStatus.REJECTED
        return pack

    def get(self, key: str) -> ContentPack | None:
        return self._packs.get(key)

    def list(self, *, kind: str | None = None, status: str | None = None) -> list[ContentPack]:
        packs = sorted(self._packs.values(), key=lambda p: (p.name, p.version))
        return [p for p in packs if kind in (None, p.kind.value) and status in (None, p.status.value)]

    def active(self, name: str) -> ContentPack | None:
        """某内容包当前已上线（approved）的最高版本。"""
        approved = [p for p in self._packs.values() if p.name == name and p.status == PackStatus.APPROVED]
        return max(approved, key=lambda p: p.version) if approved else None

    def _get(self, key: str) -> ContentPack:
        if key not in self._packs:
            raise ContentRegistryError(f"内容包不存在: {key}")
        return self._packs[key]
