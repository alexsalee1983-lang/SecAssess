"""规划器（L2 plan 阶段）：把评估人员的自然语言指令变成"下一步要做的动作"。

规划器只产出**提议**（PlannedStep）；是否执行由 Scope Gate / HITL 决定，规划器无法绕过。
接口是迭代式的：每轮根据已完成步骤的观察摘要，给出本轮要执行的步骤，返回空表示结束。
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from typing import Protocol

ALLOWED_AGENTS = ("asset", "vuln", "baseline")
ALLOWED_OPTIONS = {"profile": {"quick", "default", "deep"}}
MAX_TARGETS = 64


@dataclass
class PlannedStep:
    agent: str
    targets: list[str] | None = None  # None：由编排器从 Asset Graph 中取种子范围内已发现的资产
    options: dict = field(default_factory=dict)
    rationale: str = ""

    def to_dict(self) -> dict:
        return {"agent": self.agent, "targets": self.targets, "options": dict(self.options),
                "rationale": self.rationale}


@dataclass
class PlanContext:
    instruction: str
    project_id: str
    seeds: list[str]
    credential_ref: str | None = None
    completed: list[dict] = field(default_factory=list)  # 已完成步骤的观察摘要（不含原始发现）
    discovered: dict[str, int] = field(default_factory=dict)  # 种子范围内已发现的 asset / service 数量


@dataclass
class Plan:
    steps: list[PlannedStep]
    notes: list[str] = field(default_factory=list)
    planner: str = "rule"


class Planner(Protocol):
    name: str

    async def next_steps(self, ctx: PlanContext) -> Plan: ...


# —— 目标提取 ——
_IP = re.compile(r"(?<![\w.:/-])(\d{1,3}(?:\.\d{1,3}){3}(?:/\d{1,2})?(?::\d{1,5})?)(?![\w.-])", re.ASCII)
_URL = re.compile(r"https?://[A-Za-z0-9.\-]+(?::\d{1,5})?(?:/[^\s，。；、\"'<>]*)?")
_DOMAIN = re.compile(r"(?<![A-Za-z0-9.\-@/])((?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63})"
                     r"(?![A-Za-z0-9-])")


def extract_targets(text: str) -> list[str]:
    """从指令中提取 IP / CIDR / host:port / URL / 域名，保序去重。"""
    found: list[str] = []
    urls = _URL.findall(text)
    found += urls
    rest = _URL.sub(" ", text)
    for m in _IP.findall(rest):
        host = m.split(":")[0]
        try:
            ipaddress.ip_network(host, strict=False)
        except ValueError:
            continue
        found.append(m)
    rest = _IP.sub(" ", rest)
    found += [d.lower() for d in _DOMAIN.findall(rest)]
    return list(dict.fromkeys(found))


_KEYWORDS = {
    "asset": ("资产", "端口", "测绘", "存活", "asset", "port", "discover", "inventory"),
    "vuln": ("漏洞", "vuln", "cve"),
    "baseline": ("基线", "配置核查", "配置检查", "baseline", "hardening", "cis"),
    "deep": ("深度", "deep", "全端口"),
}
_FULL_STRONG = ("全面", "完整", "全量", "full", "comprehensive")  # 无论是否点名具体项，都做完整评估
_FULL_WEAK = ("评估", "assessment")                             # 只在没点名具体项时视为完整评估


def detect_intent(text: str) -> tuple[set[str], bool]:
    """返回（要执行的 agent 集合, 是否 deep）。什么都没识别到时默认只做资产测绘。"""
    lowered = text.lower()
    wanted = {agent for agent in ALLOWED_AGENTS if any(k in lowered for k in _KEYWORDS[agent])}
    if any(k in lowered for k in _FULL_STRONG) or (not wanted and any(k in lowered for k in _FULL_WEAK)):
        wanted = set(ALLOWED_AGENTS)
    deep = any(k in lowered for k in _KEYWORDS["deep"])
    return wanted or {"asset"}, deep


class RuleBasedPlanner:
    """确定性规划器：无 LLM 时的默认实现，也是 LLM 失败时的回退。"""
    name = "rule"

    async def next_steps(self, ctx: PlanContext) -> Plan:
        if not ctx.seeds:
            return Plan([], ["指令中没有识别到目标（IP / CIDR / 域名 / URL）"], self.name)
        wanted, deep = detect_intent(ctx.instruction)
        done = {c["agent"] for c in ctx.completed}
        options = {"profile": "deep"} if deep else {}
        notes: list[str] = []
        needs_discovery = bool(wanted & {"vuln", "baseline"}) and not ctx.discovered.get("service")
        if ("asset" in wanted or needs_discovery) and "asset" not in done:
            return Plan([PlannedStep("asset", list(ctx.seeds), options, "先做资产测绘，建立 Asset Graph")],
                        notes, self.name)
        steps = []
        if "vuln" in wanted and "vuln" not in done:
            if ctx.discovered.get("service"):
                steps.append(PlannedStep("vuln", None, {}, "对种子范围内已发现的服务做漏洞扫描"))
            else:
                notes.append("种子范围内没有发现服务，跳过漏洞扫描")
        if "baseline" in wanted and "baseline" not in done:
            if not ctx.credential_ref:
                notes.append("配置基线需要凭证引用（vault://...），已跳过")
            elif ctx.discovered.get("asset"):
                steps.append(PlannedStep("baseline", None, {}, "对已发现主机做认证基线核查"))
            else:
                notes.append("种子范围内没有发现主机，跳过配置基线")
        return Plan(steps, notes, self.name)


def sanitize_steps(steps: list[PlannedStep]) -> tuple[list[PlannedStep], list[str]]:
    """白名单校验：未知 agent / option 一律丢弃。任何规划器（含 LLM）的输出都要过这一关。"""
    clean, dropped = [], []
    for step in steps:
        if step.agent not in ALLOWED_AGENTS:
            dropped.append(f"丢弃未知 agent: {step.agent!r}")
            continue
        bad = {k: v for k, v in step.options.items() if v not in ALLOWED_OPTIONS.get(k, set())}
        if bad:
            dropped.append(f"丢弃非法选项: {bad}")
            continue
        if step.targets is not None and (not step.targets or len(step.targets) > MAX_TARGETS):
            dropped.append(f"丢弃目标数量异常的步骤: {step.agent}")
            continue
        clean.append(step)
    return clean, dropped
