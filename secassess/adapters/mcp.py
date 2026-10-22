"""通用 MCP 工具适配器（A 方案：运行时经 Scanner Adapter 调度外部 MCP server）。

最小 JSON-RPC 2.0 over stdio 客户端：initialize → notifications/initialized → tools/call，
期间把 notifications/progress 转成进度回调。不依赖 MCP SDK；子进程不经 shell 启动，
取消或超时时强制结束。

工具约定（可通过 normalizer 改写）：
- 入参 ``{"targets": [...], "options": {...}, "rate_limit": {...}, "credential"?: "..."}``
- 出参 structuredContent 或 text(JSON)：``{"findings": [{"target", "title", "severity", ...}]}``
"""
from __future__ import annotations

import asyncio
import itertools
import json
import shutil
from typing import Callable

from ..core.scope_gate import as_network, target_host
from ..models import (Capability, Category, Confidence, IntrusiveLevel, NormalizedFinding, ScanRequest,
                      ScanType, Severity)
from .base import AdapterError, ProgressCallback, ScannerAdapter

PROTOCOL_VERSION = "2025-06-18"
EvidenceSink = Callable[[str, bytes], str]  # (project_id, raw) -> evidence_ref


class MCPError(AdapterError):
    pass


def within_targets(target: str, allowed: list[str]) -> bool:
    """结果目标必须落在请求目标之内：同一主机、属于请求的网段，或是请求域名的子域。"""
    host = target_host(target)
    host_net = as_network(host)
    for item in allowed:
        allowed_host = target_host(item)
        if host == allowed_host or host.endswith("." + allowed_host):
            return True
        allowed_net = as_network(allowed_host)
        if (host_net is not None and allowed_net is not None and host_net.version == allowed_net.version
                and host_net.subnet_of(allowed_net)):
            return True
    return False


def default_normalizer(adapter: "MCPToolAdapter", request: ScanRequest, result: dict) -> list[NormalizedFinding]:
    payload = result.get("structuredContent")
    if payload is None:
        text = "".join(c.get("text", "") for c in result.get("content", []) if c.get("type") == "text")
        try:
            payload = json.loads(text or "{}")
        except json.JSONDecodeError as exc:
            raise MCPError(f"工具输出不是 JSON: {exc}") from None
    items = payload.get("findings", []) if isinstance(payload, dict) else payload
    findings = []
    for item in items or []:
        target = str(item.get("target", ""))
        if not target or not within_targets(target, request.targets):
            adapter.dropped += 1  # 越界结果一律丢弃，不进事实源
            continue
        findings.append(adapter.finding(
            request, target=target, category=Category(item.get("category", adapter.default_category.value)),
            title=str(item.get("title", "untitled"))[:500], severity=Severity(item.get("severity", "info")),
            confidence=Confidence(item.get("confidence", "tentative")), cve=list(item.get("cve", [])),
            remediation=item.get("remediation"), details=dict(item.get("details", {}))))
    return findings


Normalizer = Callable[["MCPToolAdapter", ScanRequest, dict], list[NormalizedFinding]]


class MCPToolAdapter(ScannerAdapter):
    def __init__(self, name: str, command: list[str], tool_name: str, *, scan_types: set[ScanType | str],
                 engine: str | None = None, engine_version: str = "unknown",
                 intrusive_level: IntrusiveLevel | str = IntrusiveLevel.SAFE, needs_credential: bool = False,
                 default_category: Category | str = Category.VULNERABILITY,
                 normalizer: Normalizer = default_normalizer, vault=None,
                 evidence_sink: EvidenceSink | None = None) -> None:
        if not command:
            raise ValueError("command 不能为空")
        self.name, self.command, self.tool_name = name, list(command), tool_name
        self._capability = Capability(
            engine=engine or tool_name, scan_types=frozenset(ScanType(s) for s in scan_types),
            needs_credential=needs_credential, intrusive_level=IntrusiveLevel(intrusive_level),
            engine_version=engine_version)
        self.default_category = Category(default_category)
        self.normalizer, self.vault, self.evidence_sink = normalizer, vault, evidence_sink
        self.dropped = 0
        self.last_process: asyncio.subprocess.Process | None = None

    def capability(self) -> Capability:
        return self._capability

    def available(self) -> bool:
        return shutil.which(self.command[0]) is not None

    async def scan(self, request: ScanRequest, on_progress: ProgressCallback) -> list[NormalizedFinding]:
        arguments: dict = {"targets": list(request.targets), "options": dict(request.options),
                           "rate_limit": request.rate_limit.to_dict()}
        if request.credential_ref:
            if self.vault is None:
                raise MCPError("请求带有凭证引用，但适配器未配置 Vault")
            arguments["credential"] = self.vault.resolve(request.credential_ref).reveal()
        result = await self.call_tool(arguments, on_progress)
        if result.get("isError"):
            text = "".join(c.get("text", "") for c in result.get("content", []) if c.get("type") == "text")
            raise MCPError(f"MCP 工具报错: {text[:500]}")
        findings = self.normalizer(self, request, result)
        if self.evidence_sink is not None:
            raw = json.dumps(result, ensure_ascii=False, sort_keys=True).encode()
            ref = self.evidence_sink(request.project_id, raw)
            for f in findings:
                f.raw_ref = f.raw_ref or ref
                f.evidence_ref = f.evidence_ref or ref
        return findings

    async def call_tool(self, arguments: dict, on_progress: ProgressCallback | None = None) -> dict:
        if not self.available():
            raise MCPError(f"MCP server 不可用: {self.command[0]}")
        proc = await asyncio.create_subprocess_exec(
            *self.command, stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL)
        self.last_process = proc
        ids = itertools.count(1)

        async def send(message: dict) -> None:
            assert proc.stdin is not None
            proc.stdin.write((json.dumps({"jsonrpc": "2.0", **message}) + "\n").encode())
            await proc.stdin.drain()

        async def call(method: str, params: dict) -> dict:
            request_id = next(ids)
            await send({"id": request_id, "method": method, "params": params})
            assert proc.stdout is not None
            while True:
                line = await proc.stdout.readline()
                if not line:
                    raise MCPError(f"MCP server 提前退出（{method}）")
                try:
                    message = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if message.get("method") == "notifications/progress":
                    if on_progress is not None:
                        params_ = message.get("params", {})
                        total = params_.get("total") or 0
                        fraction = float(params_.get("progress", 0)) / float(total) if total else 0.0
                        on_progress(fraction, str(params_.get("message", "")))
                    continue
                if message.get("id") != request_id:
                    continue
                if "error" in message:
                    raise MCPError(f"{method} 失败: {message['error'].get('message')}")
                return message.get("result", {})

        try:
            await call("initialize", {"protocolVersion": PROTOCOL_VERSION, "capabilities": {},
                                      "clientInfo": {"name": "secassess", "version": "0.3.0"}})
            await send({"method": "notifications/initialized"})
            return await call("tools/call", {"name": self.tool_name, "arguments": arguments,
                                             "_meta": {"progressToken": "secassess"}})
        finally:
            if proc.stdin is not None and not proc.stdin.is_closing():
                proc.stdin.close()
            if proc.returncode is None:
                proc.kill()
            await proc.wait()
