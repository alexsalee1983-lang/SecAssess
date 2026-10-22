"""OpenAPI 静态审查适配器：只读解析 OpenAPI 文档，不发出任何网络请求。

从 options.spec（dict）或 options.spec_ref（evidence:// 或本地文件路径）读取规范，
检查常见设计缺陷：接口缺少安全要求、服务器使用明文 http、未声明任何认证方案。
"""
from __future__ import annotations

import json
from pathlib import Path

from ..models import Capability, Category, Confidence, IntrusiveLevel, ScanRequest, ScanType, Severity
from .base import AdapterError, ProgressCallback, ScannerAdapter

_HTTP_METHODS = {"get", "put", "post", "delete", "patch", "options", "head", "trace"}


class OpenAPIReviewAdapter(ScannerAdapter):
    name = "openapi-review"

    def __init__(self, evidence=None) -> None:
        self.evidence = evidence  # 可选：用于解析 options.spec_ref = evidence://...

    def capability(self) -> Capability:
        return Capability(engine="openapi-static-review", scan_types=frozenset({ScanType.WEB}),
                          intrusive_level=IntrusiveLevel.READONLY, engine_version="1")

    def _load_spec(self, request: ScanRequest) -> dict:
        spec = request.options.get("spec")
        if spec is None:
            ref = request.options.get("spec_ref")
            if not ref:
                raise AdapterError("需要 options.spec（dict）或 options.spec_ref")
            if ref.startswith("evidence://") and self.evidence is not None:
                raw = self.evidence.get_raw(ref)
                if raw is None:
                    raise AdapterError(f"证据不存在: {ref}")
                spec = json.loads(raw[0])
            else:
                spec = json.loads(Path(ref).read_text(encoding="utf-8"))
        if not isinstance(spec, dict):
            raise AdapterError("OpenAPI 规范必须是对象")
        return spec

    async def scan(self, request: ScanRequest, on_progress: ProgressCallback):
        spec = self._load_spec(request)
        base = request.targets[0]
        findings = []

        def add(rule, title, severity, detail):
            findings.append(self.finding(request, target=base, category=Category.VULNERABILITY, title=title,
                                         severity=severity, confidence=Confidence.FIRM,
                                         remediation="按 OpenAPI 安全最佳实践修复",
                                         details={"rule_id": rule, "static": True, **detail}))

        global_security = spec.get("security")
        schemes = (spec.get("components") or {}).get("securitySchemes") or {}
        if not schemes:
            add("OPENAPI-NO-AUTH-SCHEME", "未声明任何认证方案 (securitySchemes)", Severity.HIGH, {})
        for server in spec.get("servers", []):
            url = str(server.get("url", ""))
            if url.startswith("http://"):
                add("OPENAPI-CLEARTEXT-SERVER", f"服务器使用明文 http: {url}", Severity.MEDIUM, {"server": url})
        paths = spec.get("paths") or {}
        total = len(paths) or 1
        for i, (path, item) in enumerate(paths.items(), 1):
            for method, op in (item or {}).items():
                if method.lower() not in _HTTP_METHODS or not isinstance(op, dict):
                    continue
                effective = op.get("security", global_security)
                if not effective:  # None 或 []：无安全要求
                    add("OPENAPI-OP-NO-SECURITY", f"接口无安全要求: {method.upper()} {path}", Severity.HIGH,
                        {"path": path, "method": method.upper()})
            on_progress(i / total, f"检查 {path}")
        return findings
