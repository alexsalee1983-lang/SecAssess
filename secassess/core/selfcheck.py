"""平台自身基线自检（M5 出口）：对平台自身配置做 CIS 风格的基线自评。

对标架构红线：授权 fail-closed、审计可追溯、职责分离、凭证不落明文、多租户隔离、内容经审查。
硬控制（severity=high）任一不通过则整体不达标；warn 级仅提示。只读、确定性，不改动任何状态。
"""
from __future__ import annotations

import os

from ..models import ScanRequest
from .rbac import MATRIX, Permission, Role


def _check(cid, title, severity, passed, detail):
    return {"id": cid, "title": title, "severity": severity, "passed": bool(passed), "detail": detail}


def _credentials_are_references() -> bool:
    """契约应拒绝明文凭证（只接受 vault:// 引用）。"""
    try:
        ScanRequest(targets=["192.0.2.1"], scan_type="port_discovery", scope_token="t",
                    credential_ref="plaintext-secret")
    except ValueError:
        return True
    return False


def _targets_sanitized() -> bool:
    try:
        ScanRequest(targets=["192.0.2.1; rm -rf /"], scan_type="port_discovery", scope_token="t")
    except ValueError:
        return True
    return False


def run_self_check(platform) -> dict:
    sep = (Permission.SCAN not in MATRIX[Role.APPROVER]
           and Permission.APPROVE not in MATRIX[Role.ASSESSOR]
           and MATRIX[Role.CLIENT] == frozenset({Permission.VIEW}))
    mock_adapters = [a["name"] for a in platform.registry.describe() if a["name"].startswith("mock-")]
    unreviewed = platform.content.list(status="candidate")
    checks = [
        _check("gate_fail_closed", "授权 fail-closed：无令牌不执行", "high",
               platform.jobs.verifier is not None, "JobManager 已绑定 Scope Gate 令牌校验器"),
        _check("audit_integrity", "审计日志哈希链完整", "high",
               platform.audit.verify_chain(), "审计链校验通过"),
        _check("rbac_separation_of_duties", "RBAC 职责分离", "high", sep,
               "审批人不可发起扫描、评估员不可审批、客户只读"),
        _check("credentials_are_references", "凭证只传 vault:// 引用，禁止明文", "high",
               _credentials_are_references(), "ScanRequest 拒绝明文凭证"),
        _check("targets_sanitized", "扫描目标经校验，防参数/命令注入", "high",
               _targets_sanitized(), "ScanRequest 拒绝含 shell 元字符的目标"),
        _check("tenant_isolation", "多租户隔离已启用", "high",
               hasattr(platform, "tenants") and platform.tenants is not None, "TenantRegistry 已装配"),
        _check("token_secret_persistent", "scope_token 签名密钥持久化", "warn",
               bool(os.environ.get("SECASSESS_SECRET")),
               "建议设置 SECASSESS_SECRET，否则令牌随重启失效"),
        _check("engines_vetted", "生产应使用经封装/审查的真实引擎", "warn",
               not mock_adapters, f"当前注册的 mock 适配器: {mock_adapters or '无'}"),
        _check("content_reviewed", "内容包均已过审查上线", "warn",
               not unreviewed, f"待审查内容包: {[p.key for p in unreviewed] or '无'}"),
    ]
    hard_failures = [c for c in checks if c["severity"] == "high" and not c["passed"]]
    warnings = [c for c in checks if c["severity"] == "warn" and not c["passed"]]
    return {"passed": not hard_failures, "hard_failures": [c["id"] for c in hard_failures],
            "warnings": [c["id"] for c in warnings], "checks": checks}
