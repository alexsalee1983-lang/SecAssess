"""Scope Gate 授权闸门（§8.3），fail-closed。

- 主动动作前校验：IP/域白名单、授权有效期、RoE 扫描类型、免扫清单（优先）；
- 任一目标越界 → 整体拒绝（策略可改为转 HITL）；
- 侵入式/对外/deep/脆弱资产/窗口外/超速率/高权限凭证 → 转 HITL；
- 通过后签发限时 HMAC scope_token，绑定 项目 + 扫描类型 + 目标集合。
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import ipaddress
import json
import secrets
from dataclasses import dataclass, field
from datetime import datetime, time, timedelta
from typing import Callable
from zoneinfo import ZoneInfo

from ..models import IntrusiveLevel, RateLimit, ScanRequest, ScanType, to_datetime, utcnow
from .hitl import ApprovalError, ApprovalQueue


class ScopeViolation(PermissionError):
    pass


IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network


def as_network(value: str) -> IPNetwork | None:
    try:
        return ipaddress.ip_network(value, strict=False)
    except ValueError:
        return None


def target_host(target: str) -> str:
    """把目标规范为可比较的主机标识：IP/CIDR 原样（规范化），URL/host:port/邮件取主机部分。"""
    t = str(target).strip()
    net = as_network(t)
    if net is not None:
        return str(net) if "/" in t else str(net.network_address)
    if "://" in t:
        t = t.split("://", 1)[1]
    t = t.split("/", 1)[0]
    if "@" in t:
        t = t.rsplit("@", 1)[1]
    if t.startswith("[") and "]" in t:
        return t[1:t.index("]")].lower()
    if t.count(":") == 1:
        t = t.split(":", 1)[0]
    return t.lower().rstrip(".")


def within_targets(target: str, allowed: list[str]) -> bool:
    """target 是否落在 allowed 之内：同一主机、属于请求的网段，或是请求域名的子域。"""
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


def _domain_match(host: str, pattern: str) -> bool:
    pattern = pattern.lower().rstrip(".")
    if pattern.startswith("*."):
        base = pattern[2:]
        return host == base or host.endswith("." + base)
    return host == pattern


@dataclass
class TimeWindow:
    """维护窗口；days 中 0=周一。start > end 表示跨午夜。"""
    days: list[int] = field(default_factory=lambda: list(range(7)))
    start: str = "00:00"
    end: str = "23:59"
    tz: str = "UTC"

    def contains(self, when: datetime) -> bool:
        local = when.astimezone(ZoneInfo(self.tz))
        start, end, now = time.fromisoformat(self.start), time.fromisoformat(self.end), local.time()
        if start <= end:
            return local.weekday() in self.days and start <= now <= end
        if now >= start:
            return local.weekday() in self.days
        return (local.weekday() - 1) % 7 in self.days and now <= end


@dataclass
class ScopePolicy:
    """L0 ① 授权与交战规则。"""
    project_id: str
    authorization_ref: str
    allowed_cidrs: list[str] = field(default_factory=list)
    allowed_domains: list[str] = field(default_factory=list)
    excluded: list[str] = field(default_factory=list)
    valid_from: datetime | None = None
    valid_until: datetime | None = None
    windows: list[TimeWindow] = field(default_factory=list)
    max_rate: RateLimit = field(default_factory=RateLimit)
    allowed_scan_types: list[str] = field(default_factory=lambda: [s.value for s in ScanType])
    fragile_assets: list[str] = field(default_factory=list)
    elevated_credentials: list[str] = field(default_factory=list)
    out_of_scope_action: str = "deny"
    emergency_contacts: list[str] = field(default_factory=list)
    roe_notes: str = ""

    def __post_init__(self) -> None:
        if not self.authorization_ref:
            raise ValueError("authorization_ref（授权书编号）必填")
        self.valid_from, self.valid_until = to_datetime(self.valid_from), to_datetime(self.valid_until)
        self.windows = [w if isinstance(w, TimeWindow) else TimeWindow(**w) for w in self.windows]
        if isinstance(self.max_rate, dict):
            self.max_rate = RateLimit.from_dict(self.max_rate)
        for cidr in self.allowed_cidrs:
            ipaddress.ip_network(cidr, strict=False)  # 配置错误尽早暴露
        for st in self.allowed_scan_types:
            ScanType(st)
        if self.out_of_scope_action not in ("deny", "hitl"):
            raise ValueError("out_of_scope_action 只能是 deny 或 hitl")

    @classmethod
    def from_dict(cls, data: dict) -> "ScopePolicy":
        return cls(**data)

    def to_dict(self) -> dict:
        return {
            "project_id": self.project_id, "authorization_ref": self.authorization_ref,
            "allowed_cidrs": list(self.allowed_cidrs), "allowed_domains": list(self.allowed_domains),
            "excluded": list(self.excluded),
            "valid_from": self.valid_from.isoformat() if self.valid_from else None,
            "valid_until": self.valid_until.isoformat() if self.valid_until else None,
            "windows": [vars(w) for w in self.windows], "max_rate": self.max_rate.to_dict(),
            "allowed_scan_types": list(self.allowed_scan_types), "fragile_assets": list(self.fragile_assets),
            "elevated_credentials": list(self.elevated_credentials),
            "out_of_scope_action": self.out_of_scope_action,
            "emergency_contacts": list(self.emergency_contacts), "roe_notes": self.roe_notes,
        }

    @staticmethod
    def _overlaps(host: str, entries: list[str]) -> bool:
        """目标与清单中任一条目有交集（CIDR 部分重叠也算）。"""
        net = as_network(host)
        for entry in entries:
            enet = as_network(entry)
            if net is not None and enet is not None:
                if net.version == enet.version and net.overlaps(enet):
                    return True
            elif net is None and enet is None and _domain_match(host, entry):
                return True
        return False

    def is_excluded(self, target: str) -> bool:
        return self._overlaps(target_host(target), self.excluded)

    def is_fragile(self, target: str) -> bool:
        return self._overlaps(target_host(target), self.fragile_assets)

    def in_scope(self, target: str) -> bool:
        """目标必须完整落在某个授权网段/域之内。"""
        host = target_host(target)
        net = as_network(host)
        if net is not None:
            for cidr in self.allowed_cidrs:
                allowed = ipaddress.ip_network(cidr, strict=False)
                if net.version == allowed.version and net.subnet_of(allowed):
                    return True
            return False
        return any(_domain_match(host, d) for d in self.allowed_domains)


@dataclass
class Decision:
    allowed: bool
    needs_approval: bool = False
    token: str | None = None
    approval_id: str | None = None
    denials: list[str] = field(default_factory=list)
    hitl_reasons: list[str] = field(default_factory=list)

    @property
    def state(self) -> str:
        if self.allowed:
            return "allowed"
        return "pending_approval" if self.needs_approval else "denied"

    def view(self) -> dict:
        return {"state": self.state, "approval_id": self.approval_id,
                "denials": list(self.denials), "hitl_reasons": list(self.hitl_reasons)}


def build_action(*, project_id: str, targets: list[str], scan_type: ScanType | str, adapter: str,
                 intrusive_level: IntrusiveLevel | str, options: dict | None = None,
                 credential_ref: str | None = None, rate_limit: RateLimit | None = None) -> dict:
    """规范化动作描述：审批指纹与令牌都绑定它。"""
    return {
        "project_id": project_id, "targets": sorted(set(targets)), "scan_type": ScanType(scan_type).value,
        "adapter": adapter, "intrusive_level": IntrusiveLevel(intrusive_level).value,
        "options": dict(options or {}), "credential_ref": credential_ref,
        "rate_limit": (rate_limit or RateLimit()).to_dict(),
    }


class ScopeGate:
    def __init__(self, secret: bytes | None = None, *, approvals: ApprovalQueue | None = None,
                 token_ttl: timedelta = timedelta(hours=1), clock: Callable[[], datetime] = utcnow) -> None:
        self._secret = secret or secrets.token_bytes(32)
        self._clock = clock
        self.approvals = approvals or ApprovalQueue(clock=clock)
        self.token_ttl = token_ttl
        self._policies: dict[str, ScopePolicy] = {}
        self._revoked: set[str] = set()

    def set_policy(self, policy: ScopePolicy) -> None:
        self._policies[policy.project_id] = policy

    def remove_policy(self, project_id: str) -> None:
        self._policies.pop(project_id, None)

    def policy(self, project_id: str) -> ScopePolicy | None:
        return self._policies.get(project_id)

    def evaluate(self, action: dict) -> tuple[list[str], list[str]]:
        """返回 (拒绝原因, 需 HITL 的原因)。拒绝原因非空即不可执行。"""
        now = self._clock()
        policy = self._policies.get(action["project_id"])
        if policy is None:
            return [f"项目 {action['project_id']} 未配置授权范围"], []
        deny: list[str] = []
        hitl: list[str] = []
        if policy.valid_from and now < policy.valid_from:
            deny.append("授权尚未生效")
        if policy.valid_until and now > policy.valid_until:
            deny.append("授权已过期")
        if action["scan_type"] not in policy.allowed_scan_types:
            deny.append(f"RoE 不允许扫描类型 {action['scan_type']}")
        if not action["targets"]:
            deny.append("目标为空")
        level = IntrusiveLevel(action["intrusive_level"])
        for target in action["targets"]:
            if policy.is_excluded(target):
                deny.append(f"命中免扫清单: {target}")
            elif not policy.in_scope(target):
                (hitl if policy.out_of_scope_action == "hitl" else deny).append(f"超出授权范围: {target}")
            elif policy.is_fragile(target) and level != IntrusiveLevel.READONLY:
                hitl.append(f"脆弱/OT 资产主动探测: {target}")
        if level == IntrusiveLevel.EXTERNAL:
            hitl.append("对外动作")
        elif level == IntrusiveLevel.INTRUSIVE:
            hitl.append("侵入式动作")
        if action.get("options", {}).get("profile") == "deep":
            hitl.append("deep 扫描")
        if policy.windows and not any(w.contains(now) for w in policy.windows):
            hitl.append("维护窗口外执行")
        rate = action.get("rate_limit") or {}
        if rate.get("pps", 0) > policy.max_rate.pps or rate.get("concurrency", 0) > policy.max_rate.concurrency:
            hitl.append("超出约定速率")
        if action.get("credential_ref") and action["credential_ref"] in policy.elevated_credentials:
            hitl.append("使用高权限凭证")
        return deny, list(dict.fromkeys(hitl))

    def authorize(self, action: dict, *, requested_by: str, approval_id: str | None = None) -> Decision:
        deny, hitl = self.evaluate(action)
        if deny:
            return Decision(allowed=False, denials=deny, hitl_reasons=hitl, approval_id=approval_id)
        if hitl:
            if approval_id is None:
                item = self.approvals.request(project_id=action["project_id"], action=action,
                                              reasons=hitl, requested_by=requested_by)
                return Decision(allowed=False, needs_approval=True, approval_id=item.approval_id,
                                hitl_reasons=hitl)
            try:
                self.approvals.consume(approval_id, action)
            except ApprovalError as exc:
                return Decision(allowed=False, denials=[f"审批无效: {exc}"], hitl_reasons=hitl,
                                approval_id=approval_id)
        return Decision(allowed=True, token=self.issue_token(action, approval_id), approval_id=approval_id,
                        hitl_reasons=hitl)

    # —— 令牌 ——
    def issue_token(self, action: dict, approval_id: str | None = None) -> str:
        claims = {"pid": action["project_id"], "st": action["scan_type"], "tg": sorted(action["targets"]),
                  "exp": int((self._clock() + self.token_ttl).timestamp()), "jti": secrets.token_hex(8),
                  "apr": approval_id}
        body = base64.urlsafe_b64encode(json.dumps(claims, sort_keys=True).encode()).decode().rstrip("=")
        return f"{body}.{self._sign(body)}"

    def revoke(self, token: str) -> None:
        self._revoked.add(self._decode(token)["jti"])

    def verify(self, token: str, request: ScanRequest) -> dict:
        claims = self._decode(token)
        if claims["jti"] in self._revoked:
            raise ScopeViolation("scope_token 已吊销")
        if claims["exp"] < self._clock().timestamp():
            raise ScopeViolation("scope_token 已过期")
        if claims["pid"] != request.project_id:
            raise ScopeViolation("scope_token 项目不匹配")
        if claims["st"] != request.scan_type.value:
            raise ScopeViolation("scope_token 扫描类型不匹配")
        extra = set(request.targets) - set(claims["tg"])
        if extra:
            raise ScopeViolation(f"目标未被令牌覆盖: {sorted(extra)}")
        policy = self._policies.get(request.project_id)
        if policy is None:
            raise ScopeViolation("项目授权范围已撤销")
        for target in request.targets:  # 纵深防御：执行时再查免扫清单
            if policy.is_excluded(target):
                raise ScopeViolation(f"命中免扫清单: {target}")
        return claims

    def _sign(self, body: str) -> str:
        return hmac.new(self._secret, body.encode(), hashlib.sha256).hexdigest()

    def _decode(self, token: str) -> dict:
        if not isinstance(token, str) or "." not in token:
            raise ScopeViolation("scope_token 格式错误")
        body, sig = token.rsplit(".", 1)
        if not hmac.compare_digest(sig, self._sign(body)):
            raise ScopeViolation("scope_token 签名无效")
        return json.loads(base64.urlsafe_b64decode(body + "=" * (-len(body) % 4)))
