"""HITL 人工审批状态机（§8.2）：回路内硬闸门，模型与申请人都不能自行跳过。

状态：pending → approved | rejected | expired；approved → consumed（一次性兑现）。
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Callable

from ..models import new_id, utcnow


class ApprovalError(RuntimeError):
    pass


class ApprovalState:
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXPIRED = "expired"
    CONSUMED = "consumed"


def action_fingerprint(action: dict) -> str:
    """审批绑定到动作内容：任何字段被改动都会导致指纹不同。"""
    blob = json.dumps(action, sort_keys=True, ensure_ascii=False, default=str)
    return hashlib.sha256(blob.encode()).hexdigest()


@dataclass
class ApprovalRequest:
    approval_id: str
    project_id: str
    action: dict
    reasons: list[str]
    requested_by: str
    created_at: datetime
    expires_at: datetime
    fingerprint: str
    state: str = ApprovalState.PENDING
    decided_by: str | None = None
    decided_at: datetime | None = None
    comment: str = ""
    meta: dict = field(default_factory=dict)

    def view(self) -> dict:
        return {
            "approval_id": self.approval_id, "project_id": self.project_id, "action": self.action,
            "reasons": list(self.reasons), "requested_by": self.requested_by, "state": self.state,
            "created_at": self.created_at.isoformat(), "expires_at": self.expires_at.isoformat(),
            "decided_by": self.decided_by, "comment": self.comment,
            "decided_at": self.decided_at.isoformat() if self.decided_at else None,
        }


class ApprovalQueue:
    def __init__(self, ttl: timedelta = timedelta(hours=24), clock: Callable[[], datetime] = utcnow) -> None:
        self.ttl = ttl
        self._clock = clock
        self._items: dict[str, ApprovalRequest] = {}

    def request(self, *, project_id: str, action: dict, reasons: list[str], requested_by: str,
                meta: dict | None = None) -> ApprovalRequest:
        now = self._clock()
        item = ApprovalRequest(
            approval_id=new_id("apr"), project_id=project_id, action=action, reasons=list(reasons),
            requested_by=requested_by, created_at=now, expires_at=now + self.ttl,
            fingerprint=action_fingerprint(action), meta=dict(meta or {}))
        self._items[item.approval_id] = item
        return item

    def get(self, approval_id: str) -> ApprovalRequest:
        item = self._items.get(approval_id)
        if item is None:
            raise ApprovalError(f"未知审批单: {approval_id}")
        self._refresh(item)
        return item

    def list(self, project_id: str | None = None, state: str | None = None) -> list[ApprovalRequest]:
        out = []
        for item in self._items.values():
            self._refresh(item)
            if project_id not in (None, item.project_id) or state not in (None, item.state):
                continue
            out.append(item)
        return out

    def approve(self, approval_id: str, approver: str, comment: str = "") -> ApprovalRequest:
        return self._decide(approval_id, approver, ApprovalState.APPROVED, comment)

    def reject(self, approval_id: str, approver: str, comment: str = "") -> ApprovalRequest:
        return self._decide(approval_id, approver, ApprovalState.REJECTED, comment)

    def consume(self, approval_id: str, action: dict) -> ApprovalRequest:
        """兑现审批：必须已批准、未过期、未使用过，且动作与审批时完全一致。"""
        item = self.get(approval_id)
        if item.state != ApprovalState.APPROVED:
            raise ApprovalError(f"审批单状态为 {item.state}，不能执行")
        if item.fingerprint != action_fingerprint(action):
            raise ApprovalError("待执行动作与审批内容不一致")
        item.state = ApprovalState.CONSUMED
        return item

    def _decide(self, approval_id: str, approver: str, state: str, comment: str) -> ApprovalRequest:
        item = self.get(approval_id)
        if item.state != ApprovalState.PENDING:
            raise ApprovalError(f"审批单已是 {item.state}")
        if approver == item.requested_by:
            raise ApprovalError("职责分离：申请人不能审批自己的请求")
        item.state, item.decided_by, item.decided_at, item.comment = state, approver, self._clock(), comment
        return item

    def _refresh(self, item: ApprovalRequest) -> None:
        if item.state in (ApprovalState.PENDING, ApprovalState.APPROVED) and self._clock() >= item.expires_at:
            item.state = ApprovalState.EXPIRED
