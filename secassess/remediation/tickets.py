"""整改工单（缺口⑨）：从发现开工单、跟踪整改状态、与复测闭环联动。

本地后端用 SQLite 存储；对接真实 ITSM（Jira/ServiceNow 等）实现 TicketConnector 接口即可，
上层不变。工单按 project_id 隔离，一条发现同一时间只有一张未关闭工单（去重）。
"""
from __future__ import annotations

import abc
import enum
import json
import sqlite3
import threading
from dataclasses import dataclass, field

from ..models import NormalizedFinding, new_id, utcnow


class TicketStatus(str, enum.Enum):
    OPEN = "open"
    IN_PROGRESS = "in_progress"
    RESOLVED = "resolved"          # 声称已整改，待复测
    CLOSED = "closed"              # 复测确认并关闭
    WONT_FIX = "wont_fix"          # 风险接受 / 不修复

    @property
    def is_terminal(self) -> bool:
        return self in (TicketStatus.CLOSED, TicketStatus.WONT_FIX)


_ALLOWED = {
    TicketStatus.OPEN: {TicketStatus.IN_PROGRESS, TicketStatus.WONT_FIX, TicketStatus.RESOLVED},
    TicketStatus.IN_PROGRESS: {TicketStatus.RESOLVED, TicketStatus.WONT_FIX},
    TicketStatus.RESOLVED: {TicketStatus.CLOSED, TicketStatus.IN_PROGRESS},  # 复测通过→closed，回归→in_progress
    TicketStatus.CLOSED: set(),
    TicketStatus.WONT_FIX: set(),
}


class TicketError(RuntimeError):
    pass


@dataclass
class Ticket:
    ticket_id: str
    project_id: str
    finding_id: str
    title: str
    severity: str
    status: TicketStatus = TicketStatus.OPEN
    assignee: str | None = None
    external_ref: str | None = None          # ITSM 系统中的工单号
    notes: list[dict] = field(default_factory=list)
    created_at: str = field(default_factory=lambda: utcnow().isoformat())
    updated_at: str = field(default_factory=lambda: utcnow().isoformat())

    def to_dict(self) -> dict:
        d = {k: getattr(self, k) for k in ("ticket_id", "project_id", "finding_id", "title", "severity",
                                           "assignee", "external_ref", "notes", "created_at", "updated_at")}
        d["status"] = self.status.value
        return d

    @classmethod
    def from_row(cls, row) -> "Ticket":
        t = cls(ticket_id=row[0], project_id=row[1], finding_id=row[2], title=row[3], severity=row[4],
                status=TicketStatus(row[5]), assignee=row[6], external_ref=row[7],
                notes=json.loads(row[8]), created_at=row[9], updated_at=row[10])
        return t


class TicketConnector(abc.ABC):
    """ITSM 连接器接口：上层只认它。真实系统实现 create / update_status。"""

    @abc.abstractmethod
    def create(self, ticket: Ticket) -> str | None: ...

    @abc.abstractmethod
    def update_status(self, ticket: Ticket) -> None: ...


class LocalConnector(TicketConnector):
    """本地连接器：不对接外部系统，external_ref 用本地标识。"""

    def create(self, ticket: Ticket) -> str | None:
        return f"local/{ticket.ticket_id}"

    def update_status(self, ticket: Ticket) -> None:
        return None


class TicketStore:
    def __init__(self, path: str = ":memory:", connector: TicketConnector | None = None) -> None:
        self._db = sqlite3.connect(path, check_same_thread=False)
        self._lock = threading.RLock()
        self.connector = connector or LocalConnector()
        self._db.execute(
            "CREATE TABLE IF NOT EXISTS tickets (ticket_id TEXT PRIMARY KEY, project_id TEXT, finding_id TEXT, "
            "title TEXT, severity TEXT, status TEXT, assignee TEXT, external_ref TEXT, notes TEXT, "
            "created_at TEXT, updated_at TEXT)")
        self._db.commit()

    def open_from_finding(self, finding: NormalizedFinding, *, assignee: str | None = None) -> Ticket:
        with self._lock:
            existing = self._db.execute(
                "SELECT * FROM tickets WHERE project_id=? AND finding_id=? AND status NOT IN ('closed','wont_fix')",
                (finding.project_id, finding.finding_id)).fetchone()
            if existing:
                return Ticket.from_row(existing)
            ticket = Ticket(ticket_id=new_id("tkt"), project_id=finding.project_id, finding_id=finding.finding_id,
                            title=finding.title, severity=finding.severity.value, assignee=assignee)
            ticket.external_ref = self.connector.create(ticket)
            self._save(ticket)
        return ticket

    def get(self, ticket_id: str) -> Ticket | None:
        row = self._db.execute("SELECT * FROM tickets WHERE ticket_id=?", (ticket_id,)).fetchone()
        return Ticket.from_row(row) if row else None

    def list(self, project_id: str, *, status: str | None = None) -> list[Ticket]:
        sql, args = "SELECT * FROM tickets WHERE project_id=?", [project_id]
        if status:
            sql, args = sql + " AND status=?", [*args, status]
        return [Ticket.from_row(r) for r in self._db.execute(sql + " ORDER BY created_at", args)]

    def transition(self, ticket_id: str, target: TicketStatus, *, actor: str = "", note: str = "") -> Ticket:
        target = TicketStatus(target)
        with self._lock:
            ticket = self.get(ticket_id)
            if ticket is None:
                raise TicketError(f"工单不存在: {ticket_id}")
            if target not in _ALLOWED[ticket.status]:
                raise TicketError(f"非法工单状态跳转: {ticket.status.value} → {target.value}")
            ticket.status = target
            ticket.updated_at = utcnow().isoformat()
            if note or actor:
                ticket.notes.append({"at": ticket.updated_at, "actor": actor, "note": note,
                                     "status": target.value})
            self.connector.update_status(ticket)
            self._save(ticket)
        return ticket

    def _save(self, t: Ticket) -> None:
        self._db.execute(
            "INSERT OR REPLACE INTO tickets VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (t.ticket_id, t.project_id, t.finding_id, t.title, t.severity, t.status.value, t.assignee,
             t.external_ref, json.dumps(t.notes, ensure_ascii=False), t.created_at, t.updated_at))
        self._db.commit()
