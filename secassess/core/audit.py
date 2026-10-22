"""横切② Audit Log：全程留痕（谁·何时·对谁·做了什么·依据），哈希链防篡改。"""
from __future__ import annotations

import hashlib
import json
import sqlite3
import threading

from ..models import utcnow

GENESIS = "0" * 64
_FIELDS = ("ts", "actor", "action", "project_id", "target", "detail", "basis")


class AuditLog:
    def __init__(self, path: str = ":memory:") -> None:
        self._db = sqlite3.connect(path, check_same_thread=False)
        self._lock = threading.Lock()
        self._db.execute(
            "CREATE TABLE IF NOT EXISTS audit (seq INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT, actor TEXT, "
            "action TEXT, project_id TEXT, target TEXT, detail TEXT, basis TEXT, prev_hash TEXT, hash TEXT)")
        self._db.commit()

    def record(self, *, actor: str, action: str, project_id: str = "", target: str = "",
               detail: dict | None = None, basis: str = "") -> dict:
        entry = {"ts": utcnow().isoformat(), "actor": actor, "action": action, "project_id": project_id,
                 "target": str(target)[:2000], "basis": basis,
                 "detail": json.dumps(detail or {}, ensure_ascii=False, sort_keys=True, default=str)}
        with self._lock:
            row = self._db.execute("SELECT hash FROM audit ORDER BY seq DESC LIMIT 1").fetchone()
            prev = row[0] if row else GENESIS
            digest = self._digest(prev, entry)
            cur = self._db.execute(
                "INSERT INTO audit (ts, actor, action, project_id, target, detail, basis, prev_hash, hash) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)", (*[entry[f] for f in _FIELDS], prev, digest))
            self._db.commit()
        return {"seq": cur.lastrowid, **entry, "detail": detail or {}, "prev_hash": prev, "hash": digest}

    def entries(self, project_id: str | None = None, limit: int = 500) -> list[dict]:
        sql = "SELECT seq, ts, actor, action, project_id, target, detail, basis, prev_hash, hash FROM audit"
        args: tuple = ()
        if project_id is not None:
            sql, args = sql + " WHERE project_id = ?", (project_id,)
        rows = self._db.execute(sql + " ORDER BY seq DESC LIMIT ?", (*args, limit)).fetchall()
        out = []
        for row in rows:
            item = dict(zip(("seq", "ts", "actor", "action", "project_id", "target", "detail", "basis",
                             "prev_hash", "hash"), row, strict=True))
            item["detail"] = json.loads(item["detail"])
            out.append(item)
        return out

    def verify_chain(self) -> bool:
        prev = GENESIS
        for row in self._db.execute(f"SELECT {', '.join(_FIELDS)}, prev_hash, hash FROM audit ORDER BY seq"):
            entry = dict(zip(_FIELDS, row[:7], strict=True))
            if row[7] != prev or row[8] != self._digest(prev, entry):
                return False
            prev = row[8]
        return True

    @staticmethod
    def _digest(prev: str, entry: dict) -> str:
        return hashlib.sha256((prev + json.dumps(entry, sort_keys=True, ensure_ascii=False)).encode()).hexdigest()
