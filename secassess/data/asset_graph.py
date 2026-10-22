"""Asset Graph：资产/服务节点与关系边（SQLite，可替换为 Neo4j）。

节点 id 由 (项目, 类型, 规范化键) 决定，同一资产不同写法自动归并为同一节点。
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
import threading

from ..models import utcnow

NODE_KINDS = frozenset({"asset", "service", "identity", "credential"})
EDGE_KINDS = frozenset({"hosts", "reachable_to", "exploitable_via", "has_privilege", "trusts"})


def normalize_key(key: str) -> str:
    k = str(key).strip().lower()
    if "://" in k:
        k = k.split("://", 1)[1].split("/", 1)[0]
    return k.rstrip(".")


def node_id(project_id: str, kind: str, key: str) -> str:
    digest = hashlib.sha256(f"{project_id}|{kind}|{normalize_key(key)}".encode()).hexdigest()[:16]
    return f"{kind}:{digest}"


class AssetGraph:
    def __init__(self, path: str = ":memory:") -> None:
        self._db = sqlite3.connect(path, check_same_thread=False)
        self._lock = threading.RLock()
        self._db.executescript("""
            CREATE TABLE IF NOT EXISTS nodes (id TEXT PRIMARY KEY, project_id TEXT, kind TEXT, key TEXT,
                attrs TEXT, updated_at TEXT);
            CREATE TABLE IF NOT EXISTS edges (project_id TEXT, src TEXT, dst TEXT, kind TEXT, attrs TEXT,
                PRIMARY KEY (src, dst, kind));
        """)
        self._db.commit()

    def upsert_node(self, project_id: str, kind: str, key: str, attrs: dict | None = None) -> str:
        if kind not in NODE_KINDS:
            raise ValueError(f"未知节点类型: {kind}")
        nid = node_id(project_id, kind, key)
        with self._lock:
            row = self._db.execute("SELECT attrs FROM nodes WHERE id = ?", (nid,)).fetchone()
            merged = json.loads(row[0]) if row else {}
            merged.update({k: v for k, v in (attrs or {}).items() if v is not None})
            self._db.execute(
                "INSERT INTO nodes VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT(id) DO UPDATE SET "
                "attrs = excluded.attrs, updated_at = excluded.updated_at",
                (nid, project_id, kind, normalize_key(key), json.dumps(merged, ensure_ascii=False),
                 utcnow().isoformat()))
            self._db.commit()
        return nid

    def add_edge(self, project_id: str, src: str, dst: str, kind: str, attrs: dict | None = None) -> None:
        if kind not in EDGE_KINDS:
            raise ValueError(f"未知边类型: {kind}")
        with self._lock:
            self._db.execute("INSERT OR REPLACE INTO edges VALUES (?, ?, ?, ?, ?)",
                             (project_id, src, dst, kind, json.dumps(attrs or {}, ensure_ascii=False)))
            self._db.commit()

    def get_node(self, nid: str) -> dict | None:
        row = self._db.execute("SELECT id, project_id, kind, key, attrs FROM nodes WHERE id = ?", (nid,)).fetchone()
        return self._node(row) if row else None

    def nodes(self, project_id: str, kind: str | None = None) -> list[dict]:
        sql, args = "SELECT id, project_id, kind, key, attrs FROM nodes WHERE project_id = ?", [project_id]
        if kind:
            sql, args = sql + " AND kind = ?", [*args, kind]
        return [self._node(r) for r in self._db.execute(sql + " ORDER BY kind, key", args)]

    def edges(self, project_id: str, kind: str | None = None) -> list[dict]:
        sql, args = "SELECT src, dst, kind, attrs FROM edges WHERE project_id = ?", [project_id]
        if kind:
            sql, args = sql + " AND kind = ?", [*args, kind]
        rows = self._db.execute(sql, args)
        return [{"src": r[0], "dst": r[1], "kind": r[2], "attrs": json.loads(r[3])} for r in rows]

    @staticmethod
    def _node(row) -> dict:
        return {"id": row[0], "project_id": row[1], "kind": row[2], "key": row[3], "attrs": json.loads(row[4])}
