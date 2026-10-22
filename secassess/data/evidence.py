"""Evidence Store：NormalizedFinding 持久化、多源去重合并、原始证据内容寻址（SQLite，可替换）。"""
from __future__ import annotations

import hashlib
import json
import sqlite3
import threading

from ..models import NormalizedFinding, Severity, utcnow


class EvidenceIntegrityError(ValueError):
    pass


def merge(existing: NormalizedFinding, new: NormalizedFinding) -> NormalizedFinding:
    """同一指纹的发现合并：保留首见时间与人工复核状态，取较高置信度/严重性，累积佐证来源。"""
    if new.confidence.rank > existing.confidence.rank:
        existing.confidence = new.confidence
        existing.evidence_ref = new.evidence_ref or existing.evidence_ref
    if new.severity.rank > existing.severity.rank:
        existing.severity = new.severity
    existing.cvss = existing.cvss or new.cvss
    existing.cve = sorted(set(existing.cve) | set(new.cve))
    existing.remediation = existing.remediation or new.remediation
    existing.raw_ref = existing.raw_ref or new.raw_ref
    existing.evidence_ref = existing.evidence_ref or new.evidence_ref
    existing.asset_ref = existing.asset_ref or new.asset_ref
    existing.details = {**new.details, **existing.details}
    known = {json.dumps(s.to_dict(), sort_keys=True) for s in existing.sources}
    for source in new.sources:
        if json.dumps(source.to_dict(), sort_keys=True) not in known:
            existing.sources.append(source)
    existing.last_seen = max(existing.last_seen, new.collected_at)
    if new.risk_score is not None:
        existing.risk_score = max(existing.risk_score or 0.0, new.risk_score)
    existing.scan_id = new.scan_id
    return existing


class EvidenceStore:
    def __init__(self, path: str = ":memory:") -> None:
        self._db = sqlite3.connect(path, check_same_thread=False)
        self._lock = threading.RLock()
        self._db.executescript("""
            CREATE TABLE IF NOT EXISTS findings (
                finding_id TEXT PRIMARY KEY, project_id TEXT NOT NULL, fingerprint TEXT NOT NULL,
                category TEXT, severity TEXT, status TEXT, target TEXT, body TEXT NOT NULL);
            CREATE UNIQUE INDEX IF NOT EXISTS ux_findings_fp ON findings(project_id, fingerprint);
            CREATE TABLE IF NOT EXISTS scan_findings (
                scan_id TEXT, finding_id TEXT, PRIMARY KEY (scan_id, finding_id));
            CREATE TABLE IF NOT EXISTS evidence (
                ref TEXT PRIMARY KEY, project_id TEXT, media_type TEXT, sha256 TEXT, created_at TEXT, content BLOB);
        """)
        self._db.commit()

    # —— 原始证据 ——
    def put_raw(self, project_id: str, content: bytes | str, media_type: str = "text/plain") -> str:
        data = content.encode() if isinstance(content, str) else bytes(content)
        digest = hashlib.sha256(data).hexdigest()
        ref = f"evidence://{project_id}/{digest}"
        with self._lock:
            self._db.execute("INSERT OR IGNORE INTO evidence VALUES (?, ?, ?, ?, ?, ?)",
                             (ref, project_id, media_type, digest, utcnow().isoformat(), data))
            self._db.commit()
        return ref

    def get_raw(self, ref: str) -> tuple[bytes, str] | None:
        row = self._db.execute("SELECT content, media_type, sha256 FROM evidence WHERE ref = ?", (ref,)).fetchone()
        if row is None:
            return None
        content, media_type, digest = row
        if hashlib.sha256(content).hexdigest() != digest or not ref.endswith(digest):
            raise EvidenceIntegrityError(f"证据完整性校验失败: {ref}")
        return content, media_type

    # —— 发现 ——
    def add_findings(self, findings: list[NormalizedFinding]) -> list[NormalizedFinding]:
        stored: list[NormalizedFinding] = []
        with self._lock:
            for f in findings:
                row = self._db.execute("SELECT body FROM findings WHERE project_id = ? AND fingerprint = ?",
                                       (f.project_id, f.fingerprint)).fetchone()
                item = merge(NormalizedFinding.from_dict(json.loads(row[0])), f) if row else f
                self._save(item)
                self._db.execute("INSERT OR IGNORE INTO scan_findings VALUES (?, ?)", (f.scan_id, item.finding_id))
                stored.append(item)
            self._db.commit()
        return stored

    def update(self, finding: NormalizedFinding) -> None:
        with self._lock:
            self._save(finding)
            self._db.commit()

    def get(self, finding_id: str) -> NormalizedFinding | None:
        row = self._db.execute("SELECT body FROM findings WHERE finding_id = ?", (finding_id,)).fetchone()
        return NormalizedFinding.from_dict(json.loads(row[0])) if row else None

    def findings_for_scan(self, scan_id: str) -> list[NormalizedFinding]:
        rows = self._db.execute(
            "SELECT f.body FROM findings f JOIN scan_findings s ON s.finding_id = f.finding_id "
            "WHERE s.scan_id = ? ORDER BY f.target", (scan_id,)).fetchall()
        return [NormalizedFinding.from_dict(json.loads(r[0])) for r in rows]

    def query(self, project_id: str, *, category: str | None = None, status: str | None = None,
              min_severity: str | None = None, target: str | None = None) -> list[NormalizedFinding]:
        sql, args = "SELECT body FROM findings WHERE project_id = ?", [project_id]
        for column, value in (("category", category), ("status", status), ("target", target)):
            if value:
                sql += f" AND {column} = ?"
                args.append(value)
        items = [NormalizedFinding.from_dict(json.loads(r[0])) for r in self._db.execute(sql, args)]
        if min_severity:
            floor = Severity(min_severity).rank
            items = [f for f in items if f.severity.rank >= floor]
        items.sort(key=lambda f: (-(f.risk_score or 0.0), -f.severity.rank, f.category.value, f.target))
        return items

    def _save(self, f: NormalizedFinding) -> None:
        self._db.execute(
            "INSERT INTO findings VALUES (?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(finding_id) DO UPDATE SET "
            "severity = excluded.severity, status = excluded.status, body = excluded.body",
            (f.finding_id, f.project_id, f.fingerprint, f.category.value, f.severity.value, f.status.value,
             f.target, f.to_json()))
