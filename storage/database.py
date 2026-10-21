"""SQLite data-access layer.

* Every statement is parameterized (``?`` placeholders) — no string-built SQL
  with user data.
* Multi-statement writes go through :meth:`Database.transaction`, which uses
  ``BEGIN IMMEDIATE`` and rolls back on any exception.
* Schema versioning: ``schema_meta.schema_version``.  New versions add an
  entry to ``MIGRATIONS``; ``init_schema`` applies pending ones in order.
"""
from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator, Sequence

from core.config import CRITICALITY_LEVELS
from core.timeutil import utc_now_iso

SCHEMA_PATH = Path(__file__).with_name("schema.sql")
SCHEMA_VERSION = 1

# version -> list of SQL statements upgrading from version-1.
MIGRATIONS: dict[int, list[str]] = {}


class DatabaseError(RuntimeError):
    """Wraps sqlite3 errors with a readable message."""


class DuplicateImportError(DatabaseError):
    """Raised when the same vulnerability report is imported twice."""


def _j(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)


class Database:
    def __init__(self, path: str | Path, read_only: bool = False):
        self.path = str(path)
        try:
            if read_only:
                if not Path(self.path).exists():
                    raise DatabaseError(f"Database not found: {self.path}")
                self.conn = sqlite3.connect(f"file:{Path(self.path).resolve()}?mode=ro", uri=True,
                                            timeout=10, isolation_level=None, check_same_thread=False)
            else:
                if self.path != ":memory:":
                    Path(self.path).parent.mkdir(parents=True, exist_ok=True)
                self.conn = sqlite3.connect(self.path, timeout=10, isolation_level=None)
        except sqlite3.Error as exc:
            raise DatabaseError(f"Cannot open database {self.path}: {exc}") from exc
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA foreign_keys = ON")
        self._in_tx = False

    # ------------------------------------------------------------------ infra
    def close(self) -> None:
        self.conn.close()

    def __enter__(self) -> "Database":
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        if self._in_tx:  # nested use joins the outer transaction
            yield self.conn
            return
        self.conn.execute("BEGIN IMMEDIATE")
        self._in_tx = True
        try:
            yield self.conn
        except Exception:
            self.conn.execute("ROLLBACK")
            raise
        else:
            self.conn.execute("COMMIT")
        finally:
            self._in_tx = False

    def init_schema(self) -> int:
        try:
            self.conn.executescript(SCHEMA_PATH.read_text(encoding="utf-8"))
        except sqlite3.Error as exc:
            raise DatabaseError(f"Schema initialisation failed: {exc}") from exc
        row = self.conn.execute("SELECT value FROM schema_meta WHERE key='schema_version'").fetchone()
        current = int(row["value"]) if row else 0
        if current == 0:
            self.conn.execute(
                "INSERT INTO schema_meta(key, value) VALUES ('schema_version', ?)", (str(SCHEMA_VERSION),))
            return SCHEMA_VERSION
        for version in range(current + 1, SCHEMA_VERSION + 1):
            with self.transaction() as conn:
                for stmt in MIGRATIONS.get(version, []):
                    conn.execute(stmt)
                conn.execute("UPDATE schema_meta SET value=? WHERE key='schema_version'", (str(version),))
        return SCHEMA_VERSION

    def query(self, sql: str, params: Sequence[Any] = ()) -> list[dict[str, Any]]:
        try:
            return [dict(r) for r in self.conn.execute(sql, tuple(params)).fetchall()]
        except sqlite3.Error as exc:
            raise DatabaseError(f"Query failed: {exc}") from exc

    def _insert(self, table: str, row: dict[str, Any]) -> int:
        # table/column names come from code, never from user input.
        cols = ", ".join(row)
        marks = ", ".join("?" for _ in row)
        cur = self.conn.execute(f"INSERT INTO {table} ({cols}) VALUES ({marks})", tuple(row.values()))
        return int(cur.lastrowid)

    # ----------------------------------------------------------------- assets
    def upsert_asset(self, asset_id: str, criticality: str, hostname: str | None = None,
                     ip_address: str | None = None, description: str | None = None,
                     data_origin: str = "HOST", changed_at: str | None = None) -> None:
        if criticality not in CRITICALITY_LEVELS:
            raise ValueError(f"invalid criticality {criticality!r}")
        now = changed_at or utc_now_iso()
        with self.transaction() as conn:
            existing = conn.execute("SELECT criticality FROM assets WHERE asset_id=?", (asset_id,)).fetchone()
            if existing is None:
                conn.execute(
                    "INSERT INTO assets(asset_id, hostname, ip_address, criticality, description, data_origin, created_at, updated_at)"
                    " VALUES (?,?,?,?,?,?,?,?)",
                    (asset_id, hostname, ip_address, criticality, description, data_origin, now, now))
                conn.execute("INSERT INTO asset_criticality_history(asset_id, criticality, changed_at) VALUES (?,?,?)",
                             (asset_id, criticality, now))
            else:
                conn.execute(
                    "UPDATE assets SET hostname=COALESCE(?, hostname), ip_address=COALESCE(?, ip_address),"
                    " criticality=?, description=COALESCE(?, description), updated_at=? WHERE asset_id=?",
                    (hostname, ip_address, criticality, description, now, asset_id))
                if existing["criticality"] != criticality:
                    conn.execute("INSERT INTO asset_criticality_history(asset_id, criticality, changed_at) VALUES (?,?,?)",
                                 (asset_id, criticality, now))

    def get_asset(self, asset_id: str) -> dict[str, Any] | None:
        rows = self.query("SELECT * FROM assets WHERE asset_id=?", (asset_id,))
        return rows[0] if rows else None

    def list_assets(self) -> list[dict[str, Any]]:
        return self.query("SELECT * FROM assets ORDER BY asset_id")

    def criticality_history(self, asset_id: str) -> list[dict[str, Any]]:
        return self.query("SELECT * FROM asset_criticality_history WHERE asset_id=? ORDER BY changed_at, history_id",
                          (asset_id,))

    # ------------------------------------------------------------ assessments
    def insert_run(self, row: dict[str, Any]) -> int:
        with self.transaction():
            return self._insert("assessment_runs", row)

    def store_assessment(self, run: dict[str, Any], snapshot: dict[str, Any] | None,
                         results: list[dict[str, Any]]) -> int:
        """Atomically store a run, its snapshot and its check results."""
        with self.transaction():
            run_id = self._insert("assessment_runs", run)
            if snapshot is not None:
                self._insert("config_snapshots", {**snapshot, "run_id": run_id})
            for res in results:
                self._insert("check_results", {
                    "run_id": run_id, "asset_id": run["asset_id"], "check_id": res["check_id"],
                    "title": res["title"], "status": res["status"],
                    "collector_status": res.get("collector_status"),
                    "expected": res.get("expected"), "actual": _j(res.get("actual")),
                    "reason": res.get("reason"), "remediation": res.get("remediation"),
                    "evidence": _j(res.get("evidence")), "evidence_hash": res.get("evidence_hash"),
                })
            return run_id

    def get_run(self, run_id: int) -> dict[str, Any] | None:
        rows = self.query("SELECT * FROM assessment_runs WHERE run_id=?", (run_id,))
        return rows[0] if rows else None

    def previous_comparable_run(self, asset_id: str, before_run_id: int, data_origin: str) -> dict[str, Any] | None:
        rows = self.query(
            "SELECT * FROM assessment_runs WHERE asset_id=? AND run_id<? AND data_origin=?"
            " AND status IN ('COMPLETE','PARTIAL') ORDER BY run_id DESC LIMIT 1",
            (asset_id, before_run_id, data_origin))
        return rows[0] if rows else None

    def latest_successful_run(self, asset_id: str) -> dict[str, Any] | None:
        rows = self.query(
            "SELECT * FROM assessment_runs WHERE asset_id=? AND status IN ('COMPLETE','PARTIAL')"
            " ORDER BY run_id DESC LIMIT 1", (asset_id,))
        return rows[0] if rows else None

    def check_results(self, run_id: int) -> dict[str, dict[str, Any]]:
        out = {}
        for r in self.query("SELECT * FROM check_results WHERE run_id=? ORDER BY check_id", (run_id,)):
            r["actual"] = json.loads(r["actual"]) if r["actual"] else None
            r["evidence"] = json.loads(r["evidence"]) if r["evidence"] else None
            out[r["check_id"]] = r
        return out

    def snapshot(self, run_id: int) -> dict[str, Any] | None:
        rows = self.query("SELECT * FROM config_snapshots WHERE run_id=?", (run_id,))
        if not rows:
            return None
        row = rows[0]
        row["normalized_evidence"] = json.loads(row["normalized_evidence"])
        return row

    # ------------------------------------------------------------------ drift
    def insert_drift_events(self, events: list[dict[str, Any]]) -> list[int]:
        ids = []
        with self.transaction():
            for ev in events:
                row = dict(ev)
                for key in ("previous_value", "current_value"):
                    if key in row and row[key] is not None and not isinstance(row[key], str):
                        row[key] = _j(row[key])
                ids.append(self._insert("config_drift_events", row))
        return ids

    def drift_events(self, asset_id: str, since: str | None = None, until: str | None = None) -> list[dict[str, Any]]:
        sql = "SELECT * FROM config_drift_events WHERE asset_id=?"
        params: list[Any] = [asset_id]
        if since:
            sql += " AND detected_at>=?"
            params.append(since)
        if until:
            sql += " AND detected_at<=?"
            params.append(until)
        return self.query(sql + " ORDER BY detected_at, drift_id", params)

    def drift_events_for_run(self, run_id: int) -> list[dict[str, Any]]:
        return self.query("SELECT * FROM config_drift_events WHERE run_id=? ORDER BY drift_id", (run_id,))

    # -------------------------------------------------------- vulnerabilities
    def store_scan(self, scan: dict[str, Any], findings: list[dict[str, Any]]) -> int:
        try:
            with self.transaction():
                scan_id = self._insert("vulnerability_scans", scan)
                for f in findings:
                    row = dict(f)
                    row["cves"] = _j(sorted(set(row.get("cves") or [])))
                    self._insert("vulnerability_findings", {**row, "scan_id": scan_id, "asset_id": scan["asset_id"]})
                return scan_id
        except sqlite3.IntegrityError as exc:
            msg = str(exc)
            if "file_sha256" in msg or "source_report_id" in msg:
                raise DuplicateImportError(
                    "This report (same file hash or same Greenbone report id for this asset) was already imported") from exc
            raise DatabaseError(f"Could not store scan: {exc}") from exc

    def latest_scan(self, asset_id: str, at: str | None = None) -> dict[str, Any] | None:
        sql = "SELECT * FROM vulnerability_scans WHERE asset_id=?"
        params: list[Any] = [asset_id]
        if at:
            sql += " AND COALESCE(scan_ended_at, scan_started_at, imported_at)<=?"
            params.append(at)
        rows = self.query(sql + " ORDER BY COALESCE(scan_ended_at, scan_started_at, imported_at) DESC, scan_id DESC LIMIT 1",
                          params)
        return rows[0] if rows else None

    def get_scan(self, scan_id: int) -> dict[str, Any] | None:
        rows = self.query("SELECT * FROM vulnerability_scans WHERE scan_id=?", (scan_id,))
        return rows[0] if rows else None

    def findings_for_scan(self, scan_id: int) -> list[dict[str, Any]]:
        rows = self.query("SELECT * FROM vulnerability_findings WHERE scan_id=? ORDER BY finding_id", (scan_id,))
        for r in rows:
            r["cves"] = json.loads(r["cves"]) if r["cves"] else []
        return rows

    # ------------------------------------------------------------------- risk
    def insert_risk_score(self, row: dict[str, Any], explanations: list[dict[str, Any]]) -> int:
        row = dict(row)
        for key in ("weights", "components", "warnings"):
            if not isinstance(row.get(key), str):
                row[key] = _j(row.get(key))
        with self.transaction():
            score_id = self._insert("risk_scores", row)
            for ex in explanations:
                self._insert("risk_explanations", {**ex, "score_id": score_id, "kind": ex.get("kind", "SCORE"),
                                                   "created_at": row["calculated_at"]})
            return score_id

    def get_score(self, score_id: int) -> dict[str, Any] | None:
        rows = self.query("SELECT * FROM risk_scores WHERE score_id=?", (score_id,))
        if not rows:
            return None
        r = rows[0]
        for key in ("weights", "components", "warnings"):
            r[key] = json.loads(r[key]) if r[key] else None
        return r

    def previous_score(self, asset_id: str, before_score_id: int) -> dict[str, Any] | None:
        rows = self.query("SELECT score_id FROM risk_scores WHERE asset_id=? AND score_id<?"
                          " AND status IN ('COMPLETE','PARTIAL') AND score IS NOT NULL ORDER BY score_id DESC LIMIT 1",
                          (asset_id, before_score_id))
        return self.get_score(rows[0]["score_id"]) if rows else None

    def has_drift_baseline(self, asset_id: str, model_version: str, before_score_id: int) -> bool:
        rows = self.query("SELECT 1 FROM risk_drift_events WHERE asset_id=? AND model_version=? AND score_id<?"
                          " AND direction<>'NOT_COMPARABLE' LIMIT 1", (asset_id, model_version, before_score_id))
        return bool(rows)

    def insert_risk_drift(self, row: dict[str, Any], explanations: list[dict[str, Any]]) -> int:
        row = dict(row)
        if row.get("component_deltas") is not None and not isinstance(row["component_deltas"], str):
            row["component_deltas"] = _j(row["component_deltas"])
        with self.transaction():
            event_id = self._insert("risk_drift_events", row)
            for ex in explanations:
                self._insert("risk_explanations", {**ex, "score_id": row["score_id"], "drift_event_id": event_id,
                                                   "kind": "DRIFT", "created_at": row["detected_at"]})
            return event_id
