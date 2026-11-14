"""DefenceIQ Database Layer — PostgreSQL (Neon/psycopg) with SQLite fallback & Append-Only Audit Triggers."""

from __future__ import annotations

import hashlib
import logging
import re
import sqlite3
import threading
from typing import Any, Iterator

from backend.config import get_settings

logger = logging.getLogger("defenceiq.db")

SQLITE_SCHEMA = """
CREATE TABLE IF NOT EXISTS alerts(
    id TEXT PRIMARY KEY,
    raw TEXT,
    status TEXT,
    severity TEXT,
    confidence REAL,
    report TEXT,
    incident_id TEXT,
    risk_score REAL,
    created_at REAL
);
CREATE TABLE IF NOT EXISTS audit(
    n INTEGER PRIMARY KEY AUTOINCREMENT,
    ts REAL,
    alert_id TEXT,
    agent TEXT,
    kind TEXT,
    msg TEXT,
    data TEXT,
    prev_hash TEXT,
    row_hash TEXT
);
CREATE TRIGGER IF NOT EXISTS audit_no_update BEFORE UPDATE ON audit
BEGIN SELECT RAISE(ABORT,'audit log is append-only'); END;
CREATE TRIGGER IF NOT EXISTS audit_no_delete BEFORE DELETE ON audit
BEGIN SELECT RAISE(ABORT,'audit log is append-only'); END;

CREATE TABLE IF NOT EXISTS raw_events(
    id TEXT PRIMARY KEY,
    source_type TEXT,
    idempotency_key TEXT UNIQUE,
    raw_payload TEXT,
    received_at REAL
);
CREATE TABLE IF NOT EXISTS normalized_events(
    id TEXT PRIMARY KEY,
    raw_event_id TEXT,
    event_type TEXT,
    severity TEXT,
    src_ip TEXT,
    username TEXT,
    hostname TEXT,
    description TEXT,
    scenario_offset INTEGER,
    occurred_at REAL
);
CREATE TABLE IF NOT EXISTS incidents(
    id TEXT PRIMARY KEY,
    title TEXT,
    status TEXT,
    priority TEXT,
    risk_score REAL,
    risk_breakdown TEXT,
    correlation_rationale TEXT,
    created_at REAL,
    updated_at REAL
);
CREATE TABLE IF NOT EXISTS indicators(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id TEXT,
    alert_id TEXT,
    indicator_type TEXT,
    indicator_value TEXT
);
CREATE TABLE IF NOT EXISTS intelligence_records(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    indicator_value TEXT,
    provider TEXT,
    abuse_score INTEGER,
    otx_pulses INTEGER,
    tags TEXT,
    mitre_id TEXT,
    mitre_name TEXT,
    retrieved_at REAL
);
CREATE TABLE IF NOT EXISTS evidence(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id TEXT,
    alert_id TEXT,
    evidence_type TEXT,
    claim TEXT,
    source_refs TEXT,
    verified INTEGER,
    created_at REAL
);
CREATE TABLE IF NOT EXISTS agent_runs(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id TEXT,
    alert_id TEXT,
    agent_type TEXT,
    status TEXT,
    model_provider TEXT,
    output TEXT,
    duration_ms REAL,
    created_at REAL
);
CREATE TABLE IF NOT EXISTS recommendations(
    id TEXT PRIMARY KEY,
    incident_id TEXT,
    alert_id TEXT,
    action_type TEXT,
    args TEXT,
    rationale TEXT,
    risk_level TEXT,
    approval_status TEXT,
    created_at REAL
);
CREATE TABLE IF NOT EXISTS approval_decisions(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    recommendation_id TEXT,
    analyst_id TEXT,
    decision TEXT,
    comment TEXT,
    execution_result TEXT,
    decided_at REAL
);
"""

POSTGRES_STATEMENTS = [
    """CREATE TABLE IF NOT EXISTS alerts (
        id TEXT PRIMARY KEY,
        raw TEXT,
        status TEXT,
        severity TEXT,
        confidence DOUBLE PRECISION,
        report TEXT,
        incident_id TEXT,
        risk_score DOUBLE PRECISION,
        created_at DOUBLE PRECISION
    )""",
    """CREATE TABLE IF NOT EXISTS audit (
        n SERIAL PRIMARY KEY,
        ts DOUBLE PRECISION,
        alert_id TEXT,
        agent TEXT,
        kind TEXT,
        msg TEXT,
        data TEXT,
        prev_hash TEXT,
        row_hash TEXT
    )""",
    """CREATE OR REPLACE FUNCTION audit_append_only_guard() RETURNS TRIGGER AS $$
    BEGIN
        RAISE EXCEPTION 'audit log is append-only';
    END;
    $$ LANGUAGE plpgsql""",
    "DROP TRIGGER IF EXISTS audit_no_update ON audit",
    "CREATE TRIGGER audit_no_update BEFORE UPDATE ON audit FOR EACH ROW EXECUTE FUNCTION audit_append_only_guard()",
    "DROP TRIGGER IF EXISTS audit_no_delete ON audit",
    "CREATE TRIGGER audit_no_delete BEFORE DELETE ON audit FOR EACH ROW EXECUTE FUNCTION audit_append_only_guard()",
    """CREATE TABLE IF NOT EXISTS raw_events (
        id TEXT PRIMARY KEY,
        source_type TEXT,
        idempotency_key TEXT UNIQUE,
        raw_payload TEXT,
        received_at DOUBLE PRECISION
    )""",
    """CREATE TABLE IF NOT EXISTS normalized_events (
        id TEXT PRIMARY KEY,
        raw_event_id TEXT,
        event_type TEXT,
        severity TEXT,
        src_ip TEXT,
        username TEXT,
        hostname TEXT,
        description TEXT,
        scenario_offset INTEGER,
        occurred_at DOUBLE PRECISION
    )""",
    """CREATE TABLE IF NOT EXISTS incidents (
        id TEXT PRIMARY KEY,
        title TEXT,
        status TEXT,
        priority TEXT,
        risk_score DOUBLE PRECISION,
        risk_breakdown TEXT,
        correlation_rationale TEXT,
        created_at DOUBLE PRECISION,
        updated_at DOUBLE PRECISION
    )""",
    """CREATE TABLE IF NOT EXISTS indicators (
        id SERIAL PRIMARY KEY,
        incident_id TEXT,
        alert_id TEXT,
        indicator_type TEXT,
        indicator_value TEXT
    )""",
    """CREATE TABLE IF NOT EXISTS intelligence_records (
        id SERIAL PRIMARY KEY,
        indicator_value TEXT,
        provider TEXT,
        abuse_score INTEGER,
        otx_pulses INTEGER,
        tags TEXT,
        mitre_id TEXT,
        mitre_name TEXT,
        retrieved_at DOUBLE PRECISION
    )""",
    """CREATE TABLE IF NOT EXISTS evidence (
        id SERIAL PRIMARY KEY,
        incident_id TEXT,
        alert_id TEXT,
        evidence_type TEXT,
        claim TEXT,
        source_refs TEXT,
        verified INTEGER,
        created_at DOUBLE PRECISION
    )""",
    """CREATE TABLE IF NOT EXISTS agent_runs (
        id SERIAL PRIMARY KEY,
        incident_id TEXT,
        alert_id TEXT,
        agent_type TEXT,
        status TEXT,
        model_provider TEXT,
        output TEXT,
        duration_ms DOUBLE PRECISION,
        created_at DOUBLE PRECISION
    )""",
    """CREATE TABLE IF NOT EXISTS recommendations (
        id TEXT PRIMARY KEY,
        incident_id TEXT,
        alert_id TEXT,
        action_type TEXT,
        args TEXT,
        rationale TEXT,
        risk_level TEXT,
        approval_status TEXT,
        created_at DOUBLE PRECISION
    )""",
    """CREATE TABLE IF NOT EXISTS approval_decisions (
        id SERIAL PRIMARY KEY,
        recommendation_id TEXT,
        analyst_id TEXT,
        decision TEXT,
        comment TEXT,
        execution_result TEXT,
        decided_at DOUBLE PRECISION
    )""",
]


def compute_audit_hash(
    prev_hash: str,
    ts: float,
    alert_id: str,
    agent: str,
    kind: str,
    msg: str,
    data_json: str,
) -> str:
    payload = f"{prev_hash}|{ts:.6f}|{alert_id}|{agent}|{kind}|{msg}|{data_json}"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


class CursorWrapper:
    """Unified cursor wrapper across psycopg and sqlite3."""

    def __init__(self, rows: list[dict[str, Any]]) -> None:
        self._rows = rows
        self._idx = 0

    def fetchone(self) -> dict[str, Any] | None:
        if self._idx >= len(self._rows):
            return None
        row = self._rows[self._idx]
        self._idx += 1
        return row

    def fetchall(self) -> list[dict[str, Any]]:
        remaining = self._rows[self._idx :]
        self._idx = len(self._rows)
        return remaining

    def __iter__(self) -> Iterator[dict[str, Any]]:
        return iter(self._rows)


class DatabaseAdapter:
    """Thread-safe dual-engine database adapter supporting PostgreSQL (Neon) and SQLite."""

    def __init__(self, target_url: str | None = None) -> None:
        settings = get_settings()
        self._lock = threading.RLock()
        self.backend_type = "sqlite"
        self._pg_conn: Any = None
        self._sqlite_conn: sqlite3.Connection | None = None

        url = target_url if target_url is not None else (settings.database_url or settings.sqlite_path)
        if url.startswith(("postgresql://", "postgres://")):
            try:
                import psycopg
                from psycopg.rows import dict_row

                self._pg_conn = psycopg.connect(url, autocommit=False, row_factory=dict_row, connect_timeout=5)
                self.backend_type = "postgresql"
                self.init_schema()
                return
            except Exception as exc:
                logger.warning("PostgreSQL connection unavailable (%s); falling back to SQLite", exc)
                self._pg_conn = None

        sqlite_target = ":memory:" if url.startswith(("postgresql://", "postgres://", "sqlite:///:memory:")) else url
        if sqlite_target.startswith("sqlite:///"):
            sqlite_target = sqlite_target[len("sqlite:///") :]
        self._sqlite_conn = sqlite3.connect(sqlite_target, check_same_thread=False)
        self._sqlite_conn.row_factory = sqlite3.Row
        self.backend_type = "sqlite"
        self.init_schema()

    def init_schema(self) -> None:
        with self._lock:
            if self.backend_type == "postgresql" and self._pg_conn is not None:
                with self._pg_conn.cursor() as cur:
                    for stmt in POSTGRES_STATEMENTS:
                        cur.execute(stmt)
                self._pg_conn.commit()
            elif self._sqlite_conn is not None:
                self._sqlite_conn.executescript(SQLITE_SCHEMA)
                self._sqlite_conn.commit()

    def _translate_query_for_pg(self, sql: str) -> str:
        translated = re.sub(r"\bORDER\s+BY\s+rowid\b", "ORDER BY created_at NULLS FIRST, id", sql, flags=re.I)
        translated = translated.replace("?", "%s")
        if re.match(r"^\s*INSERT\s+OR\s+REPLACE\s+INTO\s+alerts", translated, flags=re.I):
            translated = re.sub(r"^\s*INSERT\s+OR\s+REPLACE\s+INTO", "INSERT INTO", translated, flags=re.I)
            translated += (
                " ON CONFLICT (id) DO UPDATE SET raw=EXCLUDED.raw, status=EXCLUDED.status,"
                " severity=EXCLUDED.severity, confidence=EXCLUDED.confidence, report=EXCLUDED.report"
            )
        elif re.match(r"^\s*INSERT\s+OR\s+IGNORE\s+INTO", translated, flags=re.I):
            translated = re.sub(r"^\s*INSERT\s+OR\s+IGNORE\s+INTO", "INSERT INTO", translated, flags=re.I)
            translated += " ON CONFLICT DO NOTHING"
        return translated

    def execute(self, sql: str, params: tuple[Any, ...] | list[Any] = ()) -> CursorWrapper:
        with self._lock:
            if self.backend_type == "postgresql" and self._pg_conn is not None:
                pg_sql = self._translate_query_for_pg(sql)
                try:
                    with self._pg_conn.cursor() as cur:
                        cur.execute(pg_sql, tuple(params))
                        if cur.description is not None:
                            rows = [dict(r) for r in cur.fetchall()]
                        else:
                            rows = []
                    return CursorWrapper(rows)
                except Exception:
                    self._pg_conn.rollback()
                    raise

            assert self._sqlite_conn is not None
            cur = self._sqlite_conn.execute(sql, tuple(params))
            if cur.description is not None:
                rows = [dict(r) for r in cur.fetchall()]
            else:
                rows = []
            return CursorWrapper(rows)

    def commit(self) -> None:
        with self._lock:
            if self.backend_type == "postgresql" and self._pg_conn is not None:
                self._pg_conn.commit()
            elif self._sqlite_conn is not None:
                self._sqlite_conn.commit()

    def reset_mutable_tables(self) -> None:
        """Clears non-audit operational tables so scenarios can be re-run without server restart."""
        tables = (
            "approval_decisions",
            "recommendations",
            "agent_runs",
            "evidence",
            "indicators",
            "incidents",
            "normalized_events",
            "raw_events",
            "alerts",
        )
        with self._lock:
            for tbl in tables:
                self.execute(f"DELETE FROM {tbl}")
            self.commit()
