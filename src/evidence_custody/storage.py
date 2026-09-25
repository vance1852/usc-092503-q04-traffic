"""证据保全链服务的 SQLite 模式与事务辅助。"""

from __future__ import annotations

import contextlib
import sqlite3
from collections.abc import Iterator
from pathlib import Path


SCHEMA_VERSION = 1

SCHEMA_SQL = """
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS schema_meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS users (
    user_id TEXT PRIMARY KEY,
    display_name TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('collector', 'custodian', 'case_officer', 'reviewer', 'auditor')),
    contact TEXT NOT NULL,
    active INTEGER NOT NULL DEFAULT 1 CHECK (active IN (0, 1))
);

CREATE TABLE IF NOT EXISTS storage_locations (
    location_id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    kind TEXT NOT NULL CHECK (kind IN ('warehouse', 'cabinet', 'electronic')),
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS evidence_packages (
    package_id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL,
    title TEXT NOT NULL,
    custody_status TEXT NOT NULL CHECK (custody_status IN ('sealed', 'out_on_retrieval', 'lost')),
    current_holder_id TEXT NOT NULL REFERENCES users(user_id),
    current_location_id TEXT REFERENCES storage_locations(location_id),
    current_version_no INTEGER NOT NULL CHECK (current_version_no > 0),
    revision INTEGER NOT NULL DEFAULT 1 CHECK (revision > 0),
    created_by TEXT NOT NULL REFERENCES users(user_id),
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS evidence_versions (
    version_id INTEGER PRIMARY KEY AUTOINCREMENT,
    package_id TEXT NOT NULL REFERENCES evidence_packages(package_id),
    version_no INTEGER NOT NULL CHECK (version_no > 0),
    content_sha256 TEXT NOT NULL CHECK (length(content_sha256) = 64),
    note TEXT NOT NULL,
    uploaded_by TEXT NOT NULL REFERENCES users(user_id),
    uploaded_at TEXT NOT NULL,
    UNIQUE (package_id, version_no)
);

CREATE TABLE IF NOT EXISTS handovers (
    handover_id INTEGER PRIMARY KEY AUTOINCREMENT,
    package_id TEXT NOT NULL REFERENCES evidence_packages(package_id),
    from_user_id TEXT NOT NULL REFERENCES users(user_id),
    to_user_id TEXT NOT NULL REFERENCES users(user_id),
    to_location_id TEXT NOT NULL REFERENCES storage_locations(location_id),
    version_no INTEGER NOT NULL,
    content_sha256 TEXT NOT NULL CHECK (length(content_sha256) = 64),
    status TEXT NOT NULL CHECK (status IN ('pending', 'accepted', 'rejected')),
    note TEXT NOT NULL,
    reject_reason TEXT,
    initiated_at TEXT NOT NULL,
    resolved_at TEXT
);

CREATE UNIQUE INDEX IF NOT EXISTS one_pending_handover_per_package
ON handovers(package_id)
WHERE status = 'pending';

CREATE TABLE IF NOT EXISTS custody_events (
    event_id INTEGER PRIMARY KEY AUTOINCREMENT,
    package_id TEXT NOT NULL REFERENCES evidence_packages(package_id),
    seq INTEGER NOT NULL CHECK (seq > 0),
    event_type TEXT NOT NULL CHECK (event_type IN
        ('register', 'version_upload', 'handover', 'reject', 'loss', 'reseal', 'retrieve', 'determination')),
    version_no INTEGER,
    content_sha256 TEXT,
    from_user_id TEXT,
    to_user_id TEXT,
    location_id TEXT,
    actor_id TEXT NOT NULL,
    detail_json TEXT NOT NULL,
    prev_event_hash TEXT NOT NULL CHECK (length(prev_event_hash) = 64),
    event_hash TEXT NOT NULL CHECK (length(event_hash) = 64),
    created_at TEXT NOT NULL,
    UNIQUE (package_id, seq),
    UNIQUE (event_hash)
);

CREATE TABLE IF NOT EXISTS liability_determinations (
    determination_id INTEGER PRIMARY KEY AUTOINCREMENT,
    package_id TEXT NOT NULL REFERENCES evidence_packages(package_id),
    version_no INTEGER NOT NULL,
    content_sha256 TEXT NOT NULL CHECK (length(content_sha256) = 64),
    summary TEXT NOT NULL,
    decided_by TEXT NOT NULL REFERENCES users(user_id),
    decided_at TEXT NOT NULL,
    UNIQUE (package_id, version_no),
    FOREIGN KEY (package_id, version_no) REFERENCES evidence_versions(package_id, version_no)
);

CREATE TABLE IF NOT EXISTS audit_events (
    event_id INTEGER PRIMARY KEY AUTOINCREMENT,
    entity_type TEXT NOT NULL,
    entity_id TEXT NOT NULL,
    event_type TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    created_at TEXT NOT NULL
);
"""

REQUIRED_TABLES = frozenset({
    "schema_meta", "users", "storage_locations", "evidence_packages", "evidence_versions",
    "handovers", "custody_events", "liability_determinations", "audit_events",
})


def connect(path: str | Path) -> sqlite3.Connection:
    """打开连接并启用严格的事务与外键设置。"""

    connection = sqlite3.connect(str(path), isolation_level=None)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    connection.execute("PRAGMA busy_timeout = 5000")
    return connection


@contextlib.contextmanager
def transaction(connection: sqlite3.Connection, *, immediate: bool = False) -> Iterator[None]:
    """显式事务；异常时保证回滚。"""

    connection.execute("BEGIN IMMEDIATE" if immediate else "BEGIN")
    try:
        yield
    except BaseException:
        connection.rollback()
        raise
    else:
        connection.commit()


def initialize(connection: sqlite3.Connection) -> None:
    """初始化基础资料表，重复执行不改变已有数据。"""

    connection.executescript(SCHEMA_SQL)
    with transaction(connection, immediate=True):
        connection.execute(
            "INSERT INTO schema_meta(key, value) VALUES('schema_version', ?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (str(SCHEMA_VERSION),),
        )


def inspect_schema(connection: sqlite3.Connection) -> dict[str, object]:
    """返回适合机器检查的数据库结构摘要。"""

    table_rows = connection.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
    ).fetchall()
    tables = tuple(row["name"] for row in table_rows)
    version_row = connection.execute(
        "SELECT value FROM schema_meta WHERE key='schema_version'"
    ).fetchone()
    missing = sorted(REQUIRED_TABLES - set(tables))
    foreign_keys = connection.execute("PRAGMA foreign_keys").fetchone()[0]
    return {
        "tables": tables,
        "missing_tables": missing,
        "schema_version": None if version_row is None else version_row["value"],
        "foreign_keys": bool(foreign_keys),
    }
