"""证据一致性证据采信服务的 SQLite 模式与事务辅助。"""

from __future__ import annotations

import contextlib
import sqlite3
from collections.abc import Iterator
from pathlib import Path


SCHEMA_VERSION = 3

SCHEMA_SQL = """
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS schema_meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS evidence_protocol_catalog (
    evidence_protocol_id TEXT NOT NULL,
    version INTEGER NOT NULL CHECK (version > 0),
    title TEXT NOT NULL,
    task_family TEXT NOT NULL,
    canonical_json TEXT NOT NULL,
    content_sha256 TEXT NOT NULL CHECK (length(content_sha256) = 64),
    created_at TEXT NOT NULL,
    PRIMARY KEY (evidence_protocol_id, version),
    UNIQUE (content_sha256)
);

CREATE TABLE IF NOT EXISTS users (
    user_id TEXT PRIMARY KEY,
    display_name TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('operator', 'statistician', 'approver', 'auditor')),
    active INTEGER NOT NULL DEFAULT 1 CHECK (active IN (0, 1))
);

CREATE TABLE IF NOT EXISTS capture_devices (
    device_id TEXT PRIMARY KEY,
    model_name TEXT NOT NULL,
    vendor TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS builds (
    build_id TEXT PRIMARY KEY,
    device_id TEXT NOT NULL REFERENCES capture_devices(device_id),
    version TEXT NOT NULL,
    content_sha256 TEXT NOT NULL CHECK (length(content_sha256) = 64),
    created_at TEXT NOT NULL,
    UNIQUE (device_id, version),
    UNIQUE (content_sha256)
);

CREATE TABLE IF NOT EXISTS batches (
    batch_id TEXT PRIMARY KEY,
    evidence_protocol_id TEXT NOT NULL,
    evidence_protocol_version INTEGER NOT NULL,
    build_id TEXT NOT NULL REFERENCES builds(build_id),
    state TEXT NOT NULL CHECK (state IN ('draft', 'running', 'sealed', 'analyzing', 'analyzed', 'decided')),
    revision INTEGER NOT NULL DEFAULT 1 CHECK (revision > 0),
    created_by TEXT NOT NULL REFERENCES users(user_id),
    created_at TEXT NOT NULL,
    started_at TEXT,
    sealed_at TEXT,
    FOREIGN KEY (evidence_protocol_id, evidence_protocol_version) REFERENCES evidence_protocol_catalog(evidence_protocol_id, version)
);

CREATE TABLE IF NOT EXISTS evidence_items (
    evidence_item_id INTEGER PRIMARY KEY AUTOINCREMENT,
    batch_id TEXT NOT NULL REFERENCES batches(batch_id),
    source_batch TEXT NOT NULL,
    source_row TEXT NOT NULL,
    device_id TEXT NOT NULL REFERENCES capture_devices(device_id),
    evidence_group_key TEXT NOT NULL,
    observed_at TEXT NOT NULL,
    indicators_json TEXT NOT NULL,
    content_sha256 TEXT NOT NULL CHECK (length(content_sha256) = 64),
    imported_by TEXT NOT NULL REFERENCES users(user_id),
    imported_at TEXT NOT NULL,
    UNIQUE (batch_id, source_batch, source_row)
);

CREATE TABLE IF NOT EXISTS idempotency_keys (
    scope TEXT NOT NULL,
    key TEXT NOT NULL,
    request_sha256 TEXT NOT NULL CHECK (length(request_sha256) = 64),
    response_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY (scope, key)
);

CREATE TABLE IF NOT EXISTS exclusion_requests (
    exclusion_id INTEGER PRIMARY KEY AUTOINCREMENT,
    evidence_item_id INTEGER NOT NULL REFERENCES evidence_items(evidence_item_id),
    status TEXT NOT NULL CHECK (status IN ('pending', 'approved', 'rejected', 'revoked')),
    reason TEXT NOT NULL,
    requested_by TEXT NOT NULL REFERENCES users(user_id),
    requested_at TEXT NOT NULL,
    reviewed_by TEXT REFERENCES users(user_id),
    reviewed_at TEXT,
    review_note TEXT
);

CREATE UNIQUE INDEX IF NOT EXISTS one_open_exclusion_per_evidence_item
ON exclusion_requests(evidence_item_id)
WHERE status IN ('pending', 'approved');

CREATE TABLE IF NOT EXISTS analysis_jobs (
    job_id INTEGER PRIMARY KEY AUTOINCREMENT,
    batch_id TEXT NOT NULL REFERENCES batches(batch_id),
    batch_revision INTEGER NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('queued', 'leased', 'succeeded', 'failed')),
    attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    available_at TEXT NOT NULL,
    lease_owner TEXT,
    lease_expires_at TEXT,
    last_error TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE (batch_id, batch_revision)
);

CREATE TABLE IF NOT EXISTS analyses (
    analysis_id INTEGER PRIMARY KEY AUTOINCREMENT,
    batch_id TEXT NOT NULL REFERENCES batches(batch_id),
    batch_revision INTEGER NOT NULL,
    evidence_protocol_sha256 TEXT NOT NULL CHECK (length(evidence_protocol_sha256) = 64),
    input_sha256 TEXT NOT NULL CHECK (length(input_sha256) = 64),
    algorithm_version TEXT NOT NULL,
    seed INTEGER NOT NULL,
    result_json TEXT NOT NULL,
    created_by TEXT NOT NULL,
    created_at TEXT NOT NULL,
    UNIQUE (batch_id, batch_revision, input_sha256)
);

CREATE TABLE IF NOT EXISTS decisions (
    decision_id INTEGER PRIMARY KEY AUTOINCREMENT,
    batch_id TEXT NOT NULL REFERENCES batches(batch_id),
    analysis_id INTEGER NOT NULL REFERENCES analyses(analysis_id),
    decision TEXT NOT NULL CHECK (decision IN ('needs_more_data', 'approved', 'rejected')),
    reason TEXT NOT NULL,
    decided_by TEXT NOT NULL REFERENCES users(user_id),
    decided_at TEXT NOT NULL,
    UNIQUE (batch_id, analysis_id)
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

-- 物证保管链：材料主档，逻辑身份与批次/证据记录关联。
CREATE TABLE IF NOT EXISTS custody_materials (
    material_id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    material_type TEXT NOT NULL,
    batch_id TEXT REFERENCES batches(batch_id),
    evidence_item_id INTEGER REFERENCES evidence_items(evidence_item_id),
    state TEXT NOT NULL CHECK (state IN (
        'sealed', 'in_transfer', 'rejected', 'stored', 'lost', 'resealed',
        'access_pending', 'accessed', 'locked'
    )),
    current_version_seq INTEGER REFERENCES custody_material_versions(version_seq),
    holder_user_id TEXT REFERENCES users(user_id),
    location_id TEXT REFERENCES custody_locations(location_id),
    locked_for_decision INTEGER NOT NULL DEFAULT 0 CHECK (locked_for_decision IN (0, 1)),
    registered_by TEXT NOT NULL REFERENCES users(user_id),
    registered_at TEXT NOT NULL,
    last_event_hash TEXT,
    chain_length INTEGER NOT NULL DEFAULT 0 CHECK (chain_length >= 0),
    CHECK (holder_user_id IS NOT NULL OR state IN ('lost', 'accessed'))
);

-- 物证保管链：只追加的内容版本。后续上传只产生新版本，永不覆盖。
CREATE TABLE IF NOT EXISTS custody_material_versions (
    version_seq INTEGER PRIMARY KEY AUTOINCREMENT,
    material_id TEXT NOT NULL REFERENCES custody_materials(material_id),
    version_no INTEGER NOT NULL CHECK (version_no > 0),
    content_sha256 TEXT NOT NULL CHECK (length(content_sha256) = 64),
    package_sha256 TEXT NOT NULL CHECK (length(package_sha256) = 64),
    size_bytes INTEGER NOT NULL CHECK (size_bytes >= 0),
    media_type TEXT NOT NULL,
    change_note TEXT NOT NULL,
    supersedes_version_no INTEGER,
    created_by TEXT NOT NULL REFERENCES users(user_id),
    created_at TEXT NOT NULL,
    UNIQUE (material_id, version_no),
    UNIQUE (material_id, package_sha256)
);

-- 物证保管链：保管位置主数据。
CREATE TABLE IF NOT EXISTS custody_locations (
    location_id TEXT PRIMARY KEY,
    label TEXT NOT NULL,
    kind TEXT NOT NULL CHECK (kind IN ('vault', 'room', 'vehicle', 'court', 'external')),
    created_at TEXT NOT NULL
);

-- 物证保管链：逐次交接，交出与接收双方分别确认。
CREATE TABLE IF NOT EXISTS custody_transfers (
    transfer_id INTEGER PRIMARY KEY AUTOINCREMENT,
    material_id TEXT NOT NULL REFERENCES custody_materials(material_id),
    sequence_no INTEGER NOT NULL,
    from_user_id TEXT REFERENCES users(user_id),
    to_user_id TEXT NOT NULL REFERENCES users(user_id),
    from_location_id TEXT REFERENCES custody_locations(location_id),
    to_location_id TEXT REFERENCES custody_locations(location_id),
    state TEXT NOT NULL CHECK (state IN ('proposed', 'accepted', 'rejected', 'cancelled')),
    purpose TEXT NOT NULL,
    proposed_at TEXT NOT NULL,
    proposed_by TEXT NOT NULL REFERENCES users(user_id),
    responded_at TEXT,
    reject_reason TEXT,
    UNIQUE (material_id, sequence_no)
);

-- 物证保管链：依法调阅申请与批准。
CREATE TABLE IF NOT EXISTS custody_access_requests (
    request_id INTEGER PRIMARY KEY AUTOINCREMENT,
    material_id TEXT NOT NULL REFERENCES custody_materials(material_id),
    requester_user_id TEXT NOT NULL REFERENCES users(user_id),
    requester_name TEXT NOT NULL,
    requester_contact TEXT NOT NULL,
    legal_basis TEXT NOT NULL,
    purpose TEXT NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('pending', 'approved', 'rejected', 'returned', 'expired')),
    decided_by TEXT REFERENCES users(user_id),
    decided_at TEXT,
    decision_note TEXT,
    approved_until TEXT,
    returned_at TEXT,
    return_note TEXT,
    created_at TEXT NOT NULL
);

-- 物证保管链：只追加的哈希链事件，任何状态变化都在此留下一环。
CREATE TABLE IF NOT EXISTS custody_events (
    event_id INTEGER PRIMARY KEY AUTOINCREMENT,
    material_id TEXT NOT NULL REFERENCES custody_materials(material_id),
    sequence_no INTEGER NOT NULL,
    event_type TEXT NOT NULL,
    actor_id TEXT NOT NULL REFERENCES users(user_id),
    state_after TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    content_sha256 TEXT CHECK (content_sha256 IS NULL OR length(content_sha256) = 64),
    package_sha256 TEXT CHECK (package_sha256 IS NULL OR length(package_sha256) = 64),
    prev_hash TEXT,
    event_hash TEXT NOT NULL CHECK (length(event_hash) = 64),
    created_at TEXT NOT NULL,
    UNIQUE (material_id, sequence_no),
    UNIQUE (event_hash)
);
"""

REQUIRED_TABLES = frozenset({
    "schema_meta", "evidence_protocol_catalog", "users", "capture_devices", "builds", "batches",
    "evidence_items", "idempotency_keys", "exclusion_requests", "analysis_jobs",
    "analyses", "decisions", "audit_events",
    "custody_materials", "custody_material_versions", "custody_locations",
    "custody_transfers", "custody_access_requests", "custody_events",
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
