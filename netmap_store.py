"""Local SQLite persistence for NetMap snapshots and finding triage."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import sqlite3
import tempfile
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

SCHEMA_VERSION = 1
MAX_RESTORE_BYTES = 250 * 1024 * 1024
FINDING_STATUSES = (
    "new",
    "acknowledged",
    "in_progress",
    "resolved",
    "accepted_risk",
    "false_positive",
)


def data_directory() -> Path:
    """Return the user-configurable directory for private NetMap data."""
    configured = os.environ.get("NETMAP_DATA_DIR")
    if configured:
        return Path(os.path.expandvars(configured)).expanduser().resolve()
    if os.name == "nt":
        root = os.environ.get("LOCALAPPDATA")
        return (Path(root) if root else Path.home() / "AppData/Local") / "NetMap"
    root = os.environ.get("XDG_DATA_HOME")
    return (
        Path(root).expanduser() if root else Path.home() / ".local/share"
    ) / "netmap"


def database_path(*, synthetic: bool = False) -> Path:
    """Return the operational database path or isolated synthetic-demo path."""
    if synthetic:
        configured = os.environ.get("NETMAP_DATA_DIR")
        if configured:
            return (
                Path(os.path.expandvars(configured)).expanduser().resolve()
                / "demo.sqlite3"
            )
        if os.name == "nt":
            root = os.environ.get("LOCALAPPDATA")
            base = (Path(root) if root else Path.home() / "AppData/Local") / "NetMap"
        else:
            root = os.environ.get("XDG_DATA_HOME")
            base = (
                Path(root).expanduser() if root else Path.home() / ".local/share"
            ) / "netmap"
        return base / "demo.sqlite3"
    configured_db = os.environ.get("NETMAP_DB_PATH")
    return (
        Path(os.path.expandvars(configured_db)).expanduser().resolve()
        if configured_db
        else data_directory() / "netmap.sqlite3"
    )


def _connect(path: str | Path | None = None) -> sqlite3.Connection:
    target = Path(path) if path else database_path()
    target.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(target, timeout=10.0)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    connection.execute("PRAGMA busy_timeout = 10000")
    connection.execute("PRAGMA journal_mode = DELETE")
    return connection


@contextmanager
def _database(path: str | Path | None = None):
    connection = _connect(path)
    try:
        yield connection
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


@contextmanager
def _raw_database(path: str | Path):
    connection = sqlite3.connect(path)
    try:
        yield connection
    finally:
        connection.close()


def initialize(path: str | Path | None = None) -> Path:
    """Initialize or safely migrate the local database to the supported schema."""
    target = Path(path) if path else database_path()
    target.parent.mkdir(parents=True, exist_ok=True)
    with _database(target) as db:
        current = int(db.execute("PRAGMA user_version").fetchone()[0])
        if current > SCHEMA_VERSION:
            raise ValueError(
                f"Database schema {current} is newer than this NetMap version supports ({SCHEMA_VERSION})."
            )
        if current == 0:
            db.executescript(
                """
                CREATE TABLE snapshots (
                    snapshot_id TEXT PRIMARY KEY,
                    content_sha256 TEXT NOT NULL,
                    source_scan_id TEXT NOT NULL,
                    scan_time TEXT NOT NULL,
                    imported_at TEXT NOT NULL,
                    source TEXT NOT NULL,
                    source_kind TEXT NOT NULL,
                    scanner TEXT NOT NULL,
                    complete INTEGER CHECK (complete IN (0, 1) OR complete IS NULL),
                    coverage_known INTEGER NOT NULL CHECK (coverage_known IN (0, 1)),
                    coverage_json TEXT NOT NULL,
                    scope_json TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    UNIQUE (content_sha256, source_kind)
                );
                CREATE INDEX snapshots_time_idx ON snapshots(scan_time, imported_at);
                CREATE TABLE host_observations (
                    snapshot_id TEXT NOT NULL REFERENCES snapshots(snapshot_id) ON DELETE CASCADE,
                    host_id TEXT NOT NULL,
                    ip_address TEXT NOT NULL,
                    hostname TEXT NOT NULL,
                    host_status TEXT NOT NULL,
                    observed_at TEXT NOT NULL,
                    observation_json TEXT NOT NULL,
                    PRIMARY KEY (snapshot_id, host_id, ip_address)
                );
                CREATE INDEX host_observations_address_idx ON host_observations(ip_address, observed_at);
                CREATE TABLE service_observations (
                    snapshot_id TEXT NOT NULL REFERENCES snapshots(snapshot_id) ON DELETE CASCADE,
                    service_id TEXT NOT NULL,
                    host_id TEXT NOT NULL,
                    ip_address TEXT NOT NULL,
                    port INTEGER NOT NULL CHECK (port BETWEEN 1 AND 65535),
                    protocol TEXT NOT NULL,
                    state TEXT NOT NULL,
                    observed_at TEXT NOT NULL,
                    observation_json TEXT NOT NULL,
                    PRIMARY KEY (snapshot_id, service_id)
                );
                CREATE INDEX service_observations_asset_idx ON service_observations(ip_address, protocol, port, observed_at);
                CREATE TABLE findings (
                    finding_id TEXT PRIMARY KEY,
                    rule_id TEXT NOT NULL,
                    asset_id TEXT NOT NULL,
                    host_id TEXT NOT NULL,
                    ip_address TEXT NOT NULL,
                    port INTEGER NOT NULL,
                    protocol TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    title TEXT NOT NULL,
                    description TEXT NOT NULL,
                    evidence TEXT NOT NULL,
                    explanation TEXT NOT NULL,
                    limitation TEXT NOT NULL,
                    recommendation TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    source TEXT NOT NULL,
                    classification TEXT NOT NULL,
                    status TEXT NOT NULL CHECK (status IN ('new','acknowledged','in_progress','resolved','accepted_risk','false_positive')),
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    investigation_note TEXT NOT NULL DEFAULT '',
                    remediation_note TEXT NOT NULL DEFAULT '',
                    triage_reason TEXT NOT NULL DEFAULT '',
                    updated_at TEXT NOT NULL
                );
                CREATE INDEX findings_filter_idx ON findings(status, severity, rule_id, ip_address);
                CREATE TABLE finding_observations (
                    finding_id TEXT NOT NULL REFERENCES findings(finding_id) ON DELETE CASCADE,
                    snapshot_id TEXT NOT NULL REFERENCES snapshots(snapshot_id) ON DELETE CASCADE,
                    observed_at TEXT NOT NULL,
                    fact_json TEXT NOT NULL,
                    PRIMARY KEY (finding_id, snapshot_id)
                );
                CREATE TABLE finding_events (
                    event_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    finding_id TEXT NOT NULL REFERENCES findings(finding_id) ON DELETE CASCADE,
                    from_status TEXT,
                    to_status TEXT NOT NULL,
                    reason TEXT NOT NULL,
                    investigation_note TEXT NOT NULL,
                    remediation_note TEXT NOT NULL,
                    changed_at TEXT NOT NULL
                );
                CREATE INDEX finding_events_finding_idx ON finding_events(finding_id, changed_at);
                CREATE TABLE comparisons (
                    comparison_id TEXT PRIMARY KEY,
                    baseline_snapshot_id TEXT NOT NULL REFERENCES snapshots(snapshot_id) ON DELETE CASCADE,
                    later_snapshot_id TEXT NOT NULL REFERENCES snapshots(snapshot_id) ON DELETE CASCADE,
                    created_at TEXT NOT NULL,
                    result_json TEXT NOT NULL,
                    UNIQUE (baseline_snapshot_id, later_snapshot_id),
                    CHECK (baseline_snapshot_id <> later_snapshot_id)
                );
                PRAGMA user_version = 1;
                """
            )
        _check_database(db)
    if os.name != "nt":
        try:
            target.chmod(0o600)
            target.parent.chmod(0o700)
        except OSError:
            pass
    return target


def _check_database(db: sqlite3.Connection) -> None:
    result = db.execute("PRAGMA quick_check").fetchone()[0]
    if result != "ok":
        raise ValueError("NetMap database integrity check failed.")
    missing = db.execute("PRAGMA foreign_key_check").fetchall()
    if missing:
        raise ValueError("NetMap database contains invalid references.")


def _schema_signature(db: sqlite3.Connection) -> list[tuple[str, str, str]]:
    rows = db.execute(
        """SELECT type, name, sql FROM sqlite_master
        WHERE name NOT LIKE 'sqlite_%' ORDER BY type, name"""
    ).fetchall()
    return [(str(row[0]), str(row[1]), str(row[2] or "")) for row in rows]


def _validate_backup(path: str | Path) -> None:
    with _raw_database(path) as backup_db:
        _check_database(backup_db)
        version = int(backup_db.execute("PRAGMA user_version").fetchone()[0])
        actual_schema = _schema_signature(backup_db)
    if version != SCHEMA_VERSION:
        raise ValueError(
            "Backup schema version is not supported by this NetMap version."
        )
    with tempfile.TemporaryDirectory(prefix="netmap-schema-") as temp:
        expected_path = initialize(Path(temp) / "expected.sqlite3")
        with _raw_database(expected_path) as expected_db:
            expected_schema = _schema_signature(expected_db)
    if actual_schema != expected_schema:
        raise ValueError("Backup schema does not match the supported NetMap database.")


def _json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


def _basename(value: Any) -> str:
    return Path(str(value or "unknown").replace("\\", "/")).name or "unknown"


def _content_digest(parsed: dict[str, Any]) -> str:
    digest = str(parsed.get("content_sha256", "")).lower()
    if len(digest) == 64 and all(c in "0123456789abcdef" for c in digest):
        return digest
    payload = {
        key: value
        for key, value in parsed.items()
        if key not in {"source", "content_sha256"}
    }
    return hashlib.sha256(_json(payload).encode("utf-8")).hexdigest()


def _finding_id(finding: dict[str, Any]) -> str:
    identity = f"{finding.get('rule_id', '')}|{finding.get('asset_id', '')}"
    return hashlib.sha256(identity.encode("utf-8")).hexdigest()[:32]


def store_snapshot(
    parsed: dict[str, Any],
    findings: list[dict[str, Any]] | None = None,
    *,
    scope: dict[str, Any] | None = None,
    path: str | Path | None = None,
) -> tuple[str, bool]:
    """Persist one normalized scan; returns (snapshot_id, was_duplicate)."""
    db_path = initialize(path)
    kind = str(parsed.get("source_kind", "imported_nmap_xml"))
    digest = _content_digest(parsed)
    snapshot_id = hashlib.sha256(f"{kind}\0{digest}".encode()).hexdigest()[:32]
    source = _basename(parsed.get("source", "unknown"))
    payload = dict(parsed)
    payload["source"] = source
    payload["source_kind"] = kind
    timestamp = str(parsed.get("scan_time", "unknown"))
    complete = parsed.get("complete")
    complete_value = None if complete is None else int(bool(complete))
    hosts = parsed.get("hosts", [])
    rows = parsed.get("rows", [])
    findings = findings or []
    with _database(db_path) as db:
        existing = db.execute(
            "SELECT snapshot_id FROM snapshots WHERE content_sha256=? AND source_kind=?",
            (digest, kind),
        ).fetchone()
        if existing:
            return str(existing["snapshot_id"]), True
        imported_at = _now()
        db.execute(
            """INSERT INTO snapshots
            (snapshot_id, content_sha256, source_scan_id, scan_time, imported_at,
             source, source_kind, scanner, complete, coverage_known,
             coverage_json, scope_json, payload_json)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                snapshot_id,
                digest,
                str(parsed.get("scan_id", "unknown")),
                timestamp,
                imported_at,
                source,
                kind,
                str(parsed.get("scanner", "unknown")),
                complete_value,
                int(bool(parsed.get("coverage_known"))),
                _json(parsed.get("coverage", {})),
                _json(scope or parsed.get("scan_scope", {})),
                _json(payload),
            ),
        )
        for host in hosts:
            db.execute(
                """INSERT INTO host_observations
                (snapshot_id, host_id, ip_address, hostname, host_status, observed_at, observation_json)
                VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (
                    snapshot_id,
                    str(host.get("host_id", "unknown")),
                    str(host.get("ip_address", "unknown")),
                    str(host.get("hostname", "")),
                    str(host.get("host_status", "unknown")),
                    str(host.get("scan_time", timestamp)),
                    _json(host),
                ),
            )
        for row in rows:
            port = int(row.get("port", 0))
            if not 1 <= port <= 65535:
                continue
            db.execute(
                """INSERT INTO service_observations
                (snapshot_id, service_id, host_id, ip_address, port, protocol, state, observed_at, observation_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    snapshot_id,
                    str(row.get("service_id", "unknown")),
                    str(row.get("host_id", "unknown")),
                    str(row.get("ip_address", "unknown")),
                    port,
                    str(row.get("protocol", "unknown")),
                    str(row.get("state", "unknown")),
                    str(row.get("scan_time", timestamp)),
                    _json(row),
                ),
            )
        for finding in findings:
            _store_finding_observation(db, snapshot_id, finding, timestamp)
    return snapshot_id, False


def _store_finding_observation(
    db: sqlite3.Connection,
    snapshot_id: str,
    finding: dict[str, Any],
    timestamp: str,
) -> None:
    finding_id = _finding_id(finding)
    existing = db.execute(
        "SELECT status FROM findings WHERE finding_id=?", (finding_id,)
    ).fetchone()
    now = _now()
    status = "new"
    if existing:
        old_status = str(existing["status"])
        status = "new" if old_status == "resolved" else old_status
        db.execute(
            """UPDATE findings SET severity=?, title=?, description=?, evidence=?,
            explanation=?, limitation=?, recommendation=?, timestamp=?, source=?,
            classification=?, last_seen=?, status=?, updated_at=? WHERE finding_id=?""",
            (
                str(finding.get("severity", "unknown")),
                str(finding.get("title", "")),
                str(finding.get("description", "")),
                str(finding.get("evidence", "")),
                str(finding.get("explanation", "")),
                str(finding.get("limitation", "")),
                str(finding.get("recommendation", "")),
                str(finding.get("timestamp", timestamp)),
                str(finding.get("source", "unknown")),
                str(finding.get("classification", "")),
                timestamp,
                status,
                now,
                finding_id,
            ),
        )
        if old_status == "resolved":
            db.execute(
                """INSERT INTO finding_events
                (finding_id, from_status, to_status, reason, investigation_note, remediation_note, changed_at)
                VALUES (?, ?, ?, ?, '', '', ?)""",
                (
                    finding_id,
                    old_status,
                    "new",
                    "Finding was observed again in a later snapshot.",
                    now,
                ),
            )
    else:
        db.execute(
            """INSERT INTO findings
            (finding_id, rule_id, asset_id, host_id, ip_address, port, protocol,
             severity, title, description, evidence, explanation, limitation,
             recommendation, timestamp, source, classification, status,
             first_seen, last_seen, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'new', ?, ?, ?)""",
            (
                finding_id,
                str(finding.get("rule_id", "unknown")),
                str(finding.get("asset_id", "unknown")),
                str(finding.get("host_id", "unknown")),
                str(finding.get("address", "unknown")),
                int(finding.get("port", 0) or 0),
                str(finding.get("protocol", "unknown")),
                str(finding.get("severity", "unknown")),
                str(finding.get("title", "")),
                str(finding.get("description", "")),
                str(finding.get("evidence", "")),
                str(finding.get("explanation", "")),
                str(finding.get("limitation", "")),
                str(finding.get("recommendation", "")),
                str(finding.get("timestamp", timestamp)),
                str(finding.get("source", "unknown")),
                str(finding.get("classification", "")),
                timestamp,
                timestamp,
                now,
            ),
        )
        db.execute(
            """INSERT INTO finding_events
            (finding_id, from_status, to_status, reason, investigation_note, remediation_note, changed_at)
            VALUES (?, NULL, 'new', 'Finding first observed.', '', '', ?)""",
            (finding_id, now),
        )
    db.execute(
        """INSERT OR IGNORE INTO finding_observations
        (finding_id, snapshot_id, observed_at, fact_json) VALUES (?, ?, ?, ?)""",
        (finding_id, snapshot_id, timestamp, _json(finding)),
    )


def list_snapshots(path: str | Path | None = None) -> list[dict[str, Any]]:
    target = Path(path) if path else database_path()
    if not target.exists():
        return []
    with _database(target) as db:
        rows = db.execute(
            """SELECT s.snapshot_id, s.source_scan_id, s.scan_time, s.imported_at,
            s.source, s.source_kind, s.scanner, s.complete, s.coverage_known,
            (SELECT count(*) FROM host_observations h WHERE h.snapshot_id=s.snapshot_id) AS hosts,
            (SELECT count(*) FROM service_observations v WHERE v.snapshot_id=s.snapshot_id) AS services
            FROM snapshots s ORDER BY s.scan_time DESC, s.imported_at DESC"""
        ).fetchall()
    return [dict(row) for row in rows]


def load_snapshot(snapshot_id: str, path: str | Path | None = None) -> dict[str, Any]:
    target = Path(path) if path else database_path()
    if not target.exists():
        raise ValueError("No NetMap database exists at the configured location.")
    with _database(target) as db:
        row = db.execute(
            "SELECT payload_json FROM snapshots WHERE snapshot_id=?", (snapshot_id,)
        ).fetchone()
    if not row:
        raise ValueError("The selected scan snapshot no longer exists.")
    return json.loads(row["payload_json"])


def list_assets(path: str | Path | None = None) -> list[dict[str, Any]]:
    target = Path(path) if path else database_path()
    if not target.exists():
        return []
    with _database(target) as db:
        rows = db.execute(
            """SELECT h.* FROM host_observations h
            JOIN snapshots s ON s.snapshot_id=h.snapshot_id
            ORDER BY h.ip_address, h.observed_at, s.imported_at"""
        ).fetchall()
        service_rows = db.execute(
            """SELECT snapshot_id, ip_address, protocol, port, state, observation_json
            FROM service_observations ORDER BY observed_at, port"""
        ).fetchall()
    grouped: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for row in rows:
        key = (str(row["host_id"]), str(row["ip_address"]))
        grouped.setdefault(key, []).append(dict(row))
    services_by_address: dict[str, list[dict[str, Any]]] = {}
    for row in service_rows:
        services_by_address.setdefault(str(row["ip_address"]), []).append(
            json.loads(row["observation_json"])
        )
    assets = []
    for (_, address), observations in grouped.items():
        observation_data = [json.loads(row["observation_json"]) for row in observations]
        assets.append(
            {
                **observation_data[-1],
                "first_observed": min(row["observed_at"] for row in observations),
                "last_observed": max(row["observed_at"] for row in observations),
                "snapshot_count": len({row["snapshot_id"] for row in observations}),
                "services": services_by_address.get(address, []),
            }
        )
    return assets


def list_findings(
    path: str | Path | None = None,
    *,
    status: str | None = None,
    severity: str | None = None,
    query: str = "",
) -> list[dict[str, Any]]:
    target = Path(path) if path else database_path()
    if not target.exists():
        return []
    clauses, params = [], []
    if status and status != "all":
        clauses.append("status=?")
        params.append(status)
    if severity and severity != "all":
        clauses.append("severity=?")
        params.append(severity)
    sql = "SELECT * FROM findings"
    if clauses:
        sql += " WHERE " + " AND ".join(clauses)
    sql += " ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END, last_seen DESC"
    with _database(target) as db:
        rows = [dict(row) for row in db.execute(sql, params).fetchall()]
        observations = db.execute(
            "SELECT finding_id, count(*) AS n FROM finding_observations GROUP BY finding_id"
        ).fetchall()
    counts = {row["finding_id"]: int(row["n"]) for row in observations}
    needle = query.strip().casefold()
    for row in rows:
        row["snapshot_count"] = counts.get(row["finding_id"], 0)
        row["status_label"] = row["status"].replace("_", " ").title()
    if needle:
        rows = [
            row
            for row in rows
            if needle in " ".join(str(value) for value in row.values()).casefold()
        ]
    return rows


def update_finding(
    finding_id: str,
    status: str,
    *,
    reason: str = "",
    investigation_note: str = "",
    remediation_note: str = "",
    path: str | Path | None = None,
) -> None:
    if status not in FINDING_STATUSES:
        raise ValueError("Choose a valid finding status.")
    if status in {"accepted_risk", "false_positive"} and not reason.strip():
        raise ValueError(
            "A reason is required for accepted risk and false positive decisions."
        )
    if any(
        len(value) > 4000 for value in (reason, investigation_note, remediation_note)
    ):
        raise ValueError("Triage notes must be 4,000 characters or fewer.")
    target = initialize(path)
    now = _now()
    with _database(target) as db:
        row = db.execute(
            "SELECT status FROM findings WHERE finding_id=?", (finding_id,)
        ).fetchone()
        if not row:
            raise ValueError("The selected finding no longer exists.")
        old_status = str(row["status"])
        db.execute(
            """UPDATE findings SET status=?, triage_reason=?, investigation_note=?,
            remediation_note=?, updated_at=? WHERE finding_id=?""",
            (
                status,
                reason.strip(),
                investigation_note.strip(),
                remediation_note.strip(),
                now,
                finding_id,
            ),
        )
        db.execute(
            """INSERT INTO finding_events
            (finding_id, from_status, to_status, reason, investigation_note, remediation_note, changed_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (
                finding_id,
                old_status,
                status,
                reason.strip(),
                investigation_note.strip(),
                remediation_note.strip(),
                now,
            ),
        )


def finding_history(
    finding_id: str, path: str | Path | None = None
) -> list[dict[str, Any]]:
    target = Path(path) if path else database_path()
    if not target.exists():
        return []
    with _database(target) as db:
        rows = db.execute(
            "SELECT from_status, to_status, reason, investigation_note, remediation_note, changed_at FROM finding_events WHERE finding_id=? ORDER BY event_id",
            (finding_id,),
        ).fetchall()
    return [dict(row) for row in rows]


def save_comparison(
    baseline_id: str,
    later_id: str,
    results: list[dict[str, Any]],
    path: str | Path | None = None,
) -> str:
    if baseline_id == later_id:
        raise ValueError("Choose two different scan snapshots to compare.")
    target = initialize(path)
    comparison_id = hashlib.sha256(f"{baseline_id}\0{later_id}".encode()).hexdigest()[
        :32
    ]
    with _database(target) as db:
        db.execute(
            """INSERT OR IGNORE INTO comparisons
            (comparison_id, baseline_snapshot_id, later_snapshot_id, created_at, result_json)
            VALUES (?, ?, ?, ?, ?)""",
            (comparison_id, baseline_id, later_id, _now(), _json(results)),
        )
        row = db.execute(
            "SELECT 1 FROM comparisons WHERE comparison_id=?", (comparison_id,)
        ).fetchone()
        if not row:
            raise ValueError("Both scan snapshots must be stored before comparison.")
    return comparison_id


def list_comparisons(path: str | Path | None = None) -> list[dict[str, Any]]:
    target = Path(path) if path else database_path()
    if not target.exists():
        return []
    with _database(target) as db:
        rows = db.execute(
            """SELECT c.comparison_id, c.baseline_snapshot_id, c.later_snapshot_id,
            c.created_at, b.source AS baseline_source, b.scan_time AS baseline_time,
            a.source AS later_source, a.scan_time AS later_time, c.result_json
            FROM comparisons c JOIN snapshots b ON b.snapshot_id=c.baseline_snapshot_id
            JOIN snapshots a ON a.snapshot_id=c.later_snapshot_id ORDER BY c.created_at DESC"""
        ).fetchall()
    return [
        {
            **{
                key: row[key]
                for key in (
                    "comparison_id",
                    "baseline_snapshot_id",
                    "later_snapshot_id",
                    "created_at",
                    "baseline_source",
                    "baseline_time",
                    "later_source",
                    "later_time",
                )
            },
            "results": json.loads(row["result_json"]),
        }
        for row in rows
    ]


def delete_snapshot(snapshot_id: str, path: str | Path | None = None) -> None:
    """Delete a selected snapshot and dependent observations/comparisons atomically."""
    target = initialize(path)
    with _database(target) as db:
        if not db.execute(
            "SELECT 1 FROM snapshots WHERE snapshot_id=?", (snapshot_id,)
        ).fetchone():
            raise ValueError("The selected scan snapshot no longer exists.")
        db.execute("DELETE FROM snapshots WHERE snapshot_id=?", (snapshot_id,))
        db.execute(
            "DELETE FROM findings WHERE finding_id NOT IN (SELECT finding_id FROM finding_observations)"
        )


def database_stats(path: str | Path | None = None) -> dict[str, int]:
    target = Path(path) if path else database_path()
    if not target.exists():
        return {"bytes": 0, "snapshots": 0, "hosts": 0, "services": 0, "findings": 0}
    with _database(target) as db:
        result = {
            "bytes": target.stat().st_size,
            "snapshots": int(
                db.execute("SELECT count(*) FROM snapshots").fetchone()[0]
            ),
            "hosts": int(
                db.execute("SELECT count(*) FROM host_observations").fetchone()[0]
            ),
            "services": int(
                db.execute("SELECT count(*) FROM service_observations").fetchone()[0]
            ),
            "findings": int(db.execute("SELECT count(*) FROM findings").fetchone()[0]),
        }
    return result


def backup_database(destination: str | Path, source: str | Path | None = None) -> Path:
    src = Path(source) if source else database_path()
    if not src.is_file():
        raise ValueError("No initialized NetMap database is available to back up.")
    initialize(src)
    dst = Path(destination).expanduser().resolve()
    if dst == src.resolve():
        raise ValueError("Backup destination must differ from the active database.")
    if dst.exists():
        raise ValueError("Backup destination already exists; choose a new path.")
    temporary = None
    try:
        dst.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(
            dir=dst.parent, prefix=f".{dst.name}.", suffix=".tmp", delete=False
        ) as handle:
            temporary = Path(handle.name)
        with _raw_database(src) as source_db, _raw_database(temporary) as backup_db:
            source_db.backup(backup_db)
        _validate_backup(temporary)
        # Linking in the same directory publishes atomically without replacing
        # a destination that appeared after the initial existence check.
        os.link(temporary, dst)
        temporary.unlink()
        if os.name != "nt":
            dst.chmod(0o600)
        return dst
    except (OSError, sqlite3.Error, ValueError) as exc:
        if temporary:
            temporary.unlink(missing_ok=True)
        raise ValueError("Could not create a valid NetMap database backup.") from exc


def backup_bytes(source: str | Path | None = None) -> bytes:
    with tempfile.TemporaryDirectory(prefix="netmap-backup-") as temp:
        path = backup_database(Path(temp) / "netmap-backup.sqlite3", source)
        return path.read_bytes()


def restore_database(
    backup: str | Path,
    destination: str | Path | None = None,
    *,
    confirmed: bool = False,
) -> Path:
    if not confirmed:
        raise ValueError(
            "Restoring replaces the active database; pass an explicit confirmation."
        )
    target = Path(destination) if destination else database_path()
    source = Path(backup).expanduser().resolve()
    if source == target.resolve():
        raise ValueError("Backup source and active database must be different files.")
    if not source.is_file() or source.stat().st_size > MAX_RESTORE_BYTES:
        raise ValueError("Backup is missing or exceeds the 250 MiB restore limit.")
    target.parent.mkdir(parents=True, exist_ok=True)
    temporary = None
    safety_backup = None
    try:
        _validate_backup(source)
        if target.exists():
            safety_backup = target.with_name(
                f"{target.stem}.pre-restore-{datetime.now(UTC).strftime('%Y%m%dT%H%M%SZ')}{target.suffix}"
            )
            backup_database(safety_backup, target)
        with tempfile.NamedTemporaryFile(
            dir=target.parent,
            prefix=f".{target.name}.",
            suffix=".restore",
            delete=False,
        ) as handle:
            temporary = Path(handle.name)
        shutil.copyfile(source, temporary)
        _validate_backup(temporary)
        os.replace(temporary, target)
        if os.name != "nt":
            target.chmod(0o600)
        return target
    except (OSError, sqlite3.Error, ValueError) as exc:
        if temporary:
            temporary.unlink(missing_ok=True)
        if safety_backup and safety_backup.exists() and not target.exists():
            os.replace(safety_backup, target)
        if isinstance(exc, ValueError):
            raise
        raise ValueError(
            "Backup restore failed; the current database was preserved."
        ) from exc


def restore_bytes(
    contents: bytes,
    destination: str | Path | None = None,
    *,
    confirmed: bool = False,
) -> Path:
    if len(contents) > MAX_RESTORE_BYTES:
        raise ValueError("Backup exceeds the 250 MiB restore limit.")
    with tempfile.TemporaryDirectory(prefix="netmap-restore-") as temp:
        source = Path(temp) / "uploaded-backup.sqlite3"
        source.write_bytes(contents)
        return restore_database(source, destination, confirmed=confirmed)


def database_status(path: str | Path | None = None) -> dict[str, Any]:
    target = Path(path) if path else database_path()
    if not target.exists():
        return {"path": str(target), "initialized": False, "version": 0}
    with _database(target) as db:
        version = int(db.execute("PRAGMA user_version").fetchone()[0])
        _check_database(db)
    return {"path": str(target), "initialized": True, "version": version}
