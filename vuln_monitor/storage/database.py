import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import Optional

from loguru import logger

from vuln_monitor.config.settings import settings


class DatabaseManager:
    SCHEMA_SQL = """
    CREATE TABLE IF NOT EXISTS vulnerabilities (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        cve_id TEXT UNIQUE NOT NULL,
        title TEXT NOT NULL,
        description TEXT,
        severity TEXT,
        source TEXT NOT NULL,
        publish_date DATETIME NOT NULL,
        affected_products TEXT,
        fix_recommendation TEXT,
        "references" TEXT,
        poc_available BOOLEAN DEFAULT FALSE,
        kev_marked BOOLEAN DEFAULT FALSE,
        quality_score REAL DEFAULT 0.0,
        pushed BOOLEAN DEFAULT FALSE,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );

    CREATE INDEX IF NOT EXISTS idx_publish_date ON vulnerabilities(publish_date DESC);
    CREATE INDEX IF NOT EXISTS idx_source ON vulnerabilities(source);
    CREATE INDEX IF NOT EXISTS idx_pushed ON vulnerabilities(pushed);
    CREATE INDEX IF NOT EXISTS idx_severity ON vulnerabilities(severity);

    CREATE TABLE IF NOT EXISTS sources (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT UNIQUE NOT NULL,
        type TEXT NOT NULL,
        url TEXT NOT NULL,
        enabled BOOLEAN DEFAULT TRUE,
        crawl_interval INTEGER DEFAULT 15,
        last_crawl DATETIME,
        status TEXT DEFAULT 'active'
    );

    CREATE TABLE IF NOT EXISTS push_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        vulnerability_id INTEGER NOT NULL,
        channel TEXT NOT NULL,
        message_preview TEXT,
        status TEXT NOT NULL,
        error_message TEXT,
        pushed_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(vulnerability_id) REFERENCES vulnerabilities(id)
    );

    CREATE TABLE IF NOT EXISTS stats (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        stat_date DATE NOT NULL,
        total_count INTEGER DEFAULT 0,
        new_count INTEGER DEFAULT 0,
        pushed_count INTEGER DEFAULT 0,
        critical_count INTEGER DEFAULT 0,
        high_count INTEGER DEFAULT 0,
        medium_count INTEGER DEFAULT 0,
        low_count INTEGER DEFAULT 0,
        source_distribution TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(stat_date)
    );
    """

    def __init__(self, db_path: Optional[str] = None):
        self.db_path = db_path or settings.db_path
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _get_conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=30)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.execute("PRAGMA cache_size=-64000")
        conn.execute("PRAGMA foreign_keys=ON")
        return conn

    @contextmanager
    def _connection(self):
        conn = self._get_conn()
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def _init_db(self):
        with self._connection() as conn:
            conn.executescript(self.SCHEMA_SQL)
            logger.info(f"Database initialized: {self.db_path}")

    def insert_vulnerability(self, vuln: dict) -> bool:
        with self._connection() as conn:
            try:
                refs = vuln.get("references", [])
                if isinstance(refs, list):
                    refs = json.dumps(refs, ensure_ascii=False)

                conn.execute(
                    """INSERT OR IGNORE INTO vulnerabilities
                    (cve_id, title, description, severity, source, publish_date,
                     affected_products, fix_recommendation, "references",
                     poc_available, kev_marked, quality_score, pushed)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        vuln["cve_id"],
                        vuln["title"],
                        vuln.get("description"),
                        vuln.get("severity"),
                        vuln["source"],
                        vuln["publish_date"],
                        vuln.get("affected_products"),
                        vuln.get("fix_recommendation"),
                        refs,
                        vuln.get("poc_available", False),
                        vuln.get("kev_marked", False),
                        vuln.get("quality_score", 0.0),
                        False,
                    ),
                )
                return conn.total_changes > 0
            except sqlite3.IntegrityError:
                logger.debug(f"Duplicate vulnerability skipped: {vuln.get('cve_id')}")
                return False

    def update_vulnerability(self, cve_id: str, updates: dict):
        if not updates:
            return
        set_clauses = []
        values = []
        for key, value in updates.items():
            if key in ("id", "cve_id", "created_at"):
                continue
            if key == "references" and isinstance(value, list):
                value = json.dumps(value, ensure_ascii=False)
            quoted_key = f'"{key}"' if key == "references" else key
            set_clauses.append(f"{quoted_key} = ?")
            values.append(value)
        set_clauses.append("updated_at = ?")
        values.append(datetime.now().isoformat())
        values.append(cve_id)

        with self._connection() as conn:
            conn.execute(
                f"UPDATE vulnerabilities SET {', '.join(set_clauses)} WHERE cve_id = ?",
                values,
            )

    def vulnerability_exists(self, cve_id: str) -> bool:
        with self._connection() as conn:
            row = conn.execute(
                "SELECT 1 FROM vulnerabilities WHERE cve_id = ?", (cve_id,)
            ).fetchone()
            return row is not None

    def get_unpushed(self, score_threshold: float = 0.0) -> list[dict]:
        with self._connection() as conn:
            rows = conn.execute(
                """SELECT * FROM vulnerabilities
                WHERE pushed = FALSE AND quality_score >= ?
                ORDER BY quality_score DESC, publish_date DESC""",
                (score_threshold,),
            ).fetchall()
            return [dict(row) for row in rows]

    def mark_pushed(self, cve_id: str):
        with self._connection() as conn:
            conn.execute(
                "UPDATE vulnerabilities SET pushed = TRUE, updated_at = ? WHERE cve_id = ?",
                (datetime.now().isoformat(), cve_id),
            )

    def log_push(self, vuln_id: int, channel: str, message_preview: str, status: str, error_message: str = None):
        with self._connection() as conn:
            conn.execute(
                """INSERT INTO push_logs (vulnerability_id, channel, message_preview, status, error_message)
                VALUES (?, ?, ?, ?, ?)""",
                (vuln_id, channel, message_preview[:200] if message_preview else None, status, error_message),
            )

    def query_vulnerabilities(
        self,
        cve_id: Optional[str] = None,
        source: Optional[str] = None,
        keyword: Optional[str] = None,
        severity: Optional[str] = None,
        days: Optional[int] = None,
        pushed: Optional[bool] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[dict]:
        conditions = []
        params = []

        if cve_id:
            conditions.append("cve_id LIKE ?")
            params.append(f"%{cve_id}%")
        if source:
            conditions.append("source = ?")
            params.append(source)
        if keyword:
            conditions.append("(title LIKE ? OR description LIKE ? OR affected_products LIKE ?)")
            params.extend([f"%{keyword}%"] * 3)
        if severity:
            conditions.append("severity = ?")
            params.append(severity)
        if days is not None:
            conditions.append("publish_date >= datetime('now', ?)")
            params.append(f"-{days} days")
        if pushed is not None:
            conditions.append("pushed = ?")
            params.append(pushed)

        where_clause = " AND ".join(conditions) if conditions else "1=1"

        with self._connection() as conn:
            rows = conn.execute(
                f"""SELECT * FROM vulnerabilities WHERE {where_clause}
                ORDER BY publish_date DESC LIMIT ? OFFSET ?""",
                params + [limit, offset],
            ).fetchall()
            return [dict(row) for row in rows]

    def get_vulnerability(self, cve_id: str) -> Optional[dict]:
        with self._connection() as conn:
            row = conn.execute(
                "SELECT * FROM vulnerabilities WHERE cve_id = ?", (cve_id,)
            ).fetchone()
            return dict(row) if row else None

    def get_stats(self) -> dict:
        with self._connection() as conn:
            total = conn.execute("SELECT COUNT(*) FROM vulnerabilities").fetchone()[0]
            today = conn.execute(
                "SELECT COUNT(*) FROM vulnerabilities WHERE date(publish_date) = date('now')"
            ).fetchone()[0]
            pushed = conn.execute("SELECT COUNT(*) FROM vulnerabilities WHERE pushed = TRUE").fetchone()[0]
            unpushed = conn.execute("SELECT COUNT(*) FROM vulnerabilities WHERE pushed = FALSE").fetchone()[0]

            severity_dist = {}
            for row in conn.execute(
                "SELECT severity, COUNT(*) as cnt FROM vulnerabilities WHERE severity IS NOT NULL GROUP BY severity"
            ).fetchall():
                severity_dist[row["severity"]] = row["cnt"]

            source_dist = {}
            for row in conn.execute(
                "SELECT source, COUNT(*) as cnt FROM vulnerabilities GROUP BY source ORDER BY cnt DESC"
            ).fetchall():
                source_dist[row["source"]] = row["cnt"]

            return {
                "total": total,
                "today": today,
                "pushed": pushed,
                "unpushed": unpushed,
                "severity_distribution": severity_dist,
                "source_distribution": source_dist,
            }

    def cleanup_old_records(self, ttl_days: int = 60):
        with self._connection() as conn:
            result = conn.execute(
                "DELETE FROM vulnerabilities WHERE created_at < datetime('now', ?)",
                (f"-{ttl_days} days",),
            )
            logger.info(f"Cleaned up {result.rowcount} old records (TTL: {ttl_days} days)")

    def get_sources(self) -> list[dict]:
        with self._connection() as conn:
            rows = conn.execute("SELECT * FROM sources ORDER BY name").fetchall()
            return [dict(row) for row in rows]

    def upsert_source(self, source: dict):
        with self._connection() as conn:
            conn.execute(
                """INSERT INTO sources (name, type, url, enabled, crawl_interval, status)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(name) DO UPDATE SET
                    type=excluded.type, url=excluded.url,
                    enabled=excluded.enabled, crawl_interval=excluded.crawl_interval,
                    status=excluded.status""",
                (
                    source["name"],
                    source["type"],
                    source["url"],
                    source.get("enabled", True),
                    source.get("crawl_interval", 15),
                    source.get("status", "active"),
                ),
            )

    def toggle_source(self, name: str, enabled: bool):
        with self._connection() as conn:
            conn.execute("UPDATE sources SET enabled = ? WHERE name = ?", (enabled, name))

    def update_source_last_crawl(self, name: str):
        with self._connection() as conn:
            conn.execute(
                "UPDATE sources SET last_crawl = ? WHERE name = ?",
                (datetime.now().isoformat(), name),
            )
