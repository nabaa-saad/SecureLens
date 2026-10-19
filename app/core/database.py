"""
Database handler for SQLite operations.

The application now uses shared scan records plus per-user access mappings so
the website and browser extension can reuse the same analysis results without
duplicating scans for each user.
"""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from .config import get_settings
from .security import hash_token_value


def _utcnow() -> datetime:
    return datetime.utcnow()


def _to_db_timestamp(value: datetime) -> str:
    return value.strftime("%Y-%m-%d %H:%M:%S")


def _parse_db_timestamp(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    for fmt in ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S"):
        try:
            return datetime.strptime(value, fmt)
        except ValueError:
            continue
    return None


def _json_dumps(value: Any) -> Optional[str]:
    if value is None:
        return None
    return json.dumps(value)


class DatabaseHandler:
    """SQLite database handler for scan data, users, and extension sessions."""

    def __init__(self, db_name: str | Path | None = None):
        base_dir = get_settings().project_root
        database_name = db_name or get_settings().database_name
        database_path = Path(database_name)
        self.db_path = (
            database_path
            if database_path.is_absolute()
            else base_dir / database_path
        )
        self.init_db()

    def get_connection(self) -> sqlite3.Connection:
        """Get a database connection with row dictionaries enabled."""
        conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        return conn

    def init_db(self):
        """Initialize database tables and run migrations."""
        conn = self.get_connection()
        cursor = conn.cursor()

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT NOT NULL,
                canonical_domain TEXT,
                original_input TEXT,
                analysis_mode TEXT DEFAULT 'deep',
                source_context TEXT DEFAULT 'website',
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                verdict TEXT,
                risk_score INTEGER,
                status TEXT DEFAULT 'PENDING',
                scan_duration REAL,
                redirect_chain TEXT,
                http_headers TEXT,
                page_meta TEXT,
                dom_stats TEXT,
                server_info TEXT,
                risk_breakdown TEXT,
                security_headers TEXT,
                security_headers_score INTEGER,
                progress_stage TEXT,
                progress_step INTEGER,
                progress_message TEXT,
                progress_percent INTEGER DEFAULT 0,
                progress_updated_at DATETIME,
                open_ports TEXT,
                ports_last_updated DATETIME,
                raw_data TEXT,
                llm_analysis TEXT,
                user_id INTEGER,
                is_saved INTEGER DEFAULT 0
            )
            """
        )
        self._migrate_scans_table(cursor)

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS rules (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                domain TEXT NOT NULL UNIQUE,
                rule_type TEXT NOT NULL,
                added_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
            """
        )

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                hashed_password TEXT NOT NULL,
                is_admin INTEGER DEFAULT 0,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        self._migrate_users_table(cursor)

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS app_config (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            )
            """
        )

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS scan_requests (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER NOT NULL,
                user_id INTEGER,
                requested_url TEXT,
                canonical_domain TEXT,
                source_context TEXT DEFAULT 'website',
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            )
            """
        )

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS saved_scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                scan_id INTEGER NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(user_id, scan_id),
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
                FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
            )
            """
        )

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS chat_messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER NOT NULL,
                user_id INTEGER,
                provider TEXT NOT NULL,
                role TEXT NOT NULL,
                content TEXT NOT NULL,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            )
            """
        )
        self._migrate_chat_messages_table(cursor)

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS token_blacklist (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                jti TEXT NOT NULL UNIQUE,
                expires_at DATETIME NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
            """
        )

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS extension_pairings (
                pairing_id TEXT PRIMARY KEY,
                approval_code TEXT NOT NULL UNIQUE,
                poll_token_hash TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'PENDING',
                requested_by TEXT,
                approved_by_user_id INTEGER,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                expires_at DATETIME NOT NULL,
                approved_at DATETIME,
                delivered_at DATETIME,
                FOREIGN KEY (approved_by_user_id) REFERENCES users(id) ON DELETE SET NULL
            )
            """
        )

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS extension_sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                pairing_id TEXT,
                token_hash TEXT NOT NULL UNIQUE,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                expires_at DATETIME NOT NULL,
                revoked_at DATETIME,
                last_used_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
                FOREIGN KEY (pairing_id) REFERENCES extension_pairings(pairing_id) ON DELETE SET NULL
            )
            """
        )

        self._backfill_legacy_user_relations(cursor)

        conn.commit()
        conn.close()

    def _migrate_scans_table(self, cursor: sqlite3.Cursor):
        """Run scans table migrations."""
        columns_to_add = [
            "scan_duration REAL",
            "risk_breakdown TEXT",
            "security_headers TEXT",
            "security_headers_score INTEGER",
            "user_id INTEGER",
            "is_saved INTEGER DEFAULT 0",
            "canonical_domain TEXT",
            "original_input TEXT",
            "analysis_mode TEXT DEFAULT 'deep'",
            "source_context TEXT DEFAULT 'website'",
            "progress_stage TEXT",
            "progress_step INTEGER",
            "progress_message TEXT",
            "progress_percent INTEGER DEFAULT 0",
            "progress_updated_at DATETIME",
            "open_ports TEXT",
            "ports_last_updated DATETIME",
        ]
        for column in columns_to_add:
            try:
                cursor.execute(f"ALTER TABLE scans ADD COLUMN {column}")
            except sqlite3.OperationalError:
                pass

    def _migrate_users_table(self, cursor: sqlite3.Cursor):
        """Run user table migrations."""
        columns = [
            "is_admin INTEGER DEFAULT 0",
            "created_at DATETIME DEFAULT CURRENT_TIMESTAMP",
            "email TEXT",
            "failed_login_attempts INTEGER DEFAULT 0",
            "locked_until DATETIME",
            "last_login DATETIME",
            "must_change_password INTEGER DEFAULT 0",
            "is_primary_admin INTEGER DEFAULT 0",
        ]
        for column in columns:
            try:
                cursor.execute(f"ALTER TABLE users ADD COLUMN {column}")
            except sqlite3.OperationalError:
                pass

    def _migrate_chat_messages_table(self, cursor: sqlite3.Cursor):
        """Add new chat columns when migrating an older database."""
        try:
            cursor.execute("ALTER TABLE chat_messages ADD COLUMN user_id INTEGER")
        except sqlite3.OperationalError:
            pass

    def _backfill_legacy_user_relations(self, cursor: sqlite3.Cursor):
        """Backfill legacy per-scan ownership into the new shared-scan tables."""
        cursor.execute(
            """
            INSERT INTO scan_requests (scan_id, user_id, requested_url, canonical_domain, source_context, created_at)
            SELECT
                s.id,
                s.user_id,
                COALESCE(s.original_input, s.url),
                s.canonical_domain,
                COALESCE(s.source_context, 'website'),
                COALESCE(s.timestamp, CURRENT_TIMESTAMP)
            FROM scans s
            WHERE s.user_id IS NOT NULL
              AND NOT EXISTS (
                  SELECT 1
                  FROM scan_requests sr
                  WHERE sr.scan_id = s.id AND sr.user_id = s.user_id
              )
            """
        )
        cursor.execute(
            """
            INSERT INTO saved_scans (user_id, scan_id, created_at)
            SELECT
                s.user_id,
                s.id,
                COALESCE(s.timestamp, CURRENT_TIMESTAMP)
            FROM scans s
            WHERE s.user_id IS NOT NULL
              AND COALESCE(s.is_saved, 0) = 1
              AND NOT EXISTS (
                  SELECT 1
                  FROM saved_scans ss
                  WHERE ss.scan_id = s.id AND ss.user_id = s.user_id
              )
            """
        )
        cursor.execute(
            """
            UPDATE chat_messages
            SET user_id = (
                SELECT s.user_id
                FROM scans s
                WHERE s.id = chat_messages.scan_id
            )
            WHERE user_id IS NULL
              AND EXISTS (
                  SELECT 1
                  FROM scans s
                  WHERE s.id = chat_messages.scan_id
                    AND s.user_id IS NOT NULL
              )
            """
        )

    def has_any_users(self) -> bool:
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM users")
        count = cursor.fetchone()[0]
        conn.close()
        return count > 0

    def has_admin_users(self) -> bool:
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM users WHERE is_admin = 1")
        count = cursor.fetchone()[0]
        conn.close()
        return count > 0

    # --- Configuration Management ---
    def set_config(self, key: str, value: str):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute(
            "INSERT OR REPLACE INTO app_config (key, value) VALUES (?, ?)",
            (key, value),
        )
        conn.commit()
        conn.close()

    def get_config_value(self, key: str) -> Optional[str]:
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT value FROM app_config WHERE key = ?", (key,))
        row = cursor.fetchone()
        conn.close()
        return row[0] if row else None

    # --- Scan Operations ---
    def create_pending_scan(
        self,
        url: str,
        user_id: Optional[int] = None,
        *,
        canonical_domain: Optional[str] = None,
        original_input: Optional[str] = None,
        analysis_mode: str = "deep",
        source_context: str = "website",
    ) -> int:
        """Create a new pending scan and return its ID."""
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO scans (
                url, canonical_domain, original_input, analysis_mode,
                source_context, status, user_id, progress_stage, progress_step,
                progress_message, progress_percent, progress_updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                url,
                canonical_domain,
                original_input or url,
                analysis_mode,
                source_context,
                "PENDING",
                user_id,
                "queued",
                1,
                "Preparing the staged analysis pipeline...",
                3,
                _to_db_timestamp(_utcnow()),
            ),
        )
        scan_id = cursor.lastrowid
        conn.commit()
        conn.close()
        return scan_id

    def create_scan_request(
        self,
        scan_id: int,
        user_id: Optional[int],
        requested_url: str,
        canonical_domain: str,
        source_context: str = "website",
    ) -> int:
        """Record that a user requested access to a shared scan."""
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO scan_requests (scan_id, user_id, requested_url, canonical_domain, source_context)
            VALUES (?, ?, ?, ?, ?)
            """,
            (scan_id, user_id, requested_url, canonical_domain, source_context),
        )
        request_id = cursor.lastrowid
        conn.commit()
        conn.close()
        return request_id

    def get_scan(self, scan_id: int) -> Optional[Dict[str, Any]]:
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM scans WHERE id = ?", (scan_id,))
        row = cursor.fetchone()
        conn.close()
        return dict(row) if row else None

    def get_cached_scan_by_domain(
        self,
        canonical_domain: str,
        analysis_mode: str = "deep",
        hours_valid: int = 24,
    ) -> Optional[Dict[str, Any]]:
        """Return a fresh completed shared scan for the canonical domain."""
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT * FROM scans
            WHERE canonical_domain = ? AND analysis_mode = ? AND status = 'COMPLETED'
            ORDER BY timestamp DESC
            LIMIT 1
            """,
            (canonical_domain, analysis_mode),
        )
        row = cursor.fetchone()
        conn.close()

        if not row:
            return None

        scan = dict(row)
        scan_time = _parse_db_timestamp(scan.get("timestamp"))
        if hours_valid <= 0:
            return scan
        if scan_time and _utcnow() - scan_time < timedelta(hours=hours_valid):
            return scan
        return None

    def get_pending_scan_by_domain(
        self,
        canonical_domain: str,
        analysis_mode: str = "deep",
    ) -> Optional[Dict[str, Any]]:
        """Return an active pending scan for the canonical domain when one exists."""
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT * FROM scans
            WHERE canonical_domain = ? AND analysis_mode = ? AND status = 'PENDING'
            ORDER BY timestamp DESC
            LIMIT 1
            """,
            (canonical_domain, analysis_mode),
        )
        row = cursor.fetchone()
        conn.close()
        return dict(row) if row else None

    def update_scan_results(
        self,
        scan_id: int,
        verdict: str,
        risk_score: int,
        raw_data: Dict[str, Any],
        llm_analysis: str,
        redirect_chain: List[Dict[str, Any]],
        http_headers: Dict[str, Any],
        page_meta: Dict[str, Any],
        dom_stats: Dict[str, Any],
        server_info: Dict[str, Any],
        risk_breakdown: Optional[List[Dict[str, Any]]] = None,
        security_headers: Optional[Dict[str, Any]] = None,
        security_headers_score: int = 0,
        scan_duration: Optional[float] = None,
        open_ports: Optional[List[int]] = None,
        ports_last_updated: Optional[datetime] = None,
    ):
        """Update a scan row with completed results."""
        detected_ports = open_ports
        if detected_ports is None:
            shodan = (raw_data or {}).get("Shodan", {})
            if isinstance(shodan, dict):
                detected_ports = shodan.get("ports") or []

        if ports_last_updated is None and detected_ports is not None:
            ports_last_updated = _utcnow()

        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute(
            """
            UPDATE scans
            SET verdict = ?, risk_score = ?, raw_data = ?, llm_analysis = ?, status = 'COMPLETED',
                redirect_chain = ?, http_headers = ?, page_meta = ?, dom_stats = ?, server_info = ?,
                risk_breakdown = ?, security_headers = ?, security_headers_score = ?, scan_duration = ?,
                progress_stage = 'completed', progress_step = 4,
                progress_message = 'Scan completed successfully.',
                progress_percent = 100, progress_updated_at = CURRENT_TIMESTAMP,
                open_ports = ?, ports_last_updated = ?
            WHERE id = ?
            """,
            (
                verdict,
                risk_score,
                _json_dumps(raw_data),
                llm_analysis,
                _json_dumps(redirect_chain),
                _json_dumps(http_headers),
                _json_dumps(page_meta),
                _json_dumps(dom_stats),
                _json_dumps(server_info),
                _json_dumps(risk_breakdown),
                _json_dumps(security_headers),
                security_headers_score,
                scan_duration,
                _json_dumps(detected_ports),
                _to_db_timestamp(ports_last_updated) if ports_last_updated else None,
                scan_id,
            ),
        )
        conn.commit()
        conn.close()

    def update_scan_error(self, scan_id: int, error_message: str, scan_duration: Optional[float] = None):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute(
            """
            UPDATE scans
            SET status = 'FAILED', llm_analysis = ?, scan_duration = ?,
                progress_stage = 'failed', progress_step = 4,
                progress_message = ?, progress_percent = 100,
                progress_updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
            """,
            (f"Scan failed: {error_message}", scan_duration, f"Scan failed: {error_message}", scan_id),
        )
        conn.commit()
        conn.close()

    def update_scan_progress(
        self,
        scan_id: int,
        *,
        stage: str,
        step: int,
        message: str,
        percent: int,
    ):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute(
            """
            UPDATE scans
            SET progress_stage = ?, progress_step = ?, progress_message = ?,
                progress_percent = ?, progress_updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
            """,
            (
                (stage or "").strip().lower(),
                max(1, int(step or 1)),
                message,
                max(0, min(100, int(percent or 0))),
                scan_id,
            ),
        )
        conn.commit()
        conn.close()

    def update_scan_ports(
        self,
        scan_id: int,
        open_ports: List[int],
        refreshed_at: Optional[datetime] = None,
    ):
        """Update port enrichment without affecting the rest of the scan record."""
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute(
            """
            UPDATE scans
            SET open_ports = ?, ports_last_updated = ?
            WHERE id = ?
            """,
            (
                _json_dumps(sorted(open_ports)),
                _to_db_timestamp(refreshed_at or _utcnow()),
                scan_id,
            ),
        )
        conn.commit()
        conn.close()

    def get_latest_ports_for_domain(self, canonical_domain: str) -> Optional[Dict[str, Any]]:
        """Return the newest port enrichment for a canonical domain."""
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT open_ports, ports_last_updated, id
            FROM scans
            WHERE canonical_domain = ? AND open_ports IS NOT NULL
            ORDER BY COALESCE(ports_last_updated, timestamp) DESC
            LIMIT 1
            """,
            (canonical_domain,),
        )
        row = cursor.fetchone()
        conn.close()
        if not row:
            return None

        payload = dict(row)
        try:
            payload["open_ports"] = json.loads(payload["open_ports"]) if payload.get("open_ports") else []
        except (json.JSONDecodeError, TypeError):
            payload["open_ports"] = []
        return payload

    def user_can_access_scan(self, user_id: int, scan_id: int) -> bool:
        """Check whether a logged-in user has an access record for a scan."""
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT 1
            FROM scan_requests
            WHERE user_id = ? AND scan_id = ?
            UNION
            SELECT 1
            FROM scans
            WHERE user_id = ? AND id = ?
            LIMIT 1
            """,
            (user_id, scan_id, user_id, scan_id),
        )
        result = cursor.fetchone()
        conn.close()
        return result is not None

    def count_scan_requests(self, scan_id: int) -> int:
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM scan_requests WHERE scan_id = ?", (scan_id,))
        count = cursor.fetchone()[0]
        conn.close()
        return count

    def maybe_delete_orphan_scan(self, scan_id: int):
        """Delete scans no longer referenced by any user-specific records."""
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM scan_requests WHERE scan_id = ?", (scan_id,))
        request_count = cursor.fetchone()[0]
        cursor.execute("SELECT COUNT(*) FROM saved_scans WHERE scan_id = ?", (scan_id,))
        saved_count = cursor.fetchone()[0]
        cursor.execute("SELECT COUNT(*) FROM chat_messages WHERE scan_id = ?", (scan_id,))
        chat_count = cursor.fetchone()[0]
        if request_count == 0 and saved_count == 0 and chat_count == 0:
            cursor.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
        conn.commit()
        conn.close()

    def get_recent_scans(self, limit: int = 10, user_id: Optional[int] = None) -> List[Dict[str, Any]]:
        """Get recent completed scans. User view is derived from access records."""
        conn = self.get_connection()
        cursor = conn.cursor()

        if user_id is not None:
            cursor.execute(
                """
                WITH latest_requests AS (
                    SELECT sr.scan_id, sr.requested_url, sr.created_at
                    FROM scan_requests sr
                    JOIN (
                        SELECT scan_id, MAX(id) AS latest_id
                        FROM scan_requests
                        WHERE user_id = ?
                        GROUP BY scan_id
                    ) latest ON latest.latest_id = sr.id
                )
                SELECT s.*, lr.created_at AS requested_at, lr.requested_url AS requested_url
                FROM latest_requests lr
                JOIN scans s ON s.id = lr.scan_id
                WHERE s.status = 'COMPLETED' AND COALESCE(s.analysis_mode, 'deep') = 'deep'
                ORDER BY lr.created_at DESC
                LIMIT ?
                """,
                (user_id, limit),
            )
        else:
            cursor.execute(
                """
                SELECT *
                FROM scans
                WHERE status = 'COMPLETED' AND COALESCE(analysis_mode, 'deep') = 'deep'
                ORDER BY timestamp DESC
                LIMIT ?
                """,
                (limit,),
            )

        rows = cursor.fetchall()
        conn.close()
        return [dict(row) for row in rows]

    def get_latest_request_for_scan(self, scan_id: int, user_id: int) -> Optional[Dict[str, Any]]:
        """Return the latest request metadata for a user's shared scan."""
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT requested_url, created_at, source_context
            FROM scan_requests
            WHERE scan_id = ? AND user_id = ?
            ORDER BY id DESC
            LIMIT 1
            """,
            (scan_id, user_id),
        )
        row = cursor.fetchone()
        conn.close()
        return dict(row) if row else None

    def get_stats(self, user_id: Optional[int] = None) -> Dict[str, int]:
        """Get scan statistics."""
        conn = self.get_connection()
        cursor = conn.cursor()
        stats = {"MALICIOUS": 0, "SUSPICIOUS": 0, "CAUTION": 0, "SAFE": 0, "TOTAL": 0}

        try:
            if user_id is not None:
                cursor.execute(
                    """
                    SELECT s.verdict, COUNT(DISTINCT s.id)
                    FROM scan_requests sr
                    JOIN scans s ON s.id = sr.scan_id
                    WHERE sr.user_id = ? AND s.status = 'COMPLETED' AND COALESCE(s.analysis_mode, 'deep') = 'deep'
                    GROUP BY s.verdict
                    """,
                    (user_id,),
                )
            else:
                cursor.execute(
                    "SELECT verdict, COUNT(*) FROM scans WHERE status = 'COMPLETED' AND COALESCE(analysis_mode, 'deep') = 'deep' GROUP BY verdict"
                )

            for verdict, count in cursor.fetchall():
                if verdict == "CAUTION":
                    stats["CAUTION"] = count
                    stats["SUSPICIOUS"] += count
                elif verdict in stats:
                    stats[verdict] = count
                stats["TOTAL"] += count
        finally:
            conn.close()

        return stats

    def delete_scan_for_user(self, scan_id: int, user_id: int):
        """Remove a user's access and user-scoped data for a scan."""
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute("DELETE FROM scan_requests WHERE scan_id = ? AND user_id = ?", (scan_id, user_id))
        cursor.execute("DELETE FROM saved_scans WHERE scan_id = ? AND user_id = ?", (scan_id, user_id))
        cursor.execute("DELETE FROM chat_messages WHERE scan_id = ? AND user_id = ?", (scan_id, user_id))
        cursor.execute(
            "UPDATE scans SET user_id = NULL, is_saved = 0 WHERE id = ? AND user_id = ?",
            (scan_id, user_id),
        )
        conn.commit()
        conn.close()
        self.maybe_delete_orphan_scan(scan_id)

    def delete_scan(self, scan_id: int):
        """Hard-delete a scan and all dependent data."""
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
        conn.commit()
        conn.close()

    def toggle_save_scan(self, scan_id: int, user_id: int) -> bool:
        """Toggle the saved status of a scan for a specific user."""
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT id FROM saved_scans WHERE scan_id = ? AND user_id = ?",
            (scan_id, user_id),
        )
        row = cursor.fetchone()
        if row:
            cursor.execute(
                "DELETE FROM saved_scans WHERE scan_id = ? AND user_id = ?",
                (scan_id, user_id),
            )
            saved = False
        else:
            cursor.execute(
                "INSERT INTO saved_scans (user_id, scan_id) VALUES (?, ?)",
                (user_id, scan_id),
            )
            saved = True
        conn.commit()
        conn.close()
        return saved

    def get_saved_scans(self, user_id: int) -> List[Dict[str, Any]]:
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT s.*, ss.created_at AS saved_at
            FROM saved_scans ss
            JOIN scans s ON s.id = ss.scan_id
            WHERE ss.user_id = ?
            ORDER BY ss.created_at DESC
            """,
            (user_id,),
        )
        rows = cursor.fetchall()
        conn.close()
        return [dict(row) for row in rows]

    def is_scan_saved(self, scan_id: int, user_id: Optional[int] = None) -> bool:
        if user_id is None:
            return False
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT 1 FROM saved_scans WHERE scan_id = ? AND user_id = ?",
            (scan_id, user_id),
        )
        row = cursor.fetchone()
        conn.close()
        return row is not None

    # --- User Operations ---
    def get_user(self, username: str) -> Optional[Dict[str, Any]]:
        candidate = (username or "").strip()
        if not candidate:
            return None
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT * FROM users WHERE username = ? COLLATE NOCASE",
            (candidate,),
        )
        user = cursor.fetchone()
        conn.close()
        return dict(user) if user else None

    def get_user_by_id(self, user_id: int) -> Optional[Dict[str, Any]]:
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
        user = cursor.fetchone()
        conn.close()
        return dict(user) if user else None

    def create_user(
        self,
        username: str,
        hashed_password: str,
        is_admin: bool = False,
        is_primary_admin: bool = False,
    ) -> Optional[int]:
        candidate = (username or "").strip()
        if not candidate:
            return None
        conn = self.get_connection()
        cursor = conn.cursor()
        try:
            cursor.execute(
                "SELECT 1 FROM users WHERE username = ? COLLATE NOCASE",
                (candidate,),
            )
            if cursor.fetchone():
                return None
            cursor.execute(
                """
                INSERT INTO users (username, hashed_password, is_admin, is_primary_admin)
                VALUES (?, ?, ?, ?)
                """,
                (candidate, hashed_password, 1 if is_admin else 0, 1 if is_primary_admin else 0),
            )
            user_id = cursor.lastrowid
            conn.commit()
            return user_id
        except sqlite3.IntegrityError:
            return None
        finally:
            conn.close()

    def get_all_users(self) -> List[Dict[str, Any]]:
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT id, username, is_admin, is_primary_admin, created_at
            FROM users
            ORDER BY created_at DESC
            """
        )
        users = cursor.fetchall()
        conn.close()
        return [dict(row) for row in users]

    def delete_user(self, user_id: int):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT DISTINCT scan_id
            FROM (
                SELECT scan_id FROM scan_requests WHERE user_id = ?
                UNION
                SELECT scan_id FROM saved_scans WHERE user_id = ?
                UNION
                SELECT scan_id FROM chat_messages WHERE user_id = ?
            )
            """,
            (user_id, user_id, user_id),
        )
        affected_scan_ids = [row[0] for row in cursor.fetchall()]
        cursor.execute("DELETE FROM chat_messages WHERE user_id = ?", (user_id,))
        cursor.execute("DELETE FROM saved_scans WHERE user_id = ?", (user_id,))
        cursor.execute("DELETE FROM scan_requests WHERE user_id = ?", (user_id,))
        cursor.execute("DELETE FROM extension_sessions WHERE user_id = ?", (user_id,))
        cursor.execute("UPDATE extension_pairings SET approved_by_user_id = NULL WHERE approved_by_user_id = ?", (user_id,))
        cursor.execute("UPDATE scans SET user_id = NULL, is_saved = 0 WHERE user_id = ?", (user_id,))
        cursor.execute("DELETE FROM users WHERE id = ?", (user_id,))
        conn.commit()
        conn.close()
        for scan_id in affected_scan_ids:
            self.maybe_delete_orphan_scan(scan_id)

    def toggle_user_admin(self, user_id: int):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute(
            """
            UPDATE users
            SET is_admin = CASE WHEN is_admin = 1 THEN 0 ELSE 1 END
            WHERE id = ?
            """,
            (user_id,),
        )
        conn.commit()
        conn.close()

    def get_user_scan_count(self, user_id: int) -> int:
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT COUNT(DISTINCT sr.scan_id)
            FROM scan_requests sr
            JOIN scans s ON s.id = sr.scan_id
            WHERE sr.user_id = ? AND COALESCE(s.analysis_mode, 'deep') = 'deep'
            """,
            (user_id,),
        )
        count = cursor.fetchone()[0]
        conn.close()
        return count

    # --- Rules Operations ---
    def add_rule(self, domain: str, rule_type: str) -> bool:
        normalized_domain = self._normalize_rule_domain(domain)
        normalized_rule_type = (rule_type or "").strip().upper()

        if not normalized_domain or normalized_rule_type not in {"WHITELIST", "BLACKLIST"}:
            return False

        conn = self.get_connection()
        cursor = conn.cursor()
        try:
            cursor.execute(
                "INSERT OR REPLACE INTO rules (domain, rule_type) VALUES (?, ?)",
                (normalized_domain, normalized_rule_type),
            )
            conn.commit()
            return True
        except Exception:
            return False
        finally:
            conn.close()

    def delete_rule(self, rule_id: int):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute("DELETE FROM rules WHERE id = ?", (rule_id,))
        conn.commit()
        conn.close()

    def get_rules(self) -> List[Dict[str, Any]]:
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM rules ORDER BY added_at DESC")
        rows = cursor.fetchall()
        conn.close()
        return [dict(row) for row in rows]

    def _normalize_rule_domain(self, domain: str) -> str:
        candidate = (domain or "").strip().lower()
        if not candidate:
            return ""

        if "://" not in candidate:
            candidate = f"http://{candidate}"

        parsed = urlparse(candidate)
        hostname = (parsed.hostname or "").strip().lower().rstrip(".")
        if hostname.startswith("www."):
            hostname = hostname[4:]
        return hostname

    # --- Chat History Operations ---
    def save_chat_message(self, scan_id: int, user_id: Optional[int], provider: str, role: str, content: str):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO chat_messages (scan_id, user_id, provider, role, content)
            VALUES (?, ?, ?, ?, ?)
            """,
            (scan_id, user_id, provider, role, content),
        )
        conn.commit()
        conn.close()

    def get_chat_history(self, scan_id: int, user_id: Optional[int], provider: str) -> List[Dict[str, Any]]:
        conn = self.get_connection()
        cursor = conn.cursor()
        if user_id is None:
            cursor.execute(
                """
                SELECT role, content, timestamp
                FROM chat_messages
                WHERE scan_id = ? AND user_id IS NULL AND provider = ?
                ORDER BY timestamp ASC
                """,
                (scan_id, provider),
            )
        else:
            cursor.execute(
                """
                SELECT role, content, timestamp
                FROM chat_messages
                WHERE scan_id = ? AND user_id = ? AND provider = ?
                ORDER BY timestamp ASC
                """,
                (scan_id, user_id, provider),
            )
        rows = cursor.fetchall()
        conn.close()
        return [dict(row) for row in rows]

    def clear_chat_history(self, scan_id: int, user_id: Optional[int], provider: str):
        conn = self.get_connection()
        cursor = conn.cursor()
        if user_id is None:
            cursor.execute(
                "DELETE FROM chat_messages WHERE scan_id = ? AND user_id IS NULL AND provider = ?",
                (scan_id, provider),
            )
        else:
            cursor.execute(
                "DELETE FROM chat_messages WHERE scan_id = ? AND user_id = ? AND provider = ?",
                (scan_id, user_id, provider),
            )
        conn.commit()
        conn.close()

    def delete_old_chat_messages(self, hours: int = 24):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute(
            """
            DELETE FROM chat_messages
            WHERE scan_id IN (
                SELECT id FROM scans
                WHERE timestamp < datetime('now', '-' || ? || ' hours')
            )
            """,
            (hours,),
        )
        conn.commit()
        conn.close()

    # --- Login Security Operations ---
    def increment_failed_login(self, username: str):
        candidate = (username or "").strip()
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute(
            """
            UPDATE users
            SET failed_login_attempts = COALESCE(failed_login_attempts, 0) + 1
            WHERE username = ? COLLATE NOCASE
            """,
            (candidate,),
        )
        cursor.execute(
            """
            UPDATE users
            SET locked_until = datetime('now', '+15 minutes')
            WHERE username = ? COLLATE NOCASE AND failed_login_attempts >= 5
            """,
            (candidate,),
        )
        conn.commit()
        conn.close()

    def reset_failed_login(self, username: str):
        candidate = (username or "").strip()
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE users SET failed_login_attempts = 0, locked_until = NULL WHERE username = ? COLLATE NOCASE",
            (candidate,),
        )
        conn.commit()
        conn.close()

    def is_account_locked(self, username: str) -> bool:
        candidate = (username or "").strip()
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT locked_until FROM users WHERE username = ? COLLATE NOCASE",
            (candidate,),
        )
        row = cursor.fetchone()
        conn.close()
        locked_until = _parse_db_timestamp(row[0] if row else None)
        return bool(locked_until and _utcnow() < locked_until)

    def get_lockout_remaining(self, username: str) -> int:
        candidate = (username or "").strip()
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT locked_until FROM users WHERE username = ? COLLATE NOCASE",
            (candidate,),
        )
        row = cursor.fetchone()
        conn.close()
        locked_until = _parse_db_timestamp(row[0] if row else None)
        if not locked_until:
            return 0
        return max(0, int((locked_until - _utcnow()).total_seconds()))

    def update_last_login(self, username: str):
        candidate = (username or "").strip()
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE username = ? COLLATE NOCASE",
            (candidate,),
        )
        conn.commit()
        conn.close()

    def set_must_change_password(self, user_id: int, value: bool = True):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE users SET must_change_password = ? WHERE id = ?",
            (1 if value else 0, user_id),
        )
        conn.commit()
        conn.close()

    def update_user_password(self, user_id: int, hashed_password: str):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute(
            """
            UPDATE users
            SET hashed_password = ?, must_change_password = 0
            WHERE id = ?
            """,
            (hashed_password, user_id),
        )
        conn.commit()
        conn.close()

    # --- Token Blacklist Operations ---
    def blacklist_token(self, jti: str, expires_at: datetime):
        conn = self.get_connection()
        cursor = conn.cursor()
        try:
            cursor.execute(
                "INSERT OR IGNORE INTO token_blacklist (jti, expires_at) VALUES (?, ?)",
                (jti, _to_db_timestamp(expires_at)),
            )
            conn.commit()
        finally:
            conn.close()

    def is_token_blacklisted(self, jti: str) -> bool:
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT 1 FROM token_blacklist WHERE jti = ?", (jti,))
        result = cursor.fetchone()
        conn.close()
        return result is not None

    def cleanup_expired_tokens(self):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute("DELETE FROM token_blacklist WHERE expires_at < datetime('now')")
        conn.commit()
        conn.close()

    # --- Extension Pairing Operations ---
    def create_extension_pairing(
        self,
        pairing_id: str,
        approval_code: str,
        poll_token: str,
        expires_at: datetime,
        requested_by: str = "",
    ):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO extension_pairings (
                pairing_id, approval_code, poll_token_hash, requested_by, expires_at
            ) VALUES (?, ?, ?, ?, ?)
            """,
            (
                pairing_id,
                approval_code,
                hash_token_value(poll_token),
                requested_by,
                _to_db_timestamp(expires_at),
            ),
        )
        conn.commit()
        conn.close()

    def get_extension_pairing_by_id(self, pairing_id: str) -> Optional[Dict[str, Any]]:
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM extension_pairings WHERE pairing_id = ?", (pairing_id,))
        row = cursor.fetchone()
        conn.close()
        return dict(row) if row else None

    def get_extension_pairing_for_poll(self, pairing_id: str, poll_token: str) -> Optional[Dict[str, Any]]:
        pairing = self.get_extension_pairing_by_id(pairing_id)
        if not pairing:
            return None
        if pairing.get("poll_token_hash") != hash_token_value(poll_token):
            return None

        expires_at = _parse_db_timestamp(pairing.get("expires_at"))
        if expires_at and expires_at < _utcnow() and pairing.get("status") == "PENDING":
            self.update_extension_pairing_status(pairing_id, "EXPIRED")
            pairing["status"] = "EXPIRED"
        return pairing

    def get_extension_pairing_for_approval(self, approval_code: str) -> Optional[Dict[str, Any]]:
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM extension_pairings WHERE approval_code = ?", (approval_code,))
        row = cursor.fetchone()
        conn.close()
        if not row:
            return None
        pairing = dict(row)
        expires_at = _parse_db_timestamp(pairing.get("expires_at"))
        if expires_at and expires_at < _utcnow() and pairing.get("status") == "PENDING":
            self.update_extension_pairing_status(pairing["pairing_id"], "EXPIRED")
            pairing["status"] = "EXPIRED"
        return pairing

    def update_extension_pairing_status(self, pairing_id: str, status: str):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE extension_pairings SET status = ? WHERE pairing_id = ?",
            (status, pairing_id),
        )
        conn.commit()
        conn.close()

    def approve_extension_pairing(self, pairing_id: str, user_id: int) -> bool:
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute(
            """
            UPDATE extension_pairings
            SET status = 'APPROVED', approved_by_user_id = ?, approved_at = CURRENT_TIMESTAMP
            WHERE pairing_id = ? AND status = 'PENDING' AND expires_at >= CURRENT_TIMESTAMP
            """,
            (user_id, pairing_id),
        )
        changed = cursor.rowcount > 0
        conn.commit()
        conn.close()
        return changed

    def mark_extension_pairing_delivered(self, pairing_id: str):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute(
            """
            UPDATE extension_pairings
            SET status = 'COMPLETED', delivered_at = CURRENT_TIMESTAMP
            WHERE pairing_id = ?
            """,
            (pairing_id,),
        )
        conn.commit()
        conn.close()

    # --- Extension Session Operations ---
    def create_extension_session(self, user_id: int, pairing_id: Optional[str], raw_token: str, expires_at: datetime) -> int:
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO extension_sessions (user_id, pairing_id, token_hash, expires_at)
            VALUES (?, ?, ?, ?)
            """,
            (user_id, pairing_id, hash_token_value(raw_token), _to_db_timestamp(expires_at)),
        )
        session_id = cursor.lastrowid
        conn.commit()
        conn.close()
        return session_id

    def get_extension_session(self, raw_token: str) -> Optional[Dict[str, Any]]:
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT es.*, u.username, u.is_admin
            FROM extension_sessions es
            JOIN users u ON u.id = es.user_id
            WHERE es.token_hash = ? AND es.revoked_at IS NULL
            LIMIT 1
            """,
            (hash_token_value(raw_token),),
        )
        row = cursor.fetchone()
        if not row:
            conn.close()
            return None

        session = dict(row)
        expires_at = _parse_db_timestamp(session.get("expires_at"))
        if expires_at and expires_at < _utcnow():
            cursor.execute(
                "UPDATE extension_sessions SET revoked_at = CURRENT_TIMESTAMP WHERE id = ?",
                (session["id"],),
            )
            conn.commit()
            conn.close()
            return None

        cursor.execute(
            "UPDATE extension_sessions SET last_used_at = CURRENT_TIMESTAMP WHERE id = ?",
            (session["id"],),
        )
        conn.commit()
        conn.close()
        return session

    def revoke_extension_session(self, raw_token: str):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute(
            """
            UPDATE extension_sessions
            SET revoked_at = CURRENT_TIMESTAMP
            WHERE token_hash = ? AND revoked_at IS NULL
            """,
            (hash_token_value(raw_token),),
        )
        conn.commit()
        conn.close()

    def revoke_extension_sessions_for_user(self, user_id: int):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute(
            """
            UPDATE extension_sessions
            SET revoked_at = CURRENT_TIMESTAMP
            WHERE user_id = ? AND revoked_at IS NULL
            """,
            (user_id,),
        )
        conn.commit()
        conn.close()

    def cleanup_expired_extension_sessions(self):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute(
            """
            UPDATE extension_sessions
            SET revoked_at = CURRENT_TIMESTAMP
            WHERE revoked_at IS NULL AND expires_at < CURRENT_TIMESTAMP
            """
        )
        cursor.execute(
            """
            UPDATE extension_pairings
            SET status = 'EXPIRED'
            WHERE status = 'PENDING' AND expires_at < CURRENT_TIMESTAMP
            """
        )
        conn.commit()
        conn.close()


# Singleton database instance
_db_instance: Optional[DatabaseHandler] = None


def get_db() -> DatabaseHandler:
    """Get the database handler singleton."""
    global _db_instance
    if _db_instance is None:
        _db_instance = DatabaseHandler()
    return _db_instance


def reset_db() -> None:
    """Reset the shared database instance, primarily for tests."""
    global _db_instance
    _db_instance = None
