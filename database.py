"""
WinEvent Pro — Database
Stores scan sessions and threat alerts in a local SQLite database.
The database file lives in the user's home directory.
"""

import sqlite3
import os
from datetime import datetime
from typing import List, Optional, Tuple

from threat_engine import ThreatAlert


# ---------------------------------------------------------------------------
# Location
# ---------------------------------------------------------------------------

DB_PATH = os.path.join(os.path.expanduser("~"), "wineventpro_history.db")


# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------

_CREATE_SESSIONS = """
CREATE TABLE IF NOT EXISTS scan_sessions (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at   TEXT NOT NULL,
    ended_at     TEXT,
    scan_type    TEXT NOT NULL,
    channels     TEXT NOT NULL,
    hours_back   INTEGER,
    total_events INTEGER DEFAULT 0,
    total_alerts INTEGER DEFAULT 0
)
"""

_CREATE_ALERTS = """
CREATE TABLE IF NOT EXISTS threat_alerts (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id  INTEGER NOT NULL,
    severity    TEXT NOT NULL,
    rule_name   TEXT NOT NULL,
    description TEXT NOT NULL,
    event_id    INTEGER NOT NULL,
    channel     TEXT NOT NULL,
    timestamp   TEXT NOT NULL,
    computer    TEXT,
    user        TEXT,
    record_id   INTEGER,
    mitre       TEXT,
    FOREIGN KEY (session_id) REFERENCES scan_sessions (id)
)
"""


# ---------------------------------------------------------------------------
# Database
# ---------------------------------------------------------------------------

class Database:
    """
    Thin wrapper around SQLite for WinEvent Pro.
    All methods open and close their own connection so the object
    is safe to share across threads.
    """

    def __init__(self, path: str = DB_PATH):
        self.path = path
        self._init_schema()

    # ── Setup ───────────────────────────────────────────────────────────────

    def _init_schema(self):
        with self._connect() as conn:
            conn.execute(_CREATE_SESSIONS)
            conn.execute(_CREATE_ALERTS)

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path)
        conn.row_factory = sqlite3.Row
        return conn

    # ── Sessions ────────────────────────────────────────────────────────────

    def start_session(
        self,
        scan_type: str,
        channels: List[str],
        hours_back: Optional[int] = None,
    ) -> int:
        """
        Insert a new scan session row and return its ID.
        scan_type should be 'historical' or 'live'.
        """
        sql = """
            INSERT INTO scan_sessions (started_at, scan_type, channels, hours_back)
            VALUES (?, ?, ?, ?)
        """
        with self._connect() as conn:
            cur = conn.execute(
                sql,
                (
                    datetime.now().isoformat(sep=" ", timespec="seconds"),
                    scan_type,
                    ", ".join(channels),
                    hours_back,
                ),
            )
            return cur.lastrowid

    def close_session(self, session_id: int, total_events: int, total_alerts: int):
        """Mark a session as finished and record its final counts."""
        sql = """
            UPDATE scan_sessions
            SET ended_at = ?, total_events = ?, total_alerts = ?
            WHERE id = ?
        """
        with self._connect() as conn:
            conn.execute(
                sql,
                (
                    datetime.now().isoformat(sep=" ", timespec="seconds"),
                    total_events,
                    total_alerts,
                    session_id,
                ),
            )

    def get_sessions(self, limit: int = 50) -> List[sqlite3.Row]:
        """Return the most recent scan sessions, newest first."""
        sql = """
            SELECT * FROM scan_sessions
            ORDER BY id DESC
            LIMIT ?
        """
        with self._connect() as conn:
            return conn.execute(sql, (limit,)).fetchall()

    def delete_session(self, session_id: int):
        """Delete a session and all its associated alerts."""
        with self._connect() as conn:
            conn.execute(
                "DELETE FROM threat_alerts WHERE session_id = ?", (session_id,)
            )
            conn.execute(
                "DELETE FROM scan_sessions WHERE id = ?", (session_id,)
            )

    # ── Alerts ──────────────────────────────────────────────────────────────

    def save_alert(self, session_id: int, alert: ThreatAlert):
        """Insert a single ThreatAlert linked to the given session."""
        sql = """
            INSERT INTO threat_alerts
                (session_id, severity, rule_name, description,
                 event_id, channel, timestamp, computer, user, record_id, mitre)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """
        with self._connect() as conn:
            conn.execute(
                sql,
                (
                    session_id,
                    alert.severity,
                    alert.rule_name,
                    alert.description,
                    alert.event_id,
                    alert.channel,
                    alert.timestamp.isoformat(sep=" ", timespec="seconds"),
                    alert.computer,
                    alert.user,
                    alert.record_id,
                    alert.mitre,
                ),
            )

    def save_alerts(self, session_id: int, alerts: List[ThreatAlert]):
        """Bulk insert a list of ThreatAlert objects."""
        for alert in alerts:
            self.save_alert(session_id, alert)

    def get_alerts(self, session_id: int) -> List[sqlite3.Row]:
        """Return all alerts for a given session, ordered by severity then time."""
        severity_order = "CASE severity " \
            "WHEN 'CRITICAL' THEN 1 " \
            "WHEN 'HIGH' THEN 2 " \
            "WHEN 'MEDIUM' THEN 3 " \
            "WHEN 'LOW' THEN 4 " \
            "ELSE 5 END"
        sql = f"""
            SELECT * FROM threat_alerts
            WHERE session_id = ?
            ORDER BY {severity_order}, timestamp DESC
        """
        with self._connect() as conn:
            return conn.execute(sql, (session_id,)).fetchall()

    def get_recent_alerts(self, limit: int = 100) -> List[sqlite3.Row]:
        """Return the most recent alerts across all sessions."""
        severity_order = "CASE severity " \
            "WHEN 'CRITICAL' THEN 1 " \
            "WHEN 'HIGH' THEN 2 " \
            "WHEN 'MEDIUM' THEN 3 " \
            "WHEN 'LOW' THEN 4 " \
            "ELSE 5 END"
        sql = f"""
            SELECT ta.*, ss.started_at as session_started
            FROM threat_alerts ta
            JOIN scan_sessions ss ON ta.session_id = ss.id
            ORDER BY {severity_order}, ta.timestamp DESC
            LIMIT ?
        """
        with self._connect() as conn:
            return conn.execute(sql, (limit,)).fetchall()

    # ── Stats ───────────────────────────────────────────────────────────────

    def get_summary_stats(self) -> dict:
        """Return aggregate counts useful for the dashboard header."""
        with self._connect() as conn:
            total_sessions = conn.execute(
                "SELECT COUNT(*) FROM scan_sessions"
            ).fetchone()[0]

            total_alerts = conn.execute(
                "SELECT COUNT(*) FROM threat_alerts"
            ).fetchone()[0]

            critical = conn.execute(
                "SELECT COUNT(*) FROM threat_alerts WHERE severity = 'CRITICAL'"
            ).fetchone()[0]

            high = conn.execute(
                "SELECT COUNT(*) FROM threat_alerts WHERE severity = 'HIGH'"
            ).fetchone()[0]

            return {
                "total_sessions": total_sessions,
                "total_alerts":   total_alerts,
                "critical":       critical,
                "high":           high,
            }

    def clear_all(self):
        """Wipe the entire database. Used from the Settings dialog."""
        with self._connect() as conn:
            conn.execute("DELETE FROM threat_alerts")
            conn.execute("DELETE FROM scan_sessions")