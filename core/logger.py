"""
PentestBrowser - Database & Logging Manager
SQLite-based storage for HTTP traffic logs, tool outputs, and session data.
"""

import aiosqlite
import json
import time
from pathlib import Path
from typing import Optional, List, Dict, Any
from datetime import datetime

from core.config import LOGS_DIR


DB_PATH = LOGS_DIR / "pentestbrowser.db"

SCHEMA = """
CREATE TABLE IF NOT EXISTS http_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT NOT NULL,
    timestamp REAL NOT NULL,
    method TEXT NOT NULL,
    url TEXT NOT NULL,
    host TEXT,
    path TEXT,
    request_headers TEXT,
    request_body TEXT,
    status_code INTEGER,
    response_headers TEXT,
    response_body_preview TEXT,
    content_type TEXT,
    content_length INTEGER,
    duration_ms REAL,
    tags TEXT DEFAULT '[]',
    notes TEXT DEFAULT '',
    is_intercepted INTEGER DEFAULT 0,
    was_modified INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS tool_runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT NOT NULL,
    timestamp REAL NOT NULL,
    tool_name TEXT NOT NULL,
    command TEXT NOT NULL,
    target_url TEXT,
    args TEXT,
    status TEXT DEFAULT 'running',
    output TEXT DEFAULT '',
    exit_code INTEGER,
    duration_ms REAL,
    pid INTEGER
);

CREATE TABLE IF NOT EXISTS sessions (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    created_at REAL NOT NULL,
    target_scope TEXT DEFAULT '',
    notes TEXT DEFAULT '',
    is_active INTEGER DEFAULT 1
);

CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT NOT NULL,
    timestamp REAL NOT NULL,
    title TEXT NOT NULL,
    severity TEXT DEFAULT 'info',
    category TEXT DEFAULT '',
    description TEXT DEFAULT '',
    evidence TEXT DEFAULT '',
    source_tool TEXT DEFAULT '',
    source_request_id INTEGER,
    FOREIGN KEY (session_id) REFERENCES sessions(id),
    FOREIGN KEY (source_request_id) REFERENCES http_log(id)
);

CREATE INDEX IF NOT EXISTS idx_http_log_session ON http_log(session_id);
CREATE INDEX IF NOT EXISTS idx_http_log_host ON http_log(host);
CREATE INDEX IF NOT EXISTS idx_http_log_status ON http_log(status_code);
CREATE INDEX IF NOT EXISTS idx_tool_runs_session ON tool_runs(session_id);
CREATE INDEX IF NOT EXISTS idx_findings_session ON findings(session_id);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
"""


class LoggerDB:
    """Async SQLite database manager for all logging."""

    def __init__(self, db_path: Optional[Path] = None):
        self.db_path = db_path or DB_PATH
        self._db: Optional[aiosqlite.Connection] = None

    async def connect(self):
        """Initialize database connection and schema."""
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._db = await aiosqlite.connect(str(self.db_path))
        self._db.row_factory = aiosqlite.Row
        await self._db.execute("PRAGMA journal_mode=WAL")
        await self._db.execute("PRAGMA foreign_keys=ON")
        await self._db.executescript(SCHEMA)
        await self._db.commit()

    async def close(self):
        """Close the database connection."""
        if self._db:
            await self._db.close()

    # ── Sessions ────────────────────────────────────────────────

    async def create_session(self, session_id: str, name: str, target_scope: str = "") -> Dict:
        """Create a new audit session."""
        now = time.time()
        await self._db.execute(
            "INSERT INTO sessions (id, name, created_at, target_scope) VALUES (?, ?, ?, ?)",
            (session_id, name, now, target_scope)
        )
        await self._db.commit()
        return {"id": session_id, "name": name, "created_at": now, "target_scope": target_scope}

    async def get_sessions(self, active_only: bool = False) -> List[Dict]:
        """Get all sessions."""
        query = "SELECT * FROM sessions"
        if active_only:
            query += " WHERE is_active = 1"
        query += " ORDER BY created_at DESC"
        async with self._db.execute(query) as cursor:
            rows = await cursor.fetchall()
            return [dict(r) for r in rows]

    async def get_session(self, session_id: str) -> Optional[Dict]:
        """Get a specific session."""
        async with self._db.execute("SELECT * FROM sessions WHERE id = ?", (session_id,)) as cursor:
            row = await cursor.fetchone()
            return dict(row) if row else None

    # ── HTTP Logging ────────────────────────────────────────────

    async def log_request(self, session_id: str, method: str, url: str,
                          host: str = "", path: str = "",
                          request_headers: Optional[Dict] = None,
                          request_body: Optional[str] = None,
                          status_code: Optional[int] = None,
                          response_headers: Optional[Dict] = None,
                          response_body_preview: Optional[str] = None,
                          content_type: str = "",
                          content_length: int = 0,
                          duration_ms: float = 0,
                          is_intercepted: bool = False,
                          was_modified: bool = False) -> int:
        """Log an HTTP request/response pair."""
        now = time.time()
        cursor = await self._db.execute(
            """INSERT INTO http_log 
               (session_id, timestamp, method, url, host, path, 
                request_headers, request_body, status_code,
                response_headers, response_body_preview,
                content_type, content_length, duration_ms,
                is_intercepted, was_modified)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (session_id, now, method, url, host, path,
             json.dumps(request_headers or {}),
             request_body,
             status_code,
             json.dumps(response_headers or {}),
             response_body_preview[:2000] if response_body_preview else None,
             content_type, content_length, duration_ms,
             int(is_intercepted), int(was_modified))
        )
        await self._db.commit()
        return cursor.lastrowid

    async def get_http_logs(self, session_id: str, limit: int = 200,
                            host_filter: str = "", method_filter: str = "",
                            status_filter: Optional[int] = None) -> List[Dict]:
        """Get HTTP logs with optional filters."""
        query = "SELECT * FROM http_log WHERE session_id = ?"
        params: List[Any] = [session_id]
        
        if host_filter:
            query += " AND host LIKE ?"
            params.append(f"%{host_filter}%")
        if method_filter:
            query += " AND method = ?"
            params.append(method_filter)
        if status_filter is not None:
            query += " AND status_code = ?"
            params.append(status_filter)
        
        query += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)
        
        async with self._db.execute(query, params) as cursor:
            rows = await cursor.fetchall()
            return [dict(r) for r in rows]

    async def get_http_log_detail(self, log_id: int) -> Optional[Dict]:
        """Get detailed HTTP log entry."""
        async with self._db.execute("SELECT * FROM http_log WHERE id = ?", (log_id,)) as cursor:
            row = await cursor.fetchone()
            return dict(row) if row else None

    async def delete_http_log(self, log_id: int, session_id: Optional[str] = None) -> int:
        """Delete a single HTTP log entry. Returns number of rows deleted."""
        if session_id:
            cursor = await self._db.execute(
                "DELETE FROM http_log WHERE id = ? AND session_id = ?",
                (log_id, session_id),
            )
        else:
            cursor = await self._db.execute(
                "DELETE FROM http_log WHERE id = ?",
                (log_id,),
            )
        await self._db.commit()
        return int(cursor.rowcount or 0)

    async def clear_http_logs(self, session_id: str) -> int:
        """Clear all HTTP logs for a given session. Returns number of rows deleted."""
        cursor = await self._db.execute(
            "DELETE FROM http_log WHERE session_id = ?",
            (session_id,),
        )
        await self._db.commit()
        return int(cursor.rowcount or 0)

    # ── Tool Runs ───────────────────────────────────────────────

    async def log_tool_start(self, session_id: str, tool_name: str,
                              command: str, target_url: str = "",
                              args: str = "", pid: int = 0) -> int:
        """Log the start of a tool execution."""
        now = time.time()
        cursor = await self._db.execute(
            """INSERT INTO tool_runs 
               (session_id, timestamp, tool_name, command, target_url, args, pid)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (session_id, now, tool_name, command, target_url, args, pid)
        )
        await self._db.commit()
        return cursor.lastrowid

    async def update_tool_output(self, run_id: int, output: str):
        """Append output to a tool run."""
        await self._db.execute(
            "UPDATE tool_runs SET output = output || ? WHERE id = ?",
            (output, run_id)
        )
        await self._db.commit()

    async def finish_tool_run(self, run_id: int, exit_code: int, duration_ms: float):
        """Mark a tool run as finished."""
        status = "success" if exit_code == 0 else "error"
        await self._db.execute(
            "UPDATE tool_runs SET status = ?, exit_code = ?, duration_ms = ? WHERE id = ?",
            (status, exit_code, duration_ms, run_id)
        )
        await self._db.commit()

    async def get_tool_runs(self, session_id: str, limit: int = 50) -> List[Dict]:
        """Get tool run history."""
        async with self._db.execute(
            "SELECT * FROM tool_runs WHERE session_id = ? ORDER BY timestamp DESC LIMIT ?",
            (session_id, limit)
        ) as cursor:
            rows = await cursor.fetchall()
            return [dict(r) for r in rows]

    async def get_tool_run(self, run_id: int) -> Optional[Dict]:
        """Get a single tool run by id."""
        async with self._db.execute(
            "SELECT * FROM tool_runs WHERE id = ?",
            (run_id,),
        ) as cursor:
            row = await cursor.fetchone()
            return dict(row) if row else None

    # ── Findings ────────────────────────────────────────────────

    async def add_finding(self, session_id: str, title: str, severity: str = "info",
                          category: str = "", description: str = "",
                          evidence: str = "", source_tool: str = "",
                          source_request_id: Optional[int] = None) -> int:
        """Add a security finding."""
        now = time.time()
        cursor = await self._db.execute(
            """INSERT INTO findings 
               (session_id, timestamp, title, severity, category, 
                description, evidence, source_tool, source_request_id)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (session_id, now, title, severity, category,
             description, evidence, source_tool, source_request_id)
        )
        await self._db.commit()
        return cursor.lastrowid

    async def get_findings(self, session_id: str) -> List[Dict]:
        """Get all findings for a session."""
        async with self._db.execute(
            "SELECT * FROM findings WHERE session_id = ? ORDER BY timestamp DESC",
            (session_id,)
        ) as cursor:
            rows = await cursor.fetchall()
            return [dict(r) for r in rows]

    # ── Stats ───────────────────────────────────────────────────

    async def get_session_stats(self, session_id: str) -> Dict:
        """Get summary statistics for a session."""
        stats = {}
        
        async with self._db.execute(
            "SELECT COUNT(*) as total FROM http_log WHERE session_id = ?",
            (session_id,)
        ) as cursor:
            row = await cursor.fetchone()
            stats["total_requests"] = row["total"]

        async with self._db.execute(
            "SELECT COUNT(*) as total FROM tool_runs WHERE session_id = ?",
            (session_id,)
        ) as cursor:
            row = await cursor.fetchone()
            stats["total_tool_runs"] = row["total"]

        async with self._db.execute(
            "SELECT COUNT(*) as total FROM findings WHERE session_id = ?",
            (session_id,)
        ) as cursor:
            row = await cursor.fetchone()
            stats["total_findings"] = row["total"]

        async with self._db.execute(
            """SELECT severity, COUNT(*) as count FROM findings 
               WHERE session_id = ? GROUP BY severity""",
            (session_id,)
        ) as cursor:
            rows = await cursor.fetchall()
            stats["findings_by_severity"] = {r["severity"]: r["count"] for r in rows}

        return stats
