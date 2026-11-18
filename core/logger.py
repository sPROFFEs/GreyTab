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

CREATE TABLE IF NOT EXISTS ws_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT NOT NULL,
    timestamp REAL NOT NULL,
    flow_id TEXT,
    url TEXT,
    host TEXT,
    direction TEXT,
    content TEXT,
    length INTEGER,
    is_text INTEGER DEFAULT 1
);

CREATE TABLE IF NOT EXISTS http_log_meta (
    log_id INTEGER PRIMARY KEY,
    highlight TEXT DEFAULT '',
    comment TEXT DEFAULT '',
    updated_at REAL
);

CREATE INDEX IF NOT EXISTS idx_http_log_session ON http_log(session_id);
CREATE INDEX IF NOT EXISTS idx_http_log_host ON http_log(host);
CREATE INDEX IF NOT EXISTS idx_http_log_status ON http_log(status_code);
CREATE INDEX IF NOT EXISTS idx_tool_runs_session ON tool_runs(session_id);
CREATE INDEX IF NOT EXISTS idx_findings_session ON findings(session_id);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_ws_session ON ws_log(session_id);
CREATE INDEX IF NOT EXISTS idx_ws_flow ON ws_log(flow_id);
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

    async def import_project(self, project: Dict) -> Dict:
        """Import a project atomically, remapping all request references."""
        import uuid
        session_id = uuid.uuid4().hex[:8]
        session = project.get("session") or {}
        name = str(session.get("name") or "Project") + " (imported)"
        scope = str(session.get("target_scope") or "")
        now = time.time()
        async with aiosqlite.connect(str(self.db_path)) as conn:
            await conn.execute("PRAGMA foreign_keys=ON")
            await conn.execute("INSERT INTO sessions (id, name, created_at, target_scope) VALUES (?, ?, ?, ?)", (session_id, name, now, scope))
            id_map = {}
            for log in project.get("http_logs", []):
                columns = ["timestamp", "method", "url", "host", "path", "request_headers", "request_body", "status_code", "response_headers", "response_body_preview", "content_type", "content_length", "duration_ms"]
                values = []
                for column in columns:
                    value = log.get(column)
                    if column == "timestamp":
                        value = value or now
                    if column in {"request_headers", "response_headers"} and not isinstance(value, str):
                        value = json.dumps(value or {})
                    values.append(value)
                cursor = await conn.execute(f"INSERT INTO http_log (session_id, {', '.join(columns)}) VALUES ({', '.join('?' for _ in range(len(columns) + 1))})", [session_id, *values])
                id_map[log.get("id")] = cursor.lastrowid
                if log.get("highlight") or log.get("comment"):
                    await conn.execute("INSERT INTO http_log_meta (log_id, highlight, comment, updated_at) VALUES (?, ?, ?, ?)", (cursor.lastrowid, log.get("highlight", ""), log.get("comment", ""), now))
            for finding in project.get("findings", []):
                await conn.execute("INSERT INTO findings (session_id, timestamp, title, severity, category, description, evidence, source_tool, source_request_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)", (session_id, finding.get("timestamp") or now, finding.get("title") or "Finding", finding.get("severity") or "info", finding.get("category") or "", finding.get("description") or "", finding.get("evidence") or "", finding.get("source_tool") or "", id_map.get(finding.get("source_request_id"))))
            for run in project.get("tool_runs", []):
                await conn.execute("INSERT INTO tool_runs (session_id, timestamp, tool_name, command, target_url, status, output, exit_code, duration_ms) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)", (session_id, run.get("timestamp") or now, run.get("tool_name") or "imported", run.get("command") or "", run.get("target_url") or "", "interrupted" if run.get("status") == "running" else run.get("status") or "imported", run.get("output") or "", run.get("exit_code"), run.get("duration_ms")))
            for frame in project.get("ws_logs", []):
                await conn.execute("INSERT INTO ws_log (session_id, timestamp, flow_id, url, host, direction, content, length, is_text) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)", (session_id, frame.get("timestamp") or now, frame.get("flow_id") or "", frame.get("url") or "", frame.get("host") or "", frame.get("direction") or "", str(frame.get("content") or "")[:20000], int(frame.get("length") or 0), int(bool(frame.get("is_text", True)))))
            await conn.commit()
        return {"id": session_id, "name": name, "target_scope": scope, "created_at": now}

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
             response_body_preview[:1048576] if response_body_preview else None,
             content_type, content_length, duration_ms,
             int(is_intercepted), int(was_modified))
        )
        await self._db.commit()
        return cursor.lastrowid

    async def get_http_logs(self, session_id: str, limit: int = 200,
                            host_filter: str = "", method_filter: str = "",
                            status_filter: Optional[int] = None, after_id: int = 0,
                            summary: bool = False, offset: int = 0, *,
                            before_id: int = 0, search: str = "", status_class: int = 0,
                            mime: str = "", annotated: bool = False,
                            exact_host: str = "", path: str = "") -> List[Dict]:
        """Get HTTP logs with optional filters."""
        query = "SELECT h.*, COALESCE(m.highlight, '') AS highlight, COALESCE(m.comment, '') AS comment FROM http_log h LEFT JOIN http_log_meta m ON m.log_id = h.id WHERE h.session_id = ?"
        params: List[Any] = [session_id]
        if summary:
            query = query.replace("h.*", "h.id, h.session_id, h.timestamp, h.method, h.url, h.host, h.path, h.status_code, h.content_type, h.content_length, h.duration_ms, h.response_headers")
        if after_id:
            query += " AND h.id > ?"
            params.append(after_id)
        if before_id:
            query += " AND h.id < ?"
            params.append(before_id)
        
        if host_filter:
            query += " AND instr(lower(h.host), lower(?)) > 0"
            params.append(host_filter)
        if exact_host:
            query += " AND h.host = ? COLLATE NOCASE"
            params.append(exact_host)
        if path:
            query += " AND (h.path = ? OR substr(h.path, 1, length(?) + 1) = ? || '?')"
            params.extend([path, path, path])
        if method_filter:
            query += " AND h.method = ?"
            params.append(method_filter)
        if status_filter is not None:
            query += " AND h.status_code = ?"
            params.append(status_filter)
        if status_class:
            query += " AND h.status_code >= ? AND h.status_code < ?"
            params.extend([status_class * 100, (status_class + 1) * 100])
        if mime:
            query += " AND instr(lower(h.content_type), lower(?)) > 0"
            params.append(mime)
        if annotated:
            query += " AND (m.highlight <> '' OR m.comment <> '')"
        if search:
            query += """ AND (instr(lower(h.url), lower(?)) > 0
                           OR instr(lower(m.comment), lower(?)) > 0)"""
            params.extend([search, search])
        
        query += " ORDER BY h.id " + ("ASC" if after_id else "DESC") + " LIMIT ? OFFSET ?"
        params.extend([limit, offset])
        
        async with self._db.execute(query, params) as cursor:
            rows = await cursor.fetchall()
            return [dict(r) for r in rows]

    async def get_http_log_detail(self, log_id: int) -> Optional[Dict]:
        """Get detailed HTTP log entry."""
        async with self._db.execute(
            """SELECT h.*, COALESCE(m.highlight, '') AS highlight, COALESCE(m.comment, '') AS comment
               FROM http_log h LEFT JOIN http_log_meta m ON m.log_id = h.id WHERE h.id = ?""",
            (log_id,),
        ) as cursor:
            row = await cursor.fetchone()
            return dict(row) if row else None

    async def get_sitemap_counts(self, session_id: str) -> List[Dict]:
        """Group recent request metadata without materializing captured bodies."""
        async with self._db.execute(
            """SELECT host,
                      CASE WHEN instr(path, '?') > 0 THEN substr(path, 1, instr(path, '?') - 1)
                           ELSE path END AS endpoint,
                      method, status_code, COUNT(*) AS count
               FROM (SELECT host, path, method, status_code FROM http_log
                     WHERE session_id = ? ORDER BY id DESC LIMIT 20000)
               GROUP BY host, endpoint, method, status_code""",
            (session_id,),
        ) as cursor:
            return [dict(row) for row in await cursor.fetchall()]

    async def delete_http_log(self, log_id: int, session_id: Optional[str] = None) -> int:
        """Delete a single HTTP log entry. Returns number of rows deleted."""
        await self._db.execute("UPDATE findings SET source_request_id = NULL WHERE source_request_id = ? AND EXISTS (SELECT 1 FROM http_log WHERE id = ? AND (? IS NULL OR session_id = ?))", (log_id, log_id, session_id, session_id))
        await self._db.execute("DELETE FROM http_log_meta WHERE log_id = ? AND EXISTS (SELECT 1 FROM http_log WHERE id = ? AND (? IS NULL OR session_id = ?))", (log_id, log_id, session_id, session_id))
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
        await self._db.execute("UPDATE findings SET source_request_id = NULL WHERE source_request_id IN (SELECT id FROM http_log WHERE session_id = ?)", (session_id,))
        await self._db.execute("DELETE FROM http_log_meta WHERE log_id IN (SELECT id FROM http_log WHERE session_id = ?)", (session_id,))
        cursor = await self._db.execute(
            "DELETE FROM http_log WHERE session_id = ?",
            (session_id,),
        )
        await self._db.commit()
        return int(cursor.rowcount or 0)

    # ── WebSocket frames ────────────────────────────────────────

    async def log_ws_frame(self, session_id: str, flow_id: str, url: str, host: str,
                           direction: str, content: str, length: int, is_text: bool = True) -> int:
        now = time.time()
        cursor = await self._db.execute(
            """INSERT INTO ws_log
               (session_id, timestamp, flow_id, url, host, direction, content, length, is_text)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (session_id, now, flow_id, url, host, direction, (content or "")[:20000],
             int(length or 0), int(is_text))
        )
        await self._db.commit()
        return cursor.lastrowid

    async def get_ws_frames(self, session_id: str, flow_id: Optional[str] = None,
                            limit: int = 1000) -> List[Dict]:
        if flow_id:
            query = ("SELECT * FROM ws_log WHERE session_id = ? AND flow_id = ? "
                     "ORDER BY timestamp ASC LIMIT ?")
            params = (session_id, flow_id, limit)
        else:
            query = "SELECT * FROM ws_log WHERE session_id = ? ORDER BY timestamp DESC LIMIT ?"
            params = (session_id, limit)
        async with self._db.execute(query, params) as cursor:
            rows = await cursor.fetchall()
            return [dict(r) for r in rows]

    # ── Per-row highlight/comment overlay ───────────────────────

    async def set_log_meta(self, log_id: int, highlight: str = "", comment: str = "") -> None:
        now = time.time()
        await self._db.execute(
            """INSERT INTO http_log_meta (log_id, highlight, comment, updated_at)
               VALUES (?, ?, ?, ?)
               ON CONFLICT(log_id) DO UPDATE SET
                   highlight=excluded.highlight,
                   comment=excluded.comment,
                   updated_at=excluded.updated_at""",
            (log_id, highlight or "", comment or "", now),
        )
        await self._db.commit()

    async def get_log_meta(self, log_id: int) -> Dict:
        async with self._db.execute(
            "SELECT * FROM http_log_meta WHERE log_id = ?", (log_id,)
        ) as cursor:
            row = await cursor.fetchone()
            return dict(row) if row else {"log_id": log_id, "highlight": "", "comment": ""}

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

    async def get_tool_run(self, run_id: int, output_offset: int = 0) -> Optional[Dict]:
        """Get a single tool run by id."""
        async with self._db.execute(
            "SELECT id, session_id, timestamp, tool_name, command, target_url, args, status, exit_code, duration_ms, pid, substr(output, ?, 262144) AS output, length(output) AS output_length FROM tool_runs WHERE id = ?",
            (output_offset + 1, run_id),
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
