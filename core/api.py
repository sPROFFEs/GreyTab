"""
PentestBrowser - FastAPI Backend
REST API + WebSocket server for the Chrome extension to communicate with.
"""

import asyncio
import json
import hashlib
import uuid
import time
import resource
from typing import Any, Dict, Set, Optional, List
from contextlib import asynccontextmanager

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, Query, File, UploadFile, Request
from fastapi.responses import PlainTextResponse
from fastapi.middleware.cors import CORSMiddleware
import os
from pydantic import BaseModel

from core.config import get_config, BrowserConfig, save_user_config, load_user_config, ToolDefinition
from core.logger import LoggerDB
from core.tools import ToolRunner
from core.proxy import ProxyManager
from core.scanner import ScannerEngine
from core.ai_agent import (
    AIAgentClient,
    AIAgentError,
    mask_ai_agent_config,
    normalize_ai_agent_config,
)
from core import extras as gx


# ── Globals ─────────────────────────────────────────────────────

config: BrowserConfig = get_config()
db = LoggerDB()
tool_runner = ToolRunner()
proxy_manager = ProxyManager(
    host=config.proxy.host,
    port=config.proxy.port,
)

# Active WebSocket connections
ws_connections: Set[WebSocket] = set()

# Captured during lifespan startup so proxy-thread callbacks can hand work
# back to the running uvicorn loop without relying on the deprecated
# asyncio.get_event_loop() (which raises in fresh threads on Py 3.12+).
_main_loop: Optional[asyncio.AbstractEventLoop] = None


def _schedule_on_main_loop(coro):
    """Submit a coroutine to the main loop from any thread."""
    loop = _main_loop
    if loop is None:
        return
    try:
        asyncio.run_coroutine_threadsafe(coro, loop)
    except RuntimeError:
        # Loop already shut down — silently drop.
        pass

# Current active session
current_session_id: Optional[str] = None

# Scanner engine
async def _persist_scanner_finding(finding):
    """Save a scanner finding into the findings table of the active session."""
    if not current_session_id:
        return
    try:
        ev_parts = []
        if getattr(finding, "payload", ""):
            ev_parts.append(f"payload: {finding.payload}")
        if getattr(finding, "request_raw", ""):
            ev_parts.append("---\nREQUEST:\n" + str(finding.request_raw)[:2000])
        if getattr(finding, "response_raw", ""):
            ev_parts.append("---\nRESPONSE:\n" + str(finding.response_raw)[:2000])
        evidence = "\n".join(ev_parts)
        title = f"{(finding.vuln_type or '').upper()} — {finding.parameter or finding.url}"
        description = str(getattr(finding, "evidence", "") or "")
        if getattr(finding, "ai_analysis", None):
            ai = finding.ai_analysis or {}
            description += f"\n\nAI verdict: {ai.get('verdict','')} (confidence {ai.get('confidence','')})"
            if ai.get("reasoning"):
                description += f"\nReasoning: {ai['reasoning']}"
        await db.add_finding(
            session_id=current_session_id,
            title=title[:240],
            severity=str(finding.severity or "info"),
            category=str(finding.vuln_type or ""),
            description=description[:4000],
            evidence=evidence[:8000],
            source_tool="scanner",
        )
    except Exception as e:
        print(f"[API] failed to persist scanner finding: {e}")


scanner = ScannerEngine(broadcast_fn=None, finding_persistor=_persist_scanner_finding)  # Broadcast set after function defined
ai_agent = AIAgentClient()
oast_hits: Dict[str, dict] = {}
ai_review_cache: Dict[str, dict] = {}
ai_feedback_stats: Dict[str, Dict[str, int]] = {}
OAST_HIT_TTL_SEC = 6 * 60 * 60


# ── Broadcast helper ────────────────────────────────────────────

async def broadcast(event_type: str, data: dict):
    """Send an event to all connected WebSocket clients."""
    message = json.dumps({"type": event_type, "data": data})
    dead = set()
    for ws in ws_connections:
        try:
            await ws.send_text(message)
        except Exception:
            dead.add(ws)
    ws_connections.difference_update(dead)

# Wire the scanner's broadcast
scanner.broadcast = broadcast


def get_ai_agent_config() -> Dict:
    """Return normalized persisted AI integration settings."""
    user_cfg = load_user_config()
    saved = user_cfg.get("ai_agent", {}) if isinstance(user_cfg, dict) else {}
    return normalize_ai_agent_config(saved)


def load_ai_runtime_state():
    """Load AI cache/feedback state from user config storage."""
    global ai_review_cache, ai_feedback_stats
    user_cfg = load_user_config()
    if not isinstance(user_cfg, dict):
        ai_review_cache = {}
        ai_feedback_stats = {}
        return
    cache = user_cfg.get("ai_review_cache", {})
    feedback = user_cfg.get("ai_feedback_stats", {})
    ai_review_cache = cache if isinstance(cache, dict) else {}
    ai_feedback_stats = feedback if isinstance(feedback, dict) else {}


def persist_ai_runtime_state():
    """Persist AI cache/feedback state."""
    try:
        save_user_config({
            "ai_review_cache": ai_review_cache,
            "ai_feedback_stats": ai_feedback_stats,
        })
    except Exception:
        pass


def finding_fingerprint(finding: Dict) -> str:
    raw = "|".join([
        str(finding.get("url", "")),
        str(finding.get("vuln_type", "")),
        str(finding.get("parameter", "")),
        str(finding.get("payload", "")),
    ])
    return hashlib.md5(raw.encode()).hexdigest()


async def oast_hit_checker(token: str) -> bool:
    _cleanup_oast_hits()
    return token in oast_hits


def _cleanup_oast_hits():
    now = time.time()
    expired = [k for k, v in oast_hits.items() if now - float(v.get("last_seen", 0.0) or 0.0) > OAST_HIT_TTL_SEC]
    for k in expired:
        oast_hits.pop(k, None)


def _record_oast_hit(token: str, request: Request):
    now = time.time()
    existing = oast_hits.get(token) or {}
    existing["token"] = token
    existing["first_seen"] = float(existing.get("first_seen", now) or now)
    existing["last_seen"] = now
    existing["count"] = int(existing.get("count", 0) or 0) + 1
    existing["method"] = request.method
    existing["path"] = str(request.url.path)
    existing["query"] = str(request.url.query or "")
    existing["remote"] = str(request.client.host if request.client else "")
    existing["user_agent"] = str(request.headers.get("user-agent", "") or "")[:240]
    oast_hits[token] = existing


# ── Proxy flow callback ────────────────────────────────────────

def on_proxy_flow(flow):
    """Called by mitmproxy addon when a flow completes."""
    _schedule_on_main_loop(_handle_flow(flow))


def on_interception(flow_data):
    """Called by mitmproxy addon when a request is intercepted."""
    _schedule_on_main_loop(broadcast("request_intercepted", flow_data))


def on_response_interception(flow_data):
    """Called by mitmproxy addon when a response is intercepted."""
    _schedule_on_main_loop(broadcast("response_intercepted", flow_data))


def on_ws_frame(payload):
    """Called when a websocket frame is observed."""
    _schedule_on_main_loop(_handle_ws_frame(payload))


def on_token_captured(payload):
    """Called when the token watcher captures a value from a response."""
    try:
        cfg = gx.load_token_watch()
        cfg["captured"] = payload.get("token", "")
        cfg["captured_at"] = time.time()
        cfg["captured_source"] = payload.get("source", "")
        gx.save_token_watch(cfg)
        _schedule_on_main_loop(broadcast("token_captured", {
            "source": payload.get("source", ""),
            "url": payload.get("url", ""),
            "preview": (payload.get("token", "") or "")[:24] + ("…" if len(payload.get("token", "") or "") > 24 else ""),
            "captured_at": cfg["captured_at"],
        }))
    except Exception as e:
        print(f"[API] token capture handler error: {e}")


def on_graphql_seen(payload):
    """Called when a GraphQL-looking request flows through the proxy."""
    _schedule_on_main_loop(broadcast("graphql_request", payload))


async def _handle_ws_frame(payload: dict):
    if not current_session_id:
        return
    try:
        await db.log_ws_frame(
            session_id=current_session_id,
            flow_id=str(payload.get("flow_id") or ""),
            url=str(payload.get("url") or ""),
            host=str(payload.get("host") or ""),
            direction=str(payload.get("direction") or ""),
            content=str(payload.get("content") or ""),
            length=int(payload.get("length") or 0),
            is_text=bool(payload.get("is_text", True)),
        )
        await broadcast("ws_frame", payload)
    except Exception as e:
        print(f"[API] ws frame log error: {e}")


async def _handle_flow(flow):
    """Process a completed HTTP flow."""
    global current_session_id
    if not current_session_id:
        return

    try:
        log_id = await db.log_request(
            session_id=current_session_id,
            method=flow.method,
            url=flow.url,
            host=flow.host,
            path=flow.path,
            request_headers=flow.request_headers,
            request_body=flow.request_body,
            status_code=flow.status_code,
            response_headers=flow.response_headers,
            response_body_preview=flow.response_body_preview,
            content_type=flow.content_type,
            content_length=flow.content_length,
            duration_ms=flow.duration_ms,
        )

        await broadcast("http_flow", {
            "id": log_id,
            "method": flow.method,
            "url": flow.url,
            "host": flow.host,
            "path": flow.path,
            "status_code": flow.status_code,
            "response_headers": flow.response_headers,
            "content_type": flow.content_type,
            "content_length": flow.content_length,
            "duration_ms": round(flow.duration_ms, 1),
        })
    except Exception as e:
        print(f"[API] Error handling flow: {e}")


# ── Lifespan ────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup and shutdown."""
    global _main_loop
    _main_loop = asyncio.get_running_loop()
    load_ai_runtime_state()
    await db.connect()
    proxy_manager.set_callbacks(on_proxy_flow, on_interception, on_response_interception)
    proxy_manager.set_excludes(config.proxy.exclude_domains)
    proxy_manager.addon.set_ws_callback(on_ws_frame)
    proxy_manager.addon.set_token_callback(on_token_captured)
    proxy_manager.addon.set_graphql_callback(on_graphql_seen)
    await proxy_manager.start()
    print(f"[API] Backend running on {config.api.host}:{config.api.port}")
    print(f"[Proxy] Intercepting on {config.proxy.host}:{config.proxy.port}")
    yield
    await tool_runner.cancel_all()
    await proxy_manager.stop()
    persist_ai_runtime_state()
    await ai_agent.close()
    await db.close()
    _main_loop = None


# ── FastAPI App ─────────────────────────────────────────────────

from core import __version__ as APP_VERSION

app = FastAPI(
    title="GreyTab API",
    version=APP_VERSION,
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── Pydantic Models ────────────────────────────────────────────

class SessionCreate(BaseModel):
    name: str
    target_scope: str = ""

class ToolRunRequest(BaseModel):
    tool_name: str
    target: str = ""
    wordlist: str = ""
    extra_args: str = ""
    raw_command: str = ""

class FindingCreate(BaseModel):
    title: str
    severity: str = "info"
    category: str = ""
    description: str = ""
    evidence: str = ""
    source_tool: str = ""
    source_request_id: Optional[int] = None

class LogsClearRequest(BaseModel):
    session_id: Optional[str] = None

class ProxySettings(BaseModel):
    intercept_enabled: Optional[bool] = None
    intercept_response: Optional[bool] = None
    scope_domains: Optional[List[str]] = None
    exclude_domains: Optional[List[str]] = None
    log_traffic: Optional[bool] = None

class InterceptAction(BaseModel):
    action: str  # resume, drop
    modifications: Optional[Dict] = None

class AITestRequest(BaseModel):
    config: Optional[Dict] = None

class AIFindingAnalyzeRequest(BaseModel):
    finding: Dict
    config: Optional[Dict] = None

class AIFeedbackRequest(BaseModel):
    finding: Dict
    label: str  # true_positive | false_positive


# ── WebSocket ───────────────────────────────────────────────────

@app.websocket("/ws")
async def websocket_endpoint(ws: WebSocket):
    """Main WebSocket connection for real-time communication."""
    await ws.accept()
    ws_connections.add(ws)
    print(f"[WS] Client connected. Total: {len(ws_connections)}")
    
    try:
        # Send initial state
        await ws.send_text(json.dumps({
            "type": "connected",
            "data": {
                "session_id": current_session_id,
                "proxy_running": proxy_manager.is_running,
                "proxy_port": config.proxy.port,
                "intercept_enabled": proxy_manager.addon.intercept_enabled,
                "intercept_response": proxy_manager.addon.intercept_response
            }
        }))
        
        while True:
            data = await ws.receive_text()
            msg = json.loads(data)
            await _handle_ws_message(ws, msg)
    except WebSocketDisconnect:
        pass
    except Exception as e:
        print(f"[WS] Error: {e}")
    finally:
        ws_connections.difference_update({ws})
        print(f"[WS] Client disconnected. Total: {len(ws_connections)}")


async def _handle_ws_message(ws: WebSocket, msg: dict):
    """Handle incoming WebSocket messages from the extension."""
    msg_type = msg.get("type", "")
    data = msg.get("data", {})

    if msg_type == "ping":
        await ws.send_text(json.dumps({"type": "pong"}))
    elif msg_type == "get_status":
        await ws.send_text(json.dumps({
            "type": "status",
            "data": {
                "session_id": current_session_id,
                "proxy_running": proxy_manager.is_running,
                "running_tools": tool_runner.get_running_tools(),
            }
        }))


# ── Session Endpoints ───────────────────────────────────────────

@app.post("/api/sessions")
async def create_session(req: SessionCreate):
    """Create a new audit session."""
    global current_session_id
    session_id = str(uuid.uuid4())[:8]
    session = await db.create_session(session_id, req.name, req.target_scope)
    current_session_id = session_id
    
    if req.target_scope:
        domains = [d.strip() for d in req.target_scope.split(",")]
        proxy_manager.set_scope(domains)
    
    await broadcast("session_created", session)
    return session


@app.get("/api/sessions")
async def list_sessions():
    """List all sessions."""
    return await db.get_sessions()


@app.get("/api/sessions/{session_id}")
async def get_session(session_id: str):
    """Get a specific session."""
    session = await db.get_session(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    return session


@app.post("/api/sessions/{session_id}/activate")
async def activate_session(session_id: str):
    """Set the active session."""
    global current_session_id
    session = await db.get_session(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    current_session_id = session_id
    await broadcast("session_activated", {"session_id": session_id})
    return {"status": "ok", "session_id": session_id}


@app.get("/api/sessions/{session_id}/stats")
async def session_stats(session_id: str):
    """Get session statistics."""
    return await db.get_session_stats(session_id)


# ── HTTP Log Endpoints ──────────────────────────────────────────

@app.get("/api/logs/http")
async def get_http_logs(
    session_id: Optional[str] = None,
    limit: int = Query(1000, ge=1, le=50000),
    host: str = "",
    method: str = "",
    status: Optional[int] = None,
):
    """Get HTTP traffic logs."""
    sid = session_id or current_session_id
    if not sid:
        raise HTTPException(status_code=400, detail="No active session")
    return await db.get_http_logs(sid, limit, host, method, status)


@app.get("/api/logs/http/{log_id}")
async def get_http_log_detail(log_id: int):
    """Get detailed HTTP log entry."""
    log = await db.get_http_log_detail(log_id)
    if not log:
        raise HTTPException(status_code=404, detail="Log entry not found")
    return log


@app.delete("/api/logs/http/{log_id}")
async def delete_http_log(log_id: int, session_id: Optional[str] = None):
    """Delete a single HTTP log entry."""
    sid = session_id or current_session_id
    if not sid:
        raise HTTPException(status_code=400, detail="No active session")
    deleted = await db.delete_http_log(log_id, sid)
    if deleted <= 0:
        raise HTTPException(status_code=404, detail="Log entry not found")
    return {"status": "ok", "deleted": deleted, "log_id": log_id}


@app.post("/api/logs/http/clear")
async def clear_http_logs(req: LogsClearRequest):
    """Delete all HTTP logs for the current (or provided) session."""
    sid = req.session_id or current_session_id
    if not sid:
        raise HTTPException(status_code=400, detail="No active session")
    deleted = await db.clear_http_logs(sid)
    return {"status": "ok", "deleted": deleted, "session_id": sid}


# ── Tool Endpoints ──────────────────────────────────────────────

@app.get("/api/tools")
async def list_tools():
    """List all available pentesting tools."""
    return tool_runner.get_available_tools()


@app.get("/api/tools/running")
async def list_running_tools():
    """List currently running tools."""
    return tool_runner.get_running_tools()


@app.post("/api/tools/run")
async def run_tool(req: ToolRunRequest):
    """Execute a pentesting tool."""
    if not current_session_id:
        raise HTTPException(status_code=400, detail="No active session. Create one first.")

    try:
        if req.raw_command:
            command = req.raw_command
        else:
            command = tool_runner.build_command(
                tool_name=req.tool_name,
                target=req.target,
                wordlist=req.wordlist,
                extra_args=req.extra_args,
            )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    # Log the tool start
    run_id = await db.log_tool_start(
        session_id=current_session_id,
        tool_name=req.tool_name or "custom",
        command=command,
        target_url=req.target,
        args=req.extra_args,
    )

    async def on_output(rid: int, line: str):
        await db.update_tool_output(rid, line + "\n")
        await broadcast("tool_output", {"run_id": rid, "line": line})

    async def on_complete(rid: int, exit_code: int, duration_ms: float):
        await db.finish_tool_run(rid, exit_code, duration_ms)
        await broadcast("tool_complete", {
            "run_id": rid,
            "exit_code": exit_code,
            "duration_ms": round(duration_ms, 1),
        })

    pid = await tool_runner.run_tool(
        run_id=run_id,
        tool_name=req.tool_name or "custom",
        raw_command=command,
        on_output=on_output,
        on_complete=on_complete,
    )

    await broadcast("tool_started", {
        "run_id": run_id,
        "tool_name": req.tool_name or "custom",
        "command": command,
        "pid": pid,
    })

    return {"run_id": run_id, "pid": pid, "command": command}


@app.post("/api/tools/{run_id}/cancel")
async def cancel_tool(run_id: int):
    """Cancel a running tool."""
    success = await tool_runner.cancel_tool(run_id)
    if not success:
        raise HTTPException(status_code=404, detail="Tool not found or already finished")
    return {"status": "cancelled", "run_id": run_id}


@app.get("/api/tools/history")
async def tool_history(session_id: Optional[str] = None, limit: int = 50):
    """Get tool execution history."""
    sid = session_id or current_session_id
    if not sid:
        raise HTTPException(status_code=400, detail="No active session")
    return await db.get_tool_runs(sid, limit)


@app.get("/api/tools/{run_id}")
async def tool_run_detail(run_id: int):
    """Get a specific tool run detail (including accumulated output)."""
    run = await db.get_tool_run(run_id)
    if not run:
        raise HTTPException(status_code=404, detail="Tool run not found")
    return run


@app.get("/api/tools/wordlists")
async def list_wordlists():
    """List available wordlists."""
    return tool_runner.get_wordlists()


@app.post("/api/tools/wordlists/upload")
async def upload_wordlist(file: UploadFile = File(...)):
    """Upload a custom wordlist."""
    try:
        from core.config import WORDLISTS_DIR
        os.makedirs(WORDLISTS_DIR, exist_ok=True)
        file_path = WORDLISTS_DIR / file.filename
        with open(file_path, "wb") as buffer:
            buffer.write(await file.read())
        return {"status": "success", "filename": file.filename, "path": str(file_path)}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/tools/scripts")
async def list_scripts():
    """List available custom scripts."""
    return tool_runner.get_custom_scripts()


# ── Config / Settings Endpoints ─────────────────────────────────

class ConfigUpdate(BaseModel):
    proxy_port: Optional[int] = None
    ai_agent: Optional[Dict] = None

class CustomToolCreate(BaseModel):
    name: str
    command: str
    description: str = ""
    category: str = "custom"
    args_template: str = "{target}"
    requires_target: bool = True

@app.get("/api/config")
async def get_app_config():
    """Get current application configuration."""
    ai_cfg = get_ai_agent_config()
    return {
        "proxy_port": config.proxy.port,
        "custom_tools": tool_runner.get_custom_tools(),
        "ai_agent": mask_ai_agent_config(ai_cfg),
    }

@app.post("/api/config")
async def update_app_config(req: ConfigUpdate):
    """Update application configuration (some changes require restart)."""
    changes = {}
    restart_needed = False

    if req.proxy_port is not None and req.proxy_port != config.proxy.port:
        if not (1024 <= req.proxy_port <= 65535):
            raise HTTPException(status_code=400, detail="Port must be between 1024-65535")
        save_user_config({"proxy_port": req.proxy_port})
        # Reflect configured value immediately in runtime status APIs/UI.
        config.proxy.port = req.proxy_port
        changes["proxy_port"] = req.proxy_port
        restart_needed = True

    if req.ai_agent is not None:
        current_ai_cfg = get_ai_agent_config()
        merged_ai_cfg = normalize_ai_agent_config(req.ai_agent, existing=current_ai_cfg)
        save_user_config({"ai_agent": merged_ai_cfg})
        changes["ai_agent"] = {
            "enabled": merged_ai_cfg.get("enabled", False),
            "provider": merged_ai_cfg.get("provider", ""),
            "model": merged_ai_cfg.get("model", ""),
            "endpoint": merged_ai_cfg.get("endpoint", ""),
            "verify_findings": merged_ai_cfg.get("verify_findings", True),
            "review_scope": merged_ai_cfg.get("review_scope", "ambiguous_or_high"),
            "max_reviews_per_scan": merged_ai_cfg.get("max_reviews_per_scan", 20),
            "cache_enabled": merged_ai_cfg.get("cache_enabled", True),
        }

    return {
        "status": "ok",
        "changes": changes,
        "restart_needed": restart_needed,
    }


@app.post("/api/ai/test")
async def test_ai_connection(req: AITestRequest):
    """Test AI agent connectivity with the provided (or saved) configuration."""
    base_cfg = get_ai_agent_config()
    merged_cfg = normalize_ai_agent_config(req.config or {}, existing=base_cfg)
    try:
        result = await ai_agent.test_connection(merged_cfg)
        return {"status": "ok", "result": result}
    except AIAgentError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/ai/analyze_finding")
async def ai_analyze_finding(req: AIFindingAnalyzeRequest):
    """Run AI triage for a single finding."""
    base_cfg = get_ai_agent_config()
    merged_cfg = normalize_ai_agent_config(req.config or {}, existing=base_cfg)
    if not merged_cfg.get("enabled"):
        raise HTTPException(status_code=400, detail="AI agent is disabled in settings")
    try:
        analysis = await ai_agent.analyze_finding(merged_cfg, req.finding or {})
        return {"status": "ok", "analysis": analysis}
    except AIAgentError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/ai/feedback")
async def ai_feedback(req: AIFeedbackRequest):
    """Store analyst feedback for a finding (true/false positive)."""
    label = str(req.label or "").strip().lower()
    if label not in {"true_positive", "false_positive"}:
        raise HTTPException(status_code=400, detail="label must be true_positive or false_positive")
    finding = req.finding or {}
    fp = finding_fingerprint(finding)
    bucket = ai_feedback_stats.get(fp, {"true_positive": 0, "false_positive": 0})
    bucket[label] = int(bucket.get(label, 0)) + 1
    ai_feedback_stats[fp] = bucket
    persist_ai_runtime_state()
    return {"status": "ok", "fingerprint": fp, "feedback": bucket}


@app.post("/api/ai/cache/clear")
async def ai_clear_cache():
    """Clear cached AI analysis results."""
    ai_review_cache.clear()
    persist_ai_runtime_state()
    return {"status": "ok", "cache_size": 0}


@app.get("/api/oast/hits")
async def list_oast_hits():
    """Return observed OAST callback hits (debug/support endpoint)."""
    _cleanup_oast_hits()
    items = sorted(oast_hits.values(), key=lambda x: float(x.get("last_seen", 0.0)), reverse=True)
    return {"count": len(items), "hits": items[:500]}


@app.post("/api/oast/hits/clear")
async def clear_oast_hits():
    """Clear cached OAST callback hits."""
    oast_hits.clear()
    return {"status": "ok", "count": 0}


@app.api_route("/api/oast/hit/{token}", methods=["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"])
@app.api_route("/oast/hit/{token}", methods=["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"])
async def oast_callback(token: str, request: Request):
    """Receive out-of-band callback interactions for scanner OAST checks."""
    token = str(token or "").strip()
    if not token or len(token) < 6 or len(token) > 96:
        raise HTTPException(status_code=400, detail="Invalid OAST token")
    _record_oast_hit(token, request)
    return PlainTextResponse("ok", status_code=200)

@app.get("/api/tools/custom")
async def list_custom_tools():
    """List user-defined custom tools."""
    return tool_runner.get_custom_tools()

@app.post("/api/tools/custom")
async def add_custom_tool(req: CustomToolCreate):
    """Add a custom tool definition."""
    try:
        td = ToolDefinition(
            name=req.name,
            command=req.command,
            description=req.description,
            category=req.category,
            args_template=req.args_template,
            requires_target=req.requires_target,
        )
        tool_runner.add_custom_tool(td)
        return {"status": "ok", "tool": req.name}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.put("/api/tools/custom/{name}")
async def update_custom_tool(name: str, req: CustomToolCreate):
    """Update a custom tool definition."""
    try:
        td = ToolDefinition(
            name=req.name,
            command=req.command,
            description=req.description,
            category=req.category,
            args_template=req.args_template,
            requires_target=req.requires_target,
        )
        tool_runner.update_custom_tool(name, td)
        return {"status": "ok", "tool": name}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.delete("/api/tools/custom/{name}")
async def delete_custom_tool(name: str):
    """Delete a custom tool definition."""
    try:
        tool_runner.remove_custom_tool(name)
        return {"status": "ok", "tool": name}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


# ── Proxy Control Endpoints ─────────────────────────────────────

@app.get("/api/proxy/status")
async def proxy_status():
    """Get proxy status."""
    return {
        "running": proxy_manager.is_running,
        "host": config.proxy.host,
        "port": config.proxy.port,
        "intercept_enabled": proxy_manager.addon.intercept_enabled,
        "log_traffic": proxy_manager.addon.log_traffic,
        "scope_domains": list(proxy_manager.addon.scope_domains),
        "exclude_domains": list(proxy_manager.addon.exclude_domains),
    }


@app.post("/api/proxy/settings")
async def update_proxy_settings(settings: ProxySettings):
    """Update proxy settings."""
    if settings.intercept_enabled is not None:
        proxy_manager.set_intercept_mode(settings.intercept_enabled)
    if settings.intercept_response is not None:
        proxy_manager.set_intercept_response(settings.intercept_response)
    if settings.scope_domains is not None:
        proxy_manager.set_scope(settings.scope_domains)
    if settings.exclude_domains is not None:
        proxy_manager.set_excludes(settings.exclude_domains)
    if settings.log_traffic is not None:
        proxy_manager.addon.log_traffic = settings.log_traffic
    
    await broadcast("proxy_settings_updated", {
        "intercept_enabled": proxy_manager.addon.intercept_enabled,
        "intercept_response": proxy_manager.addon.intercept_response,
        "log_traffic": proxy_manager.addon.log_traffic,
    })
    return {"status": "ok"}


@app.post("/api/proxy/flows/{flow_id}/resume")
async def resume_flow(flow_id: str, action: InterceptAction):
    """Resume a successfully intercepted request flow, applying modifications if any."""
    if action.action == "drop":
        proxy_manager.drop_flow(flow_id)
        return {"status": "dropped"}
    
    proxy_manager.resume_flow(flow_id, action.modifications)
    return {"status": "resumed"}


@app.post("/api/proxy/responses/{flow_id}/resume")
async def resume_response(flow_id: str, action: InterceptAction):
    """Resume a successfully intercepted response flow, applying modifications if any."""
    if action.action == "drop":
        proxy_manager.drop_response(flow_id)
        return {"status": "dropped"}
    
    proxy_manager.resume_response(flow_id, action.modifications)
    return {"status": "resumed"}


# ── Repeater Endpoints ──────────────────────────────────────────

class RepeaterRequest(BaseModel):
    method: str
    url: str
    headers: Dict[str, str] = {}
    body: Optional[str] = None
    follow_redirects: bool = False

@app.post("/api/repeater/send")
async def repeater_send(req: RepeaterRequest):
    """Execute a request via the backend (Repeater functionality)."""
    import httpx
    
    # Filter restricted headers that might confuse httpx
    headers = {k: v for k, v in req.headers.items() if k.lower() not in ['content-length', 'host']}
    
    try:
        async with httpx.AsyncClient(verify=False, follow_redirects=req.follow_redirects, timeout=30.0) as client:
            response = await client.request(
                method=req.method,
                url=req.url,
                headers=headers,
                content=req.body.encode('utf-8') if req.body else None,
            )
            
            # Serialize response
            resp_body = ""
            try:
                resp_body = response.content.decode('utf-8', errors='replace')
            except:
                resp_body = f"[Binary content: {len(response.content)} bytes]"
            
            return {
                "status_code": response.status_code,
                "headers": dict(response.headers),
                "body": resp_body,
                "duration_ms": response.elapsed.total_seconds() * 1000
            }
    except Exception as e:
        return {
            "error": str(e),
            "status_code": 0,
            "headers": {},
            "body": "",
            "duration_ms": 0
        }


# ── Intruder Endpoints ──────────────────────────────────────────

@app.get("/api/intruder/wordlist")
async def read_intruder_wordlist(path: str = Query(...)):
    """Read a wordlist file for Intruder payloads."""
    from pathlib import Path as P
    
    wl_path = P(path)
    if not wl_path.is_file():
        raise HTTPException(status_code=404, detail="Wordlist file not found")
    
    try:
        lines = []
        with open(wl_path, 'r', errors='replace') as f:
            for i, line in enumerate(f):
                if i >= 100000:  # Cap at 100K lines
                    break
                stripped = line.rstrip('\n\r')
                if stripped:
                    lines.append(stripped)
        return {"lines": lines, "count": len(lines)}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ── Scanner Endpoints ───────────────────────────────────────────

class ScannerStart(BaseModel):
    target_url: str
    scan_depth: int = 3
    test_types: List[str] = ["xss", "sqli", "path_traversal", "lfi", "open_redirect", "ssti", "cmdi", "crlf", "ssrf", "cors", "oast"]
    headers: Dict[str, str] = {}
    fuzz_dirs: bool = False
    crawl_enabled: bool = True
    ai_verify_findings: Optional[bool] = None
    xss_headless_confirm: bool = True
    oast_enabled: bool = False
    oast_base_url: str = ""

@app.post("/api/scanner/start")
async def start_scanner(req: ScannerStart):
    """Start the auto scanner."""
    try:
        if req.oast_enabled and not str(req.oast_base_url or "").strip():
            raise HTTPException(
                status_code=400,
                detail="OAST is enabled but oast_base_url is empty. Use a callback URL with optional {token} placeholder.",
            )
        ai_cfg = get_ai_agent_config()
        if req.ai_verify_findings is not None:
            ai_cfg["verify_findings"] = bool(req.ai_verify_findings)
        ai_cfg["runtime_cache"] = ai_review_cache
        ai_cfg["feedback_stats"] = ai_feedback_stats
        await scanner.start(
            target_url=req.target_url,
            scan_depth=req.scan_depth,
            test_types=req.test_types,
            headers=req.headers,
            fuzz_dirs=req.fuzz_dirs,
            crawl_enabled=req.crawl_enabled,
            ai_config=ai_cfg,
            ai_analyzer=ai_agent.analyze_finding,
            xss_headless_confirm=req.xss_headless_confirm,
            oast_enabled=req.oast_enabled,
            oast_base_url=req.oast_base_url,
            oast_hit_checker=oast_hit_checker,
        )
        # Keep cache references synchronized
        ai_review_cache.update(scanner.ai_config.get("runtime_cache", {}) if isinstance(scanner.ai_config, dict) else {})
        persist_ai_runtime_state()
        return {"status": "started", "target": req.target_url}
    except RuntimeError as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.get("/api/scanner/status")
async def scanner_status():
    """Get scanner status."""
    return scanner.status()

@app.get("/api/scanner/attempts")
async def scanner_attempts(limit: int = Query(0, ge=0, le=50000)):
    """Get scanner payload-attempt log. limit=0 returns all stored entries."""
    return {
        "count": len(scanner.test_log),
        "attempts": scanner.get_test_log(limit=limit),
    }

@app.post("/api/scanner/stop")
async def stop_scanner():
    """Stop the scanner."""
    await scanner.stop()
    return {"status": "stopped"}


# ── Findings Endpoints ──────────────────────────────────────────

@app.post("/api/findings")
async def create_finding(req: FindingCreate):
    """Create a security finding."""
    if not current_session_id:
        raise HTTPException(status_code=400, detail="No active session")
    
    finding_id = await db.add_finding(
        session_id=current_session_id,
        title=req.title,
        severity=req.severity,
        category=req.category,
        description=req.description,
        evidence=req.evidence,
        source_tool=req.source_tool,
        source_request_id=req.source_request_id,
    )
    
    await broadcast("finding_added", {"id": finding_id, "title": req.title, "severity": req.severity})
    return {"id": finding_id}


@app.get("/api/findings")
async def list_findings(session_id: Optional[str] = None):
    """List all findings for the current session."""
    sid = session_id or current_session_id
    if not sid:
        raise HTTPException(status_code=400, detail="No active session")
    return await db.get_findings(sid)


# ── Health ──────────────────────────────────────────────────────

@app.get("/api/health")
async def health():
    """Health check endpoint."""
    mem_mb = 0.0
    try:
        usage_kb = float(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss or 0.0)
        # Linux returns KB, macOS returns bytes; normalize heuristically.
        mem_mb = usage_kb / 1024.0 if usage_kb > 1024 else usage_kb / (1024.0 * 1024.0)
    except Exception:
        mem_mb = 0.0

    return {
        "status": "ok",
        "version": APP_VERSION,
        "session_id": current_session_id,
        "proxy_running": proxy_manager.is_running,
        "proxy_port": config.proxy.port,
        "memory_mb": round(mem_mb, 1),
        "ws_clients": len(ws_connections),
    }


# ──────────────────────────────────────────────────────────────────
# Match & Replace rules
# ──────────────────────────────────────────────────────────────────

@app.get("/api/rules")
async def list_rules():
    return [r.to_dict() for r in gx.load_rules()]


@app.post("/api/rules")
async def create_or_update_rule(req: Dict):
    try:
        r = gx.upsert_rule(req)
        return r.to_dict()
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Bad rule: {e}")


@app.delete("/api/rules/{rule_id}")
async def remove_rule(rule_id: str):
    if not gx.delete_rule(rule_id):
        raise HTTPException(status_code=404, detail="Rule not found")
    return {"status": "ok"}


# ──────────────────────────────────────────────────────────────────
# Token watcher
# ──────────────────────────────────────────────────────────────────

@app.get("/api/token_watch")
async def token_watch_get():
    return gx.load_token_watch()


@app.post("/api/token_watch")
async def token_watch_update(req: Dict):
    return gx.save_token_watch(req or {})


# ──────────────────────────────────────────────────────────────────
# Login macros
# ──────────────────────────────────────────────────────────────────

@app.get("/api/macros")
async def macros_list():
    return gx.list_macros()


@app.post("/api/macros")
async def macros_save(req: Dict):
    return gx.save_macro(req or {})


@app.delete("/api/macros/{macro_id}")
async def macros_delete(macro_id: str):
    if not gx.delete_macro(macro_id):
        raise HTTPException(status_code=404, detail="Macro not found")
    return {"status": "ok"}


@app.post("/api/macros/{macro_id}/run")
async def macros_run(macro_id: str):
    """Replay a login macro and return the captured value(s)."""
    macro = gx.get_macro(macro_id)
    if not macro:
        raise HTTPException(status_code=404, detail="Macro not found")
    import httpx as _httpx
    import re as _re
    extracted: Dict[str, str] = {}
    try:
        async with _httpx.AsyncClient(verify=False, follow_redirects=True, timeout=15.0) as client:
            for step in macro.get("steps", []) or []:
                method = (step.get("method") or "GET").upper()
                url = step.get("url") or ""
                headers = dict(step.get("headers") or {})
                body = step.get("body") or ""
                # Variable interpolation
                for k, v in extracted.items():
                    url = url.replace("{" + k + "}", v)
                    body = body.replace("{" + k + "}", v)
                    for hk in list(headers.keys()):
                        headers[hk] = headers[hk].replace("{" + k + "}", v)

                resp = await client.request(
                    method, url, headers=headers,
                    content=body.encode("utf-8") if body else None,
                )

                for var, pattern in (step.get("extract") or {}).items():
                    if not pattern:
                        continue
                    kind = step.get("extract_kind", "regex")
                    if kind == "header":
                        val = resp.headers.get(pattern, "")
                        if val:
                            extracted[var] = val
                    else:
                        try:
                            m = _re.search(pattern, resp.text or "")
                            if m:
                                extracted[var] = m.group(1) if m.groups() else m.group(0)
                        except _re.error:
                            continue
        # Optional auto-inject
        if macro.get("inject_header") and macro.get("inject_template"):
            tmpl = macro["inject_template"]
            for k, v in extracted.items():
                tmpl = tmpl.replace("{" + k + "}", v)
            cfg = gx.load_token_watch()
            cfg["captured"] = next(iter(extracted.values()), "") if extracted else ""
            cfg["captured_source"] = "macro"
            cfg["captured_at"] = time.time()
            cfg["enabled"] = True
            cfg["header_name"] = macro["inject_header"]
            cfg["header_template"] = macro["inject_template"]
            gx.save_token_watch(cfg)
        return {"status": "ok", "extracted": extracted}
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Macro failed: {e}")


# ──────────────────────────────────────────────────────────────────
# Exports
# ──────────────────────────────────────────────────────────────────

@app.get("/api/export/findings.html", response_class=PlainTextResponse)
async def export_findings_html(session_id: Optional[str] = None):
    sid = session_id or current_session_id
    if not sid:
        raise HTTPException(status_code=400, detail="No session")
    session = await db.get_session(sid) or {}
    findings = await db.get_findings(sid)
    html = gx.findings_to_html(session, findings)
    return PlainTextResponse(html, media_type="text/html")


@app.get("/api/export/findings.csv", response_class=PlainTextResponse)
async def export_findings_csv(session_id: Optional[str] = None):
    sid = session_id or current_session_id
    if not sid:
        raise HTTPException(status_code=400, detail="No session")
    findings = await db.get_findings(sid)
    return PlainTextResponse(gx.findings_to_csv(findings), media_type="text/csv")


@app.get("/api/export/findings.md", response_class=PlainTextResponse)
async def export_findings_md(session_id: Optional[str] = None):
    sid = session_id or current_session_id
    if not sid:
        raise HTTPException(status_code=400, detail="No session")
    session = await db.get_session(sid) or {}
    findings = await db.get_findings(sid)
    return PlainTextResponse(gx.findings_to_markdown(session, findings), media_type="text/markdown")


@app.get("/api/export/traffic.har")
async def export_traffic_har(session_id: Optional[str] = None, limit: int = 5000):
    sid = session_id or current_session_id
    if not sid:
        raise HTTPException(status_code=400, detail="No session")
    session = await db.get_session(sid) or {}
    logs = await db.get_http_logs(sid, limit=min(max(1, limit), 50000))
    return gx.http_logs_to_har(session, logs)


# ──────────────────────────────────────────────────────────────────
# WebSocket frame log
# ──────────────────────────────────────────────────────────────────

@app.get("/api/ws_log")
async def ws_log_list(session_id: Optional[str] = None, flow_id: Optional[str] = None, limit: int = 500):
    sid = session_id or current_session_id
    if not sid:
        raise HTTPException(status_code=400, detail="No session")
    return await db.get_ws_frames(sid, flow_id=flow_id, limit=min(max(1, limit), 5000))


# ──────────────────────────────────────────────────────────────────
# Site map
# ──────────────────────────────────────────────────────────────────

@app.get("/api/sitemap")
async def sitemap(session_id: Optional[str] = None):
    """Aggregate logged requests into a host → path tree."""
    sid = session_id or current_session_id
    if not sid:
        raise HTTPException(status_code=400, detail="No session")
    logs = await db.get_http_logs(sid, limit=20000)
    tree: Dict[str, Dict[str, Any]] = {}
    for log in logs:
        host = log.get("host") or ""
        path = log.get("path") or "/"
        method = log.get("method") or "GET"
        status = int(log.get("status_code") or 0)
        host_node = tree.setdefault(host, {"host": host, "endpoints": {}})
        ep = host_node["endpoints"].setdefault(path, {"path": path, "methods": {}, "count": 0, "statuses": {}})
        ep["count"] += 1
        ep["methods"][method] = ep["methods"].get(method, 0) + 1
        if status:
            ep["statuses"][str(status)] = ep["statuses"].get(str(status), 0) + 1
    # Flatten endpoints back to list
    result = []
    for h in sorted(tree.keys()):
        node = tree[h]
        endpoints = list(node["endpoints"].values())
        endpoints.sort(key=lambda e: e["path"])
        result.append({"host": node["host"], "endpoints": endpoints, "count": sum(e["count"] for e in endpoints)})
    return {"hosts": result, "total_hosts": len(result)}


# ──────────────────────────────────────────────────────────────────
# Active scan from a captured request
# ──────────────────────────────────────────────────────────────────

class ScanFromRequest(BaseModel):
    log_id: Optional[int] = None
    method: Optional[str] = None
    url: Optional[str] = None
    headers: Optional[Dict[str, str]] = None
    body: Optional[str] = None
    test_types: List[str] = ["xss", "sqli", "path_traversal", "lfi", "open_redirect", "ssti", "cmdi", "crlf", "ssrf", "cors"]


@app.post("/api/scanner/from_request")
async def scan_from_request(req: ScanFromRequest):
    if scanner.running:
        raise HTTPException(status_code=400, detail="Scanner already running")
    method = req.method or "GET"
    url = req.url or ""
    headers = req.headers or {}
    body = req.body
    if req.log_id and (not url or not method):
        log = await db.get_http_log_detail(req.log_id)
        if not log:
            raise HTTPException(status_code=404, detail="Log entry not found")
        method = method or log.get("method") or "GET"
        url = url or log.get("url") or ""
        try:
            headers = headers or json.loads(log.get("request_headers") or "{}")
        except Exception:
            pass
        body = body or log.get("request_body")
    if not url:
        raise HTTPException(status_code=400, detail="url is required")
    ai_cfg = get_ai_agent_config()
    ai_cfg["runtime_cache"] = ai_review_cache
    ai_cfg["feedback_stats"] = ai_feedback_stats
    try:
        await scanner.scan_single_request(
            method=method,
            url=url,
            headers=headers,
            body=body,
            test_types=req.test_types,
            ai_config=ai_cfg,
            ai_analyzer=ai_agent.analyze_finding,
            oast_hit_checker=oast_hit_checker,
        )
        return {"status": "started", "url": url}
    except RuntimeError as e:
        raise HTTPException(status_code=400, detail=str(e))


# ──────────────────────────────────────────────────────────────────
# Race-condition tester
# ──────────────────────────────────────────────────────────────────

class RaceRequest(BaseModel):
    method: str = "POST"
    url: str
    headers: Dict[str, str] = {}
    body: Optional[str] = None
    parallel: int = 30
    follow_redirects: bool = False


@app.post("/api/race/run")
async def race_run(req: RaceRequest):
    """Fire N requests in parallel and return their timeline."""
    import httpx as _httpx
    n = max(2, min(int(req.parallel), 200))
    headers = {k: v for k, v in (req.headers or {}).items()
               if k.lower() not in ("content-length", "host")}
    body_bytes = req.body.encode("utf-8") if req.body else None

    async def one(client, idx):
        t0 = time.perf_counter()
        try:
            r = await client.request(req.method, req.url, headers=headers, content=body_bytes)
            t1 = time.perf_counter()
            text = ""
            try:
                text = r.content.decode("utf-8", errors="replace")[:1500]
            except Exception:
                text = ""
            return {
                "index": idx,
                "status": r.status_code,
                "duration_ms": round((t1 - t0) * 1000, 2),
                "length": len(r.content),
                "body": text,
            }
        except Exception as e:
            return {"index": idx, "status": 0, "duration_ms": 0, "length": 0, "error": str(e)}

    async with _httpx.AsyncClient(verify=False, follow_redirects=req.follow_redirects, timeout=30.0) as client:
        results = await asyncio.gather(*(one(client, i) for i in range(n)))
    statuses: Dict[str, int] = {}
    for r in results:
        statuses[str(r["status"])] = statuses.get(str(r["status"]), 0) + 1
    return {
        "count": n,
        "statuses": statuses,
        "results": results,
        "unique_lengths": sorted(set(r["length"] for r in results)),
    }


# ──────────────────────────────────────────────────────────────────
# JWT inspector
# ──────────────────────────────────────────────────────────────────

class JwtRequest(BaseModel):
    token: str


@app.post("/api/jwt/decode")
async def jwt_decode(req: JwtRequest):
    try:
        return gx.decode_jwt(req.token.strip())
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


class JwtResignRequest(BaseModel):
    token: str
    key: str = ""
    alg: str = "HS256"  # HS256 | none


@app.post("/api/jwt/resign")
async def jwt_resign(req: JwtResignRequest):
    try:
        decoded = gx.decode_jwt(req.token.strip())
        if req.alg.lower() == "none":
            return {"token": gx.jwt_strip_signature(req.token.strip())}
        if not req.key:
            raise HTTPException(status_code=400, detail="key required for HS256")
        new = gx.jwt_resign_hs256(decoded["header"], decoded["payload"], req.key)
        return {"token": new}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


# ──────────────────────────────────────────────────────────────────
# GraphQL helper
# ──────────────────────────────────────────────────────────────────

class GraphQLIntrospect(BaseModel):
    url: str
    headers: Dict[str, str] = {}


@app.post("/api/graphql/introspect")
async def graphql_introspect(req: GraphQLIntrospect):
    import httpx as _httpx
    headers = dict(req.headers or {})
    headers.setdefault("Content-Type", "application/json")
    async with _httpx.AsyncClient(verify=False, timeout=20.0) as client:
        try:
            r = await client.post(
                req.url, headers=headers,
                json={"query": gx.INTROSPECTION_QUERY},
            )
            return {
                "status": r.status_code,
                "introspection": r.json() if "json" in (r.headers.get("content-type") or "").lower() else {"raw": r.text[:5000]},
            }
        except Exception as e:
            raise HTTPException(status_code=400, detail=str(e))


# ──────────────────────────────────────────────────────────────────
# AI extras
# ──────────────────────────────────────────────────────────────────

class AIExplainRequest(BaseModel):
    request_raw: str
    response_raw: str = ""


@app.post("/api/ai/explain_request")
async def ai_explain_request(req: AIExplainRequest):
    cfg = get_ai_agent_config()
    if not cfg.get("enabled"):
        raise HTTPException(status_code=400, detail="AI agent is disabled in settings")
    try:
        return await ai_agent.explain_request(cfg, req.request_raw, req.response_raw)
    except AIAgentError as e:
        raise HTTPException(status_code=400, detail=str(e))


class AISuggestPayloads(BaseModel):
    parameter: str = ""
    context: str = ""
    vuln_class: str = "xss"


@app.post("/api/ai/suggest_payloads")
async def ai_suggest_payloads(req: AISuggestPayloads):
    cfg = get_ai_agent_config()
    if not cfg.get("enabled"):
        raise HTTPException(status_code=400, detail="AI agent is disabled in settings")
    try:
        return await ai_agent.suggest_payloads(cfg, req.parameter, req.context, req.vuln_class)
    except AIAgentError as e:
        raise HTTPException(status_code=400, detail=str(e))


class AIExplainDiff(BaseModel):
    left: str
    right: str


@app.post("/api/ai/explain_diff")
async def ai_explain_diff(req: AIExplainDiff):
    cfg = get_ai_agent_config()
    if not cfg.get("enabled"):
        raise HTTPException(status_code=400, detail="AI agent is disabled in settings")
    try:
        return await ai_agent.explain_diff(cfg, req.left, req.right)
    except AIAgentError as e:
        raise HTTPException(status_code=400, detail=str(e))


# ──────────────────────────────────────────────────────────────────
# Per-row highlight/comment overlay
# ──────────────────────────────────────────────────────────────────

class LogMeta(BaseModel):
    highlight: str = ""
    comment: str = ""


@app.post("/api/logs/http/{log_id}/meta")
async def set_log_meta(log_id: int, req: LogMeta):
    await db.set_log_meta(log_id, req.highlight or "", req.comment or "")
    return {"status": "ok"}


@app.get("/api/logs/http/{log_id}/meta")
async def get_log_meta(log_id: int):
    return await db.get_log_meta(log_id)
