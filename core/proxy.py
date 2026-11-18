"""
PentestBrowser - mitmproxy Addon
Programmatic mitmproxy addon for HTTP/HTTPS traffic interception and logging.
"""

import json
import time
import asyncio
import threading
from typing import Optional, Dict, Set, Callable, List
from dataclasses import dataclass, field
from urllib.parse import urlparse

from mitmproxy import ctx, http, options
from mitmproxy.tools.dump import DumpMaster

from core.extras import (
    apply_rules_to_request,
    apply_rules_to_response,
    maybe_capture_token,
    detect_graphql,
    inject_watched_token,
)
from core.config import CA_CERT_DIR


def update_headers(headers, updated):
    """Keep repeated headers intact unless a rule actually changed them."""
    for key in list(headers.keys()):
        if not any(key.lower() == k.lower() for k in updated):
            del headers[key]
    for key, value in updated.items():
        if headers.get(key) != value:
            headers[key] = value


@dataclass
class InterceptedFlow:
    """Represents an intercepted HTTP flow for the queue."""
    flow_id: str
    method: str
    url: str
    host: str
    path: str
    request_headers: Dict[str, str]
    request_body: Optional[str]
    timestamp: float
    # Response fields (filled after response)
    status_code: Optional[int] = None
    response_headers: Optional[Dict[str, str]] = None
    response_body_preview: Optional[str] = None
    content_type: str = ""
    content_length: int = 0
    duration_ms: float = 0
    session_id: Optional[str] = None


class PentestProxyAddon:
    """mitmproxy addon that intercepts traffic and forwards to our backend."""

    def __init__(self):
        self.intercept_enabled = False  # Start disabled by default
        self.intercept_response = False  # Intercept responses too
        self.log_traffic = True
        self.session_id = None
        self.scope_domains: Set[str] = set()
        self.exclude_domains: Set[str] = set()
        
        # Callbacks
        self._flow_callback: Optional[Callable] = None
        self._intercept_callback: Optional[Callable] = None
        self._response_intercept_callback: Optional[Callable] = None
        self._ws_callback: Optional[Callable] = None
        self._token_callback: Optional[Callable] = None
        self._graphql_callback: Optional[Callable] = None

        # State
        self._flow_start_times: Dict[str, float] = {}
        self._pending_flows: Dict[str, http.HTTPFlow] = {}
        self._pending_responses: Dict[str, http.HTTPFlow] = {}

    def set_callbacks(self, on_flow: Callable, on_intercept: Callable, on_response_intercept: Optional[Callable] = None):
        """Set callbacks for flow completion, request interception, and response interception."""
        self._flow_callback = on_flow
        self._intercept_callback = on_intercept
        self._response_intercept_callback = on_response_intercept

    def set_ws_callback(self, cb: Callable):
        self._ws_callback = cb

    def set_token_callback(self, cb: Callable):
        self._token_callback = cb

    def set_graphql_callback(self, cb: Callable):
        self._graphql_callback = cb

    def set_scope(self, domains: List[str]):
        """Set target scope domains."""
        self.scope_domains = {d.strip().lower().removeprefix("*.") for d in domains if d.strip()}

    def set_excludes(self, domains: List[str]):
        """Set domains to exclude from logging."""
        self.exclude_domains = set(domains)

    def _is_in_scope(self, host: str) -> bool:
        """Check if a host is within the audit scope."""
        host = host.lower()
        if not self.scope_domains:
            # Check excludes even if no scope set
            pass
        else:
            is_in = any(
                host == d or host.endswith(f".{d}")
                for d in self.scope_domains
            )
            if not is_in:
                return False
        
        if self.exclude_domains:
            for d in self.exclude_domains:
                if d.startswith("*."):
                    if host.endswith(d[1:]):
                        return False
                elif host == d:
                    return False
        
        return True

    def request(self, flow: http.HTTPFlow):
        """Called when a request is received."""
        parsed = urlparse(flow.request.pretty_url)
        host = parsed.hostname or ""
        if host in {"127.0.0.1", "localhost", "::1"} and parsed.port == 8443:
            return

        # Even if not in scope, we pass it through.
        # But if intercept is ON and it IS in scope, we stop it.
        in_scope = self._is_in_scope(host)

        flow.metadata["greytab_session_id"] = self.session_id
        self._flow_start_times[flow.id] = time.time()
        if not in_scope:
            return

        inject_watched_token(host, flow.request.headers)

        # ── Match & Replace (request phase) ─────────────────────
        try:
            req = flow.request
            headers = dict(req.headers)
            try:
                body = req.content.decode("utf-8", errors="replace") if req.content else ""
            except Exception:
                body = ""
            new_method, new_url, new_headers, new_body, applied = apply_rules_to_request(
                host, req.method, req.pretty_url, headers, body
            )
            if applied:
                if new_method != req.method:
                    req.method = new_method
                if new_url != req.pretty_url:
                    try:
                        req.url = new_url
                    except Exception:
                        pass
                # Only modify body/headers if changed (avoid unnecessary work)
                update_headers(req.headers, new_headers)
                if new_body != body:
                    try:
                        req.content = new_body.encode("utf-8")
                    except Exception:
                        pass
        except Exception as e:
            print(f"[Proxy] Match&Replace request error: {e}")

        # ── GraphQL detection ───────────────────────────────────
        try:
            req = flow.request
            try:
                body = req.content.decode("utf-8", errors="replace") if req.content else ""
            except Exception:
                body = ""
            gql = detect_graphql(dict(req.headers), body, req.path or "")
            if gql and self._graphql_callback:
                try:
                    self._graphql_callback({
                        "url": req.pretty_url,
                        "host": host,
                        "method": req.method,
                        **gql,
                    })
                except Exception:
                    pass
        except Exception:
            pass

        if self.intercept_enabled and in_scope:
            # Don't intercept websocket upgrades or static assets usually
            is_static = any(flow.request.path.endswith(ext) for ext in 
                          ['.css', '.js', '.png', '.jpg', '.jpeg', '.gif', '.ico', '.svg', '.woff', '.woff2'])
            
            if not is_static:
                flow.intercept()
                self._pending_flows[flow.id] = flow
                
                # Notify API
                if self._intercept_callback:
                    # serialize for API
                    data = self._serialize_flow_request(flow)
                    # We run callback in a safe way
                    try:
                        self._intercept_callback(data)
                    except Exception as e:
                        print(f"[Proxy] Error in intercept callback: {e}")

    def response(self, flow: http.HTTPFlow):
        """Called when a response is received."""
        parsed = urlparse(flow.request.pretty_url)
        host = parsed.hostname or ""
        if host in {"127.0.0.1", "localhost", "::1"} and parsed.port == 8443:
            return
        in_scope = self._is_in_scope(host)
        if not in_scope:
            self._flow_start_times.pop(flow.id, None)
            return

        # ── Match & Replace (response phase) ────────────────────
        try:
            resp = flow.response
            if resp:
                headers = dict(resp.headers)
                try:
                    body = resp.content.decode("utf-8", errors="replace") if resp.content else ""
                except Exception:
                    body = ""
                new_status, new_headers, new_body, applied = apply_rules_to_response(
                    host, int(resp.status_code or 0), headers, body
                )
                if applied:
                    if new_status and new_status != resp.status_code:
                        resp.status_code = new_status
                    update_headers(resp.headers, new_headers)
                    if new_body != body:
                        try:
                            resp.content = new_body.encode("utf-8")
                        except Exception:
                            pass
        except Exception as e:
            print(f"[Proxy] Match&Replace response error: {e}")

        # ── Token watcher ───────────────────────────────────────
        try:
            resp = flow.response
            if resp and in_scope:
                try:
                    body = resp.content.decode("utf-8", errors="replace") if resp.content else ""
                except Exception:
                    body = ""
                captured = maybe_capture_token(dict(resp.headers), body)
                if captured and self._token_callback:
                    try:
                        self._token_callback({
                            "token": captured[0],
                            "source": captured[1],
                            "url": flow.request.pretty_url,
                            "host": host,
                        })
                    except Exception:
                        pass
        except Exception:
            pass

        # Response interception
        if self.intercept_response and in_scope:
            is_static = any(flow.request.path.endswith(ext) for ext in
                          ['.css', '.js', '.png', '.jpg', '.jpeg', '.gif', '.ico', '.svg', '.woff', '.woff2'])

            if not is_static:
                flow.intercept()
                self._pending_responses[flow.id] = flow

                if self._response_intercept_callback:
                    data = self._serialize_flow_response(flow)
                    try:
                        self._response_intercept_callback(data)
                    except Exception as e:
                        print(f"[Proxy] Error in response intercept callback: {e}")
                return  # Don't log yet — will log after resume

        if not self.log_traffic:
            self._flow_start_times.pop(flow.id, None)
            return

        start_time = self._flow_start_times.pop(flow.id, time.time())
        duration_ms = (time.time() - start_time) * 1000

        # Create serialized flow object
        intercepted_flow = self._serialize_flow_full(flow, start_time, duration_ms)

        if self._flow_callback:
            try:
                self._flow_callback(intercepted_flow)
            except Exception as e:
                ctx.log.error(f"Flow callback error: {e}")

    def resume_flow(self, flow_id: str, updates: Optional[Dict] = None):
        """Resume a pending flow, optionally applying updates."""
        if flow_id in self._pending_flows:
            flow = self._pending_flows[flow_id]
            
            if updates:
                if 'method' in updates:
                    flow.request.method = updates['method']
                if 'url' in updates:
                    flow.request.url = updates['url']
                if 'headers' in updates:
                    # updates['headers'] is dict
                    update_headers(flow.request.headers, updates['headers'])
                if 'body' in updates:
                    # updates['body'] is user string
                    flow.request.content = updates['body'].encode('utf-8')
                flow.request.headers.pop('transfer-encoding', None)
                if flow.request.content is not None:
                    flow.request.headers['content-length'] = str(len(flow.request.raw_content or b''))
            
            self._pending_flows.pop(flow_id, None)
            flow.resume()
            return True
        return False

    def drop_flow(self, flow_id: str):
        """Kill a pending flow."""
        if flow_id in self._pending_flows:
            flow = self._pending_flows.pop(flow_id)
            self._flow_start_times.pop(flow.id, None)
            flow.kill()
            return True
        return False

    def resume_response(self, flow_id: str, updates: Optional[Dict] = None):
        """Resume a pending response, optionally applying updates."""
        if flow_id in self._pending_responses:
            flow = self._pending_responses[flow_id]

            if updates:
                if 'status_code' in updates:
                    flow.response.status_code = int(updates['status_code'])
                if 'headers' in updates:
                    update_headers(flow.response.headers, updates['headers'])
                if 'body' in updates:
                    flow.response.content = updates['body'].encode('utf-8')
                    # Update content-length
                    flow.response.headers.pop('transfer-encoding', None)
                    flow.response.headers['content-length'] = str(len(flow.response.raw_content or b''))

            self._pending_responses.pop(flow_id, None)
            flow.resume()

            # Now log the flow
            start_time = self._flow_start_times.pop(flow.id, time.time())
            if self.log_traffic:
                duration_ms = (time.time() - start_time) * 1000
                intercepted_flow = self._serialize_flow_full(flow, start_time, duration_ms)
                if self._flow_callback:
                    try:
                        self._flow_callback(intercepted_flow)
                    except Exception as e:
                        print(f"[Proxy] Error logging flow after response resume: {e}")
            return True
        return False

    def drop_response(self, flow_id: str):
        """Kill a pending response flow."""
        if flow_id in self._pending_responses:
            flow = self._pending_responses.pop(flow_id)
            self._flow_start_times.pop(flow.id, None)
            flow.kill()
            return True
        return False

    def error(self, flow):
        self._flow_start_times.pop(flow.id, None)
        self._pending_flows.pop(flow.id, None)
        self._pending_responses.pop(flow.id, None)

    def websocket_message(self, flow):
        """Log each frame on a WebSocket connection."""
        try:
            if not self.log_traffic or not flow.websocket or not flow.websocket.messages:
                return
            msg = flow.websocket.messages[-1]
            host = flow.request.host if flow.request else ""
            if not self._is_in_scope(host):
                return
            content = ""
            try:
                content = msg.content.decode("utf-8", errors="replace") if isinstance(msg.content, (bytes, bytearray)) else str(msg.content)
            except Exception:
                content = "<binary>"
            payload = {
                "session_id": flow.metadata.get("greytab_session_id"),
                "flow_id": flow.id,
                "url": flow.request.pretty_url if flow.request else "",
                "host": host,
                "direction": "from_client" if msg.from_client else "from_server",
                "timestamp": time.time(),
                "content": content[:10000],
                "length": len(msg.content) if msg.content is not None else 0,
                "is_text": getattr(msg, "is_text", True),
            }
            if self._ws_callback:
                try:
                    self._ws_callback(payload)
                except Exception:
                    pass
        except Exception as e:
            print(f"[Proxy] ws frame error: {e}")

    def _serialize_flow_request(self, flow: http.HTTPFlow) -> Dict:
        """Helper to serialize a flow request for API."""
        req_body = ""
        if flow.request.content:
            try:
                req_body = flow.request.content.decode('utf-8', errors='replace')
            except:
                req_body = "[BINARY]"
        
        return {
            "type": "request",
            "id": flow.id,
            "method": flow.request.method,
            "url": flow.request.pretty_url,
            "host": flow.request.host,
            "path": flow.request.path,
            "headers": dict(flow.request.headers),
            "body": req_body
        }

    def _serialize_flow_response(self, flow: http.HTTPFlow) -> Dict:
        """Helper to serialize a flow response for API."""
        resp_body = ""
        if flow.response and flow.response.content:
            content_type = flow.response.headers.get("content-type", "")
            if "text" in content_type or "json" in content_type or "xml" in content_type or "javascript" in content_type:
                try:
                    resp_body = flow.response.content.decode('utf-8', errors='replace')
                except:
                    resp_body = "[BINARY]"
            else:
                resp_body = f"[Binary content: {len(flow.response.content)} bytes]"

        return {
            "type": "response",
            "id": flow.id,
            "method": flow.request.method,
            "url": flow.request.pretty_url,
            "host": flow.request.host,
            "path": flow.request.path,
            "status_code": flow.response.status_code,
            "response_headers": dict(flow.response.headers),
            "response_body": resp_body,
        }

    def _serialize_flow_full(self, flow: http.HTTPFlow, start_time: float, duration_ms: float) -> InterceptedFlow:
        """Helper to create full InterceptedFlow object."""
        # Extract request body
        request_body = None
        if flow.request.content:
            try:
                request_body = flow.request.content.decode('utf-8', errors='replace')[:1048576]
            except Exception:
                request_body = f"<binary: {len(flow.request.content)} bytes>"

        # Extract response body preview
        response_body_preview = None
        content_type = flow.response.headers.get("content-type", "")
        if flow.response.content and ("text" in content_type or "json" in content_type or "xml" in content_type or "javascript" in content_type):
            try:
                response_body_preview = flow.response.content.decode('utf-8', errors='replace')[:1048576]
            except Exception:
                response_body_preview = None

        return InterceptedFlow(
            flow_id=flow.id,
            method=flow.request.method,
            url=flow.request.pretty_url,
            host=flow.request.host,
            path=flow.request.path or "/",
            request_headers=dict(flow.request.headers),
            request_body=request_body,
            timestamp=start_time,
            status_code=flow.response.status_code,
            response_headers=dict(flow.response.headers),
            response_body_preview=response_body_preview,
            content_type=content_type,
            content_length=len(flow.response.content) if flow.response.content else 0,
            duration_ms=duration_ms,
            session_id=flow.metadata.get("greytab_session_id"),
        )


class ProxyManager:
    """Manages the mitmproxy instance in a separate thread."""

    def __init__(self, host: str = "127.0.0.1", port: int = 8080):
        self.host = host
        self.port = port
        self.addon = PentestProxyAddon()
        self._master: Optional[DumpMaster] = None
        self._thread: Optional[threading.Thread] = None
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._startup_error = None

    def set_callbacks(self, on_flow: Callable, on_intercept: Callable, on_response_intercept: Optional[Callable] = None):
        """Set the callbacks."""
        self.addon.set_callbacks(on_flow, on_intercept, on_response_intercept)

    async def start(self):
        """Start mitmproxy in a background thread."""
        opts = options.Options(
            listen_host=self.host,
            listen_port=self.port,
            ssl_insecure=True,
            confdir=str(CA_CERT_DIR),
        )

        self._thread = threading.Thread(
            target=self._run_proxy,
            args=(opts,),
            daemon=True,
            name="mitmproxy-thread",
        )
        self._thread.start()
        for _ in range(100):
            await asyncio.sleep(0.1)
            if self._startup_error or not self.is_running:
                raise RuntimeError(f"Proxy startup failed: {self._startup_error}")
            if self._master and CA_CERT_DIR.joinpath("mitmproxy-ca-cert.pem").exists():
                try:
                    reader, writer = await asyncio.open_connection(self.host, self.port)
                    writer.close()
                    await writer.wait_closed()
                    return
                except OSError:
                    pass
        raise RuntimeError("Proxy startup timed out")

    def _run_proxy(self, opts: options.Options):
        """Run mitmproxy in its own event loop (separate thread)."""
        self._loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self._loop)

        async def _start():
            self._master = DumpMaster(opts)
            self._master.addons.add(self.addon)
            await self._master.run()

        try:
            self._loop.run_until_complete(_start())
        except Exception as e:
            self._startup_error = str(e)
            print(f"[Proxy] Error: {e}")
        finally:
            self._loop.close()

    async def stop(self):
        """Stop the proxy."""
        if self._master:
            self._master.shutdown()
        if self._thread:
            await asyncio.to_thread(self._thread.join, 5)

    @property
    def is_running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def set_intercept_mode(self, enabled: bool):
        """Toggle intercept mode (hold requests)."""
        def apply():
            self.addon.intercept_enabled = enabled
            if not enabled:
                for flow_id in list(self.addon._pending_flows):
                    self.addon.resume_flow(flow_id)
        if self._loop:
            self._loop.call_soon_threadsafe(apply)
        else:
            apply()

    def set_intercept_response(self, enabled: bool):
        """Toggle response intercept mode."""
        def apply():
            self.addon.intercept_response = enabled
            if not enabled:
                for flow_id in list(self.addon._pending_responses):
                    self.addon.resume_response(flow_id)
        if self._loop:
            self._loop.call_soon_threadsafe(apply)
        else:
            apply()

    def set_scope(self, domains: List[str]):
        """Set target scope."""
        self.addon.set_scope(domains)

    def set_excludes(self, domains: List[str]):
        """Set excluded domains."""
        self.addon.set_excludes(domains)

    async def _call(self, fn, *args):
        if not self._loop or self._loop.is_closed():
            return False
        async def invoke():
            return fn(*args)
        return await asyncio.wrap_future(asyncio.run_coroutine_threadsafe(invoke(), self._loop))

    async def resume_flow(self, flow_id, updates=None):
        return await self._call(self.addon.resume_flow, flow_id, updates)

    async def drop_flow(self, flow_id):
        return await self._call(self.addon.drop_flow, flow_id)

    async def resume_response(self, flow_id, updates=None):
        return await self._call(self.addon.resume_response, flow_id, updates)

    async def drop_response(self, flow_id):
        return await self._call(self.addon.drop_response, flow_id)

    async def pending(self):
        def snapshot():
            return {"requests": [self.addon._serialize_flow_request(f) for f in self.addon._pending_flows.values()],
                    "responses": [self.addon._serialize_flow_response(f) for f in self.addon._pending_responses.values()]}
        return await self._call(snapshot) or {"requests": [], "responses": []}
