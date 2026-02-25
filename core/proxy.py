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


class PentestProxyAddon:
    """mitmproxy addon that intercepts traffic and forwards to our backend."""

    def __init__(self):
        self.intercept_enabled = False  # Start disabled by default
        self.intercept_response = False  # Intercept responses too
        self.log_traffic = True
        self.scope_domains: Set[str] = set()
        self.exclude_domains: Set[str] = set()
        
        # Callbacks
        self._flow_callback: Optional[Callable] = None
        self._intercept_callback: Optional[Callable] = None
        self._response_intercept_callback: Optional[Callable] = None
        
        # State
        self._flow_start_times: Dict[str, float] = {}
        self._pending_flows: Dict[str, http.HTTPFlow] = {}
        self._pending_responses: Dict[str, http.HTTPFlow] = {}

    def set_callbacks(self, on_flow: Callable, on_intercept: Callable, on_response_intercept: Optional[Callable] = None):
        """Set callbacks for flow completion, request interception, and response interception."""
        self._flow_callback = on_flow
        self._intercept_callback = on_intercept
        self._response_intercept_callback = on_response_intercept

    def set_scope(self, domains: List[str]):
        """Set target scope domains."""
        self.scope_domains = set(domains)

    def set_excludes(self, domains: List[str]):
        """Set domains to exclude from logging."""
        self.exclude_domains = set(domains)

    def _is_in_scope(self, host: str) -> bool:
        """Check if a host is within the audit scope."""
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
        
        # Even if not in scope, we pass it through. 
        # But if intercept is ON and it IS in scope, we stop it.
        in_scope = self._is_in_scope(host)
        
        self._flow_start_times[flow.id] = time.time()

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
        in_scope = self._is_in_scope(host)

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
            flow = self._pending_flows.pop(flow_id)
            
            if updates:
                if 'method' in updates:
                    flow.request.method = updates['method']
                if 'url' in updates:
                    flow.request.url = updates['url']
                if 'headers' in updates:
                    # updates['headers'] is dict
                    flow.request.headers.clear()
                    for k, v in updates['headers'].items():
                        flow.request.headers[k] = v
                if 'body' in updates:
                    # updates['body'] is user string
                    flow.request.content = updates['body'].encode('utf-8')
            
            flow.resume()
            return True
        return False

    def drop_flow(self, flow_id: str):
        """Kill a pending flow."""
        if flow_id in self._pending_flows:
            flow = self._pending_flows.pop(flow_id)
            flow.kill()
            return True
        return False

    def resume_response(self, flow_id: str, updates: Optional[Dict] = None):
        """Resume a pending response, optionally applying updates."""
        if flow_id in self._pending_responses:
            flow = self._pending_responses.pop(flow_id)

            if updates:
                if 'status_code' in updates:
                    flow.response.status_code = int(updates['status_code'])
                if 'headers' in updates:
                    flow.response.headers.clear()
                    for k, v in updates['headers'].items():
                        flow.response.headers[k] = v
                if 'body' in updates:
                    flow.response.content = updates['body'].encode('utf-8')
                    # Update content-length
                    flow.response.headers['content-length'] = str(len(flow.response.content))

            flow.resume()

            # Now log the flow
            if self.log_traffic:
                start_time = self._flow_start_times.pop(flow.id, time.time())
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
                    resp_body = flow.response.content.decode('utf-8', errors='replace')[:5000]
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
                request_body = flow.request.content.decode('utf-8', errors='replace')[:5000]
            except Exception:
                request_body = f"<binary: {len(flow.request.content)} bytes>"

        # Extract response body preview
        response_body_preview = None
        content_type = flow.response.headers.get("content-type", "")
        if flow.response.content and ("text" in content_type or "json" in content_type or "xml" in content_type or "javascript" in content_type):
            try:
                response_body_preview = flow.response.content.decode('utf-8', errors='replace')[:50000]
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

    def set_callbacks(self, on_flow: Callable, on_intercept: Callable, on_response_intercept: Optional[Callable] = None):
        """Set the callbacks."""
        self.addon.set_callbacks(on_flow, on_intercept, on_response_intercept)

    async def start(self):
        """Start mitmproxy in a background thread."""
        opts = options.Options(
            listen_host=self.host,
            listen_port=self.port,
            ssl_insecure=True,
        )

        self._thread = threading.Thread(
            target=self._run_proxy,
            args=(opts,),
            daemon=True,
            name="mitmproxy-thread",
        )
        self._thread.start()

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
            print(f"[Proxy] Error: {e}")

    async def stop(self):
        """Stop the proxy."""
        if self._master:
            self._master.shutdown()
        if self._thread:
            self._thread.join(timeout=5)

    @property
    def is_running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def set_intercept_mode(self, enabled: bool):
        """Toggle intercept mode (hold requests)."""
        self.addon.intercept_enabled = enabled

    def set_intercept_response(self, enabled: bool):
        """Toggle response intercept mode."""
        self.addon.intercept_response = enabled

    def set_scope(self, domains: List[str]):
        """Set target scope."""
        self.addon.set_scope(domains)

    def set_excludes(self, domains: List[str]):
        """Set excluded domains."""
        self.addon.set_excludes(domains)

    def resume_flow(self, flow_id: str, updates: Optional[Dict] = None):
        """Resume a flow via the addon, scheduled in the proxy loop."""
        if self._loop:
             self._loop.call_soon_threadsafe(
                 self.addon.resume_flow, flow_id, updates
             )

    def drop_flow(self, flow_id: str):
        """Drop a flow via the addon."""
        if self._loop:
             self._loop.call_soon_threadsafe(
                 self.addon.drop_flow, flow_id
             )

    def resume_response(self, flow_id: str, updates: Optional[Dict] = None):
        """Resume a response via the addon, scheduled in the proxy loop."""
        if self._loop:
             self._loop.call_soon_threadsafe(
                 self.addon.resume_response, flow_id, updates
             )

    def drop_response(self, flow_id: str):
        """Drop a response via the addon."""
        if self._loop:
             self._loop.call_soon_threadsafe(
                 self.addon.drop_response, flow_id
             )
