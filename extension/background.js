/**
 * PentestBrowser - Background Service Worker
 * Manages WebSocket connection and coordinates extension state.
 */

const API_BASE = 'http://127.0.0.1:8443';
const WS_URL = 'ws://127.0.0.1:8443/ws';

let ws = null;
let wsReconnectTimer = null;
let isConnected = false;

// ── WebSocket Management ───────────────────────────────────────

function connectWebSocket() {
    if (ws && ws.readyState === WebSocket.OPEN) return;

    try {
        ws = new WebSocket(WS_URL);

        ws.onopen = () => {
            console.log('[PB] WebSocket connected');
            isConnected = true;
            clearTimeout(wsReconnectTimer);
            // Notify side panel
            chrome.runtime.sendMessage({ type: 'ws_connected' }).catch(() => { });
        };

        ws.onmessage = (event) => {
            try {
                const msg = JSON.parse(event.data);
                // Forward all messages to the side panel
                chrome.runtime.sendMessage({ type: 'ws_message', data: msg }).catch(() => { });
            } catch (e) {
                console.error('[PB] Failed to parse WS message:', e);
            }
        };

        ws.onclose = () => {
            console.log('[PB] WebSocket disconnected');
            isConnected = false;
            ws = null;
            chrome.runtime.sendMessage({ type: 'ws_disconnected' }).catch(() => { });
            // Reconnect after 3 seconds
            wsReconnectTimer = setTimeout(connectWebSocket, 3000);
        };

        ws.onerror = (err) => {
            console.error('[PB] WebSocket error:', err);
            ws.close();
        };
    } catch (e) {
        console.error('[PB] Failed to connect WebSocket:', e);
        wsReconnectTimer = setTimeout(connectWebSocket, 3000);
    }
}

// ── Side Panel Toggle ──────────────────────────────────────────

chrome.action.onClicked.addListener(async (tab) => {
    try {
        await chrome.sidePanel.open({ tabId: tab.id });
    } catch (e) {
        // Fallback: try window-scoped
        await chrome.sidePanel.open({ windowId: tab.windowId });
    }
});

// ── Message Handler ────────────────────────────────────────────

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.type === 'ws_send') {
        if (ws && ws.readyState === WebSocket.OPEN) {
            ws.send(JSON.stringify(message.data));
            sendResponse({ success: true });
        } else {
            sendResponse({ success: false, error: 'WebSocket not connected' });
        }
        return true;
    }

    if (message.type === 'get_ws_status') {
        sendResponse({ connected: isConnected });
        return true;
    }

    if (message.type === 'get_current_url') {
        chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
            if (tabs[0]) {
                sendResponse({ url: tabs[0].url, title: tabs[0].title });
            } else {
                sendResponse({ url: '', title: '' });
            }
        });
        return true;
    }

    if (message.type === 'api_request') {
        // Proxy API requests through background script
        const { method, endpoint, body } = message.data;
        fetch(`${API_BASE}${endpoint}`, {
            method: method || 'GET',
            headers: { 'Content-Type': 'application/json' },
            body: body ? JSON.stringify(body) : undefined,
        })
            .then(async (res) => {
                const text = await res.text();
                let data = null;
                try {
                    data = text ? JSON.parse(text) : {};
                } catch {
                    data = { raw: text || '' };
                }

                if (!res.ok) {
                    const detail = (data && (data.detail || data.error || data.message)) || text || `${res.status}`;
                    sendResponse({ success: false, error: `HTTP ${res.status}: ${String(detail).slice(0, 500)}` });
                    return;
                }
                sendResponse({ success: true, data });
            })
            .catch(err => sendResponse({ success: false, error: err.message }));
        return true;
    }
});

// ── Initialize ─────────────────────────────────────────────────

chrome.runtime.onInstalled.addListener(() => {
    console.log('[PB] PentestBrowser extension installed');
    // Enable side panel
    chrome.sidePanel.setOptions({
        enabled: true,
    });
});

// Auto-connect WebSocket on startup
connectWebSocket();
