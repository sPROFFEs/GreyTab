/**
 * PentestBrowser - Background Service Worker
 * Manages WebSocket connection and coordinates extension state.
 */

const API_BASE = 'http://127.0.0.1:8443';
const WS_URL = 'ws://127.0.0.1:8443/ws';
const WORKSPACE_URL = chrome.runtime.getURL('sidepanel.html?view=workspace');

let ws = null;
let wsReconnectTimer = null;
let isConnected = false;
let heartbeat = null;
let openingWorkspace = null;

// ── WebSocket Management ───────────────────────────────────────

function connectWebSocket() {
    if (ws && [WebSocket.OPEN, WebSocket.CONNECTING].includes(ws.readyState)) return;

    try {
        ws = new WebSocket(WS_URL);

        ws.onopen = () => {
            console.log('[PB] WebSocket connected');
            isConnected = true;
            clearInterval(heartbeat);
            heartbeat = setInterval(() => {
                if (ws?.readyState === WebSocket.OPEN) ws.send(JSON.stringify({type: 'ping'}));
            }, 20000);
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
            clearInterval(heartbeat);
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

async function openWorkspace() {
    if (!openingWorkspace) {
        openingWorkspace = (async () => {
            const popups = await chrome.windows.getAll({populate: true, windowTypes: ['popup']});
            const existing = popups.find(window => window.tabs.some(tab =>
                tab.url === WORKSPACE_URL || tab.pendingUrl === WORKSPACE_URL));
            if (existing) {
                if (existing.state === 'minimized') await chrome.windows.update(existing.id, {state: 'normal'});
                return chrome.windows.update(existing.id, {focused: true});
            }
            return chrome.windows.create({url: WORKSPACE_URL, type: 'popup', width: 1360, height: 900});
        })().finally(() => { openingWorkspace = null; });
    }
    return openingWorkspace;
}

async function openStartupWorkspace() {
    try {
        const response = await fetch(`${API_BASE}/api/health`);
        if (!response.ok) return;
        const health = await response.json();
        if (health.open_workspace_on_launch === true) await openWorkspace();
    } catch (error) {
        console.warn('Unable to open the GreyTab workspace:', error.message);
    }
}

chrome.runtime.onStartup.addListener(openStartupWorkspace);

async function getBrowserWindow(sender) {
    if (sender.tab?.windowId !== undefined) {
        const current = await chrome.windows.get(sender.tab.windowId).catch(() => null);
        if (current?.type === 'normal') return current;
    }
    const browser = await chrome.windows.getLastFocused({windowTypes: ['normal']}).catch(() => null);
    if (browser?.type === 'normal') return browser;
    const [first] = await chrome.windows.getAll({windowTypes: ['normal']});
    return first;
}

async function focusBrowser(sender) {
    const browser = await getBrowserWindow(sender);
    if (!browser) return chrome.windows.create({url: 'about:blank', type: 'normal'});
    if (browser.state === 'minimized') await chrome.windows.update(browser.id, {state: 'normal'});
    return chrome.windows.update(browser.id, {focused: true});
}

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

    if (message.type === 'open_workspace' || message.type === 'focus_browser') {
        const action = message.type === 'open_workspace' ? openWorkspace() : focusBrowser(sender);
        action.then(window => sendResponse({success: true, windowId: window.id}))
            .catch(error => sendResponse({success: false, error: error.message}));
        return true;
    }

    if (message.type === 'get_current_url') {
        getBrowserWindow(sender).then(async browser => {
            const [tab] = browser ? await chrome.tabs.query({active: true, windowId: browser.id}) : [];
            sendResponse({url: tab?.url || '', title: tab?.title || ''});
        }).catch(() => sendResponse({url: '', title: ''}));
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

chrome.runtime.onInstalled.addListener(({reason}) => {
    console.log('[PB] PentestBrowser extension installed');
    // Enable side panel
    chrome.sidePanel.setOptions({
        enabled: true,
    });
    if (reason === 'install') openStartupWorkspace();
});

// Auto-connect WebSocket on startup
connectWebSocket();
