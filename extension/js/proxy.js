// ══════════════════════════════════════════════════════════════════
// WebSocket Events
// ══════════════════════════════════════════════════════════════════

chrome.runtime.onMessage.addListener((msg) => {
    if (msg.type === 'ws_connected') {
        state.connected = true;
        updateConnectionStatus();
    }
    if (msg.type === 'ws_disconnected') {
        state.connected = false;
        updateConnectionStatus();
    }
    if (msg.type === 'ws_message') {
        handleWsEvent(msg.data);
    }
});

function handleWsEvent(event) {
    const { type, data } = event;

    switch (type) {
        case 'connected':
            state.sessionId = data.session_id;
            state.proxyRunning = data.proxy_running;
            if (Number.isFinite(Number(data.proxy_port))) state.proxyPort = Number(data.proxy_port);
            dom.proxyIntercept.checked = data.intercept_enabled;
            if (dom.proxyInterceptResponse) dom.proxyInterceptResponse.checked = data.intercept_response || false;
            updateProxyStatus();
            if (state.sessionId) {
                showActiveSession(state.sessionId);
            }
            break;

        case 'request_intercepted':
            if (document.body.classList.contains('scanner-detached')) {
                apiRequest('POST', `/api/proxy/flows/${data.id}/resume`, { action: 'resume' }).catch(() => { });
                break;
            }
            enqueueInterceptRequest(data);
            activateTab('proxy');
            break;

        case 'response_intercepted':
            if (document.body.classList.contains('scanner-detached')) {
                apiRequest('POST', `/api/proxy/responses/${data.id}/resume`, { action: 'resume' }).catch(() => { });
                break;
            }
            enqueueInterceptResponse(data);
            activateTab('proxy');
            break;

        case 'http_flow':
            addHistoryItem(data);
            state.stats.requests++;
            updateStats();
            if (dom.scannerPassive?.checked) {
                processPassiveScannerFlow(data);
            }
            break;

        case 'tool_started':
            state.currentRunId = data.run_id;
            dom.toolOutput.textContent = '';
            dom.toolOutputHeader.style.display = 'flex';
            dom.toolOutputName.textContent = `${data.tool_name}: ${data.command}`;
            dom.toolOutputStatus.textContent = 'Running...';
            dom.toolOutputStatus.className = 'tool-output-status tool-output-status--running';
            $('#btn-cancel-all').style.display = 'inline-flex';
            updateRunningTools();
            break;

        case 'tool_output':
            if (data.run_id === state.currentRunId) {
                dom.toolOutput.textContent += data.line + '\n';
                dom.toolOutput.scrollTop = dom.toolOutput.scrollHeight;
            }
            break;

        case 'tool_complete':
            if (data.run_id === state.currentRunId) {
                const isOk = data.exit_code === 0;
                dom.toolOutputStatus.textContent = isOk
                    ? `Done (${(data.duration_ms / 1000).toFixed(1)}s)`
                    : `Error (exit: ${data.exit_code})`;
                dom.toolOutputStatus.className = `tool-output-status tool-output-status--${isOk ? 'success' : 'error'}`;
                state.stats.tools++;
                updateStats();
            }
            updateRunningTools();
            break;

        case 'scanner_progress':
            updateScannerProgress(data);
            if (data.activity) {
                appendScannerActivity(data.activity);
                processScannerActivity(data.activity);
            }
            break;

        case 'scanner_test_result':
            addScannerTestLog(data);
            break;

        case 'scanner_finding':
            if (addScannerFinding(data)) {
                state.stats.findings++;
                updateStats();
            }
            break;

        case 'scanner_complete':
            setScannerState(false);
            updateScannerProgress(data);
            if (dom.scannerProgressText) dom.scannerProgressText.textContent = `Scan complete. URLs: ${data.urls_crawled} | Findings: ${data.findings_count} | Requests: ${data.requests_sent}`;
            if (dom.scannerProgressFill) dom.scannerProgressFill.style.width = '100%';
            appendScannerActivity({
                seq: (state.scanner.activitySeq || 0) + 1,
                type: 'done',
                message: `Scan finished in ${Number(data.elapsed_s || 0).toFixed(1)}s`,
            });
            break;

        case 'session_created':
            showActiveSession(data.name, data.id);
            break;

        case 'finding_added':
            state.stats.findings++;
            updateStats();
            break;

        case 'proxy_settings_updated':
            dom.proxyIntercept.checked = data.intercept_enabled;
            if (dom.proxyInterceptResponse) dom.proxyInterceptResponse.checked = data.intercept_response || false;
            updateProxyStatus();
            break;
    }
}

// ══════════════════════════════════════════════════════════════════
// Interception Logic — Raw View
// ══════════════════════════════════════════════════════════════════

function renderRequestInterceptQueue() {
    if (!dom.requestInterceptQueue) return;
    const q = state.intercept.requestQueue || [];
    if (q.length === 0) {
        dom.requestInterceptQueue.innerHTML = '';
        return;
    }
    dom.requestInterceptQueue.innerHTML = q.map((f) => {
        const active = String(f.id) === String(state.intercept.currentRequestId);
        return `<div class="intercept-queue__item${active ? ' intercept-queue__item--active' : ''}" data-flow-id="${escHtml(f.id)}">${escHtml((f.method || 'REQ').toUpperCase())} ${escHtml(f.url || '')}</div>`;
    }).join('');
    dom.requestInterceptQueue.querySelectorAll('.intercept-queue__item').forEach((el) => {
        el.addEventListener('click', () => {
            selectInterceptRequest(el.dataset.flowId);
        });
    });
}

function selectInterceptRequest(flowId) {
    const q = state.intercept.requestQueue || [];
    const flow = q.find((x) => String(x.id) === String(flowId));
    if (!flow || !dom.interceptEditor || !dom.editorRaw) return;
    state.intercept.currentRequestId = flow.id;
    dom.interceptEditor.style.display = 'block';
    dom.editorRaw.value = buildRawRequest(flow.method, flow.url, flow.headers, flow.body);
    if (dom.requestInterceptMeta) {
        dom.requestInterceptMeta.textContent = `${q.length} queued`;
    }
    renderRequestInterceptQueue();
}

function enqueueInterceptRequest(flow) {
    if (!flow || !flow.id) return;
    const q = state.intercept.requestQueue;
    if (q.some((x) => String(x.id) === String(flow.id))) return;
    q.push(flow);
    if (!state.intercept.currentRequestId) {
        selectInterceptRequest(flow.id);
    } else {
        renderRequestInterceptQueue();
    }
}

async function forwardCurrentInterceptedRequest() {
    const currentInterceptId = state.intercept.currentRequestId;
    if (!currentInterceptId) return;

    const parsed = parseRawRequest(dom.editorRaw?.value || '');
    const modifications = {
        method: parsed.method,
        url: parsed.url,
        headers: parsed.headers,
        body: parsed.body,
    };

    try {
        await apiRequest('POST', `/api/proxy/flows/${currentInterceptId}/resume`, {
            action: 'resume',
            modifications,
        });
        state.intercept.requestQueue = state.intercept.requestQueue.filter((x) => String(x.id) !== String(currentInterceptId));
        state.intercept.currentRequestId = null;
        if (state.intercept.requestQueue.length > 0) {
            selectInterceptRequest(state.intercept.requestQueue[0].id);
        } else if (dom.interceptEditor) {
            dom.interceptEditor.style.display = 'none';
            renderRequestInterceptQueue();
        }
    } catch (e) {
        console.error('Failed to forward request:', e);
    }
}

dom.btnForward.addEventListener('click', async () => {
    await forwardCurrentInterceptedRequest();
});

dom.btnDrop.addEventListener('click', async () => {
    const currentInterceptId = state.intercept.currentRequestId;
    if (!currentInterceptId) return;
    try {
        await apiRequest('POST', `/api/proxy/flows/${currentInterceptId}/resume`, {
            action: 'drop',
        });
        state.intercept.requestQueue = state.intercept.requestQueue.filter((x) => String(x.id) !== String(currentInterceptId));
        state.intercept.currentRequestId = null;
        if (state.intercept.requestQueue.length > 0) {
            selectInterceptRequest(state.intercept.requestQueue[0].id);
        } else if (dom.interceptEditor) {
            dom.interceptEditor.style.display = 'none';
            renderRequestInterceptQueue();
        }
    } catch (e) {
        console.error('Failed to drop request:', e);
    }
});

// Proxy settings toggle
$('#proxy-intercept').addEventListener('change', async (e) => {
    try {
        await apiRequest('POST', '/api/proxy/settings', {
            intercept_enabled: e.target.checked,
        });
        updateProxyStatus();
        // Burp-like behavior: if user turns intercept OFF with queued requests, forward all.
        if (!e.target.checked && state.intercept.requestQueue.length > 0) {
            const pending = [...state.intercept.requestQueue];
            for (const flow of pending) {
                await apiRequest('POST', `/api/proxy/flows/${flow.id}/resume`, { action: 'resume' }).catch(() => { });
            }
            state.intercept.requestQueue = [];
            state.intercept.currentRequestId = null;
            if (dom.interceptEditor) dom.interceptEditor.style.display = 'none';
            renderRequestInterceptQueue();
        }
    } catch (err) {
        console.error('Failed to update proxy settings:', err);
        e.target.checked = !e.target.checked;
    }
});

$('#proxy-logging').addEventListener('change', async (e) => {
    try {
        await apiRequest('POST', '/api/proxy/settings', {
            log_traffic: e.target.checked,
        });
    } catch (err) {
        console.error('Failed to update proxy settings:', err);
    }
});

// Response intercept toggle
if (dom.proxyInterceptResponse) {
    dom.proxyInterceptResponse.addEventListener('change', async (e) => {
        try {
            await apiRequest('POST', '/api/proxy/settings', {
                intercept_response: e.target.checked,
            });
            updateProxyStatus();
            if (!e.target.checked && state.intercept.responseQueue.length > 0) {
                const pending = [...state.intercept.responseQueue];
                for (const flow of pending) {
                    await apiRequest('POST', `/api/proxy/responses/${flow.id}/resume`, { action: 'resume' }).catch(() => { });
                }
                state.intercept.responseQueue = [];
                state.intercept.currentResponseId = null;
                if (dom.responseInterceptEditor) dom.responseInterceptEditor.style.display = 'none';
                renderResponseInterceptQueue();
            }
        } catch (err) {
            console.error('Failed to update proxy settings:', err);
            e.target.checked = !e.target.checked;
        }
    });
}

// ══════════════════════════════════════════════════════════════════
// Response Interception
// ══════════════════════════════════════════════════════════════════

function renderResponseInterceptQueue() {
    if (!dom.responseInterceptQueue) return;
    const q = state.intercept.responseQueue || [];
    if (q.length === 0) {
        dom.responseInterceptQueue.innerHTML = '';
        return;
    }
    dom.responseInterceptQueue.innerHTML = q.map((f) => {
        const active = String(f.id) === String(state.intercept.currentResponseId);
        const code = Number(f.status_code || 0);
        return `<div class="intercept-queue__item${active ? ' intercept-queue__item--active' : ''}" data-flow-id="${escHtml(f.id)}">HTTP ${code || '-'} ${escHtml(f.url || '')}</div>`;
    }).join('');
    dom.responseInterceptQueue.querySelectorAll('.intercept-queue__item').forEach((el) => {
        el.addEventListener('click', () => {
            selectInterceptResponse(el.dataset.flowId);
        });
    });
}

function buildRawResponseFull(statusCode, headers, body) {
    let raw = `HTTP/1.1 ${statusCode || '???'}\n`;
    if (headers) {
        const h = typeof headers === 'string' ? JSON.parse(headers) : headers;
        for (const [k, v] of Object.entries(h)) {
            raw += `${k}: ${v}\n`;
        }
    }
    if (body) {
        raw += `\n${body}`;
    }
    return raw;
}

function parseRawResponse(raw) {
    const idx = raw.indexOf('\n\n');
    const headerBlock = idx >= 0 ? raw.substring(0, idx) : raw;
    const body = idx >= 0 ? raw.substring(idx + 2) : '';

    const lines = headerBlock.split('\n');
    const statusLine = lines[0] || '';

    // Parse status line: HTTP/1.1 200 OK
    const slParts = statusLine.trim().split(/\s+/);
    const statusCode = parseInt(slParts[1]) || 200;

    // Parse headers
    const headers = {};
    for (let i = 1; i < lines.length; i++) {
        const line = lines[i];
        const colonIdx = line.indexOf(':');
        if (colonIdx > 0) {
            headers[line.substring(0, colonIdx).trim()] = line.substring(colonIdx + 1).trim();
        }
    }

    return { statusCode, headers, body };
}

function showResponseInterceptEditor(data) {
    state.intercept.currentResponseId = data.id;
    if (!dom.responseInterceptEditor) return;

    dom.responseInterceptEditor.style.display = 'block';

    // Build raw response
    const raw = buildRawResponseFull(data.status_code, data.response_headers, data.response_body);
    dom.editorResponseRaw.value = raw;

    // Show meta info
    if (dom.responseInterceptMeta) {
        dom.responseInterceptMeta.textContent = `${(state.intercept.responseQueue || []).length} queued • ${data.method} ${data.url}`;
    }
    renderResponseInterceptQueue();
}

function selectInterceptResponse(flowId) {
    const q = state.intercept.responseQueue || [];
    const flow = q.find((x) => String(x.id) === String(flowId));
    if (!flow) return;
    showResponseInterceptEditor(flow);
}

function enqueueInterceptResponse(flow) {
    if (!flow || !flow.id) return;
    const q = state.intercept.responseQueue;
    if (q.some((x) => String(x.id) === String(flow.id))) return;
    q.push(flow);
    if (!state.intercept.currentResponseId) {
        selectInterceptResponse(flow.id);
    } else {
        renderResponseInterceptQueue();
    }
}

async function forwardCurrentInterceptedResponse() {
    const currentResponseInterceptId = state.intercept.currentResponseId;
    if (!currentResponseInterceptId) return;

    const parsed = parseRawResponse(dom.editorResponseRaw.value);
    const modifications = {
        status_code: parsed.statusCode,
        headers: parsed.headers,
        body: parsed.body,
    };

    try {
        await apiRequest('POST', `/api/proxy/responses/${currentResponseInterceptId}/resume`, {
            action: 'resume',
            modifications,
        });
        state.intercept.responseQueue = state.intercept.responseQueue.filter((x) => String(x.id) !== String(currentResponseInterceptId));
        state.intercept.currentResponseId = null;
        if (state.intercept.responseQueue.length > 0) {
            selectInterceptResponse(state.intercept.responseQueue[0].id);
        } else if (dom.responseInterceptEditor) {
            dom.responseInterceptEditor.style.display = 'none';
            renderResponseInterceptQueue();
        }
    } catch (e) {
        console.error('Failed to forward response:', e);
    }
}

if (dom.btnForwardResponse) {
    dom.btnForwardResponse.addEventListener('click', async () => {
        await forwardCurrentInterceptedResponse();
    });
}

if (dom.btnDropResponse) {
    dom.btnDropResponse.addEventListener('click', async () => {
        const currentResponseInterceptId = state.intercept.currentResponseId;
        if (!currentResponseInterceptId) return;
        try {
            await apiRequest('POST', `/api/proxy/responses/${currentResponseInterceptId}/resume`, {
                action: 'drop',
            });
            state.intercept.responseQueue = state.intercept.responseQueue.filter((x) => String(x.id) !== String(currentResponseInterceptId));
            state.intercept.currentResponseId = null;
            if (state.intercept.responseQueue.length > 0) {
                selectInterceptResponse(state.intercept.responseQueue[0].id);
            } else if (dom.responseInterceptEditor) {
                dom.responseInterceptEditor.style.display = 'none';
                renderResponseInterceptQueue();
            }
        } catch (e) {
            console.error('Failed to drop response:', e);
        }
    });
}

// ══════════════════════════════════════════════════════════════════
// UI Updates
// ══════════════════════════════════════════════════════════════════

function updateConnectionStatus() {
    dom.wsIndicator.className = `status-dot status-dot--${state.connected ? 'connected' : 'disconnected'}`;
    dom.wsIndicator.title = state.connected ? 'Backend: Connected' : 'Backend: Disconnected';
}

function updateProxyStatus() {
    dom.proxyIndicator.className = `status-dot status-dot--${state.proxyRunning ? 'connected' : 'disconnected'}`;
    dom.proxyIndicator.title = state.proxyRunning ? 'Proxy: Running' : 'Proxy: Stopped';
    dom.proxyStatus.textContent = state.proxyRunning ? 'Running' : 'Stopped';
    dom.proxyStatus.style.color = state.proxyRunning ? 'var(--success)' : 'var(--danger)';
    if (dom.proxyPort) dom.proxyPort.textContent = String(state.proxyPort || 8080);
    if (dom.memUsage) {
        const mb = Number(state.memoryMb || 0);
        dom.memUsage.textContent = `RAM: ${Number.isFinite(mb) ? mb.toFixed(1) : '--'} MB`;
    }

    // Intercept bar visual state
    const intercepting = dom.proxyIntercept.checked;
    const interceptingResponse = dom.proxyInterceptResponse ? dom.proxyInterceptResponse.checked : false;
    document.body.classList.toggle('intercept-active', intercepting);
    if (dom.interceptBar) {
        dom.interceptBar.classList.toggle('intercept-bar--active', intercepting);
    }
    if (dom.interceptText) {
        let text = 'Intercept OFF';
        if (intercepting && interceptingResponse) text = 'Intercept ON (Req + Resp)';
        else if (intercepting) text = 'Intercept ON (Requests)';
        else if (interceptingResponse) text = 'Intercept ON (Responses)';
        dom.interceptText.textContent = text;

        if (interceptingResponse && !intercepting) {
            dom.interceptBar.classList.add('intercept-bar--active');
        }
    }
}

async function refreshProxyRuntimeStatus() {
    try {
        const ps = await apiRequest('GET', '/api/proxy/status');
        if (ps && typeof ps === 'object') {
            state.proxyRunning = Boolean(ps.running);
            state.proxyPort = Number(ps.port || state.proxyPort || 8080);
            if (dom.proxyIntercept && typeof ps.intercept_enabled === 'boolean') dom.proxyIntercept.checked = ps.intercept_enabled;
            if (dom.proxyInterceptResponse && typeof ps.intercept_response === 'boolean') dom.proxyInterceptResponse.checked = ps.intercept_response;
        }
    } catch {
        // ignore
    }
}

function updateStats() {
    dom.statRequests.textContent = `REQ: ${state.stats.requests}`;
    dom.statTools.textContent = `TOOLS: ${state.stats.tools}`;
    dom.statFindings.textContent = `FIND: ${state.stats.findings}`;
}

function showActiveSession(name, id) {
    state.sessionId = id || state.sessionId;
    state.sessionName = name || state.sessionName || 'Unknown';
    if (dom.landingPage) dom.landingPage.style.display = 'none';
    if (dom.appContainer) dom.appContainer.style.display = 'flex';
    if (dom.activeSessionName) dom.activeSessionName.textContent = state.sessionName;
    if (state.sessionId) {
        loadHttpHistory();
    }
    scheduleWorkspaceSave();
}

