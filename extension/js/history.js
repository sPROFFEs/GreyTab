// ══════════════════════════════════════════════════════════════════
// Traffic & History
// ══════════════════════════════════════════════════════════════════

function addTrafficItem(flow) {
    state.trafficItems.unshift(flow);
    if (state.trafficItems.length > 20000) state.trafficItems.pop();
    renderTrafficItem(flow, true);
    if (dom.trafficCount) dom.trafficCount.textContent = state.trafficItems.length;
    // Trigger passive scan on new traffic
    try { scanForFindings(flow); } catch { }
    scheduleWorkspaceSave();
}

function renderTrafficItem(flow, prepend = false) {
    const emptyState = dom.trafficList.querySelector('.empty-state');
    if (emptyState) emptyState.remove();

    const el = document.createElement('div');
    el.className = 'traffic-item';
    el.dataset.id = flow.id;

    const statusClass = getStatusClass(flow.status_code);
    const methodClass = `method-${flow.method}`;

    const host = new URL(flow.url).host;
    el.innerHTML = `
      <div class="traffic-item__main">
        <div class="traffic-item__line1">
          <span class="traffic-item__method ${methodClass}">${flow.method}</span>
          <span class="traffic-item__url" title="${escHtml(flow.url)}">${escHtml(flow.path || flow.url)}</span>
        </div>
        <div class="traffic-item__host">Host: ${escHtml(host)}</div>
      </div>
      <div class="traffic-item__meta">
        <span class="traffic-item__status ${statusClass}">${flow.status_code || ''}</span>
        <span class="traffic-item__time">${flow.duration_ms ? Math.round(flow.duration_ms) + 'ms' : ''}</span>
      </div>
    `;

    el.addEventListener('click', () => showRequestDetail(flow.id));

    // Context menu on right-click
    el.addEventListener('contextmenu', (e) => {
        e.preventDefault();
        showContextMenu(e.clientX, e.clientY, flow);
    });

    if (prepend) {
        dom.trafficList.prepend(el);
    } else {
        dom.trafficList.appendChild(el);
    }

    // Apply active filters
    applyTrafficFilters(el, flow);
}

function applyTrafficFilters(el, flow) {
    const hostFilter = dom.trafficFilterHost.value.toLowerCase();
    const methodFilter = dom.trafficFilterMethod.value;

    let show = true;
    if (hostFilter && !flow.url.toLowerCase().includes(hostFilter)) show = false;
    if (methodFilter && flow.method !== methodFilter) show = false;

    el.style.display = show ? 'flex' : 'none';
}

function updateAllTrafficFilters() {
    const hostFilter = dom.trafficFilterHost.value.toLowerCase();
    const methodFilter = dom.trafficFilterMethod.value;

    $$('.traffic-item').forEach(el => {
        const method = el.querySelector('.traffic-item__method').textContent;
        const url = el.querySelector('.traffic-item__url').title.toLowerCase();

        let show = true;
        if (hostFilter && !url.includes(hostFilter)) show = false;
        if (methodFilter && method !== methodFilter) show = false;

        el.style.display = show ? 'flex' : 'none';
    });
}

// Filter listeners
if (dom.trafficFilterHost) dom.trafficFilterHost.addEventListener('input', updateAllTrafficFilters);
if (dom.trafficFilterMethod) dom.trafficFilterMethod.addEventListener('change', updateAllTrafficFilters);

function getStatusClass(code) {
    if (!code) return '';
    if (code >= 200 && code < 300) return 'status-2xx';
    if (code >= 300 && code < 400) return 'status-3xx';
    if (code >= 400 && code < 500) return 'status-4xx';
    if (code >= 500) return 'status-5xx';
    return '';
}

function escHtml(str) {
    if (!str) return '';
    return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

// ══════════════════════════════════════════════════════════════════
// Session Management
// ══════════════════════════════════════════════════════════════════

$('#btn-create-session').addEventListener('click', async () => {
    const name = dom.sessionName.value.trim();
    if (!name) {
        dom.sessionName.style.borderColor = 'var(--danger)';
        return;
    }
    try {
        const session = await apiRequest('POST', '/api/sessions', {
            name,
            target_scope: dom.sessionScope.value.trim(),
        });
        state.sessionId = session.id;
        showActiveSession(session.name, session.id);
        loadTools();
    } catch (e) {
        console.error('Failed to create session:', e);
    }
});

// Resume previous session
$('#btn-load-session').addEventListener('click', async () => {
    const container = $('#session-list-container');
    const list = $('#session-list');

    if (container.style.display === 'block') {
        container.style.display = 'none';
        return;
    }

    try {
        const sessions = await apiRequest('GET', '/api/sessions');
        list.innerHTML = '';
        if (sessions.length === 0) {
            list.innerHTML = '<div class="empty-state"><span class="empty-state__text">No previous sessions.</span></div>';
        } else {
            for (const s of sessions) {
                const el = document.createElement('div');
                el.className = 'session-list-item';
                el.innerHTML = `
                    <span class="session-list-item__name">${escHtml(s.name)}</span>
                    <span class="session-list-item__date">${new Date(s.created_at * 1000).toLocaleDateString()}</span>
                `;
                el.addEventListener('click', async () => {
                    try {
                        await apiRequest('POST', `/api/sessions/${s.id}/activate`);
                        state.sessionId = s.id;
                        showActiveSession(s.name, s.id);
                        loadTools();
                    } catch (err) {
                        console.error('Failed to activate session:', err);
                    }
                });
                list.appendChild(el);
            }
        }
        container.style.display = 'block';
    } catch (e) {
        console.error('Failed to list sessions:', e);
    }
});

// ══════════════════════════════════════════════════════════════════
// Project Save / Load
// ══════════════════════════════════════════════════════════════════

$('#btn-save-project').addEventListener('click', async () => {
    if (!state.sessionId) return;

    try {
        persistActiveRepeaterEditor();
        const [session, logs, findings, toolRuns, scannerStatus, scannerAttempts] = await Promise.all([
            apiRequest('GET', `/api/sessions/${state.sessionId}`),
            apiRequest('GET', `/api/logs/http?session_id=${state.sessionId}&limit=1000`),
            apiRequest('GET', `/api/findings?session_id=${state.sessionId}`),
            apiRequest('GET', `/api/tools/history?session_id=${state.sessionId}`),
            apiRequest('GET', '/api/scanner/status'),
            apiRequest('GET', '/api/scanner/attempts?limit=0'),
        ]);

        const project = {
            version: '1.0',
            type: 'pentestbrowser_project',
            exported_at: new Date().toISOString(),
            session,
            http_logs: logs,
            findings,
            tool_runs: toolRuns,
            repeater_state: {
                active_tab_id: state.repeater.activeTabId,
                tabs: state.repeater.tabs.map((t) => ({
                    id: t.id,
                    title: t.title,
                    manual_title: t.manual_title,
                    raw_request: t.raw_request,
                    follow_redirect: t.follow_redirect,
                    response_raw: t.response_raw,
                    response_render: t.response_render,
                    status_text: t.status_text,
                    status_class: t.status_class,
                    time_text: t.time_text,
                    created_at: t.created_at,
                })),
                // backward compatibility
                raw_request: dom.repeaterRawRequest.value,
            },
            intruder_state: {
                target: dom.intruderTarget?.value || '',
                raw_request: dom.intruderRawRequest?.value || '',
                payloads: dom.intruderPayloads?.value || '',
                attack_type: $('#intruder-attack-type')?.value || 'sniper',
                results: state.intruder.results,
            },
            scanner_state: {
                form: getScannerFormState(),
                findings: state.scanner.findings.length ? state.scanner.findings : (scannerStatus?.findings || []),
                request_log: state.scanner.requestLog || [],
                activity: state.scanner.activities || [],
                test_log: state.scanner.testLog.length ? state.scanner.testLog : (scannerAttempts?.attempts || []),
                tree: serializeScannerTreeNode(state.scanner.treeRoot),
                tree_expanded: Array.from(state.scanner.treeExpanded || []),
                backend_status: scannerStatus || {},
            },
        };

        const blob = new Blob([JSON.stringify(project, null, 2)], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `${state.sessionName || 'project'}_${new Date().toISOString().slice(0, 10)}.pbx`;
        a.click();
        URL.revokeObjectURL(url);
    } catch (e) {
        console.error('Failed to save project:', e);
    }
});

$('#btn-load-project').addEventListener('click', () => {
    $('#file-load-project').click();
});

$('#file-load-project').addEventListener('change', async (e) => {
    const file = e.target.files[0];
    if (!file) return;

    try {
        const text = await file.text();
        const project = JSON.parse(text);

        if (project.type !== 'pentestbrowser_project') {
            alert('Invalid project file.');
            return;
        }

        // Create or activate session
        let sessionId;
        try {
            const session = await apiRequest('POST', '/api/sessions', {
                name: project.session.name + ' (imported)',
                target_scope: project.session.target_scope || '',
            });
            sessionId = session.id;
        } catch (err) {
            console.error('Failed to create session for import:', err);
            return;
        }

        state.sessionId = sessionId;
        showActiveSession(project.session.name + ' (imported)', sessionId);

        // Restore repeater
        if (project.repeater_state) {
            state.repeater.tabs = [];
            state.repeater.activeTabId = null;
            state.repeater.tabCounter = 1;

            if (Array.isArray(project.repeater_state.tabs) && project.repeater_state.tabs.length > 0) {
                for (const t of project.repeater_state.tabs) {
                    createRepeaterTab(t);
                }
                state.repeater.activeTabId = project.repeater_state.active_tab_id || state.repeater.tabs[0]?.id || null;
                if (!state.repeater.tabs.some(t => t.id === state.repeater.activeTabId)) {
                    state.repeater.activeTabId = state.repeater.tabs[0]?.id || null;
                }
                activateRepeaterTab(state.repeater.activeTabId, false);
            } else {
                // Backward compatibility with old format
                const legacyRaw = project.repeater_state.raw_request || DEFAULT_REPEATER_RAW;
                const tab = createRepeaterTab({
                    title: 'Tab 1',
                    raw_request: legacyRaw,
                });
                state.repeater.activeTabId = tab.id;
                activateRepeaterTab(tab.id, false);
            }
        }

        // Restore intruder
        if (project.intruder_state) {
            if (dom.intruderTarget) dom.intruderTarget.value = project.intruder_state.target || '';
            if (dom.intruderRawRequest) dom.intruderRawRequest.value = project.intruder_state.raw_request || '';
            if (dom.intruderPayloads) dom.intruderPayloads.value = project.intruder_state.payloads || '';
            if ($('#intruder-attack-type')) $('#intruder-attack-type').value = project.intruder_state.attack_type || 'sniper';

            // Restore intruder results
            if (project.intruder_state.results && project.intruder_state.results.length > 0) {
                state.intruder.results = project.intruder_state.results;
                renderIntruderResults();
            }
        }

        // Restore scanner state
        if (project.scanner_state && typeof project.scanner_state === 'object') {
            const ss = project.scanner_state;
            resetScannerPanels();
            if (ss.form) {
                applyScannerFormState(ss.form);
            }

            state.scanner.findings = [];
            if (dom.scannerFindings) {
                dom.scannerFindings.innerHTML = `
                    <div class="empty-state">
                      <span class="empty-state__text">No findings yet. Configure a target and start scanning.</span>
                    </div>
                `;
            }
            if (Array.isArray(ss.findings)) {
                for (const f of ss.findings) addScannerFinding(f);
            }

            if (Array.isArray(ss.request_log)) {
                for (const r of ss.request_log) addScannerRequestLog(r);
            }
            if (Array.isArray(ss.activity)) {
                for (const a of ss.activity) appendScannerActivity(a);
            }
            if (Array.isArray(ss.test_log)) {
                for (const t of ss.test_log) addScannerTestLog(t);
            }

            const restoredTree = deserializeScannerTreeNode(ss.tree);
            if (restoredTree) {
                state.scanner.treeRoot = restoredTree;
                state.scanner.treeExpanded = new Set(Array.isArray(ss.tree_expanded) ? ss.tree_expanded : ['root']);
                renderScannerTree();
            }
        }

        loadTools();
    } catch (err) {
        console.error('Failed to load project:', err);
        alert('Failed to parse project file.');
    }
});

// ══════════════════════════════════════════════════════════════════
// Tools
// ══════════════════════════════════════════════════════════════════

async function loadTools() {
    try {
        const tools = await apiRequest('GET', '/api/tools');
        cachedToolDefs = tools;  // Cache for description lookup
        dom.toolSelect.innerHTML = '<option value="">Select a tool...</option>';
        for (const [name, tool] of Object.entries(tools)) {
            const opt = document.createElement('option');
            opt.value = name;
            const statusIcon = tool.installed ? '\u2713' : '\u2717';
            opt.textContent = `[${statusIcon}] ${name}`;
            opt.disabled = !tool.installed;
            dom.toolSelect.appendChild(opt);
        }

        const wordlists = await apiRequest('GET', '/api/tools/wordlists');
        dom.toolWordlist.innerHTML = '<option value="">Default / None</option>';
        const intruderWl = $('#intruder-wordlist');
        if (intruderWl) intruderWl.innerHTML = '<option value="">Select wordlist...</option>';

        for (const wl of wordlists) {
            const opt = document.createElement('option');
            opt.value = wl.path;
            opt.textContent = `${wl.relative} (${formatBytes(wl.size)})`;
            dom.toolWordlist.appendChild(opt);

            if (intruderWl) {
                intruderWl.appendChild(opt.cloneNode(true));
            }
        }

        // Add Upload option at the end
        const uploadOpt = document.createElement('option');
        uploadOpt.value = '__upload__';
        uploadOpt.textContent = 'Upload Custom...';
        dom.toolWordlist.appendChild(uploadOpt);
        if (intruderWl) intruderWl.appendChild(uploadOpt.cloneNode(true));
    } catch (e) {
        console.error('Failed to load tools:', e);
    }
}

$('#btn-run-tool').addEventListener('click', async () => {
    const rawCommand = dom.toolRawCommand.value.trim();
    const toolName = dom.toolSelect.value;
    const target = dom.toolTarget.value.trim();

    if (!rawCommand && !toolName) {
        dom.toolSelect.style.borderColor = 'var(--danger)';
        return;
    }

    try {
        const resp = await apiRequest('POST', '/api/tools/run', {
            tool_name: toolName,
            target: target,
            wordlist: dom.toolWordlist.value || $('#tool-wordlist-path')?.value?.trim() || '',
            extra_args: dom.toolExtraArgs.value.trim(),
            raw_command: rawCommand,
        });

        if (resp && resp.run_id) {
            // Open terminal in new tab
            const termUrl = chrome.runtime.getURL(`terminal.html?runId=${resp.run_id}&toolName=${encodeURIComponent(toolName)}&target=${encodeURIComponent(target)}`);
            chrome.tabs.create({ url: termUrl });
        }
    } catch (e) {
        dom.toolOutput.textContent = `Error: ${e.message}`;
    }
});

// Allow manual wordlist path input in Tools tab
$('#btn-use-wordlist-path')?.addEventListener('click', () => {
    const pathInput = $('#tool-wordlist-path');
    const path = pathInput?.value.trim();
    if (!path) {
        pathInput.style.borderColor = 'var(--danger)';
        return;
    }
    pathInput.style.borderColor = '';
    // Add as custom option and select it
    const existing = dom.toolWordlist.querySelector(`option[value="${CSS.escape(path)}"]`);
    if (existing) {
        dom.toolWordlist.value = path;
    } else {
        const opt = document.createElement('option');
        opt.value = path;
        opt.textContent = `[path] ${path}`;
        dom.toolWordlist.appendChild(opt);
        dom.toolWordlist.value = path;
    }
});

$('#btn-cancel-all').addEventListener('click', async () => {
    try {
        const running = await apiRequest('GET', '/api/tools/running');
        for (const id of Object.keys(running)) {
            await apiRequest('POST', `/api/tools/${id}/cancel`);
        }
    } catch (e) {
        console.error('Failed to cancel tools:', e);
    }
});

$('#btn-cancel-current').addEventListener('click', async () => {
    if (state.currentRunId) {
        try {
            await apiRequest('POST', `/api/tools/${state.currentRunId}/cancel`);
        } catch (e) {
            console.error('Failed to cancel tool:', e);
        }
    }
});

$('#btn-use-current-url').addEventListener('click', () => {
    chrome.runtime.sendMessage({ type: 'get_current_url' }, (response) => {
        if (response && response.url) {
            dom.toolTarget.value = response.url;
        }
    });
});

async function updateRunningTools() {
    try {
        const running = await apiRequest('GET', '/api/tools/running');
        const entries = Object.values(running);
        dom.runningCount.textContent = entries.length;

        if (entries.length === 0) {
            dom.runningTools.innerHTML = '<div class="empty-state"><span class="empty-state__text">No tools running</span></div>';
            $('#btn-cancel-all').style.display = 'none';
            return;
        }

        dom.runningTools.innerHTML = entries.map((t) => `
      <div class="running-tool">
        <span class="running-tool__name">${escHtml(t.tool_name)}</span>
        <span class="running-tool__info">PID: ${t.pid} | Lines: ${t.output_lines}</span>
      </div>
    `).join('');
    } catch (e) {
        // Backend might not be ready
    }
}

async function refreshHealth() {
    try {
        const health = await apiRequest('GET', '/api/health');
        if (!health || typeof health !== 'object') return;
        state.proxyRunning = Boolean(health.proxy_running);
        if (Number.isFinite(Number(health.proxy_port))) {
            state.proxyPort = Number(health.proxy_port);
        }
        if (Number.isFinite(Number(health.memory_mb))) {
            state.memoryMb = Number(health.memory_mb);
        }
        updateProxyStatus();
    } catch {
        // ignore
    }
}

// ══════════════════════════════════════════════════════════════════
// HTTP History
// ══════════════════════════════════════════════════════════════════

async function loadHttpHistory() {
    if (!state.sessionId) return;
    try {
        const logs = await apiRequest('GET', `/api/logs/http?session_id=${state.sessionId}&limit=5000`);
        dom.requestList.innerHTML = '';

        // Reset passive findings on load so we don't duplicate
        if (typeof passiveFindings !== 'undefined') {
            passiveFindings.length = 0;
            if (dom.historyFindingsList) dom.historyFindingsList.innerHTML = '';
            if (dom.findingsBadge) dom.findingsBadge.style.display = 'none';
        }

        if (logs.length === 0) {
            dom.requestList.innerHTML = '<div class="empty-state"><span class="empty-state__text">No requests logged yet.</span></div>';
            return;
        }
        for (const log of logs) {
            renderRequestItem(log);
            if (typeof scanForFindings === 'function') {
                try { scanForFindings(log, true); } catch { }
            }
        }

        // Update badge once after scanning all history
        if (typeof updateFindingsBadge === 'function') {
            updateFindingsBadge();
        }
    } catch (e) {
        console.error('Failed to load HTTP history:', e);
    }
}

$('#btn-refresh-history').addEventListener('click', () => loadHttpHistory());

dom.btnClearHistory?.addEventListener('click', async () => {
    if (!state.sessionId) return;
    if (!confirm('Clear all history requests for this session?')) return;
    try {
        await apiRequest('POST', '/api/logs/http/clear', { session_id: state.sessionId });
        dom.requestList.innerHTML = '<div class="empty-state"><span class="empty-state__text">No requests logged yet.</span></div>';
        dom.requestDetail.style.display = 'none';
        state.currentLog = null;
        state.selectedLogId = null;
        state.trafficItems = [];

        // Reset passive findings so new traffic gets scanned fresh
        if (typeof passiveFindings !== 'undefined') {
            passiveFindings.length = 0;
        }
        if (typeof updateFindingsBadge === 'function') {
            updateFindingsBadge();
        }

        scheduleWorkspaceSave();
    } catch (e) {
        console.error('Failed to clear history:', e);
    }
});

function addHistoryItem(log) {
    const emptyState = dom.requestList.querySelector('.empty-state');
    if (emptyState) emptyState.remove();
    renderRequestItem(log, true);
    // Scan new history item for passive findings
    if (typeof scanForFindings === 'function') {
        try { scanForFindings(log); } catch { }
    }
    scheduleWorkspaceSave();
}

function renderRequestItem(log, prepend = false) {
    const el = document.createElement('div');
    el.className = 'request-item';
    el.dataset.id = String(log.id || '');
    const statusClass = getStatusClass(log.status_code);
    const methodClass = `method-${log.method}`;

    let path = log.path || log.url;
    try { path = new URL(log.url).pathname; } catch (e) { }

    el.innerHTML = `
      <div class="req-main">
        <div class="req-line1">
          <span class="req-method ${methodClass}">${log.method}</span>
          <span class="req-url" title="${escHtml(log.url)}">${escHtml(path)}</span>
        </div>
        <div class="req-host">Host: ${escHtml(log.host)}</div>
      </div>
      <div class="req-meta">
        <span class="req-status ${statusClass}">${log.status_code || ''}</span>
      </div>
    `;

    el.addEventListener('click', () => {
        dom.requestList.querySelectorAll('.request-item--active').forEach(x => x.classList.remove('request-item--active'));
        el.classList.add('request-item--active');
        showRequestDetail(log.id);
    });

    // Context menu on right-click
    el.addEventListener('contextmenu', (e) => {
        e.preventDefault();
        showContextMenu(e.clientX, e.clientY, log);
    });

    if (prepend) {
        dom.requestList.prepend(el);
    } else {
        dom.requestList.appendChild(el);
    }

    // Apply active filters
    applyHistoryFilters(el, log);
}

function applyHistoryFilters(el, log) {
    const hostFilter = (dom.historyFilterHost?.value || '').toLowerCase();
    const methodFilter = dom.historyFilterMethod?.value || '';
    const statusFilter = dom.historyFilterStatus?.value || '';
    const searchFilter = (dom.historySearch?.value || '').toLowerCase();

    let show = true;
    if (hostFilter && !log.url.toLowerCase().includes(hostFilter)) show = false;
    if (methodFilter && log.method !== methodFilter) show = false;
    if (statusFilter) {
        const sc = parseInt(log.status_code || log.status || 0);
        if (statusFilter === '2xx' && (sc < 200 || sc >= 300)) show = false;
        else if (statusFilter === '3xx' && (sc < 300 || sc >= 400)) show = false;
        else if (statusFilter === '4xx' && (sc < 400 || sc >= 500)) show = false;
        else if (statusFilter === '5xx' && (sc < 500 || sc >= 600)) show = false;
    }
    if (searchFilter) {
        const text = (log.url + ' ' + (log.request_body || '') + ' ' + (log.response_body || '')).toLowerCase();
        if (!text.includes(searchFilter)) show = false;
    }
    el.style.display = show ? 'flex' : 'none';
}

function updateAllHistoryFilters() {
    const hostFilter = (dom.historyFilterHost?.value || '').toLowerCase();
    const methodFilter = dom.historyFilterMethod?.value || '';
    const statusFilter = dom.historyFilterStatus?.value || '';
    const searchFilter = (dom.historySearch?.value || '').toLowerCase();

    $$('.request-item').forEach(el => {
        const method = el.querySelector('.req-method')?.textContent || '';
        const url = (el.querySelector('.req-url')?.title || '').toLowerCase();
        const status = el.querySelector('.req-status')?.textContent || '';
        const sc = parseInt(status) || 0;

        let show = true;
        if (hostFilter && !url.includes(hostFilter)) show = false;
        if (methodFilter && method !== methodFilter) show = false;
        if (statusFilter) {
            if (statusFilter === '2xx' && (sc < 200 || sc >= 300)) show = false;
            else if (statusFilter === '3xx' && (sc < 300 || sc >= 400)) show = false;
            else if (statusFilter === '4xx' && (sc < 400 || sc >= 500)) show = false;
            else if (statusFilter === '5xx' && (sc < 500 || sc >= 600)) show = false;
        }
        if (searchFilter && !url.includes(searchFilter)) show = false;
        el.style.display = show ? 'flex' : 'none';
    });
}

// Filter listeners
if (dom.historyFilterHost) dom.historyFilterHost.addEventListener('input', updateAllHistoryFilters);
if (dom.historyFilterMethod) dom.historyFilterMethod.addEventListener('change', updateAllHistoryFilters);
if (dom.historyFilterStatus) dom.historyFilterStatus.addEventListener('change', updateAllHistoryFilters);
if (dom.historySearch) {
    let searchDebounce;
    dom.historySearch.addEventListener('input', () => {
        clearTimeout(searchDebounce);
        searchDebounce = setTimeout(updateAllHistoryFilters, 200);
    });
}

async function showRequestDetail(logId) {
    try {
        const log = await apiRequest('GET', `/api/logs/http/${logId}`);
        state.selectedLogId = logId;
        state.currentLog = log;

        // Build raw request
        const reqRaw = buildRawRequest(
            log.method,
            log.url,
            log.request_headers,
            log.request_body
        );
        dom.detailRequest.innerHTML = highlightHttp(reqRaw);

        // Build raw response
        const resRaw = buildRawResponse(
            log.status_code,
            log.response_headers,
            log.response_body_preview
        );
        dom.detailResponse.innerHTML = highlightHttp(resRaw);

        dom.requestDetail.style.display = 'flex';
    } catch (e) {
        console.error('Failed to load request detail:', e);
    }
}

$('#btn-close-detail').addEventListener('click', () => {
    dom.requestDetail.style.display = 'none';
});

$('#btn-send-to-repeater').addEventListener('click', () => {
    if (!state.currentLog) return;
    sendToRepeater(state.currentLog);
});

$('#btn-send-to-intruder').addEventListener('click', () => {
    if (!state.currentLog) return;
    sendToIntruder(state.currentLog);
});

$('#btn-send-to-tool').addEventListener('click', async () => {
    if (!state.selectedLogId) return;
    try {
        const log = await apiRequest('GET', `/api/logs/http/${state.selectedLogId}`);
        dom.toolTarget.value = log.url;
        $$('.tab[data-tab="tools"]')[0].click();
        analyzeForTools(log);
    } catch (e) {
        console.error(e);
    }
});

