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
        const [session, logs, findings, toolRuns, scannerStatus, scannerAttempts, wsLogs] = await Promise.all([
            apiRequest('GET', `/api/sessions/${state.sessionId}`),
            apiRequest('GET', `/api/logs/http?session_id=${state.sessionId}&limit=50000`),
            apiRequest('GET', `/api/findings?session_id=${state.sessionId}`),
            apiRequest('GET', `/api/tools/history?session_id=${state.sessionId}&limit=5000`),
            apiRequest('GET', '/api/scanner/status'),
            apiRequest('GET', '/api/scanner/attempts?limit=0'),
            apiRequest('GET', `/api/ws_log?session_id=${state.sessionId}&limit=5000`),
        ]);

        const project = {
            version: '1.0',
            type: 'pentestbrowser_project',
            exported_at: new Date().toISOString(),
            session,
            http_logs: logs,
            findings,
            tool_runs: toolRuns,
            ws_logs: wsLogs,
            repeater_state: {
                active_tab_id: state.repeater.activeTabId,
                tabs: state.repeater.tabs.map((t) => ({
                    id: t.id,
                    title: t.title,
                    manual_title: t.manual_title,
                    raw_request: t.raw_request,
                    target_url: t.target_url,
                    prev_response_raw: t.prev_response_raw,
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
            const session = await apiRequest('POST', '/api/projects/import', {
                type: project.type, session: project.session, http_logs: project.http_logs || [],
                findings: project.findings || [], tool_runs: project.tool_runs || [], ws_logs: project.ws_logs || [],
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

const HISTORY_PAGE_SIZE = 200;
let historyPages = [0];
let historyRequest = 0;
let loadedHistorySession = null;
let historyTimer;
let historyLive = true;
let historyDirty = false;
let historyEndpoint = null;
let regexWorker;
const historySeen = new Set();

function setHistoryStatus(message) {
    $('#history-page-status').textContent = message;
}

function resetHistorySession() {
    historyRequest++;
    loadedHistorySession = null;
    clearTimeout(historyTimer);
    historyTimer = null;
    historyPages = [0];
    historyEndpoint = null;
    historyDirty = false;
    closeHistoryDetail();
    dom.requestList.replaceChildren();
    closeSiteMap();
    historySeen.clear();
    passiveFindings.length = 0;
    updateFindingsBadge();
}

function applyPageRegex(rows, pattern) {
    regexWorker?.terminate();
    const worker = new Worker('js/history-regex.js');
    regexWorker = worker;
    return new Promise((resolve, reject) => {
        const finish = (result, error) => {
            clearTimeout(timeout);
            worker.terminate();
            if (regexWorker === worker) regexWorker = null;
            if (error) reject(new Error(error));
            else resolve(rows.filter(row => result.includes(row.id)));
        };
        const timeout = setTimeout(() => finish(null, 'Regex took too long. Simplify the pattern.'), 400);
        worker.onmessage = ({data}) => finish(data.ids, data.error);
        worker.onerror = () => finish(null, 'Could not run the regex.');
        worker.postMessage({pattern, rows: rows.map(({id, url}) => ({id, url}))});
    });
}

function openHistory() {
    if (loadedHistorySession !== state.sessionId) {
        loadHttpHistory();
    } else if (historyDirty && historyLive && historyPages.length === 1 && !dom.requestList.scrollTop) {
        historyDirty = false;
        loadHttpHistory({keepScroll: true});
    }
}

async function loadHttpHistory({keepScroll = false} = {}) {
    const sessionId = state.sessionId;
    if (!sessionId) return;
    const request = ++historyRequest;
    const before = historyPages.at(-1);
    const search = dom.historySearch.value.trim();
    const regex = $('#history-regex-toggle').checked;
    const path = historyEndpoint?.path || '';
    const query = new URLSearchParams({
        session_id: sessionId,
        limit: HISTORY_PAGE_SIZE + 1,
        summary: 'true',
        before_id: before,
        host: dom.historyFilterHost.value.trim(),
        method: dom.historyFilterMethod.value,
        status_class: parseInt(dom.historyFilterStatus.value, 10) || 0,
        mime: $('#history-filter-mime').value,
        annotated: $('#history-filter-annotated').checked,
        search: regex ? '' : search,
        exact_host: historyEndpoint?.host || '',
        path,
    });
    if (!keepScroll) {
        setHistoryStatus('Loading requests…');
        $('#btn-history-newer').disabled = true;
        $('#btn-history-older').disabled = true;
    }
    try {
        const logs = await apiRequest('GET', '/api/logs/http?' + query);
        if (request !== historyRequest || state.sessionId !== sessionId) return;
        const page = logs.slice(0, HISTORY_PAGE_SIZE);
        const visible = regex && search ? await applyPageRegex(page, search) : page;
        if (request !== historyRequest || state.sessionId !== sessionId) return;
        const scrollTop = keepScroll ? dom.requestList.scrollTop : 0;
        const focusedId = document.activeElement.closest('.request-item')?.dataset.id;
        const fragment = document.createDocumentFragment();
        for (const log of visible) {
            fragment.append(renderRequestItem(log));
            recordPassiveHistory(log);
        }
        updateFindingsBadge();
        if (!visible.length) {
            const empty = document.createElement('div');
            empty.className = 'empty-state';
            empty.textContent = 'No matching requests on this page.';
            fragment.append(empty);
        }
        dom.requestList.replaceChildren(fragment);
        loadedHistorySession = sessionId;
        dom.requestList.scrollTop = scrollTop;
        if (focusedId) dom.requestList.querySelector(`[data-id="${CSS.escape(focusedId)}"] .history-row-main`)?.focus({preventScroll: true});
        $('#btn-history-older').disabled = logs.length <= HISTORY_PAGE_SIZE;
        $('#btn-history-older').dataset.before = String(page.at(-1)?.id || '');
        $('#btn-history-newer').disabled = historyPages.length < 2;
        $('#history-page-status').title = path;
        const count = regex && search ? `${visible.length} / ${page.length}` : visible.length;
        setHistoryStatus(`Page ${historyPages.length} · ${count} ${count === 1 ? 'request' : 'requests'}${historyDirty ? ' · New traffic' : ''}${path ? ' · ' + path : ''}`);
    } catch (e) {
        if (request === historyRequest) {
            setHistoryStatus(e.message);
            $('#btn-history-newer').disabled = historyPages.length < 2;
        }
    }
}

function refreshHistoryFilters() {
    historyRequest++;
    clearTimeout(historyTimer);
    historyTimer = null;
    historyPages = [0];
    historyDirty = false;
    historyTimer = setTimeout(() => {
        historyTimer = null;
        loadHttpHistory();
    }, 180);
}

$('#btn-refresh-history').addEventListener('click', () => {
    historyPages = [0];
    historyDirty = false;
    loadHttpHistory();
});
$('#btn-history-live').addEventListener('click', (e) => {
    historyLive = !historyLive;
    e.currentTarget.setAttribute('aria-pressed', String(historyLive));
    e.currentTarget.textContent = historyLive ? 'Live' : 'Paused';
    if (historyLive && historyPages.length === 1) $('#btn-refresh-history').click();
});
$('#btn-history-older').addEventListener('click', (e) => {
    const before = Number(e.currentTarget.dataset.before);
    if (!before) return;
    e.currentTarget.disabled = true;
    historyPages.push(before);
    loadHttpHistory();
});
$('#btn-history-newer').addEventListener('click', () => {
    if (historyPages.length < 2) return;
    historyPages.pop();
    if (historyPages.length === 1) historyDirty = false;
    loadHttpHistory();
});
const historyFilters = $$('#tab-requests .history-filters input, #tab-requests .history-filters select');
for (const control of historyFilters) {
    control.addEventListener(control.type === 'search' ? 'input' : 'change', refreshHistoryFilters);
}
dom.historyFilterHost.addEventListener('input', () => { historyEndpoint = null; });
$('#btn-history-reset').addEventListener('click', () => {
    for (const control of historyFilters) {
        if (control.type === 'checkbox') control.checked = false;
        else control.value = '';
    }
    historyEndpoint = null;
    refreshHistoryFilters();
});

dom.btnClearHistory?.addEventListener('click', async () => {
    const sessionId = state.sessionId;
    if (!sessionId || !confirm('Clear all history requests for this session?')) return;
    try {
        await apiRequest('POST', '/api/logs/http/clear', {session_id: sessionId});
        if (sessionId !== state.sessionId) return;
        resetHistorySession();
        state.stats.requests = 0;
        updateStats();
        loadHttpHistory();
    } catch (e) { setHistoryStatus(e.message); }
});

function recordPassiveHistory(log) {
    if (!dom.passiveScanEnabled?.checked || historySeen.has(log.id)) return;
    historySeen.add(log.id);
    if (historySeen.size > 2000) historySeen.delete(historySeen.values().next().value);
    scanForFindings(log, true);
    if (passiveFindings.length > 1000) passiveFindings.splice(0, passiveFindings.length - 1000);
}

function addHistoryItem(log) {
    if (log.session_id && log.session_id !== state.sessionId) return;
    recordPassiveHistory(log);
    updateFindingsBadge();
    if (!historyDirty) {
        historyDirty = true;
        if (state.activeTab === 'requests') {
            const current = $('#history-page-status').textContent;
            setHistoryStatus(current && current.startsWith('Page ') ? current + ' · New traffic' : 'New traffic available');
        }
    }
    if (!$('#sitemap-panel').hidden || !historyLive || historyPages.length > 1 || state.activeTab !== 'requests' || dom.requestList.scrollTop > 0) return;
    // Coalesce bursts so a stream of requests does not repaint the list per packet.
    if (historyTimer) return;
    historyTimer = setTimeout(() => {
        historyTimer = null;
        if (!$('#sitemap-panel').hidden || !historyLive || historyPages.length > 1 || state.activeTab !== 'requests' || dom.requestList.scrollTop > 0) return;
        historyDirty = false;
        loadHttpHistory({keepScroll: true});
    }, 450);
}

function renderRequestItem(log) {
    const el = document.createElement('div');
    el.className = 'request-item';
    el.dataset.id = String(log.id);
    if (state.selectedLogId === log.id) el.classList.add('request-item--active');
    el.dataset.highlight = log.highlight || '';
    el.title = log.comment || '';
    const method = String(log.method || '');
    const path = log.path || log.url || '/';
    const statusClass = getStatusClass(log.status_code);
    el.innerHTML = `
      <button class="history-row-main">
        <span class="req-method method-${method.replace(/[^A-Z]/g, '')}">${escHtml(method)}</span>
        <span class="history-row-location">
          <span class="req-url" title="${escHtml(log.url)}">${escHtml(path)}</span>
          <small class="req-host">${escHtml(log.host || '')}</small>
        </span>
        <span class="req-status ${statusClass}">${Number(log.status_code) || '—'}</span>
        <span class="history-size">${Number.isFinite(log.content_length) ? formatBytes(log.content_length) : '—'}</span>
        <span class="history-time">${Number.isFinite(log.duration_ms) ? Math.round(log.duration_ms) + ' ms' : '—'}</span>
      </button>
      <button class="req-quick-copy" data-action="scan" aria-label="Scan this request" title="Scan this request">⚡</button>
      <button class="btn btn--ghost btn--xs history-row-menu" aria-label="Request actions" title="Request actions">⋯</button>
    `;
    el.querySelector('.history-row-main').addEventListener('click', () => showRequestDetail(log.id));
    const scan = el.querySelector('[data-action="scan"]');
    scan.addEventListener('click', async () => {
        try {
            await apiRequest('POST', '/api/scanner/from_request', {log_id: log.id});
            activateTab('autoscanner');
        } catch (error) {
            setHistoryStatus(error.message);
        }
    });
    el.querySelector('.history-row-menu').addEventListener('click', event => {
        event.stopPropagation();
        const rect = event.currentTarget.getBoundingClientRect();
        showContextMenu(rect.left, rect.bottom, log);
    });
    el.addEventListener('contextmenu', (event) => {
        event.preventDefault();
        showContextMenu(event.clientX, event.clientY, log);
    });
    return el;
}

let historyDetailRequest = 0;
let historyDetailView = 'request';
let historyMessages = {};

function closeHistoryDetail() {
    historyDetailRequest++;
    state.selectedLogId = null;
    state.currentLog = null;
    historyMessages = {};
    dom.requestDetail.style.display = 'none';
    dom.requestList.querySelector('.request-item--active')?.classList.remove('request-item--active');
}

function setHistoryDetailView(view) {
    historyDetailView = view;
    for (const tab of $$('.detail-tab[data-detail]')) {
        tab.classList.toggle('detail-tab--active', tab.dataset.detail === view);
        tab.setAttribute('aria-pressed', String(tab.dataset.detail === view));
    }
    dom.detailRequest.style.display = view === 'request' ? 'block' : 'none';
    dom.detailResponse.style.display = view === 'response' ? 'block' : 'none';
    $('#history-inspector').hidden = view !== 'inspect';
    $('#btn-history-copy').disabled = !historyMessages[view];
    $('#btn-history-copy').hidden = view === 'inspect';
    $('#btn-history-wrap').hidden = view === 'inspect';
}

function historyHeaderEntries(value) {
    try {
        const headers = typeof value === 'string' ? JSON.parse(value) : value;
        return Object.entries(headers || {});
    } catch {
        return [];
    }
}

function renderHistoryInspector(log) {
    const host = $('#history-inspector-fields');
    host.replaceChildren();
    const requestHeaders = historyHeaderEntries(log.request_headers);
    let query = [];
    try { query = Array.from(new URL(log.url).searchParams); } catch { }
    const isForm = requestHeaders.some(([name, value]) =>
        name.toLowerCase() === 'content-type' && String(value).toLowerCase().includes('application/x-www-form-urlencoded'));
    const fields = [
        ['Connection', [
            ['URL', log.url],
            ['Status', log.status_code ?? 'No response recorded'],
            ['Captured', log.timestamp ? new Date(log.timestamp * 1000).toLocaleString() : '—'],
            ['Duration', log.duration_ms == null ? '—' : Math.round(log.duration_ms) + ' ms'],
            ['Response size', log.content_length == null ? '—' : formatBytes(log.content_length)],
        ]],
        ['Query parameters', query],
        ['Form fields', isForm ? Array.from(new URLSearchParams(log.request_body || '')) : []],
        ['Request headers', requestHeaders],
        ['Response headers', historyHeaderEntries(log.response_headers)],
    ];
    for (const [title, entries] of fields) {
        if (!entries.length) continue;
        const group = document.createElement('details');
        const summary = document.createElement('summary');
        summary.textContent = `${title} (${entries.length})`;
        group.append(summary);
        group.open = title === 'Connection' || title === 'Query parameters';
        const list = document.createElement('dl');
        for (const [name, value] of entries.slice(0, 200)) {
            const term = document.createElement('dt');
            const definition = document.createElement('dd');
            term.textContent = name;
            definition.textContent = value;
            list.append(term, definition);
        }
        group.append(list);
        if (entries.length > 200) {
            const note = document.createElement('p');
            note.textContent = 'Showing the first 200 fields. The message view contains the captured text.';
            group.append(note);
        }
        host.append(group);
    }
    $('#history-note').value = log.comment || '';
    $('#history-highlight').value = log.highlight || '';
}

async function showRequestDetail(logId) {
    const request = ++historyDetailRequest;
    const session = state.sessionId;
    state.selectedLogId = logId;
    state.currentLog = null;
    historyMessages = {};
    dom.requestList.querySelector('.request-item--active')?.classList.remove('request-item--active');
    dom.requestList.querySelector(`[data-id="${Number(logId)}"]`)?.classList.add('request-item--active');
    dom.requestDetail.style.display = 'flex';
    dom.detailRequest.replaceChildren();
    dom.detailResponse.replaceChildren();
    $('#history-inspector-fields').replaceChildren();
    $('#jwt-chip-host').replaceChildren();
    $('#history-detail-title').textContent = 'Exchange';
    $('#history-detail-status').textContent = 'Loading exchange…';
    $('#history-note-form').hidden = true;
    setHistoryDetailView(historyDetailView);
    try {
        const log = await apiRequest('GET', `/api/logs/http/${logId}`);
        if (historyDetailRequest !== request || state.sessionId !== session) return;
        if (log.session_id !== session) throw new Error('This request belongs to a different session.');
        state.currentLog = log;
        historyMessages = {
            request: buildRawRequest(log.method, log.url, Object.fromEntries(historyHeaderEntries(log.request_headers)), log.request_body),
            response: log.status_code ? buildRawResponse(log.status_code, Object.fromEntries(historyHeaderEntries(log.response_headers)), log.response_body_preview) : '',
        };
        for (const [kind, output] of [['request', dom.detailRequest], ['response', dom.detailResponse]]) {
            const message = historyMessages[kind];
            if (message && message.length <= 65000) output.innerHTML = highlightHttp(message);
            else output.textContent = message || 'No response recorded.';
            output.scrollTop = output.scrollLeft = 0;
        }
        $('#history-detail-title').textContent = `${log.method} · #${log.id}`;
        $('#history-detail-status').textContent = '';
        $('#history-note-form').hidden = false;
        renderHistoryInspector(log);
        setHistoryDetailView(historyDetailView);
        renderJwtChipsForLog(log);
    } catch (e) {
        if (historyDetailRequest === request) $('#history-detail-status').textContent = e.message;
    }
}

for (const tab of $$('.detail-tab[data-detail]')) {
    tab.addEventListener('click', () => setHistoryDetailView(tab.dataset.detail));
}

$('#btn-close-detail').addEventListener('click', closeHistoryDetail);
$('#btn-history-wrap').addEventListener('click', (e) => {
    const wrap = e.currentTarget.getAttribute('aria-pressed') !== 'true';
    e.currentTarget.setAttribute('aria-pressed', String(wrap));
    $('#detail-content').classList.toggle('history-wrap', wrap);
});
$('#btn-history-copy').addEventListener('click', async () => {
    try {
        await navigator.clipboard.writeText(historyMessages[historyDetailView] || '');
        $('#history-detail-status').textContent = 'Message copied.';
    } catch (e) {
        $('#history-detail-status').textContent = e.message;
    }
});
$('#history-note-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const log = state.currentLog;
    if (!log) return;
    const button = e.submitter;
    const meta = {comment: $('#history-note').value, highlight: $('#history-highlight').value};
    button.disabled = true;
    try {
        await apiRequest('POST', `/api/logs/http/${log.id}/meta`, meta);
        if (state.currentLog === log) {
            Object.assign(log, meta);
            $('#history-detail-status').textContent = 'Note saved.';
            loadHttpHistory({keepScroll: true});
        }
    } catch (error) {
        if (state.currentLog === log) $('#history-detail-status').textContent = error.message;
    } finally {
        button.disabled = false;
    }
});

const JWT_REGEX = /\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*\b/g;

function findJwtsInLog(log) {
    const hay = [
        log.request_headers || '',
        log.request_body || '',
        log.response_headers || '',
        log.response_body_preview || '',
    ].join('\n');
    const out = new Set();
    JWT_REGEX.lastIndex = 0;
    let m;
    while (out.size < 12 && (m = JWT_REGEX.exec(hay))) out.add(m[0]);
    return Array.from(out);
}

function renderJwtChipsForLog(log) {
    const host = $('#jwt-chip-host');
    host.replaceChildren();
    const tokens = findJwtsInLog(log);
    if (tokens.length === 0) return;
    for (const t of tokens) {
        const chip = document.createElement('button');
        chip.className = 'btn btn--ghost btn--xs';
        chip.textContent = `JWT (${t.slice(0, 12)}…)`;
        chip.title = 'Click to decode';
        chip.addEventListener('click', async () => {
            try {
                const decoded = await apiRequest('POST', '/api/jwt/decode', { token: t });
                const txt = JSON.stringify(decoded, null, 2);
                alert(txt.slice(0, 5000));
            } catch (e) {
                alert('JWT decode failed: ' + e.message);
            }
        });
        host.appendChild(chip);
    }
}

// ── Global keyboard shortcuts ────────────────────────────────────
document.addEventListener('keydown', (e) => {
    // Ignore when typing in input/textarea (unless Ctrl/Cmd combo)
    const tag = (e.target?.tagName || '').toLowerCase();
    const typing = (tag === 'input' || tag === 'textarea' || e.target?.isContentEditable);
    const meta = e.ctrlKey || e.metaKey;

    if (meta && e.key.toLowerCase() === 'r' && state.currentLog) {
        e.preventDefault();
        sendToRepeater(state.currentLog);
        return;
    }
    if (meta && e.key.toLowerCase() === 'i' && state.currentLog) {
        e.preventDefault();
        sendToIntruder(state.currentLog);
        return;
    }
    if (meta && e.key.toLowerCase() === 'f') {
        const search = dom.historySearch;
        if (search && state.sessionId) { e.preventDefault(); activateTab('requests'); search.focus(); }
        return;
    }
    if (typing || state.activeTab !== 'requests' || !$('#sitemap-panel').hidden) return;
    if (e.key === 'j' || e.key === 'k') {
        const items = Array.from(dom.requestList?.querySelectorAll('.request-item') || []).filter(x => x.style.display !== 'none');
        if (!items.length) return;
        let idx = items.findIndex(x => x.classList.contains('request-item--active'));
        if (idx < 0) idx = 0;
        else idx = e.key === 'j' ? Math.min(items.length - 1, idx + 1) : Math.max(0, idx - 1);
        items[idx].querySelector('.history-row-main').click();
        items[idx].scrollIntoView({ block: 'nearest' });
    }
});

$('#btn-send-to-repeater').addEventListener('click', () => {
    if (!state.currentLog) return;
    sendToRepeater(state.currentLog);
});

$('#btn-send-to-intruder').addEventListener('click', () => {
    if (!state.currentLog) return;
    sendToIntruder(state.currentLog);
});

function closeSiteMap() {
    $('#sitemap-panel').hidden = true;
    $('#sitemap-panel').replaceChildren();
    $('#btn-sitemap').setAttribute('aria-pressed', 'false');
    dom.requestList.hidden = false;
    $('.history-columns').hidden = false;
    $('.history-pagination').hidden = false;
}

$('#btn-sitemap').addEventListener('click', async (e) => {
    const panel = $('#sitemap-panel');
    const button = e.currentTarget;
    if (!panel.hidden) {
        closeSiteMap();
        return;
    }
    const session = state.sessionId;
    if (!session) return;
    button.disabled = true;
    try {
        const data = await apiRequest('GET', `/api/sitemap?session_id=${encodeURIComponent(session)}`);
        if (state.sessionId !== session) return;
        panel.replaceChildren();
        const description = document.createElement('p');
        description.className = 'history-map-description';
        description.textContent = data.hosts.length
            ? `${data.total_hosts} ${data.total_hosts === 1 ? 'host' : 'hosts'} in recent traffic. Select a path to view its requests.`
            : 'No traffic captured for this session.';
        panel.append(description);
        for (const host of data.hosts.slice(0, 200)) {
            const group = document.createElement('details');
            const title = document.createElement('summary');
            title.textContent = `${host.host || '(Unknown host)'} · ${host.count} requests`;
            group.append(title);
            group.addEventListener('toggle', () => {
                if (!group.open || group.children.length > 1) return;
                const entries = document.createElement('div');
                let shown = 0;
                const more = document.createElement('button');
                more.className = 'btn btn--ghost btn--sm';
                more.textContent = 'Show more paths';
                const appendPaths = () => {
                    for (const endpoint of host.endpoints.slice(shown, shown + 100)) {
                        const row = document.createElement('button');
                        row.className = 'history-map-path';
                        row.textContent = `${endpoint.path} · ${endpoint.count}`;
                        row.addEventListener('click', () => {
                            historyEndpoint = {host: host.host, path: endpoint.path};
                            dom.historyFilterHost.value = host.host;
                            closeSiteMap();
                            refreshHistoryFilters();
                        });
                        entries.insertBefore(row, more);
                    }
                    shown += 100;
                    more.hidden = shown >= host.endpoints.length;
                };
                entries.append(more);
                more.addEventListener('click', appendPaths);
                appendPaths();
                group.append(entries);
            });
            panel.append(group);
        }
        if (data.hosts.length > 200) description.textContent += ' Showing the first 200 hosts.';
        dom.requestList.hidden = true;
        $('.history-columns').hidden = true;
        $('.history-pagination').hidden = true;
        panel.hidden = false;
        button.setAttribute('aria-pressed', 'true');
    } catch (error) {
        setHistoryStatus(error.message);
    } finally {
        button.disabled = false;
    }
});

// HAR export
$('#btn-export-har').addEventListener('click', async (event) => {
    if (!state.sessionId) return;
    const button = event.currentTarget;
    const filename = `${state.sessionName || 'greytab'}-${new Date().toISOString().slice(0, 10)}.har`;
    button.disabled = true;
    button.textContent = 'Exporting…';
    try {
        const query = new URLSearchParams({session_id: state.sessionId});
        const response = await fetch(`${API_BASE}/api/export/traffic.har?${query}`);
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        const url = URL.createObjectURL(await response.blob());
        const link = document.createElement('a');
        link.href = url;
        link.download = filename;
        link.click();
        setTimeout(() => URL.revokeObjectURL(url), 30000);
    } catch (error) {
        alert('HAR export failed: ' + error.message);
    } finally {
        button.disabled = false;
        button.textContent = 'HAR';
    }
});

// Findings report (HTML)
document.getElementById('btn-export-findings')?.addEventListener('click', async () => {
    if (!state.sessionId) { alert('No active session.'); return; }
    try {
        const res = await fetch(`http://127.0.0.1:8443/api/export/findings.html?session_id=${state.sessionId}`);
        if (!res.ok) throw new Error(`Report export failed: HTTP ${res.status}`);
        const html = await res.text();
        const blob = new Blob([html], { type: 'text/html' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `${state.sessionName || 'greytab'}-report.html`;
        a.click();
        URL.revokeObjectURL(url);
    } catch (e) { alert('Report export failed: ' + e.message); }
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

