// ══════════════════════════════════════════════════════════════════
// Raw Message Helpers
// ══════════════════════════════════════════════════════════════════

function parseRawRequest(raw) {
    const text = String(raw || '');
    const split = text.match(/\r?\n\r?\n/);
    const idx = split ? split.index : -1;
    const sepLen = split ? split[0].length : 0;
    const headerBlock = idx >= 0 ? text.substring(0, idx) : text;
    const body = idx >= 0 ? text.substring(idx + sepLen) : '';

    const lines = headerBlock.split(/\r?\n/);
    const requestLine = lines[0] || '';

    // Parse request line: METHOD URL [HTTP/x.x]
    const rlParts = requestLine.trim().split(/\s+/);
    const method = rlParts[0] || 'GET';
    const url = rlParts[1] || '';

    // Parse headers
    const headers = {};
    for (let i = 1; i < lines.length; i++) {
        const line = lines[i] || '';
        const colonIdx = line.indexOf(':');
        if (colonIdx > 0) {
            const key = line.substring(0, colonIdx).trim();
            const value = line.substring(colonIdx + 1).trim();
            if (key) headers[key] = value;
        }
    }

    return { method, url, headers, body };
}

function buildRawRequest(method, url, headers, body) {
    let path = url;
    let host = '';
    try {
        const u = new URL(url);
        path = u.pathname + u.search;
        host = u.host;
    } catch { }

    let raw = `${method} ${path} HTTP/1.1\n`;
    let hasHost = false;
    let headersContent = '';

    if (headers) {
        const h = typeof headers === 'string' ? JSON.parse(headers) : headers;
        for (const [k, v] of Object.entries(h)) {
            if (k.toLowerCase() === 'host') hasHost = true;
            headersContent += `${k}: ${v}\n`;
        }
    }

    if (!hasHost && host) {
        raw += `Host: ${host}\n`;
    }
    raw += headersContent;

    if (body) {
        if (!raw.endsWith('\n\n')) raw += '\n';
        raw += body;
    } else {
        if (!raw.endsWith('\n\n')) raw += '\n';
    }
    return raw;
}

function buildRawResponse(statusCode, headers, body) {
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

function normalizeParsedRequestUrl(parsed, fallbackTarget = '') {
    const rawUrl = String(parsed?.url || '').trim();
    if (!rawUrl) return '';
    if (/^https?:\/\//i.test(rawUrl)) return rawUrl;

    let host = String(parsed?.headers?.Host || parsed?.headers?.host || '').trim();
    let hostPathHint = '';
    if (/^https?:\/\//i.test(host)) {
        try {
            const hu = new URL(host);
            host = hu.host;
            if (hu.pathname && hu.pathname !== '/') hostPathHint = hu.pathname;
        } catch {
            host = host.replace(/^https?:\/\//i, '');
        }
    }
    if (!host && fallbackTarget) {
        try {
            const fu = new URL(fallbackTarget);
            host = fu.host;
            if (fu.pathname && fu.pathname !== '/') hostPathHint = fu.pathname;
        } catch {
            host = '';
        }
    }
    if (!host) return rawUrl;

    host = host.replace(/^https?:\/\//i, '').split('/')[0].trim();

    let scheme = 'https';
    if (fallbackTarget) {
        try {
            scheme = new URL(fallbackTarget).protocol.replace(':', '') || 'https';
        } catch {
            scheme = 'https';
        }
    }

    let path = rawUrl.startsWith('/') ? rawUrl : `/${rawUrl}`;
    if ((path === '/' || path.startsWith('/?')) && hostPathHint) {
        path = hostPathHint + (path.length > 1 ? path.slice(1) : '');
    }
    return `${scheme}://${host}${path}`;
}

// ══════════════════════════════════════════════════════════════════
// Repeater Logic — Raw
// ══════════════════════════════════════════════════════════════════

const DEFAULT_REPEATER_RAW = 'GET / HTTP/1.1\nHost: example.com\nUser-Agent: GreyTab/1.0\n\n';

function buildRepeaterTabTitle(raw, fallback = '') {
    return fallback || `Tab ${state.repeater.tabCounter}`;
}

function createRepeaterTab(partial = {}) {
    const id = partial.id || `rep_${Date.now()}_${Math.random().toString(36).slice(2, 7)}`;
    const raw = partial.raw_request || DEFAULT_REPEATER_RAW;
    const tabNumber = state.repeater.tabCounter;
    const tab = {
        id,
        title: partial.title || `Tab ${tabNumber}`,
        manual_title: Boolean(partial.manual_title),
        raw_request: raw,
        follow_redirect: Boolean(partial.follow_redirect),
        response_raw: partial.response_raw || '',
        response_render: partial.response_render || '',
        status_text: partial.status_text || '---',
        status_class: partial.status_class || 'status-badge',
        time_text: partial.time_text || '0ms',
        created_at: partial.created_at || Date.now(),
    };
    state.repeater.tabs.push(tab);
    state.repeater.tabCounter += 1;
    return tab;
}

function getActiveRepeaterTab() {
    return state.repeater.tabs.find(t => t.id === state.repeater.activeTabId) || null;
}

function persistActiveRepeaterEditor() {
    const tab = getActiveRepeaterTab();
    if (!tab) return;
    tab.raw_request = dom.repeaterRawRequest?.value || '';
    tab.follow_redirect = Boolean(dom.repeaterFollowRedirect?.checked);
}

function applyRepeaterTabToEditor(tab) {
    if (!tab) return;
    if (dom.repeaterRawRequest) dom.repeaterRawRequest.value = tab.raw_request || '';
    if (dom.repeaterFollowRedirect) dom.repeaterFollowRedirect.checked = Boolean(tab.follow_redirect);
    if (dom.repeaterStatus) {
        dom.repeaterStatus.className = tab.status_class || 'status-badge';
        dom.repeaterStatus.textContent = tab.status_text || '---';
    }
    if (dom.repeaterTime) dom.repeaterTime.textContent = tab.time_text || '0ms';
    if (dom.repeaterResRaw) {
        dom.repeaterResRaw.innerHTML = tab.response_raw ? highlightHttp(tab.response_raw) : '';
    }
    if (dom.repeaterResRender) dom.repeaterResRender.srcdoc = tab.response_render || '';
    renderRepeaterRequestPreview();
}

function renderRepeaterTabbar() {
    if (!dom.repeaterTabbar) return;
    dom.repeaterTabbar.innerHTML = '';
    for (const tab of state.repeater.tabs) {
        const el = document.createElement('button');
        el.className = `repeater-tab${tab.id === state.repeater.activeTabId ? ' repeater-tab--active' : ''}`;
        el.textContent = tab.title || 'Request';
        el.title = tab.title || 'Request';
        el.addEventListener('click', () => activateRepeaterTab(tab.id));
        el.addEventListener('dblclick', () => {
            const next = prompt('Rename repeater tab:', tab.title || '');
            if (!next) return;
            tab.title = next.trim().slice(0, 80) || tab.title;
            tab.manual_title = true;
            renderRepeaterTabbar();
        });
        el.addEventListener('contextmenu', (e) => {
            e.preventDefault();
            showRepeaterTabContextMenu(e.clientX, e.clientY, tab.id);
        });
        dom.repeaterTabbar.appendChild(el);
    }
}

let repeaterMenuTabId = null;

function hideRepeaterTabContextMenu() {
    if (dom.repeaterTabMenu) dom.repeaterTabMenu.style.display = 'none';
    repeaterMenuTabId = null;
}

function showRepeaterTabContextMenu(x, y, tabId) {
    if (!dom.repeaterTabMenu) return;
    repeaterMenuTabId = tabId;
    dom.repeaterTabMenu.innerHTML = `
      <div class="ctx-menu__item" data-action="rename-tab">Rename</div>
      <div class="ctx-menu__item" data-action="duplicate-tab">Duplicate</div>
      <div class="ctx-menu__item" data-action="close-tab">Close</div>
      <div class="ctx-menu__item" data-action="close-others">Close Others</div>
      <div class="ctx-menu__separator"></div>
      <div class="ctx-menu__item" data-action="reset-tab">Reset</div>
    `;
    dom.repeaterTabMenu.style.display = 'block';

    const rect = dom.repeaterTabMenu.getBoundingClientRect();
    const left = Math.min(x, window.innerWidth - rect.width - 8);
    const top = Math.min(y, window.innerHeight - rect.height - 8);
    dom.repeaterTabMenu.style.left = `${Math.max(8, left)}px`;
    dom.repeaterTabMenu.style.top = `${Math.max(8, top)}px`;

    dom.repeaterTabMenu.querySelectorAll('.ctx-menu__item').forEach((item) => {
        item.addEventListener('click', () => {
            handleRepeaterTabContextAction(item.dataset.action);
        }, { once: true });
    });
}

function handleRepeaterTabContextAction(action) {
    const tab = state.repeater.tabs.find(t => t.id === repeaterMenuTabId);
    if (!tab) {
        hideRepeaterTabContextMenu();
        return;
    }

    if (action === 'rename-tab') {
        const next = prompt('Rename repeater tab:', tab.title || '');
        if (next) {
            tab.title = next.trim().slice(0, 80) || tab.title;
            tab.manual_title = true;
        }
    } else if (action === 'duplicate-tab') {
        persistActiveRepeaterEditor();
        const cloned = createRepeaterTab({
            title: `${tab.title} copy`,
            manual_title: true,
            raw_request: tab.raw_request,
            follow_redirect: tab.follow_redirect,
            response_raw: tab.response_raw,
            response_render: tab.response_render,
            status_text: tab.status_text,
            status_class: tab.status_class,
            time_text: tab.time_text,
        });
        activateRepeaterTab(cloned.id, false);
    } else if (action === 'close-tab') {
        activateRepeaterTab(tab.id);
        closeActiveRepeaterTab();
    } else if (action === 'close-others') {
        state.repeater.tabs = [tab];
        state.repeater.activeTabId = tab.id;
        applyRepeaterTabToEditor(tab);
        renderRepeaterTabbar();
    } else if (action === 'reset-tab') {
        tab.raw_request = DEFAULT_REPEATER_RAW;
        tab.response_raw = '';
        tab.response_render = '';
        tab.status_text = '---';
        tab.status_class = 'status-badge';
        tab.time_text = '0ms';
        if (state.repeater.activeTabId === tab.id) applyRepeaterTabToEditor(tab);
    }

    hideRepeaterTabContextMenu();
    renderRepeaterTabbar();
}

function activateRepeaterTab(tabId, persistCurrent = true) {
    if (persistCurrent) persistActiveRepeaterEditor();
    state.repeater.activeTabId = tabId;
    const tab = getActiveRepeaterTab();
    if (tab) applyRepeaterTabToEditor(tab);
    renderRepeaterTabbar();
}

function closeActiveRepeaterTab() {
    if (state.repeater.tabs.length <= 1) {
        const tab = getActiveRepeaterTab();
        if (!tab) return;
        tab.raw_request = DEFAULT_REPEATER_RAW;
        tab.response_raw = '';
        tab.response_render = '';
        tab.status_text = '---';
        tab.status_class = 'status-badge';
        tab.time_text = '0ms';
        applyRepeaterTabToEditor(tab);
        renderRepeaterTabbar();
        return;
    }

    const idx = state.repeater.tabs.findIndex(t => t.id === state.repeater.activeTabId);
    if (idx === -1) return;
    state.repeater.tabs.splice(idx, 1);
    const nextIdx = Math.max(0, idx - 1);
    state.repeater.activeTabId = state.repeater.tabs[nextIdx]?.id || null;
    const tab = getActiveRepeaterTab();
    if (tab) applyRepeaterTabToEditor(tab);
    renderRepeaterTabbar();
}

function initRepeaterWorkspace() {
    if (state.repeater.tabs.length === 0) {
        const first = createRepeaterTab({ title: 'Tab 1', raw_request: DEFAULT_REPEATER_RAW });
        state.repeater.activeTabId = first.id;
    }
    activateRepeaterTab(state.repeater.activeTabId, false);

    dom.repeaterRawRequest?.addEventListener('input', () => {
        persistActiveRepeaterEditor();
        renderRepeaterTabbar();
        renderRepeaterRequestPreview();
        scheduleWorkspaceSave();
    });
    dom.repeaterFollowRedirect?.addEventListener('change', () => {
        persistActiveRepeaterEditor();
        scheduleWorkspaceSave();
    });

    dom.btnRepeaterNewTab?.addEventListener('click', () => {
        persistActiveRepeaterEditor();
        const tab = createRepeaterTab({});
        activateRepeaterTab(tab.id, false);
    });

    dom.btnRepeaterCloneTab?.addEventListener('click', () => {
        const current = getActiveRepeaterTab();
        if (!current) return;
        persistActiveRepeaterEditor();
        const cloned = createRepeaterTab({
            title: `${current.title} copy`,
            manual_title: true,
            raw_request: current.raw_request,
            follow_redirect: current.follow_redirect,
            response_raw: current.response_raw,
            response_render: current.response_render,
            status_text: current.status_text,
            status_class: current.status_class,
            time_text: current.time_text,
        });
        activateRepeaterTab(cloned.id, false);
    });

    dom.btnRepeaterCloseTab?.addEventListener('click', () => {
        persistActiveRepeaterEditor();
        closeActiveRepeaterTab();
    });
}

dom.btnRepeaterSend?.addEventListener('click', async () => {
    const tab = getActiveRepeaterTab();
    if (!tab) return;

    persistActiveRepeaterEditor();
    tab.status_class = 'status-badge';
    tab.status_text = 'Sending...';
    tab.time_text = '';
    applyRepeaterTabToEditor(tab);

    const parsed = parseRawRequest(tab.raw_request);
    const normalizedUrl = normalizeParsedRequestUrl(parsed, dom.scannerTarget?.value || dom.intruderTarget?.value || '');
    const followRedirects = Boolean(tab.follow_redirect);
    if (!normalizedUrl) {
        tab.status_class = 'status-badge status-badge--error';
        tab.status_text = 'Error';
        tab.time_text = '0ms';
        tab.response_raw = 'Invalid request line: missing URL.';
        applyRepeaterTabToEditor(tab);
        return;
    }

    try {
        const res = await apiRequest('POST', '/api/repeater/send', {
            method: parsed.method,
            url: normalizedUrl,
            headers: parsed.headers,
            body: parsed.body || null,
            follow_redirects: followRedirects,
        });

        const sc = res.status_code;
        const statusClass = sc >= 500 ? 'status-badge--error'
            : sc >= 400 ? 'status-badge--warning'
                : sc >= 300 ? 'status-badge--info' : 'status-badge--success';

        tab.status_text = `${res.status_code}`;
        tab.status_class = `status-badge ${statusClass}`;
        tab.time_text = `${Math.round(res.duration_ms)}ms`;
        tab.response_raw = buildRawResponse(res.status_code, res.headers, res.body);
        tab.response_render = res.body || '';
        applyRepeaterTabToEditor(tab);
        renderRepeaterTabbar();
    } catch (err) {
        console.error('Repeater error:', err);
        tab.status_text = 'Error';
        tab.status_class = 'status-badge status-badge--error';
        tab.time_text = '0ms';
        tab.response_raw = String(err.message || err);
        tab.response_render = '';
        applyRepeaterTabToEditor(tab);
    }
});

function sendToRepeater(request) {
    $$('.tab[data-tab="repeater"]')[0].click();
    persistActiveRepeaterEditor();
    const reqHeaders = request.headers || request.request_headers || {};
    const normalizedUrl = normalizeParsedRequestUrl(
        { url: request.url, headers: reqHeaders },
        dom.intruderTarget?.value || dom.scannerTarget?.value || request.url || ''
    );
    const raw = buildRawRequest(
        request.method,
        normalizedUrl || request.url,
        reqHeaders,
        request.body || request.request_body
    );
    const tab = createRepeaterTab({
        raw_request: raw,
        title: `Tab ${state.repeater.tabCounter}`,
    });
    activateRepeaterTab(tab.id, false);
}
