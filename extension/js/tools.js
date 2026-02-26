// Context Menu
// ══════════════════════════════════════════════════════════════════

let ctxMenuFlowData = null;

function showContextMenu(x, y, flowOrLog) {
    ctxMenuFlowData = flowOrLog;
    const menu = dom.ctxMenu;
    if (!menu) return;

    const hasUrl = flowOrLog.url;
    const hasParams = hasUrl && flowOrLog.url.includes('?');
    const isPost = flowOrLog.method === 'POST';

    let items = `
        <div class="ctx-menu__label">Actions</div>
        <div class="ctx-menu__item" data-action="view-detail">
            <svg viewBox="0 0 24 24"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path><circle cx="12" cy="12" r="3"></circle></svg>
            View Detail
        </div>
        <div class="ctx-menu__item" data-action="send-repeater">
            <svg viewBox="0 0 24 24"><polyline points="17 1 21 5 17 9"></polyline><path d="M3 11V9a4 4 0 0 1 4-4h14"></path><polyline points="7 23 3 19 7 15"></polyline><path d="M21 13v2a4 4 0 0 1-4 4H3"></path></svg>
            Send to Repeater
        </div>
        <div class="ctx-menu__item" data-action="send-intruder">
            <svg viewBox="0 0 24 24"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path></svg>
            Send to Intruder
        </div>
        <div class="ctx-menu__item" data-action="send-decoder">
            <svg viewBox="0 0 24 24"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect><path d="M7 11V7a5 5 0 0 1 10 0v4"></path></svg>
            Send to Decoder
        </div>
        <div class="ctx-menu__separator"></div>
        <div class="ctx-menu__label">Quick Tool Launch</div>
    `;

    // Smart tool suggestions based on request
    if (hasParams || isPost) {
        items += `
            <div class="ctx-menu__item ctx-menu__item--tool" data-action="tool-sqlmap">
                <svg viewBox="0 0 24 24"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"></polygon></svg>
                sqlmap (injection test)
            </div>
            <div class="ctx-menu__item ctx-menu__item--tool" data-action="tool-xsser">
                <svg viewBox="0 0 24 24"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"></polygon></svg>
                xsser (XSS test)
            </div>
        `;
    }

    items += `
        <div class="ctx-menu__item ctx-menu__item--tool" data-action="tool-nuclei">
            <svg viewBox="0 0 24 24"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"></polygon></svg>
            nuclei (vuln scan)
        </div>
        <div class="ctx-menu__item ctx-menu__item--tool" data-action="tool-nikto">
            <svg viewBox="0 0 24 24"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"></polygon></svg>
            nikto (web scan)
        </div>
        <div class="ctx-menu__item ctx-menu__item--tool" data-action="tool-whatweb">
            <svg viewBox="0 0 24 24"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"></polygon></svg>
            whatweb (fingerprint)
        </div>
        <div class="ctx-menu__separator"></div>
        <div class="ctx-menu__label">Export</div>
        <div class="ctx-menu__item" data-action="copy-url">
            <svg viewBox="0 0 24 24"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path></svg>
            Copy URL
        </div>
        <div class="ctx-menu__item" data-action="copy-curl">
            <svg viewBox="0 0 24 24"><polyline points="16 18 22 12 16 6"></polyline><polyline points="8 6 2 12 8 18"></polyline></svg>
            Copy as cURL
        </div>
        <div class="ctx-menu__item" data-action="copy-python">
            <svg viewBox="0 0 24 24"><polyline points="16 18 22 12 16 6"></polyline><polyline points="8 6 2 12 8 18"></polyline></svg>
            Copy as Python
        </div>
        <div class="ctx-menu__item" data-action="copy-fetch">
            <svg viewBox="0 0 24 24"><polyline points="16 18 22 12 16 6"></polyline><polyline points="8 6 2 12 8 18"></polyline></svg>
            Copy as fetch()
        </div>
        <div class="ctx-menu__item" data-action="copy-powershell">
            <svg viewBox="0 0 24 24"><polyline points="16 18 22 12 16 6"></polyline><polyline points="8 6 2 12 8 18"></polyline></svg>
            Copy as PowerShell
        </div>
        <div class="ctx-menu__separator"></div>
        <div class="ctx-menu__item" data-action="delete-log">
            <svg viewBox="0 0 24 24"><polyline points="3 6 5 6 21 6"></polyline><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"></path></svg>
            Delete Request
        </div>
    `;

    menu.innerHTML = items;
    menu.style.display = 'block';

    // Position menu within viewport
    const menuRect = menu.getBoundingClientRect();
    const viewW = window.innerWidth;
    const viewH = window.innerHeight;

    let left = x;
    let top = y;
    if (x + menuRect.width > viewW) left = viewW - menuRect.width - 8;
    if (y + menuRect.height > viewH) top = viewH - menuRect.height - 8;
    if (left < 0) left = 8;
    if (top < 0) top = 8;

    menu.style.left = left + 'px';
    menu.style.top = top + 'px';

    // Attach click handlers
    menu.querySelectorAll('.ctx-menu__item').forEach(item => {
        item.addEventListener('click', () => handleContextAction(item.dataset.action), { once: true });
    });
}

function hideContextMenu() {
    if (dom.ctxMenu) dom.ctxMenu.style.display = 'none';
}

// Close context menu on any click or Escape
document.addEventListener('click', () => {
    hideContextMenu();
    hideRepeaterTabContextMenu();
});
document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') {
        hideContextMenu();
        hideRepeaterTabContextMenu();
    }
});

async function handleContextAction(action) {
    hideContextMenu();
    if (!ctxMenuFlowData) return;

    const flow = ctxMenuFlowData;
    const flowId = flow.id;

    switch (action) {
        case 'view-detail':
            $$('.tab[data-tab="requests"]')[0].click();
            showRequestDetail(flowId);
            break;

        case 'send-repeater': {
            // Need full detail for repeater
            try {
                const log = await apiRequest('GET', `/api/logs/http/${flowId}`);
                sendToRepeater(log);
            } catch {
                // Fallback: use partial flow data
                sendToRepeater(flow);
            }
            break;
        }

        case 'send-intruder': {
            try {
                const log = await apiRequest('GET', `/api/logs/http/${flowId}`);
                sendToIntruder(log);
            } catch {
                sendToIntruder(flow);
            }
            break;
        }

        case 'send-decoder': {
            try {
                const log = await apiRequest('GET', `/api/logs/http/${flowId}`);
                const raw = buildRawRequest(log) || log.url || '';
                sendToDecoder(raw);
            } catch {
                sendToDecoder(flow.url || '');
            }
            break;
        }

        case 'tool-sqlmap':
            await launchToolForFlow(flow, 'sqlmap');
            break;
        case 'tool-xsser':
            await launchToolForFlow(flow, 'xsser');
            break;
        case 'tool-nuclei':
            await launchToolForFlow(flow, 'nuclei');
            break;
        case 'tool-nikto':
            await launchToolForFlow(flow, 'nikto');
            break;
        case 'tool-whatweb':
            await launchToolForFlow(flow, 'whatweb');
            break;

        case 'copy-url':
            navigator.clipboard.writeText(flow.url || '').catch(() => { });
            break;

        case 'copy-curl': {
            try {
                const log = await apiRequest('GET', `/api/logs/http/${flowId}`);
                const curl = buildCurlCommand(log);
                navigator.clipboard.writeText(curl).catch(() => { });
            } catch {
                navigator.clipboard.writeText(`curl -v '${flow.url}'`).catch(() => { });
            }
            break;
        }

        case 'copy-python': {
            try {
                const log = await apiRequest('GET', `/api/logs/http/${flowId}`);
                navigator.clipboard.writeText(buildPythonRequests(log)).catch(() => { });
            } catch {
                navigator.clipboard.writeText(`import requests\nresponse = requests.get("${flow.url}")\nprint(response.text)`).catch(() => { });
            }
            break;
        }

        case 'copy-fetch': {
            try {
                const log = await apiRequest('GET', `/api/logs/http/${flowId}`);
                navigator.clipboard.writeText(buildFetchCode(log)).catch(() => { });
            } catch {
                navigator.clipboard.writeText(`fetch("${flow.url}").then(r => r.text()).then(console.log)`).catch(() => { });
            }
            break;
        }

        case 'copy-powershell': {
            try {
                const log = await apiRequest('GET', `/api/logs/http/${flowId}`);
                navigator.clipboard.writeText(buildPowerShell(log)).catch(() => { });
            } catch {
                navigator.clipboard.writeText(`Invoke-WebRequest -Uri "${flow.url}"`).catch(() => { });
            }
            break;
        }

        case 'delete-log': {
            const id = Number(flowId || 0);
            if (!id) break;
            try {
                await apiRequest('DELETE', `/api/logs/http/${id}`);
                state.trafficItems = state.trafficItems.filter((x) => Number(x.id || 0) !== id);
                const hEl = dom.requestList?.querySelector(`.request-item[data-id="${id}"]`);
                if (hEl) hEl.remove();
                if (state.currentLog && Number(state.currentLog.id || 0) === id) {
                    state.currentLog = null;
                    state.selectedLogId = null;
                    if (dom.requestDetail) dom.requestDetail.style.display = 'none';
                }
            } catch (e) {
                console.error('Failed to delete log:', e);
            }
            break;
        }
    }
}

function buildCurlCommand(log) {
    let cmd = `curl -v`;
    if (log.method && log.method !== 'GET') {
        cmd += ` -X ${log.method}`;
    }
    // Add headers
    let headers = log.request_headers;
    if (typeof headers === 'string') {
        try { headers = JSON.parse(headers); } catch { headers = {}; }
    }
    if (headers) {
        for (const [k, v] of Object.entries(headers)) {
            if (!['host', 'content-length'].includes(k.toLowerCase())) {
                cmd += ` -H '${k}: ${v}'`;
            }
        }
    }
    const body = log.request_body || log.body;
    if (body) {
        cmd += ` -d '${body.replace(/'/g, "'\\''")}'`;
    }
    cmd += ` '${log.url}'`;
    return cmd;
}

// ── Copy As… format builders ──

function buildPythonRequests(log) {
    let headers = log.request_headers;
    if (typeof headers === 'string') { try { headers = JSON.parse(headers); } catch { headers = {}; } }
    const method = (log.method || 'GET').toLowerCase();
    const body = log.request_body || log.body || '';
    let code = `import requests\n\n`;
    code += `url = "${log.url}"\n`;
    if (headers && Object.keys(headers).length) {
        code += `headers = {\n`;
        for (const [k, v] of Object.entries(headers)) {
            if (!['host', 'content-length'].includes(k.toLowerCase())) {
                code += `    "${k}": "${v}",\n`;
            }
        }
        code += `}\n`;
    } else {
        code += `headers = {}\n`;
    }
    if (body) {
        code += `data = """${body}"""\n\n`;
        code += `response = requests.${method}(url, headers=headers, data=data)\n`;
    } else {
        code += `\nresponse = requests.${method}(url, headers=headers)\n`;
    }
    code += `print(response.status_code)\nprint(response.text)\n`;
    return code;
}

function buildFetchCode(log) {
    let headers = log.request_headers;
    if (typeof headers === 'string') { try { headers = JSON.parse(headers); } catch { headers = {}; } }
    const body = log.request_body || log.body || '';
    let code = `fetch("${log.url}", {\n`;
    code += `  method: "${log.method || 'GET'}",\n`;
    if (headers && Object.keys(headers).length) {
        code += `  headers: {\n`;
        for (const [k, v] of Object.entries(headers)) {
            if (!['host', 'content-length'].includes(k.toLowerCase())) {
                code += `    "${k}": "${v}",\n`;
            }
        }
        code += `  },\n`;
    }
    if (body) {
        code += `  body: ${JSON.stringify(body)},\n`;
    }
    code += `})\n.then(r => r.text())\n.then(console.log)\n.catch(console.error);\n`;
    return code;
}

function buildPowerShell(log) {
    let headers = log.request_headers;
    if (typeof headers === 'string') { try { headers = JSON.parse(headers); } catch { headers = {}; } }
    const body = log.request_body || log.body || '';
    let code = `$headers = @{\n`;
    if (headers) {
        for (const [k, v] of Object.entries(headers)) {
            if (!['host', 'content-length'].includes(k.toLowerCase())) {
                code += `    "${k}" = "${v}"\n`;
            }
        }
    }
    code += `}\n\n`;
    if (body) {
        code += `$body = @"\n${body}\n"@\n\n`;
        code += `Invoke-WebRequest -Uri "${log.url}" -Method ${log.method || 'GET'} -Headers $headers -Body $body\n`;
    } else {
        code += `Invoke-WebRequest -Uri "${log.url}" -Method ${log.method || 'GET'} -Headers $headers\n`;
    }
    return code;
}

// ══════════════════════════════════════════════════════════════════
// Passive Findings Engine
// ══════════════════════════════════════════════════════════════════

const passiveFindings = [];

const PASSIVE_PATTERNS = [
    // SQL errors
    { name: 'SQL Error', severity: 'high', re: /(?:SQL syntax|mysql_|pg_query|ORA-\d{5}|sqlite3\.|SQLSTATE\[|syntax error.*SQL|Unclosed quotation|quoted string not properly terminated)/i },
    // Stack traces
    { name: 'Stack Trace', severity: 'medium', re: /(?:Traceback \(most recent|at [\w.]+\([\w.]+:\d+\)|Exception in thread|java\.lang\.|System\.NullReferenceException|Fatal error:.*on line)/i },
    // Internal IPs
    { name: 'Internal IP', severity: 'low', re: /(?:(?:10|172\.(?:1[6-9]|2\d|3[01])|192\.168)\.\d{1,3}\.\d{1,3})/g },
    // Exposed tokens/keys
    { name: 'API Key/Token', severity: 'high', re: /(?:(?:api[_-]?key|apikey|secret[_-]?key|access[_-]?token|auth[_-]?token|private[_-]?key)\s*[:=]\s*["']?[A-Za-z0-9_\-]{16,})/i },
    // AWS keys
    { name: 'AWS Key', severity: 'critical', re: /(?:AKIA[0-9A-Z]{16}|aws_secret_access_key)/i },
    // Version disclosure
    { name: 'Version Disclosure', severity: 'info', re: /(?:X-Powered-By|Server|X-AspNet-Version|X-AspNetMvc-Version)\s*:\s*\S+/i },
    // Debug info
    { name: 'Debug Info', severity: 'medium', re: /(?:DEBUG\s*=\s*True|DJANGO_SETTINGS|WP_DEBUG|display_errors\s*=\s*on|var_dump|phpinfo\(\)|console\.log)/i },
    // Directory listing
    { name: 'Directory Listing', severity: 'medium', re: /(?:Index of \/|Parent Directory|<title>Directory listing)/i },
    // Email addresses
    { name: 'Email Exposed', severity: 'low', re: /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g },
    // File paths
    { name: 'Server Path', severity: 'low', re: /(?:\/(?:var|usr|home|etc|tmp|opt)\/[\w\/.-]+|[A-Z]:\\\\(?:Users|Windows|Program)\\\\[\w\\\\.-]+)/g },
    // Open redirect potential
    { name: 'Redirect Parameter', severity: 'medium', re: /[?&](?:redirect|url|next|return|goto|target|rurl|dest|destination|redir|redirect_uri|return_url|continue)=/i },
    // CORS wildcard
    { name: 'CORS Wildcard', severity: 'medium', re: /Access-Control-Allow-Origin\s*:\s*\*/i },
    // Missing security headers (check in scanResponseHeaders)
];

function scanForFindings(flowOrLog, skipBadgeUpdate = false) {
    // Check if passive scanning is enabled
    const toggle = dom.passiveScanEnabled || document.getElementById('passive-scan-enabled');
    if (toggle && !toggle.checked) return [];

    const findings = [];
    const url = flowOrLog.url || '';
    const responseBody = flowOrLog.response_body || '';
    const rawResponse = flowOrLog.response_raw || '';
    const responseHeaders = flowOrLog.response_headers || '';
    const searchText = url + '\n' + rawResponse + '\n' + responseBody + '\n' + responseHeaders;

    for (const pattern of PASSIVE_PATTERNS) {
        if (pattern.re.test(searchText)) {
            pattern.re.lastIndex = 0; // Reset regex
            findings.push({
                name: pattern.name,
                severity: pattern.severity,
                url: url,
                id: flowOrLog.id,
                timestamp: new Date().toISOString(),
            });
        }
    }

    // Check missing security headers
    const headerStr = (typeof responseHeaders === 'string' ? responseHeaders : JSON.stringify(responseHeaders)).toLowerCase();
    const secHeaders = [
        { name: 'Missing CSP', header: 'content-security-policy' },
        { name: 'Missing X-Frame-Options', header: 'x-frame-options' },
        { name: 'Missing X-Content-Type-Options', header: 'x-content-type-options' },
    ];
    // Only check HTML responses
    if (headerStr.includes('text/html')) {
        for (const sh of secHeaders) {
            if (!headerStr.includes(sh.header)) {
                findings.push({
                    name: sh.name,
                    severity: 'info',
                    url: url,
                    id: flowOrLog.id,
                    timestamp: new Date().toISOString(),
                });
            }
        }
    }

    if (findings.length > 0) {
        passiveFindings.push(...findings);
        if (!skipBadgeUpdate) updateFindingsBadge();
    }
    return findings;
}

function updateFindingsBadge() {
    const badge = $('#findings-badge');
    if (!badge) return;
    const count = passiveFindings.length;
    if (count > 0) {
        badge.style.display = 'inline';
        badge.textContent = count > 99 ? '99+' : count;
        // Color by max severity
        const hasCrit = passiveFindings.some(f => f.severity === 'critical');
        const hasHigh = passiveFindings.some(f => f.severity === 'high');
        if (hasCrit) badge.style.background = '#ef4444';
        else if (hasHigh) badge.style.background = '#f97316';
        else badge.style.background = 'var(--accent)';
    } else {
        badge.style.display = 'none';
        if (dom.historyFindingsPanel) dom.historyFindingsPanel.style.display = 'none';
    }
    renderFindingsPanel();
}

function renderFindingsPanel() {
    if (!dom.historyFindingsList) return;
    if (passiveFindings.length === 0) {
        dom.historyFindingsList.innerHTML = `<div class="empty-state"><span class="empty-state__text">No findings detected yet.</span></div>`;
        return;
    }

    // Sort by severity (critical > high > medium > low > info) then by time desc
    const sevScore = { critical: 5, high: 4, medium: 3, low: 2, info: 1 };
    const sorted = [...passiveFindings].sort((a, b) => {
        const sA = sevScore[a.severity] || 0;
        const sB = sevScore[b.severity] || 0;
        if (sA !== sB) return sB - sA;
        return new Date(b.timestamp) - new Date(a.timestamp);
    });

    let html = '';
    for (const f of sorted) {
        let icon = '⚪';
        if (f.severity === 'critical') icon = '🔴';
        else if (f.severity === 'high') icon = '🟠';
        else if (f.severity === 'medium') icon = '🟡';
        else if (f.severity === 'low') icon = '🔵';

        html += `
        <div class="finding-item" data-id="${f.id || ''}">
            <div class="finding-item__title">
                ${icon} <span>${escHtml(f.name)}</span>
            </div>
            <div class="finding-item__url" title="${escHtml(f.url)}">${escHtml(f.url)}</div>
        </div>
        `;
    }

    dom.historyFindingsList.innerHTML = html;

    // Wire clicks to open request detail
    dom.historyFindingsList.querySelectorAll('.finding-item').forEach(item => {
        item.addEventListener('click', () => {
            const id = item.dataset.id;
            if (id) {
                // hide panel
                if (dom.historyFindingsPanel) dom.historyFindingsPanel.style.display = 'none';
                // Find request and click it
                const el = document.querySelector(`.request-item[data-id="${id}"]`);
                if (el) el.click();
                else showRequestDetail(id);
            }
        });
    });
}

async function launchToolForFlow(flow, toolName) {
    // Switch to tools tab and pre-fill
    $$('.tab[data-tab="tools"]')[0].click();
    dom.toolTarget.value = flow.url || '';

    // Load full request details for smarter args
    try {
        const log = await apiRequest('GET', `/api/logs/http/${flow.id}`);
        analyzeForTools(log, toolName);
    } catch {
        analyzeForTools(flow, toolName);
    }
}

// ══════════════════════════════════════════════════════════════════
// Smart Tool Logic
// ══════════════════════════════════════════════════════════════════

function analyzeForTools(request, forceTool = null) {
    const url = request.url || '';
    const method = request.method || 'GET';
    const body = request.request_body || request.body || '';
    const hasParams = url.includes('?');
    const isPost = method === 'POST' || method === 'PUT';
    const contentType = '';

    // Determine best tool
    let toolName = forceTool;
    if (!toolName) {
        if (hasParams || isPost) {
            toolName = 'sqlmap';
        } else {
            toolName = 'gobuster';
        }
    }

    selectTool(toolName);

    // Build smart args based on tool
    let args = '';
    let contextMsg = '';
    let contextDetail = '';

    switch (toolName) {
        case 'sqlmap': {
            args = '--batch --random-agent --level=1 --risk=1';
            if (isPost && body) {
                const safeBody = body.replace(/"/g, '\\"');
                args += ` --data="${safeBody}"`;
                args += ` --method=${method}`;
                contextMsg = 'Injection testing: POST body detected';
                contextDetail = `Method: ${method} | Body params will be tested for SQLi`;
            } else if (hasParams) {
                contextMsg = 'Injection testing: URL parameters detected';
                contextDetail = 'URL parameters will be tested for SQLi';
            } else {
                contextMsg = 'Injection testing configured';
                contextDetail = 'Add -p parameter_name to specify injection points';
            }
            break;
        }

        case 'xsser': {
            args = '--auto';
            if (isPost && body) {
                args = `-p "${body.split('=')[0] || 'input'}" --auto`;
                contextMsg = 'XSS testing: POST body detected';
                contextDetail = `Testing first parameter for reflected/stored XSS`;
            } else if (hasParams) {
                contextMsg = 'XSS testing: URL parameters detected';
                contextDetail = 'URL parameters will be tested for XSS';
            } else {
                contextMsg = 'XSS testing configured';
            }
            break;
        }

        case 'nuclei': {
            args = '-as';
            contextMsg = 'Vulnerability scanning with auto-selected templates';
            contextDetail = 'Nuclei will auto-select relevant templates based on technology detection';
            break;
        }

        case 'nikto': {
            args = '';
            contextMsg = 'Web server vulnerability scanning';
            contextDetail = 'Nikto will check for known vulnerabilities, misconfigurations, and outdated software';
            break;
        }

        case 'whatweb': {
            args = '-v';
            contextMsg = 'Technology fingerprinting';
            contextDetail = 'Identifying web technologies, CMS, frameworks, and server software';
            break;
        }

        case 'gobuster': {
            args = '-t 20';
            contextMsg = 'Directory/path fuzzing configured';
            contextDetail = 'Select a wordlist above, or use -w /path/to/wordlist';
            break;
        }

        case 'ffuf': {
            args = '';
            contextMsg = 'Web fuzzing configured';
            contextDetail = 'FUZZ keyword will be placed in the URL path';
            break;
        }

        case 'wfuzz': {
            args = '--hc 404';
            contextMsg = 'Web fuzzing with 404 filtering';
            contextDetail = 'Select a wordlist above';
            break;
        }

        default: {
            contextMsg = `Tool ${toolName} selected`;
            break;
        }
    }

    dom.toolExtraArgs.value = args;
    showToolContext(contextMsg, contextDetail);
}

function selectTool(name) {
    dom.toolSelect.value = name;
    // Update description
    updateToolDescription();
}

// Store tool definitions for description lookup
let cachedToolDefs = {};

function updateToolDescription() {
    const name = dom.toolSelect.value;
    if (dom.toolDescription) {
        if (name && cachedToolDefs[name]) {
            dom.toolDescription.textContent = cachedToolDefs[name].description || '';
        } else {
            dom.toolDescription.textContent = '';
        }
    }
}

// Listen for tool select changes
dom.toolSelect.addEventListener('change', updateToolDescription);

function showToolContext(msg, detail = '') {
    let ctx = $('#tool-smart-context');
    if (!ctx) return;

    let html = `<h4>${escHtml(msg)}</h4>`;
    if (detail) {
        html += `<div class="smart-detail">${escHtml(detail)}</div>`;
    }
    ctx.innerHTML = html;
    ctx.style.display = 'block';
}

// ══════════════════════════════════════════════════════════════════
// Auto Scanner
// ══════════════════════════════════════════════════════════════════

function getScannerTestCheckboxes() {
    return Array.from(document.querySelectorAll('#tab-autoscanner .scanner-check input[type="checkbox"][value]'));
}

function getScannerFormState() {
    const validTests = new Set(['xss', 'sqli', 'path_traversal', 'lfi', 'open_redirect', 'oast']);
    return {
        target: dom.scannerTarget?.value || '',
        depth: Number(dom.scannerDepth?.value || 3),
        checks: getScannerTestCheckboxes()
            .filter((cb) => cb.checked)
            .map(cb => cb.value)
            .filter(v => validTests.has(v)),
        auth: Boolean($('#scanner-auth')?.checked),
        fuzzDirs: Boolean($('#scanner-fuzz-dirs')?.checked),
        crawlEnabled: Boolean($('#scanner-crawl-enabled')?.checked),
        passiveEnabled: Boolean($('#scanner-passive')?.checked),
        xssHeadlessConfirm: Boolean(dom.scannerXssHeadless?.checked),
        oastBaseUrl: String(dom.scannerOastBase?.value || ''),
    };
}

function applyScannerFormState(payload) {
    if (!payload) return;
    if (dom.scannerTarget && typeof payload.target === 'string') dom.scannerTarget.value = payload.target;
    if (dom.scannerDepth && Number.isFinite(payload.depth)) {
        dom.scannerDepth.value = String(payload.depth);
        if (dom.scannerDepthVal) dom.scannerDepthVal.textContent = String(payload.depth);
    }
    if (Array.isArray(payload.checks)) {
        const selected = new Set(payload.checks);
        getScannerTestCheckboxes().forEach((cb) => {
            cb.checked = selected.has(cb.value);
        });
    }
    if ($('#scanner-auth') && typeof payload.auth === 'boolean') $('#scanner-auth').checked = payload.auth;
    if ($('#scanner-fuzz-dirs') && typeof payload.fuzzDirs === 'boolean') $('#scanner-fuzz-dirs').checked = payload.fuzzDirs;
    if ($('#scanner-crawl-enabled') && typeof payload.crawlEnabled === 'boolean') $('#scanner-crawl-enabled').checked = payload.crawlEnabled;
    if ($('#scanner-passive') && typeof payload.passiveEnabled === 'boolean') $('#scanner-passive').checked = payload.passiveEnabled;
    if (dom.scannerXssHeadless && typeof payload.xssHeadlessConfirm === 'boolean') dom.scannerXssHeadless.checked = payload.xssHeadlessConfirm;
    if (dom.scannerOastBase && typeof payload.oastBaseUrl === 'string') dom.scannerOastBase.value = payload.oastBaseUrl;
    updateScannerAuthStatus().catch(() => { });
}

function persistScannerFormState() {
    const payload = getScannerFormState();
    if (chrome?.storage?.local) {
        chrome.storage.local.set({ greytab_scanner_form: payload });
    }
}

async function loadPersistedScannerFormState() {
    if (!chrome?.storage?.local) return;
    try {
        const data = await chrome.storage.local.get('greytab_scanner_form');
        if (data?.greytab_scanner_form) applyScannerFormState(data.greytab_scanner_form);
    } catch (e) {
        // ignore
    }
}

async function syncScannerStatusFromBackend() {
    try {
        const status = await apiRequest('GET', '/api/scanner/status');
        if (!status) return;

        if (status.target && dom.scannerTarget && !dom.scannerTarget.value) {
            dom.scannerTarget.value = status.target;
        }

        updateScannerProgress(status);

        if (status.running) {
            setScannerState(true);
            if (Array.isArray(status.findings) && status.findings.length > 0 && state.scanner.findings.length === 0) {
                dom.scannerFindings.innerHTML = '';
                for (const f of status.findings) addScannerFinding(f);
            }
            if (Number(status.test_log_count || 0) > 0 && state.scanner.testLog.length === 0) {
                await syncScannerAttemptsFromBackend();
            }
        } else {
            setScannerState(false);
            if (Number(status.test_log_count || 0) > 0 && state.scanner.testLog.length === 0) {
                await syncScannerAttemptsFromBackend();
            }
        }
    } catch (e) {
        // backend may not be ready
    }
}

async function syncScannerAttemptsFromBackend() {
    try {
        const data = await apiRequest('GET', '/api/scanner/attempts?limit=0');
        if (!data || !Array.isArray(data.attempts)) return;
        if (dom.scannerTestLog) {
            dom.scannerTestLog.innerHTML = `
                <div class="empty-state">
                  <span class="empty-state__text">No test attempts yet.</span>
                </div>
            `;
        }
        state.scanner.testLog = [];
        for (const t of data.attempts) addScannerTestLog(t);
    } catch {
        // ignore
    }
}

function bindScannerSyncControls() {
    const syncNow = () => {
        persistScannerFormState();
        broadcastUiSync('scanner_form', getScannerFormState());
    };
    dom.scannerTarget?.addEventListener('input', syncNow);
    dom.scannerDepth?.addEventListener('input', syncNow);
    getScannerTestCheckboxes().forEach((cb) => cb.addEventListener('change', syncNow));
    $('#scanner-auth')?.addEventListener('change', syncNow);
    $('#scanner-fuzz-dirs')?.addEventListener('change', syncNow);
    $('#scanner-crawl-enabled')?.addEventListener('change', syncNow);
    $('#scanner-passive')?.addEventListener('change', syncNow);
    dom.scannerXssHeadless?.addEventListener('change', syncNow);
    dom.scannerOastBase?.addEventListener('input', syncNow);
    dom.scannerTarget?.addEventListener('input', () => updateScannerAuthStatus().catch(() => { }));
    $('#scanner-auth')?.addEventListener('change', () => updateScannerAuthStatus().catch(() => { }));
}

async function getAuthCookiesForTarget(targetUrl) {
    let cookies = [];
    const u = new URL(targetUrl);
    try {
        cookies = await chrome.cookies.getAll({ url: u.origin });
    } catch {
        cookies = [];
    }
    if (!cookies || cookies.length === 0) {
        try {
            cookies = await chrome.cookies.getAll({ domain: u.hostname });
        } catch {
            cookies = [];
        }
    }
    const nowSec = Date.now() / 1000;
    const isHttps = u.protocol === 'https:';
    return (cookies || [])
        .filter(c => (!c.expirationDate || c.expirationDate > nowSec))
        .filter(c => isHttps || !c.secure);
}

async function updateScannerAuthStatus() {
    if (!dom.scannerAuthStatus) return;
    const authEnabled = Boolean($('#scanner-auth')?.checked);
    const target = (dom.scannerTarget?.value || '').trim();

    if (!authEnabled) {
        dom.scannerAuthStatus.textContent = 'Authenticated OFF. Scanner sends requests without browser session cookies.';
        return;
    }
    if (!target) {
        dom.scannerAuthStatus.textContent = 'Authenticated ON. Enter Target URL to load cookies from this browser profile.';
        return;
    }

    try {
        const cookies = await getAuthCookiesForTarget(target);
        const host = new URL(target).hostname;
        if (cookies.length > 0) {
            dom.scannerAuthStatus.textContent = `Authenticated ON. ${cookies.length} cookie(s) from ${host} will be attached as Cookie header.`;
        } else {
            dom.scannerAuthStatus.textContent = `Authenticated ON, but no cookies were found for ${host}. Scan will run unauthenticated unless you log in first.`;
        }
    } catch {
        dom.scannerAuthStatus.textContent = 'Authenticated ON, but target URL is invalid. Add a full URL like https://target.tld.';
    }
}

// Depth slider
dom.scannerDepth?.addEventListener('input', (e) => {
    if (dom.scannerDepthVal) dom.scannerDepthVal.textContent = e.target.value;
});

// Start Scanner
dom.btnScannerStart?.addEventListener('click', async () => {
    const target = dom.scannerTarget.value.trim();
    if (!target) {
        alert('Please enter a target URL');
        return;
    }

    const depth = parseInt(dom.scannerDepth.value);

    // Filter test types (exclude advanced options which might be 'on')
    const validTests = new Set(['xss', 'sqli', 'path_traversal', 'lfi', 'open_redirect', 'oast']);
    const checks = getScannerTestCheckboxes()
        .filter((cb) => cb.checked)
        .map(cb => cb.value)
        .filter(v => validTests.has(v));

    const isAuth = $('#scanner-auth')?.checked;
    const isFuzz = $('#scanner-fuzz-dirs')?.checked;
    const isCrawlEnabled = $('#scanner-crawl-enabled')?.checked !== false;
    const xssHeadlessConfirm = Boolean(dom.scannerXssHeadless?.checked);
    const oastEnabled = checks.includes('oast');
    const oastBaseUrl = String(dom.scannerOastBase?.value || '').trim();
    const aiVerifyFindings = Boolean(dom.aiVerifyFindings?.checked);
    state.scanner.passiveEnabled = Boolean(dom.scannerPassive?.checked);

    if (oastEnabled && !oastBaseUrl) {
        alert('OAST is enabled. Please set "OAST Callback Base URL" first.');
        return;
    }

    let headers = {};
    if (isAuth) {
        try {
            const cookies = await getAuthCookiesForTarget(target);
            if (cookies && cookies.length > 0) {
                const cookieStr = cookies.map(c => `${c.name}=${c.value}`).join('; ');
                headers['Cookie'] = cookieStr;
            } else {
                const host = new URL(target).hostname;
                alert(`Authenticated is enabled, but no cookies were found for ${host}. The scan will run unauthenticated.`);
            }
        } catch (e) {
            console.error('Failed to get auth cookies:', e);
        }
    }

    try {
        await apiRequest('POST', '/api/scanner/start', {
            target_url: target,
            scan_depth: depth,
            test_types: checks,
            headers: headers,
            fuzz_dirs: isFuzz,
            crawl_enabled: isCrawlEnabled,
            ai_verify_findings: aiVerifyFindings,
            xss_headless_confirm: xssHeadlessConfirm,
            oast_enabled: oastEnabled,
            oast_base_url: oastBaseUrl,
        });
        setScannerState(true);
        resetScannerPanels();
        broadcastUiSync('scanner_form', getScannerFormState());
        broadcastUiSync('scanner_state', { running: true });
        dom.scannerFindings.innerHTML = '';
        dom.scannerCount.textContent = '0';
        state.scanner.findings = [];
    } catch (e) {
        alert('Failed to start scanner: ' + e.message);
    }
});

// Stop Scanner
dom.btnScannerStop?.addEventListener('click', async () => {
    try {
        await apiRequest('POST', '/api/scanner/stop');
        setScannerState(false);
        broadcastUiSync('scanner_state', { running: false });
    } catch (e) {
        console.error('Stop failed:', e);
    }
});

function setScannerState(running) {
    state.scanner.running = running;
    if (dom.btnScannerStart) dom.btnScannerStart.style.display = running ? 'none' : 'inline-flex';
    if (dom.btnScannerStop) dom.btnScannerStop.style.display = running ? 'inline-flex' : 'none';
    if (running) {
        if (dom.scannerProgress) dom.scannerProgress.style.display = 'flex';
        if (dom.scannerStats) dom.scannerStats.style.display = 'grid';
        if (dom.scannerActivity) dom.scannerActivity.style.display = 'block';
    }

    if (running) {
        if (dom.scannerProgressText) dom.scannerProgressText.textContent = 'Starting scan...';
        if (dom.scannerProgressFill) dom.scannerProgressFill.style.width = '0%';
    }
}

function formatScannerStage(stage) {
    const map = {
        initializing: 'Initializing',
        fetching: 'Fetching',
        testing: 'Testing',
        completed_url: 'URL Done',
        stopping: 'Stopping',
        done: 'Done',
        idle: 'Idle'
    };
    return map[String(stage || '').toLowerCase()] || (stage || 'Unknown');
}

function updateScannerProgress(data) {
    const pct = Math.max(0, Math.min(100, Number(data.progress_percent || 0)));
    if (dom.scannerProgressFill) dom.scannerProgressFill.style.width = `${pct}%`;
    if (dom.scannerProgressText) {
        dom.scannerProgressText.textContent =
            `${pct}% | Crawled: ${data.urls_crawled || 0} | Queue: ${data.urls_queued ?? data.queue_size ?? 0} | Findings: ${data.findings_count || 0} | AI: ${data.ai_reviews_used || 0}/${data.ai_reviews_budget || 0}\n${data.current_url || ''}`;
    }
    if (dom.scannerStage) dom.scannerStage.textContent = formatScannerStage(data.current_stage);
    if (dom.scannerQueue) dom.scannerQueue.textContent = String(data.urls_queued ?? data.queue_size ?? 0);
    if (dom.scannerRequestsCount) dom.scannerRequestsCount.textContent = String(data.requests_sent || 0);
    if (dom.scannerTests) dom.scannerTests.textContent = `${data.tests_completed || 0}/${data.tests_total || 0}`;
    if (dom.scannerRate) dom.scannerRate.textContent = `${Number(data.rate_rps || 0).toFixed(2)} r/s`;
    if (dom.scannerTestCount && Number.isFinite(Number(data.test_log_count))) {
        dom.scannerTestCount.textContent = `${Number(data.test_log_count)} tests`;
    }
}

function appendScannerActivity(activity) {
    if (!dom.scannerActivityList || !activity) return;
    const seq = Number(activity.seq || 0);
    if (seq && seq <= state.scanner.activitySeq) return;
    if (seq) state.scanner.activitySeq = seq;
    state.scanner.activities.push(activity);
    while (state.scanner.activities.length > 400) state.scanner.activities.shift();

    const empty = dom.scannerActivityList.querySelector('.empty-state');
    if (empty) empty.remove();

    const el = document.createElement('div');
    const isError = ['error', 'timeout'].includes(String(activity.type || '').toLowerCase());
    el.className = `scanner-activity__item${isError ? ' scanner-activity__item--error' : ''}`;

    const ts = new Date(activity.ts ? activity.ts * 1000 : Date.now()).toLocaleTimeString();
    el.innerHTML = `<span class="scanner-activity__item-time">${escHtml(ts)}</span>${escHtml(activity.message || activity.url || activity.type || 'activity')}`;
    dom.scannerActivityList.appendChild(el);
    dom.scannerActivityList.scrollTop = dom.scannerActivityList.scrollHeight;

    while (dom.scannerActivityList.children.length > 160) {
        dom.scannerActivityList.removeChild(dom.scannerActivityList.firstChild);
    }
    scheduleWorkspaceSave();
}

function resetScannerPanels() {
    state.scanner.findings = [];
    state.scanner.activitySeq = 0;
    state.scanner.activities = [];
    state.scanner.requestLog = [];
    state.scanner.testLog = [];
    state.scanner.treeSeen = new Set();
    state.scanner.treeRoot = null;
    state.scanner.treeExpanded = new Set();
    if (dom.scannerStage) dom.scannerStage.textContent = '-';
    if (dom.scannerQueue) dom.scannerQueue.textContent = '0';
    if (dom.scannerRequestsCount) dom.scannerRequestsCount.textContent = '0';
    if (dom.scannerTests) dom.scannerTests.textContent = '0/0';
    if (dom.scannerRate) dom.scannerRate.textContent = '0 r/s';
    if (dom.scannerCount) dom.scannerCount.textContent = '0';
    if (dom.scannerTestCount) dom.scannerTestCount.textContent = '0 tests';

    if (dom.scannerActivityList) {
        dom.scannerActivityList.innerHTML = `
            <div class="empty-state">
              <span class="empty-state__text">No activity yet.</span>
            </div>
        `;
    }
    if (dom.scannerRequestLog) {
        dom.scannerRequestLog.innerHTML = `
            <div class="empty-state">
              <span class="empty-state__text">No scanner requests yet.</span>
            </div>
        `;
    }
    if (dom.scannerTestLog) {
        dom.scannerTestLog.innerHTML = `
            <div class="empty-state">
              <span class="empty-state__text">No test attempts yet.</span>
            </div>
        `;
    }
    if (dom.scannerTree) {
        dom.scannerTree.innerHTML = `
            <div class="empty-state">
              <span class="empty-state__text">No crawl tree yet.</span>
            </div>
        `;
    }
}

function addScannerRequestLog(entry) {
    if (!dom.scannerRequestLog || !entry) return;
    const key = `${entry.type || ''}|${entry.url || ''}|${entry.message || ''}`;
    if (state.scanner.requestLog.some((r) => r.key === key)) return;
    state.scanner.requestLog.push({ key, ...entry });
    const empty = dom.scannerRequestLog.querySelector('.empty-state');
    if (empty) empty.remove();

    const row = document.createElement('div');
    row.className = 'scanner-request-row';
    row.innerHTML = `
      <div class="req-main" style="flex:1; min-width:0;">
        <div class="req-line1">
          <span class="req-method ${entry.method === 'POST' ? 'method-POST' : (entry.method === 'PUT' ? 'method-PUT' : 'method-GET')}">${escHtml(entry.method || 'GET')}</span>
          <span class="req-url" title="${escHtml(entry.url || '')}">${escHtml(entry.url ? new URL(entry.url).pathname + new URL(entry.url).search : entry.message || '')}</span>
        </div>
        <div class="req-host">Host: ${escHtml(entry.url ? new URL(entry.url).host : '')}</div>
      </div>
      <div class="req-meta">
        <span class="req-status status-2xx">${escHtml((entry.type || 'event').toUpperCase())}</span>
      </div>
    `;
    dom.scannerRequestLog.appendChild(row);
    scheduleWorkspaceSave();
}

function scannerOutcomeClass(outcome) {
    const o = String(outcome || '').toLowerCase();
    if (o === 'confirmed') return 'status-2xx';
    if (o === 'signal') return 'status-3xx';
    if (o === 'error') return 'status-5xx';
    return 'status-4xx';
}

function addScannerTestLog(test) {
    if (!dom.scannerTestLog || !test) return;
    const id = Number(test.id || 0);
    if (id && state.scanner.testLog.some((t) => Number(t.id || 0) === id)) return;
    if (!id) {
        const key = `${test.timestamp || ''}|${test.url || ''}|${test.test_type || ''}|${test.parameter || ''}|${test.payload || ''}|${test.stage || ''}`;
        if (state.scanner.testLog.some((t) => t.__key === key)) return;
        test.__key = key;
    }

    state.scanner.testLog.push(test);
    if (state.scanner.testLog.length > 20000) state.scanner.testLog.shift();
    if (dom.scannerTestCount) dom.scannerTestCount.textContent = `${state.scanner.testLog.length} tests`;

    const empty = dom.scannerTestLog.querySelector('.empty-state');
    if (empty) empty.remove();

    const row = document.createElement('div');
    row.className = 'scanner-request-row';
    const outcome = String(test.outcome || 'no_signal').toUpperCase();
    const type = String(test.test_type || 'test').toUpperCase();
    const stage = String(test.stage || 'probe').toUpperCase();
    const method = String(test.method || 'GET').toUpperCase();
    const statusCode = Number(test.status_code || 0);
    const statusTxt = statusCode > 0 ? String(statusCode) : '-';
    row.innerHTML = `
      <div class="req-main" style="flex:1; min-width:0;">
        <div class="req-line1">
          <span class="req-method ${method === 'POST' ? 'method-POST' : (method === 'PUT' ? 'method-PUT' : 'method-GET')}">${escHtml(method)}</span>
          <span class="req-url" title="${escHtml(test.url || '')}">${escHtml(test.url ? new URL(test.url).pathname + new URL(test.url).search : test.evidence || '')}</span>
        </div>
        <div class="req-host">Host: ${escHtml(test.url ? new URL(test.url).host : '')}</div>
        <div style="font-family:var(--font-mono); font-size:0.72rem; opacity:0.9; margin-top:0.15rem;">
          ${escHtml(test.parameter || 'global')} = ${escHtml(test.payload || '')}
        </div>
      </div>
      <div class="req-meta" style="align-items:flex-end;">
        <span class="req-status ${scannerOutcomeClass(outcome)}">${escHtml(outcome)}</span>
        <span class="traffic-item__time">${escHtml(stage)} | HTTP ${escHtml(statusTxt)} | ${escHtml(String(test.elapsed_ms || 0))}ms</span>
      </div>
    `;
    row.addEventListener('click', () => {
        const pseudoFinding = {
            url: test.url || '',
            vuln_type: `test_${String(test.test_type || '').toLowerCase()}`,
            severity: String(test.outcome || '').toLowerCase() === 'confirmed' ? 'high' : (
                String(test.outcome || '').toLowerCase() === 'signal' ? 'medium' : (
                    String(test.outcome || '').toLowerCase() === 'error' ? 'low' : 'info'
                )
            ),
            evidence: `[${String(test.outcome || '').toUpperCase()}|${String(test.stage || '').toUpperCase()}] ${test.evidence || ''}`,
            payload: test.payload || '',
            parameter: test.parameter || '',
            request_raw: test.request_raw || '',
            response_raw: test.response_raw || '',
        };
        showScannerDetail(pseudoFinding);
    });
    dom.scannerTestLog.appendChild(row);
    scheduleWorkspaceSave();
}

function ensureScannerTreeModel() {
    if (state.scanner.treeRoot) return;
    state.scanner.treeRoot = {
        id: 'root',
        name: 'root',
        kind: 'root',
        children: new Map(),
        sources: new Set(),
        hits: 0,
    };
    state.scanner.treeExpanded = new Set(['root']);
}

function createTreeNode(id, name, kind = 'dir', url = '') {
    return {
        id,
        name,
        kind,
        url,
        children: new Map(),
        sources: new Set(),
        hits: 0,
    };
}

function buildScannerTreePath(url) {
    try {
        const u = new URL(url);
        const host = u.host || u.hostname || 'unknown-host';
        const pathParts = (u.pathname || '/').split('/').filter(Boolean);
        const hasTrailingSlash = (u.pathname || '/').endsWith('/');

        const nodes = [{ key: `h:${host}`, label: host, kind: 'host', url: `${u.protocol}//${host}/` }];
        let prefix = `h:${host}`;
        let cumulativePath = '';
        for (let i = 0; i < pathParts.length; i++) {
            const p = pathParts[i];
            const isLast = i === pathParts.length - 1;
            const looksFile = p.includes('.') && !hasTrailingSlash && isLast;
            prefix += `/${p}`;
            cumulativePath += `/${p}`;
            nodes.push({
                key: prefix,
                label: decodeURIComponent(p),
                kind: looksFile ? 'file' : 'dir',
                url: looksFile ? `${u.origin}${cumulativePath}` : `${u.origin}${cumulativePath}/`,
            });
        }

        const leafQuery = u.search ? `${u.search}` : '';
        if (!pathParts.length && !leafQuery) {
            nodes.push({ key: `${prefix}/`, label: '/', kind: 'file', url: `${u.origin}/` });
        } else if (leafQuery) {
            const qKey = `${prefix}${leafQuery}`;
            const baseName = pathParts[pathParts.length - 1] || '/';
            nodes.push({
                key: qKey,
                label: `${decodeURIComponent(baseName)}${leafQuery}`,
                kind: 'file',
                url: `${u.origin}${u.pathname}${u.search}`,
            });
        }
        return nodes;
    } catch {
        return [{ key: `h:unknown`, label: String(url), kind: 'file', url: String(url) }];
    }
}

function openScannerTreeNodeUrl(url) {
    if (!url) return;
    try {
        if (chrome?.tabs?.create) {
            chrome.tabs.create({ url });
            return;
        }
    } catch {
        // fallback below
    }
    window.open(url, '_blank', 'noopener,noreferrer');
}

function renderScannerTree() {
    if (!dom.scannerTree) return;
    ensureScannerTreeModel();
    dom.scannerTree.innerHTML = '';

    const root = state.scanner.treeRoot;
    if (!root || root.children.size === 0) {
        dom.scannerTree.innerHTML = `
            <div class="empty-state">
              <span class="empty-state__text">No crawl tree yet.</span>
            </div>
        `;
        return;
    }

    const container = document.createElement('div');
    container.className = 'scanner-tree-root';
    dom.scannerTree.appendChild(container);

    const renderNode = (node, level) => {
        const item = document.createElement('div');
        item.className = 'scanner-tree-item';
        item.style.paddingLeft = `${8 + level * 14}px`;

        const hasChildren = node.children && node.children.size > 0;
        const expanded = state.scanner.treeExpanded.has(node.id);

        const toggle = document.createElement('button');
        toggle.className = 'scanner-tree-toggle';
        toggle.textContent = hasChildren ? (expanded ? '▾' : '▸') : '•';
        toggle.disabled = !hasChildren;
        toggle.addEventListener('click', (e) => {
            e.stopPropagation();
            if (!hasChildren) return;
            if (expanded) state.scanner.treeExpanded.delete(node.id);
            else state.scanner.treeExpanded.add(node.id);
            renderScannerTree();
        });
        item.appendChild(toggle);

        const label = document.createElement('span');
        label.className = `scanner-tree-label scanner-tree-label--${node.kind}`;
        label.textContent = node.name;
        if (node.url) {
            label.classList.add('scanner-tree-label--link');
            label.title = `Open ${node.url}`;
            label.addEventListener('click', (e) => {
                e.stopPropagation();
                openScannerTreeNodeUrl(node.url);
            });
        }
        item.appendChild(label);

        if (node.hits > 1) {
            const count = document.createElement('span');
            count.className = 'scanner-tree-meta';
            count.textContent = `x${node.hits}`;
            item.appendChild(count);
        }

        if (node.sources.has('active')) {
            const a = document.createElement('span');
            a.className = 'scanner-tree-badge scanner-tree-badge--active';
            a.textContent = 'active';
            item.appendChild(a);
        }
        if (node.sources.has('passive')) {
            const p = document.createElement('span');
            p.className = 'scanner-tree-badge scanner-tree-badge--passive';
            p.textContent = 'passive';
            item.appendChild(p);
        }

        container.appendChild(item);

        if (!hasChildren || !expanded) return;
        const children = Array.from(node.children.values()).sort((a, b) => {
            const rank = (n) => (n.kind === 'host' ? 0 : n.kind === 'dir' ? 1 : 2);
            const r = rank(a) - rank(b);
            return r !== 0 ? r : a.name.localeCompare(b.name);
        });
        for (const child of children) renderNode(child, level + 1);
    };

    const hosts = Array.from(root.children.values()).sort((a, b) => a.name.localeCompare(b.name));
    for (const host of hosts) renderNode(host, 0);
}

function serializeScannerTreeNode(node) {
    if (!node) return null;
    return {
        id: node.id,
        name: node.name,
        kind: node.kind,
        url: node.url || '',
        hits: Number(node.hits || 0),
        sources: Array.from(node.sources || []),
        children: Array.from((node.children || new Map()).values()).map(serializeScannerTreeNode),
    };
}

function deserializeScannerTreeNode(raw) {
    if (!raw || typeof raw !== 'object') return null;
    const node = createTreeNode(raw.id || '', raw.name || '', raw.kind || 'dir', raw.url || '');
    node.hits = Number(raw.hits || 0);
    node.sources = new Set(Array.isArray(raw.sources) ? raw.sources : []);
    node.children = new Map();
    const children = Array.isArray(raw.children) ? raw.children : [];
    for (const child of children) {
        const parsed = deserializeScannerTreeNode(child);
        if (parsed) node.children.set(parsed.id, parsed);
    }
    return node;
}

function addScannerTreeNode(url, depth = 0, source = 'active') {
    if (!dom.scannerTree || !url) return;
    ensureScannerTreeModel();
    const k = String(url);
    state.scanner.treeSeen.add(k);

    const pathNodes = buildScannerTreePath(k);
    let parent = state.scanner.treeRoot;
    for (const seg of pathNodes) {
        if (!parent.children.has(seg.key)) {
            parent.children.set(seg.key, createTreeNode(seg.key, seg.label, seg.kind, seg.url || ''));
        }
        const node = parent.children.get(seg.key);
        if (!node.url && seg.url) node.url = seg.url;
        node.sources.add(source);
        node.hits += 1;
        parent = node;
        if (seg.kind === 'host' || Number(depth || 0) <= 1) {
            state.scanner.treeExpanded.add(seg.key);
        }
    }
    renderScannerTree();
}

function processScannerActivity(activity) {
    const type = String(activity.type || '').toLowerCase();
    if (activity.url && (type === 'queue' || type === 'url_start' || type === 'url_done')) {
        addScannerTreeNode(activity.url, Number(activity.depth || 0), 'active');
    }
    if (['url_start', 'url_done', 'timeout', 'error', 'finding', 'crawl_expand', 'ai_review_start', 'ai_review_done', 'ai_review_error'].includes(type)) {
        addScannerRequestLog({
            type,
            method: type === 'url_start' ? 'GET' : '',
            url: activity.url || '',
            message: activity.message || activity.url || type,
        });
    }
}

function processPassiveScannerFlow(flow) {
    if (!flow || !flow.url) return;
    addScannerTreeNode(flow.url, 0, 'passive');

    // Passive checks should be high-signal only: in-scope pages/API responses.
    let parsedFlowUrl;
    try {
        parsedFlowUrl = new URL(flow.url);
    } catch {
        return;
    }

    const target = (dom.scannerTarget?.value || '').trim();
    if (target) {
        try {
            const targetHost = new URL(target).hostname.toLowerCase();
            const flowHost = parsedFlowUrl.hostname.toLowerCase();
            const inScopeHost = flowHost === targetHost || flowHost.endsWith(`.${targetHost}`);
            if (!inScopeHost) return;
        } catch {
            // If target parsing fails, do not apply host-scope filtering.
        }
    }

    const method = String(flow.method || '').toUpperCase();
    if (method && !['GET', 'POST'].includes(method)) return;

    const path = (parsedFlowUrl.pathname || '/').toLowerCase();
    const staticExtPattern = /\.(png|jpe?g|gif|svg|webp|ico|css|js|mjs|map|woff2?|ttf|eot|otf|pdf|zip|gz|mp4|webm|mp3|wav|avi)$/i;
    if (staticExtPattern.test(path)) return;

    let headers = flow.response_headers || {};
    if (typeof headers === 'string') {
        try { headers = JSON.parse(headers); } catch { headers = {}; }
    }
    const h = {};
    for (const [k, v] of Object.entries(headers || {})) h[String(k).toLowerCase()] = String(v);

    const contentType = (h['content-type'] || '').toLowerCase();
    const isHtmlLike = contentType.includes('text/html') || contentType.includes('application/xhtml+xml');
    const isJsonLike = contentType.includes('application/json') || contentType.includes('application/problem+json');
    if (!isHtmlLike && !isJsonLike) return;

    const statusCode = Number(flow.status_code || 0);
    if (statusCode && (statusCode < 200 || statusCode >= 400)) return;

    if (isHtmlLike && !h['content-security-policy']) {
        if (addScannerFinding({
            url: flow.url,
            vuln_type: 'passive_missing_csp',
            severity: 'low',
            evidence: 'Passive check: response missing Content-Security-Policy',
            payload: '',
            parameter: 'response_header',
            request_raw: '',
            response_raw: '',
        })) {
            state.stats.findings++;
            updateStats();
        }
    }
    if (isHtmlLike && !h['x-frame-options']) {
        if (addScannerFinding({
            url: flow.url,
            vuln_type: 'passive_clickjacking',
            severity: 'low',
            evidence: 'Passive check: response missing X-Frame-Options',
            payload: '',
            parameter: 'response_header',
            request_raw: '',
            response_raw: '',
        })) {
            state.stats.findings++;
            updateStats();
        }
    }
    if (!h['x-content-type-options']) {
        if (addScannerFinding({
            url: flow.url,
            vuln_type: 'passive_mime_sniffing',
            severity: 'info',
            evidence: 'Passive check: response missing X-Content-Type-Options',
            payload: '',
            parameter: 'response_header',
            request_raw: '',
            response_raw: '',
        })) {
            state.stats.findings++;
            updateStats();
        }
    }
}

function addScannerFinding(finding) {
    // Remove empty state
    const empty = dom.scannerFindings.querySelector('.empty-state');
    if (empty) empty.remove();

    // Avoid dupes in UI (backend logic also dedups, but safe to check)
    if (state.scanner.findings.some(f => f.url === finding.url && f.vuln_type === finding.vuln_type && f.parameter === finding.parameter)) {
        return false;
    }
    state.scanner.findings.push(finding);
    dom.scannerCount.textContent = String(state.scanner.findings.length);
    if (finding.request_raw || finding.response_raw) {
        addScannerRequestLog({
            type: 'finding',
            method: '',
            url: finding.url,
            message: `${String(finding.vuln_type || '').toUpperCase()} -> ${finding.parameter || 'global'}`,
        });
    }

    const ai = finding.ai_analysis || null;
    const aiVerdict = String(ai?.verdict || '').toLowerCase();
    const aiLabel = ai ? formatAiVerdict(aiVerdict) : '';
    const aiConfidence = ai ? formatAiConfidence(ai.confidence) : '';
    const score = Number(finding.score || 0);
    const deterministic = Boolean(finding.deterministic_confirmed);
    const insertion = String(finding.insertion_point || '').trim();
    const el = document.createElement('div');
    el.className = `scanner-finding-card scanner-finding-card--${finding.severity}`;
    el.innerHTML = `
        <span class="scanner-finding-title">${escHtml(finding.vuln_type.toUpperCase())}: ${escHtml(finding.parameter || 'Global')}</span>
        <div class="scanner-finding-meta">
            <span style="font-family:var(--font-mono);">${escHtml(finding.url)}</span>
            <span>${finding.severity.toUpperCase()}</span>
        </div>
        <div class="scanner-finding-meta">
            <span>Score: ${Number.isFinite(score) ? score : 0}/100</span>
            <span>${deterministic ? 'Deterministic' : 'Heuristic'}</span>
            <span>${escHtml(insertion || 'global')}</span>
        </div>
        ${ai ? `<div class="scanner-finding-ai">AI: <span class="scanner-finding-ai__verdict scanner-finding-ai__verdict--${escHtml(aiVerdict)}">${escHtml(aiLabel)}</span> ${escHtml(aiConfidence)}</div>` : ''}
    `;

    el.addEventListener('click', () => {
        showScannerDetail(finding);
    });

    dom.scannerFindings.appendChild(el);
    scheduleWorkspaceSave();
    return true;
}

function formatAiVerdict(verdict) {
    const v = String(verdict || '').toLowerCase();
    if (v === 'confirmed') return 'Likely Valid';
    if (v === 'likely_false_positive') return 'Likely False Positive';
    if (v === 'needs_manual_review') return 'Needs Manual Review';
    return 'Not analyzed';
}

function formatAiConfidence(confidence) {
    const num = Number(confidence);
    if (!Number.isFinite(num)) return '';
    return `(${Math.max(0, Math.min(100, Math.round(num * 100)))}%)`;
}

function renderScannerModalAi(finding) {
    const ai = finding?.ai_analysis;
    if (!ai) {
        if (dom.scannerModalAiVerdict) dom.scannerModalAiVerdict.textContent = 'Not analyzed';
        if (dom.scannerModalAiConfidence) dom.scannerModalAiConfidence.textContent = '-';
        if (dom.scannerModalAiReasoning) dom.scannerModalAiReasoning.textContent = 'No AI analysis available.';
        return;
    }

    const verdict = formatAiVerdict(ai.verdict);
    const confidence = formatAiConfidence(ai.confidence) || '-';
    if (dom.scannerModalAiVerdict) dom.scannerModalAiVerdict.textContent = verdict;
    if (dom.scannerModalAiConfidence) dom.scannerModalAiConfidence.textContent = confidence;

    const reasoning = [ai.reasoning || 'No reasoning provided.'];
    if (Array.isArray(ai.follow_up_tests) && ai.follow_up_tests.length) {
        reasoning.push('');
        reasoning.push('Follow-up tests:');
        ai.follow_up_tests.slice(0, 5).forEach((s, idx) => {
            reasoning.push(`${idx + 1}. ${s}`);
        });
    }
    if (dom.scannerModalAiReasoning) dom.scannerModalAiReasoning.textContent = reasoning.join('\n');
}

function showScannerDetail(finding) {
    if (!dom.scannerDetailModal) return;

    dom.scannerModalType.textContent = finding.vuln_type.toUpperCase();
    dom.scannerModalSeverity.textContent = finding.severity.toUpperCase();
    dom.scannerModalSeverity.className = `badge badge--${finding.severity}`;
    dom.scannerModalUrl.textContent = finding.url;
    dom.scannerModalParam.textContent = finding.parameter || 'N/A';
    if (dom.scannerModalScore) dom.scannerModalScore.textContent = String(Number(finding.score || 0));
    if (dom.scannerModalConfirmed) dom.scannerModalConfirmed.textContent = finding.deterministic_confirmed ? 'yes' : 'no';
    if (dom.scannerModalInsertion) dom.scannerModalInsertion.textContent = finding.insertion_point || 'N/A';
    dom.scannerModalEvidence.textContent = finding.evidence || 'No evidence provided.';
    const suggestedTool = getSuggestedToolForFinding(finding.vuln_type);
    if (dom.scannerModalToolHint) dom.scannerModalToolHint.textContent = suggestedTool || 'manual review';
    renderScannerModalAi(finding);

    dom.scannerModalRequest.textContent = finding.request_raw || 'Request data not captured.';
    dom.scannerModalResponse.textContent = finding.response_raw || 'Response data not captured.';

    // Show modal
    dom.scannerDetailModal.style.display = 'flex';

    // Reset tabs
    const tabs = dom.scannerDetailModal.querySelectorAll('.detail-tab');
    tabs.forEach(t => t.classList.remove('detail-tab--active'));
    tabs[0].classList.add('detail-tab--active');

    dom.scannerModalRequest.style.display = 'block';
    dom.scannerModalResponse.style.display = 'none';

    // Store current finding for actions
    dom.scannerDetailModal.dataset.finding = JSON.stringify(finding);
}

function getSuggestedToolForFinding(vulnType) {
    const t = String(vulnType || '').toLowerCase();
    if (t === 'xss') return 'xsser';
    if (t === 'sqli') return 'sqlmap';
    if (t === 'lfi' || t === 'path_traversal' || t === 'open_redirect') return 'nuclei';
    if (t === 'oast_blind_interaction') return 'nuclei';
    if (t === 'discovery' || t === 'info') return 'whatweb';
    return '';
}

// Scanner Modal Events
if (dom.btnCloseScannerModal) {
    dom.btnCloseScannerModal.addEventListener('click', () => {
        dom.scannerDetailModal.style.display = 'none';
    });
}

// Scanner Modal Tabs
if (dom.scannerDetailModal) {
    const tabs = dom.scannerDetailModal.querySelectorAll('.detail-tab');
    tabs.forEach(tab => {
        tab.addEventListener('click', () => {
            const type = tab.dataset.scannerModal; // 'request' or 'response'

            tabs.forEach(t => t.classList.remove('detail-tab--active'));
            tab.classList.add('detail-tab--active');

            if (type === 'request') {
                dom.scannerModalRequest.style.display = 'block';
                dom.scannerModalResponse.style.display = 'none';
            } else {
                dom.scannerModalRequest.style.display = 'none';
                dom.scannerModalResponse.style.display = 'block';
            }
        });
    });
}

// Scanner to Repeater
if (dom.btnScannerToRepeater) {
    dom.btnScannerToRepeater.addEventListener('click', () => {
        try {
            const finding = JSON.parse(dom.scannerDetailModal.dataset.finding);
            if (finding.request_raw) {
                const parsed = parseRawRequest(finding.request_raw);
                sendToRepeater({
                    method: parsed.method,
                    url: parsed.url,
                    headers: parsed.headers,
                    body: parsed.body
                });
                dom.scannerDetailModal.style.display = 'none';
            } else {
                alert('No raw request data available to send.');
            }
        } catch (e) {
            console.error(e);
        }
    });
}

if (dom.btnScannerToTools) {
    dom.btnScannerToTools.addEventListener('click', () => {
        try {
            const finding = JSON.parse(dom.scannerDetailModal.dataset.finding);
            const suggested = getSuggestedToolForFinding(finding.vuln_type);
            $$('.tab[data-tab="tools"]')[0].click();
            if (dom.toolTarget) dom.toolTarget.value = finding.url || '';
            if (suggested) {
                selectTool(suggested);
                showToolContext(
                    `Suggested from AutoScanner: ${suggested}`,
                    `Finding: ${finding.vuln_type.toUpperCase()} on parameter "${finding.parameter || 'N/A'}"`
                );
            }
            dom.scannerDetailModal.style.display = 'none';
        } catch (e) {
            console.error(e);
        }
    });
}

if (dom.btnScannerAiRecheck) {
    dom.btnScannerAiRecheck.addEventListener('click', async () => {
        const originalText = dom.btnScannerAiRecheck.textContent;
        try {
            const finding = JSON.parse(dom.scannerDetailModal.dataset.finding || '{}');
            if (!finding || !finding.url) return;
            dom.btnScannerAiRecheck.textContent = 'Analyzing...';
            dom.btnScannerAiRecheck.disabled = true;

            const res = await apiRequest('POST', '/api/ai/analyze_finding', { finding });
            const analysis = res?.analysis;
            if (!analysis) throw new Error('No analysis returned');

            finding.ai_analysis = analysis;
            dom.scannerDetailModal.dataset.finding = JSON.stringify(finding);
            renderScannerModalAi(finding);

            const idx = state.scanner.findings.findIndex((f) =>
                f.url === finding.url &&
                f.vuln_type === finding.vuln_type &&
                (f.parameter || '') === (finding.parameter || '')
            );
            if (idx !== -1) {
                state.scanner.findings[idx].ai_analysis = analysis;
            }
        } catch (e) {
            alert(`AI re-check failed: ${e.message}`);
        } finally {
            dom.btnScannerAiRecheck.textContent = originalText || 'AI Re-check';
            dom.btnScannerAiRecheck.disabled = false;
        }
    });
}

async function submitScannerFindingFeedback(label, buttonEl) {
    const original = buttonEl?.textContent || '';
    try {
        const finding = JSON.parse(dom.scannerDetailModal?.dataset?.finding || '{}');
        if (!finding || !finding.url) return;
        if (buttonEl) {
            buttonEl.disabled = true;
            buttonEl.textContent = 'Saving...';
        }
        await apiRequest('POST', '/api/ai/feedback', { finding, label });
        if (buttonEl) buttonEl.textContent = label === 'true_positive' ? 'Marked TP' : 'Marked FP';
    } catch (e) {
        alert(`Feedback save failed: ${e.message}`);
    } finally {
        if (buttonEl) {
            setTimeout(() => {
                buttonEl.disabled = false;
                buttonEl.textContent = original;
            }, 800);
        }
    }
}

if (dom.btnScannerFeedbackTp) {
    dom.btnScannerFeedbackTp.addEventListener('click', async () => {
        await submitScannerFindingFeedback('true_positive', dom.btnScannerFeedbackTp);
    });
}

if (dom.btnScannerFeedbackFp) {
    dom.btnScannerFeedbackFp.addEventListener('click', async () => {
        await submitScannerFindingFeedback('false_positive', dom.btnScannerFeedbackFp);
    });
}

// ══════════════════════════════════════════════════════════════════
// Settings Tab
// ══════════════════════════════════════════════════════════════════

const settingsState = {
    loaded: false,
    editingTool: null,
    aiKeySet: false,
};

function aiProviderDefaults(provider) {
    const p = String(provider || '').toLowerCase();
    if (p === 'openai') {
        return { model: 'gpt-4o-mini', endpoint: 'https://api.openai.com/v1/chat/completions' };
    }
    if (p === 'anthropic') {
        return { model: 'claude-3-5-sonnet-latest', endpoint: 'https://api.anthropic.com/v1/messages' };
    }
    if (p === 'gemini') {
        return { model: 'gemini-1.5-flash', endpoint: 'https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent' };
    }
    if (p === 'custom') {
        return { model: 'custom-model', endpoint: 'http://127.0.0.1:8000/v1/chat/completions' };
    }
    return { model: 'llama3.1:8b', endpoint: 'http://127.0.0.1:11434/api/generate' };
}

function getAiProviderHint(provider) {
    const p = String(provider || '').toLowerCase();
    if (p === 'openai') {
        return 'OpenAI: default endpoint https://api.openai.com/v1/chat/completions and API key is required.';
    }
    if (p === 'anthropic') {
        return 'Anthropic: default endpoint https://api.anthropic.com/v1/messages and API key is required.';
    }
    if (p === 'gemini') {
        return 'Gemini: use a Google AI Studio API key. You can keep endpoint empty to use the default official endpoint.';
    }
    if (p === 'custom') {
        return 'Custom: your endpoint must accept JSON and return text/JSON with the model output.';
    }
    return 'Ollama local/LAN: for example http://127.0.0.1:11434/api/generate or http://VM_IP:11434/api/generate.';
}

function setAiStatus(text, type = '') {
    if (!dom.aiStatus) return;
    dom.aiStatus.textContent = text || '';
    dom.aiStatus.className = 'settings-note';
    if (type === 'ok') dom.aiStatus.classList.add('settings-note--ok');
    if (type === 'warn') dom.aiStatus.classList.add('settings-note--warn');
}

function applyAiSettingsToForm(aiCfg) {
    const cfg = aiCfg || {};
    const provider = String(cfg.provider || 'ollama');
    if (dom.aiEnabled) dom.aiEnabled.checked = Boolean(cfg.enabled);
    if (dom.aiVerifyFindings) dom.aiVerifyFindings.checked = cfg.verify_findings !== false;
    if (dom.aiProvider) dom.aiProvider.value = provider;
    if (dom.aiModel) dom.aiModel.value = cfg.model || '';
    if (dom.aiEndpoint) dom.aiEndpoint.value = cfg.endpoint || '';
    if (dom.aiTimeout) dom.aiTimeout.value = String(cfg.timeout_seconds || 20);
    if (dom.aiTemperature) dom.aiTemperature.value = String(cfg.temperature ?? 0.1);
    if (dom.aiReviewScope) dom.aiReviewScope.value = String(cfg.review_scope || 'ambiguous_or_high');
    if (dom.aiMaxReviews) dom.aiMaxReviews.value = String(cfg.max_reviews_per_scan ?? 20);
    if (dom.aiCacheEnabled) dom.aiCacheEnabled.checked = cfg.cache_enabled !== false;
    if (dom.aiApiKey) {
        dom.aiApiKey.value = '';
        if (cfg.api_key_set) {
            settingsState.aiKeySet = true;
            dom.aiApiKey.placeholder = cfg.api_key_hint ? `${cfg.api_key_hint} (saved)` : 'API key already configured';
        } else {
            settingsState.aiKeySet = false;
            dom.aiApiKey.placeholder = 'sk-...';
        }
    }
    if (dom.aiClearKey) dom.aiClearKey.checked = false;
    if (dom.aiProviderHint) dom.aiProviderHint.textContent = getAiProviderHint(provider);
}

function collectAiSettingsPayload() {
    const provider = String(dom.aiProvider?.value || 'ollama');
    const timeoutValue = Number(dom.aiTimeout?.value || 20);
    const temperatureValue = Number(dom.aiTemperature?.value || 0.1);
    const payload = {
        enabled: Boolean(dom.aiEnabled?.checked),
        verify_findings: Boolean(dom.aiVerifyFindings?.checked),
        provider,
        model: (dom.aiModel?.value || '').trim(),
        endpoint: (dom.aiEndpoint?.value || '').trim(),
        timeout_seconds: Number.isFinite(timeoutValue) ? timeoutValue : 20,
        temperature: Number.isFinite(temperatureValue) ? temperatureValue : 0.1,
        review_scope: String(dom.aiReviewScope?.value || 'ambiguous_or_high'),
        max_reviews_per_scan: Number.isFinite(Number(dom.aiMaxReviews?.value))
            ? Number(dom.aiMaxReviews?.value)
            : 20,
        cache_enabled: Boolean(dom.aiCacheEnabled?.checked),
        clear_api_key: Boolean(dom.aiClearKey?.checked),
    };
    const apiKey = (dom.aiApiKey?.value || '').trim();
    if (apiKey) payload.api_key = apiKey;
    return payload;
}

function handleAiProviderChange() {
    const provider = String(dom.aiProvider?.value || 'ollama');
    const defaults = aiProviderDefaults(provider);
    if (dom.aiProviderHint) dom.aiProviderHint.textContent = getAiProviderHint(provider);

    if (dom.aiModel && !dom.aiModel.value.trim()) dom.aiModel.value = defaults.model;
    if (dom.aiEndpoint && !dom.aiEndpoint.value.trim()) dom.aiEndpoint.value = defaults.endpoint;
}

function bindAiSettingsHandlers() {
    dom.aiProvider?.addEventListener('change', handleAiProviderChange);
    dom.aiClearKey?.addEventListener('change', () => {
        if (!dom.aiClearKey.checked) return;
        if (dom.aiApiKey) dom.aiApiKey.value = '';
    });

    dom.btnAiSave?.addEventListener('click', async () => {
        const payload = collectAiSettingsPayload();
        setAiStatus('Saving...', '');
        try {
            await apiRequest('POST', '/api/config', { ai_agent: payload });
            setAiStatus('AI settings saved.', 'ok');
            const cfg = await apiRequest('GET', '/api/config');
            applyAiSettingsToForm(cfg.ai_agent || {});
        } catch (e) {
            setAiStatus(`Error: ${e.message}`, 'warn');
        }
    });

    dom.btnAiTest?.addEventListener('click', async () => {
        const payload = collectAiSettingsPayload();
        setAiStatus('Testing connection...', '');
        try {
            const res = await apiRequest('POST', '/api/ai/test', { config: payload });
            const result = (res && typeof res === 'object' && res.result && typeof res.result === 'object')
                ? res.result
                : (res && typeof res === 'object' ? res : {});
            const latency = Number(result.latency_ms);
            const latencyTxt = Number.isFinite(latency) ? `${latency}ms` : 'n/a';
            if (result.ok) {
                setAiStatus(`Connected (${result.provider || 'ai'}/${result.model || 'default'}) ${latencyTxt}`, 'ok');
            } else {
                const reason = String(result.message || result.raw_preview || 'Connected but provider returned non-JSON output.');
                setAiStatus(`Connected but non-JSON response (${latencyTxt}). ${reason}`, 'warn');
            }
        } catch (e) {
            setAiStatus(`Test failed: ${e.message}`, 'warn');
        }
    });

    dom.btnAiClearCache?.addEventListener('click', async () => {
        setAiStatus('Clearing AI cache...', '');
        try {
            await apiRequest('POST', '/api/ai/cache/clear', {});
            setAiStatus('AI cache cleared.', 'ok');
        } catch (e) {
            setAiStatus(`Cache clear failed: ${e.message}`, 'warn');
        }
    });
}

async function loadSettings() {
    try {
        const cfg = await apiRequest('GET', '/api/config');
        const portInput = $('#settings-proxy-port');
        if (portInput) portInput.value = cfg.proxy_port || 8080;
        state.proxyPort = Number(cfg.proxy_port || state.proxyPort || 8080);
        updateProxyStatus();
        applyAiSettingsToForm(cfg.ai_agent || {});
        handleAiProviderChange();
        renderCustomTools(cfg.custom_tools || {});
        settingsState.loaded = true;
    } catch (e) {
        console.error('Failed to load settings:', e);
    }
}

function renderCustomTools(tools) {
    const list = $('#custom-tools-list');
    if (!list) return;

    const entries = Object.entries(tools);
    if (entries.length === 0) {
        list.innerHTML = '<div class="empty-state"><span class="empty-state__text">No custom tools configured yet.</span></div>';
        return;
    }

    list.innerHTML = '';
    for (const [name, tool] of entries) {
        const card = document.createElement('div');
        card.className = 'settings-tool-card';
        card.innerHTML = `
            <div class="settings-tool-card__info">
                <div class="settings-tool-card__name">${escHtml(name)}</div>
                <div class="settings-tool-card__cmd">${escHtml(tool.command)} ${escHtml(tool.args_template || '')}</div>
                ${tool.description ? `<div class="settings-tool-card__desc">${escHtml(tool.description)}</div>` : ''}
            </div>
            <div class="settings-tool-card__actions">
                <button class="btn btn--ghost btn--xs" data-tool-edit="${escHtml(name)}" title="Edit tool">
                    <svg viewBox="0 0 24 24" width="14" height="14" stroke="currentColor" stroke-width="2" fill="none">
                        <path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"></path>
                        <path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"></path>
                    </svg>
                </button>
                <button class="btn--icon-danger" data-tool-delete="${escHtml(name)}" title="Delete tool">
                    <svg viewBox="0 0 24 24" width="16" height="16" stroke="currentColor" stroke-width="2" fill="none">
                        <polyline points="3 6 5 6 21 6"></polyline>
                        <path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"></path>
                    </svg>
                </button>
            </div>
        `;

        // Edit handler
        card.querySelector('[data-tool-edit]').addEventListener('click', () => {
            const form = $('#tool-form');
            if (!form) return;
            form.style.display = 'block';
            settingsState.editingTool = name;
            $('#tool-form-name').value = name;
            $('#tool-form-name').disabled = true; // Can't rename
            $('#tool-form-command').value = tool.command || '';
            $('#tool-form-description').value = tool.description || '';
            $('#tool-form-category').value = tool.category || 'custom';
            $('#tool-form-args').value = tool.args_template || '{target}';
            $('#tool-form-requires-target').checked = tool.requires_target !== false;
            form.scrollIntoView({ behavior: 'smooth', block: 'start' });
        });

        // Delete handler
        card.querySelector('[data-tool-delete]').addEventListener('click', async () => {
            if (!confirm(`Delete custom tool "${name}"?`)) return;
            try {
                await apiRequest('DELETE', `/api/tools/custom/${name}`);
                loadSettings();
                loadTools();
            } catch (e) {
                console.error('Failed to delete tool:', e);
            }
        });

        list.appendChild(card);
    }
}

// Proxy port save
const btnSavePort = $('#btn-save-proxy-port');
if (btnSavePort) {
    btnSavePort.addEventListener('click', async () => {
        const portInput = $('#settings-proxy-port');
        const status = $('#settings-port-status');
        const port = parseInt(portInput.value);

        if (isNaN(port) || port < 1024 || port > 65535) {
            status.textContent = 'Invalid port (1024-65535)';
            status.className = 'settings-note settings-note--warn';
            return;
        }

        try {
            const res = await apiRequest('POST', '/api/config', { proxy_port: port });
            state.proxyPort = port;
            updateProxyStatus();
            if (res.restart_needed) {
                status.textContent = '✓ Saved — restart required to apply runtime proxy';
                status.className = 'settings-note settings-note--warn';
            } else {
                status.textContent = '✓ No change';
                status.className = 'settings-note settings-note--ok';
            }
        } catch (e) {
            status.textContent = 'Error: ' + e.message;
            status.className = 'settings-note settings-note--warn';
        }
    });
}

// Add tool form toggle
const btnShowAddTool = $('#btn-show-add-tool');
const toolForm = $('#tool-form');
const btnCancelTool = $('#btn-cancel-tool');

if (btnShowAddTool) {
    btnShowAddTool.addEventListener('click', () => {
        toolForm.style.display = 'block';
        settingsState.editingTool = null;
        // Clear form
        $('#tool-form-name').value = '';
        $('#tool-form-command').value = '';
        $('#tool-form-description').value = '';
        $('#tool-form-category').value = 'custom';
        $('#tool-form-args').value = '{target}';
        $('#tool-form-requires-target').checked = true;
        $('#tool-form-name').disabled = false;
    });
}

if (btnCancelTool) {
    btnCancelTool.addEventListener('click', () => {
        toolForm.style.display = 'none';
    });
}

// Save tool
const btnSaveTool = $('#btn-save-tool');
if (btnSaveTool) {
    btnSaveTool.addEventListener('click', async () => {
        const name = $('#tool-form-name').value.trim();
        const command = $('#tool-form-command').value.trim();

        if (!name || !command) {
            alert('Name and Command are required.');
            return;
        }

        const payload = {
            name,
            command,
            description: $('#tool-form-description').value.trim(),
            category: $('#tool-form-category').value.trim() || 'custom',
            args_template: $('#tool-form-args').value.trim() || '{target}',
            requires_target: $('#tool-form-requires-target').checked,
        };

        try {
            if (settingsState.editingTool) {
                await apiRequest('PUT', `/api/tools/custom/${settingsState.editingTool}`, payload);
            } else {
                await apiRequest('POST', '/api/tools/custom', payload);
            }
            toolForm.style.display = 'none';
            loadSettings();
            loadTools();  // Refresh main Tools dropdown
        } catch (e) {
            alert('Error: ' + (e.message || 'Failed to save tool'));
        }
    });
}

// Load settings when tab is opened
// We hook into the tab click event
const settingsTabBtn = $$('.tab[data-tab="settings"]')[0];
if (settingsTabBtn) {
    settingsTabBtn.addEventListener('click', () => {
        if (!settingsState.loaded) loadSettings();
    });
}

// ══════════════════════════════════════════════════════════════════
// INTRUDER
// ══════════════════════════════════════════════════════════════════

function sendToIntruder(request) {
    $$('.tab[data-tab="intruder"]')[0].click();
    if (dom.intruderTarget) dom.intruderTarget.value = request.url;

    const raw = buildRawRequest(
        request.method,
        request.url,
        request.headers || request.request_headers,
        request.body || request.request_body
    );
    if (dom.intruderRawRequest) dom.intruderRawRequest.value = raw;
    updatePositionCount();
    renderIntruderRequestPreview();
    scheduleWorkspaceSave();
}

// Payload type switching
$('#intruder-payload-type')?.addEventListener('change', (e) => {
    const type = e.target.value;
    const listGroup = $('#intruder-payload-list-group');
    const numGroup = $('#intruder-payload-numbers-group');
    const wlGroup = $('#intruder-payload-wordlist-group');

    if (listGroup) listGroup.style.display = type === 'simple_list' ? 'block' : 'none';
    if (numGroup) numGroup.style.display = type === 'numbers' ? 'block' : 'none';
    if (wlGroup) wlGroup.style.display = type === 'wordlist' ? 'block' : 'none';
});

// Load system wordlist from path
$('#btn-load-wordlist')?.addEventListener('click', async () => {
    const pathInput = $('#intruder-wordlist-path');
    const status = $('#wordlist-load-status');
    const path = pathInput?.value.trim();
    if (!path) {
        if (status) { status.textContent = 'Enter a file path'; status.style.color = 'var(--danger)'; }
        return;
    }
    try {
        if (status) { status.textContent = 'Loading...'; status.style.color = 'var(--text-muted)'; }
        const data = await apiRequest('GET', `/api/intruder/wordlist?path=${encodeURIComponent(path)}`);
        // Switch to simple_list mode and populate textarea
        const payloadType = $('#intruder-payload-type');
        if (payloadType) {
            payloadType.value = 'simple_list';
            payloadType.dispatchEvent(new Event('change'));
        }
        const textarea = $('#intruder-payloads');
        if (textarea) textarea.value = data.lines.join('\n');
        if (status) { status.textContent = `✓ Loaded ${data.count} lines`; status.style.color = 'var(--success)'; }
    } catch (e) {
        if (status) { status.textContent = `Error: ${e.message || 'Failed to load'}`; status.style.color = 'var(--danger)'; }
    }
});

// Mark selection as position
$('#btn-intruder-mark')?.addEventListener('click', () => {
    const textarea = dom.intruderRawRequest;
    if (!textarea) return;

    const start = textarea.selectionStart;
    const end = textarea.selectionEnd;
    if (start === end) return;

    const val = textarea.value;
    const selected = val.substring(start, end);
    const newVal = val.substring(0, start) + '\u00A7' + selected + '\u00A7' + val.substring(end);
    textarea.value = newVal;
    updatePositionCount();
});

// Clear all position markers
$('#btn-intruder-clear')?.addEventListener('click', () => {
    if (!dom.intruderRawRequest) return;
    dom.intruderRawRequest.value = dom.intruderRawRequest.value.replace(/\u00A7/g, '');
    updatePositionCount();
    renderIntruderRequestPreview();
    scheduleWorkspaceSave();
});

// Auto-detect positions
$('#btn-intruder-auto')?.addEventListener('click', () => {
    if (!dom.intruderRawRequest) return;
    let raw = dom.intruderRawRequest.value.replace(/\u00A7/g, '');

    // Auto-detect common injection points in the body
    const idx = raw.indexOf('\n\n');
    if (idx >= 0) {
        const headerPart = raw.substring(0, idx);
        let body = raw.substring(idx + 2);

        // URL-encoded body: key=value&key=value
        if (body.includes('=')) {
            body = body.replace(/=([^&]*)/g, (match, val) => `=\u00A7${val}\u00A7`);
        }

        raw = headerPart + '\n\n' + body;
    }

    // Also mark URL parameters
    const lines = raw.split('\n');
    if (lines[0] && lines[0].includes('?')) {
        lines[0] = lines[0].replace(/=([^&\s]*)/g, (match, val) => `=\u00A7${val}\u00A7`);
        raw = lines.join('\n');
    }

    dom.intruderRawRequest.value = raw;
    updatePositionCount();
    renderIntruderRequestPreview();
    scheduleWorkspaceSave();
});

function updatePositionCount() {
    if (!dom.intruderRawRequest) return;
    const markers = (dom.intruderRawRequest.value.match(/\u00A7/g) || []).length;
    const positions = Math.floor(markers / 2);
    const el = $('#intruder-position-count');
    if (el) el.textContent = `Positions: ${positions}`;
}

dom.intruderRawRequest?.addEventListener('input', updatePositionCount);
dom.intruderRawRequest?.addEventListener('input', () => {
    renderIntruderRequestPreview();
    scheduleWorkspaceSave();
});

// Get payloads based on type
async function getPayloads() {
    const type = $('#intruder-payload-type')?.value || 'simple_list';

    if (type === 'simple_list') {
        const raw = dom.intruderPayloads?.value || '';
        return raw.split('\n').filter(l => l.trim() !== '');
    }

    if (type === 'numbers') {
        const from = parseInt($('#intruder-num-from')?.value || '0');
        const to = parseInt($('#intruder-num-to')?.value || '100');
        const step = parseInt($('#intruder-num-step')?.value || '1');
        const payloads = [];
        for (let i = from; i <= to; i += step) {
            payloads.push(String(i));
        }
        return payloads;
    }

    if (type === 'wordlist') {
        const wlPath = $('#intruder-wordlist')?.value;
        if (!wlPath) return [];
        try {
            const data = await apiRequest('GET', `/api/intruder/wordlist?path=${encodeURIComponent(wlPath)}`);
            return data.lines || [];
        } catch (e) {
            console.error('Failed to load wordlist:', e);
            return [];
        }
    }

    return [];
}

// Start attack
$('#btn-intruder-start')?.addEventListener('click', async () => {
    if (state.intruder.running) return;

    const rawTemplate = dom.intruderRawRequest?.value || '';
    const payloads = await getPayloads();

    if (payloads.length === 0) {
        dom.intruderProgress.textContent = 'No payloads configured.';
        return;
    }

    // Extract positions
    const markers = [];
    let tempRaw = rawTemplate;
    let searchFrom = 0;
    while (true) {
        const start = tempRaw.indexOf('\u00A7', searchFrom);
        if (start === -1) break;
        const end = tempRaw.indexOf('\u00A7', start + 1);
        if (end === -1) break;
        markers.push({ start, end, original: tempRaw.substring(start + 1, end) });
        searchFrom = end + 1;
    }

    if (markers.length === 0) {
        dom.intruderProgress.textContent = 'No positions marked.';
        return;
    }

    state.intruder.running = true;
    state.intruder.results = [];
    state.intruder.abortController = new AbortController();
    dom.intruderResults.innerHTML = '';

    $('#btn-intruder-start').style.display = 'none';
    $('#btn-intruder-stop').style.display = 'inline-flex';

    const threads = parseInt($('#intruder-threads')?.value || '5');
    const attackType = $('#intruder-attack-type')?.value || 'sniper';

    let requestQueue = [];

    // Build request queue based on attack type
    if (attackType === 'sniper') {
        // One position at a time, each payload
        for (const payload of payloads) {
            for (let i = 0; i < markers.length; i++) {
                requestQueue.push({ payloads: markers.map((m, idx) => idx === i ? payload : m.original), displayPayload: payload });
            }
        }
    } else if (attackType === 'battering_ram') {
        // Same payload in all positions
        for (const payload of payloads) {
            requestQueue.push({ payloads: markers.map(() => payload), displayPayload: payload });
        }
    } else if (attackType === 'pitchfork') {
        // Each payload set maps to position (for now, single set = all positions get same)
        for (const payload of payloads) {
            requestQueue.push({ payloads: markers.map(() => payload), displayPayload: payload });
        }
    } else {
        // cluster_bomb — similar to sniper for single set
        for (const payload of payloads) {
            requestQueue.push({ payloads: markers.map(() => payload), displayPayload: payload });
        }
    }

    const total = requestQueue.length;
    let completed = 0;

    dom.intruderProgress.textContent = `0 / ${total}`;
    dom.intruderResultCount.textContent = '0';

    // Worker function
    async function processRequest(item, index) {
        if (state.intruder.abortController.signal.aborted) return;

        // Replace markers with payloads
        let raw = rawTemplate;
        let offset = 0;
        for (let i = 0; i < markers.length; i++) {
            const m = markers[i];
            const payload = item.payloads[i];
            const before = raw.substring(0, m.start + offset);
            const after = raw.substring(m.end + 1 + offset);
            raw = before + payload + after;
            offset += payload.length - (m.end - m.start + 1);
        }

        const parsed = parseRawRequest(raw);
        const normalizedUrl = normalizeParsedRequestUrl(parsed, dom.intruderTarget?.value || '');

        try {
            if (!normalizedUrl) {
                throw new Error('Invalid request line: missing URL.');
            }
            const startTime = performance.now();
            const res = await apiRequest('POST', '/api/repeater/send', {
                method: parsed.method,
                url: normalizedUrl,
                headers: parsed.headers,
                body: parsed.body || null,
            });
            const elapsed = performance.now() - startTime;

            const result = {
                index: completed + 1,
                payload: item.displayPayload,
                status_code: res.status_code,
                length: res.body ? res.body.length : 0,
                time: Math.round(res.duration_ms || elapsed),
                request_raw: raw,
                response: res,
            };

            state.intruder.results.push(result);
            appendIntruderResult(result);
        } catch (err) {
            const result = {
                index: completed + 1,
                payload: item.displayPayload,
                status_code: 0,
                length: 0,
                time: 0,
                error: err.message,
            };
            state.intruder.results.push(result);
            appendIntruderResult(result);
        }

        completed++;
        dom.intruderProgress.textContent = `${completed} / ${total}`;
        dom.intruderResultCount.textContent = String(state.intruder.results.length);
    }

    // Execute with concurrency control
    const executing = new Set();
    for (let i = 0; i < requestQueue.length; i++) {
        if (state.intruder.abortController.signal.aborted) break;

        const p = processRequest(requestQueue[i], i).then(() => {
            executing.delete(p);
        });
        executing.add(p);

        if (executing.size >= threads) {
            await Promise.race(executing);
        }
    }
    await Promise.allSettled(executing);

    // Done
    state.intruder.running = false;
    $('#btn-intruder-start').style.display = 'inline-flex';
    $('#btn-intruder-stop').style.display = 'none';
    dom.intruderProgress.textContent = `Done: ${completed} / ${total}`;
});

// Stop attack
$('#btn-intruder-stop')?.addEventListener('click', () => {
    if (state.intruder.abortController) {
        state.intruder.abortController.abort();
    }
    state.intruder.running = false;
    $('#btn-intruder-start').style.display = 'inline-flex';
    $('#btn-intruder-stop').style.display = 'none';
    dom.intruderProgress.textContent += ' (Stopped)';
});

function appendIntruderResult(result) {
    // Remove empty state
    const empty = dom.intruderResults.querySelector('.empty-state');
    if (empty) empty.remove();

    const el = document.createElement('div');
    el.className = 'intruder-result-row';

    const statusClass = getStatusClass(result.status_code);

    el.innerHTML = `
    <span class="col-num">${result.index}</span>
    <span class="col-payload" title="${escHtml(result.payload)}">${escHtml(result.payload)}</span>
    <span class="col-status ${statusClass}">${result.status_code || 'ERR'}</span>
    <span class="col-length">${result.length}</span>
    <span class="col-time">${result.time}ms</span>
  `;

    el.addEventListener('click', () => {
        dom.intruderResults.querySelectorAll('.intruder-result-row--active').forEach(x => x.classList.remove('intruder-result-row--active'));
        el.classList.add('intruder-result-row--active');
        showIntruderDetail(result);
    });

    dom.intruderResults.appendChild(el);
    dom.intruderResults.scrollTop = dom.intruderResults.scrollHeight;
}


function showIntruderDetail(result) {
    state.intruder.selectedResult = result;

    // Safety check for DOM reference
    if (!dom.intruderDetailModal) {
        dom.intruderDetailModal = $('#intruder-detail-modal');
        dom.intruderModalRequest = $('#intruder-modal-request');
        dom.intruderModalResponse = $('#intruder-modal-response');
    }

    if (dom.intruderDetailModal) {
        dom.intruderDetailModal.style.display = 'flex';
    } else {
        console.error('Intruder detail modal not found in DOM');
        alert('Error: Modal not found');
        return;
    }

    // Request content
    let reqText = `Payload: ${result.payload}\n`;
    if (result.response) {
        reqText += `Status: ${result.response.status_code}\n`;
        reqText += `Duration: ${result.response.duration_ms || result.time}ms\n`;
    }
    if (result.error) {
        reqText += `Error: ${result.error}\n`;
    }
    // Add raw request body if available (or construct it)
    // For now showing metadata + payload as "Request" view
    // Ideally we reconstruct the full HTTP request using the template and payload

    dom.intruderModalRequest.textContent = result.request_raw || reqText;

    // Response content
    if (result.response) {
        let resText = '';
        if (result.response.headers) {
            for (const [k, v] of Object.entries(result.response.headers)) {
                resText += `${k}: ${v}\n`;
            }
        }
        resText += '\n';
        if (result.response.body) {
            resText += result.response.body;
        }
        dom.intruderModalResponse.textContent = resText;
    } else {
        dom.intruderModalResponse.textContent = '(No response data)';
    }

    // Reset tabs
    $$('.detail-tab[data-intruder-modal]').forEach(t => t.classList.remove('detail-tab--active'));
    $$('.detail-tab[data-intruder-modal="request"]')[0].classList.add('detail-tab--active');
    dom.intruderModalRequest.style.display = 'block';
    dom.intruderModalResponse.style.display = 'none';
}

function initModalHandlers() {
    // Re-bind if they were null at init
    if (!dom.btnToolHelp) dom.btnToolHelp = $('#btn-tool-help');
    if (!dom.toolHelpModal) dom.toolHelpModal = $('#tool-help-modal');
    if (!dom.btnCloseToolHelp) dom.btnCloseToolHelp = $('#btn-close-tool-help');
    if (!dom.btnAiHelp) dom.btnAiHelp = $('#btn-ai-help');
    if (!dom.aiHelpModal) dom.aiHelpModal = $('#ai-help-modal');
    if (!dom.btnCloseAiHelp) dom.btnCloseAiHelp = $('#btn-close-ai-help');
    if (!dom.intruderDetailModal) dom.intruderDetailModal = $('#intruder-detail-modal');
    if (!dom.btnCloseIntruderModal) dom.btnCloseIntruderModal = $('#btn-close-intruder-modal');
    if (!dom.btnIntruderToRepeater) dom.btnIntruderToRepeater = $('#btn-intruder-to-repeater');
    if (!dom.btnIntruderToTools) dom.btnIntruderToTools = $('#btn-intruder-to-tools');

    // Tool Help
    dom.btnToolHelp?.addEventListener('click', () => {
        dom.toolHelpModal.style.display = 'flex';
    });
    dom.btnCloseToolHelp?.addEventListener('click', () => {
        dom.toolHelpModal.style.display = 'none';
    });
    dom.toolHelpModal?.addEventListener('click', (e) => {
        if (e.target === dom.toolHelpModal) dom.toolHelpModal.style.display = 'none';
    });

    // AI Help
    dom.btnAiHelp?.addEventListener('click', () => {
        if (dom.aiHelpModal) dom.aiHelpModal.style.display = 'flex';
    });
    dom.btnCloseAiHelp?.addEventListener('click', () => {
        if (dom.aiHelpModal) dom.aiHelpModal.style.display = 'none';
    });
    dom.aiHelpModal?.addEventListener('click', (e) => {
        if (e.target === dom.aiHelpModal) dom.aiHelpModal.style.display = 'none';
    });

    // Intruder Modal
    dom.btnCloseIntruderModal?.addEventListener('click', () => {
        dom.intruderDetailModal.style.display = 'none';
    });
    dom.intruderDetailModal?.addEventListener('click', (e) => {
        if (e.target === dom.intruderDetailModal) dom.intruderDetailModal.style.display = 'none';
    });


    // Modal Tabs
    $$('.detail-tab[data-intruder-modal]').forEach(tab => {
        tab.addEventListener('click', () => {
            $$('.detail-tab[data-intruder-modal]').forEach(t => t.classList.remove('detail-tab--active'));
            tab.classList.add('detail-tab--active');
            const which = tab.dataset.intruderModal;
            dom.intruderModalRequest.style.display = which === 'request' ? 'block' : 'none';
            dom.intruderModalResponse.style.display = 'none';
            if (which === 'response') dom.intruderModalResponse.style.display = 'block';
        });
    });

    // Intruder Actions
    dom.btnIntruderToRepeater?.addEventListener('click', () => {
        const result = state.intruder.selectedResult;
        if (!result) return;

        if (result.request_raw) {
            const parsed = parseRawRequest(result.request_raw);
            const normalizedUrl = normalizeParsedRequestUrl(parsed, dom.intruderTarget?.value || '');
            sendToRepeater({
                method: parsed.method || 'GET',
                url: normalizedUrl || (dom.intruderTarget?.value || ''),
                headers: parsed.headers || {},
                body: parsed.body || '',
            });
        } else {
            sendToRepeater({
                method: 'GET',
                url: dom.intruderTarget?.value || '',
                headers: {},
                body: '',
            });
        }
        dom.intruderDetailModal.style.display = 'none';
    });

    dom.btnIntruderToTools?.addEventListener('click', () => {
        const result = state.intruder.selectedResult;
        if (!result) return;
        if (result.request_raw) {
            const parsed = parseRawRequest(result.request_raw);
            const normalizedUrl = normalizeParsedRequestUrl(parsed, dom.intruderTarget?.value || '');
            dom.toolTarget.value = normalizedUrl || dom.intruderTarget.value || '';
        } else {
            dom.toolTarget.value = dom.intruderTarget.value || '';
        }
        $$('.tab[data-tab="tools"]')[0].click();
        dom.intruderDetailModal.style.display = 'none';
    });
}


function renderIntruderResults() {
    dom.intruderResults.innerHTML = '';
    for (const result of state.intruder.results) {
        appendIntruderResult(result);
    }
    dom.intruderResultCount.textContent = String(state.intruder.results.length);
}
