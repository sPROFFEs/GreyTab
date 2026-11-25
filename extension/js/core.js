/**
 * PentestBrowser - Side Panel Logic
 * Full rewrite: Unified Raw views, Intruder, Project Save/Load
 */

const API_BASE = 'http://127.0.0.1:8443';
const VIEW_ID = `${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;
const uiSyncChannel = typeof BroadcastChannel !== 'undefined'
    ? new BroadcastChannel('greytab_ui_sync')
    : null;
let isApplyingUiSync = false;

const state = {
    connected: false,
    sessionId: null,
    sessionName: null,
    proxyRunning: false,
    proxyPort: 8080,
    memoryMb: 0,
    activeTab: 'proxy',
    selectedLogId: null,
    currentLog: null,
    currentRunId: null,
    stats: { requests: 0, tools: 0, findings: 0 },
    // Intruder
    intruder: {
        running: false,
        results: [],
        abortController: null,
        selectedResult: null,
    },
    repeater: {
        tabs: [],
        activeTabId: null,
        tabCounter: 1,
    },
    scanner: {
        running: false,
        findings: [],
        activitySeq: 0,
        activities: [],
        requestLog: [],
        testLog: [],
        treeSeen: new Set(),
        treeRoot: null,
        treeExpanded: new Set(),
        passiveEnabled: false,
    },
    intercept: {
        requestQueue: [],
        responseQueue: [],
        currentRequestId: null,
        currentResponseId: null,
    },
};

// ══════════════════════════════════════════════════════════════════
// API Helper
// ══════════════════════════════════════════════════════════════════

function apiRequest(method, endpoint, body) {
    return new Promise((resolve, reject) => {
        chrome.runtime.sendMessage(
            { type: 'api_request', data: { method, endpoint, body } },
            (response) => {
                if (chrome.runtime.lastError) {
                    reject(new Error(chrome.runtime.lastError.message));
                    return;
                }
                if (!response || !response.success) {
                    reject(new Error(response?.error || 'Request failed'));
                    return;
                }
                resolve(response.data);
            }
        );
    });
}

function wsSend(data) {
    chrome.runtime.sendMessage({ type: 'ws_send', data });
}

const viewParams = new URLSearchParams(location.search);
const isWorkspaceWindow = viewParams.get('view') === 'workspace';
const PANEL_STORAGE_KEY = 'greytab_workspace_state_v1';
const WORKSPACE_STORAGE_KEY = isWorkspaceWindow ? 'greytab_desktop_state_v1' : PANEL_STORAGE_KEY;
const ACTIVE_TOOL_KEY = isWorkspaceWindow ? 'greytab_desktop_tool' : 'greytab_panel_tool';
const toolTabs = document.querySelector('.workspace-layout > .tabs');
const desktopNavigation = window.matchMedia('(min-width: 1060px)');
document.body.classList.toggle('workspace-window', isWorkspaceWindow);
if (isWorkspaceWindow) {
    document.getElementById('btn-external').hidden = true;
    document.getElementById('btn-focus-browser').hidden = false;
}
let workspaceSaveTimer = null;

function scheduleWorkspaceSave(delayMs = 2000) {
    if (!chrome?.storage?.local) return;
    if (workspaceSaveTimer) return;
    workspaceSaveTimer = setTimeout(() => {
        workspaceSaveTimer = null;
        persistWorkspaceState().catch(() => { });
    }, delayMs);
}

function snapshotWorkspaceState() {
    const intruderResults = Array.isArray(state.intruder.results) ? state.intruder.results.slice(-200) : [];
    const scannerFindings = Array.isArray(state.scanner.findings) ? state.scanner.findings.slice(0, 3000) : [];
    const scannerActivity = Array.isArray(state.scanner.activities) ? state.scanner.activities.slice(-2000) : [];
    const scannerRequestLog = Array.isArray(state.scanner.requestLog) ? state.scanner.requestLog.slice(-4000) : [];
    const scannerTestLog = Array.isArray(state.scanner.testLog) ? state.scanner.testLog.slice(-500) : [];

    return {
        ts: Date.now(),
        active_tab: state.activeTab || 'proxy',
        repeater_state: {
            active_tab_id: state.repeater.activeTabId,
            tabs: (state.repeater.tabs || []).map((t) => ({
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
        },
        intruder_state: {
            target: dom.intruderTarget?.value || '',
            raw_request: dom.intruderRawRequest?.value || '',
            payloads: dom.intruderPayloads?.value || '',
            attack_type: $('#intruder-attack-type')?.value || 'sniper',
            results: intruderResults,
        },
        scanner_state: {
            form: getScannerFormState(),
            findings: scannerFindings,
            request_log: scannerRequestLog,
            activity: scannerActivity,
            test_log: scannerTestLog,
            tree: serializeScannerTreeNode(state.scanner.treeRoot),
            tree_expanded: Array.from(state.scanner.treeExpanded || []),
        },
    };
}

async function persistWorkspaceState() {
    if (!chrome?.storage?.local) return;
    persistActiveRepeaterEditor();
    const snapshot = snapshotWorkspaceState();
    await chrome.storage.local.set({ [WORKSPACE_STORAGE_KEY]: snapshot });
}

async function restoreWorkspaceState() {
    if (!chrome?.storage?.local) return;
    const data = await chrome.storage.local.get([PANEL_STORAGE_KEY, WORKSPACE_STORAGE_KEY, ACTIVE_TOOL_KEY]);
    const ws = data[WORKSPACE_STORAGE_KEY] || data[PANEL_STORAGE_KEY];
    if (!ws || typeof ws !== 'object') {
        if (data?.[ACTIVE_TOOL_KEY]) activateTab(data[ACTIVE_TOOL_KEY]);
        return;
    }

    const rep = ws.repeater_state;
    if (rep && typeof rep === 'object' && Array.isArray(rep.tabs) && rep.tabs.length > 0) {
        state.repeater.tabs = [];
        state.repeater.activeTabId = null;
        state.repeater.tabCounter = 1;
        rep.tabs.forEach((t) => createRepeaterTab(t));
        state.repeater.activeTabId = rep.active_tab_id || state.repeater.tabs[0]?.id || null;
        activateRepeaterTab(state.repeater.activeTabId, false);
    }

    const intr = ws.intruder_state;
    if (intr && typeof intr === 'object') {
        if (dom.intruderTarget) dom.intruderTarget.value = intr.target || '';
        if (dom.intruderRawRequest) dom.intruderRawRequest.value = intr.raw_request || '';
        if (dom.intruderPayloads) dom.intruderPayloads.value = intr.payloads || '';
        if ($('#intruder-attack-type')) $('#intruder-attack-type').value = intr.attack_type || 'sniper';
        state.intruder.results = Array.isArray(intr.results) ? intr.results.slice(0, 2000) : [];
        renderIntruderResults();
    }

    const ss = ws.scanner_state;
    if (ss && typeof ss === 'object') {
        resetScannerPanels();
        if (ss.form) applyScannerFormState(ss.form);
        if (Array.isArray(ss.findings)) ss.findings.forEach((f) => addScannerFinding(f));
        if (Array.isArray(ss.request_log)) ss.request_log.forEach((r) => addScannerRequestLog(r));
        if (Array.isArray(ss.activity)) ss.activity.forEach((a) => appendScannerActivity(a));
        if (Array.isArray(ss.test_log)) ss.test_log.forEach((t) => addScannerTestLog(t));
        const restoredTree = deserializeScannerTreeNode(ss.tree);
        if (restoredTree) {
            state.scanner.treeRoot = restoredTree;
            state.scanner.treeExpanded = new Set(Array.isArray(ss.tree_expanded) ? ss.tree_expanded : ['root']);
            renderScannerTree();
        }
    }

    const activeTab = String(data[ACTIVE_TOOL_KEY] || ws.active_tab || '').trim();
    if (activeTab) activateTab(activeTab);
}

// ══════════════════════════════════════════════════════════════════
// DOM References
// ══════════════════════════════════════════════════════════════════

const $ = (sel) => document.querySelector(sel);
const $$ = (sel) => document.querySelectorAll(sel);

const dom = {
    wsIndicator: $('#ws-indicator'),
    proxyIndicator: $('#proxy-indicator'),
    memUsage: $('#mem-usage'),
    // Session
    landingPage: $('#landing-page'),
    appContainer: $('#app-container'),
    sessionName: $('#session-name'),
    sessionScope: $('#session-scope'),
    // Active Bar
    sessionActive: $('#session-active'),
    activeSessionName: $('#active-session-name'),
    statRequests: $('#stat-requests'),
    statTools: $('#stat-tools'),
    statFindings: $('#stat-findings'),
    // Lists
    requestList: $('#request-list'),
    findingsList: $('#findings-list'),
    // Forms
    toolSelect: $('#tool-select'),
    toolTarget: $('#tool-target'),
    toolWordlist: $('#tool-wordlist'),
    toolExtraArgs: $('#tool-extra-args'),
    toolRawCommand: $('#tool-raw-command'),
    toolOutput: $('#tool-output'),
    toolOutputHeader: $('#tool-output-header'),
    toolOutputName: $('#tool-output-name'),
    toolOutputStatus: $('#tool-output-status'),
    runningTools: $('#running-tools'),
    runningCount: $('#running-count'),
    // Detail
    requestDetail: $('#request-detail'),
    detailRequest: $('#detail-request'),
    detailResponse: $('#detail-response'),
    proxyStatus: $('#proxy-status'),
    proxyPort: $('#proxy-port'),
    btnClearTraffic: $('#btn-clear-traffic'),
    btnClearHistory: $('#btn-clear-history'),
    // Scanner
    scannerTarget: $('#scanner-target'),
    scannerDepth: $('#scanner-depth'),
    scannerDepthVal: $('#scanner-depth-val'),
    scannerProgress: $('#scanner-progress'),
    scannerProgressFill: $('#scanner-progress-fill'),
    scannerProgressText: $('#scanner-progress-text'),
    scannerStats: $('#scanner-stats'),
    scannerStage: $('#scanner-stage'),
    scannerQueue: $('#scanner-queue'),
    scannerRequestsCount: $('#scanner-requests-count'),
    scannerTests: $('#scanner-tests'),
    scannerRate: $('#scanner-rate'),
    scannerActivity: $('#scanner-activity'),
    scannerActivityList: $('#scanner-activity-list'),
    scannerFindings: $('#scanner-findings'),
    scannerRequestLog: $('#scanner-request-log'),
    scannerTestLog: $('#scanner-test-log'),
    scannerTree: $('#scanner-tree'),
    scannerCount: $('#scanner-finding-count'),
    scannerTestCount: $('#scanner-test-count'),
    scannerPassive: $('#scanner-passive'),
    scannerCrawlEnabled: $('#scanner-crawl-enabled'),
    scannerXssHeadless: $('#scanner-xss-headless'),
    scannerOastBase: $('#scanner-oast-base'),
    scannerAuthStatus: $('#scanner-auth-status'),
    btnScannerStart: $('#btn-scanner-start'),
    btnScannerStop: $('#btn-scanner-stop'),
    btnScannerDetach: $('#btn-scanner-detach'),
    // Proxy Editor — Raw
    interceptEditor: $('#intercept-editor'),
    editorRaw: $('#editor-raw'),
    requestInterceptMeta: $('#request-intercept-meta'),
    requestInterceptQueue: $('#request-intercept-queue'),
    btnForward: $('#btn-forward'),
    btnDrop: $('#btn-drop'),
    proxyIntercept: $('#proxy-intercept'),
    // Repeater — Raw
    repeaterTabbar: $('#repeater-tabbar'),
    btnRepeaterNewTab: $('#btn-repeater-new-tab'),
    btnRepeaterCloneTab: $('#btn-repeater-clone-tab'),
    btnRepeaterCloseTab: $('#btn-repeater-close-tab'),
    repeaterRawRequest: $('#repeater-raw-request'),
    repeaterReqPreview: $('#repeater-req-preview'),
    repeaterReqHighlight: $('#repeater-req-highlight'),
    repeaterResRaw: $('#repeater-res-raw'),
    repeaterResRender: $('#repeater-res-render'),
    repeaterStatus: $('#repeater-status'),
    repeaterTime: $('#repeater-time'),
    btnRepeaterSend: $('#btn-repeater-send'),
    btnExternal: $('#btn-external'),
    // Intruder
    intruderTarget: $('#intruder-target'),
    intruderRawRequest: $('#intruder-raw-request'),
    intruderReqPreview: $('#intruder-req-preview'),
    intruderPayloads: $('#intruder-payloads'),
    intruderResults: $('#intruder-results'),
    intruderResultCount: $('#intruder-result-count'),
    intruderProgress: $('#intruder-progress'),
    // Intercept bar
    interceptBar: $('#intercept-bar'),
    interceptDot: $('#intercept-dot'),
    interceptText: $('#intercept-text'),
    // Context menu
    ctxMenu: $('#ctx-menu'),
    repeaterTabMenu: $('#repeater-tab-menu'),
    // Tool description
    toolDescription: $('#tool-description'),

    // Modals - Scanner
    scannerDetailModal: $('#scanner-detail-modal'),
    btnCloseScannerModal: $('#btn-close-scanner-modal'),
    scannerModalType: $('#scanner-modal-type'),
    scannerModalSeverity: $('#scanner-modal-severity'),
    scannerModalUrl: $('#scanner-modal-url'),
    scannerModalParam: $('#scanner-modal-param'),
    scannerModalScore: $('#scanner-modal-score'),
    scannerModalConfirmed: $('#scanner-modal-confirmed'),
    scannerModalInsertion: $('#scanner-modal-insertion'),
    scannerModalEvidence: $('#scanner-modal-evidence'),
    scannerModalToolHint: $('#scanner-modal-tool-hint'),
    scannerModalRequest: $('#scanner-modal-request'),
    scannerModalResponse: $('#scanner-modal-response'),
    btnScannerToRepeater: $('#btn-scanner-to-repeater'),
    btnScannerToTools: $('#btn-scanner-to-tools'),
    btnScannerFeedbackTp: $('#btn-scanner-feedback-tp'),
    btnScannerFeedbackFp: $('#btn-scanner-feedback-fp'),

    // Modals - Intruder
    intruderDetailModal: $('#intruder-detail-modal'),
    btnCloseIntruderModal: $('#btn-close-intruder-modal'),
    intruderModalRequest: $('#intruder-modal-request'),
    intruderModalResponse: $('#intruder-modal-response'),
    btnIntruderToRepeater: $('#btn-intruder-to-repeater'),
    btnIntruderToTools: $('#btn-intruder-to-tools'),

    // Modals - Tools Help
    toolHelpModal: $('#tool-help-modal'),
    btnToolHelp: $('#btn-tool-help'),
    btnCloseToolHelp: $('#btn-close-tool-help'),
    // Modals - AI Help
    aiHelpModal: $('#ai-help-modal'),
    btnAiHelp: $('#btn-ai-help'),
    btnCloseAiHelp: $('#btn-close-ai-help'),

    // Response interception
    responseInterceptEditor: $('#response-intercept-editor'),
    editorResponseRaw: $('#editor-response-raw'),
    responseInterceptMeta: $('#response-intercept-meta'),
    responseInterceptQueue: $('#response-intercept-queue'),
    btnForwardResponse: $('#btn-forward-response'),
    btnDropResponse: $('#btn-drop-response'),
    proxyInterceptResponse: $('#proxy-intercept-response'),
    // Repeater - follow redirect
    repeaterFollowRedirect: $('#repeater-follow-redirect'),
    wordlistUploadInput: $('#wordlist-upload-input'),
    historyFilterHost: $('#history-filter-host'),
    historySearch: $('#history-search'),
    historyFilterStatus: $('#history-filter-status'),
    historyFilterMethod: $('#history-filter-method'),
    findingsBadge: $('#findings-badge'),
    passiveScanEnabled: $('#passive-scan-enabled'),
    historyFindingsPanel: $('#history-findings-panel'),
    historyFindingsList: $('#history-findings-list'),
    btnCloseFindingsModal: $('#btn-close-findings-modal'),
    btnAddFinding: $('#btn-add-finding'),
    // AI settings
    aiEnabled: $('#ai-enabled'),
    aiVerifyFindings: $('#ai-verify-findings'),
    aiProvider: $('#ai-provider'),
    aiModel: $('#ai-model'),
    aiEndpoint: $('#ai-endpoint'),
    aiApiKey: $('#ai-api-key'),
    aiClearKey: $('#ai-clear-key'),
    aiTimeout: $('#ai-timeout'),
    aiTemperature: $('#ai-temperature'),
    aiReviewScope: $('#ai-review-scope'),
    aiMaxReviews: $('#ai-max-reviews'),
    aiCacheEnabled: $('#ai-cache-enabled'),
    btnAiSave: $('#btn-ai-save'),
    btnAiTest: $('#btn-ai-test'),
    btnAiClearCache: $('#btn-ai-clear-cache'),
    aiStatus: $('#ai-status'),
    aiProviderHint: $('#ai-provider-hint'),
    // Scanner modal AI
    scannerModalAiVerdict: $('#scanner-modal-ai-verdict'),
    scannerModalAiConfidence: $('#scanner-modal-ai-confidence'),
    scannerModalAiReasoning: $('#scanner-modal-ai-reasoning'),
    btnScannerAiRecheck: $('#btn-scanner-ai-recheck'),
};

function broadcastUiSync(topic, payload) {
    if (!uiSyncChannel || isApplyingUiSync) return;
    uiSyncChannel.postMessage({ source: VIEW_ID, topic, payload, ts: Date.now() });
}

if (uiSyncChannel) {
    uiSyncChannel.onmessage = (event) => {
        const msg = event?.data || {};
        if (!msg || msg.source === VIEW_ID) return;

        isApplyingUiSync = true;
        try {
            if (msg.topic === 'scanner_form') {
                applyScannerFormState(msg.payload || {});
            } else if (msg.topic === 'scanner_state') {
                const payload = msg.payload || {};
                if (payload.running) {
                    setScannerState(true);
                    if (payload.progress) updateScannerProgress(payload.progress);
                } else {
                    setScannerState(false);
                }
            }
        } finally {
            isApplyingUiSync = false;
        }
    };
}

// ══════════════════════════════════════════════════════════════════
// External Window
// ══════════════════════════════════════════════════════════════════

function bindWindowAction(button, type, failure) {
    button.addEventListener('click', async () => {
        button.disabled = true;
        try {
            const result = await chrome.runtime.sendMessage({type});
            if (!result?.success) throw new Error(result?.error);
        } catch (error) {
            console.warn(failure, error);
            alert(failure);
        } finally {
            button.disabled = false;
        }
    });
}

bindWindowAction(dom.btnExternal, 'open_workspace', 'Could not open the GreyTab workspace.');
bindWindowAction($('#btn-focus-browser'), 'focus_browser', 'Could not focus the browser window.');

if (dom.btnScannerDetach) {
    dom.btnScannerDetach.addEventListener('click', () => {
        const url = chrome.runtime.getURL('sidepanel.html?detached=scanner');
        window.open(url, '_blank', 'width=1500,height=950');
    });
}

// ══════════════════════════════════════════════════════════════════
// Tab Navigation
// ══════════════════════════════════════════════════════════════════

function activateTab(tabId) {
    if (!tabId) return;
    const tabBtn = $(`.tab[data-tab="${CSS.escape(tabId)}"]`);
    const tabPanel = document.getElementById(`tab-${tabId}`);
    if (!tabBtn || !tabPanel) return;
    toolTabs.querySelectorAll('.tab').forEach(button => {
        const selected = button === tabBtn;
        button.classList.toggle('tab--active', selected);
        button.setAttribute('aria-selected', String(selected));
        button.tabIndex = selected ? 0 : -1;
    });
    $$('.tab-content').forEach(panel => panel.classList.remove('tab-content--active'));
    tabPanel.classList.add('tab-content--active');
    state.activeTab = tabId;
    tabBtn.scrollIntoView({block: 'nearest', inline: 'nearest'});

    if (tabId === 'requests') openHistory();
    if (tabId === 'tools') loadTools();
    if (tabId === 'autoscanner' && typeof refreshScanMacros === 'function') refreshScanMacros().catch(() => {});
    if (tabId === 'bookmarklets') {
        if (typeof loadBookmarklets === 'function') loadBookmarklets();
        if (typeof updateBookmarkletTargetInfo === 'function') updateBookmarkletTargetInfo();
    }
    if (tabId === 'settings') loadSettings();
}

function updateNavigationOrientation() {
    toolTabs.setAttribute('aria-orientation', isWorkspaceWindow && desktopNavigation.matches ? 'vertical' : 'horizontal');
    requestAnimationFrame(() => toolTabs.querySelector('.tab--active')?.scrollIntoView({block: 'nearest', inline: 'nearest'}));
}

updateNavigationOrientation();
desktopNavigation.addEventListener('change', updateNavigationOrientation);

const toolButtons = Array.from(toolTabs.querySelectorAll('.tab'));
for (const button of toolButtons) {
    const id = button.dataset.tab;
    const panel = document.getElementById(`tab-${id}`);
    button.id = `tool-${id}`;
    button.setAttribute('role', 'tab');
    button.setAttribute('aria-controls', panel.id);
    const selected = button.classList.contains('tab--active');
    button.setAttribute('aria-selected', String(selected));
    button.tabIndex = selected ? 0 : -1;
    panel.setAttribute('role', 'tabpanel');
    panel.setAttribute('aria-labelledby', button.id);
    panel.tabIndex = 0;
    button.addEventListener('click', () => {
        activateTab(id);
        if (!viewParams.has('detached') && !viewParams.has('tab')) {
            chrome.storage.local.set({[ACTIVE_TOOL_KEY]: id}).catch(() => {});
        }
    });
}

toolTabs.addEventListener('keydown', event => {
    const buttons = toolButtons.filter(button => button.getClientRects().length > 0);
    const index = buttons.indexOf(event.target);
    if (index < 0) return;
    const vertical = toolTabs.getAttribute('aria-orientation') === 'vertical';
    const previous = vertical ? 'ArrowUp' : 'ArrowLeft';
    const next = vertical ? 'ArrowDown' : 'ArrowRight';
    let target;
    if (event.key === 'Home') target = buttons[0];
    else if (event.key === 'End') target = buttons.at(-1);
    else if (event.key === previous) target = buttons.at(index - 1);
    else if (event.key === next) target = buttons[(index + 1) % buttons.length];
    if (!target) return;
    event.preventDefault();
    buttons[index].tabIndex = -1;
    target.tabIndex = 0;
    target.focus();
});

toolTabs.addEventListener('focusout', event => {
    if (toolTabs.contains(event.relatedTarget)) return;
    for (const button of toolButtons) button.tabIndex = button.classList.contains('tab--active') ? 0 : -1;
});

// Repeater response tabs (Raw/Render/Diff)
$$('.detail-tab[data-repeater-res]').forEach((tab) => {
    tab.addEventListener('click', () => {
        tab.parentElement.querySelectorAll('.detail-tab').forEach(t => t.classList.remove('detail-tab--active'));
        tab.classList.add('detail-tab--active');
        const which = tab.dataset.repeaterRes;
        dom.repeaterResRaw.style.display = which === 'raw' ? 'block' : 'none';
        dom.repeaterResRender.style.display = which === 'render' ? 'block' : 'none';
        $('#repeater-extension-view').hidden = which !== 'extensions';
        const diffEl = document.getElementById('repeater-res-diff');
        if (diffEl) {
            diffEl.style.display = which === 'diff' ? 'block' : 'none';
        }
        renderRepeaterResponse();
    });
});

// Simple line-based diff renderer for two response_raw strings.
function lineDiff(a, b) {
    const aLines = (a || '').split('\n');
    const bLines = (b || '').split('\n');
    const n = aLines.length, m = bLines.length;
    // LCS DP — bounded to avoid huge cost
    if (n * m > 1000000 || n > 4000 || m > 4000) {
        return aLines.map((l, i) => `  ${l}`).join('\n') + '\n--- B ---\n' + bLines.join('\n');
    }
    const dp = Array.from({ length: n + 1 }, () => new Uint32Array(m + 1));
    for (let i = n - 1; i >= 0; i--) {
        for (let j = m - 1; j >= 0; j--) {
            dp[i][j] = aLines[i] === bLines[j] ? dp[i + 1][j + 1] + 1 : Math.max(dp[i + 1][j], dp[i][j + 1]);
        }
    }
    const out = [];
    let i = 0, j = 0;
    while (i < n && j < m) {
        if (aLines[i] === bLines[j]) { out.push('  ' + aLines[i]); i++; j++; }
        else if (dp[i + 1][j] >= dp[i][j + 1]) { out.push('- ' + aLines[i]); i++; }
        else { out.push('+ ' + bLines[j]); j++; }
    }
    while (i < n) { out.push('- ' + aLines[i++]); }
    while (j < m) { out.push('+ ' + bLines[j++]); }
    return out.join('\n');
}

function renderRepeaterDiff() {
    const tab = (typeof getActiveRepeaterTab === 'function') ? getActiveRepeaterTab() : null;
    const diffEl = document.getElementById('repeater-res-diff');
    if (!diffEl || !tab) return;
    if (!tab.prev_response_raw) {
        diffEl.textContent = 'No previous response yet — send the request twice to compare.';
        return;
    }
    diffEl.textContent = lineDiff(tab.prev_response_raw, tab.response_raw || '');
}

$$('.detail-tab[data-scanner-view]').forEach((tab) => {
    tab.addEventListener('click', () => {
        $$('.detail-tab[data-scanner-view]').forEach(t => t.classList.remove('detail-tab--active'));
        tab.classList.add('detail-tab--active');
        const view = tab.dataset.scannerView;
        $$('[data-scanner-view-panel]').forEach((panel) => {
            panel.style.display = panel.dataset.scannerViewPanel === view ? 'flex' : 'none';
        });
    });
});
