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
    trafficItems: [],
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

const WORKSPACE_STORAGE_KEY = 'greytab_workspace_state_v1';
let workspaceSaveTimer = null;

function scheduleWorkspaceSave(delayMs = 350) {
    if (!chrome?.storage?.local) return;
    if (workspaceSaveTimer) clearTimeout(workspaceSaveTimer);
    workspaceSaveTimer = setTimeout(() => {
        workspaceSaveTimer = null;
        persistWorkspaceState().catch(() => { });
    }, delayMs);
}

function snapshotWorkspaceState() {
    const trafficItems = Array.isArray(state.trafficItems) ? state.trafficItems.slice(0, 10000) : [];
    const intruderResults = Array.isArray(state.intruder.results) ? state.intruder.results.slice(0, 2000) : [];
    const scannerFindings = Array.isArray(state.scanner.findings) ? state.scanner.findings.slice(0, 3000) : [];
    const scannerActivity = Array.isArray(state.scanner.activities) ? state.scanner.activities.slice(-2000) : [];
    const scannerRequestLog = Array.isArray(state.scanner.requestLog) ? state.scanner.requestLog.slice(-4000) : [];
    const scannerTestLog = Array.isArray(state.scanner.testLog) ? state.scanner.testLog.slice(-12000) : [];

    return {
        ts: Date.now(),
        active_tab: state.activeTab || 'proxy',
        traffic_items: trafficItems,
        repeater_state: {
            active_tab_id: state.repeater.activeTabId,
            tabs: (state.repeater.tabs || []).map((t) => ({
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
    const data = await chrome.storage.local.get(WORKSPACE_STORAGE_KEY);
    const ws = data?.[WORKSPACE_STORAGE_KEY];
    if (!ws || typeof ws !== 'object') return;

    if (Array.isArray(ws.traffic_items) && ws.traffic_items.length > 0) {
        state.trafficItems = ws.traffic_items.slice(0, 10000);
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

    const activeTab = String(ws.active_tab || '').trim();
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
    trafficList: $('#traffic-list'),
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
    trafficCount: $('#traffic-count'),
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
    trafficFilterHost: $('#traffic-filter-host'),
    trafficFilterMethod: $('#traffic-filter-method'),
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

if (dom.btnExternal) {
    dom.btnExternal.addEventListener('click', () => {
        const url = chrome.runtime.getURL('sidepanel.html');
        window.open(url, '_blank', 'width=900,height=800');
    });
}

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
    $$('.tab').forEach((t) => t.classList.remove('tab--active'));
    $$('.tab-content').forEach((c) => c.classList.remove('tab-content--active'));
    const tabBtn = $(`.tab[data-tab="${tabId}"]`);
    const tabPanel = $(`#tab-${tabId}`);
    if (!tabBtn || !tabPanel) return;
    tabBtn.classList.add('tab--active');
    tabPanel.classList.add('tab-content--active');
    state.activeTab = tabId;
    scheduleWorkspaceSave();

    if (tabId === 'requests') loadHttpHistory();
    if (tabId === 'tools') loadTools();
    if (tabId === 'settings') loadSettings();
}

$$('.tab').forEach((tab) => {
    tab.addEventListener('click', () => {
        activateTab(tab.dataset.tab);
    });
});

// Detail tabs (History Request/Response)
$$('.detail-tab[data-detail]').forEach((tab) => {
    tab.addEventListener('click', () => {
        tab.parentElement.querySelectorAll('.detail-tab').forEach(t => t.classList.remove('detail-tab--active'));
        tab.classList.add('detail-tab--active');
        const which = tab.dataset.detail;
        dom.detailRequest.style.display = which === 'request' ? 'block' : 'none';
        dom.detailResponse.style.display = which === 'response' ? 'block' : 'none';
    });
});

// Repeater response tabs (Raw/Render)
$$('.detail-tab[data-repeater-res]').forEach((tab) => {
    tab.addEventListener('click', () => {
        tab.parentElement.querySelectorAll('.detail-tab').forEach(t => t.classList.remove('detail-tab--active'));
        tab.classList.add('detail-tab--active');
        const which = tab.dataset.repeaterRes;
        dom.repeaterResRaw.style.display = which === 'raw' ? 'block' : 'none';
        dom.repeaterResRender.style.display = which === 'render' ? 'block' : 'none';
    });
});

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
