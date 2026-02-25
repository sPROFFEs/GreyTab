
// ══════════════════════════════════════════════════════════════════
// Utilities
// ══════════════════════════════════════════════════════════════════

function formatBytes(bytes) {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
}

// ══════════════════════════════════════════════════════════════════
// Initialize
// ══════════════════════════════════════════════════════════════════

async function init() {
    initModalHandlers();
    initRepeaterWorkspace();
    bindScannerSyncControls();
    bindAiSettingsHandlers();
    applyInitialViewMode();
    await loadPersistedScannerFormState();
    await restoreWorkspaceState().catch(() => { });
    renderRepeaterRequestPreview();
    // Sync scroll between textarea and highlight layer
    if (dom.repeaterRawRequest && dom.repeaterReqHighlight) {
        dom.repeaterRawRequest.addEventListener('scroll', () => {
            dom.repeaterReqHighlight.scrollTop = dom.repeaterRawRequest.scrollTop;
            dom.repeaterReqHighlight.scrollLeft = dom.repeaterRawRequest.scrollLeft;
        });
    }

    // Global right-click: Send selected text to Decoder (works on any element)
    document.addEventListener('contextmenu', (e) => {
        // Get selected text from either window selection or textarea selection
        let sel = '';
        const active = document.activeElement;
        if (active && (active.tagName === 'TEXTAREA' || active.tagName === 'INPUT') && active.selectionStart !== active.selectionEnd) {
            sel = active.value.substring(active.selectionStart, active.selectionEnd);
        } else {
            sel = window.getSelection()?.toString() || '';
        }
        if (!sel.trim()) return; // No selection, let default context menu show

        // Don't intercept if we're inside the existing request-list ctx-menu flow
        if (e.target.closest('.ctx-menu') || e.target.closest('.request-item')) return;

        e.preventDefault();
        // Remove any lingering selection menus
        document.querySelectorAll('.ctx-menu--selection').forEach(m => m.remove());

        const menu = document.createElement('div');
        menu.className = 'ctx-menu ctx-menu--selection';
        menu.style.cssText = `position:fixed; left:${e.clientX}px; top:${e.clientY}px; z-index:9999;`;
        menu.innerHTML = `
            <div class="ctx-menu__label">Selected Text (${sel.length} chars)</div>
            <div class="ctx-menu__item" data-action="decode-sel">
                <svg viewBox="0 0 24 24"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect><path d="M7 11V7a5 5 0 0 1 10 0v4"></path></svg>
                Send to Decoder
            </div>
            <div class="ctx-menu__item" data-action="copy-sel">
                <svg viewBox="0 0 24 24"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path></svg>
                Copy
            </div>
            <div class="ctx-menu__item" data-action="b64-sel">
                <svg viewBox="0 0 24 24"><polyline points="16 18 22 12 16 6"></polyline><polyline points="8 6 2 12 8 18"></polyline></svg>
                Quick Base64 Decode
            </div>
            <div class="ctx-menu__item" data-action="url-sel">
                <svg viewBox="0 0 24 24"><path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"></path><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"></path></svg>
                Quick URL Decode
            </div>
        `;
        document.body.appendChild(menu);

        // Clamp menu position to viewport
        const rect = menu.getBoundingClientRect();
        if (rect.right > window.innerWidth) menu.style.left = (window.innerWidth - rect.width - 4) + 'px';
        if (rect.bottom > window.innerHeight) menu.style.top = (window.innerHeight - rect.height - 4) + 'px';

        menu.addEventListener('click', (ev) => {
            const action = ev.target.closest('[data-action]')?.dataset.action;
            if (action === 'decode-sel') sendToDecoder(sel);
            else if (action === 'copy-sel') navigator.clipboard.writeText(sel).catch(() => { });
            else if (action === 'b64-sel') {
                try { sendToDecoder(sel); $('#decoder-operation').value = 'base64'; $('#btn-dir-decode').click(); } catch { }
            }
            else if (action === 'url-sel') {
                try { sendToDecoder(sel); $('#decoder-operation').value = 'url'; $('#btn-dir-decode').click(); } catch { }
            }
            menu.remove();
        });
        const dismiss = (ev) => { if (!menu.contains(ev.target)) { menu.remove(); document.removeEventListener('mousedown', dismiss); } };
        setTimeout(() => document.addEventListener('mousedown', dismiss), 10);
    });

    // Findings Panel Toggle (Centered Popup)
    const closeFindingsPopup = () => {
        if (dom.historyFindingsPanel) dom.historyFindingsPanel.style.display = 'none';
    };

    if (dom.findingsBadge) {
        dom.findingsBadge.addEventListener('click', () => {
            if (dom.historyFindingsPanel) {
                dom.historyFindingsPanel.style.display = 'flex';
                if (typeof renderFindingsPanel === 'function') renderFindingsPanel();
            }
        });
    }

    // Close on backdrop click (click on .findings-backdrop but not on .findings-popup)
    if (dom.historyFindingsPanel) {
        dom.historyFindingsPanel.addEventListener('click', (e) => {
            if (e.target === dom.historyFindingsPanel) closeFindingsPopup();
        });
    }

    if (dom.btnCloseFindingsModal) dom.btnCloseFindingsModal.addEventListener('click', closeFindingsPopup);

    // Manual Add Finding
    if (dom.btnAddFinding) {
        dom.btnAddFinding.addEventListener('click', () => {
            if (!state.currentLog) {
                alert('No request selected. Select a request in History first.');
                return;
            }
            const flow = state.currentLog;
            const finding = {
                id: 'F' + Date.now(),
                url: flow.url,
                method: flow.method,
                name: 'Manual Finding',
                severity: 'medium',
                status: 'pending',
                description: 'Manually added finding from HTTP History.',
                request: typeof buildRawRequest === 'function' ? buildRawRequest(flow.method || 'GET', flow.url, flow.request_headers, flow.request_body) : '',
                response: flow.response_raw || flow.response_body || ''
            };
            if (typeof addScannerFinding === 'function') {
                addScannerFinding(finding);
                const scannerTabBtn = document.querySelector('.tab[data-tab="autoscanner"]');
                if (scannerTabBtn) scannerTabBtn.click();
            }
        });
    }

    // Resizable repeater splitter
    const repeaterSplitter = $('#repeater-splitter');
    if (repeaterSplitter) {
        const grid = repeaterSplitter.parentElement;
        const cols = grid.querySelectorAll('.repeater-column');
        if (cols.length === 2) {
            let dragging = false;
            repeaterSplitter.addEventListener('mousedown', (e) => {
                e.preventDefault();
                dragging = true;
                repeaterSplitter.classList.add('panel-splitter--active');
                document.body.style.cursor = 'col-resize';
                document.body.style.userSelect = 'none';

                const onMove = (ev) => {
                    if (!dragging) return;
                    const rect = grid.getBoundingClientRect();
                    const pct = ((ev.clientX - rect.left) / rect.width) * 100;
                    const clamped = Math.max(20, Math.min(80, pct));
                    cols[0].style.flex = 'none';
                    cols[1].style.flex = 'none';
                    cols[0].style.width = clamped + '%';
                    cols[1].style.width = (100 - clamped) + '%';
                };

                const onUp = () => {
                    dragging = false;
                    repeaterSplitter.classList.remove('panel-splitter--active');
                    document.body.style.cursor = '';
                    document.body.style.userSelect = '';
                    document.removeEventListener('mousemove', onMove);
                    document.removeEventListener('mouseup', onUp);
                };

                document.addEventListener('mousemove', onMove);
                document.addEventListener('mouseup', onUp);
            });
        }
    }
    // Intruder file browse handler
    const browseBtn = $('#btn-browse-intruder-wordlist');
    const fileInput = $('#intruder-file-input');
    if (browseBtn && fileInput) {
        browseBtn.addEventListener('click', () => fileInput.click());
        fileInput.addEventListener('change', (e) => {
            const file = e.target.files[0];
            if (!file) return;
            const status = $('#wordlist-load-status');
            const reader = new FileReader();
            reader.onload = (ev) => {
                const text = ev.target.result;
                const lines = text.split('\n').filter(l => l.trim() !== '');
                // Switch to simple_list mode and populate textarea
                const payloadType = $('#intruder-payload-type');
                if (payloadType) {
                    payloadType.value = 'simple_list';
                    payloadType.dispatchEvent(new Event('change'));
                }
                const textarea = $('#intruder-payloads');
                if (textarea) textarea.value = lines.join('\n');
                if (status) { status.textContent = `✓ Loaded ${lines.length} lines from ${file.name}`; status.style.color = 'var(--success)'; }
            };
            reader.onerror = () => {
                if (status) { status.textContent = 'Error reading file'; status.style.color = 'var(--danger)'; }
            };
            reader.readAsText(file);
            fileInput.value = ''; // Reset for re-selection
        });
    }
    await updateScannerAuthStatus().catch(() => { });
    chrome.runtime.sendMessage({ type: 'get_ws_status' }, (response) => {
        if (response) {
            state.connected = response.connected;
            updateConnectionStatus();
        }
    });

    try {
        const health = await apiRequest('GET', '/api/health');
        state.proxyRunning = health.proxy_running;
        state.proxyPort = Number(health.proxy_port || state.proxyPort || 8080);
        state.memoryMb = Number(health.memory_mb || 0);
        updateProxyStatus();
        if (health.session_id) {
            state.sessionId = health.session_id;
            const sessions = await apiRequest('GET', '/api/sessions');
            const active = sessions.find((s) => s.id === health.session_id);
            if (active) {
                showActiveSession(active.name, active.id);
            }
        }
    } catch (e) {
        console.log('Backend not available yet, will connect via WebSocket');
    }

    await syncScannerStatusFromBackend();
    await refreshProxyRuntimeStatus();
    await loadHttpHistory();
    window.addEventListener('beforeunload', () => {
        persistWorkspaceState().catch(() => { });
    });
    setInterval(() => {
        if (!state.connected || state.scanner.running) {
            syncScannerStatusFromBackend();
        }
        refreshHealth();
        refreshProxyRuntimeStatus();
        updateRunningTools();
        if (state.sessionId && (state.activeTab === 'requests' || dom.requestList?.children?.length <= 1)) {
            loadHttpHistory();
        }
    }, 3000);

    loadTools();
}

init();

function applyInitialViewMode() {
    try {
        const params = new URLSearchParams(window.location.search || '');
        const detached = String(params.get('detached') || '').toLowerCase();
        const forcedTab = String(params.get('tab') || '').toLowerCase();
        if (detached === 'scanner') {
            document.body.classList.add('scanner-detached');
            activateTab('autoscanner');
        } else if (forcedTab) {
            activateTab(forcedTab);
        }
    } catch {
        // ignore
    }
}

// Wordlist upload handling
dom.toolWordlist?.addEventListener('change', () => {
    if (dom.toolWordlist.value === '__upload__') {
        dom.wordlistUploadInput.click();
        dom.toolWordlist.value = ''; // Reset to allow re-selection
    }
});

// Same for intruder wordlist if it exists
document.addEventListener('change', (e) => {
    if (e.target.id === 'intruder-wordlist' && e.target.value === '__upload__') {
        dom.wordlistUploadInput.click();
        e.target.value = '';
    }
});

dom.wordlistUploadInput?.addEventListener('change', async (e) => {
    const file = e.target.files[0];
    if (!file) return;

    const formData = new FormData();
    formData.append('file', file);

    try {
        const res = await fetch(`${API_BASE}/api/tools/wordlists/upload`, {
            method: 'POST',
            body: formData,
        });
        if (!res.ok) {
            const err = await res.json();
            throw new Error(err.detail || 'Upload failed');
        }
        const data = await res.json();
        alert('Wordlist uploaded successfully: ' + data.filename);

        // Refresh all wordlist selects
        await loadTools();

        // Try to select the newly uploaded one
        if (dom.toolWordlist) dom.toolWordlist.value = data.path;
        const iwl = document.getElementById('intruder-wordlist');
        if (iwl) iwl.value = data.path;

    } catch (err) {
        alert('Upload error: ' + err.message);
        console.error(err);
    } finally {
        // Clear input to allow re-uploading same file
        e.target.value = '';
    }
});
