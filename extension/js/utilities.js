// Advanced audit workflows share captured requests with the rest of the workspace.
let utilityMacros = [];
const parseHeaders = value => typeof value === 'string' ? JSON.parse(value || '{}') : value || {};
async function runUtility(button, output, work) {
    button.disabled = true;
    output.textContent = 'Working…';
    try { await work(); }
    catch (e) { output.textContent = e.message; }
    finally { button.disabled = false; }
}
function selectedHistoryRequest() {
    if (!state.currentLog) throw new Error('Select a request in History first.');
    return state.currentLog;
}
$('#btn-race-history')?.addEventListener('click', () => {
    try {
        const log = selectedHistoryRequest();
        $('#race-target').value = log.url;
        $('#race-request').value = buildRawRequest(log.method, log.url, log.request_headers, log.request_body);
    } catch (e) { $('#race-output').textContent = e.message; }
});
$('#btn-race-repeater')?.addEventListener('click', () => {
    persistActiveRepeaterEditor();
    const tab = getActiveRepeaterTab();
    $('#race-request').value = tab?.raw_request || '';
    $('#race-target').value = tab?.target_url || '';
});
$('#btn-race-run')?.addEventListener('click', e => runUtility(e.currentTarget, $('#race-output'), async () => {
    const parsed = parseRawRequest($('#race-request').value);
    const parallel = Number($('#race-parallel').value);
    if (!Number.isInteger(parallel) || parallel < 2 || parallel > 100) throw new Error('Choose 2–100 parallel requests.');
    const result = await apiRequest('POST', '/api/race/run', { ...parsed, url: normalizeParsedRequestUrl(parsed, $('#race-target').value), parallel });
    $('#race-output').textContent = `Responses: ${result.count}\nStatuses: ${JSON.stringify(result.statuses)}\nLengths: ${result.unique_lengths.join(', ')}\n\n` + result.results.map(r => `#${r.index + 1}  HTTP ${r.status}  ${r.duration_ms} ms  ${r.length} B${r.error ? '  ' + r.error : ''}`).join('\n');
}));
async function refreshWsFrames() {
    if (!state.sessionId) return;
    const frames = await apiRequest('GET', `/api/ws_log?session_id=${state.sessionId}&limit=500`);
    const filter = $('#ws-filter').value.toLowerCase();
    const host = $('#ws-frames'); host.replaceChildren();
    for (const frame of frames.filter(f => `${f.url} ${f.content}`.toLowerCase().includes(filter))) {
        const row = document.createElement('button'); row.className = 'ws-frame';
        row.textContent = `${frame.direction === 'from_client' ? '↑' : '↓'} ${frame.length} B · ${frame.url}\n${(frame.content || '').slice(0, 120)}`;
        row.addEventListener('click', () => { $('#ws-frame-detail').textContent = `${new Date(frame.timestamp * 1000).toLocaleTimeString()} · ${frame.direction}\n${frame.content}`; });
        host.append(row);
    }
    if (!host.children.length) host.textContent = 'No matching frames captured.';
}
$('#btn-ws-refresh')?.addEventListener('click', e => runUtility(e.currentTarget, $('#ws-frame-detail'), refreshWsFrames));
$('#ws-filter')?.addEventListener('input', () => refreshWsFrames().catch(() => {}));
async function refreshMacros() {
    utilityMacros = await apiRequest('GET', '/api/macros');
    const selected = $('#macro-select').value;
    $('#macro-select').replaceChildren(new Option('New macro', ''));
    utilityMacros.forEach(m => $('#macro-select').add(new Option(m.name || m.id, m.id)));
    $('#macro-select').value = selected;
}
function applyMacro(m = {}) {
    $('#macro-select').value = m.id || '';
    $('#macro-name').value = m.name || '';
    $('#macro-steps').value = JSON.stringify(m.steps || [], null, 2);
    $('#macro-header').value = m.inject_header || '';
    $('#macro-template').value = m.inject_template || '';
}
$('#macro-select')?.addEventListener('change', () => applyMacro(utilityMacros.find(m => m.id === $('#macro-select').value)));
$('#btn-macro-new')?.addEventListener('click', () => applyMacro());
$('#btn-macro-add')?.addEventListener('click', () => {
    try {
        const log = selectedHistoryRequest();
        const steps = JSON.parse($('#macro-steps').value);
        if (!Array.isArray(steps)) throw new Error('Steps must be a JSON array.');
        steps.push({method: log.method, url: log.url, headers: parseHeaders(log.request_headers), body: log.request_body || '', extract: {}, extract_kind: 'regex'});
        $('#macro-steps').value = JSON.stringify(steps, null, 2);
    } catch (e) { $('#macro-output').textContent = e.message; }
});
$('#btn-macro-save')?.addEventListener('click', e => runUtility(e.currentTarget, $('#macro-output'), async () => {
    const steps = JSON.parse($('#macro-steps').value);
    if (!Array.isArray(steps) || !steps.length) throw new Error('Add at least one step.');
    const saved = await apiRequest('POST', '/api/macros', {id: $('#macro-select').value || undefined, name: $('#macro-name').value, steps, inject_header: $('#macro-header').value, inject_template: $('#macro-template').value});
    await refreshMacros(); applyMacro(saved); $('#macro-output').textContent = 'Macro saved.';
}));
$('#btn-macro-run')?.addEventListener('click', e => runUtility(e.currentTarget, $('#macro-output'), async () => {
    if (!$('#macro-select').value) throw new Error('Save or select a macro first.');
    const result = await apiRequest('POST', `/api/macros/${$('#macro-select').value}/run`);
    $('#macro-output').textContent = JSON.stringify(result, null, 2);
}));
$('#btn-macro-delete')?.addEventListener('click', e => runUtility(e.currentTarget, $('#macro-output'), async () => {
    if (!$('#macro-select').value) throw new Error('Select a saved macro first.');
    await apiRequest('DELETE', `/api/macros/${$('#macro-select').value}`); await refreshMacros(); applyMacro(); $('#macro-output').textContent = 'Macro deleted.';
}));
$('#btn-graphql-history')?.addEventListener('click', () => {
    try { const log = selectedHistoryRequest(); $('#graphql-url').value = log.url; $('#graphql-headers').value = JSON.stringify(parseHeaders(log.request_headers), null, 2); }
    catch (e) { $('#graphql-output').textContent = e.message; }
});
$('#btn-graphql-run')?.addEventListener('click', e => runUtility(e.currentTarget, $('#graphql-output'), async () => {
    const result = await apiRequest('POST', '/api/graphql/introspect', {url: $('#graphql-url').value, headers: parseHeaders($('#graphql-headers').value)});
    $('#graphql-output').textContent = JSON.stringify(result, null, 2);
}));
$('.tab[data-tab="utilities"]')?.addEventListener('click', () => {
    refreshMacros().catch(e => { $('#macro-output').textContent = e.message; });
    refreshWsFrames().catch(e => { $('#ws-frame-detail').textContent = e.message; });
});

async function refreshScanMacros() {
    const select = $('#scanner-macro');
    const chosen = select.value;
    const macros = await apiRequest('GET', '/api/macros');
    select.replaceChildren(new Option('None', ''));
    macros.forEach(m => select.add(new Option(m.name || m.id, m.id)));
    select.value = chosen;
}
