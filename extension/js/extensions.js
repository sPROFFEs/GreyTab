const VIEW_PACK_STORAGE_KEY = 'greytab_view_packs_v1';
const MAX_VIEW_PACK_FILE_BYTES = 32 * 1024;
const MAX_BURP_ARCHIVE_BYTES = 16 * 1024 * 1024;
const ARCHIVE_UI_NAMES = {
    workspace_tab: 'Suite tab', request_editor: 'HTTP request editor', response_editor: 'HTTP response editor',
    http_editor: 'Legacy HTTP editor', websocket_editor: 'WebSocket editor', context_menu: 'Context menu',
    settings_panel: 'Settings panel', hotkey: 'Keyboard shortcut', theme: 'Theme integration', menu_bar: 'Menu bar',
};
const PLACEMENT_NAMES = {
    workspace: 'Offline workspace', 'history-request': 'History request',
    'history-response': 'History response', 'repeater-response': 'Repeater response',
    'history-exchange': 'History exchange', 'history-menu': 'History row menu',
};

let viewPackState = {builtinEnabled: true, packs: []};

function readViewPackState(saved = {}) {
    const packs = [];
    for (const item of Array.isArray(saved?.packs) ? saved.packs.slice(0, VIEW_PACK_LIMIT) : []) {
        try {
            const {enabled, ...manifest} = item;
            const pack = validateViewPack(manifest);
            if (packs.some(existing => existing.id === pack.id)) continue;
            packs.push({...pack, enabled: enabled !== false});
        } catch (error) {
            console.warn('Skipping invalid GreyTab view pack:', error.message);
        }
    }
    return {builtinEnabled: saved?.builtinEnabled !== false, packs};
}

async function changeViewPacks(update) {
    await navigator.locks.request(VIEW_PACK_STORAGE_KEY, async () => {
        const stored = await chrome.storage.local.get(VIEW_PACK_STORAGE_KEY);
        const next = readViewPackState(stored[VIEW_PACK_STORAGE_KEY]);
        update(next);
        await chrome.storage.local.set({[VIEW_PACK_STORAGE_KEY]: next});
    });
}

async function installViewPack(manifest) {
    const pack = validateViewPack(manifest);
    await changeViewPacks(next => {
        const index = next.packs.findIndex(item => item.id === pack.id);
        if (index >= 0) {
            next.packs[index] = {...pack, enabled: next.packs[index].enabled};
        } else {
            if (next.packs.length >= VIEW_PACK_LIMIT) throw new Error('Remove a view pack before installing another.');
            next.packs.push({...pack, enabled: true});
        }
    });
    return pack;
}

function viewPacks() {
    return [{...BUILTIN_VIEW_PACK, enabled: viewPackState.builtinEnabled}, ...viewPackState.packs];
}

function fillViewPicker(picker, placement) {
    const previous = picker.value;
    const choices = new Map();
    const groups = [];
    for (const pack of viewPacks()) {
        if (!pack.enabled) continue;
        const views = pack.views.filter(view => view.placements.includes(placement));
        if (!views.length) continue;
        const group = document.createElement('optgroup');
        group.label = pack.name;
        for (const view of views) {
            const key = `${pack.id}:${view.id}`;
            choices.set(key, view);
            group.append(new Option(view.label, key));
        }
        groups.push(group);
    }
    picker.replaceChildren(...(groups.length ? groups : [new Option('No enabled views', '')]));
    picker.disabled = choices.size === 0;
    if (choices.has(previous)) picker.value = previous;
    return choices.get(picker.value);
}

function paintMessageView(result, status, view, input) {
    result.replaceChildren();
    result.hidden = true;
    if (!view || !input) {
        status.textContent = view ? 'No message selected.' : 'Enable a view pack in Extensions.';
        return;
    }
    try {
        result.textContent = runMessageView(view.operation, input);
        result.hidden = false;
        status.textContent = '';
    } catch (error) {
        status.textContent = error.message;
    }
}

function mountMessageViews(id, getPlacement, getInput, showSource = false) {
    const host = document.getElementById(id);
    host.append($('#message-extension-template').content.cloneNode(true));
    const source = host.querySelector('.message-extension-source');
    const message = source.querySelector('select');
    const picker = host.querySelector('.message-extension-picker');
    const result = host.querySelector('pre');
    const status = host.querySelector('[role="status"]');
    const copy = host.querySelector('.message-extension-copy');
    source.hidden = !showSource;
    function refresh() {
        if (host.hidden) return;
        if (showSource) {
            const exchangeOption = message.querySelector('[value="exchange"]');
            const available = viewPacks().some(pack => pack.enabled &&
                pack.views.some(view => view.placements.includes('history-exchange')));
            exchangeOption.hidden = exchangeOption.disabled = !available;
            if (!available && message.value === 'exchange') message.value = 'response';
        }
        const view = fillViewPicker(picker, getPlacement(message.value));
        paintMessageView(result, status, view, getInput(message.value));
        copy.disabled = result.hidden;
    }
    copy.addEventListener('click', async () => {
        if (result.hidden) return;
        try {
            await navigator.clipboard.writeText(result.textContent);
            status.textContent = 'View copied.';
        } catch (error) {
            status.textContent = error.message;
        }
    });
    host.addEventListener('change', refresh);
    return refresh;
}

const refreshHistoryExtensionView = mountMessageViews('history-extension-view',
    kind => `history-${kind}`, kind => kind === 'exchange' ?
        (historyMessages.request ? historyMessages : null) : historyMessages[kind], true);
const refreshRepeaterExtensionView = mountMessageViews('repeater-extension-view',
    () => 'repeater-response', () => getActiveRepeaterTab()?.response_raw);

function appendHistoryExtensionActions(menu, logId) {
    const packs = viewPacks().filter(pack => pack.enabled);
    const actions = packs.flatMap(pack => pack.views.filter(view => view.placements.includes('history-menu'))
        .map(view => ({key: `${pack.id}:${view.id}`, name: `${pack.name} · ${view.label}`,
            source: view.placements.includes('history-exchange') ? 'exchange' : 'response'}))).slice(0, 6);
    if (!actions.length) return;
    const label = document.createElement('div');
    label.className = 'ctx-menu__label';
    label.textContent = 'Extensions';
    menu.prepend(label);
    let previous = label;
    for (const action of actions) {
        const item = document.createElement('button');
        item.className = 'ctx-menu__item extension-menu-action';
        item.textContent = action.name;
        item.addEventListener('click', async () => {
            hideContextMenu();
            await showRequestDetail(logId);
            if (Number(state.currentLog?.id) !== Number(logId)) return;
            setHistoryDetailView('extensions');
            $('#history-extension-view .message-extension-source select').value = action.source;
            refreshHistoryExtensionView();
            const picker = $('#history-extension-view .message-extension-picker');
            if (!Array.from(picker.options).some(option => option.value === action.key)) return;
            picker.value = action.key;
            refreshHistoryExtensionView();
        });
        previous.after(item);
        previous = item;
    }
}

const packStatus = $('#view-pack-status');
const workspaceViewPicker = $('#workspace-extension-picker');
const workspaceViewInput = $('#workspace-extension-input');
const workspaceViewOutput = $('#workspace-extension-output');
const workspaceViewStatus = $('#workspace-extension-status');

function clearWorkspaceView() {
    workspaceViewOutput.textContent = '';
    workspaceViewOutput.hidden = true;
    workspaceViewStatus.textContent = workspaceViewPicker.disabled ? 'Enable a view pack to use this workspace.' : '';
}

async function changePackFromList(update, restore) {
    try {
        await changeViewPacks(update);
        packStatus.textContent = '';
    } catch (error) {
        restore();
        packStatus.textContent = error.message;
    }
}

function renderViewPacks() {
    const list = $('#view-pack-list');
    list.replaceChildren();
    for (const pack of viewPacks()) {
        const builtin = pack.id === BUILTIN_VIEW_PACK.id;
        const card = document.createElement('div');
        card.className = 'extension-pack';
        card.dataset.packId = pack.id;
        const name = document.createElement('strong');
        name.textContent = pack.name;
        const version = document.createElement('span');
        version.className = 'text-muted';
        version.textContent = `${builtin ? 'Built in · ' : ''}${pack.version}`;
        const placements = new Set(pack.views.flatMap(view => view.placements));
        const locations = document.createElement('p');
        locations.textContent = [...placements].map(key => PLACEMENT_NAMES[key]).join(' · ');
        const actions = document.createElement('div');
        actions.className = 'extension-pack-actions';
        const label = document.createElement('label');
        const toggle = document.createElement('input');
        toggle.type = 'checkbox';
        toggle.checked = pack.enabled;
        toggle.setAttribute('aria-label', `Enable ${pack.name}`);
        toggle.addEventListener('change', () => changePackFromList(next => {
            if (builtin) next.builtinEnabled = toggle.checked;
            else {
                const current = next.packs.find(item => item.id === pack.id);
                if (current) current.enabled = toggle.checked;
            }
        }, () => { toggle.checked = pack.enabled; }));
        label.append(toggle, ' Enabled');
        actions.append(label);
        if (!builtin) {
            const remove = document.createElement('button');
            remove.className = 'btn btn--ghost btn--xs';
            remove.textContent = 'Remove';
            remove.setAttribute('aria-label', `Remove ${pack.name}`);
            remove.addEventListener('click', () => changePackFromList(next => {
                next.packs = next.packs.filter(item => item.id !== pack.id);
            }, () => {}));
            actions.append(remove);
        }
        card.append(name, version, locations, actions);
        list.append(card);
    }
    fillViewPicker(workspaceViewPicker, 'workspace');
    $('#workspace-extension-form button').disabled = workspaceViewPicker.disabled;
    clearWorkspaceView();
    refreshHistoryExtensionView();
    refreshRepeaterExtensionView();
    renderExtensionCatalog();
}

$('#workspace-extension-form').addEventListener('submit', event => {
    event.preventDefault();
    const view = fillViewPicker(workspaceViewPicker, 'workspace');
    paintMessageView(workspaceViewOutput, workspaceViewStatus, view, workspaceViewInput.value);
});
workspaceViewPicker.addEventListener('change', clearWorkspaceView);
workspaceViewInput.addEventListener('input', clearWorkspaceView);

$('#view-pack-form').addEventListener('submit', async event => {
    event.preventDefault();
    const form = event.currentTarget;
    const button = form.querySelector('button');
    if (button.disabled) return;
    button.disabled = true;
    try {
        const [file] = $('#view-pack-file').files;
        if (!file || file.size > MAX_VIEW_PACK_FILE_BYTES) throw new Error('Select a GreyTab JSON view pack up to 32 KiB.');
        let manifest;
        try {
            manifest = JSON.parse(await file.text());
        } catch {
            throw new Error('The selected view pack is not valid JSON.');
        }
        const pack = await installViewPack(manifest);
        packStatus.textContent = `${pack.name} saved.`;
        form.reset();
    } catch (error) {
        packStatus.textContent = error.message;
    } finally {
        button.disabled = false;
    }
});

function showBurpArchiveReport(report) {
    const list = $('#burp-archive-report');
    const {scanned, skipped, bundled_api: bundled} = report.classes;
    const classCount = count => `${count} ${count === 1 ? 'class' : 'classes'}`;
    const coverage = [`${classCount(scanned)} inspected`];
    if (skipped) coverage.push(`${classCount(skipped)} skipped`);
    if (bundled) coverage.push(`${classCount(bundled)} from the bundled Montoya API excluded`);
    if (report.nested_archives) coverage.push(`${report.nested_archives} nested archives left unopened`);
    const fields = [
        ['Burp API references', report.apis.join(', ') || 'None detected'],
        ['Montoya packages', report.montoya_packages.join(', ') || 'None detected'],
        ['Interface contributions', report.ui_contributions.map(key => ARCHIVE_UI_NAMES[key]).join(', ') || 'None detected'],
        ['Java UI frameworks', report.ui_frameworks.join(', ') || 'None detected'],
        ['Coverage', coverage.join(' · ')],
    ];
    if (report.bapp_entry_point) fields.unshift(['BApp entry point', report.bapp_entry_point]);
    list.replaceChildren();
    for (const [label, value] of fields) {
        const term = document.createElement('dt');
        const detail = document.createElement('dd');
        term.textContent = label;
        detail.textContent = value;
        list.append(term, detail);
    }
    list.hidden = false;
}

$('#burp-archive-form').addEventListener('submit', async event => {
    event.preventDefault();
    const button = event.currentTarget.querySelector('button');
    if (button.disabled) return;
    const status = $('#burp-archive-status');
    const input = $('#burp-archive');
    $('#burp-archive-report').hidden = true;
    button.disabled = true;
    input.disabled = true;
    try {
        const [file] = input.files;
        if (!file || file.size > MAX_BURP_ARCHIVE_BYTES) throw new Error('Select a JAR, BApp or ZIP archive up to 16 MiB.');
        status.textContent = 'Reading class references…';
        const response = await fetch(`${API_BASE}/api/extensions/inspect`, {method: 'POST', body: file});
        const report = await response.json();
        if (!response.ok) throw new Error(report.detail || 'Archive inspection failed.');
        showBurpArchiveReport(report);
        status.textContent = `Static inspection complete for ${file.name}.`;
    } catch (error) {
        status.textContent = error.message;
    } finally {
        button.disabled = false;
        input.disabled = false;
    }
});

$('#burp-archive').addEventListener('change', () => {
    $('#burp-archive-report').hidden = true;
    $('#burp-archive-status').textContent = '';
});

chrome.storage.onChanged.addListener((changes, area) => {
    if (area !== 'local' || !changes[VIEW_PACK_STORAGE_KEY]) return;
    viewPackState = readViewPackState(changes[VIEW_PACK_STORAGE_KEY].newValue);
    renderViewPacks();
});

chrome.storage.local.get(VIEW_PACK_STORAGE_KEY).then(stored => {
    viewPackState = readViewPackState(stored[VIEW_PACK_STORAGE_KEY]);
    renderViewPacks();
}).catch(error => { packStatus.textContent = error.message; });
