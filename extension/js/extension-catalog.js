const EXTENSION_CATALOG = [
    {
        type: 'native',
        description: 'Format JSON responses and open the formatted view directly from the History menu.',
        manifest: {
            format: VIEW_PACK_FORMAT, id: 'example.json-inspector', name: 'JSON Inspector', version: '1.0',
            views: [{id: 'json', label: 'Readable JSON', operation: 'json-format',
                placements: ['workspace', 'history-response', 'repeater-response', 'history-menu']}],
        },
    },
    {
        type: 'native',
        description: 'Copy a recorded request and response together, with bodies or with headers only.',
        manifest: {
            format: VIEW_PACK_FORMAT, id: 'greytab.exchange-export', name: 'HTTP Exchange Export', version: '1.0',
            views: [
                {id: 'full', label: 'Request and response', operation: 'http-exchange', placements: ['history-exchange', 'history-menu']},
                {id: 'headers', label: 'Request and response headers', operation: 'http-exchange-headers', placements: ['history-exchange', 'history-menu']},
            ],
        },
    },
    {
        type: 'bapp', name: 'JQ', version: '1.2',
        description: 'Apply jq queries to JSON in Burp’s HTTP message editor.',
        url: 'https://portswigger.net/bappstore/c0d90a42c99848588d3df017cca717b5',
    },
    {
        type: 'bapp', name: 'Copy Request Response', version: '2.4.0',
        description: 'Copy HTTP exchanges from Burp for reports. HTTP Exchange Export covers full messages and headers in GreyTab.',
        url: 'https://portswigger.net/bappstore/0d05f52c00a64cb2b2bea68744f6316c',
    },
];

const extensionPageTabs = Array.from($$('.extension-nav [role="tab"]'));
const catalogSearch = $('#extension-catalog-search');
const catalogSource = $('#extension-catalog-source');
const catalogStatus = $('#extension-catalog-status');
const catalogList = $('#extension-catalog-list');
const pendingCatalogPacks = new Set();

function selectExtensionPage(selected) {
    for (const tab of extensionPageTabs) {
        const active = tab === selected;
        tab.setAttribute('aria-selected', String(active));
        tab.tabIndex = active ? 0 : -1;
        document.getElementById(tab.getAttribute('aria-controls')).hidden = !active;
    }
    $('#tab-extensions').scrollTop = 0;
}

for (const [index, tab] of extensionPageTabs.entries()) {
    tab.addEventListener('click', () => selectExtensionPage(tab));
    tab.addEventListener('keydown', event => {
        const end = extensionPageTabs.length - 1;
        const positions = {Home: 0, End: end, ArrowLeft: index === 0 ? end : index - 1,
            ArrowRight: index === end ? 0 : index + 1};
        if (!Object.hasOwn(positions, event.key)) return;
        event.preventDefault();
        const next = extensionPageTabs[positions[event.key]];
        selectExtensionPage(next);
        next.focus();
    });
}

function manageCatalogPack(id) {
    selectExtensionPage($('#extension-tab-installed'));
    const control = $(`.extension-pack[data-pack-id="${CSS.escape(id)}"] input`);
    if (control) control.focus();
    else $('#extension-tab-installed').focus();
}

async function installCatalogPack(manifest) {
    if (pendingCatalogPacks.has(manifest.id)) return;
    pendingCatalogPacks.add(manifest.id);
    renderExtensionCatalog();
    try {
        const pack = await installViewPack(manifest);
        catalogStatus.textContent = `${pack.name} installed.`;
    } catch (error) {
        catalogStatus.textContent = error.message;
    } finally {
        pendingCatalogPacks.delete(manifest.id);
        renderExtensionCatalog();
    }
}

function createCatalogAction(entry, name) {
    if (entry.type === 'bapp') {
        const link = document.createElement('a');
        link.className = 'btn btn--ghost btn--sm extension-catalog-link';
        link.textContent = 'View on BApp Store';
        link.setAttribute('aria-label', `View ${name} on BApp Store`);
        link.href = entry.url;
        link.target = '_blank';
        link.rel = 'noopener noreferrer';
        return link;
    }

    const manifest = entry.manifest;
    const installed = viewPackState.packs.find(pack => pack.id === manifest.id);
    let matches = false;
    if (installed) {
        const {enabled, ...definition} = installed;
        matches = JSON.stringify(definition) === JSON.stringify(validateViewPack(manifest));
    }
    const button = document.createElement('button');
    button.type = 'button';
    button.dataset.catalogPack = manifest.id;
    button.disabled = pendingCatalogPacks.has(manifest.id);
    button.className = `btn btn--sm ${matches ? 'btn--ghost' : 'btn--primary'}`;
    const action = matches ? 'Manage' : installed ? 'Install catalog version' : 'Install';
    button.textContent = button.disabled ? 'Installing…' : action;
    button.setAttribute('aria-label', `${action} ${name}`);
    button.addEventListener('click', () => {
        if (matches) manageCatalogPack(manifest.id);
        else installCatalogPack(manifest);
    });
    return button;
}

function renderExtensionCatalog() {
    const term = catalogSearch.value.trim().toLowerCase();
    const source = catalogSource.value;
    const activePack = document.activeElement?.dataset.catalogPack;
    const cards = [];
    for (const entry of EXTENSION_CATALOG) {
        if (source !== 'all' && entry.type !== source) continue;
        const {name, version} = entry.manifest || entry;
        if (term && !`${name} ${entry.description}`.toLowerCase().includes(term)) continue;

        const card = document.createElement('article');
        card.className = 'extension-catalog-card';
        const title = document.createElement('h3');
        title.textContent = name;
        const description = document.createElement('p');
        description.textContent = entry.description;
        const origin = document.createElement('p');
        origin.className = 'extension-catalog-origin';
        const installed = entry.manifest && viewPackState.packs.find(pack => pack.id === entry.manifest.id);
        const location = entry.type === 'native' ? 'GreyTab' : 'PortSwigger BApp listing';
        const status = installed ? (installed.enabled ? ' · Installed' : ' · Disabled') : '';
        origin.textContent = `${location} · ${version}${status}`;
        const action = createCatalogAction(entry, name);
        card.append(title, origin, description, action);
        cards.push(card);
    }
    if (!cards.length) {
        const empty = document.createElement('p');
        empty.className = 'text-muted';
        empty.textContent = 'No extensions match this search.';
        cards.push(empty);
    }
    catalogList.replaceChildren(...cards);
    if (activePack) $(`[data-catalog-pack="${CSS.escape(activePack)}"]`)?.focus();
}

function filterExtensionCatalog() {
    catalogStatus.textContent = '';
    renderExtensionCatalog();
}

catalogSearch.addEventListener('input', filterExtensionCatalog);
catalogSource.addEventListener('change', filterExtensionCatalog);
