const webhookInboxForm = $('#webhook-inbox-form');
const webhookInboxInput = $('#webhook-inbox-id');
const webhookInboxName = $('#webhook-inbox-name');
const webhookInboxSaved = $('#webhook-inbox-saved');
const webhookInboxForget = $('#webhook-inbox-forget');
const webhookInboxOpen = $('#webhook-inbox-open');
const webhookInboxStatus = $('#webhook-inbox-status');
const webhookInboxResponseStatus = $('#webhook-inbox-response-status');
const webhookInboxEvents = $('#webhook-inbox-events');
const webhookInboxDetail = $('#webhook-inbox-detail');
const webhookInboxResponse = $('#webhook-inbox-response');
const WEBHOOK_SITE_URL = 'https://webhook.site/';
const WEBHOOK_INBOX_STORAGE = 'greytab_webhook_inboxes_v1';
const MAX_WEBHOOK_INBOXES = 20;
const WEBHOOK_INBOX_ID = /^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/;
let webhookSavedInboxes = [];
let webhookInboxRevision = 0;

function currentWebhookId() {
    const id = webhookInboxInput.value.trim().toLowerCase()
        .replace(/^https:\/\/webhook\.site\/(?:#!\/view\/)?/, '').replace(/\/$/, '');
    return WEBHOOK_INBOX_ID.test(id) ? id : '';
}

function syncWebhookInboxSelection() {
    const id = currentWebhookId();
    const saved = webhookSavedInboxes.find(inbox => inbox.id === id);
    webhookInboxSaved.value = saved?.id || '';
    webhookInboxForget.disabled = !saved;
    webhookInboxOpen.href = id ? `${WEBHOOK_SITE_URL}#!/view/${id}` : WEBHOOK_SITE_URL;
    webhookInboxOpen.textContent = id ? 'Open in Webhook.site' : 'Open Webhook.site';
}

function readWebhookInboxList(value) {
    if (!Array.isArray(value)) return [];
    return value.filter(inbox => typeof inbox?.id === 'string' && WEBHOOK_INBOX_ID.test(inbox.id)
        && typeof inbox.name === 'string').slice(0, MAX_WEBHOOK_INBOXES);
}

function renderWebhookInboxList(value) {
    webhookSavedInboxes = readWebhookInboxList(value);
    const options = webhookSavedInboxes.map(({id, name}) => new Option(name || id, id));
    webhookInboxSaved.replaceChildren(new Option('Choose a saved inbox', ''), ...options);
    syncWebhookInboxSelection();
}

function changeWebhookInbox() {
    webhookInboxRevision++;
    webhookInboxEvents.replaceChildren();
    webhookInboxEvents.hidden = true;
    for (const preview of [webhookInboxDetail, webhookInboxResponse]) {
        preview.textContent = '';
        preview.hidden = true;
    }
    webhookInboxStatus.textContent = '';
    webhookInboxResponseStatus.textContent = '';
    syncWebhookInboxSelection();
}

function showWebhookDelivery(event, selected) {
    for (const row of webhookInboxEvents.children) {
        row.setAttribute('aria-pressed', String(row === selected));
    }
    const headers = Object.entries(event.headers).flatMap(([name, values]) => values.map(value => `${name}: ${value}`));
    webhookInboxDetail.textContent = [event.received_at, `${event.method} ${event.url}`, ...headers, '',
        event.body_preview, ...(event.body_truncated ? ['\n[Body preview truncated]'] : [])].join('\n');
    webhookInboxDetail.scrollTop = 0;
    webhookInboxDetail.hidden = false;
}

function showWebhookDeliveries({events}) {
    webhookInboxDetail.hidden = true;
    webhookInboxDetail.textContent = '';
    webhookInboxEvents.replaceChildren(...events.map(delivery => {
        const row = document.createElement('button');
        row.type = 'button';
        row.className = 'ws-frame';
        row.textContent = `${delivery.method} · ${delivery.received_at}\n${delivery.url}`;
        row.setAttribute('aria-pressed', 'false');
        row.addEventListener('click', () => showWebhookDelivery(delivery, row));
        return row;
    }));
    const count = events.length;
    webhookInboxEvents.hidden = !count;
    return count ? `${count} recent HTTP ${count === 1 ? 'delivery' : 'deliveries'}.` : 'No HTTP deliveries in this inbox.';
}

function showWebhookResponse(response) {
    webhookInboxResponse.textContent = [`Status: ${response.status}`, `Content-Type: ${response.content_type || '—'}`, '',
        response.body_preview, ...(response.body_truncated ? ['\n[Body preview truncated]'] : [])].join('\n');
    webhookInboxResponse.scrollTop = 0;
    webhookInboxResponse.hidden = false;
    return '';
}

async function setWebhookInboxSaved(keep) {
    const id = currentWebhookId();
    if (!id) {
        webhookInboxStatus.textContent = 'Enter a Webhook.site inbox URL or UUID.';
        return;
    }
    const name = webhookInboxName.value.trim();
    const revision = webhookInboxRevision;
    try {
        const message = await navigator.locks.request(WEBHOOK_INBOX_STORAGE, async () => {
            const data = await chrome.storage.local.get(WEBHOOK_INBOX_STORAGE);
            const inboxes = readWebhookInboxList(data[WEBHOOK_INBOX_STORAGE]);
            const index = inboxes.findIndex(inbox => inbox.id === id);
            if (keep && index === -1 && inboxes.length >= MAX_WEBHOOK_INBOXES) {
                return `Forget an inbox before saving another. You can save up to ${MAX_WEBHOOK_INBOXES}.`;
            }
            if (index !== -1) inboxes.splice(index, 1);
            if (keep) inboxes.unshift({id, name});
            await chrome.storage.local.set({[WEBHOOK_INBOX_STORAGE]: inboxes});
            return keep ? 'Inbox saved on this browser profile.' : 'Inbox removed from the saved list.';
        });
        if (revision === webhookInboxRevision) webhookInboxStatus.textContent = message;
    } catch {
        if (revision === webhookInboxRevision) webhookInboxStatus.textContent = 'Could not update saved inboxes.';
    }
}

chrome.storage.onChanged.addListener((changes, area) => {
    if (area === 'local' && changes[WEBHOOK_INBOX_STORAGE]) {
        renderWebhookInboxList(changes[WEBHOOK_INBOX_STORAGE].newValue);
    }
});
chrome.storage.local.get(WEBHOOK_INBOX_STORAGE).then(data => {
    renderWebhookInboxList(data[WEBHOOK_INBOX_STORAGE]);
}).catch(() => {
    if (!webhookInboxRevision) webhookInboxStatus.textContent = 'Could not load saved inboxes.';
});

webhookInboxSaved.addEventListener('change', () => {
    const saved = webhookSavedInboxes.find(inbox => inbox.id === webhookInboxSaved.value);
    webhookInboxInput.value = saved?.id || '';
    webhookInboxName.value = saved?.name || '';
    changeWebhookInbox();
});
webhookInboxInput.addEventListener('input', () => {
    webhookInboxName.value = webhookSavedInboxes.find(inbox => inbox.id === currentWebhookId())?.name || '';
    changeWebhookInbox();
});
webhookInboxForm.addEventListener('reset', event => {
    event.preventDefault();
    webhookInboxInput.value = '';
    webhookInboxName.value = '';
    changeWebhookInbox();
});
$('#webhook-inbox-save').addEventListener('click', () => setWebhookInboxSaved(true));
webhookInboxForget.addEventListener('click', () => setWebhookInboxSaved(false));

async function loadWebhookInbox(button, route, status, loading, show) {
    if (button.disabled) return;
    const inbox = currentWebhookId();
    if (!inbox) {
        status.textContent = 'Enter a Webhook.site inbox URL or UUID.';
        return;
    }
    const revision = webhookInboxRevision;
    button.disabled = true;
    status.textContent = loading;
    try {
        const data = await apiRequest('POST', `/api/webhook-inbox/${route}`, {inbox});
        if (revision === webhookInboxRevision) status.textContent = show(data);
    } catch (error) {
        if (revision === webhookInboxRevision) status.textContent = error.message;
    } finally {
        button.disabled = false;
    }
}

webhookInboxForm.addEventListener('submit', event => {
    event.preventDefault();
    loadWebhookInbox($('#webhook-inbox-refresh'), 'refresh', webhookInboxStatus, 'Reading HTTP deliveries…', showWebhookDeliveries);
});
$('#webhook-inbox-view-response').addEventListener('click', event => {
    loadWebhookInbox(event.currentTarget, 'response', webhookInboxResponseStatus, 'Reading default response…', showWebhookResponse);
});
