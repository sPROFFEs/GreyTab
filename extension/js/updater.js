const updatesVersion = $('#updates-version');
const updatesCheck = $('#updates-check');
const updatesPrepare = $('#updates-prepare');
const updatesStatus = $('#updates-status');
const extensionVersion = chrome.runtime.getManifest().version;
let updateUiBusy = false;
let updatePoll;

updatesVersion.textContent = `GreyTab ${extensionVersion}`;

function renderUpdater(update) {
    const {enabled, installed, latest, phase, source, message} = update;
    updatesVersion.textContent = installed === extensionVersion
        ? `GreyTab ${installed}`
        : `Backend ${installed} · Extension ${extensionVersion}`;
    updatesCheck.disabled = !enabled || phase === 'downloading' || phase === 'ready';
    updatesPrepare.hidden = phase !== 'available';
    updatesPrepare.disabled = false;
    const labels = {
        unavailable: 'The updater is available when GreyTab is started from an installed release.',
        available: `${latest} is available${source ? ' via ' + source : ''}.`,
        current: 'GreyTab is up to date.',
        downloading: 'Downloading and verifying the release…',
        ready: `${latest} is ready. Close all GreyTab and Chromium windows and reopen GreyTab to install it.`,
    };
    updatesStatus.textContent = message || labels[phase] || '';
    if (phase === 'downloading') updatePoll = setTimeout(refreshUpdater, 1200);
}

async function requestUpdater(method, suffix, loading) {
    if (updateUiBusy) return;
    updateUiBusy = true;
    clearTimeout(updatePoll);
    if (loading) {
        updatesStatus.textContent = loading;
        updatesCheck.disabled = true;
        updatesPrepare.disabled = true;
    }
    try {
        renderUpdater(await apiRequest(method, `/api/updates${suffix}`));
    } catch (error) {
        updatesStatus.textContent = error.message;
        if (!loading && error.message.startsWith('HTTP 404:')) {
            const health = await apiRequest('GET', '/api/health').catch(() => null);
            if (health?.version && health.version !== extensionVersion) {
                updatesVersion.textContent = `Backend ${health.version} · Extension ${extensionVersion}`;
                updatesStatus.textContent = 'Close all GreyTab and Chromium windows and reopen GreyTab.';
            }
        }
        if (loading) {
            updatesCheck.disabled = false;
            updatesPrepare.disabled = false;
        }
    } finally {
        updateUiBusy = false;
    }
}

function refreshUpdater() {
    return requestUpdater('GET', '');
}

updatesCheck.addEventListener('click', () => requestUpdater('POST', '/check', 'Checking GitHub releases…'));
updatesPrepare.addEventListener('click', () => requestUpdater('POST', '/prepare', 'Preparing update…'));
