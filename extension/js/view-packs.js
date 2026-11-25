/* Declarative, offline message views. Packages select built-in transforms. */

const VIEW_PACK_FORMAT = 'greytab-views-1';
const VIEW_PACK_LIMIT = 8;
const VIEW_INPUT_LIMIT = 65_536;
const VIEW_OUTPUT_LIMIT = 262_144;
const MESSAGE_VIEW_PLACEMENTS = ['workspace', 'history-request', 'history-response', 'repeater-response'];
const VIEW_PLACEMENTS = [...MESSAGE_VIEW_PLACEMENTS, 'history-exchange', 'history-menu'];
const VIEW_ID_PATTERN = /^[a-z][a-z0-9.-]{1,47}$/;
const EXCHANGE_OPERATIONS = ['http-exchange', 'http-exchange-headers'];

const BUILTIN_VIEW_PACK = {
    id: 'greytab.message-views', name: 'Message views', version: '1.0',
    views: [
        {id: 'json', label: 'Format JSON', operation: 'json-format', placements: MESSAGE_VIEW_PLACEMENTS},
        {id: 'headers', label: 'HTTP headers', operation: 'http-headers', placements: MESSAGE_VIEW_PLACEMENTS},
    ],
};

function validateViewPack(pack) {
    if (!pack || pack.format !== VIEW_PACK_FORMAT || typeof pack.id !== 'string' ||
        !VIEW_ID_PATTERN.test(pack.id) || pack.id === BUILTIN_VIEW_PACK.id ||
        typeof pack.name !== 'string' || !pack.name.trim() || pack.name.length > 64 ||
        typeof pack.version !== 'string' || !pack.version.trim() || pack.version.length > 32 ||
        !Array.isArray(pack.views) || pack.views.length === 0 || pack.views.length > 4) {
        throw new Error('Use a GreyTab view pack with an ID, name, version and 1–4 views.');
    }
    if (Object.keys(pack).some(key => !['format', 'id', 'name', 'version', 'views'].includes(key))) {
        throw new Error('Use only the documented view pack fields.');
    }
    const ids = new Set();
    const views = pack.views.map(view => {
        const exchange = EXCHANGE_OPERATIONS.includes(view?.operation);
        if (!view || typeof view.id !== 'string' || !VIEW_ID_PATTERN.test(view.id) || ids.has(view.id) ||
            Object.keys(view).some(key => !['id', 'label', 'operation', 'placements'].includes(key)) ||
            typeof view.label !== 'string' || !view.label.trim() || view.label.length > 48 ||
            (!exchange && !['json-format', 'http-headers'].includes(view.operation)) ||
            !Array.isArray(view.placements) || !view.placements.length || view.placements.length > VIEW_PLACEMENTS.length ||
            view.placements.some(placement => !VIEW_PLACEMENTS.includes(placement))) {
            throw new Error('Each view needs a unique ID, a label, a supported operation and valid placements.');
        }
        if (exchange) {
            if (!view.placements.includes('history-exchange') || view.placements.some(placement => MESSAGE_VIEW_PLACEMENTS.includes(placement))) {
                throw new Error('Exchange operations need a History exchange placement.');
            }
        } else if (view.placements.includes('history-exchange') ||
                   (view.placements.includes('history-menu') && !view.placements.includes('history-response'))) {
            throw new Error('Single-message menu actions need a History response placement.');
        }
        ids.add(view.id);
        return {id: view.id, label: view.label.trim(), operation: view.operation, placements: [...new Set(view.placements)]};
    });
    return {format: VIEW_PACK_FORMAT, id: pack.id, name: pack.name.trim(), version: pack.version.trim(), views};
}

function formatViewJson(input) {
    if (!input.trim()) throw new Error('There is no JSON body to format.');
    try {
        JSON.parse(input);
    } catch {
        throw new Error('This body is not complete, valid JSON.');
    }
    // Keep the original number spellings, escape sequences and duplicate keys.
    const tokens = input.matchAll(/"(?:[^"\\]|\\[\s\S])*"|[{}\[\],:]|[^\s{}\[\],:]+/g);
    const output = [];
    let length = 0;
    let depth = 0;
    let previous = '';
    function append(text) {
        length += text.length;
        if (length > VIEW_OUTPUT_LIMIT) throw new Error('The formatted JSON exceeds the view limit.');
        output.push(text);
    }
    function newline() {
        append('\n' + '  '.repeat(depth));
    }
    for (const [token] of tokens) {
        const closing = token === '}' || token === ']';
        const previousOpened = previous === '{' || previous === '[';
        if (closing) depth--;
        if (previous === ',' || (closing && !previousOpened) || (previousOpened && !closing)) newline();
        append(token === ':' ? ': ' : token);
        if (token === '{' || token === '[') {
            depth++;
            if (depth > 64) throw new Error('JSON is nested more than 64 levels.');
        }
        previous = token;
    }
    return output.join('');
}

function runMessageView(operation, input) {
    if (EXCHANGE_OPERATIONS.includes(operation)) {
        const {request, response} = input || {};
        if (typeof request !== 'string' || !request || typeof response !== 'string' || !response) {
            throw new Error('This exchange needs a captured request and response.');
        }
        if (request.length + response.length > VIEW_INPUT_LIMIT) throw new Error('This view accepts up to 65,536 characters.');
        if (operation === 'http-exchange-headers') {
            return `${runMessageView('http-headers', request)}\n\n${runMessageView('http-headers', response)}`;
        }
        const end = /\r?\n\r?\n$/.test(request) ? '' : '\n\n';
        return `${request}${end}${response}`;
    }
    const text = input || '';
    if (text.length > VIEW_INPUT_LIMIT) throw new Error('This view accepts up to 65,536 characters.');
    const isHttp = /^(?:HTTP\/\d(?:\.\d)? \d{3}|\S+ +\S+ +HTTP\/\d(?:\.\d)?)(?:[ \r\n]|$)/.test(text);
    const separator = isHttp ? /\r?\n\r?\n/.exec(text) : null;
    if (operation === 'json-format') return formatViewJson(isHttp ? (separator ? text.slice(separator.index + separator[0].length) : '') : text);
    if (operation === 'http-headers') {
        if (!isHttp) throw new Error('Select or paste a raw HTTP message with a start line.');
        return (separator ? text.slice(0, separator.index) : text).replace(/\r\n/g, '\n');
    }
    throw new Error('Unsupported message view.');
}
