// ══════════════════════════════════════════════════════════════════
// Syntax Highlighting (Improved)
// ══════════════════════════════════════════════════════════════════

function highlightHttp(text) {
    if (!text) return '';

    const parts = text.split('\n\n');
    const headersPart = parts[0];
    const bodyPart = parts.slice(1).join('\n\n');

    let html = '';
    const lines = headersPart.split('\n');
    lines.forEach((line, index) => {
        if (index === 0) {
            // Request or Response line
            const words = line.split(' ');
            const first = words[0];

            if (first.startsWith('HTTP/')) {
                // Response line: HTTP/1.1 200 OK
                const statusCode = parseInt(words[1]);
                let statusCls = 'syn-status';
                if (statusCode >= 200 && statusCode < 300) statusCls += ' syn-status-2xx';
                else if (statusCode >= 300 && statusCode < 400) statusCls += ' syn-status-3xx';
                else if (statusCode >= 400 && statusCode < 500) statusCls += ' syn-status-4xx';
                else if (statusCode >= 500) statusCls += ' syn-status-5xx';

                html += `<span class="syn-proto">${escHtml(first)}</span> `;
                html += `<span class="${statusCls}">${escHtml(words.slice(1).join(' '))}</span>\n`;
            } else {
                // Request line: GET /path HTTP/1.1
                const method = first.toUpperCase();
                let methodCls = 'syn-method';
                const methodMap = {
                    'GET': 'syn-method-get', 'POST': 'syn-method-post',
                    'PUT': 'syn-method-put', 'DELETE': 'syn-method-delete',
                    'PATCH': 'syn-method-patch', 'OPTIONS': 'syn-method-options',
                    'HEAD': 'syn-method-head'
                };
                if (methodMap[method]) methodCls += ' ' + methodMap[method];

                const rest = words.slice(1);
                const urlPart = rest[0] || '';
                const protoPart = rest.slice(1).join(' ');

                html += `<span class="${methodCls}">${escHtml(first)}</span> `;
                html += `<span class="syn-url">${escHtml(urlPart)}</span>`;
                if (protoPart) html += ` <span class="syn-proto">${escHtml(protoPart)}</span>`;
                html += '\n';
            }
        } else if (line.includes(':')) {
            const colonIdx = line.indexOf(':');
            const key = line.substring(0, colonIdx);
            const val = line.substring(colonIdx + 1);

            // Highlight specific header values differently
            let valCls = 'syn-header-val';
            const keyLower = key.toLowerCase().trim();
            if (keyLower === 'content-type' || keyLower === 'authorization') {
                valCls = 'syn-header-val-ct';
            }

            html += `<span class="syn-header-key">${escHtml(key)}</span>`;
            html += `<span class="syn-header-sep">:</span>`;
            html += `<span class="${valCls}">${escHtml(val)}</span>\n`;
        } else {
            html += escHtml(line) + '\n';
        }
    });

    if (bodyPart) {
        html += '<span class="syn-body-sep"></span>\n';

        // Detect content type from headers
        let contentType = '';
        for (const line of lines) {
            const lower = line.toLowerCase().trim();
            if (lower.startsWith('content-type:')) {
                contentType = lower.substring(13).trim();
                break;
            }
        }

        if (contentType.includes('json') || (bodyPart.trim().startsWith('{') || bodyPart.trim().startsWith('['))) {
            try {
                const json = JSON.parse(bodyPart);
                html += highlightJson(JSON.stringify(json, null, 2));
            } catch {
                // Malformed JSON — still try to show raw
                html += escHtml(bodyPart);
            }
        } else if (contentType.includes('xml') || contentType.includes('html') || bodyPart.trim().startsWith('<')) {
            html += highlightXml(bodyPart);
        } else if (contentType.includes('x-www-form-urlencoded') || (bodyPart.includes('=') && !bodyPart.includes('<'))) {
            html += highlightUrlEncoded(bodyPart);
        } else {
            html += escHtml(bodyPart);
        }
    }

    return html;
}

function highlightJson(jsonStr) {
    if (!jsonStr) return '';
    // Highlight braces and brackets first, then tokens
    let result = jsonStr.replace(
        /("(?:\\u[a-zA-Z0-9]{4}|\\[^u]|[^\\"])*"(\s*:)?|\b(true|false|null)\b|-?\d+(?:\.\d*)?(?:[eE][+-]?\d+)?|[{}\[\],])/g,
        function (match) {
            if (match === '{' || match === '}' || match === '[' || match === ']') {
                return '<span class="syn-brace">' + match + '</span>';
            }
            if (match === ',') return '<span class="syn-brace">,</span>';
            let cls = 'syn-number';
            if (/^"/.test(match)) {
                if (/:$/.test(match)) {
                    cls = 'syn-key';
                } else {
                    cls = 'syn-string';
                }
            } else if (/true|false/.test(match)) {
                cls = 'syn-bool';
            } else if (/null/.test(match)) {
                cls = 'syn-null';
            }
            return '<span class="' + cls + '">' + escHtml(match) + '</span>';
        }
    );
    return result;
}

function highlightXml(text) {
    if (!text) return '';
    let html = '';
    let i = 0;
    while (i < text.length) {
        // Comments: <!-- ... -->
        if (text.startsWith('<!--', i)) {
            const end = text.indexOf('-->', i);
            const commentEnd = end >= 0 ? end + 3 : text.length;
            html += '<span class="syn-comment">' + escHtml(text.substring(i, commentEnd)) + '</span>';
            i = commentEnd;
        }
        // CDATA: <![CDATA[ ... ]]>
        else if (text.startsWith('<![CDATA[', i)) {
            const end = text.indexOf(']]>', i);
            const cdataEnd = end >= 0 ? end + 3 : text.length;
            html += '<span class="syn-cdata">' + escHtml(text.substring(i, cdataEnd)) + '</span>';
            i = cdataEnd;
        }
        // DOCTYPE: <!DOCTYPE ...>
        else if (text.substring(i, i + 9).toUpperCase() === '<!DOCTYPE') {
            const end = text.indexOf('>', i);
            const dtEnd = end >= 0 ? end + 1 : text.length;
            html += '<span class="syn-doctype">' + escHtml(text.substring(i, dtEnd)) + '</span>';
            i = dtEnd;
        }
        // Tags: <tag attr="val"> or </tag> or <tag/>
        else if (text[i] === '<' && (i + 1 < text.length) && text[i + 1] !== '!') {
            const end = text.indexOf('>', i);
            if (end < 0) {
                html += escHtml(text.substring(i));
                break;
            }
            const tagContent = text.substring(i + 1, end);
            const isClosing = tagContent.startsWith('/');
            const isSelfClosing = tagContent.endsWith('/');
            const clean = tagContent.replace(/^\//, '').replace(/\/$/, '').trim();

            // Extract tag name
            const spaceIdx = clean.search(/[\s]/);
            const tagName = spaceIdx >= 0 ? clean.substring(0, spaceIdx) : clean;
            const attrsStr = spaceIdx >= 0 ? clean.substring(spaceIdx) : '';

            html += '<span class="syn-tag">&lt;' + (isClosing ? '/' : '') + '</span>';
            html += '<span class="syn-tag-name">' + escHtml(tagName) + '</span>';

            // Parse attributes
            if (attrsStr) {
                const attrRegex = /([\w:.-]+)\s*(=)\s*(?:"([^"]*?)"|'([^']*?)'|([\w.-]+))/g;
                let lastIdx = 0;
                let match;
                while ((match = attrRegex.exec(attrsStr)) !== null) {
                    // Text before this attr
                    if (match.index > lastIdx) {
                        html += escHtml(attrsStr.substring(lastIdx, match.index));
                    }
                    html += '<span class="syn-attr-name">' + escHtml(match[1]) + '</span>';
                    html += '<span class="syn-attr-eq">=</span>';
                    const val = match[3] !== undefined ? match[3] : (match[4] !== undefined ? match[4] : match[5]);
                    const quote = match[3] !== undefined ? '"' : (match[4] !== undefined ? "'" : '');
                    html += '<span class="syn-attr-val">' + quote + escHtml(val) + quote + '</span>';
                    lastIdx = match.index + match[0].length;
                }
                if (lastIdx < attrsStr.length) {
                    html += escHtml(attrsStr.substring(lastIdx));
                }
            }

            html += '<span class="syn-tag">' + (isSelfClosing ? '/' : '') + '&gt;</span>';
            i = end + 1;
        }
        // Entity references: &amp; etc
        else if (text[i] === '&') {
            const end = text.indexOf(';', i);
            if (end >= 0 && end - i < 12) {
                html += '<span class="syn-entity">' + escHtml(text.substring(i, end + 1)) + '</span>';
                i = end + 1;
            } else {
                html += escHtml(text[i]);
                i++;
            }
        }
        // Regular text
        else {
            const nextTag = text.indexOf('<', i + 1);
            const nextEntity = text.indexOf('&', i + 1);
            let nextSpecial = text.length;
            if (nextTag >= 0) nextSpecial = Math.min(nextSpecial, nextTag);
            if (nextEntity >= 0) nextSpecial = Math.min(nextSpecial, nextEntity);
            html += escHtml(text.substring(i, nextSpecial));
            i = nextSpecial;
        }
    }
    return html;
}

function highlightUrlEncoded(text) {
    if (!text) return '';
    return text.split('&').map((pair, i) => {
        const sep = i > 0 ? '<span class="syn-param-amp">&amp;</span>' : '';
        const eqIdx = pair.indexOf('=');
        if (eqIdx >= 0) {
            const key = pair.substring(0, eqIdx);
            const val = pair.substring(eqIdx + 1);
            let decodedVal;
            try { decodedVal = decodeURIComponent(val); } catch { decodedVal = val; }
            return `${sep}<span class="syn-param-key">${escHtml(key)}</span><span class="syn-param-eq">=</span><span class="syn-param-val">${escHtml(decodedVal.substring(0, 500))}</span>`;
        }
        return sep + escHtml(pair);
    }).join('');
}

function renderRepeaterRequestPreview() {
    if (!dom.repeaterReqHighlight) return;
    const raw = String(dom.repeaterRawRequest?.value || '');
    dom.repeaterReqHighlight.innerHTML = raw ? highlightHttp(raw) + '\n' : '';
}

function renderIntruderRequestPreview() {
    // Syntax preview removed — highlighting is inline in the editor
}

// ══════════════════════════════════════════════════════════════════
// Decoder / Encoder
// ══════════════════════════════════════════════════════════════════

const decoderChain = [];

function b64UrlEncode(str) {
    return btoa(str).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
function b64UrlDecode(str) {
    let s = str.replace(/-/g, '+').replace(/_/g, '/');
    while (s.length % 4) s += '=';
    return atob(s);
}

function hexEncode(str) {
    return Array.from(new TextEncoder().encode(str)).map(b => b.toString(16).padStart(2, '0')).join('');
}
function hexDecode(hex) {
    const bytes = hex.match(/.{1,2}/g);
    if (!bytes) return '';
    return new TextDecoder().decode(new Uint8Array(bytes.map(b => parseInt(b, 16))));
}

function htmlEntityEncode(str) {
    return str.replace(/[&<>"'\/]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;', '/': '&#x2F;' }[c] || c));
}
function htmlEntityDecode(str) {
    const el = document.createElement('textarea');
    el.innerHTML = str;
    return el.value;
}

function unicodeEscape(str) {
    return Array.from(str).map(c => '\\u' + c.charCodeAt(0).toString(16).padStart(4, '0')).join('');
}
function unicodeUnescape(str) {
    return str.replace(/\\u([0-9a-fA-F]{4})/g, (_, hex) => String.fromCharCode(parseInt(hex, 16)));
}

function asciiHexEncode(str) {
    return Array.from(new TextEncoder().encode(str)).map(b => '\\x' + b.toString(16).padStart(2, '0')).join('');
}
function asciiHexDecode(str) {
    const cleaned = str.replace(/\\x/g, '');
    return hexDecode(cleaned);
}

function urlEncodeFull(str) {
    return Array.from(new TextEncoder().encode(str)).map(b => '%' + b.toString(16).padStart(2, '0').toUpperCase()).join('');
}

async function hashDigest(algo, str) {
    const data = new TextEncoder().encode(str);
    const hashBuffer = await crypto.subtle.digest(algo, data);
    return Array.from(new Uint8Array(hashBuffer)).map(b => b.toString(16).padStart(2, '0')).join('');
}

// Simple MD5 (no crypto.subtle support for MD5)
function md5(str) {
    // Minimal MD5 implementation
    function md5cycle(x, k) {
        let a = x[0], b = x[1], c = x[2], d = x[3];
        a = ff(a, b, c, d, k[0], 7, -680876936); d = ff(d, a, b, c, k[1], 12, -389564586);
        c = ff(c, d, a, b, k[2], 17, 606105819); b = ff(b, c, d, a, k[3], 22, -1044525330);
        a = ff(a, b, c, d, k[4], 7, -176418897); d = ff(d, a, b, c, k[5], 12, 1200080426);
        c = ff(c, d, a, b, k[6], 17, -1473231341); b = ff(b, c, d, a, k[7], 22, -45705983);
        a = ff(a, b, c, d, k[8], 7, 1770035416); d = ff(d, a, b, c, k[9], 12, -1958414417);
        c = ff(c, d, a, b, k[10], 17, -42063); b = ff(b, c, d, a, k[11], 22, -1990404162);
        a = ff(a, b, c, d, k[12], 7, 1804603682); d = ff(d, a, b, c, k[13], 12, -40341101);
        c = ff(c, d, a, b, k[14], 17, -1502002290); b = ff(b, c, d, a, k[15], 22, 1236535329);
        a = gg(a, b, c, d, k[1], 5, -165796510); d = gg(d, a, b, c, k[6], 9, -1069501632);
        c = gg(c, d, a, b, k[11], 14, 643717713); b = gg(b, c, d, a, k[0], 20, -373897302);
        a = gg(a, b, c, d, k[5], 5, -701558691); d = gg(d, a, b, c, k[10], 9, 38016083);
        c = gg(c, d, a, b, k[15], 14, -660478335); b = gg(b, c, d, a, k[4], 20, -405537848);
        a = gg(a, b, c, d, k[9], 5, 568446438); d = gg(d, a, b, c, k[14], 9, -1019803690);
        c = gg(c, d, a, b, k[3], 14, -187363961); b = gg(b, c, d, a, k[8], 20, 1163531501);
        a = gg(a, b, c, d, k[13], 5, -1444681467); d = gg(d, a, b, c, k[2], 9, -51403784);
        c = gg(c, d, a, b, k[7], 14, 1735328473); b = gg(b, c, d, a, k[12], 20, -1926607734);
        a = hh(a, b, c, d, k[5], 4, -378558); d = hh(d, a, b, c, k[8], 11, -2022574463);
        c = hh(c, d, a, b, k[11], 16, 1839030562); b = hh(b, c, d, a, k[14], 23, -35309556);
        a = hh(a, b, c, d, k[1], 4, -1530992060); d = hh(d, a, b, c, k[4], 11, 1272893353);
        c = hh(c, d, a, b, k[7], 16, -155497632); b = hh(b, c, d, a, k[10], 23, -1094730640);
        a = hh(a, b, c, d, k[13], 4, 681279174); d = hh(d, a, b, c, k[0], 11, -358537222);
        c = hh(c, d, a, b, k[3], 16, -722521979); b = hh(b, c, d, a, k[6], 23, 76029189);
        a = hh(a, b, c, d, k[9], 4, -640364487); d = hh(d, a, b, c, k[12], 11, -421815835);
        c = hh(c, d, a, b, k[15], 16, 530742520); b = hh(b, c, d, a, k[2], 23, -995338651);
        a = ii(a, b, c, d, k[0], 6, -198630844); d = ii(d, a, b, c, k[7], 10, 1126891415);
        c = ii(c, d, a, b, k[14], 15, -1416354905); b = ii(b, c, d, a, k[5], 21, -57434055);
        a = ii(a, b, c, d, k[12], 6, 1700485571); d = ii(d, a, b, c, k[3], 10, -1894986606);
        c = ii(c, d, a, b, k[10], 15, -1051523); b = ii(b, c, d, a, k[1], 21, -2054922799);
        a = ii(a, b, c, d, k[8], 6, 1873313359); d = ii(d, a, b, c, k[15], 10, -30611744);
        c = ii(c, d, a, b, k[6], 15, -1560198380); b = ii(b, c, d, a, k[13], 21, 1309151649);
        a = ii(a, b, c, d, k[4], 6, -145523070); d = ii(d, a, b, c, k[11], 10, -1120210379);
        c = ii(c, d, a, b, k[2], 15, 718787259); b = ii(b, c, d, a, k[9], 21, -343485551);
        x[0] = add32(a, x[0]); x[1] = add32(b, x[1]); x[2] = add32(c, x[2]); x[3] = add32(d, x[3]);
    }
    function cmn(q, a, b, x, s, t) { a = add32(add32(a, q), add32(x, t)); return add32((a << s) | (a >>> (32 - s)), b); }
    function ff(a, b, c, d, x, s, t) { return cmn((b & c) | ((~b) & d), a, b, x, s, t); }
    function gg(a, b, c, d, x, s, t) { return cmn((b & d) | (c & (~d)), a, b, x, s, t); }
    function hh(a, b, c, d, x, s, t) { return cmn(b ^ c ^ d, a, b, x, s, t); }
    function ii(a, b, c, d, x, s, t) { return cmn(c ^ (b | (~d)), a, b, x, s, t); }
    function add32(a, b) { return (a + b) & 0xFFFFFFFF; }
    function md5blk(s) {
        const md5blks = []; for (let i = 0; i < 64; i += 4) md5blks[i >> 2] = s.charCodeAt(i) + (s.charCodeAt(i + 1) << 8) + (s.charCodeAt(i + 2) << 16) + (s.charCodeAt(i + 3) << 24);
        return md5blks;
    }
    function rhex(n) { let s = ''; for (let j = 0; j < 4; j++) s += ('0' + ((n >> (j * 8 + 4)) & 0x0F).toString(16) + ((n >> (j * 8)) & 0x0F).toString(16)); return s; }
    function hex(x) { return x.map(rhex).join(''); }
    function md5str(s) {
        const n = s.length; let state = [1732584193, -271733879, -1732584194, 271733878];
        let i;
        for (i = 64; i <= n; i += 64) md5cycle(state, md5blk(s.substring(i - 64, i)));
        s = s.substring(i - 64);
        const tail = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        for (i = 0; i < s.length; i++) tail[i >> 2] |= s.charCodeAt(i) << ((i % 4) << 3);
        tail[i >> 2] |= 0x80 << ((i % 4) << 3);
        if (i > 55) { md5cycle(state, tail); for (i = 0; i < 16; i++) tail[i] = 0; }
        tail[14] = n * 8;
        md5cycle(state, tail);
        return hex(state);
    }
    return md5str(str);
}

async function applyDecoderOperation(input, operation, direction) {
    const isEncode = direction === 'encode';
    switch (operation) {
        case 'base64':
            return isEncode ? btoa(unescape(encodeURIComponent(input))) : decodeURIComponent(escape(atob(input)));
        case 'base64url':
            return isEncode ? b64UrlEncode(unescape(encodeURIComponent(input))) : decodeURIComponent(escape(b64UrlDecode(input)));
        case 'url':
            return isEncode ? encodeURIComponent(input) : decodeURIComponent(input);
        case 'url-full':
            return isEncode ? urlEncodeFull(input) : decodeURIComponent(input);
        case 'hex':
            return isEncode ? hexEncode(input) : hexDecode(input);
        case 'html':
            return isEncode ? htmlEntityEncode(input) : htmlEntityDecode(input);
        case 'unicode':
            return isEncode ? unicodeEscape(input) : unicodeUnescape(input);
        case 'ascii-hex':
            return isEncode ? asciiHexEncode(input) : asciiHexDecode(input);
        case 'md5':
            return md5(input);
        case 'sha1':
            return await hashDigest('SHA-1', input);
        case 'sha256':
            return await hashDigest('SHA-256', input);
        case 'sha512':
            return await hashDigest('SHA-512', input);
        case 'length':
            return String(input.length);
        case 'reverse':
            return Array.from(input).reverse().join('');
        case 'lower':
            return input.toLowerCase();
        case 'upper':
            return input.toUpperCase();
        default:
            return input;
    }
}

function detectEncoding(input) {
    if (!input) return null;
    const trimmed = input.trim();
    // JWT: three Base64URL segments separated by dots
    if (/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*$/.test(trimmed)) {
        try { JSON.parse(b64UrlDecode(trimmed.split('.')[0])); return 'jwt'; } catch { }
    }
    // Base64
    if (/^[A-Za-z0-9+/]+=*$/.test(trimmed) && trimmed.length >= 4 && trimmed.length % 4 <= 1) {
        try { atob(trimmed); return 'base64'; } catch { }
    }
    // Base64URL
    if (/^[A-Za-z0-9_-]+$/.test(trimmed) && trimmed.length >= 4) {
        try { b64UrlDecode(trimmed); return 'base64url'; } catch { }
    }
    // Hex
    if (/^[0-9a-fA-F]+$/.test(trimmed) && trimmed.length % 2 === 0 && trimmed.length >= 4) {
        return 'hex';
    }
    // URL-encoded
    if (/%[0-9a-fA-F]{2}/.test(trimmed)) return 'url';
    // Unicode escape
    if (/\\u[0-9a-fA-F]{4}/.test(trimmed)) return 'unicode';
    // ASCII hex
    if (/\\x[0-9a-fA-F]{2}/.test(trimmed)) return 'ascii-hex';
    // HTML entities
    if (/&[a-zA-Z]+;|&#x?[0-9a-fA-F]+;/.test(trimmed)) return 'html';
    return null;
}

function sendToDecoder(text) {
    const input = $('#decoder-input');
    if (input) input.value = text;
    // Switch to decoder tab
    const tab = document.querySelector('.tab[data-tab="decoder"]');
    if (tab) tab.click();
    // Auto-detect
    const detected = detectEncoding(text);
    if (detected === 'jwt') {
        decodeJwt(text.trim());
    } else if (detected) {
        const opSelect = $('#decoder-operation');
        if (opSelect) opSelect.value = detected;
        // Set direction to decode
        const btnDec = $('#btn-dir-decode');
        const btnEnc = $('#btn-dir-encode');
        if (btnDec) { btnDec.classList.add('decoder-dir-btn--active'); btnDec.classList.remove('btn--ghost'); btnDec.classList.add('btn--primary'); }
        if (btnEnc) { btnEnc.classList.remove('decoder-dir-btn--active'); btnEnc.classList.add('btn--ghost'); btnEnc.classList.remove('btn--primary'); }
    }
}

function decodeJwt(token) {
    const parts = token.split('.');
    if (parts.length < 2) return;
    try {
        const header = JSON.parse(b64UrlDecode(parts[0]));
        const payload = JSON.parse(b64UrlDecode(parts[1]));
        const sig = parts[2] || '';
        $('#jwt-header').value = JSON.stringify(header, null, 2);
        $('#jwt-payload').value = JSON.stringify(payload, null, 2);
        $('#jwt-signature').textContent = sig || '(none)';
        $('#jwt-status').textContent = `Decoded. Algorithm: ${header.alg || 'none'}`;
        $('#jwt-status').style.color = 'var(--success)';
    } catch (e) {
        $('#jwt-status').textContent = 'Invalid JWT: ' + e.message;
        $('#jwt-status').style.color = 'var(--danger)';
    }
}

async function rebuildJwt() {
    try {
        const headerJson = $('#jwt-header').value.trim();
        const payloadJson = $('#jwt-payload').value.trim();
        const secret = $('#jwt-secret').value;
        const header = JSON.parse(headerJson);
        const payload = JSON.parse(payloadJson);

        const headerB64 = b64UrlEncode(JSON.stringify(header));
        const payloadB64 = b64UrlEncode(JSON.stringify(payload));
        const unsigned = headerB64 + '.' + payloadB64;

        let sig = '';
        if (secret && header.alg && header.alg.startsWith('HS')) {
            // HMAC-SHA signing
            const algoMap = { 'HS256': 'SHA-256', 'HS384': 'SHA-384', 'HS512': 'SHA-512' };
            const algo = algoMap[header.alg] || 'SHA-256';
            const key = await crypto.subtle.importKey(
                'raw', new TextEncoder().encode(secret),
                { name: 'HMAC', hash: algo }, false, ['sign']
            );
            const sigBuf = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(unsigned));
            sig = btoa(String.fromCharCode(...new Uint8Array(sigBuf))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
        } else {
            sig = b64UrlEncode('unsigned');
        }

        const jwt = unsigned + '.' + sig;
        const decodedOutput = $('#jwt-encoded-input');
        if (decodedOutput) {
            decodedOutput.value = jwt;
        }

        $('#jwt-signature').textContent = sig;
        $('#jwt-status').textContent = secret ? `Signed with ${header.alg}` : 'Unsigned (no secret provided)';
        $('#jwt-status').style.color = secret ? 'var(--success)' : 'var(--warning)';
    } catch (e) {
        $('#jwt-status').textContent = 'Error: ' + e.message;
        $('#jwt-status').style.color = 'var(--danger)';
    }
}

// Wire up decoder UI
$('#btn-decoder-apply')?.addEventListener('click', async () => {
    const input = $('#decoder-input').value;
    const op = $('#decoder-operation').value;
    const dirBtn = document.querySelector('.decoder-dir-btn--active');
    const dir = dirBtn?.dataset.dir || 'encode';
    try {
        const result = await applyDecoderOperation(input, op, dir);
        $('#decoder-output').value = result;
        decoderChain.push(`${dir === 'encode' ? '→' : '←'} ${op}`);
        $('#decoder-chain-log').textContent = decoderChain.join(' | ');
    } catch (e) {
        $('#decoder-output').value = `Error: ${e.message}`;
    }
});

$('#btn-dir-encode')?.addEventListener('click', () => {
    $('#btn-dir-encode').classList.add('decoder-dir-btn--active', 'btn--primary');
    $('#btn-dir-encode').classList.remove('btn--ghost');
    $('#btn-dir-decode').classList.remove('decoder-dir-btn--active', 'btn--primary');
    $('#btn-dir-decode').classList.add('btn--ghost');
});

$('#btn-dir-decode')?.addEventListener('click', () => {
    $('#btn-dir-decode').classList.add('decoder-dir-btn--active', 'btn--primary');
    $('#btn-dir-decode').classList.remove('btn--ghost');
    $('#btn-dir-encode').classList.remove('decoder-dir-btn--active', 'btn--primary');
    $('#btn-dir-encode').classList.add('btn--ghost');
});

$('#btn-decoder-clear')?.addEventListener('click', () => {
    $('#decoder-input').value = '';
    $('#decoder-output').value = '';
    decoderChain.length = 0;
    $('#decoder-chain-log').textContent = '—';
});

$('#btn-decoder-paste')?.addEventListener('click', async () => {
    try {
        const text = await navigator.clipboard.readText();
        $('#decoder-input').value = text;
    } catch { /* clipboard API may not be available */ }
});

$('#btn-decoder-copy')?.addEventListener('click', () => {
    const output = $('#decoder-output').value;
    if (output) navigator.clipboard.writeText(output).catch(() => { });
});

$('#btn-decoder-swap')?.addEventListener('click', () => {
    const inp = $('#decoder-input');
    const out = $('#decoder-output');
    const tmp = inp.value;
    inp.value = out.value;
    out.value = tmp;
});

$('#btn-decoder-to-input')?.addEventListener('click', () => {
    $('#decoder-input').value = $('#decoder-output').value;
    $('#decoder-output').value = '';
});

$('#btn-decoder-detect')?.addEventListener('click', () => {
    const input = $('#decoder-input').value;
    const detected = detectEncoding(input);
    if (detected === 'jwt') {
        decodeJwt(input.trim());
        $('#decoder-output').value = '[JWT detected — decoded in JWT Inspector below]';
    } else if (detected) {
        $('#decoder-operation').value = detected;
        // Auto-set to decode
        $('#btn-dir-decode').click();
        $('#decoder-output').value = `[Detected: ${detected}] Click Apply to decode.`;
    } else {
        $('#decoder-output').value = '[No encoding detected]';
    }
});

// Buttons removed from HTML, keeping logic for safety if called programmatically
$('#btn-jwt-decode')?.addEventListener('click', () => {
    const input = $('#jwt-encoded-input')?.value.trim() || $('#decoder-input')?.value.trim();
    if (input) decodeJwt(input);
});

$('#btn-jwt-encode')?.addEventListener('click', () => {
    rebuildJwt();
});

// Live updating for JWT like jwt.io
$('#jwt-header')?.addEventListener('input', () => rebuildJwt());
$('#jwt-payload')?.addEventListener('input', () => rebuildJwt());
$('#jwt-secret')?.addEventListener('input', () => rebuildJwt());

// Left-Column Auto-Decode
$('#jwt-encoded-input')?.addEventListener('input', (e) => {
    const text = e.target.value.trim();
    if (text) {
        decodeJwt(text);
    }
});

$('#decoder-input')?.addEventListener('input', (e) => {
    const text = e.target.value.trim();
    if (detectEncoding(text) === 'jwt') {
        decodeJwt(text);

        // Also populate the specific JWT encoded input if empty
        const jwtEncoded = $('#jwt-encoded-input');
        if (jwtEncoded && !jwtEncoded.value) {
            jwtEncoded.value = text;
        }

        // Auto-switch operation to jwt
        const opSelect = $('#decoder-operation');
        if (opSelect) opSelect.value = 'jwt';

        // Let the user know it was decoded below
        const output = $('#decoder-output');
        if (output && output.value.indexOf('[JWT detected') === -1) {
            output.value = '[Live JWT detected — decoded in JWT Inspector below]';
        }
    }
});

// ══════════════════════════════════════════════════════════════════
