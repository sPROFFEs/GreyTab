const test = require('node:test');
const assert = require('node:assert/strict');
const {readFileSync} = require('node:fs');
const {resolve} = require('node:path');
const vm = require('node:vm');
const {webcrypto, createHash} = require('node:crypto');
const sandbox = {
    $: () => null, $$: () => [], dom: {}, state: {},
    document: {getElementById: () => null},
    TextEncoder, TextDecoder, btoa, atob, crypto: webcrypto, URL,
};
vm.createContext(sandbox);
for (const file of ['repeater', 'decoder', 'view-packs']) vm.runInContext(readFileSync(resolve(__dirname, `../extension/js/${file}.js`), 'utf8'), sandbox);

test('raw HTTP keeps body separators and accepts CRLF', () => {
    const request = sandbox.parseRawRequest('POST /login HTTP/1.1\r\nHOST: example.test\r\n\r\none\r\n\r\ntwo');
    assert.equal(request.method, 'POST');
    assert.equal(request.body, 'one\r\n\r\ntwo');
    assert.equal(sandbox.normalizeParsedRequestUrl(request, 'http://127.0.0.1:9000/original'), 'http://127.0.0.1:9000/login');
    assert.equal(request.headers.HOST, 'example.test');
});
test('destination is independent from the editable Host header', () => {
    assert.equal(sandbox.normalizeParsedRequestUrl({url:'/path',headers:{Host:'virtual.example'}}, 'http://127.0.0.1:9000'), 'http://127.0.0.1:9000/path');
    assert.equal(sandbox.normalizeParsedRequestUrl({url:'/',headers:{Host:'example.test'}}, 'https://example.test/deep'), 'https://example.test/');
});
for (const text of ['', 'abc', 'á', 'Hello 🌍', 'x'.repeat(200)]) {
    test(`MD5 matches UTF-8 known digest (${text.length} characters)`, async () => {
        assert.equal(await sandbox.applyDecoderOperation(text, 'md5', 'encode'), createHash('md5').update(text).digest('hex'));
    });
}
for (const operation of ['base64', 'base64url', 'hex', 'unicode', 'ascii-hex', 'url']) {
    test(`${operation} round trips astral Unicode`, async () => {
        const original = 'José 🌍\nsecond line';
        const encoded = await sandbox.applyDecoderOperation(original, operation, 'encode');
        assert.equal(await sandbox.applyDecoderOperation(encoded, operation, 'decode'), original);
    });
}
test('malformed hex is rejected', async () => {
    await assert.rejects(sandbox.applyDecoderOperation('xx', 'hex', 'decode'));
    await assert.rejects(sandbox.applyDecoderOperation('abc', 'hex', 'decode'));
});

test('offline views keep JSON numbers, duplicate fields and HTTP header order intact', () => {
    const body = '{"counter":18446744073709551615,"counter":-0.0,"items":[{},[1,2]],"content":"a\\n b"}';
    const prefix = 'HTTP/1.1 200 OK\r\nSet-Cookie: a=1\r\nSet-Cookie: b=2';
    const input = `${prefix}\r\n\r\n${body}`;
    assert.equal(sandbox.runMessageView('json-format', input), '{\n  "counter": 18446744073709551615,\n  "counter": -0.0,\n  "items": [\n    {},\n    [\n      1,\n      2\n    ]\n  ],\n  "content": "a\\n b"\n}');
    assert.equal(sandbox.runMessageView('http-headers', input), prefix.replaceAll('\r\n', '\n'));
    assert.throws(() => sandbox.runMessageView('json-format', '{"cutoff":'), /valid JSON/);
    assert.throws(() => sandbox.runMessageView('json-format', ' '.repeat(65537)), /65,536/);
});

test('view packs reject executable fields, unrecognized placements and duplicate view IDs', () => {
    const view = {id: 'format', label: 'Formatter', operation: 'json-format', placements: ['history-response']};
    const pack = {format: 'greytab-views-1', id: 'example.formatter', name: 'Local views', version: '1.0', views: [view]};
    assert.equal(sandbox.validateViewPack(pack).views[0].label, 'Formatter');
    assert.throws(() => sandbox.validateViewPack({...pack, script: 'anything'}), /documented/);
    assert.throws(() => sandbox.validateViewPack({...pack, views: [{...view, placements: ['live-proxy']}]}), /valid placements/);
    assert.throws(() => sandbox.validateViewPack({...pack, views: [view, view]}), /unique/);
});

test('exchange exports preserve original messages and render a separate headers-only view', () => {
    const request = 'POST /api HTTP/1.1\r\nHost: example.org\r\n\r\none\r\n\r\ntwo';
    const response = 'HTTP/1.1 200\r\nSet-Cookie: a=1\r\nSet-Cookie: b=2\r\n\r\nok';
    const input = {request, response};
    assert.equal(sandbox.runMessageView('http-exchange', input), `${request}\n\n${response}`);
    assert.equal(sandbox.runMessageView('http-exchange-headers', input),
        'POST /api HTTP/1.1\nHost: example.org\n\nHTTP/1.1 200\nSet-Cookie: a=1\nSet-Cookie: b=2');
    assert.throws(() => sandbox.runMessageView('http-exchange', {request}), /captured request and response/);
    assert.throws(() => sandbox.runMessageView('http-exchange', {request, response: 'x'.repeat(65536)}), /65,536/);
    const pack = {format: 'greytab-views-1', id: 'example.copy', name: 'Copy', version: '1.0',
        views: [{id: 'full', label: 'Full exchange', operation: 'http-exchange', placements: ['history-response']}]};
    assert.throws(() => sandbox.validateViewPack(pack), /History exchange placement/);
});
