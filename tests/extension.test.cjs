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
for (const file of ['repeater', 'decoder']) vm.runInContext(readFileSync(resolve(__dirname, `../extension/js/${file}.js`), 'utf8'), sandbox);

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
