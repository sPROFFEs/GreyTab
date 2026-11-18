#!/usr/bin/env python3
"""Real Linux extension QA. Uses only local targets; saves screenshots and a JSON report."""
from __future__ import annotations
import argparse
import asyncio
import base64
import hashlib
import json
import os
import signal
import traceback
import shutil
import ssl
import subprocess
import sys
import tempfile
import threading
import time
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse, parse_qs

import httpx
from playwright.async_api import async_playwright

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))


class Target(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'
    def log_message(self, *args):
        pass
    def do_GET(self):
        self.respond()
    do_POST = do_PUT = do_PATCH = do_DELETE = do_GET
    def respond(self):
        body = self.rfile.read(int(self.headers.get('content-length', '0')))
        if self.path.startswith('/slow'):
            time.sleep(.5)
        if self.path.startswith('/redirect'):
            self.send_response(302); self.send_header('Location', '/echo'); self.send_header('Content-Length', '0'); self.end_headers(); return
        if self.path.startswith('/html'):
            content = b'<!doctype html><title>Audit target</title><h1>Local target</h1><input id="hidden-field" hidden disabled value="secret"><div id="invisible" style="display:none">Hidden</div><details id="closed"><summary>More</summary>Details</details>'
            ct = 'text/html'
        elif self.path.startswith('/ssti'):
            try: value = json.loads(body).get('user', {}).get('name', '')
            except ValueError: value = parse_qs(urlparse(self.path).query).get('name', [''])[0]
            content = value.replace('{{7*7}}', '49').replace('{{13*37}}', '481').encode()
            ct = 'text/plain'
        elif self.path.startswith('/graphql'):
            content = json.dumps({'data': {'__schema': {'types': [{'name': 'Query'}]}}}).encode(); ct = 'application/json'
        else:
            content = json.dumps({'method': self.command, 'path': self.path, 'body': body.decode(errors='replace'), 'headers': dict(self.headers), 'token': 'qa-token', 'timestamp': time.time()}, ensure_ascii=False).encode(); ct = 'application/json'
        self.send_response(200); self.send_header('Content-Type', ct); self.send_header('Content-Length', str(len(content))); self.send_header('Set-Cookie', 'session=qa; Path=/'); self.end_headers()
        try: self.wfile.write(content)
        except (BrokenPipeError, ConnectionResetError): pass


def tls_context(runtime):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'localhost')])
    cert = x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(datetime.now(timezone.utc) - timedelta(days=1)).not_valid_after(datetime.now(timezone.utc) + timedelta(days=1)).sign(key, hashes.SHA256())
    cert_file, key_file = runtime / 'target.pem', runtime / 'target.key'
    cert_file.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_file.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); context.load_cert_chain(cert_file, key_file)
    return context


async def wait(page, expression, timeout=15):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if await page.evaluate(expression):
            return
        await asyncio.sleep(.05)
    raise AssertionError('Timed out: ' + expression + '\n' + await page.locator('body').inner_text())


async def check_history_workspace(page, target_page, api, output, ok):
    await page.bring_to_front()
    logs = [
        {
            'id': i + 1, 'method': 'GET', 'url': f'http://127.0.0.1:19443/catalog?q={i}&q=two',
            'host': '127.0.0.1', 'path': f'/catalog?q={i}&q=two', 'status_code': 200,
            'content_type': 'application/json', 'content_length': 42, 'duration_ms': 17,
            'request_headers': {'Accept': 'application/json'},
            'response_headers': {'Content-Type': 'application/json'}, 'response_body_preview': '{"ok": true}',
        }
        for i in range(240)
    ]
    logs[0]['comment'] = 'Old office record'
    await api('POST', '/api/projects/import', json={
        'type': 'pentestbrowser_project', 'session': {'name': 'History QA'}, 'http_logs': logs,
    })
    await page.click('.tab[data-tab="requests"]')
    await wait(page, 'document.querySelectorAll("#request-list > .request-item").length === 200')
    newer = page.locator('#btn-history-newer')
    older = page.locator('#btn-history-older')
    assert await newer.is_disabled() and not await older.is_disabled()

    await page.click('#btn-history-live')
    await older.click()
    await wait(page, 'document.querySelector("#history-page-status").textContent.includes("Page 2")')
    assert await page.locator('.request-item').count() == 40
    await target_page.goto('http://127.0.0.1:19443/html')
    await wait(page, 'document.querySelector("#history-page-status").textContent.includes("New traffic")')
    assert await page.locator('.request-item').count() == 40
    await newer.click()
    await wait(page, 'document.querySelector("#history-page-status").textContent.includes("Page 1")')
    first_id = await page.locator('.request-item').first.get_attribute('data-id')
    await page.click('.tab[data-tab="decoder"]')
    await target_page.goto('http://127.0.0.1:19443/echo?paused=1')
    await page.click('.tab[data-tab="requests"]')
    assert await page.locator('.request-item').first.get_attribute('data-id') == first_id
    await page.click('#btn-history-live')
    await wait(page, f'document.querySelector(".request-item")?.dataset.id !== "{first_id}"')
    await page.click('#btn-history-live')
    ok('200-row History pagination and pause stay stable with incoming traffic and tab switches')

    await page.fill('#history-search', 'Old office record')
    await wait(page, 'document.querySelectorAll(".request-item").length === 1')
    row = page.locator('.request-item .history-row-main').first
    assert 'q=0&q=two' in await row.inner_text()
    await row.click()
    await page.click('[data-detail="inspect"]')
    await wait(page, 'document.querySelector("#history-note").value === "Old office record"')
    assert 'Query parameters (2)' in await page.inner_text('#history-inspector')
    assert 'Request headers (1)' in await page.inner_text('#history-inspector')
    await page.fill('#history-note', 'Investigated')
    await page.select_option('#history-highlight', 'blue')
    await page.click('#history-note-form [type=submit]')
    await wait(page, 'document.querySelector("#history-detail-status").textContent === "Note saved."')
    await page.fill('#history-search', 'Investigated')
    await wait(page, 'document.querySelector(".request-item")?.dataset.highlight === "blue"')
    ok('Global search finds an older note and Inspector preserves repeated query fields and annotations')

    for width in (320, 380, 768, 1440):
        await page.set_viewport_size({'width': width, 'height': 950})
        await page.screenshot(path=output / f'history-inspector-{width}.png')
        assert await page.evaluate('document.querySelector("#history-inspector").clientWidth > 100')
        assert await page.evaluate('document.querySelector("#request-detail").getBoundingClientRect().right <= innerWidth')
    await page.click('#btn-close-detail')
    await page.click('#btn-history-reset')
    await wait(page, 'document.querySelectorAll(".request-item").length === 200')
    await page.check('#history-regex-toggle')
    await page.fill('#history-search', 'q=239&')
    await wait(page, 'document.querySelectorAll(".request-item").length === 1')
    await page.fill('#history-search', '[')
    await wait(page, 'document.querySelector("#history-page-status").textContent.includes("regular expression")')
    await page.click('#btn-history-reset')
    await page.click('#btn-sitemap')
    await page.locator('#sitemap-panel summary').first.click()
    await page.get_by_role('button', name='/catalog · 240', exact=True).click()
    await wait(page, 'document.querySelector("#history-page-status").textContent.includes("/catalog")')
    assert await page.locator('.request-item').count() == 200
    ok('Page regex handles invalid patterns and Site Map opens endpoint history')

    async with page.expect_download() as event:
        await page.click('#btn-export-har')
    download = await event.value
    har_file = output / 'history.har'
    await download.save_as(har_file)
    entries = json.loads(har_file.read_text())['log']['entries']
    assert sum('/catalog?' in entry['request']['url'] for entry in entries) == len(logs)
    ok('HAR downloads the full session as valid JSON across multiple batches')

    await page.click('.tab[data-tab="repeater"]')
    await page.evaluate('sendToRepeater({method: "GET", url: "http://127.0.0.1:19443/slow"})')
    await page.click('#btn-repeater-send')
    await page.fill('#repeater-raw-request', 'GET /draft HTTP/1.1\nHost: localhost\n\n')
    await wait(page, 'document.querySelector("#repeater-status").textContent === "200"')
    assert '/draft' in await page.input_value('#repeater-raw-request')
    assert 'method' in await page.text_content('#repeater-res-raw')
    await page.click('[data-repeater-res="render"]')
    assert 'method' in await page.locator('#repeater-res-render').get_attribute('srcdoc')
    ok('Repeater paints the selected response view and keeps the draft during a send')


async def capture_views(page, output):
    for width, height in [(320, 850), (380, 850), (768, 1000), (1440, 1000)]:
        await page.set_viewport_size({'width': width, 'height': height})
        for name in ['proxy', 'repeater', 'intruder', 'tools', 'decoder', 'bookmarklets', 'requests', 'autoscanner', 'utilities', 'settings']:
            await page.click(f'.tab[data-tab="{name}"]')
            await page.evaluate("document.querySelector('.tab-content--active').scrollTop = 0")
            await page.screenshot(path=output / f'{name}-{width}.png')
            bounds = await page.locator('.tab-content--active').bounding_box()
            assert bounds['x'] + bounds['width'] <= width + 1, (name, bounds)
            assert bounds['y'] + bounds['height'] <= height + 1, (name, bounds)


async def run(chrome, output, inspection_only=False):
    output.mkdir(parents=True, exist_ok=True)
    errors, checks = [], []
    runtime = Path(tempfile.mkdtemp(prefix='greytab-qa-'))
    target = ThreadingHTTPServer(('127.0.0.1', 19443), Target)
    secure = ThreadingHTTPServer(('127.0.0.1', 19444), Target)
    secure.socket = tls_context(runtime).wrap_socket(secure.socket, server_side=True)
    for server in (target, secure): threading.Thread(target=server.serve_forever, daemon=True).start()
    env = {**os.environ, 'GREYTAB_RUNTIME_DIR': str(runtime), 'GREYTAB_CHROME_BIN': chrome}
    log = (output / 'backend.log').open('w')
    backend = subprocess.Popen([sys.executable, '-m', 'uvicorn', 'core.api:app', '--host', '127.0.0.1', '--port', '8443'], cwd=ROOT, env=env, stdout=log, stderr=log, start_new_session=True)
    async def api(method, path, **kwargs):
        async with httpx.AsyncClient(trust_env=False) as client:
            response = await client.request(method, 'http://127.0.0.1:8443' + path, **kwargs)
            response.raise_for_status(); return response.json()
    def ok(name):
        checks.append(name); print('PASS', name, flush=True)
    try:
        for _ in range(100):
            try:
                if (await api('GET', '/api/health'))['proxy_running']: break
            except (httpx.HTTPError, OSError): pass
            if backend.poll() is not None: raise RuntimeError((output / 'backend.log').read_text())
            await asyncio.sleep(.1)
        else: raise RuntimeError('Backend startup timeout')
        from cryptography import x509
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
        cert = x509.load_pem_x509_certificate((runtime / 'certs/mitmproxy-ca-cert.pem').read_bytes())
        spki = base64.b64encode(hashlib.sha256(cert.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)).digest()).decode()
        async with async_playwright() as p:
            context = await p.chromium.launch_persistent_context(str(runtime / 'profile'), executable_path=chrome, headless=True, args=[f'--disable-extensions-except={ROOT / "extension"}', f'--load-extension={ROOT / "extension"}', '--proxy-server=http://127.0.0.1:8080', '--proxy-bypass-list=<-loopback>;127.0.0.1:8443;localhost:8443', f'--ignore-certificate-errors-spki-list={spki}', '--disable-quic'])
            worker = context.service_workers[0] if context.service_workers else await context.wait_for_event('serviceworker')
            extension_id = worker.url.split('/')[2]
            page = await context.new_page()
            page.on('pageerror', lambda e: errors.append(str(e)))
            page.on('dialog', lambda dialog: dialog.accept())
            await page.goto(f'chrome-extension://{extension_id}/sidepanel.html')
            await page.fill('#session-name', 'Release QA')
            await page.click('#btn-create-session')
            await page.wait_for_selector('#app-container', state='visible')
            target_page = await context.new_page()
            target_page.on('dialog', lambda dialog: dialog.accept())
            await target_page.goto('http://127.0.0.1:19443/html')
            await target_page.goto('https://127.0.0.1:19444/echo')
            await page.click('.tab[data-tab="requests"]')
            await wait(page, 'document.querySelectorAll(".request-item").length >= 2')
            logs = await api('GET', '/api/logs/http')
            assert any(l['url'].startswith('https://127.0.0.1:19444') for l in logs)
            assert not any(':8443' in l['url'] for l in logs)
            ok('HTTP and HTTPS capture; API traffic excluded')
            if inspection_only:
                await check_history_workspace(page, target_page, api, output, ok)
                await capture_views(page, output)
                ok('All 10 views at 320/380/768/1440 pixels')
                assert not errors, errors
                await context.close()
                return

            await page.bring_to_front()
            await page.evaluate('sendToRepeater({method:"POST", url:"http://127.0.0.1:19443/echo", request_headers:{"Content-Type":"text/plain"}, request_body:"one\\n\\ntwo"})')
            assert await page.input_value('#repeater-target') == 'http://127.0.0.1:19443/echo'
            await page.click('#btn-repeater-send')
            await wait(page, 'document.querySelector("#repeater-status").textContent === "200"')
            assert 'one' in await page.text_content('#repeater-res-raw')
            await page.click('#btn-repeater-send')
            await wait(page, '!document.querySelector("#btn-repeater-send").disabled')
            await page.click('[data-repeater-res="diff"]')
            assert 'timestamp' in await page.text_content('#repeater-res-diff')
            ok('Repeater preserves HTTP destination/body and compares responses')
            await page.evaluate('sendToRepeater({method:"GET",url:"http://127.0.0.1:19443/slow"})')
            await page.click('#btn-repeater-send')
            await page.click('#btn-repeater-new-tab')
            await page.fill('#repeater-raw-request', 'GET /keep-me HTTP/1.1\nHost: example.test\n\n')
            await page.wait_for_timeout(700)
            assert '/keep-me' in await page.input_value('#repeater-raw-request')
            assert await page.text_content('#repeater-status') == '---'
            ok('In-flight Repeater response cannot overwrite another tab')
            # Exercise request/response interception and edited bodies via the real proxy loop.
            await page.click('.tab[data-tab="proxy"]')
            await page.locator('label:has(> #proxy-intercept)').click()
            await asyncio.sleep(.15)
            navigation = asyncio.create_task(target_page.goto('http://127.0.0.1:19443/echo?intercept=1', timeout=15000))
            await page.wait_for_selector('#intercept-editor', state='visible')
            await page.evaluate('document.querySelector("#editor-raw").value += ""')
            await page.click('#btn-forward')
            await navigation
            await page.locator('label:has(> #proxy-intercept)').click()
            await page.locator('label:has(> #proxy-intercept-response)').click()
            await asyncio.sleep(.15)
            navigation = asyncio.create_task(target_page.goto('http://127.0.0.1:19443/echo?response=1', timeout=15000))
            try:
                await page.wait_for_selector('#response-intercept-editor', state='visible', timeout=6000)
            except Exception:
                print('STATUS', await api('GET', '/api/proxy/status'), 'PENDING', await api('GET', '/api/proxy/pending'), 'ERRORS', errors, flush=True)
                await page.screenshot(path=str(output / 'failure.png'))
                raise
            await page.click('#btn-forward-response')
            await navigation
            await page.locator('label:has(> #proxy-intercept-response)').click()
            ok('Proxy forwards request and response interceptions')
            # Intruder modes, including independent sets.
            for mode, payloads, expected in [('sniper','a\nb',4),('battering_ram','a\nb',2),('pitchfork','a\nb\n\nx\ny',2),('cluster_bomb','a\nb\n\nx\ny',4)]:
                await page.evaluate('sendToIntruder({method:"GET",url:"http://127.0.0.1:19443/echo?a=x&b=y",request_headers:{}})')
                await page.fill('#intruder-raw-request', 'GET /echo?a=§x§&b=§y§ HTTP/1.1\nHost: 127.0.0.1:19443\n\n')
                await page.select_option('#intruder-attack-type', mode)
                await page.select_option('#intruder-payload-type', 'simple_list')
                await page.fill('#intruder-payloads', payloads)
                await page.click('#btn-intruder-start')
                await wait(page, 'document.querySelector("#intruder-progress").textContent.startsWith("Done:")')
                assert await page.evaluate('state.intruder.results.length') == expected
                assert await page.evaluate('state.intruder.results.every(r => r.status_code === 200)')
            ok('All four Intruder attack modes')
            await page.select_option('#intruder-payload-type', 'numbers')
            await page.fill('#intruder-num-step', '0')
            await page.click('#btn-intruder-start')
            assert 'positive step' in await page.text_content('#intruder-progress')
            await page.select_option('#intruder-payload-type', 'simple_list')
            ok('Invalid Intruder number ranges rejected without hanging')
            await page.click('.tab[data-tab="decoder"]')
            await page.fill('#decoder-input', 'Hola á 🌍')
            await page.select_option('#decoder-operation', 'base64')
            await page.click('#btn-dir-encode'); await page.click('#btn-decoder-apply')
            encoded = await page.input_value('#decoder-output')
            assert base64.b64decode(encoded).decode() == 'Hola á 🌍'
            ok('Unicode decoder round trip')
            await page.click('.tab[data-tab="utilities"]')
            await page.fill('#race-target', 'http://127.0.0.1:19443/echo')
            await page.fill('#race-request', 'POST /echo HTTP/1.1\nHost: 127.0.0.1:19443\n\nrace=1')
            await page.fill('#race-parallel', '3'); await page.click('#btn-race-run')
            await wait(page, 'document.querySelector("#race-output").textContent.includes("Responses: 3")')
            await page.fill('#graphql-url', 'http://127.0.0.1:19443/graphql')
            await page.click('#btn-graphql-run')
            await wait(page, 'document.querySelector("#graphql-output").textContent.includes("__schema")')
            await page.fill('#macro-name', 'Login QA')
            await page.fill('#macro-steps', json.dumps([{'method':'GET','url':'http://127.0.0.1:19443/echo','extract':{'token':'"token":\\s*"([^"]+)"'}}]))
            await page.click('#btn-macro-save')
            await wait(page, 'document.querySelector("#macro-output").textContent === "Macro saved."')
            await page.click('#btn-macro-run')
            await wait(page, 'document.querySelector("#macro-output").textContent.includes("qa-token")')
            ok('Race, GraphQL and login macro UI workflows')
            # Execute built-ins in a normal target tab using the extension scripting API.
            await target_page.goto('http://127.0.0.1:19443/html')
            await target_page.bring_to_front()
            result = await page.evaluate('runBookmarkletOnActiveTab(BUILTIN_BOOKMARKLETS[0].code)')
            assert result and await target_page.locator('#hidden-field').is_visible()
            assert not await target_page.locator('#hidden-field').is_disabled()
            await page.evaluate('runBookmarkletOnActiveTab(BUILTIN_BOOKMARKLETS[0].code)')
            assert not await target_page.locator('#hidden-field').is_visible()
            assert await target_page.locator('#hidden-field').is_disabled()
            ok('Smart Reveal toggle restores target fields')
            await page.bring_to_front()
            # WebSocket frames pass through the same local proxy and session DB.
            from websockets.asyncio.server import serve
            async def echo(socket):
                async for value in socket: await socket.send(value)
            async with serve(echo, '127.0.0.1', 19445):
                await target_page.evaluate("""() => new Promise((resolve, reject) => {
                    const ws = new WebSocket('ws://127.0.0.1:19445/echo');
                    ws.onopen = () => ws.send('qa-frame');
                    ws.onmessage = e => { ws.close(); resolve(e.data); };
                    ws.onerror = reject;
                })""")
            await page.click('.tab[data-tab="utilities"]')
            await page.click('#btn-ws-refresh')
            await wait(page, 'document.querySelector("#ws-frames").textContent.includes("qa-frame")')
            ok('Real WebSocket frames captured and displayed')
            # External tools stream into a late-opening terminal tab.
            await page.click('.tab[data-tab="tools"]')
            await page.locator('#tab-tools details').evaluate_all('(els)=>els.forEach(el=>el.open=true)')
            await page.fill('#tool-raw-command', "printf 'qa-tool\\n'")
            async with context.expect_page() as terminal_event: await page.click('#btn-run-tool')
            terminal = await terminal_event.value
            await terminal.wait_for_load_state()
            await wait(terminal, 'document.querySelector("#status-badge").textContent === "Completed"')
            assert 'qa-tool' in await terminal.text_content('#terminal-output')
            await terminal.close()
            ok('Tool execution and terminal recovery after fast completion')
            # JWTs retain Unicode and alg=none uses an empty signature.
            await page.click('.tab[data-tab="decoder"]')
            await page.fill('#jwt-header', '{"alg":"none","typ":"JWT"}')
            await page.fill('#jwt-payload', '{"name":"José 🌍"}')
            await page.evaluate('rebuildJwt()')
            jwt = await page.input_value('#jwt-encoded-input')
            assert jwt.endswith('.')
            assert json.loads(base64.urlsafe_b64decode(jwt.split('.')[1] + '=='))['name'] == 'José 🌍'
            assert await page.evaluate("applyDecoderOperation('🌍', 'unicode', 'encode').then(s => applyDecoderOperation(s, 'unicode', 'decode'))") == '🌍'
            assert await page.evaluate("applyDecoderOperation('á', 'md5', 'encode')") == hashlib.md5('á'.encode()).hexdigest()
            ok('JWT, Unicode escapes and UTF-8 hashes')
            # Manual findings must be saved into backend reports.
            await page.click('.tab[data-tab="requests"]')
            await page.locator('.request-item').first.click()
            await wait(page, 'state.currentLog !== null')
            await page.click('#btn-add-finding')
            await wait(page, 'state.scanner.findings.some(f => f.vuln_type === "manual")')
            assert any(f['source_tool'] == 'manual' for f in await api('GET','/api/findings'))
            ok('Manual findings persist into exported reports')
            # A real captured POST scan must find the fixture's nested-JSON SSTI.
            await target_page.evaluate("fetch('http://127.0.0.1:19443/ssti', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({user:{name:'alice'},fixed:'keep'})}).then(r=>r.text())")
            captured = next(l for l in await api('GET','/api/logs/http') if l['method']=='POST' and '/ssti' in l['url'])
            await api('POST','/api/scanner/from_request', json={'log_id':captured['id'],'test_types':['ssti']})
            await wait(page, 'state.scanner.findings.some(f => f.vuln_type === "ssti")')
            for _ in range(100):
                scan = await api('GET','/api/scanner/status')
                if not scan['running']: break
                await asyncio.sleep(.05)
            active_finding = next(f for f in scan['findings'] if f['vuln_type']=='ssti')
            assert active_finding['request_raw'].startswith('POST ')
            assert active_finding['deterministic_confirmed']
            assert scan['requests_sent'] > 1
            ok('Captured POST scan confirms nested JSON SSTI and persists evidence')
            # End-to-end downloads must contain data and be valid project/report formats.
            await page.click('.tab[data-tab="requests"]')
            async with page.expect_download() as event: await page.click('#btn-export-har')
            download = await event.value
            har_file = output / 'traffic.har'; await download.save_as(har_file)
            assert json.loads(har_file.read_text())['log']['entries']
            async with page.expect_download() as event: await page.click('#btn-export-findings')
            await (await event.value).save_as(output / 'report.html')
            async with page.expect_download() as event: await page.click('#btn-save-project')
            project_file = output / 'project.pbx'; await (await event.value).save_as(project_file)
            project = json.loads(project_file.read_text()); assert project['http_logs'] and project['ws_logs']
            await page.set_input_files('#file-load-project', project_file)
            await wait(page, 'document.querySelector("#active-session-name").textContent.includes("imported")')
            assert (await api('GET','/api/logs/http'))
            ok('HAR/report/project export and complete project import')
            # CRUD for a custom executable is accessible from Settings.
            await page.click('.tab[data-tab="settings"]')
            await page.click('#btn-show-add-tool')
            await page.fill('#tool-form-name','qa-custom')
            await page.fill('#tool-form-command','printf')
            await page.fill('#tool-form-args','%s qa-custom')
            await page.locator('label:has(> #tool-form-requires-target)').click()
            await page.click('#btn-save-tool')
            await wait(page, 'document.querySelector("#custom-tools-list").textContent.includes("qa-custom")')
            await page.locator('[data-tool-delete="qa-custom"]').click()
            await wait(page, '!document.querySelector("#custom-tools-list").textContent.includes("qa-custom")')
            ok('Custom tool creation and deletion from Settings')
            # Import a larger history and verify the rendered working set stays bounded.
            started = time.perf_counter()
            bulk = [{'id':i+1,'method':'GET','url':f'http://127.0.0.1:19443/load/{i}','host':'127.0.0.1','path':f'/load/{i}','status_code':200,'response_body_preview':'x'*2048} for i in range(2000)]
            await api('POST','/api/projects/import',json={'type':'pentestbrowser_project','session':{'name':'Load QA'},'http_logs':bulk,'ws_logs':project['ws_logs']})
            await wait(page, 'document.querySelectorAll("#request-list > .request-item").length === 200')
            load_metrics = {'stored_requests':2000,'rendered_requests':await page.locator('#request-list > .request-item').count(),'import_and_render_ms':round((time.perf_counter()-started)*1000,2)}
            (output / 'performance.json').write_text(json.dumps(load_metrics,indent=2))
            ok('2000-request history imports with a 200-row rendering budget')
            # Expand configuration controls before narrow screenshots.
            await page.click('.tab[data-tab="settings"]')
            await page.locator('#tab-settings details').evaluate_all('(els)=>els.forEach(el=>el.open=true)')
            await page.click('#btn-rule-new')
            await page.locator('.rule-row [data-f="name"]').last.fill('QA rule')
            await page.locator('.rule-row [data-f="name"]').last.blur()
            await capture_views(page, output)
            ok('All 10 views at 320/380/768/1440 pixels')
            assert not errors, errors
            ok('No uncaught extension JavaScript errors')
            await context.close()
    except BaseException:
        traceback.print_exc()
        raise
    finally:
        backend.terminate()
        try: backend.wait(timeout=15)
        except subprocess.TimeoutExpired: backend.kill(); backend.wait()
        for server in (target, secure): server.shutdown(); server.server_close()
        log.close()
        (output / 'qa.json').write_text(json.dumps({'checks':checks,'errors':errors,'browser':chrome},indent=2))
        shutil.rmtree(runtime, ignore_errors=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--chromium', default=str(ROOT / 'browser/chrome'))
    parser.add_argument('--output', type=Path, default=ROOT / 'tests/_runtime/browser')
    parser.add_argument('--inspection-only', action='store_true', help='Run local traffic, History, Repeater draft and layout checks.')
    args = parser.parse_args()
    asyncio.run(run(args.chromium, args.output, args.inspection_only))
