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

from tests.test_burp_extensions import sample_bapp_archive
from tests.test_webhook_site import INBOX, SECOND_INBOX


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
    await page.locator('.history-row-main').first.click()
    await page.click('[data-detail="inspect"]')
    await wait(page, 'document.querySelector("#history-inspector-fields").textContent.includes("Query parameters")')
    splitter = page.locator('#history-splitter')
    left_pane = page.locator('.history-list-pane')
    original = (await left_pane.bounding_box())['width']
    await splitter.press('ArrowRight')
    assert (await left_pane.bounding_box())['width'] > original
    handle = await splitter.bounding_box()
    await page.mouse.move(handle['x'] + 2, handle['y'] + handle['height'] / 2)
    await page.mouse.down()
    await page.mouse.move(handle['x'] - 150, handle['y'] + handle['height'] / 2, steps=6)
    await page.mouse.up()
    assert (await left_pane.bounding_box())['width'] < original
    await splitter.dblclick()
    assert abs((await left_pane.bounding_box())['width'] - original) < 1
    ok('History and Inspector resize by mouse and keyboard')
    await splitter.blur()
    await page.mouse.move(0, 0)
    await page.screenshot(path=output / 'desktop-history-1440.png', animations='disabled', clip={'x': 0, 'y': 0, 'width': 1440, 'height': 720})
    await page.click('#btn-close-detail')
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
        await page.screenshot(path=output / f'history-inspector-{width}.png', animations='disabled')
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
    endpoint = page.get_by_role('button', name='/catalog · 240', exact=True)
    await endpoint.wait_for(state='visible')
    await page.mouse.move(0, 0)
    await page.screenshot(path=output / 'history-sitemap-1440.png', clip={'x': 0, 'y': 0, 'width': 1440, 'height': 478})
    await endpoint.click()
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
    await page.evaluate('sendToRepeater({method: "GET", url: "http://127.0.0.1:19443/echo?view=docs"})')
    await page.click('[data-repeater-res="raw"]')
    await page.click('#btn-repeater-send')
    await wait(page, 'document.querySelector("#repeater-status").textContent === "200"')
    await page.mouse.move(0, 0)
    await page.screenshot(path=output / 'repeater-exchange-1440.png', animations='disabled', clip={'x': 0, 'y': 0, 'width': 1440, 'height': 742})


async def capture_views(page, output):
    for width, height in [(320, 850), (380, 850), (768, 1000), (1440, 1000)]:
        await page.set_viewport_size({'width': width, 'height': height})
        for name in ['proxy', 'repeater', 'intruder', 'tools', 'decoder', 'bookmarklets', 'requests', 'autoscanner', 'utilities', 'extensions', 'settings']:
            await page.click(f'.tab[data-tab="{name}"]')
            await page.evaluate("document.querySelector('.tab-content--active').scrollTop = 0")
            await page.screenshot(path=output / f'{name}-{width}.png', animations='disabled')
            bounds = await page.locator('.tab-content--active').bounding_box()
            assert bounds['x'] + bounds['width'] <= width + 1, (name, bounds)
            assert bounds['y'] + bounds['height'] <= height + 1, (name, bounds)


async def check_desktop_window(context, worker, output, ok):
    workspace_url = f'chrome-extension://{worker.url.split("/")[2]}/sidepanel.html?view=workspace'
    for _ in range(150):
        page = next((candidate for candidate in context.pages if candidate.url == workspace_url), None)
        if page:
            break
        await asyncio.sleep(.05)
    else:
        raise AssertionError('GreyTab did not open its desktop workspace at startup')

    windows = await worker.evaluate('chrome.windows.getAll({populate: true})')
    normal = next(window for window in windows if window['type'] == 'normal')
    assert sum(window['type'] == 'popup' for window in windows) == 1
    await page.set_viewport_size({'width': 1440, 'height': 900})
    await page.wait_for_selector('#btn-focus-browser', state='visible')
    await wait(page, 'document.querySelector("#ws-label").textContent === "Backend connected"')
    await page.screenshot(path=output / 'desktop-start-1440.png')

    # Headless Chromium reports both windows as focused. Check the result of the
    # window API call for the same request used by the Browser button.
    await page.click('#btn-focus-browser')
    result = await page.evaluate('chrome.runtime.sendMessage({type: "focus_browser"})')
    assert result == {'success': True, 'windowId': normal['id']}, result
    target = await worker.evaluate('''async id => {
        const [tab] = await chrome.tabs.query({windowId: id, active: true});
        return tab.url;
    }''', normal['id'])
    assert not target.startswith('chrome-extension://'), target

    panel_url = workspace_url.split('?')[0]
    async with context.expect_page() as panel_event:
        await worker.evaluate('''([windowId, url]) => chrome.tabs.create({windowId, url})''', [normal['id'], panel_url])
    panel = await panel_event.value
    await panel.locator('#btn-external').click()
    assert await worker.evaluate('chrome.windows.getAll({windowTypes: ["popup"]}).then(w => w.length)') == 1
    await panel.close()
    assert await page.locator('.tabs').get_attribute('aria-orientation') == 'vertical'
    ok('Desktop workspace opens once, focuses Chromium and reuses its existing window')
    return page


async def check_expanded_settings(page, output):
    for width in (320, 380, 1440):
        await page.set_viewport_size({'width': width, 'height': 850 if width < 400 else 1000})
        await page.click('.tab[data-tab="settings"]')
        details = page.locator('#ai-settings-details')
        await details.evaluate('(element) => { element.open = true; }')
        await details.locator('summary').scroll_into_view_if_needed()
        await page.screenshot(path=output / f'settings-expanded-{width}.png')
        await page.click('#btn-ai-help')
        dialog = page.locator('#ai-help-modal .modal-content')
        bounds = await dialog.bounding_box()
        assert bounds and bounds['x'] >= 0 and bounds['x'] + bounds['width'] <= width, bounds
        assert await dialog.locator('.modal-body').evaluate('body => body.scrollWidth <= body.clientWidth + 1')
        await page.screenshot(path=output / f'settings-dialog-{width}.png')
        await page.click('#btn-close-ai-help')


async def check_workspace_drafts(context, page, output, ok):
    await page.click('.tab[data-tab="repeater"]')
    await page.locator('#repeater-raw-request').fill('GET /desktop-draft HTTP/1.1\nHost: example.test\n\n')
    await wait(page, '''(async () => {
        const snapshot = await chrome.storage.local.get('greytab_desktop_state_v1');
        return snapshot.greytab_desktop_state_v1?.repeater_state.tabs.some(tab => tab.raw_request.includes('/desktop-draft'));
    })()''')

    panel = await context.new_page()
    await panel.set_viewport_size({'width': 380, 'height': 850})
    await panel.goto(page.url.split('?')[0])
    await panel.wait_for_selector('#app-container', state='visible')
    assert await panel.locator('.tabs').get_attribute('aria-orientation') == 'horizontal'
    await panel.click('.tab[data-tab="repeater"]')
    await panel.locator('#repeater-raw-request').fill('GET /panel-draft HTTP/1.1\nHost: example.test\n\n')
    await wait(panel, '''(async () => {
        const snapshot = await chrome.storage.local.get('greytab_workspace_state_v1');
        return snapshot.greytab_workspace_state_v1?.repeater_state.tabs.some(tab => tab.raw_request.includes('/panel-draft'));
    })()''')
    await panel.click('.tab[data-tab="requests"]')
    await wait(panel, 'document.querySelectorAll("#request-list .request-item").length > 0')
    await panel.locator('.history-row-main').filter(has_text='/catalog').first.click()
    await panel.click('[data-detail="inspect"]')
    await wait(panel, 'document.querySelector("#history-inspector-fields").textContent.includes("Query parameters")')
    await panel.screenshot(path=output / 'desktop-qa-side-panel-380.png', animations='disabled')
    await panel.close()

    await page.reload()
    await page.wait_for_selector('#tab-repeater', state='visible')
    assert '/desktop-draft' in await page.locator('#repeater-raw-request').input_value()
    ok('Desktop and toolbar panel preserve their own Repeater drafts')


async def check_extension_views(page, output, ok):
    await page.click('.tab[data-tab="extensions"]')
    catalog = page.locator('#extension-catalog-list')
    await page.get_by_role('button', name='Install JSON Inspector').wait_for()
    assert await catalog.locator('article').count() == 4
    await page.locator('#extension-tab-catalog').press('ArrowRight')
    assert await page.locator('#extension-tab-installed').get_attribute('aria-selected') == 'true'
    await page.locator('#extension-tab-installed').press('ArrowLeft')
    await page.select_option('#extension-catalog-source', 'bapp')
    assert await catalog.locator('article').count() == 2
    jq = page.get_by_role('link', name='View JQ on BApp Store')
    assert await jq.get_attribute('href') == 'https://portswigger.net/bappstore/c0d90a42c99848588d3df017cca717b5'
    assert await jq.get_attribute('rel') == 'noopener noreferrer'
    assert await catalog.get_by_role('button').count() == 0
    await page.fill('#extension-catalog-search', 'nothing matches')
    assert 'No extensions match' in await catalog.inner_text()
    await page.fill('#extension-catalog-search', 'copy http exchanges')
    assert await catalog.locator('article').count() == 1
    await page.fill('#extension-catalog-search', '')
    await page.select_option('#extension-catalog-source', 'all')
    await page.get_by_role('button', name='Install JSON Inspector').click()
    await page.get_by_role('button', name='Manage JSON Inspector').wait_for()
    await page.get_by_role('button', name='Install HTTP Exchange Export').click()
    await page.get_by_role('button', name='Manage HTTP Exchange Export').wait_for()
    await page.get_by_role('button', name='Manage JSON Inspector').click()
    assert await page.get_by_role('checkbox', name='Enable JSON Inspector').is_checked()
    await page.locator('#view-pack-file').set_input_files(ROOT / 'docs/examples/json-inspector.json')
    await page.click('#view-pack-form button')
    await page.locator('#view-pack-status', has_text='JSON Inspector saved.').wait_for()
    assert await page.get_by_role('checkbox', name='Enable JSON Inspector').count() == 1
    await page.click('#extension-tab-catalog')
    await page.get_by_role('button', name='Manage JSON Inspector').wait_for()

    await page.click('#extension-tab-compatibility')
    await page.locator('#burp-archive').set_input_files({
        'name': 'inspector.bapp', 'mimeType': 'application/octet-stream', 'buffer': sample_bapp_archive(),
    })
    await page.click('#burp-archive-form button')
    report = page.locator('#burp-archive-report')
    await report.wait_for(state='visible')
    result = await report.inner_text()
    for expected in ['build/inspector.jar', 'Montoya', 'Legacy Extender', 'Suite tab', 'HTTP response editor', 'Context menu', 'Swing']:
        assert expected in result, result

    await page.click('#extension-tab-views')
    choice = 'example.json-inspector:json'
    await page.select_option('#workspace-extension-picker', choice)
    await page.fill('#workspace-extension-input', '{"first":9007199254740993,"display":"<b>example</b>"}')
    await page.click('#workspace-extension-form button')
    assert '9007199254740993' in await page.text_content('#workspace-extension-output')
    assert await page.locator('#workspace-extension-output b').count() == 0

    for width in (320, 380, 1440):
        await page.set_viewport_size({'width': width, 'height': 1000})
        await page.click('#extension-tab-catalog')
        await page.screenshot(path=output / f'extension-catalog-{width}.png', animations='disabled')
        await page.click('#extension-tab-compatibility')
        await page.screenshot(path=output / f'extension-archive-{width}.png', animations='disabled')
        await page.click('#extension-tab-views')
        await page.locator('#workspace-extension-input').scroll_into_view_if_needed()
        await page.screenshot(path=output / f'extension-format-{width}.png', animations='disabled')

    await page.click('.tab[data-tab="requests"]')
    await page.click('#btn-history-reset')
    await page.locator('.history-row-main').filter(has_text='/catalog').first.click(button='right')
    await page.get_by_role('button', name='JSON Inspector · Readable JSON').click()
    await wait(page, 'document.querySelector("#history-extension-view pre").textContent.includes(\'"ok": true\')')
    assert await page.input_value('#history-extension-view .message-extension-picker') == choice
    await page.click('#btn-close-detail')

    await page.locator('.history-row-main').filter(has_text='/catalog').first.click(button='right')
    await page.get_by_role('button', name='HTTP Exchange Export · Request and response', exact=True).click()
    exchange = page.locator('#history-extension-view pre')
    assert 'GET /catalog' in await exchange.text_content()
    assert 'HTTP/1.1 200' in await exchange.text_content()
    await page.get_by_role('button', name='Copy view').click()
    await page.locator('#history-extension-view .message-extension-status', has_text='View copied.').wait_for()
    await page.select_option('#history-extension-view .message-extension-picker', 'greytab.exchange-export:headers')
    assert 'HTTP/1.1 200' in await exchange.text_content()
    assert '{"ok": true}' not in await exchange.text_content()
    await page.screenshot(path=output / 'extension-exchange-1440.png', animations='disabled')
    await page.click('#btn-close-detail')

    await page.click('.tab[data-tab="repeater"]')
    await page.click('[data-repeater-res="extensions"]')
    await page.select_option('#repeater-extension-view .message-extension-picker', choice)
    assert '"method": "GET"' in await page.text_content('#repeater-extension-view pre')
    await page.click('[data-repeater-res="raw"]')

    await page.reload()
    await page.wait_for_selector('#app-container', state='visible')
    await page.click('.tab[data-tab="extensions"]')
    await page.get_by_role('button', name='Manage HTTP Exchange Export').wait_for()
    await page.click('#extension-tab-installed')
    toggle = page.get_by_role('checkbox', name='Enable JSON Inspector')
    assert await toggle.is_checked()
    await toggle.uncheck()
    await wait(page, '!Array.from(document.querySelector("#workspace-extension-picker").options).some(option => option.value.startsWith("example."))')
    await page.get_by_role('button', name='Remove JSON Inspector').click()
    await wait(page, '!document.querySelector("#view-pack-list").textContent.includes("JSON Inspector")')
    await page.get_by_role('button', name='Remove HTTP Exchange Export').click()
    await page.click('#extension-tab-catalog')
    await page.get_by_role('button', name='Install HTTP Exchange Export').wait_for()
    await page.screenshot(path=output / 'extension-catalog-clean-1440.png', animations='disabled')
    ok('Extension catalog, BApp report, native pack lifecycle and HTTP exchange clipboard export')


async def check_webhook_inbox(page, output, ok):
    await page.click('.tab[data-tab="utilities"]')
    await page.fill('#webhook-inbox-id', f'https://webhook.site/#!/view/{INBOX}')
    await page.fill('#webhook-inbox-name', 'Orders')
    await page.click('#webhook-inbox-save')
    await page.locator(f'#webhook-inbox-saved option[value="{INBOX}"]').wait_for(state='attached')
    await page.fill('#webhook-inbox-id', SECOND_INBOX)
    await page.fill('#webhook-inbox-name', 'Notifications')
    await page.click('#webhook-inbox-save')
    await page.locator(f'#webhook-inbox-saved option[value="{SECOND_INBOX}"]').wait_for(state='attached')
    await page.reload()
    await page.wait_for_selector('#app-container', state='visible')
    await page.click('.tab[data-tab="utilities"]')
    await page.locator(f'#webhook-inbox-saved option[value="{SECOND_INBOX}"]').wait_for(state='attached')
    await page.select_option('#webhook-inbox-saved', INBOX)
    assert await page.locator('#webhook-inbox-name').input_value() == 'Orders'
    assert await page.locator('#webhook-inbox-open').get_attribute('href') == f'https://webhook.site/#!/view/{INBOX}'
    await page.click('#webhook-inbox-refresh')
    await page.locator('#webhook-inbox-events button').click()
    assert 'x-fixture: second' in await page.inner_text('#webhook-inbox-detail')
    assert '<strong>Delivery text</strong>' in await page.inner_text('#webhook-inbox-detail')
    assert await page.locator('#webhook-inbox-detail strong').count() == 0
    await page.click('#webhook-inbox-view-response')
    response = page.locator('#webhook-inbox-response')
    await response.wait_for(state='visible')
    assert 'Status: 202' in await response.inner_text()
    assert '<strong>Accepted</strong>' in await response.inner_text()
    assert await response.locator('strong').count() == 0
    assert '1 recent HTTP delivery.' in await page.inner_text('#webhook-inbox-status')
    for width in (320, 380, 1440):
        await page.set_viewport_size({'width': width, 'height': 950})
        await page.locator('#webhook-inbox-title').scroll_into_view_if_needed()
        await page.screenshot(path=output / f'webhook-inbox-{width}.png', animations='disabled')
    await page.select_option('#webhook-inbox-saved', SECOND_INBOX)
    assert await response.is_hidden()
    assert await page.locator('#webhook-inbox-detail').is_hidden()
    await page.click('#webhook-inbox-view-response')
    await response.wait_for(state='visible')
    assert 'Status: 204' in await response.inner_text()
    await page.click('#webhook-inbox-forget')
    await page.locator(f'#webhook-inbox-saved option[value="{SECOND_INBOX}"]').wait_for(state='detached')
    assert await page.locator(f'#webhook-inbox-saved option[value="{INBOX}"]').count() == 1
    await page.get_by_role('button', name='Clear', exact=True).click()
    assert await response.is_hidden()
    assert await page.locator('#webhook-inbox-id').input_value() == ''
    ok('Free Webhook.site inbox saves, switches and forgets IDs and displays deliveries and default responses as text')


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
    backend_args = ['-m', 'uvicorn', 'core.api:app', '--host', '127.0.0.1', '--port', '8443']
    if inspection_only:
        backend_args = ['-c', 'import uvicorn, httpx; from functools import partial; '
                        'from core.api import app; from core import webhook_site; '
                        'from tests.test_webhook_site import webhook_provider_fixture; '
                        'webhook_site.read_deliveries = partial(webhook_site.read_deliveries, transport=httpx.MockTransport(webhook_provider_fixture)); '
                        'webhook_site.read_default_response = partial(webhook_site.read_default_response, transport=httpx.MockTransport(webhook_provider_fixture)); '
                        'app.state.open_workspace_on_launch = True; '
                        'uvicorn.run(app, host="127.0.0.1", port=8443)']
    backend = subprocess.Popen([sys.executable, *backend_args], cwd=ROOT, env=env, stdout=log, stderr=log, start_new_session=True)
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
            page = await check_desktop_window(context, worker, output, ok) if inspection_only else await context.new_page()
            page.on('pageerror', lambda e: errors.append(str(e)))
            page.on('dialog', lambda dialog: dialog.accept())
            if not inspection_only:
                await page.goto(f'chrome-extension://{extension_id}/sidepanel.html')
            await page.fill('#session-name', 'Release QA')
            await page.locator('#session-name').press('Enter')
            await page.wait_for_selector('#app-container', state='visible')
            if inspection_only:
                await page.locator('#tool-proxy').focus()
                await page.keyboard.press('ArrowDown')
                assert await page.locator('#tool-proxy').get_attribute('aria-selected') == 'true'
                await page.keyboard.press('Enter')
                assert await page.locator('#tool-requests').get_attribute('aria-selected') == 'true'
                target_page = next(tab for tab in context.pages if tab is not page and tab.url == 'about:blank')
            else:
                target_page = await context.new_page()
            target_page.on('dialog', lambda dialog: dialog.accept())
            await target_page.goto('http://127.0.0.1:19443/html')
            await target_page.goto('https://127.0.0.1:19444/echo')
            if inspection_only:
                current = await page.evaluate('chrome.runtime.sendMessage({type: "get_current_url"})')
                assert current['url'] == target_page.url, current
            await page.click('.tab[data-tab="requests"]')
            await wait(page, 'document.querySelectorAll(".request-item").length >= 2')
            logs = await api('GET', '/api/logs/http')
            assert any(l['url'].startswith('https://127.0.0.1:19444') for l in logs)
            assert not any(':8443' in l['url'] for l in logs)
            ok('HTTP and HTTPS capture; API traffic excluded')
            if inspection_only:
                await check_history_workspace(page, target_page, api, output, ok)
                await check_extension_views(page, output, ok)
                await check_webhook_inbox(page, output, ok)
                await capture_views(page, output)
                await check_expanded_settings(page, output)
                ok('All 11 views at 320/380/768/1440 pixels')
                ok('Expanded settings and dialog at 320/380/1440 pixels')
                await check_workspace_drafts(context, page, output, ok)
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
            ok('All 11 views at 320/380/768/1440 pixels')
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
