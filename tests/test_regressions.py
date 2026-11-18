"""Regression checks for real request semantics and complete audit workflows."""
import asyncio
import json
from urllib.parse import urlparse
from unittest.mock import AsyncMock

import httpx
import pytest
from mitmproxy import http

from core.scanner import ScannerEngine
from core.proxy import PentestProxyAddon, ProxyManager
from core.tools import ToolRunner
from core import extras

pytestmark = pytest.mark.asyncio


async def test_tool_discovery_routes_are_not_shadowed(app_client):
    client, _ = app_client
    for route in ("wordlists", "scripts", "custom", "running"):
        response = await client.get(f"/api/tools/{route}")
        assert response.status_code == 200, (route, response.text)


async def test_untrusted_browser_cannot_control_backend(app_client):
    client, _ = app_client
    for method, url in (("GET", "/api/config"), ("POST", "/api/tools/run")):
        response = await client.request(method, url, headers={"Origin": "https://audited.example"}, json={})
        assert response.status_code == 403
        assert "access-control-allow-origin" not in response.headers
    assert (await client.get('/api/health', headers={'Origin': 'null'})).status_code == 403
    assert (await client.get('/api/health', headers={'Host': 'rebinding.example'})).status_code == 403
    assert (await client.get('/api/health', headers={'Origin': 'chrome-extension://' + 'a' * 32})).status_code == 200


async def test_upload_cannot_escape_wordlist_directory(app_client, tmp_path):
    client, _ = app_client
    for name in ('../../launcher.py', '/tmp/attack.txt', '..\\attack.txt'):
        response = await client.post('/api/tools/wordlists/upload', files={'file': (name, b'a\nb')})
        assert response.status_code == 400
    response = await client.post('/api/tools/wordlists/upload', files={'file': ('payloads.txt', b'a\nb')})
    assert response.status_code == 200
    assert response.json()['filename'] == 'payloads.txt'


async def test_configured_port_does_not_lie_about_running_listener(app_client):
    client, api = app_client
    port = api.proxy_manager.port
    response = await client.post('/api/config', json={'proxy_port': 9123})
    assert response.json()['restart_needed'] is True
    assert (await client.get('/api/config')).json()['proxy_port'] == 9123
    assert (await client.get('/api/proxy/status')).json()['port'] == port
    assert (await client.get('/api/health')).json()['proxy_port'] == port


async def test_scope_is_reset_and_restored_on_session_change(app_client):
    client, api = app_client
    first = (await client.post('/api/sessions', json={'name': 'one', 'target_scope': 'example.com'})).json()
    assert api.proxy_manager.addon.scope_domains == {'example.com'}
    await client.post('/api/sessions', json={'name': 'two'})
    assert not api.proxy_manager.addon.scope_domains
    await client.post(f'/api/sessions/{first["id"]}/activate')
    assert api.proxy_manager.addon.scope_domains == {'example.com'}


async def test_captured_post_is_scanned_without_changing_method(session_client, monkeypatch):
    client, api, sid = session_client
    log_id = await api.db.log_request(sid, 'POST', 'http://example.test/login', request_headers={'Content-Type': 'application/json'}, request_body='{"user":"alice"}')
    scan = AsyncMock()
    monkeypatch.setattr(api.scanner, 'scan_single_request', scan)
    response = await client.post('/api/scanner/from_request', json={'log_id': log_id})
    assert response.status_code == 200
    assert scan.await_args.kwargs['method'] == 'POST'
    assert scan.await_args.kwargs['body'] == '{"user":"alice"}'


async def test_request_bodies_and_metadata_survive_project_roundtrip(session_client):
    client, api, sid = session_client
    text = 'α' * 6000
    log_id = await api.db.log_request(sid, 'POST', 'http://example.test/login', request_body=text, response_body_preview=text)
    await api.db.set_log_meta(log_id, 'blue', 'review token')
    await api.db.add_finding(sid, 'Test finding', source_request_id=log_id)
    logs = (await client.get('/api/logs/http')).json()
    assert logs[0]['response_body_preview'] == text
    response = await client.post('/api/projects/import', json={'type': 'pentestbrowser_project', 'session': {'name': 'source'}, 'http_logs': logs, 'findings': await api.db.get_findings(sid)})
    assert response.status_code == 200, response.text
    new_id = response.json()['id']
    imported = await api.db.get_http_logs(new_id)
    assert imported[0]['request_body'] == text
    assert imported[0]['comment'] == 'review token'
    assert imported[0]['highlight'] == 'blue'
    findings = await api.db.get_findings(new_id)
    assert findings[0]['source_request_id'] == imported[0]['id'] != log_id
    assert (await client.delete(f'/api/logs/http/{imported[0]["id"]}')).status_code == 200
    assert (await api.db.get_findings(new_id))[0]['source_request_id'] is None


async def test_invalid_project_import_rolls_back(session_client):
    client, api, _ = session_client
    before = await api.db.get_sessions()
    response = await client.post('/api/projects/import', json={'type': 'pentestbrowser_project', 'session': {'name': 'bad'}, 'http_logs': [{'url': 'http://example.test'}]})
    assert response.status_code == 400
    assert await api.db.get_sessions() == before


async def test_incremental_history_avoids_loading_bodies(session_client):
    client, api, sid = session_client
    first = await api.db.log_request(sid, 'GET', 'http://example.test/a', response_body_preview='large body')
    second = await api.db.log_request(sid, 'GET', 'http://example.test/b')
    response = await client.get(f'/api/logs/http?after_id={first}&summary=true')
    assert [item['id'] for item in response.json()] == [second]
    assert 'response_body_preview' not in response.json()[0]


@pytest.mark.parametrize('kind', ['query', 'body_form', 'body_json', 'path', 'header', 'cookie'])
async def test_scanner_actually_sends_payloads(kind):
    captured = []
    def handler(request):
        captured.append(request)
        return httpx.Response(200, text='baseline')
    engine = ScannerEngine()
    meta = {'base_form': {'fixed': 'keep'}, 'base_json': {'fixed': 'keep'}, 'segments': ['search'], 'index': 0}
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        response, _, _, request_raw, _ = await engine._inject_param(client, urlparse('http://example.test/search?q=old&empty='), 'q', 'canary', method='POST', insertion_kind=kind, insertion_meta=meta)
    assert response is not None and response.status_code == 200
    assert len(captured) == 1
    assert 'canary' in str(captured[0].url) + str(captured[0].headers) + captured[0].content.decode()
    assert captured[0].method == 'POST'
    assert 'POST ' in request_raw
    assert captured[0].extensions['timeout']['read'] == 12.0


async def test_captured_nested_json_mutates_one_field_and_retains_context():
    engine = ScannerEngine()
    engine.scan_headers = {'Content-Type': 'application/json', 'Authorization': 'Bearer original'}
    engine._single_request = {'method': 'PATCH', 'body': '{"user":{"name":"alice","id":42},"flags":[false]}'}
    points = engine._captured_insertion_points('http://example.test/users?mode=edit')
    point = next(p for p in points if p['name'] == 'user.name')
    requests = []
    def handler(request):
        requests.append(request)
        return httpx.Response(200, text='ok')
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        await engine._inject_param(client, urlparse(point['url']), point['name'], 'canary', method=point['method'], insertion_kind=point['kind'], insertion_meta=point['meta'])
    assert requests[0].method == 'PATCH'
    assert json.loads(requests[0].content) == {'user': {'name': 'canary', 'id': 42}, 'flags': [False]}
    assert requests[0].headers['authorization'] == 'Bearer original'


async def test_match_replace_keeps_duplicate_cookies_and_correct_length(app_client):
    _, _api = app_client
    rule = extras.upsert_rule({'name': 'body', 'phase': 'response', 'target': 'body', 'match': 'old', 'replace': 'longer text'})
    addon = PentestProxyAddon()
    flow = http.HTTPFlow(None, None)
    flow.request = http.Request.make('GET', 'http://example.test/')
    flow.response = http.Response.make(200, b'old', [(b'content-type', b'text/plain'), (b'set-cookie', b'a=1'), (b'set-cookie', b'b=2')])
    addon.response(flow)
    assert flow.response.content == b'longer text'
    assert flow.response.headers['content-length'] == str(len(b'longer text'))
    assert flow.response.headers.get_all('set-cookie') == ['a=1', 'b=2']
    extras.delete_rule(rule.id)


async def test_disabling_interception_releases_requests_without_ui():
    manager = ProxyManager()
    addon = manager.addon
    addon.intercept_enabled = True
    flow = http.HTTPFlow(None, None)
    flow.request = http.Request.make('POST', 'http://example.test/login', b'user=alice')
    addon.request(flow)
    assert flow.intercepted
    manager.set_intercept_mode(False)
    assert not flow.intercepted and not addon._pending_flows
    assert flow.request.content == b'user=alice'


async def test_token_injection_is_limited_to_captured_host(app_client):
    extras.save_token_watch({'enabled': True, 'captured': 'abc', 'captured_host': 'example.test'})
    assert extras.inject_watched_token('example.test', {}) == {'Authorization': 'Bearer abc'}
    assert extras.inject_watched_token('thirdparty.test', {}) == {}


async def test_tool_template_quotes_target_as_one_shell_argument():
    runner = ToolRunner()
    command = runner.build_command('curl', target='http://example.test/?a=1&b=$(danger)')
    import shlex
    assert shlex.split(command) == ['curl', '-v', 'http://example.test/?a=1&b=$(danger)']


async def test_repeater_preserves_body_host_and_no_shared_cookies(app_client, monkeypatch):
    client, api = app_client
    seen = []
    def handler(request):
        seen.append(request)
        return httpx.Response(200, text='écho', headers={'Set-Cookie': 'session=target'})
    await api.repeater_client.aclose()
    api.repeater_client = httpx.AsyncClient(transport=httpx.MockTransport(handler), trust_env=False)
    for _ in range(2):
        response = await client.post('/api/repeater/send', json={'method': 'POST', 'url': 'http://example.test/echo', 'headers': {'Host': 'virtual.test'}, 'body': 'one\n\ntwo'})
        assert response.status_code == 200
        assert response.json()['body'] == 'écho'
        assert response.json()['content_length'] == 5
    assert seen[0].headers['host'] == 'virtual.test'
    assert seen[0].content == b'one\n\ntwo'
    # Separate replays must not silently inherit Set-Cookie from an earlier replay.
    assert 'cookie' not in seen[1].headers


@pytest.mark.parametrize('vulnerable', [True, False])
async def test_ssti_detector_confirms_execution_and_rejects_plain_reflection(vulnerable):
    from core.detectors import ssti
    from urllib.parse import parse_qs
    seen = []
    def handler(request):
        payload = parse_qs(request.url.query.decode())['name'][0]
        seen.append(payload)
        if vulnerable:
            payload = payload.replace('{{7*7}}', '49').replace('{{13*37}}', '481')
        return httpx.Response(200, text=payload, headers={'content-type': 'text/html'})
    engine = ScannerEngine()
    url = 'http://example.test/template?name=alice'
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        await ssti.run(engine, client, url, urlparse(url), 'name')
    assert seen
    assert bool(engine.findings) is vulnerable
    if vulnerable:
        assert engine.findings[0].deterministic_confirmed
        assert '481' in engine.findings[0].response_raw
    assert all(entry.outcome != 'error' for entry in engine.test_log)


@pytest.mark.parametrize('family', ['xss', 'sqli', 'path_traversal', 'lfi', 'open_redirect', 'ssti', 'cmdi', 'crlf', 'ssrf', 'cors', 'oast'])
async def test_every_detector_can_run_against_a_safe_target(family):
    engine = ScannerEngine()
    engine.test_types = [family]
    url = 'http://example.test/search?q=one'
    def handler(request):
        return httpx.Response(200, text='Nothing vulnerable here', headers={'content-type': 'text/plain'})
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        await engine._run_tests_for_insertion(client, {'kind':'query','url':url,'method':'GET','name':'q','baseline':'one','meta':{}})
    assert not engine.findings
    assert not any(entry.outcome == 'error' for entry in engine.test_log)
    if family != 'oast':
        assert engine._requests_sent > 0


async def test_ai_key_is_masked_and_preserved_on_partial_save(app_client):
    client, _ = app_client
    assert (await client.post('/api/config', json={'ai_agent': {'enabled':True,'provider':'custom','model':'qa','api_key':'qa-secret'}})).status_code == 200
    data = (await client.get('/api/config')).json()
    assert 'qa-secret' not in json.dumps(data)
    await client.post('/api/config', json={'ai_agent': {'model': 'new-model'}})
    from core.config import load_user_config
    assert load_user_config()['ai_agent']['api_key'] == 'qa-secret'
    await client.post('/api/config', json={'ai_agent': {'clear_api_key':True}})
    assert load_user_config()['ai_agent']['api_key'] == ''


async def test_tool_output_is_paginated_without_losing_unicode(session_client):
    client, api, sid = session_client
    rid = await api.db.log_tool_start(sid, 'test', 'printf')
    await api.db.update_tool_output(rid, 'á🌍\nline two\n')
    response = await client.get(f'/api/tools/{rid}?output_offset=3')
    assert response.json()['output'] == 'line two\n'
    assert response.json()['output_length'] == 12


async def test_clearing_history_keeps_findings_and_removes_metadata(session_client):
    client, api, sid = session_client
    rid = await api.db.log_request(sid, 'GET', 'http://example.test/')
    await api.db.set_log_meta(rid, 'red', 'note')
    await api.db.add_finding(sid, 'Finding', source_request_id=rid)
    assert (await client.post('/api/logs/http/clear', json={})).status_code == 200
    assert (await api.db.get_findings(sid))[0]['source_request_id'] is None
    assert not (await api.db.get_log_meta(rid))['comment']


async def test_new_session_does_not_expose_previous_scanner_results(app_client):
    client, api = app_client
    api.scanner.test_log.append({'old': True})
    api.scanner._requests_sent = 19
    response = await client.post('/api/sessions', json={'name':'fresh'})
    assert response.status_code == 200
    assert not api.scanner.test_log
    assert api.scanner.status()['requests_sent'] == 0
