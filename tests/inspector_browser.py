#!/usr/bin/env python3
"""Real WASM tests with intercepted transport, or --live-server in GitHub CI only.

External requests are always blocked. Live mode owns one loopback child server
and tests the actual HTTP adapter; its only synthetic response is failure injection.
"""
import argparse
import asyncio
import json
import mimetypes
import subprocess
import os
import http.client
import hashlib
from pathlib import Path
from urllib.parse import urlsplit, unquote
from playwright.async_api import async_playwright, expect
from harness_support import manifest

def actual_http_checks(root):
    records=[]
    def request(target,method='GET',headers=None,expected=200,asset=None):
        connection=http.client.HTTPConnection('127.0.0.1',47831,timeout=5)
        try:
            connection.request(method,target,headers={'Connection':'close',**(headers or {})})
            response=connection.getresponse()
            body=response.read(32*1024*1024+1)
            received={k.lower():v for k,v in response.getheaders()}
            row={'target':target,'method':method,'request_headers':headers or {},'status':response.status,'headers':received,'bytes':len(body),'sha256':hashlib.sha256(body).hexdigest()}
            records.append(row)
            assert response.status==expected,row
            assert received.get('cache-control')=='no-store',row
            assert received.get('x-content-type-options')=='nosniff',row
            assert "script-src 'self' 'wasm-unsafe-eval'" in received.get('content-security-policy',''),row
            assert "frame-ancestors 'none'" in received.get('content-security-policy',''),row
            assert received.get('access-control-allow-origin') is None,row
            assert int(received['content-length'])==len(body),row
            if asset is not None:
                assert body==asset.read_bytes(),row
                mime='application/wasm' if asset.suffix=='.wasm' else 'text/javascript' if asset.suffix=='.js' else 'text/html'
                assert received['content-type'].split(';')[0]==mime,row
            return row
        finally:
            connection.close()
    try:
        request('/api/overview')
        request('/api/overview',headers={'Host':'evil.example'},expected=403)
        request('/api/overview',headers={'Origin':'https://evil.example'},expected=403)
        request('/api/overview',headers={'Origin':'null'},expected=403)
        request('/api/overview',headers={'Sec-Fetch-Site':'cross-site'},expected=403)
        request('/api/overview',method='POST',expected=405)
        request('/api/overview',headers={'Origin':'http://127.0.0.1:47831'})
        request('/',asset=root/'index.html')
        request('/?demo=1',asset=root/'index.html')
        request('/../outside.js',expected=400)
        request('/%2e%2e/outside.js',expected=400)
        assets=sorted([*root.rglob('*.wasm'),*root.rglob('*.js')])
        assert any(p.suffix=='.wasm' for p in assets),'No WASM assets to verify'
        assert any('snippets' in p.parts for p in assets),'No module snippets to verify'
        for asset in assets:
            request('/'+asset.relative_to(root).as_posix(),asset=asset)
    except Exception as exc:
        return {'passed':False,'failure':str(exc),'requests':records}
    return {'passed':True,'requests':records}


async def run(args):
    if args.live_server and os.environ.get('GITHUB_ACTIONS')!='true':
        raise RuntimeError('--live-server is only authorized in native GitHub CI; do not run it in the restricted cloud environment')
    out=Path(args.artifacts);out.mkdir(parents=True,exist_ok=True)
    fixture=json.loads(Path(args.fixture).read_text())
    before=manifest(fixture['state'])
    workspace_before={k:manifest(v) for k,v in fixture['workspaces'].items()}
    server=None;log_task=None
    async def drain_log(stream,first):
        with (out/'server.log').open('wb') as log:
            log.write(first);log.flush()
            while True:
                chunk=await stream.read(8192)
                if not chunk: break
                log.write(chunk);log.flush()
    try:
        if args.live_server:
            server=await asyncio.create_subprocess_exec(str(Path(args.inspector).resolve()),'--state',fixture['state'],'--assets',str(Path(args.assets).resolve()),'--bind','127.0.0.1:47831',stdout=asyncio.subprocess.DEVNULL,stderr=asyncio.subprocess.PIPE)
            first=await asyncio.wait_for(server.stderr.readline(),timeout=10)
            log_task=asyncio.create_task(drain_log(server.stderr,first))
            assert first.startswith(b'Read-only local inspector: http://127.0.0.1:47831'),first.decode(errors='replace')
            assert server.returncode is None,'Owned server exited during readiness'
            # Readiness and hostile requests hit the actual owned TCP listener.
            raw=await asyncio.wait_for(asyncio.to_thread(actual_http_checks,Path(args.assets).resolve()),timeout=120)
            (out/'http-results.json').write_text(json.dumps(raw,indent=2)+'\n')
            assert raw['passed'],raw
        await run_checks(args)
    finally:
        if server is not None and server.returncode is None:
            server.terminate()
            try:
                await asyncio.wait_for(server.wait(),timeout=3)
            except asyncio.TimeoutError:
                server.kill()
                await asyncio.wait_for(server.wait(),timeout=3)
        if log_task is not None:
            await asyncio.wait_for(log_task,timeout=3)
        unchanged=manifest(fixture['state'])==before and {k:manifest(v) for k,v in fixture['workspaces'].items()}==workspace_before
        (out/'server-lifecycle.json').write_text(json.dumps({'live_server':args.live_server,'owned_pid':server.pid if server else None,'exit_code':server.returncode if server else None,'state_and_workspaces_unchanged':unchanged},indent=2)+'\n')
        assert unchanged,'Server startup, inspection, or shutdown modified source state/workspaces'


async def run_checks(args):
    root=Path(args.assets).resolve()
    fixture=json.loads(Path(args.fixture).read_text())
    state=Path(fixture['state'])
    inspector=str(Path(args.inspector).resolve())
    out=Path(args.artifacts);out.mkdir(parents=True,exist_ok=True)
    before=manifest(state)
    live={k:manifest(v) for k,v in fixture['workspaces'].items()}
    events=[];errors=[];dialogs=[];console=[];responses=[];response_tasks=set()
    transport={"history_fail":False}
    # Use exactly the production admission/security headers, not a relaxed mock.
    probe=await asyncio.create_subprocess_exec(inspector,'--state',str(state),'--assets',str(root),'--request','/',stdout=asyncio.subprocess.PIPE,stderr=asyncio.subprocess.PIPE)
    probe_stdout,probe_stderr=await probe.communicate()
    assert probe.returncode==0,probe_stderr.decode()
    static_response=json.loads(probe_stdout)
    assert static_response['status']==200,static_response
    static_headers=static_response['headers']
    assert any(k.lower()=='content-security-policy' for k in static_headers),static_headers
    def response_headers(source,mime,body):
        headers={k:v for k,v in source.items() if k.lower() not in ('content-type','content-length')}
        headers['Content-Type']=mime
        headers['Content-Length']=str(len(body.encode() if isinstance(body,str) else body))
        return headers
    async with async_playwright() as pw:
        browser=await pw.chromium.launch(headless=True,args=['--disable-dev-shm-usage','--no-sandbox'])
        context=await browser.new_context(viewport={'width':1440,'height':1000},service_workers='block')
        async def route(request_route):
            req=request_route.request; u=urlsplit(req.url)
            if u.scheme!='http' or u.netloc!='127.0.0.1:47831':
                events.append({'aborted':req.url});await request_route.abort();return
            target=u.path+('?' + u.query if u.query else '')
            if u.path.startswith('/api/'):
                if u.path=='/api/history' and transport['history_fail']:
                    events.append({'api':target,'status':503,'injected':True})
                    body=json.dumps({'error':{'code':'state_busy'}})
                    injected_headers=response_headers(static_headers,'application/json',body)
                    injected_headers['X-Inspector-Test-Injection']='failure-retry'
                    await request_route.fulfill(status=503,headers=injected_headers,body=body)
                    return
                if args.live_server:
                    await request_route.continue_();return
                proc=await asyncio.create_subprocess_exec(inspector,'--state',str(state),'--request',target,'--method',req.method,stdout=asyncio.subprocess.PIPE,stderr=asyncio.subprocess.PIPE)
                stdout,stderr=await proc.communicate()
                if proc.returncode: raise AssertionError(stderr.decode())
                data=json.loads(stdout)
                events.append({'api':target,'status':data['status']})
                body=json.dumps(data['body'])
                await request_route.fulfill(status=data['status'],headers=response_headers(data['headers'],data['content_type'],body),body=body)
            else:
                if args.live_server:
                    await request_route.continue_();return
                if u.path=='/' or u.path.endswith('.html'):
                    html_proc=await asyncio.create_subprocess_exec(inspector,'--state',str(state),'--assets',str(root),'--request',target,stdout=asyncio.subprocess.PIPE,stderr=asyncio.subprocess.PIPE)
                    html_stdout,html_stderr=await html_proc.communicate()
                    assert html_proc.returncode==0,html_stderr.decode()
                    html_response=json.loads(html_stdout)
                    body=html_response['body']
                    if not isinstance(body,str): body=json.dumps(body)
                    await request_route.fulfill(status=html_response['status'],headers=response_headers(html_response['headers'],html_response['content_type'],body),body=body)
                    return
                relative='index.html' if u.path=='/' else unquote(u.path[1:])
                asset=(root/relative).resolve()
                assert asset.is_relative_to(root),asset
                if not asset.is_file():
                    events.append({'missing_asset':str(asset)});await request_route.fulfill(status=404,body='missing');return
                mime='application/wasm' if asset.suffix=='.wasm' else mimetypes.guess_type(str(asset))[0] or 'application/octet-stream'
                body=asset.read_bytes()
                await request_route.fulfill(status=200,headers=response_headers(static_headers,mime,body),body=body)
        await context.route('**/*',route)
        page=await context.new_page()
        async def observe_response(response):
            headers=await response.all_headers()
            url=urlsplit(response.url)
            target=url.path+('?' + url.query if url.query else '')
            injected='x-inspector-test-injection' in headers
            responses.append({'target':target,'status':response.status,'headers':headers,'injected':injected})
            if args.live_server and url.path.startswith('/api/') and not injected:
                events.append({'api':target,'status':response.status,'actual_http':True})
        def start_observation(response):
            task=asyncio.create_task(observe_response(response))
            response_tasks.add(task)
        page.on('response',start_observation)
        page.on('pageerror',lambda e: errors.append(str(e)))
        page.on('console',lambda message: console.append({'type':message.type,'text':message.text}))
        async def dialog(d): dialogs.append(d.message); await d.dismiss()
        page.on('dialog',dialog)
        try:
            await page.goto('http://127.0.0.1:47831/',wait_until='networkidle')
            await expect(page.locator('.history-entry')).to_have_count(6,timeout=30000)
            await page.screenshot(path=str(out/'private-all.png'),full_page=True)
            # Keyboard navigation must respect input focus rather than hijacking typing.
            await page.locator('.history-entry').first.click()
            await page.keyboard.press('/')
            await expect(page.get_by_label('Filter loaded history')).to_be_focused()
            split_before=await page.get_by_role('button',name='Split',exact=True).get_attribute('aria-pressed')
            await page.keyboard.press('s')
            await expect(page.get_by_label('Filter loaded history')).to_have_value('s')
            assert await page.get_by_role('button',name='Split',exact=True).get_attribute('aria-pressed')==split_before
            await page.get_by_label('Filter loaded history').fill('')
            await page.locator('.history-entry').first.click()
            await page.keyboard.press('j')
            await expect(page.locator('.history-entry').nth(1)).to_have_attribute('aria-pressed','true')
            await page.keyboard.press('k')
            await expect(page.locator('.history-entry').first).to_have_attribute('aria-pressed','true')
            await page.get_by_label('Filter by workspace').select_option('C')
            await expect(page.locator('.history-entry')).to_have_count(1)
            await expect(page.locator('.file-row')).to_have_count(4)
            await page.locator('.file-row',has_text='docs/unicode.txt').click()
            await expect(page.locator('.diff-scroll')).to_contain_text('café 日本語 🚀')
            await expect(page.locator('.diff-scroll')).to_contain_text('<img src=x onerror=alert(1)>')
            assert await page.locator('img[onerror]').count()==0
            assert not dialogs
            await page.get_by_role('button',name='Split',exact=True).click()
            await expect(page.get_by_role('table',name='Side-by-side source diff')).to_be_visible()
            await page.get_by_role('button',name='Wrap',exact=True).click()
            await expect(page.locator('.diff-scroll')).to_have_class('diff-scroll wrap')
            await page.screenshot(path=str(out/'unicode-split.png'),full_page=True)
            await page.locator('.file-row',has_text='data/binary.bin').click()
            await expect(page.locator('.notice')).to_contain_text('Binary file changed')
            await page.locator('.file-row',has_text='docs/huge.txt').click()
            await expect(page.locator('.notice.warning')).to_contain_text('truncated')
            assert await page.locator('.split-row').count()<=8000
            await page.get_by_label('Filter by workspace').select_option('A')
            await expect(page.locator('.history-entry')).to_have_count(2)
            await page.locator('.history-entry').last.click()
            await page.locator('.file-row',has_text='private-broken.py').click()
            await expect(page.locator('.diff-scroll')).to_contain_text('INSPECTOR_PRIVATE_ONLY_A_9ca641')
            await page.get_by_role('button',name='Shared history',exact=True).click()
            await expect(page.locator('.history-entry')).to_have_count(2)
            await expect(page.locator('body')).not_to_contain_text('INSPECTOR_PRIVATE_ONLY_A_9ca641')
            await page.get_by_label('Filter by workspace').select_option('B')
            await expect(page.locator('.history-entry')).to_have_count(1)
            await expect(page.locator('.history-entry')).to_contain_text('quarantined')
            await expect(page.locator('.diff-scroll')).to_contain_text('B incompatible')
            await page.screenshot(path=str(out/'conflict.png'),full_page=True)
            transport['history_fail']=True
            await page.get_by_label('Refresh all inspector data').click()
            await expect(page.get_by_role('alert')).to_contain_text('HTTP 503')
            transport['history_fail']=False
            await page.get_by_role('button',name='Try again',exact=True).click()
            await expect(page.locator('.history-entry')).to_have_count(1)
            await page.get_by_label('Filter loaded history').fill('definitely missing')
            await expect(page.locator('.history-entry')).to_have_count(0)
            await page.get_by_label('Filter loaded history').fill('')
            await page.get_by_label('Show keyboard shortcuts').click()
            await expect(page.get_by_role('dialog')).to_be_visible()
            await page.keyboard.press('Escape')
            await expect(page.get_by_role('dialog')).to_have_count(0)
            await page.get_by_label('Switch light or dark theme').click()
            await expect(page.locator('.inspector')).to_have_class('inspector light')
            await page.set_viewport_size({'width':390,'height':844})
            await page.get_by_label('Mobile workspace',exact=True).select_option('C')
            await page.get_by_role('button',name='Private checkpoints',exact=True).click()
            await expect(page.locator('.history-entry')).to_have_count(1)
            await expect(page.locator('.scope-pill')).to_contain_text('Private scope')
            await page.locator('.file-row',has_text='docs/unicode.txt').click()
            await expect(page.locator('.diff-scroll')).to_contain_text('café 日本語 🚀')
            await page.get_by_role('button',name='Shared history',exact=True).click()
            await expect(page.locator('.history-entry')).to_have_count(2)
            await expect(page.locator('.scope-pill')).to_contain_text('Shared scope')
            await page.locator('.file-row',has_text='docs/unicode.txt').click()
            await expect(page.locator('.diff-path')).to_contain_text('docs/unicode.txt')
            await expect(page.locator('.diff-scroll')).to_contain_text('café 日本語 🚀')
            await expect(page.locator('.loading-state')).to_have_count(0)
            mobile_width=await page.evaluate('({viewport:innerWidth, page:Math.max(document.documentElement.scrollWidth, document.body.scrollWidth)})')
            assert mobile_width['page']<=mobile_width['viewport']+1, mobile_width
            await page.screenshot(path=str(out/'mobile.png'),full_page=True)
            # Finish real-state assertions before taking clearly labelled synthetic previews.
            assert manifest(state)==before, 'Real UI inspection modified state'
            assert {k:manifest(v) for k,v in fixture['workspaces'].items()}==live, 'Real UI inspection modified workspaces'
            if response_tasks: await asyncio.gather(*response_tasks)
            real_api_count=len([e for e in events if 'api' in e])
            await page.set_viewport_size({'width':1440,'height':1000})
            await page.evaluate("localStorage.setItem('wipstash-theme','dark')")
            await page.goto('http://127.0.0.1:47831/?demo=1',wait_until='networkidle')
            await expect(page.locator('.demo-banner')).to_contain_text('Synthetic workspace and source data')
            await expect(page.locator('.inspector')).to_have_class('inspector')
            await page.locator('.file-row',has_text='src/checkpoint.rs').click()
            await expect(page.locator('.diff-scroll')).to_contain_text('fs::rename(&staged, &path)?;')
            await expect(page.locator('.loading-state')).to_have_count(0)
            await page.screenshot(path=str(out/'demo-dark.png'),full_page=True)
            await page.get_by_label('Switch light or dark theme').click()
            await expect(page.locator('.inspector')).to_have_class('inspector light')
            await page.screenshot(path=str(out/'demo-light.png'),full_page=True)
            if response_tasks: await asyncio.gather(*response_tasks)
            assert len([e for e in events if 'api' in e])==real_api_count, 'Synthetic preview unexpectedly called live API'
        except Exception as exc:
            try:
                await page.screenshot(path=str(out/'failure.png'),full_page=True)
                (out/'failure-page.html').write_text(await page.content())
            except Exception as capture_error:
                errors.append('Failure capture: '+str(capture_error))
            (out/'browser-results.json').write_text(json.dumps({'passed':False,'failure':str(exc),'events':events,'responses':responses,'page_errors':errors,'console':console,'dialogs':dialogs},indent=2)+'\n')
            raise
        finally:
            await browser.close()
    state_unchanged=manifest(state)==before
    workspaces_unchanged={k:manifest(v) for k,v in fixture['workspaces'].items()}==live
    unexpected=any('aborted' in e or 'missing_asset' in e for e in events)
    response_errors=[]
    for response in responses:
        headers=response['headers']
        if response['status']!=(503 if response['injected'] else 200):
            response_errors.append({'reason':'unexpected_status','response':response})
        if headers.get('cache-control')!='no-store' or "script-src 'self' 'wasm-unsafe-eval'" not in headers.get('content-security-policy',''):
            response_errors.append({'reason':'missing_production_security_headers','response':response})
    passed=state_unchanged and workspaces_unchanged and not errors and not dialogs and not unexpected and not response_errors
    result={'passed':passed,'transport':('Actual owned loopback HTTP server; external requests blocked; one explicit failure-injection response' if args.live_server else 'All requests intercepted with production security headers; no listener or external network'),'events':events,'responses':responses,'page_errors':errors,'console':console,'dialogs':dialogs,'response_errors':response_errors,'state_unchanged':state_unchanged,'workspaces_unchanged':workspaces_unchanged}
    (out/'browser-results.json').write_text(json.dumps(result,indent=2)+'\n')
    assert passed,result
    print(json.dumps({'passed':True,'api_requests':len(events),'artifacts':str(out)}))

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--assets',required=True)
    parser.add_argument('--live-server',action='store_true',help='Use actual owned loopback HTTP server; native GitHub CI only')
    parser.add_argument('--fixture',default='evidence/inspector/security-fixture-v3/fixture.json')
    parser.add_argument('--inspector',default='services/inspector/target/debug/wipstash-inspector')
    parser.add_argument('--artifacts',default='evidence/inspector/browser')
    args=parser.parse_args()
    try:
        asyncio.run(run(args))
    except Exception as exc:
        out=Path(args.artifacts);out.mkdir(parents=True,exist_ok=True)
        report=out/'browser-results.json'
        if not report.exists():
            report.write_text(json.dumps({'passed':False,'failure':str(exc),'stage':'startup'},indent=2)+'\n')
        raise
