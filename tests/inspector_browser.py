#!/usr/bin/env python3
"""Real WASM browser checks with every request intercepted, no listening sockets.

All virtual-origin assets come from --assets; all API reads execute the service's
in-memory --request hook. Any other request is aborted before network access.
"""
import argparse
import asyncio
import json
import mimetypes
import subprocess
from pathlib import Path
from urllib.parse import urlsplit, unquote
from playwright.async_api import async_playwright, expect
from harness_support import manifest

async def run(args):
    root=Path(args.assets).resolve()
    fixture=json.loads(Path(args.fixture).read_text())
    state=Path(fixture['state'])
    inspector=str(Path(args.inspector).resolve())
    out=Path(args.artifacts);out.mkdir(parents=True,exist_ok=True)
    before=manifest(state)
    live={k:manifest(v) for k,v in fixture['workspaces'].items()}
    events=[];errors=[];dialogs=[];console=[]
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
                    await request_route.fulfill(status=503,headers=response_headers(static_headers,'application/json',body),body=body)
                    return
                proc=await asyncio.create_subprocess_exec(inspector,'--state',str(state),'--request',target,'--method',req.method,stdout=asyncio.subprocess.PIPE,stderr=asyncio.subprocess.PIPE)
                stdout,stderr=await proc.communicate()
                if proc.returncode: raise AssertionError(stderr.decode())
                data=json.loads(stdout)
                events.append({'api':target,'status':data['status']})
                body=json.dumps(data['body'])
                await request_route.fulfill(status=data['status'],headers=response_headers(data['headers'],data['content_type'],body),body=body)
            else:
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
        page.on('pageerror',lambda e: errors.append(str(e)))
        page.on('console',lambda message: console.append({'type':message.type,'text':message.text}))
        async def dialog(d): dialogs.append(d.message); await d.dismiss()
        page.on('dialog',dialog)
        try:
            await page.goto('http://127.0.0.1:47831/',wait_until='networkidle')
            await expect(page.locator('.history-entry')).to_have_count(6,timeout=30000)
            await page.screenshot(path=str(out/'private-all.png'),full_page=True)
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
            await page.screenshot(path=str(out/'mobile.png'),full_page=True)
        except Exception as exc:
            try:
                await page.screenshot(path=str(out/'failure.png'),full_page=True)
                (out/'failure-page.html').write_text(await page.content())
            except Exception as capture_error:
                errors.append('Failure capture: '+str(capture_error))
            (out/'browser-results.json').write_text(json.dumps({'passed':False,'failure':str(exc),'events':events,'page_errors':errors,'console':console,'dialogs':dialogs},indent=2)+'\n')
            raise
        finally:
            await browser.close()
    state_unchanged=manifest(state)==before
    workspaces_unchanged={k:manifest(v) for k,v in fixture['workspaces'].items()}==live
    unexpected=any('aborted' in e or 'missing_asset' in e for e in events)
    passed=state_unchanged and workspaces_unchanged and not errors and not dialogs and not unexpected
    result={'passed':passed,'transport':'All requests intercepted with production security headers; no listener or external network','events':events,'page_errors':errors,'console':console,'dialogs':dialogs,'state_unchanged':state_unchanged,'workspaces_unchanged':workspaces_unchanged}
    (out/'browser-results.json').write_text(json.dumps(result,indent=2)+'\n')
    assert passed,result
    print(json.dumps({'passed':True,'api_requests':len(events),'artifacts':str(out)}))

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--assets',required=True)
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
