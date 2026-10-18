#!/usr/bin/env python3
"""Independent, socket-free Inspector security checks against real core state.

Builds four scripted workspaces through the real CLI; never calls a network listener.
The fixture-only mode also provides repeatable realistic UI demonstration data.
"""
import argparse
import json
import sqlite3
import shutil
import subprocess
from urllib.parse import urlencode
import time
from pathlib import Path
from harness_support import Harness, manifest, write, canaries

PRIVATE = 'INSPECTOR_PRIVATE_ONLY_A_9ca641'
HTML = '<img src=x onerror=alert(1)> & " café 日本語 🚀'


def create_fixture(binary, root):
    root = Path(root).resolve()
    h = Harness(binary, root)
    state = root / 'state'
    source = h.fixture(root / 'source')
    n = 0
    def req(**r):
        nonlocal n
        n += 1
        r.setdefault('operation_id', 'inspector-fixture-' + str(n))
        return h.call('--state', state, json.dumps(r))
    initial = req(op='init', source=str(source))
    paths, generations = {}, {}
    for actor in 'ABCD':
        paths[actor] = root / ('workspace-' + actor)
        opened = req(op='open', workspace=actor, path=str(paths[actor]))
        generations[actor] = opened['generation']
        canaries(paths[actor], actor)
    def checkpoint(actor):
        result = req(op='checkpoint', workspace=actor, expected_generation=generations[actor])
        generations[actor] = result['generation']
        return result
    write(paths['A'], 'private-broken.py', 'def broken(\n' + PRIVATE + '\n')
    private = checkpoint('A')
    (paths['A'] / 'private-broken.py').unlink()
    checkpoints, proposals = {}, {}
    for actor in 'ABCD':
        if actor in 'AB':
            write(paths[actor], 'notes/shared.txt', actor + ' incompatible\n')
        else:
            write(paths[actor], 'docs/' + actor + '.txt', actor + ' isolated change\n')
        if actor == 'C':
            write(paths[actor], 'docs/unicode.txt', HTML + '\n')
            write(paths[actor], 'data/binary.bin', bytes(range(256)) * 16)
            write(paths[actor], 'docs/huge.txt', ('big line ' + 'x' * 200 + '\n') * 12000)
        checkpoints[actor] = checkpoint(actor)
        proposals[actor] = req(op='publish', workspace=actor, checkpoint=checkpoints[actor]['checkpoint'], intent='QA ' + actor + ': ' + HTML)
    integrated = req(op='integrate')
    # Keep an extra unpublished checkpoint and unsaved live files after integration.
    write(paths['D'], 'private-latest.txt', 'private D only\n')
    newest = checkpoint('D')
    write(paths['B'], 'unsaved-live.txt', 'must never be read as historical source\n')
    status = req(op='status')
    with sqlite3.connect('file:' + str(state/'state.sqlite') + '?mode=ro', uri=True) as db:
        dispositions = dict(db.execute('select workspace,state from proposals'))
    assert dispositions['B'] == 'quarantined', dispositions
    assert all(dispositions[a] == 'integrated' for a in 'ACD'), dispositions
    result = {'state': str(state), 'workspaces': {a:str(p) for a,p in paths.items()},
              'private_checkpoint':private, 'checkpoints':checkpoints, 'proposals':proposals,
              'latest_private_checkpoint':newest, 'initial':initial, 'status':status,
              'integrated':integrated, 'dispositions':dispositions}
    (root/'fixture.json').write_text(json.dumps(result, indent=2, ensure_ascii=False)+'\n')
    h.save_log()
    (root/'fixture-commands.json').write_text(json.dumps(h.events,indent=2)+'\n')
    return h, result


def run_security(h, fixture, inspector):
    inspector = str(Path(inspector).resolve())
    state = Path(fixture['state'])
    checks = []
    scratch=h.root/('security-cases-'+str(time.time_ns()))
    scratch.mkdir()
    baseline = manifest(state)
    live = {a:manifest(p) for a,p in fixture['workspaces'].items()}
    def request(path, params=None, expected=200, state_path=state, **options):
        if params:
            path += '?' + urlencode(params)
        argv = [inspector, '--state', str(state_path), '--request', path]
        for key,value in options.items():
            argv += ['--'+key.replace('_','-'), str(value)]
        p = h.command(argv, ok=False)
        assert p.returncode == 0, (argv,p.stderr)
        result = json.loads(p.stdout)
        assert result['status'] == expected, (argv,result)
        expected_origin=options.get('origin') if options.get('origin')==options.get('allow_origin') else None
        assert result.get('origin')==expected_origin, (argv,result)
        headers={k.lower():v for k,v in result['headers'].items()}
        assert headers['cache-control']=='no-store'
        assert headers['x-content-type-options']=='nosniff'
        assert headers['cross-origin-resource-policy']=='same-origin'
        assert "frame-ancestors 'none'" in headers['content-security-policy']
        assert "script-src 'self' 'wasm-unsafe-eval'" in headers['content-security-policy']
        assert headers.get('access-control-allow-origin')==expected_origin
        checks.append({'target':path, 'options':{k:str(v) for k,v in options.items()}, 'status':result['status']})
        return result['body']
    overview = request('/api/overview')
    assert overview['read_only'] is True
    assert {w['id'] for w in overview['workspaces']} == set('ABCD')
    assert {p['workspace']:p['state'] for p in overview['proposals']} == fixture['dispositions']
    private = request('/api/history', {'kind':'private'})['entries']
    shared = request('/api/history', {'kind':'shared'})['entries']
    private_id = 'checkpoint:' + fixture['private_checkpoint']['checkpoint']
    assert private_id in {e['id'] for e in private}
    assert all(e['kind']=='checkpoint' for e in private)
    assert all(e['kind']!='checkpoint' for e in shared)
    assert private_id not in {e['id'] for e in shared}
    assert fixture['private_checkpoint']['commit'] not in json.dumps(shared)
    assert len(shared)==7, shared
    assert len(private)==6, private
    assert request('/api/history',{'kind':'private','workspace':''})['entries']==private
    for actor in 'ABCD':
        filtered = request('/api/history', {'kind':'private','workspace':actor})['entries']
        assert filtered and all(e['workspace']==actor for e in filtered)
    for kind, entries in [('private',private),('shared',shared)]:
        gathered=[]; offset=0
        while True:
            page=request('/api/history', {'kind':kind,'limit':2,'offset':offset})
            gathered.extend(page['entries'])
            if page['next_offset'] is None: break
            assert page['next_offset'] > offset
            offset=page['next_offset']
        assert gathered==entries
    for key,value in [('limit',0),('limit',201),('offset',-1),('limit','nan'),('offset','99999999999999999999999999')]:
        request('/api/history', {key:value}, expected=400)
    request('/api/history?limit=2&limit=3',expected=400)
    request('/api/history',{'kind':'live'},expected=400)
    assert request('/api/history', {'offset':1000000})['entries']==[]
    for entry in private+shared:
        changes=request('/api/changes', {'entry':entry['id'],'limit':200})
        if entry['id']==private_id:
            assert any(f['path']=='private-broken.py' for f in changes['files'])
            patch=request('/api/diff',{'entry':entry['id'],'path':'private-broken.py'})
            assert PRIVATE in patch['text']
        if entry['kind']!='checkpoint':
            assert all(f['path']!='private-broken.py' for f in changes['files'])
        assert all(f['path']!='unsaved-live.txt' for f in changes['files'])
        assert all(f['path'] not in ('.env','.agent/session.txt','local/keep.bin','build/cache.bin') for f in changes['files'])
    c='checkpoint:'+fixture['checkpoints']['C']['checkpoint']
    files=request('/api/changes',{'entry':c,'limit':200})['files']
    assert next(f for f in files if f['path']=='data/binary.bin')['binary']
    binary=request('/api/diff',{'entry':c,'path':'data/binary.bin'})
    assert binary['binary'] and binary['text']=='' and not binary['truncated']
    huge=request('/api/diff',{'entry':c,'path':'docs/huge.txt'})
    assert huge['truncated'] and len(huge['text'].encode())<=256*1024+3
    unicode=request('/api/diff',{'entry':c,'path':'docs/unicode.txt'})
    assert HTML in unicode['text'] and not unicode['binary']
    for bad in ['../../etc/passwd','/etc/passwd',':(glob)**','--output=/tmp/inspector-pwn','HEAD:docs/api.md','docs/unicode.txt\x00']:
        request('/api/diff',{'entry':c,'path':bad},expected=400 if '\x00' in bad else 404)
    for bad in ['HEAD','checkpoint:../../etc/passwd','checkpoint:--help','checkpoint:x;touch pwn',"checkpoint:x' OR 1=1 --",'checkpoint:HEAD~1']:
        request('/api/changes',{'entry':bad},expected=404 if bad=='checkpoint:--help' else 400)
    request('/api/changes',{'entry':'checkpoint:missing'},expected=404)
    request('/api/changes',{'entry':'proposal:missing'},expected=404)
    for method in ['POST','PUT','PATCH','DELETE','OPTIONS','HEAD']:
        request('/api/overview',method=method,expected=405)
    for host in ['evil.example','localhost:47831','127.0.0.1:9','127.0.0.1:47831.evil','127.0.0.1:47831@evil']:
        request('/api/overview',host=host,expected=403)
    for origin in ['https://evil.example','null','http://127.0.0.1:47831.evil','http://127.0.0.1:47831@evil','http://localhost:9999']:
        request('/api/overview',origin=origin,expected=403)
    request('/api/overview',origin='http://127.0.0.1:47831')
    request('/api/overview',fetch_site='cross-site',expected=403)
    request('/api/overview',origin='http://127.0.0.1:8080',allow_origin='http://127.0.0.1:8080')
    # All source files, refs, object contents, SQLite bytes and live workspaces unchanged.
    assert manifest(state)==baseline, 'Inspector mutated persistent source state'
    assert {a:manifest(p) for a,p in fixture['workspaces'].items()}==live, 'Inspector mutated live workspaces'
    # Missing directories and incomplete state are never initialized or repaired.
    missing=scratch/'missing-state'
    p=h.command([inspector,'--state',missing,'--request','/api/overview'],ok=False)
    assert p.returncode != 0 and not missing.exists()
    empty=scratch/'empty-state'; empty.mkdir()
    request('/api/overview',state_path=empty,expected=503)
    assert list(empty.iterdir())==[]
    # Copy an interrupted journal: read-only inspection must not invoke core recovery.
    damaged=scratch/'pending-state'; shutil.copytree(state,damaged)
    with sqlite3.connect(damaged/'state.sqlite') as db:
        db.execute("INSERT INTO operations(id,digest,request,result) VALUES('pending-qa','x','{}',NULL)")
    before=manifest(damaged)
    request('/api/overview',state_path=damaged)
    assert manifest(damaged)==before, 'Inspector recovered or mutated pending journal'
    # Public proposals remain readable when original local repositories are unavailable.
    public_only=scratch/'public-only';shutil.copytree(state,public_only)
    (public_only/'locals').rename(public_only/'private-stores-offline')
    public_before=manifest(public_only)
    for entry in shared:
        request('/api/changes',{'entry':entry['id']},state_path=public_only)
    request('/api/changes',{'entry':private_id},state_path=public_only,expected=503)
    assert manifest(public_only)==public_before
    # A poisoned stored revision never becomes Git option syntax.
    poisoned=scratch/'poisoned-state';shutil.copytree(state,poisoned)
    with sqlite3.connect(poisoned/'state.sqlite') as db:
        db.execute('UPDATE checkpoints SET commit_oid=? WHERE id=?',('--help',fixture['private_checkpoint']['checkpoint']))
    poisoned_before=manifest(poisoned)
    request('/api/changes',{'entry':private_id},state_path=poisoned,expected=503)
    assert manifest(poisoned)==poisoned_before
    # Static path admission shares host/method/origin guard and forbids escapes.
    assets=scratch/'assets'; assets.mkdir()
    write(assets,'index.html','<!doctype html><title>test</title>')
    write(assets,'app.js','console.log(1)')
    write(scratch,'outside.js','DO_NOT_EXPOSE')
    (assets/'link.js').symlink_to(scratch/'outside.js')
    request('/',assets=assets)
    request('/app.js',assets=assets)
    for path in ['/../outside.js','/%2e%2e/outside.js','//outside.js','/app.js?x=1','/app.js#x','/a/./app.js']:
        request(path,assets=assets,expected=400)
    request('/link.js',assets=assets,expected=403)
    request('/',assets=assets,host='evil.example',expected=403)
    request('/',assets=assets,origin='https://evil.example',expected=403)
    request('/',assets=assets,method='POST',expected=405)
    assert manifest(state)==baseline
    crash_h,crash_fixture=create_fixture(h.binary,scratch/'crash-fixture')
    crash_request={'op':'adopt','workspace':'D','target':'latest','expected_generation':crash_fixture['latest_private_checkpoint']['generation'],'operation_id':'inspector-crash-mid-apply'}
    crashed=crash_h.command([h.binary,'--state',crash_fixture['state'],json.dumps(crash_request)],env={'WIPSTASH_FAULT':'adoption_mid_apply'},ok=False)
    assert crashed.returncode==86, (crashed.returncode,crashed.stdout,crashed.stderr)
    crash_state_before=manifest(crash_fixture['state'])
    crash_live_before={a:manifest(p) for a,p in crash_fixture['workspaces'].items()}
    request('/api/overview',state_path=crash_fixture['state'])
    request('/api/history',{'kind':'private'},state_path=crash_fixture['state'])
    assert manifest(crash_fixture['state'])==crash_state_before, 'Inspector recovered crashed adoption'
    assert {a:manifest(p) for a,p in crash_fixture['workspaces'].items()}==crash_live_before, 'Inspector rolled back live files'
    crash_h.save_log()
    result={'passed':len(checks),'checks':checks,'state_unchanged':True,'workspaces_unchanged':True,
            'missing_state_not_created':True,'pending_journal_not_recovered':True,'interrupted_adoption_not_recovered':True}
    (h.root/'security-results.json').write_text(json.dumps(result,indent=2)+'\n')
    h.save_log()
    return result

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', default='target/debug/wipstash')
    parser.add_argument('--artifacts', default='evidence/inspector/' + time.strftime('%Y%m%dT%H%M%S'))
    parser.add_argument('--fixture-only', action='store_true')
    parser.add_argument('--fixture', help='Reuse fixture.json created earlier')
    parser.add_argument('--inspector', default='services/inspector/target/debug/wipstash-inspector')
    args = parser.parse_args()
    if args.fixture:
        fixture=json.loads(Path(args.fixture).read_text())
        h=Harness(args.binary, Path(args.fixture).parent)
    else:
        h, fixture = create_fixture(args.binary, args.artifacts)
    if not args.fixture_only:
        result=run_security(h,fixture,args.inspector)
        print(json.dumps({'security':result['passed'],'state_unchanged':True}))
    print(json.dumps({'fixture': str(h.root/'fixture.json'), 'state':fixture['state'], 'dispositions':fixture['dispositions']}))

if __name__ == '__main__':
    main()
