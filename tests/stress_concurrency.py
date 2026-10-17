#!/usr/bin/env python3
"""Seeded four-process CLI state-machine stress; retained replayable per-actor JSONL.
Not real AI clients; engine operations remain serialized by the global state lock.
"""
import argparse, collections, hashlib, json, multiprocessing as mp, os, random, shutil, sqlite3, subprocess, time, traceback
from pathlib import Path

def digest(b): return hashlib.sha256(b).hexdigest()
def manifest(path):
    return {str(p.relative_to(path)): {'sha256':digest(p.read_bytes()),'executable':bool(p.stat().st_mode&0o111)} for p in sorted(path.rglob('*')) if p.is_file()}
def git(repo,*args,input=None):
    p=subprocess.run(['git','--git-dir',str(repo),*args],input=input,capture_output=True)
    assert p.returncode==0,(args,p.stderr.decode(errors='replace'))
    return p.stdout

def tree_manifest(repo,tree):
    result={}
    for item in git(repo,'ls-tree','-rz',tree).split(b'\0'):
        if not item:continue
        meta,path=item.split(b'\t',1);mode,typ,oid=meta.split()
        assert typ==b'blob'
        result[path.decode()]={'sha256':digest(git(repo,'cat-file','blob',oid.decode())),'executable':mode==b'100755'}
    return result

class Client:
    def __init__(self,binary,root,actor):self.binary=str(binary);self.root=Path(root);self.actor=actor;self.log=self.root/f'{actor}.jsonl';self.counter=0
    def call(self,**req):
        start=time.monotonic_ns()
        p=subprocess.run([self.binary,'--state',str(self.root/'state'),json.dumps(req)],capture_output=True,text=True,timeout=90)
        end=time.monotonic_ns()
        try:r=json.loads(p.stdout)
        except Exception:raise AssertionError((req,p.returncode,p.stdout,p.stderr))
        with self.log.open('a') as f:f.write(json.dumps({'actor':self.actor,'request':req,'response':r,'exit':p.returncode,'start_ns':start,'end_ns':end,'stderr':p.stderr})+'\n')
        assert (p.returncode==0)==bool(r.get('ok')), (req,p.returncode,r)
        return r
    def oid(self):self.counter+=1;return f'{self.actor}-{self.counter}'

def actor(binary,root,name,seed,steps,barrier):
    c=Client(binary,root,name);root=Path(root);path=root/name;rng=random.Random(seed*1009+ord(name));g=0;checkpoints=[];retries=[];proposals=[]
    try:
        barrier.wait(timeout=30)
        g=c.call(op='status',workspace=name)['generation']
        # A never-published private ancestor must remain unreachable publicly.
        private=path/'private-ancestor.txt';private.write_text(f'PRIVATE_ANCESTOR_{root.name}_{name}\n')
        initial=c.call(op='checkpoint',workspace=name,expected_generation=g,operation_id=c.oid());assert initial['ok'];g=initial['generation']
        initial_manifest={k:v for k,v in manifest(path).items() if k!='.env'}
        with (root/f'{name}-snapshots.jsonl').open('a') as f:f.write(json.dumps({'checkpoint':initial,'manifest':initial_manifest})+'\n')
        private.unlink()
        for i in range(steps):
            choice=rng.choices(['checkpoint','publish','integrate','adopt','updates','retry','stale','cancel','retry_proposal','status'],[28,19,11,10,5,8,5,4,3,7])[0]
            if not checkpoints:choice='checkpoint'
            if choice=='publish' and not checkpoints:choice='checkpoint'
            if choice=='retry' and not retries:choice='status'
            if choice in ('cancel','retry_proposal') and not proposals:choice='integrate'
            if choice=='checkpoint':
                target=path/('shared.txt' if rng.random()<.45 else f'{name}-{rng.randrange(4)}.txt')
                data=f'seed={seed} actor={name} step={i} random={rng.getrandbits(64)}\n'
                if rng.random()<.12 and target.exists():target.unlink();edit={'path':target.name,'delete':True}
                else:target.write_text(data);edit={'path':target.name,'data':data}
                with c.log.open('a') as f:f.write(json.dumps({'edit':edit,'actor':name,'at_ns':time.monotonic_ns()})+'\n')
                req=dict(op='checkpoint',workspace=name,expected_generation=g,operation_id=c.oid())
            elif choice=='publish':req=dict(op='publish',workspace=name,checkpoint=rng.choice(checkpoints)['checkpoint'],intent='Seeded randomized snapshot',operation_id=c.oid())
            elif choice=='adopt':req=dict(op='adopt',workspace=name,target='latest',expected_generation=g,operation_id=c.oid())
            elif choice=='updates':req=dict(op='updates',workspace=name)
            elif choice=='retry':req,expected=rng.choice(retries)
            elif choice=='stale':req=dict(op='checkpoint',workspace=name,expected_generation=g+10,operation_id=c.oid())
            elif choice in ('cancel','retry_proposal'):req=dict(op=choice,proposal=rng.choice(proposals),operation_id=c.oid())
            elif choice=='status':req=dict(op='status',workspace=name)
            else:req=dict(op='integrate')
            before=manifest(path);r=c.call(**req);after=manifest(path)
            if choice=='retry':assert r==expected,('retry_changed',req,r,expected)
            if choice!='adopt':assert before==after,('implicit_adopt',choice,before,after)
            if choice=='adopt':
                assert after['.env']==before['.env'],'excluded_canary_changed'
                if not r['ok']:assert before==after,('failed_adopt_changed_wip',r)
            if choice=='stale':assert not r['ok'] and 'generation' in json.dumps(r),r
            if choice in ('checkpoint','publish','updates','integrate','status'):assert r['ok'],(req,r)
            if choice=='checkpoint':
                expected_tree={k:v for k,v in before.items() if k!='.env'}
                assert tree_manifest(root/'state'/'locals'/name/'objects.git',r['commit'])==expected_tree,('snapshot_mismatch',req)
                checkpoints.append(r)
                with (root/f'{name}-snapshots.jsonl').open('a') as f:f.write(json.dumps({'checkpoint':r,'manifest':expected_tree})+'\n')
            if choice=='publish' and r['ok']:proposals.append(r['proposal'])
            if choice in ('checkpoint','adopt') and r['ok']:g=r['generation']
            if choice not in ('retry','stale') and 'operation_id' in req:retries.append((req,r))
        (root/f'{name}-done.json').write_text(json.dumps({'ok':True,'steps':steps,'generation':g}))
    except BaseException:
        (root/f'{name}-done.json').write_text(json.dumps({'ok':False,'error':traceback.format_exc()}));raise

def audit(root,c):
    state=root/'state';head=c.call(op='status')['head'];repo=state/'coordinator.git'
    assert git(repo,'rev-parse','refs/wipstash/integration').decode().strip()==head
    db=sqlite3.connect(state/'state.sqlite');assert db.execute('pragma integrity_check').fetchall()==[('ok',)]
    assert not db.execute('pragma foreign_key_check').fetchall()
    for name,base,g in db.execute('select id,base,generation from workspaces'):
        done=json.loads((root/f'{name}-done.json').read_text());assert done['ok'],done
        assert done['generation']==g,('generation',name,g,done)
    for name in 'ABCD':
        for line in (root/f'{name}-snapshots.jsonl').read_text().splitlines():
            snap=json.loads(line);r=snap['checkpoint'];local=state/'locals'/name/'objects.git'
            assert tree_manifest(local,r['commit'])==snap['manifest'],('acknowledged_snapshot_lost',r)
    states=collections.Counter()
    for pid,w,checkpoint,oid,disposition,ph in db.execute('select id,workspace,checkpoint,commit_oid,state,head from proposals'):
        states[disposition]+=1
        status=c.call(op='proposal_status',proposal=pid);assert status['state']==disposition
        selected=db.execute('select tree from checkpoints where id=?',(checkpoint,)).fetchone()[0]
        assert git(repo,'rev-parse',oid+'^{tree}').decode().strip()==selected,('wrong_published_snapshot',pid)
        if disposition=='integrated':
            assert subprocess.run(['git','--git-dir',str(repo),'merge-base','--is-ancestor',oid,head],capture_output=True).returncode==0,('integrated_not_in_head',pid)
    audits=[]
    for repository in sorted(state.rglob('*.git')):
        p=subprocess.run(['git','--git-dir',str(repository),'fsck','--full'],capture_output=True,text=True)
        assert p.returncode==0,(repository,p.stdout,p.stderr);audits.append({'repository':str(repository.relative_to(root)),'exit':p.returncode,'stdout':p.stdout,'stderr':p.stderr})
    public=git(repo,'rev-list','--objects','--all').decode()
    assert '.env' not in public
    private_tokens=[f'{prefix}_{root.name}_{n}' for n in 'ABCD' for prefix in ('PRIVATE_CANARY','PRIVATE_ANCESTOR')]
    for line in public.splitlines():
        oid=line.split()[0]
        if git(repo,'cat-file','-t',oid).strip()==b'blob':
            blob=git(repo,'cat-file','blob',oid)
            assert all(token.encode() not in blob for token in private_tokens),'private_canary_exported'
    out={'sqlite_integrity':'ok','foreign_keys':'ok','head':head,'proposals':dict(states),'git_fsck':audits}
    (root/'audit.json').write_text(json.dumps(out,indent=2));return out

def run_seed(binary,base,seed,steps,sequential=False):
    root=base/f'seed-{seed:04d}';root.mkdir();source=root/'source';source.mkdir();(source/'shared.txt').write_text('base\n');(source/'base.txt').write_text('stable\n')
    c=Client(binary,root,'control');assert c.call(op='init',source=str(source))['ok']
    for name in 'ABCD':
        assert c.call(op='open',workspace=name,path=str(root/name),operation_id='open-'+name)['ok']
        (root/name/'.env').write_text(f'PRIVATE_CANARY_{root.name}_{name}\n')
    # Distinct seeds exercise trusted scripted repair, failing required checks, and unchecked integration.
    policy={'checks':[]}
    if seed%4==1:policy={'checks':[{'id':'required','argv':['/bin/sh','-c','exit 7'],'required':True,'timeout_seconds':2}]}
    if seed%4==2:
        script="import os,json,pathlib; paths=json.loads(os.environ['WIPSTASH_CONFLICT_PATHS']); [(pathlib.Path(p).parent.mkdir(parents=True,exist_ok=True),pathlib.Path(p).write_text('scripted resolution\\n')) for p in paths]; pathlib.Path(os.environ['WIPSTASH_RESOLUTION_FILE']).write_text(json.dumps({'head':os.environ['WIPSTASH_HEAD'],'proposal':os.environ['WIPSTASH_PROPOSAL'],'input_tree':os.environ['WIPSTASH_CANDIDATE_TREE'],'resolved_paths':paths}))"
        policy['repair']={'execution_profile':'trusted_unsandboxed','argv':['/usr/bin/python3','-c',script],'max_attempts':1,'timeout_seconds':5}
    assert c.call(op='configure',policy=policy,operation_id='policy')['ok']
    # Offline reads/checkpoint/publish are separately exercised before the contending actor phase.
    if seed%5==0:
        repo=root/'state'/'coordinator.git';offline=root/'offline.git';repo.rename(offline)
        try:
            assert not c.call(op='status',workspace='A')['coordinator_online']
            (root/'A'/'offline.txt').write_text(f'offline seed {seed}\n')
            saved=c.call(op='checkpoint',workspace='A',expected_generation=0,operation_id='offline-checkpoint');assert saved['ok']
            with (root/'A-snapshots.jsonl').open('a') as f:f.write(json.dumps({'checkpoint':saved,'manifest':{k:v for k,v in manifest(root/'A').items() if k!='.env'}})+'\n')
            queued=c.call(op='publish',workspace='A',checkpoint='offline-checkpoint',intent='Offline seeded snapshot',operation_id='offline-publish');assert queued['ok'] and queued['state']=='queued_offline',queued
            assert not c.call(op='adopt',workspace='A',target='latest',expected_generation=1,operation_id='offline-adopt')['ok']
        finally:offline.rename(repo)
    if sequential:
        class Barrier:
            def wait(self,**kwargs):pass
        for n in 'ABCD':actor(binary,root,n,seed,steps,Barrier())
    else:
        barrier=mp.Barrier(4);ps=[mp.Process(target=actor,args=(binary,root,n,seed,steps,barrier)) for n in 'ABCD']
        for p in ps:p.start()
        for p in ps:p.join(timeout=180)
        for p in ps:
            if p.is_alive():p.terminate();p.join();raise AssertionError('actor timeout')
            assert p.exitcode==0,('actor_failed',p.pid,p.exitcode)
    assert c.call(op='integrate')['ok']
    a=audit(root,c)
    if seed%10==0:
        dest=root/'backup.git';subprocess.run(['git','init','--bare',str(dest)],check=True,capture_output=True)
        r=c.call(op='backup_flush',destination=str(dest),operation_id='backup');assert r['ok'] and r['state']=='complete',r
        assert c.call(op='backup_verify_restore',destination=str(dest))['ok']
        assert subprocess.run(['git','--git-dir',str(dest),'fsck','--full'],capture_output=True).returncode==0
    records=[json.loads(line) for p in root.glob('*.jsonl') if not p.name.endswith('-snapshots.jsonl') for line in p.read_text().splitlines()];calls=[r for r in records if 'request'in r]
    intervals=sorted([(r['start_ns'],1) for r in calls if r['actor']!='control']+[(r['end_ns'],-1) for r in calls if r['actor']!='control']);active=peak=0;overlap_ns=0;last=None
    for when,delta in intervals:
        if last is not None and active>=2:overlap_ns+=when-last
        active+=delta;peak=max(peak,active);last=when
    summary={'seed':seed,'attempts':len(calls),'successes':sum(bool(r['response'].get('ok')) for r in calls),'operations':dict(collections.Counter(r['request']['op'] for r in calls)),'peak_outstanding_actor_calls':peak,'overlap_seconds':overlap_ns/1e9,'proposals':a['proposals']}
    (root/'summary.json').write_text(json.dumps(summary,indent=2));return summary

def main():
    p=argparse.ArgumentParser();p.add_argument('--binary',default='target/debug/wipstash');p.add_argument('--artifacts',default='tests/artifacts/stress-concurrency-'+time.strftime('%Y%m%dT%H%M%S'));p.add_argument('--seeds',type=int,default=100);p.add_argument('--start-seed',type=int,default=0);p.add_argument('--steps',type=int,default=32);p.add_argument('--sequential',action='store_true');args=p.parse_args()
    base=Path(args.artifacts).resolve();base.mkdir(parents=True,exist_ok=True);binary=base/'wipstash-tested';shutil.copy2(Path(args.binary).resolve(),binary);started=time.monotonic();summaries=[];shutil.copy2(Path(__file__).resolve(),base/'stress_concurrency-tested.py')
    (base/'run.json').write_text(json.dumps({'arguments':vars(args),'binary_sha256':digest(binary.read_bytes()),'script_sha256':digest(Path(__file__).read_bytes()),'started_utc':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()),'scope':'Four scripted OS processes, cooperative workspace writers, one-machine globally serialized engine; no real LLM clients.'},indent=2))
    for seed in range(args.start_seed,args.start_seed+args.seeds):
        try:s=run_seed(binary,base,seed,args.steps,args.sequential);summaries.append(s);print(json.dumps(s),flush=True)
        except Exception:
            (base/'failure.txt').write_text(traceback.format_exc());print(traceback.format_exc(),flush=True);raise
        aggregate={'completed_seeds':len(summaries),'attempts':sum(x['attempts'] for x in summaries),'successes':sum(x['successes'] for x in summaries),'elapsed_seconds':time.monotonic()-started,'seeds':summaries}
        (base/'summary.json').write_text(json.dumps(aggregate,indent=2))
    print('COMPLETE '+str(base),flush=True)
if __name__=='__main__':main()
