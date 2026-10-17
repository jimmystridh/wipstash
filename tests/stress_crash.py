#!/usr/bin/env python3
"""Seeded real-process crash campaign; retained filesystem, never power-loss evidence."""
import argparse, collections, hashlib, json, os, platform, random, shutil, signal, sqlite3, subprocess, sys, time, traceback
from pathlib import Path
from harness_support import Harness, manifest, write, canaries
FAULTS=['checkpoint_after_pin','checkpoint_after_commit','publish_after_pin','promotion_before_cas','promotion_after_cas','adoption_after_intent','adoption_mid_apply','adoption_after_apply','backup_after_pending','backup_after_push']
class Campaign:
 def __init__(self,binary,root,seed):
  self.h=Harness(binary,root);self.seed=seed;self.rng=random.Random(seed);self.state=self.h.root/'state';self.paths={a:self.h.root/a for a in 'ABCD'};self.n=0;self.oracle=[];self.deaths=collections.Counter();self.external=[];self.source=self.h.fixture(self.h.root/'source');self.req(op='init',source=str(self.source))
  for a,p in self.paths.items():self.req(op='open',workspace=a,path=str(p),operation_id='open-'+a);canaries(p,a)
 def oid(self,p='op'):self.n+=1;return f'{p}-{self.seed}-{self.n}'
 def req(self,ok=True,state=None,**body):return self.h.call('--state',state or self.state,json.dumps(body),ok=ok)
 def gen(self,a):return self.req(op='status',workspace=a)['generation']
 def head(self):return self.req(op='status')['head']
 def crash(self,fault,body):
  p=self.h.command([self.h.binary,'--state',self.state,json.dumps(body)],env={'WIPSTASH_FAULT':fault},ok=False)
  assert p.returncode==86,(fault,p.returncode,p.stdout,p.stderr)
  self.deaths[fault]+=1
 def cp(self,a,fault=None):
  # Capture immutable expected bytes before the CLI can acknowledge a save.
  expected=manifest(self.paths[a],exclude=('.env','local','build','.agent'))
  request=dict(op='checkpoint',workspace=a,expected_generation=self.gen(a),operation_id=self.oid('save'))
  if fault:self.crash(fault,request)
  r=self.req(**request);assert self.req(**request)==r
  self.oracle.append({'actor':a,'commit':r['commit'],'files':expected,'request':request,'response':r})
  return r
 def pub(self,a,c,fault=None):
  request=dict(op='publish',workspace=a,checkpoint=c['checkpoint'],intent='PUBLIC fixture change',operation_id=self.oid('publish'))
  if fault:self.crash(fault,request)
  r=self.req(**request);assert self.req(**request)==r;return r
 def change(self,a,tag):
  # Vary byte content and file counts by seed; use disjoint actor paths.
  for i in range(1+self.rng.randrange(4)):write(self.paths[a],f'docs/{a}-{tag}-{i}.txt',f'{self.seed}:{tag}:{self.rng.getrandbits(64)}\n')
 def integrate(self,fault=None):
  old=self.head()
  if fault:self.crash(fault,{'op':'integrate'})
  self.req(op='integrate');new=self.head();self.h.git(self.state/'coordinator.git','merge-base','--is-ancestor',old,new);return new
 def signal_interrupt(self,worker=False):
  marker=self.h.root/('worker-child.json' if worker else 'command-child.json')
  script="import os,time,json;from pathlib import Path;Path(%r).write_text(json.dumps({'pid':os.getpid(),'pgid':os.getpgrp()}));time.sleep(60)"%str(marker)
  if worker:
   self.change('A','external-worker');self.pub('A',self.cp('A'))
   self.req(op='configure',operation_id=self.oid(),policy={'checks':[{'id':'kill-observer','argv':[sys.executable,'-c',script],'required':True,'timeout_seconds':60}]})
   arg='worker'
  else:arg=json.dumps(dict(op='command_run',workspace='D',expected_generation=self.gen('D'),operation_id=self.oid('interrupt-command'),argv=[sys.executable,'-c',script],timeout_seconds=60))
  p=subprocess.Popen([self.h.binary,'--state',str(self.state),arg],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
  child=None
  try:
   deadline=time.monotonic()+15
   while not marker.exists():
    assert p.poll() is None,'Owner exited before command began'
    assert time.monotonic()<deadline,'Command never reached running marker'
    time.sleep(.01)
   child=json.loads(marker.read_text());assert child['pid']==child['pgid'],'Only kill our dedicated child group'
   os.kill(p.pid,signal.SIGKILL);p.wait(timeout=5);assert p.returncode==-signal.SIGKILL
   self.deaths['external_worker_SIGKILL' if worker else 'external_command_SIGKILL']+=1
   time.sleep(.03)
   survived=Path('/proc') .joinpath(str(child['pid'])).exists()
   self.external.append({'owner_pid':p.pid,'owner_exit':p.returncode,'child':child,'descendant_survived_owner_death':survived,'known_limit':True})
  finally:
   if p.poll() is None:p.kill();p.wait()
   if child:
    try:os.killpg(child['pgid'],signal.SIGKILL)
    except ProcessLookupError:pass
  self.req(op='status')
  if worker:self.req(op='configure',operation_id=self.oid(),policy={'checks':[]});self.integrate()
 def audit_repo(self,repo,public=False):
  self.h.git(repo,'fsck','--full','--strict')
  if public:
   ids=[l.split()[0] for l in self.h.git(repo,'rev-list','--objects','--all').splitlines()]
   # Inspect reachable object bytes in one batch, not just filenames.
   raw=subprocess.run(['git','--git-dir',str(repo),'cat-file','--batch'],input=('\n'.join(ids)+'\n').encode(),capture_output=True,check=True).stdout
   assert b'PRIVATE_CRASH_CANARY' not in raw and b'NOT_A_REAL_SECRET' not in raw
 def audit(self):
  with sqlite3.connect(self.state/'state.sqlite') as db:
   assert db.execute('pragma integrity_check').fetchall()==[('ok',)]
   assert db.execute('pragma foreign_key_check').fetchall()==[]
  for repo in [self.state/'coordinator.git']+[self.state/'locals'/a/'objects.git' for a in 'ABCD']:self.audit_repo(repo,repo.name=='coordinator.git')
  for saved in self.oracle:
   repo=self.state/'locals'/saved['actor']/'objects.git'
   rows=self.h.git(repo,'ls-tree','-r',saved['commit']).splitlines();actual={}
   for row in rows:
    info,path=row.split('\t');mode,typ,oid=info.split();assert typ=='blob'
    data=subprocess.check_output(['git','--git-dir',str(repo),'cat-file','blob',oid]);actual[path]={'sha256':hashlib.sha256(data).hexdigest(),'mode':0o755 if mode=='100755' else 0o644}
   assert actual==saved['files'],('acknowledged_source_changed',saved['request'],actual,saved['files'])
 def backup(self):
  # Keep a proposal pending and unpublished private checkpoints in the same state.
  self.change('C','pending');pending=self.pub('C',self.cp('C'))
  write(self.paths['D'],'private-unpublished.txt','PRIVATE_CRASH_CANARY_'+str(self.seed));self.cp('D')
  remote=self.h.root/'backup.git';self.h.command(['git','init','--bare',remote])
  for fault in FAULTS[-2:]:
   self.change('B',fault);self.pub('B',self.cp('B'))
   request=dict(op='backup_flush',destination=str(remote),operation_id=self.oid('backup'))
   self.crash(fault,request);r=self.req(**request);assert r['state']=='complete',r
  self.req(op='backup_verify_restore',destination=str(remote))
  fresh=self.h.root/'restored-state';head=self.head();r=self.req(state=fresh,op='restore',destination=str(remote));assert r['integration']==head
  assert self.req(state=fresh,op='status')['workspaces']==0
  ps=self.req(state=fresh,op='proposal_status',proposal=pending['proposal']);assert ps['state']=='recovery_quarantined',ps
  assert not self.req(state=fresh,op='retry_proposal',proposal=pending['proposal'],operation_id=self.oid(),ok=False)['ok']
  self.req(state=fresh,op='integrate');assert self.req(state=fresh,op='status')['head']==head
  assert pending['commit'] in self.h.git(fresh/'coordinator.git','rev-list','--all').splitlines()
  for repo in [remote,fresh/'coordinator.git']:self.audit_repo(repo,True)
  with sqlite3.connect(fresh/'state.sqlite') as db:
   assert db.execute('pragma integrity_check').fetchall()==[('ok',)]
   assert db.execute('select count(*) from workspaces').fetchone()[0]==0
   for kind,data in db.execute('select kind,data from events'):
    assert kind in ('published','integrated','cancelled');assert set(json.loads(data)) <= {'proposal','commit','head'}
 def stale_resolution(self):
  # D's private unpublished checkpoint is never exported.
  write(self.paths['A'],'notes/shared.txt',f'public-conflict-{self.seed}\n');self.pub('A',self.cp('A'));self.integrate()
  write(self.paths['D'],'notes/shared.txt',f'private-conflict-{self.seed}\n')
  c=self.req(op='adopt',workspace='D',target='latest',expected_generation=self.gen('D'),operation_id=self.oid(),ok=False);assert c['state']=='conflict',c
  write(self.paths['D'],'notes/shared.txt','manual resolution\n');cp=self.cp('D');self.change('D','intervening');self.cp('D')
  before=manifest(self.paths['D']);r=self.req(op='resolve_adoption',workspace='D',candidate=c['candidate'],target=c['target'],checkpoint=cp['checkpoint'],expected_generation=self.gen('D'),operation_id=self.oid(),ok=False)
  assert not r['ok'] and 'stale' in json.dumps(r),r
  assert before==manifest(self.paths['D'])
 def run(self):
  # Four independently addressed scripted actors, with shuffled prior history.
  actors=list('ABCD');self.rng.shuffle(actors)
  for a in actors:
   for i in range(1+self.rng.randrange(3)):self.change(a,f'warm-{i}');self.cp(a)
   self.pub(a,self.cp(a))
  self.integrate()
  for fault in FAULTS[:2]:self.change(self.rng.choice(actors),fault);self.cp(actors[0],fault)
  a=actors[1];self.change(a,'publish');self.pub(a,self.cp(a),'publish_after_pin');self.integrate()
  for fault in FAULTS[3:5]:
   a=self.rng.choice(actors);self.change(a,fault);self.pub(a,self.cp(a));self.integrate(fault)
  for fault in FAULTS[5:8]:
   a='A';self.change(a,fault);self.pub(a,self.cp(a));target=self.integrate();b='B';before=manifest(self.paths[b]);oldgen=self.gen(b)
   req=dict(op='adopt',workspace=b,target='latest',expected_generation=oldgen,operation_id=self.oid('adopt'))
   self.crash(fault,req);status=self.req(op='status',workspace=b);after=manifest(self.paths[b])
   for path in ('.env','local/keep.bin','build/cache.bin','.agent/session.txt'):assert before[path]==after[path]
   if status['generation']==oldgen:assert before==after;self.req(**req)
   else:assert status['generation']==oldgen+1 and status['adopted']==target
   self.cp(b)
  self.signal_interrupt(worker=False);self.signal_interrupt(worker=True)
  self.stale_resolution();self.backup();self.audit()
 def save(self):
  self.h.save_log();(self.h.root/'acknowledged-source-oracle.json').write_text(json.dumps(self.oracle,indent=2));(self.h.root/'result.json').write_text(json.dumps({'seed':self.seed,'deaths':self.deaths,'external':self.external},indent=2))
def main():
 p=argparse.ArgumentParser();p.add_argument('--binary',default='target/debug/wipstash');p.add_argument('--artifacts',default='tests/artifacts/crash-'+time.strftime('%Y%m%dT%H%M%S'));p.add_argument('--seeds',type=int,default=20);p.add_argument('--start-seed',type=int,default=7000);args=p.parse_args();root=Path(args.artifacts).resolve();root.mkdir(parents=True,exist_ok=False)
 binary=root/'wipstash-tested';shutil.copy2(Path(args.binary).resolve(),binary)
 (root/'environment.json').write_text(json.dumps({'platform':platform.platform(),'python':sys.version,'binary_sha256':hashlib.sha256(binary.read_bytes()).hexdigest(),'source_sha256':{str(x):hashlib.sha256(x.read_bytes()).hexdigest() for x in Path('src').glob('*.rs')},'scope':'Scripted Linux CLI process deaths on retained local filesystem; not power-loss, host-loss, native OS matrix, sockets or model sessions.'},indent=2))
 total=collections.Counter();failures=[];passed=[];start=time.monotonic()
 for seed in range(args.start_seed,args.start_seed+args.seeds):
  c=None
  try:c=Campaign(binary,root/str(seed),seed);c.run();passed.append(seed);print('PASS',seed,dict(c.deaths),flush=True)
  except Exception:
   failure={'seed':seed,'traceback':traceback.format_exc(),'reproduce':f'python3 tests/stress_crash.py --binary {binary} --start-seed {seed} --seeds 1 --artifacts /tmp/wipstash-repro-{seed}'};failures.append(failure);print(json.dumps(failure),flush=True)
  finally:
   if c:c.save();total.update(c.deaths)
  (root/'summary.json').write_text(json.dumps({'passed_seeds':passed,'failures':failures,'actual_injected_process_deaths':sum(total.values()),'deaths_by_boundary':total,'ordinary_cli_commands':sum(sum(1 for e in json.loads(f.read_text()) if e.get('argv',[None])[0]==str(binary) and e.get('exit')!=86) for f in root.glob('*/commands.json')),'seconds':time.monotonic()-start},indent=2))
 print('Evidence:',root,flush=True);return bool(failures)
if __name__=='__main__':sys.exit(main())
