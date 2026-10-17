#!/usr/bin/env python3
"""Real CLI/storage integration suite. Four scripted actors, never AI sessions.
Run: python3 tests/adversarial.py [--binary target/debug/wipstash]
Retains complete evidence under --artifacts (default tests/artifacts).
"""
import argparse,json,os,platform,sys,time,unittest,subprocess,hashlib
from pathlib import Path
from harness_support import Harness,manifest,write,canaries
P=argparse.ArgumentParser();P.add_argument('--binary',default='target/debug/wipstash');P.add_argument('--artifacts',default='tests/artifacts');ARGS,REST=P.parse_known_args()
RUN=Path(ARGS.artifacts).resolve()/time.strftime('%Y%m%dT%H%M%S')
class Adversarial(unittest.TestCase):
    def setUp(self):
        self.h=Harness(ARGS.binary,RUN/self._testMethodName)
        self.state=self.h.root/'state';self.source=self.h.fixture(self.h.root/'source');self.paths={};self.gen={};self.counter=0
        self.init=self.req(op='init',source=str(self.source))
        for a in 'ABCD':
            self.paths[a]=self.h.root/a
            r=self.req(op='open',workspace=a,path=str(self.paths[a]),operation_id='open-'+a)
            self.gen[a]=r.get('generation',0);canaries(self.paths[a],a)
    def tearDown(self):self.h.save_log()
    def req(self,env=None,ok=True,**r):return self.h.call('--state',self.state,json.dumps(r),env=env,ok=ok)
    def crash(self,fault,**r):
        p=self.h.command([self.h.binary,'--state',str(self.state),json.dumps(r)],env={'WIPSTASH_FAULT':fault},ok=False)
        self.assertEqual(p.returncode,86,f'Fault {fault} did not terminate process: {p.stdout} {p.stderr}')
    def oid(self,prefix='op'):
        self.counter+=1;return f'{prefix}-{self.counter}'
    def checkpoint(self,a,opid=None):
        r=self.req(op='checkpoint',workspace=a,expected_generation=self.gen[a],operation_id=opid or self.oid('checkpoint'))
        self.gen[a]=r['generation'];return r
    def publish(self,a,c,opid=None):return self.req(op='publish',workspace=a,checkpoint=c['checkpoint'],intent=f'Scripted actor {a} fixture change',operation_id=opid or self.oid('publish'))
    def integrate(self,**kwargs):return self.req(op='integrate',operation_id=self.oid('integrate'),**kwargs)
    def adopt(self,a,**kwargs):
        r=self.req(op='adopt',workspace=a,target='latest',expected_generation=self.gen[a],operation_id=self.oid('adopt'),**kwargs)
        if 'generation' in r:self.gen[a]=r['generation']
        return r
    def coordinator(self):
        candidates=[p.parent for p in self.state.rglob('HEAD') if (p.parent/'objects').is_dir()]
        for p in candidates:
            if any(s in str(p).lower() for s in ('coordinator','shared','public')):return p
        raise AssertionError(f'Cannot identify coordinator repository: {candidates}')
    def head(self):
        r=self.req(op='status')
        for k in ('head','integration_head','shared_head','latest_known_head'):
            if k in r:return r[k]
        raise AssertionError(f'Head absent from status {r}')
    def blob(self,commit,path):return self.h.git(self.coordinator(),'show',f'{commit}:{path}')
    def test_four_actor_disjoint_concurrency(self):
        before={a:manifest(p) for a,p in self.paths.items()}
        for a,p in self.paths.items():write(p,f'docs/{a}.txt',f'Actor {a}\n')
        cs=self.h.parallel([lambda a=a:self.checkpoint(a,'parallel-save-'+a) for a in 'ABCD'])
        self.h.parallel([lambda a=a,c=c:self.publish(a,c,'parallel-publish-'+a) for a,c in zip('ABCD',cs)])
        live={a:manifest(p) for a,p in self.paths.items()}
        self.integrate();head=self.head()
        for a in 'ABCD':self.assertEqual(self.blob(head,f'docs/{a}.txt'),f'Actor {a}')
        for a in 'ABCD':
            self.req(op='updates',workspace=a)
            self.assertEqual(manifest(self.paths[a]),live[a],f'Implicit adoption in {a}')
        for a in 'ABCD':
            self.adopt(a)
            for b in 'ABCD':self.assertEqual((self.paths[a]/f'docs/{b}.txt').read_text(),f'Actor {b}\n')
            for path in ('.env','local/keep.bin','build/cache.bin','.agent/session.txt'):
                self.assertEqual(manifest(self.paths[a])[path],before[a][path])
        parents=self.h.git(self.coordinator(),'rev-list','--parents','-n','1',head).split()
        self.assertGreaterEqual(len(parents),3,'Integration commit lacks H/P provenance')
    def test_private_broken_and_sanitized_history(self):
        a=self.paths['A'];write(a,'private-draft.txt','PRIVATE_ANCESTOR_CANARY\n');old=self.checkpoint('A')
        (a/'private-draft.txt').unlink();write(a,'src/pricing.py','def quote(\n');chosen=self.checkpoint('A')
        self.publish('A',chosen);write(a,'src/pricing.py','newer private broken (((\n')
        live={x:manifest(p) for x,p in self.paths.items()};self.integrate();head=self.head()
        self.assertEqual(self.blob(head,'src/pricing.py'),'def quote(')
        for x in 'ABCD':self.assertEqual(manifest(self.paths[x]),live[x])
        repo=self.coordinator();objects=self.h.git(repo,'rev-list','--objects','--all')
        self.assertNotIn('private-draft.txt',objects);self.assertNotIn('.env',objects)
        for line in objects.splitlines():
            oid=line.split(' ',1)[0]
            if self.h.git(repo,'cat-file','-t',oid)=='blob':
                raw=self.h.command(['git','--git-dir',repo,'cat-file','blob',oid]).stdout
                self.assertNotIn('PRIVATE_ANCESTOR_CANARY',raw)
                self.assertNotIn('NOT_A_REAL_SECRET',raw)
        self.assertNotEqual(old['commit'],chosen['commit'])
    def test_same_line_conflict_does_not_block_disjoint(self):
        write(self.paths['A'],'notes/shared.txt','A incompatible\n');write(self.paths['B'],'notes/shared.txt','B incompatible\n')
        write(self.paths['C'],'docs/C.txt','C survives\n');write(self.paths['D'],'docs/D.txt','D survives\n')
        cs={a:self.checkpoint(a) for a in 'ABCD'}
        for a in 'ABCD':self.publish(a,cs[a])
        r=self.integrate();head=self.head();status=self.req(op='status')
        self.assertEqual(self.blob(head,'notes/shared.txt'),'A incompatible')
        for a in 'CD':self.assertEqual(self.blob(head,f'docs/{a}.txt'),f'{a} survives')
        self.assertIn('quarantin',json.dumps([r,status]).lower(),'No explicit conflict disposition')
        self.assertEqual((self.paths['B']/'notes/shared.txt').read_text(),'B incompatible\n')
    def test_operation_id_binding_and_stale_generation(self):
        write(self.paths['A'],'docs/A.txt','first\n');g=self.gen['A']
        r=self.checkpoint('A','retry-checkpoint')
        same=self.req(op='checkpoint',workspace='A',expected_generation=g,operation_id='retry-checkpoint')
        self.assertEqual(same,r)
        changed=self.req(op='checkpoint',workspace='B',expected_generation=self.gen['B'],operation_id='retry-checkpoint',ok=False)
        self.assertTrue(any(w in json.dumps(changed).lower() for w in ('mismatch','conflict','reuse','bound')))
        before=manifest(self.paths['A'])
        stale=self.req(op='adopt',workspace='A',target='latest',expected_generation=g,operation_id='stale-adopt',ok=False)
        self.assertTrue(any(w in json.dumps(stale).lower() for w in ('stale','generation_mismatch')));self.assertEqual(before,manifest(self.paths['A']))
        p=self.publish('A',r,'retry-publish');p2=self.publish('A',r,'retry-publish');self.assertEqual(p,p2)
        self.integrate();h=self.head();self.integrate();self.assertEqual(h,self.head())
    def test_dirty_adoption_conflict_preserves_live(self):
        write(self.paths['A'],'notes/shared.txt','shared new\n');self.publish('A',self.checkpoint('A'));self.integrate()
        write(self.paths['B'],'notes/shared.txt','private other\n');before=manifest(self.paths['B'])
        r=self.adopt('B',ok=False)
        self.assertIn('conflict',json.dumps(r).lower());self.assertEqual(before,manifest(self.paths['B']))
    def test_byte_roundtrip_and_private_adoption(self):
        write(self.paths['A'],'docs/new.txt','new\n');self.publish('A',self.checkpoint('A'));self.integrate()
        write(self.paths['B'],'notes/shared.txt','B private WIP\n');before=manifest(self.paths['B']);self.adopt('B')
        after=manifest(self.paths['B'])
        for path in ('assets/palette.bin','data/lf.txt','data/crlf.txt','scripts/show.sh','notes/shared.txt','.env','local/keep.bin'):
            self.assertEqual(before[path],after[path],path)
        self.assertEqual((self.paths['B']/'docs/new.txt').read_text(),'new\n')
    def test_public_restore_preserves_source_and_fences_pending(self):
        write(self.paths['A'],'docs/restored.txt','integrated recovery source\n');self.publish('A',self.checkpoint('A'));self.integrate();head=self.head()
        write(self.paths['B'],'docs/pending.txt','accepted unresolved source\n');pending=self.publish('B',self.checkpoint('B'))
        write(self.paths['A'],'private-not-published.txt','PRIVATE_RESTORE_CANARY\n');self.checkpoint('A')
        remote=self.h.root/'restore-source.git';self.h.command(['git','init','--bare',str(remote)])
        backed=self.req(op='backup_flush',destination=str(remote),operation_id='restore-backup');self.assertEqual(backed['state'],'complete')
        fresh=self.h.root/'restored-state'
        def restored(ok=True,**r):return self.h.call('--state',fresh,json.dumps(r),ok=ok)
        r=restored(op='restore',destination=str(remote));self.assertEqual(r['integration'],head)
        self.assertFalse(r['private_workspaces_restored']);self.assertTrue(r['ownership_restored']);self.assertTrue(r['intent_restored']);self.assertTrue(r['activation_required']);self.assertFalse(r['authenticated_migration'])
        status=restored(op='status');self.assertEqual(status['workspaces'],0);self.assertEqual(status['head'],head)
        self.assertEqual(self.h.git(fresh/'coordinator.git','show',head+':docs/restored.txt'),'integrated recovery source')
        ps=restored(op='proposal_status',proposal=pending['proposal']);self.assertEqual(ps['state'],'recovery_quarantined')
        blocked=restored(op='integrate',ok=False);self.assertEqual(blocked['error']['code'],'public_recovery_activation_required');self.assertEqual(restored(op='status')['head'],head)
        retry=restored(op='retry_proposal',proposal=pending['proposal'],operation_id='unsafe-recovered-retry',ok=False)
        self.assertEqual(retry.get('ok'),False);self.assertEqual(restored(op='status')['head'],head)
        self.assertIn(pending['commit'],self.h.git(fresh/'coordinator.git','rev-list','--all').splitlines())
        self.assertNotIn('private-not-published.txt',self.h.git(fresh/'coordinator.git','rev-list','--objects','--all'))
        self.assertEqual(ps['details']['public_queue_snapshot']['intent'],'Scripted actor B fixture change')
        self.assertEqual(ps['details']['public_queue_snapshot']['ownership']['kind'],'local_authority')
        missing=restored(op='recovery_activate',sync_binding=None,ok=False);self.assertEqual(missing['error']['code'],'public_recovery_confirmation_required')
        activated=restored(op='recovery_activate',sync_binding=None,confirm_old_authority_stopped=True,confirm_public_recovery_reviewed=True)
        self.assertFalse(activated['activation_required']);self.assertEqual(activated['fencing'],'operator_assertion_only')
        self.assertEqual(restored(op='proposal_status',proposal=pending['proposal'])['state'],'coordinator_accepted')
        restored(op='integrate');new_head=restored(op='status')['head']
        self.assertEqual(self.h.git(fresh/'coordinator.git','show',new_head+':docs/pending.txt'),'accepted unresolved source')
        self.assertEqual(restored(op='status')['workspaces'],0)
        self.assertNotIn('private-not-published.txt',self.h.git(fresh/'coordinator.git','rev-list','--objects','--all'))
    def test_public_restore_rejects_existing_state(self):
        remote=self.h.root/'restore-source.git';self.h.command(['git','init','--bare',str(remote)])
        self.req(op='backup_flush',destination=str(remote),operation_id='restore-backup')
        head=self.head();before={a:manifest(p) for a,p in self.paths.items()}
        r=self.req(op='restore',destination=str(remote),ok=False);self.assertEqual(r.get('ok'),False)
        self.assertEqual(self.head(),head);self.assertEqual(self.req(op='status')['workspaces'],4)
        for a,p in self.paths.items():self.assertEqual(before[a],manifest(p))
    def test_divergent_head_fences_crash_recovery(self):
        write(self.paths['A'],'docs/fence.txt','pending proposal\n');self.publish('A',self.checkpoint('A'))
        self.crash('promotion_before_cas',op='integrate')
        repo=self.coordinator();tree=self.h.git(repo,'rev-parse',self.init['head']+'^{tree}')
        foreign=self.h.git(repo,'-c','user.name=Fixture','-c','user.email=fixture@example.invalid','commit-tree',tree,'-m','Unrelated fixture root')
        self.h.git(repo,'update-ref','refs/wipstash/integration',foreign)
        r=self.req(op='status',ok=False);self.assertIn('recovery_required',json.dumps(r))
        self.assertEqual(self.h.git(repo,'rev-parse','refs/wipstash/integration'),foreign,'Recovery force-reset divergent history')
    def test_mcp_stdio_protocol_smoke(self):
        requests=[{'jsonrpc':'2.0','id':1,'method':'initialize','params':{'protocolVersion':'2024-11-05','capabilities':{},'clientInfo':{'name':'scripted-test','version':'1'}}},
            {'jsonrpc':'2.0','method':'notifications/initialized'},
            {'jsonrpc':'2.0','id':2,'method':'tools/list'},
            {'jsonrpc':'2.0','id':3,'method':'tools/call','params':{'name':'wipstash','arguments':{'request':{'op':'status'}}}}]
        argv=[self.h.binary,'--state',str(self.state),'mcp']
        result=subprocess.run(argv,input=''.join(json.dumps(x)+'\n' for x in requests),capture_output=True,text=True,timeout=10)
        self.h.events.append({'argv':argv,'stdin':requests,'stdout':result.stdout,'stderr':result.stderr,'exit':result.returncode})
        self.assertEqual(result.returncode,0);responses=[json.loads(l) for l in result.stdout.splitlines()]
        self.assertEqual([r['id'] for r in responses],[1,2,3]);self.assertEqual(responses[1]['result']['tools'][0]['name'],'wipstash')
        status=json.loads(responses[2]['result']['content'][0]['text']);self.assertEqual(status['head'],self.head())
    def test_declared_scripted_repair_records_exact_inputs(self):
        write(self.paths['A'],'notes/shared.txt','A incompatible\n');write(self.paths['B'],'notes/shared.txt','B incompatible\n')
        for a in 'AB':self.publish(a,self.checkpoint(a))
        script="import os,json;from pathlib import Path;Path('notes/shared.txt').write_text('explicit scripted resolution\\n');Path('.wipstash-resolution.json').write_text(json.dumps({'head':os.environ['WIPSTASH_HEAD'],'proposal':os.environ['WIPSTASH_PROPOSAL'],'input_tree':os.environ['WIPSTASH_CANDIDATE_TREE'],'resolved_paths':json.loads(os.environ['WIPSTASH_CONFLICT_PATHS'])}))"
        self.req(op='configure',policy={'checks':[],'repair':{'execution_profile':'trusted_unsandboxed','argv':[sys.executable,'-c',script],'max_attempts':1,'timeout_seconds':2}},operation_id='configure-scripted-repair')
        r=self.integrate();self.assertEqual(r['outcomes'][1]['state'],'integrated');self.assertEqual(r['outcomes'][1]['evidence'],'agent_resolved_unchecked')
        self.assertEqual(self.blob(self.head(),'notes/shared.txt'),'explicit scripted resolution')
        self.assertNotIn('.wipstash-resolution.json',self.h.git(self.coordinator(),'ls-tree','-r','--name-only',self.head()))
        status=self.req(op='proposal_status',proposal=r['outcomes'][1]['proposal']);details=json.loads(status['details']) if isinstance(status['details'],str) else status['details']
        parents=self.h.git(self.coordinator(),'rev-list','--parents','-n','1',self.head()).split()[1:]
        self.assertEqual(parents,[details['head'],details['proposal']])
        self.assertEqual(details['candidate_tree'],self.h.git(self.coordinator(),'rev-parse',self.head()+'^{tree}'))
    def test_repair_unrelated_edit_does_not_resolve_conflict(self):
        write(self.paths['A'],'notes/shared.txt','A incompatible\n');write(self.paths['B'],'notes/shared.txt','B incompatible\n')
        for a in 'AB':self.publish(a,self.checkpoint(a))
        self.req(op='configure',policy={'checks':[],'repair':{'execution_profile':'trusted_unsandboxed','argv':['/bin/sh','-c',"printf 'unrelated\\n' > docs/unrelated.txt"],'max_attempts':1,'timeout_seconds':2}},operation_id='configure-bad-repair')
        r=self.integrate()
        self.assertEqual(r['outcomes'][1]['state'],'quarantined','Unrelated edit is not a conflict resolution')
        self.assertEqual(self.blob(self.head(),'notes/shared.txt'),'A incompatible')
    def test_optional_required_check_rejects_exact_candidate(self):
        base=self.head();write(self.paths['A'],'docs/check.txt','candidate\n');p=self.publish('A',self.checkpoint('A'))
        self.req(op='configure',policy={'checks':[{'id':'deliberate-fail','argv':['/bin/sh','-c','exit 7'],'required':True,'timeout_seconds':2}]},operation_id='configure-required')
        r=self.integrate();self.assertEqual(self.head(),base);self.assertEqual(r['outcomes'][0]['state'],'quarantined')
        status=self.req(op='proposal_status',proposal=p['proposal']);details=json.loads(status['details']) if isinstance(status['details'],str) else status['details']
        self.assertEqual(details['checks'][0]['exit_code'],7);self.assertEqual(details['checks'][0]['candidate_tree'],details['candidate_tree'])
    def test_offline_cached_adoption_requires_explicit_oid(self):
        write(self.paths['A'],'docs/cached.txt','cached bytes\n');self.publish('A',self.checkpoint('A'));self.integrate();target=self.head()
        self.req(op='updates',workspace='B');coordinator=self.state/'coordinator.git';offline=self.h.root/'coordinator-offline.git';coordinator.rename(offline)
        try:
            r=self.adopt('B',ok=False);self.assertIn('coordinator_unreachable',json.dumps(r))
            r=self.req(op='adopt',workspace='B',target=target,expected_generation=self.gen['B'],operation_id='adopt-cached')
            self.assertEqual(r['adopted'],target);self.assertEqual((self.paths['B']/'docs/cached.txt').read_text(),'cached bytes\n')
        finally:offline.rename(coordinator)
    def test_offline_save_publish_and_reconnect(self):
        coordinator=self.state/'coordinator.git';offline=self.h.root/'coordinator-offline.git';coordinator.rename(offline)
        try:
            write(self.paths['A'],'docs/offline.txt','offline private then queued\n');c=self.checkpoint('A');p=self.publish('A',c,'offline-publish')
            self.assertEqual(p['state'],'queued_offline');self.assertEqual(p['durability'],'local_saved')
            st=self.req(op='status',workspace='A');self.assertFalse(st['coordinator_online'])
        finally:offline.rename(coordinator)
        self.integrate();self.assertEqual(self.blob(self.head(),'docs/offline.txt'),'offline private then queued')
        self.assertFalse((self.paths['B']/'docs/offline.txt').exists())
    def test_explicit_adoption_resolution_and_stale_live_guard(self):
        write(self.paths['A'],'notes/shared.txt','shared new\n');self.publish('A',self.checkpoint('A'));self.integrate()
        write(self.paths['B'],'notes/shared.txt','private other\n');conflict=self.adopt('B',ok=False)
        write(self.paths['B'],'notes/shared.txt','deliberately resolved\n');c=self.checkpoint('B')
        request=dict(op='resolve_adoption',workspace='B',candidate=conflict['candidate'],target=conflict['target'],checkpoint=c['checkpoint'],expected_generation=self.gen['B'],operation_id='resolve-explicit')
        write(self.paths['B'],'notes/shared.txt','newer private edit\n');before=manifest(self.paths['B']);stale=self.req(**request,ok=False)
        self.assertIn('stale_adoption_candidate',json.dumps(stale));self.assertEqual(before,manifest(self.paths['B']))
        write(self.paths['B'],'notes/shared.txt','deliberately resolved\n');self.assertEqual(self.req(**request,ok=False),stale)
        request['operation_id']='resolve-explicit-retry';r=self.req(**request)
        self.assertEqual(r['adopted'],self.head());self.assertEqual(r['resolution'],'explicit_checkpoint')
        self.assertEqual((self.paths['B']/'notes/shared.txt').read_text(),'deliberately resolved\n')
    def test_backup_preserves_accepted_unintegrated_proposal(self):
        write(self.paths['A'],'docs/backup.txt','accepted but not integrated\n');p=self.publish('A',self.checkpoint('A'))
        remote=self.h.root/'backup.git';fresh=self.h.root/'fresh.git'
        self.h.command(['git','init','--bare',str(remote)])
        r=self.req(op='backup_flush',destination=str(remote),operation_id='backup-local')
        self.assertFalse(r['github_backed_up']);self.assertEqual(r['state'],'complete')
        self.h.command(['git','clone','--bare',str(remote),str(fresh)])
        self.assertIn(p['commit'],self.h.git(fresh,'rev-list','--all').splitlines(),'Proposal must be reachable, not merely present')
        self.h.git(fresh,'cat-file','-e',p['commit']+'^{commit}')
        self.assertEqual(self.h.git(fresh,'show',p['commit']+':docs/backup.txt'),'accepted but not integrated')
    def test_semantically_broken_clean_merge_remains_unchecked(self):
        write(self.paths['A'],'src/pricing.py','def quote(item):\n    return item["cents"] * item["qty"]\n')
        write(self.paths['C'],'src/discount.py','from pricing import quote\n\ndef discount(cents, qty):\n    return quote(cents, qty) - 100\n')
        for a in 'AC':self.publish(a,self.checkpoint(a))
        r=self.integrate();self.assertEqual(r['evidence'],'unchecked')
        self.assertTrue(all(o['state']=='integrated' for o in r['outcomes']))
        self.adopt('B')
        # Observer probe after integration, explicitly not an integration check.
        probe=self.h.command([sys.executable,'-c','from discount import discount; discount(100, 2)'],cwd=self.paths['B'],env={'PYTHONPATH':str(self.paths['B']/'src')},ok=False)
        self.assertNotEqual(probe.returncode,0);self.assertIn('TypeError',probe.stderr)
    def test_background_worker_integrates_without_adopting(self):
        write(self.paths['A'],'docs/background.txt','autonomous integration\n');self.publish('A',self.checkpoint('A'))
        before={a:manifest(p) for a,p in self.paths.items()};base=self.head()
        worker=subprocess.Popen([self.h.binary,'--state',str(self.state),'worker'],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
        try:
            deadline=time.monotonic()+10
            while self.head()==base and time.monotonic()<deadline:
                self.assertIsNone(worker.poll(),'Background worker exited early');time.sleep(.05)
            self.assertNotEqual(self.head(),base,'Worker did not integrate within test deadline')
            self.assertEqual(self.blob(self.head(),'docs/background.txt'),'autonomous integration')
            for a,p in self.paths.items():self.assertEqual(before[a],manifest(p))
        finally:
            worker.terminate()
            try:stdout,stderr=worker.communicate(timeout=5)
            except subprocess.TimeoutExpired:worker.kill();stdout,stderr=worker.communicate()
            self.h.events.append({'background_worker_pid':worker.pid,'exit':worker.returncode,'stdout':stdout,'stderr':stderr})
    def test_unchanged_and_republished_tree_is_noop(self):
        base=self.head();c=self.checkpoint('A');self.publish('A',c);r=self.integrate()
        self.assertEqual(self.head(),base,'Unchanged source created a false integration transition')
        self.assertTrue(any(x in json.dumps(r) for x in ('no_op','noop','already_included')))
        write(self.paths['A'],'docs/real.txt','real change\n');c=self.checkpoint('A');self.publish('A',c);self.integrate();head=self.head()
        self.publish('A',c);self.integrate();self.assertEqual(head,self.head())
    def test_checkpoint_after_commit_retry(self):
        write(self.paths['A'],'docs/saved.txt','acknowledgement lost\n')
        request=dict(op='checkpoint',workspace='A',expected_generation=0,operation_id='interrupted-save')
        self.crash('checkpoint_after_commit',**request)
        status=self.req(op='operation_status',operation_id='interrupted-save');retry=self.req(**request)
        self.assertEqual(status,retry);self.assertEqual(retry['generation'],1)
        self.assertEqual(self.req(op='status',workspace='A')['generation'],1)
        self.assertEqual(self.h.git(self.state/'locals'/'A'/'objects.git','show',retry['commit']+':docs/saved.txt'),'acknowledgement lost')
    def test_checkpoint_after_pin_retry(self):
        write(self.paths['A'],'docs/saved.txt','pinned bytes\n')
        request=dict(op='checkpoint',workspace='A',expected_generation=0,operation_id='interrupted-pin')
        self.crash('checkpoint_after_pin',**request);retry=self.req(**request)
        self.assertEqual(retry['generation'],1);self.assertEqual(self.req(**request),retry)
    def test_publish_after_pin_retry(self):
        write(self.paths['A'],'docs/saved.txt','accepted bytes\n');c=self.checkpoint('A')
        request=dict(op='publish',workspace='A',checkpoint=c['checkpoint'],intent='fault fixture',operation_id='interrupted-publish')
        self.crash('publish_after_pin',**request);retry=self.req(**request);self.assertEqual(self.req(**request),retry)
        self.integrate();head=self.head();self.assertEqual(self.blob(head,'docs/saved.txt'),'accepted bytes')
        self.integrate();self.assertEqual(head,self.head())
    def test_promotion_before_cas_recovery(self):
        write(self.paths['A'],'docs/promotion.txt','promotion bytes\n');self.publish('A',self.checkpoint('A'))
        self.crash('promotion_before_cas',op='integrate');self.req(op='status')
        head=self.head();self.assertEqual(self.blob(head,'docs/promotion.txt'),'promotion bytes');self.integrate();self.assertEqual(head,self.head())
    def test_ignored_collision_blocks_adoption(self):
        write(self.paths['A'],'docs/collision.txt','public bytes\n');self.publish('A',self.checkpoint('A'));self.integrate()
        with (self.paths['B']/'.gitignore').open('a') as f:f.write('docs/collision.txt\n')
        write(self.paths['B'],'docs/collision.txt','private ignored bytes\n');before=manifest(self.paths['B'])
        r=self.adopt('B',ok=False);self.assertEqual(r.get('ok'),False);self.assertIn('collision',json.dumps(r));self.assertEqual(before,manifest(self.paths['B']))
    def test_deletions_and_allowed_untracked_files(self):
        (self.paths['A']/'docs/api.md').unlink();write(self.paths['A'],'docs/untracked.txt','new file\n')
        self.publish('A',self.checkpoint('A'));self.integrate();self.adopt('B')
        self.assertFalse((self.paths['B']/'docs/api.md').exists());self.assertEqual((self.paths['B']/'docs/untracked.txt').read_text(),'new file\n')
    def test_unsupported_paths_fail_before_checkpoint(self):
        a=self.paths['A'];write(a,'Case.txt','upper');write(a,'case.txt','lower')
        before=manifest(a)
        r=self.req(op='checkpoint',workspace='A',expected_generation=self.gen['A'],operation_id='collision-save',ok=False)
        self.assertIn('collision',json.dumps(r).lower());self.assertEqual(before,manifest(a))
        (a/'Case.txt').unlink();(a/'case.txt').unlink()
        outside=self.h.root/'outside-secret.txt';outside.write_text('OUTSIDE_CANARY')
        (a/'escape').symlink_to(outside)
        r=self.req(op='checkpoint',workspace='A',expected_generation=self.gen['A'],operation_id='symlink-save',ok=False)
        self.assertIn('symlink',json.dumps(r).lower());self.assertEqual(outside.read_text(),'OUTSIDE_CANARY')
    def test_foreign_or_backward_adoption_is_rejected(self):
        base=self.head()
        write(self.paths['A'],'docs/forward.txt','forward\n');c=self.checkpoint('A');self.publish('A',c);self.integrate();self.adopt('B')
        before=manifest(self.paths['B'])
        for target in (base,c['commit'],'0'*40):
            r=self.req(op='adopt',workspace='B',target=target,expected_generation=self.gen['B'],operation_id=self.oid('invalid-target'),ok=False)
            self.assertEqual(r.get('ok'),False,f'Accepted invalid target {target}: {r}')
            self.assertEqual(before,manifest(self.paths['B']))
    def test_promotion_process_crash_reconciliation(self):
        write(self.paths['A'],'docs/crash.txt','durable proposal\n');self.publish('A',self.checkpoint('A'))
        self.crash('promotion_after_cas',op='integrate',operation_id='crash-integration')
        recovered=self.req(op='status');head=self.head()
        self.assertEqual(self.blob(head,'docs/crash.txt'),'durable proposal')
        self.integrate();self.assertEqual(self.head(),head)
    def test_adoption_process_crash_reconciliation(self):
        self.adoption_crash("adoption_after_apply")
    def test_adoption_mid_apply_process_crash(self):
        self.adoption_crash("adoption_mid_apply")
    def test_adoption_intent_process_crash(self):
        self.adoption_crash("adoption_after_intent")
    def adoption_crash(self,fault):
        write(self.paths['A'],'docs/crash.txt','adoption bytes\n');self.publish('A',self.checkpoint('A'));self.integrate()
        before=manifest(self.paths['B'])
        self.crash(fault,op='adopt',workspace='B',target='latest',expected_generation=self.gen['B'],operation_id='crash-adoption')
        status=self.req(op='status',workspace='B')
        after=manifest(self.paths['B'])
        self.assertEqual(after['.env'],before['.env']);self.assertEqual(after['local/keep.bin'],before['local/keep.bin'])
        # Restart may roll forward or roll back; either complete tree is valid.
        added=self.paths['B']/'docs/crash.txt'
        if added.exists():
            self.assertEqual(added.read_text(),'adoption bytes\n')
            expected=dict(before);expected['docs/crash.txt']=manifest(self.paths['A'])['docs/crash.txt']
            self.assertEqual(expected,after);self.assertEqual(status['generation'],1);self.assertEqual(status['adopted'],self.head())
        else:
            self.assertEqual(before,after);self.assertEqual(status['generation'],0);self.assertEqual(status['adopted'],self.init['head'])
if __name__=='__main__':
    RUN.mkdir(parents=True,exist_ok=True)
    (RUN/'environment.json').write_text(json.dumps({'platform':platform.platform(),'python':sys.version,'binary':str(Path(ARGS.binary).resolve()),'binary_sha256':hashlib.sha256(Path(ARGS.binary).read_bytes()).hexdigest(),'source_sha256':{str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in Path('src').glob('*.rs')},'git':subprocess.check_output(['git','--version'],text=True).strip(),'actors':'four scripted process clients, not Codex/Claude sessions','durability':'process-crash tests on this retained local filesystem only'},indent=2)+'\n')
    suite=unittest.defaultTestLoader.loadTestsFromNames(REST,module=sys.modules[__name__]) if REST else unittest.defaultTestLoader.loadTestsFromTestCase(Adversarial)
    result=unittest.TextTestRunner(verbosity=2).run(suite)
    (RUN/'summary.json').write_text(json.dumps({'tests':result.testsRun,'failures':[str(t) for t,_ in result.failures],'errors':[str(t) for t,_ in result.errors],'successful':result.wasSuccessful()},indent=2)+'\n')
    print(f'Evidence: {RUN}')
    sys.exit(not result.wasSuccessful())
