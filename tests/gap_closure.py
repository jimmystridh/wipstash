#!/usr/bin/env python3
"""Independent gap-closure CLI tests. Deterministic state fixtures; no kill campaign."""
import argparse, hashlib, json, os, platform, sqlite3, subprocess, sys, time, unittest
from pathlib import Path
from harness_support import Harness, manifest, write
P=argparse.ArgumentParser(); P.add_argument('--binary',default='target/debug/wipstash'); P.add_argument('--artifacts',default='evidence/gap-closure/runs'); ARGS,REST=P.parse_known_args()
RUN=Path(ARGS.artifacts).resolve()/time.strftime('%Y%m%dT%H%M%S')
class Gaps(unittest.TestCase):
    def setUp(self):
        self.h=Harness(ARGS.binary,RUN/self._testMethodName); self.state=self.h.root/'state'; self.source=self.h.fixture(self.h.root/'source'); self.n=0
        self.req(op='init',source=str(self.source)); self.paths={}; self.gen={}
        for a in 'AB':
            self.paths[a]=self.h.root/a
            self.gen[a]=self.req(op='open',workspace=a,path=str(self.paths[a]))['generation']
    def tearDown(self): self.h.save_log()
    def req(self,ok=True,**r):
        self.n+=1
        if r['op'] not in ('status','proposal_status','updates'): r.setdefault('operation_id',f'gap-{self.n}')
        return self.h.call('--state',self.state,json.dumps(r),ok=ok)
    def cp(self,a):
        c=self.req(op='checkpoint',workspace=a,expected_generation=self.gen[a]); self.gen[a]=c['generation']; return c
    def pub(self,a): return self.req(op='publish',workspace=a,checkpoint=self.cp(a)['checkpoint'],intent='synthetic gap test')
    def test_invalid_policy_is_atomic(self):
        self.req(op='configure',policy={'checks':[]})
        with sqlite3.connect(self.state/'state.sqlite') as db: before=db.execute("select value from meta where key='policy'").fetchone()
        bad=[{'checks':'wrong'}, {'checks':[{'id':'x','argv':[]}]}, {'checks':[{'id':'x','argv':['/bin/true'],'required':'true'}]}, {'checks':[{'id':'x','argv':['/bin/true']},{'id':'x','argv':['/bin/true']}]}, {'repair':{'execution_profile':'trusted_unsandboxed','argv':['/bin/true'],'max_attempts':3}}, {'repair':{'execution_profile':'trusted_unsandboxed','argv':['/bin/true'],'timeout_seconds':0}}, {'unexpected':True}]
        for policy in bad:
            with self.subTest(policy=policy):
                self.assertFalse(self.req(op='configure',policy=policy,ok=False)['ok'])
                with sqlite3.connect(self.state/'state.sqlite') as db: self.assertEqual(before,db.execute("select value from meta where key='policy'").fetchone())
    def test_persisted_command_intent_fences_until_explicit_ack(self):
        cp=self.cp('A'); before=manifest(self.paths['A']); g=self.gen['A']
        with sqlite3.connect(self.state/'state.sqlite') as db:
            db.execute("insert into commands(id,workspace,state,generation) values('seeded-running','A','running',?)",(g,))
        self.req(op='status')
        with sqlite3.connect(self.state/'state.sqlite') as db: self.assertEqual('uncertain',db.execute("select state from commands where id='seeded-running'").fetchone()[0])
        requests=[dict(op='checkpoint'),dict(op='publish',checkpoint=cp['checkpoint'],intent='fixture'),dict(op='adopt',target='latest'),dict(op='command_run',argv=['/bin/true'])]
        for r in requests:
            with self.subTest(op=r['op']):
                reply=self.req(workspace='A',expected_generation=g,ok=False,**r)
                self.assertEqual('writer_recovery_required',reply['error']['code'])
                self.assertEqual(before,manifest(self.paths['A']))
        self.assertFalse(self.req(op='command_recover',workspace='A',expected_generation=g,ok=False)['ok'])
        self.assertFalse(self.req(op='command_recover',workspace='A',expected_generation=g-1,confirm_writers_stopped=True,ok=False)['ok'])
        ack=self.req(op='command_recover',workspace='A',expected_generation=g,confirm_writers_stopped=True,operation_id='ack')
        self.assertEqual(g+1,ack['generation']); self.assertEqual(1,ack['commands_acknowledged'])
        self.assertEqual(ack,self.req(op='command_recover',workspace='A',expected_generation=g,confirm_writers_stopped=True,operation_id='ack'))
        self.gen['A']=ack['generation']; self.cp('A')
        self.assertEqual(before,manifest(self.paths['A']))
    def test_legacy_pending_command_is_not_replayed(self):
        marker=self.h.root/'never-launch'
        request={'op':'command_run','workspace':'A','expected_generation':0,'operation_id':'legacy','argv':[sys.executable,'-c',f"open({str(marker)!r},'w').write('bad')"]}
        encoded=json.dumps(request,sort_keys=True,separators=(',',':')); digest=hashlib.sha256(encoded.encode()).hexdigest()
        with sqlite3.connect(self.state/'state.sqlite') as db: db.execute('insert into operations(id,digest,request) values(?,?,?)',('legacy',digest,encoded))
        status=self.req(op='status',workspace='A'); self.assertTrue(status['writer_recovery_required']); self.assertIsNone(status['dirty']); self.assertEqual(1,status['generation'])
        reply=self.req(**request,ok=False); self.assertFalse(reply['ok']); self.assertFalse(marker.exists())
        with sqlite3.connect(self.state/'state.sqlite') as db: self.assertEqual('uncertain',db.execute("select state from commands where id='legacy'").fetchone()[0])
    def test_repair_budget_persists_across_retry_and_policy_change(self):
        write(self.paths['A'],'notes/shared.txt','A incompatible\n'); write(self.paths['B'],'notes/shared.txt','B incompatible\n')
        self.pub('A'); b=self.pub('B')
        marker=self.h.root/'repair-count'
        script=f"from pathlib import Path; p=Path({str(marker)!r}); p.write_text(p.read_text()+'x' if p.exists() else 'x')"
        policy={'checks':[],'repair':{'execution_profile':'trusted_unsandboxed','argv':[sys.executable,'-c',script],'max_attempts':1,'timeout_seconds':2}}
        self.req(op='configure',policy=policy); self.req(op='integrate'); self.assertEqual('x',marker.read_text())
        policy['repair']['timeout_seconds']=3
        self.req(op='configure',policy=policy); self.req(op='retry_proposal',proposal=b['proposal']); self.req(op='integrate')
        self.assertEqual('x',marker.read_text())
        with sqlite3.connect(self.state/'repair-budget.sqlite') as db: self.assertEqual((1,2),db.execute('select attempts,seconds from repair_budgets where proposal=?',(b['commit'],)).fetchone())
        status=self.req(op='proposal_status',proposal=b['proposal']); details=json.loads(status['details']) if isinstance(status['details'],str) else status['details']
        self.assertTrue(details['repair_budget_durable']); self.assertTrue(details['repair_budget_exhausted'])
    def test_reserved_interrupted_budget_prevents_worker_launch(self):
        write(self.paths['A'],'notes/shared.txt','A incompatible\n'); write(self.paths['B'],'notes/shared.txt','B incompatible\n'); self.pub('A'); b=self.pub('B')
        with sqlite3.connect(self.state/'repair-budget.sqlite') as db:
            db.execute('create table repair_budgets(proposal text primary key, attempts integer not null, seconds integer not null)'); db.execute('insert into repair_budgets values(?,2,600)',(b['commit'],))
        marker=self.h.root/'must-not-exist'
        self.req(op='configure',policy={'checks':[],'repair':{'execution_profile':'trusted_unsandboxed','argv':[sys.executable,'-c',f"open({str(marker)!r},'w').write('bad')"],'max_attempts':2,'timeout_seconds':1}})
        self.req(op='integrate'); self.assertFalse(marker.exists()); self.assertEqual('quarantined',self.req(op='proposal_status',proposal=b['proposal'])['state'])
    def test_restore_retains_queue_history_without_eligibility(self):
        write(self.paths['A'],'docs/pending.txt','pending public bytes\n'); p=self.pub('A')
        policy={'checks':[{'id':'restored-required-check','argv':[sys.executable,'-c','pass'],'timeout_seconds':2}]}
        self.req(op='configure',policy=policy)
        remote=self.h.root/'backup.git'; self.h.command(['git','init','--bare',str(remote)])
        self.req(op='backup_flush',destination=str(remote))
        fresh=self.h.root/'restored'
        def restored(ok=True,**r):return self.h.call('--state',fresh,json.dumps(r),ok=ok)
        restored(op='restore',destination=str(remote))
        status=restored(op='proposal_status',proposal=p['proposal']); self.assertEqual('recovery_quarantined',status['state'])
        details=json.loads(status['details']) if isinstance(status['details'],str) else status['details']
        snapshot=details['public_queue_snapshot']; self.assertEqual('coordinator_accepted',snapshot['state']); self.assertIsInstance(snapshot['queue_order'],int)
        self.assertFalse(details['eligibility_restored']); self.assertTrue(details['ownership_restored']); self.assertTrue(details['intent_restored'])
        self.assertEqual(snapshot['intent'],'synthetic gap test'); self.assertEqual(snapshot['ownership']['kind'],'local_authority')
        head=restored(op='status')['head']; blocked=restored(op='integrate',ok=False)
        self.assertEqual(blocked['error']['code'],'public_recovery_activation_required'); self.assertEqual(head,restored(op='status')['head'])
        activation=dict(op='recovery_activate',sync_binding=None,confirm_old_authority_stopped=True,confirm_public_recovery_reviewed=True)
        missing_policy=restored(ok=False,**activation); self.assertEqual(missing_policy['error']['code'],'public_recovery_policy_mismatch')
        restored(op='configure',operation_id='restore-matching-policy',policy=policy)
        activated=restored(**activation); self.assertFalse(activated['activation_required']); self.assertFalse(activated['authenticated_migration'])
        self.assertEqual(restored(op='proposal_status',proposal=p['proposal'])['state'],'coordinator_accepted')
        restored(op='integrate')
        final=restored(op='proposal_status',proposal=p['proposal']); self.assertEqual(final['state'],'integrated'); self.assertEqual(final['evidence'],'checks_executed')
        self.assertEqual(restored(op='status')['workspaces'],0)
    def test_mcp_lifecycle_notifications_and_invalid_tools(self):
        frames=[{'jsonrpc':'2.0','id':1,'method':'tools/list'},
            {'jsonrpc':'2.0','id':2,'method':'initialize','params':{'protocolVersion':'2024-11-05','capabilities':{},'clientInfo':{'name':'independent-script','version':'1'}}},
            {'jsonrpc':'2.0','method':'notifications/initialized'},
            {'jsonrpc':'2.0','id':3,'method':'tools/list'},
            {'jsonrpc':'2.0','method':'tools/call','params':{'name':'wipstash_open','arguments':{'workspace':'never','path':str(self.h.root/'never'),'operation_id':'never'}}},
            {'jsonrpc':'2.0','id':4,'method':'tools/call','params':{'name':'wipstash_commit','arguments':{'workspace':'A','intent':'Invalid generation','operation_id':'mcp-bad','expected_generation':-1}}},
            {'jsonrpc':'2.0','id':5,'method':'tools/call','params':{'name':'unknown','arguments':{}}},
            {'jsonrpc':'2.0','id':6,'method':'tools/call','params':{'name':'wipstash_status','arguments':{}}}]
        wire='\n'.join(json.dumps(f) for f in frames)+'\n'
        run=subprocess.run([self.h.binary,'--state',str(self.state),'mcp'],input=wire,capture_output=True,text=True,timeout=15)
        self.h.events.append({'argv':[self.h.binary,'--state',str(self.state),'mcp'],'stdin':wire,'stdout':run.stdout,'stderr':run.stderr,'exit':run.returncode})
        self.assertEqual(0,run.returncode); replies=[json.loads(line) for line in run.stdout.splitlines()]; self.assertEqual([1,2,3,4,5,6],[r['id'] for r in replies])
        self.assertEqual(-32002,replies[0]['error']['code']); self.assertEqual('2025-11-25',replies[1]['result']['protocolVersion'])
        self.assertIn('wipstash_adopt',[t['name'] for t in replies[2]['result']['tools']]); self.assertTrue(replies[3]['result']['isError']); self.assertEqual(-32602,replies[4]['error']['code'])
        self.assertEqual(2,json.loads(replies[5]['result']['content'][0]['text'])['workspaces']); self.assertFalse((self.h.root/'never').exists())
    def test_mcp_oversized_frame_recovers_at_next_line(self):
        wire='x'*(1024*1024+1)+'\n'+json.dumps({'jsonrpc':'2.0','id':9,'method':'ping'})+'\n'
        run=subprocess.run([self.h.binary,'--state',str(self.state),'mcp'],input=wire,capture_output=True,text=True,timeout=15)
        self.h.events.append({'argv':[self.h.binary,'--state',str(self.state),'mcp'],'stdin_description':'1048577 x bytes, newline, valid ping id 9, newline','stdin_sha256':hashlib.sha256(wire.encode()).hexdigest(),'stdout':run.stdout,'stderr':run.stderr,'exit':run.returncode})
        self.assertEqual(0,run.returncode); replies=[json.loads(line) for line in run.stdout.splitlines()]
        self.assertEqual(2,len(replies)); self.assertIn('error',replies[0]); self.assertEqual({'jsonrpc':'2.0','id':9,'result':{}},replies[1])
    def test_oversized_blob_rejected_without_checkpoint(self):
        large=self.paths['A']/'oversized.bin'
        with large.open('wb') as f: f.truncate(16*1024*1024+1)
        r=self.req(op='checkpoint',workspace='A',expected_generation=0,ok=False)
        self.assertFalse(r['ok'])
        with sqlite3.connect(self.state/'state.sqlite') as db:
            self.assertEqual(0,db.execute("select generation from workspaces where id='A'").fetchone()[0]); self.assertEqual(0,db.execute("select count(*) from checkpoints where workspace='A'").fetchone()[0])
        self.assertEqual(16*1024*1024+1,large.stat().st_size)
    def test_workspace_alias_is_canonical_and_cannot_redirect(self):
        actual=self.h.root/'actual'; actual.mkdir(); alias=self.h.root/'alias'; alias.symlink_to(actual,target_is_directory=True)
        opened=self.req(op='open',workspace='C',path=str(alias/'workspace'))
        self.assertTrue(opened['ok'])
        with sqlite3.connect(self.state/'state.sqlite') as db: self.assertEqual(str(actual/'workspace'),db.execute("select path from workspaces where id='C'").fetchone()[0])
        other=self.h.root/'other'; other.mkdir(); write(other,'workspace/sentinel.txt','must remain untouched\n'); before=manifest(other)
        alias.unlink(); alias.symlink_to(other,target_is_directory=True)
        write(self.paths['A'],'docs/public.txt','canonical target\n'); self.pub('A'); self.req(op='integrate')
        self.req(op='adopt',workspace='C',expected_generation=opened['generation'],target='latest')
        self.assertEqual('canonical target\n',(actual/'workspace/docs/public.txt').read_text()); self.assertEqual(before,manifest(other))
    def test_internal_symlink_checkpoint_fails_without_generation_change(self):
        target=self.h.root/'outside'; target.write_text('outside bytes\n'); (self.paths['A']/'link.txt').symlink_to(target)
        before=manifest(self.paths['A']); g=self.gen['A']
        r=self.req(op='checkpoint',workspace='A',expected_generation=g,ok=False)
        self.assertFalse(r['ok'])
        with sqlite3.connect(self.state/'state.sqlite') as db: self.assertEqual(g,db.execute("select generation from workspaces where id='A'").fetchone()[0])
        self.assertEqual(before,manifest(self.paths['A']))
if __name__=='__main__':
    RUN.mkdir(parents=True,exist_ok=True)
    def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
    env={'platform':platform.platform(),'python':sys.version,'argv':sys.argv,'binary':str(Path(ARGS.binary).resolve()),'binary_sha256':sha(Path(ARGS.binary)),'source_sha256':{str(p):sha(p) for p in sorted(Path('src').glob('*.rs'))},'test_sha256':sha(Path(__file__)),'git':subprocess.check_output(['git','--version'],text=True).strip(),'scope':'Linux local scripted CLI and deterministic persisted state fixtures; no process termination campaign, real clients, network or power-loss validation'}
    (RUN/'environment.json').write_text(json.dumps(env,indent=2)+'\n')
    suite=unittest.defaultTestLoader.loadTestsFromNames(REST,module=sys.modules[__name__]) if REST else unittest.defaultTestLoader.loadTestsFromTestCase(Gaps)
    result=unittest.TextTestRunner(verbosity=2).run(suite)
    (RUN/'summary.json').write_text(json.dumps({'tests':result.testsRun,'failures':[str(t) for t,_ in result.failures],'errors':[str(t) for t,_ in result.errors],'successful':result.wasSuccessful()},indent=2)+'\n')
    print(f'Evidence: {RUN}'); sys.exit(not result.wasSuccessful())
