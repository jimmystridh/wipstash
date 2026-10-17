#!/usr/bin/env python3
"""Independent artifact-transport QA. Scripted clients, real bytes/delays, no sockets."""
import argparse, copy, hashlib, json, os, platform, random, shutil, sqlite3, struct, subprocess, sys, time, unittest
from pathlib import Path
from harness_support import Harness, manifest, write, canaries
P=argparse.ArgumentParser(); P.add_argument('--binary',default='target/debug/wipstash'); P.add_argument('--artifacts',default='evidence/source-sync/runs'); P.add_argument('--seed',type=int,default=731927); P.add_argument('--delay-scale',type=float,default=1.0); ARGS,REST=P.parse_known_args()
RUN=Path(ARGS.artifacts).resolve()/time.strftime('%Y%m%dT%H%M%S')
HEAD='refs/wipstash/integration'
def sha(p): return hashlib.sha256(Path(p).read_bytes()).hexdigest()
class SourceSync(unittest.TestCase):
    def setUp(self):
        self.h=Harness(ARGS.binary,RUN/self._testMethodName); self.n=0; self.transport=[]; self.saved={}; self.rng=random.Random(ARGS.seed)
        self.states={a:self.h.root/('state-'+a) for a in ['hub',*'ABCD']}; self.paths={a:self.h.root/('workspace-'+a) for a in 'ABCD'}; self.gen={}
        source=self.h.fixture(self.h.root/'source'); write(source,'exact.bin',bytes(range(256))+b'\r\n\x00end\n'); self.source_manifest=manifest(source)
        self.req('hub',op='init',source=str(source))
        for a in self.states:
            self.req(a,op='sync_configure',project='qa-source',authority='hub',epoch=1,device=a,role='authority' if a=='hub' else 'client',peers=list('ABCD') if a=='hub' else ['hub'])
        self.bootstrap=self.export('hub','head')
        for a in 'ABCD':
            self.deliver(self.bootstrap,a); opened=self.req(a,op='open',workspace=a,path=str(self.paths[a])); self.gen[a]=opened['generation']; self.assertEqual(self.source_manifest,manifest(self.paths[a])); canaries(self.paths[a],a)
    def test_duplicate_head_repairs_cache_from_journal(self):
        # Durable import records must not short-circuit repair of a lost cache ref.
        before=self.req('A',op='sync_status')['cursor']
        self.h.git(self.repo('A'),'update-ref','-d',HEAD)
        self.assertNotIn(HEAD,self.refs('A'))
        result=self.deliver(self.bootstrap,'A')
        self.assertTrue(result['duplicate'])
        self.assertEqual(before,result['sequence'])
        self.assertEqual(self.req('hub',op='sync_status')['head'],self.req('A',op='sync_status')['head'])
        self.audit('A')

    def tearDown(self):
        self.h.save_log(); (self.h.root/'transport.json').write_text(json.dumps(self.transport,indent=2)+'\n')
    def req(self,a,ok=True,**r):
        self.n+=1
        if r['op'] not in ('status','sync_status','sync_export_history','sync_import','proposal_status','operation_status','updates'):r.setdefault('operation_id',f'{a}-{self.n}')
        result=self.h.call('--state',self.states[a],json.dumps(r),ok=ok)
        if ok:self.assertTrue(result['ok'],result)
        return result
    def cp(self,a):
        c=self.req(a,op='checkpoint',workspace=a,expected_generation=self.gen[a]); self.gen[a]=c['generation']; self.saved[(a,c['checkpoint'])]=manifest(self.paths[a],exclude=('.env','local','build','.agent')); return c
    def pub(self,a):
        p=self.req(a,op='publish',workspace=a,checkpoint=self.cp(a)['checkpoint'],intent='intentional synthetic source publication'); self.assertEqual('queued_offline',p['state']); return p
    def export(self,a,kind,proposal=None):
        dest=self.h.root/f'outbox-{a}-{self.n}'; r=dict(op='sync_export',kind=kind,destination=str(dest))
        if proposal:r['proposal']=proposal
        self.req(a,**r); self.assertTrue((dest/'manifest.json').is_file()); self.assertTrue((dest/'objects.json').is_file()); return dest
    def deliver(self,artifact,a,*,drop=False,ok=True):
        delay=self.rng.uniform(.015,.045)*ARGS.delay_scale; start=time.monotonic(); time.sleep(delay)
        e={'source':str(artifact),'recipient':a,'planned_delay':delay,'elapsed_delay':time.monotonic()-start,'dropped':drop}; self.transport.append(e)
        self.assertGreaterEqual(e['elapsed_delay'],delay)
        if drop:return None
        dest=self.h.root/f'inbox-{a}-{len(self.transport)}'; shutil.copytree(artifact,dest)
        self.assertEqual(manifest(artifact),manifest(dest)); result=self.req(a,op='sync_import',source=str(dest),confirm_trusted_source=True,ok=ok); e['result']=result; return result
    def repo(self,a):return self.states[a]/'coordinator.git'
    def refs(self,a):return self.h.git(self.repo(a),'show-ref')
    def db(self,a,query):
        with sqlite3.connect(self.states[a]/'state.sqlite') as db:return db.execute(query).fetchall()
    def audit(self,a,private=()):
        repo=self.repo(a); self.h.git(repo,'fsck','--full','--strict'); refs=self.refs(a); objects=self.h.git(repo,'cat-file','--batch-all-objects','--batch-check=%(objectname) %(objecttype)'); reachable=self.h.git(repo,'rev-list','--objects','--all')
        with sqlite3.connect(self.states[a]/'state.sqlite') as db:
            self.assertEqual([('ok',)],db.execute('pragma integrity_check').fetchall()); tables={r[0]:db.execute('select count(*) from "'+r[0]+'"').fetchone()[0] for r in db.execute("select name from sqlite_master where type='table'")}
        for oid in private:self.assertNotIn(oid,objects)
        public_tree={}
        head=self.h.git(repo,'rev-parse',HEAD)
        for line in self.h.git(repo,'ls-tree','-r',head).splitlines():
            meta,path=line.split('\t',1); mode,kind,oid=meta.split(); self.assertEqual('blob',kind)
            blob=subprocess.run(['git','--git-dir',str(repo),'cat-file','blob',oid],capture_output=True,check=True).stdout
            self.assertNotIn(b'NOT_A_REAL_SECRET_',blob); self.assertNotIn(b'private synthetic',blob)
            public_tree[path]={'sha256':hashlib.sha256(blob).hexdigest(),'mode':0o755 if mode=='100755' else 0o644}
        for old,new,proposal in self.db(a,"select old,new,proposal from promotions where state='committed'"):
            commit=self.db(a,"select commit_oid from proposals where id='"+proposal+"'")[0][0]
            self.assertEqual([old,commit],self.h.git(repo,'rev-list','--parents','-n','1',new).split()[1:])
            self.assertEqual(self.h.git(repo,'merge-tree','--write-tree',old,commit).splitlines()[0],self.h.git(repo,'rev-parse',new+'^{tree}'))
        if a in self.paths:
            local=self.states[a]/'locals'/a/'objects.git'; self.h.git(local,'fsck','--full','--strict'); retained=set(self.h.git(local,'rev-list','--all').splitlines())
            for checkpoint,commit,tree in self.db(a,'select id,commit_oid,tree from checkpoints'):
                self.assertIn(commit,retained); self.assertEqual(tree,self.h.git(local,'rev-parse',commit+'^{tree}')); actual={}
                for line in self.h.git(local,'ls-tree','-r',commit).splitlines():
                    meta,path=line.split('\t',1); mode,kind,oid=meta.split(); self.assertEqual('blob',kind)
                    body=subprocess.run(['git','--git-dir',str(local),'cat-file','blob',oid],capture_output=True,check=True).stdout
                    actual[path]={'sha256':hashlib.sha256(body).hexdigest(),'mode':0o755 if mode=='100755' else 0o644}
                self.assertEqual(self.saved[(a,checkpoint)],actual)
        alternates=repo/'objects/info/alternates'; self.assertFalse(alternates.exists())
        (self.h.root/f'audit-{a}.json').write_text(json.dumps({'refs':refs,'all_objects':objects,'reachable':reachable,'tables':tables,'public_tree':public_tree,'workspace_manifest':manifest(self.paths[a]) if a in self.paths else None},indent=2)+'\n'); return public_tree
    def test_four_clients_private_wip_publish_conflict_and_adopt(self):
        write(self.paths['A'],'private-broken.py','def broken(\nPRIVATE_ONLY_A_731927\n'); private=self.cp('A'); local=self.states['A']/'locals/A/objects.git'
        private_commit=self.db('A',"select commit_oid from checkpoints order by rowid desc limit 1")[0][0]; private_blob=self.h.git(local,'rev-parse',private_commit+':private-broken.py'); (self.paths['A']/'private-broken.py').unlink()
        proposals={}; artifacts={}; payloads={a:self.rng.randbytes(128)+bytes(range(255,-1,-1))+a.encode() for a in 'CD'}
        for a in 'ABCD':
            write(self.paths[a],'notes/shared.txt',f'{a} incompatible\n') if a in 'AB' else write(self.paths[a],f'docs/{a}.bin',payloads[a])
            proposals[a]=self.pub(a); artifacts[a]=self.export(a,'proposal',proposals[a]['proposal'])
        frozen={a:manifest(self.paths[a]) for a in 'ABCD'}; heads=[]
        disjoint=list('CD'); self.rng.shuffle(disjoint)
        for a in ['A',*disjoint,'B']:
            before=self.req('hub',op='status')['head']; accepted=self.deliver(artifacts[a],'hub'); self.deliver(artifacts[a],'hub') # lost response and retry
            accepted_receipt=self.export('hub','receipt',accepted['proposal'])
            self.req('hub',op='integrate'); status=self.req('hub',op='proposal_status',proposal=accepted['proposal'])
            if a=='B':self.assertEqual('quarantined',status['state']); self.assertEqual(before,self.req('hub',op='status')['head'])
            else:self.assertEqual('integrated',status['state'])
            terminal_receipt=self.export('hub','receipt',accepted['proposal']); generation=self.req(a,op='status',workspace=a)['generation']; self.deliver(terminal_receipt,a); self.deliver(terminal_receipt,a)
            self.assertFalse(self.deliver(accepted_receipt,a,ok=False)['ok']); observed=self.req(a,op='proposal_status',proposal=proposals[a]['proposal']); self.assertEqual(status['state'],observed['state']); self.assertEqual('local_queued',observed['local_state']); self.assertEqual(generation,self.req(a,op='status',workspace=a)['generation']); self.assertEqual(frozen[a],manifest(self.paths[a]))
            heads.append(self.export('hub','head'))
        final=self.req('hub',op='status')['head']; self.assertEqual(4,self.db('hub','select count(*) from proposals')[0][0]); public_tree=self.audit('hub',(private_commit,private_blob))
        expected=copy.deepcopy(self.source_manifest); expected['notes/shared.txt']={'sha256':hashlib.sha256(b'A incompatible\n').hexdigest(),'mode':0o644}
        for a in 'CD':expected[f'docs/{a}.bin']={'sha256':hashlib.sha256(payloads[a]).hexdigest(),'mode':0o644}
        self.assertEqual(expected,public_tree)
        for a in 'ABCD':
            for artifact in heads:self.deliver(artifact,a)
            self.req(a,op='updates',workspace=a); status=self.req(a,op='status',workspace=a); self.assertFalse(status['coordinator_online']); self.assertEqual(frozen[a],manifest(self.paths[a])); self.assertNotEqual(final,status['adopted'])
            adopted=self.req(a,op='adopt',workspace=a,target='latest',expected_generation=self.gen[a],ok=a!='B')
            if a=='B':self.assertEqual('adoption_conflict',adopted['error']['code']); self.assertEqual(frozen[a],manifest(self.paths[a]))
            else:
                self.assertEqual(b'A incompatible\n',(self.paths[a]/'notes/shared.txt').read_bytes())
                for owner in 'CD':self.assertEqual(payloads[owner],(self.paths[a]/f'docs/{owner}.bin').read_bytes())
                self.assertEqual(bytes(range(256))+b'\r\n\x00end\n',(self.paths[a]/'exact.bin').read_bytes())
                for name in ('.env','local/keep.bin','build/cache.bin','.agent/session.txt'):self.assertEqual(frozen[a][name],manifest(self.paths[a])[name])
            self.audit(a,(private_commit,private_blob))
        self.assertEqual(private_blob,self.h.git(local,'rev-parse',private_commit+':private-broken.py'))
    def test_drop_reorder_duplicate_restart_and_offline_reconnect(self):
        before=manifest(self.paths['D']); first=self.h.root/'retry-export'
        request=dict(op='sync_export',kind='head',destination=str(first),operation_id='lost-export-response')
        original=self.req('hub',**request); bytes_before=manifest(first); self.assertEqual(original,self.req('hub',**request)); self.assertEqual(bytes_before,manifest(first))
        second=self.export('hub','head')
        self.deliver(first,'D',drop=True); rejected=self.deliver(second,'D',ok=False); self.assertFalse(rejected['ok']); self.assertEqual(before,manifest(self.paths['D']))
        self.deliver(first,'D'); self.deliver(first,'D'); self.deliver(second,'D'); self.deliver(second,'D')
        # Every invocation reopens Git/SQLite in a fresh process, including replay after reopen.
        self.req('D',op='sync_status'); self.assertEqual(before,manifest(self.paths['D'])); self.assertFalse(self.req('D',op='integrate',ok=False)['ok'])
        write(self.paths['D'],'offline.txt','offline survives reconnect\n'); p=self.pub('D'); artifact=self.export('D','proposal',p['proposal']); self.deliver(artifact,'hub',drop=True)
        self.assertEqual(0,self.db('hub','select count(*) from proposals')[0][0]); self.deliver(artifact,'hub'); self.deliver(artifact,'hub'); self.req('hub',op='integrate'); final=self.export('hub','head'); frozen=manifest(self.paths['D']); self.deliver(final,'D'); latest=self.req('D',op='status')['head']; self.deliver(self.bootstrap,'D'); self.assertEqual(latest,self.req('D',op='status')['head']); self.assertEqual(frozen,manifest(self.paths['D']))
        prior=json.loads((self.bootstrap/'manifest.json').read_text())['head']; self.h.git(self.repo('D'),'update-ref',HEAD,prior,latest)
        self.assertEqual(latest,self.req('D',op='status')['head']); self.assertEqual(frozen,manifest(self.paths['D']))
        # A late-joining empty client catches up from retained export history after originals are offline.
        self.states['E']=self.h.root/'state-E'; self.req('E',op='sync_configure',project='qa-source',authority='hub',epoch=1,device='E',role='client',peers=['hub'])
        history=self.req('hub',op='sync_export_history')['exports']; self.assertEqual([1,2,3,4],[e['sequence'] for e in history])
        originals={json.loads((x/'manifest.json').read_text())['operation']:manifest(x) for x in (self.bootstrap,first,second,final)}
        for item in history:
            rebuilt=self.h.root/('reexport-'+item['operation_id']); self.req('hub',op='sync_reexport',operation_id=item['operation_id'],destination=str(rebuilt)); self.assertEqual(originals[item['operation_id']],manifest(rebuilt)); self.deliver(rebuilt,'E')
        self.assertEqual(history,self.req('hub',op='sync_export_history')['exports']); self.assertEqual(latest,self.req('E',op='status')['head']); self.audit('E')
        self.req('D',op='adopt',workspace='D',target='latest',expected_generation=self.gen['D']); self.assertEqual('offline survives reconnect\n',(self.paths['D']/'offline.txt').read_text()); self.audit('D')
    def test_receipt_identity_privacy_monotonicity_and_cancel_guard(self):
        write(self.paths['A'],'public-receipt.txt','explicitly published\n'); p=self.pub('A'); artifact=self.export('A','proposal',p['proposal']); frozen=manifest(self.paths['A']); generation=self.gen['A']; refs=self.refs('A')
        cancel=self.req('A',op='cancel',proposal=p['proposal'],ok=False); self.assertFalse(cancel['ok']); self.assertEqual('remote_cancel_unsupported',cancel['error']['code'])
        accepted=self.deliver(artifact,'hub'); receipt=self.export('hub','receipt',accepted['proposal']); m=json.loads((receipt/'manifest.json').read_text())
        self.assertEqual(b'',(receipt/'objects.json').read_bytes()); self.assertEqual({'recipient','authority_proposal','revision','state','integration_head','evidence','repaired'},set(m['receipt'])); self.assertIsNone(m['intent']); self.assertIsNone(m['envelope'])
        self.assertFalse(self.deliver(receipt,'B',ok=False)['ok'])
        mutations={'recipient':lambda m:m['receipt'].update(recipient='B'),'commit':lambda m:m.update(head='1'*40),'proposal':lambda m:m.update(proposal='unknown-proposal'),'private-field':lambda m:m['receipt'].update(private_detail='must never transmit'),'authority-proposal':lambda m:m['receipt'].update(authority_proposal='unknown-authority-proposal')}
        for name,mutate in mutations.items():
            bad=self.h.root/('bad-receipt-'+name); shutil.copytree(receipt,bad); badm=copy.deepcopy(m); mutate(badm); (bad/'manifest.json').write_text(json.dumps(badm)); self.assertFalse(self.deliver(bad,'A',ok=False)['ok'],name)
            self.assertEqual(refs,self.refs('A')); self.assertEqual(frozen,manifest(self.paths['A'])); self.assertEqual(generation,self.req('A',op='status',workspace='A')['generation'])
        self.deliver(receipt,'A'); self.assertEqual('coordinator_accepted',self.req('A',op='proposal_status',proposal=p['proposal'])['state'])
        self.req('hub',op='integrate'); terminal=self.export('hub','receipt',accepted['proposal']); self.deliver(terminal,'A'); self.assertEqual('integrated',self.req('A',op='proposal_status',proposal=p['proposal'])['state']); self.deliver(terminal,'A')
        changed=self.h.root/'terminal-reversal'; shutil.copytree(terminal,changed); reverse=json.loads((changed/'manifest.json').read_text()); reverse['receipt'].update(state='coordinator_accepted',revision=reverse['receipt']['revision']+1); (changed/'manifest.json').write_text(json.dumps(reverse)); self.assertFalse(self.deliver(changed,'A',ok=False)['ok'])
        self.assertEqual('integrated',self.req('A',op='proposal_status',proposal=p['proposal'])['state']); self.assertEqual(refs,self.refs('A')); self.assertEqual(frozen,manifest(self.paths['A'])); self.assertEqual(generation,self.req('A',op='status',workspace='A')['generation'])
    def test_oversized_source_artifact_fails_without_losing_local_work(self):
        write(self.paths['A'],'large-public.bin',b'Q'*(8*1024*1024+1)); p=self.pub('A'); frozen=manifest(self.paths['A']); refs=self.refs('hub')
        dest=self.h.root/'oversized-export'; result=self.req('A',op='sync_export',kind='proposal',proposal=p['proposal'],destination=str(dest),ok=False)
        self.assertFalse(result['ok']); self.assertEqual(frozen,manifest(self.paths['A'])); self.assertEqual(refs,self.refs('hub')); self.assertEqual(0,self.db('hub','select count(*) from proposals')[0][0]); self.assertFalse((dest/'manifest.json').exists())
        self.assertEqual('local_queued',self.req('A',op='proposal_status',proposal=p['proposal'])['state'])
    def test_private_ancestry_rejected_before_public_object_install(self):
        write(self.paths['A'],'private-broken.py','def broken(\nPRIVATE_ANCESTRY_ONLY\n'); self.cp('A')
        private=self.db('A',"select commit_oid from checkpoints order by rowid desc limit 1")[0][0]
        p=self.pub('A'); artifact=self.export('A','proposal',p['proposal']); bad=self.h.root/'private-ancestry'; shutil.copytree(artifact,bad)
        repo=self.states['A']/'locals/A/objects.git'
        # Independent binary container encoder: bypass exporter to send an actual private commit closure.
        def raw(*args):
            r=subprocess.run(['git','--git-dir',str(repo),*args],capture_output=True,check=True); return r.stdout
        ids=sorted({line.split()[0] for line in raw('rev-list','--objects',private).decode().splitlines()})
        payload=b'WIPSTASH-SOURCE-1\0'+struct.pack('>I',1)+private.encode()+struct.pack('>I',len(ids))
        for oid in ids:
            kind=raw('cat-file','-t',oid).strip(); body=raw('cat-file',kind.decode(),oid)
            payload+=oid.encode()+bytes([{b'commit':1,b'tree':2,b'blob':3}[kind]])+struct.pack('>I',len(body))+body
        (bad/'objects.json').write_bytes(payload); m=json.loads((bad/'manifest.json').read_text()); m.update(head=private,payload_len=len(payload),payload_sha256=hashlib.sha256(payload).hexdigest()); (bad/'manifest.json').write_text(json.dumps(m))
        before=self.h.git(self.repo('hub'),'cat-file','--batch-all-objects','--batch-check=%(objectname)'); refs=self.refs('hub')
        rejected=self.deliver(bad,'hub',ok=False); self.assertFalse(rejected['ok']); self.assertEqual(refs,self.refs('hub')); self.assertEqual(before,self.h.git(self.repo('hub'),'cat-file','--batch-all-objects','--batch-check=%(objectname)')); self.assertEqual(0,self.db('hub','select count(*) from proposals')[0][0])
        self.audit('hub',(private,))
    def test_malformed_untrusted_and_authority_mismatch_are_atomic(self):
        artifact=self.export('hub','head'); before=self.refs('A'); frozen=manifest(self.paths['A'])
        variants={'authority':lambda m:m.update(authority='impostor'),'project':lambda m:m.update(project='wrong-project'),'epoch':lambda m:m.update(epoch=2),'unknown':lambda m:m.update(extra='reject'),'checksum':lambda m:m.update(payload_sha256='0'*64)}
        for name,mutate in variants.items():
            bad=self.h.root/('bad-'+name); shutil.copytree(artifact,bad); m=json.loads((bad/'manifest.json').read_text()); mutate(m); (bad/'manifest.json').write_text(json.dumps(m))
            self.assertFalse(self.deliver(bad,'A',ok=False)['ok'],name); self.assertEqual(before,self.refs('A')); self.assertEqual(frozen,manifest(self.paths['A']))
        self.assertFalse(self.req('A',op='sync_import',source=str(artifact),ok=False)['ok']); self.assertFalse(self.req('A',op='sync_import',source=str(artifact),confirm_trusted_source=False,ok=False)['ok']); self.assertEqual(before,self.refs('A'))
        bad=self.h.root/'bad-json'; shutil.copytree(artifact,bad); (bad/'objects.json').write_text('{truncated'); self.assertFalse(self.deliver(bad,'A',ok=False)['ok']); self.assertEqual(before,self.refs('A'))
        self.deliver(artifact,'A'); self.audit('A')
if __name__=='__main__':
    RUN.mkdir(parents=True,exist_ok=True)
    (RUN/'environment.json').write_text(json.dumps({'platform':platform.platform(),'python':sys.version,'argv':sys.argv,'seed':ARGS.seed,'binary_sha256':sha(ARGS.binary),'source_sha256':{str(p):sha(p) for p in sorted(Path('src').glob('*.rs'))},'test_sha256':sha(__file__),'scope':'Four isolated scripted CLI clients and one authority, copied artifacts with real elapsed delays; no sockets, process-kill, distributed authentication or real-user session claim.'},indent=2)+'\n')
    suite=unittest.defaultTestLoader.loadTestsFromNames(REST,module=sys.modules[__name__]) if REST else unittest.defaultTestLoader.loadTestsFromTestCase(SourceSync)
    result=unittest.TextTestRunner(verbosity=2).run(suite)
    (RUN/'summary.json').write_text(json.dumps({'tests':result.testsRun,'failures':[(str(t),s) for t,s in result.failures],'errors':[(str(t),s) for t,s in result.errors],'successful':result.wasSuccessful()},indent=2)+'\n'); print(f'Evidence: {RUN}'); sys.exit(not result.wasSuccessful())
