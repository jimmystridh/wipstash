#!/usr/bin/env python3
"""Independent trust-boundary regressions; local disposable files only."""
import hashlib, json, os, pathlib, shutil, sqlite3, subprocess, tempfile, unittest
ROOT=pathlib.Path(__file__).resolve().parents[2]
BINARY=pathlib.Path(os.environ.get('WIPSTASH_BINARY', ROOT/'target/debug/wipstash')).resolve()
class Review(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(prefix='wipstash-review-')
        self.root=pathlib.Path(self.tmp.name)
        self.a=self.root/'authority'; self.c=self.root/'client'
        source=self.root/'source'; source.mkdir(); (source/'a.txt').write_text('public\n')
        self.good(self.a,op='init',source=str(source))
        self.cfg=dict(project='project',authority='authority',epoch=1)
        self.good(self.a,op='sync_configure',**self.cfg,device='authority',role='authority',peers=['client'],operation_id='configure-a')
        self.good(self.c,op='sync_configure',**self.cfg,device='client',role='client',peers=['authority'],operation_id='configure-c')
    def tearDown(self): self.tmp.cleanup()
    def req(self,state,**body):
        p=subprocess.run([str(BINARY),'--state',str(state),json.dumps(body)],capture_output=True,text=True,timeout=30)
        try: return json.loads(p.stdout)
        except Exception: self.fail(f'Invalid response {p.returncode}: {p.stdout} {p.stderr}')
    def good(self,state,**body):
        r=self.req(state,**body); self.assertTrue(r.get('ok'),(body,r)); return r
    def bad(self,state,**body):
        r=self.req(state,**body); self.assertFalse(r.get('ok'),(body,r)); return r
    def test_client_role_cannot_change_or_initialize(self):
        self.bad(self.c,op='sync_configure',**self.cfg,device='client',role='authority',peers=['authority'],operation_id='switch')
        self.bad(self.c,op='sync_configure',project='project',authority='authority',epoch=2,device='client',role='client',peers=['authority'],operation_id='epoch')
        self.bad(self.c,op='init',source=str(self.root/'source'))
        self.bad(self.c,op='integrate')
        self.bad(self.c,op='configure',policy={'checks':[]},operation_id='policy')
        self.bad(self.c,op='retry_proposal',proposal='missing',operation_id='retry')
        self.bad(self.c,op='backup_tick')
        self.bad(self.c,op='restore',destination=str(self.a/'coordinator.git'))
    def test_export_cannot_modify_live_workspace(self):
        workspace=self.root/'workspace'
        self.good(self.a,op='open',workspace='w',path=str(workspace),operation_id='open')
        before=sorted(str(p.relative_to(workspace)) for p in workspace.rglob('*'))
        self.bad(self.a,op='sync_export',kind='head',destination=str(workspace/'artifact'),operation_id='export-overlap')
        self.assertEqual(before, sorted(str(p.relative_to(workspace)) for p in workspace.rglob('*')))
    def test_client_requires_pristine_repository(self):
        state=self.root/'orphan'; state.mkdir()
        subprocess.run(['git','init','--bare','--template=',str(state/'coordinator.git')],check=True,capture_output=True)
        self.bad(state,op='sync_configure',**self.cfg,device='client',role='client',peers=['authority'],operation_id='orphan')
    def test_rejected_divergent_head_does_not_install_roots(self):
        artifact=self.root/'head1'
        self.good(self.a,op='sync_export',kind='head',destination=str(artifact),operation_id='head1')
        self.good(self.c,op='sync_import',source=str(artifact),confirm_trusted_source=True)
        other=self.root/'other'; source=self.root/'other-source'; source.mkdir()
        (source/'a.txt').write_text('divergent public source\n')
        self.good(other,op='init',source=str(source))
        self.good(other,op='sync_configure',**self.cfg,device='authority',role='authority',peers=['client'],operation_id='configure-other')
        divergent=self.root/'divergent'
        self.good(other,op='sync_export',kind='head',destination=str(divergent),operation_id='head2')
        manifest=json.loads((divergent/'manifest.json').read_text())
        manifest['envelope']['sequence']=2
        (divergent/'manifest.json').write_text(json.dumps(manifest))
        def refs():
            return subprocess.check_output(['git','--git-dir',str(self.c/'coordinator.git'),'show-ref'])
        before=refs()
        self.bad(self.c,op='sync_import',source=str(divergent),confirm_trusted_source=True)
        self.assertEqual(before,refs(),'Rejected divergent head installed a persistent public root')
        with sqlite3.connect(self.c/'sync-replay.sqlite') as db:
            self.assertEqual(1,db.execute('SELECT cursor FROM replication_binding').fetchone()[0])
    def refs(self,state):
        return subprocess.check_output(['git','--git-dir',str(state/'coordinator.git'),'show-ref'])
    def bootstrap(self):
        artifact=self.root/'bootstrap'
        self.good(self.a,op='sync_export',kind='head',destination=str(artifact),operation_id='head1')
        self.good(self.c,op='sync_import',source=str(artifact),confirm_trusted_source=True)
    def proposal(self,state,name='w'):
        path=self.root/(name+'-worktree')
        self.good(state,op='open',workspace=name,path=str(path),operation_id='open-'+name)
        (path/'a.txt').write_text('published new source\n')
        self.good(state,op='checkpoint',workspace=name,expected_generation=0,operation_id='save-'+name)
        return self.good(state,op='publish',workspace=name,checkpoint='save-'+name,intent='review fixture',operation_id='publish-'+name)
    def test_rejected_sequence_gap_does_not_install_roots(self):
        self.bootstrap(); self.proposal(self.a)
        self.good(self.a,op='integrate')
        artifact=self.root/'head2'
        self.good(self.a,op='sync_export',kind='head',destination=str(artifact),operation_id='head2')
        manifest=json.loads((artifact/'manifest.json').read_text()); manifest['envelope']['sequence']=3
        (artifact/'manifest.json').write_text(json.dumps(manifest))
        before=self.refs(self.c)
        self.bad(self.c,op='sync_import',source=str(artifact),confirm_trusted_source=True)
        self.assertEqual(before,self.refs(self.c),'Rejected sequence gap installed a public root')
        with sqlite3.connect(self.c/'sync-replay.sqlite') as db:
            self.assertEqual(1,db.execute('SELECT cursor FROM replication_binding').fetchone()[0])
    def test_rejected_proposal_identity_does_not_install_roots(self):
        self.bootstrap(); proposal=self.proposal(self.c)
        artifact=self.root/'proposal'
        self.good(self.c,op='sync_export',kind='proposal',proposal=proposal['proposal'],destination=str(artifact),operation_id='proposal-export')
        manifest=json.loads((artifact/'manifest.json').read_text()); manifest['proposal']='forged-id'
        (artifact/'manifest.json').write_text(json.dumps(manifest))
        before=self.refs(self.a)
        self.bad(self.a,op='sync_import',source=str(artifact),confirm_trusted_source=True)
        self.assertEqual(before,self.refs(self.a),'Rejected proposal identity installed a public root')
    def test_head_cannot_switch_first_parent_authority_history(self):
        self.bootstrap()
        original=subprocess.check_output(['git','--git-dir',str(self.a/'coordinator.git'),'rev-parse','refs/wipstash/integration'],text=True).strip()
        workspace=self.root/'authority-worktree'
        self.good(self.a,op='open',workspace='authority-w',path=str(workspace),operation_id='open-authority')
        (workspace/'a.txt').write_text('new independent first-parent tree\n')
        self.good(self.a,op='checkpoint',workspace='authority-w',expected_generation=0,operation_id='save-authority')
        proposal=self.good(self.a,op='publish',workspace='authority-w',checkpoint='save-authority',intent='fixture',operation_id='publish-authority')
        repo=str(self.a/'coordinator.git')
        tree=subprocess.check_output(['git','--git-dir',repo,'rev-parse',proposal['commit']+'^{tree}'],text=True).strip()
        env=dict(os.environ,GIT_AUTHOR_NAME='Fixture',GIT_AUTHOR_EMAIL='fixture@example.invalid',GIT_COMMITTER_NAME='Fixture',GIT_COMMITTER_EMAIL='fixture@example.invalid')
        unrelated=subprocess.check_output(['git','--git-dir',repo,'commit-tree',tree],input='Wipstash initial public import\n',text=True,env=env).strip()
        forged=subprocess.check_output(['git','--git-dir',repo,'commit-tree',tree,'-p',unrelated,'-p',original],input='Wipstash integration\noperation: integration-review\n',text=True,env=env).strip()
        subprocess.run(['git','--git-dir',repo,'update-ref','refs/wipstash/integration',forged],check=True)
        artifact=self.root/'switched-head'
        self.good(self.a,op='sync_export',kind='head',destination=str(artifact),operation_id='switched-head')
        before=self.refs(self.c)
        self.bad(self.c,op='sync_import',source=str(artifact),confirm_trusted_source=True)
        self.assertEqual(before,self.refs(self.c))
    def test_duplicate_proposal_keeps_terminal_state_and_event_count(self):
        self.bootstrap(); proposal=self.proposal(self.c)
        first=self.root/'proposal-first'; second=self.root/'proposal-second'
        self.good(self.c,op='sync_export',kind='proposal',proposal=proposal['proposal'],destination=str(first),operation_id='export-first')
        accepted=self.good(self.a,op='sync_import',source=str(first),confirm_trusted_source=True)
        self.good(self.a,op='cancel',proposal=accepted['proposal'],operation_id='cancel-remote')
        self.good(self.c,op='sync_export',kind='proposal',proposal=proposal['proposal'],destination=str(second),operation_id='export-second')
        duplicate=self.good(self.a,op='sync_import',source=str(second),confirm_trusted_source=True)
        self.assertEqual('cancelled',duplicate['state'])
        with sqlite3.connect(self.a/'state.sqlite') as db:
            self.assertEqual('cancelled',db.execute('SELECT state FROM proposals WHERE id=?',(accepted['proposal'],)).fetchone()[0])
            self.assertEqual(1,db.execute("SELECT count(*) FROM events WHERE kind='remote_proposal_accepted'").fetchone()[0])
    def receipt_fixture(self):
        self.bootstrap(); proposal=self.proposal(self.c)
        artifact=self.root/'proposal-for-receipt'
        self.good(self.c,op='sync_export',kind='proposal',proposal=proposal['proposal'],destination=str(artifact),operation_id='proposal-for-receipt')
        accepted=self.good(self.a,op='sync_import',source=str(artifact),confirm_trusted_source=True)
        receipt=self.root/'receipt'
        self.good(self.a,op='sync_export',kind='receipt',proposal=accepted['proposal'],destination=str(receipt),operation_id='receipt1')
        return proposal,accepted,receipt
    def mutate_receipt(self,receipt,name,edit):
        path=self.root/name; shutil.copytree(receipt,path)
        manifest=json.loads((path/'manifest.json').read_text()); edit(manifest)
        (path/'manifest.json').write_text(json.dumps(manifest)); return path
    def test_receipt_revision_conflict_and_operation_binding(self):
        proposal,accepted,receipt=self.receipt_fixture()
        self.good(self.c,op='sync_import',source=str(receipt),confirm_trusted_source=True)
        def change_operation(m): m['operation']='other-operation'
        same_revision=self.mutate_receipt(receipt,'same-revision',change_operation)
        self.bad(self.c,op='sync_import',source=str(same_revision),confirm_trusted_source=True)
        def change_state(m): m['receipt']['revision']=2; m['receipt']['state']='quarantined'
        reused_operation=self.mutate_receipt(receipt,'same-operation',change_state)
        self.bad(self.c,op='sync_import',source=str(reused_operation),confirm_trusted_source=True)
        status=self.good(self.c,op='proposal_status',proposal=proposal['proposal'])
        self.assertEqual('coordinator_accepted',status['state'])
        self.assertEqual(1,status['remote_observation']['revision'])
    def test_receipt_rejects_unexported_and_cancelled_proposals(self):
        proposal,accepted,receipt=self.receipt_fixture()
        unexported=self.proposal(self.c,'unexported')
        def rewrite(m):
            m['operation']='receipt-for-unexported'; m['proposal']=unexported['proposal']; m['head']=unexported['commit']; m['base']=unexported['base']
            bound=json.dumps({'device':'client','proposal':unexported['proposal']},sort_keys=True,separators=(',',':')).encode()
            m['receipt']['authority_proposal']='remote-'+hashlib.sha256(bound).hexdigest()
        forged=self.mutate_receipt(receipt,'receipt-unexported',rewrite)
        self.bad(self.c,op='sync_import',source=str(forged),confirm_trusted_source=True)
        self.good(self.c,op='cancel',proposal=unexported['proposal'],operation_id='cancel-unexported')
        self.bad(self.c,op='sync_import',source=str(forged),confirm_trusted_source=True)
        status=self.good(self.c,op='proposal_status',proposal=unexported['proposal'])
        self.assertEqual('cancelled',status['state']); self.assertNotIn('remote_observation',status)
    def test_failed_export_reservation_cannot_be_locally_recalled(self):
        self.bootstrap(); proposal=self.proposal(self.c)
        occupied=self.root/'occupied'; occupied.mkdir(); (occupied/'unrelated').write_text('occupied')
        self.bad(self.c,op='sync_export',kind='proposal',proposal=proposal['proposal'],destination=str(occupied),operation_id='reserved-export')
        self.bad(self.c,op='cancel',proposal=proposal['proposal'],operation_id='cancel-reserved')
        repaired=self.root/'reconstructed-export'
        self.good(self.c,op='sync_reexport',destination=str(repaired),operation_id='reserved-export')
        accepted=self.good(self.a,op='sync_import',source=str(repaired),confirm_trusted_source=True)
        self.assertEqual('coordinator_accepted',accepted['state'])
    def test_bootstrap_never_adopts_or_claims_live_connection(self):
        artifact=self.root/'artifact'
        self.good(self.a,op='sync_export',kind='head',destination=str(artifact),operation_id='head1')
        self.good(self.c,op='sync_import',source=str(artifact),confirm_trusted_source=True)
        workspace=self.root/'client-workspace'
        self.good(self.c,op='open',workspace='w',path=str(workspace),operation_id='open')
        (workspace/'a.txt').write_text('private dirty\n')
        before=(workspace/'a.txt').read_bytes()
        self.good(self.c,op='sync_import',source=str(artifact),confirm_trusted_source=True)
        status=self.good(self.c,op='status',workspace='w')
        updates=self.good(self.c,op='updates',workspace='w')
        self.assertFalse(status.get('coordinator_online'),status)
        self.assertFalse(updates.get('coordinator_online'),updates)
        self.assertEqual(before,(workspace/'a.txt').read_bytes())
if __name__=='__main__': unittest.main(verbosity=2)
