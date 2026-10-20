#!/usr/bin/env python3
"""Four isolated CLI clients exercise agent feedback regressions through real Git/SQLite."""
import concurrent.futures
import hashlib
import time
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'examples/clients'))
from wipstash_client import WipstashClient
METRICS=[]
BINARY = str(Path(os.environ.get('WIPSTASH_ENGINE', 'target/debug/wipstash.exe' if os.name == 'nt' else 'target/debug/wipstash')).resolve())

class Experience(unittest.TestCase):
    def setUp(self):
        self.started=time.monotonic()
        self.temp=tempfile.TemporaryDirectory(prefix='wipstash-experience-')
        self.root=Path(self.temp.name).resolve();self.state=self.root/'state';self.source=self.root/'source';self.source.mkdir()
        (self.source/'file.txt').write_text('initial\n');(self.source/'other.txt').write_text('other\n')
        self.cli(op='init',source=str(self.source))
        self.clients={};self.paths={}
        for name in ('codex','claude','opencode','pi'):
            self.clients[name]=WipstashClient([BINARY,'--state',str(self.state)],self.root/('journal-'+name),timeout=90)
            self.paths[name]=self.root/name
            self.mutate(name,op='clone',workspace=name,path=str(self.paths[name]),operation_id='clone-'+name)
        self.addCleanup(self.cleanup)
    def cleanup(self):
        db=sqlite3.connect(self.state/'state.sqlite')
        try:
            rows=list(db.execute("SELECT request,result FROM operations"))
            requests=[json.loads(r[0]) for r in rows]
            outcomes=[json.loads(r[1]) for r in rows if r[1]]
            METRICS.append(dict(test=self.id(),seconds=round(time.monotonic()-self.started,3),comparison_clones=max(0,sum(r['op']=='open' for r in requests)-4),review_opens=sum(r['op']=='resolution_open' for r in requests),commit_attempts=sum(r['op']=='commit' for r in requests),overlap_warnings=sum(v.get('overlaps_total',0) for v in outcomes)))
        finally:db.close()
        for c in self.clients.values():c.close()
        self.temp.cleanup()
    def cli(self,**request):
        p=subprocess.run([BINARY,'--state',str(self.state),json.dumps(request)],capture_output=True,text=True)
        v=json.loads(p.stdout);self.assertTrue(v['ok'],v);return v
    def mutate(self,agent,**request):
        v=self.clients[agent].mutate(request);self.assertTrue(v['ok'],v);return v
    def status(self,agent):return self.clients[agent].read('status',workspace=agent,inspect_files=True)
    def commit(self,agent,identifier,**extra):
        return self.clients[agent].mutate(dict(op='commit',workspace=agent,message=identifier,expected_generation=self.status(agent)['generation'],operation_id=identifier,**extra))
    def shared(self,path):return subprocess.check_output(['git','--git-dir',str(self.state/'coordinator.git'),'show','refs/wipstash/integration:'+path],text=True)
    def review(self,agent,conflict,wid):
        return self.mutate(agent,op='resolution_open',workspace=agent,candidate=conflict['candidate'],resolution_workspace=wid,path=str(self.root/wid),operation_id='review-'+wid)
    def test_baseline_failure_is_saved_but_unshared_and_has_prepared_review(self):
        (self.paths['codex']/'README.md').write_text('incoming README\n')
        self.assertTrue(self.commit('codex','incoming-readme')['shared'])
        (self.paths['claude']/'other.txt').write_text('claude change\n')
        self.assertTrue(self.commit('claude','claude-first')['shared'])
        (self.paths['claude']/'README.md').write_text('my README\n')
        before=self.status('claude')['generation'];failed=self.commit('claude','readme-conflict')
        self.assertFalse(failed['ok'],failed);self.assertEqual(failed['error']['code'],'commit_baseline_conflict')
        self.assertTrue(failed['saved_locally']);self.assertFalse(failed['submitted']);self.assertFalse(failed['shared']);self.assertEqual(failed['generation_after'],before+1)
        self.assertIn('README.md',failed['conflict_paths']);self.assertEqual(failed['next_action']['op'],'resolution_open')
        status=self.status('claude');self.assertTrue(status['has_unshared_changes']);self.assertFalse(status['changes_since_save'])
        opened=self.review('claude',failed,'readme-review')
        self.assertEqual(set(opened['side_paths']),{'base','local','shared'})
        self.assertEqual((self.paths['claude']/'README.md').read_text(),'my README\n')
        (self.root/'readme-review/README.md').write_text('combined README\n')
        shared=self.mutate('claude',op='commit',workspace='readme-review',message='Reconcile README',expected_generation=0,expected_head=opened['resolution_head'],resolved_conflicts=opened['conflict_paths'],operation_id='readme-resolved')
        self.assertTrue(shared['shared']);self.assertEqual(self.shared('README.md'),'combined README\n')
        (self.root/'readme-review/next.txt').write_text('ordinary work\n')
        again=self.mutate('claude',op='commit',workspace='readme-review',message='Continue in review directory',expected_generation=1,operation_id='after-readme-review')
        self.assertTrue(again['shared'])
    def test_merge_review_applies_atomically_and_rejects_changed_original(self):
        (self.paths['codex']/'file.txt').write_text('shared\n');self.assertTrue(self.commit('codex','first')['shared'])
        (self.paths['claude']/'file.txt').write_text('local\n')
        failed=self.clients['claude'].mutate(dict(op='merge',workspace='claude',target='latest',expected_generation=0,operation_id='merge-overlap'))
        self.assertFalse(failed['ok']);self.assertEqual(failed['conflict_paths'],['file.txt'])
        opened=self.review('claude',failed,'merge-review')
        self.assertEqual(opened['completion'],'resolve_merge')
        marker=self.clients['claude'].mutate(dict(op='resolve_merge',workspace='claude',candidate=failed['candidate'],target=failed['target'],expected_generation=0,resolution_workspace='merge-review',resolved_conflicts=opened['conflict_paths'],operation_id='reject-markers'))
        self.assertFalse(marker['ok']);self.assertEqual((self.paths['claude']/'file.txt').read_text(),'local\n')
        (self.root/'merge-review/file.txt').write_text('combined\n')
        (self.paths['claude']/'new-local.txt').write_text('preserve\n')
        stale=self.clients['claude'].mutate(dict(op='resolve_merge',workspace='claude',candidate=failed['candidate'],target=failed['target'],expected_generation=0,resolution_workspace='merge-review',resolved_conflicts=opened['conflict_paths'],operation_id='reject-stale-review'))
        self.assertFalse(stale['ok']);self.assertEqual(stale['error']['code'],'stale_conflict')
        (self.paths['claude']/'new-local.txt').unlink()
        accepted=self.mutate('claude',op='resolve_merge',workspace='claude',candidate=failed['candidate'],target=failed['target'],expected_generation=0,resolution_workspace='merge-review',resolved_conflicts=opened['conflict_paths'],operation_id='accept-review')
        self.assertEqual(accepted['generation'],1);self.assertEqual((self.paths['claude']/'file.txt').read_text(),'combined\n')
        self.assertEqual(self.shared('file.txt'),'shared\n');self.assertTrue(self.commit('claude','share-combined')['shared'])
    def test_successful_blocked_commit_resolution_becomes_an_ordinary_workspace(self):
        (self.paths['codex']/'file.txt').write_text('first\n');self.commit('codex','first')
        (self.paths['pi']/'file.txt').write_text('second\n');blocked=self.commit('pi','second');self.assertFalse(blocked['shared'])
        opened=self.mutate('pi',op='resolution_open',workspace='pi',commit_id='second',resolution_workspace='fix',path=str(self.root/'fix'),operation_id='open-fix')
        self.assertEqual(set(opened['side_paths']),{'base','local','shared'})
        (self.root/'fix/file.txt').write_text('both\n')
        invalid=self.clients['pi'].mutate(dict(op='commit',workspace='fix',message='Missing review identity',expected_generation=0,operation_id='missing-head'))
        self.assertFalse(invalid['ok']);self.assertFalse(invalid['saved_locally']);self.assertEqual(invalid['generation'],0)
        result=self.mutate('pi',op='commit',workspace='fix',message='Resolve',expected_generation=0,expected_head=opened['resolution_head'],resolved_conflicts=opened['conflict_paths'],operation_id='fixed')
        self.assertTrue(result['shared']);(self.root/'fix/continue.txt').write_text('continue\n')
        continued=self.mutate('pi',op='commit',workspace='fix',message='Ordinary next increment',expected_generation=1,operation_id='continue')
        self.assertTrue(continued['shared']);self.assertEqual(self.shared('continue.txt'),'continue\n')
    def test_get_latest_summarizes_incoming_without_touching_files(self):
        original=(self.paths['opencode']/'file.txt').read_bytes()
        (self.paths['codex']/'file.txt').write_text('new\n');self.commit('codex','incoming')
        result=self.clients['opencode'].read('get_latest',workspace='opencode')
        self.assertFalse(result['files_changed']);self.assertTrue(result['incoming']['shared_changes_available'])
        self.assertEqual(result['incoming']['changes'][0]['path'],'file.txt');self.assertEqual(result['incoming']['commits'][0]['message'],'incoming')
        self.assertEqual((self.paths['opencode']/'file.txt').read_bytes(),original)
    def test_four_clients_claim_overlaps_renew_and_expire_without_locks(self):
        def claim(agent):return self.mutate(agent,op='task_claim',workspace=agent,task_id='policy-validation',title='Improve policy validation',acceptance_criteria='Allow nullable maximum and preserve error context',paths=['src/policy.py'],lease_seconds=300,operation_id='claim-'+agent)
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:claims=dict(zip(self.clients,pool.map(claim,self.clients)))
        self.assertEqual(sorted(c['overlaps_total'] for c in claims.values()),[0,1,2,3]);self.assertTrue(all(c['confirmed'] and not c['files_locked'] for c in claims.values()))
        self.assertEqual(claim('codex'),claims['codex'])
        wrong=self.clients['pi'].mutate(dict(op='task_update',workspace='pi',claim_id=claims['codex']['claim_id'],action='release',expected_revision=1,operation_id='wrong-owner'))
        self.assertFalse(wrong['ok']);self.assertEqual(wrong['error']['code'],'task_owner_mismatch')
        renewed=self.mutate('codex',op='task_update',workspace='codex',claim_id=claims['codex']['claim_id'],action='renew',expected_revision=1,operation_id='renew')
        self.assertEqual(renewed['revision'],2)
        stale=self.clients['codex'].mutate(dict(op='task_update',workspace='codex',claim_id=claims['codex']['claim_id'],action='complete',expected_revision=1,operation_id='old-revision'))
        self.assertFalse(stale['ok'])
        db=sqlite3.connect(self.state/'state.sqlite')
        try:
            db.execute('UPDATE task_claims SET expires=0 WHERE id=?',[claims['codex']['claim_id']]);db.commit()
        finally:db.close()
        self.assertEqual(len(self.clients['pi'].read('task_list')['claims']),3)
        expired=self.clients['codex'].mutate(dict(op='task_update',workspace='codex',claim_id=claims['codex']['claim_id'],action='renew',expected_revision=2,operation_id='expired'))
        self.assertEqual(expired['error']['code'],'task_lease_expired')
        for agent in self.clients:self.assertEqual((self.paths[agent]/'file.txt').read_text(),'initial\n')
    def test_archive_is_recoverable_and_refuses_pending_or_active_work(self):
        (self.paths['codex']/'unshared.txt').write_text('valuable\n')
        denied=self.clients['codex'].mutate(dict(op='workspace_close',workspace='codex',expected_generation=0,confirm_writers_stopped=True,operation_id='cannot-close'))
        self.assertEqual(denied['error']['code'],'workspace_has_unshared_work');self.assertTrue((self.paths['codex']/'unshared.txt').exists())
        closed=self.mutate('pi',op='workspace_close',workspace='pi',expected_generation=0,confirm_writers_stopped=True,operation_id='close-pi')
        self.assertTrue(closed['recoverable']);self.assertFalse(closed['files_deleted'])
        rejected=self.commit('pi','closed-commit');self.assertEqual(rejected['error']['code'],'workspace_closed')
        self.mutate('pi',op='workspace_reopen',workspace='pi',expected_generation=0,operation_id='reopen-pi')
        inventory=self.clients['pi'].read('workspace_inventory');self.assertEqual(inventory['total'],4)
        claim=self.mutate('pi',op='task_claim',workspace='pi',task_id='task',title='Task',acceptance_criteria='Done',paths=['file.txt'],operation_id='task')
        busy=self.clients['pi'].mutate(dict(op='workspace_close',workspace='pi',expected_generation=0,confirm_writers_stopped=True,operation_id='busy'))
        self.assertEqual(busy['error']['code'],'workspace_busy')
        self.mutate('pi',op='task_update',workspace='pi',claim_id=claim['claim_id'],action='complete',expected_revision=1,operation_id='finish')
        self.mutate('pi',op='workspace_close',workspace='pi',expected_generation=0,confirm_writers_stopped=True,operation_id='finished-close')
    def test_rename_conflict_reports_both_destinations(self):
        (self.paths['codex']/'other.txt').rename(self.paths['codex']/'shared-name.txt');self.commit('codex','shared-rename')
        (self.paths['claude']/'other.txt').rename(self.paths['claude']/'local-name.txt')
        conflict=self.clients['claude'].mutate(dict(op='merge',workspace='claude',target='latest',expected_generation=0,operation_id='rename-overlap'))
        self.assertFalse(conflict['ok']);self.assertIn('local-name.txt',conflict['conflict_paths']);self.assertIn('shared-name.txt',conflict['conflict_paths'])
        self.assertTrue(any(c['local']['kind']=='renamed' or c['shared']['kind']=='renamed' for c in conflict['conflict']['paths']))
        opened=self.review('claude',conflict,'rename-review')
        self.assertTrue((Path(opened['side_paths']['local'])/'local-name.txt').exists());self.assertTrue((Path(opened['side_paths']['shared'])/'shared-name.txt').exists())
    def test_accepted_merge_recovers_after_process_crash(self):
        (self.paths['codex']/'file.txt').write_text('shared\n');self.commit('codex','shared-crash-case')
        (self.paths['pi']/'file.txt').write_text('local\n')
        failed=self.clients['pi'].mutate(dict(op='merge',workspace='pi',target='latest',expected_generation=0,operation_id='merge-crash-case'))
        opened=self.review('pi',failed,'apply-review');(self.root/'apply-review/file.txt').write_text('reviewed\n')
        request=dict(op='resolve_merge',workspace='pi',candidate=failed['candidate'],target=failed['target'],expected_generation=0,resolution_workspace='apply-review',resolved_conflicts=opened['conflict_paths'],operation_id='accept-crash-case')
        crashed=subprocess.run([BINARY,'--state',str(self.state),json.dumps(request)],env=dict(os.environ,WIPSTASH_FAULT='review_after_apply'),capture_output=True)
        self.assertNotEqual(crashed.returncode,0)
        result=self.mutate('pi',**request);self.assertEqual(result['generation'],1)
        self.assertEqual((self.paths['pi']/'file.txt').read_text(),'reviewed\n');self.assertEqual(self.shared('file.txt'),'shared\n')
        status=self.clients['pi'].read('conflict_status',workspace='pi',candidate=failed['candidate']);self.assertEqual(status['conflict']['state'],'resolved')
    def test_combined_shared_tree_is_checked_and_has_one_repair_owner(self):
        for name in ('left.txt','right.txt'):(self.source/name).write_text('0')
        policy={"checks":[{"id":"combined-invariant","argv":[sys.executable,"-B","-c","from pathlib import Path; import sys; sys.exit(sum(int(Path(p).read_text()) if Path(p).exists() else 0 for p in ('left.txt','right.txt')) > 1)"],"required":True,"timeout_seconds":10}]}
        self.mutate('codex',op='configure',policy=policy,operation_id='required-checks')
        (self.paths['codex']/'left.txt').write_text('1');(self.paths['claude']/'right.txt').write_text('1')
        # Each private change passes independently; only the server's combined result violates the invariant.
        check=policy['checks'][0]['argv']
        for agent in ('codex','claude'):self.assertEqual(subprocess.run(check,cwd=self.paths[agent]).returncode,0)
        first=self.commit('codex','checked-left');self.assertTrue(first['shared']);self.assertEqual(first['validation']['state'],'pending')
        self.cli(op='validation_tick')
        shared=self.commit('claude','checked-right');self.assertTrue(shared['shared']);self.assertEqual(shared['validation']['state'],'pending')
        self.assertEqual(self.cli(op='validation_tick')['validation']['state'],'failed')
        self.assertEqual(self.shared('left.txt'),'1')
        self.assertEqual(self.shared('right.txt'),'1')
        status=self.clients['claude'].read('commit_status',commit_id='checked-right')
        self.assertTrue(status['validation']['candidate_tree']);self.assertTrue(status['validation']['policy_sha256']);self.assertEqual(status['validation']['checks'][0]['id'],'combined-invariant')
        self.status('claude')
        repair=self.clients['claude'].read('repair_list')['repairs'][0]
        self.assertEqual(repair['owner']['workspace'],'claude')
        self.mutate('claude',op='repair_update',workspace='claude',incident_id=repair['incident_id'],expected_revision=repair['revision'],action='acknowledge',operation_id='accept-combined-repair')
        (self.paths['claude']/'right.txt').write_text('0')
        fixed=self.commit('claude','checked-fix')
        self.assertTrue(fixed['shared']);self.assertEqual(fixed['validation']['state'],'pending')
        self.assertEqual(self.cli(op='validation_tick')['validation']['state'],'passed')
    def test_binary_edit_delete_and_rename_conflicts_have_exact_sides(self):
        (self.paths['codex']/'file.txt').write_bytes(b'first\0binary');self.commit('codex','binary-first')
        (self.paths['pi']/'file.txt').write_bytes(b'second\0binary')
        conflict=self.clients['pi'].mutate(dict(op='merge',workspace='pi',target='latest',expected_generation=0,operation_id='binary-merge'))
        self.assertFalse(conflict['ok']);self.assertTrue(conflict['conflict']['paths'][0]['binary'])
        opened=self.review('pi',conflict,'binary-review');self.assertEqual((Path(opened['side_paths']['shared'])/'file.txt').read_bytes(),b'first\0binary')
        # A deletion is reported as a deletion rather than an empty textual version.
        (self.paths['claude']/'file.txt').unlink()
        deleted=self.clients['claude'].mutate(dict(op='merge',workspace='claude',target='latest',expected_generation=0,operation_id='delete-merge'))
        self.assertFalse(deleted['ok']);self.assertEqual(deleted['conflict']['paths'][0]['local']['kind'],'deleted')
        # Rename/edit metadata is available even when Git can combine the changes cleanly.
        (self.paths['opencode']/'other.txt').rename(self.paths['opencode']/'renamed.txt')
        status=self.status('opencode');rename=next(c for c in status['local_changes'] if c['path']=='renamed.txt')
        self.assertEqual(rename['kind'],'renamed');self.assertEqual(rename['old_path'],'other.txt')
    def test_review_crash_and_lost_reply_resume_without_overwriting_new_edits(self):
        (self.paths['codex']/'file.txt').write_text('shared\n');self.commit('codex','shared')
        (self.paths['pi']/'file.txt').write_text('local\n')
        failed=self.clients['pi'].mutate(dict(op='merge',workspace='pi',target='latest',expected_generation=0,operation_id='conflict'))
        request=dict(op='resolution_open',workspace='pi',candidate=failed['candidate'],resolution_workspace='crash-review',path=str(self.root/'crash-review'),operation_id='crash-open')
        # The engine fault is a process exit after durable materialization, not a mocked operation.
        raw=dict(request)
        env=dict(os.environ,WIPSTASH_FAULT='conflict_review_after_materialize')
        crashed=subprocess.run([BINARY,'--state',str(self.state),json.dumps(raw)],env=env,capture_output=True)
        self.assertNotEqual(crashed.returncode,0)
        recovered=self.mutate('pi',**request);self.assertEqual(recovered['conflict_paths'],['file.txt'])
        (self.root/'crash-review/file.txt').write_text('my reviewed files\n')
        self.assertEqual(self.mutate('pi',**request),recovered)
        self.assertEqual((self.root/'crash-review/file.txt').read_text(),'my reviewed files\n')
    @unittest.skipIf(os.name=='nt','Unix launcher lease uses flock')
    def test_active_launcher_lease_prevents_archive(self):
        import fcntl
        leases=self.state/'workspace-leases';leases.mkdir()
        with (leases/'pi.lock').open('a+') as lock:
            fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
            denied=self.clients['pi'].mutate(dict(op='workspace_close',workspace='pi',expected_generation=0,confirm_writers_stopped=True,operation_id='active-close'))
            self.assertEqual(denied['error']['code'],'workspace_busy')
        self.mutate('pi',op='workspace_close',workspace='pi',expected_generation=0,confirm_writers_stopped=True,operation_id='inactive-close')
    def test_generated_files_are_visible_and_ignore_templates_are_explicit(self):
        folder=self.paths['pi']/'__pycache__';folder.mkdir();(folder/'example.pyc').write_bytes(b'generated')
        status=self.status('pi');self.assertIn('__pycache__/example.pyc',status['hygiene']['generated_files']);self.assertTrue((folder/'example.pyc').exists())
        source=self.root/'python-source';source.mkdir();(source/'script.py').write_text('print(1)\n');(source/'example.pyc').write_bytes(b'cache')
        state=self.root/'python-state'
        p=subprocess.run([BINARY,'--state',str(state),json.dumps({'op':'init','source':str(source),'ignore_template':'python'})],capture_output=True,text=True)
        result=json.loads(p.stdout);self.assertTrue(result['ok'],result)
        files=subprocess.check_output(['git','--git-dir',str(state/'coordinator.git'),'ls-tree','-r','--name-only','refs/wipstash/integration'],text=True)
        self.assertNotIn('example.pyc',files);self.assertIn('.gitignore',files);self.assertTrue((source/'example.pyc').exists());self.assertFalse((source/'.gitignore').exists())

if __name__=='__main__':
    program=unittest.main(verbosity=2,exit=False)
    destination=os.environ.get('WIPSTASH_EXPERIENCE_ARTIFACTS')
    if destination:
        path=Path(destination);path.mkdir(parents=True,exist_ok=True)
        (path/'summary.json').write_text(json.dumps({'scripted_cli_clients':True,'native_models':False,'passed':program.result.wasSuccessful(),'metrics':METRICS},indent=2)+'\n')
    raise SystemExit(0 if program.result.wasSuccessful() else 1)
