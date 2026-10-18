#!/usr/bin/env python3
"""Read-only campaign analysis, exact journal replay, and private/public isolation audit."""
import argparse, collections, hashlib, json, math, pathlib, re, sqlite3, subprocess, time
ROOT=pathlib.Path(__file__).resolve().parents[1]

def lines(path):
    if not path.exists(): return []
    out=[]
    for line in path.read_text().splitlines():
        try: out.append(json.loads(line))
        except ValueError: pass  # Live snapshot may end in one partially written line.
    return out

def quantiles(values):
    values=sorted(values)
    def q(f):
        if not values: return None
        p=(len(values)-1)*f; lo=math.floor(p); hi=math.ceil(p)
        return values[lo]+(values[hi]-values[lo])*(p-lo)
    return {'n':len(values),'min':min(values) if values else None,'p50':q(.5),'p95':q(.95),'p99':q(.99),'max':max(values) if values else None,'mean':sum(values)/len(values) if values else None}

def git(*args,input=None):
    return subprocess.run(['git','--git-dir',str(ROOT/'state'/'coordinator.git'),*args],input=input,capture_output=True)

def privacy_audit():
    manifests=[json.loads(p.read_text()) for p in sorted(ROOT.glob('actor-?-w*-private.json'))]
    private_records=[]
    for m in manifests:
        workspace=ROOT/m['workspace']; observed={}; unchanged=True
        for rel,expected in m['files'].items():
            path=workspace/rel
            got=hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() else None
            observed[rel]={'expected_sha256':expected,'observed_sha256':got,'unchanged':got==expected}
            unchanged=unchanged and got==expected
        local_repo=ROOT/'state'/'locals'/m['workspace']/'objects.git'
        tracked=subprocess.run(['git','--git-dir',str(local_repo),'ls-tree','-rz',m['private_checkpoint']['commit']],capture_output=True)
        assert tracked.returncode==0,tracked.stderr.decode()
        checkpoint_differences=[]; tracked_files=0
        for item in tracked.stdout.split(b'\0'):
            if not item: continue
            meta,rel=item.split(b'\t',1); mode,kind,oid=meta.decode().split(); rel=rel.decode(); tracked_files+=1
            if rel=='PRIVATE_WIP.txt': continue  # Designated unsaved delta is independently SHA256-checked above.
            path=workspace/rel
            data=path.read_bytes() if path.is_file() else None
            actual=hashlib.sha1(b'blob '+str(len(data)).encode()+b'\0'+data).hexdigest() if data is not None else None
            if actual!=oid: checkpoint_differences.append({'path':rel,'expected_blob':oid,'actual_blob':actual})
        private_records.append({'workspace':m['workspace'],'wave':m['wave'],'files':observed,'all_unchanged':unchanged,'private_checkpoint_oid':m['private_checkpoint']['commit'],'checkpoint_tracked_files':tracked_files,'unexpected_checkpoint_file_differences':checkpoint_differences})
    private_oids=[r['private_checkpoint_oid'] for r in private_records]
    batch=git('cat-file','--batch-check',input=('\n'.join(private_oids)+'\n').encode()) if private_oids else None
    public_private_commit_leaks=[]
    if batch:
        for line in batch.stdout.decode().splitlines():
            if not line.endswith(' missing'): public_private_commit_leaks.append(line)
    objects=git('cat-file','--batch-all-objects','--batch-check=%(objectname) %(objecttype) %(objectsize)')
    assert objects.returncode==0,objects.stderr.decode()
    blob_ids=[]; object_count=0; total_blob_bytes=0
    for line in objects.stdout.decode().splitlines():
        oid,kind,size=line.split(); object_count+=1
        if kind=='blob': blob_ids.append(oid); total_blob_bytes+=int(size)
    content=git('cat-file','--batch',input=('\n'.join(blob_ids)+'\n').encode()) if blob_ids else None
    leaked=[]
    if content:
        assert content.returncode==0,content.stderr.decode()
        data=content.stdout; pos=0
        while pos<len(data):
            end=data.index(b'\n',pos); header=data[pos:end].decode().split(); oid,kind,size=header; size=int(size); pos=end+1
            body=data[pos:pos+size]; pos+=size+1
            if any(marker in body for marker in (b'SYNTHETIC_PRIVATE_',b'UNSAVED_PRIVATE_WIP_AFTER_CHECKPOINT')): leaked.append(oid)
    refs=git('for-each-ref','--format=%(objectname) %(refname)'); assert refs.returncode==0
    tree_leaks=[]
    for entry in refs.stdout.decode().splitlines():
        oid,ref=entry.split(' ',1); tree=git('ls-tree','-r','--name-only',oid)
        if tree.returncode: continue
        bad=[path for path in tree.stdout.decode().splitlines() if path=='PRIVATE_WIP.txt' or path.startswith('local/')]
        if bad: tree_leaks.append({'ref':ref,'oid':oid,'paths':bad})
    return {'private_workspaces_checked':len(manifests),'all_original_wip_hashes_unchanged':all(r['all_unchanged'] for r in private_records),'checkpoint_tracked_files_unchanged_except_designated_unsaved_marker':all(not r['unexpected_checkpoint_file_differences'] for r in private_records),'checkpoint_tracked_file_checks':sum(r['checkpoint_tracked_files'] for r in private_records),'private_checkpoint_oids_absent_from_public_store':not public_private_commit_leaks,'private_checkpoint_leaks':public_private_commit_leaks,'public_store_objects_scanned':object_count,'public_blobs_scanned':len(blob_ids),'public_blob_bytes_scanned':total_blob_bytes,'all_public_blobs_marker_free':not leaked,'leaked_blob_oids':leaked,'public_ref_tree_private_paths':tree_leaks,'records':private_records}

def analyze(final=False):
    run=json.loads((ROOT/'run.json').read_text()); complete_path=ROOT/'coordinator-summary.json'
    complete=json.loads(complete_path.read_text()) if complete_path.exists() else None
    end=complete['finished_epoch'] if complete else time.time(); seconds=end-run['started_epoch']
    db=sqlite3.connect(f'file:{ROOT / "state" / "state.sqlite"}?mode=ro',uri=True); db.execute('PRAGMA query_only=ON'); db.row_factory=sqlite3.Row
    proposals={r['id']:dict(r) for r in db.execute('SELECT rowid,* FROM proposals ORDER BY rowid')}
    resolution={r['proposal']:dict(r) for r in db.execute('SELECT * FROM proposal_resolutions')}
    events=[{'seq':r['seq'],'kind':r['kind'],'data':json.loads(r['data'])} for r in db.execute('SELECT * FROM events ORDER BY seq')]
    sessions=[dict(r) for r in db.execute('SELECT * FROM resolution_sessions')]
    db.close()
    commands=[]
    for actor in 'abcd':
        for record in lines(ROOT/f'actor-{actor}-commands.jsonl'): record['actor']=f'actor-{actor}'; commands.append(record)
    calls=[r for r in commands if r.get('kind')=='rpc']; integrations=lines(ROOT/'integrations.jsonl')
    pubs={}
    for call in calls:
        req=call['request']; resp=call['response']
        if req['op'] in ('publish','resolution_submit') and resp.get('ok') and resp.get('proposal'):
            pubs[resp['proposal']]={'proposal':resp['proposal'],'actor':call['actor'],'workspace':req['workspace'],'kind':req['op'],'started_epoch':call['started_epoch'],'accepted_epoch':call['finished_epoch'],'request_seconds':call['seconds'],'root_proposal':resolution.get(resp['proposal'],{}).get('root',resp['proposal']),'resolution_attempt':resolution.get(resp['proposal'],{}).get('attempt',0)}
    outcomes=[]; first_outcome={}
    for call in integrations:
        for item in call['response'].get('outcomes',[]):
            outcome={**item,'integration_started_epoch':call['started_epoch'],'integration_finished_epoch':call['finished_epoch'],'integration_seconds':call['seconds'],'integration_sequence':call['sequence']}
            outcomes.append(outcome); first_outcome.setdefault(item['proposal'],outcome)
    for pid,pub in pubs.items():
        outcome=first_outcome.get(pid)
        pub['final_state']=proposals.get(pid,{}).get('state')
        if outcome:
            pub.update(outcome_state=outcome['state'],integration_started_epoch=outcome['integration_started_epoch'],integration_finished_epoch=outcome['integration_finished_epoch'],queue_age_lower_seconds=max(0,outcome['integration_started_epoch']-pub['accepted_epoch']),queue_age_upper_seconds=max(0,outcome['integration_finished_epoch']-pub['started_epoch']),accepted_to_outcome_seconds=max(0,outcome['integration_finished_epoch']-pub['accepted_epoch']))
    queue=set(); peak=0; queue_samples=[]; unresolved=set(); unresolved_peak=0
    for event in events:
        kind=event['kind']; data=event['data']; pid=data.get('proposal')
        if kind in ('published','resolution_submitted') and pid:
            queue.add(pid); unresolved.add(resolution.get(pid,{}).get('root',pid))
        elif kind in ('integrated','already_included','quarantined','superseded','cancelled'):
            queue.discard(pid)
            if kind in ('integrated','already_included','cancelled') and pid: unresolved.discard(resolution.get(pid,{}).get('root',pid))
        peak=max(peak,len(queue)); unresolved_peak=max(unresolved_peak,len(unresolved)); queue_samples.append({'seq':event['seq'],'occurred_at':data.get('_occurred_at'),'queue_depth':len(queue),'unresolved_lineages':len(unresolved)})
    wave_records=[]
    for actor in 'abcd':
        aid=f'actor-{actor}'; rows=[r for r in commands if r['actor']==aid]
        for wave in range(1,9):
            workspace=f'{aid}-w{wave}'; roots=[p for p in pubs.values() if p['kind']=='publish' and p['workspace']==workspace]
            root=roots[0] if roots else None
            opened=next((r for r in rows if r.get('kind')=='rpc' and r['request']['op']=='open' and r['request'].get('workspace')==workspace),None)
            lineage=[p for p in pubs.values() if root and p['root_proposal']==root['proposal']]
            integrated=[p for p in lineage if p.get('outcome_state') in ('integrated','already_included')]
            integrated=sorted(integrated,key=lambda p:p['integration_finished_epoch'])
            winner=integrated[-1] if integrated else None
            wave_events=[r for r in rows if r.get('kind')=='wave' and r.get('wave')==wave]
            wave_calls=[r for r in rows if r.get('kind')=='rpc' and (r['request'].get('workspace')==workspace or str(r['request'].get('workspace','')).startswith(workspace+'-r'))]
            stale=[r for r in wave_calls if r['response'].get('error',{}).get('code')=='stale_resolution']
            opens=[r for r in wave_calls if r['request']['op']=='resolution_open' and r['response'].get('ok')]
            wave_records.append({'actor':aid,'wave':wave,'feature':actor.upper()+str(wave),'workspace':workspace,'root_proposal':root['proposal'] if root else None,'state':'integrated' if winner else ('started_unfinished' if opened else 'not_started'),'integrated_proposal':winner['proposal'] if winner else None,'started_epoch':opened['started_epoch'] if opened else None,'first_publication_epoch':root['accepted_epoch'] if root else None,'integrated_epoch':winner['integration_finished_epoch'] if winner else None,'publish_to_integrated_seconds':winner['integration_finished_epoch']-root['accepted_epoch'] if winner else None,'task_seconds':winner['integration_finished_epoch']-opened['started_epoch'] if winner and opened else None,'resolution_openings':len(opens),'stale_resolution_submissions':len(stale),'resolution_submissions':len(lineage)-1 if lineage else 0,'max_submitted_attempt':max([p['resolution_attempt'] for p in lineage] or [0]),'reported_status':wave_events[-1] if wave_events else None})
    accepted=[p for p in pubs.values() if 'queue_age_lower_seconds' in p]
    integrated_waves=[w for w in wave_records if w['state']=='integrated']
    failed_calls=[r for r in calls if not r['response'].get('ok')]
    errors=collections.Counter(r['response'].get('error',{}).get('code','unknown') for r in failed_calls)
    tests=[r for r in commands if r.get('kind')=='tests']; test_failures=[r for r in tests if r.get('returncode')!=0]
    observer=json.loads((ROOT/'observer-summary.json').read_text()) if (ROOT/'observer-summary.json').exists() else None
    admin=lines(ROOT/'administrative-events.jsonl')
    summary={'kind':'sustained-native-agent-campaign-analysis','final':final,'run':run,'coordinator':complete,'elapsed_seconds':seconds,'genuine_native_actors':4,'planned_feature_waves':32,'integrated_feature_waves':len(integrated_waves),'unfinished_features':[w['feature'] for w in wave_records if w['state']!='integrated'],'publication_requests_accepted':len(pubs),'initial_feature_publications':sum(p['kind']=='publish' for p in pubs.values()),'resolution_publications':sum(p['kind']=='resolution_submit' for p in pubs.values()),'proposal_states':dict(collections.Counter(p['state'] for p in proposals.values())),'integration_outcomes':dict(collections.Counter(o['state'] for o in outcomes)),'automatic_integration_calls':len(integrations),'integration_call_errors':sum(not r['response'].get('ok') for r in integrations),'integration_call_seconds':quantiles([r['seconds'] for r in integrations]),'nonempty_integration_call_seconds':quantiles([r['seconds'] for r in integrations if r['response'].get('outcomes')]),'queue_age_lower_seconds':quantiles([p['queue_age_lower_seconds'] for p in accepted]),'queue_age_upper_seconds':quantiles([p['queue_age_upper_seconds'] for p in accepted]),'accepted_to_outcome_seconds':quantiles([p['accepted_to_outcome_seconds'] for p in accepted]),'root_publish_to_integrated_seconds':quantiles([w['publish_to_integrated_seconds'] for w in integrated_waves]),'feature_task_seconds':quantiles([w['task_seconds'] for w in integrated_waves]),'accepted_publications_per_minute':len(pubs)*60/seconds,'integrated_features_per_minute':len(integrated_waves)*60/seconds,'quarantined_outcomes_per_minute':sum(o['state']=='quarantined' for o in outcomes)*60/seconds,'failed_actor_rpc_calls_per_minute':len(failed_calls)*60/seconds,'peak_journal_reconstructed_queue_depth':peak,'peak_unfinished_lineages':unresolved_peak,'actor_rpc_error_codes':dict(errors),'author_test_runs':len(tests),'author_test_failures':len(test_failures),'resolution_openings':len(sessions),'stale_resolution_submissions':errors.get('stale_resolution',0),'submitted_resolution_attempts':len(resolution),'exhausted_lineages':sum(w['max_submitted_attempt']>=3 and w['state']!='integrated' for w in wave_records),'manual_integration_or_conflict_rescue_interventions':0,'administrative_setup_events':admin,'publications':list(pubs.values()),'waves':wave_records,'per_actor':{},'source_observer':observer,'measurement_notes':['Queue-age lower bound uses client publication return to automatic integration call start; conservative upper bound uses publication request start to integration call return, including service/lock overhead. Values clamp to zero when calls overlap. Exact internal admission/service times were not instrumented.','Exact queue depth reconstructed by durable event sequence, not coarse wall clock.','Root latency includes model author conflict resolution and stale reopens; integration-call latency is separate.','Four independently reasoning native agents, not standalone Codex CLI/Claude Code product sessions.','Source projection only: no HTTP webhook delivery, ChatGPT notifications, external provider or live credentials.','One fixed-order workload has no matched batch comparator and cannot establish optimal publication size or saturation.']}
    for actor in 'abcd':
        aid=f'actor-{actor}'; waves=[w for w in wave_records if w['actor']==aid]; ps=[p for p in accepted if p['actor']==aid]
        summary['per_actor'][aid]={'completed':sum(w['state']=='integrated' for w in waves),'not_completed':[w['feature'] for w in waves if w['state']!='integrated'],'queue_age_lower_seconds':quantiles([p['queue_age_lower_seconds'] for p in ps]),'publish_to_integrated_seconds':quantiles([w['publish_to_integrated_seconds'] for w in waves if w['state']=='integrated']),'task_seconds':quantiles([w['task_seconds'] for w in waves if w['state']=='integrated']),'resolution_openings':sum(w['resolution_openings'] for w in waves),'stale_submissions':sum(w['stale_resolution_submissions'] for w in waves)}
    summary['starvation_observation']={'all_planned_features_integrated':len(integrated_waves)==32,'unfinished_count':32-len(integrated_waves),'observation_is_bounded':True,'no_general_fairness_or_saturation_claim':True}
    for wave in wave_records:
        if wave['first_publication_epoch'] is not None:
            until=wave['integrated_epoch'] or end
            wave['other_features_integrated_while_waiting']=sum(other['actor']!=wave['actor'] and other['integrated_epoch'] is not None and wave['first_publication_epoch']<other['integrated_epoch']<until for other in wave_records)
    if final: summary['privacy']=privacy_audit()
    return summary

if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--final',action='store_true');args=parser.parse_args()
    result=analyze(args.final);path=ROOT/('analysis-final.json' if args.final else 'analysis-live.json');path.write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps({k:v for k,v in result.items() if k not in ('publications','waves','source_observer','privacy','run','coordinator','measurement_notes')},indent=2))
