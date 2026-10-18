#!/usr/bin/env python3
"""Automatic fixed-cadence integration only. Never edits actor code or resolves tasks."""
import fcntl, hashlib, json, pathlib, sqlite3, subprocess, time
from datetime import datetime, timezone
ROOT=pathlib.Path(__file__).resolve().parents[1]
BIN=pathlib.Path('/workspace/shared/wipstash/target/debug/wipstash')
STATE=ROOT.parent/'state'
ACTORS=['actor-c']
def save(name,value):
    path=ROOT/name; temp=path.with_suffix(path.suffix+'.next'); temp.write_text(json.dumps(value,indent=2)+'\n'); temp.replace(path)
def append(name,value):
    with (ROOT/name).open('a') as f: f.write(json.dumps(value,sort_keys=True)+'\n')
def snapshot():
    with (STATE/'state.lock').open('rb') as lock:
        try: fcntl.flock(lock,fcntl.LOCK_SH|fcntl.LOCK_NB)
        except BlockingIOError: return None
        with sqlite3.connect(f'file:{STATE / "state.sqlite"}?mode=ro',uri=True) as db:
            db.execute('PRAGMA query_only=ON'); db.row_factory=sqlite3.Row
            proposals=[dict(row) for row in db.execute('SELECT rowid,id,workspace,state,head FROM proposals ORDER BY rowid')]
            return {'at_epoch':time.time(),'proposals':proposals,'max_event_seq':db.execute('SELECT COALESCE(MAX(seq),0) FROM events').fetchone()[0]}
def run():
    assert not (ROOT/'run.json').exists(), 'Fresh run required'
    assert (ROOT/'oracle-frozen.json').is_file(), 'Independent oracle must be frozen before run'
    started=time.time(); active_deadline=started+10*60; drain_deadline=active_deadline+2*60
    metadata={'kind':'separate-oracle-guided-recovery-phase','started_epoch':started,'started_at':datetime.now(timezone.utc).isoformat(),'active_deadline_epoch':active_deadline,'drain_deadline_epoch':drain_deadline,'integration_interval_seconds':0.35,'max_proposals_per_call':1,'external_oracle_feedback_interventions':1,'source_projection_only':True,'webhook_delivery_chain':False,'core_binary_sha256':hashlib.sha256(BIN.read_bytes()).hexdigest(),'policy_checks_configured':False,'feature_count':1}
    save('run.json',metadata)
    sequence=0; last_snapshot=None; deadline_notified=False; reason=''
    while True:
        tick=time.monotonic(); stamp=time.time()
        if stamp>=active_deadline and not deadline_notified:
            save('active-deadline.json',{'reached_epoch':stamp,'instruction':'Do not start new features; drain existing proposals only.'}); deadline_notified=True
        if stamp>=drain_deadline: reason='fixed_10_minute_active_plus_2_minute_drain_bound'; break
        if (ROOT/'coordinator.stop').exists(): reason='operator_sentinel'; break
        sequence+=1
        request={'op':'integrate','max_proposals':1,'operation_id':f'recovery-auto-integrate-{sequence:06d}'}
        result=subprocess.run([str(BIN),'--state',str(STATE),json.dumps(request)],text=True,capture_output=True)
        try: response=json.loads(result.stdout)
        except ValueError: response={'unparsed_stdout':result.stdout}
        append('integrations.jsonl',{'sequence':sequence,'request':request,'started_epoch':stamp,'finished_epoch':time.time(),'seconds':time.monotonic()-tick,'returncode':result.returncode,'stderr':result.stderr,'response':response})
        snap=snapshot()
        if snap is not None:
            save('latest-state.json',snap)
            compact=json.dumps(snap['proposals'],sort_keys=True)
            if compact!=last_snapshot: append('state-transitions.jsonl',snap); last_snapshot=compact
            pending=[p for p in snap['proposals'] if p['state'] in ('coordinator_accepted','local_queued')]
            if all((ROOT/f'{a}.done.json').exists() for a in ACTORS) and not pending:
                reason='recovery_actor_terminal_and_queue_drained'; break
        elapsed=time.monotonic()-tick
        time.sleep(max(0,0.35-elapsed))
    # No process is killed. Observer receives its existing graceful-stop sentinel.
    save('coordinator-summary.json',{**metadata,'finished_epoch':time.time(),'seconds':time.time()-started,'integration_calls':sequence,'stop_reason':reason,'final_snapshot':snapshot(),'complete':True})
    (ROOT/'observer.stop').write_text(reason+'\n')
    print(json.dumps({'complete':True,'stop_reason':reason,'integration_calls':sequence,'seconds':time.time()-started}))
if __name__=='__main__': run()
