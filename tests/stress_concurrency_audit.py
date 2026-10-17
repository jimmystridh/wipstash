#!/usr/bin/env python3
"""Independent retained-storage promotion/content audit; runs after campaign."""
import collections,json,sqlite3,subprocess,sys
from pathlib import Path
assert len(sys.argv)>1, 'usage: stress_concurrency_audit.py ARTIFACT_ROOT [--partial]'
base=Path(sys.argv[1]).resolve();out=[];errors=collections.Counter();operations=collections.Counter();successes=collections.Counter();replays=0;snapshots=0;seen={}
def git(repo,*args):
 p=subprocess.run(['git','--git-dir',str(repo),*args],capture_output=True,text=True);assert p.returncode==0,(args,p.stderr);return p.stdout.strip()
for root in sorted(base.glob('seed-*')):
 if '--partial' in sys.argv and not (root/'summary.json').exists(): continue
 assert (root/'summary.json').exists(),('incomplete_seed',str(root))
 for file in root.glob('*.jsonl'):
  if file.name.endswith('-snapshots.jsonl'):
   snapshots+=len(file.read_text().splitlines());continue
  for line in file.read_text().splitlines():
   record=json.loads(line)
   if 'request' not in record:continue
   request=record['request'];response=record['response'];op=request['op'];operations[op]+=1
   if response['ok']:successes[op]+=1
   else:
    code=response['error']['code'];errors[code]+=1
    allowed={'adopt':{'adoption_conflict','coordinator_unreachable'},'checkpoint':{'generation_mismatch'},'cancel':{'already_terminal'},'retry_proposal':{'already_terminal'}}
    assert code in allowed.get(op,set()),('unexpected_error',root,record)
   if 'operation_id' in request:
    key=(str(root),request['operation_id'])
    if key in seen:assert seen[key]==(request,response),('inconsistent_replay',key);replays+=1
    else:seen[key]=(request,response)
 db=sqlite3.connect(root/'state'/'state.sqlite');repo=root/'state'/'coordinator.git'
 initial=json.loads(db.execute("select data from events where kind='initialized' order by seq limit 1").fetchone()[0])['head'];last=initial;promotions=clean=repaired=0
 for pid,pid2,old,new,state in db.execute('select id,proposal,old,new,state from promotions order by rowid'):
  assert state=='committed',('pending_promotion',root,pid,state)
  assert old==last,('broken_public_chain',root,pid,old,last)
  proposal=db.execute('select commit_oid from proposals where id=?',(pid2,)).fetchone()[0]
  parents=git(repo,'rev-list','--parents','-n','1',new).split()[1:];assert parents==[old,proposal],('wrong_promotion_parents',pid,parents)
  tree=git(repo,'rev-parse',new+'^{tree}')
  matches=db.execute('select tree,evidence,state from candidates where head=? and proposal=? and tree=?',(old,proposal,tree)).fetchall();assert matches,('unrecorded_candidate',pid)
  accepted=[json.loads(e) for t,e,s in matches if s=='ready' and json.loads(e)['accepted']];assert accepted,('unaccepted_promoted',pid)
  e=accepted[0];assert e['candidate_tree']==tree
  if not e['repaired']:
   merged=git(repo,'merge-tree','--write-tree',old,proposal).splitlines()[0];assert merged==tree,('wrong_merge_bytes',pid,merged,tree);clean+=1
  else:
   assert e['repair_status']=='agent_resolved_unchecked',e
   for path in e['conflict_paths']: assert git(repo,'show',new+':'+path)=='scripted resolution',('wrong_scripted_repair_bytes',pid,path)
   assert e['repair_attempts'][-1]['resolution_report_valid']
   repaired+=1
  last=new;promotions+=1
 assert last==git(repo,'rev-parse','refs/wipstash/integration'),('head_not_last_promotion',root)
 out.append({'seed':root.name,'promotions':promotions,'independently_remerged':clean,'recorded_repairs':repaired})
result={'operations':dict(operations),'successes_by_operation':dict(successes),'expected_errors':dict(errors),'idempotent_replays':replays,'acknowledged_snapshot_records':snapshots,'seeds':len(out),'promotions':sum(x['promotions'] for x in out),'independently_remerged':sum(x['independently_remerged'] for x in out),'recorded_repairs':sum(x['recorded_repairs'] for x in out),'details':out}
(base/('deep-audit-partial.json' if '--partial' in sys.argv else 'deep-audit.json')).write_text(json.dumps(result,indent=2));print(json.dumps({k:v for k,v in result.items() if k!='details'}))
