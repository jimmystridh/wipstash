import fcntl,json,pathlib,re,sqlite3,subprocess,sys
ROOT=pathlib.Path('/workspace/shared/mcp-pressure/sustained-agents')
OUT=pathlib.Path('/workspace/shared/mcp-pressure/sustained-oracle/heads');OUT.mkdir(exist_ok=True)
state=ROOT/'state'
with (state/'state.lock').open('rb') as lock:
 fcntl.flock(lock,fcntl.LOCK_SH)
 with sqlite3.connect(f'file:{state}/state.sqlite?mode=ro',uri=True) as db:
  records=db.execute("SELECT seq,kind,data FROM events WHERE kind IN ('integrated','already_included') ORDER BY seq").fetchall()
  roots=dict(db.execute('SELECT proposal,root FROM proposal_resolutions'))
features=set();results=[];lasthead=None
for seq,kind,data in records:
 v=json.loads(data);p=v['proposal'];root=roots.get(p,p);match=re.fullmatch(r'actor-([a-d])-w([1-8])-publish',root)
 if not match:raise RuntimeError('unmapped integrated proposal '+root)
 features.add(match[1].upper()+match[2]);head=v.get('head',lasthead);lasthead=head
 candidate=OUT/f'{seq}-{head}';candidate.mkdir(exist_ok=True)
 (candidate/'report.py').write_bytes(subprocess.check_output(['git','--git-dir',str(state/'coordinator.git'),'show',head+':report.py']))
 output=candidate/'oracle-result.json'
 if not output.exists():
  run=subprocess.run([sys.executable,str(OUT.parent/'oracle.py'),str(candidate),'--features',','.join(sorted(features)),'--output',str(output)],capture_output=True,text=True)
  if not output.exists():raise RuntimeError(run.stderr)
 check=json.loads(output.read_text());results.append({'seq':seq,'head':head,'proposal':p,'root':root,'features':sorted(features),'pass':check['pass'],'failure_count':len(check['failures']),'checks':check['checks'],'result_path':str(output)})
summary={'snapshots':len(results),'passed':sum(x['pass'] for x in results),'features':sorted(features),'results':results};(OUT.parent/'snapshot-summary.json').write_text(json.dumps(summary,indent=2));print(json.dumps(summary))
