#!/usr/bin/env python3
"""Opt-in native Codex/Claude/OpenCode/Pi acceptance exercise in one isolated fixture repo."""
import argparse
import concurrent.futures
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import sqlite3
import subprocess
import sys
import time


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--artifacts',required=True)
    parser.add_argument('--binary',default='target/debug/wipstash')
    parser.add_argument('--pi-model',help='Optional Pi model override for this test only.')
    parser.add_argument('--run-native',action='store_true',required=True,help='Run the four installed model-backed clients; may use their accounts.')
    args=parser.parse_args()
    root=Path(args.artifacts).resolve();root.mkdir(parents=True,exist_ok=False)
    binary=Path(args.binary).resolve();state=root/'state';source=root/'source';source.mkdir()
    (source/'README.md').write_text('Isolated Wipstash native client validation fixture.\n')
    (source/'notes').mkdir();(source/'notes/guide.txt').write_text('Each client contributes one separate note.\n')
    def engine(request):
        p=subprocess.run([str(binary),'--state',str(state),'stdin'],input=json.dumps(request)+'\n',text=True,capture_output=True,timeout=120)
        value=json.loads(p.stdout);assert p.returncode==0 and value['ok'],value;return value
    engine(dict(op='init',source=str(source)))
    policy={'checks':[{'id':'nonempty-notes','argv':[sys.executable,'-B','-c',"from pathlib import Path; import sys; sys.exit(any(not p.read_text().strip() for p in Path('notes').glob('*.txt')))"],'required':True,'timeout_seconds':15}]}
    engine(dict(op='configure',policy=policy,operation_id='native-policy'))
    paths={};cli_binary=binary.with_name("wip.exe" if os.name=="nt" else "wip")
    for client in ('codex','claude','opencode','pi'):
        if not shutil.which(client):raise RuntimeError(client+' is not installed')
        path=root/client;paths[client]=path
        engine(dict(op='open',workspace=client,path=str(path),operation_id='clone-'+client))
        subprocess.run([str(cli_binary),'--json','-C',str(path),'attach','--state',str(state),'--workspace',client],check=True,capture_output=True)
    skill=Path(__file__).resolve().parents[1]/'skills/wipstash-source-control/SKILL.md'
    def run_client(client):
        path=paths[client]
        prompt=f'''You are {client}, working in your separate Wipstash clone at {str(path)!r}. Wipstash commits within this acceptance task are explicitly authorized; GitHub pushes and deployments are not.
Read the skill at {str(skill)!r}. Use the standalone wip CLI through shell commands. Read wip status --json and wip task list --json, then claim task native-acceptance with title "{client} acceptance note", acceptance "One useful note reaches shared", and --paths notes/{client}.txt --lease 600. Inspect advisory overlap warnings and leave the claim active for the supervisor.
Write notes/{client}.txt with one useful sentence about isolated workspaces. Run wip add notes/{client}.txt, then wip commit -m "test: add {client} acceptance note" --json. Require shared=true; a pending result is not shared. Checks run asynchronously; the supervisor checks the final combined tree. Read wip get-latest --json and wip status --json afterward and confirm your note is unchanged. Report the commit ID, sharing and validation states. Preserve other agents' files.'''
        env=dict(os.environ,PATH=str(cli_binary.parent)+os.pathsep+os.environ.get('PATH',''),WIPSTASH_STATE=str(state),WIPSTASH_WORKSPACE_ID=client,WIPSTASH_WORKSPACE_PATH=str(path),WIPSTASH_AGENT_CLIENT=client,WIPSTASH_SESSION_ID='native-validation-'+client)
        if client=='codex':
            command=[client,'exec','--ignore-user-config','--skip-git-repo-check','--json','--sandbox','workspace-write','--add-dir',str(root),'-c','approval_policy="never"','-C',str(path),prompt]
        elif client=='claude':
            command=[client,'-p','--setting-sources','','--settings','{"disableAllHooks":true}','--output-format','stream-json','--verbose','--permission-mode','acceptEdits','--allowedTools','Read,Write,Edit,Bash','--max-budget-usd','5',prompt]
        elif client=='opencode':
            env['OPENCODE_CONFIG_CONTENT']=json.dumps({'permission':{'*':'allow'}})
            command=[client,'run','--pure','--format','json','--dir',str(path),prompt]
        else:
            command=[client,*(['--model',args.pi_model] if args.pi_model else []),'--print','--mode','json','--no-context-files','--no-skills','--no-prompt-templates','--session-dir',str(root/'pi-sessions'),prompt]
        (root/(client+'-request.json')).write_text(json.dumps({'command':command,'cwd':str(path)},indent=2)+'\n')
        started=time.monotonic()
        with (root/(client+'.jsonl')).open('w') as out,(root/(client+'.stderr')).open('w') as err:
            try:
                with subprocess.Popen(command,cwd=path,env=env,stdin=subprocess.DEVNULL,stdout=out,stderr=err,start_new_session=True) as process:
                    try:code=process.wait(timeout=600)
                    except subprocess.TimeoutExpired:
                        os.killpg(process.pid,signal.SIGTERM)
                        try:process.wait(timeout=10)
                        except subprocess.TimeoutExpired:os.killpg(process.pid,signal.SIGKILL);process.wait()
                        return {'client':client,'timed_out':True,'seconds':round(time.monotonic()-started,3)}
                    return {'client':client,'exit_code':code,'seconds':round(time.monotonic()-started,3)}
            except OSError as error:return {'client':client,'launch_error':str(error),'seconds':round(time.monotonic()-started,3)}
    started=time.monotonic()
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:results=list(pool.map(run_client,paths))
    checked=engine(dict(op='validation_tick'))
    shared_health=engine(dict(op='validation_status'))['repo_health']
    db=sqlite3.connect(state/'state.sqlite');db.row_factory=sqlite3.Row
    try:
        commits=[dict(r) for r in db.execute('SELECT id,workspace,state,details FROM proposals')]
        workspace_count=db.execute('SELECT COUNT(*) FROM workspaces').fetchone()[0]
        claims=[dict(r) for r in db.execute('SELECT id,workspace,revision,state,expires FROM task_claims')]
        overlaps=[json.loads(r[0]).get('overlaps',0) for r in db.execute("SELECT data FROM events WHERE kind='task_claimed'")]
        operations=[json.loads(r[0]) for r in db.execute('SELECT request FROM operations')]
    finally:db.close()
    for claim in claims:
        if claim['state']=='active' and claim['expires']>time.time():engine(dict(op='task_update',workspace=claim['workspace'],claim_id=claim['id'],expected_revision=claim['revision'],action='complete',operation_id='supervisor-complete-'+claim['workspace']))
    shared=subprocess.check_output(['git','--git-dir',str(state/'coordinator.git'),'ls-tree','-r','--name-only','refs/wipstash/integration'],text=True).splitlines()
    for result in results:
        client=result['client'];own=paths[client]/'notes'/f'{client}.txt'
        result['own_note_exists']=own.is_file()
        result['isolated']=all(not (paths[client]/'notes'/f'{other}.txt').exists() for other in paths if other!=client)
        result['shared']=any(c['workspace']==client and c['state'] in ('integrated','already_included') for c in commits)
        result['included_in_verified_shared_head']=result['shared'] and shared_health['state']=='passed'
        result['note_sha256']=hashlib.sha256(own.read_bytes()).hexdigest() if own.is_file() else None
    summary={'native_clients':True,'pi_model_override':args.pi_model,'overlap_counts':overlaps,'results':results,'seconds':round(time.monotonic()-started,3),'shared_files':shared,'workspace_count':workspace_count,'comparison_clones':max(0,workspace_count-4),'resolution_attempts':sum(o.get('op')=='resolution_open' for o in operations),'commit_attempts':sum(o.get('op')=='commit' for o in operations),'claims':claims,'commits':commits,'repo_health':shared_health,'validation_run':checked,'passed':all(r.get('exit_code')==0 and r['shared'] and r['isolated'] and r['included_in_verified_shared_head'] for r in results)}
    (root/'summary.json').write_text(json.dumps(summary,indent=2)+'\n')
    print(json.dumps({k:v for k,v in summary.items() if k not in ('commits','claims')},indent=2))
    return 0 if summary['passed'] else 1

if __name__=='__main__':raise SystemExit(main())
