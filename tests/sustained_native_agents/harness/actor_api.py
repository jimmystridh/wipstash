#!/usr/bin/env python3
"""Instrument individual native-agent choices. No actor workflow/implementation loop."""
import hashlib, json, os, pathlib, subprocess, sys, time
from datetime import datetime, timezone
ROOT = pathlib.Path(__file__).resolve().parents[1]
BIN = pathlib.Path('/workspace/shared/wipstash/target/debug/wipstash')
STATE = ROOT / 'state'

def now(): return datetime.now(timezone.utc).isoformat()
def save(path, value):
    temp = path.with_suffix(path.suffix + '.next')
    temp.write_text(json.dumps(value, indent=2) + '\n'); temp.replace(path)
def log(actor, item):
    item.setdefault('recorded_at', now())
    with (ROOT / f'{actor}-commands.jsonl').open('a') as f:
        f.write(json.dumps(item, sort_keys=True) + '\n')
def rpc(actor, request):
    if request['op'] in ('integrate', 'configure', 'command_run', 'retry_proposal'):
        raise ValueError('Actor operation outside frozen protocol')
    started = time.time(); mono = time.monotonic()
    result = subprocess.run([str(BIN), '--state', str(STATE), json.dumps(request)], text=True, capture_output=True)
    try: response = json.loads(result.stdout)
    except ValueError: response = {'unparsed_stdout': result.stdout}
    log(actor, {'kind':'rpc','request':request,'response':response,'started_epoch':started,'finished_epoch':time.time(),'seconds':time.monotonic()-mono,'returncode':result.returncode,'stderr':result.stderr})
    return response

def tests(actor, workspace):
    path = ROOT / workspace
    started = time.time(); mono = time.monotonic()
    result = subprocess.run([sys.executable,'-m','unittest','discover','-s','tests','-v'],cwd=path,text=True,capture_output=True)
    evidence={'kind':'tests','workspace':workspace,'started_epoch':started,'finished_epoch':time.time(),'seconds':time.monotonic()-mono,'returncode':result.returncode,'stdout':result.stdout,'stderr':result.stderr}
    log(actor,evidence); return evidence

def seal(actor, workspace, wave, expected_generation):
    """Explicit post-publication private checkpoint plus unsaved-WIP probe."""
    path=ROOT/workspace
    marker=f'SYNTHETIC_PRIVATE_{actor}_WAVE_{wave}_CHECKPOINT_ONLY'
    (path/'local').mkdir(exist_ok=True)
    (path/'local'/'excluded.txt').write_text(marker+'_EXCLUDED\n')
    (path/'PRIVATE_WIP.txt').write_text(marker+'\n')
    report=path/'report.py'; report.write_text(report.read_text()+'\n# '+marker+'\n')
    response=rpc(actor,{'op':'checkpoint','workspace':workspace,'expected_generation':expected_generation,'operation_id':f'{workspace}-private-checkpoint'})
    if not response.get('ok'): return {'ok':False,'private_checkpoint':response}
    (path/'PRIVATE_WIP.txt').write_text(marker+'\nUNSAVED_PRIVATE_WIP_AFTER_CHECKPOINT\n')
    files={str(f.relative_to(path)):hashlib.sha256(f.read_bytes()).hexdigest() for f in (report,path/'PRIVATE_WIP.txt',path/'local'/'excluded.txt')}
    evidence={'kind':'private_manifest','actor':actor,'workspace':workspace,'wave':wave,'created_at':now(),'marker':marker,'files':files,'private_checkpoint':response}
    save(ROOT/f'{workspace}-private.json',evidence); log(actor,evidence)
    return {'ok':True,**evidence}

if __name__=='__main__':
    actor, command, *args=sys.argv[1:]
    assert actor in ('actor-a','actor-b','actor-c','actor-d')
    if command=='rpc': result=rpc(actor,json.loads(args[0]))
    elif command=='test': result=tests(actor,args[0])
    elif command=='seal': result=seal(actor,args[0],int(args[1]),int(args[2]))
    elif command=='wave':
        result=json.loads(args[0]); result.update(actor=actor,recorded_at=now(),recorded_epoch=time.time())
        log(actor,{'kind':'wave',**result}); save(ROOT/f'{actor}-progress.json',result)
    elif command=='done':
        result=json.loads(args[0]); result.update(actor=actor,finished_at=now(),finished_epoch=time.time())
        log(actor,{'kind':'done',**result}); save(ROOT/f'{actor}.done.json',result)
    elif command=='note': result={'kind':'note','text':' '.join(args)}; log(actor,result)
    else: raise ValueError(command)
    print(json.dumps(result,indent=2))
