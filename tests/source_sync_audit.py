#!/usr/bin/env python3
"""Second independent post-run audit of every public blob/commit, not only final trees."""
import hashlib,json,pathlib,sqlite3,subprocess,sys
base=pathlib.Path(sys.argv[1]);rows=[];inodes={}
def git(repo,*args):return subprocess.run(['git','--git-dir',str(repo),*args],capture_output=True,check=True).stdout
for repo in sorted(base.rglob('coordinator.git')):
    if any(x.startswith('legacy') or x == 'regressions' for x in repo.relative_to(base).parts):continue
    state=repo.parent;assert not (repo/'objects/info/alternates').exists()
    objects=git(repo,'cat-file','--batch-all-objects','--batch-check=%(objectname) %(objecttype)').decode().splitlines();blobs=commits=0
    for line in objects:
        oid,kind=line.split();body=git(repo,'cat-file',kind,oid)
        if kind=='blob':
            blobs+=1
            for marker in (b'NOT_A_REAL_SECRET_',b'private synthetic ',b'PRIVATE_ONLY_',b'PRIVATE_ANCESTRY_ONLY'):assert marker not in body,(str(repo),oid,marker)
        if kind=='commit':
            commits+=1;message=body.split(b'\n\n',1)[1]
            assert message.rstrip(b'\n')==b'Wipstash initial public import' or message.startswith((b'proposal ',b'Wipstash integration\n')),(str(repo),oid,message)
    for file in (repo/'objects').rglob('*'):
        if file.is_file():
            inode=(file.stat().st_dev,file.stat().st_ino);assert inode not in inodes,(str(file),inodes.get(inode));inodes[inode]=str(file)
    db=sqlite3.connect(state/'state.sqlite');assert db.execute('pragma integrity_check').fetchall()==[('ok',)];db.close()
    rows.append({'repo':str(repo.relative_to(base)),'objects':len(objects),'blobs_checked':blobs,'public_commits_checked':commits,'objects_listing_sha256':hashlib.sha256('\n'.join(objects).encode()).hexdigest()})
result={'successful':True,'stores':len(rows),'objects_checked':sum(r['objects'] for r in rows),'blobs_checked':sum(r['blobs_checked'] for r in rows),'public_commits_checked':sum(r['public_commits_checked'] for r in rows),'distinct_object_file_inodes':len(inodes),'scope':'All objects, including unreachable objects, in all source-sync public authority/client-cache stores; no cross-store object hardlinks or alternates; private checkpoint source/canary markers absent. Retained raw stores required for rerun.','details':rows}
(base/'public-store-audit.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps({k:v for k,v in result.items() if k!='details'}))
