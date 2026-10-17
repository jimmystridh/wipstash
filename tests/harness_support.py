"""Independent real-process tests. Actors are scripted personas, not AI sessions."""
from pathlib import Path
import hashlib,json,os,shutil,subprocess,time
from concurrent.futures import ThreadPoolExecutor
FIXTURE=Path(__file__).parent/'fixtures'/'base'
class Harness:
    def __init__(self,binary,root):
        self.binary=str(Path(binary).resolve());self.root=Path(root).resolve()
        self.root.mkdir(parents=True,exist_ok=True);self.events=[]
    def command(self,args,*,env=None,ok=True,cwd=None):
        started=time.monotonic()
        p=subprocess.run([str(x) for x in args],cwd=cwd,env=dict(os.environ,**(env or {})),capture_output=True,text=True,errors="replace",timeout=40)
        event={'argv':[str(x) for x in args],'exit':p.returncode,'stdout':p.stdout,'stderr':p.stderr,'seconds':time.monotonic()-started}
        self.events.append(event)
        if ok and p.returncode: raise AssertionError(json.dumps(event,indent=2))
        return p
    def call(self,*args,**kwargs):
        p=self.command([self.binary,*args],**kwargs)
        try:return json.loads(p.stdout)
        except ValueError:
            if not kwargs.get('ok',True):return {'exit':p.returncode,'stdout':p.stdout,'stderr':p.stderr}
            raise AssertionError(f'Not a JSON reply: {p.stdout!r}; {p.stderr!r}')
    def parallel(self,functions):
        with ThreadPoolExecutor(max_workers=4) as e:return list(e.map(lambda f:f(),functions))
    def git(self,repo,*args):return self.command(['git','--git-dir',str(repo),*args]).stdout.strip()
    def save_log(self):
        (self.root/'commands.json').write_text(json.dumps(self.events,indent=2)+'\n')
    def fixture(self,dest):
        shutil.copytree(FIXTURE,dest)
        return Path(dest)
def manifest(root,exclude=()):
    root=Path(root)
    return {str(p.relative_to(root)):{'sha256':hashlib.sha256(p.read_bytes()).hexdigest(),'mode':p.stat().st_mode&0o777}
        for p in sorted(root.rglob('*')) if p.is_file() and not any(x in p.relative_to(root).parts for x in exclude)}
def write(root,path,data):
    p=Path(root)/path;p.parent.mkdir(parents=True,exist_ok=True)
    p.write_bytes(data.encode() if isinstance(data,str) else data)
def canaries(root,actor):
    write(root,'.env',f'NOT_A_REAL_SECRET_{actor}\n')
    write(root,'local/keep.bin',actor.encode()*32)
    write(root,'build/cache.bin',b'cache-'+actor.encode())
    write(root,'.agent/session.txt',f'private synthetic {actor}\n')
