#!/usr/bin/env -S uv run --python 3.12 --with tomlkit --script
"""Migrate this provisioned desktop installation to the standalone wip CLI."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shlex
import shutil
import signal
import sqlite3
import subprocess
import time
import tomlkit

CLIENTS = ('codex', 'opencode', 'claude', 'pi')
HOME_DIR = Path.home()
DESKTOP = HOME_DIR / '.local/share/wipstash/desktop-20261018'
CLOUD = HOME_DIR / '.local/share/wipstash/cloudrun-20261019-b'
EXCLUDED = {'.wip', '.agent', '.agents', '.git', 'node_modules', 'target', '__pycache__', '.venv', '.cache'}


def write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    pending = path.with_name(path.name + '.pending')
    pending.write_text(json.dumps(value, indent=2) + '\n')
    pending.chmod(0o600)
    pending.replace(path)


def invoke(binary, *args, cwd=None, codes=(0,)):
    completed = subprocess.run([str(binary), '--json', *map(str, args)], cwd=cwd, capture_output=True, text=True, timeout=240)
    if completed.returncode not in codes:
        raise RuntimeError(f'CLI {args[0]} failed: {completed.stdout[-3000:]} {completed.stderr[-500:]}')
    return json.loads(completed.stdout)


def states():
    result = [(DESKTOP/'demo/state', None), (HOME_DIR/'.local/share/wipstash/local/state', None)]
    result += [(CLOUD/'devices'/client/'state', 'cloud-' + client) for client in CLIENTS]
    return [(state, profile) for state, profile in result if (state/'state.sqlite').is_file()]


def inventory():
    result = []
    for state, profile in states():
        with sqlite3.connect(state/'state.sqlite') as db:
            workspaces = [{'workspace': wid, 'path': path, 'generation': generation, 'exists': Path(path).is_dir()}
                          for wid, path, generation in db.execute('SELECT id,path,generation FROM workspaces')]
            has_receipts = db.execute("SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='sync_remote_status')").fetchone()[0]
            query = ("SELECT p.id FROM proposals p LEFT JOIN sync_remote_status s ON s.proposal=p.id WHERE COALESCE(json_extract(s.receipt,'$.state'),p.state) IN ('local_queued','coordinator_accepted')"
                     if has_receipts else "SELECT id FROM proposals WHERE state IN ('local_queued','coordinator_accepted')")
            pending = [row[0] for row in db.execute(query)]
        result.append({'state': str(state), 'profile': profile, 'workspaces': workspaces, 'pending': pending})
    return result


def source_manifest(workspaces):
    result = {}
    for workspace in workspaces:
        root = Path(workspace['path'])
        if not root.is_dir():
            continue
        files = {}
        for directory, children, names in os.walk(root, followlinks=False):
            children[:] = [name for name in children if name not in EXCLUDED]
            for name in names:
                file = Path(directory)/name
                if file.is_symlink():
                    files[str(file.relative_to(root))] = {'symlink': os.readlink(file)}
                elif file.is_file():
                    hasher = hashlib.sha256()
                    with file.open('rb') as stream:
                        while block := stream.read(1024*1024):
                            hasher.update(block)
                    files[str(file.relative_to(root))] = {'sha256': hasher.hexdigest(), 'mode': file.stat().st_mode & 0o777}
        result[str(root)] = files
    return result


def backup_file(source, backup):
    if not source.exists() and not source.is_symlink():
        return
    target = backup/'files'/source.relative_to(HOME_DIR)
    target.parent.mkdir(parents=True, exist_ok=True)
    if source.is_symlink():
        if not target.is_symlink():
            target.symlink_to(os.readlink(source))
    else:
        shutil.copy2(source, target)
        target.chmod(0o600)


def remove_servers(value):
    changed = False
    if isinstance(value, dict):
        for key, child in list(value.items()):
            if key in ('mcpServers', 'mcp', 'servers') and isinstance(child, dict) and 'wipstash' in child:
                del child['wipstash']
                changed = True
            if isinstance(child, (dict, list)):
                changed = remove_servers(child) or changed
    elif isinstance(value, list):
        for item in value:
            if isinstance(item, (dict, list)):
                changed = remove_servers(item) or changed
    return changed


def retire_mcp(backup):
    codex = HOME_DIR/'.codex/config.toml'
    backup_file(codex, backup)
    document = tomlkit.parse(codex.read_text())
    before = json.loads(json.dumps(document.unwrap()))
    document.get('mcp_servers', {}).pop('wipstash', None)
    expected = dict(before.get('mcp_servers', {})); expected.pop('wipstash', None)
    assert document.unwrap().get('mcp_servers', {}) == expected
    pending = codex.with_suffix('.cli-migration.pending')
    pending.write_text(tomlkit.dumps(document)); pending.chmod(0o600); pending.replace(codex)
    for path in [HOME_DIR/'.claude.json', HOME_DIR/'.config/opencode/opencode.jsonc',
                 HOME_DIR/'.pi/agent/mcp.json', HOME_DIR/'.pi/agent/mcp-cache.json']:
        if path.is_file():
            original = json.loads(path.read_text())
            if remove_servers(original):
                backup_file(path, backup)
                write(path, original)


def processes():
    rows = subprocess.check_output(['ps', '-axo', 'pid=,command='], text=True)
    found = []
    for line in rows.splitlines():
        try:
            number, command = line.strip().split(None, 1)
            argv = shlex.split(command)
        except ValueError:
            continue
        if not argv:
            continue
        kind = None
        if argv[0].endswith('/wipstash') and argv[-1:] == ['mcp'] and '--state' in argv:
            kind = 'mcp'
        elif Path(argv[0]).name in ('uv', 'python', 'python3', 'python3.12', 'python3.13') and any(item.endswith('/wipstash-audit-collector.py') and (item.startswith(str(DESKTOP)+'/') or item.startswith(str(CLOUD)+'/')) for item in argv):
            kind = 'collector'
        elif argv[0] == str(CLOUD/'bin/wipstash-transport') and len(argv)>1 and argv[1]=='worker':
            kind = 'client_worker'
        if kind:
            found.append({'pid': int(number), 'kind': kind, 'executable': argv[0]})
    return found


def stop_clients(backup):
    for path in (HOME_DIR/'Library/LaunchAgents').glob('com.wipstash.cloudrun.*.plist'):
        backup_file(path, backup)
        subprocess.run(['launchctl', 'bootout', f'gui/{os.getuid()}', str(path)], capture_output=True)
        path.unlink()
    targets = processes()
    for process in targets:
        try:
            os.kill(process['pid'], signal.SIGTERM)
        except ProcessLookupError:
            pass
    deadline = time.monotonic()+30
    while processes() and time.monotonic()<deadline:
        time.sleep(1)
    # Raw histories and per-record offsets remain durable if an import was interrupted.
    for process in processes():
        if process['kind'] in ('collector', 'client_worker', 'mcp'):
            try:
                os.kill(process['pid'], signal.SIGKILL)
            except ProcessLookupError:
                pass
    return targets


def install(binary, backup):
    destination = HOME_DIR/'.local/share/wip/bin/wip'
    destination.parent.mkdir(parents=True, exist_ok=True)
    pending = destination.with_suffix('.pending')
    shutil.copyfile(binary, pending); pending.chmod(0o700); pending.replace(destination)
    link = HOME_DIR/'.local/bin/wip'
    if link.exists() or link.is_symlink():
        if link.resolve() != destination.resolve():
            raise RuntimeError('An unrelated wip executable already occupies ~/.local/bin/wip')
    else:
        link.symlink_to(destination)
    for root in [DESKTOP, CLOUD]:
        old = root/'bin/wipstash'
        replacement = binary.with_name('wipstash')
        if old.is_file() and replacement.is_file():
            backup_file(old, backup)
            pending = old.with_suffix('.pending')
            shutil.copyfile(replacement, pending); pending.chmod(0o700); pending.replace(old)
    return destination


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, default=Path('target/release/wip'))
    parser.add_argument('--apply', action='store_true')
    parser.add_argument('--backup', type=Path, required=True)
    args = parser.parse_args()
    os.umask(0o077)
    before = inventory()
    if not args.apply:
        print(json.dumps({'inventory': before, 'client_processes': processes()}, indent=2)); return
    binary = args.binary.resolve()
    invoke(binary, 'remote', 'list')
    backup = args.backup.resolve(); backup.mkdir(parents=True, exist_ok=True)
    write(backup/'inventory-before.json', before)
    original_files = source_manifest([workspace for state in before for workspace in state['workspaces']])
    write(backup/'source-before.json', original_files)
    for index, item in enumerate(before):
        state = Path(item['state'])
        destination = backup/'states'/str(index); destination.mkdir(parents=True, exist_ok=True)
        for name in ['state.sqlite', 'audit.sqlite', 'audit-collector.sqlite']:
            if (state/name).is_file():
                with sqlite3.connect(state/name) as original, sqlite3.connect(destination/name) as copy:
                    original.backup(copy)
        if (state/'transport-outbox.json').exists():
            shutil.copy2(state/'transport-outbox.json', destination/'transport-outbox.json')
    installed = install(binary, backup)
    retire_mcp(backup)
    stopped = stop_clients(backup)
    for name in CLIENTS:
        profile = 'cloud-' + name
        known = invoke(installed, 'remote', 'list')['profiles']
        if not any(row['name']==profile for row in known):
            invoke(installed, 'remote', 'add', profile, '--config', CLOUD/'devices'/name/'client.json', *(['--default'] if name=='codex' else []))
    attached = []
    for item in before:
        for workspace in item['workspaces']:
            root = Path(workspace['path'])
            if not workspace['exists']:
                continue
            configured = root/'.wip/repo.json'
            if configured.exists():
                value = json.loads(configured.read_text())
                assert value['state']==item['state'] and value['workspace']==workspace['workspace']
            else:
                invoke(installed, '-C', root, 'attach', '--state', item['state'], '--workspace', workspace['workspace'],
                       *(['--profile', item['profile']] if item['profile'] else []))
            attached.append({'workspace': workspace['workspace'], 'path': str(root), 'state': item['state']})
    retired = [HOME_DIR/'.local/bin'/name for name in ['wipstash-agent', 'wipstash-cloud']]
    retired += [DESKTOP/'agent.py', CLOUD/'client/scripts/wipstash-agent.py']
    for path in retired:
        if path.exists() or path.is_symlink():
            backup_file(path, backup); path.unlink()
    canonical = HOME_DIR/'.codex/skills/wipstash-source-control/SKILL.md'
    backup_file(canonical, backup)
    shutil.copyfile(Path(__file__).resolve().parents[1]/'skills/wipstash-source-control/SKILL.md', canonical)
    after_files = source_manifest([workspace for state in before for workspace in state['workspaces']])
    write(backup/'source-after.json', after_files)
    changes = [path for path in set(original_files)|set(after_files) if original_files.get(path)!=after_files.get(path)]
    result={'installed':str(installed),'attached':attached,'stopped':stopped,'remaining_client_processes':processes(),
            'source_directories_changed':changes,'backup':str(backup),'operator_servers_retained':True}
    write(backup/'migration-result.json',result)
    print(json.dumps(result,indent=2))
    if changes:
        raise SystemExit('Concurrent source changes detected; inspect the preserved manifests before continuing.')
    if result['remaining_client_processes']:
        raise SystemExit('A client process is still active; inspect the preserved result.')


if __name__=='__main__':main()
