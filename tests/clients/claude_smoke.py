#!/usr/bin/env python3
"""Claude Code project config + actual stdio handshake; never invokes a model.

Usage: python3 tests/clients/claude_smoke.py --claude /absolute/path/to/claude
Only generated source and temporary HOME/config are used. Credentials are not inherited.
"""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]
p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--claude', required=True)
p.add_argument('--binary', default=str(ROOT / 'target/debug/wipstash'))
p.add_argument('--evidence', help='Write sanitized test result JSON')
a = p.parse_args()
claude = str(Path(a.claude).resolve())
binary = str(Path(a.binary).resolve())
with tempfile.TemporaryDirectory(prefix='wipstash-claude-') as tmp:
    root = Path(tmp)
    home, project, source, state = [root / x for x in ('home', 'project', 'source', 'state')]
    for directory in (home, project, source):
        directory.mkdir()
    (source / 'hello.txt').write_text('Synthetic Claude integration fixture.\n')
    env = {'PATH': os.environ.get('PATH', '/usr/bin:/bin'), 'HOME': str(home),
           'CLAUDE_CONFIG_DIR': str(home / '.claude'), 'DISABLE_AUTOUPDATER': '1',
           'DISABLE_UPDATES': '1', 'DISABLE_TELEMETRY': '1', 'DISABLE_ERROR_REPORTING': '1',
           'CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC': '1', 'MCP_TIMEOUT': '10000'}
    def run(args):
        r = subprocess.run(args, cwd=project, env=env, text=True, capture_output=True, timeout=35)
        assert r.returncode == 0, (args, r.returncode, r.stdout, r.stderr)
        return r.stdout
    initialized = json.loads(run([binary, '--state', str(state), json.dumps({'op':'init', 'source':str(source)})]))
    assert initialized['ok'], initialized
    # Transparent line relay captures what the REAL client sends and receives.
    proxy = root / 'relay.py'
    transcript = root / 'transcript.jsonl'
    proxy.write_text('''import json, subprocess, sys, threading
log = open(sys.argv[1], 'a', buffering=1)
lock = threading.Lock()
p = subprocess.Popen(sys.argv[2:], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
def record(direction, line):
    with lock:
        log.write(json.dumps({'direction':direction,'message':json.loads(line)}) + '\\n')
def incoming():
    for line in sys.stdin:
        record('client_to_server', line)
        p.stdin.write(line); p.stdin.flush()
    p.stdin.close()
threading.Thread(target=incoming, daemon=True).start()
for line in p.stdout:
    record('server_to_client', line)
    sys.stdout.write(line); sys.stdout.flush()
p.wait()
''')
    version = run([claude, '--version']).strip()
    added = run([claude, 'mcp', 'add', '--scope', 'project', '--transport', 'stdio', 'wipstash', '--', sys.executable, str(proxy), str(transcript), binary, '--state', str(state), 'mcp'])
    config = json.loads((project / '.mcp.json').read_text())
    assert config['mcpServers']['wipstash']['type'] == 'stdio', config
    pending = run([claude, 'mcp', 'get', 'wipstash'])
    assert 'Pending approval' in pending, pending
    assert not transcript.exists(), 'Unapproved project server was launched'
    # Explicitly approve ONLY this synthetic server via per-invocation settings.
    # This does not save approval in a real user configuration.
    connected = run([claude, '--settings', json.dumps({'enabledMcpjsonServers':['wipstash']}), 'mcp', 'get', 'wipstash'])
    assert 'Connected' in connected, connected
    messages = [json.loads(line) for line in transcript.read_text().splitlines()]
    requests = [m['message'] for m in messages if m['direction'] == 'client_to_server']
    methods = [m.get('method') for m in requests]
    assert 'initialize' in methods and 'notifications/initialized' in methods, methods
    init = next(m for m in requests if m.get('method') == 'initialize')
    response = next(m['message'] for m in messages if m['direction'] == 'server_to_client' and m['message'].get('id') == init['id'])
    assert response['result']['serverInfo']['name'] == 'wipstash-local-prototype', response
    assert response['result']['capabilities']['tools'] is not None, response
    discovery = next(m for m in requests if m.get('method') == 'tools/list')
    tools_reply = next(m['message'] for m in messages if m['direction'] == 'server_to_client' and m['message'].get('id') == discovery['id'])
    tool_names = sorted(t['name'] for t in tools_reply['result']['tools'])
    assert {'wipstash_status', 'wipstash_checkpoint', 'wipstash_publish', 'wipstash_adopt', 'wipstash_operation_status'} <= set(tool_names), tool_names
    result = {'client_version':version, 'config_scope':'project', 'unapproved_server_not_started':True,
              'health_status':'Connected', 'client_methods':methods, 'tool_names':tool_names, 'transcript':messages,
              'model_invoked':False, 'tool_workflow_tested':False,
              'limits':'Health check proves actual client initialization and tool discovery, not model-driven tool use.'}
    if a.evidence:
        Path(a.evidence).parent.mkdir(parents=True, exist_ok=True)
        Path(a.evidence).write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result, indent=2))
