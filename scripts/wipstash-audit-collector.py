#!/usr/bin/env python3
"""Forward persisted native client activity for this Wipstash project's workspaces."""
import argparse
import hashlib
import json
import os
import re
from pathlib import Path
import signal
import sqlite3
import subprocess
import sys
import time

MAX_LINE = 16 * 1024 * 1024
CWD_FIELD = re.compile(rb'"cwd"\s*:\s*("(?:[^"\\]|\\.)*")')
IGNORED = ("thinking", "reasoning", "redacted_thinking", "encrypted_content", "agent_reasoning", "agent_reasoning_raw_content")


def encoded(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def digest(value):
    return hashlib.sha256(value.encode()).hexdigest()


def safe(value):
    if isinstance(value, dict):
        if value.get("type") in IGNORED or value.get("role") in ("system", "developer") or value.get("channel") == "analysis":
            return {"type": "private_content_omitted"}
        return {k: safe(v) for k, v in value.items() if k not in IGNORED and k not in {
            "base_instructions", "reasoning_content", "internal_chat_message_metadata_passthrough"}}
    if isinstance(value, list):
        return [safe(v) for v in value if not isinstance(v, dict) or v.get("type") not in IGNORED]
    return value


def event_name(agent, value):
    content = value.get("payload", value)
    kind = content.get("type", value.get("type", "activity")) if isinstance(content, dict) else "activity"
    if kind in ("function_call", "custom_tool_call"):
        return "tool_call", "started"
    if kind in ("function_call_output", "custom_tool_call_output", "tool_result"):
        return "tool_call", "completed"
    message = value.get("message", {})
    if isinstance(message, dict):
        if message.get("role") in ("toolResult", "tool"):
            return "tool_call", "failed" if message.get("isError") else "completed"
        blocks = message.get("content", [])
        if isinstance(blocks, list):
            if any(isinstance(b, dict) and b.get("type") in ("tool_use", "toolCall") for b in blocks):
                return "tool_call", "started"
            results = [b for b in blocks if isinstance(b, dict) and b.get("type") == "tool_result"]
            if results:
                return "tool_call", "failed" if any(b.get("is_error") for b in results) else "completed"
    if agent == "opencode" and kind == "tool":
        state = content.get("state", {})
        status = state.get("status") if isinstance(state, dict) else None
        return "tool_call", {"completed": "completed", "error": "failed"}.get(status if isinstance(status, str) else "", "started")
    return "session_activity", "recorded"


class Collector:
    def __init__(self, binary, state, home):
        self.binary, self.state, self.home = Path(binary).resolve(), Path(state).resolve(), Path(home).resolve()
        self.state.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(self.state / "audit-collector.sqlite", timeout=30)
        os.chmod(self.state / "audit-collector.sqlite", 0o600)
        self.db.executescript("""PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;
        CREATE TABLE IF NOT EXISTS files(path TEXT PRIMARY KEY,inode TEXT NOT NULL,offset INTEGER NOT NULL,workspace TEXT NOT NULL,session TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS revisions(source TEXT PRIMARY KEY,digest TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS health(source TEXT PRIMARY KEY,checked_at REAL NOT NULL,error TEXT);
        """)
        self.roots = {}
        self.cwd_cache = {}
        self.unowned = {}
        self.last_report = None
        self.last_report_at = 0

    def workspace(self, path):
        if not path or not isinstance(path, str):
            return None
        if path not in self.cwd_cache:
            candidate = Path(path).resolve()
            # Directory ownership is exact. Ancestor projects and unrelated sessions stay out.
            self.cwd_cache[path] = self.roots.get(str(candidate))
        return self.cwd_cache[path]

    def owned_roots(self):
        path = self.state / "state.sqlite"
        with sqlite3.connect(path.as_uri() + "?mode=ro", uri=True, timeout=30) as db:
            roots = {str(Path(path).resolve()): identity for identity, path in db.execute("SELECT id,path FROM workspaces")}
            if roots != self.roots:
                self.cwd_cache.clear()
            self.roots = roots

    def send(self, agent, session, workspace, key, payload):
        cleaned = safe(payload)
        nested = cleaned.get("payload")
        if cleaned.get("type") == "private_content_omitted" or (isinstance(nested, dict) and nested.get("type") == "private_content_omitted"):
            return
        action, phase = event_name(agent, cleaned)
        body = {"event_id": "native-" + digest(key), "agent": agent, "session_id": session,
                "workspace": workspace, "action": action, "phase": phase,
                "client_time": cleaned.get("timestamp"), "payload": cleaned}
        complete = subprocess.run([str(self.binary), "--state", str(self.state), "audit-record"],
                                  input=encoded(body), capture_output=True, text=True, timeout=90)
        try:
            reply = json.loads(complete.stdout)
        except ValueError as error:
            raise RuntimeError("audit_record_response_invalid") from error
        if complete.returncode or reply.get("ok") is not True:
            raise RuntimeError("audit_record_not_acknowledged")

    def health(self, source, error=None):
        self.db.execute("INSERT INTO health VALUES(?,?,?) ON CONFLICT(source) DO UPDATE SET checked_at=excluded.checked_at,error=excluded.error",
                        (source, time.time(), str(error) if error else None))
        self.db.commit()

    def jsonl(self, agent, path, hinted_workspace=None):
        source = str(path)
        previous = self.db.execute("SELECT inode,offset,workspace,session FROM files WHERE path=?", [source]).fetchone()
        stat = path.stat()
        inode = str(stat.st_ino)
        offset, workspace, session = 0, hinted_workspace, path.stem
        if previous:
            old_inode, offset, workspace, session = previous
            if workspace not in self.roots.values():
                workspace = ""
            if inode != old_inode or stat.st_size < offset:
                raise RuntimeError("native_history_rotated_or_truncated")
        if not previous and self.unowned.get(source) == (inode, stat.st_size, stat.st_mtime_ns, tuple(sorted(self.roots))):
            return False
        with path.open("rb") as stream:
            if not previous and not workspace:
                # A resumed session can enter this project long after its first record.
                while True:
                    start = stream.tell()
                    line = stream.readline(MAX_LINE + 1)
                    if not line:
                        break
                    if len(line) > MAX_LINE:
                        raise RuntimeError("native_record_bound")
                    try:
                        if not any(self.workspace(json.loads(match.group(1))) for match in CWD_FIELD.finditer(line)):
                            continue
                        value = json.loads(line)
                    except (ValueError, UnicodeDecodeError):
                        continue
                    if not isinstance(value, dict):
                        continue
                    metadata = value.get("payload", {}) if value.get("type") == "session_meta" else value
                    if not isinstance(metadata, dict):
                        continue
                    workspace = self.workspace(metadata.get("cwd"))
                    if workspace:
                        session = str(metadata.get("session_id") or metadata.get("sessionId") or metadata.get("id") or path.stem)
                        offset = start
                        break
                if not workspace:
                    self.unowned[source] = (inode, stat.st_size, stat.st_mtime_ns, tuple(sorted(self.roots)))
                    return False
            self.db.execute("INSERT OR IGNORE INTO files VALUES(?,?,?,?,?)", (source, inode, offset, workspace, session))
            self.db.commit()
            stream.seek(offset)
            while True:
                start = stream.tell()
                line = stream.readline(MAX_LINE + 1)
                if not line:
                    break
                if len(line) > MAX_LINE:
                    raise RuntimeError("native_record_bound")
                if not line.endswith(b"\n"):
                    break  # A live writer has not finished this record yet.
                try:
                    value = json.loads(line)
                except (ValueError, UnicodeDecodeError) as error:
                    raise RuntimeError("native_record_invalid") from error
                if not isinstance(value, dict):
                    raise RuntimeError("native_record_invalid")
                cwd = value.get("cwd") or (value.get("payload", {}).get("cwd") if isinstance(value.get("payload"), dict) else None)
                key = f"{agent}:{session}:{source}:{start}:{hashlib.sha256(line).hexdigest()}"
                if cwd:
                    current = self.workspace(cwd) or ""
                    if workspace and current != workspace:
                        self.send(agent, session, workspace, key + ":scope", {"type": "scope_transition", "from_workspace": workspace, "to_workspace": current or None})
                    workspace = current
                if workspace:
                    self.send(agent, session, workspace, key, value)
                offset = stream.tell()
                self.db.execute("INSERT INTO files VALUES(?,?,?,?,?) ON CONFLICT(path) DO UPDATE SET inode=excluded.inode,offset=excluded.offset,workspace=excluded.workspace,session=excluded.session",
                                (source, inode, offset, workspace, session))
                self.db.commit()  # Advance only after durable local acceptance; retry IDs stay identical.
        self.health(source)
        return True

    def opencode(self, path):
        with sqlite3.connect(path.as_uri() + "?mode=ro", uri=True, timeout=30) as db:
            sessions = [(sid, directory) for sid, directory in db.execute("SELECT id,directory FROM session") if self.workspace(directory)]
            for session, directory in sessions:
                workspace = self.workspace(directory)
                for table in ("message", "part"):
                    for identity, updated, raw in db.execute(f"SELECT id,time_updated,data FROM {table} WHERE session_id=? ORDER BY time_created,id", [session]):
                        source = f"opencode:{table}:{identity}"
                        version = digest(raw)
                        old = self.db.execute("SELECT digest FROM revisions WHERE source=?", [source]).fetchone()
                        if old and old[0] == version:
                            continue
                        value = json.loads(raw)
                        payload = {"type": "native_" + table, "source_id": identity, "updated_at": updated, "payload": value}
                        self.send("opencode", session, workspace, f"{source}:{updated}:{version}", payload)
                        self.db.execute("INSERT INTO revisions VALUES(?,?) ON CONFLICT(source) DO UPDATE SET digest=excluded.digest", (source, version))
                        self.db.commit()
        self.health(str(path))
        return len(sessions)

    def scan(self):
        self.owned_roots()
        matched = {name: 0 for name in ("codex", "claude", "pi", "opencode")}
        directories = {"codex": self.home / ".codex/sessions", "claude": self.home / ".claude/projects", "pi": self.home / ".pi/agent/sessions"}
        errors = []
        for agent, directory in directories.items():
            for path in directory.rglob("*.jsonl"):
                if path.is_symlink() or not path.is_file():
                    continue
                try:
                    if self.jsonl(agent, path):
                        matched[agent] += 1
                except (OSError, ValueError, TypeError, RuntimeError, subprocess.SubprocessError) as error:
                    # Do not report unrelated history as project coverage errors.
                    if self.db.execute("SELECT 1 FROM files WHERE path=?", [str(path)]).fetchone():
                        self.health(str(path), error)
                        errors.append({"source": str(path), "error": str(error)})
        for (known,) in self.db.execute("SELECT path FROM files").fetchall():
            if not Path(known).is_file():
                self.health(known, "native_history_missing")
                errors.append({"source": known, "error": "native_history_missing"})
        path = self.home / ".local/share/opencode/opencode.db"
        if path.is_file() and not path.is_symlink():
            try:
                matched["opencode"] = self.opencode(path)
            except (OSError, ValueError, TypeError, RuntimeError, sqlite3.Error, subprocess.SubprocessError) as error:
                self.health(str(path), error)
                errors.append({"source": str(path), "error": str(error)})
        result = {"ok": not errors, "clients": matched, "errors": errors, "checked_at": time.time(),
                  "scope": "persisted_native_history_for_registered_workspaces"}
        report = encoded({k: v for k, v in result.items() if k != "checked_at"})
        if report != self.last_report or time.time() - self.last_report_at >= 30:
            try:
                self.send("collector", "collector", "project", f"coverage:{encoded(result)}", {"type": "collection_coverage", **result})
                self.last_report, self.last_report_at = report, time.time()
            except (OSError, ValueError, TypeError, RuntimeError, subprocess.SubprocessError) as error:
                result["ok"] = False
                result["errors"].append({"source": "collector", "error": str(error)})
        return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True)
    parser.add_argument("--state", required=True)
    parser.add_argument("--home", default=str(Path.home()))
    parser.add_argument("--once", action="store_true")
    parser.add_argument("--interval", type=float, default=2)
    args = parser.parse_args()
    if args.interval < 1:
        parser.error("interval must be at least one second")
    state = Path(args.state).resolve()
    state.mkdir(parents=True, exist_ok=True)
    os.umask(0o077)
    with (state / "audit-collector.lock").open("a+") as lock:
        try:
            if os.name == "nt":
                import msvcrt
                lock.write("0"); lock.flush(); lock.seek(0)
                msvcrt.locking(lock.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            raise SystemExit("audit_collector_already_running")
        collector = Collector(args.binary, state, args.home)
        running = True
        def stop(*_):
            nonlocal running
            running = False
        signal.signal(signal.SIGTERM, stop)
        signal.signal(signal.SIGINT, stop)
        while running:
            try:
                result = collector.scan()
            except (OSError, ValueError, TypeError, RuntimeError, sqlite3.Error, subprocess.SubprocessError) as error:
                result = {"ok": False, "errors": [{"source": "collector", "error": str(error)}], "checked_at": time.time()}
            status = state / "audit-collector-status.json"
            pending = status.with_suffix(".tmp")
            pending.write_text(encoded(result) + "\n")
            with pending.open("rb") as stream:
                os.fsync(stream.fileno())
            os.replace(pending, status)
            if os.name != "nt":
                directory = os.open(state, os.O_RDONLY)
                try:
                    os.fsync(directory)
                finally:
                    os.close(directory)
            if args.once:
                print(encoded(result))
                return
            for _ in range(int(args.interval * 10)):
                if not running:
                    break
                time.sleep(.1)


if __name__ == "__main__":
    main()
