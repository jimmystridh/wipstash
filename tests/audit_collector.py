#!/usr/bin/env python3
"""Audit native activity using synthetic histories and the real Wipstash engine."""
import importlib.util
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
BINARY = Path(os.environ.get("WIPSTASH_ENGINE", ROOT / "target/debug/wipstash")).resolve()
SPEC = importlib.util.spec_from_file_location("collector", ROOT / "scripts/wipstash-audit-collector.py")
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class AuditCollector(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="wipstash-audit-")
        self.root = Path(self.tmp.name).resolve()
        self.home, self.state, self.workspace = [self.root / name for name in ("home", "state", "workspace")]
        source = self.root / "source"
        source.mkdir()
        (source / "file.txt").write_text("initial\n")
        self.cli(op="init", source=str(source))
        self.cli(op="clone", workspace="agent-A", path=str(self.workspace), operation_id="clone")
        self.collector = MODULE.Collector(BINARY, self.state, self.home)
        self.addCleanup(self.tmp.cleanup)
        self.addCleanup(self.collector.db.close)

    def cli(self, **request):
        completed = subprocess.run([str(BINARY), "--state", str(self.state), json.dumps(request)], capture_output=True, text=True)
        value = json.loads(completed.stdout)
        self.assertTrue(value["ok"], value)
        return value

    def history(self, name, rows):
        roots = {"codex": ".codex/sessions", "claude": ".claude/projects", "pi": ".pi/agent/sessions"}
        path = self.home / roots[name] / "session.jsonl"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("".join(json.dumps(row) + "\n" for row in rows))
        return path

    def reports(self):
        with sqlite3.connect(self.state / "audit.sqlite") as db:
            return [json.loads(row[0]) for row in db.execute("SELECT entry FROM audit_server ORDER BY sequence")
                    if json.loads(row[0])["record"]["data"].get("origin") == "agent_reported"]

    def test_nested_json_schemas_are_action_data(self):
        schema = {"type": {"type": "string"}, "role": {"type": "string"}}
        self.assertEqual(MODULE.safe(schema), schema)
        self.history("codex", [{"type": "session_meta", "payload": {"cwd": str(self.workspace), "session_id": "schema"}},
                               {"type": "response_item", "payload": {"type": "function_call", "arguments": {"schema": schema}}}])
        self.assertTrue(self.collector.scan()["ok"])
        self.assertIn('"schema"', json.dumps(self.reports()))

    def test_four_clients_and_tool_inputs_results_are_recorded_once(self):
        self.history("codex", [{"type": "session_meta", "payload": {"cwd": str(self.workspace), "session_id": "codex-1", "base_instructions": "private"}},
                               {"type": "response_item", "payload": {"type": "function_call", "name": "exec_command", "arguments": "test command"}},
                               {"type": "response_item", "payload": {"type": "function_call_output", "output": "test output"}}])
        self.history("claude", [{"cwd": str(self.workspace), "sessionId": "claude-1", "message": {"role": "assistant", "content": [{"type": "thinking", "thinking": "private"}, {"type": "tool_use", "name": "Edit", "input": {"new_string": "patch"}}]}},
                                {"message": {"role": "user", "content": [{"type": "tool_result", "content": "edited"}]}}])
        self.history("pi", [{"type": "session", "id": "pi-1", "cwd": str(self.workspace)},
                            {"type": "message", "message": {"role": "toolResult", "content": [{"type": "text", "text": "pi output"}]}}])
        path = self.home / ".local/share/opencode/opencode.db"
        path.parent.mkdir(parents=True)
        with sqlite3.connect(path) as db:
            db.executescript("CREATE TABLE session(id TEXT,directory TEXT); CREATE TABLE message(id TEXT,session_id TEXT,time_created INTEGER,time_updated INTEGER,data TEXT); CREATE TABLE part(id TEXT,session_id TEXT,time_created INTEGER,time_updated INTEGER,data TEXT);")
            db.execute("INSERT INTO session VALUES('open-1',?)", [str(self.workspace)])
            db.execute("INSERT INTO part VALUES('p','open-1',1,2,?)", [json.dumps({"type": "tool", "tool": "bash", "state": {"status": "completed", "input": {"command": "tests"}, "output": "passed"}})])
        result = self.collector.scan()
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["clients"], dict(codex=1, claude=1, pi=1, opencode=1))
        records = self.reports()
        text = json.dumps(records)
        for expected in ("test command", "test output", "patch", "pi output", "passed"):
            self.assertIn(expected, text)
        self.assertNotIn('"base_instructions"', text)
        self.assertNotIn('"thinking"', text)
        self.assertTrue(all(row["origin"] == "agent_reported" for row in records))
        self.collector.scan()
        self.assertEqual(self.reports(), records)
        self.assertTrue(self.cli(op="audit_verify")["ok"])

    def test_unowned_sessions_are_excluded_and_partial_lines_wait(self):
        path = self.history("codex", [{"type": "session_meta", "payload": {"cwd": str(self.workspace), "session_id": "session"}}])
        other = self.history("pi", [{"type": "session", "id": "private", "cwd": str(self.root)}, {"private": "unrelated"}])
        with path.open("ab") as stream:
            stream.write(b'{"type":"response_item","payload":"pending"}')
        self.collector.scan()
        self.assertNotIn("pending", json.dumps(self.reports()))
        self.assertNotIn("unrelated", json.dumps(self.reports()))
        with path.open("ab") as stream:
            stream.write(b"\n")
        self.collector.scan()
        self.assertIn("pending", json.dumps(self.reports()))
        self.assertEqual(self.collector.db.execute("SELECT COUNT(*) FROM files WHERE path=?", [str(other)]).fetchone()[0], 0)

    def test_failed_write_does_not_advance_cursor_and_is_reported(self):
        path = self.history("pi", [{"type": "session", "id": "p", "cwd": str(self.workspace)}])
        with mock.patch.object(self.collector, "send", side_effect=RuntimeError("delivery_failed")):
            failed = self.collector.scan()
        self.assertFalse(failed["ok"])
        self.assertEqual(self.collector.db.execute("SELECT offset FROM files WHERE path=?", [str(path)]).fetchone()[0], 0)
        self.assertTrue(self.collector.scan()["ok"])
        self.assertGreater(self.collector.db.execute("SELECT offset FROM files WHERE path=?", [str(path)]).fetchone()[0], 0)
        path.write_text("")
        failed = self.collector.scan()
        self.assertFalse(failed["ok"])
        self.assertIn("truncated", json.dumps(failed))
        path.unlink()
        self.assertIn("native_history_missing", json.dumps(self.collector.scan()))

    def test_private_messages_and_unowned_history_segments_are_omitted(self):
        path = self.history("codex", [{"type": "session_meta", "payload": {"cwd": str(self.workspace), "session_id": "c"}},
                                     {"type": "response_item", "payload": {"type": "message", "role": "developer", "content": "private instructions"}},
                                     {"type": "response_item", "payload": {"type": "reasoning", "content": "private reasoning"}},
                                     {"type": "event_msg", "payload": {"type": "agent_reasoning", "text": "private reasoning"}},
                                     {"type": "response_item", "payload": {"role": "assistant", "channel": "analysis", "content": "private reasoning"}}])
        self.assertTrue(self.collector.scan()["ok"])
        self.assertNotIn("private instructions", json.dumps(self.reports()))
        self.assertNotIn("private reasoning", json.dumps(self.reports()))
        with path.open("a") as stream:
            stream.write(json.dumps({"cwd": str(self.root), "tool": "unrelated"}) + "\n")
        self.assertTrue(self.collector.scan()["ok"])
        reports = json.dumps(self.reports())
        self.assertNotIn('"tool": "unrelated"', reports)
        self.assertIn("scope_transition", reports)
        with path.open("a") as stream:
            stream.write(json.dumps({"cwd": str(self.workspace), "tool": "returned"}) + "\n")
        self.assertTrue(self.collector.scan()["ok"])
        self.assertIn("returned", json.dumps(self.reports()))

    def test_resumed_session_can_enter_the_project_after_unrelated_history(self):
        path = self.history("claude", [{"cwd": str(self.root), "sessionId": "resumed", "private": "unrelated earlier task"}] * 150 +
                            [{"cwd": str(self.workspace), "sessionId": "resumed", "message": {"role": "assistant", "content": "project activity"}}])
        self.assertTrue(self.collector.scan()["ok"])
        reports = json.dumps(self.reports())
        self.assertNotIn("unrelated earlier task", reports)
        self.assertIn("project activity", reports)


if __name__ == "__main__":
    unittest.main()
