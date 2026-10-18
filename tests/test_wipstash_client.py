#!/usr/bin/env python3
"""Deterministic fake-stdio client/protocol tests; no policy commands, sockets or kills.

Run: python3 -m unittest discover -s tests -p test_wipstash_client.py -v
Optional real stdio smoke: WIPSTASH_CLIENT_SMOKE_BINARY=/absolute/wipstash ...
The opt-in smoke uses synthetic init/open/checkpoint only, with no policy runner.
Set WIPSTASH_CLIENT_JOURNAL_BINARY to opt into real native-journal integration.
Fake journal tests verify sequencing/recovery, not filesystem security/durability;
the Rust client_journal tests own those native negative-path contracts.
"""

import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "wipstash_client", ROOT / "examples" / "clients" / "wipstash_client.py")
client_module = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(client_module)
WipstashClient = client_module.WipstashClient


def fake_server(root, journal, mode):
    """A real piped Python subprocess, deliberately not an engine/command runner."""
    root, journal = Path(root), Path(journal)
    trace = root / "trace.jsonl"
    saved = root / "server-results.json"
    outcomes = json.loads(saved.read_text()) if saved.exists() else {}
    phase = "new"

    def log(value):
        with trace.open("a") as stream:
            stream.write(json.dumps(value) + "\n")

    def reply(message, result):
        identifier = message["id"]
        if mode == "wrong-id" and message["method"] == "tools/call":
            identifier += 1
        print(json.dumps({"jsonrpc": "2.0", "id": identifier, "result": result}), flush=True)
        log({"reply": message["method"]})

    for raw in sys.stdin.buffer:
        message = json.loads(raw)
        method = message["method"]
        log({"method": method})
        if method == "initialize":
            assert phase == "new"
            phase = "initialized"
            reply(message, {"protocolVersion": "bad-version" if mode == "bad-version"
                           else client_module.PROTOCOL_VERSION, "capabilities": {"tools": {}}})
        elif method == "notifications/initialized":
            assert phase == "initialized"
            phase = "ready"
        elif method == "tools/list":
            assert phase == "ready"
            phase = "discovered"
            names = ["wipstash"] + ["wipstash_" + name for name in (
                "status", "updates", "checkpoint", "publish", "adopt",
                "operation_status", "proposal_status")]
            reply(message, {"tools": [{"name": name, "inputSchema": {
                "properties": {"include_record": {"type": "boolean"}}
                if name == "wipstash_operation_status" and mode != "legacy" else {}}}
                for name in names]})
        elif method == "tools/call":
            assert phase == "discovered", "tools/call before handshake completed"
            params = message["params"]
            if params["name"] == "wipstash":
                request = params["arguments"]["request"]
            else:
                request = dict(params["arguments"], op=params["name"][len("wipstash_"):])
            log({"request": request})
            op = request["op"]
            identifier = request.get("operation_id")
            if op in client_module.MUTATIONS:
                # Validate the exact private receipt BEFORE acknowledging or
                # simulating the mutation. No command is ever executed here.
                pending_path = journal / ("op-" + identifier.encode("ascii").hex() + ".json")
                if not pending_path.exists():
                    pending_path = journal / (identifier + ".json")  # Wire fake's storage.
                record = json.loads(pending_path.read_text())
                assert record["request"] == request and record["state"] == "pending"
                if os.name == "posix":
                    assert stat.S_IMODE(pending_path.stat().st_mode) == 0o600
                result = {"ok": True, "state": "saved", "operation_id": identifier,
                          "generation": 1, "echo": request}
                if identifier.startswith("command-uncertain"):
                    result = {"ok": False, "state": "uncertain", "writer_recovery_required": True}
                if identifier.startswith("lost-failure"):
                    result = {"ok": False, "error": {"code": "stale_generation"}}
                if not identifier.startswith("missing-"):
                    if identifier in outcomes:
                        result = (outcomes[identifier]["result"]
                                  if outcomes[identifier]["request"] == request
                                  else {"ok": False, "error": {"code": "idempotency_mismatch"}})
                    else:
                        outcomes[identifier] = {"request": request,
                            "result": ({"ok": True, "state": "pending"}
                                       if identifier.startswith("pending-") else result)}
                        saved.write_text(json.dumps(outcomes))
                if identifier.startswith(("lost-", "pending-", "missing-", "command-uncertain")):
                    return  # Deliberate EOF after simulated application, no kill.
            elif op == "operation_status":
                entry = outcomes.get(identifier)
                result = (entry["result"] if entry else
                          {"ok": False, "error": {"code": "operation_not_found"}})
                if request.get("include_record") and identifier in outcomes:
                    pending = result.get("state") == "pending"
                    result = {"ok": True, "operation_id": identifier, "recorded": True,
                              "state": "pending" if pending else "completed",
                              "request": entry["request"],
                              "result": None if pending else result}
            elif op == "proposal_status":
                result = {"ok": True, "state": "coordinator_accepted", "proposal": request["proposal"]}
            else:
                result = {"ok": True, "generation": 0}
            if mode == "notification":
                print(json.dumps({"jsonrpc": "2.0", "method": "notifications/message",
                                  "params": {"data": "synthetic diagnostic"}}), flush=True)
            if mode == "malformed" and op == "status":
                print("not json", flush=True)
                continue
            reply(message, {"isError": not result["ok"], "structuredContent": result,
                            "content": [{"type": "text", "text": json.dumps(result)}]})
        else:
            raise AssertionError(method)


class FakeClock:
    def __init__(self):
        self.value = 0.0
        self.sleeps = []

    def monotonic(self):
        return self.value

    def sleep(self, seconds):
        self.sleeps.append(seconds)
        self.value += seconds


def fake_journal(directory, mode):
    """Wire-contract fake only; it does NOT establish native storage security."""
    directory = Path(directory)
    directory.mkdir(mode=0o700, exist_ok=True)
    locked = False
    for raw in sys.stdin.buffer:
        message = json.loads(raw)
        method = message["method"]
        arguments = message["params"]
        if method == "journal/info":
            result = {"protocolVersion": 1, "platform": "synthetic", "durability": "synthetic_test_only"}
        elif method == "journal/lock":
            assert not locked
            locked = True
            result = {"locked": True}
        elif method == "journal/unlock":
            assert locked
            locked = False
            result = {"locked": False}
        elif method == "journal/read":
            assert locked
            path = directory / arguments["name"]
            result = {"found": path.exists()}
            if path.exists():
                try:
                    result["value_json"] = path.read_text()
                    json.loads(result["value_json"])
                except ValueError:
                    print(json.dumps({"jsonrpc": "2.0", "id": message["id"],
                                      "error": {"code": -32000, "message": "invalid record"}}), flush=True)
                    continue
        elif method == "journal/write":
            assert locked
            path = directory / arguments["name"]
            with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "w") as stream:
                stream.write(arguments["value_json"])
            if mode == "drop-pending" and json.loads(arguments["value_json"]).get("state") == "pending":
                return
            result = {"written": True}
        else:
            raise AssertionError(method)
        print(json.dumps({"jsonrpc": "2.0", "id": message["id"], "result": result}), flush=True)


class DurableClientTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="wipstash-python-client-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.journal = self.root / "journal"

    def client(self, mode="normal", **kwargs):
        command = [sys.executable, str(Path(__file__).resolve()), "--fake-server",
                   str(self.root), str(self.journal), mode]
        journal_command = [sys.executable, str(Path(__file__).resolve()), "--fake-journal",
                           str(self.journal), "normal"]
        value = WipstashClient(command, self.journal, timeout=3, journal_command=journal_command, **kwargs)
        self.addCleanup(value.close)
        return value

    def trace(self):
        path = self.root / "trace.jsonl"
        return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []

    def requests(self):
        return [item["request"] for item in self.trace() if "request" in item]

    @staticmethod
    def checkpoint(identifier="save-1"):
        return {"op": "checkpoint", "workspace": "alice", "operation_id": identifier,
                "expected_generation": 0}

    def test_handshake_long_lived_exact_receipt_and_cached_replay(self):
        client = self.client()
        self.assertTrue(client.read("status")["ok"])
        request = self.checkpoint()
        result = client.mutate(request)
        self.assertEqual(result["echo"], request)
        self.assertEqual(client.mutate(dict(reversed(list(request.items())))), result)
        client.read("updates", workspace="alice")
        client.close()
        methods = [item["method"] for item in self.trace() if "method" in item]
        self.assertEqual(methods, ["initialize", "notifications/initialized", "tools/list",
                                   "tools/call", "tools/call", "tools/call"])
        self.assertEqual(self.trace()[:5], [
            {"method": "initialize"}, {"reply": "initialize"},
            {"method": "notifications/initialized"}, {"method": "tools/list"},
            {"reply": "tools/list"}])
        receipt = json.loads((self.journal / "save-1.json").read_text())
        self.assertEqual(receipt["request"], request)
        self.assertEqual(receipt["state"], "completed")
        if os.name == "posix":
            self.assertEqual(stat.S_IMODE(self.journal.stat().st_mode), 0o700)
        self.assertEqual([r["op"] for r in self.requests()], ["status", "checkpoint", "updates"])

    def test_changed_id_rejected_before_server_call_including_value_types(self):
        client = self.client()
        request = self.checkpoint()
        client.mutate(request)
        for change in ({"expected_generation": 1}, {"expected_generation": 0.0},
                       {"workspace": "bob"}, {"op": "adopt"}):
            with self.assertRaises(client_module.IdempotencyMismatch):
                client.mutate(dict(request, **change))
        self.assertEqual(len(self.requests()), 1)

    def test_completed_receipt_survives_restart_without_relaunch(self):
        first = self.client()
        request = self.checkpoint()
        expected = first.mutate(request)
        first.close()
        before = self.trace()
        second = self.client()
        self.assertEqual(second.mutate(request), expected)
        self.assertIsNone(second._session)
        self.assertEqual(self.trace(), before)

    def test_lost_reply_reconciles_same_id_after_restart_without_resend(self):
        first = self.client()
        request = self.checkpoint("lost-save")
        with self.assertRaises(client_module.UncertainOperation):
            first.mutate(request)
        first.close()
        second = self.client()
        recovered = second.mutate(request)
        self.assertEqual(recovered["echo"], request)
        self.assertEqual([r["op"] for r in self.requests()], ["checkpoint", "operation_status"])
        self.assertEqual(second.reconcile("lost-save"), recovered)
        self.assertEqual(len(self.requests()), 2)

    def test_recorded_failure_reconciles_as_exact_failure(self):
        client = self.client()
        request = self.checkpoint("lost-failure-1")
        with self.assertRaises(client_module.UncertainOperation):
            client.mutate(request)
        expected = {"ok": False, "error": {"code": "stale_generation"}}
        self.assertEqual(client.reconcile(request["operation_id"]), expected)
        self.assertEqual(client.mutate(request), expected)
        self.assertEqual([r["op"] for r in self.requests()], ["checkpoint", "operation_status"])
        self.assertTrue(self.requests()[-1]["include_record"])

    def test_legacy_lookup_is_conservative_about_ambiguous_failure(self):
        client = self.client("legacy")
        request = self.checkpoint("lost-failure-1")
        with self.assertRaises(client_module.UncertainOperation):
            client.mutate(request)
        with self.assertRaises(client_module.UncertainOperation):
            client.reconcile(request["operation_id"])
        self.assertNotIn("include_record", self.requests()[-1])

    def test_legacy_success_does_not_prove_request_binding(self):
        client = self.client("legacy")
        request = self.checkpoint("lost-legacy-success")
        with self.assertRaises(client_module.UncertainOperation):
            client.mutate(request)
        with self.assertRaises(client_module.UncertainOperation):
            client.reconcile(request["operation_id"])

    def test_remote_id_collision_cannot_cache_another_requests_success(self):
        request = self.checkpoint("lost-collision")
        other = dict(request, workspace="someone-else")
        (self.root / "server-results.json").write_text(json.dumps({request["operation_id"]: {
            "request": other, "result": {"ok": True, "generation": 9}}}))
        client = self.client()
        with self.assertRaises(client_module.UncertainOperation):
            client.mutate(request)
        with self.assertRaises(client_module.UncertainOperation):
            client.reconcile(request["operation_id"])
        with client.journal.locked():
            record = client.journal.record(request["operation_id"])
        self.assertEqual(record["state"], "pending")
        self.assertEqual(record["request"], request)
        self.assertEqual([r["op"] for r in self.requests()], ["checkpoint", "operation_status"])

    def test_new_operation_id_is_valid_and_fresh(self):
        first, second = WipstashClient.new_operation_id("publish"), WipstashClient.new_operation_id("publish")
        self.assertNotEqual(first, second)
        self.assertTrue(first.startswith("publish-"))
        self.assertRegex(first, client_module.IDENTIFIER)
        for prefix in ("../unsafe", "x" * 100, "non_ascii_é"):
            with self.assertRaises(ValueError):
                WipstashClient.new_operation_id(prefix)

    def test_pending_and_missing_command_are_never_replayed(self):
        client = self.client()
        for prefix in ("pending-", "missing-"):
            request = {"op": "command_run", "workspace": "alice", "expected_generation": 0,
                       "argv": ["synthetic-never-executed"], "operation_id": prefix + "command"}
            with self.assertRaises(client_module.UncertainOperation):
                client.mutate(request)
            for _ in range(2):
                with self.assertRaises(client_module.UncertainOperation) as error:
                    client.mutate(request)
                self.assertEqual(error.exception.operation_id, request["operation_id"])
            record = json.loads((self.journal / (request["operation_id"] + ".json")).read_text())
            self.assertEqual(record["state"], "pending")
        self.assertEqual(sum(r["op"] == "command_run" for r in self.requests()), 2)
        self.assertEqual(sum(r["op"] == "operation_status" for r in self.requests()), 4)

    def test_uncertain_command_result_keeps_writer_fence_and_is_not_replayed(self):
        client = self.client()
        request = {"op": "command_run", "workspace": "alice", "expected_generation": 0,
                   "argv": ["synthetic-never-executed"], "operation_id": "command-uncertain-1"}
        with self.assertRaises(client_module.UncertainOperation):
            client.mutate(request)
        result = client.reconcile(request["operation_id"])
        self.assertFalse(result["ok"])
        self.assertTrue(result["writer_recovery_required"])
        self.assertEqual(client.mutate(request), result)
        self.assertEqual([r["op"] for r in self.requests()], ["command_run", "operation_status"])


    def test_completed_receipt_write_failure_reconciles_without_replay(self):
        client = self.client()
        original = client.journal.write
        def fail_completion(name, value):
            if value.get("state") == "completed":
                raise OSError("synthetic receipt write failure")
            original(name, value)
        with mock.patch.object(client.journal, "write", side_effect=fail_completion):
            with self.assertRaises(OSError):
                client.mutate(self.checkpoint())
        self.assertTrue(client.mutate(self.checkpoint())["ok"])
        self.assertEqual([r["op"] for r in self.requests()], ["checkpoint", "operation_status"])


    def test_journal_binding_prevents_cross_server_receipt_reuse(self):
        self.client().close()
        with self.assertRaises(client_module.JournalError):
            self.client("different-server")


    def test_corrupt_receipt_is_preserved_and_not_replaced(self):
        client = self.client()
        receipt = self.journal / "save-1.json"
        receipt.write_text("{broken")
        receipt.chmod(0o600)
        with self.assertRaises(client_module.JournalError):
            client.mutate(self.checkpoint())
        self.assertEqual(receipt.read_text(), "{broken")
        self.assertEqual(self.trace(), [])

    def test_notifications_do_not_consume_tool_reply(self):
        client = self.client("notification")
        self.assertTrue(client.read("status")["ok"])
        self.assertTrue(client.read("status")["ok"])

    def test_bad_version_disconnects_before_tool_discovery(self):
        client = self.client("bad-version")
        with self.assertRaises(client_module.ProtocolError):
            client.start()
        self.assertEqual([x["method"] for x in self.trace() if "method" in x], ["initialize"])

    def test_wrong_response_id_is_uncertain_for_mutation(self):
        client = self.client("wrong-id")
        with self.assertRaises(client_module.UncertainOperation):
            client.mutate(self.checkpoint())
        self.assertEqual(json.loads((self.journal / "save-1.json").read_text())["state"], "pending")

    def test_invalid_response_is_transport_error(self):
        with self.assertRaises(client_module.TransportError):
            self.client("malformed").read("status")

    def test_mutation_requires_valid_id_json_and_journalled_operation(self):
        client = self.client()
        for request in ({"op": "integrate"}, {"op": "init"}, self.checkpoint("../unsafe"),
                        self.checkpoint("endpoint"),
                        dict(self.checkpoint(), bad=float("nan")),
                        dict(self.checkpoint(), bad={1: "not a string key"})):
            with self.assertRaises(ValueError):
                client.mutate(request)
        with self.assertRaises(ValueError):
            client.read("publish", workspace="alice")
        self.assertEqual(self.trace(), [])

    def test_publish_and_adopt_remain_separate_explicit_calls(self):
        client = self.client()
        client.mutate(self.checkpoint())
        client.mutate({"op": "publish", "workspace": "alice", "checkpoint": "save-1",
                       "intent": "Deliberate publication", "operation_id": "publish-1"})
        self.assertEqual([r["op"] for r in self.requests()], ["checkpoint", "publish"])
        client.read("updates", workspace="alice")
        client.mutate({"op": "adopt", "workspace": "alice", "target": "latest",
                       "expected_generation": 1, "operation_id": "adopt-1"})
        self.assertEqual([r["op"] for r in self.requests()], ["checkpoint", "publish", "updates", "adopt"])

    def test_proposal_polling_uses_bounded_exponential_backoff(self):
        clock = FakeClock()
        client = self.client(clock=clock.monotonic, sleep=clock.sleep)
        observations = [{"ok": True, "state": state} for state in (
            "coordinator_accepted", "coordinator_accepted", "local_queued", "integrated")]
        with mock.patch.object(client, "read", side_effect=observations) as read:
            self.assertEqual(client.wait_for_proposal("p", timeout=10, initial_delay=.5,
                                                     max_delay=1)["state"], "integrated")
        self.assertEqual(clock.sleeps, [.5, 1, 1])
        self.assertEqual(read.call_count, 4)
        self.assertEqual(self.trace(), [])

    def test_deadline_caps_sleep_and_per_call_timeout(self):
        clock = FakeClock()
        client = self.client(clock=clock.monotonic, sleep=clock.sleep)
        with mock.patch.object(client, "read", return_value={"ok": True, "state": "local_queued"}) as read:
            with self.assertRaises(client_module.ProposalTimeout) as error:
                client.wait_for_proposal("p", timeout=1.2, initial_delay=.5, max_delay=1)
        self.assertEqual(clock.sleeps, [.5, .7])
        self.assertEqual(error.exception.last_status["state"], "local_queued")
        self.assertEqual([call.kwargs["timeout"] for call in read.call_args_list], [1.2, .7])

    def test_all_actionable_proposal_outcomes_stop_without_followup_actions(self):
        client = self.client()
        for state in client_module.PROPOSAL_OUTCOMES:
            with mock.patch.object(client, "read", return_value={"ok": True, "state": state}) as read:
                self.assertEqual(client.wait_for_proposal("p")["state"], state)
                self.assertEqual(read.call_count, 1)
        self.assertEqual(self.trace(), [])

    def test_polling_rejects_unbounded_parameters(self):
        client = self.client()
        for arguments in ({"timeout": 0}, {"timeout": float("inf")}, {"initial_delay": 0},
                          {"max_delay": float("nan")}):
            with self.assertRaises(ValueError):
                client.wait_for_proposal("p", **arguments)


class TransportDeadlineTests(unittest.TestCase):
    def test_timeout_is_bounded_without_terminating_server(self):
        # In-process queues model a silent transport deterministically. No live
        # process is stalled or killed, and no policy runner is invoked.
        session = object.__new__(client_module._StdioSession)
        session.closed, session.serial = False, 0
        session.request_limit = client_module.MAX_REQUEST_BYTES
        session.requests = client_module.queue.Queue()
        session.replies = mock.Mock()
        session.replies.get.side_effect = client_module.queue.Empty
        with self.assertRaises(client_module.TransportError):
            session.request("tools/list", {}, .125)
        session.replies.get.assert_called_once_with(timeout=.125)

    @unittest.skipUnless(os.environ.get("WIPSTASH_CLIENT_SMOKE_BINARY"), "Real-server smoke is opt-in")
    def test_real_server_readonly_stdio_smoke(self):
        binary = os.environ["WIPSTASH_CLIENT_SMOKE_BINARY"]
        with tempfile.TemporaryDirectory(prefix="wipstash-client-real-smoke-") as directory:
            state = Path(directory) / "empty-state"
            with WipstashClient([binary, "--state", str(state), "mcp"], timeout=10) as client:
                self.assertIn("wipstash_checkpoint", client.tools)
                result = client.read("status")
                self.assertFalse(result["ok"])
                self.assertEqual(result["error"]["code"], "project_not_initialized")

    @unittest.skipUnless(os.environ.get("WIPSTASH_CLIENT_SMOKE_BINARY"), "Real-server smoke is opt-in")
    def test_real_engine_and_native_journal_lost_checkpoint_reply(self):
        binary = os.environ["WIPSTASH_CLIENT_SMOKE_BINARY"]
        with tempfile.TemporaryDirectory(prefix="wipstash-client-engine-recovery-") as directory:
            root = Path(directory).resolve()
            source, state = root / "source", root / "state"
            source.mkdir()
            (source / "hello.txt").write_text("synthetic source\n")
            initialized = subprocess.run(
                [binary, "--state", str(state), json.dumps({"op": "init", "source": str(source)})],
                text=True, capture_output=True, check=True)
            self.assertTrue(json.loads(initialized.stdout)["ok"])
            with WipstashClient([binary, "--state", str(state), "mcp"], root / "journal") as client:
                opened = client.mutate({"op": "open", "workspace": "alice",
                                       "path": str(root / "alice"), "operation_id": "open-alice"})
                self.assertTrue(opened["ok"])
                request = {"op": "checkpoint", "workspace": "alice", "expected_generation": 0,
                           "operation_id": "lost-real-checkpoint"}
                call, observed = client._call_engine, []
                def lose_reply(body, **kwargs):
                    result = call(body, **kwargs)
                    observed.append(body)
                    if body["op"] == "checkpoint":
                        raise client_module.TransportError("Synthetic withheld completed reply")
                    return result
                with mock.patch.object(client, "_call_engine", side_effect=lose_reply):
                    with self.assertRaises(client_module.UncertainOperation):
                        client.mutate(request)
                    recovered = client.reconcile(request["operation_id"])
                    self.assertTrue(recovered["ok"])
                    self.assertEqual(recovered["checkpoint"], request["operation_id"])
                    self.assertEqual(client.mutate(request), recovered)
                self.assertEqual([r["op"] for r in observed], ["checkpoint", "operation_status"])
                self.assertTrue(observed[-1]["include_record"])


class NativeBackendProtocolTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="wipstash-native-journal-wire-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.journal = self.root / "journal"

    def client(self, mode="normal"):
        script = str(Path(__file__).resolve())
        command = [sys.executable, script, "--fake-server", str(self.root), str(self.journal), "normal"]
        journal_command = [sys.executable, script, "--fake-journal", str(self.journal), mode]
        client = WipstashClient(command, self.journal, timeout=3, journal_command=journal_command)
        self.addCleanup(client.close)
        return client

    def test_explicit_backend_preserves_journal_contract_and_restart(self):
        client = self.client()
        self.assertEqual(client.journal_durability, "synthetic_test_only")
        request = dict(DurableClientTests.checkpoint(),
                       synthetic_exact_numbers={"large": 10 ** 80, "float": 1.0})
        result = client.mutate(request)
        with client.journal.locked():
            self.assertEqual(client.journal.record("save-1")["state"], "completed")
        client.close()
        restarted = self.client()
        self.assertEqual(restarted.mutate(request), result)
        with self.assertRaises(client_module.IdempotencyMismatch):
            restarted.mutate(dict(request, expected_generation=5))
        trace = [json.loads(line) for line in (self.root / "trace.jsonl").read_text().splitlines()]
        self.assertEqual(sum("request" in item for item in trace), 1)

    def test_backend_lost_persist_ack_never_dispatches_engine(self):
        client = self.client("drop-pending")
        with self.assertRaises(client_module.JournalError):
            client.mutate(DurableClientTests.checkpoint())
        self.assertFalse((self.root / "trace.jsonl").exists())
        self.assertEqual(json.loads((self.journal / "save-1.json").read_text())["state"], "pending")
        client.close()
        restarted = self.client()
        with self.assertRaises(client_module.UncertainOperation):
            restarted.mutate(DurableClientTests.checkpoint())
        trace = [json.loads(line) for line in (self.root / "trace.jsonl").read_text().splitlines()]
        self.assertEqual([item["request"]["op"] for item in trace if "request" in item], ["operation_status"])

    @unittest.skipUnless(os.environ.get("WIPSTASH_CLIENT_JOURNAL_BINARY"), "Native journal integration is opt-in")
    def test_real_native_journal_fake_engine_mutation_recovery_and_replay(self):
        binary = os.environ["WIPSTASH_CLIENT_JOURNAL_BINARY"]
        command = [sys.executable, str(Path(__file__).resolve()), "--fake-server",
                   str(self.root), str(self.journal), "normal"]
        journal_command = [binary, "client-journal", str(self.journal)]
        request = dict(DurableClientTests.checkpoint("lost-real-journal"),
                       synthetic_exact_numbers={"large": 10 ** 80, "float": 1.0})
        with WipstashClient(command, self.journal, journal_command=journal_command) as client:
            with self.assertRaises(client_module.UncertainOperation):
                client.mutate(request)
        with WipstashClient(command, self.journal, journal_command=journal_command) as restarted:
            result = restarted.mutate(request)
            self.assertEqual(result["echo"], request)
            with restarted.journal.locked():
                self.assertEqual(restarted.journal.record(request["operation_id"])["state"], "completed")
            self.assertEqual(restarted.mutate(request), result)
            with self.assertRaises(client_module.IdempotencyMismatch):
                restarted.mutate(dict(request, expected_generation=8))
        trace = [json.loads(line) for line in (self.root / "trace.jsonl").read_text().splitlines()]
        self.assertEqual([item["request"]["op"] for item in trace if "request" in item],
                         ["checkpoint", "operation_status"])


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--fake-server":
        fake_server(*sys.argv[2:])
    elif len(sys.argv) > 1 and sys.argv[1] == "--fake-journal":
        fake_journal(*sys.argv[2:])
    else:
        unittest.main()
