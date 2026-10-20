#!/usr/bin/env python3
"""Single-call source control through real CLI/Git/SQLite; no model sessions."""
import argparse
import concurrent.futures
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "examples/clients"))
from wipstash_client import WipstashClient, UncertainOperation, IdempotencyMismatch

PARSER = argparse.ArgumentParser(description=__doc__)
PARSER.add_argument("--binary", default="target/debug/wipstash.exe" if os.name == "nt" else "target/debug/wipstash")
PARSER.add_argument("--artifacts")
ARGS, TESTS = PARSER.parse_known_args()
BINARY = str(Path(ARGS.binary).resolve())


class SharedCommit(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="wipstash-shared-commit-")
        self.root = Path(self.temporary.name).resolve()
        self.state = self.root / "state"
        source = self.root / "source"
        source.mkdir()
        (source / "file.txt").write_text("initial\n")
        self.cli({"op": "init", "source": str(source)})
        self.clients, self.paths = {}, {}
        for actor in "ABCD":
            client = WipstashClient([BINARY, "--state", str(self.state)], self.root / ("journal-" + actor), timeout=60)
            self.clients[actor] = client
            self.paths[actor] = self.root / actor
            opened = client.mutate({"op": "clone", "workspace": actor, "path": str(self.paths[actor]), "operation_id": "clone-" + actor})
            self.assertTrue(opened["ok"], opened)

    def tearDown(self):
        for client in self.clients.values():
            client.close()
        self.temporary.cleanup()

    def cli(self, body, **kwargs):
        done = subprocess.run([BINARY, "--state", str(self.state), json.dumps(body)], capture_output=True, text=True, **kwargs)
        self.assertEqual(done.returncode, 0, done.stderr + done.stdout)
        result = json.loads(done.stdout)
        self.assertTrue(result["ok"], result)
        return result

    def commit(self, actor, identifier, generation=0, **extra):
        return self.clients[actor].mutate(dict(op="commit", workspace=actor, message="Share " + identifier,
                                              expected_generation=generation, operation_id=identifier, **extra))

    def public(self, path):
        return subprocess.check_output(["git", "--git-dir", str(self.state / "coordinator.git"),
                                        "show", "refs/wipstash/integration:" + path], text=True)

    def test_commit_is_the_only_save_tool(self):
        client = self.clients["A"]
        client.start()
        for op in ["checkpoint", "publish", "integrate", "resolution_submit"]:
            result = client._call_engine({"op": op})
            self.assertFalse(result["ok"])
            self.assertEqual(result["error"]["code"], "removed_workflow")

    def test_git_vocabulary_and_get_latest_then_merge(self):
        client = self.clients["A"]
        for request in [{"op": "open"}, {"op": "updates"}, {"op": "adopt"}, {"op": "proposal_status"}, {"op": "commit", "intent": "old"}]:
            result = client._call_engine(request)
            self.assertIn(result["error"]["code"], ("removed_workflow", "invalid_arguments"), result)
        (self.paths["A"] / "file.txt").write_text("shared new terms\n")
        message = "Preserve literal snapshot, quarantine and adopt in user text"
        result = client.mutate(dict(op="commit", workspace="A", message=message, expected_generation=0, operation_id="new-terms"))
        self.assertTrue(result["shared"], result)
        self.assertEqual(result["commit_id"], "new-terms")
        record = client.read("operation_status", operation_id="new-terms", include_record=True)
        self.assertEqual(record["request"]["message"], message)
        latest = self.clients["B"].read("get_latest", workspace="B")
        self.assertTrue(latest["ok"], latest)
        self.assertEqual((self.paths["B"] / "file.txt").read_text(), "initial\n")
        merged = self.clients["B"].mutate(dict(op="merge", workspace="B", target="latest", expected_generation=0, operation_id="merge-new-terms"))
        self.assertTrue(merged["ok"], merged)
        self.assertEqual((self.paths["B"] / "file.txt").read_text(), "shared new terms\n")
        status = client.read("status", workspace="A")
        self.assertIn("merged_base", status)
        self.assertIn("commits", status)
        self.assertFalse({"checkpoint", "checkpoint_commit", "checkpoint_generation", "adopted", "proposals"} & status.keys())

    def test_commit_reaches_shared_without_a_second_action_or_worker(self):
        (self.paths["A"] / "LICENSE").write_text("Synthetic license fixture\n")
        result = self.commit("A", "license")
        self.assertTrue(result["shared"], result)
        self.assertEqual(result["state"], "integrated")
        self.assertEqual(result["validation"]["state"], "unchecked")
        self.assertEqual(self.public("LICENSE"), "Synthetic license fixture\n")
        self.assertFalse((self.paths["B"] / "LICENSE").exists())
        (self.paths["A"] / "website.html").write_text("newer private bytes\n")
        self.assertEqual(self.commit("A", "license"), result)
        observed = self.clients["A"].read("status", workspace="A")
        self.assertEqual(observed["generation"], 1)

    def test_concurrent_actors_share_disjoint_changes_without_adopting_each_other(self):
        for actor in "ABCD":
            (self.paths[actor] / (actor + ".txt")).write_text(actor + "\n")
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
            results = list(pool.map(lambda actor: self.commit(actor, "change-" + actor), "ABCD"))
        self.assertTrue(all(result.get("shared") is True for result in results), results)
        for actor in "ABCD":
            self.assertEqual(self.public(actor + ".txt"), actor + "\n")
            for other in set("ABCD") - {actor}:
                self.assertFalse((self.paths[actor] / (other + ".txt")).exists())

    def test_conflict_resolution_commits_once_and_preserves_intervening_work(self):
        (self.paths["A"] / "file.txt").write_text("alice\n")
        (self.paths["B"] / "file.txt").write_text("bob\n")
        self.assertTrue(self.commit("A", "alice")["shared"])
        blocked = self.commit("B", "bob")
        self.assertFalse(blocked["shared"])
        self.assertEqual(blocked["state"], "blocked")
        opened = self.clients["B"].mutate(dict(op="resolution_open", workspace="B", commit_id="bob",
            resolution_workspace="fix", path=str(self.root / "fix"), operation_id="open-fix"))
        self.assertTrue(opened["ok"], opened)
        (self.root / "fix/file.txt").write_text("alice and bob\n")
        (self.paths["C"] / "unrelated.txt").write_text("intervening change\n")
        self.assertTrue(self.commit("C", "unrelated")["shared"])
        result = self.clients["B"].mutate(dict(op="commit", workspace="fix", message="Combine greetings",
            expected_generation=0, operation_id="fix-bob", expected_head=opened["resolution_head"],
            resolved_conflicts=opened["conflict_paths"]))
        self.assertTrue(result["shared"], result)
        self.assertEqual(self.public("file.txt"), "alice and bob\n")
        self.assertEqual(self.public("unrelated.txt"), "intervening change\n")
        self.assertEqual((self.paths["B"] / "file.txt").read_text(), "bob\n")

    def test_successive_commits_from_one_workspace_do_not_conflict_with_themselves(self):
        (self.paths["A"] / "file.txt").write_text("version one\n")
        self.assertTrue(self.commit("A", "first")["shared"])
        (self.paths["B"] / "other.txt").write_text("other agent\n")
        self.assertTrue(self.commit("B", "other")["shared"])
        (self.paths["A"] / "file.txt").write_text("version two\n")
        result = self.commit("A", "second", generation=1)
        self.assertTrue(result["shared"], result)
        self.assertEqual(self.public("file.txt"), "version two\n")
        self.assertEqual(self.public("other.txt"), "other agent\n")
        self.assertFalse((self.paths["A"] / "other.txt").exists())
        (self.paths["A"] / "file.txt").write_text("version three\n")
        self.assertTrue(self.commit("A", "third", generation=2)["shared"])
        self.assertEqual(self.public("file.txt"), "version three\n")

    def test_adoption_after_own_commits_preserves_newer_private_edits(self):
        (self.paths["A"] / "file.txt").write_text("shared version\n")
        self.assertTrue(self.commit("A", "first")["shared"])
        (self.paths["B"] / "other.txt").write_text("other agent\n")
        self.assertTrue(self.commit("B", "other")["shared"])
        (self.paths["A"] / "file.txt").write_text("new private version\n")
        adopted = self.clients["A"].mutate(dict(op="merge", workspace="A", target="latest", expected_generation=1, operation_id="adopt-after-own-commit"))
        self.assertTrue(adopted["ok"], adopted)
        self.assertEqual((self.paths["A"] / "file.txt").read_text(), "new private version\n")
        self.assertEqual((self.paths["A"] / "other.txt").read_text(), "other agent\n")
        result = self.commit("A", "after-adopt", generation=2)
        self.assertTrue(result["shared"], result)
        self.assertEqual(self.public("file.txt"), "new private version\n")
        self.assertEqual(self.public("other.txt"), "other agent\n")

    def test_checks_fail_after_sharing_and_an_ordinary_commit_repairs_them(self):
        policy = {"checks": [{"id": "fixture", "argv": [sys.executable, "-c",
            "from pathlib import Path; import sys; sys.exit('bad' in Path('file.txt').read_text())"],
            "required": True, "timeout_seconds": 10}]}
        configured = self.clients["A"].mutate(dict(op="configure", policy=policy, operation_id="checks"))
        self.assertTrue(configured["ok"])
        (self.paths["A"] / "file.txt").write_text("bad candidate\n")
        shared = self.commit("A", "bad")
        self.assertTrue(shared["shared"])
        self.assertEqual(shared["validation"]["state"], "pending")
        self.assertEqual(self.public("file.txt"), "bad candidate\n")
        self.assertEqual(self.cli(dict(op="validation_tick"))["validation"]["state"], "failed")
        self.assertEqual(self.clients["A"].read("commit_status", commit_id="bad")["validation"]["state"], "failed")
        (self.paths["A"] / "file.txt").write_text("corrected candidate\n")
        fixed = self.commit("A", "checked-fix", generation=1)
        self.assertTrue(fixed["shared"], fixed)
        self.assertEqual(fixed["validation"]["state"], "pending")
        self.assertEqual(self.cli(dict(op="validation_tick"))["validation"]["state"], "passed")

    def test_completed_reply_loss_reconciles_without_a_duplicate_commit(self):
        client = self.clients["A"]
        original = client._call_engine
        request = dict(op="commit", workspace="A", message="Recover lost reply", expected_generation=0, operation_id="lost")
        (self.paths["A"] / "file.txt").write_text("shared despite reply loss\n")
        def lose_reply(body, **kwargs):
            result = original(body, **kwargs)
            if body["op"] == "commit":
                raise __import__("wipstash_client").TransportError("Withheld completed reply")
            return result
        with mock.patch.object(client, "_call_engine", side_effect=lose_reply):
            with self.assertRaises(UncertainOperation):
                client.mutate(request)
        recovered = client.reconcile("lost")
        self.assertTrue(recovered["shared"], recovered)
        self.assertEqual(client.mutate(request), recovered)
        with self.assertRaises(IdempotencyMismatch):
            client.mutate(dict(request, message="different request"))
        self.assertEqual(client.read("status", workspace="A")["generation"], 1)

    def test_private_adoption_conflict_needs_no_private_checkpoint_action(self):
        (self.paths["A"] / "file.txt").write_text("shared greeting\n")
        (self.paths["B"] / "file.txt").write_text("private greeting\n")
        self.assertTrue(self.commit("A", "greeting")["shared"])
        blocked = self.clients["B"].mutate(dict(op="merge", workspace="B", target="latest", expected_generation=0, operation_id="adopt-b"))
        self.assertFalse(blocked["ok"])
        self.assertEqual((self.paths["B"] / "file.txt").read_text(), "private greeting\n")
        (self.paths["B"] / "file.txt").write_text("reviewed private combination\n")
        resolved = self.clients["B"].mutate(dict(op="resolve_merge", workspace="B", candidate=blocked["candidate"],
            target=blocked["target"], expected_generation=0, operation_id="reconcile-b"))
        self.assertTrue(resolved["ok"], resolved)
        self.assertEqual(resolved["generation"], 1)
        self.assertEqual(self.public("file.txt"), "shared greeting\n")
        self.assertTrue(self.commit("B", "share-combination", generation=1)["shared"])
        self.assertEqual(self.public("file.txt"), "reviewed private combination\n")

    def interrupted_commit(self, fault, saved):
        request = dict(op="commit", workspace="A", message="Recover exact selected snapshot", expected_generation=0, operation_id="crash")
        (self.root / "exact-request.json").write_text(json.dumps(request))
        (self.paths["A"] / "file.txt").write_text("selected bytes\n")
        done = subprocess.run([BINARY, "--state", str(self.state), json.dumps(request)],
            env=dict(os.environ, WIPSTASH_FAULT=fault), capture_output=True, text=True)
        self.assertEqual(done.returncode, 86, done.stdout + done.stderr)
        (self.paths["A"] / "file.txt").write_text("newer private bytes\n")
        record = self.clients["A"].read("operation_status", operation_id="crash", include_record=True)
        self.assertEqual(record["request"], request)
        if not saved:
            self.assertFalse(record["result"]["ok"])
            self.assertEqual(record["result"]["error"]["code"], "commit_interrupted")
            self.assertEqual(self.public("file.txt"), "initial\n")
            return
        worker_log=self.root/"recovery-worker.stderr.log"
        with worker_log.open("wb") as diagnostics, subprocess.Popen([BINARY, "--state", str(self.state), "worker"], stdout=subprocess.DEVNULL,
                              stderr=diagnostics) as worker:
            try:
                limit = time.monotonic() + 30
                while time.monotonic() < limit:
                    observed = self.clients["A"].read("commit_status", commit_id="crash")
                    if observed["state"] == "integrated":
                        break
                    time.sleep(0.1)
                self.assertEqual(observed["state"], "integrated", dict(observed,worker_diagnostics=worker_log.read_text()))
            finally:
                worker.terminate()
                worker.wait(timeout=10)
        self.assertEqual(self.public("file.txt"), "selected bytes\n")
        self.assertEqual((self.paths["A"] / "file.txt").read_text(), "newer private bytes\n")
        self.assertEqual(self.clients["A"].read("status", workspace="A")["generation"], 1)

    def test_crash_after_durable_snapshot_resumes_only_that_snapshot(self):
        self.interrupted_commit("commit_after_snapshot", True)

    def test_crash_after_public_pin_resumes_only_that_snapshot(self):
        self.interrupted_commit("publish_after_pin", True)

    def test_crash_after_submission_keeps_identity_and_never_recaptures(self):
        self.interrupted_commit("commit_after_submit", True)

    def test_incomplete_capture_is_not_automatically_recaptured(self):
        self.interrupted_commit("checkpoint_after_pin", False)


if __name__ == "__main__":
    suite = unittest.defaultTestLoader.loadTestsFromNames(TESTS, module=sys.modules[__name__]) if TESTS else unittest.defaultTestLoader.loadTestsFromTestCase(SharedCommit)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    summary = {"tests": result.testsRun, "successful": result.wasSuccessful(),
               "failures": [str(test) for test, _ in result.failures], "errors": [str(test) for test, _ in result.errors],
               "actors": "scripted native MCP clients, not model sessions", "workflow": "commit-to-shared"}
    if ARGS.artifacts:
        directory = Path(ARGS.artifacts)
        directory.mkdir(parents=True, exist_ok=True)
        (directory / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    sys.exit(not result.wasSuccessful())
