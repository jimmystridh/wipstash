#!/usr/bin/env python3
"""Deterministic scripted actors over real long-lived stdio MCP sessions.

The default campaign runs no configured policy commands, sockets, or process
termination. --required-checks-ci additionally requires genuine native GitHub CI
and WIPSTASH_ERGONOMICS_CI=1. Never set those guards to run checks locally.

The comparison changes only the observation recipe on the SAME revised binary:
repeated status/updates/proposal_status/resolution_tasks versus compact status.
This is a bounded client-call comparison, not a model-agent or throughput study.
Only summary.json is a publishable artifact; disposable journals/worktrees are
private scratch state, even though every canary in this fixture is synthetic.
"""
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing, contextmanager
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time


ROOT = Path(__file__).resolve().parents[1]
PRIVATE_MARKER = "SYNTHETIC_PRIVATE_ERGONOMICS_CANARY"
ACTORS = ("A", "B", "C", "D")
READ_ONLY = {"status", "updates", "proposal_status", "resolution_tasks", "operation_status"}


def require_ci_checks(enabled, environ=None):
    """Reject before making a directory, spawning an engine, or configuring policy."""
    env = os.environ if environ is None else environ
    if enabled and not (env.get("GITHUB_ACTIONS") == "true"
                        and env.get("WIPSTASH_ERGONOMICS_CI") == "1"):
        raise ValueError("Required-check execution is native GitHub CI only; both "
                         "GITHUB_ACTIONS=true and WIPSTASH_ERGONOMICS_CI=1 are required. "
                         "Do not spoof these guards locally.")


def check(condition, message):
    if not condition:
        raise AssertionError(message)


def write(root, relative, body):
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body, encoding="utf-8", newline="")


def tree_manifest(root):
    return {p.relative_to(root).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in sorted(root.rglob("*")) if p.is_file()}


def load_helper():
    path = ROOT / "examples/clients/wipstash_client.py"
    spec = importlib.util.spec_from_file_location("wipstash_pressure_client", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def validation_state(value):
    validation = value["validation"]
    check(validation["state"] in {"unchecked", "pending", "passed", "failed"}, validation)
    check(validation["semantic_correctness_claimed"] is False, validation)
    check(isinstance(validation["scope"], str), validation)
    for field in ("candidate_tree", "checks_total", "checks_passed", "checks_failed"):
        check(field in validation, validation)
    return validation["state"]


def next_op(value):
    action = value["next_action"]
    check(action["requires_explicit_request"] is True, action)
    check(isinstance(action["arguments"], dict), action)
    return action["op"]


def observe_recipe(read, mode, workspace, proposals):
    """Return equivalent required information; never let compact data mask reads."""
    status = read("status", workspace=workspace)
    if mode == "compact_status":
        check(not status["proposals_truncated"], "Fixture exceeds compact result bound")
        by_id = {p["proposal"]: p for p in status["proposals"]}
        proposal_results = [by_id[p] for p in proposals]
        tasks = status["resolution_tasks"]
        latest = status["latest"]
    elif mode == "repeated_reads":
        latest = read("updates", workspace=workspace)["latest"]
        proposal_results = [read("proposal_status", proposal=p) for p in proposals]
        tasks = read("resolution_tasks", workspace=workspace)["tasks"]
    else:
        raise ValueError("Unknown observation recipe")
    return status, latest, proposal_results, tasks


class Ledger:
    def __init__(self):
        self.lock = threading.Lock()
        self.local = threading.local()
        self.calls = Counter()
        self.response_bytes = Counter()
        self.session_calls = Counter()

    @contextmanager
    def phase(self, name):
        previous = getattr(self.local, "phase", "workflow")
        self.local.phase = name
        try:
            yield
        finally:
            self.local.phase = previous

    def record(self, transport, actor, request, response):
        category = getattr(self.local, "phase", "workflow")
        key = category + "/" + transport + "/" + request["op"]
        with self.lock:
            self.calls[key] += 1
            self.response_bytes[category + "/" + transport] += len(
                json.dumps(response, sort_keys=True, separators=(",", ":")).encode())
            if transport == "mcp":
                self.session_calls[actor] += 1

    def report(self):
        return {"engine_requests_by_phase_transport_operation": dict(sorted(self.calls.items())),
                "observation_engine_requests": sum(n for k, n in self.calls.items()
                                                   if k.startswith("observation/")),
                "all_engine_requests": sum(self.calls.values()),
                "structured_response_bytes_by_phase_transport": dict(self.response_bytes),
                "engine_requests_by_stdio_session": dict(self.session_calls),
                "mcp_lifecycle_requests_excluded": "initialize/tools-list/notifications are not engine requests"}


class Campaign:
    def __init__(self, binary, root, mode, helper, required_checks=False):
        self.binary = binary
        self.root = root
        self.root.mkdir(parents=True)
        self.state = root / "state"
        self.mode = mode
        self.helper = helper
        self.required_checks = required_checks
        self.ledger = Ledger()
        self.clients = {}
        self.processes = {}
        self.eof_shutdowns = []
        self.paths = {actor: root / ("work-" + actor) for actor in ACTORS}
        self.generations = {}
        self.proposals = {actor: [] for actor in ACTORS}
        self.roles = {}
        self.observations = []
        self.assertions = []
        self.session_serial = Counter()
        self.serial = 0
        self.serial_lock = threading.Lock()

    def operation(self, label):
        with self.serial_lock:
            self.serial += 1
            return "erg-" + label + "-" + str(self.serial)

    def command(self, argv):
        # No timeout-driven kill or signal is used. The harness's CI job owns its
        # outer execution limit; individual MCP reads are bounded by the helper.
        result = subprocess.run([str(x) for x in argv], capture_output=True)
        check(result.returncode == 0,
              "Command failed: " + repr(argv) + "\n" + result.stderr.decode(errors="replace"))
        return result.stdout

    def cli(self, request):
        value = json.loads(self.command([self.binary, "--state", self.state,
                                        json.dumps(request)]))
        self.ledger.record("cli", "coordinator", request, value)
        check(value.get("ok"), value)
        return value

    def start(self, actor):
        self.session_serial[actor] += 1
        label = actor + "-session-" + str(self.session_serial[actor])
        client = self.helper.WipstashClient(
            [str(self.binary), "--state", str(self.state), "mcp"],
            self.root / ("journal-" + actor), timeout=30)
        client.__enter__()
        original = client._call_engine

        def counted(request, *args, **kwargs):
            response = original(request, *args, **kwargs)
            self.ledger.record("mcp", label, request, response)
            return response

        client._call_engine = counted
        self.clients[actor] = client
        self.processes[actor] = (label, client._session.process)
        return client

    def close(self, actor):
        client = self.clients.pop(actor)
        label, process = self.processes.pop(actor)
        client.__exit__(None, None, None)
        # Wait only; never terminate a server if graceful shutdown is blocked.
        check(process.wait(timeout=10) == 0, "Nonzero EOF shutdown: " + label)
        self.eof_shutdowns.append(label)

    def cleanup(self):
        failures = []
        for actor in list(self.clients):
            try:
                self.close(actor)
            except Exception as error:
                failures.append(str(error))
        check(not failures, "Graceful EOF shutdown failed: " + repr(failures))

    def read(self, actor, op, **fields):
        response = self.clients[actor].read(op, **fields)
        check(response.get("ok"), response)
        return response

    def mutate(self, actor, op, *, ok=True, **fields):
        fields.setdefault("operation_id", self.operation(op + "-" + actor))
        response = self.clients[actor].mutate(dict(op=op, **fields))
        check(bool(response.get("ok")) == ok, response)
        return response

    def checkpoint(self, actor, workspace=None):
        workspace = workspace or actor
        response = self.mutate(actor, "checkpoint", workspace=workspace,
                               expected_generation=self.generations[workspace])
        self.generations[workspace] = response["generation"]
        check(validation_state(response) == "unchecked", response)
        return response

    def publish(self, actor, role):
        checkpoint = self.checkpoint(actor)
        result = self.mutate(actor, "publish", workspace=actor,
                             checkpoint=checkpoint["checkpoint"], intent="Scripted ergonomics fixture")
        self.proposals[actor].append(result["proposal"])
        self.roles[result["proposal"]] = role
        return result

    def frozen(self):
        return {actor: tree_manifest(path) for actor, path in self.paths.items()}

    def observe(self, actor, phase):
        with self.ledger.phase("observation"):
            status, latest, proposals, tasks = observe_recipe(
                lambda op, **fields: self.read(actor, op, **fields),
                self.mode, actor, self.proposals[actor])
        if status["checkpoint_generation"] is not None:
            check(status["checkpoint_generation"] <= status["generation"], status)
        else:
            check(status["checkpoint"] is None, status)
        snapshot = {"phase": phase, "actor": actor,
                    "generation": status["generation"], "dirty": status["dirty"],
                    "adopted_is_latest": status["adopted"] == latest,
                    "checkpoint_present": status["checkpoint"] is not None,
                    "proposals": sorted(
                        [{"role": self.roles[p["proposal"]], "state": p["state"],
                          "validation": validation_state(p), "next_op": next_op(p)} for p in proposals],
                        key=lambda p: p["role"]),
                    "tasks": sorted(
                        [{"role": self.roles[t["proposal"]], "state": t["state"],
                          "reason": t["reason"], "conflict_paths": sorted(t["conflict_paths"])}
                         for t in tasks], key=lambda t: t["role"])}
        self.observations.append(snapshot)
        return status, proposals, tasks

    def open_resolution(self, actor, proposal, suffix, client=None):
        client = client or actor
        workspace = actor + "-resolve-" + suffix
        path = self.root / workspace
        response = self.mutate(client, "resolution_open", workspace=actor, proposal=proposal,
                               resolution_workspace=workspace, path=str(path))
        self.generations[workspace] = response["generation"]
        check(response["files_changed_in_original_workspace"] is False, response)
        return {"workspace": workspace, "path": path, "head": response["current_head"],
                "conflicts": response["conflict_paths"], "client": client,
                "owner": actor, "proposal": proposal}

    def prepare_resolution(self, resolution, body):
        write(resolution["path"], "shared.txt", body)
        checkpoint = self.checkpoint(resolution["client"], resolution["workspace"])
        return dict(op="resolution_submit", workspace=resolution["owner"],
                    proposal=resolution["proposal"], resolution_workspace=resolution["workspace"],
                    checkpoint=checkpoint["checkpoint"], expected_head=resolution["head"],
                    resolved_conflicts=resolution["conflicts"],
                    operation_id=self.operation("submit-" + resolution["workspace"]))

    def remember_resolution(self, owner, response, role):
        check(response.get("ok"), response)
        self.proposals[owner].append(response["proposal"])
        self.roles[response["proposal"]] = role

    def audit(self, private_commit):
        repo = self.state / "coordinator.git"
        self.command(["git", "--git-dir", repo, "fsck", "--full", "--strict"])
        listing = self.command(["git", "--git-dir", repo, "cat-file", "--batch-all-objects",
                                "--batch-check=%(objectname) %(objecttype)"]).decode()
        objects = [line.split() for line in listing.splitlines()]
        check(private_commit not in {oid for oid, _ in objects}, "Private ancestor reached public store")
        blobs = 0
        for oid, kind in objects:
            if kind == "blob":
                data = self.command(["git", "--git-dir", repo, "cat-file", "blob", oid])
                check(PRIVATE_MARKER.encode() not in data, "Private canary in public object")
                blobs += 1
        with closing(sqlite3.connect(self.state / "state.sqlite")) as db:
            check(db.execute("pragma integrity_check").fetchall() == [("ok",)], "SQLite integrity")
            check(not db.execute("select proposal from promotions where state='committed' "
                                 "group by proposal having count(*) > 1").fetchall(), "Double promotion")
        return {"public_objects_audited_including_unreachable": len(objects), "public_blobs_audited": blobs,
                "private_ancestor_absent": True, "sqlite_integrity": "ok"}

    def run(self):
        source = self.root / "source"
        source.mkdir()
        write(source, "shared.txt", "base\n")
        write(source, "README.txt", "Identical scripted ergonomics fixture\n")
        fixture_hash = hashlib.sha256(json.dumps(tree_manifest(source), sort_keys=True).encode()).hexdigest()
        self.cli({"op": "init", "source": str(source)})
        for actor in ACTORS:
            self.start(actor)
            opened = self.mutate(actor, "open", workspace=actor, path=str(self.paths[actor]))
            self.generations[actor] = opened["generation"]
            check(validation_state(opened) == "unchecked", opened)
            write(self.paths[actor], ".env", PRIVATE_MARKER + " excluded " + actor + "\n")
        # Explicitly empty policy documents the local safety boundary. Neither
        # normal flow nor response-loss injection configures a command runner.
        self.mutate("A", "configure", policy={"checks": []})
        write(self.paths["B"], "private-ancestor.txt", PRIVATE_MARKER + " ancestor\n")
        private_commit = self.checkpoint("B")["commit"]
        (self.paths["B"] / "private-ancestor.txt").unlink()
        for actor in "ABC":
            write(self.paths[actor], "shared.txt", actor + "\n")
        write(self.paths["D"], "progress.txt", "unrelated D progress\n")
        # Four real independent sessions submit overlapping checkpoint requests.
        gate = threading.Barrier(4)
        def capture(actor):
            gate.wait(timeout=30)
            return actor, self.checkpoint(actor)
        with ThreadPoolExecutor(max_workers=4) as pool:
            checkpoints = dict(pool.map(capture, ACTORS))
        original = {}
        for actor in ACTORS:
            result = self.mutate(actor, "publish", workspace=actor,
                                 checkpoint=checkpoints[actor]["checkpoint"], intent="Scripted ergonomics fixture")
            check(validation_state(result) == "unchecked", result)
            original[actor] = result["proposal"]
            self.proposals[actor].append(result["proposal"])
            self.roles[result["proposal"]] = actor + "-original"
            # Unselected live WIP begins only after selecting and publishing the
            # public snapshot. An ordinary local/ filename is not excluded.
            write(self.paths[actor], "local/keep.txt", PRIVATE_MARKER + " local " + actor + "\n")
            write(self.paths[actor], "unsaved-" + actor + ".txt", PRIVATE_MARKER + " unsaved " + actor + "\n")
            self.observe(actor, "queued")
        frozen = self.frozen()
        self.cli({"op": "integrate"})
        for actor in ACTORS:
            _, observed, tasks = self.observe(actor, "initial_integration")
            check(observed[0]["state"] == ("integrated" if actor in "AD" else "quarantined"), observed)
            check(validation_state(observed[0]) == "unchecked", observed)
            check(bool(tasks) == (actor in "BC"), tasks)
        check(frozen == self.frozen(), "Integration or reads modified owner WIP")
        self.assertions.append("unrelated proposal integrated past conflicting proposals; no automatic adoption")

        self.start("B-rival")
        first = self.open_resolution("B", original["B"], "first")
        rival = self.open_resolution("B", original["B"], "rival", client="B-rival")
        stale = self.open_resolution("C", original["C"], "stale")
        requests = [self.prepare_resolution(r, "A\nresolved-B\n") for r in (first, rival)]
        stale_request = self.prepare_resolution(stale, "A\nresolved-C\n")
        ready = threading.Barrier(2)
        def compete(item):
            resolution, request = item
            ready.wait(timeout=30)
            return request, self.clients[resolution["client"]].mutate(request)
        with ThreadPoolExecutor(max_workers=2) as pool:
            races = list(pool.map(compete, zip((first, rival), requests)))
        check(sorted(bool(reply.get("ok")) for _, reply in races) == [False, True], races)
        accepted_request, accepted = next(pair for pair in races if pair[1].get("ok"))
        rejected_request, rejected = next(pair for pair in races if not pair[1].get("ok"))
        self.remember_resolution("B", accepted, "B-resolution")
        self.cli({"op": "integrate"})
        stale_reply = self.clients["C"].mutate(stale_request)
        check(not stale_reply.get("ok") and "stale_resolution" in json.dumps(stale_reply), stale_reply)
        check("recovery" in stale_reply and "current_generation" in stale_reply, stale_reply)
        check(stale_reply["current_generation"] == self.generations[stale["workspace"]], stale_reply)
        self.observe("B", "competing_resolution")
        self.observe("C", "stale_resolution")
        fresh = self.open_resolution("C", original["C"], "fresh")
        fresh_request = self.prepare_resolution(fresh, "A\nresolved-B\nresolved-C\n")
        fresh_reply = self.clients["C"].mutate(fresh_request)
        self.remember_resolution("C", fresh_reply, "C-resolution")
        self.cli({"op": "integrate"})
        check(frozen == self.frozen(), "Resolution workflow modified owner WIP")
        self.assertions.append("two concurrent submissions yielded one durable resolution; stale head rejected and explicitly reopened")

        # Persisted failed-generation receipt stays bound to its original bytes.
        stale_generation_request = dict(op="checkpoint", workspace="D", expected_generation=0,
                                        operation_id=self.operation("stale-generation"))
        stale_generation = self.clients["D"].mutate(stale_generation_request)
        check(not stale_generation.get("ok") and stale_generation.get("error", {}).get("code") == "generation_mismatch", stale_generation)
        check(stale_generation["current_generation"] == self.generations["D"], stale_generation)
        check("recovery" in stale_generation, stale_generation)
        before = sum(self.ledger.calls.values())
        check(self.clients["D"].mutate(stale_generation_request) == stale_generation, "Failed receipt replay changed")
        check(sum(self.ledger.calls.values()) == before, "Terminal failed receipt unexpectedly called server")
        try:
            self.clients["D"].mutate(dict(stale_generation_request,
                                         expected_generation=self.generations["D"]))
        except self.helper.IdempotencyMismatch:
            pass
        else:
            raise AssertionError("Receipt accepted a changed request under its existing operation ID")
        check(sum(self.ledger.calls.values()) == before, "Changed receipt binding reached engine")
        self.assertions.append("stale-generation feedback includes current generation; terminal receipt replay costs no engine call")

        # Deliberate post-completion response withholding, NOT a process crash,
        # power loss, pre-commit failure, or server fault. The actor sees no result.
        lost_request = dict(op="checkpoint", workspace="D", expected_generation=self.generations["D"],
                            operation_id=self.operation("withheld-checkpoint"))
        actual_response = []
        counted = self.clients["D"]._call_engine
        def withhold(request, *args, **kwargs):
            response = counted(request, *args, **kwargs)
            if request == lost_request:
                actual_response.append(response)
                raise self.helper.TransportError("Fixture withheld a completed response")
            return response
        self.clients["D"]._call_engine = withhold
        with self.ledger.phase("recovery"):
            try:
                self.clients["D"].mutate(lost_request)
            except self.helper.UncertainOperation:
                pass
            else:
                raise AssertionError("Withheld response did not surface uncertainty")
            check(len(actual_response) == 1 and actual_response[0].get("ok"), actual_response)
            self.close("D")
            self.start("D")
            recovered = self.clients["D"].reconcile(lost_request["operation_id"])
        check(recovered == actual_response[0], "Durable recovery differs from committed outcome")
        self.generations["D"] = recovered["generation"]
        before = sum(self.ledger.calls.values())
        check(self.clients["D"].mutate(lost_request) == recovered, "Recovered receipt replay changed")
        check(before == sum(self.ledger.calls.values()), "Recovered terminal receipt called engine again")
        with closing(sqlite3.connect(self.state / "state.sqlite")) as db:
            count = db.execute("select count(*) from checkpoints where id=?", (lost_request["operation_id"],)).fetchone()[0]
            check(count == 1, "Withheld response produced duplicate checkpoint")
        self.assertions.append("withheld completed response recovered after graceful session restart via operation_status, without mutation replay")

        for actor in ACTORS:
            status, proposals, tasks = self.observe(actor, "before_explicit_adopt")
            check(not tasks, tasks)
            check(status["adopted"] != status["latest"], "Workspace adopted without request")
            check(all(validation_state(p) == "unchecked" for p in proposals), proposals)
        check(frozen == self.frozen(), "Recovery or status modified files")
        target = self.read("D", "status", workspace="D")["latest"]
        adopted = self.mutate("D", "adopt", workspace="D", target=target,
                              expected_generation=self.generations["D"])
        self.generations["D"] = adopted["generation"]
        check(validation_state(adopted) == "unchecked", adopted)
        expected_d = dict(frozen["D"])
        expected_d["shared.txt"] = hashlib.sha256(b"A\nresolved-B\nresolved-C\n").hexdigest()
        check(tree_manifest(self.paths["D"]) == expected_d, "Explicit adoption lost compatible WIP or excluded files")
        check(all(tree_manifest(self.paths[a]) == frozen[a] for a in "ABC"), "Adoption changed other owners")
        self.observe("D", "after_explicit_adopt")
        self.assertions.append("explicit adoption preserved all compatible unsaved and excluded files; other owners unchanged")
        checks = self.run_required_checks() if self.required_checks else {
            "state": "not_run", "reason": "Required-check command execution is native-CI-only"}
        audit = self.audit(private_commit)
        return {"mode": self.mode, "fixture_sha256": fixture_hash, "actors": list(ACTORS),
                "actor_kind": "deterministic scripted personas, not autonomous model agents",
                "assertions": self.assertions, "observations": self.observations,
                "final_worktrees": self.frozen(), "audit": audit, "required_checks": checks,
                "competing_resolution": {"accepted": 1, "rejected": 1,
                                         "accepted_workspace": accepted_request["resolution_workspace"],
                                         "rejection_code": rejected.get("error", {}).get("code")},
                "call_counts": self.ledger.report()}

    def run_required_checks(self):
        require_ci_checks(True)
        # This method is never reached in default/local runs. The required check
        # validates a tiny synthetic file and runs only on the authorized runner.
        program = ("from pathlib import Path; import sys; "
                   "p=Path('business.txt'); sys.exit(7 if p.exists() and p.read_text() != 'valid\\n' else 0)")
        self.mutate("A", "configure", policy={"checks": [{"id": "semantic-fixture", "required": True,
                    "argv": [sys.executable, "-c", program], "timeout_seconds": 5}]})
        # D has explicitly adopted latest; its private WIP must not be published.
        # An additional fresh isolated actor therefore owns the checks campaign.
        self.start("E-checks")
        path = self.root / "work-E-checks"
        opened = self.mutate("E-checks", "open", workspace="E-checks", path=str(path))
        self.generations["E-checks"] = opened["generation"]
        write(path, "business.txt", "invalid\n")
        checkpoint = self.checkpoint("E-checks")
        published = self.mutate("E-checks", "publish", workspace="E-checks",
                                checkpoint=checkpoint["checkpoint"], intent="Native CI failed required-check fixture")
        check(validation_state(published) == "pending", published)
        head_before_failed_check = self.read("E-checks", "status")["head"]
        self.cli({"op": "integrate"})
        failed = self.read("E-checks", "proposal_status", proposal=published["proposal"])
        check(failed["state"] == "quarantined" and validation_state(failed) == "failed", failed)
        check(failed["validation"]["checks_failed"] == 1, failed)
        check(self.read("E-checks", "status")["head"] == head_before_failed_check,
              "Failed required check advanced the public head")
        task = self.read("E-checks", "resolution_tasks", workspace="E-checks")["tasks"][0]
        check(task["reason"] == "required_checks_failed" and not task["conflict_paths"], task)
        resolution = self.open_resolution("E-checks", published["proposal"], "checks")
        write(resolution["path"], "business.txt", "valid\n")
        checkpoint = self.checkpoint("E-checks", resolution["workspace"])
        submitted = self.mutate("E-checks", "resolution_submit", workspace="E-checks",
                                proposal=published["proposal"], resolution_workspace=resolution["workspace"],
                                checkpoint=checkpoint["checkpoint"], expected_head=resolution["head"],
                                resolved_conflicts=resolution["conflicts"])
        check(validation_state(submitted) == "pending", submitted)
        self.cli({"op": "integrate"})
        passed = self.read("E-checks", "proposal_status", proposal=submitted["proposal"])
        check(passed["state"] == "integrated" and validation_state(passed) == "passed", passed)
        check(passed["validation"]["checks_passed"] == 1, passed)
        check(path.joinpath("business.txt").read_text() == "invalid\n", "Check repair adopted owner files")
        return {"state": "passed", "observed_validation_states": ["pending", "failed", "pending", "passed"],
                "required_check_failure_exit": 7, "owner_worktree_unchanged": True,
                "failed_candidate_did_not_advance_public_head": True,
                "semantic_correctness_claimed": False}


def compare_runs(baseline, compact):
    for field in ("fixture_sha256", "observations", "final_worktrees"):
        check(baseline[field] == compact[field], "Observation recipes diverged in " + field)
    old = baseline["call_counts"]["observation_engine_requests"]
    new = compact["call_counts"]["observation_engine_requests"]
    check(new < old, "Compact recipe did not reduce observation requests")
    return {"same_revised_binary": True, "identical_fixture": True, "equivalent_observed_state": True,
            "equivalent_final_worktrees": True, "repeated_read_observation_calls": old,
            "compact_status_observation_calls": new, "observation_calls_saved": old - new,
            "observation_call_reduction_percent": round(100 * (old - new) / old, 2),
            "scope": "Identical scripted fixture; only the observation recipe differs. Baseline deliberately issues redundant reads against the same revised server.",
            "not_established": ["autonomous model success or reasoning quality", "general agent productivity",
                                "latency or throughput improvement", "pre-change server payload comparison",
                                "power-loss or pre-commit crash recovery", "multi-host isolation"]}


@contextmanager
def cleanup_preserving_failure(cleanup, summary):
    """Always attempt cleanup without replacing the campaign's primary failure."""
    primary = None
    try:
        yield
    except BaseException as error:
        primary = error
        raise
    finally:
        try:
            cleanup()
        except Exception as error:
            summary.setdefault("cleanup_failure_types", []).append(type(error).__name__)
            if primary is None:
                raise
            add_note = getattr(primary, "add_note", None)
            if callable(add_note):
                add_note("Additional cleanup failure: " + type(error).__name__)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, default=ROOT / "target/debug" / ("wipstash.exe" if os.name == "nt" else "wipstash"))
    parser.add_argument("--artifacts", type=Path, default=ROOT / "evidence/agent-ergonomics")
    parser.add_argument("--required-checks-ci", action="store_true")
    args = parser.parse_args(argv)
    try:
        require_ci_checks(args.required_checks_ci)
    except ValueError as error:
        parser.error(str(error))
    binary = args.binary.resolve(strict=True)
    helper = load_helper()
    started = time.monotonic()
    summary = {"schema_version": 1, "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
               "platform": platform.platform(), "actor_kind": "deterministic scripted personas",
               "transport": "long-lived real stdio MCP; init/integrate use real CLI",
               "required_checks_requested": args.required_checks_ci, "runs": []}
    args.artifacts.mkdir(parents=True, exist_ok=True)
    try:
        temporary = tempfile.TemporaryDirectory(prefix="wip-ergo-")
        with cleanup_preserving_failure(temporary.cleanup, summary):
            scratch = temporary.name
            for mode in ("repeated_reads", "compact_status"):
                campaign = Campaign(binary, Path(scratch).resolve() / mode, mode, helper, args.required_checks_ci)
                with cleanup_preserving_failure(campaign.cleanup, summary):
                    summary["runs"].append(campaign.run())
                summary["runs"][-1]["verified_graceful_eof_shutdowns"] = campaign.eof_shutdowns
            summary["comparison"] = compare_runs(*summary["runs"])
        summary["state"] = "passed"
    except Exception as error:
        summary["state"] = "failed"
        # No raw responses/journal contents are published on failure.
        summary["failure_type"] = type(error).__name__
        raise
    finally:
        summary["elapsed_seconds_descriptive_only"] = round(time.monotonic() - started, 3)
        (args.artifacts / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps({"state": summary["state"], "comparison": summary["comparison"],
                      "summary": str(args.artifacts / "summary.json")}, indent=2))


if __name__ == "__main__":
    main()
