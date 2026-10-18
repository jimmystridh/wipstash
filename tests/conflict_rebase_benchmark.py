#!/usr/bin/env python3
"""Matched, deterministic four-actor stale-resolution benchmark.

This is scripted contention with a frozen logical schedule, not model-authored
work or simultaneous-process/storage stress. Each CLI invocation uses ordinary
subprocess.run without a timeout, termination, sockets, policy commands, or fault
injection. All operations/rounds are bounded; existing fixture trees are refused.

Example (separate retained output directories are mandatory):
  python tests/conflict_rebase_benchmark.py --binary OLD --expect baseline \
      --artifacts /absolute/path/before
  python tests/conflict_rebase_benchmark.py --binary NEW --expect optimized \
      --artifacts /absolute/path/after --compare /absolute/path/before/summary.json

Both runs use the same rotations, edits, barriers, head-move order, and simulated
think delay. Actual elapsed times and Git commit timestamps are not deterministic.
Recovery opens/checkpoints differ only as a consequence of the tested behavior.
"""

import argparse
from collections import Counter, defaultdict
import contextlib
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import shutil
import sqlite3
import subprocess
import sys
import time
import traceback


ACTORS = "ABCD"
MODES = ("disjoint", "overlap", "repeated")
FIXTURE = Path(__file__).parent / "fixtures" / "base"
BASELINE_SHA256 = "ded60ad5c3a533d01cf646228f03f38e7e3aa5b45941da115f5e6429233d9a51"
PRIVATE_MARKER = b"PRIVATE_REBASE_CANARY"


def sha(data):
    return hashlib.sha256(data).hexdigest()


def json_write(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def stats(values):
    """Nearest-rank quantiles; no interpolation or unstated population claim."""
    values = sorted(values)
    if not values:
        return {"n": 0, "p50": None, "p95": None, "max": None}
    return {"n": len(values), "p50": values[math.ceil(len(values) * .5) - 1],
            "p95": values[math.ceil(len(values) * .95) - 1], "max": values[-1]}


def write(root, relative, data):
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data.encode() if isinstance(data, str) else data)


def manifest(root):
    return {p.relative_to(root).as_posix(): {"sha256": sha(p.read_bytes()),
            "mode": "100755" if p.stat().st_mode & 0o111 else "100644"}
            for p in sorted(root.rglob("*")) if p.is_file()}


def content(value, tail="base"):
    # The distant tail is a same-file, non-overlapping merge, not merely a
    # different-file shortcut. The expected text is independent of engine output.
    return ("value=" + value + "\n" + "".join("context-%02d\n" % i
            for i in range(24)) + "tail=" + tail + "\n").encode()


class Case:
    def __init__(self, binary, root, mode, rotation, think_ms, expect):
        self.binary, self.root, self.mode = binary, root, mode
        self.rotation, self.think_ms, self.expect = rotation, think_ms, expect
        self.root.mkdir(parents=True)
        self.state = root / "state"
        self.repo = self.state / "coordinator.git"
        self.events, self.schedule, self.samples = [], [], []
        self.serial = 0
        self.generations, self.paths, self.open_counts = {}, {}, Counter()
        self.counts, self.actor_counts = Counter(), defaultdict(Counter)
        self.private_oids, self.private_refs = set(), []
        self.expected, self.values, self.tails = {}, {}, {}
        order = list(ACTORS[rotation % 4:] + ACTORS[:rotation % 4])
        self.winner, self.losers = order[0], order[1:]
        # Reverse alternate rotations, so completion position rotates too.
        if rotation % 2:
            self.losers.reverse()
        self.order = [self.winner] + self.losers
        self.round_started = None
        self.round_finished = None

    def operation(self, actor, expected=True, error=None, **request):
        self.serial += 1
        if self.serial > 350:
            raise AssertionError("bounded operation budget exceeded")
        request.setdefault("operation_id", "op-%04d" % self.serial)
        argv = [str(self.binary), "--state", str(self.state), json.dumps(request)]
        started = time.perf_counter()
        result = subprocess.run(argv, capture_output=True, text=True, errors="replace")
        ended = time.perf_counter()
        try:
            response = json.loads(result.stdout)
        except ValueError as exc:
            raise AssertionError("non-JSON CLI response: " + result.stdout + result.stderr) from exc
        event = {"actor": actor, "request": request, "response": response,
                 "exit": result.returncode, "stderr": result.stderr,
                 "seconds": ended - started, "started": started, "ended": ended}
        self.events.append(event)
        self.counts["cli_requests"] += 1
        self.actor_counts[actor]["cli_requests"] += 1
        self.actor_counts[actor]["cli_seconds"] += ended - started
        if expected is not None:
            assert response.get("ok", False) is expected, event
        if error:
            assert response.get("error", {}).get("code") == error, event
        assert result.returncode == (0 if response.get("ok", False) else 1), event
        return response

    def git(self, repo, *arguments, input_bytes=None):
        result = subprocess.run(["git", "--git-dir", str(repo), *arguments],
                                input=input_bytes, capture_output=True)
        assert result.returncode == 0, (arguments, result.stderr.decode(errors="replace"))
        return result.stdout

    def rows(self, query, parameters=()):
        # Audit only. No direct persistent-state edits are used by this harness.
        with contextlib.closing(sqlite3.connect(
                self.state.joinpath("state.sqlite").as_uri() + "?mode=ro", uri=True)) as db:
            return db.execute(query, parameters).fetchall()

    def workspace_state(self, workspace):
        return self.rows("select base,checkpoint,generation from workspaces where id=?",
                         (workspace,))

    def checkpoint(self, workspace, actor):
        result = self.operation(actor, op="checkpoint", workspace=workspace,
                                expected_generation=self.generations[workspace])
        self.generations[workspace] = result["generation"]
        return result

    def open_workspace(self, workspace, actor):
        path = self.root / workspace
        result = self.operation(actor, op="open", workspace=workspace, path=str(path))
        self.generations[workspace] = result["generation"]
        return path

    def publish(self, workspace, actor):
        cp = self.checkpoint(workspace, actor)
        return self.operation(actor, op="publish", workspace=workspace,
                              checkpoint=cp["checkpoint"], intent="Fixed matched rebase trace")["proposal"]

    def expected_write(self, path, data):
        self.expected[path] = {"sha256": sha(data), "mode": "100644"}

    def batch_blobs(self, repo, oids):
        if not oids:
            return []
        raw = self.git(repo, "cat-file", "--batch", input_bytes=("\n".join(oids) + "\n").encode())
        result, offset = [], 0
        for expected in oids:
            end = raw.index(b"\n", offset)
            oid, kind, size = raw[offset:end].split()
            assert oid.decode() == expected and kind == b"blob", (oid, kind)
            size, offset = int(size), end + 1
            result.append(raw[offset:offset + size])
            offset += size
            assert raw[offset:offset + 1] == b"\n"
            offset += 1
        assert offset == len(raw)
        return result

    def oracle(self):
        raw = self.git(self.repo, "ls-tree", "-rz", "refs/wipstash/integration")
        entries = []
        for entry in raw.split(b"\0"):
            if entry:
                meta, path = entry.split(b"\t", 1)
                mode, kind, oid = meta.split()
                assert kind == b"blob", entry
                entries.append((path.decode(), mode.decode(), oid.decode()))
        blobs = self.batch_blobs(self.repo, [item[2] for item in entries])
        actual = {path: {"mode": mode, "sha256": sha(blob)}
                  for (path, mode, _), blob in zip(entries, blobs)}
        assert actual == self.expected, {"expected": self.expected, "actual": actual}
        self.counts["oracle_snapshots_passed"] += 1

    def integrate(self, actor, states):
        result = self.operation(actor, op="integrate")
        assert [outcome["state"] for outcome in result["outcomes"]] == states, result
        self.counts["integrations"] += states.count("integrated")
        self.actor_counts[actor]["integrated_checkpoints"] += states.count("integrated")
        self.oracle()
        return self.events[-1]["ended"]

    def private_checkpoint(self, workspace, actor, filename):
        path = self.root / workspace
        write(path, filename, PRIVATE_MARKER + b" " + workspace.encode() + b"\n")
        cp = self.checkpoint(workspace, actor)
        repo = self.state / "locals" / workspace / "objects.git"
        blob = self.git(repo, "rev-parse", cp["commit"] + ":" + filename).decode().strip()
        self.private_oids.update((cp["commit"], blob))
        self.private_refs.append((repo, cp["commit"], filename, blob))
        (path / filename).unlink()

    def open_resolution(self, actor, proposal):
        self.open_counts[actor] += 1
        workspace = "resolve-%s-%d" % (actor, self.open_counts[actor])
        path = self.root / workspace
        opened = self.operation(actor, op="resolution_open", workspace=actor,
                                proposal=proposal, resolution_workspace=workspace, path=str(path))
        self.generations[workspace] = opened["generation"]
        assert opened["conflict_paths"] == ["hotspots/" + actor + ".txt"], opened
        self.counts["resolution_opens"] += 1
        self.actor_counts[actor]["resolution_opens"] += 1
        return {"workspace": workspace, "path": path, "opened": opened,
                "started": self.events[-1]["started"]}

    def resolve(self, actor, resolution):
        path = "hotspots/" + actor + ".txt"
        resolved = content(self.values[actor] + "+resolved-" + actor, self.tails[actor])
        write(resolution["path"], path, resolved)
        self.counts["resolution_edits"] += 1
        self.actor_counts[actor]["resolution_edits"] += 1
        return resolved

    def submit_request(self, actor, proposal, resolution, checkpoint):
        return {"op": "resolution_submit", "workspace": actor, "proposal": proposal,
                "resolution_workspace": resolution["workspace"], "checkpoint": checkpoint,
                "expected_head": resolution["opened"]["current_head"],
                "resolved_conflicts": resolution["opened"]["conflict_paths"]}

    def task(self, actor, proposal):
        status = self.operation(actor, op="proposal_status", proposal=proposal)
        return status["resolution_task"]

    def move_head(self, number, target=None, overlap=False):
        workspace = "move-%02d" % number
        path = self.open_workspace(workspace, self.winner)
        if target:
            relative = "hotspots/" + target + ".txt"
            if overlap:
                self.values[target] = "anchor-%s-move-%d" % (self.winner, number)
            else:
                self.tails[target] = "disjoint-tail-%d" % number
            data = content(self.values[target], self.tails[target])
        else:
            relative = "arrivals/%02d.txt" % number
            data = ("arrival-%d-by-%s\n" % (number, self.winner)).encode()
        self.schedule.append({"kind": "head_move", "number": number, "actor": self.winner,
                              "path": relative, "sha256": sha(data)})
        write(path, relative, data)
        self.publish(workspace, self.winner)
        self.expected_write(relative, data)
        self.integrate(self.winner, ["integrated"])

    def guard_checks(self, actor, proposal, resolution, cp):
        request = self.submit_request(actor, proposal, resolution, cp)
        # Checkpoint generations, ownership, exact attestation and live-tree
        # validation must all remain intact before exercising the stale path.
        self.operation(actor, expected=False, error="generation_mismatch", op="checkpoint",
                       workspace=resolution["workspace"], expected_generation=0)
        self.operation(actor, expected=False, **dict(request, workspace=self.winner))
        self.operation(actor, expected=False, error="stale_resolution",
                       **dict(request, expected_head="0" * 40))
        self.operation(actor, expected=False, error="resolution_attestation_required",
                       **dict(request, resolved_conflicts=[]))
        self.operation(actor, expected=False, error="resolution_attestation_required",
                       **dict(request, resolved_conflicts=request["resolved_conflicts"] * 2))
        write(resolution["path"], "dirty-after-checkpoint.txt", "must not publish\n")
        self.operation(actor, expected=False, error="stale_resolution_checkpoint", **request)
        (resolution["path"] / "dirty-after-checkpoint.txt").unlink()
        # A newer same-byte checkpoint advances the generation. Replaying the
        # previously selected checkpoint must fail even though its tree matches.
        latest_cp = self.checkpoint(resolution["workspace"], actor)["checkpoint"]
        self.operation(actor, expected=False, error="stale_resolution_checkpoint", **request)
        self.counts["guards_passed"] += 7
        return latest_cp

    def run(self):
        source = self.root / "source"
        shutil.copytree(FIXTURE, source)
        for actor in ACTORS:
            write(source, "hotspots/" + actor + ".txt", content("base"))
        self.expected = manifest(source)
        self.operation("setup", op="init", source=str(source))
        for actor in ACTORS:
            self.paths[actor] = self.open_workspace(actor, actor)
            for path, data in ((".env", "NOT_A_REAL_SECRET_" + actor),
                               ("local/keep.bin", "private-local-" + actor),
                               ("build/cache.bin", "private-build-" + actor),
                               (".agent/session.txt", "private-agent-" + actor)):
                write(self.paths[actor], path, data)
        # Both original-owner and resolver private ancestry are excluded from
        # every public object, including unreachable objects, after all submits.
        self.private_checkpoint(self.losers[0], self.losers[0], "private-ancestor.txt")
        proposals, publish_started = {}, {}
        for actor in self.order:
            if actor == self.winner:
                changes = self.losers
                value = "anchor-" + actor
            else:
                changes, value = [actor], "proposal-" + actor
            for target in changes:
                data = content(value)
                write(self.paths[actor], "hotspots/" + target + ".txt", data)
                if actor == self.winner:
                    self.values[target], self.tails[target] = value, "base"
                    self.expected_write("hotspots/" + target + ".txt", data)
            self.schedule.append({"kind": "initial_proposal", "actor": actor,
                                  "targets": changes, "value": value})
            cp = self.checkpoint(actor, actor)
            if self.round_started is None:
                self.round_started = time.perf_counter()
            response = self.operation(actor, op="publish", workspace=actor,
                                      checkpoint=cp["checkpoint"], intent="Fixed matched rebase trace")
            proposals[actor] = response["proposal"]
            publish_started[actor] = self.events[-1]["started"]
            write(self.paths[actor], "unpublished-" + actor + ".txt", PRIVATE_MARKER + actor.encode())
        frozen = {actor: (manifest(path), self.workspace_state(actor))
                  for actor, path in self.paths.items()}
        integrated_at = self.integrate(self.winner, ["integrated"] + ["quarantined"] * 3)
        self.samples.append({"actor": self.winner, "kind": "initial_winner",
                             "publish_to_integrated_seconds": integrated_at - publish_started[self.winner]})
        resolutions = {}
        for actor in self.losers:
            self.operation(actor, expected=False, op="resolution_open", workspace=self.winner,
                           proposal=proposals[actor], resolution_workspace="wrong-owner-" + actor,
                           path=str(self.root / ("wrong-owner-" + actor)))
            self.counts["guards_passed"] += 1
            assert self.task(actor, proposals[actor])["attempt"] == 0
            resolution = self.open_resolution(actor, proposals[actor])
            self.resolve(actor, resolution)
            self.private_checkpoint(resolution["workspace"], actor, "private-resolver-ancestor.txt")
            cp = self.checkpoint(resolution["workspace"], actor)["checkpoint"]
            resolution["checkpoint"] = cp
            resolutions[actor] = resolution
            resolution["checkpoint"] = self.guard_checks(actor, proposals[actor], resolution, cp)
        for index, actor in enumerate(self.losers):
            other = resolutions[self.losers[(index + 1) % len(self.losers)]]
            request = self.submit_request(actor, proposals[actor], other, other["checkpoint"])
            self.operation(actor, expected=False, error="resolution_owner_mismatch", **request)
            self.counts["guards_passed"] += 1
        moves = 3 if self.mode == "repeated" else 1
        for number in range(1, moves + 1):
            self.move_head(number)
        for index, actor in enumerate(self.losers):
            original = resolution = resolutions[actor]
            if self.mode in ("overlap", "repeated"):
                self.move_head(moves + index + 1, actor, overlap=self.mode == "overlap")
            request = self.submit_request(actor, proposals[actor], resolution,
                                          resolution["checkpoint"])
            # Substituting the latest head into an old request must never grant
            # permission to use old bytes, even when the remap could merge.
            actual_head = self.operation(actor, op="status")["head"]
            assert actual_head != request["expected_head"]
            self.operation(actor, expected=False, error="stale_resolution",
                           **dict(request, expected_head=actual_head))
            self.counts["guards_passed"] += 1
            self.schedule.append({"kind": "submit_slot", "actor": actor,
                                  "think_ms": self.think_ms, "mode": self.mode})
            if self.think_ms:
                time.sleep(self.think_ms / 1000)
            before = manifest(resolution["path"])
            result = self.operation(actor, expected=None, **request)
            first_accepted = result.get("ok", False)
            expected_acceptance = self.expect == "optimized" and self.mode != "overlap"
            assert first_accepted == expected_acceptance, result
            if first_accepted:
                assert result["head_advanced"] is True and result["observed_head"] == actual_head, result
                assert result["base"] == original["opened"]["current_head"], result
                assert result["checks_pending"] is True, result
                self.counts["resolved_edits_retained_without_reopen"] += 1
                self.actor_counts[actor]["resolved_edits_retained_without_reopen"] += 1
            else:
                assert result["error"]["code"] == "stale_resolution", result
                self.counts["rejected_stale_submissions"] += 1
                self.actor_counts[actor]["rejected_stale_submissions"] += 1
                assert manifest(resolution["path"]) == before
                assert self.task(actor, proposals[actor])["attempt"] == 0
                resolution = self.open_resolution(actor, proposals[actor])
                self.resolve(actor, resolution)
                cp = self.checkpoint(resolution["workspace"], actor)["checkpoint"]
                result = self.operation(actor, **self.submit_request(actor, proposals[actor], resolution, cp))
                self.counts["reopens"] += 1
                self.actor_counts[actor]["reopens"] += 1
            assert manifest(original["path"]) == before, "submit changed an existing resolution directory"
            assert result["attempt"] == 1 and result["checks_pending"] is True, result
            accepted = result["proposal"]
            submitted_at = self.events[-1]["ended"]
            self.values[actor] += "+resolved-" + actor
            self.expected_write("hotspots/" + actor + ".txt", content(self.values[actor], self.tails[actor]))
            integrated_at = self.integrate(actor, ["integrated"])
            self.round_finished = integrated_at
            assert self.operation(actor, op="proposal_status", proposal=accepted)["state"] == "integrated"
            assert self.operation(actor, op="proposal_status", proposal=proposals[actor])["state"] == "superseded"
            self.samples.append({"actor": actor, "kind": "resolved",
                                 "first_submit_accepted": first_accepted,
                                 "publish_to_integrated_seconds": integrated_at - publish_started[actor],
                                 "resolution_open_to_integrated_seconds": integrated_at - original["started"],
                                 "accepted_submit_to_integrated_seconds": integrated_at - submitted_at})
        for actor, path in self.paths.items():
            assert (manifest(path), self.workspace_state(actor)) == frozen[actor], "private owner state changed"
            assert self.operation(actor, op="resolution_tasks", workspace=actor)["tasks"] == []
        self.audit()
        self.counts["initial_proposals_completed"] = 4
        self.counts["resolutions_completed"] = 3
        return self.summary()

    def audit(self):
        self.git(self.repo, "fsck", "--full", "--strict")
        objects = self.git(self.repo, "cat-file", "--batch-all-objects",
                           "--batch-check=%(objectname) %(objecttype)").decode().splitlines()
        object_ids = {line.split()[0] for line in objects}
        assert not self.private_oids & object_ids, "private checkpoint ancestry leaked"
        blobs = [line.split()[0] for line in objects if line.endswith(" blob")]
        for blob in self.batch_blobs(self.repo, blobs):
            assert PRIVATE_MARKER not in blob and b"NOT_A_REAL_SECRET_" not in blob
        for repo, commit, filename, expected_blob in self.private_refs:
            assert self.git(repo, "rev-parse", commit + ":" + filename).decode().strip() == expected_blob
        assert self.rows("pragma integrity_check") == [("ok",)]
        assert self.rows("select proposal from promotions where state='committed' "
                         "group by proposal having count(*)>1") == []
        assert not (self.repo / "objects/info/alternates").exists()
        self.counts["private_objects_verified_absent"] = len(self.private_oids)
        self.counts["private_workspaces_preserved"] = 4

    def summary(self):
        wall = self.round_finished - self.round_started
        actors = {}
        for actor in ACTORS:
            values = dict(self.actor_counts[actor])
            values["initial_proposals_completed"] = 1
            values["initial_proposal_throughput_per_second"] = 1 / wall
            values["publish_to_integrated_seconds"] = next(
                sample["publish_to_integrated_seconds"] for sample in self.samples if sample["actor"] == actor)
            actors[actor] = values
        return {"name": self.root.name, "mode": self.mode, "rotation": self.rotation,
                "actor_order": self.order, "counts": dict(self.counts), "actors": actors,
                "scheduled_workload_seconds": wall, "samples": self.samples,
                "initial_proposals_per_second": 4 / wall,
                "all_integrations_per_second": self.counts["integrations"] / wall,
                "schedule_sha256": sha(json.dumps(self.schedule, sort_keys=True).encode()),
                "final_manifest_sha256": sha(json.dumps(self.expected, sort_keys=True).encode()),
                "schedule": self.schedule, "final_expected_manifest": self.expected}

    def save(self):
        json_write(self.root / "commands.json", self.events)
        json_write(self.root / "schedule.json", self.schedule)


def aggregate(cases):
    counts, actors = Counter(), defaultdict(Counter)
    latencies, actor_latencies = defaultdict(list), defaultdict(lambda: defaultdict(list))
    total_seconds = sum(case["scheduled_workload_seconds"] for case in cases)
    for case in cases:
        counts.update(case["counts"])
        for actor, values in case["actors"].items():
            for key in ("initial_proposals_completed", "integrated_checkpoints", "resolution_opens",
                        "resolution_edits", "reopens", "rejected_stale_submissions",
                        "resolved_edits_retained_without_reopen", "cli_requests", "cli_seconds"):
                actors[actor][key] += values.get(key, 0)
        for sample in case["samples"]:
            for key, value in sample.items():
                if key.endswith("_seconds"):
                    latencies[key].append(value)
                    actor_latencies[sample["actor"]][key].append(value)
    for actor, values in actors.items():
        values["initial_proposal_throughput_per_second"] = values["initial_proposals_completed"] / total_seconds
        values["latency_seconds"] = {name: stats(samples)
                                     for name, samples in actor_latencies[actor].items()}
    completions = [actors[a]["initial_proposals_completed"] for a in ACTORS]
    fairness = sum(completions) ** 2 / (len(completions) * sum(n * n for n in completions))
    return {"counts": dict(counts), "actors": dict(actors),
            "latency_seconds": {name: stats(values) for name, values in latencies.items()},
            "scheduled_workload_seconds": total_seconds,
            "initial_proposals_per_second": counts["initial_proposals_completed"] / total_seconds,
            "all_integrations_per_second": counts["integrations"] / total_seconds,
            "jain_index_equal_offered_initial_work_completed": fairness,
            "fairness_scope": "Equal bounded offered work; not scheduler fairness or sustained saturation."}


def compare(before, after):
    assert before["passed"] and after["passed"], "both independent runs must pass"
    assert before["configuration"] == after["configuration"], "unmatched configuration"
    assert before["harness_sha256"] == after["harness_sha256"], "harness changed between measurements"
    assert before["expect"] == "baseline" and after["expect"] == "optimized"
    prior = {case["name"]: case for case in before["cases"]}
    rows = []
    for case in after["cases"]:
        old = prior[case["name"]]
        assert old["schedule_sha256"] == case["schedule_sha256"], "unmatched business trace"
        assert old["final_manifest_sha256"] == case["final_manifest_sha256"], "semantic divergence"
        rows.append({"case": case["name"], "mode": case["mode"],
                     "before_seconds": old["scheduled_workload_seconds"],
                     "after_seconds": case["scheduled_workload_seconds"],
                     "before_reopens": old["counts"].get("reopens", 0),
                     "after_reopens": case["counts"].get("reopens", 0)})
    return {"matched_cases": len(rows), "all_schedules_and_final_oracles_match": True,
            "before_binary_sha256": before["binary_sha256"],
            "after_binary_sha256": after["binary_sha256"], "cases": rows,
            "before": before["aggregate"], "after": after["aggregate"],
            "limits": "Fixed-order local scripted sample. Extra safety preflight can cost CPU. "
                      "No guaranteed speedup, model-authored result, saturation, storage-race, "
                      "cross-platform or SQLITE_IOERR-fix claim."}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--artifacts", required=True, type=Path)
    parser.add_argument("--expect", choices=("baseline", "optimized"), required=True)
    parser.add_argument("--rotations", type=int, default=4)
    parser.add_argument("--think-ms", type=int, default=5)
    parser.add_argument("--compare", type=Path)
    args = parser.parse_args()
    assert 1 <= args.rotations <= 12 and 0 <= args.think_ms <= 1000
    assert not os.environ.get("WIPSTASH_FAULT"), "fault injection is outside this benchmark"
    binary, artifacts = args.binary.resolve(), args.artifacts.resolve()
    binary_sha = sha(binary.read_bytes())
    if args.expect == "baseline":
        assert binary_sha == BASELINE_SHA256, "baseline is not the frozen approved executable"
    # Never delete, reset, or overwrite a previous run's source/store/evidence.
    artifacts.mkdir(parents=True, exist_ok=False)
    harness_bytes = Path(__file__).read_bytes()
    (artifacts / "harness.py").write_bytes(harness_bytes)
    fixture_before = manifest(FIXTURE)
    summary = {"passed": False, "binary": str(binary), "binary_sha256": binary_sha,
               "harness_sha256": sha(harness_bytes),
               "expect": args.expect, "platform": platform.platform(),
               "configuration": {"rotations": args.rotations, "think_ms": args.think_ms,
                                 "modes": list(MODES), "actors": ACTORS},
               "method": "Deterministic barrier-style logical contention; sequential real CLI processes. "
                         "Same business edits, head moves, order and think delays; recovery differs by behavior.",
               "latency_definition": "Wall times include scripted scheduling, intervening work and audit reads; "
                                     "p50/p95 use nearest rank. No human/model resolution time is simulated beyond think_ms.",
               "limits": "Not simultaneous writer stress, native coding agents, CI, required-policy execution, "
                         "saturation, multi-host or an explanation/fix for prior SQLITE_IOERR.",
               "cases": []}
    try:
        for mode in MODES:
            for rotation in range(args.rotations):
                case = Case(binary, artifacts / (mode + "-%02d" % rotation), mode,
                            rotation, args.think_ms, args.expect)
                try:
                    result = case.run()
                    summary["cases"].append(result)
                    print(json.dumps({"case": result["name"], "passed": True,
                                      "counts": result["counts"],
                                      "seconds": result["scheduled_workload_seconds"]}), flush=True)
                finally:
                    case.save()
                    json_write(artifacts / "summary.json", summary)
        assert manifest(FIXTURE) == fixture_before, "checked-in fixture was changed"
        assert sha(binary.read_bytes()) == binary_sha, "executable changed during measurement"
        summary["aggregate"] = aggregate(summary["cases"])
        summary["by_mode"] = {mode: aggregate([case for case in summary["cases"] if case["mode"] == mode])
                              for mode in MODES}
        operations = defaultdict(list)
        for case in summary["cases"]:
            for event in json.loads((artifacts / case["name"] / "commands.json").read_text()):
                operations[event["request"]["op"]].append(event["seconds"])
        summary["cli_operation_latency_seconds"] = {name: stats(values) for name, values in operations.items()}
        summary["passed"] = True
        if args.compare:
            comparison = compare(json.loads(args.compare.read_text()), summary)
            json_write(artifacts / "comparison.json", comparison)
    except Exception as exc:
        summary["passed"] = False
        summary["failure"] = {"type": type(exc).__name__, "message": str(exc),
                              "traceback": traceback.format_exc()}
        traceback.print_exc()
    finally:
        json_write(artifacts / "summary.json", summary)
    print(json.dumps({"passed": summary["passed"], "summary": str(artifacts / "summary.json")}), flush=True)
    return 0 if summary["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
