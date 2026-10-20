#!/usr/bin/env python3
"""Exercise sharing, background workers, repair ownership and timing through real CLI subprocesses."""
import argparse
import concurrent.futures
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import time
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "examples/clients"))
from wipstash_client import WipstashClient

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--binary", default="target/debug/wipstash.exe" if os.name == "nt" else "target/debug/wipstash")
parser.add_argument("--artifacts")
args, tests = parser.parse_known_args()
BINARY = str(Path(args.binary).resolve())
MEASUREMENTS = []


class AsyncValidation(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="wipstash-async-")
        self.root = Path(self.temp.name).resolve()
        self.state = self.root / "state"
        source = self.root / "source"
        source.mkdir()
        (source / "file.txt").write_text("good\n")
        self.cli(dict(op="init", source=str(source)))
        self.clients, self.paths = {}, {}
        for actor in "ABC":
            self.paths[actor] = self.root / actor
            client = WipstashClient([BINARY, "--state", str(self.state)], self.root / ("journal-" + actor), timeout=60)
            self.clients[actor] = client
            opened = client.mutate(dict(op="clone", workspace=actor, path=str(self.paths[actor]), operation_id="clone-" + actor))
            self.assertTrue(opened["ok"], opened)

    def tearDown(self):
        for client in self.clients.values():
            client.close()
        self.temp.cleanup()

    def cli(self, body):
        done = subprocess.run([BINARY, "--state", str(self.state), json.dumps(body)], capture_output=True, text=True, timeout=60)
        self.assertEqual(done.returncode, 0, done.stderr + done.stdout)
        value = json.loads(done.stdout)
        self.assertTrue(value["ok"], value)
        return value

    def policy(self, code=None, executable=None):
        code = code or "from pathlib import Path; import sys; print('fixture check'); sys.exit('bad' in Path('file.txt').read_text())"
        return self.cli(dict(op="configure", operation_id="policy-" + str(time.time_ns()), policy={"checks": [dict(id="fixture", argv=[executable or sys.executable, "-B", "-c", code], required=True, timeout_seconds=30)]}))

    def commit(self, actor, identifier, generation=0):
        result = self.clients[actor].mutate(dict(op="commit", workspace=actor, message=identifier, operation_id=identifier, expected_generation=generation))
        self.assertTrue(result["ok"], result)
        return result

    def tick(self):
        return self.cli(dict(op="validation_tick"))

    def status(self, actor="A"):
        return self.clients[actor].read("status", workspace=actor)

    def repair(self):
        return self.clients["A"].read("repair_list")["repairs"][0]

    def update(self, actor, incident, action, revision=None, identifier=None):
        return self.clients[actor].mutate(dict(op="repair_update", workspace=actor, incident_id=incident["incident_id"], action=action,
            expected_revision=revision if revision is not None else incident["revision"], operation_id=identifier or action + "-" + actor + "-" + str(time.time_ns())))

    def sql(self, statement, parameters=()):
        with sqlite3.connect(self.state / "state.sqlite") as db:
            return db.execute(statement, parameters).fetchall()

    def introduce_failure(self):
        self.policy()
        self.tick()  # A verified parent makes attribution explicit.
        (self.paths["A"] / "file.txt").write_text("bad\n")
        committed = self.commit("A", "introduce-failure")
        self.assertTrue(committed["shared"])
        self.assertEqual(committed["validation"]["state"], "pending")
        self.assertEqual(self.tick()["validation"]["state"], "failed")
        return committed

    def wait_for(self, path):
        deadline = time.monotonic() + 45
        while not path.exists():
            self.assertLess(time.monotonic(), deadline, str(path))
            time.sleep(0.05)

    def gated_policy(self, only_good=False):
        marker, gate = self.root / "started", self.root / "release"
        condition = "'good' in text" if only_good else "True"
        self.policy("from pathlib import Path; import time,sys; text=Path('file.txt').read_text(); "
            f"gate=Path({str(gate)!r}); marker=Path({str(marker)!r}); "
            f"exec(\"if {condition}:\\n marker.write_text('running')\\n while not gate.exists(): time.sleep(0.05)\"); "
            "sys.exit('bad' in text)")
        return marker, gate

    def test_slow_checks_do_not_hold_the_repo_lock_or_delay_other_commits(self):
        marker, gate = self.gated_policy()
        (self.paths["A"] / "note-a").write_text("first")
        first = self.commit("A", "first")
        self.assertTrue(first["shared"])
        worker = subprocess.Popen([BINARY, "--state", str(self.state), "validate-once"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            self.wait_for(marker)
            started = time.monotonic()
            status = self.status("B")
            (self.paths["B"] / "note-b").write_text("second")
            second = self.commit("B", "second")
            self.assertTrue(second["shared"], second)
            self.assertEqual(second["validation"]["state"], "pending")
            self.assertTrue({"capture_ms","submission_ms","sharing_ms","merge_ms","lock_wait_ms"} <= second["timing"].keys())
            self.assertIsNone(worker.poll(), "Check must still be waiting when both operations finish")
            self.assertFalse(gate.exists())
            MEASUREMENTS.append(dict(scenario="commit_while_checks_wait", elapsed_seconds=time.monotonic()-started,
                commit_timing=second["timing"], status_timing=status["timing"]))
        finally:
            gate.touch()
            output, error = worker.communicate(timeout=45)
        self.assertEqual(worker.returncode, 0, error + output)
        self.assertEqual(self.status()["repo_health"]["state"], "pending", "Older green must not green the new head")
        self.assertEqual(self.tick()["validation"]["state"], "passed")
        health = self.clients["A"].read("validation_status", head=second["head"], include_timings=True)
        self.assertTrue(health["release_ready"])
        self.assertTrue(health["operation_timings"])
        self.assertTrue(health["recent_checks"][0]["checks"][0]["duration_ms"] >= 0)

    def test_failure_notices_target_one_owner_and_inherited_failures_are_deduplicated(self):
        committed = self.introduce_failure()
        own = self.clients["A"].read("get_latest", workspace="A")
        self.assertEqual(len(own["notices"]), 1)
        incident = self.repair()
        self.assertEqual(incident["owner"]["workspace"], "A")
        self.assertEqual(incident["attribution"], "first_failing_commit_after_verified_parent")
        self.assertEqual(incident["failure"]["stdout_prefix"].strip(), "fixture check")
        self.assertEqual(self.status("B")["notices"], [])
        (self.paths["B"] / "unrelated").write_text("continue")
        second = self.commit("B", "unrelated")
        self.assertTrue(second["shared"])
        self.tick()
        self.assertEqual(len(self.clients["B"].read("repair_list")["repairs"]), 1)
        self.assertEqual(self.repair()["owner"]["workspace"], "A")
        self.assertEqual(self.update("B", incident, "acknowledge")["error"]["code"], "repair_owner_mismatch")
        acknowledged = self.update("A", incident, "acknowledge", identifier="acknowledge-once")
        self.assertTrue(acknowledged["confirmed"])
        self.assertEqual(self.update("A", incident, "acknowledge", identifier="acknowledge-once"), acknowledged)
        self.assertEqual(self.status()["notices"], [])
        (self.paths["A"] / "file.txt").write_text("good fixed\n")
        fixed = self.commit("A", "normal-fix", generation=1)
        self.assertTrue(fixed["shared"])
        self.assertEqual(fixed["validation"]["state"], "pending")
        self.assertEqual(self.tick()["validation"]["state"], "passed")
        self.assertEqual(self.repair()["state"], "resolved")
        self.assertTrue(self.repair()["resolved_job_id"])
        historical = self.clients["A"].read("commit_status", commit_id=committed["commit_id"])
        self.assertEqual(historical["validation"]["state"], "failed")
        self.assertEqual(historical["state"], "integrated")

    def test_repair_claim_is_atomic_and_expired_owner_cannot_renew(self):
        self.introduce_failure()
        self.status("A")
        incident = self.repair()
        self.sql("UPDATE repair_incidents SET expires=0 WHERE id=?", (incident["incident_id"],))
        self.assertEqual(self.update("A", incident, "renew")["error"]["code"], "repair_lease_expired")
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(lambda actor: self.update(actor, incident, "claim"), "BC"))
        self.assertEqual(sum(r["ok"] for r in results), 1, results)
        self.assertEqual(self.repair()["revision"], incident["revision"] + 1)
        self.assertIn(self.repair()["owner"]["workspace"], "BC")
        self.assertEqual(self.update("A", incident, "claim")["error"]["code"], "repair_revision_mismatch")

    def test_release_allows_one_explicit_handoff(self):
        self.introduce_failure()
        self.status("A")
        incident = self.repair()
        released = self.update("A", incident, "release")
        self.assertTrue(released["ok"])
        incident = self.repair()
        self.assertTrue(incident["claimable"])
        self.assertTrue(self.update("B", incident, "claim")["confirmed"])
        self.assertEqual(self.update("C", incident, "claim")["error"]["code"], "repair_revision_mismatch")

    def test_queued_runs_coalesce_without_marking_skipped_commits_passed(self):
        self.policy()
        (self.paths["A"] / "one").write_text("one")
        first = self.commit("A", "first")
        (self.paths["A"] / "two").write_text("two")
        latest = self.commit("A", "latest", generation=1)
        self.assertEqual(self.tick()["validation"]["state"], "passed")
        skipped = self.clients["A"].read("commit_status", commit_id=first["commit_id"])
        self.assertEqual(skipped["validation"]["state"], "unchecked")
        self.assertEqual(skipped["validation"]["reason"], "superseded_before_testing")
        exact = self.clients["A"].read("validation_status", head=first["head"])
        self.assertFalse(exact["release_ready"])
        self.assertTrue(self.clients["A"].read("validation_status", head=latest["head"])["release_ready"])

    def test_interrupted_worker_is_recovered_without_losing_the_job(self):
        marker, gate = self.gated_policy()
        worker = subprocess.Popen([BINARY, "--state", str(self.state), "validate-once"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            self.wait_for(marker)
            busy = self.tick()
            self.assertEqual(busy["state"], "worker_busy")
            worker.kill()
            worker.wait(timeout=10)
        finally:
            gate.touch()
            worker.communicate(timeout=45)
        completed = self.tick()
        self.assertEqual(completed["validation"]["state"], "passed")
        self.assertEqual(completed["validation"]["attempt"], 2)

    def test_changed_policy_cannot_reuse_old_green_and_does_not_leave_old_repairs_active(self):
        self.introduce_failure()
        old = self.repair()
        self.policy("print('replacement policy')")
        self.assertEqual(self.repair()["state"], "superseded")
        self.assertEqual(self.status()["repo_health"]["state"], "pending")
        self.assertEqual(self.tick()["validation"]["state"], "passed")
        self.assertEqual(self.update("A", old, "acknowledge")["error"]["code"], "repair_closed")

    def test_infrastructure_failure_has_no_blame_and_retries_are_bounded(self):
        self.policy(executable=str(self.root / "missing-runtime"))
        for attempt in range(1, 4):
            result = self.tick()
            self.assertEqual(result["validation"]["state"], "failed")
            self.assertEqual(result["validation"]["failure_kind"], "infrastructure")
            self.assertEqual(result["validation"]["attempt"], attempt)
            self.sql("UPDATE validation_jobs SET finished=0 WHERE state='failed'")
        self.assertEqual(self.tick()["state"], "idle")
        self.assertEqual(self.clients["A"].read("repair_list")["repairs"], [])

    def test_ordinary_worker_runs_checks_automatically(self):
        self.policy()
        worker = subprocess.Popen([BINARY, "--state", str(self.state), "worker"], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        try:
            deadline = time.monotonic()+45
            while self.status()["repo_health"]["state"] != "passed":
                self.assertLess(time.monotonic(), deadline)
                time.sleep(0.2)
        finally:
            worker.terminate()
            worker.communicate(timeout=15)

    def test_recovered_promotion_does_not_reuse_old_green_health(self):
        self.policy()
        self.tick()
        (self.paths["A"] / "file.txt").write_text("bad after interrupted promotion\n")
        request=dict(op="commit",workspace="A",message="Interrupted sharing",expected_generation=0,operation_id="crash-promotion")
        process=subprocess.run([BINARY,"--state",str(self.state),json.dumps(request)],env=dict(os.environ,WIPSTASH_FAULT="promotion_after_cas"),capture_output=True,timeout=60)
        self.assertEqual(process.returncode,86)
        recovered=self.status()
        self.assertEqual(recovered["repo_health"]["state"],"pending")
        self.assertFalse(recovered["repo_health"]["release_ready"])
        self.assertEqual(self.tick()["validation"]["state"],"failed")

    def test_infrastructure_problem_does_not_hide_a_separate_code_failure(self):
        policy={"checks":[dict(id="missing-runtime",argv=[str(self.root/"missing")]),dict(id="code-failure",argv=[sys.executable,"-B","-c","raise SystemExit(1)"])]}
        self.cli(dict(op="configure",operation_id="mixed-policy",policy=policy))
        (self.paths["A"] / "change").write_text("change")
        self.assertTrue(self.commit("A","mixed")["shared"])
        self.assertEqual(self.tick()["validation"]["state"],"failed")
        repairs=self.clients["A"].read("repair_list")["repairs"]
        self.assertEqual([r["check_id"] for r in repairs],["code-failure"])

    def test_automatic_repair_policy_is_rejected_before_configuration_changes(self):
        rejected=self.clients["A"].mutate(dict(op="configure",operation_id="retired-repair",policy={"repair":{"argv":[sys.executable,"-c","raise SystemExit(0)"]}}))
        self.assertFalse(rejected["ok"])
        self.assertEqual(rejected["error"]["code"],"invalid_request")
        self.assertEqual(self.sql("SELECT value FROM meta WHERE key='policy'"),[])

    def test_older_budget_exhaustion_evidence_is_retried_as_infrastructure(self):
        self.policy(executable=str(self.root/"missing-runtime"))
        self.assertEqual(self.tick()["validation"]["attempt"],1)
        self.sql("UPDATE validation_jobs SET evidence=json_set(evidence,'$.failure_kind','timeout','$.checks[0].reason','evaluation_budget_exhausted'),finished=0 WHERE state='failed'")
        retried=self.tick()
        self.assertEqual(retried["validation"]["attempt"],2)
        self.assertEqual(retried["validation"]["failure_kind"],"infrastructure")
        self.assertEqual(self.clients["A"].read("repair_list")["repairs"],[])

    @unittest.skipIf(os.name=="nt","Uses a Unix file lock to hold unrelated repository work")
    def test_coordination_and_status_continue_while_global_state_lock_is_held(self):
        import fcntl
        measurements=[]
        with (self.state/"state.lock").open("a+") as held:
            fcntl.flock(held,fcntl.LOCK_EX)
            def work(actor):
                client=self.clients[actor]
                began=time.monotonic()
                status=client.read("status",workspace=actor,accept_repairs=False)
                listed=client.read("task_list")
                claimed=client.mutate(dict(op="task_claim",workspace=actor,task_id="responsive-"+actor,title="Parallel work",acceptance_criteria="Metadata stays available",paths=[actor+".txt"],operation_id="responsive-claim-"+actor))
                self.assertTrue(status["ok"],status)
                self.assertIsNone(status["has_unshared_changes"])
                self.assertTrue(status["timing"]["state_lock_bypassed"])
                self.assertTrue(listed["ok"])
                self.assertTrue(claimed["confirmed"],claimed)
                return time.monotonic()-began
            with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
                futures=[pool.submit(work,a) for a in "ABC"]
                try:
                    measurements=[f.result(timeout=10) for f in futures]
                finally:
                    fcntl.flock(held,fcntl.LOCK_UN)
        MEASUREMENTS.append(dict(scenario="coordination_while_state_lock_held",seconds=measurements))

    def test_next_active_caller_gets_one_offer_and_origin_is_preserved(self):
        failed=self.introduce_failure()
        unassigned=self.repair()
        self.assertTrue(unassigned["claimable"])
        self.assertEqual(unassigned["origin"]["workspace"],"A")
        replies={}
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            replies=dict(pool.map(lambda a:(a,self.status(a)),"BC"))
        incident=self.repair()
        winner=incident["owner"]["workspace"]
        self.assertIn(winner,"BC")
        self.assertEqual(sum(bool(v["notices"]) for v in replies.values()),1)
        self.assertEqual(incident["assignment_state"],"offered")
        self.assertLessEqual(incident["expires_at_ms"]-incident["server_time_ms"] if "server_time_ms" in incident else incident["expires_at_ms"]-int(time.time()*1000),30000)
        self.assertTrue(self.update(winner,incident,"acknowledge")["ok"])
        self.assertEqual(self.repair()["origin"]["commit_id"],failed["commit_id"])
        other="B" if winner=="C" else "C"
        self.sql("UPDATE repair_incidents SET expires=0")
        self.assertTrue(self.status(other)["notices"])
        self.assertEqual(self.repair()["owner"]["workspace"],other)

    def test_ignored_offer_expires_and_read_only_agent_can_decline(self):
        self.introduce_failure()
        self.clients["B"].read("status",workspace="B",accept_repairs=False)
        self.assertTrue(self.repair()["claimable"])
        self.status("B")
        incident=self.repair()
        self.assertTrue(self.update("B",incident,"release")["ok"])
        self.assertEqual(self.status("B")["notices"],[])
        self.assertTrue(self.status("C")["notices"])

    def test_comments_are_durable_targeted_and_do_not_transfer_repairs(self):
        self.introduce_failure()
        self.status("A")
        incident=self.repair()
        request=dict(op="comment_add",workspace="B",subject_type="repair",subject_id=incident["incident_id"],body="The child Python process may need -B.",mentions=["A"],operation_id="tip-for-owner")
        sent=self.clients["B"].mutate(request)
        self.assertTrue(sent["confirmed"],sent)
        self.assertFalse(sent["read_by_recipient"])
        self.assertEqual(self.clients["B"].mutate(request),sent)
        comments=self.clients["A"].read("comment_list",subject_type="repair",subject_id=incident["incident_id"])
        self.assertEqual(len(comments["comments"]),1)
        self.assertEqual(comments["comments"][0]["workspace"],"B")
        self.assertEqual(len(self.status("A")["comment_notices"]),1)
        self.assertEqual(self.status("C")["comment_notices"],[])
        self.assertEqual(self.repair()["owner"],incident["owner"])
        self.assertEqual(self.repair()["revision"],incident["revision"])

    def test_public_diff_is_bounded_and_cannot_read_private_commits(self):
        first=self.clients["A"].read("get_latest",workspace="A")["latest"]
        (self.paths["A"]/"file.txt").write_text("new public version\n")
        changed=self.commit("A","public-diff")
        diff=self.clients["A"].read("diff",base=first,head=changed["head"],path="file.txt")
        self.assertIn("+new public version",diff["diff"])
        private=self.sql("SELECT commit_oid FROM checkpoints WHERE workspace='A'")[0][0]
        rejected=self.clients["A"].read("diff",base=first,head=private,path="file.txt")
        self.assertFalse(rejected["ok"])

    def test_python_preset_reaches_children_and_mutation_reports_exact_paths(self):
        (self.paths["A"]/"module.py").write_text("VALUE=1\n")
        self.commit("A","python-module")
        command="import subprocess,sys; subprocess.run([sys.executable,'-c','import module'],check=True)"
        self.cli(dict(op="configure",operation_id="python-preset",policy={"checks":[dict(id="python",argv=[sys.executable,"-c",command],preset="python")]}))
        self.assertEqual(self.tick()["validation"]["state"],"passed")
        self.policy("from pathlib import Path; Path('new-cache').write_text('generated')")
        result=self.tick()
        self.assertEqual(result["validation"]["state"],"failed")
        incident=self.repair()
        self.assertEqual(incident["failure"]["failure_kind"],"check_mutated_checkout")
        self.assertIn(dict(path="new-cache",kind="added"),incident["failure"]["mutated_paths"])

    def test_invalid_page_is_certain_and_does_not_suggest_operation_recovery(self):
        rejected=self.clients["A"].read("task_list",limit=100)
        self.assertFalse(rejected["ok"])
        self.assertNotEqual(rejected.get("recovery",{}).get("action"),"operation_status")
        self.assertEqual(rejected["error"]["code"],"invalid_arguments")



    def test_capture_crash_reuses_ready_bytes_and_never_recaptures_incomplete_intent(self):
        for actor,phase in [("A","capture_after_ready"),("B","capture_after_intent")]:
            request=dict(op="commit",workspace=actor,message="Capture crash",operation_id="capture-crash-"+actor,expected_generation=0)
            (self.paths[actor]/"file.txt").write_text("captured bytes\n")
            failed=subprocess.run([BINARY,"--state",str(self.state),json.dumps(request)],env=dict(os.environ,WIPSTASH_FAULT=phase),capture_output=True,timeout=60)
            self.assertEqual(failed.returncode,86,failed.stderr+failed.stdout)
            (self.paths[actor]/"file.txt").write_text("new private work\n")
            recorded=self.clients[actor].read("operation_status",operation_id=request["operation_id"],include_record=True)
            self.assertTrue(recorded["recorded"])
            self.assertEqual(recorded["request"]["workspace"],actor)
            result=self.clients[actor].mutate(request)
            if actor=="A":
                self.assertTrue(result["shared"],result)
                done=subprocess.run(["git","--git-dir",str(self.state/"coordinator.git"),"show",result["head"]+":file.txt"],capture_output=True,text=True,check=True)
                self.assertEqual(done.stdout,"captured bytes\n")
            else:
                self.assertFalse(result["ok"])
                self.assertEqual(result["error"]["code"],"commit_interrupted")
            self.assertEqual((self.paths[actor]/"file.txt").read_text(),"new private work\n")


    @unittest.skipIf(os.name=="nt","Uses a Unix lock to hold another repository operation")
    def test_commit_prepares_capture_outside_the_repository_lock(self):
        import fcntl
        request=dict(op="commit",workspace="C",message="Capture while busy",expected_generation=0,operation_id="capture-outside-lock")
        (self.paths["C"]/"file.txt").write_text("prepared privately\n")
        with (self.state/"state.lock").open("a+") as held:
            fcntl.flock(held,fcntl.LOCK_EX)
            try:
                process=subprocess.run([BINARY,"--state",str(self.state),json.dumps(request)],env=dict(os.environ,WIPSTASH_FAULT="capture_after_ready"),capture_output=True,timeout=10)
                self.assertEqual(process.returncode,86,process.stderr+process.stdout)
                record=self.clients["C"].read("operation_status",operation_id=request["operation_id"],include_record=True)
                self.assertTrue(record["capture_ready"])
            finally:
                fcntl.flock(held,fcntl.LOCK_UN)
        shared=self.clients["C"].mutate(request)
        self.assertTrue(shared["shared"],shared)


    @unittest.skipIf(os.name=="nt","Uses a POSIX Git fixture wrapper")
    def test_metadata_writes_during_merge_do_not_invalidate_integration_snapshot(self):
        import shutil,shlex
        wrapper=self.root/"git-wrapper";wrapper.mkdir()
        marker=self.root/"merge-started";gate=self.root/"merge-continue"
        actual_git=shutil.which("git")
        script=wrapper/"git"
        script.write_text("#!/bin/sh\nfor arg do\n case \"$arg\" in\n merge-tree) : > "+shlex.quote(str(marker))+"; while [ ! -f "+shlex.quote(str(gate))+" ]; do /bin/sleep 0.02; done;;\n esac\ndone\nexec "+shlex.quote(actual_git)+" \"$@\"\n")
        script.chmod(0o700)
        (self.paths["A"]/"file.txt").write_text("candidate\n")
        request=dict(op="commit",workspace="A",message="Queued for gated integration",expected_generation=0,operation_id="gated-integration")
        stopped=subprocess.run([BINARY,"--state",str(self.state),json.dumps(request)],env=dict(os.environ,WIPSTASH_FAULT="commit_after_submit"),capture_output=True,timeout=60)
        self.assertEqual(stopped.returncode,86)
        process=subprocess.Popen([BINARY,"--state",str(self.state),json.dumps(dict(op="integrate",max_proposals=1))],env=dict(os.environ,PATH=str(wrapper)+os.pathsep+os.environ.get("PATH","")),stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
        try:
            self.wait_for(marker)
            self.assertTrue(self.clients["B"].read("validation_status")["ok"])
            claimed=self.clients["B"].mutate(dict(op="task_claim",workspace="B",task_id="during-merge",title="Concurrent metadata",acceptance_criteria="Sharing survives independent coordination writes",paths=["other.txt"],operation_id="claim-during-merge"))
            self.assertTrue(claimed["confirmed"],claimed)
        finally:
            gate.touch()
            out,err=process.communicate(timeout=45)
        self.assertEqual(process.returncode,0,err+out)
        self.assertEqual(json.loads(out)["outcomes"][0]["state"],"integrated")



if __name__ == "__main__":
    result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromNames(tests or ["__main__"]))
    if args.artifacts:
        destination = Path(args.artifacts)
        destination.mkdir(parents=True, exist_ok=True)
        (destination / "async-validation.json").write_text(json.dumps(dict(passed=result.wasSuccessful(), tests=result.testsRun, measurements=MEASUREMENTS), indent=2)+"\n")
    raise SystemExit(not result.wasSuccessful())
