#!/usr/bin/env python3
"""Actual standalone CLI, Git and SQLite; no MCP, model sessions or client daemons."""
import concurrent.futures
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
BINARY = Path(os.environ.get("WIP_BINARY", ROOT / "target/debug" / ("wip.exe" if os.name == "nt" else "wip"))).resolve()


class CliContracts(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="wip-cli-", dir="/private/tmp" if os.name != "nt" and Path("/private/tmp").exists() else None)
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.env = dict(os.environ, WIP_DATA_HOME=str(self.root / "data"), WIP_CONFIG_HOME=str(self.root / "config"))
        self.source = self.root / "source"
        self.source.mkdir()
        (self.source / "apa.js").write_text("initial\n")
        (self.source / "other.txt").write_text("other\n")
        self.run_cli("init", self.source)
        self.a = self.root / "alice"
        self.b = self.root / "bob"
        self.run_cli("clone", self.source, self.a)
        self.run_cli("clone", self.source, self.b)
        self.repo = json.loads((self.a / ".wip/repo.json").read_text())
        self.state = Path(self.repo["state"])

    def run_cli(self, *args, cwd=None, codes=(0,), env=None):
        result = subprocess.run([str(BINARY), "--json", *map(str, args)], cwd=cwd or self.root,
                                env=env or self.env, capture_output=True, text=True, timeout=120)
        self.assertIn(result.returncode, codes, (args, result.stdout, result.stderr))
        try:
            return json.loads(result.stdout)
        except ValueError:
            self.fail((args, result.returncode, result.stdout, result.stderr))

    def public(self, path):
        return subprocess.check_output(["git", "--git-dir", str(self.state / "coordinator.git"), "show", "refs/wipstash/integration:" + path])

    def test_staging_uses_exact_added_bytes_and_preserves_unstaged_work(self):
        (self.a / "apa.js").write_text("staged\n")
        self.run_cli("add", "apa.js", cwd=self.a)
        (self.a / "apa.js").write_text("newer unstaged\n")
        (self.a / "other.txt").write_text("unfinished\n")
        result = self.run_cli("commit", "-m", "tjenis tjenis", cwd=self.a)
        self.assertTrue(result["shared"])
        self.assertEqual(self.public("apa.js"), b"staged\n")
        self.assertEqual(self.public("other.txt"), b"other\n")
        self.assertEqual((self.a / "apa.js").read_text(), "newer unstaged\n")
        self.assertEqual((self.a / "other.txt").read_text(), "unfinished\n")
        status = self.run_cli("status", cwd=self.a)
        self.assertEqual(status["staged"], [])
        self.assertEqual({v["path"] for v in status["unstaged"]}, {"apa.js", "other.txt"})
        tree = subprocess.check_output(["git", "--git-dir", str(self.state / "coordinator.git"), "ls-tree", "-r", "--name-only", "refs/wipstash/integration"], text=True)
        self.assertNotIn(".wip", tree)
        self.assertEqual((self.b / "apa.js").read_text(), "initial\n")

    def test_saved_legacy_work_can_be_staged_and_shared_after_migration(self):
        (self.a/"apa.js").write_text("previously private\n")
        result=self.run_cli("admin","checkpoint","--params",json.dumps({"workspace":self.repo["workspace"],"expected_generation":0,"operation_id":"legacy-private-save"}),cwd=self.a)
        self.assertTrue(result["ok"])
        self.assertTrue(self.run_cli("add","apa.js",cwd=self.a)["staged"])
        self.assertTrue(self.run_cli("commit","-m","Share retained work",cwd=self.a)["shared"])
        self.assertEqual(self.public("apa.js"),b"previously private\n")

    def test_independent_agents_share_successive_commits_without_merging(self):
        (self.a / "apa.js").write_text("first\n")
        self.run_cli("add", "apa.js", cwd=self.a)
        self.assertTrue(self.run_cli("commit", "-m", "First", cwd=self.a)["shared"])
        (self.b / "other.txt").write_text("bob\n")
        self.assertTrue(self.run_cli("commit", "-am", "Bob", cwd=self.b)["shared"])
        (self.a / "apa.js").write_text("second\n")
        self.assertTrue(self.run_cli("commit", "-am", "Second", cwd=self.a)["shared"])
        self.assertEqual(self.public("other.txt"), b"bob\n")
        self.assertEqual(self.public("apa.js"), b"second\n")
        self.assertEqual((self.a / "other.txt").read_text(), "other\n")
        self.run_cli("get-latest", cwd=self.a)
        self.assertEqual((self.a / "other.txt").read_text(), "other\n")
        self.run_cli("merge", cwd=self.a)
        self.assertEqual((self.a / "other.txt").read_text(), "bob\n")

    def test_unstage_and_deletion_leave_live_files_untouched(self):
        (self.a / "apa.js").write_text("staged then removed\n")
        self.run_cli("add", "apa.js", cwd=self.a)
        self.run_cli("restore", "--staged", "apa.js", cwd=self.a)
        self.assertEqual((self.a / "apa.js").read_text(), "staged then removed\n")
        self.run_cli("commit", "-m", "Empty", cwd=self.a, codes=(1,))
        (self.a / "other.txt").unlink()
        self.run_cli("add", "other.txt", cwd=self.a)
        self.assertTrue(self.run_cli("commit", "-m", "Remove other", cwd=self.a)["shared"])
        files=subprocess.check_output(["git","--git-dir",str(self.state/"coordinator.git"),"ls-tree","-r","--name-only","refs/wipstash/integration"],text=True)
        self.assertNotIn("other.txt",files)
        self.assertEqual(self.public("apa.js"),b"initial\n")

    def test_exact_id_retry_preserves_original_commit_and_new_edits(self):
        (self.a/"apa.js").write_text("saved\n")
        self.run_cli("add","apa.js",cwd=self.a)
        first=self.run_cli("commit","-m","First","--operation-id","stable",cwd=self.a)
        (self.a/"apa.js").write_text("new WIP\n")
        self.run_cli("add","apa.js",cwd=self.a)
        retried=self.run_cli("commit","-m","First","--operation-id","stable",cwd=self.a)
        self.assertEqual(first["head"],retried["head"])
        self.assertEqual(self.public("apa.js"),b"saved\n")
        self.assertTrue(self.run_cli("status",cwd=self.a)["staged"])
        self.run_cli("commit","-m","Changed message","--operation-id","stable",cwd=self.a,codes=(1,))
        record=self.run_cli("operation","show","stable",cwd=self.a)
        self.assertEqual(record["request"]["message"],"First")

    def test_interrupted_cli_resumes_retained_staged_bytes(self):
        (self.a/"apa.js").write_text("selected before crash\n")
        self.run_cli("add","apa.js",cwd=self.a)
        failed=subprocess.run([str(BINARY),"--json","commit","-m","Crash recovery","--operation-id","crash"],cwd=self.a,env=dict(self.env,WIPSTASH_FAULT="commit_after_snapshot"),capture_output=True,text=True,timeout=60)
        self.assertEqual(failed.returncode,86,failed.stderr)
        (self.a/"apa.js").write_text("newer live WIP\n")
        recovered=self.run_cli("operation","retry","crash",cwd=self.a)
        self.assertTrue(recovered["shared"],recovered)
        self.assertEqual(self.public("apa.js"),b"selected before crash\n")
        self.assertEqual((self.a/"apa.js").read_text(),"newer live WIP\n")
        status=self.run_cli("status",cwd=self.a)
        self.assertEqual(status["staged"],[])
        self.assertEqual({entry["path"] for entry in status["unstaged"]},{"apa.js"})

    def test_nested_deletions_and_new_file_unstage(self):
        (self.a/"nested").mkdir();(self.a/"nested/file.txt").write_text("nested\n")
        self.run_cli("commit","-am","Nested",cwd=self.a)
        (self.a/"nested/file.txt").unlink();(self.a/"nested").rmdir()
        self.run_cli("add","nested/file.txt",cwd=self.a)
        self.assertTrue(self.run_cli("commit","-m","Delete nested",cwd=self.a)["shared"])
        (self.a/"new").mkdir();(self.a/"new/file.txt").write_text("keep local\n")
        self.run_cli("add","new/file.txt",cwd=self.a)
        self.run_cli("restore","--staged","new/file.txt",cwd=self.a)
        self.assertEqual((self.a/"new/file.txt").read_text(),"keep local\n")
        self.assertEqual(self.run_cli("status",cwd=self.a)["staged"],[])

    def test_conflict_review_is_complete_and_original_directory_is_untouched(self):
        (self.a/"apa.js").write_text("alice\n")
        (self.b/"apa.js").write_text("bob\n")
        self.run_cli("commit","-am","Alice",cwd=self.a)
        blocked=self.run_cli("commit","-am","Bob",cwd=self.b,codes=(4,))
        self.assertEqual(blocked["state"],"blocked")
        review=self.root/"review"
        opened=self.run_cli("conflict","open",review,"--commit",blocked["commit_id"],cwd=self.b)
        self.assertEqual(set(opened["side_paths"]),{"base","local","shared"})
        self.assertEqual((self.b/"apa.js").read_text(),"bob\n")
        (review/"apa.js").write_text("alice and bob\n")
        self.run_cli("add","apa.js",cwd=review)
        self.run_cli("commit","-m","Unreviewed",cwd=review,codes=(1,))
        resolved=self.run_cli("commit","-m","Combine both","--resolved-conflicts","apa.js",cwd=review)
        self.assertTrue(resolved["shared"],resolved)
        self.assertEqual(self.public("apa.js"),b"alice and bob\n")
        (review/"other.txt").write_text("ordinary follow-up\n")
        self.assertTrue(self.run_cli("commit","-am","Follow-up",cwd=review)["shared"])

    def test_tasks_comments_workspace_lifecycle_and_audit(self):
        claim=self.run_cli("task","claim","editing","--title","Edit file","--acceptance","Tests pass","--paths","apa.js",cwd=self.a)
        peer=self.run_cli("task","claim","overlap","--title","Overlap","--acceptance","Review","--paths","apa.js",cwd=self.b)
        self.assertTrue(peer["overlaps"])
        self.run_cli("comment","add","task",claim["claim_id"],"-m","Please coordinate",cwd=self.b)
        self.assertTrue(self.run_cli("comment","list","--subject-type","task","--subject-id",claim["claim_id"],cwd=self.a)["comments"])
        self.run_cli("task","complete",claim["claim_id"],"--revision",claim["revision"],cwd=self.a)
        self.run_cli("task","release",peer["claim_id"],"--revision",peer["revision"],cwd=self.b)
        self.run_cli("workspace","close","--writers-stopped",cwd=self.a)
        self.run_cli("workspace","reopen",cwd=self.a)
        self.assertGreater(self.run_cli("audit","verify",cwd=self.a)["verified"],0)
        self.assertTrue(self.run_cli("audit","log",cwd=self.a)["records"])

    def test_discovery_isolation_and_reserved_paths(self):
        nested=self.a/"subdir";nested.mkdir()
        self.assertEqual(self.run_cli("status","--quick",cwd=nested)["workspace"],self.repo["workspace"])
        self.assertNotEqual(json.loads((self.b/".wip/repo.json").read_text())["workspace"],self.repo["workspace"])
        self.run_cli("add",".wip/repo.json",cwd=self.a,codes=(1,))
        self.run_cli("add","../source/apa.js",cwd=self.a,codes=(1,))
        self.run_cli("clone",self.source,self.a,codes=(1,))
        if os.name!="nt":
            (self.a/"outside").symlink_to(self.root,target_is_directory=True)
            self.run_cli("add","outside/source/apa.js",cwd=self.a,codes=(1,))

    def test_concurrent_cli_invocations_refuse_a_busy_repository(self):
        # The lock is held by a different OS process, not another descriptor in this process.
        if os.name=="nt":self.skipTest("Windows lock fixture is covered by native platform tests")
        blocker=subprocess.Popen(["uv","run","--no-project","python","-c","import fcntl,sys,time; f=open(sys.argv[1],'a+'); fcntl.flock(f,fcntl.LOCK_EX); print('locked',flush=True); time.sleep(20)",str(self.a/".wip/cli.lock")],stdout=subprocess.PIPE,text=True)
        self.addCleanup(lambda:(blocker.terminate(),blocker.wait(),blocker.stdout.close()))
        self.assertEqual(blocker.stdout.readline().strip(),"locked")
        self.assertEqual(self.run_cli("status",cwd=self.a,codes=(1,))["error"]["code"],"repository_busy")


if __name__=="__main__":unittest.main(verbosity=2)
