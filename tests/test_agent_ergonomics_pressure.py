#!/usr/bin/env python3
"""Pure synthetic accounting/guard tests; no engine, policy commands or sockets."""
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
import io
from contextlib import redirect_stderr
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import agent_ergonomics_pressure as pressure


class CleanupTests(unittest.TestCase):
    def test_cleanup_failure_does_not_mask_primary_failure(self):
        summary = {}
        primary = AssertionError("campaign failed")
        def fail_cleanup():
            raise PermissionError("locked file")
        with self.assertRaises(AssertionError) as raised:
            with pressure.cleanup_preserving_failure(fail_cleanup, summary):
                raise primary
        self.assertIs(raised.exception, primary)
        self.assertEqual(summary["cleanup_failure_types"], ["PermissionError"])
        self.assertEqual(primary.__notes__, ["Additional cleanup failure: PermissionError"])

    def test_audit_closes_database_even_when_assertion_fails(self):
        campaign = pressure.Campaign.__new__(pressure.Campaign)
        campaign.state = Path("synthetic-unused")
        campaign.command = mock.Mock(return_value=b"")
        for integrity in ([("ok",)], [("bad",)]):
            with self.subTest(integrity=integrity):
                db = mock.Mock()
                db.execute.return_value.fetchall.side_effect = [integrity, []]
                with mock.patch.object(pressure.sqlite3, "connect", return_value=db):
                    if integrity == [("ok",)]:
                        campaign.audit("private")
                    else:
                        with self.assertRaises(AssertionError):
                            campaign.audit("private")
                db.close.assert_called_once_with()

    def test_cleanup_failure_alone_still_fails(self):
        summary = {}
        def fail_cleanup():
            raise PermissionError("locked file")
        with self.assertRaises(PermissionError):
            with pressure.cleanup_preserving_failure(fail_cleanup, summary):
                pass
        self.assertEqual(summary["cleanup_failure_types"], ["PermissionError"])


class GuardTests(unittest.TestCase):
    def test_default_never_requires_or_enables_ci(self):
        pressure.require_ci_checks(False, {})

    def test_checks_require_both_exact_ci_guards(self):
        for env in ({}, {"GITHUB_ACTIONS": "true"}, {"WIPSTASH_ERGONOMICS_CI": "1"},
                    {"GITHUB_ACTIONS": "TRUE", "WIPSTASH_ERGONOMICS_CI": "1"},
                    {"GITHUB_ACTIONS": "true", "WIPSTASH_ERGONOMICS_CI": "true"}):
            with self.subTest(env=env), self.assertRaises(ValueError):
                pressure.require_ci_checks(True, env)
        # Pure input validation only. This does not set environment variables or
        # invoke the guarded campaign, engine, policy runner, or a child process.
        pressure.require_ci_checks(True, {"GITHUB_ACTIONS": "true", "WIPSTASH_ERGONOMICS_CI": "1"})

    def test_cli_guard_precedes_helper_load_artifact_creation_and_binary_access(self):
        with tempfile.TemporaryDirectory() as directory:
            artifact = Path(directory) / "must-not-exist"
            with mock.patch.dict(pressure.os.environ, {}, clear=True), \
                    mock.patch.object(pressure, "load_helper") as load, \
                    mock.patch.object(pressure.Campaign, "run") as run, redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as raised:
                    pressure.main(["--required-checks-ci", "--binary", "/nonexistent-binary",
                                   "--artifacts", str(artifact)])
                self.assertEqual(2, raised.exception.code)
                load.assert_not_called()
                run.assert_not_called()
                self.assertFalse(artifact.exists())


class ObservationRecipeTests(unittest.TestCase):
    def setUp(self):
        self.proposals = [{"proposal": "p1", "state": "integrated"},
                          {"proposal": "p2", "state": "quarantined"}]
        self.tasks = [{"proposal": "p2", "state": "action_required"}]
        self.status = {"latest": "head", "proposals": self.proposals,
                       "resolution_tasks": self.tasks, "proposals_truncated": False}
        self.calls = []

    def read(self, op, **fields):
        self.calls.append((op, fields))
        return {"status": self.status, "updates": {"latest": "head"},
                "resolution_tasks": {"tasks": self.tasks},
                "proposal_status": next((p for p in self.proposals if p["proposal"] == fields.get("proposal")), {})}[op]

    def test_recipes_return_identical_information_and_count_actual_calls(self):
        baseline = pressure.observe_recipe(self.read, "repeated_reads", "A", ["p1", "p2"])
        self.assertEqual(["status", "updates", "proposal_status", "proposal_status", "resolution_tasks"],
                         [op for op, _ in self.calls])
        self.calls.clear()
        compact = pressure.observe_recipe(self.read, "compact_status", "A", ["p1", "p2"])
        self.assertEqual(baseline, compact)
        self.assertEqual([("status", {"workspace": "A"})], self.calls)

    def test_baseline_ignores_embedded_proposals_and_tasks(self):
        self.status = dict(self.status, proposals=[], resolution_tasks=[])
        _, _, proposals, tasks = pressure.observe_recipe(self.read, "repeated_reads", "A", ["p1", "p2"])
        self.assertEqual(self.proposals, proposals)
        self.assertEqual(self.tasks, tasks)
        self.assertEqual(5, len(self.calls))

    def test_compact_never_hides_truncated_or_missing_required_information(self):
        self.status["proposals_truncated"] = True
        with self.assertRaises(AssertionError):
            pressure.observe_recipe(self.read, "compact_status", "A", ["p1"])
        self.status["proposals_truncated"] = False
        with self.assertRaises(KeyError):
            pressure.observe_recipe(self.read, "compact_status", "A", ["missing"])

    def test_unknown_recipe_is_rejected(self):
        with self.assertRaises(ValueError):
            pressure.observe_recipe(self.read, "invented", "A", [])


class LedgerTests(unittest.TestCase):
    def test_thread_local_phase_counts_keep_concurrent_workflow_separate(self):
        ledger = pressure.Ledger()
        def record(actor):
            with ledger.phase("observation"):
                for _ in range(10):
                    ledger.record("mcp", actor, {"op": "status"}, {"ok": True})
            ledger.record("mcp", actor, {"op": "checkpoint"}, {"ok": True})
        with ThreadPoolExecutor(max_workers=4) as pool:
            list(pool.map(record, "ABCD"))
        ledger.record("cli", "coordinator", {"op": "integrate"}, {"ok": True})
        report = ledger.report()
        self.assertEqual(40, report["observation_engine_requests"])
        self.assertEqual(45, report["all_engine_requests"])
        self.assertEqual({actor: 11 for actor in "ABCD"}, report["engine_requests_by_stdio_session"])
        self.assertEqual(1, report["engine_requests_by_phase_transport_operation"]["workflow/cli/integrate"])

    def test_nested_phase_restores_after_exception(self):
        ledger = pressure.Ledger()
        with ledger.phase("observation"):
            with self.assertRaises(RuntimeError), ledger.phase("recovery"):
                raise RuntimeError("synthetic")
            ledger.record("mcp", "A", {"op": "status"}, {})
        ledger.record("mcp", "A", {"op": "checkpoint"}, {})
        self.assertEqual({"observation/mcp/status": 1, "workflow/mcp/checkpoint": 1}, ledger.calls)


class ComparisonTests(unittest.TestCase):
    @staticmethod
    def fixture(calls):
        return {"fixture_sha256": "fixture", "observations": ["same"],
                "final_worktrees": {"A": "same"},
                "call_counts": {"observation_engine_requests": calls}}

    def test_reports_only_measured_call_savings_with_explicit_limits(self):
        result = pressure.compare_runs(self.fixture(12), self.fixture(3))
        self.assertEqual(9, result["observation_calls_saved"])
        self.assertEqual(75.0, result["observation_call_reduction_percent"])
        self.assertIn("autonomous model success or reasoning quality", result["not_established"])
        self.assertIn("latency or throughput improvement", result["not_established"])

    def test_different_fixture_observation_or_final_state_cannot_claim_savings(self):
        baseline = self.fixture(12)
        for field in ("fixture_sha256", "observations", "final_worktrees"):
            with self.subTest(field=field):
                compact = deepcopy(self.fixture(3))
                compact[field] = "different"
                with self.assertRaises(AssertionError):
                    pressure.compare_runs(baseline, compact)

    def test_non_improvement_is_not_reported_as_savings(self):
        for calls in (12, 13):
            with self.subTest(calls=calls), self.assertRaises(AssertionError):
                pressure.compare_runs(self.fixture(12), self.fixture(calls))


if __name__ == "__main__":
    unittest.main(verbosity=2)
