#!/usr/bin/env python3
"""Synthetic wave-scheduling regressions; no engine, Git, sockets or CI guard.

Run directly with: python tests/test_agent_conflict_stress_harness.py
"""
from concurrent.futures import ThreadPoolExecutor
import json
import subprocess
import tempfile
import threading
from types import SimpleNamespace
import unittest
from unittest import mock

import agent_conflict_stress as stress
import harness_support


class PreparedWaveTests(unittest.TestCase):
    def test_all_preparations_finish_before_gate_and_submissions_overlap(self):
        actors = ['A', 'B', 'C']
        lock = threading.Lock()
        preparing = threading.Barrier(len(actors))
        submitting = threading.Barrier(len(actors))
        fast_prepared = threading.Event()
        release_slow = threading.Event()
        gate_created = threading.Event()
        submission_started = threading.Event()
        prepared = set()
        gate_timeouts = []

        def prepare(actor):
            # All actors must prepare concurrently, even while one is delayed.
            preparing.wait(timeout=5)
            if actor == 'C':
                self.assertTrue(release_slow.wait(timeout=5))
            with lock:
                prepared.add(actor)
                if {'A', 'B'} <= prepared:
                    fast_prepared.set()
            return actor, 'request-' + actor

        def make_gate(parties):
            self.assertEqual(set(actors), prepared)
            self.assertEqual(len(actors), parties)
            gate_created.set()
            gate = threading.Barrier(parties)

            def wait(*, timeout):
                with lock:
                    self.assertEqual(set(actors), prepared)
                    gate_timeouts.append(timeout)
                return gate.wait(timeout=timeout)

            return SimpleNamespace(wait=wait)

        def submit(item):
            actor, request = item
            with lock:
                self.assertEqual(set(actors), prepared)
            self.assertEqual('request-' + actor, request)
            submission_started.set()
            # Serial submission cannot pass this independent overlap check.
            submitting.wait(timeout=5)
            return actor, 'proposal-' + actor

        with mock.patch.object(stress, 'threading', SimpleNamespace(Barrier=make_gate)):
            with ThreadPoolExecutor(max_workers=1) as coordinator:
                future = coordinator.submit(stress.prepare_and_submit_wave,
                                            actors, prepare, submit)
                try:
                    self.assertTrue(fast_prepared.wait(timeout=5))
                    self.assertFalse(gate_created.is_set(),
                                     'Delayed preparation must not start the gate budget')
                    self.assertFalse(submission_started.is_set())
                finally:
                    release_slow.set()
                self.assertEqual([(a, 'proposal-' + a) for a in actors],
                                 future.result(timeout=10))
        self.assertEqual([30] * len(actors), gate_timeouts)

    def test_preparation_failure_is_preserved_without_entering_submit_gate(self):
        preparing = threading.Barrier(3)
        failure = RuntimeError('synthetic preparation failure')
        submit = mock.Mock()

        def prepare(actor):
            preparing.wait(timeout=5)
            if actor == 'B':
                raise failure
            return actor

        with mock.patch.object(stress, 'threading') as synchronization:
            with self.assertRaises(RuntimeError) as caught:
                stress.prepare_and_submit_wave(['A', 'B', 'C'], prepare, submit)
        self.assertIs(failure, caught.exception)
        synchronization.Barrier.assert_not_called()
        submit.assert_not_called()

    def test_submission_synchronization_failure_remains_distinct(self):
        failure = threading.BrokenBarrierError('synthetic synchronization failure')
        arriving = threading.Barrier(2)
        gate = mock.Mock()

        def fail_wait(*, timeout):
            arriving.wait(timeout=5)
            raise failure

        gate.wait.side_effect = fail_wait
        submit = mock.Mock()
        with mock.patch.object(stress, 'threading') as synchronization:
            synchronization.Barrier.return_value = gate
            with self.assertRaises(threading.BrokenBarrierError) as caught:
                stress.prepare_and_submit_wave(['A', 'B'], lambda actor: actor, submit)
        self.assertIs(failure, caught.exception)
        synchronization.Barrier.assert_called_once_with(2)
        self.assertEqual([mock.call(timeout=30)] * 2, gate.wait.call_args_list)
        submit.assert_not_called()

    def test_all_supported_wave_sizes_preserve_results(self):
        for size in range(1, 5):
            with self.subTest(size=size):
                self.assertEqual([actor * 2 + 1 for actor in range(size)],
                                 stress.prepare_and_submit_wave(
                                     range(size), lambda actor: actor * 2,
                                     lambda request: request + 1))

    def test_invalid_wave_size_fails_before_preparation(self):
        for size in (0, 5):
            with self.subTest(size=size):
                prepare, submit = mock.Mock(), mock.Mock()
                with self.assertRaises(ValueError):
                    stress.prepare_and_submit_wave(range(size), prepare, submit)
                prepare.assert_not_called()
                submit.assert_not_called()


class TimingEvidenceTests(unittest.TestCase):
    def event(self, stderr, **fields):
        return dict(argv=['unshared-path', json.dumps({'op': 'resolution_open',
                         'path': 'PRIVATE_PATH', 'proposal': 'PRIVATE_PROPOSAL'})],
                    seconds=40.1, stderr=stderr, **fields)

    def test_complete_phases_report_lock_dispatch_and_materialization(self):
        lines = [
            'wipstash_sqlite_phase pid=123 phase=state_lock_waiting elapsed_ms=1',
            'wipstash_sqlite_phase pid=123 phase=state_lock_acquired elapsed_ms=20001',
            'wipstash_sqlite_phase pid=123 phase=dispatch elapsed_ms=20005',
            'wipstash_resolution_phase pid=123 phase=materialization_started elapsed_ms=0',
            'wipstash_resolution_phase pid=123 phase=checkout_materialized elapsed_ms=3000',
            'wipstash_resolution_phase pid=123 phase=materialization_complete elapsed_ms=10000',
            'wipstash_sqlite_phase pid=123 phase=dispatch_complete elapsed_ms=30100',
        ]
        result = stress.resolution_timing(self.event('\n'.join(lines)))
        self.assertEqual(20000, result['state_lock_wait_ms'])
        self.assertEqual(10095, result['dispatch_ms'])
        self.assertEqual(10000, result['materialization_ms'])
        self.assertFalse(result['timed_out'])

    def test_timeout_keeps_partial_phases_without_inventing_completion(self):
        result = stress.resolution_timing(self.event(
            b'wipstash_sqlite_phase pid=123 phase=entered elapsed_ms=0\n'
            b'wipstash_sqlite_phase pid=123 phase=state_lock_waiting elapsed_ms=1\n',
            timed_out=True))
        self.assertTrue(result['timed_out'])
        self.assertEqual({'entered': 0, 'state_lock_waiting': 1}, result['phases']['sqlite'])
        for key in ('state_lock_wait_ms', 'dispatch_ms', 'materialization_ms'):
            self.assertNotIn(key, result)

    def test_diagnostics_are_strictly_allowlisted_and_bounded(self):
        private = 'PRIVATE_PATH PRIVATE_PROPOSAL PRIVATE_CONTENT'
        lines = [private,
                 'wipstash_sqlite_phase pid=123 phase=private_path elapsed_ms=9',
                 'wipstash_sqlite_phase pid=123 phase=entered elapsed_ms=0 ' + private,
                 'wipstash_resolution_phase pid=123 phase=dispatch elapsed_ms=3',
                 'wipstash_sqlite_phase pid=123 phase=entered elapsed_ms=-1',
                 'wipstash_sqlite_phase pid=123 phase=entered elapsed_ms=2',
                 'wipstash_sqlite_phase pid=123 phase=entered elapsed_ms=3']
        result = stress.resolution_timing(self.event('\n'.join(lines)))
        self.assertEqual({'entered': 2}, result['phases']['sqlite'])
        self.assertEqual({}, result['phases']['resolution'])
        self.assertNotIn('PRIVATE', json.dumps(result))
        self.assertNotIn('123', json.dumps(result))
        result = stress.resolution_timing(self.event('x\n' * 256 + lines[-1]))
        self.assertEqual({}, result['phases']['sqlite'])
        for stderr in (None, '', object()):
            self.assertEqual({'sqlite': {}, 'resolution': {}},
                             stress.resolution_timing(self.event(stderr))['phases'])
        for seconds in (-1, float('inf'), float('nan'), True, 'private'):
            event = self.event('')
            event['seconds'] = seconds
            self.assertIsNone(stress.resolution_timing(event))
        self.assertIsNone(stress.resolution_timing({'argv': ['invalid']}))
        self.assertIsNone(stress.resolution_timing({'argv': ['null'], 'seconds': 0}))

    def test_harness_records_timeout_then_rethrows_same_exception_without_retry(self):
        failure = subprocess.TimeoutExpired(['synthetic'], 40, output=b'PRIVATE\xff',
            stderr=b'wipstash_sqlite_phase pid=123 phase=state_lock_waiting elapsed_ms=1\n')
        with tempfile.TemporaryDirectory() as root:
            harness = harness_support.Harness('unused-binary', root)
            with mock.patch.object(harness_support.subprocess, 'run', side_effect=failure) as run:
                with self.assertRaises(subprocess.TimeoutExpired) as caught:
                    harness.command(['synthetic'])
            harness.save_log()
            self.assertEqual('PRIVATE\ufffd', json.loads((harness.root / 'commands.json').read_text())[0]['stdout'])
        self.assertIs(failure, caught.exception)
        run.assert_called_once()
        self.assertEqual(40, run.call_args.kwargs['timeout'])
        self.assertEqual(1, len(harness.events))
        self.assertTrue(harness.events[0]['timed_out'])
        self.assertEqual(failure.stderr.decode('utf-8'), harness.events[0]['stderr'])
        self.assertIsNone(harness.events[0]['exit'])

    def test_summary_timing_count_is_bounded_across_cases(self):
        case = stress.ConflictStress('test_distinct_agents_concurrent_publish_and_resolution_waves')
        case.h = SimpleNamespace(events=[self.event('')] * (stress.MAX_RESOLUTION_TIMINGS + 5))
        with mock.patch.object(stress, 'RESOLUTION_TIMINGS', []) as timings:
            case.tearDown()
            self.assertEqual(stress.MAX_RESOLUTION_TIMINGS, len(timings))
            before = list(timings)
            case.tearDown()
            self.assertEqual(before, timings)
            self.assertNotIn('PRIVATE', json.dumps(timings))


if __name__ == '__main__':
    unittest.main(verbosity=2)
