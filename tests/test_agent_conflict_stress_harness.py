#!/usr/bin/env python3
"""Synthetic wave-scheduling regressions; no engine, Git, sockets or CI guard.

Run directly with: python tests/test_agent_conflict_stress_harness.py
"""
from concurrent.futures import ThreadPoolExecutor
import threading
from types import SimpleNamespace
import unittest
from unittest import mock

import agent_conflict_stress as stress


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


if __name__ == '__main__':
    unittest.main(verbosity=2)
