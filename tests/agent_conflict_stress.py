#!/usr/bin/env python3
"""Four scripted agents, real CLI processes, deterministic conflict campaigns.

Native GitHub CI only: GITHUB_ACTIONS=true WIPSTASH_CONFLICT_STRESS_CI=1
python tests/agent_conflict_stress.py --seed 731927
Every request reopens SQLite/Git; no daemon, sockets, kill, or AI-session claim.
Only summary.json is intended for upload; scratch state contains synthetic WIP.
"""
import argparse
import contextlib
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import os
from pathlib import Path
import random
import sqlite3
import sys
import tempfile
import threading
import time
import unittest

from harness_support import Harness, canaries, manifest, write

ARGS = None
ROOT = None
HEAD = 'refs/wipstash/integration'
COUNTS = Counter()
COUNT_LOCK = threading.Lock()
DISTINCT = {'published_proposals': set(), 'submitted_resolutions': set(), 'returned_conflicts': set(), 'integrated_proposals': set()}

def observe(scope, request, response):
    with COUNT_LOCK:
        COUNTS['requests'] += 1
        COUNTS['op_' + request['op']] += 1
        if not response.get('ok', False):
            COUNTS['rejected_requests'] += 1
        elif request['op'] == 'publish':
            DISTINCT['published_proposals'].add((scope, response['proposal']))
        elif request['op'] == 'resolution_submit':
            DISTINCT['submitted_resolutions'].add((scope, response['proposal']))
        elif request['op'] == 'integrate':
            for outcome in response['outcomes']:
                if outcome['state'] == 'quarantined':
                    DISTINCT['returned_conflicts'].add((scope, outcome['proposal']))
                elif outcome['state'] == 'integrated':
                    DISTINCT['integrated_proposals'].add((scope, outcome['proposal']))


class ConflictStress(unittest.TestCase):
    def setUp(self):
        # Keep fixtures beneath Windows MAX_PATH without weakening production guards.
        # Descriptive test names remain in unittest output and summary evidence.
        case_id = 't-' + hashlib.sha256(self._testMethodName.encode()).hexdigest()[:8]
        self.h = Harness(ARGS.binary, ROOT / case_id)
        self.state = self.h.root / 'state'
        self.paths = {a: self.h.root / ('work-' + a) for a in 'ABCD'}
        self.generations = {}
        self.serial = 0
        self.conflicts = {}
        self.lock = threading.Lock()
        self.rng = random.Random(ARGS.seed)
        self.req(op='init', source=str(self.h.fixture(self.h.root / 'source')))
        for a, path in self.paths.items():
            self.generations[a] = self.req(op='open', workspace=a, path=str(path))['generation']
            canaries(path, a)

    def req(self, ok=True, **request):
        with self.lock:
            self.serial += 1
            request.setdefault('operation_id', 'stress-' + str(self.serial))
        reply = self.h.call('--state', self.state, json.dumps(request), ok=ok)
        observe(self._testMethodName, request, reply)
        if ok:
            self.assertTrue(reply['ok'], reply)
        else:
            self.assertFalse(reply.get('ok', False), reply)
        return reply

    def cp(self, workspace):
        reply = self.req(op='checkpoint', workspace=workspace,
                         expected_generation=self.generations[workspace])
        self.generations[workspace] = reply['generation']
        return reply['checkpoint']

    def publish(self, a):
        return self.req(op='publish', workspace=a, checkpoint=self.cp(a),
                        intent='Synthetic four-agent conflict stress')['proposal']

    def status(self, proposal):
        return self.req(op='proposal_status', proposal=proposal)

    def tasks(self, a):
        return self.req(op='resolution_tasks', workspace=a)['tasks']

    def head(self):
        return self.req(op='status')['head']

    def repo(self):
        return self.state / 'coordinator.git'

    def open_resolution(self, a, proposal, suffix):
        workspace = 'resolve-' + a + '-' + suffix
        path = self.h.root / workspace
        reply = self.req(op='resolution_open', workspace=a, proposal=proposal,
                         resolution_workspace=workspace, path=str(path))
        self.generations[workspace] = reply['generation']
        self.conflicts[workspace] = reply['conflict_paths']
        self.assertNotIn(path, self.paths.values())
        return workspace, path, reply['current_head']

    def submit_request(self, a, proposal, resolution, operation):
        workspace, _, head = resolution
        return dict(op='resolution_submit', workspace=a, proposal=proposal,
                    resolution_workspace=workspace, checkpoint=self.cp(workspace),
                    expected_head=head, resolved_conflicts=self.conflicts[workspace], operation_id=operation)

    def frozen(self):
        return {a: manifest(path) for a, path in self.paths.items()}

    def audit(self, private_oids=()):
        self.h.git(self.repo(), 'fsck', '--full', '--strict')
        objects = self.h.git(self.repo(), 'cat-file', '--batch-all-objects', '--batch-check=%(objectname)')
        for oid in private_oids:
            self.assertNotIn(oid, objects.splitlines())
        for line in self.h.git(self.repo(), 'ls-tree', '-r', self.head()).splitlines():
            meta, path = line.split('\t', 1)
            self.assertNotIn(path.split('/')[0], ('.env', 'local', 'build', '.agent'))
            body = self.h.git(self.repo(), 'cat-file', 'blob', meta.split()[2])
            self.assertNotIn('NOT_A_REAL_SECRET_', body)
            self.assertNotIn('PRIVATE_CONFLICT_CANARY', body)
        self.assertFalse((self.repo() / 'objects/info/alternates').exists())
        with contextlib.closing(sqlite3.connect(self.state / 'state.sqlite')) as db:
            self.assertEqual([('ok',)], db.execute('pragma integrity_check').fetchall())
            self.assertEqual([], db.execute("select proposal from promotions where state='committed' group by proposal having count(*) > 1").fetchall())

    def test_four_overlapping_agents_return_resolve_rebase_and_duplicate(self):
        # A private ancestor must not hitch a ride on a later resolution proposal.
        write(self.paths['B'], 'private-only.txt', 'PRIVATE_CONFLICT_CANARY\n')
        private_checkpoint = self.cp('B')
        with contextlib.closing(sqlite3.connect(self.state / 'state.sqlite')) as db:
            private_commit = db.execute('select commit_oid from checkpoints where id=?', (private_checkpoint,)).fetchone()[0]
        private_repo = self.state / 'locals/B/objects.git'
        private_blob = self.h.git(private_repo, 'rev-parse', private_commit + ':private-only.txt')
        (self.paths['B'] / 'private-only.txt').unlink()
        order = list('ABCD')
        self.rng.shuffle(order)
        proposals = {}
        for a in order:
            write(self.paths[a], 'notes/shared.txt', 'overlap-' + a + '\n')
            proposals[a] = self.publish(a)
            write(self.paths[a], 'unsaved-' + a + '.txt', 'PRIVATE_CONFLICT_CANARY ' + a + '\n')
        frozen = self.frozen()
        result = self.req(op='integrate')
        self.assertEqual(4, len(result['outcomes']))
        winner, *losers = order
        self.assertEqual('integrated', self.status(proposals[winner])['state'])
        self.assertEqual([], self.tasks(winner))
        resolutions = {}
        for a in losers:
            self.assertEqual('quarantined', self.status(proposals[a])['state'])
            task = self.tasks(a)
            self.assertEqual(1, len(task))
            self.assertEqual(proposals[a], task[0]['proposal'])
            self.assertIn('notes/shared.txt', task[0]['conflict_paths'])
            self.assertEqual(task, self.tasks(a), 'Fresh process must recover identical durable task')
            self.req(ok=False, op='resolution_open', workspace=winner, proposal=proposals[a],
                     resolution_workspace='wrong-owner-' + a, path=str(self.h.root / ('wrong-' + a)))
            resolutions[a] = self.open_resolution(a, proposals[a], 'initial')
        self.assertEqual(frozen, self.frozen())
        first = losers[0]
        resolution = resolutions[first]
        text = 'overlap-' + winner + '\nresolved-' + first + '\n'
        write(resolution[1], 'notes/shared.txt', text)
        request = self.submit_request(first, proposals[first], resolution, 'same-resolution-response')
        self.req(ok=False, **dict(request, workspace=winner, operation_id='wrong-owner-submit'))
        self.req(ok=False, **dict(request, resolved_conflicts=[], operation_id='missing-attestation'))
        self.req(ok=False, **dict(request, resolved_conflicts=['notes/shared.txt', 'notes/shared.txt'], operation_id='duplicate-attestation'))
        rival = self.open_resolution(first, proposals[first], 'rival')
        write(rival[1], 'notes/shared.txt', text)
        rival_request = self.submit_request(first, proposals[first], rival, 'distinct-rival-resolution')
        gate = threading.Barrier(2)
        def compete(candidate):
            gate.wait(timeout=30)
            reply = self.h.call('--state', self.state, json.dumps(candidate), ok=False)
            observe(self._testMethodName, candidate, reply)
            return candidate, reply
        with ThreadPoolExecutor(max_workers=2) as pool:
            raced = list(pool.map(compete, [request, rival_request]))
        self.assertEqual([False, True], sorted(reply.get('ok', False) for _, reply in raced), raced)
        request, accepted = next((candidate, reply) for candidate, reply in raced if reply.get('ok'))
        rejected_request, rejected = next((candidate, reply) for candidate, reply in raced if not reply.get('ok'))
        self.assertEqual(rejected, self.req(ok=False, **rejected_request))
        with ThreadPoolExecutor(max_workers=4) as pool:
            replies = list(pool.map(lambda _: self.req(**request), range(4)))
        self.assertEqual(accepted, replies[0])
        self.assertTrue(all(r == replies[0] for r in replies), replies)
        replacement = replies[0]['proposal']
        self.assertEqual(replies[0], self.req(**request))
        self.req(ok=False, **dict(request, expected_head='0' * 40))
        self.assertEqual('superseded', self.status(proposals[first])['state'])
        self.req(ok=False, **dict(request, operation_id='second-resolution-response'))
        self.req(op='integrate')
        self.assertEqual('integrated', self.status(replacement)['state'])
        for a in losers[1:]:
            old = resolutions[a]
            write(old[1], 'notes/shared.txt', 'stale must never land\n')
            rejected = self.req(ok=False, **self.submit_request(a, proposals[a], old, 'stale-' + a))
            self.assertIn('stale_resolution', json.dumps(rejected))
            resolution = self.open_resolution(a, proposals[a], 'fresh')
            text += 'resolved-' + a + '\n'
            write(resolution[1], 'notes/shared.txt', text)
            replacement = self.req(**self.submit_request(a, proposals[a], resolution, 'fresh-' + a))['proposal']
            self.req(op='integrate')
            self.assertEqual('integrated', self.status(replacement)['state'])
            self.assertEqual('superseded', self.status(proposals[a])['state'])
        self.assertEqual(text.rstrip(), self.h.git(self.repo(), 'show', self.head() + ':notes/shared.txt'))
        self.assertEqual(frozen, self.frozen(), 'Return/open/submit/integrate must never mutate owner WIP')
        for a in order:
            self.assertEqual([], self.tasks(a))
        self.audit((private_commit, private_blob))
        self.assertEqual(private_blob, self.h.git(private_repo, 'rev-parse', private_commit + ':private-only.txt'))

    def test_clean_merge_checks_return_bounded_retries_and_queue_progress(self):
        check = "from pathlib import Path; import sys; p=Path('business.txt'); sys.exit(7 if p.exists() and p.read_text() != 'valid\\n' else 0)"
        self.req(op='configure', policy={'checks': [{'id': 'semantic-contract', 'argv': [sys.executable, '-c', check], 'required': True, 'timeout_seconds': 5}]})
        write(self.paths['A'], 'business.txt', 'invalid\n')
        proposal = self.publish('A')
        # Disjoint proposals must flow past a returned failing proposal.
        for a in 'BCD':
            write(self.paths[a], 'docs/' + a + '.txt', 'unrelated-' + a + '\n')
            self.publish(a)
        frozen = self.frozen()
        result = self.req(op='integrate')
        self.assertEqual(['quarantined', 'integrated', 'integrated', 'integrated'], [r['state'] for r in result['outcomes']])
        task = self.tasks('A')[0]
        self.assertEqual([], task['conflict_paths'])
        self.assertEqual(3, task['max_attempts'])
        self.assertTrue(any(c.get('exit_code') == 7 for c in task['checks']), task)
        for attempt in range(1, 4):
            resolution = self.open_resolution('A', proposal, str(attempt))
            write(resolution[1], 'business.txt', 'still-invalid-' + str(attempt) + '\n')
            # A compatible head advance must not force a resolution reopen or
            # waive the required check when the unchanged candidate integrates.
            progress_path = 'docs/check-progress-' + str(attempt) + '.txt'
            write(self.paths['B'], progress_path, 'unrelated\n')
            frozen['B'][progress_path] = manifest(self.paths['B'])[progress_path]
            progress = self.publish('B')
            self.req(op='integrate')
            self.assertEqual('integrated', self.status(progress)['state'])
            submitted = self.req(**self.submit_request('A', proposal, resolution, 'retry-' + str(attempt)))
            self.assertTrue(submitted['head_advanced'])
            self.assertTrue(submitted['checks_pending'])
            self.assertEqual(resolution[2], submitted['base'])
            proposal = submitted['proposal']
            before = self.head()
            self.req(op='integrate')
            self.assertEqual(before, self.head(), 'Failed checks must not promote a clean textual merge')
            self.assertEqual('quarantined', self.status(proposal)['state'])
            task = self.tasks('A')[0]
            self.assertEqual('action_required' if attempt < 3 else 'escalated', task['state'])
            self.assertTrue(any(c.get('exit_code') == 7 for c in task['checks']), task)
        self.req(ok=False, op='resolution_open', workspace='A', proposal=proposal,
                 resolution_workspace='over-budget', path=str(self.h.root / 'over-budget'))
        for _ in range(4):
            self.assertEqual([], self.req(op='integrate')['outcomes'], 'No autonomous unbounded retries')
        self.assertEqual(frozen, self.frozen())
        for a in 'BCD':
            self.assertEqual('unrelated-' + a, self.h.git(self.repo(), 'show', self.head() + ':docs/' + a + '.txt'))
        self.audit()


    def test_distinct_agents_concurrent_publish_and_resolution_waves(self):
        # Three waves, four independently owned workspaces per wave. The actor
        # that wins is discovered from integration results, never thread order.
        for wave in range(3):
            owners = ['wave-' + str(wave) + '-' + a for a in 'ABCD']
            paths = {}
            for owner in owners:
                path = self.h.root / owner
                paths[owner] = path
                self.generations[owner] = self.req(op='open', workspace=owner, path=str(path))['generation']
                canaries(path, owner)
            barrier = threading.Barrier(4)
            def publish_actor(owner):
                write(paths[owner], 'notes/shared.txt', owner + '\n')
                barrier.wait(timeout=30)
                proposal = self.publish(owner)
                write(paths[owner], 'unpublished.txt', 'PRIVATE_CONFLICT_CANARY ' + owner + '\n')
                return owner, proposal
            with ThreadPoolExecutor(max_workers=4) as pool:
                proposals = dict(pool.map(publish_actor, owners))
            frozen = {owner: manifest(path) for owner, path in paths.items()}
            outcomes = self.req(op='integrate')['outcomes']
            self.assertEqual(4, len(outcomes))
            integrated = [o['proposal'] for o in outcomes if o['state'] == 'integrated']
            self.assertEqual(1, len(integrated), outcomes)
            winner = next(owner for owner, proposal in proposals.items() if proposal == integrated[0])
            pending = {owner: proposal for owner, proposal in proposals.items() if owner != winner}
            resolved_owners = set()
            for attempt in range(1, 4):
                if not pending:
                    break
                head = self.head()
                baseline = self.h.git(self.repo(), 'show', head + ':notes/shared.txt') + '\n'
                barrier = threading.Barrier(len(pending))
                def resolve_actor(item):
                    owner, proposal = item
                    resolution = self.open_resolution(owner, proposal, 'wave-attempt-' + str(attempt))
                    self.assertEqual(head, resolution[2])
                    write(resolution[1], 'notes/shared.txt', baseline + 'resolved-' + owner + '\n')
                    request = self.submit_request(owner, proposal, resolution,
                                                  'wave-submit-' + owner + '-' + str(attempt))
                    barrier.wait(timeout=30)
                    return owner, self.req(**request)['proposal']
                with ThreadPoolExecutor(max_workers=4) as pool:
                    submitted = dict(pool.map(resolve_actor, pending.items()))
                self.assertEqual(len(pending), len(set(submitted.values())))
                outcomes = self.req(op='integrate')['outcomes']
                self.assertEqual(len(submitted), len(outcomes))
                integrated = [o['proposal'] for o in outcomes if o['state'] == 'integrated']
                self.assertEqual(1, len(integrated), outcomes)
                integrated_owner = next(owner for owner, proposal in submitted.items() if proposal == integrated[0])
                resolved_owners.add(integrated_owner)
                pending = {owner: proposal for owner, proposal in submitted.items() if owner != integrated_owner}
                for owner, proposal in pending.items():
                    tasks = self.tasks(owner)
                    self.assertEqual([proposal], [t['proposal'] for t in tasks])
                    self.assertEqual(attempt, tasks[0]['attempt'])
                    self.assertEqual('action_required', tasks[0]['state'])
                self.assertEqual(frozen, {owner: manifest(path) for owner, path in paths.items()})
            self.assertEqual({}, pending, 'Every distinct agent must finish within the three-attempt lineage budget')
            final = self.h.git(self.repo(), 'show', self.head() + ':notes/shared.txt').splitlines()
            self.assertEqual({winner, *('resolved-' + owner for owner in resolved_owners)}, set(final))
            self.assertEqual(4, len(final))
            for owner in owners:
                self.assertEqual([], self.tasks(owner))
        self.audit()

    def test_resolution_fault_recovery_and_cancelled_session(self):
        for a in 'AB':
            write(self.paths[a], 'notes/shared.txt', 'fault-' + a + '\n')
        self.publish('A')
        proposal = self.publish('B')
        self.req(op='integrate')
        frozen = self.frozen()
        def fault(point, request):
            reply = self.h.command([self.h.binary, '--state', self.state, json.dumps(request)],
                                   env={'WIPSTASH_FAULT': point}, ok=False)
            self.assertEqual(86, reply.returncode, 'Expected explicit injected exit, not a spontaneous process failure')
        for suffix, point in [('intent', 'resolution_open_after_intent'), ('materialize', 'resolution_open_after_materialize')]:
            workspace = 'fault-resolution-' + suffix
            path = self.h.root / workspace
            request = dict(op='resolution_open', workspace='B', proposal=proposal,
                           resolution_workspace=workspace, path=str(path), operation_id='fault-open-' + suffix)
            fault(point, request)
            opened = self.req(**request)
            self.assertEqual(opened, self.req(**request))
            self.generations[workspace] = opened['generation']
            self.conflicts[workspace] = opened['conflict_paths']
        resolution = workspace, path, opened['current_head']
        # Unchanged generated markers may not be blessed by an attestation.
        marked_request = self.submit_request('B', proposal, resolution, 'unchanged-markers')
        self.assertIn('unresolved_conflict_markers', json.dumps(self.req(ok=False, **marked_request)))
        self.req(ok=False, op='publish', workspace=workspace, checkpoint=marked_request['checkpoint'],
                 intent='Attempt to bypass resolution lineage')
        write(path, 'notes/shared.txt', 'fault-A\nresolved-B\n')
        request = self.submit_request('B', proposal, resolution, 'fault-submit-pin')
        fault('resolution_submit_after_pin', request)
        pinned = self.h.git(self.state / 'locals/B/objects.git', 'rev-parse', 'refs/wipstash/exports/fault-submit-pin')
        # Cross Git's one-second commit timestamp boundary before retrying.
        # Reusing the operation must recover the original pin, not synthesize a
        # sibling commit that only happened to hash identically on a fast runner.
        time.sleep(2.1)
        submitted = self.req(**request)
        self.assertEqual(pinned, submitted['commit'])
        self.assertEqual(pinned, self.h.git(self.state / 'locals/B/objects.git', 'rev-parse', 'refs/wipstash/exports/fault-submit-pin'))
        self.assertEqual(submitted, self.req(**request))
        self.req(op='integrate')
        self.assertEqual('integrated', self.status(submitted['proposal'])['state'])
        # A second lineage exercises recovery after the transaction committed.
        write(self.paths['B'], 'notes/shared.txt', 'second-fault-B\n')
        proposal = self.publish('B')
        self.req(op='integrate')
        resolution = self.open_resolution('B', proposal, 'after-commit')
        write(resolution[1], 'notes/shared.txt', 'fault-A\nresolved-B\nsecond-B\n')
        request = self.submit_request('B', proposal, resolution, 'fault-submit-commit')
        fault('resolution_submit_after_commit', request)
        submitted = self.req(**request)
        self.assertEqual(submitted, self.req(**request))
        self.req(op='integrate')
        self.assertEqual('integrated', self.status(submitted['proposal'])['state'])
        # Cancellation retires already-open sessions instead of reviving a task.
        write(self.paths['C'], 'notes/shared.txt', 'cancelled-C\n')
        proposal = self.publish('C')
        self.req(op='integrate')
        resolution = self.open_resolution('C', proposal, 'cancelled')
        write(resolution[1], 'notes/shared.txt', 'must never publish\n')
        request = self.submit_request('C', proposal, resolution, 'cancelled-submit')
        self.req(op='cancel', proposal=proposal)
        self.req(ok=False, **request)
        self.assertEqual([], self.tasks('C'))
        # Only explicit test edits/checkpoints touched owner WIP.
        self.assertEqual(frozen['A'], manifest(self.paths['A']))
        self.assertEqual(frozen['D'], manifest(self.paths['D']))
        self.assertEqual('second-fault-B\n', (self.paths['B'] / 'notes/shared.txt').read_text())
        self.assertEqual('cancelled-C\n', (self.paths['C'] / 'notes/shared.txt').read_text())
        self.audit()

    def test_remote_four_agents_owner_receipts_forgery_and_stale_offline_resolution(self):
        states = {a: self.h.root / ('remote-state-' + a) for a in ['hub', *'ABCD']}
        paths = {a: self.h.root / ('remote-work-' + a) for a in 'ABCD'}
        generations = {}
        def req(a, ok=True, **request):
            with self.lock:
                self.serial += 1
                request.setdefault('operation_id', 'remote-' + str(self.serial))
            result = self.h.call('--state', states[a], json.dumps(request), ok=ok)
            observe(self._testMethodName + a, request, result)
            self.assertEqual(ok, result.get('ok', False), result)
            return result
        def export(a, kind, proposal=None):
            path = self.h.root / ('artifact-' + str(self.serial))
            request = dict(op='sync_export', kind=kind, destination=str(path))
            if proposal:
                request['proposal'] = proposal
            req(a, **request)
            return path
        def deliver(a, artifact, ok=True):
            return req(a, ok=ok, op='sync_import', source=str(artifact), confirm_trusted_source=True)
        def publish(a):
            cp = req(a, op='checkpoint', workspace=a, expected_generation=generations[a])
            generations[a] = cp['generation']
            return req(a, op='publish', workspace=a, checkpoint=cp['checkpoint'], intent='Synthetic remote agent conflict')['proposal']
        def resolve(a, proposal, suffix, content):
            workspace = 'remote-resolve-' + a + '-' + suffix
            path = self.h.root / workspace
            opened = req(a, op='resolution_open', workspace=a, proposal=proposal,
                         resolution_workspace=workspace, path=str(path))
            self.assertFalse(any(p.name.startswith('unsaved-') for p in path.rglob('*')))
            self.assertFalse((path / '.env').exists())
            write(path, 'notes/shared.txt', content)
            cp = req(a, op='checkpoint', workspace=workspace, expected_generation=opened['generation'])
            request = dict(op='resolution_submit', workspace=a, proposal=proposal,
                           resolution_workspace=workspace, checkpoint=cp['checkpoint'],
                           expected_head=opened['current_head'], resolved_conflicts=opened['conflict_paths'],
                           operation_id='remote-submit-' + a + '-' + suffix)
            result = req(a, **request)
            self.assertEqual(result, req(a, **request))
            return result['proposal']
        def hub_snapshot():
            repo = states['hub'] / 'coordinator.git'
            with contextlib.closing(sqlite3.connect(states['hub'] / 'state.sqlite')) as db:
                proposals = db.execute('select id,state from proposals order by id').fetchall()
            return (self.h.git(repo, 'show-ref'), self.h.git(repo, 'cat-file', '--batch-all-objects', '--batch-check=%(objectname)'), proposals)
        req('hub', op='init', source=str(self.h.root / 'source'))
        for a in states:
            req(a, op='sync_configure', project='conflict-stress', authority='hub', epoch=1,
                device=a, role='authority' if a == 'hub' else 'client', peers=list('ABCD') if a == 'hub' else ['hub'])
        bootstrap = export('hub', 'head')
        proposals, authority_ids = {}, {}
        for a in 'ABCD':
            deliver(a, bootstrap)
            generations[a] = req(a, op='open', workspace=a, path=str(paths[a]))['generation']
            canaries(paths[a], a)
            write(paths[a], 'notes/shared.txt', 'remote-' + a + '\n')
            proposals[a] = publish(a)
            artifact = export(a, 'proposal', proposals[a])
            authority_ids[a] = deliver('hub', artifact)['proposal']
            deliver('hub', artifact)
            write(paths[a], 'unsaved-' + a + '.txt', 'PRIVATE_CONFLICT_CANARY ' + a + '\n')
        frozen = {a: manifest(p) for a, p in paths.items()}
        req('hub', op='integrate')
        shared_head = export('hub', 'head')
        receipts = {}
        for a in 'BCD':
            receipts[a] = export('hub', 'receipt', authority_ids[a])
            before_head = req(a, op='status')['head']
            deliver('A', receipts[a], ok=False)
            deliver(a, receipts[a])
            deliver(a, receipts[a])
            self.assertEqual(before_head, req(a, op='status')['head'], 'Task delivery must not implicitly adopt or advance cached head')
            tasks = req(a, op='resolution_tasks', workspace=a)['tasks']
            self.assertEqual([proposals[a]], [t['proposal'] for t in tasks])
            self.assertEqual(tasks, req(a, op='resolution_tasks', workspace=a)['tasks'])
            task_payload = json.loads((receipts[a] / 'manifest.json').read_text())['receipt']['resolution_task']
            self.assertNotIn('diagnosis', task_payload)
            self.assertNotIn('spawn_error', json.dumps(task_payload))
            self.assertNotIn(str(self.h.root), json.dumps(task_payload))
            if a != 'B':
                deliver(a, shared_head)
        # Both offline agents submit against the same observed head; only B gets there first.
        cached_b = req('B', op='status')['head']
        self.assertNotEqual(req('hub', op='status')['head'], cached_b)
        revised_b = resolve('B', proposals['B'], 'first', 'remote-A\nresolved-B\n')
        self.assertEqual(req('hub', op='status')['head'], self.h.git(states['B'] / 'locals/B/objects.git', 'rev-parse', req('B', op='proposal_status', proposal=revised_b)['commit'] + '^'))
        self.assertEqual(cached_b, req('B', op='status')['head'], 'Using receipt inputs must not advance cached integration HEAD')
        deliver('B', shared_head)
        revised_c = resolve('C', proposals['C'], 'first', 'remote-A\nresolved-C\n')
        artifact_b = export('B', 'proposal', revised_b)
        artifact_c = export('C', 'proposal', revised_c)
        import shutil
        for label, mutate in [
            ('root', lambda m: m['resolution'].update(root=proposals['D'])),
            ('parent', lambda m: m['resolution'].update(parent=proposals['D'])),
            ('attempt', lambda m: m['resolution'].update(attempt=3)),
            ('device', lambda m: m.update(device='D')),
        ]:
            bad = self.h.root / ('forged-' + label)
            shutil.copytree(artifact_b, bad)
            m = json.loads((bad / 'manifest.json').read_text())
            mutate(m)
            (bad / 'manifest.json').write_text(json.dumps(m))
            before = hub_snapshot()
            deliver('hub', bad, ok=False)
            self.assertEqual(before, hub_snapshot(), 'Forged lineage must fail before public object installation')
        accepted_b = deliver('hub', artifact_b)['proposal']
        deliver('hub', artifact_b)
        req('hub', op='integrate')
        self.assertEqual('integrated', req('hub', op='proposal_status', proposal=accepted_b)['state'])
        # The authority must accept a stale public revision into its normal merge
        # pipeline, or issue a durable owner-routed rejection task. A silent reject
        # after the client superseded its parent would strand the work.
        accepted_c = deliver('hub', artifact_c)['proposal']
        req('hub', op='integrate')
        self.assertEqual('quarantined', req('hub', op='proposal_status', proposal=accepted_c)['state'])
        receipt_c = export('hub', 'receipt', accepted_c)
        deliver('C', receipt_c)
        deliver('C', receipt_c)
        deliver('C', receipts['C'])  # Late duplicate parent observation cannot erase the new task.
        latest_parent = export('hub', 'receipt', authority_ids['C'])
        old_revision = json.loads((receipts['C'] / 'manifest.json').read_text())['receipt']['revision']
        new_revision = json.loads((latest_parent / 'manifest.json').read_text())['receipt']['revision']
        self.assertGreater(new_revision, old_revision)
        deliver('C', latest_parent)  # Newly issued superseded-parent observation is harmless too.
        replay = deliver('C', receipts['C'])  # Exact known artifacts return their cached acknowledgment.
        self.assertTrue(replay['duplicate'])
        parent_status = req('C', op='proposal_status', proposal=proposals['C'])
        self.assertEqual('superseded', parent_status['state'])
        self.assertEqual(new_revision, parent_status['remote_observation']['revision'])
        fresh_stale = self.h.root / 'fresh-stale-parent'
        shutil.copytree(receipts['C'], fresh_stale)
        stale_manifest = json.loads((fresh_stale / 'manifest.json').read_text())
        stale_manifest['operation'] = 'fresh-old-parent-observation'
        (fresh_stale / 'manifest.json').write_text(json.dumps(stale_manifest))
        stale_result = deliver('C', fresh_stale, ok=False)
        self.assertIn('stale_receipt', json.dumps(stale_result))
        self.assertEqual(parent_status, req('C', op='proposal_status', proposal=proposals['C']))
        tasks = req('C', op='resolution_tasks', workspace='C')['tasks']
        self.assertEqual([revised_c], [t['proposal'] for t in tasks])
        self.assertEqual(1, tasks[0]['attempt'])
        next_head = export('hub', 'head')
        for a in 'BCD':
            deliver(a, next_head)
        revised_c2 = resolve('C', revised_c, 'fresh', 'remote-A\nresolved-B\nresolved-C\n')
        accepted_c2 = deliver('hub', export('C', 'proposal', revised_c2))['proposal']
        req('hub', op='integrate')
        self.assertEqual('integrated', req('hub', op='proposal_status', proposal=accepted_c2)['state'])
        deliver('C', export('hub', 'receipt', accepted_c2))
        self.assertEqual([], req('C', op='resolution_tasks', workspace='C')['tasks'])
        self.assertEqual(frozen, {a: manifest(p) for a, p in paths.items()})
        for a in states:
            repo = states[a] / 'coordinator.git'
            self.h.git(repo, 'fsck', '--full', '--strict')
            self.assertFalse((repo / 'objects/info/alternates').exists())
            with contextlib.closing(sqlite3.connect(states[a] / 'state.sqlite')) as db:
                self.assertEqual([('ok',)], db.execute('pragma integrity_check').fetchall())


def main():
    global ARGS, ROOT
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', default='target/debug/' + ('wipstash.exe' if os.name == 'nt' else 'wipstash'))
    parser.add_argument('--artifacts', default='evidence/agent-conflict')
    parser.add_argument('--seed', type=int, default=731927)
    ARGS = parser.parse_args()
    if os.environ.get('GITHUB_ACTIONS') != 'true' or os.environ.get('WIPSTASH_CONFLICT_STRESS_CI') != '1':
        parser.error('native GitHub CI and WIPSTASH_CONFLICT_STRESS_CI=1 are required')
    binary = Path(ARGS.binary).resolve()
    if os.name == 'nt' and not binary.exists() and binary.with_suffix('.exe').exists():
        binary = binary.with_suffix('.exe')
    ARGS.binary = str(binary)
    artifacts = Path(ARGS.artifacts)
    artifacts.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='wc-') as scratch:
        ROOT = Path(scratch).resolve()
        result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(ConflictStress))
        summary = {'seed': ARGS.seed, 'tests': result.testsRun, 'successful': result.wasSuccessful(),
                   'failed_tests': [t.id() for t, _ in result.failures + result.errors],
                   'binary_sha256': hashlib.sha256(Path(ARGS.binary).read_bytes()).hexdigest(),
                   'test_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                   'max_concurrent_agents': 4, 'distinct_agent_waves': 3,
                   'operation_counts': dict(sorted(COUNTS.items())),
                   'distinct_outcome_counts': {key: len(values) for key, values in DISTINCT.items()},
                   'scope': 'Four scripted agents; real concurrent CLI requests and fresh-process durable recovery; no sockets or process killing; no real AI sessions.'}
        (artifacts / 'summary.json').write_text(json.dumps(summary, indent=2) + '\n')
        return 0 if result.wasSuccessful() else 1


if __name__ == '__main__':
    sys.exit(main())
