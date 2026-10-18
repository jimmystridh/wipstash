#!/usr/bin/env python3
"""Local-only peer enrollment invariants. No sockets, credentials or process kills."""
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
BINARY = Path(os.environ.get('WIPSTASH_BINARY', ROOT / 'target/debug/wipstash'))


class PeerAuthorization(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='wipstash-peers-')
        self.root = Path(self.tmp.name)
        self.state = self.root / 'authority'
        source = self.root / 'source'
        source.mkdir()
        (source / 'public.txt').write_text('public\n')
        self.good(op='init', source=str(source))
        self.binding = dict(project='project', authority='authority', epoch=1, device='hub')

    def tearDown(self):
        self.tmp.cleanup()

    def request(self, state=None, **body):
        p = subprocess.run([str(BINARY), '--state', str(state or self.state), json.dumps(body)],
                           capture_output=True, text=True, timeout=30)
        return json.loads(p.stdout)

    def good(self, state=None, **body):
        result = self.request(state, **body)
        self.assertTrue(result.get('ok'), (body, result))
        return result

    def bad(self, code=None, state=None, **body):
        result = self.request(state, **body)
        self.assertFalse(result.get('ok'), (body, result))
        if code:
            self.assertEqual(result['error']['code'], code, result)
        return result

    def initialize(self, operation='initialize'):
        return self.good(op='sync_initialize_authority', operation_id=operation, **self.binding)

    def config(self):
        return self.good(op='sync_status')['config']

    def execute_sql(self, sql, params=()):
        with sqlite3.connect(self.state / 'state.sqlite') as db:
            return db.execute(sql, params).fetchall()

    def test_binding_probe_never_initializes_or_recovers(self):
        fresh = self.root / 'fresh'
        expected = dict(ok=True, state='unconfigured', initialized=False, config=None, pending_config=None)
        self.assertEqual(self.good(fresh, op='sync_binding_status'), expected)
        self.assertFalse(fresh.exists())
        fresh.mkdir()
        self.assertEqual(self.good(fresh, op='sync_binding_status'), expected)
        self.assertEqual(list(fresh.iterdir()), [])
        unconfigured = self.good(op='sync_binding_status')
        self.assertTrue(unconfigured['initialized'])
        self.assertIsNone(unconfigured['config'])
        self.initialize()
        config = self.config()
        self.execute_sql("INSERT INTO meta VALUES('public_recovery_gate',?)", (json.dumps({'activation_required': True}),))
        # Close/checkpoint the test connection before inspecting an immutable snapshot.
        with sqlite3.connect(self.state / 'state.sqlite') as db:
            db.execute('PRAGMA wal_checkpoint(TRUNCATE)')
        def snapshot():
            return {str(p.relative_to(self.state)): (p.stat().st_mtime_ns, p.stat().st_mode,
                    p.read_bytes() if p.is_file() else None) for p in self.state.rglob('*')}
        before = snapshot()
        result = self.good(op='sync_binding_status')
        self.assertEqual(result['config'], config)
        self.assertTrue(result['initialized'])
        self.assertEqual(snapshot(), before)
        (fresh / 'state.sqlite').write_bytes(b'corrupt')
        (fresh / 'state.lock').touch()
        self.bad(state=fresh, op='sync_binding_status')
        (self.state / 'state.sqlite-journal').write_bytes(b'pending')
        self.bad('binding_inspection_requires_recovery', op='sync_binding_status')

    def test_client_initialization_resumes_exact_pending_binding(self):
        client = self.root / 'resume-client'
        self.good(client, op='recovery_status')  # Initialize only the local schema.
        config = dict(project='project', authority='authority', epoch=1,
                      device='client', role='client', peers=['hub'])
        db = sqlite3.connect(client / 'state.sqlite')
        db.execute("CREATE TRIGGER fail_config BEFORE INSERT ON meta WHEN NEW.key='sync_config' BEGIN SELECT RAISE(FAIL, 'synthetic configuration failure'); END")
        db.commit()
        db.close()
        self.bad(state=client, op='sync_configure', **config)
        self.assertTrue((client / 'coordinator.git' / 'HEAD').is_file())
        probe = self.good(client, op='sync_binding_status')
        self.assertEqual(probe['pending_config'], config)
        self.assertIsNone(probe['config'])
        self.assertFalse(probe['initialized'])
        self.bad('authority_binding_mismatch', client, op='sync_configure', **dict(config, device='different'))
        db = sqlite3.connect(client / 'state.sqlite')
        db.execute('DROP TRIGGER fail_config')
        db.commit()
        db.close()
        self.assertEqual(self.good(client, op='sync_configure', **config)['config'], config)
        probe = self.good(client, op='sync_binding_status')
        self.assertEqual(probe['config'], config)
        self.assertIsNone(probe['pending_config'])
        self.assertTrue(probe['initialized'])

    def test_pending_client_rejects_foreign_content_and_accepts_empty_partial(self):
        config = dict(project='project', authority='authority', epoch=1,
                      device='client', role='client', peers=['hub'])
        for name, foreign in [('partial', None), ('object', 'objects/aa/object'),
                              ('reference', 'refs/heads/foreign'), ('config', 'config')]:
            client = self.root / name
            self.good(client, op='recovery_status')
            db = sqlite3.connect(client / 'state.sqlite')
            db.execute("INSERT INTO meta VALUES('sync_client_pending',?)", (json.dumps(config),))
            db.commit()
            db.close()
            repo = client / 'coordinator.git'
            (repo / 'refs').mkdir(parents=True)
            if foreign:
                target = repo / foreign
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text('[include]\npath = /foreign\n' if foreign == 'config' else 'foreign')
                self.bad('client_initialization_not_pristine', client, op='sync_configure', **config)
                self.assertTrue(target.is_file())
            else:
                self.good(client, op='sync_configure', **config)
        foreign = self.root / 'unowned'
        (foreign / 'coordinator.git').mkdir(parents=True)
        self.bad('client_requires_empty_state', foreign, op='sync_configure', **config)

    def test_explicit_empty_bootstrap_and_strict_legacy(self):
        self.bad('invalid_sync_config', op='sync_configure', role='authority', peers=[], **self.binding)
        first = self.initialize()
        self.assertEqual(first['config']['peers'], [])
        self.good(op='sync_add_peer', operation_id='add', peer='laptop')
        self.assertEqual(self.initialize(), first)  # Exact journal retry.
        self.assertEqual(self.initialize('initialize-again')['config']['peers'], ['laptop'])
        self.bad('authority_binding_mismatch', op='sync_configure', role='authority', peers=['other'], **self.binding)
        self.bad('invalid_sync_config', op='sync_configure', role='authority', peers=[], **self.binding)
        self.good(op='sync_configure', role='authority', peers=['laptop'], **self.binding)
        for key, value in [('project', 'other'), ('authority', 'other'), ('epoch', 2), ('device', 'other')]:
            changed = dict(self.binding, **{key: value})
            self.bad('authority_binding_mismatch', op='sync_initialize_authority', operation_id='change-' + key, **changed)
        self.assertEqual(self.config()['peers'], ['laptop'])

    def test_add_is_monotonic_and_journaled(self):
        self.initialize()
        first = self.good(op='sync_add_peer', operation_id='add-one', peer='one')
        self.assertFalse(first['already_present'])
        self.assertFalse(first['transport_access_granted'])
        self.good(op='sync_add_peer', operation_id='add-two', peer='two')
        self.assertEqual(self.good(op='sync_add_peer', operation_id='add-one', peer='one'), first)
        self.assertTrue(self.good(op='sync_add_peer', operation_id='repeat', peer='one')['already_present'])
        self.bad('idempotency_mismatch', op='sync_add_peer', operation_id='add-one', peer='three')
        expected = dict(self.binding, role='authority', peers=['one', 'two'])
        self.assertEqual(self.config(), expected)
        self.assertEqual(self.execute_sql("SELECT count(*) FROM events WHERE kind='sync_peer_added'")[0][0], 2)

    def test_validations_and_capacity(self):
        self.initialize()
        self.bad('invalid_request', op='sync_add_peer', peer='one')
        self.bad('peer_identity_collision', op='sync_add_peer', operation_id='self', peer='hub')
        for i, peer in enumerate(['', '../bad', 'two words', 'é', 'x' * 101]):
            self.bad('invalid_request', op='sync_add_peer', operation_id='bad-' + str(i), peer=peer)
        self.bad('invalid_request', op='sync_add_peer', operation_id='extras', peer='one', epoch=2)
        self.bad('invalid_request', op='sync_initialize_authority', operation_id='init-extras', peers=[], **self.binding)
        for i in range(100):
            self.good(op='sync_add_peer', operation_id='add-' + str(i), peer='peer-' + str(i))
        self.bad('peer_limit_reached', op='sync_add_peer', operation_id='overflow', peer='overflow')
        self.assertTrue(self.good(op='sync_add_peer', operation_id='repeat-full', peer='peer-0')['already_present'])
        self.assertEqual(len(self.config()['peers']), 100)

    def test_bootstrap_validation_does_not_pin_binding(self):
        for i, epoch in enumerate([0, -1, 2 ** 63, "1", None]):
            binding = dict(self.binding, epoch=epoch)
            self.bad(op='sync_initialize_authority', operation_id='epoch-' + str(i), **binding)
        for key in ['project', 'authority', 'device']:
            binding = dict(self.binding, **{key: '../invalid'})
            self.bad('invalid_request', op='sync_initialize_authority', operation_id='bad-' + key, **binding)
        self.assertEqual(self.execute_sql("SELECT value FROM meta WHERE key='sync_config'"), [])
        self.initialize()
        client = self.root / 'empty-client'
        self.bad('invalid_sync_config', client, op='sync_configure', project='project',
                 authority='authority', epoch=1, device='client', role='client', peers=[])

    def test_preserves_sync_history(self):
        self.initialize()
        self.execute_sql("INSERT INTO sync_imports VALUES('old','op','digest','{}')")
        self.execute_sql("INSERT INTO sync_remote_status VALUES('proposal',1,'digest','{}')")
        self.execute_sql("INSERT INTO sync_proposal_origins VALUES('proposal','old','source')")
        self.execute_sql("INSERT INTO sync_exports VALUES('export','digest','{}')")
        tables = ['sync_imports', 'sync_remote_status', 'sync_proposal_origins', 'sync_exports']
        before = {table: self.execute_sql('SELECT * FROM ' + table) for table in tables}
        self.good(op='sync_add_peer', operation_id='add', peer='new')
        self.assertEqual(before, {table: self.execute_sql('SELECT * FROM ' + table) for table in tables})

    def test_requires_initialized_authority(self):
        self.bad('project_not_initialized', state=self.root / 'empty', op='sync_initialize_authority', operation_id='init', **self.binding)
        self.bad('sync_not_configured', op='sync_add_peer', operation_id='unconfigured', peer='one')
        client = self.root / 'client'
        self.good(client, op='sync_configure', project='project', authority='authority', epoch=1,
                  device='client', role='client', peers=['hub'])
        self.bad('authority_required', client, op='sync_add_peer', operation_id='add', peer='other')
        self.bad('authority_required', client, op='sync_initialize_authority', operation_id='initialize', **self.binding)

    def test_recovery_gate_blocks_mutations_even_retries(self):
        self.initialize()
        self.good(op='sync_add_peer', operation_id='add', peer='one')
        self.execute_sql("INSERT INTO meta VALUES('public_recovery_gate',?)", (json.dumps({'activation_required': True}),))
        self.bad('public_recovery_activation_required', op='sync_add_peer', operation_id='add', peer='one')
        self.bad('public_recovery_activation_required', op='sync_initialize_authority', operation_id='initialize', **self.binding)
        self.assertEqual(self.config()['peers'], ['one'])

    def test_atomic_configuration_and_journal_finish(self):
        self.execute_sql("CREATE TRIGGER fail_finish BEFORE UPDATE OF result ON operations BEGIN SELECT RAISE(FAIL, 'synthetic finish failure'); END")
        self.bad(op='sync_initialize_authority', operation_id='initialize', **self.binding)
        self.assertEqual(self.execute_sql("SELECT value FROM meta WHERE key='sync_config'"), [])
        self.execute_sql('DROP TRIGGER fail_finish')
        self.initialize()
        self.execute_sql("CREATE TRIGGER fail_finish BEFORE UPDATE OF result ON operations BEGIN SELECT RAISE(FAIL, 'synthetic finish failure'); END")
        self.bad(op='sync_add_peer', operation_id='add', peer='one')
        self.assertEqual(self.config()['peers'], [])
        self.execute_sql('DROP TRIGGER fail_finish')
        self.good(op='sync_add_peer', operation_id='add', peer='one')
        self.assertEqual(self.config()['peers'], ['one'])
        for operation in ['initialize', 'add']:
            self.assertIsNotNone(self.execute_sql('SELECT result FROM operations WHERE id=?', (operation,))[0][0])


if __name__ == '__main__':
    unittest.main()
