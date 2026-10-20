import base64
import datetime
import hashlib
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import AsyncMock, patch
import asyncio
import httpx
import app as application

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from app import authenticate
from durable import Checkpoints, Fenced, digest, encoded


class Objects:
    def __init__(self):
        self.values = {}
        self.counter = 0
        self.fail = False

    def get(self, name):
        return self.values.get(name, (None, 0))

    def put(self, name, value, generation):
        if self.fail or self.get(name)[1] != generation:
            raise Fenced("object_generation_changed")
        self.counter += 1
        self.values[name] = value, self.counter
        return self.counter


class DurabilityTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.path = Path(self.temporary.name)
        self.objects = Objects()
        self.now = [1000]
        self.store = Checkpoints(self.objects, self.path / "first", lambda: self.now[0])
        self.store.acquire()
        self.store.root.mkdir()

    def test_checkpoint_preserves_committed_wal_git_and_empty_directories(self):
        database = sqlite3.connect(self.store.root / "state.sqlite")
        self.addCleanup(database.close)
        database.execute("PRAGMA journal_mode=WAL")
        database.execute("CREATE TABLE values_(value)")
        database.execute("INSERT INTO values_ VALUES('committed')")
        database.commit()
        (self.store.root / "objects").mkdir()
        (self.store.root / "objects/blob").write_bytes(b"git object")
        (self.store.root / "script").write_text("#!/bin/sh\nexit 0\n")
        (self.store.root / "script").chmod(0o700)
        (self.store.root / "empty").mkdir()
        checkpoint = self.store.checkpoint()
        recovered = Checkpoints(self.objects, self.path / "second", lambda: self.now[0])
        recovered.restore(checkpoint)
        self.assertFalse((recovered.root / "state.sqlite-wal").exists())
        with sqlite3.connect(recovered.root / "state.sqlite") as db:
            self.assertEqual(db.execute("SELECT value FROM values_").fetchone()[0], "committed")
        self.assertEqual((recovered.root / "objects/blob").read_bytes(), b"git object")
        self.assertTrue((recovered.root / "empty").is_dir())
        self.assertTrue((recovered.root/"script").stat().st_mode & 0o100)
        self.assertFalse((recovered.root/"objects/blob").stat().st_mode & 0o111)

    def test_stale_writer_cannot_publish_after_takeover(self):
        (self.store.root / "value").write_text("acknowledged")
        original = self.store.checkpoint()
        newer = Checkpoints(self.objects, self.path / "new", lambda: self.now[0])
        with self.assertRaisesRegex(Fenced, "lease_active"):
            newer.acquire()
        self.now[0] += 91
        self.assertEqual(newer.acquire(), original)
        newer.restore(original)
        (newer.root / "value").write_text("new authority")
        latest = newer.checkpoint()
        (self.store.root / "value").write_text("stale")
        with self.assertRaises(Fenced):
            self.store.checkpoint()
        self.assertTrue(self.store.failed)
        self.assertEqual(json.loads(self.objects.get("authority.json")[0])["checkpoint"], latest)

    def test_failed_upload_keeps_last_acknowledged_checkpoint(self):
        (self.store.root / "value").write_text("first")
        original = self.store.checkpoint()
        (self.store.root / "value").write_text("second")
        self.objects.fail = True
        with self.assertRaises(Fenced):
            self.store.checkpoint()
        self.assertEqual(json.loads(self.objects.get("authority.json")[0])["checkpoint"], original)

    def test_rolling_revision_can_fence_an_active_writer_without_losing_acknowledged_state(self):
        (self.store.root / "value").write_text("acknowledged")
        original = self.store.checkpoint()
        replacement = Checkpoints(self.objects,self.path/"replacement",lambda:self.now[0],revision=1)
        self.assertEqual(replacement.acquire(takeover=True),original)
        replacement.restore(original)
        self.assertEqual((replacement.root/"value").read_text(),"acknowledged")
        with self.assertRaises(Fenced):
            self.store.publish()

    def test_retired_revision_cannot_restart_or_reclaim_after_expiry(self):
        replacement=Checkpoints(self.objects,self.path/"new",lambda:self.now[0],revision=2)
        replacement.acquire(takeover=True)
        self.now[0]+=100
        retired=Checkpoints(self.objects,self.path/"old",lambda:self.now[0],revision=1)
        with self.assertRaisesRegex(Fenced,"retired_revision"):
            retired.acquire(takeover=True)

    def test_same_revision_startup_respects_live_owner_lease(self):
        competing=Checkpoints(self.objects,self.path/"competing",lambda:self.now[0])
        with self.assertRaisesRegex(Fenced,"lease_active"):
            competing.acquire(takeover=True)

    def test_corrupt_chunks_are_rejected(self):
        (self.store.root / "value").write_text("first")
        checkpoint = self.store.checkpoint()
        key = "objects/" + digest(b"first")
        value, generation = self.objects.get(key)
        self.objects.values[key] = b"wrong", generation
        with self.assertRaisesRegex(Fenced, "checksum"):
            Checkpoints(self.objects, self.path / "restored").restore(checkpoint)

    def test_traversal_and_symlinks_are_rejected(self):
        for name in ["../escape", "/escape", "a/../../escape", "a\\escape"]:
            manifest = encoded({"format":1,"files":{name:{"chunks":[],"bytes":0,"sha256":digest(b"")}},
                                "directories":[],"bytes":0})
            checksum = self.store.immutable(manifest)
            destination = self.path / ("restore-" + digest(name.encode()))
            with self.assertRaises(Fenced):
                Checkpoints(self.objects, destination).restore(checksum)
        (self.store.root / "link").symlink_to(self.path)
        with self.assertRaisesRegex(Fenced, "symlink"):
            self.store.checkpoint()

    def test_identical_checkpoint_reuses_content_objects(self):
        (self.store.root / "value").write_bytes(b"x" * 800_000)
        self.store.checkpoint()
        count = len(self.objects.values)
        self.store.checkpoint()
        self.assertEqual(len(self.objects.values), count)


class AuthenticationTests(unittest.TestCase):
    def setUp(self):
        self.key = ec.generate_private_key(ec.SECP256R1())
        now = datetime.datetime.now(datetime.timezone.utc)
        self.now = int(now.timestamp())
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "device")])
        certificate = x509.CertificateBuilder().subject_name(subject).issuer_name(subject).public_key(
            self.key.public_key()).serial_number(1).not_valid_before(now-datetime.timedelta(minutes=5)).not_valid_after(
            now+datetime.timedelta(days=1)).sign(self.key, hashes.SHA256())
        self.certificate = certificate.public_bytes(serialization.Encoding.DER)
        self.identity = hashlib.sha256(self.certificate).hexdigest()
        self.acl = {"peers":{self.identity:{"device":"alice","project":"demo","role":"client","revoked":False}}}
        self.audience = "https://example.run.app"
        self.envelope = {"certificate":base64.b64encode(self.certificate).decode(),"method":"GET",
                         "path":"/v1/history","body":"","timestamp":self.now,"nonce":"a"*64}
        self.sign()

    def sign(self):
        e = self.envelope
        message = json.dumps(["wipstash-cloudrun-v1",self.audience,e["method"],e["path"],e["timestamp"],
                              e["nonce"],hashlib.sha256(base64.b64decode(e["body"])).hexdigest()],
                             separators=(",",":")).encode()
        e["signature"] = base64.b64encode(self.key.sign(message,ec.ECDSA(hashes.SHA256()))).decode()

    def test_valid_device_proof_is_bound_to_all_request_fields(self):
        self.assertEqual(authenticate(self.envelope,self.acl,self.audience,self.now)[0],self.identity)
        for field, value in [("path","/v1/audit"),("method","POST"),("body","eA=="),("nonce","b"*64),
                             ("timestamp",self.now+1)]:
            changed = dict(self.envelope, **{field:value})
            with self.assertRaises(Exception):
                authenticate(changed,self.acl,self.audience,self.now)
        with self.assertRaises(Exception):
            authenticate(self.envelope,self.acl,"https://other.run.app",self.now)

    def test_expired_revoked_unknown_and_unsupported_proofs_fail(self):
        with self.assertRaises(Exception):
            authenticate(self.envelope,self.acl,self.audience,self.now+121)
        with self.assertRaises(Exception):
            authenticate(self.envelope,{"peers":{}},self.audience,self.now)
        self.acl["peers"][self.identity]["revoked"] = True
        with self.assertRaises(Exception):
            authenticate(self.envelope,self.acl,self.audience,self.now)


class RpcTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.fixture = AuthenticationTests()
        self.fixture.setUp()
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()/"authority"
        self.root.mkdir()
        (self.root/"acl.json").write_text(json.dumps(self.fixture.acl))
        with sqlite3.connect(self.root/"nonces.sqlite") as db:
            db.execute("CREATE TABLE nonces(identity TEXT,nonce TEXT,created INTEGER,PRIMARY KEY(identity,nonce))")
        self.objects = Objects()
        self.store = Checkpoints(self.objects,self.root)
        self.store.acquire()
        self.patches = [
            patch.object(application,"ROOT",self.root),patch.object(application,"AUDIENCE",self.fixture.audience),
            patch.object(application,"store",self.store),patch.object(application,"ready",True),
            patch.object(application,"gate",asyncio.Lock()),
            patch.object(application,"process",AsyncMock(return_value={"ok":True,"body":"b2s=","content_type":"text/plain"}))
        ]
        for mock in self.patches:
            mock.start()
            self.addCleanup(mock.stop)
        self.http = httpx.AsyncClient(transport=httpx.ASGITransport(app=application.app),
                                     base_url="https://example.run.app")
        self.addAsyncCleanup(self.http.aclose)

    async def test_acknowledgement_has_durable_nonce_and_replay_is_rejected(self):
        response = await self.http.post("/rpc",json=self.fixture.envelope)
        self.assertEqual(response.status_code,200)
        self.assertEqual(response.content,b"ok")
        checkpoint = json.loads(self.objects.get("authority.json")[0])["checkpoint"]
        recovered = Checkpoints(self.objects,self.root.parent/"restored")
        recovered.restore(checkpoint)
        with sqlite3.connect(recovered.root/"nonces.sqlite") as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM nonces").fetchone()[0],1)
        self.assertEqual((await self.http.post("/rpc",json=self.fixture.envelope)).status_code,409)

    async def test_failed_persistence_never_acknowledges_and_fences_following_requests(self):
        self.store.checkpoint()
        original = self.store.record["checkpoint"]
        self.objects.fail = True
        response = await self.http.post("/rpc",json=self.fixture.envelope)
        self.assertEqual(response.status_code,503)
        self.assertFalse(application.ready)
        self.assertEqual(json.loads(self.objects.get("authority.json")[0])["checkpoint"],original)
        self.assertEqual((await self.http.post("/rpc",json=self.fixture.envelope)).status_code,503)

    async def test_unauthenticated_calls_do_not_dispatch_or_create_checkpoints(self):
        self.fixture.envelope["path"]="/v1/audit"
        response = await self.http.post("/rpc",json=self.fixture.envelope)
        self.assertEqual(response.status_code,403)
        application.process.assert_not_called()
        self.assertIsNone(self.store.record["checkpoint"])


if __name__ == "__main__":
    unittest.main()
