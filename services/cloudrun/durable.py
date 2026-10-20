"""Durable content-addressed checkpoints with a generation-fenced authority."""
import concurrent.futures
from collections import OrderedDict
from contextlib import closing
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import sqlite3
import tempfile
import threading
import time
import uuid

CHUNK = 256 * 1024
MAX_BYTES = 4 * 1024**3


class Fenced(RuntimeError):
    pass


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def digest(value):
    return hashlib.sha256(value).hexdigest()


class GcsObjects:
    def __init__(self, bucket):
        from google.cloud import storage
        self.bucket = storage.Client().bucket(bucket)

    def get(self, name):
        from google.api_core.exceptions import NotFound
        blob = self.bucket.blob(name)
        try:
            if name.startswith("objects/"):
                return blob.download_as_bytes(timeout=60), 0
            blob.reload(timeout=30)
            return blob.download_as_bytes(if_generation_match=blob.generation, timeout=60), int(blob.generation)
        except NotFound:
            return None, 0

    def put(self, name, value, generation):
        from google.api_core.exceptions import PreconditionFailed
        blob = self.bucket.blob(name)
        try:
            blob.upload_from_string(value, if_generation_match=generation, timeout=60)
            return int(blob.generation)
        except PreconditionFailed as error:
            raise Fenced("object_generation_changed") from error


class Checkpoints:
    def __init__(self, objects, root, clock=time.time, revision=0):
        self.objects, self.root, self.clock = objects, Path(root).resolve(), clock
        self.owner = uuid.uuid4().hex
        self.mutex = threading.RLock()
        self.generation = 0
        self.record = None
        self.failed = False
        self.known = set()
        self.revision = revision

    def acquire(self, takeover=False):
        with self.mutex:
            data, generation = self.objects.get("authority.json")
            record = json.loads(data) if data else {"format": 1, "checkpoint": None}
            minimum = record.get("minimum_revision",0)
            if self.revision < minimum:
                raise Fenced("retired_revision")
            if record.get("lease_until", 0) > self.clock() and (not takeover or self.revision == minimum):
                raise Fenced("authority_lease_active")
            record.update(owner=self.owner, lease_until=self.clock() + 90,minimum_revision=self.revision)
            self.generation = self.objects.put("authority.json", encoded(record), generation)
            self.record = record
            return record["checkpoint"]

    def publish(self, checkpoint=None):
        with self.mutex:
            if self.failed or self.record is None:
                raise Fenced("authority_unavailable")
            value = dict(self.record, lease_until=self.clock() + 90)
            if checkpoint is not None:
                value["checkpoint"] = checkpoint
            try:
                self.generation = self.objects.put("authority.json", encoded(value), self.generation)
                self.record = value
            except Exception:
                self.failed = True
                raise

    def immutable(self, value):
        checksum = digest(value)
        if checksum not in self.known:
            try:
                self.objects.put("objects/" + checksum, value, 0)
            except Fenced:
                existing, _ = self.objects.get("objects/" + checksum)
                if existing != value:
                    raise Fenced("immutable_object_mismatch")
            self.known.add(checksum)
        return checksum

    def checkpoint(self):
        # The caller excludes every authoritative mutation. Check evaluation only
        # reads immutable Git objects and writes disposable candidate directories.
        files, directories, total = {}, [], 0
        pending = {}
        with tempfile.TemporaryDirectory() as temporary:
            for directory, children, names in os.walk(self.root, followlinks=False):
                directory = Path(directory)
                children[:] = sorted(name for name in children if name != "candidates")
                relative = directory.relative_to(self.root).as_posix()
                if relative != ".":
                    directories.append(relative)
                for name in sorted(children + names):
                    if (directory / name).is_symlink():
                        raise Fenced("checkpoint_symlink")
                for name in sorted(names):
                    if name.endswith((".lock", "-wal", "-shm")) or name == "state-lock-owner.json":
                        continue
                    path = directory / name
                    source = path
                    if name.endswith(".sqlite"):
                        source = Path(temporary) / str(len(files))
                        with closing(sqlite3.connect(path)) as original, closing(sqlite3.connect(source)) as copy:
                            original.backup(copy)
                    parts, size, hasher = [], 0, hashlib.sha256()
                    with source.open("rb") as stream:
                        while block := stream.read(CHUNK):
                            size += len(block)
                            total += len(block)
                            if total > MAX_BYTES:
                                raise Fenced("checkpoint_too_large")
                            checksum = digest(block)
                            parts.append(checksum)
                            hasher.update(block)
                            if checksum not in self.known:
                                pending[checksum] = block
                    files[path.relative_to(self.root).as_posix()] = {
                        "chunks": parts, "bytes": size, "sha256": hasher.hexdigest(),
                        "executable": bool(path.stat().st_mode & 0o111)
                    }
            with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
                list(executor.map(self.immutable, pending.values()))
            manifest = encoded({"format": 1, "files": files, "directories": directories, "bytes": total})
            checkpoint = self.immutable(manifest)
            self.publish(checkpoint)
            return checkpoint

    def restore(self, checkpoint):
        if self.root.exists() and any(self.root.iterdir()):
            raise Fenced("restore_requires_empty_directory")
        self.root.mkdir(mode=0o700, parents=True, exist_ok=True)
        if not checkpoint:
            return
        cache=OrderedDict()
        def load(checksum):
            if len(checksum) != 64 or any(c not in "0123456789abcdef" for c in checksum):
                raise Fenced("invalid_object_hash")
            if checksum in cache:
                cache.move_to_end(checksum)
                return cache[checksum]
            value, _ = self.objects.get("objects/" + checksum)
            if value is None or digest(value) != checksum:
                raise Fenced("checkpoint_checksum_mismatch")
            self.known.add(checksum)
            if len(value)<=CHUNK:
                cache[checksum]=value
                if len(cache)>64:
                    cache.popitem(last=False)
            return value
        manifest = json.loads(load(checkpoint))
        if manifest["format"] != 1 or manifest["bytes"] > MAX_BYTES or len(manifest["files"]) > 200_000:
            raise Fenced("invalid_checkpoint_manifest")
        def target(name):
            path = PurePosixPath(name)
            if path.is_absolute() or not path.parts or any(part in (".", "..") for part in path.parts) or "\\" in name:
                raise Fenced("invalid_checkpoint_path")
            result = self.root.joinpath(*path.parts)
            if any(parent.is_symlink() for parent in [result, *result.parents]):
                raise Fenced("checkpoint_symlink")
            return result
        for name in manifest["directories"]:
            target(name).mkdir(mode=0o700, parents=True, exist_ok=True)
        total = 0
        for name, description in manifest["files"].items():
            path = target(name)
            path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            hasher, size = hashlib.sha256(), 0
            with path.open("xb") as stream:
                os.chmod(path, 0o700 if description.get("executable",False) else 0o600)
                for checksum in description["chunks"]:
                    value = load(checksum)
                    size += len(value)
                    total += len(value)
                    if total > MAX_BYTES:
                        raise Fenced("checkpoint_too_large")
                    hasher.update(value)
                    stream.write(value)
            if size != description["bytes"] or hasher.hexdigest() != description["sha256"]:
                raise Fenced("checkpoint_file_mismatch")
        if total != manifest["bytes"]:
            raise Fenced("checkpoint_size_mismatch")
