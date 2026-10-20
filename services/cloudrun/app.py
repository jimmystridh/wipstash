import asyncio
import base64
from contextlib import asynccontextmanager, closing, contextmanager
import datetime
import hashlib
import json
import os
import re
from pathlib import Path
import signal
import shutil
import sqlite3
import tempfile
import time

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse, Response
from durable import Checkpoints, Fenced, GcsObjects

ROOT = Path(os.environ.get("WIPSTASH_ROOT", "/srv/wipstash"))
ENGINE = os.environ.get("WIPSTASH_ENGINE", "/usr/local/bin/wipstash")
TRANSPORT = os.environ.get("WIPSTASH_TRANSPORT", "/usr/local/bin/wipstash-transport")
AUDIENCE = os.environ.get("WIPSTASH_AUDIENCE", "")
gate = asyncio.Lock()
store = None
ready = False


@contextmanager
def database(path):
    with closing(sqlite3.connect(path)) as db:
        with db:
            yield db


def decode(text, limit):
    if not isinstance(text, str) or len(text) > (limit * 4 // 3) + 8:
        raise ValueError("encoding_bound")
    value = base64.b64decode(text, validate=True)
    if len(value) > limit:
        raise ValueError("encoding_bound")
    return value


def authenticate(envelope, acl, audience, now):
    if set(envelope) != {"certificate", "method", "path", "timestamp", "nonce", "signature", "body"}:
        raise ValueError("request_fields")
    certificate = decode(envelope["certificate"], 8192)
    identity = hashlib.sha256(certificate).hexdigest()
    peer = acl["peers"].get(identity)
    if not peer or peer["revoked"] or peer["role"] != "client":
        raise ValueError("unknown_or_revoked_device")
    timestamp, nonce = envelope["timestamp"], envelope["nonce"]
    if type(timestamp) is not int or abs(now - timestamp) > 120:
        raise ValueError("request_expired")
    if not isinstance(nonce, str) or len(nonce) != 64 or any(c not in "0123456789abcdef" for c in nonce):
        raise ValueError("invalid_nonce")
    if envelope["method"] not in ("GET", "POST", "PUT") or not isinstance(envelope["path"], str) or len(envelope["path"]) > 512 or not envelope["path"].startswith("/v1/"):
        raise ValueError("invalid_route")
    body = decode(envelope["body"], 8 * 1024**2 + 16388)
    message = json.dumps(["wipstash-cloudrun-v1", audience, envelope["method"], envelope["path"],
                          timestamp, nonce, hashlib.sha256(body).hexdigest()],
                         separators=(",", ":"), ensure_ascii=False).encode()
    cert = x509.load_der_x509_certificate(certificate)
    current = datetime.datetime.fromtimestamp(now, datetime.timezone.utc)
    if not cert.not_valid_before_utc <= current <= cert.not_valid_after_utc:
        raise ValueError("certificate_expired")
    key = cert.public_key()
    if not isinstance(key, ec.EllipticCurvePublicKey) or not isinstance(key.curve, ec.SECP256R1):
        raise ValueError("unsupported_key")
    key.verify(decode(envelope["signature"], 80), message, ec.ECDSA(hashes.SHA256()))
    return identity, body


async def process(arguments, value, timeout=90):
    child = await asyncio.create_subprocess_exec(*arguments, stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE, start_new_session=True)
    try:
        output, errors = await asyncio.wait_for(child.communicate(json.dumps(value).encode() + b"\n"), timeout)
    except BaseException:
        try:
            os.killpg(child.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        await child.wait()
        raise
    if child.returncode or len(output) > 24 * 1024**2:
        raise RuntimeError("engine_process_failed:" + errors.decode(errors="replace")[-1024:])
    return json.loads(output)


async def engine(value, timeout=90, state=None):
    return await process([ENGINE, "--state", str(state or ROOT / "state"), "stdin"], value, timeout)


async def checkpoint():
    global ready
    try:
        return await asyncio.to_thread(store.checkpoint)
    except BaseException:
        ready = False
        store.failed = True
        raise


async def initialize():
    config = json.loads((ROOT / "bootstrap.json").read_text())
    if not (ROOT / "state/state.sqlite").exists():
        result = await engine({"op": "init", "source": str(ROOT / "source"),
                               "public_history": str(ROOT / "public.git")})
        if result.get("ok") is not True:
            raise RuntimeError("authority_initialization_failed:"+str(result.get("error",{}).get("code","unknown")))
        result = await engine({"op": "sync_initialize_authority", "operation_id": "cloud-authority-init",
            "project": config["project"], "authority": config["authority"], "epoch": 1, "device": config["device"]})
        if result.get("ok") is not True:
            raise RuntimeError("authority_binding_failed")
        for device in config["devices"]:
            result = await engine({"op": "sync_add_peer", "peer": device, "operation_id": "cloud-peer-" + device})
            if result.get("ok") is not True:
                raise RuntimeError("peer_registration_failed")
        result = await engine({"op": "configure", "operation_id": "cloud-checks", "policy": config["policy"]})
        if result.get("ok") is not True:
            raise RuntimeError("check_configuration_failed")
    (ROOT / "staging").mkdir(mode=0o700, exist_ok=True)
    with database(ROOT / "nonces.sqlite") as db:
        db.execute("CREATE TABLE IF NOT EXISTS nonces(identity TEXT,nonce TEXT,created INTEGER,PRIMARY KEY(identity,nonce))")


async def export_head():
    with tempfile.TemporaryDirectory(prefix="head-export-",dir=ROOT/"staging") as directory:
        result = await engine({"op": "sync_export_current_head", "destination": str(Path(directory)/"artifact")})
    if result.get("ok") is not True:
        raise RuntimeError("head_export_failed")


async def validate_loop():
    global ready
    while ready:
        try:
            async with gate:
                if not ready:
                    return
                with database(ROOT / "state/state.sqlite") as db:
                    pending = db.execute("""SELECT EXISTS(SELECT 1 FROM validation_jobs WHERE state IN ('queued','running')
                        OR (state='failed' AND attempt<3 AND finished<? AND (json_extract(evidence,'$.failure_kind')='infrastructure'
                        OR EXISTS(SELECT 1 FROM json_each(validation_jobs.evidence,'$.checks') WHERE json_extract(value,'$.reason')='evaluation_budget_exhausted'))))""",
                        (int(time.time()*1000)-10000,)).fetchone()[0]
                claim = await engine({"op": "validation_claim"}) if pending else {}
                if claim.get("job_id"):
                    await checkpoint()
                    evaluation = tempfile.TemporaryDirectory(prefix="check-",dir=ROOT.parent)
                    await asyncio.to_thread(shutil.copytree,ROOT/"state/coordinator.git",Path(evaluation.name)/"coordinator.git")
            if claim.get("job_id"):
                try:
                    details = await engine({"op": "validation_evaluate", "claim": claim}, timeout=660,state=Path(evaluation.name))
                except Exception:
                    details = {"head":claim["head"],"proposal":claim["head"],"candidate_tree":claim["candidate_tree"],
                               "policy_sha256":claim["policy_sha256"],"policy":claim["policy"],"checks":[],
                               "failure_kind":"infrastructure","evaluation_error":"check_process_interrupted"}
                finally:
                    evaluation.cleanup()
                async with gate:
                    if not ready:
                        return
                    result = await engine({"op": "validation_complete", "job_id": claim["job_id"],
                                           "token": claim["token"], "details": details})
                    if result.get("ok") is not True:
                        raise RuntimeError("validation_completion_failed")
                    await checkpoint()
        except asyncio.CancelledError:
            raise
        except Exception as error:
            print(json.dumps({"event": "validation_error", "error": str(error)[:300]}), flush=True)
        await asyncio.sleep(1)


async def renew_loop():
    global ready
    while ready:
        await asyncio.sleep(15)
        try:
            await asyncio.to_thread(store.publish)
        except Exception:
            ready = False
            return


@asynccontextmanager
async def lifespan(app):
    global store, ready
    os.umask(0o077)
    revision_name=os.environ.get("K_REVISION","")
    revision=re.search(r"-(\d+)-[^-]+$",revision_name)
    if not revision:
        raise RuntimeError("automatically_numbered_cloud_run_revision_required")
    store = Checkpoints(GcsObjects(os.environ["WIPSTASH_BUCKET"]), ROOT,revision=int(revision[1]))
    for attempt in range(36):
        try:
            saved = await asyncio.to_thread(store.acquire, takeover=True)
            break
        except Fenced as error:
            if str(error) != "authority_lease_active" or attempt == 35:
                raise
            await asyncio.sleep(3)
    await asyncio.to_thread(store.restore, saved)
    await initialize()
    await export_head()
    await checkpoint()
    ready = True
    tasks = [asyncio.create_task(validate_loop()), asyncio.create_task(renew_loop())]
    try:
        yield
    finally:
        ready = False
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        # Lease expiry fences unclean exits too. No checkpoint is needed for
        # acknowledged requests: each reply was already durably published.
        if not store.failed:
            with store.mutex:
                store.record["lease_until"] = 0
                try:
                    store.generation = store.objects.put("authority.json",
                        json.dumps(store.record).encode(), store.generation)
                except Exception:
                    pass


app = FastAPI(lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)


@app.get("/health")
async def health():
    return JSONResponse({"ok": ready and not store.failed}, status_code=200 if ready and not store.failed else 503)


@app.post("/rpc")
async def rpc(request: Request):
    global ready
    started = time.monotonic()
    if not ready:
        raise HTTPException(503, "authority_unavailable")
    data = bytearray()
    async for block in request.stream():
        data.extend(block)
        if len(data) > 12 * 1024**2:
            raise HTTPException(413, "request_bound")
    try:
        envelope = json.loads(data)
        acl = json.loads((ROOT / "acl.json").read_text())
        identity, body = authenticate(envelope, acl, AUDIENCE, int(time.time()))
    except Exception:
        print(json.dumps({"event":"authentication_rejected"}),flush=True)
        raise HTTPException(403, "request_authentication_failed") from None
    async with gate:
        queue_ms = round((time.monotonic()-started)*1000)
        if not ready:
            raise HTTPException(503, "authority_unavailable")
        try:
            with database(ROOT / "nonces.sqlite") as db:
                db.execute("DELETE FROM nonces WHERE created < ?", (int(time.time()) - 300,))
                count = db.execute("SELECT COUNT(*) FROM nonces WHERE identity=? AND created>=?",
                                   (identity, int(time.time()) - 60)).fetchone()[0]
                if count >= 120:
                    raise HTTPException(429, "rate_limited", headers={"Retry-After": "1"})
                db.execute("INSERT INTO nonces VALUES(?,?,?)", (identity, envelope["nonce"], int(time.time())))
        except sqlite3.IntegrityError:
            raise HTTPException(409, "request_replayed") from None
        try:
            phase = time.monotonic()
            result = await process([TRANSPORT, "cloud-route", str(ROOT / "service.json")], envelope)
            route_ms = round((time.monotonic()-phase)*1000)
            phase = time.monotonic()
            if envelope["method"] in ("POST", "PUT") and envelope["path"] != "/v1/history":
                integrated = await engine({"op": "integrate", "max_proposals": 4})
                if integrated.get("ok") is not True:
                    raise RuntimeError("integration_failed")
                await export_head()
            promotion_ms = round((time.monotonic()-phase)*1000)
            phase = time.monotonic()
            await checkpoint()
            checkpoint_ms = round((time.monotonic()-phase)*1000)
        except BaseException as error:
            ready = False
            store.failed = True
            print(json.dumps({"event":"durability_unconfirmed","failure_type":type(error).__name__}),flush=True)
            raise HTTPException(503, "durability_unconfirmed_retry_same_operation") from None
    print(json.dumps({"event":"rpc", "path":envelope["path"], "identity":identity,
                      "elapsed_ms":round((time.monotonic()-started)*1000),
                      "queue_ms":queue_ms,"route_ms":route_ms,"promotion_ms":promotion_ms,"checkpoint_ms":checkpoint_ms,
                      "checkpoint":store.record["checkpoint"]}), flush=True)
    if not result["ok"]:
        return JSONResponse({"ok":False,"error":result["error"]},status_code=400)
    return Response(base64.b64decode(result["body"]), media_type=result["content_type"])
