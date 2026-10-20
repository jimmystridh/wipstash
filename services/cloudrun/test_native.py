"""Real engine/transport acceptance; requires locally built release binaries."""
import asyncio
import base64
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

import httpx
import app
from durable import Checkpoints
from test_cloudrun import AuthenticationTests, Objects

REPO = Path(__file__).resolve().parent.parent.parent
ENGINE = REPO/"target/release/wipstash"
TRANSPORT = REPO/"services/transport/target/release/wipstash-transport"


@unittest.skipUnless(ENGINE.exists() and TRANSPORT.exists(), "Build native release binaries first")
class NativeGatewayTests(unittest.IsolatedAsyncioTestCase):
    async def test_preserved_history_and_foreground_rpc_during_real_background_check(self):
        temporary = tempfile.TemporaryDirectory(dir="/private/tmp" if sys.platform=="darwin" else None)
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name).resolve()
        source = root/"source"
        source.mkdir()
        (source/"hello.txt").write_text("first\n")
        def run(state, request):
            result = subprocess.run([str(ENGINE),"--state",str(state),"stdin"],
                input=json.dumps(request)+"\n",capture_output=True,text=True,check=True)
            reply = json.loads(result.stdout)
            self.assertNotEqual(reply.get("ok"),False,reply)
            return reply
        original = root/"original"
        run(original,{"op":"init","source":str(source)})
        workspace = root/"workspace"
        run(original,{"op":"clone","workspace":"writer","path":str(workspace),"operation_id":"clone"})
        (workspace/"hello.txt").write_text("second\n")
        shared = run(original,{"op":"commit","workspace":"writer","expected_generation":0,
                             "message":"test: preserve public history","operation_id":"fixture-commit"})
        self.assertTrue(shared["shared"],shared)
        public = root/"public.git"
        subprocess.run(["git","init","--bare","--template=",str(public)],check=True,capture_output=True)
        run(original,{"op":"backup_flush","destination":str(public),"operation_id":"fixture-backup"})
        server = root/"server"
        server.mkdir()
        shutil.copytree(public,server/"public.git")
        shutil.copytree(workspace,server/"source")
        fixture = AuthenticationTests()
        fixture.setUp()
        (server/"acl.json").write_text(json.dumps(fixture.acl))
        (server/"bootstrap.json").write_text(json.dumps({
            "project":"demo","authority":"cloud-authority","device":"central","devices":["alice"],
            "policy":{"checks":[{"id":"slow","argv":[sys.executable,"-B","-c","import time; time.sleep(3); print('passed')"],
                                "preset":"python","required":True,"timeout_seconds":10}]}
        }))
        (server/"service.json").write_text(json.dumps({
            "engine":str(ENGINE),"state":str(server/"state"),"staging":str(server/"staging"),
            "project":"demo","authority":"cloud-authority","epoch":1,"device":"central",
            "acl":str(server/"acl.json"),"ca":str(server/"unused-ca"),"certificate":str(server/"unused-certificate"),
            "key":str(server/"unused-key"),"listen":"127.0.0.1:7443"
        }))
        store = Checkpoints(Objects(),server)
        store.acquire()
        with (
            patch.object(app,"ROOT",server),patch.object(app,"ENGINE",str(ENGINE)),
            patch.object(app,"TRANSPORT",str(TRANSPORT)),patch.object(app,"AUDIENCE",fixture.audience),
            patch.object(app,"store",store),patch.object(app,"gate",asyncio.Lock()),patch.object(app,"ready",True)
        ):
            await app.initialize()
            await app.export_head()
            status = await app.engine({"op":"status"})
            expected = subprocess.check_output(["git","--git-dir",str(public),"rev-parse","refs/heads/wipstash/integration"],text=True).strip()
            actual = subprocess.check_output(["git","--git-dir",str(server/"state/coordinator.git"),"rev-parse","refs/wipstash/integration"],text=True).strip()
            self.assertEqual(actual,expected)
            validator = asyncio.create_task(app.validate_loop())
            try:
                for _ in range(100):
                    with app.database(server/"state/state.sqlite") as db:
                        running = db.execute("SELECT COUNT(*) FROM validation_jobs WHERE state='running'").fetchone()[0]
                    if running:
                        break
                    await asyncio.sleep(0.05)
                self.assertTrue(running)
                started = time.monotonic()
                async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app.app),base_url=fixture.audience) as client:
                    response = await client.post("/rpc",json=fixture.envelope)
                elapsed = time.monotonic()-started
                self.assertEqual(response.status_code,200,response.text)
                self.assertLess(elapsed,1.5,"Foreground RPC waited for the three-second check")
                for _ in range(200):
                    observed = await app.engine({"op":"validation_status","head":expected})
                    if observed.get("release_ready"):
                        break
                    await asyncio.sleep(0.05)
                self.assertTrue(observed.get("release_ready"),observed)
                print(json.dumps({"native_gateway":True,"history_preserved":expected,
                                  "rpc_during_three_second_check_ms":round(elapsed*1000),"release_ready":True}))
            finally:
                app.ready = False
                validator.cancel()
                await asyncio.gather(validator,return_exceptions=True)


if __name__=="__main__":
    unittest.main()
