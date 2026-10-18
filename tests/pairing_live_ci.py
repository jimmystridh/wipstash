#!/usr/bin/env python3
"""Native CI only: disposable, real-process guided-pairing acceptance test.

Build both executables first, then on a native GitHub Actions runner:
  WIPSTASH_PAIRING_LIVE_CI=1 python tests/pairing_live_ci.py \
    --binary target/debug/wipstash --transport services/transport/target/debug/wipstash-transport \
    --artifacts evidence/pairing-live
Windows accepts the corresponding .exe paths. GITHUB_ACTIONS must also equal
true. Never upload the temporary tree: only summary.json and safe-stderr.txt
are artifacts. This script intentionally never executes on a developer machine.
"""
import argparse
import hashlib
import json
import contextlib
import os
from pathlib import Path
import signal
import socket
import sqlite3
import ssl
import subprocess
import sys
import tempfile
import threading
import time


class Failure(Exception):
    pass


class BindRace(Failure):
    pass


def require(condition, code):
    if not condition:
        raise Failure(code)


def guard():
    require(os.environ.get("GITHUB_ACTIONS") == "true"
            and os.environ.get("WIPSTASH_PAIRING_LIVE_CI") == "1",
            "native_ci_opt_in_required")


# Exact diagnostic allowlist. Never persist raw output, arguments, paths, keys,
# invitation bodies, fingerprints, or unexpected exception text.
SAFE_CODES = (
    "connectivity_remote_rejected", "connectivity_authority_pin_mismatch",
    "connectivity_unverified", "connectivity_timeout", "enrollment_denied",
    "join_incomplete", "join_recovery_incomplete", "enrollment_rejected",
    "remote_rejected", "private_object_requires_current_owner_and_0700_or_0600",
    "writable_private_path_ancestor", "untrusted_private_path_ancestor_owner",
    "transport_worker_already_running", "device_generation_conflict",
    "Address already in use", "address already in use", "AddrInUse",
    "10048", "invitation_expired_before_join", "existing_profile_conflicts",
)


class Runner:
    def __init__(self, args):
        self.engine = Path(args.binary).resolve()
        self.transport = Path(args.transport).resolve()
        self.deadline = time.monotonic() + args.timeout
        self.steps = []
        self.diagnostics = []
        self.children = []
        self.env = dict(os.environ, GIT_CONFIG_NOSYSTEM="1", GIT_TERMINAL_PROMPT="0",
                        GIT_AUTHOR_NAME="Pairing CI", GIT_AUTHOR_EMAIL="pairing@example.invalid",
                        GIT_COMMITTER_NAME="Pairing CI", GIT_COMMITTER_EMAIL="pairing@example.invalid")
        # Ignore developer/user Git configuration, including signing/hooks.
        self.env["GIT_CONFIG_GLOBAL"] = os.devnull
        self.env["RUST_BACKTRACE"] = "0"

    def remaining(self, limit=35):
        left = self.deadline - time.monotonic()
        require(left > 0, "suite_deadline_exceeded")
        return min(limit, left)

    def record_stderr(self, label, data):
        text = data.decode("utf-8", "replace") if isinstance(data, bytes) else data
        codes = sorted({code for code in SAFE_CODES if code in text})
        if text:
            self.diagnostics.append(label + ": " + (", ".join(codes) or "[stderr redacted]"))

    def spawn(self, argv, **kwargs):
        guard()  # Also gate every actual process start, not merely main().
        self.remaining()
        options = {"start_new_session": True} if os.name != "nt" else {
            "creationflags": subprocess.CREATE_NEW_PROCESS_GROUP}
        proc = subprocess.Popen([str(x) for x in argv], env=self.env,
                                stdin=subprocess.DEVNULL, **options, **kwargs)
        self.children.append(proc)
        return proc

    def stop(self, proc):
        if proc.poll() is None:
            try:
                # Graceful signal is scoped to this owned process group. In
                # particular, never taskkill /IM or killall other executables.
                if os.name == "nt":
                    proc.send_signal(signal.CTRL_BREAK_EVENT)
                else:
                    os.killpg(proc.pid, signal.SIGTERM)
                proc.wait(timeout=5)
            except (OSError, subprocess.TimeoutExpired):
                if proc.poll() is None:
                    if os.name == "nt":
                        proc.kill()
                    else:
                        os.killpg(proc.pid, signal.SIGKILL)
                    proc.wait(timeout=5)
        if proc in self.children:
            self.children.remove(proc)

    def command(self, label, argv, expected=True):
        proc = self.spawn(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            out, err = proc.communicate(timeout=self.remaining())
        except subprocess.TimeoutExpired:
            self.stop(proc)
            raise Failure(label + "_timeout") from None
        finally:
            if proc.poll() is not None and proc in self.children:
                self.children.remove(proc)
        self.record_stderr(label, err)
        require((proc.returncode == 0) == expected, label + "_unexpected_exit")
        return out.decode("utf-8", "replace"), err.decode("utf-8", "replace")

    def cli(self, label, *args, expected=True):
        return self.command(label, [self.transport, *args], expected)

    def engine_request(self, state, op):
        out, _ = self.command("engine_" + op, [self.engine, "--state", state,
                                                   json.dumps({"op": op})])
        value = json.loads(out)
        require(value.get("ok") is True, "engine_request_failed")
        return value

    def start_server(self, authority, ports):
        proc = self.spawn([self.transport, "serve", "--directory", authority],
                          stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        # Drain continuously; keep only a bounded tail in memory, never a raw log.
        tail = bytearray()
        def drain():
            while True:
                block = proc.stderr.read(1024)
                if not block:
                    break
                tail.extend(block)
                del tail[:-8192]
        reader = threading.Thread(target=drain, daemon=True)
        reader.start()
        end = time.monotonic() + self.remaining(15)
        while time.monotonic() < end:
            if proc.poll() is not None:
                reader.join(timeout=1)
                self.record_stderr("serve", bytes(tail))
                self.stop(proc)
                if any(code.encode() in tail for code in
                       ("Address already in use", "address already in use", "AddrInUse", "10048")):
                    raise BindRace("loopback_bind_race")
                raise Failure("serve_exited_before_ready")
            ready = True
            for port in ports:
                try:
                    with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                        pass
                except OSError:
                    ready = False
            if ready and proc.poll() is None:
                return proc, reader, tail
            time.sleep(0.1)
        self.stop(proc)
        reader.join(timeout=1)
        self.record_stderr("serve", bytes(tail))
        raise Failure("serve_readiness_timeout")

    def stop_server(self, server):
        proc, reader, tail = server
        self.stop(proc)
        reader.join(timeout=2)
        self.record_stderr("serve", bytes(tail))
        require(not reader.is_alive(), "serve_stderr_drain_timeout")
        proc.stderr.close()

    def doctor(self, profile):
        out, _ = self.cli("doctor_online", "doctor", "--directory", profile,
                          "--online")
        require("Authenticated read-only connectivity verified now" in out,
                "doctor_missing_live_confirmation")

    def denied_doctor(self, profile, authority, healthy_profile):
        # The service rejects unauthorized certificates immediately after TLS,
        # before HTTP. Its intentional close can map to connectivity_unverified.
        # Establish the exact certificate's authoritative denial state and use
        # fresh healthy requests on both sides; failure alone proves nothing.
        self.doctor(healthy_profile)
        certificate = ssl.PEM_cert_to_DER_cert(
            (profile / "client.pem").read_text(encoding="ascii"))
        fingerprint = hashlib.sha256(certificate).hexdigest()
        with contextlib.closing(sqlite3.connect(
                (authority / "pairing.sqlite").as_uri() + "?mode=ro", uri=True,
                timeout=self.remaining(5))) as db, db:
            row = db.execute(
                "SELECT c.revoked,c.generation,c.not_after,d.state,d.generation "
                "FROM certificates c JOIN devices d ON d.device=c.device "
                "WHERE c.fingerprint=?", (fingerprint,)).fetchone()
        require(row is not None, "denied_certificate_missing_from_authority")
        revoked, generation, not_after, device_state, active_generation = row
        require(not_after > int(time.time()), "negative_certificate_expired")
        require(revoked == 1 or generation < active_generation,
                "certificate_not_revoked_or_superseded")
        require(device_state == "revoked" or
                (device_state == "active" and generation < active_generation),
                "device_state_does_not_deny_certificate")
        _, err = self.cli("doctor_online_denied", "doctor", "--directory", profile,
                          "--online", expected=False)
        require("connectivity_timeout" not in err and
                "connectivity_authority_pin_mismatch" not in err and
                ("connectivity_remote_rejected" in err or "connectivity_unverified" in err),
                "denial_not_expected_close_or_rejection")
        self.doctor(healthy_profile)

    def snapshot(self, state):
        status = self.engine_request(state, "sync_status")
        plain = self.engine_request(state, "status")
        with contextlib.closing(sqlite3.connect((state / "state.sqlite").as_uri() + "?mode=ro", uri=True,
                             timeout=self.remaining(5))) as db, db:
            counts = {name: db.execute("SELECT count(*) FROM " + name).fetchone()[0]
                      for name in ("workspaces", "checkpoints", "proposals", "promotions")}
        require(all(count == 0 for count in counts.values()), "unexpected_source_side_effect")
        return {"head": status["head"], "cursor": status["cursor"],
                "config": status["config"], "workspaces": plain["workspaces"], "counts": counts}

    def audit_public_objects(self, state, markers):
        repo = state / "coordinator.git"
        listing, _ = self.command("git_object_inventory", ["git", "--git-dir", repo,
            "cat-file", "--batch-all-objects", "--batch-check=%(objectname)"])
        for oid in listing.splitlines():
            require(len(oid) in (40, 64) and all(c in "0123456789abcdef" for c in oid),
                    "invalid_object_inventory")
            body, _ = self.command("git_object_privacy", ["git", "--git-dir", repo,
                                                         "cat-file", "-p", oid])
            require(not any(marker in body for marker in markers), "private_marker_in_public_store")

    def exercise(self, root):
        source = root / "source"
        source.mkdir(mode=0o700)
        (source / "hello.txt").write_text("synthetic public seed\n", encoding="utf-8")
        markers = ["PAIRING_CI_PRIVATE_ENV_" + os.urandom(16).hex(),
                   "PAIRING_CI_PRIVATE_AGENT_" + os.urandom(16).hex()]
        (source / ".env").write_text(markers[0], encoding="utf-8")
        (source / ".agent").mkdir()
        (source / ".agent" / "session.txt").write_text(markers[1], encoding="utf-8")
        before_source = {str(p.relative_to(source)): hashlib.sha256(p.read_bytes()).hexdigest()
                         for p in source.rglob("*") if p.is_file()}
        authority, state = root / "authority", root / "authority-state"
        # Reserve both ports simultaneously. The CLI cannot inherit sockets, so
        # release immediately before serve; main retries a fresh disposable
        # fixture on a positively identified address-in-use race only.
        reservations = []
        try:
            guard()
            for _ in range(2):
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                reservations.append(sock)
                if os.name == "nt":
                    sock.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
                sock.bind(("127.0.0.1", 0))
            ports = [sock.getsockname()[1] for sock in reservations]
            self.cli("setup", "setup", "--directory", authority, "--state", state,
                     "--engine", self.engine, "--source", source, "--project", "pairing-ci",
                     "--authority", "central", "--device", "central-device",
                     "--server-name", "localhost", "--enrollment-address", f"127.0.0.1:{ports[0]}",
                     "--sync-address", f"127.0.0.1:{ports[1]}")
        finally:
            for sock in reservations:
                sock.close()
        server = self.start_server(authority, ports)
        self.steps.append("setup_explicit_source_and_serve")
        try:
            authority_head = self.snapshot(state)["head"]
            require(authority_head is not None, "missing_authority_initial_head")
            profiles, states, snapshots = {}, {}, {}
            for name in ("alpha", "bravo", "charlie", "delta"):
                invite = authority / (name + ".invite")
                self.cli("invite", "device", "invite", "--directory", authority,
                         "--device", name, "--out", invite)
                profiles[name], states[name] = root / name, root / (name + "-state")
                self.cli("join", "join", "--directory", profiles[name], "--state", states[name],
                         "--engine", self.engine, "--invite-file", invite)
                self.doctor(profiles[name])
                snapshots[name] = self.snapshot(states[name])
                require(snapshots[name]["head"] is None, "join_implicitly_downloaded_head")
                require(snapshots[name]["config"]["device"] == name, "wrong_client_binding")
            listing, _ = self.cli("list", "device", "list", "--directory", authority)
            for name in profiles:
                require(f"{name}\tactive\tgeneration 1" in listing, "missing_active_device")
            self.steps.append("four_independent_invite_join_online_doctor_and_list")

            # Cancel a pending replacement, preserving the active certificate.
            canceled = authority / "charlie-canceled.invite"
            self.cli("rotate_pending", "device", "rotate", "--directory", authority,
                     "--device", "charlie", "--generation", "1", "--out", canceled)
            self.cli("cancel_invite", "device", "cancel-invite", "--directory", authority,
                     "--device", "charlie")
            _, err = self.cli("canceled_join", "join", "--directory", root / "canceled-profile",
                             "--state", states["charlie"], "--engine", self.engine,
                             "--invite-file", canceled, expected=False)
            # The CLI deliberately masks enrollment errors as join_incomplete.
            # Corroborate with the authority's read-only record and absence of
            # installed credentials, rather than calling a network outage a
            # successful negative test.
            require("join_incomplete" in err or "join_recovery_incomplete" in err,
                    "canceled_invite_unexpected_error")
            require(not (root / "canceled-profile" / "client.pem").exists(),
                    "canceled_invite_installed_certificate")
            with contextlib.closing(sqlite3.connect((authority / "pairing.sqlite").as_uri() + "?mode=ro",
                                 uri=True, timeout=self.remaining(5))) as db, db:
                require(db.execute("SELECT count(*) FROM invites WHERE device='charlie' "
                                   "AND state='cancelled' AND response IS NULL").fetchone()[0] == 1,
                        "canceled_invite_not_persisted")
                require(db.execute("SELECT count(*) FROM certificates WHERE device='charlie'")
                        .fetchone()[0] == 1, "canceled_invite_issued_certificate")
            self.doctor(profiles["charlie"])
            self.steps.append("canceled_invite_denied_active_certificate_preserved")

            self.cli("revoke", "device", "revoke", "--directory", authority, "--device", "alpha")
            self.denied_doctor(profiles["alpha"], authority, profiles["bravo"])
            for name in ("bravo", "charlie", "delta"):
                self.doctor(profiles[name])
            self.steps.append("revoked_client_denied_other_three_accepted")

            replacement = authority / "charlie-reissued.invite"
            self.cli("reissue", "device", "rotate", "--directory", authority,
                     "--device", "charlie", "--generation", "1", "--out", replacement)
            rotated = root / "charlie-generation-2"
            self.cli("replacement_join", "join", "--directory", rotated, "--state", states["charlie"],
                     "--engine", self.engine, "--invite-file", replacement)
            self.denied_doctor(profiles["charlie"], authority, profiles["bravo"])
            self.doctor(rotated)
            require(self.snapshot(states["charlie"]) == snapshots["charlie"],
                    "rotation_changed_engine_identity_or_source_state")
            listing, _ = self.cli("list_rotated", "device", "list", "--directory", authority)
            require("charlie\tactive\tgeneration 2" in listing, "rotation_generation_not_advanced")
            require("alpha\trevoked\tgeneration 1" in listing, "revocation_not_recorded")
            self.steps.append("rotation_same_engine_old_certificate_denied_new_accepted")

            self.stop_server(server)
            server = None
            # Rebind only these persisted endpoints. Retry a short-lived bind
            # race without changing existing invitations or authority identity.
            for attempt in range(3):
                try:
                    server = self.start_server(authority, ports)
                    break
                except BindRace:
                    if attempt == 2:
                        raise Failure("restart_bind_race_exhausted") from None
                    time.sleep(min(1, self.remaining()))
            for profile in (profiles["bravo"], profiles["delta"], rotated):
                self.doctor(profile)
            self.denied_doctor(profiles["alpha"], authority, profiles["bravo"])
            self.denied_doctor(profiles["charlie"], authority, profiles["bravo"])
            self.steps.append("owned_server_restart_persists_acceptance_and_revocation")
            for name in profiles:
                require(self.snapshot(states[name]) == snapshots[name], "pairing_changed_client_source_state")
            require(self.snapshot(state)["head"] == authority_head, "pairing_changed_authority_head")
            self.audit_public_objects(state, markers)
            after_source = {str(p.relative_to(source)): hashlib.sha256(p.read_bytes()).hexdigest()
                            for p in source.rglob("*") if p.is_file()}
            require(after_source == before_source, "source_files_mutated")
            self.steps.append("no_publication_adoption_or_private_marker_leak")
        finally:
            if server is not None:
                self.stop_server(server)


def main():
    try:
        guard()
    except Failure:
        print("SKIP: requires GITHUB_ACTIONS=true and WIPSTASH_PAIRING_LIVE_CI=1")
        return 2
    parser = argparse.ArgumentParser(description=__doc__)
    suffix = ".exe" if os.name == "nt" else ""
    parser.add_argument("--binary", default="target/debug/wipstash" + suffix)
    parser.add_argument("--transport", default="services/transport/target/debug/wipstash-transport" + suffix)
    parser.add_argument("--artifacts", default="evidence/pairing-live")
    parser.add_argument("--timeout", type=int, default=360)
    args = parser.parse_args()
    require(60 <= args.timeout <= 900, "timeout_must_be_60_to_900_seconds")
    runner = Runner(args)
    artifact_dir = Path(args.artifacts).resolve()
    artifact_dir.mkdir(parents=True, exist_ok=True)
    started, result, failure = time.monotonic(), "failed", None
    try:
        require(runner.engine.is_file() and runner.transport.is_file(), "native_binaries_missing")
        for attempt in range(3):
            try:
                with tempfile.TemporaryDirectory(prefix="wipstash-pairing-ci-") as temp:
                    # resolve() removes platform temp-dir symlinks before the
                    # production no-symlink private-path validator sees them.
                    runner.exercise(Path(temp).resolve())
                break
            except BindRace:
                if attempt == 2:
                    raise Failure("initial_bind_race_exhausted") from None
                runner.steps.clear()
        result = "passed"
    except Failure as exc:
        failure = str(exc)  # All Failure messages above are fixed safe labels.
    except Exception:
        failure = "unexpected_exception_details_redacted"
    finally:
        for proc in list(runner.children):
            try:
                runner.stop(proc)
            except Exception:
                result, failure = "failed", "owned_child_cleanup_failed"
        summary = {"result": result, "platform": sys.platform, "failure": failure,
                   "elapsed_seconds": round(time.monotonic() - started, 2),
                   "checks": runner.steps, "synthetic_credentials_only": True,
                   "local_execution_supported": False}
        (artifact_dir / "summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
        (artifact_dir / "safe-stderr.txt").write_text("\n".join(runner.diagnostics)[-8192:] + "\n", encoding="utf-8")
    print("pairing-live-ci: " + result + (" (" + failure + ")" if failure else ""))
    return 0 if result == "passed" else 1


if __name__ == "__main__":
    sys.exit(main())
