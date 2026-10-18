"""Small, serialized stdio MCP client with a durable mutation receipt journal.

Uses only the Python standard library and Wipstash's native private-file journal
subprocess on Linux, macOS and Windows. journal_command explicitly selects a
backend executable when the engine is launched through a wrapper. Windows does
not promise directory-entry power-loss durability.
Unsupported backends fail closed. Read-only sessions need no journal backend.
This is not a native Codex/Claude client or proof of filesystem durability.

Keep the journal outside source/workspace trees: it contains exact requests and
results, which may be private. Give each engine/state endpoint its own journal.
No operation is implicitly published, integrated, adopted, or replayed. A timed
out server is disconnected, never killed; its operation/writers may still run.
"""

from __future__ import annotations

import contextlib
import json
import math
import os
import queue
import re
import shutil
import subprocess
import threading
import time
import uuid


PROTOCOL_VERSION = "2025-11-25"
MAX_REQUEST_BYTES = 1024 * 1024
MAX_RESPONSE_BYTES = 8 * 1024 * 1024
MAX_JOURNAL_FRAME = 10 * 1024 * 1024
IDENTIFIER = re.compile(r"[A-Za-z0-9_-]{1,100}\Z")
# Only operations the engine itself journals can enter the durable API.
MUTATIONS = frozenset({
    "open", "checkpoint", "publish", "adopt", "cancel", "command_run",
    "command_recover", "configure", "resolve_adoption", "resolution_open",
    "resolution_submit", "backup_flush", "retry_proposal",
    "sync_initialize_authority", "sync_add_peer",
})
READS = frozenset({
    "status", "updates", "proposal_status", "operation_status", "events",
    "resolution_tasks", "backup_status", "sync_status", "recovery_status",
    "sync_export_history", "sync_export_lookup", "sync_pending",
})
PROPOSAL_OUTCOMES = frozenset({
    "integrated", "already_included", "quarantined", "cancelled", "superseded",
    "recovery_quarantined",
})


class ClientError(Exception):
    """Client safety, transport or protocol failure."""


class TransportError(ClientError):
    """No trustworthy reply was received; an operation may still have run."""


class ProtocolError(TransportError):
    pass


class JournalError(ClientError):
    pass


class IdempotencyMismatch(JournalError):
    pass


class UncertainOperation(ClientError):
    def __init__(self, operation_id, status=None):
        self.operation_id = operation_id
        self.status = status
        super().__init__(
            f"Operation {operation_id!r} is unresolved; reconcile the same ID. "
            "Do not rerun an uncertain command or invent a replacement ID."
        )


class ProposalTimeout(TimeoutError):
    def __init__(self, proposal, last_status):
        self.proposal = proposal
        self.last_status = last_status
        super().__init__(f"Deadline reached while waiting for proposal {proposal!r}")


def _json(value):
    """Canonical JSON preserves request values, including integer/float types."""
    def validate(v):
        if isinstance(v, dict):
            if any(not isinstance(k, str) for k in v):
                raise ValueError("JSON object keys must be strings")
            for child in v.values():
                validate(child)
        elif isinstance(v, list):
            for child in v:
                validate(child)
        elif v is not None and not isinstance(v, (str, bool, int, float)):
            raise ValueError("Request must contain JSON values only")
    validate(value)
    return json.dumps(value, ensure_ascii=False, allow_nan=False,
                      sort_keys=True, separators=(",", ":"))


def _seconds(value):
    value = float(value)
    if not math.isfinite(value) or value <= 0:
        raise ValueError("Timeout and backoff values must be positive and finite")
    return value


class _StdioSession:
    """One IO worker bounds waits even if a server stops reading or replying."""

    def __init__(self, command, cwd, *, request_limit=MAX_REQUEST_BYTES,
                 response_limit=MAX_RESPONSE_BYTES):
        self.process = subprocess.Popen(command, cwd=cwd, stdin=subprocess.PIPE,
                                        stdout=subprocess.PIPE, stderr=None, bufsize=0)
        self.requests = queue.Queue()
        self.replies = queue.Queue()
        self.serial = 0
        self.closed = False
        self.request_limit, self.response_limit = request_limit, response_limit
        self.worker = threading.Thread(target=self._work, daemon=True)
        self.worker.start()

    def _work(self):
        try:
            while True:
                item = self.requests.get()
                if item is None:
                    return
                identifier, frame = item
                view = memoryview(frame)
                while view:
                    count = self.process.stdin.write(view)
                    if not count:
                        raise TransportError("Server stdin closed")
                    view = view[count:]
                self.process.stdin.flush()
                if identifier is None:
                    continue
                while True:
                    raw = self.process.stdout.readline(self.response_limit + 1)
                    if not raw:
                        raise TransportError("Server disconnected before replying")
                    if len(raw) > self.response_limit or not raw.endswith(b"\n"):
                        raise ProtocolError("Oversized or incomplete MCP response")
                    message = json.loads(raw)
                    if not isinstance(message, dict) or message.get("jsonrpc") != "2.0":
                        raise ProtocolError("Invalid MCP response envelope")
                    if "id" not in message and isinstance(message.get("method"), str):
                        continue  # Notifications are not tool results.
                    if type(message.get("id")) is not int or message["id"] != identifier:
                        raise ProtocolError("Mismatched MCP response ID")
                    if ("result" in message) == ("error" in message):
                        raise ProtocolError("MCP reply must contain one result or error")
                    self.replies.put(message)
                    break
        except Exception as error:
            self.replies.put(error if isinstance(error, TransportError)
                             else TransportError(str(error)))
        finally:
            self.process.stdout.close()

    def request(self, method, params, timeout):
        if self.closed:
            raise TransportError("Session is closed")
        self.serial += 1
        message = {"jsonrpc": "2.0", "id": self.serial, "method": method, "params": params}
        frame = (_json(message) + "\n").encode("utf-8")
        if len(frame) > self.request_limit:
            raise ValueError("Request exceeds the configured server frame limit")
        self.requests.put((self.serial, frame))
        try:
            reply = self.replies.get(timeout=_seconds(timeout))
        except queue.Empty as error:
            raise TransportError("MCP reply deadline exceeded") from error
        if isinstance(reply, Exception):
            raise reply
        if "error" in reply:
            raise ProtocolError(f"MCP JSON-RPC error: {reply['error']!r}")
        return reply["result"]

    def initialized(self):
        self.requests.put((None, b'{"jsonrpc":"2.0","method":"notifications/initialized"}\n'))

    def close(self, *, grace=0.0):
        if self.closed:
            return
        self.closed = True
        # Never terminate a process: EOF lets the owned server finish its call.
        self.process.stdin.close()
        self.requests.put(None)
        try:
            self.process.wait(timeout=grace)
        except subprocess.TimeoutExpired:
            # Keep/reap the owned process after EOF without blocking shutdown or
            # killing an in-flight operation. It may legitimately outlive us.
            threading.Thread(target=self.process.wait, daemon=True).start()


class _NativeJournal:
    """Same journal interface through the engine's cross-platform private store."""

    def __init__(self, command, endpoint, timeout):
        if isinstance(command, (str, bytes)) or not command:
            raise ValueError("journal_command must be an argv sequence")
        self.timeout = timeout
        self._session = _StdioSession([os.fspath(arg) for arg in command], endpoint["cwd"],
                                     request_limit=MAX_JOURNAL_FRAME,
                                     response_limit=MAX_JOURNAL_FRAME)
        try:
            info = self._rpc("info", {})
            if info.get("protocolVersion") != 1 or not isinstance(info.get("durability"), str):
                raise JournalError("Unsupported native journal protocol or durability contract")
            self.durability = info["durability"]
            with self.locked():
                expected = {"version": 1, "endpoint": endpoint}
                binding = self.read("endpoint.json")
                if binding is None:
                    self.write("endpoint.json", expected)
                elif _json(binding) != _json(expected):
                    raise JournalError("Journal belongs to a different engine/state endpoint")
        except Exception:
            self.close()
            raise

    def _rpc(self, method, arguments):
        if self._session is None:
            raise JournalError("Native journal disconnected; create a new client to reconcile")
        try:
            result = self._session.request("journal/" + method, arguments, self.timeout)
            if not isinstance(result, dict):
                raise ProtocolError("Invalid native journal response")
            return result
        except TransportError as error:
            self.close(grace=0.0)
            raise JournalError("Native journal failed; no further engine request will be sent") from error

    @contextlib.contextmanager
    def locked(self):
        if self._rpc("lock", {}).get("locked") is not True:
            self.close()
            raise JournalError("Native journal did not grant its exclusive lock")
        try:
            yield
        finally:
            if self._session is not None:
                if self._rpc("unlock", {}).get("locked") is not False:
                    self.close()
                    raise JournalError("Native journal did not release its lock")

    def read(self, name):
        result = self._rpc("read", {"name": name})
        if result.get("found") is False:
            return None
        if result.get("found") is not True or not isinstance(result.get("value_json"), str):
            raise JournalError("Invalid native journal read response")
        try:
            value = json.loads(result["value_json"])
            _json(value)
        except ValueError as error:
            raise JournalError("Invalid native journal JSON record") from error
        return value

    def write(self, name, value):
        # Preserve canonical JSON as text across the Rust transport; integer
        # precision and float spellings must not silently change an exact request.
        value_json = _json(value)
        if self._rpc("write", {"name": name, "value_json": value_json}).get("written") is not True:
            raise JournalError("Native journal did not confirm persistence")

    def record(self, operation_id):
        record = self.read(operation_id + ".json")
        if record is not None:
            if (not isinstance(record, dict) or record.get("version") != 1
                    or not isinstance(record.get("request"), dict)
                    or record["request"].get("operation_id") != operation_id
                    or record.get("state") not in {"pending", "completed"}
                    or (record["state"] == "completed"
                        and (not isinstance(record.get("result"), dict)
                             or type(record["result"].get("ok")) is not bool))):
                raise JournalError("Invalid operation receipt; refusing to overwrite it")
        return record

    def close(self, *, grace=1.0):
        if self._session is not None:
            self._session.close(grace=grace)
            self._session = None


class WipstashClient:
    """Use read(), explicit mutate(), reconcile(), and wait_for_proposal().

    Completed same-ID requests return the saved reply. Pending same-ID requests
    only query operation_status, even after a client restart. Unresolved results
    raise UncertainOperation; there is deliberately no automatic replay method.
    Operations lacking engine idempotency (init/integrate/restore, for example)
    are outside this helper and require a separate, explicit caller action.
    Engine failures are returned as dictionaries with ok:false, not raised.
    Check them before dependent actions. For command_run, also inspect
    execution.success: top-level ok is not proof that project checks passed.
    """

    def __init__(self, command, journal_dir=None, *, timeout=30.0, journal_command=None,
                 clock=time.monotonic, sleep=time.sleep):
        if not command or isinstance(command, (str, bytes)):
            raise ValueError("command must be an argv sequence, never a shell string")
        self.command = [os.fspath(arg) for arg in command]
        executable = shutil.which(self.command[0])
        if executable is None:
            raise ValueError("Server executable was not found")
        self.command[0] = os.path.abspath(executable)
        self.cwd = os.getcwd()
        self.timeout = _seconds(timeout)
        self.clock, self.sleep = clock, sleep
        self._lock = threading.RLock()
        self._session = None
        self._closed = False
        self.tools = {}
        self.journal = None
        self.journal_durability = None
        endpoint = {"command": self.command, "cwd": self.cwd}
        if journal_dir is not None:
            if journal_command is None:
                journal_command = [self.command[0], "client-journal",
                                   os.path.abspath(os.fspath(journal_dir))]
            self.journal = _NativeJournal(journal_command, endpoint, self.timeout)
            self.journal_durability = self.journal.durability
        elif journal_command is not None:
            raise ValueError("journal_command requires a journal_dir")

    def __enter__(self):
        try:
            self.start()
            return self
        except Exception:
            self.close()
            raise

    def __exit__(self, *_):
        self.close()

    def start(self, timeout=None):
        with self._lock:
            if self._closed:
                raise ClientError("Client is closed")
            if self._session is not None:
                return
            deadline = time.monotonic() + _seconds(self.timeout if timeout is None else timeout)
            session = _StdioSession(self.command, self.cwd)
            try:
                result = session.request("initialize", {
                    "protocolVersion": PROTOCOL_VERSION, "capabilities": {},
                    "clientInfo": {"name": "wipstash-durable-python", "version": "1"},
                }, self._remaining(deadline))
                if not isinstance(result, dict) or result.get("protocolVersion") != PROTOCOL_VERSION:
                    raise ProtocolError("Server negotiated an unsupported MCP version")
                session.initialized()
                discovery = session.request("tools/list", {}, self._remaining(deadline))
                if not isinstance(discovery, dict) or not isinstance(discovery.get("tools"), list):
                    raise ProtocolError("Invalid tools/list response")
                self.tools = {tool["name"]: tool for tool in discovery["tools"]
                              if isinstance(tool, dict) and isinstance(tool.get("name"), str)}
                if "wipstash" not in self.tools or discovery.get("nextCursor") is not None:
                    raise ProtocolError("Expected unpaginated Wipstash tool discovery")
                self._session = session
            except Exception:
                session.close()
                raise

    @staticmethod
    def _remaining(deadline):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TransportError("MCP deadline exceeded")
        return remaining

    def _disconnect(self, *, grace=0.0):
        if self._session is not None:
            self._session.close(grace=grace)
            self._session = None

    def _call_engine(self, request, *, timeout=None):
        deadline = time.monotonic() + _seconds(self.timeout if timeout is None else timeout)
        self.start(self._remaining(deadline))
        name = "wipstash_" + request["op"]
        if name in self.tools:
            arguments = {key: value for key, value in request.items() if key != "op"}
        else:
            name, arguments = "wipstash", {"request": request}
        try:
            result = self._session.request("tools/call", {"name": name, "arguments": arguments},
                                           self._remaining(deadline))
            if not isinstance(result, dict) or not isinstance(result.get("structuredContent"), dict):
                raise ProtocolError("Tool result is missing structuredContent")
            value = result["structuredContent"]
            if type(value.get("ok")) is not bool:
                raise ProtocolError("Engine result is missing boolean ok")
            return value
        except TransportError:
            self._disconnect()
            raise

    def read(self, op, *, timeout=None, **fields):
        if op not in READS:
            raise ValueError("Use mutate() for an explicitly authorized journalled mutation")
        limit = _seconds(self.timeout if timeout is None else timeout)
        deadline = time.monotonic() + limit
        if not self._lock.acquire(timeout=limit):
            raise TransportError("Deadline exceeded waiting for the serialized client")
        try:
            return self._call_engine({"op": op, **fields}, timeout=self._remaining(deadline))
        finally:
            self._lock.release()

    @staticmethod
    def _operation_id(value):
        if not isinstance(value, str) or IDENTIFIER.fullmatch(value) is None:
            raise ValueError("operation_id must contain 1-100 ASCII letters, digits, '_' or '-'")
        if value == "endpoint":
            raise ValueError("operation_id 'endpoint' is reserved by the client journal")
        return value

    @staticmethod
    def new_operation_id(prefix="op"):
        """Generate once per deliberate action, retain it, and reuse on recovery."""
        value = prefix + "-" + uuid.uuid4().hex
        return WipstashClient._operation_id(value)

    def _require_journal(self):
        if self._closed:
            raise ClientError("Client is closed")
        if self.journal is None:
            raise JournalError("Mutations require an explicitly configured durable journal")

    def mutate(self, request):
        if not isinstance(request, dict) or request.get("op") not in MUTATIONS:
            raise ValueError("Operation is not supported by the engine's idempotent mutation journal")
        request = json.loads(_json(request))  # Isolate mutable caller-owned values.
        operation_id = self._operation_id(request.get("operation_id"))
        with self._lock:
            self._require_journal()
            with self.journal.locked():
                record = self.journal.record(operation_id)
                if record is not None:
                    if _json(record["request"]) != _json(request):
                        raise IdempotencyMismatch("operation_id already binds a different exact request")
                    return self._reconcile(record)
                record = {"version": 1, "request": request, "state": "pending"}
                self.journal.write(operation_id + ".json", record)
                try:
                    result = self._call_engine(request)
                except TransportError as error:
                    self._disconnect()
                    raise UncertainOperation(operation_id) from error
                self._complete(record, result)
                return result

    def _complete(self, record, result):
        record = dict(record, state="completed", result=result)
        self.journal.write(record["request"]["operation_id"] + ".json", record)

    def _reconcile(self, record):
        if record["state"] == "completed":
            return record["result"]
        operation_id = record["request"]["operation_id"]
        try:
            self.start()
            query = {"op": "operation_status", "operation_id": operation_id}
            schema = self.tools.get("wipstash_operation_status", {}).get("inputSchema", {})
            envelope = "include_record" in schema.get("properties", {})
            if envelope:
                query["include_record"] = True
            result = self._call_engine(query)
        except TransportError as error:
            raise UncertainOperation(operation_id) from error
        if envelope:
            if (not result["ok"] or result.get("recorded") is not True
                    or result.get("state") != "completed"
                    or result.get("operation_id") != operation_id
                    or not isinstance(result.get("request"), dict)
                    or not isinstance(result.get("result"), dict)
                    or type(result["result"].get("ok")) is not bool):
                raise UncertainOperation(operation_id, result)
            if _json(result["request"]) != _json(record["request"]):
                raise UncertainOperation(operation_id, result)
            result = result["result"]
        else:
            # Legacy unwrapped results cannot prove the server's ID binds this
            # client's request. A different client could have used the same ID.
            raise UncertainOperation(operation_id, result)
        self._complete(record, result)
        return result

    def reconcile(self, operation_id):
        operation_id = self._operation_id(operation_id)
        with self._lock:
            self._require_journal()
            with self.journal.locked():
                record = self.journal.record(operation_id)
                if record is None:
                    raise JournalError("No local receipt for that operation ID")
                return self._reconcile(record)

    def wait_for_proposal(self, proposal, *, timeout=60.0, initial_delay=0.25, max_delay=2.0):
        """Poll to an actionable disposition; never integrate, retry or adopt.

        Quarantine is an outcome requiring review, not successful integration.
        Deadline covers each read (including reconnect) as well as backoff.
        """
        deadline = self.clock() + _seconds(timeout)
        delay, maximum = _seconds(initial_delay), _seconds(max_delay)
        delay = min(delay, maximum)
        last = None
        while True:
            remaining = deadline - self.clock()
            if remaining <= 0:
                raise ProposalTimeout(proposal, last)
            try:
                last = self.read("proposal_status", proposal=proposal,
                                 timeout=min(self.timeout, remaining))
            except TransportError as error:
                if self.clock() >= deadline:
                    raise ProposalTimeout(proposal, last) from error
                raise
            if not last["ok"] or last.get("state") in PROPOSAL_OUTCOMES:
                return last
            remaining = deadline - self.clock()
            if remaining <= 0:
                raise ProposalTimeout(proposal, last)
            self.sleep(min(delay, remaining))
            delay = min(delay * 2, maximum)

    def close(self):
        with self._lock:
            self._disconnect(grace=1.0)
            if self.journal is not None:
                self.journal.close()
            self._closed = True
