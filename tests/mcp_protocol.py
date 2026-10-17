#!/usr/bin/env python3
"""Real subprocess stdio protocol test; no Codex/Claude/model invocation."""
import json
import os
from pathlib import Path
import queue
import subprocess
import tempfile
import threading

binary = Path(__file__).resolve().parents[1] / "target" / "debug" / ("wipstash.exe" if os.name == "nt" else "wipstash")
with tempfile.TemporaryDirectory(prefix="wipstash-mcp-") as directory:
    process = subprocess.Popen([str(binary), "--state", str(Path(directory) / "state"), "mcp"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    lines = queue.Queue()
    def reader():
        for line in process.stdout:
            lines.put(line)
    threading.Thread(target=reader, daemon=True).start()
    def send(message):
        process.stdin.write(json.dumps(message) + "\n")
        process.stdin.flush()
    def receive():
        return json.loads(lines.get(timeout=10))
    def request(identifier, method, params=None):
        message = {"jsonrpc": "2.0", "id": identifier, "method": method}
        if params is not None:
            message["params"] = params
        send(message)
        result = receive()
        assert result["id"] == identifier, result
        return result
    try:
        assert request(1, "tools/list")["error"]["code"] == -32002
        init = request(2, "initialize", {"protocolVersion": "unknown-future-revision", "capabilities": {}, "clientInfo": {"name": "standalone-protocol-test", "version": "1"}})
        assert init["result"]["protocolVersion"] == "2025-11-25"
        send({"jsonrpc": "2.0", "method": "notifications/initialized"})
        # A tools/call notification must never execute, even after initialization.
        send({"jsonrpc": "2.0", "method": "tools/call", "params": {"name": "wipstash", "arguments": {"request": {"op": "status"}}}})
        tools = request("list", "tools/list")["result"]["tools"]
        assert {tool["name"] for tool in tools} >= {"wipstash", "wipstash_status", "wipstash_checkpoint", "wipstash_adopt"}
        assert not (Path(directory) / "state").exists(), "notification executed engine"
        # Hostile envelopes are rejected with a null ID; no batch is executed.
        for invalid in [None, 42, [], [{"jsonrpc": "2.0", "id": 99, "method": "ping"}],
                        {"jsonrpc": "2.0", "id": None, "method": "ping"},
                        {"jsonrpc": "2.0", "id": True, "method": "ping"}]:
            send(invalid)
            reply = receive()
            assert reply["id"] is None and reply["error"]["code"] == -32600, reply
        assert request("duplicate", "initialize", {"protocolVersion": "2025-11-25", "capabilities": {}, "clientInfo": {"name": "test", "version": "1"}})["error"]["code"] == -32600
        extra = request("extra-argument", "tools/call", {"name": "wipstash_status", "arguments": {"unexpected": "must not execute"}})
        assert extra["result"]["isError"] and not (Path(directory) / "state").exists()
        # The suffix looks like an engine call but belongs to one oversized frame.
        suffix = {"jsonrpc": "2.0", "id": "smuggled", "method": "tools/call", "params": {"name": "wipstash_status", "arguments": {}}}
        process.stdin.write(" " * (1024 * 1024 + 1) + json.dumps(suffix) + "\n")
        process.stdin.flush()
        oversized = receive()
        assert oversized["id"] is None and oversized["error"]["code"] == -32600
        assert request("after-oversize", "ping")["result"] == {}
        assert not (Path(directory) / "state").exists(), "oversized frame suffix executed"
        assert request(3, "tools/call", {"name": "missing"})["error"]["code"] == -32602
        assert request(4, "tools/call", {"name": "wipstash_checkpoint", "arguments": {}})["result"]["isError"]
        failed = request(5, "tools/call", {"name": "wipstash_status", "arguments": {}})["result"]
        assert failed["isError"] and failed["structuredContent"]["ok"] is False
        assert json.loads(failed["content"][0]["text"]) == failed["structuredContent"]
        assert request(6, "unknown")["error"]["code"] == -32601
        assert request(7, "ping")["result"] == {}
        process.stdin.close()
        assert process.wait(timeout=10) == 0
        assert lines.empty(), "unexpected notification response or stdout contamination"
        print("PASS: subprocess stdio lifecycle, negotiation, tool discovery, validation, error mapping, notifications, hostile envelopes, duplicate initialization, unknown arguments, oversized-frame smuggling, flushing, EOF shutdown")
    finally:
        if process.poll() is None:
            process.kill()
            process.wait()
