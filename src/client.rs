//! Bounded newline-delimited stdio MCP, pinned to the 2025-11-25 lifecycle.
//! Calls are serialized; no cancellation, background tasks, or native-editor interception.
use serde_json::{json, Value};
use std::io::{self, BufRead, Write};

const VERSION: &str = "2025-11-25";
const MAX_FRAME: usize = 1024 * 1024;

#[derive(Default)]
struct Session {
    initialized: bool,
    ready: bool,
}
fn error(id: Value, code: i64, message: &str) -> Value {
    json!({"jsonrpc":"2.0","id":id,"error":{"code":code,"message":message}})
}
fn tools() -> Value {
    let mut result = vec![json!({
        "name":"wipstash", "description":"Execute a Wipstash JSON request. Full trusted local engine access, including command execution and configuration. Stop unmanaged writers first. Use operation_id for retry-safe mutations; inspect operation_status after a lost response.",
        "inputSchema":{"type":"object","properties":{"request":{"type":"object","properties":{"op":{"type":"string","minLength":1}},"required":["op"]}},"required":["request"],"additionalProperties":false},
        "annotations":{"readOnlyHint":false,"destructiveHint":true,"idempotentHint":false,"openWorldHint":true}
    })];
    for (op, description, fields, required) in [
        (
            "status",
            "Read project or workspace state, including generation. Does not adopt.",
            vec!["workspace"],
            vec![],
        ),
        (
            "updates",
            "Fetch latest public head metadata without adopting live files.",
            vec!["workspace"],
            vec!["workspace"],
        ),
        (
            "open",
            "Create an isolated workspace at an empty absolute directory.",
            vec!["workspace", "path", "operation_id"],
            vec!["workspace", "path", "operation_id"],
        ),
        (
            "checkpoint",
            "Capture private WIP, including broken code. Stop unmanaged writers first.",
            vec!["workspace", "operation_id", "expected_generation"],
            vec!["workspace", "operation_id", "expected_generation"],
        ),
        (
            "publish",
            "Deliberately publish a selected checkpoint; does not adopt or integrate.",
            vec!["workspace", "checkpoint", "intent", "operation_id"],
            vec!["workspace", "checkpoint", "intent", "operation_id"],
        ),
        (
            "adopt",
            "Deliberately update workspace files to a public target; stop unmanaged writers first.",
            vec!["workspace", "target", "operation_id", "expected_generation"],
            vec!["workspace", "target", "operation_id", "expected_generation"],
        ),
        (
            "proposal_status",
            "Read a proposal's integration state and evidence.",
            vec!["proposal"],
            vec!["proposal"],
        ),
        (
            "resolution_tasks",
            "Read actionable conflict or failed-check tasks for this workspace. Resolve only in a separate resolution checkout.",
            vec!["workspace"],
            vec!["workspace"],
        ),
        (
            "resolution_open",
            "Open a separate public-snapshot resolution workspace for a quarantined proposal. Leaves the original workspace untouched.",
            vec!["workspace", "proposal", "resolution_workspace", "path", "operation_id"],
            vec!["workspace", "proposal", "resolution_workspace", "path", "operation_id"],
        ),
        (
            "resolution_submit",
            "Submit a checkpoint from the resolution workspace as a new proposal against expected_head. Requires deliberate publication approval; stale heads must be refreshed.",
            vec!["workspace", "proposal", "resolution_workspace", "checkpoint", "expected_head", "resolved_conflicts", "operation_id"],
            vec!["workspace", "proposal", "resolution_workspace", "checkpoint", "expected_head", "resolved_conflicts", "operation_id"],
        ),
        (
            "operation_status",
            "Read the durable outcome for an operation ID before retrying after a disconnect.",
            vec!["operation_id"],
            vec!["operation_id"],
        ),
    ] {
        let properties: serde_json::Map<String, Value> = fields
            .into_iter()
            .map(|field| {
                let schema = if field == "resolved_conflicts" {
                    json!({"type":"array","items":{"type":"string"},"uniqueItems":true,"maxItems":10000})
                } else if field == "expected_generation" {
                    json!({"type":"integer","minimum":0})
                } else {
                    json!({"type":"string","minLength":1})
                };
                (field.into(), schema)
            })
            .collect();
        result.push(json!({"name":format!("wipstash_{op}"),"description":description,
            "inputSchema":{"type":"object","properties":properties,"required":required,"additionalProperties":false},
            "annotations":{"readOnlyHint":matches!(op,"status"|"proposal_status"|"operation_status"|"resolution_tasks"),"destructiveHint":op=="adopt","idempotentHint":false,"openWorldHint":false}}));
    }
    json!({"tools":result})
}
impl Session {
    fn handle(&mut self, msg: Value, execute: &mut impl FnMut(Value) -> Value) -> Option<Value> {
        let id = msg.get("id").cloned();
        let valid_id = id
            .as_ref()
            .is_none_or(|id| id.is_string() || id.as_i64().is_some() || id.as_u64().is_some());
        if !msg.is_object() || msg["jsonrpc"] != "2.0" || !msg["method"].is_string() || !valid_id {
            return Some(error(Value::Null, -32600, "Invalid Request"));
        }
        let method = msg["method"].as_str().unwrap();
        // Notifications never execute tools and never receive replies.
        let Some(id) = id else {
            if method == "notifications/initialized"
                && self.initialized
                && msg.get("params").is_none_or(Value::is_object)
            {
                self.ready = true;
            }
            return None;
        };
        if msg.get("params").is_some_and(|v| !v.is_object()) {
            return Some(error(id, -32602, "params must be an object"));
        }
        let params = &msg["params"];
        let result = match method {
            "initialize" => {
                if self.initialized {
                    return Some(error(id, -32600, "Already initialized"));
                }
                if !params["protocolVersion"].is_string()
                    || !params["capabilities"].is_object()
                    || !params["clientInfo"]["name"].is_string()
                    || !params["clientInfo"]["version"].is_string()
                {
                    return Some(error(
                        id,
                        -32602,
                        "initialize requires protocolVersion, capabilities, and clientInfo",
                    ));
                }
                self.initialized = true;
                // Offer our supported version when the requested revision differs.
                json!({"protocolVersion":VERSION,"capabilities":{"tools":{}},
                    "serverInfo":{"name":"wipstash-local-prototype","version":env!("CARGO_PKG_VERSION")},
                    "instructions":"Cooperative local prototype. Stop native/unmanaged writers before checkpoint/adopt. Publication and adoption require deliberate approval. Calls are serialized; cancellation is not implemented. Use operation IDs to recover uncertain outcomes. Inspect resolution_tasks returned by status and updates. For conflicts or failed checks, use resolution_open, edit and checkpoint only the separate resolution workspace, then resolution_submit against its expected head. Never overwrite the original workspace to resolve a proposal."})
            }
            "ping" => json!({}),
            _ if !self.ready => {
                return Some(error(
                    id,
                    -32002,
                    "Send initialize and notifications/initialized first",
                ))
            }
            "tools/list" => {
                if params.get("cursor").is_some() {
                    return Some(error(id, -32602, "No pagination cursor is supported"));
                }
                tools()
            }
            "tools/call" => {
                let definitions = tools();
                let Some(tool) = definitions["tools"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .find(|tool| tool["name"] == params["name"])
                else {
                    return Some(error(id, -32602, "Unknown tool"));
                };
                let arguments = params.get("arguments").cloned().unwrap_or(json!({}));
                if !arguments.is_object() {
                    return Some(error(id, -32602, "arguments must be an object"));
                }
                if params.get("task").is_some() {
                    return Some(error(id, -32602, "Task-augmented calls are not supported"));
                }
                let schema = &tool["inputSchema"];
                let invalid = schema["required"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|key| arguments.get(key.as_str().unwrap()).is_none())
                    || arguments.as_object().unwrap().iter().any(|(key, value)| {
                        let definition = &schema["properties"][key];
                        match definition["type"].as_str() {
                            Some("string") => value.as_str().is_none_or(str::is_empty),
                            Some("integer") => value.as_u64().is_none(),
                            Some("object") => !value.is_object(),
                            Some("array") => value.as_array().is_none_or(|a|a.len()>10000 || a.iter().any(|v|v.as_str().is_none_or(str::is_empty))),
                            _ => true,
                        }
                    });
                let name = tool["name"].as_str().unwrap();
                let invalid = invalid
                    || (name == "wipstash"
                        && arguments["request"]["op"]
                            .as_str()
                            .is_none_or(str::is_empty));
                let result = if invalid {
                    json!({"ok":false,"error":{"code":"invalid_arguments","message":"Arguments must conform to this tool's inputSchema"}})
                } else {
                    let request = if name == "wipstash" {
                        arguments["request"].clone()
                    } else {
                        let mut request = arguments;
                        request["op"] = json!(name.strip_prefix("wipstash_").unwrap());
                        request
                    };
                    execute(request)
                };
                json!({"content":[{"type":"text","text":result.to_string()}],"structuredContent":result,"isError":result["ok"]==false})
            }
            _ => return Some(error(id, -32601, "Method not found")),
        };
        Some(json!({"jsonrpc":"2.0","id":id,"result":result}))
    }
}

pub fn serve(
    mut input: impl BufRead,
    mut output: impl Write,
    mut execute: impl FnMut(Value) -> Value,
) -> io::Result<()> {
    let mut session = Session::default();
    loop {
        // Read through a fixed-size adapter. Oversized frames are drained without allocation.
        let mut frame = Vec::new();
        let mut oversized = false;
        loop {
            let available = input.fill_buf()?;
            if available.is_empty() {
                break;
            }
            let end = available.iter().position(|b| *b == b'\n').map(|n| n + 1);
            let count = end.unwrap_or(available.len());
            if frame.len() + count > MAX_FRAME {
                oversized = true;
            }
            if !oversized {
                frame.extend_from_slice(&available[..count]);
            }
            input.consume(count);
            if end.is_some() {
                break;
            }
        }
        if frame.is_empty() && !oversized {
            return Ok(());
        }
        let response = if oversized {
            Some(error(Value::Null, -32600, "Frame exceeds 1 MiB limit"))
        } else {
            match serde_json::from_slice(&frame) {
                Ok(msg) => session.handle(msg, &mut execute),
                Err(_) => Some(error(Value::Null, -32700, "Parse error")),
            }
        };
        if let Some(response) = response {
            serde_json::to_writer(&mut output, &response)?;
            output.write_all(b"\n")?;
            output.flush()?;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn init(s: &mut Session) {
        let response = s.handle(json!({"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":VERSION,"capabilities":{},"clientInfo":{"name":"test","version":"1"}}}), &mut |_| panic!("unexpected engine call")).unwrap();
        assert_eq!(response["result"]["protocolVersion"], VERSION);
        assert!(s
            .handle(
                json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
                &mut |_| panic!()
            )
            .is_none());
    }
    #[test]
    fn lifecycle_and_notification_safety() {
        let mut s = Session::default();
        assert_eq!(
            s.handle(
                json!({"jsonrpc":"2.0","id":1,"method":"tools/list"}),
                &mut |_| panic!()
            )
            .unwrap()["error"]["code"],
            -32002
        );
        init(&mut s);
        assert!(s.handle(json!({"jsonrpc":"2.0","method":"tools/call","params":{"name":"wipstash","arguments":{"request":{"op":"init"}}}}), &mut |_| panic!()).is_none());
        assert_eq!(
            s.handle(
                json!({"jsonrpc":"2.0","id":2,"method":"tools/list"}),
                &mut |_| panic!()
            )
            .unwrap()["result"]["tools"]
                .as_array()
                .unwrap()
                .len(),
            12
        );
    }
    #[test]
    fn resolution_submit_accepts_explicit_conflict_attestation() {
        let mut s=Session::default(); init(&mut s);
        let args=json!({"workspace":"owner","proposal":"p","resolution_workspace":"fix","checkpoint":"cp","expected_head":"head","resolved_conflicts":["file"],"operation_id":"submit"});
        let result=s.handle(json!({"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"wipstash_resolution_submit","arguments":args}}), &mut |request| {
            assert_eq!(request["op"],"resolution_submit");
            assert_eq!(request["resolved_conflicts"],json!(["file"]));
            json!({"ok":true})
        }).unwrap();
        assert_eq!(result["result"]["isError"],false);
        let mut bad=args;bad["resolved_conflicts"]=json!("file");
        let result=s.handle(json!({"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"wipstash_resolution_submit","arguments":bad}}), &mut |_|panic!("invalid arguments executed")).unwrap();
        assert_eq!(result["result"]["isError"],true);
    }
    #[test]
    fn envelope_and_argument_errors_never_execute() {
        let mut s = Session::default();
        for msg in [
            json!([]),
            json!(null),
            json!({"jsonrpc":"2.0","id":null,"method":"ping"}),
            json!({"jsonrpc":"1.0","id":1,"method":"ping"}),
        ] {
            assert_eq!(
                s.handle(msg, &mut |_| panic!()).unwrap()["error"]["code"],
                -32600
            );
        }
        init(&mut s);
        assert_eq!(
            s.handle(
                json!({"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"unknown"}}),
                &mut |_| panic!()
            )
            .unwrap()["error"]["code"],
            -32602
        );
        assert_eq!(s.handle(json!({"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"wipstash_checkpoint","arguments":{"workspace":"a"}}}), &mut |_| panic!()).unwrap()["result"]["isError"], true);
    }
    #[test]
    fn typed_tool_dispatch_and_engine_error() {
        let mut s = Session::default();
        init(&mut s);
        let response = s.handle(json!({"jsonrpc":"2.0","id":"x","method":"tools/call","params":{"name":"wipstash_status","arguments":{"workspace":"a"}}}), &mut |request| {
            assert_eq!(request, json!({"op":"status","workspace":"a"}));
            json!({"ok":false,"error":{"code":"fixture"}})
        }).unwrap();
        assert_eq!(response["id"], "x");
        assert_eq!(response["result"]["isError"], true);
        assert_eq!(
            response["result"]["structuredContent"]["error"]["code"],
            "fixture"
        );
    }
    #[test]
    fn framing_recovers_after_oversize_and_parse_error() {
        let mut input = vec![b'x'; MAX_FRAME + 20];
        input
            .extend_from_slice(b"\n{broken}\n{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\"}\n");
        let mut output = Vec::new();
        serve(io::Cursor::new(input), &mut output, |_| panic!()).unwrap();
        let responses: Vec<Value> = String::from_utf8(output)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        assert_eq!(responses.len(), 3);
        assert_eq!(responses[0]["error"]["code"], -32600);
        assert_eq!(responses[1]["error"]["code"], -32700);
        assert_eq!(responses[2]["result"], json!({}));
    }
}
