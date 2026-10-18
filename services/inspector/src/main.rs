use std::{
    collections::HashMap,
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    path::PathBuf,
    time::{Duration, Instant},
};
use wipstash_inspector::{Inspector, Response};
fn security_headers(origin: Option<&str>) -> HashMap<&'static str, String> {
    let mut headers: HashMap<_, _> = [
        ("Cache-Control", "no-store"),
        ("X-Content-Type-Options", "nosniff"),
        ("Referrer-Policy", "no-referrer"),
        ("Content-Security-Policy", "default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self' 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'"),
        ("Cross-Origin-Resource-Policy", "same-origin"),
    ].into_iter().map(|(k,v)| (k,v.to_owned())).collect();
    if let Some(origin) = origin {
        headers.insert("Access-Control-Allow-Origin", origin.to_owned());
        headers.insert("Vary", "Origin".into());
    }
    headers
}
fn main() {
    if let Err(e) = run() {
        eprintln!("inspector: {e}");
        std::process::exit(1)
    }
}
fn run() -> Result<(), String> {
    let mut options = HashMap::new();
    let mut args = std::env::args().skip(1);
    while let Some(k) = args.next() {
        if k == "--help" {
            println!("wipstash-inspector --state PATH [--bind 127.0.0.1:47831] [--assets DIRECTORY] [--allow-origin http://127.0.0.1:PORT]\nIn-memory: --request '/api/overview' [--method GET] [--host HOST] [--origin ORIGIN] [--fetch-site same-origin]");
            return Ok(());
        }
        if ![
            "--state",
            "--bind",
            "--assets",
            "--allow-origin",
            "--request",
            "--method",
            "--host",
            "--origin",
            "--fetch-site",
        ]
        .contains(&k.as_str())
        {
            return Err("unknown option".into());
        }
        let v = args.next().ok_or("missing option value")?;
        if options.insert(k, v).is_some() {
            return Err("duplicate option".into());
        }
    }
    let authority = options
        .get("--bind")
        .cloned()
        .unwrap_or("127.0.0.1:47831".into());
    let inspector = Inspector::new(
        options.get("--state").ok_or("--state is required")?,
        authority.clone(),
        options.get("--allow-origin").cloned(),
    )
    .map_err(|e| e.code.to_owned())?;
    let assets = options
        .get("--assets")
        .map(std::fs::canonicalize)
        .transpose()
        .map_err(|_| "assets unavailable")?;
    if let Some(target) = options.get("--request") {
        let response = dispatch(
            &inspector,
            assets.as_ref(),
            options.get("--method").map(String::as_str).unwrap_or("GET"),
            target,
            options
                .get("--host")
                .map(String::as_str)
                .unwrap_or(&authority),
            options.get("--origin").map(String::as_str),
            options.get("--fetch-site").map(String::as_str),
        );
        println!(
            "{}",
            serde_json::json!({"status":response.0.status,"body":serde_json::from_slice::<serde_json::Value>(&response.0.body).unwrap_or_else(|_|serde_json::json!(String::from_utf8_lossy(&response.0.body))),"content_type":response.1,"origin":response.0.origin,"headers":security_headers(response.0.origin.as_deref())})
        );
        return Ok(());
    }
    let listener = TcpListener::bind(&authority).map_err(|_| "loopback listener unavailable")?;
    eprintln!("Read-only local inspector: http://{authority} (private checkpoints are visible to local users)");
    // Single bounded connection at a time avoids unbounded threads and copies.
    for stream in listener.incoming() {
        let mut stream = stream.map_err(|_| "listener failed")?;
        let _ = serve(&mut stream, &inspector, assets.as_ref());
    }
    Ok(())
}
fn reject(code: &str, status: u16) -> (Response, &'static str) {
    (
        Response {
            status,
            body: serde_json::to_vec(
                &serde_json::json!({"error":{"code":code,"message":code.replace('_'," ")}}),
            )
            .unwrap(),
            origin: None,
        },
        "application/json",
    )
}
fn dispatch(
    i: &Inspector,
    assets: Option<&PathBuf>,
    method: &str,
    target: &str,
    host: &str,
    origin: Option<&str>,
    fetch: Option<&str>,
) -> (Response, &'static str) {
    if target.starts_with("/api/") {
        return (
            i.handle(method, target, host, origin, fetch),
            "application/json",
        );
    }
    // Run the exact API admission checks before serving any file. No DB needed on rejection.
    if let Err(e) = i.admit(method, target, host, origin, fetch) {
        return reject(e.code, e.status);
    }
    let Some(root) = assets else {
        return reject("not_found", 404);
    };
    // The explicit synthetic demo uses the same document; no arbitrary query path is accepted.
    let target = if target == "/?demo=1" { "/" } else { target };
    if target.contains(['%', '?', '#', '\\'])
        || !target.starts_with('/')
        || target.starts_with("//")
        || target.split('/').any(|s| s == ".." || s == ".")
    {
        return reject("invalid_asset_path", 400);
    }
    let rel = if target == "/" {
        "index.html"
    } else {
        &target[1..]
    };
    let candidate = root.join(rel);
    let Ok(path) = std::fs::canonicalize(&candidate) else {
        return reject("not_found", 404);
    };
    if !path.starts_with(root) {
        return reject("asset_outside_root", 403);
    }
    let mime = match path.extension().and_then(|e| e.to_str()) {
        Some("html") => "text/html; charset=utf-8",
        Some("js") => "text/javascript; charset=utf-8",
        Some("css") => "text/css; charset=utf-8",
        Some("wasm") => "application/wasm",
        Some("svg") => "image/svg+xml",
        Some("png") => "image/png",
        Some("ico") => "image/x-icon",
        _ => return reject("asset_type_denied", 403),
    };
    let Ok(meta) = std::fs::metadata(&path) else {
        return reject("not_found", 404);
    };
    if !meta.is_file() || meta.len() > 32 * 1024 * 1024 {
        return reject("asset_size_limit", 413);
    }
    match std::fs::read(path) {
        Ok(body) => (
            Response {
                status: 200,
                body,
                origin: None,
            },
            mime,
        ),
        Err(_) => reject("asset_unavailable", 503),
    }
}
fn serve(stream: &mut TcpStream, i: &Inspector, assets: Option<&PathBuf>) -> std::io::Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(2)))?;
    stream.set_write_timeout(Some(Duration::from_secs(2)))?;
    let deadline = Instant::now() + Duration::from_secs(2);
    let mut header = Vec::new();
    let mut byte = [0];
    while header.len() < 16384 {
        let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
            return Ok(());
        };
        stream.set_read_timeout(Some(remaining))?;
        if stream.read(&mut byte)? == 0 {
            return Ok(());
        }
        header.push(byte[0]);
        if header.ends_with(b"\r\n\r\n") {
            break;
        }
    }
    let (response, mime) = parse(&header)
        .map(|(method, target, headers)| {
            dispatch(
                i,
                assets,
                method,
                target,
                headers.get("host").copied().unwrap_or(""),
                headers.get("origin").copied(),
                headers.get("sec-fetch-site").copied(),
            )
        })
        .unwrap_or_else(|| reject("invalid_http_request", 400));
    let reason = match response.status {
        200 => "OK",
        400 => "Bad Request",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        413 => "Content Too Large",
        422 => "Unprocessable Content",
        _ => "Service Unavailable",
    };
    write!(
        stream,
        "HTTP/1.1 {} {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n",
        response.status,
        reason,
        mime,
        response.body.len()
    )?;
    for (name, value) in security_headers(response.origin.as_deref()) {
        write!(stream, "{name}: {value}\r\n")?;
    }
    write!(stream, "\r\n")?;
    stream.write_all(&response.body)
}
fn parse(header: &[u8]) -> Option<(&str, &str, HashMap<String, &str>)> {
    let h = std::str::from_utf8(header).ok()?;
    if !h.ends_with("\r\n\r\n") {
        return None;
    }
    let mut lines = h.split("\r\n");
    let request: Vec<_> = lines.next()?.split(' ').collect();
    if request.len() != 3 || request[2] != "HTTP/1.1" {
        return None;
    }
    let mut map = HashMap::new();
    for line in lines.filter(|l| !l.is_empty()) {
        let (k, v) = line.split_once(':')?;
        if k.is_empty() || !k.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-') {
            return None;
        }
        let k = k.to_ascii_lowercase();
        let v = v.trim();
        if v.bytes().any(|b| b < 32 || b == 127) || map.insert(k, v).is_some() {
            return None;
        }
    }
    if map.contains_key("transfer-encoding") || map.get("content-length").is_some_and(|v| *v != "0")
    {
        return None;
    }
    Some((request[0], request[1], map))
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn explicit_demo_document_is_served_without_reading_state() {
        let temp = tempfile::tempdir().unwrap();
        let assets = temp.path().join("assets");
        std::fs::create_dir(&assets).unwrap();
        std::fs::write(
            assets.join("index.html"),
            "<!doctype html><title>Inspector</title>",
        )
        .unwrap();
        let assets = assets.canonicalize().unwrap();
        let inspector = Inspector::new(temp.path(), "127.0.0.1:47831".into(), None).unwrap();
        for target in ["/", "/?demo=1"] {
            let (reply, mime) = dispatch(
                &inspector,
                Some(&assets),
                "GET",
                target,
                "127.0.0.1:47831",
                None,
                None,
            );
            assert_eq!(reply.status, 200);
            assert_eq!(mime, "text/html; charset=utf-8");
            assert_eq!(reply.body, b"<!doctype html><title>Inspector</title>");
        }
        for target in [
            "/?demo=2",
            "/?demo=1&path=../",
            "/index.html?demo=1",
            "/?demo=1#ignored",
        ] {
            assert_eq!(
                dispatch(
                    &inspector,
                    Some(&assets),
                    "GET",
                    target,
                    "127.0.0.1:47831",
                    None,
                    None
                )
                .0
                .status,
                400
            );
        }
        assert!(!temp.path().join("state.sqlite").exists());
    }
    #[test]
    fn strict_http() {
        assert!(parse(b"GET /api/overview HTTP/1.1\r\nHost: a\r\nhost: b\r\n\r\n").is_none());
        assert!(
            parse(b"GET / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n").is_none()
        );
        assert!(parse(b"GET / HTTP/1.1\r\nHost: a\r\n\r\n").is_some());
    }
}
