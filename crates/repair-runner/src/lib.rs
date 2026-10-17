//! Optional repair execution. Unsupported hosts and unavailable namespaces fail closed.
//! The coordinator must own and exclusively hold the candidate for the entire call;
//! never pass a live workspace, store, home, or a directory writable by other actors.
//! This backend deliberately provides no inference credentials or network broker.
use std::{
    ffi::OsString,
    path::{Path, PathBuf},
    time::Duration,
};

#[derive(Debug, Clone)]
pub struct Bindings {
    pub head: String,
    pub proposal: String,
    pub candidate_tree: String,
    pub conflict_paths_json: String,
}
#[derive(Debug, Clone)]
pub struct Request {
    pub bindings: Option<Bindings>,
    pub candidate: PathBuf,
    /// Absolute sandbox path under /usr/bin or /bin, never an implicit shell.
    pub executable: PathBuf,
    pub args: Vec<String>,
    pub timeout: Duration,
    /// Combined stdout/stderr bytes; exceeding this terminates the job.
    pub output_limit: usize,
}
#[derive(Debug)]
pub struct Outcome {
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}
#[derive(Debug)]
pub enum Error {
    Unsupported,
    Invalid(String),
    Io(std::io::Error),
    /// Includes namespace/setup failure; there is never an unsandboxed fallback.
    Failed {
        code: Option<i32>,
        stderr: Vec<u8>,
    },
    TimedOut,
    OutputLimit,
}
impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for Error {}

fn invalid(s: &str) -> Error {
    Error::Invalid(s.into())
}
fn validate(r: &Request) -> Result<PathBuf, Error> {
    if r.timeout.is_zero() || r.timeout > Duration::from_secs(120) {
        return Err(invalid("timeout must be 1ns..120s"));
    }
    if r.output_limit == 0 || r.output_limit > 1024 * 1024 {
        return Err(invalid("output limit must be 1..1048576"));
    }
    let exe = r
        .executable
        .to_str()
        .ok_or_else(|| invalid("non-UTF8 executable"))?;
    if !(exe.starts_with("/usr/bin/") || exe.starts_with("/bin/"))
        || exe.len() > 256
        || exe.contains('\0')
        || r.executable.components().any(|c| {
            matches!(
                c,
                std::path::Component::ParentDir | std::path::Component::CurDir
            )
        })
    {
        return Err(invalid("executable must be an absolute runtime binary"));
    }
    if r.args.len() > 128
        || r.args.iter().any(|s| s.len() > 8192 || s.contains('\0'))
        || r.args.iter().map(|s| s.len()).sum::<usize>() > 32768
    {
        return Err(invalid("argument bounds exceeded"));
    }
    if !r.candidate.is_absolute() || r.candidate.as_os_str().len() > 4096 {
        return Err(invalid("candidate must be bounded absolute path"));
    }
    let canonical = r.candidate.canonicalize()?;
    if canonical != r.candidate || !canonical.is_dir() || canonical == Path::new("/") {
        return Err(invalid("candidate must be a canonical dedicated directory"));
    }
    // Fail closed on links, sockets, devices and oversized trees. Hard links can
    // otherwise expose writable host inodes despite mount namespace isolation.
    let mut stack = vec![(canonical.clone(), 0)];
    let mut entries = 0usize;
    let mut bytes = 0u64;
    while let Some((dir, depth)) = stack.pop() {
        if depth > 64 {
            return Err(invalid("candidate nesting exceeds 64"));
        }
        for entry in std::fs::read_dir(dir)? {
            let entry = entry?;
            entries += 1;
            if entries > 100_000 {
                return Err(invalid("candidate exceeds 100000 entries"));
            }
            let m = entry.path().symlink_metadata()?;
            if m.is_dir() {
                stack.push((entry.path(), depth + 1));
            } else if m.is_file() {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::MetadataExt;
                    if m.nlink() != 1 {
                        return Err(invalid("candidate contains hard links"));
                    }
                }
                bytes = bytes.saturating_add(m.len());
                if bytes > 1024 * 1024 * 1024 {
                    return Err(invalid("candidate exceeds 1GiB"));
                }
            } else {
                return Err(invalid("candidate contains symlink or special file"));
            }
        }
    }
    Ok(canonical)
}

/// Inspectable command contract; does not run anything or probe namespaces.
pub fn sandbox_arguments(r: &Request) -> Result<Vec<OsString>, Error> {
    let candidate = validate(r)?;
    if let Some(b) = &r.bindings {
        if [
            &b.head,
            &b.proposal,
            &b.candidate_tree,
            &b.conflict_paths_json,
        ]
        .iter()
        .any(|s| s.len() > 65536 || s.contains('\0'))
        {
            return Err(invalid("invalid provenance binding"));
        }
    }
    let mut a: Vec<OsString> = [
        "--unshare-user",
        "--unshare-pid",
        "--unshare-net",
        "--unshare-ipc",
        "--unshare-uts",
        "--disable-userns",
        "--die-with-parent",
        "--new-session",
        "--cap-drop",
        "ALL",
        "--clearenv",
        "--ro-bind",
        "/usr/bin",
        "/usr/bin",
        "--ro-bind",
        "/usr/lib",
        "/usr/lib",
        "--symlink",
        "usr/bin",
        "/bin",
        "--symlink",
        "usr/lib",
        "/lib",
    ]
    .into_iter()
    .map(Into::into)
    .collect();
    if Path::new("/usr/lib64").exists() {
        a.extend(
            [
                "--ro-bind",
                "/usr/lib64",
                "/usr/lib64",
                "--symlink",
                "usr/lib64",
                "/lib64",
            ]
            .into_iter()
            .map(OsString::from),
        );
    }
    a.push("--bind".into());
    a.push(candidate.into_os_string());
    a.push("/workspace".into());
    a.extend(
        [
            "--size",
            "67108864",
            "--tmpfs",
            "/tmp",
            "--proc",
            "/proc",
            "--dev",
            "/dev",
            "--setenv",
            "PATH",
            "/usr/bin:/bin",
            "--setenv",
            "HOME",
            "/tmp",
            "--setenv",
            "TMPDIR",
            "/tmp",
            "--chdir",
            "/workspace",
            "--remount-ro",
            "/",
            "--",
        ]
        .into_iter()
        .map(OsString::from),
    );
    // Insert only fixed provenance keys before the command separator.
    if let Some(b) = &r.bindings {
        a.pop(); // --
        for (key, value) in [
            ("WIPSTASH_HEAD", b.head.as_str()),
            ("WIPSTASH_PROPOSAL", b.proposal.as_str()),
            ("WIPSTASH_CANDIDATE_TREE", b.candidate_tree.as_str()),
            ("WIPSTASH_CONFLICT_PATHS", b.conflict_paths_json.as_str()),
            (
                "WIPSTASH_RESOLUTION_FILE",
                "/workspace/.wipstash-resolution.json",
            ),
        ] {
            a.extend([OsString::from("--setenv"), key.into(), value.into()]);
        }
        a.push("--".into());
    }
    a.push(r.executable.as_os_str().into());
    a.extend(r.args.iter().map(OsString::from));
    Ok(a)
}

#[cfg(not(target_os = "linux"))]
pub fn run(_r: &Request) -> Result<Outcome, Error> {
    Err(Error::Unsupported)
}

#[cfg(target_os = "linux")]
pub fn run(r: &Request) -> Result<Outcome, Error> {
    use std::os::unix::process::CommandExt;
    use std::{
        io::Read,
        process::{Command, Stdio},
        sync::{
            atomic::{AtomicUsize, Ordering},
            Arc,
        },
        thread,
        time::Instant,
    };
    let args = sandbox_arguments(r)?;
    let mut cmd = Command::new("/usr/bin/bwrap");
    cmd.args(args)
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let cpu = r.timeout.as_secs().saturating_add(2);
    // Only async-signal-safe syscalls before exec. Ensure arbitrary caller FDs
    // cannot carry credentials, host directories, or network connections inside.
    unsafe {
        cmd.pre_exec(move || {
            if libc::syscall(libc::SYS_close_range, 3u32, u32::MAX, 4u32) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            for (resource, limit) in [
                (libc::RLIMIT_CORE, 0u64),
                (libc::RLIMIT_FSIZE, 64 * 1024 * 1024),
                (libc::RLIMIT_AS, 1024 * 1024 * 1024),
                (libc::RLIMIT_CPU, cpu),
                (libc::RLIMIT_NOFILE, 256),
                (libc::RLIMIT_NPROC, 64),
            ] {
                let lim = libc::rlimit {
                    rlim_cur: limit as libc::rlim_t,
                    rlim_max: limit as libc::rlim_t,
                };
                if libc::setrlimit(resource, &lim) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
            }
            Ok(())
        });
    }
    let mut child = cmd.spawn()?;
    let count = Arc::new(AtomicUsize::new(0));
    fn drain(
        mut pipe: impl Read + Send + 'static,
        count: Arc<AtomicUsize>,
        limit: usize,
    ) -> thread::JoinHandle<std::io::Result<Vec<u8>>> {
        thread::spawn(move || {
            let mut out = Vec::new();
            let mut buf = [0u8; 4096];
            loop {
                let n = pipe.read(&mut buf)?;
                if n == 0 {
                    break;
                }
                let before = count.fetch_add(n, Ordering::Relaxed);
                let keep = limit.saturating_sub(before).min(n);
                out.extend_from_slice(&buf[..keep]);
                if before.saturating_add(n) > limit {
                    break;
                }
            }
            Ok(out)
        })
    }
    let stdout = drain(child.stdout.take().unwrap(), count.clone(), r.output_limit);
    let stderr = drain(child.stderr.take().unwrap(), count.clone(), r.output_limit);
    let start = Instant::now();
    let mut reason = None;
    let status = loop {
        if count.load(Ordering::Relaxed) > r.output_limit {
            reason = Some(Error::OutputLimit);
        }
        if start.elapsed() >= r.timeout {
            reason = Some(Error::TimedOut);
        }
        if reason.is_some() {
            let _ = child.kill();
            break child.wait();
        }
        match child.try_wait() {
            Ok(Some(s)) => break Ok(s),
            Ok(None) => thread::sleep(Duration::from_millis(5)),
            Err(e) => {
                let _ = child.kill();
                let _ = child.wait();
                break Err(e);
            }
        }
    };
    let out = stdout
        .join()
        .map_err(|_| invalid("stdout reader panicked"))??;
    let err = stderr
        .join()
        .map_err(|_| invalid("stderr reader panicked"))??;
    if let Some(e) = reason {
        return Err(e);
    }
    if count.load(Ordering::Relaxed) > r.output_limit {
        return Err(Error::OutputLimit);
    }
    let status = status?;
    if !status.success() {
        return Err(Error::Failed {
            code: status.code(),
            stderr: err,
        });
    }
    Ok(Outcome {
        stdout: out,
        stderr: err,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    static ID: AtomicUsize = AtomicUsize::new(0);
    struct Fixture(PathBuf);
    impl Fixture {
        fn new() -> Self {
            let p = std::env::temp_dir().join(format!(
                "wipstash-repair-{}-{}",
                std::process::id(),
                ID.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir(&p).unwrap();
            Self(p.canonicalize().unwrap())
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    fn request(f: &Fixture) -> Request {
        Request {
            bindings: None,
            candidate: f.0.clone(),
            executable: "/bin/sh".into(),
            args: vec!["-c".into(), "printf fixture".into()],
            timeout: Duration::from_secs(2),
            output_limit: 8192,
        }
    }
    #[test]
    fn contract_is_fail_closed() {
        let f = Fixture::new();
        let r = request(&f);
        let a = sandbox_arguments(&r).unwrap();
        let a: Vec<_> = a.iter().map(|s| s.to_str().unwrap()).collect();
        for required in [
            "--unshare-user",
            "--unshare-pid",
            "--unshare-net",
            "--disable-userns",
            "--clearenv",
            "--die-with-parent",
            "--new-session",
            "--remount-ro",
        ] {
            assert!(a.contains(&required));
        }
        for forbidden in [
            "--share-net",
            "--unshare-user-try",
            "--dev-bind",
            "--not-a-security-boundary",
            "/home",
            "/etc",
            "/run",
        ] {
            assert!(!a.contains(&forbidden));
        }
        assert_eq!(a.iter().filter(|s| **s == "--bind").count(), 1);
        assert!(a
            .windows(3)
            .any(|s| s == ["--bind", f.0.to_str().unwrap(), "/workspace"]));
        assert!(a.windows(3).any(|s| s == ["--setenv", "HOME", "/tmp"]));
    }
    #[test]
    fn provenance_is_fixed_and_remapped() {
        let f = Fixture::new();
        let mut r = request(&f);
        r.bindings = Some(Bindings {
            head: "h".into(),
            proposal: "p".into(),
            candidate_tree: "t".into(),
            conflict_paths_json: "[\"file\"]".into(),
        });
        let a = sandbox_arguments(&r).unwrap();
        let a: Vec<_> = a.iter().map(|s| s.to_str().unwrap()).collect();
        assert!(a.windows(3).any(|s| s
            == [
                "--setenv",
                "WIPSTASH_RESOLUTION_FILE",
                "/workspace/.wipstash-resolution.json"
            ]));
        assert!(a
            .windows(3)
            .any(|s| s == ["--setenv", "WIPSTASH_HEAD", "h"]));
        assert_eq!(a.iter().filter(|s| **s == f.0.to_str().unwrap()).count(), 1);
    }
    #[test]
    fn input_bounds() {
        let f = Fixture::new();
        let mut r = request(&f);
        r.timeout = Duration::ZERO;
        assert!(sandbox_arguments(&r).is_err());
        r = request(&f);
        r.executable = "/usr/bin/../../bin/sh".into();
        assert!(sandbox_arguments(&r).is_err());
        r = request(&f);
        r.args = vec!["x".repeat(8193)];
        assert!(sandbox_arguments(&r).is_err());
        r = request(&f);
        r.output_limit = 1024 * 1024 + 1;
        assert!(sandbox_arguments(&r).is_err());
    }
    #[test]
    #[cfg(unix)]
    fn rejects_symlinks_and_hardlinks() {
        let f = Fixture::new();
        let external = Fixture::new();
        let file = external.0.join("source");
        std::fs::write(&file, "unchanged").unwrap();
        std::os::unix::fs::symlink(&file, f.0.join("link")).unwrap();
        assert!(sandbox_arguments(&request(&f)).is_err());
        std::fs::remove_file(f.0.join("link")).unwrap();
        std::fs::hard_link(&file, f.0.join("link")).unwrap();
        assert!(sandbox_arguments(&request(&f)).is_err());
        assert_eq!(std::fs::read_to_string(file).unwrap(), "unchanged");
    }
    /// One explicit opt-in capability/confinement probe. A failure is a blocker,
    /// not permission to fall back, elevate, or alter host namespace settings.
    #[test]
    #[ignore]
    #[cfg(target_os = "linux")]
    fn live_confinement_probe() {
        let f = Fixture::new();
        let outside = Fixture::new();
        std::fs::write(outside.0.join("source"), "unchanged").unwrap();
        let mut r = request(&f);
        r.args=vec!["-c".into(), format!("set -eu; test ! -e '{}'; test ! -e /home; test ! -e /etc; test -z \"${{AWS_ACCESS_KEY_ID:-}}\"; test -z \"${{OPENAI_API_KEY:-}}\"; test ! -e /proc/1/root{}; test $(grep -c ':' /proc/net/dev) -le 1; test $(wc -l < /proc/net/route) -eq 1; ! touch /usr/bin/wipstash-write-probe 2>/dev/null; printf repaired > /workspace/result; printf confined",outside.0.display(),outside.0.display())];
        let result = run(&r);
        assert_eq!(
            std::fs::read_to_string(outside.0.join("source")).unwrap(),
            "unchanged"
        );
        let output = result.unwrap_or_else(|e| panic!("LIVE CONFINEMENT UNVERIFIED: {e}"));
        assert_eq!(output.stdout, b"confined");
        assert_eq!(
            std::fs::read_to_string(f.0.join("result")).unwrap(),
            "repaired"
        );
    }
}
