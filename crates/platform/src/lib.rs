//! Native lifecycle primitives, not a security sandbox or client interception layer.
//! No caller-supplied boolean can enable confined repair. See docs/PLATFORM.md in the repository root.
use std::{
    ffi::OsString,
    io,
    path::PathBuf,
    time::{Duration, Instant},
};

pub mod git_path;
pub mod ipc;
#[cfg(unix)]
mod unix;
pub mod vault;
#[cfg(windows)]
mod windows;
#[cfg(any(windows, test))]
mod windows_command_line;
#[cfg(unix)]
use unix::Process;
#[cfg(windows)]
use windows::Process;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TreeContainment {
    CooperativeProcessGroup,
    WindowsJob,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Capabilities {
    pub tree_containment: TreeContainment,
    pub detached_descendants_contained: bool,
    pub controller_crash_kills_tree: bool,
    pub filesystem_isolated: bool,
    pub network_isolated: bool,
}
/// Describes the adapter, not a native release-validation certificate.
pub fn capabilities() -> Capabilities {
    Capabilities {
        tree_containment: if cfg!(windows) {
            TreeContainment::WindowsJob
        } else {
            TreeContainment::CooperativeProcessGroup
        },
        detached_descendants_contained: cfg!(windows),
        controller_crash_kills_tree: cfg!(windows),
        filesystem_isolated: false,
        network_isolated: false,
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Purpose {
    CooperativeCommand,
    EnforcedWholeSession,
    ConfinedModelRepair,
}

#[derive(Debug, Clone)]
pub struct Launch {
    /// Absolute executable path. No shell parsing or PATH lookup.
    pub executable: PathBuf,
    pub arguments: Vec<OsString>,
    pub directory: PathBuf,
    /// Explicit environment allowlist; inherited environment is discarded.
    pub environment: Vec<(OsString, OsString)>,
    pub purpose: Purpose,
}
impl Launch {
    fn validate(&self) -> io::Result<()> {
        if !self.executable.is_absolute() || !self.directory.is_absolute() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "absolute executable and working directory required",
            ));
        }
        let mut environment_keys = std::collections::BTreeSet::new();
        for (key, value) in &self.environment {
            if key.is_empty()
                || key.to_string_lossy().contains(['=', '\0'])
                || value.to_string_lossy().contains('\0')
                || !environment_keys.insert(if cfg!(windows) {
                    key.to_string_lossy().to_uppercase()
                } else {
                    key.to_string_lossy().into_owned()
                })
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "invalid environment entry",
                ));
            }
        }
        match self.purpose {
            Purpose::ConfinedModelRepair => Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "repair_unavailable: no verified filesystem/network confinement backend",
            )),
            Purpose::EnforcedWholeSession if !capabilities().detached_descendants_contained => {
                Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "whole_session_unavailable: detached descendants are not contained",
                ))
            }
            _ => Ok(()),
        }
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Completion {
    Exited { code: Option<i32> },
    TimedOut,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DrainEvidence {
    /// No containment proof. Never use this to authorize capture/adoption.
    CooperativeOnly,
    /// Job query observed zero active processes after successful termination.
    WindowsJobEmpty,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Outcome {
    pub completion: Completion,
    pub drain: DrainEvidence,
}

/// Owns its process resources. Dropping requests cleanup, but only a successful
/// `finish` returns drain evidence. Persist intent BEFORE `spawn`, and persist the
/// outcome BEFORE releasing a writer lease. Errors keep the lease fenced.
pub type OutputReader = Box<dyn io::Read + Send>;

pub struct ManagedProcess {
    inner: Process,
}
impl ManagedProcess {
    pub fn spawn(launch: &Launch) -> io::Result<Self> {
        launch.validate()?;
        Ok(Self {
            inner: Process::spawn(launch, false)?,
        })
    }
    /// Capture stdout/stderr through private pipes. Drain both concurrently before
    /// finish to avoid pipe-buffer deadlock. This does not grant sandboxing.
    pub fn spawn_piped(launch: &Launch) -> io::Result<Self> {
        launch.validate()?;
        Ok(Self {
            inner: Process::spawn(launch, true)?,
        })
    }
    pub fn take_output(&mut self) -> Option<(OutputReader, OutputReader)> {
        self.inner.take_output()
    }
    /// The timeout includes waiting for the root. Descendants are terminated on
    /// root exit, not allowed to keep writing after completion.
    pub fn finish(mut self, timeout: Duration) -> io::Result<Outcome> {
        let started = Instant::now();
        loop {
            if let Some(code) = self.inner.poll()? {
                let drain = self.inner.drain()?;
                return Ok(Outcome {
                    completion: Completion::Exited { code },
                    drain,
                });
            }
            if started.elapsed() >= timeout {
                let drain = self.inner.drain()?;
                return Ok(Outcome {
                    completion: Completion::TimedOut,
                    drain,
                });
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn launch(purpose: Purpose) -> Launch {
        Launch {
            executable: PathBuf::from(if cfg!(windows) {
                r"C:\Windows\System32\cmd.exe"
            } else {
                "/bin/sh"
            }),
            arguments: vec![],
            directory: std::env::current_dir().unwrap(),
            environment: vec![],
            purpose,
        }
    }
    #[test]
    fn repair_is_unavailable_even_on_job_platform() {
        assert_eq!(
            launch(Purpose::ConfinedModelRepair)
                .validate()
                .unwrap_err()
                .kind(),
            io::ErrorKind::Unsupported
        );
        assert!(!capabilities().filesystem_isolated);
        assert!(!capabilities().network_isolated);
    }
    #[test]
    fn relative_launch_rejected() {
        let mut spec = launch(Purpose::CooperativeCommand);
        spec.executable = "sh".into();
        assert_eq!(
            spec.validate().unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
    }
    #[cfg(unix)]
    #[test]
    fn unix_cannot_authorize_enforced_session() {
        assert!(launch(Purpose::EnforcedWholeSession).validate().is_err());
        assert!(!capabilities().detached_descendants_contained);
        assert!(!capabilities().controller_crash_kills_tree);
    }
    #[test]
    fn duplicate_environment_is_rejected() {
        let mut spec = launch(Purpose::CooperativeCommand);
        spec.environment = vec![("A".into(), "one".into()), ("A".into(), "two".into())];
        assert_eq!(
            spec.validate().unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
    }
    #[test]
    fn invalid_environment_is_rejected() {
        for key in ["", "A=B", "A\0B"] {
            let mut spec = launch(Purpose::CooperativeCommand);
            spec.environment = vec![(key.into(), "value".into())];
            assert!(spec.validate().is_err());
        }
    }
    #[cfg(windows)]
    fn windows_output(spec: &Launch) -> (Outcome, String, String) {
        use std::io::Read;
        let mut process = ManagedProcess::spawn_piped(spec).unwrap();
        let (mut out, mut err) = process.take_output().unwrap();
        let stdout = std::thread::spawn(move || {
            let mut bytes = Vec::new();
            out.read_to_end(&mut bytes).unwrap();
            bytes
        });
        let stderr = std::thread::spawn(move || {
            let mut bytes = Vec::new();
            err.read_to_end(&mut bytes).unwrap();
            bytes
        });
        let outcome = process.finish(Duration::from_secs(5)).unwrap();
        (
            outcome,
            String::from_utf8_lossy(&stdout.join().unwrap()).into_owned(),
            String::from_utf8_lossy(&stderr.join().unwrap()).into_owned(),
        )
    }
    #[cfg(windows)]
    #[test]
    fn native_piped_output() {
        let mut spec = launch(Purpose::CooperativeCommand);
        spec.arguments = vec![
            "/D".into(),
            "/C".into(),
            "echo output& echo error 1>&2& exit 0".into(),
        ];
        // An empty allowlist must work without silently inheriting the host's
        // environment. Also exercise the explicit SystemRoot configuration.
        for environment in [
            vec![],
            vec![("SystemRoot".into(), std::env::var_os("SystemRoot").unwrap())],
        ] {
            spec.environment = environment;
            let (outcome, stdout, stderr) = windows_output(&spec);
            assert_eq!(outcome.drain, DrainEvidence::WindowsJobEmpty);
            assert_eq!(
                outcome.completion,
                Completion::Exited { code: Some(0) },
                "stdout: {stdout:?}; stderr: {stderr:?}"
            );
            assert!(
                stdout.contains("output"),
                "stdout: {stdout:?}; stderr: {stderr:?}"
            );
            assert!(
                stderr.contains("error"),
                "stdout: {stdout:?}; stderr: {stderr:?}"
            );
        }
    }
    #[cfg(windows)]
    #[test]
    fn native_job_reports_drained_after_exit() {
        let mut spec = launch(Purpose::EnforcedWholeSession);
        spec.arguments = vec!["/D".into(), "/C".into(), "exit 7".into()];
        let (outcome, stdout, stderr) = windows_output(&spec);
        assert_eq!(
            outcome.completion,
            Completion::Exited { code: Some(7) },
            "stdout: {stdout:?}; stderr: {stderr:?}"
        );
        assert_eq!(outcome.drain, DrainEvidence::WindowsJobEmpty);
        // Keep exercising the no-inherited-handles path as well as the piped
        // path above, whose output makes command-line failures diagnosable.
        let uncaptured = ManagedProcess::spawn(&spec)
            .unwrap()
            .finish(Duration::from_secs(5))
            .unwrap();
        assert_eq!(
            uncaptured, outcome,
            "captured stdout: {stdout:?}; stderr: {stderr:?}"
        );
    }
    #[cfg(windows)]
    const WINDOWS_ARGV_CASES: &[&str] = &[
        "plain-value",
        "value with spaces",
        "value\twith tab",
        "embedded\"quote",
        "trailing\\",
        "space trailing\\",
        "slash\\\"quote",
        "雪-value",
    ];
    #[cfg(windows)]
    #[test]
    fn native_windows_argv_child() {
        if std::env::var_os("WIPSTASH_ARGV_CHILD").is_none() {
            return;
        }
        // libtest accepts repeated --skip arguments, letting this child inspect
        // real CRT/Rust decoding without needing a separate fixture executable.
        let actual: Vec<_> = std::env::args().skip(4).collect();
        let expected: Vec<_> = WINDOWS_ARGV_CASES
            .iter()
            .flat_map(|value| ["--skip".to_owned(), (*value).to_owned()])
            .collect();
        assert_eq!(actual, expected);
    }
    #[cfg(windows)]
    #[test]
    fn native_windows_argv_round_trip() {
        let mut spec = launch(Purpose::EnforcedWholeSession);
        spec.executable = std::env::current_exe().unwrap();
        spec.arguments = vec![
            "--exact".into(),
            "tests::native_windows_argv_child".into(),
            "--nocapture".into(),
        ];
        for value in WINDOWS_ARGV_CASES {
            spec.arguments.extend(["--skip".into(), (*value).into()]);
        }
        spec.environment = vec![("WIPSTASH_ARGV_CHILD".into(), "1".into())];
        let (outcome, stdout, stderr) = windows_output(&spec);
        assert_eq!(
            outcome.completion,
            Completion::Exited { code: Some(0) },
            "stdout: {stdout:?}; stderr: {stderr:?}"
        );
        assert!(
            stdout.contains("1 passed"),
            "child did not run: {stdout:?}; {stderr:?}"
        );
        assert_eq!(outcome.drain, DrainEvidence::WindowsJobEmpty);
    }
    #[cfg(unix)]
    #[test]
    fn cooperative_exit_and_timeout() {
        let mut spec = launch(Purpose::CooperativeCommand);
        spec.arguments = vec!["-c".into(), "exit 7".into()];
        let outcome = ManagedProcess::spawn(&spec)
            .expect("spawn cooperative exit command")
            .finish(Duration::from_secs(3))
            .expect("observe exit and drain unreaped cooperative group");
        assert_eq!(
            outcome,
            Outcome {
                completion: Completion::Exited { code: Some(7) },
                drain: DrainEvidence::CooperativeOnly
            }
        );
        spec.arguments = vec!["-c".into(), "sleep 10".into()];
        let outcome = ManagedProcess::spawn(&spec)
            .expect("spawn cooperative timeout command")
            .finish(Duration::from_millis(20))
            .expect("terminate and drain timed-out cooperative group");
        assert_eq!(outcome.completion, Completion::TimedOut);
        assert_eq!(outcome.drain, DrainEvidence::CooperativeOnly);
    }
}
