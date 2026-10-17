use crate::{DrainEvidence, Launch};
use std::{
    io,
    os::unix::process::CommandExt,
    process::{Child, Command, Stdio},
};

pub(crate) struct Process {
    child: Child,
    drained: bool,
}
impl Process {
    pub fn spawn(spec: &Launch, capture: bool) -> io::Result<Self> {
        let child = Command::new(&spec.executable)
            .args(&spec.arguments)
            .current_dir(&spec.directory)
            .env_clear()
            .envs(spec.environment.iter().cloned())
            .stdin(Stdio::null())
            .stdout(if capture {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stderr(if capture {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .process_group(0)
            .spawn()?;
        Ok(Self {
            child,
            drained: false,
        })
    }
    pub fn take_output(&mut self) -> Option<(crate::OutputReader, crate::OutputReader)> {
        Some((
            Box::new(self.child.stdout.take()?),
            Box::new(self.child.stderr.take()?),
        ))
    }
    /// Observe without reaping. Keeping the child PID allocated prevents reuse
    /// before the group signal. Never replace this with Child::try_wait().
    pub fn poll(&mut self) -> io::Result<Option<Option<i32>>> {
        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        let result = unsafe {
            libc::waitid(
                libc::P_PID,
                self.child.id(),
                &mut info,
                libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
            )
        };
        if result != 0 {
            return Err(io::Error::last_os_error());
        }
        if unsafe { info.si_pid() } == 0 {
            return Ok(None);
        }
        Ok(Some(if info.si_code == libc::CLD_EXITED {
            Some(unsafe { info.si_status() })
        } else {
            None
        }))
    }
    pub fn drain(&mut self) -> io::Result<DrainEvidence> {
        if !self.drained {
            // SIGKILL covers ordinary group members only. setsid/setpgid escapes
            // remain possible. Do not convert this to containment evidence.
            let result = unsafe { libc::kill(-(self.child.id() as i32), libc::SIGKILL) };
            if result != 0 {
                let err = io::Error::last_os_error();
                if !self.benign_group_signal_error(&err)? {
                    return Err(err);
                }
            }
            self.child.wait()?;
            self.drained = true;
        }
        Ok(DrainEvidence::CooperativeOnly)
    }

    fn benign_group_signal_error(&mut self, error: &io::Error) -> io::Result<bool> {
        if error.raw_os_error() == Some(libc::ESRCH) {
            return Ok(true);
        }
        #[cfg(target_os = "macos")]
        if error.raw_os_error() == Some(libc::EPERM) && self.poll()?.is_some() {
            // Darwin's killpg1 excludes SZOMB members and returns EPERM if
            // nothing remains eligible. Do not ignore general EPERM: prove
            // the unreaped leader is the ONLY member, including zombies.
            // WNOWAIT keeps its PID/PGID reserved throughout this check.
            // Source: apple-oss-distributions/xnu, bsd/kern/kern_sig.c,
            // killpg1; bsd/kern/proc_info.c, proc_listpids.
            let leader = self.child.id() as libc::pid_t;
            let mut members = [0 as libc::pid_t; 2];
            let count = unsafe {
                libc::proc_listpgrppids(
                    leader,
                    members.as_mut_ptr().cast(),
                    std::mem::size_of_val(&members) as libc::c_int,
                )
            };
            // libproc returns a PID count (not bytes), with zero also used
            // for errors. Two slots distinguish a singleton from truncation.
            // Any query failure or additional member preserves the EPERM.
            return Ok(sole_unreaped_leader(leader, count, &members));
        }
        Ok(false)
    }
}

#[cfg(any(target_os = "macos", test))]
fn sole_unreaped_leader(leader: libc::pid_t, count: i32, members: &[libc::pid_t; 2]) -> bool {
    count == 1 && members[0] == leader
}

impl Drop for Process {
    fn drop(&mut self) {
        let _ = self.drain();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zombie_group_exception_requires_a_complete_singleton_snapshot() {
        assert!(sole_unreaped_leader(123, 1, &[123, 0]));
        for count in [-1, 0, 2, 3, std::mem::size_of::<libc::pid_t>() as i32] {
            assert!(!sole_unreaped_leader(123, count, &[123, 456]));
        }
        assert!(!sole_unreaped_leader(123, 1, &[456, 0]));
        assert!(!sole_unreaped_leader(123, 2, &[456, 123]));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn native_unreaped_singleton_drains_without_releasing_pid_early() {
        let spec = Launch {
            executable: "/bin/sh".into(),
            arguments: vec!["-c".into(), "exit 7".into()],
            directory: std::env::temp_dir(),
            environment: vec![],
            purpose: crate::Purpose::CooperativeCommand,
        };
        let mut process = Process::spawn(&spec, false).expect("spawn singleton");
        let started = std::time::Instant::now();
        while process.poll().expect("observe without reaping").is_none() {
            assert!(started.elapsed() < std::time::Duration::from_secs(5));
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        assert_eq!(process.poll().unwrap(), Some(Some(7)));
        let mut members = [0 as libc::pid_t; 2];
        let count = unsafe {
            libc::proc_listpgrppids(
                process.child.id() as libc::pid_t,
                members.as_mut_ptr().cast(),
                std::mem::size_of_val(&members) as libc::c_int,
            )
        };
        assert_eq!(count, 1, "libproc returns a count, not a byte length");
        assert_eq!(members[0], process.child.id() as libc::pid_t);
        assert!(process
            .benign_group_signal_error(&io::Error::from_raw_os_error(libc::EPERM))
            .unwrap());
        assert!(!process
            .benign_group_signal_error(&io::Error::from_raw_os_error(libc::EACCES))
            .unwrap());
        assert_eq!(process.poll().unwrap(), Some(Some(7)));
        assert_eq!(process.drain().unwrap(), DrainEvidence::CooperativeOnly);
        assert_eq!(process.drain().unwrap(), DrainEvidence::CooperativeOnly);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn native_exited_leader_with_live_group_member_does_not_excuse_eperm() {
        let spec = Launch {
            executable: "/bin/sh".into(),
            arguments: vec!["-c".into(), "/bin/sleep 10 & exit 7".into()],
            directory: std::env::temp_dir(),
            environment: vec![],
            purpose: crate::Purpose::CooperativeCommand,
        };
        let mut process = Process::spawn(&spec, false).expect("spawn group with descendant");
        let started = std::time::Instant::now();
        while process.poll().expect("observe without reaping").is_none() {
            assert!(started.elapsed() < std::time::Duration::from_secs(5));
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        assert!(!process
            .benign_group_signal_error(&io::Error::from_raw_os_error(libc::EPERM))
            .unwrap());
        assert_eq!(process.poll().unwrap(), Some(Some(7)));
        assert_eq!(process.drain().unwrap(), DrainEvidence::CooperativeOnly);
    }
}
