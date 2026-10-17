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
                if err.raw_os_error() != Some(libc::ESRCH) {
                    return Err(err);
                }
            }
            self.child.wait()?;
            self.drained = true;
        }
        Ok(DrainEvidence::CooperativeOnly)
    }
}
impl Drop for Process {
    fn drop(&mut self) {
        let _ = self.drain();
    }
}
