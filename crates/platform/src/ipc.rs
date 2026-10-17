//! Identity of an already-connected local transport. This module does not bind,
//! create, discover, or grant permissions to any endpoint.
#[cfg(unix)]
use std::{
    io,
    os::{fd::AsRawFd, unix::net::UnixStream},
};
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnixPeer {
    pub uid: u32,
    pub gid: u32,
    pub pid: Option<u32>,
}
impl UnixPeer {
    /// Authentication of a local OS account only; not device/project authority.
    pub fn require_uid(&self, expected: u32) -> std::io::Result<()> {
        if self.uid == expected {
            Ok(())
        } else {
            Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "local peer owner mismatch",
            ))
        }
    }
}
#[cfg(target_os = "linux")]
pub fn unix_peer(stream: &UnixStream) -> io::Result<UnixPeer> {
    let mut credentials: libc::ucred = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    let result = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&mut credentials as *mut libc::ucred).cast(),
            &mut len,
        )
    };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    if len as usize != std::mem::size_of::<libc::ucred>() || credentials.pid <= 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid kernel peer credentials",
        ));
    }
    Ok(UnixPeer {
        uid: credentials.uid,
        gid: credentials.gid,
        pid: Some(credentials.pid as u32),
    })
}
#[cfg(target_os = "macos")]
pub fn unix_peer(stream: &UnixStream) -> io::Result<UnixPeer> {
    let mut uid = 0;
    let mut gid = 0;
    if unsafe { libc::getpeereid(stream.as_raw_fd(), &mut uid, &mut gid) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(UnixPeer {
        uid,
        gid,
        pid: None,
    })
}
#[cfg(windows)]
pub use crate::windows::pipe_peer_sid;

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn authorization_is_exact_uid() {
        let identity = UnixPeer {
            uid: 42,
            gid: 7,
            pid: None,
        };
        assert!(identity.require_uid(42).is_ok());
        assert_eq!(
            identity.require_uid(7).unwrap_err().kind(),
            std::io::ErrorKind::PermissionDenied
        );
    }
    // No socket fixtures run here: the task environment denied socket bind.
    // Native CI must test actual connected endpoint credentials separately.
}
