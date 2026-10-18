//! Narrow process-boundary adaptation for Git for Windows. Never use the
//! returned path in place of filesystem validation or canonical identity.
use std::{
    io,
    path::{Path, PathBuf},
};

/// Git for Windows does not consistently accept Rust's canonical `\\?\C:\...`
/// arguments. Convert only unambiguous local drive paths within the traditional
/// Win32 directory bound. UNC/device namespaces and names whose interpretation
/// could change without the verbatim prefix fail closed. Unix is unchanged.
pub fn argument(path: &Path) -> io::Result<PathBuf> {
    #[cfg(not(windows))]
    {
        Ok(path.to_path_buf())
    }
    #[cfg(windows)]
    {
        use std::{
            os::windows::ffi::OsStrExt,
            path::{Component, Prefix},
        };
        let absolute = if path.is_absolute() {
            path.to_path_buf()
        } else {
            std::env::current_dir()?.join(path)
        };
        let reject = || {
            io::Error::new(io::ErrorKind::InvalidInput, "unsupported_git_path: require an unambiguous local drive path shorter than 248 UTF-16 units")
        };
        // Normal (non-verbatim) Path components may normalize away interior
        // dots. Reject them lexically as well instead of silently simplifying.
        let raw: Vec<u16> = absolute.as_os_str().encode_wide().collect();
        if raw
            .split(|c| matches!(*c, 47 | 92))
            .any(|part| part == [46] || part == [46, 46])
        {
            return Err(reject());
        }
        let mut parts = absolute.components();
        let drive = match parts.next() {
            Some(Component::Prefix(p)) => match p.kind() {
                Prefix::Disk(d) | Prefix::VerbatimDisk(d) => d,
                _ => return Err(reject()),
            },
            _ => return Err(reject()),
        };
        if !matches!(parts.next(), Some(Component::RootDir)) {
            return Err(reject());
        }
        let mut result = PathBuf::from(format!("{}:\\", drive as char));
        for part in parts {
            match part {
                Component::Normal(name)
                    if safe_component(&name.encode_wide().collect::<Vec<_>>()) =>
                {
                    result.push(name)
                }
                _ => return Err(reject()),
            }
        }
        if result.as_os_str().encode_wide().count() >= 248 {
            return Err(reject());
        }
        Ok(result)
    }
}

#[cfg(any(windows, test))]
fn safe_component(name: &[u16]) -> bool {
    if String::from_utf16(name).is_err()
        || name.is_empty()
        || matches!(name.last(), Some(32 | 46))
        || name
            .iter()
            .any(|c| *c < 32 || matches!(*c, 34 | 42 | 47 | 58 | 60 | 62 | 63 | 92 | 124))
    {
        return false;
    }
    let stem = name.split(|c| *c == 46).next().unwrap();
    let stem = String::from_utf16_lossy(stem)
        .trim_matches(' ')
        .to_ascii_uppercase();
    if matches!(
        stem.as_str(),
        "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$"
    ) {
        return false;
    }
    for prefix in ["COM", "LPT"] {
        if let Some(suffix) = stem.strip_prefix(prefix) {
            if matches!(
                suffix,
                "0" | "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9" | "¹" | "²" | "³"
            ) {
                return false;
            }
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_windows_alias_components() {
        assert!(!safe_component(&[0xd800]));
        for bad in [
            "",
            ".",
            "..",
            "dir.",
            "dir ",
            "file:stream",
            "NUL",
            "con.txt",
            "NUL .txt",
            "COM0",
            " LPT1.txt",
            "COM1.log",
            "LPT²",
            "CONOUT$",
            "a\\b",
            "a/b",
            "a?b",
            "a\0b",
        ] {
            assert!(
                !safe_component(&bad.encode_utf16().collect::<Vec<_>>()),
                "{bad:?}"
            );
        }
        for good in [
            "directory",
            "space inside",
            "COM10",
            "unicode-é",
            "file.txt",
        ] {
            assert!(
                safe_component(&good.encode_utf16().collect::<Vec<_>>()),
                "{good:?}"
            );
        }
    }
    #[cfg(windows)]
    #[test]
    fn converts_only_safe_local_process_arguments() {
        assert_eq!(
            argument(Path::new(r"\\?\C:\Users\name\repo")).unwrap(),
            PathBuf::from(r"C:\Users\name\repo")
        );
        assert_eq!(
            argument(Path::new(r"C:\Users\name\repo")).unwrap(),
            PathBuf::from(r"C:\Users\name\repo")
        );
        for bad in [
            r"\\server\share\repo",
            r"\\?\UNC\server\share\repo",
            r"\\.\C:\repo",
            r"\\?\C:\repo.",
            r"\\?\C:\repo ",
            r"\\?\C:\NUL\repo",
            r"\\?\C:\repo:stream",
            r"\\?\C:\a\..\b",
            r"C:\a\.\b",
        ] {
            assert!(argument(Path::new(bad)).is_err(), "{bad}");
        }
        assert!(argument(Path::new(&format!(r"\\?\C:\{}", "a".repeat(245)))).is_err());
    }
    #[cfg(not(windows))]
    #[test]
    fn unix_arguments_are_unchanged() {
        for path in [
            "relative",
            "/tmp/trailing.",
            "/tmp/with space",
            "//host/path",
        ] {
            assert_eq!(argument(Path::new(path)).unwrap(), PathBuf::from(path));
        }
    }
}
