//! Windows 10 / Server 2016+ job-list process creation. No fallback to an
//! uncontained process when a parent job or OS restriction prevents assignment.
use crate::{DrainEvidence, Launch};
use std::{
    ffi::OsStr,
    fs::File,
    io,
    mem::{size_of, zeroed},
    os::windows::{
        ffi::OsStrExt,
        io::{AsRawHandle, BorrowedHandle, FromRawHandle},
    },
    ptr::{null, null_mut},
    time::{Duration, Instant},
};
use windows_sys::Win32::{
    Foundation::*,
    Security::*,
    System::{
        JobObjects::*,
        Pipes::{CreatePipe, ImpersonateNamedPipeClient},
        Threading::*,
    },
};

struct Handle(HANDLE);
impl Drop for Handle {
    fn drop(&mut self) {
        unsafe {
            CloseHandle(self.0);
        }
    }
}
fn checked(value: i32) -> io::Result<()> {
    if value == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}
fn wide(value: &OsStr) -> io::Result<Vec<u16>> {
    let mut result: Vec<_> = value.encode_wide().collect();
    if result.contains(&0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "NUL in Windows argument",
        ));
    }
    result.push(0);
    Ok(result)
}
// Anonymous pipe readers are deliberately non-inheritable. RAII closes every
// handle on all setup failures. stdin has no writer, so reads receive EOF.
fn pipe() -> io::Result<(Handle, Handle)> {
    let security = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: null_mut(),
        bInheritHandle: 1,
    };
    let (mut read, mut write) = (null_mut(), null_mut());
    checked(unsafe { CreatePipe(&mut read, &mut write, &security, 0) })?;
    Ok((Handle(read), Handle(write)))
}
fn reader(handle: Handle) -> io::Result<File> {
    checked(unsafe { SetHandleInformation(handle.0, HANDLE_FLAG_INHERIT, 0) })?;
    let file = unsafe { File::from_raw_handle(handle.0) };
    std::mem::forget(handle);
    Ok(file)
}
struct StdioPipes {
    stdin: Handle,
    stdout: Handle,
    stderr: Handle,
    out_read: File,
    err_read: File,
}
impl StdioPipes {
    fn new() -> io::Result<Self> {
        let (stdin, input_writer) = pipe()?;
        drop(input_writer);
        let (out_read, stdout) = pipe()?;
        let (err_read, stderr) = pipe()?;
        Ok(Self {
            stdin,
            stdout,
            stderr,
            out_read: reader(out_read)?,
            err_read: reader(err_read)?,
        })
    }
}
struct Attributes {
    storage: Vec<usize>,
}
impl Attributes {
    fn new(job: &mut HANDLE, handles: &mut [HANDLE]) -> io::Result<Self> {
        let mut bytes = 0;
        unsafe {
            InitializeProcThreadAttributeList(
                null_mut(),
                if handles.is_empty() { 1 } else { 2 },
                0,
                &mut bytes,
            );
        }
        if bytes == 0 {
            return Err(io::Error::last_os_error());
        }
        let mut storage = vec![0usize; bytes.div_ceil(size_of::<usize>())];
        checked(unsafe {
            InitializeProcThreadAttributeList(
                storage.as_mut_ptr().cast(),
                if handles.is_empty() { 1 } else { 2 },
                0,
                &mut bytes,
            )
        })?;
        let mut result = Self { storage };
        checked(unsafe {
            UpdateProcThreadAttribute(
                result.pointer(),
                0,
                PROC_THREAD_ATTRIBUTE_JOB_LIST as usize,
                (job as *mut HANDLE).cast(),
                size_of::<HANDLE>(),
                null_mut(),
                null_mut(),
            )
        })?;
        if !handles.is_empty() {
            checked(unsafe {
                UpdateProcThreadAttribute(
                    result.pointer(),
                    0,
                    PROC_THREAD_ATTRIBUTE_HANDLE_LIST as usize,
                    handles.as_mut_ptr().cast(),
                    std::mem::size_of_val(handles),
                    null_mut(),
                    null_mut(),
                )
            })?;
        }
        Ok(result)
    }
    fn pointer(&mut self) -> LPPROC_THREAD_ATTRIBUTE_LIST {
        self.storage.as_mut_ptr().cast()
    }
}
impl Drop for Attributes {
    fn drop(&mut self) {
        unsafe {
            DeleteProcThreadAttributeList(self.pointer());
        }
    }
}

pub(crate) struct Process {
    job: Handle,
    process: Handle,
    drained: bool,
    output: Option<(File, File)>,
}
impl Process {
    pub fn spawn(spec: &Launch, capture: bool) -> io::Result<Self> {
        let raw_job = unsafe { CreateJobObjectW(null(), null()) };
        if raw_job.is_null() {
            return Err(io::Error::last_os_error());
        }
        let job = Handle(raw_job);
        let mut limits: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { zeroed() };
        // Neither BREAKAWAY_OK nor SILENT_BREAKAWAY_OK is permitted.
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        checked(unsafe {
            SetInformationJobObject(
                job.0,
                JobObjectExtendedLimitInformation,
                (&limits as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
                size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            )
        })?;
        // Inherit only these three stdio handles, never unrelated process handles.
        let pipes = if capture {
            Some(StdioPipes::new()?)
        } else {
            None
        };
        let mut handles = pipes
            .as_ref()
            .map(|p| vec![p.stdin.0, p.stdout.0, p.stderr.0])
            .unwrap_or_default();
        let mut job_value = job.0;
        let mut attributes = Attributes::new(&mut job_value, &mut handles)?;
        let mut startup: STARTUPINFOEXW = unsafe { zeroed() };
        startup.StartupInfo.cb = size_of::<STARTUPINFOEXW>() as u32;
        startup.lpAttributeList = attributes.pointer();
        if let Some(pipes) = &pipes {
            startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
            startup.StartupInfo.hStdInput = pipes.stdin.0;
            startup.StartupInfo.hStdOutput = pipes.stdout.0;
            startup.StartupInfo.hStdError = pipes.stderr.0;
        }
        let application = wide(spec.executable.as_os_str())?;
        let directory = wide(spec.directory.as_os_str())?;
        // Explicit lpApplicationName prevents ambiguous executable resolution.
        let mut command = crate::windows_command_line::quote(&application[..application.len() - 1]);
        for arg in &spec.arguments {
            command.push(b' ' as u16);
            let arg = wide(arg)?;
            command.extend(crate::windows_command_line::quote(&arg[..arg.len() - 1]));
        }
        command.push(0);
        if command.len() > 32767 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Windows command line too long",
            ));
        }
        let mut environment = Vec::new();
        let mut entries = spec.environment.clone();
        entries.sort_by_key(|(key, _)| key.to_string_lossy().to_uppercase());
        for (key, value) in entries {
            let key = wide(&key)?;
            environment.extend_from_slice(&key[..key.len() - 1]);
            environment.push(b'=' as u16);
            environment.extend(wide(&value)?);
        }
        environment.push(0);
        if environment.len() == 1 {
            environment.push(0);
        }
        let mut information: PROCESS_INFORMATION = unsafe { zeroed() };
        checked(unsafe {
            CreateProcessW(
                application.as_ptr(),
                command.as_mut_ptr(),
                null(),
                null(),
                i32::from(capture),
                EXTENDED_STARTUPINFO_PRESENT | CREATE_UNICODE_ENVIRONMENT | CREATE_NO_WINDOW,
                environment.as_ptr().cast(),
                directory.as_ptr(),
                &startup.StartupInfo,
                &mut information,
            )
        })?;
        let _thread = Handle(information.hThread);
        Ok(Self {
            job,
            process: Handle(information.hProcess),
            drained: false,
            output: pipes.map(|p| (p.out_read, p.err_read)),
        })
    }
    pub fn take_output(&mut self) -> Option<(crate::OutputReader, crate::OutputReader)> {
        self.output.take().map(|(out, err)| {
            (
                Box::new(out) as crate::OutputReader,
                Box::new(err) as crate::OutputReader,
            )
        })
    }
    pub fn poll(&mut self) -> io::Result<Option<Option<i32>>> {
        match unsafe { WaitForSingleObject(self.process.0, 0) } {
            WAIT_TIMEOUT => Ok(None),
            WAIT_OBJECT_0 => {
                let mut code = 0;
                checked(unsafe { GetExitCodeProcess(self.process.0, &mut code) })?;
                Ok(Some(Some(code as i32)))
            }
            _ => Err(io::Error::last_os_error()),
        }
    }
    pub fn drain(&mut self) -> io::Result<DrainEvidence> {
        if !self.drained {
            checked(unsafe { TerminateJobObject(self.job.0, 1) })?;
            let deadline = Instant::now() + Duration::from_secs(5);
            loop {
                let mut accounting: JOBOBJECT_BASIC_ACCOUNTING_INFORMATION = unsafe { zeroed() };
                checked(unsafe {
                    QueryInformationJobObject(
                        self.job.0,
                        JobObjectBasicAccountingInformation,
                        (&mut accounting as *mut JOBOBJECT_BASIC_ACCOUNTING_INFORMATION).cast(),
                        size_of::<JOBOBJECT_BASIC_ACCOUNTING_INFORMATION>() as u32,
                        null_mut(),
                    )
                })?;
                if accounting.ActiveProcesses == 0 {
                    break;
                }
                if Instant::now() >= deadline {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "job drain unverified; keep writer lease fenced",
                    ));
                }
                std::thread::sleep(Duration::from_millis(5));
            }
            self.drained = true;
        }
        Ok(DrainEvidence::WindowsJobEmpty)
    }
}
// Closing the sole noninheritable job handle is the crash/drop backstop.
impl Drop for Process {
    fn drop(&mut self) {
        if !self.drained {
            unsafe {
                TerminateJobObject(self.job.0, 1);
            }
        }
    }
}

/// Returns the kernel-authenticated user's binary SID for an already-connected
/// server pipe, after its request has been read. Call synchronously on a dedicated
/// OS thread, never across async suspension. The endpoint must separately reject
/// remote clients and use an owner-restricted DACL. This does not create a pipe.
pub fn pipe_peer_sid(pipe: BorrowedHandle<'_>) -> io::Result<Vec<u8>> {
    checked(unsafe { ImpersonateNamedPipeClient(pipe.as_raw_handle()) })?;
    struct Revert;
    impl Drop for Revert {
        fn drop(&mut self) {
            // Continuing under an unexpected client token is unsafe.
            if unsafe { RevertToSelf() } == 0 {
                std::process::abort();
            }
        }
    }
    let _revert = Revert;
    let mut token = null_mut();
    checked(unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, &mut token) })?;
    let token = Handle(token);
    let mut bytes = 0;
    unsafe {
        GetTokenInformation(token.0, TokenUser, null_mut(), 0, &mut bytes);
    }
    if bytes == 0 {
        return Err(io::Error::last_os_error());
    }
    let mut storage = vec![0usize; (bytes as usize).div_ceil(size_of::<usize>())];
    checked(unsafe {
        GetTokenInformation(
            token.0,
            TokenUser,
            storage.as_mut_ptr().cast(),
            bytes,
            &mut bytes,
        )
    })?;
    let user = unsafe { &*storage.as_ptr().cast::<TOKEN_USER>() };
    if unsafe { IsValidSid(user.User.Sid) } == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid pipe caller SID",
        ));
    }
    let length = unsafe { GetLengthSid(user.User.Sid) } as usize;
    Ok(unsafe { std::slice::from_raw_parts(user.User.Sid.cast::<u8>(), length) }.to_vec())
}
