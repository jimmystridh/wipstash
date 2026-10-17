//! Test-only, explicitly selected VFS. No default VFS or production connection is changed.
//! Faults are one-shot and local to the calling test thread; connections must stay on
//! that thread while armed. This tests SQLite's error path, not power-loss durability.
use rusqlite::{ffi, Connection, OpenFlags};
use std::{
    cell::Cell,
    ffi::{c_char, c_int, c_void},
    path::Path,
    ptr,
    sync::Once,
};

thread_local! {
    static COUNTDOWN: Cell<Option<usize>> = const { Cell::new(None) };
    static FAILURES: Cell<usize> = const { Cell::new(0) };
    static SYNCS: Cell<usize> = const { Cell::new(0) };
}
pub(super) struct FaultGuard;
impl Drop for FaultGuard {
    fn drop(&mut self) {
        disarm();
    }
}
/// Fail the xSync after `successful_syncs` forwarded sync calls.
pub(super) fn fail_sync_after(successful_syncs: usize) -> FaultGuard {
    COUNTDOWN.with(|v| v.set(Some(successful_syncs)));
    FAILURES.with(|v| v.set(0));
    SYNCS.with(|v| v.set(0));
    FaultGuard
}
pub(super) fn disarm() {
    COUNTDOWN.with(|v| v.set(None));
}
fn failures() -> usize {
    FAILURES.with(Cell::get)
}
fn syncs() -> usize {
    SYNCS.with(Cell::get)
}
const NAME: &str = "wipstash-test-sync-fault";
static REGISTER: Once = Once::new();

pub(super) fn open(path: impl AsRef<Path>) -> rusqlite::Result<Connection> {
    REGISTER.call_once(|| unsafe {
        assert_eq!(ffi::sqlite3_initialize(), ffi::SQLITE_OK);
        let real = ffi::sqlite3_vfs_find(ptr::null());
        assert!(!real.is_null());
        // SQLite retains the registered VFS for process lifetime. This single small
        // allocation is intentional; no connection can outlive its callbacks.
        let mut vfs = Box::new(ptr::read(real));
        vfs.zName = c"wipstash-test-sync-fault".as_ptr();
        vfs.pNext = ptr::null_mut();
        vfs.pAppData = real.cast();
        vfs.szOsFile = std::mem::size_of::<File>() as c_int;
        vfs.xOpen = Some(vfs_open);
        if vfs.xDelete.is_some() {
            vfs.xDelete = Some(vfs_delete);
        }
        if vfs.xAccess.is_some() {
            vfs.xAccess = Some(vfs_access);
        }
        if vfs.xFullPathname.is_some() {
            vfs.xFullPathname = Some(vfs_full_path);
        }
        if vfs.xDlOpen.is_some() {
            vfs.xDlOpen = Some(vfs_dl_open);
        }
        if vfs.xDlError.is_some() {
            vfs.xDlError = Some(vfs_dl_error);
        }
        if vfs.xDlSym.is_some() {
            vfs.xDlSym = Some(vfs_dl_sym);
        }
        if vfs.xDlClose.is_some() {
            vfs.xDlClose = Some(vfs_dl_close);
        }
        if vfs.xRandomness.is_some() {
            vfs.xRandomness = Some(vfs_randomness);
        }
        if vfs.xSleep.is_some() {
            vfs.xSleep = Some(vfs_sleep);
        }
        if vfs.xCurrentTime.is_some() {
            vfs.xCurrentTime = Some(vfs_time);
        }
        if vfs.xGetLastError.is_some() {
            vfs.xGetLastError = Some(vfs_last_error);
        }
        if vfs.xCurrentTimeInt64.is_some() {
            vfs.xCurrentTimeInt64 = Some(vfs_time_i64);
        }
        if vfs.xSetSystemCall.is_some() {
            vfs.xSetSystemCall = Some(vfs_set_call);
        }
        if vfs.xGetSystemCall.is_some() {
            vfs.xGetSystemCall = Some(vfs_get_call);
        }
        if vfs.xNextSystemCall.is_some() {
            vfs.xNextSystemCall = Some(vfs_next_call);
        }
        assert_eq!(
            ffi::sqlite3_vfs_register(Box::into_raw(vfs), 0),
            ffi::SQLITE_OK
        );
    });
    Connection::open_with_flags_and_vfs(path, OpenFlags::default(), NAME)
}

#[repr(C)]
struct File {
    base: ffi::sqlite3_file,
    real: *mut ffi::sqlite3_file,
    methods: ffi::sqlite3_io_methods,
}
unsafe extern "C" fn vfs_open(
    v: *mut ffi::sqlite3_vfs,
    name: ffi::sqlite3_filename,
    f: *mut ffi::sqlite3_file,
    flags: c_int,
    out: *mut c_int,
) -> c_int {
    let v = (*v).pAppData.cast::<ffi::sqlite3_vfs>();
    let real = ffi::sqlite3_malloc((*v).szOsFile).cast::<ffi::sqlite3_file>();
    if real.is_null() {
        return ffi::SQLITE_NOMEM;
    }
    ptr::write_bytes(real.cast::<u8>(), 0, (*v).szOsFile as usize);
    let rc = (*v).xOpen.unwrap()(v, name, real, flags, out);
    if rc != ffi::SQLITE_OK {
        if !(*real).pMethods.is_null() {
            ((*(*real).pMethods).xClose.unwrap())(real);
        }
        ffi::sqlite3_free(real.cast());
        return rc;
    }
    let mut methods = ptr::read((*real).pMethods);
    if methods.xRead.is_some() {
        methods.xRead = Some(read);
    }
    if methods.xWrite.is_some() {
        methods.xWrite = Some(write);
    }
    if methods.xTruncate.is_some() {
        methods.xTruncate = Some(truncate);
    }
    if methods.xFileSize.is_some() {
        methods.xFileSize = Some(file_size);
    }
    if methods.xLock.is_some() {
        methods.xLock = Some(lock);
    }
    if methods.xUnlock.is_some() {
        methods.xUnlock = Some(unlock);
    }
    if methods.xCheckReservedLock.is_some() {
        methods.xCheckReservedLock = Some(reserved);
    }
    if methods.xFileControl.is_some() {
        methods.xFileControl = Some(control);
    }
    if methods.xSectorSize.is_some() {
        methods.xSectorSize = Some(sector);
    }
    if methods.xDeviceCharacteristics.is_some() {
        methods.xDeviceCharacteristics = Some(device);
    }
    if methods.xShmMap.is_some() {
        methods.xShmMap = Some(shm_map);
    }
    if methods.xShmLock.is_some() {
        methods.xShmLock = Some(shm_lock);
    }
    if methods.xShmBarrier.is_some() {
        methods.xShmBarrier = Some(shm_barrier);
    }
    if methods.xShmUnmap.is_some() {
        methods.xShmUnmap = Some(shm_unmap);
    }
    if methods.xFetch.is_some() {
        methods.xFetch = Some(fetch);
    }
    if methods.xUnfetch.is_some() {
        methods.xUnfetch = Some(unfetch);
    }
    methods.xClose = Some(close);
    methods.xSync = Some(sync);
    let wrapped = f.cast::<File>();
    ptr::write(
        wrapped,
        File {
            base: ffi::sqlite3_file {
                pMethods: ptr::null(),
            },
            real,
            methods,
        },
    );
    (*wrapped).base.pMethods = ptr::addr_of!((*wrapped).methods);
    ffi::SQLITE_OK
}
unsafe extern "C" fn close(f: *mut ffi::sqlite3_file) -> c_int {
    let wrapped = f.cast::<File>();
    let real = (*wrapped).real;
    let rc = ((*(*real).pMethods).xClose.unwrap())(real);
    ffi::sqlite3_free(real.cast());
    (*wrapped).base.pMethods = ptr::null();
    rc
}
unsafe extern "C" fn sync(f: *mut ffi::sqlite3_file, flags: c_int) -> c_int {
    SYNCS.with(|n| n.set(n.get() + 1));
    let fail = COUNTDOWN.with(|n| match n.get() {
        Some(0) => {
            n.set(None);
            true
        }
        Some(v) => {
            n.set(Some(v - 1));
            false
        }
        None => false,
    });
    if fail {
        FAILURES.with(|n| n.set(n.get() + 1));
        return ffi::SQLITE_IOERR_FSYNC;
    }
    let real = (*f.cast::<File>()).real;
    ((*(*real).pMethods).xSync.unwrap())(real, flags)
}
unsafe extern "C" fn read(
    f: *mut ffi::sqlite3_file,
    buf: *mut c_void,
    amt: c_int,
    off: i64,
) -> c_int {
    let real = (*f.cast::<File>()).real;
    ((*(*real).pMethods).xRead.unwrap())(real, buf, amt, off)
}
unsafe extern "C" fn write(
    f: *mut ffi::sqlite3_file,
    buf: *const c_void,
    amt: c_int,
    off: i64,
) -> c_int {
    let real = (*f.cast::<File>()).real;
    ((*(*real).pMethods).xWrite.unwrap())(real, buf, amt, off)
}
unsafe extern "C" fn truncate(f: *mut ffi::sqlite3_file, size: i64) -> c_int {
    let real = (*f.cast::<File>()).real;
    ((*(*real).pMethods).xTruncate.unwrap())(real, size)
}
unsafe extern "C" fn file_size(f: *mut ffi::sqlite3_file, size: *mut i64) -> c_int {
    let real = (*f.cast::<File>()).real;
    ((*(*real).pMethods).xFileSize.unwrap())(real, size)
}
unsafe extern "C" fn lock(f: *mut ffi::sqlite3_file, level: c_int) -> c_int {
    let real = (*f.cast::<File>()).real;
    ((*(*real).pMethods).xLock.unwrap())(real, level)
}
unsafe extern "C" fn unlock(f: *mut ffi::sqlite3_file, level: c_int) -> c_int {
    let real = (*f.cast::<File>()).real;
    ((*(*real).pMethods).xUnlock.unwrap())(real, level)
}
unsafe extern "C" fn reserved(f: *mut ffi::sqlite3_file, out: *mut c_int) -> c_int {
    let real = (*f.cast::<File>()).real;
    ((*(*real).pMethods).xCheckReservedLock.unwrap())(real, out)
}
unsafe extern "C" fn control(f: *mut ffi::sqlite3_file, op: c_int, arg: *mut c_void) -> c_int {
    let real = (*f.cast::<File>()).real;
    ((*(*real).pMethods).xFileControl.unwrap())(real, op, arg)
}
unsafe extern "C" fn sector(f: *mut ffi::sqlite3_file) -> c_int {
    let real = (*f.cast::<File>()).real;
    ((*(*real).pMethods).xSectorSize.unwrap())(real)
}
unsafe extern "C" fn device(f: *mut ffi::sqlite3_file) -> c_int {
    let real = (*f.cast::<File>()).real;
    ((*(*real).pMethods).xDeviceCharacteristics.unwrap())(real)
}
unsafe extern "C" fn shm_map(
    f: *mut ffi::sqlite3_file,
    page: c_int,
    size: c_int,
    extend: c_int,
    out: *mut *mut c_void,
) -> c_int {
    let real = (*f.cast::<File>()).real;
    ((*(*real).pMethods).xShmMap.unwrap())(real, page, size, extend, out)
}
unsafe extern "C" fn shm_lock(
    f: *mut ffi::sqlite3_file,
    off: c_int,
    n: c_int,
    flags: c_int,
) -> c_int {
    let real = (*f.cast::<File>()).real;
    ((*(*real).pMethods).xShmLock.unwrap())(real, off, n, flags)
}
unsafe extern "C" fn shm_barrier(f: *mut ffi::sqlite3_file) {
    let real = (*f.cast::<File>()).real;
    ((*(*real).pMethods).xShmBarrier.unwrap())(real)
}
unsafe extern "C" fn shm_unmap(f: *mut ffi::sqlite3_file, delete: c_int) -> c_int {
    let real = (*f.cast::<File>()).real;
    ((*(*real).pMethods).xShmUnmap.unwrap())(real, delete)
}
unsafe extern "C" fn fetch(
    f: *mut ffi::sqlite3_file,
    off: i64,
    amt: c_int,
    out: *mut *mut c_void,
) -> c_int {
    let real = (*f.cast::<File>()).real;
    ((*(*real).pMethods).xFetch.unwrap())(real, off, amt, out)
}
unsafe extern "C" fn unfetch(f: *mut ffi::sqlite3_file, off: i64, p: *mut c_void) -> c_int {
    let real = (*f.cast::<File>()).real;
    ((*(*real).pMethods).xUnfetch.unwrap())(real, off, p)
}
unsafe extern "C" fn vfs_delete(
    v: *mut ffi::sqlite3_vfs,
    name: *const c_char,
    sync: c_int,
) -> c_int {
    let real = (*v).pAppData.cast::<ffi::sqlite3_vfs>();
    ((*real).xDelete.unwrap())(real, name, sync)
}
unsafe extern "C" fn vfs_access(
    v: *mut ffi::sqlite3_vfs,
    name: *const c_char,
    flags: c_int,
    out: *mut c_int,
) -> c_int {
    let real = (*v).pAppData.cast::<ffi::sqlite3_vfs>();
    ((*real).xAccess.unwrap())(real, name, flags, out)
}
unsafe extern "C" fn vfs_full_path(
    v: *mut ffi::sqlite3_vfs,
    name: *const c_char,
    n: c_int,
    out: *mut c_char,
) -> c_int {
    let real = (*v).pAppData.cast::<ffi::sqlite3_vfs>();
    ((*real).xFullPathname.unwrap())(real, name, n, out)
}
unsafe extern "C" fn vfs_dl_open(v: *mut ffi::sqlite3_vfs, name: *const c_char) -> *mut c_void {
    let real = (*v).pAppData.cast::<ffi::sqlite3_vfs>();
    ((*real).xDlOpen.unwrap())(real, name)
}
unsafe extern "C" fn vfs_dl_error(v: *mut ffi::sqlite3_vfs, n: c_int, out: *mut c_char) {
    let real = (*v).pAppData.cast::<ffi::sqlite3_vfs>();
    ((*real).xDlError.unwrap())(real, n, out)
}
unsafe extern "C" fn vfs_dl_sym(
    v: *mut ffi::sqlite3_vfs,
    handle: *mut c_void,
    name: *const c_char,
) -> Option<unsafe extern "C" fn(*mut ffi::sqlite3_vfs, *mut c_void, *const c_char)> {
    let real = (*v).pAppData.cast::<ffi::sqlite3_vfs>();
    ((*real).xDlSym.unwrap())(real, handle, name)
}
unsafe extern "C" fn vfs_dl_close(v: *mut ffi::sqlite3_vfs, handle: *mut c_void) {
    let real = (*v).pAppData.cast::<ffi::sqlite3_vfs>();
    ((*real).xDlClose.unwrap())(real, handle)
}
unsafe extern "C" fn vfs_randomness(v: *mut ffi::sqlite3_vfs, n: c_int, out: *mut c_char) -> c_int {
    let real = (*v).pAppData.cast::<ffi::sqlite3_vfs>();
    ((*real).xRandomness.unwrap())(real, n, out)
}
unsafe extern "C" fn vfs_sleep(v: *mut ffi::sqlite3_vfs, micros: c_int) -> c_int {
    let real = (*v).pAppData.cast::<ffi::sqlite3_vfs>();
    ((*real).xSleep.unwrap())(real, micros)
}
unsafe extern "C" fn vfs_time(v: *mut ffi::sqlite3_vfs, out: *mut f64) -> c_int {
    let real = (*v).pAppData.cast::<ffi::sqlite3_vfs>();
    ((*real).xCurrentTime.unwrap())(real, out)
}
unsafe extern "C" fn vfs_last_error(v: *mut ffi::sqlite3_vfs, n: c_int, out: *mut c_char) -> c_int {
    let real = (*v).pAppData.cast::<ffi::sqlite3_vfs>();
    ((*real).xGetLastError.unwrap())(real, n, out)
}
unsafe extern "C" fn vfs_time_i64(v: *mut ffi::sqlite3_vfs, out: *mut i64) -> c_int {
    let real = (*v).pAppData.cast::<ffi::sqlite3_vfs>();
    ((*real).xCurrentTimeInt64.unwrap())(real, out)
}
unsafe extern "C" fn vfs_set_call(
    v: *mut ffi::sqlite3_vfs,
    name: *const c_char,
    call: ffi::sqlite3_syscall_ptr,
) -> c_int {
    let real = (*v).pAppData.cast::<ffi::sqlite3_vfs>();
    ((*real).xSetSystemCall.unwrap())(real, name, call)
}
unsafe extern "C" fn vfs_get_call(
    v: *mut ffi::sqlite3_vfs,
    name: *const c_char,
) -> ffi::sqlite3_syscall_ptr {
    let real = (*v).pAppData.cast::<ffi::sqlite3_vfs>();
    ((*real).xGetSystemCall.unwrap())(real, name)
}
unsafe extern "C" fn vfs_next_call(v: *mut ffi::sqlite3_vfs, name: *const c_char) -> *const c_char {
    let real = (*v).pAppData.cast::<ffi::sqlite3_vfs>();
    ((*real).xNextSystemCall.unwrap())(real, name)
}

#[cfg(test)]
mod tests {
    use super::super::{fingerprint, Binding, Store, CHUNK_MAX};
    use super::*;
    use serde_json::json;

    fn fixture() -> (tempfile::TempDir, Store, Binding, String, Vec<u8>) {
        let root = tempfile::tempdir().unwrap();
        let binding = Binding {
            certificate: fingerprint(b"sync-fault-certificate"),
            device: "alice".into(),
            project: "demo".into(),
        };
        let payload = vec![37; CHUNK_MAX + 19];
        let manifest = serde_json::to_vec(&json!({"version":1,"kind":"proposal",
            "device":"alice","project":"demo","authority":"central","epoch":1,
            "payload_len":payload.len(),"payload_sha256":fingerprint(&payload)}))
        .unwrap();
        let mut store = Store::open(root.path()).unwrap();
        let id = store.begin(&binding, &manifest).unwrap().transfer_id;
        store.chunk(&binding, &id, 0, &payload[..19]).unwrap();
        store.fault_vfs = true;
        (root, store, binding, id, payload)
    }
    fn assert_sync_error(error: &(dyn std::error::Error + 'static)) {
        let sqlite = error.downcast_ref::<rusqlite::Error>();
        assert!(
            matches!(sqlite, Some(rusqlite::Error::SqliteFailure(e, _))
            if e.extended_code == ffi::SQLITE_IOERR_FSYNC),
            "{error}"
        );
        assert_eq!(failures(), 1, "the intended xSync must actually fail");
    }

    #[test]
    fn sqlite_every_chunk_sync_failure_returns_no_ack_and_reopens_atomically() {
        // Discover actual sync count on this platform rather than assume a Unix
        // or Windows journal implementation's particular sequence of syncs.
        let (_root, store, binding, id, payload) = fixture();
        let guard = fail_sync_after(usize::MAX);
        store.chunk(&binding, &id, 19, &payload[19..]).unwrap();
        let count = syncs();
        drop(guard);
        assert!(count > 0);
        for position in 0..count {
            let (root, store, binding, id, payload) = fixture();
            let guard = fail_sync_after(position);
            let result = store.chunk(&binding, &id, 19, &payload[19..]);
            assert!(
                result.is_err(),
                "sync {position} must not acknowledge a chunk"
            );
            assert_sync_error(&*result.unwrap_err());
            drop(guard);
            drop(store);
            let reopened = Store::open(root.path()).unwrap();
            let db = reopened.connection().unwrap();
            let (record, bytes) = Store::read(&db, &binding, &id).unwrap();
            let offset = record.status.committed_offset;
            assert!(offset == 19 || offset == payload.len() as u64);
            assert_eq!(bytes, payload[..offset as usize]);
            assert_eq!(record.chunks.len(), if offset == 19 { 1 } else { 2 });
            drop(db);
            // Retry accepts either rolled-back or wholly committed state.
            reopened.chunk(&binding, &id, 19, &payload[19..]).unwrap();
            assert_eq!(reopened.artifact(&binding, &id).unwrap().objects, payload);
        }
    }

    #[test]
    fn sqlite_every_completion_sync_failure_keeps_result_and_payload_atomic() {
        let (_root, store, binding, id, payload) = fixture();
        store.chunk(&binding, &id, 19, &payload[19..]).unwrap();
        let imported = json!({"ok":true,"proposal":"sync-fault-test"});
        let guard = fail_sync_after(usize::MAX);
        store.complete(&binding, &id, imported.clone()).unwrap();
        let count = syncs();
        drop(guard);
        assert!(count > 0);
        for position in 0..count {
            let (root, store, binding, id, payload) = fixture();
            store.chunk(&binding, &id, 19, &payload[19..]).unwrap();
            let guard = fail_sync_after(position);
            let result = store.complete(&binding, &id, imported.clone());
            assert!(
                result.is_err(),
                "sync {position} must not acknowledge completion"
            );
            assert_sync_error(&*result.unwrap_err());
            drop(guard);
            drop(store);
            let reopened = Store::open(root.path()).unwrap();
            let db = reopened.connection().unwrap();
            let (record, bytes) = Store::read(&db, &binding, &id).unwrap();
            assert_eq!(record.status.committed_offset, payload.len() as u64);
            match record.status.import_result {
                None => assert_eq!(bytes, payload),
                Some(result) => {
                    assert_eq!(result, imported);
                    assert!(bytes.is_empty());
                }
            }
            drop(db);
            reopened.complete(&binding, &id, imported.clone()).unwrap();
            assert_eq!(
                reopened.status(&binding, &id).unwrap().import_result,
                Some(imported.clone())
            );
        }
    }

    #[test]
    fn sqlite_fault_vfs_never_changes_default_connections() {
        let root = tempfile::tempdir().unwrap();
        // Register before testing the default VFS; registration must not replace it.
        drop(open(root.path().join("wrapped.sqlite")).unwrap());
        let guard = fail_sync_after(0);
        let ordinary = Connection::open(root.path().join("ordinary.sqlite")).unwrap();
        ordinary
            .execute_batch("PRAGMA synchronous=EXTRA; CREATE TABLE t(x); INSERT INTO t VALUES(1)")
            .unwrap();
        assert_eq!(failures(), 0);
        assert_eq!(syncs(), 0);
        drop(guard);
    }
}
