//! Every independently locked SQLite consumer runs this same linked-runtime guard.
//! SQLite's WAL-reset corruption bug is fixed in 3.51.3 and newer:
//! https://www.sqlite.org/wal.html#the_wal_reset_bug
use rusqlite::Connection;

#[test]
fn sqlite_runtime_includes_wal_reset_fix() {
    let db = Connection::open_in_memory().unwrap();
    let (version, source_id): (String, String) = db
        .query_row("SELECT sqlite_version(), sqlite_source_id()", [], |row| {
            Ok((row.get(0)?, row.get(1)?))
        })
        .unwrap();
    eprintln!("linked SQLite version={version} source_id={source_id}");
    let parts: Vec<u32> = version.split('.').map(|n| n.parse().unwrap()).collect();
    assert_eq!(parts.len(), 3, "unexpected SQLite version: {version}");
    assert!(
        (parts[0], parts[1], parts[2]) >= (3, 51, 3),
        "SQLite {version} ({source_id}) predates the WAL-reset fix"
    );
    assert_eq!(version, rusqlite::version());
    assert_eq!(
        rusqlite::version_number(),
        (parts[0] * 1_000_000 + parts[1] * 1_000 + parts[2]) as i32
    );
    assert!(
        !source_id.is_empty(),
        "SQLite source identity must be present"
    );
}

#[test]
fn unsigned_bindings_remain_checked() {
    // rusqlite 0.39 gates these existing conversions behind fallible_uint.
    // Preserve signed SQLite INTEGER bounds rather than truncating large counters.
    let db = Connection::open_in_memory().unwrap();
    let max = i64::MAX as u64;
    let round_trip: u64 = db.query_row("SELECT ?1", [max], |row| row.get(0)).unwrap();
    assert_eq!(round_trip, max);
    assert!(matches!(
        db.query_row("SELECT ?1", [max + 1], |row| row.get::<_, i64>(0)),
        Err(rusqlite::Error::ToSqlConversionFailure(_))
    ));
    assert!(matches!(
        db.query_row("SELECT ?1", [u64::MAX], |row| row.get::<_, i64>(0)),
        Err(rusqlite::Error::ToSqlConversionFailure(_))
    ));
    let size: usize = 123;
    assert_eq!(
        db.query_row("SELECT ?1", [size], |row| row.get::<_, usize>(0))
            .unwrap(),
        size
    );
}
