//! Bounded, uncompressed, self-contained public object transport.
//! This is a content container, never a source of authority, configuration, or refs.
//! Caller must select roots from an authorized public event/head/proposal. Commit
//! grammar and private-ref rejection prevent accidental private-history export;
//! neither proves data is public nor authenticates a malicious sender. SHA-1 only.
//! Limits: 64 MiB artifact, 10,000 objects/expanded paths, 1,000 commits, 128 roots,
//! 16 MiB blobs, 4 MiB trees, 16 KiB commits, 64 path components. Long histories
//! fail closed. Subprocess CPU/wall time is not bounded. Local repository config,
//! parent directories and same-account concurrent processes remain trusted.
use crate::git::{allowed_path, register_path, Git, Result};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

const MAGIC: &[u8] = b"WIPSTASH-SOURCE-1\0";
pub const MAX_ARTIFACT_BYTES: usize = 64 * 1024 * 1024;
const MAX_OBJECTS: usize = 10_000;
const MAX_ROOTS: usize = 128;
const MAX_COMMITS: usize = 1000;
static NEXT: AtomicU64 = AtomicU64::new(0);
#[derive(Clone)]
struct Object {
    kind: u8,
    bytes: Vec<u8>,
}
fn kind(k: u8) -> Result<&'static str> {
    match k {
        1 => Ok("commit"),
        2 => Ok("tree"),
        3 => Ok("blob"),
        _ => Err("source_invalid: unsupported object type".into()),
    }
}
fn id(s: &str) -> Result<()> {
    if s.len() == 40
        && s.bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
    {
        Ok(())
    } else {
        Err("source_invalid: expected lowercase SHA-1 object id".into())
    }
}
fn roots(input: &[String]) -> Result<Vec<String>> {
    if input.is_empty() || input.len() > MAX_ROOTS {
        return Err("source_limit: root count".into());
    }
    for s in input {
        id(s)?;
    }
    let sorted: BTreeSet<_> = input.iter().cloned().collect();
    if sorted.len() != input.len() {
        return Err("source_invalid: duplicate roots".into());
    }
    Ok(sorted.into_iter().collect())
}
fn commit(bytes: &[u8]) -> Result<(String, Vec<String>)> {
    if bytes.len() > 16 * 1024 {
        return Err("source_limit: commit size".into());
    }
    let s = std::str::from_utf8(bytes).map_err(|_| "source_invalid: commit UTF-8")?;
    let (headers, message) = s
        .split_once("\n\n")
        .ok_or("source_invalid: commit headers")?;
    let mut lines = headers.lines();
    let tree = lines
        .next()
        .and_then(|s| s.strip_prefix("tree "))
        .ok_or("source_invalid: commit tree")?
        .to_owned();
    id(&tree)?;
    let mut parents = Vec::new();
    let mut author = false;
    let mut committer = false;
    for line in lines {
        if let Some(p) = line.strip_prefix("parent ") {
            if author || parents.len() >= 2 {
                return Err("source_invalid: commit parents".into());
            }
            id(p)?;
            parents.push(p.to_owned());
        } else if line.starts_with("author ") && !author && !committer {
            author = true;
        } else if line.starts_with("committer ") && author && !committer {
            committer = true;
        } else {
            return Err("source_invalid: unexpected commit header".into());
        }
    }
    let message = message.trim_end_matches('\n');
    let public = (message == "Wipstash initial public import" && parents.is_empty())
        || (message.strip_prefix("proposal ").is_some_and(|v| {
            !v.is_empty()
                && v.len() <= 128
                && v.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
        }) && parents.len() == 1)
        || (message.starts_with("Wipstash integration\noperation: integration-")
            && parents.len() == 2);
    if !author || !committer || !public {
        return Err("source_private: non-public commit or ancestry".into());
    }
    Ok((tree, parents))
}
fn tree(bytes: &[u8]) -> Result<Vec<(String, String, u8)>> {
    if bytes.len() > 4 * 1024 * 1024 {
        return Err("source_limit: tree size".into());
    }
    let mut remaining = bytes;
    let mut entries = Vec::new();
    while !remaining.is_empty() {
        let nul = remaining
            .iter()
            .position(|&b| b == 0)
            .ok_or("source_invalid: tree entry")?;
        let header =
            std::str::from_utf8(&remaining[..nul]).map_err(|_| "source_invalid: tree name")?;
        let (mode, name) = header.split_once(' ').ok_or("source_invalid: tree mode")?;
        if name.contains('/') {
            return Err("source_invalid: nested tree name".into());
        }
        allowed_path(name)?;
        let k = match mode {
            "40000" => 2,
            "100644" | "100755" => 3,
            _ => return Err("source_invalid: unsupported mode".into()),
        };
        if remaining.len() < nul + 21 {
            return Err("source_invalid: truncated tree id".into());
        }
        let oid = remaining[nul + 1..nul + 21]
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        entries.push((name.to_owned(), oid, k));
        if entries.len() > MAX_OBJECTS {
            return Err("source_limit: tree entries".into());
        }
        remaining = &remaining[nul + 21..];
    }
    Ok(entries)
}
fn links(o: &Object) -> Result<Vec<(String, u8)>> {
    match o.kind {
        1 => {
            let (t, p) = commit(&o.bytes)?;
            let mut v = vec![(t, 2)];
            v.extend(p.into_iter().map(|p| (p, 1)));
            Ok(v)
        }
        2 => Ok(tree(&o.bytes)?
            .into_iter()
            .map(|(_, s, k)| (s, k))
            .collect()),
        3 => Ok(vec![]),
        _ => Err("source_invalid: object kind".into()),
    }
}
fn validate(objects: &BTreeMap<String, Object>, root_ids: &[String]) -> Result<()> {
    let mut pending: Vec<_> = root_ids.iter().map(|s| (s.clone(), 1)).collect();
    let mut seen = BTreeSet::new();
    let mut commits = 0;
    let mut trees = BTreeSet::new();
    while let Some((oid, k)) = pending.pop() {
        let o = objects
            .get(&oid)
            .ok_or("source_invalid: incomplete object closure")?;
        if o.kind != k {
            return Err("source_invalid: object type mismatch".into());
        }
        if !seen.insert(oid.clone()) {
            continue;
        }
        if k == 1 {
            commits += 1;
            trees.insert(commit(&o.bytes)?.0);
        }
        if commits > MAX_COMMITS {
            return Err("source_limit: commit ancestry".into());
        }
        pending.extend(links(o)?);
    }
    if seen.len() != objects.len() {
        return Err("source_invalid: unreachable extra objects".into());
    }
    for t in trees {
        let mut pending = vec![(t, String::new(), 0)];
        let mut names = HashMap::new();
        let mut exact = BTreeSet::new();
        let mut bytes = 0usize;
        while let Some((t, prefix, depth)) = pending.pop() {
            if depth > 64 {
                return Err("source_limit: tree depth".into());
            }
            for (name, oid, k) in tree(&objects[&t].bytes)? {
                let path = format!("{prefix}{name}");
                allowed_path(&path)?;
                register_path(&path, &mut names)?;
                if !exact.insert(path.clone()) {
                    return Err("source_invalid: duplicate tree path".into());
                }
                if exact.len() > MAX_OBJECTS {
                    return Err("source_limit: snapshot entries".into());
                }
                if k == 2 {
                    pending.push((oid, format!("{path}/"), depth + 1));
                } else {
                    bytes = bytes
                        .checked_add(objects[&oid].bytes.len())
                        .ok_or("source_limit: size overflow")?;
                }
                if bytes > MAX_ARTIFACT_BYTES {
                    return Err("source_limit: snapshot bytes".into());
                }
            }
        }
    }
    Ok(())
}

/// Export only caller-authorized public roots, with their exact complete closure.
pub fn export(git: &Git, input: &[String]) -> Result<Vec<u8>> {
    let root_ids = roots(input)?;
    let mut pending: Vec<_> = root_ids.iter().map(|s| (s.clone(), 1)).collect();
    let mut objects = BTreeMap::new();
    let mut size = MAGIC.len() + 8 + root_ids.len() * 40;
    while let Some((oid, k)) = pending.pop() {
        if objects.contains_key(&oid) {
            continue;
        }
        let bytes = git.verified_object(kind(k)?, &oid)?;
        size = size
            .checked_add(45 + bytes.len())
            .ok_or("source_limit: size overflow")?;
        if size > MAX_ARTIFACT_BYTES || objects.len() >= MAX_OBJECTS {
            return Err("source_limit: artifact exceeds bound".into());
        }
        let o = Object { kind: k, bytes };
        pending.extend(links(&o)?);
        objects.insert(oid, o);
    }
    validate(&objects, &root_ids)?;
    let private = git.run(
        &[
            "for-each-ref",
            "--format=%(objectname)",
            "refs/wipstash/checkpoints/",
            "refs/wipstash/recovery/",
            "refs/wipstash/adoptions/",
        ],
        None,
    )?;
    for oid in std::str::from_utf8(&private)
        .map_err(|_| "source_invalid: private refs")?
        .lines()
    {
        if objects.contains_key(oid) {
            return Err("source_private: private reference in public closure".into());
        }
    }
    let mut out = MAGIC.to_vec();
    out.extend_from_slice(&(root_ids.len() as u32).to_be_bytes());
    for r in &root_ids {
        out.extend_from_slice(r.as_bytes());
    }
    out.extend_from_slice(&(objects.len() as u32).to_be_bytes());
    for (oid, o) in objects {
        out.extend_from_slice(oid.as_bytes());
        out.push(o.kind);
        out.extend_from_slice(&(o.bytes.len() as u32).to_be_bytes());
        out.extend_from_slice(&o.bytes);
    }
    Ok(out)
}
struct Cursor<'a>(&'a [u8]);
impl<'a> Cursor<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        if n > self.0.len() {
            return Err("source_invalid: truncated artifact".into());
        }
        let (a, b) = self.0.split_at(n);
        self.0 = b;
        Ok(a)
    }
    fn count(&mut self) -> Result<usize> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into().unwrap()) as usize)
    }
    fn oid(&mut self) -> Result<String> {
        let s = std::str::from_utf8(self.take(40)?)
            .map_err(|_| "source_invalid: object id")?
            .to_owned();
        id(&s)?;
        Ok(s)
    }
}
struct Quarantine(PathBuf);
impl Drop for Quarantine {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// Verify the exact expected root manifest before touching destination objects.
/// Object writes are individually atomic; a single ref transaction pins all roots.
/// A crash before the transaction can leave only unreachable validated objects.
#[cfg(test)]
pub fn import(git: &Git, bytes: &[u8], expected_roots: &[String]) -> Result<()> {
    prepare(git, bytes, expected_roots)?.install(git)
}

/// A validated quarantined closure. Dropping it leaves destination objects/refs untouched.
/// Inspect graph semantics here, then install only after application admission passes.
pub struct Prepared {
    quarantine: Quarantine,
    git: Git,
    objects: BTreeMap<String, Object>,
    manifest: Vec<String>,
}
impl Prepared {
    pub fn git(&self) -> &Git {
        &self.git
    }
    pub fn install(self, git: &Git) -> Result<()> {
        let _keep_quarantine_alive = &self.quarantine;
        install(git, &self.objects, &self.manifest)
    }
}

pub fn prepare(git: &Git, bytes: &[u8], expected_roots: &[String]) -> Result<Prepared> {
    let expected = roots(expected_roots)?;
    if git.run(&["rev-parse", "--show-object-format"], None)? != b"sha1\n" {
        return Err("source_invalid: destination must use SHA-1".into());
    }
    if bytes.len() > MAX_ARTIFACT_BYTES {
        return Err("source_limit: artifact bytes".into());
    }
    let mut c = Cursor(bytes);
    if c.take(MAGIC.len())? != MAGIC {
        return Err("source_invalid: artifact version".into());
    }
    let count = c.count()?;
    if count == 0 || count > MAX_ROOTS {
        return Err("source_limit: manifest roots".into());
    }
    let mut manifest = Vec::new();
    for _ in 0..count {
        manifest.push(c.oid()?);
    }
    if manifest != expected {
        return Err("source_invalid: root manifest mismatch".into());
    }
    let count = c.count()?;
    if count == 0 || count > MAX_OBJECTS {
        return Err("source_limit: object count".into());
    }
    let mut objects = BTreeMap::new();
    for _ in 0..count {
        let oid = c.oid()?;
        let k = c.take(1)?[0];
        kind(k)?;
        let n = c.count()?;
        let limit = match k {
            1 => 16 * 1024,
            2 => 4 * 1024 * 1024,
            _ => 16 * 1024 * 1024,
        };
        if n > limit {
            return Err("source_limit: object size".into());
        }
        let o = Object {
            kind: k,
            bytes: c.take(n)?.to_vec(),
        };
        if objects.insert(oid, o).is_some() {
            return Err("source_invalid: duplicate object".into());
        }
    }
    if !c.0.is_empty() {
        return Err("source_invalid: trailing bytes".into());
    }
    validate(&objects, &manifest)?;
    let required = (bytes.len() as u64)
        .checked_mul(3)
        .and_then(|n| n.checked_add((objects.len() as u64) * 8192))
        .and_then(|n| n.checked_add(1024 * 1024))
        .ok_or("source_limit: capacity overflow")?;
    if fs2::available_space(&git.repo).map_err(|e| format!("storage_capacity_error: {e}"))?
        < required
    {
        return Err("insufficient_storage: source quarantine and install reserve".into());
    }
    let qpath = git.repo.join(format!(
        "wipstash-quarantine-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir(&qpath).map_err(|e| e.to_string())?;
    let guard = Quarantine(qpath.clone());
    let q = Git::init(&qpath)?;
    for (oid, o) in &objects {
        let actual = q.run(
            &[
                "hash-object",
                "-w",
                "-t",
                kind(o.kind)?,
                "--stdin",
                "--no-filters",
            ],
            Some(&o.bytes),
        )?;
        if actual != format!("{oid}\n").as_bytes() {
            return Err("source_invalid: object identity mismatch".into());
        }
    }
    let mut args = vec!["fsck", "--strict", "--no-reflogs", "--no-dangling"];
    args.extend(manifest.iter().map(String::as_str));
    q.run(&args, None)?;
    Ok(Prepared {
        quarantine: guard,
        git: q,
        objects,
        manifest,
    })
}
fn install(git: &Git, objects: &BTreeMap<String, Object>, manifest: &[String]) -> Result<()> {
    // Install only after all objects, connectivity, public ancestry and trees passed.
    for (oid, o) in objects {
        let actual = git.run(
            &[
                "hash-object",
                "-w",
                "-t",
                kind(o.kind)?,
                "--stdin",
                "--no-filters",
            ],
            Some(&o.bytes),
        )?;
        if actual != format!("{oid}\n").as_bytes() {
            return Err("source_invalid: destination object format".into());
        }
        // hash-object can reuse an existing loose object; verify it was not corrupt.
        git.verified_object(kind(o.kind)?, oid)?;
    }
    let mut transaction = String::from("start\n");
    for oid in manifest {
        transaction.push_str(&format!("update refs/wipstash/transfers/{oid} {oid}\n"));
    }
    transaction.push_str("prepare\ncommit\n");
    git.run(
        &["update-ref", "--no-deref", "--stdin"],
        Some(transaction.as_bytes()),
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    struct Temp(PathBuf);
    impl Temp {
        fn new() -> Self {
            let p = std::env::temp_dir().join(format!(
                "wipstash-transfer-test-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&p).unwrap();
            Self(p)
        }
    }
    impl Drop for Temp {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    fn fixture() -> (Temp, Git, Git, String) {
        let t = Temp::new();
        let a = Git::init(&t.0.join("a")).unwrap();
        let b = Git::init(&t.0.join("b")).unwrap();
        fs::create_dir(t.0.join("source")).unwrap();
        fs::write(t.0.join("source/file"), b"hello\0\xff\r\n").unwrap();
        let tree = a.capture(&t.0.join("source")).unwrap();
        let root = a
            .commit(&tree, &[], "Wipstash initial public import")
            .unwrap();
        (t, a, b, root)
    }
    fn no_pins(g: &Git) {
        assert!(g.run(&["for-each-ref"], None).unwrap().is_empty());
    }
    #[test]
    fn transfers_independent_objects_exactly_and_idempotently() {
        let (t, a, b, root) = fixture();
        let bytes = export(&a, std::slice::from_ref(&root)).unwrap();
        assert!(b.tree(&root).is_err());
        import(&b, &bytes, std::slice::from_ref(&root)).unwrap();
        import(&b, &bytes, std::slice::from_ref(&root)).unwrap();
        fs::create_dir(t.0.join("out")).unwrap();
        b.materialize(&root, &t.0.join("out")).unwrap();
        assert_eq!(fs::read(t.0.join("out/file")).unwrap(), b"hello\0\xff\r\n");
        assert_eq!(
            b.head(&format!("refs/wipstash/transfers/{root}")).unwrap(),
            root
        );
        assert!(b.head("refs/wipstash/integration").is_err());
        assert!(!fs::read_dir(&b.repo).unwrap().any(|e| e
            .unwrap()
            .file_name()
            .to_string_lossy()
            .contains("quarantine")));
    }
    #[test]
    fn fails_closed_on_private_ancestry_and_private_pins() {
        let (_t, a, b, root) = fixture();
        let tree = a.tree(&root).unwrap();
        let private = a
            .commit(
                &tree,
                std::slice::from_ref(&root),
                "private checkpoint secret",
            )
            .unwrap();
        let proposal = a.commit(&tree, &[private], "proposal p").unwrap();
        assert!(export(&a, &[proposal])
            .unwrap_err()
            .contains("source_private"));
        a.set_ref("refs/wipstash/checkpoints/suspicious", &root, None)
            .unwrap();
        assert!(export(&a, &[root]).unwrap_err().contains("source_private"));
        no_pins(&b);
    }
    #[test]
    fn rejects_manifest_truncation_trailing_corruption_and_extra_objects() {
        let (_t, a, b, root) = fixture();
        let bytes = export(&a, std::slice::from_ref(&root)).unwrap();
        let other = "0".repeat(40);
        assert!(import(&b, &bytes, &[other])
            .unwrap_err()
            .contains("manifest"));
        for n in [0, MAGIC.len(), bytes.len() - 1] {
            assert!(import(&b, &bytes[..n], std::slice::from_ref(&root)).is_err());
        }
        let mut extra = bytes.clone();
        extra.push(0);
        assert!(import(&b, &extra, std::slice::from_ref(&root))
            .unwrap_err()
            .contains("trailing"));
        let mut corrupt = bytes.clone();
        let offset = MAGIC.len() + 4 + 40 + 4;
        corrupt[offset] = if corrupt[offset] == b'0' { b'1' } else { b'0' };
        assert!(import(&b, &corrupt, std::slice::from_ref(&root)).is_err());
        // Extra valid blob is still forbidden even though its object hash is genuine.
        let blob = a
            .run(&["hash-object", "--stdin"], Some(b"private transcript"))
            .unwrap();
        let mut extra = bytes.clone();
        let count_at = MAGIC.len() + 4 + 40;
        let count = u32::from_be_bytes(extra[count_at..count_at + 4].try_into().unwrap());
        extra[count_at..count_at + 4].copy_from_slice(&(count + 1).to_be_bytes());
        extra.extend_from_slice(&blob[..40]);
        extra.push(3);
        extra.extend_from_slice(&18u32.to_be_bytes());
        extra.extend_from_slice(b"private transcript");
        assert!(import(&b, &extra, std::slice::from_ref(&root))
            .unwrap_err()
            .contains("unreachable"));
        no_pins(&b);
    }
    #[test]
    fn rejects_object_identity_corruption_without_installation() {
        let (_t, a, b, root) = fixture();
        let mut bytes = export(&a, std::slice::from_ref(&root)).unwrap();
        let mut at = MAGIC.len() + 4 + 40 + 4;
        loop {
            let k = bytes[at + 40];
            let n = u32::from_be_bytes(bytes[at + 41..at + 45].try_into().unwrap()) as usize;
            if k == 3 {
                bytes[at + 45] ^= 1;
                break;
            }
            at += 45 + n;
        }
        assert!(import(&b, &bytes, std::slice::from_ref(&root))
            .unwrap_err()
            .contains("identity"));
        no_pins(&b);
        assert!(b.tree(&root).is_err());
    }
    #[test]
    fn rejects_excluded_paths_and_symlinks() {
        let (_t, a, _b, _root) = fixture();
        let blob = String::from_utf8(
            a.run(&["hash-object", "-w", "--stdin"], Some(b"secret"))
                .unwrap(),
        )
        .unwrap();
        for (mode, name) in [("100644", ".env"), ("120000", "link"), ("100644", "CON")] {
            let tree = String::from_utf8(
                a.run(
                    &["mktree"],
                    Some(format!("{mode} blob {}\t{name}\n", blob.trim()).as_bytes()),
                )
                .unwrap(),
            )
            .unwrap();
            let root = a
                .commit(tree.trim(), &[], "Wipstash initial public import")
                .unwrap();
            assert!(export(&a, &[root]).is_err());
        }
    }
    #[test]
    fn refuses_allocation_bombs_before_quarantine() {
        let (_t, a, b, root) = fixture();
        let mut bytes = export(&a, std::slice::from_ref(&root)).unwrap();
        let offset = MAGIC.len() + 4 + 40 + 4 + 41;
        bytes[offset..offset + 4].copy_from_slice(&u32::MAX.to_be_bytes());
        assert!(import(&b, &bytes, std::slice::from_ref(&root))
            .unwrap_err()
            .contains("source_limit"));
        no_pins(&b);
    }
    #[test]
    fn rejects_small_graph_with_exponential_tree_expansion() {
        let mut objects = BTreeMap::new();
        let blob = "1".repeat(40);
        objects.insert(
            blob.clone(),
            Object {
                kind: 3,
                bytes: b"x".to_vec(),
            },
        );
        let mut child = blob;
        let mut child_kind = 3;
        for level in 0..15 {
            let oid = format!("{level:040x}");
            let raw: Vec<u8> = (0..20)
                .map(|i| u8::from_str_radix(&child[i * 2..i * 2 + 2], 16).unwrap())
                .collect();
            let mut bytes = Vec::new();
            for name in ["a", "b"] {
                bytes.extend_from_slice(
                    format!(
                        "{} {name}\0",
                        if child_kind == 3 { "100644" } else { "40000" }
                    )
                    .as_bytes(),
                );
                bytes.extend_from_slice(&raw);
            }
            objects.insert(oid.clone(), Object { kind: 2, bytes });
            child = oid;
            child_kind = 2;
        }
        let root = "f".repeat(40);
        let bytes=format!("tree {child}\nauthor A <a@b> 0 +0000\ncommitter A <a@b> 0 +0000\n\nWipstash initial public import\n").into_bytes();
        objects.insert(root.clone(), Object { kind: 1, bytes });
        assert!(validate(&objects, &[root])
            .unwrap_err()
            .contains("source_limit"));
    }
    #[cfg(unix)]
    #[test]
    fn import_never_runs_reference_hooks_or_content_filters() {
        use std::os::unix::fs::PermissionsExt;
        let (t, a, b, root) = fixture();
        let hooks = t.0.join("hooks");
        fs::create_dir(&hooks).unwrap();
        let marker = t.0.join("executed");
        let hook = hooks.join("reference-transaction");
        fs::write(&hook, format!("#!/bin/sh\ntouch '{}'\n", marker.display())).unwrap();
        fs::set_permissions(&hook, fs::Permissions::from_mode(0o755)).unwrap();
        b.run(&["config", "core.hooksPath", hooks.to_str().unwrap()], None)
            .unwrap();
        b.run(
            &[
                "config",
                "filter.evil.clean",
                &format!("touch '{}'", marker.display()),
            ],
            None,
        )
        .unwrap();
        let bytes = export(&a, std::slice::from_ref(&root)).unwrap();
        import(&b, &bytes, &[root]).unwrap();
        assert!(!marker.exists());
    }
    #[test]
    fn dropping_prepared_rejected_root_does_not_install_or_pin() {
        let (_t, a, b, root) = fixture();
        let bytes = export(&a, std::slice::from_ref(&root)).unwrap();
        let prepared = prepare(&b, &bytes, std::slice::from_ref(&root)).unwrap();
        assert!(prepared.git().tree(&root).is_ok());
        assert!(b.tree(&root).is_err());
        no_pins(&b);
        drop(prepared);
        assert!(b.tree(&root).is_err());
        no_pins(&b);
        assert!(!fs::read_dir(&b.repo).unwrap().any(|e| e
            .unwrap()
            .file_name()
            .to_string_lossy()
            .contains("quarantine")));
    }
    #[test]
    fn generated_pin_does_not_follow_symbolic_ref_into_authority() {
        let (_t, a, b, root) = fixture();
        let empty = b.empty_tree().unwrap();
        let old = b
            .commit(&empty, &[], "Wipstash initial public import")
            .unwrap();
        b.set_ref("refs/wipstash/integration", &old, None).unwrap();
        b.run(
            &[
                "symbolic-ref",
                &format!("refs/wipstash/transfers/{root}"),
                "refs/wipstash/integration",
            ],
            None,
        )
        .unwrap();
        let bytes = export(&a, std::slice::from_ref(&root)).unwrap();
        import(&b, &bytes, std::slice::from_ref(&root)).unwrap();
        assert_eq!(b.head("refs/wipstash/integration").unwrap(), old);
        assert_eq!(
            b.head(&format!("refs/wipstash/transfers/{root}")).unwrap(),
            root
        );
    }
}
