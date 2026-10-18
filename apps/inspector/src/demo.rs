//! Explicitly synthetic data for offline design review; never a live-data fallback.
use crate::model::*;
pub fn overview() -> Overview {
    Overview {
        read_only: true,
        workspaces: vec![
            Workspace {
                id: "atlas".into(),
                generation: 12,
                base: "8ea9f24d7b31c8b4481e34ca8c237c2b94e5cc01".into(),
                checkpoint: Some("save-atlas-12".into()),
            },
            Workspace {
                id: "nova".into(),
                generation: 7,
                base: "3b87c1930ab1f45948709bcdee72f827925779fd".into(),
                checkpoint: Some("save-nova-7".into()),
            },
            Workspace {
                id: "sage".into(),
                generation: 4,
                base: "8ea9f24d7b31c8b4481e34ca8c237c2b94e5cc01".into(),
                checkpoint: None,
            },
        ],
        proposals: vec![
            Proposal {
                id: "publish-atlas".into(),
                workspace: "atlas".into(),
                checkpoint: "save-atlas-11".into(),
                intent: "Make checkpoint writes atomic".into(),
                state: "integrated".into(),
                head: Some("8ea9f24d".into()),
            },
            Proposal {
                id: "publish-nova".into(),
                workspace: "nova".into(),
                checkpoint: "save-nova-7".into(),
                intent: "Simplify workspace adoption".into(),
                state: "quarantined".into(),
                head: None,
            },
        ],
        conflicts: vec![Conflict {
            id: "adopt-nova".into(),
            workspace: "nova".into(),
            target: "8ea9f24d".into(),
            base: "3b87c193".into(),
            generation: 7,
            state: "unresolved".into(),
        }],
    }
}
pub fn history(kind: &str, workspace: &str) -> History {
    let rows = if kind == "private" {
        vec![
            (
                "save-atlas-12",
                "atlas",
                "checkpoint",
                "Guard checkpoint writes with an atomic rename",
                "private",
                12,
            ),
            (
                "save-nova-7",
                "nova",
                "checkpoint",
                "Simplify the workspace adoption path",
                "private",
                7,
            ),
            (
                "save-atlas-11",
                "atlas",
                "checkpoint",
                "Preserve generation on interrupted writes",
                "private",
                11,
            ),
            (
                "save-sage-4",
                "sage",
                "checkpoint",
                "Add recovery-path regression coverage",
                "private",
                4,
            ),
            (
                "save-atlas-10",
                "atlas",
                "checkpoint",
                "Sketch the journal boundary",
                "private",
                10,
            ),
        ]
    } else {
        vec![
            (
                "integrate-18",
                "atlas",
                "promotion",
                "Make checkpoint writes atomic",
                "integrated",
                12,
            ),
            (
                "publish-nova",
                "nova",
                "proposal",
                "Simplify workspace adoption",
                "quarantined",
                7,
            ),
            (
                "publish-atlas",
                "atlas",
                "proposal",
                "Make checkpoint writes atomic",
                "integrated",
                11,
            ),
            (
                "integrate-17",
                "sage",
                "promotion",
                "Add recovery-path regression coverage",
                "integrated",
                4,
            ),
        ]
    };
    History {
        entries: rows
            .into_iter()
            .filter(|r| workspace.is_empty() || r.1 == workspace)
            .enumerate()
            .map(|(i, r)| Entry {
                id: format!("{}:{}", r.2, r.0),
                workspace: r.1.into(),
                kind: r.2.into(),
                title: r.3.into(),
                status: r.4.into(),
                commit: format!("8ea9f24d7b31c8b4481e34ca8c237c2b94e5cc0{i}"),
                base: "3b87c1930ab1f45948709bcdee72f827925779fd".into(),
                generation: Some(r.5),
                sequence: Some(42 - i as i64),
            })
            .collect(),
        next_offset: None,
    }
}
pub fn changes() -> Changes {
    Changes {
        files: vec![
            ChangedFile {
                path: "src/checkpoint.rs".into(),
                status: "M".into(),
                additions: Some(8),
                deletions: Some(3),
                binary: false,
            },
            ChangedFile {
                path: "src/journal.rs".into(),
                status: "M".into(),
                additions: Some(3),
                deletions: Some(1),
                binary: false,
            },
            ChangedFile {
                path: "tests/checkpoint_recovery.rs".into(),
                status: "A".into(),
                additions: Some(12),
                deletions: Some(0),
                binary: false,
            },
        ],
        next_offset: None,
        comparison: "adopted_base".into(),
    }
}
pub fn diff(path: &str) -> Diff {
    let text = match path {
        "src/checkpoint.rs" => "diff --git a/src/checkpoint.rs b/src/checkpoint.rs\n--- a/src/checkpoint.rs\n+++ b/src/checkpoint.rs\n@@ -38,10 +38,15 @@ impl CheckpointStore {\n     pub fn persist(&self, snapshot: &Snapshot) -> Result<()> {\n         let path = self.snapshot_path(&snapshot.id);\n-        let mut file = File::create(&path)?;\n-        serde_json::to_writer(&mut file, snapshot)?;\n-        file.flush()?;\n+        let staged = path.with_extension(\"pending\");\n+        let mut file = File::create(&staged)?;\n+\n+        serde_json::to_writer(&mut file, &snapshot)?;\n+        file.sync_all()?;\n+        fs::rename(&staged, &path)?;\n+\n+        self.sync_parent(&path)?;\n         Ok(())\n     }\n }\n",
        "src/journal.rs" => "--- a/src/journal.rs\n+++ b/src/journal.rs\n@@ -12,3 +12,5 @@\n pub fn commit(&self) -> Result<()> {\n-    self.flush()\n+    self.flush()?;\n+    self.sync_all()?;\n+    Ok(())\n }\n",
        _ => "--- /dev/null\n+++ b/tests/checkpoint_recovery.rs\n@@ -0,0 +1,12 @@\n+#[test]\n+fn interrupted_write_keeps_previous_checkpoint() {\n+    let store = TestStore::new();\n+    let first = store.checkpoint(\"initial\");\n+\n+    store.interrupt_next_write();\n+    assert!(store.checkpoint_result(\"pending\").is_err());\n+\n+    let recovered = store.reopen();\n+    assert_eq!(recovered.head(), first);\n+    assert_eq!(recovered.generation(), 1);\n+}\n"
    };
    Diff {
        path: path.into(),
        text: text.into(),
        binary: false,
        truncated: false,
    }
}
