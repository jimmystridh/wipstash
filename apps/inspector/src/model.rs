use serde::{Deserialize, Serialize};
#[derive(Clone, Debug, Default, PartialEq, Deserialize, Serialize)]
pub struct Overview {
    pub read_only: bool,
    pub workspaces: Vec<Workspace>,
    pub proposals: Vec<Proposal>,
    pub conflicts: Vec<Conflict>,
}
#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
pub struct Workspace {
    pub id: String,
    pub generation: u64,
    pub base: String,
    pub checkpoint: Option<String>,
}
#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
pub struct Proposal {
    pub id: String,
    pub workspace: String,
    pub checkpoint: String,
    pub intent: String,
    pub state: String,
    pub head: Option<String>,
}
#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
pub struct Conflict {
    pub id: String,
    pub workspace: String,
    pub target: String,
    pub base: String,
    pub generation: u64,
    pub state: String,
}
#[derive(Clone, Debug, Default, PartialEq, Deserialize, Serialize)]
pub struct History {
    pub entries: Vec<Entry>,
    pub next_offset: Option<usize>,
}
#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
pub struct Entry {
    pub id: String,
    pub workspace: String,
    pub kind: String,
    pub title: String,
    pub status: String,
    pub commit: String,
    pub base: String,
    pub generation: Option<u64>,
    #[serde(default)]
    pub sequence: Option<i64>,
}
#[derive(Clone, Debug, Default, PartialEq, Deserialize, Serialize)]
pub struct Changes {
    pub files: Vec<ChangedFile>,
    pub next_offset: Option<usize>,
    pub comparison: String,
}
#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
pub struct ChangedFile {
    pub path: String,
    pub status: String,
    pub additions: Option<u64>,
    pub deletions: Option<u64>,
    pub binary: bool,
}
#[derive(Clone, Debug, Default, PartialEq, Deserialize, Serialize)]
pub struct Diff {
    pub path: String,
    pub text: String,
    pub binary: bool,
    pub truncated: bool,
}

pub fn short(value: &str) -> String {
    value.chars().take(8).collect()
}
pub fn encode(value: &str) -> String {
    value
        .bytes()
        .map(|b| {
            if b.is_ascii_alphanumeric() || b"-_.~".contains(&b) {
                (b as char).to_string()
            } else {
                format!("%{b:02X}")
            }
        })
        .collect()
}
pub fn state_class(state: &str) -> &'static str {
    match state {
        "integrated" | "accepted" | "promoted" | "applied" | "published" => "good",
        "quarantined" | "conflict" | "conflicted" | "blocked" | "failed" | "unresolved" => {
            "warning"
        }
        "queued" | "pending" | "proposed" => "pending",
        _ => "neutral",
    }
}
pub fn comparison_label(value: &str) -> &str {
    match value {
        "adopted_base" => "Adopted base → checkpoint",
        "proposal_base" => "Proposal base → published snapshot",
        "previous_shared_head" => "Previous shared head → integration",
        _ => "Snapshot comparison",
    }
}
/// Preserve a compact status glyph without inventing a new status vocabulary.
pub fn file_status_symbol(status: &str) -> &str {
    match status {
        "added" => "A",
        "deleted" => "D",
        "modified" => "M",
        "type_changed" => "T",
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn opaque_ids_and_paths_are_query_encoded() {
        assert_eq!(
            encode("checkpoint:a/b &?é"),
            "checkpoint%3Aa%2Fb%20%26%3F%C3%A9"
        );
    }
    #[test]
    fn short_unicode_is_safe() {
        assert_eq!(short("ééééééééé"), "éééééééé");
    }
    #[test]
    fn unknown_status_is_not_claimed_successful() {
        assert_eq!(state_class("new_state"), "neutral");
    }
}
