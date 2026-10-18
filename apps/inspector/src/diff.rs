//! Pure, bounded unified-diff presentation. Source stays text; never HTML.
#[derive(Clone, Debug, PartialEq)]
pub struct Line {
    pub kind: &'static str,
    pub old: Option<usize>,
    pub new: Option<usize>,
    pub text: String,
}
#[derive(Clone, Debug, PartialEq)]
pub struct SplitLine {
    pub left: Option<Line>,
    pub right: Option<Line>,
    pub heading: Option<String>,
}
pub const MAX_LINES: usize = 8000;
pub fn parse(input: &str) -> Vec<Line> {
    let mut old: usize = 0;
    let mut new: usize = 0;
    let mut in_hunk = false;
    input
        .lines()
        .take(MAX_LINES)
        .map(|s| {
            if s.starts_with("diff --git ") {
                in_hunk = false;
            }
            if s.starts_with("@@ ") {
                let parts: Vec<_> = s.split_whitespace().collect();
                old = parts
                    .get(1)
                    .and_then(|p| p.trim_start_matches('-').split(',').next()?.parse().ok())
                    .unwrap_or(0);
                new = parts
                    .get(2)
                    .and_then(|p| p.trim_start_matches('+').split(',').next()?.parse().ok())
                    .unwrap_or(0);
                in_hunk = true;
                return Line {
                    kind: "hunk",
                    old: None,
                    new: None,
                    text: s.into(),
                };
            }
            let (kind, a, b) = if in_hunk && s.starts_with('+') {
                let n = new;
                new = new.saturating_add(1);
                ("add", None, Some(n))
            } else if in_hunk && s.starts_with('-') {
                let n = old;
                old = old.saturating_add(1);
                ("remove", Some(n), None)
            } else if in_hunk && s.starts_with(' ') {
                let a = old;
                let b = new;
                old = old.saturating_add(1);
                new = new.saturating_add(1);
                ("context", Some(a), Some(b))
            } else {
                ("meta", None, None)
            };
            Line {
                kind,
                old: a,
                new: b,
                text: s.into(),
            }
        })
        .collect()
}
pub fn split(lines: &[Line]) -> Vec<SplitLine> {
    let mut result = Vec::new();
    let mut i = 0;
    while i < lines.len() {
        let line = &lines[i];
        match line.kind {
            "remove" | "add" => {
                let mut removed = Vec::new();
                let mut added = Vec::new();
                while i < lines.len() && matches!(lines[i].kind, "remove" | "add") {
                    if lines[i].kind == "remove" {
                        removed.push(lines[i].clone());
                    } else {
                        added.push(lines[i].clone());
                    }
                    i += 1;
                }
                for j in 0..removed.len().max(added.len()) {
                    result.push(SplitLine {
                        left: removed.get(j).cloned(),
                        right: added.get(j).cloned(),
                        heading: None,
                    });
                }
            }
            "context" => {
                result.push(SplitLine {
                    left: Some(line.clone()),
                    right: Some(line.clone()),
                    heading: None,
                });
                i += 1;
            }
            _ => {
                result.push(SplitLine {
                    left: None,
                    right: None,
                    heading: Some(line.text.clone()),
                });
                i += 1;
            }
        }
    }
    result
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn numbers_follow_hunks_and_changes() {
        let lines = parse("--- a/x\n+++ b/x\n@@ -9,2 +12,3 @@\n same\n-old\n+new\n+more\n\\ No newline at end of file\n");
        assert_eq!((lines[3].old, lines[3].new), (Some(9), Some(12)));
        assert_eq!((lines[4].old, lines[4].new), (Some(10), None));
        assert_eq!(lines[6].new, Some(14));
        assert_eq!(lines[7].kind, "meta");
    }
    #[test]
    fn split_pairs_changed_blocks_and_keeps_context() {
        let lines = parse("@@ -1,2 +1,3 @@\n-a\n+b\n+c\n d");
        let rows = split(&lines);
        assert_eq!(rows.len(), 4);
        assert_eq!(rows[1].left.as_ref().unwrap().text, "-a");
        assert_eq!(rows[1].right.as_ref().unwrap().text, "+b");
        assert!(rows[2].left.is_none());
        assert_eq!(rows[3].left, rows[3].right);
    }
    #[test]
    fn handles_empty_binary_and_zero_length_hunks() {
        assert!(parse("").is_empty());
        assert_eq!(parse("Binary files a/x and b/x differ")[0].kind, "meta");
        assert_eq!(parse("@@ -0,0 +1 @@\n+first")[1].new, Some(1));
    }
    #[test]
    fn bounds_render_work() {
        assert_eq!(parse(&" context\n".repeat(MAX_LINES + 20)).len(), MAX_LINES);
    }
    #[test]
    fn multi_file_headers_do_not_consume_line_numbers() {
        let lines = parse("diff --git a/a b/a\n@@ -1 +1 @@\n-a\n+b\ndiff --git a/b b/b\n--- a/b\n+++ b/b\n@@ -2 +3 @@\n x");
        assert_eq!(lines[5].kind, "meta");
        assert_eq!(lines[6].kind, "meta");
        assert_eq!((lines[8].old, lines[8].new), (Some(2), Some(3)));
    }
    #[test]
    fn extreme_hunk_indices_do_not_overflow() {
        let text = format!("@@ -{},2 +{},2 @@\n x\n y", usize::MAX, usize::MAX);
        let lines = parse(&text);
        assert_eq!(lines[2].old, Some(usize::MAX));
        assert_eq!(lines[2].new, Some(usize::MAX));
    }
}
