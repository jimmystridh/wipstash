//! Independent pure-parser checks; no web runtime or sockets.
#[path = "../apps/inspector/src/diff.rs"]
mod diff;

#[test]
fn independent_multi_file_headers_do_not_inherit_hunk_numbers() {
    let input="diff --git a/a b/a\n--- a/a\n+++ b/a\n@@ -1 +1 @@\n-old\n+new\ndiff --git a/b b/b\n--- a/b\n+++ b/b\n@@ -10 +20 @@\n-b\n+c\n";
    let lines=diff::parse(input);
    for i in [6,7,8] {
        assert_eq!(lines[i].kind,"meta");
        assert_eq!((lines[i].old,lines[i].new),(None,None));
    }
    assert_eq!(lines[10].old,Some(10));
    assert_eq!(lines[11].new,Some(20));
}

#[test]
fn independent_extreme_hunk_numbers_do_not_overflow() {
    let input=format!("@@ -{},2 +{},2 @@\n-one\n-two\n+one\n+two\n",usize::MAX,usize::MAX);
    let lines=diff::parse(&input);
    assert_eq!(lines[2].old,Some(usize::MAX));
    assert_eq!(lines[4].new,Some(usize::MAX));
}

#[test]
fn independent_html_unicode_and_header_like_content_stays_literal() {
    let payload="<img src=x onerror=alert(1)> café 日本語 🚀";
    let input=format!("@@ -1,2 +1,2 @@\n--- old source\n-old\n+++ new source\n+{payload}\n");
    let lines=diff::parse(&input);
    assert_eq!(lines[1].kind,"remove");
    assert_eq!(lines[3].kind,"add");
    assert_eq!(lines[4].text,format!("+{payload}"));
    let split=diff::split(&lines);
    assert_eq!(split[2].right.as_ref().unwrap().text,format!("+{payload}"));
}
