use dioxus::prelude::*;
use wipstash_inspector_ui::{model::Diff, DiffView, Inspector};

#[test]
fn demo_is_actual_dioxus_and_always_labelled_synthetic() {
    let mut dom = VirtualDom::new(|| rsx! { Inspector { demo_mode: true } });
    dom.rebuild_in_place();
    let html = dioxus_ssr::render(&dom);
    for expected in [
        "Synthetic workspace",
        "Recovery",
        "Make checkpoint writes atomic",
        "src/checkpoint.rs",
        "fs::rename",
        "Read only",
        "Mobile workspace",
        "Shared history",
    ] {
        assert!(html.contains(expected), "missing {expected}");
    }
    assert!(!html.contains("dangerous_inner_html"));
}

#[test]
fn source_is_escaped_as_text_in_both_diff_layouts() {
    for split_view in [false, true] {
        let patch = Diff {
            path: "<&file>.rs".into(),
            text: "@@ -1 +1 @@\n-hello\n+<script>alert('secret')</script> ☃\n".into(),
            binary: false,
            truncated: false,
        };
        let html = dioxus_ssr::render_element(rsx! { DiffView { patch, split_view, wrap: true } });
        assert!(
            html.contains("&lt;script&gt;") || html.contains("&#60;script&#62;"),
            "{html}"
        );
        assert!(!html.contains("<script>"));
        assert!(html.contains("☃"));
    }
}

#[test]
fn binary_and_truncation_are_explicit() {
    let patch = Diff {
        path: "asset.bin".into(),
        text: "".into(),
        binary: true,
        truncated: true,
    };
    let html =
        dioxus_ssr::render_element(rsx! { DiffView { patch, split_view: false, wrap: false } });
    assert!(html.contains("Binary file changed"));
    assert!(html.contains("preview is truncated"));
}

#[test]
fn absent_live_data_is_not_replaced_with_demo() {
    let mut dom = VirtualDom::new(|| rsx! { Inspector { demo_mode: false } });
    dom.rebuild_in_place();
    let html = dioxus_ssr::render(&dom);
    assert!(!html.contains("Guard checkpoint writes"));
    assert!(!html.contains("Synthetic workspace"));
    assert!(html.contains("Loading workspace history"));
}
