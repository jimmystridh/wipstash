pub mod demo;
pub mod diff;
pub mod model;
use dioxus::prelude::*;
use model::*;

pub const STYLES: &str = include_str!("../assets/inspector.css");

#[cfg(target_arch = "wasm32")]
async fn get<T: serde::de::DeserializeOwned>(url: &str) -> Result<T, String> {
    let response = gloo_net::http::Request::get(url)
        .send()
        .await
        .map_err(|_| {
            "Could not reach the local inspector. Check that its server is running, then refresh."
                .to_string()
        })?;
    if !response.ok() {
        let status = response.status();
        // Never display untrusted server HTML or leak arbitrary response bodies.
        return Err(format!("The inspector returned HTTP {status}. Refresh, or check the local server's configuration."));
    }
    response.json().await.map_err(|_| "The server response did not match the inspector API. Check that the UI and server versions match.".into())
}
#[cfg(not(target_arch = "wasm32"))]
async fn get<T: serde::de::DeserializeOwned>(_: &str) -> Result<T, String> {
    Err("Live requests require the browser build.".into())
}

pub fn demo_requested() -> bool {
    #[cfg(target_arch = "wasm32")]
    {
        web_sys::window()
            .and_then(|w| w.location().search().ok())
            .is_some_and(|q| q.trim_start_matches('?').split('&').any(|v| v == "demo=1"))
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        false
    }
}
fn focus_element(id: &str) {
    #[cfg(target_arch = "wasm32")]
    {
        use wasm_bindgen::JsCast;
        if let Some(element) = web_sys::window()
            .and_then(|w| w.document())
            .and_then(|d| d.get_element_by_id(id))
        {
            if let Some(el) = element.dyn_ref::<web_sys::HtmlElement>() {
                let _ = el.focus();
            }
        }
    }
    let _ = id;
}

fn editable_has_focus() -> bool {
    #[cfg(target_arch = "wasm32")]
    {
        web_sys::window()
            .and_then(|w| w.document())
            .and_then(|d| d.active_element())
            .is_some_and(|el| {
                matches!(el.tag_name().as_str(), "INPUT" | "TEXTAREA" | "SELECT")
                    || el.get_attribute("contenteditable").as_deref() == Some("true")
            })
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        false
    }
}
fn initial_theme() -> bool {
    #[cfg(target_arch = "wasm32")]
    {
        web_sys::window()
            .and_then(|w| w.local_storage().ok().flatten())
            .and_then(|s| s.get_item("wipstash-theme").ok().flatten())
            .is_some_and(|v| v == "light")
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        false
    }
}
fn save_theme(light: bool) {
    #[cfg(target_arch = "wasm32")]
    if let Some(storage) = web_sys::window().and_then(|w| w.local_storage().ok().flatten()) {
        let _ = storage.set_item("wipstash-theme", if light { "light" } else { "dark" });
    }
    let _ = light;
}

/// The same component is rendered in the WASM application and the SSR design preview.
#[component]
pub fn Inspector(#[props(default)] demo_mode: bool) -> Element {
    let mut light = use_signal(initial_theme);
    let mut kind = use_signal(|| "private".to_string());
    let mut workspace = use_signal(String::new);
    let mut query = use_signal(String::new);
    let mut file_query = use_signal(String::new);
    let mut selected = use_signal(|| None::<String>);
    let mut selected_path = use_signal(|| None::<String>);
    let mut split_view = use_signal(|| false);
    let mut wrap = use_signal(|| false);
    let mut help = use_signal(|| false);
    use_effect(move || {
        if help() {
            focus_element("shortcut-close");
        }
    });
    let mut refresh = use_signal(|| 0u64);
    let mut history_offset = use_signal(|| 0usize);
    let mut file_offset = use_signal(|| 0usize);
    let mut overview = use_resource(move || async move {
        let _ = refresh();
        if demo_mode {
            Ok(demo::overview())
        } else {
            get::<Overview>("/api/overview").await
        }
    });
    let mut history = use_resource(move || {
        let k = kind();
        let w = workspace();
        let offset = history_offset();
        let revision = refresh();
        async move {
            let workspace_query = if w.is_empty() {
                String::new()
            } else {
                format!("&workspace={}", encode(&w))
            };
            let result = if demo_mode {
                Ok(demo::history(&k, &w))
            } else {
                get::<History>(&format!(
                    "/api/history?kind={}&limit=50&offset={offset}{workspace_query}",
                    encode(&k)
                ))
                .await
            };
            ((k, w, offset, revision), result)
        }
    });
    let overview_result = overview
        .read()
        .clone()
        .or_else(|| demo_mode.then(|| Ok(demo::overview())));
    let history_result = history
        .read()
        .clone()
        .filter(|(key, _)| *key == (kind(), workspace(), history_offset(), refresh()))
        .map(|(_, result)| result)
        .or_else(|| demo_mode.then(|| Ok(demo::history(&kind(), &workspace()))));
    let data = overview_result
        .as_ref()
        .and_then(|r| r.as_ref().ok())
        .cloned()
        .unwrap_or_default();
    let history_data = history_result
        .as_ref()
        .and_then(|r| r.as_ref().ok())
        .cloned()
        .unwrap_or_default();
    let needle = query().to_lowercase();
    let visible: Vec<Entry> = history_data
        .entries
        .iter()
        .filter(|e| {
            format!(
                "{} {} {} {} {}",
                e.title, e.id, e.workspace, e.status, e.commit
            )
            .to_lowercase()
            .contains(&needle)
        })
        .cloned()
        .collect();
    let entry = visible
        .iter()
        .find(|e| selected().as_deref() == Some(e.id.as_str()))
        .or_else(|| visible.first())
        .cloned();
    // Resource keys are derived from current history, so switching filters cannot leave a stale diff on screen.
    let current_entry = entry.as_ref().map(|e| e.id.clone()).unwrap_or_default();
    let entry_key = use_memo(use_reactive((&current_entry,), |(id,)| id));
    let mut changes = use_resource(move || {
        let id = entry_key();
        let offset = file_offset();
        let revision = refresh();
        async move {
            let result = if id.is_empty() {
                Ok(Changes::default())
            } else if demo_mode {
                Ok(demo::changes())
            } else {
                get::<Changes>(&format!(
                    "/api/changes?entry={}&limit=100&offset={offset}",
                    encode(&id)
                ))
                .await
            };
            ((id, offset, revision), result)
        }
    });
    let changes_result = changes
        .read()
        .clone()
        .filter(|(key, _)| *key == (current_entry.clone(), file_offset(), refresh()))
        .map(|(_, result)| result)
        .or_else(|| demo_mode.then(|| Ok(demo::changes())));
    let changes_data = changes_result
        .as_ref()
        .and_then(|r| r.as_ref().ok())
        .cloned()
        .unwrap_or_default();
    let file_needle = file_query().to_lowercase();
    let files: Vec<ChangedFile> = changes_data
        .files
        .iter()
        .filter(|f| f.path.to_lowercase().contains(&file_needle))
        .cloned()
        .collect();
    let file = files
        .iter()
        .find(|f| selected_path().as_deref() == Some(f.path.as_str()))
        .or_else(|| files.first())
        .cloned();
    let current_path = file.as_ref().map(|f| f.path.clone()).unwrap_or_default();
    let path_key = use_memo(use_reactive((&current_path,), |(path,)| path));
    let mut patch = use_resource(move || {
        let id = entry_key();
        let path = path_key();
        let revision = refresh();
        async move {
            let result = if id.is_empty() || path.is_empty() {
                Ok(Diff::default())
            } else if demo_mode {
                Ok(demo::diff(&path))
            } else {
                get::<Diff>(&format!(
                    "/api/diff?entry={}&path={}",
                    encode(&id),
                    encode(&path)
                ))
                .await
            };
            ((id, path, revision), result)
        }
    });
    let patch_result = patch
        .read()
        .clone()
        .filter(|(key, _)| *key == (current_entry.clone(), current_path.clone(), refresh()))
        .map(|(_, result)| result)
        .or_else(|| demo_mode.then(|| Ok(demo::diff(&current_path))));
    let selected_for_keys = entry.clone();
    let visible_for_keys = visible.clone();
    let next_history = history_data.next_offset;
    let next_files = changes_data.next_offset;
    let all_additions: u64 = changes_data.files.iter().filter_map(|f| f.additions).sum();
    let all_deletions: u64 = changes_data.files.iter().filter_map(|f| f.deletions).sum();
    let active_workspace = data
        .workspaces
        .iter()
        .find(|w| w.id == workspace())
        .cloned();
    let status_message = if demo_mode {
        "Synthetic demo · no connection to your workspaces"
    } else {
        "Read-only · your files stay untouched"
    };

    rsx! {
        style { "{STYLES}" }
        div {
            class: if light() { "inspector light" } else { "inspector" },
            onkeydown: move |event: KeyboardEvent| {
                if event.key() == Key::Escape { if help() { help.set(false); focus_element("shortcut-toggle"); } return; }
                if help() { return; }
                if editable_has_focus() || event.modifiers().ctrl() || event.modifiers().meta() || event.modifiers().alt() { return; }
                if let Key::Character(key) = event.key() { match key.as_str() {
                    "/" => { event.prevent_default(); focus_element("history-search"); },
                    "?" => help.set(!help()),
                    "s" => split_view.set(!split_view()),
                    "j" | "k" => {
                        let index = visible_for_keys.iter().position(|e| selected_for_keys.as_ref().is_some_and(|s| s.id == e.id)).unwrap_or(0);
                        let next = if key == "j" { (index + 1).min(visible_for_keys.len().saturating_sub(1)) } else { index.saturating_sub(1) };
                        if let Some(e) = visible_for_keys.get(next) { selected.set(Some(e.id.clone())); selected_path.set(None); file_offset.set(0); }
                    }, _ => ()
                }}
            },
            a { class: "skip-link", href: "#diff-content", "Skip to diff" }
            header { class: "topbar",
                div { class: "brand", span { class: "brand-mark", "w" } span { "wipstash" } span { class: "brand-divider", "/" } span { class: "product-name", "inspector" } }
                div { class: "top-actions",
                    span { class: "readonly", span { class: "status-dot" } "Read only" }
                    button { class: "icon-button", title: "Refresh data", aria_label: "Refresh all inspector data", onclick: move |_| { refresh += 1; overview.restart(); history.restart(); changes.restart(); patch.restart(); }, Icon { name: "refresh" } }
                    button { class: "icon-button", title: "Switch color theme", aria_label: "Switch light or dark theme", onclick: move |_| { let next = !light(); light.set(next); save_theme(next); }, Icon { name: "sun" } }
                    button { id: "shortcut-toggle", class: "icon-button", title: "Keyboard shortcuts (?)", aria_label: "Show keyboard shortcuts", onclick: move |_| help.set(!help()), Icon { name: "keyboard" } }
                }
            }
            if demo_mode { div { class: "demo-banner", span { "DEMO" } "Synthetic workspace and source data for interface preview." a { href: "/", "Open live inspector ↗" } } }
            div { class: "workbench",
                aside { class: "sidebar", aria_label: "Workspace and history navigation",
                    div { class: "project-label", "LOCAL WORKSPACE" }
                    label { class: "workspace-picker", Icon { name: "workspace" }
                        select { aria_label: "Filter by workspace", value: "{workspace}", onchange: move |e| { workspace.set(e.value()); selected.set(None); selected_path.set(None); history_offset.set(0); file_offset.set(0); },
                            option { value: "", "All workspaces" }
                            for w in &data.workspaces { option { value: "{w.id}", "{w.id}" } }
                        }
                    }
                    if let Some(w) = active_workspace {
                        div { class: "workspace-meta", span { "Generation {w.generation}" } code { title: "Adopted base: {w.base}", "{short(&w.base)}" } }
                    } else { div { class: "workspace-meta", "{data.workspaces.len()} isolated workspaces" } }
                    nav { class: "history-nav", aria_label: "History visibility",
                        button { class: if kind() == "private" { "nav-item active" } else { "nav-item" }, aria_pressed: kind() == "private", onclick: move |_| { kind.set("private".into()); selected.set(None); selected_path.set(None); history_offset.set(0); file_offset.set(0); }, Icon { name: "lock" } "Private checkpoints" }
                        button { class: if kind() == "shared" { "nav-item active" } else { "nav-item" }, aria_pressed: kind() == "shared", onclick: move |_| { kind.set("shared".into()); selected.set(None); selected_path.set(None); history_offset.set(0); file_offset.set(0); }, Icon { name: "branch" } "Shared history" }
                    }
                    div { class: "section-label", span { "WORKSPACES" } span { "{data.workspaces.len()}" } }
                    div { class: "workspace-list",
                        for w in &data.workspaces {
                            button { class: if workspace() == w.id { "workspace-row chosen" } else { "workspace-row" }, onclick: { let id = w.id.clone(); move |_| { workspace.set(id.clone()); selected.set(None); selected_path.set(None); history_offset.set(0); file_offset.set(0); } },
                                span { class: "workspace-avatar", "{w.id.chars().next().unwrap_or('w')}" } span { "{w.id}" } span { class: "generation", "g{w.generation}" }
                            }
                        }
                    }
                    div { class: "sidebar-bottom",
                        div { class: "section-label", "COLLABORATION" }
                        div { class: "stat-row", span { "Proposals" } span { "{data.proposals.len()}" } }
                        div { class: "stat-row", span { "Conflict records" } span { class: if data.conflicts.is_empty() { "" } else { "warning-text" }, "{data.conflicts.len()}" } }
                        p { class: "boundary-note", Icon { name: "lock" } "Checkpoints stay private until deliberately published." }
                    }
                }
                main { class: "main",
                    div { class: "mobile-navigation",
                        label { class: "workspace-picker", Icon { name: "workspace" }
                            select { aria_label: "Mobile workspace", value: "{workspace}", onchange: move |e| { workspace.set(e.value()); selected.set(None); selected_path.set(None); history_offset.set(0); file_offset.set(0); },
                                option { value: "", "All workspaces" }
                                for w in &data.workspaces { option { value: "{w.id}", "{w.id}" } }
                            }
                        }
                        div { class: "mobile-tabs",
                            button { class: if kind() == "private" { "nav-item active" } else { "nav-item" }, aria_pressed: kind() == "private", onclick: move |_| { kind.set("private".into()); selected.set(None); selected_path.set(None); history_offset.set(0); file_offset.set(0); }, Icon { name: "lock" } "Private checkpoints" }
                            button { class: if kind() == "shared" { "nav-item active" } else { "nav-item" }, aria_pressed: kind() == "shared", onclick: move |_| { kind.set("shared".into()); selected.set(None); selected_path.set(None); history_offset.set(0); file_offset.set(0); }, Icon { name: "branch" } "Shared history" }
                        }
                    }
                    div { class: "page-heading",
                        div { div { class: "eyebrow", "WORKSPACE ACTIVITY" } h1 { if kind() == "private" { "Private checkpoints" } else { "Shared history" } } p { if kind() == "private" { "Every saved step. Only shared when you choose." } else { "Published proposals and their integration into the shared head." } } }
                        span { class: "scope-pill", Icon { name: if kind() == "private" { "lock" } else { "branch" } } if kind() == "private" { "Private scope" } else { "Shared scope" } }
                    }
                    if let Some(Err(error)) = &overview_result { div { class: "notice error", role: "alert", "{error}" } }
                    div { class: "inspection-grid",
                        section { class: "history-panel", aria_label: "History entries",
                            div { class: "panel-toolbar", span { "History" } span { class: "count", "{visible.len()}" } span { class: "muted push", "Journal order" } }
                            div { class: "search-field", Icon { name: "search" } input { id: "history-search", aria_label: "Filter loaded history", placeholder: "Filter loaded history…", value: "{query}", oninput: move |e| query.set(e.value()) } kbd { "/" } }
                            div { class: "history-list",
                                match &history_result {
                                    None => rsx! { Loading { label: "Loading workspace history…" } },
                                    Some(Err(error)) => rsx! { ErrorState { message: error.clone(), onretry: move |_| history.restart() } },
                                    Some(Ok(_)) if visible.is_empty() => rsx! { EmptyState { title: if query().is_empty() { "No history yet" } else { "No matching entries" }, detail: if query().is_empty() { "Saved checkpoints and published proposals will appear here." } else { "Try another title, workspace, status, or snapshot ID." } } },
                                    _ => rsx! {
                                        for e in &visible {
                                            button { key: "{e.id}", class: if entry.as_ref().is_some_and(|s| s.id == e.id) { "history-entry selected" } else { "history-entry" }, aria_pressed: entry.as_ref().is_some_and(|s| s.id == e.id), onclick: { let id = e.id.clone(); move |_| { selected.set(Some(id.clone())); selected_path.set(None); file_offset.set(0); } },
                                                div { class: "timeline", span { class: "timeline-node {state_class(&e.status)}" } }
                                                div { class: "entry-body", div { class: "entry-top", span { class: "entry-workspace", "{e.workspace}" } code { "{short(&e.commit)}" } } h3 { "{e.title}" } div { class: "entry-bottom", Badge { status: e.status.clone() } span { class: "entry-kind", if let Some(seq) = e.sequence { "#{seq}" } else { "order unknown" } } if let Some(g) = e.generation { span { class: "entry-generation", "g{g}" } } } }
                                            }
                                        }
                                    }
                                }
                            }
                            div { class: "pagination",
                                button { disabled: history_offset() == 0, onclick: move |_| { history_offset.set(history_offset().saturating_sub(50)); selected.set(None); selected_path.set(None); file_offset.set(0); }, "← Newer" }
                                span { "Page {history_offset() / 50 + 1}" }
                                button { disabled: next_history.is_none(), onclick: move |_| { if let Some(n) = next_history { history_offset.set(n); selected.set(None); selected_path.set(None); file_offset.set(0); } }, "Older →" }
                            }
                        }
                        section { class: "detail-panel", aria_label: "Selected snapshot",
                            if let Some(e) = &entry {
                                div { class: "snapshot-heading", div { class: "snapshot-top", span { class: "eyebrow", "{e.kind}" } Badge { status: e.status.clone() } } h2 { "{e.title}" } div { class: "snapshot-meta", span { Icon { name: "workspace" } "{e.workspace}" } code { title: "Snapshot: {e.commit}", "{short(&e.commit)}" } span { "←" } code { title: "Comparison base: {e.base}", "{short(&e.base)}" } if let Some(g) = e.generation { span { "Generation {g}" } } } }
                                if state_class(&e.status) == "warning" { div { class: "notice warning", Icon { name: "alert" } "This entry needs attention. Inspect the changes here; resolve it through the workspace tools." } }
                                div { class: "changes-toolbar", span { "Changes" } span { class: "count", "{changes_data.files.len()}" } span { class: "diff-stat add-text", "+{all_additions}" } span { class: "diff-stat remove-text", "−{all_deletions}" } span { class: "comparison", "{comparison_label(&changes_data.comparison)}" } }
                                div { class: "changes-layout",
                                    aside { class: "files-panel", aria_label: "Changed files",
                                        div { class: "search-field file-search", Icon { name: "search" } input { aria_label: "Filter loaded changed files", placeholder: "Find a file…", value: "{file_query}", oninput: move |e| file_query.set(e.value()) } }
                                        match &changes_result {
                                            None => rsx! { Loading { label: "Loading files…" } },
                                            Some(Err(error)) => rsx! { ErrorState { message: error.clone(), onretry: move |_| changes.restart() } },
                                            _ => rsx! { for f in &files {
                                                button { key: "{f.path}", class: if file.as_ref().is_some_and(|s| s.path == f.path) { "file-row selected-file" } else { "file-row" }, title: "{f.path}", aria_pressed: file.as_ref().is_some_and(|s| s.path == f.path), onclick: { let path = f.path.clone(); move |_| selected_path.set(Some(path.clone())) },
                                                    span { class: "file-status", title: "{f.status}", "{file_status_symbol(&f.status)}" } span { class: "file-path", "{f.path}" } if f.binary { span { class: "binary-label", "bin" } }
                                                }
                                            } if files.is_empty() { p { class: "small-empty", "No matching files." } } }
                                        }
                                        if file_offset() > 0 || next_files.is_some() { div { class: "file-pages", button { disabled: file_offset() == 0, onclick: move |_| { file_offset.set(file_offset().saturating_sub(100)); selected_path.set(None); }, "←" } span { "Page {file_offset() / 100 + 1}" } button { disabled: next_files.is_none(), onclick: move |_| { if let Some(n) = next_files { file_offset.set(n); selected_path.set(None); } }, "→" } } }
                                    }
                                    div { class: "diff-panel", id: "diff-content", tabindex: "-1",
                                        if let Some(f) = &file {
                                            div { class: "diff-toolbar", div { class: "diff-path", Icon { name: "file" } span { title: "{f.path}", "{f.path}" } } div { class: "diff-controls", button { class: if wrap() { "small-button on" } else { "small-button" }, aria_pressed: wrap(), onclick: move |_| wrap.set(!wrap()), "Wrap" } div { class: "segmented", aria_label: "Diff layout", button { class: if !split_view() { "on" } else { "" }, aria_pressed: !split_view(), onclick: move |_| split_view.set(false), "Unified" } button { class: if split_view() { "on" } else { "" }, aria_pressed: split_view(), onclick: move |_| split_view.set(true), "Split" } } } }
                                            match &patch_result {
                                                None => rsx! { Loading { label: "Loading diff…" } },
                                                Some(Err(error)) => rsx! { ErrorState { message: error.clone(), onretry: move |_| patch.restart() } },
                                                Some(Ok(p)) => rsx! { DiffView { patch: p.clone(), split_view: split_view(), wrap: wrap() } },
                                            }
                                        } else { EmptyState { title: "No file selected", detail: "Choose a changed file to inspect its diff." } }
                                    }
                                }
                            } else { EmptyState { title: "Your work, in perspective", detail: "Select a checkpoint or published entry to inspect what changed." } }
                        }
                    }
                    if !data.conflicts.is_empty() && kind() == "shared" {
                        details { class: "conflict-details", summary { "Conflict records ({data.conflicts.len()})" } for c in &data.conflicts { div { class: "conflict-row", code { "{c.id}" } span { "{c.workspace}" } Badge { status: c.state.clone() } span { "Generation {c.generation}" } } } }
                    }
                }
            }
            footer { class: "statusbar", span { span { class: "status-dot" } "{status_message}" } span { class: "footer-hint", kbd { "j" } kbd { "k" } " navigate · " kbd { "s" } " split · " kbd { "?" } " shortcuts" } }
            if help() { div { class: "modal-backdrop", onclick: move |_| { help.set(false); focus_element("shortcut-toggle"); }, div { class: "shortcut-dialog", role: "dialog", aria_modal: "true", aria_label: "Keyboard shortcuts", onkeydown: move |e: KeyboardEvent| { if e.key() == Key::Tab { e.prevent_default(); } }, onclick: move |e| e.stop_propagation(), h2 { "A little less clicking." } p { "Shortcuts work outside text fields." } dl { dt { kbd { "/" } } dd { "Filter history" } dt { kbd { "j" } " / " kbd { "k" } } dd { "Next / previous entry" } dt { kbd { "s" } } dd { "Toggle split diff" } dt { kbd { "?" } } dd { "Show shortcuts" } dt { kbd { "Esc" } } dd { "Close this panel" } } button { id: "shortcut-close", class: "primary-button", autofocus: true, onclick: move |_| { help.set(false); focus_element("shortcut-toggle"); }, "Got it" } } } }
        }
    }
}

#[component]
fn Badge(status: String) -> Element {
    rsx! { span { class: "badge {state_class(&status)}", "{status}" } }
}
#[component]
fn Loading(label: String) -> Element {
    rsx! { div { class: "loading-state", role: "status", span { class: "loading-line" } span { class: "loading-line short" } p { "{label}" } } }
}
#[component]
fn EmptyState(title: String, detail: String) -> Element {
    rsx! { div { class: "empty-state", Icon { name: "layers" } h3 { "{title}" } p { "{detail}" } } }
}
#[component]
fn ErrorState(message: String, onretry: EventHandler<()>) -> Element {
    rsx! { div { class: "error-state", role: "alert", Icon { name: "alert" } p { "{message}" } button { class: "small-button", onclick: move |_| onretry.call(()), "Try again" } } }
}

#[component]
pub fn DiffView(patch: Diff, split_view: bool, wrap: bool) -> Element {
    let lines = diff::parse(&patch.text);
    let line_count = patch.text.lines().count();
    rsx! {
        if patch.binary { div { class: "notice", "Binary file changed. A text diff is unavailable." } }
        if patch.truncated || line_count > diff::MAX_LINES { div { class: "notice warning", role: "status", "Large diff: this preview is truncated. Inspect the full change with the local CLI." } }
        if patch.text.is_empty() && !patch.binary { EmptyState { title: "No text changes", detail: "This comparison has no displayable text diff." } }
        div { class: if wrap { "diff-scroll wrap" } else { "diff-scroll" }, tabindex: "0", aria_label: "Source diff; horizontally scrollable",
            if split_view {
                div { class: "split-head", span { "BASE" } span { "SNAPSHOT" } }
                div { class: "split-diff", role: "table", aria_label: "Side-by-side source diff",
                    for (index, row) in diff::split(&lines).iter().enumerate() {
                        if let Some(heading) = &row.heading { div { key: "h{index}", class: if heading.starts_with("@@ ") { "split-meta hunk" } else { "split-meta" }, role: "row", "{heading}" } }
                        else { div { key: "r{index}", class: "split-row", role: "row",
                            for (side, line) in [("left", &row.left), ("right", &row.right)] { div { class: if let Some(l) = line { format!("split-cell {}", l.kind) } else { "split-cell blank".into() }, role: "cell",
                                if let Some(l) = line { span { class: "line-number", {(if side == "left" { l.old } else { l.new }).map(|n| n.to_string()).unwrap_or_default()} } code { "{l.text}" } } else { span { class: "line-number", " " } code { " " } }
                            } }
                        } }
                    }
                }
            } else { div { class: "unified-diff", role: "table", aria_label: "Unified source diff",
                for (index, line) in lines.iter().enumerate() { div { key: "{index}", class: "diff-line {line.kind}", role: "row", span { class: "line-number", "{line.old.map(|n| n.to_string()).unwrap_or_default()}" } span { class: "line-number", "{line.new.map(|n| n.to_string()).unwrap_or_default()}" } code { role: "cell", "{line.text}" } } }
            } }
        }
    }
}

#[component]
fn Icon(name: String) -> Element {
    let path = match name.as_str() {
        "lock" => "M7 10V7a5 5 0 0 1 10 0v3M5 10h14v11H5zM12 14v3",
        "branch" => "M6 6v12M18 6v3a6 6 0 0 1-6 6H6M8 4a2 2 0 1 1-4 0 2 2 0 0 1 4 0M20 4a2 2 0 1 1-4 0 2 2 0 0 1 4 0M8 20a2 2 0 1 1-4 0 2 2 0 0 1 4 0",
        "workspace" => "M3 7h18v13H3zM3 7V4h7l2 3",
        "search" => "M16 16l5 5M18 10a8 8 0 1 1-16 0 8 8 0 0 1 16 0",
        "refresh" => "M20 7V2l-3 3a9 9 0 1 0 3 12M20 7h-5",
        "sun" => "M12 2v2M12 20v2M2 12h2M20 12h2M5 5l1 1M18 18l1 1M5 19l1-1M18 6l1-1M16 12a4 4 0 1 1-8 0 4 4 0 0 1 8 0",
        "keyboard" => "M2 5h20v14H2zM6 9h1M11 9h1M16 9h1M6 12h1M11 12h1M16 12h1M7 16h10",
        "file" => "M5 2h9l5 5v15H5zM14 2v6h5M9 13h6M9 17h6",
        "alert" => "M12 3 2 21h20zM12 9v5M12 17v1",
        _ => "m12 3 10 5-10 5L2 8zM2 12l10 5 10-5M2 16l10 5 10-5",
    };
    rsx! { svg { class: "icon", width: "16", height: "16", view_box: "0 0 24 24", fill: "none", stroke: "currentColor", stroke_width: "1.6", stroke_linecap: "round", stroke_linejoin: "round", "aria-hidden": "true", path { d: path } } }
}
