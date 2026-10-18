use dioxus::prelude::*;
use wipstash_inspector_ui::{demo_requested, Inspector};
fn main() {
    dioxus::launch(App);
}
#[component]
fn App() -> Element {
    rsx! { Inspector { demo_mode: demo_requested() } }
}
