use dioxus::prelude::*;
use wipstash_inspector_ui::Inspector;
fn main() {
    let mut dom = VirtualDom::new(|| rsx! { Inspector { demo_mode: true } });
    dom.rebuild_in_place();
    let markup = dioxus_ssr::render(&dom);
    let html = format!("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"><meta name=\"color-scheme\" content=\"dark light\"><title>Wipstash Inspector · synthetic design preview</title></head><body>{markup}</body></html>");
    let path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "preview.html".into());
    std::fs::write(&path, html).expect("write preview");
    eprintln!("Rendered actual Dioxus Inspector to {path} (synthetic, static preview; controls need WASM)");
}
