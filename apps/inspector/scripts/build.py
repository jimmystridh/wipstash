#!/usr/bin/env python3
"""Build real Dioxus WASM with an external CSP-compatible bootstrap. No server."""
import argparse, json, pathlib, subprocess
root = pathlib.Path(__file__).resolve().parents[1]
p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--debug', action='store_true')
a = p.parse_args()
subprocess.run(['cargo', 'build', '--locked', '--target', 'wasm32-unknown-unknown', *([] if a.debug else ['--release'])], cwd=root, check=True)
metadata = json.loads(subprocess.check_output(['cargo', 'metadata', '--format-version', '1', '--no-deps'], cwd=root))
wasm = pathlib.Path(metadata['target_directory']) / 'wasm32-unknown-unknown' / ('debug' if a.debug else 'release') / 'wipstash-inspector-ui.wasm'
out = root / 'dist'
out.mkdir(exist_ok=True)
subprocess.run(['wasm-bindgen', '--target', 'web', '--out-dir', str(out), '--out-name', 'inspector', str(wasm)], cwd=root, check=True)
(out / 'bootstrap.js').write_text('''import init from './inspector.js';
init().catch(() => {
  const error = document.createElement('p');
  error.textContent = 'The inspector could not start. Reload the page, or check that the WASM build matches the server assets.';
  error.setAttribute('role', 'alert');
  document.body.replaceChildren(error);
});
''')
(out / 'index.html').write_text('''<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><meta name="color-scheme" content="dark light"><meta name="referrer" content="no-referrer"><title>Wipstash · Inspector</title><link rel="icon" href="data:,"></head><body><noscript>Wipstash Inspector needs JavaScript and WebAssembly. The read-only CLI remains available.</noscript><div id="main"></div><script type="module" src="./bootstrap.js"></script></body></html>
''')
print(f'Built local-only static assets: {out}')
