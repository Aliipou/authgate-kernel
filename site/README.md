# authgate-kernel demo site

Static page (no build step) that runs the actual compiled kernel in the
browser via WebAssembly. `pkg/` is committed so the site deploys with no
build step; regenerate it after changing `authgate-kernel/src/` with:

```bash
cd ../authgate-kernel
cargo build --target wasm32-unknown-unknown --no-default-features --features wasm --release --lib
wasm-bindgen --target web --out-dir ../site/pkg target/wasm32-unknown-unknown/release/authgate_kernel.wasm
```

(`wasm-pack build --target web -- --features wasm` does the same thing if
`wasm-pack` and its bundled `wasm-opt` download work in your environment —
they didn't in the sandbox this was first built in, so the two commands above
were run directly instead, using a prebuilt `wasm-bindgen` CLI matching the
`wasm-bindgen` crate version pinned in `Cargo.lock`.)

`verify_json_unsigned` is used rather than `verify_json_wasm`: the signed
variant calls `std::time::SystemTime::now()` to timestamp the signature,
which panics on `wasm32-unknown-unknown` (no wall clock without JS interop
this crate doesn't wire up yet). `kernel_pubkey_wasm()` is unused for the same
class of reason — it lazily generates an ed25519 keypair via `OsRng`, which
needs a working `getrandom` "js" backend; that should work in a real browser
(`Crypto.getRandomValues`) but wasn't reliably reproducible under plain Node
without a bundler, so the demo doesn't depend on it.
