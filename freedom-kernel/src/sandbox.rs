/// Capability-constrained WASM tool executor.
///
/// ## The credibility jump
///
/// Before this module: `verify() → Permit/Deny` — a decision with no enforcement.
///
/// After this module:
/// ```text
/// Agent → verify() → Permit → sandboxed executor → constrained IO
/// ```
///
/// The mechanism: the rights bitmask in the capability proof determines which host
/// functions are linked into the WASM instance. Any import not linked causes WASM
/// **instantiation failure** — not a runtime check, not a policy lookup. The WebAssembly
/// VM refuses to instantiate a module that requests an unlisted import.
///
/// ## Typed tool ABI (authgate v1)
///
/// Tools are WASM modules that import from the `authgate` namespace:
///
/// | Import                          | Right required        |
/// |---------------------------------|-----------------------|
/// | `read_byte(idx: i32) -> i32`    | `RIGHT_READ`          |
/// | `input_len() -> i32`            | `RIGHT_READ`          |
/// | `write_byte(byte: i32)`         | `RIGHT_WRITE`         |
/// | `http_status() -> i32`          | `RIGHT_NETWORK`       |
/// | `invoke_model(tokens: i32) -> i32` | `RIGHT_MODEL_INVOKE` |
/// | `spawn_agent(id: i32) -> i32`   | `RIGHT_SPAWN`         |
///
/// A tool that imports `write_byte` but was granted only `RIGHT_READ` will fail at
/// instantiation. This happens before any WASM bytecode executes.
#[cfg(feature = "sandbox")]
pub use inner::*;

#[cfg(feature = "sandbox")]
mod inner {
    use crate::tcb::call_gate::CallGate;
    use crate::tcb::types::{
        CanonicalAction, Decision, Rights,
        RIGHT_MODEL_INVOKE, RIGHT_NETWORK, RIGHT_READ, RIGHT_SPAWN, RIGHT_WRITE,
    };
    use ed25519_dalek::VerifyingKey;
    use wasmtime::{Caller, Engine, Linker, Module, Store};

    struct SandboxState {
        input:  Vec<u8>,
        output: Vec<u8>,
    }

    /// Result of a sandboxed tool execution.
    #[derive(Debug)]
    pub enum SandboxResult {
        /// The capability gate denied the action. Zero WASM bytecode ran.
        CapabilityDenied(&'static str),
        /// The tool ran to completion.
        Executed { output: Vec<u8> },
        /// WASM-level error: invalid module, unlisted import (wrong rights), or execution trap.
        ///
        /// An error message containing "unknown import" means the tool tried to call
        /// a host function not covered by the capability rights — the enforcement worked.
        RuntimeError(String),
    }

    impl SandboxResult {
        pub fn is_denied(&self) -> bool {
            matches!(self, SandboxResult::CapabilityDenied(_))
        }
        pub fn is_executed(&self) -> bool {
            matches!(self, SandboxResult::Executed { .. })
        }
        pub fn is_runtime_error(&self) -> bool {
            matches!(self, SandboxResult::RuntimeError(_))
        }
        pub fn output_bytes(&self) -> Option<&[u8]> {
            if let SandboxResult::Executed { output } = self {
                Some(output)
            } else {
                None
            }
        }
        pub fn error_message(&self) -> Option<&str> {
            if let SandboxResult::RuntimeError(s) = self {
                Some(s)
            } else {
                None
            }
        }
    }

    /// Capability-gated WASM tool executor.
    ///
    /// Call `execute()` with a `CanonicalAction` and a compiled WASM tool.
    /// The capability proof in the action determines which host functions the tool
    /// may call. Attempting to call an unlisted host function fails at instantiation.
    pub struct SandboxedExecutor {
        gate:   CallGate,
        engine: Engine,
    }

    impl SandboxedExecutor {
        pub fn new(root_key: VerifyingKey) -> Self {
            Self {
                gate:   CallGate::new(root_key),
                engine: Engine::default(),
            }
        }

        /// Execute a WASM tool, gated by the capability proof in `action`.
        ///
        /// - `wasm_bytes`: compiled WASM module (use `wat::parse_str` in tests)
        /// - `input`: raw bytes the tool may read via `authgate::read_byte`
        /// - `now`: current Unix seconds for expiry checks
        pub fn execute(
            &self,
            action:     &CanonicalAction,
            wasm_bytes: &[u8],
            input:      Vec<u8>,
            now:        u64,
        ) -> SandboxResult {
            match self.gate.execute(action, now) {
                Decision::Deny { reason } => SandboxResult::CapabilityDenied(reason),
                Decision::Permit          => self.run_sandboxed(action.required_rights, wasm_bytes, input),
            }
        }

        fn run_sandboxed(&self, rights: Rights, wasm_bytes: &[u8], input: Vec<u8>) -> SandboxResult {
            let module = match Module::from_binary(&self.engine, wasm_bytes) {
                Ok(m)  => m,
                Err(e) => return SandboxResult::RuntimeError(format!("invalid wasm: {e}")),
            };

            let linker = match self.build_linker(rights) {
                Ok(l)  => l,
                Err(e) => return SandboxResult::RuntimeError(format!("linker error: {e}")),
            };

            let state = SandboxState { input, output: Vec::new() };
            let mut store = Store::new(&self.engine, state);

            let instance = match linker.instantiate(&mut store, &module) {
                Ok(i)  => i,
                Err(e) => return SandboxResult::RuntimeError(format!("{e}")),
            };

            let run = match instance.get_typed_func::<(), ()>(&mut store, "run") {
                Ok(f)  => f,
                Err(e) => return SandboxResult::RuntimeError(format!("no 'run' export: {e}")),
            };

            match run.call(&mut store, ()) {
                Ok(_)  => {
                    let output = store.data().output.clone();
                    SandboxResult::Executed { output }
                }
                Err(e) => SandboxResult::RuntimeError(format!("trap: {e}")),
            }
        }

        fn build_linker(&self, rights: Rights) -> Result<Linker<SandboxState>, String> {
            let mut linker = Linker::<SandboxState>::new(&self.engine);

            if rights & RIGHT_READ != 0 {
                linker
                    .func_wrap("authgate", "read_byte", |caller: Caller<'_, SandboxState>, idx: i32| -> i32 {
                        let s = caller.data();
                        if idx < 0 || (idx as usize) >= s.input.len() { -1 }
                        else { s.input[idx as usize] as i32 }
                    })
                    .map_err(|e| e.to_string())?;

                linker
                    .func_wrap("authgate", "input_len", |caller: Caller<'_, SandboxState>| -> i32 {
                        caller.data().input.len() as i32
                    })
                    .map_err(|e| e.to_string())?;
            }

            if rights & RIGHT_WRITE != 0 {
                linker
                    .func_wrap("authgate", "write_byte", |mut caller: Caller<'_, SandboxState>, byte: i32| {
                        caller.data_mut().output.push(byte as u8);
                    })
                    .map_err(|e| e.to_string())?;
            }

            if rights & RIGHT_NETWORK != 0 {
                linker
                    .func_wrap("authgate", "http_status", |_: Caller<'_, SandboxState>| -> i32 {
                        200i32
                    })
                    .map_err(|e| e.to_string())?;
            }

            if rights & RIGHT_MODEL_INVOKE != 0 {
                linker
                    .func_wrap("authgate", "invoke_model", |_: Caller<'_, SandboxState>, tokens: i32| -> i32 {
                        tokens
                    })
                    .map_err(|e| e.to_string())?;
            }

            if rights & RIGHT_SPAWN != 0 {
                linker
                    .func_wrap("authgate", "spawn_agent", |_: Caller<'_, SandboxState>, id: i32| -> i32 {
                        id
                    })
                    .map_err(|e| e.to_string())?;
            }

            Ok(linker)
        }
    }

    // ── Tests ─────────────────────────────────────────────────────────────────

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::tcb::types::*;
        use ed25519_dalek::{SigningKey, Signer};
        use rand_core::OsRng;
        use sha2::{Digest, Sha256};

        const ACTOR:     [u8; 32] = [0xAA; 32];
        const RESOURCE:  [u8; 32] = [0xBB; 32];
        const NOW:       u64 = 10_000;
        const EXPIRY:    u64 = 99_999;
        const EPOCH:     u64 = 1;
        const MIN_EPOCH: u64 = 1;

        fn rk() -> SigningKey { SigningKey::generate(&mut OsRng) }

        fn make_cap(root_sk: &SigningKey, rights: Rights) -> CapabilityProof {
            let mut p = CapabilityProof {
                proof_hash:    [0; 32],
                subject_id:    ACTOR,
                resource_hash: RESOURCE,
                rights,
                expiry:        EXPIRY,
                epoch:         EPOCH,
                issuer:        IssuerRef::Root,
                signature:     [0; 64],
                issuer_pubkey: root_sk.verifying_key().to_bytes(),
            };
            p.signature  = root_sk.sign(&p.signing_message()).to_bytes();
            p.proof_hash = Sha256::digest(p.to_canonical_bytes()).into();
            p
        }

        fn make_action(root_sk: &SigningKey, rights: Rights) -> (CanonicalAction, SigningKey) {
            let cap = make_cap(root_sk, rights);
            let mut a = CanonicalAction {
                actor_id:           ACTOR,
                resource_hash:      RESOURCE,
                required_rights:    rights,
                capability_proofs:  vec![cap],
                revocation_proofs:  vec![],
                nonce:              [0xEE; 16],
                timestamp:          NOW,
                min_epoch:          MIN_EPOCH,
                binding_hash:       [0; 32],
            };
            a.binding_hash = a.compute_hash();
            (a, root_sk.clone())
        }

        // WAT: imports only read_byte, calls it once, drops result
        const WAT_READ_TOOL: &str = r#"
(module
  (import "authgate" "read_byte"  (func $rb (param i32) (result i32)))
  (import "authgate" "input_len"  (func $il (result i32)))
  (func (export "run")
    i32.const 0
    call $rb
    drop
  )
)
"#;

        // WAT: imports only write_byte, writes 'A' (65)
        const WAT_WRITE_TOOL: &str = r#"
(module
  (import "authgate" "write_byte" (func $wb (param i32)))
  (func (export "run")
    i32.const 65
    call $wb
  )
)
"#;

        // WAT: imports write_byte three times, writes [1, 2, 3]
        const WAT_WRITE_THREE: &str = r#"
(module
  (import "authgate" "write_byte" (func $wb (param i32)))
  (func (export "run")
    i32.const 1 call $wb
    i32.const 2 call $wb
    i32.const 3 call $wb
  )
)
"#;

        // WAT: imports http_status, calls it, drops result
        const WAT_NETWORK_TOOL: &str = r#"
(module
  (import "authgate" "http_status" (func $hs (result i32)))
  (func (export "run")
    call $hs
    drop
  )
)
"#;

        // WAT: imports invoke_model with token count
        const WAT_MODEL_TOOL: &str = r#"
(module
  (import "authgate" "invoke_model" (func $im (param i32) (result i32)))
  (func (export "run")
    i32.const 100
    call $im
    drop
  )
)
"#;

        // WAT: imports BOTH read_byte and write_byte
        const WAT_READ_WRITE_TOOL: &str = r#"
(module
  (import "authgate" "read_byte"  (func $rb (param i32) (result i32)))
  (import "authgate" "write_byte" (func $wb (param i32)))
  (func (export "run")
    i32.const 0
    call $rb   ;; read first input byte
    call $wb   ;; write it as output
  )
)
"#;

        // ── Happy path: Permit + correct rights ───────────────────────────────

        #[test]
        fn read_tool_permits_and_executes() {
            let root_sk = rk();
            let executor = SandboxedExecutor::new(root_sk.verifying_key());
            let (action, _) = make_action(&root_sk, RIGHT_READ);
            let wasm = wat::parse_str(WAT_READ_TOOL).expect("valid WAT");
            let result = executor.execute(&action, &wasm, b"hello".to_vec(), NOW);
            assert!(result.is_executed(), "expected Executed, got: {:?}", result);
        }

        #[test]
        fn write_tool_permits_and_executes() {
            let root_sk = rk();
            let executor = SandboxedExecutor::new(root_sk.verifying_key());
            let (action, _) = make_action(&root_sk, RIGHT_WRITE);
            let wasm = wat::parse_str(WAT_WRITE_TOOL).expect("valid WAT");
            let result = executor.execute(&action, &wasm, vec![], NOW);
            assert!(result.is_executed());
            assert_eq!(result.output_bytes(), Some(&[65u8][..])); // 'A'
        }

        #[test]
        fn output_bytes_collected_correctly() {
            let root_sk = rk();
            let executor = SandboxedExecutor::new(root_sk.verifying_key());
            let (action, _) = make_action(&root_sk, RIGHT_WRITE);
            let wasm = wat::parse_str(WAT_WRITE_THREE).expect("valid WAT");
            let result = executor.execute(&action, &wasm, vec![], NOW);
            assert_eq!(result.output_bytes(), Some(&[1u8, 2, 3][..]));
        }

        #[test]
        fn network_tool_permits_with_network_right() {
            let root_sk = rk();
            let executor = SandboxedExecutor::new(root_sk.verifying_key());
            let (action, _) = make_action(&root_sk, RIGHT_NETWORK);
            let wasm = wat::parse_str(WAT_NETWORK_TOOL).expect("valid WAT");
            let result = executor.execute(&action, &wasm, vec![], NOW);
            assert!(result.is_executed());
        }

        #[test]
        fn model_invoke_with_correct_right() {
            let root_sk = rk();
            let executor = SandboxedExecutor::new(root_sk.verifying_key());
            let (action, _) = make_action(&root_sk, RIGHT_MODEL_INVOKE);
            let wasm = wat::parse_str(WAT_MODEL_TOOL).expect("valid WAT");
            let result = executor.execute(&action, &wasm, vec![], NOW);
            assert!(result.is_executed());
        }

        #[test]
        fn read_write_tool_with_both_rights_linked() {
            let root_sk = rk();
            let executor = SandboxedExecutor::new(root_sk.verifying_key());
            let (action, _) = make_action(&root_sk, RIGHT_READ | RIGHT_WRITE);
            let wasm = wat::parse_str(WAT_READ_WRITE_TOOL).expect("valid WAT");
            // input[0] = 42; tool reads it and writes it to output
            let result = executor.execute(&action, &wasm, vec![42u8], NOW);
            assert!(result.is_executed());
            assert_eq!(result.output_bytes(), Some(&[42u8][..]));
        }

        // ── Capability denied: zero WASM code runs ────────────────────────────

        #[test]
        fn read_tool_denied_when_capability_expired() {
            let root_sk = rk();
            let executor = SandboxedExecutor::new(root_sk.verifying_key());
            // Cap expired at NOW - 1
            let mut cap = make_cap(&root_sk, RIGHT_READ);
            cap.expiry = NOW - 1;
            // Re-sign the modified cap
            cap.signature = root_sk.sign(&cap.signing_message()).to_bytes();
            cap.proof_hash = Sha256::digest(cap.to_canonical_bytes()).into();
            let mut action = CanonicalAction {
                actor_id:          ACTOR,
                resource_hash:     RESOURCE,
                required_rights:   RIGHT_READ,
                capability_proofs: vec![cap],
                revocation_proofs: vec![],
                nonce:             [0xEE; 16],
                timestamp:         NOW,
                min_epoch:         MIN_EPOCH,
                binding_hash:      [0; 32],
            };
            action.binding_hash = action.compute_hash();
            let wasm = wat::parse_str(WAT_READ_TOOL).expect("valid WAT");
            let result = executor.execute(&action, &wasm, vec![], NOW);
            assert!(result.is_denied(), "expired cap must deny before WASM runs");
        }

        #[test]
        fn tool_denied_when_wrong_root_key() {
            let root_sk = rk();
            let wrong_sk = rk(); // executor will use wrong_sk's verifying key
            let executor = SandboxedExecutor::new(wrong_sk.verifying_key());
            let (action, _) = make_action(&root_sk, RIGHT_READ); // signed by root_sk
            let wasm = wat::parse_str(WAT_READ_TOOL).expect("valid WAT");
            let result = executor.execute(&action, &wasm, vec![], NOW);
            assert!(result.is_denied());
        }

        // ── Wrong rights: WASM instantiation fails (not CapabilityDenied) ─────
        // This is the key enforcement property: the capability is permitted but
        // the tool requests a host function not linked for the granted rights.
        // Result: RuntimeError (WASM-level refusal), not CapabilityDenied.

        #[test]
        fn write_tool_blocked_with_only_read_right() {
            let root_sk = rk();
            let executor = SandboxedExecutor::new(root_sk.verifying_key());
            // Action has only RIGHT_READ, but tool imports write_byte
            let (action, _) = make_action(&root_sk, RIGHT_READ);
            let wasm = wat::parse_str(WAT_WRITE_TOOL).expect("valid WAT");
            let result = executor.execute(&action, &wasm, vec![], NOW);
            // Must be RuntimeError, not CapabilityDenied (capability was permitted)
            assert!(result.is_runtime_error(), "expected RuntimeError, got: {:?}", result);
            // The error should mention the unlisted import
            let msg = result.error_message().unwrap();
            assert!(
                msg.contains("write_byte") || msg.contains("unknown import") || msg.contains("Linker"),
                "error should identify the missing import: {msg}"
            );
        }

        #[test]
        fn network_tool_blocked_without_network_right() {
            let root_sk = rk();
            let executor = SandboxedExecutor::new(root_sk.verifying_key());
            let (action, _) = make_action(&root_sk, RIGHT_READ); // only READ, not NETWORK
            let wasm = wat::parse_str(WAT_NETWORK_TOOL).expect("valid WAT");
            let result = executor.execute(&action, &wasm, vec![], NOW);
            assert!(result.is_runtime_error());
        }

        #[test]
        fn invalid_wasm_bytes_returns_runtime_error() {
            let root_sk = rk();
            let executor = SandboxedExecutor::new(root_sk.verifying_key());
            let (action, _) = make_action(&root_sk, RIGHT_READ);
            let garbage = b"this is not wasm";
            let result = executor.execute(&action, garbage, vec![], NOW);
            assert!(result.is_runtime_error());
            let msg = result.error_message().unwrap();
            assert!(msg.contains("invalid wasm"), "expected 'invalid wasm' in: {msg}");
        }
    }
}
