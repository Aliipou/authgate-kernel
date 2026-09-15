/* tslint:disable */
/* eslint-disable */

/**
 * Return this kernel instance's ed25519 verifying key (hex, 64 chars).
 */
export function kernel_pubkey_wasm(): string;

/**
 * Pure JSON verification without signatures (no randomness required).
 * Useful for WASM targets where getrandom is unavailable.
 */
export function verify_json_unsigned(input_json: string): string;

/**
 * Verify an action against a registry using the JSON wire format.
 *
 * Input JSON:  `{"registry": <OwnershipRegistryWire>, "action": <ActionWire>}`
 * Output JSON: `<VerificationResultWire>` (with ed25519 signature when available)
 *
 * This is the WASM equivalent of `FreedomVerifier.verify_signed()`.
 */
export function verify_json_wasm(input_json: string): string;

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
    readonly memory: WebAssembly.Memory;
    readonly authgate_kernel_pubkey: (a: number, b: number) => number;
    readonly authgate_kernel_verify: (a: number, b: number, c: number, d: number) => number;
    readonly kernel_pubkey_wasm: (a: number) => void;
    readonly verify_json_unsigned: (a: number, b: number, c: number) => void;
    readonly verify_json_wasm: (a: number, b: number, c: number) => void;
    readonly __wbindgen_export: (a: number) => void;
    readonly __wbindgen_add_to_stack_pointer: (a: number) => number;
    readonly __wbindgen_export2: (a: number, b: number, c: number) => void;
    readonly __wbindgen_export3: (a: number, b: number) => number;
    readonly __wbindgen_export4: (a: number, b: number, c: number, d: number) => number;
}

export type SyncInitInput = BufferSource | WebAssembly.Module;

/**
 * Instantiates the given `module`, which can either be bytes or
 * a precompiled `WebAssembly.Module`.
 *
 * @param {{ module: SyncInitInput }} module - Passing `SyncInitInput` directly is deprecated.
 *
 * @returns {InitOutput}
 */
export function initSync(module: { module: SyncInitInput } | SyncInitInput): InitOutput;

/**
 * If `module_or_path` is {RequestInfo} or {URL}, makes a request and
 * for everything else, calls `WebAssembly.instantiate` directly.
 *
 * @param {{ module_or_path: InitInput | Promise<InitInput> }} module_or_path - Passing `InitInput` directly is deprecated.
 *
 * @returns {Promise<InitOutput>}
 */
export default function __wbg_init (module_or_path?: { module_or_path: InitInput | Promise<InitInput> } | InitInput | Promise<InitInput>): Promise<InitOutput>;
