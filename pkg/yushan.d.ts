/* tslint:disable */
/* eslint-disable */

/**
 * Initialize panic hook for better error messages in browser
 */
export function init(): void;

export function test_wasm(): string;

export function wasm_combine(data: string): string;

export function wasm_keygen_finalize(data: string): string;

export function wasm_keygen_round1(threshold: number, n_parties: number, my_index: number): string;

export function wasm_keygen_round2(data: string): string;

export function wasm_sign(session: string, message: string, data: string): string;

export function wasm_sign_nonce(session: string): string;

export function wasm_verify(signature: string, public_key: string, message: string): string;

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
  readonly memory: WebAssembly.Memory;
  readonly wasm_combine: (a: number, b: number) => [number, number, number, number];
  readonly wasm_keygen_finalize: (a: number, b: number) => [number, number, number, number];
  readonly wasm_keygen_round1: (a: number, b: number, c: number) => [number, number, number, number];
  readonly wasm_keygen_round2: (a: number, b: number) => [number, number, number, number];
  readonly wasm_sign: (a: number, b: number, c: number, d: number, e: number, f: number) => [number, number, number, number];
  readonly wasm_sign_nonce: (a: number, b: number) => [number, number, number, number];
  readonly wasm_verify: (a: number, b: number, c: number, d: number, e: number, f: number) => [number, number, number, number];
  readonly init: () => void;
  readonly test_wasm: () => [number, number];
  readonly __wbindgen_exn_store: (a: number) => void;
  readonly __externref_table_alloc: () => number;
  readonly __wbindgen_externrefs: WebAssembly.Table;
  readonly __wbindgen_free: (a: number, b: number, c: number) => void;
  readonly __wbindgen_malloc: (a: number, b: number) => number;
  readonly __wbindgen_realloc: (a: number, b: number, c: number, d: number) => number;
  readonly __externref_table_dealloc: (a: number) => void;
  readonly __wbindgen_start: () => void;
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
