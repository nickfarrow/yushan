/* tslint:disable */
/* eslint-disable */
export const memory: WebAssembly.Memory;
export const wasm_combine: (a: number, b: number) => [number, number, number, number];
export const wasm_generate_nonce: (a: number, b: number) => [number, number, number, number];
export const wasm_keygen_finalize: (a: number, b: number) => [number, number, number, number];
export const wasm_keygen_round1: (a: number, b: number, c: number) => [number, number, number, number];
export const wasm_keygen_round2: (a: number, b: number) => [number, number, number, number];
export const wasm_sign: (a: number, b: number, c: number, d: number, e: number, f: number) => [number, number, number, number];
export const wasm_verify: (a: number, b: number, c: number, d: number, e: number, f: number) => [number, number, number, number];
export const init: () => void;
export const test_wasm: () => [number, number];
export const __wbindgen_exn_store: (a: number) => void;
export const __externref_table_alloc: () => number;
export const __wbindgen_externrefs: WebAssembly.Table;
export const __wbindgen_free: (a: number, b: number, c: number) => void;
export const __wbindgen_malloc: (a: number, b: number) => number;
export const __wbindgen_realloc: (a: number, b: number, c: number, d: number) => number;
export const __externref_table_dealloc: (a: number) => void;
export const __wbindgen_start: () => void;
