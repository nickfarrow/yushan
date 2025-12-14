use wasm_bindgen::prelude::*;

pub mod keygen;
pub mod signing;

// Test function to verify WASM compilation works
#[wasm_bindgen]
pub fn test_wasm() -> String {
    "WASM is working!".to_string()
}
