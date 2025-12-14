use wasm_bindgen::prelude::*;

#[cfg(target_arch = "wasm32")]
use serde::Serialize;

#[cfg(target_arch = "wasm32")]
use crate::{keygen, signing};

/// Initialize panic hook for better error messages in browser
#[wasm_bindgen(start)]
pub fn init() {
    console_error_panic_hook::set_once();
}

/// Helper struct for WASM JSON serialization
#[cfg(target_arch = "wasm32")]
#[derive(Serialize)]
struct WasmCommandResult {
    output: String,
    result: String,
}

/// Convert CommandResult to JSON string for WASM
#[cfg(target_arch = "wasm32")]
fn command_result_to_json(cmd_result: crate::CommandResult) -> Result<String, JsValue> {
    let wasm_result = WasmCommandResult {
        output: cmd_result.output,
        result: cmd_result.result,
    };
    serde_json::to_string(&wasm_result)
        .map_err(|e| JsValue::from_str(&format!("JSON serialization error: {}", e)))
}

// WASM-exposed keygen functions

#[wasm_bindgen]
#[cfg_attr(not(target_arch = "wasm32"), allow(unused_variables))]
pub fn wasm_keygen_round1(threshold: u32, n_parties: u32, my_index: u32) -> Result<String, JsValue> {
    #[cfg(target_arch = "wasm32")]
    {
        use crate::storage::LocalStorageImpl;
        let storage = LocalStorageImpl;
        let cmd_result = keygen::round1_core(threshold, n_parties, my_index, &storage)
            .map_err(|e| JsValue::from_str(&format!("Error: {}", e)))?;
        command_result_to_json(cmd_result)
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        Err(JsValue::from_str("WASM functions only available in WASM target"))
    }
}

#[wasm_bindgen]
#[cfg_attr(not(target_arch = "wasm32"), allow(unused_variables))]
pub fn wasm_keygen_round2(data: String) -> Result<String, JsValue> {
    #[cfg(target_arch = "wasm32")]
    {
        use crate::storage::LocalStorageImpl;
        let storage = LocalStorageImpl;
        let cmd_result = keygen::round2_core(&data, &storage)
            .map_err(|e| JsValue::from_str(&format!("Error: {}", e)))?;
        command_result_to_json(cmd_result)
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        Err(JsValue::from_str("WASM functions only available in WASM target"))
    }
}

#[wasm_bindgen]
#[cfg_attr(not(target_arch = "wasm32"), allow(unused_variables))]
pub fn wasm_keygen_finalize(data: String) -> Result<String, JsValue> {
    #[cfg(target_arch = "wasm32")]
    {
        use crate::storage::LocalStorageImpl;
        let storage = LocalStorageImpl;
        let cmd_result = keygen::finalize_core(&data, &storage)
            .map_err(|e| JsValue::from_str(&format!("Error: {}", e)))?;
        command_result_to_json(cmd_result)
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        Err(JsValue::from_str("WASM functions only available in WASM target"))
    }
}

// WASM-exposed signing functions

#[wasm_bindgen]
#[cfg_attr(not(target_arch = "wasm32"), allow(unused_variables))]
pub fn wasm_generate_nonce(session: String) -> Result<String, JsValue> {
    #[cfg(target_arch = "wasm32")]
    {
        use crate::storage::LocalStorageImpl;
        let storage = LocalStorageImpl;
        let cmd_result = signing::generate_nonce_core(&session, &storage)
            .map_err(|e| JsValue::from_str(&format!("Error: {}", e)))?;
        command_result_to_json(cmd_result)
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        Err(JsValue::from_str("WASM functions only available in WASM target"))
    }
}

#[wasm_bindgen]
#[cfg_attr(not(target_arch = "wasm32"), allow(unused_variables))]
pub fn wasm_sign(session: String, message: String, data: String) -> Result<String, JsValue> {
    #[cfg(target_arch = "wasm32")]
    {
        use crate::storage::LocalStorageImpl;
        let storage = LocalStorageImpl;
        let cmd_result = signing::create_signature_share_core(&session, &message, &data, &storage)
            .map_err(|e| JsValue::from_str(&format!("Error: {}", e)))?;
        command_result_to_json(cmd_result)
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        Err(JsValue::from_str("WASM functions only available in WASM target"))
    }
}

#[wasm_bindgen]
#[cfg_attr(not(target_arch = "wasm32"), allow(unused_variables))]
pub fn wasm_combine(data: String) -> Result<String, JsValue> {
    #[cfg(target_arch = "wasm32")]
    {
        use crate::storage::LocalStorageImpl;
        let storage = LocalStorageImpl;
        let cmd_result = signing::combine_signatures_core(&data, &storage)
            .map_err(|e| JsValue::from_str(&format!("Error: {}", e)))?;
        command_result_to_json(cmd_result)
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        Err(JsValue::from_str("WASM functions only available in WASM target"))
    }
}

#[wasm_bindgen]
#[cfg_attr(not(target_arch = "wasm32"), allow(unused_variables))]
pub fn wasm_verify(signature: String, public_key: String, message: String) -> Result<String, JsValue> {
    #[cfg(target_arch = "wasm32")]
    {
        let cmd_result = signing::verify_signature_core(&signature, &public_key, &message)
            .map_err(|e| JsValue::from_str(&format!("Error: {}", e)))?;
        command_result_to_json(cmd_result)
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        Err(JsValue::from_str("WASM functions only available in WASM target"))
    }
}
