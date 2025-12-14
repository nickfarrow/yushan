use crate::storage::{FileStorage, Storage};
use crate::CommandResult;
use anyhow::{Context, Result};
use rand_chacha::ChaCha20Rng;
use schnorr_fun::binonce::NonceKeyPair;
use schnorr_fun::frost::{self, PairedSecretShare, SharedKey};
use schnorr_fun::{Message, Signature};
use secp256kfun::prelude::*;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::collections::BTreeMap;

// Import the parser from keygen module
use crate::keygen::parse_space_separated_json;

const STATE_DIR: &str = ".frost_state";

#[derive(Serialize, Deserialize, Debug)]
pub struct NonceOutput {
    pub party_index: u32,
    pub session: String,
    pub nonce: String, // Bincode hex of public nonce
    #[serde(rename = "type")]
    pub event_type: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct NonceInput {
    pub nonces: Vec<NonceData>,
    pub public_key: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct NonceData {
    pub index: u32,
    pub nonce: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct SignatureShareOutput {
    pub party_index: u32,
    pub session: String,
    pub message: String,
    pub signature_share: String,
    #[serde(rename = "type")]
    pub event_type: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct SignatureShareInput {
    pub shares: Vec<SignatureShareData>,
    pub public_key: String,
    pub final_nonce: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct SignatureShareData {
    pub index: u32,
    pub share: String,
}

pub fn generate_nonce_core(session: &str, storage: &dyn Storage) -> Result<CommandResult> {
    let mut out = String::new();

    out.push_str("FROST Signing - Nonce Generation\n\n");
    out.push_str("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
    out.push_str(&format!("Session ID: {}\n", session));
    out.push_str("⚠  NEVER reuse a nonce as it will leak your secret share!\n");
    out.push_str("    Each signature needs fresh nonces!\n");
    out.push_str("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n");

    // Load paired secret share
    let paired_share_bytes = storage
        .read("paired_secret_share.bin")
        .context("Failed to load secret share. Did you run keygen-finalize?")?;
    let paired_share: PairedSecretShare<EvenY> = bincode::deserialize(&paired_share_bytes)?;

    let party_index = {
        // ~hack to go back from scalar index to u32
        let mut u32_index_bytes = [0u8; 4];
        u32_index_bytes.copy_from_slice(&paired_share.index().to_bytes()[28..]);

        u32::from_be_bytes(u32_index_bytes)
    };

    out.push_str("⚙️  Using schnorr_fun's FROST nonce generation\n");
    out.push_str("   Calling: frost.seed_nonce_rng() and frost.gen_nonce()\n\n");

    // Create FROST instance with deterministic nonces
    let frost = frost::new_with_synthetic_nonces::<Sha256, rand::rngs::ThreadRng>();

    // Seed the nonce RNG with session ID
    let mut nonce_rng: ChaCha20Rng = frost.seed_nonce_rng(paired_share, session.as_bytes());

    // Generate nonce
    let nonce = frost.gen_nonce(&mut nonce_rng);

    out.push_str("❄️  Generated NonceKeyPair:\n");
    out.push_str("   - Secret nonces: (k₁, k₂) - kept private\n");
    out.push_str("   - Public nonces: (R₁, R₂) where R₁ = k₁*G, R₂ = k₂*G\n\n");
    out.push_str("🧠 Why do we need nonces?\n");
    out.push_str("   Schnorr signatures require randomness to be secure!\n");
    out.push_str("   If you ever reuse a nonce with the same key, an attacker\n");
    out.push_str("   can solve for your secret share and steal your key.\n");
    out.push_str("   \n");
    out.push_str("   FROST uses TWO nonces (k₁, k₂) for extra security:\n");
    out.push_str("   • k₁ is the primary nonce\n");
    out.push_str("   • k₂ protects against rogue-key attacks in multi-party signing\n\n");
    out.push_str("❓ Think about it:\n");
    out.push_str("   Notice: We can generate nonces BEFORE knowing the message!\n");
    out.push_str("   Current flow: share nonces → then sign (2 rounds)\n");
    out.push_str("   How could we optimize FROST to sign in just 1 round?\n");
    out.push_str("   (Hint: What if we pre-shared nonces?)\n\n");

    // Serialize nonce keypair for later use
    let nonce_bytes = bincode::serialize(&nonce)?;
    storage.write(&format!("nonce_{}.bin", session), &nonce_bytes)?;

    // Serialize public nonce for sharing
    let public_nonce = nonce.public();
    let public_nonce_bytes = bincode::serialize(&public_nonce)?;
    let public_nonce_hex = hex::encode(&public_nonce_bytes);

    out.push_str("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
    out.push_str("✉️  Your public nonce generated!\n\n");

    out.push_str("➜ Paste the result JSON into the webpage\n");
    out.push_str("➜ Wait for threshold number of signers to post nonces\n");
    out.push_str(&format!(
        "➜ Copy the \"nonces for session {}\" JSON from webpage\n",
        session
    ));
    out.push_str(&format!(
        "➜ Run: yushan sign --session {} --message \"<msg>\" --data '<JSON>'\n",
        session
    ));

    // Create JSON result for copy-pasting
    let output = NonceOutput {
        party_index,
        session: session.to_string(),
        nonce: public_nonce_hex,
        event_type: "signing_nonce".to_string(),
    };
    let result = serde_json::to_string(&output)?;

    Ok(CommandResult {
        output: out,
        result,
    })
}

pub fn generate_nonce(session: &str) -> Result<()> {
    let storage = FileStorage::new(STATE_DIR)?;
    let cmd_result = generate_nonce_core(session, &storage)?;
    println!("{}", cmd_result.output);
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("📋 Copy this JSON:");
    println!("{}\n", cmd_result.result);
    Ok(())
}

pub fn create_signature_share_core(
    session: &str,
    message: &str,
    data: &str,
    storage: &dyn Storage,
) -> Result<CommandResult> {
    let mut out = String::new();

    out.push_str("🔐 FROST Signing - Create Signature Share\n\n");

    // Load nonce
    let nonce_bytes = storage
        .read(&format!("nonce_{}.bin", session))
        .context("Failed to load nonce. Did you run generate-nonce?")?;
    let nonce: NonceKeyPair = bincode::deserialize(&nonce_bytes)?;

    // Load paired secret share
    let paired_share_bytes = storage.read("paired_secret_share.bin")?;
    let paired_share: PairedSecretShare<EvenY> = bincode::deserialize(&paired_share_bytes)?;

    let party_index = {
        // ~hack to go back from scalar index to u32
        let mut u32_index_bytes = [0u8; 4];
        u32_index_bytes.copy_from_slice(&paired_share.index().to_bytes()[28..]);

        u32::from_be_bytes(u32_index_bytes)
    };

    // Load shared key
    let shared_key_bytes = storage.read("shared_key.bin")?;
    let shared_key: SharedKey<EvenY> = bincode::deserialize(&shared_key_bytes)?;

    // Parse input - space-separated NonceOutput objects
    let nonce_outputs: Vec<NonceOutput> = parse_space_separated_json(data)?;

    // Convert to expected format
    let nonces: Vec<NonceData> = nonce_outputs
        .into_iter()
        .map(|output| NonceData {
            index: output.party_index,
            nonce: output.nonce,
        })
        .collect();

    let num_signers = nonces.len();

    let public_key_hex = hex::encode(bincode::serialize(&shared_key)?);
    let input = NonceInput {
        nonces,
        public_key: public_key_hex,
    };

    out.push_str(&format!(" Signing with {} parties\n", num_signers));
    out.push_str(&format!("  Message: \"{}\"\n\n", message));

    out.push_str("📐 Using schnorr_fun's FROST signing\n");
    out.push_str("   Calling: frost.party_sign_session()\n\n");

    // Reconstruct nonces map
    let mut nonces_map = BTreeMap::new();
    for nonce_data in &input.nonces {
        let nonce_bytes = hex::decode(&nonce_data.nonce)?;
        let public_nonce: schnorr_fun::binonce::Nonce = bincode::deserialize(&nonce_bytes)?;

        let share_index = Scalar::<Secret, Zero>::from(nonce_data.index)
            .non_zero()
            .expect("index should be nonzero")
            .public();
        nonces_map.insert(share_index, public_nonce);
    }

    // Create FROST instance
    let frost = frost::new_with_deterministic_nonces::<Sha256>();

    out.push_str("🔢 Creating coordinator sign session...\n");
    out.push_str("   Aggregating all nonces\n");
    out.push_str("   Computing binding coefficient\n");
    out.push_str("   Computing challenge = H(R || PubKey || message)\n\n");

    // Create message
    let msg = Message::new("frostsnap-yushan", message.as_bytes());

    // Create coordinator session
    let coord_session = frost.coordinator_sign_session(&shared_key, nonces_map.clone(), msg);

    out.push_str("✓ Coordinator session created:\n");
    out.push_str("   - Aggregated nonce: R = R1 + R2 + ...\n");
    out.push_str("   - Challenge: c = H(R || PK || msg)\n");
    out.push_str(&format!(
        "   - Parties: {:?}\n\n",
        coord_session
            .parties()
            .iter()
            .map(|s| s.to_bytes()[0] as u32)
            .collect::<Vec<_>>()
    ));

    out.push_str("📝 Creating party sign session...\n");
    let agg_binonce = coord_session.agg_binonce();
    let parties = coord_session.parties();

    let sign_session =
        frost.party_sign_session(shared_key.public_key(), parties.clone(), agg_binonce, msg);

    out.push_str("⚙️  Computing Lagrange coefficient...\n");
    out.push_str("🧠 Why Lagrange coefficients?\n");
    out.push_str(&format!(
        "   During keygen, you received a share for index {}\n",
        party_index
    ));
    out.push_str(&format!(
        "   But only {} parties are signing in this session!\n",
        num_signers
    ));
    out.push_str("   \n");
    out.push_str("   Lagrange interpolation adjusts your share to work with\n");
    out.push_str("   ANY threshold subset of signers (not just all parties).\n");
    out.push_str("   \n");
    out.push_str(&format!(
        "   λ{} = the coefficient that makes YOUR share compatible\n",
        party_index
    ));
    out.push_str(&format!(
        "   with this specific group of {} signers.\n\n",
        num_signers
    ));
    out.push_str("❓ Think about it:\n");
    out.push_str(&format!(
        "   You've selected a specific group of {} signers for this signature.\n",
        num_signers
    ));
    out.push_str("   What downstream implication does this have?\n");
    out.push_str("   (Hint: How does this differ from Bitcoin script multisig,\n");
    out.push_str("   where ANY threshold combination can spend?)\n\n");

    out.push_str("⚙️  Creating signature share...\n");
    out.push_str("🧠 Schnorr signature math:\n");
    out.push_str(&format!(
        "   s{} = k{} + λ{} × c × secret_share{}\n",
        party_index, party_index, party_index, party_index
    ));
    out.push_str("   where:\n");
    out.push_str(&format!("   • k{} = your secret nonce\n", party_index));
    out.push_str(&format!(
        "   • λ{} = your Lagrange coefficient\n",
        party_index
    ));
    out.push_str("   • c = challenge = Hash(R || PubKey || message)\n");
    out.push_str(&format!(
        "   • secret_share{} = your piece of the private key\n\n",
        party_index
    ));

    // Sign
    let sig_share = sign_session.sign(&paired_share, nonce);

    let sig_share_bytes = bincode::serialize(&sig_share)?;
    let sig_share_hex = hex::encode(&sig_share_bytes);

    // Save the final nonce and nonces map for combine step
    let final_nonce = coord_session.final_nonce();
    let final_nonce_bytes = bincode::serialize(&final_nonce)?;
    storage.write(&format!("final_nonce_{}.bin", session), &final_nonce_bytes)?;

    // Save nonces map for coordinator session recreation
    let nonces_json = serde_json::to_string(&input.nonces)?;
    storage.write(
        &format!("session_nonces_{}.json", session),
        nonces_json.as_bytes(),
    )?;

    out.push_str("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
    out.push_str("✓ Your signature share generated!\n\n");

    out.push_str("➜ Paste the result JSON into the webpage\n");
    out.push_str("➜ Once all signers post shares, anyone can combine them\n");
    out.push_str(&format!(
        "➜ Run: yushan combine --message \"{}\" --data '<shares JSON>'\n",
        message
    ));

    // Create JSON result for copy-pasting
    let output = SignatureShareOutput {
        party_index,
        session: session.to_string(),
        message: message.to_string(),
        signature_share: sig_share_hex,
        event_type: "signing_share".to_string(),
    };
    let result = serde_json::to_string(&output)?;

    Ok(CommandResult {
        output: out,
        result,
    })
}

pub fn create_signature_share(session: &str, message: &str, data: &str) -> Result<()> {
    let storage = FileStorage::new(STATE_DIR)?;
    let cmd_result = create_signature_share_core(session, message, data, &storage)?;
    println!("{}", cmd_result.output);
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("📋 Copy this JSON:");
    println!("{}\n", cmd_result.result);
    Ok(())
}

pub fn combine_signatures_core(data: &str, storage: &dyn Storage) -> Result<CommandResult> {
    let mut out = String::new();

    out.push_str("🔐 FROST Signing - Combine Signature Shares\n\n");

    // Parse input - space-separated SignatureShareOutput objects
    let sig_outputs: Vec<SignatureShareOutput> = parse_space_separated_json(data)?;

    // Extract message and session from first signature share
    // (all signers sign the same message in the same session)
    let first = sig_outputs
        .first()
        .context("No signature shares provided")?;
    let message = &first.message;
    let session = &first.session;

    // Convert to expected format
    let shares: Vec<SignatureShareData> = sig_outputs
        .iter()
        .map(|output| SignatureShareData {
            index: output.party_index,
            share: output.signature_share.clone(),
        })
        .collect();

    // Get shared key to compute public key and final nonce
    let shared_key_bytes = storage.read("shared_key.bin")?;
    let shared_key: SharedKey<EvenY> = bincode::deserialize(&shared_key_bytes)?;

    let final_nonce_bytes = storage.read(&format!("final_nonce_{}.bin", session))?;
    let final_nonce_hex = hex::encode(&final_nonce_bytes);
    let public_key_hex = hex::encode(bincode::serialize(&shared_key)?);

    let input = SignatureShareInput {
        shares,
        public_key: public_key_hex,
        final_nonce: final_nonce_hex,
    };

    out.push_str(&format!(
        "✓ Received {} signature shares\n",
        input.shares.len()
    ));
    out.push_str(&format!("  Message: \"{}\"\n\n", message));

    out.push_str("⚙️  Using schnorr_fun's FROST coordinator API\n");
    out.push_str("   Calling: coord_session.verify_and_combine_signature_shares()\n\n");

    // Load saved nonces for this session
    let nonces_json = String::from_utf8(storage.read(&format!("session_nonces_{}.json", session))?)
        .context("Failed to load session nonces. Did a signer run the sign command?")?;
    let nonces_data: Vec<NonceData> = serde_json::from_str(&nonces_json)?;

    out.push_str("⚙️  Recreating coordinator session...\n");
    out.push_str("🧠 Why? The coordinator needs the same context that was used during signing:\n");
    out.push_str("   - All participant nonces\n");
    out.push_str("   - The message being signed\n");
    out.push_str("   - The shared public key\n\n");

    // Reconstruct nonces map
    let mut nonces_map = BTreeMap::new();
    for nonce_data in &nonces_data {
        let nonce_bytes = hex::decode(&nonce_data.nonce)?;
        let public_nonce: schnorr_fun::binonce::Nonce = bincode::deserialize(&nonce_bytes)?;

        let share_index = Scalar::<Secret, Zero>::from(nonce_data.index)
            .non_zero()
            .expect("index should be nonzero")
            .public();
        nonces_map.insert(share_index, public_nonce);
    }

    // Create FROST instance
    let frost = frost::new_with_synthetic_nonces::<Sha256, rand::rngs::ThreadRng>();

    // Create message
    let msg = Message::new("frostsnap-yushan", message.as_bytes());

    // Recreate coordinator session
    let coord_session = frost.coordinator_sign_session(&shared_key, nonces_map, msg);

    out.push_str("⚙️  Verifying and combining signature shares...\n");
    out.push_str("🧠 What the coordinator does:\n");
    out.push_str("   1. Verifies each signature share is valid\n");
    out.push_str("   2. Checks: sig_share = k + λ × c × secret_share\n");
    out.push_str("   3. Combines all shares: final_s = Σ sig_shares\n");
    out.push_str("   4. Creates final signature (R, s)\n\n");

    // Parse signature shares into the format the coordinator expects
    let mut sig_shares = BTreeMap::new();
    for share_data in &input.shares {
        let share_bytes = hex::decode(&share_data.share)?;
        let sig_share: Scalar<Public, Zero> = bincode::deserialize(&share_bytes)?;

        let share_index = Scalar::<Secret, Zero>::from(share_data.index)
            .non_zero()
            .expect("index should be nonzero")
            .public();
        sig_shares.insert(share_index, sig_share);
        out.push_str(&format!(
            "   Verifying Party {}'s share...\n",
            share_data.index
        ));
    }

    // Use coordinator API to verify and combine
    let signature = coord_session
        .verify_and_combine_signature_shares(&shared_key, sig_shares)
        .map_err(|e| anyhow::anyhow!("Signature verification failed: {:?}", e))?;

    let valid = true; // If we got here, verification passed

    if valid {
        out.push_str("  ✓ Signature is VALID!\n\n");
    } else {
        out.push_str("  ✗ Signature verification FAILED!\n\n");
        anyhow::bail!("Signature verification failed");
    }

    let sig_bytes = bincode::serialize(&signature)?;
    let sig_hex = hex::encode(&sig_bytes);

    let pubkey_bytes = bincode::serialize(&shared_key.public_key())?;
    let pubkey_hex = hex::encode(&pubkey_bytes);

    out.push_str("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
    out.push_str("🎉 FROST SIGNATURE VALID!\n\n");
    out.push_str("✨ You just created a threshold signature using schnorr_fun's FROST!\n");
    out.push_str("   - Used real cryptographic API from production library\n");
    out.push_str("   - Signature is valid under the shared public key\n");
    out.push_str("   - No single party knew the full secret key!\n\n");
    out.push_str("❓ Challenge:\n");
    out.push_str("   This signature can be used anywhere Schnorr signatures are valid!\n");
    out.push_str("   Try signing:\n");
    out.push_str("   • A Nostr event (kind 1 message)\n");
    out.push_str("   • A Bitcoin transaction (taproot spend)\n");
    out.push_str("   • Git commits\n");
    out.push_str("   The same FROST key works for all of them!\n\n");

    // Create result with the signature details
    let result = format!(
        "Signature: {}\nPublic Key: {}\nMessage: \"{}\"",
        sig_hex, pubkey_hex, message
    );

    Ok(CommandResult {
        output: out,
        result,
    })
}

pub fn combine_signatures(data: &str) -> Result<()> {
    let storage = FileStorage::new(STATE_DIR)?;
    let cmd_result = combine_signatures_core(data, &storage)?;
    println!("{}", cmd_result.output);
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("📋 Signature:");
    println!("{}\n", cmd_result.result);
    Ok(())
}

/// Verify a FROST signature
#[allow(dead_code)]
pub fn verify_signature_core(
    signature_hex: &str,
    public_key_hex: &str,
    message: &str,
) -> Result<CommandResult> {
    let mut out = String::new();

    out.push_str("🔍 Schnorr Signature Verification\n\n");

    // Decode signature
    let sig_bytes = hex::decode(signature_hex).context("Failed to decode signature hex")?;
    let signature: Signature =
        bincode::deserialize(&sig_bytes).context("Failed to deserialize signature")?;

    // Decode public key
    let pubkey_bytes = hex::decode(public_key_hex).context("Failed to decode public key hex")?;
    let public_key: Point<EvenY> =
        bincode::deserialize(&pubkey_bytes).context("Failed to deserialize public key")?;

    // Create message
    let msg = Message::new("frostsnap-yushan", message.as_bytes());

    out.push_str("📋 Verification inputs:\n");
    out.push_str(&format!("   Message: \"{}\"\n", message));
    out.push_str(&format!("   Signature: {}...\n", &signature_hex[..32]));
    out.push_str(&format!("   Public Key: {}...\n\n", &public_key_hex[..32]));

    // Verify signature
    let frost = frost::new_with_deterministic_nonces::<Sha256>();
    let is_valid = frost.schnorr.verify(&public_key, msg, &signature);

    let result = if is_valid {
        out.push_str("✅ SIGNATURE VALID!\n");
        out.push_str("   The signature is cryptographically valid.\n");
        out.push_str("   It was created by threshold parties holding the private key.\n");
        "VALID".to_string()
    } else {
        out.push_str("❌ SIGNATURE INVALID!\n");
        out.push_str("   The signature verification failed.\n");
        out.push_str("   Either the signature, public key, or message is incorrect.\n");
        "INVALID".to_string()
    };

    Ok(CommandResult {
        output: out,
        result,
    })
}

#[allow(dead_code)]
pub fn verify_signature(signature_hex: &str, public_key_hex: &str, message: &str) -> Result<()> {
    let cmd_result = verify_signature_core(signature_hex, public_key_hex, message)?;
    println!("{}", cmd_result.output);
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("📋 Result: {}\n", cmd_result.result);
    Ok(())
}
