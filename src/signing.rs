use anyhow::{Context, Result};
use rand_chacha::ChaCha20Rng;
use schnorr_fun::binonce::NonceKeyPair;
use schnorr_fun::frost::{self, PairedSecretShare, SharedKey};
use schnorr_fun::Message;
use secp256kfun::prelude::*;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::collections::BTreeMap;
use std::fs;

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

pub fn generate_nonce(session: &str) -> Result<()> {
    println!("FROST Signing - Nonce Generation\n");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("Session ID: {}", session);
    println!("⚠  NEVER reuse a nonce as it will leak your secret share!");
    println!("    Each signature needs fresh nonces!");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");

    // Load paired secret share
    let paired_share_bytes = fs::read(format!("{}/paired_secret_share.bin", STATE_DIR))
        .context("Failed to load secret share. Did you run keygen-finalize?")?;
    let paired_share: PairedSecretShare<EvenY> = bincode::deserialize(&paired_share_bytes)?;

    let party_index = {
        // ~hack to go back from scalar index to u32
        let mut u32_index_bytes = [0u8; 4];
        u32_index_bytes.copy_from_slice(&paired_share.index().to_bytes()[28..]);
        let u32_index = u32::from_be_bytes(u32_index_bytes);
        u32_index
    };

    println!("⚙️  Using schnorr_fun's FROST nonce generation");
    println!("   Calling: frost.seed_nonce_rng() and frost.gen_nonce()\n");

    // Create FROST instance with deterministic nonces
    let frost = frost::new_with_synthetic_nonces::<Sha256, rand::rngs::ThreadRng>();

    // Seed the nonce RNG with session ID
    let mut nonce_rng: ChaCha20Rng = frost.seed_nonce_rng(paired_share, session.as_bytes());

    // Generate nonce
    let nonce = frost.gen_nonce(&mut nonce_rng);

    println!("❄️  Generated NonceKeyPair:");
    println!("   - Secret nonces: (k₁, k₂) - kept private");
    println!("   - Public nonces: (R₁, R₂) where R₁ = k₁*G, R₂ = k₂*G\n");
    println!("🧠 Why do we need nonces?");
    println!("   Schnorr signatures require randomness to be secure!");
    println!("   If you ever reuse a nonce with the same key, an attacker");
    println!("   can solve for your secret share and steal your key.");
    println!("   ");
    println!("   FROST uses TWO nonces (k₁, k₂) for extra security:");
    println!("   • k₁ is the primary nonce");
    println!("   • k₂ protects against rogue-key attacks in multi-party signing\n");
    println!("❓ Think about it:");
    println!("   Notice: We can generate nonces BEFORE knowing the message!");
    println!("   Current flow: share nonces → then sign (2 rounds)");
    println!("   How could we optimize FROST to sign in just 1 round?");
    println!("   (Hint: What if we pre-shared nonces?)\n");

    // Serialize nonce keypair for later use
    let nonce_bytes = bincode::serialize(&nonce)?;
    fs::write(format!("{}/nonce_{}.bin", STATE_DIR, session), &nonce_bytes)?;

    // Serialize public nonce for sharing
    let public_nonce = nonce.public();
    let public_nonce_bytes = bincode::serialize(&public_nonce)?;
    let public_nonce_hex = hex::encode(&public_nonce_bytes);

    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("✉️  Your public nonce (copy this JSON):\n");

    let output = NonceOutput {
        party_index: party_index,
        session: session.to_string(),
        nonce: public_nonce_hex,
        event_type: "signing_nonce".to_string(),
    };

    println!("{}\n", serde_json::to_string_pretty(&output)?);
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("\n➜ Paste this JSON into the webpage");
    println!("➜ Wait for threshold number of signers to post nonces");
    println!(
        "➜ Copy the \"nonces for session {}\" JSON from webpage",
        session
    );
    println!(
        "➜ Run: cargo run -- sign --session {} --message \"<msg>\" --data '<JSON>'",
        session
    );

    Ok(())
}

pub fn create_signature_share(session: &str, message: &str, data: &str) -> Result<()> {
    println!("🔐 FROST Signing - Create Signature Share\n");

    // Load nonce
    let nonce_bytes = fs::read(format!("{}/nonce_{}.bin", STATE_DIR, session))
        .context("Failed to load nonce. Did you run sign-nonce?")?;
    let nonce: NonceKeyPair = bincode::deserialize(&nonce_bytes)?;

    // Load paired secret share
    let paired_share_bytes = fs::read(format!("{}/paired_secret_share.bin", STATE_DIR))?;
    let paired_share: PairedSecretShare<EvenY> = bincode::deserialize(&paired_share_bytes)?;

    let party_index = {
        // ~hack to go back from scalar index to u32
        let mut u32_index_bytes = [0u8; 4];
        u32_index_bytes.copy_from_slice(&paired_share.index().to_bytes()[28..]);
        let u32_index = u32::from_be_bytes(u32_index_bytes);
        u32_index
    };

    // Load shared key
    let shared_key_bytes = fs::read(format!("{}/shared_key.bin", STATE_DIR))?;
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

    println!(" Signing with {} parties", num_signers);
    println!("  Message: \"{}\"\n", message);

    println!("📐 Using schnorr_fun's FROST signing");
    println!("   Calling: frost.party_sign_session()\n");

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

    println!("🔢 Creating coordinator sign session...");
    println!("   Aggregating all nonces");
    println!("   Computing binding coefficient");
    println!("   Computing challenge = H(R || PubKey || message)\n");

    // Create message
    let msg = Message::new("frosty-taipei", message.as_bytes());

    // Create coordinator session
    let coord_session = frost.coordinator_sign_session(&shared_key, nonces_map.clone(), msg);

    println!("✓ Coordinator session created:");
    println!("   - Aggregated nonce: R = R1 + R2 + ...");
    println!("   - Challenge: c = H(R || PK || msg)");
    println!(
        "   - Parties: {:?}\n",
        coord_session
            .parties()
            .iter()
            .map(|s| s.to_bytes()[0] as u32)
            .collect::<Vec<_>>()
    );

    println!("📝 Creating party sign session...");
    let agg_binonce = coord_session.agg_binonce();
    let parties = coord_session.parties();

    let sign_session =
        frost.party_sign_session(shared_key.public_key(), parties.clone(), agg_binonce, msg);

    println!("⚙️  Computing Lagrange coefficient...");
    println!("🧠 Why Lagrange coefficients?");
    println!("   During keygen, you received a share for index {}", party_index);
    println!("   But only {} parties are signing in this session!", num_signers);
    println!("   ");
    println!("   Lagrange interpolation adjusts your share to work with");
    println!("   ANY threshold subset of signers (not just all parties).");
    println!("   ");
    println!("   λ{} = the coefficient that makes YOUR share compatible", party_index);
    println!("   with this specific group of {} signers.\n", num_signers);
    println!("❓ Think about it:");
    println!("   You've selected a specific group of {} signers for this signature.", num_signers);
    println!("   What downstream implication does this have?");
    println!("   (Hint: How does this differ from Bitcoin script multisig,");
    println!("   where ANY threshold combination can spend?)\n");

    println!("⚙️  Creating signature share...");
    println!("🧠 Schnorr signature math:");
    println!("   s{} = k{} + λ{} × c × secret_share{}", party_index, party_index, party_index, party_index);
    println!("   where:");
    println!("   • k{} = your secret nonce", party_index);
    println!("   • λ{} = your Lagrange coefficient", party_index);
    println!("   • c = challenge = Hash(R || PubKey || message)");
    println!("   • secret_share{} = your piece of the private key\n", party_index);

    // Sign
    let sig_share = sign_session.sign(&paired_share, nonce);

    let sig_share_bytes = bincode::serialize(&sig_share)?;
    let sig_share_hex = hex::encode(&sig_share_bytes);

    // Save the final nonce and nonces map for combine step
    let final_nonce = coord_session.final_nonce();
    let final_nonce_bytes = bincode::serialize(&final_nonce)?;
    fs::write(
        format!("{}/final_nonce_{}.bin", STATE_DIR, session),
        &final_nonce_bytes,
    )?;

    // Save nonces map for coordinator session recreation
    let nonces_json = serde_json::to_string(&input.nonces)?;
    fs::write(
        format!("{}/session_nonces_{}.json", STATE_DIR, session),
        nonces_json,
    )?;

    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("✓ Your signature share (copy this JSON):\n");

    let output = SignatureShareOutput {
        party_index,
        session: session.to_string(),
        message: message.to_string(),
        signature_share: sig_share_hex,
        event_type: "signing_share".to_string(),
    };

    println!("{}\n", serde_json::to_string_pretty(&output)?);
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("\n➜ Paste this JSON into the webpage");
    println!("➜ Once all signers post shares, anyone can combine them");
    println!(
        "➜ Run: cargo run -- combine --message \"{}\" --data '<shares JSON>'",
        message
    );

    Ok(())
}

pub fn combine_signatures(data: &str) -> Result<()> {
    println!("🔐 FROST Signing - Combine Signature Shares\n");

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
    let shared_key_bytes = fs::read(format!("{}/shared_key.bin", STATE_DIR))?;
    let shared_key: SharedKey<EvenY> = bincode::deserialize(&shared_key_bytes)?;

    let final_nonce_bytes = fs::read(format!("{}/final_nonce_{}.bin", STATE_DIR, session))?;
    let final_nonce_hex = hex::encode(&final_nonce_bytes);
    let public_key_hex = hex::encode(bincode::serialize(&shared_key)?);

    let input = SignatureShareInput {
        shares,
        public_key: public_key_hex,
        final_nonce: final_nonce_hex,
    };

    println!("✓ Received {} signature shares", input.shares.len());
    println!("  Message: \"{}\"\n", message);

    println!("⚙️  Using schnorr_fun's FROST coordinator API");
    println!("   Calling: coord_session.verify_and_combine_signature_shares()\n");

    // Load saved nonces for this session
    let nonces_json = fs::read_to_string(format!("{}/session_nonces_{}.json", STATE_DIR, session))
        .context("Failed to load session nonces. Did a signer run the sign command?")?;
    let nonces_data: Vec<NonceData> = serde_json::from_str(&nonces_json)?;

    println!("⚙️  Recreating coordinator session...");
    println!("🧠 Why? The coordinator needs the same context that was used during signing:");
    println!("   - All participant nonces");
    println!("   - The message being signed");
    println!("   - The shared public key\n");

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
    let msg = Message::new("frosty-taipei", message.as_bytes());

    // Recreate coordinator session
    let coord_session = frost.coordinator_sign_session(&shared_key, nonces_map, msg);

    println!("⚙️  Verifying and combining signature shares...");
    println!("🧠 What the coordinator does:");
    println!("   1. Verifies each signature share is valid");
    println!("   2. Checks: sig_share = k + λ × c × secret_share");
    println!("   3. Combines all shares: final_s = Σ sig_shares");
    println!("   4. Creates final signature (R, s)\n");

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
        println!("   Verifying Party {}'s share...", share_data.index);
    }

    // Use coordinator API to verify and combine
    let signature = coord_session
        .verify_and_combine_signature_shares(&shared_key, sig_shares)
        .map_err(|e| anyhow::anyhow!("Signature verification failed: {:?}", e))?;

    let valid = true; // If we got here, verification passed

    if valid {
        println!("  ✓ Signature is VALID!\n");
    } else {
        println!("  ✗ Signature verification FAILED!\n");
        anyhow::bail!("Signature verification failed");
    }

    let sig_bytes = bincode::serialize(&signature)?;
    let sig_hex = hex::encode(&sig_bytes);

    let pubkey_bytes = bincode::serialize(&shared_key.public_key())?;
    let pubkey_hex = hex::encode(&pubkey_bytes);

    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("🎉 FROST SIGNATURE VALID!\n");
    println!("Signature:");
    println!("  {}\n", sig_hex);
    println!("Public key:");
    println!("  {}\n", pubkey_hex);
    println!("Message:");
    println!("  \"{}\"\n", message);
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("\n✨ You just created a threshold signature using schnorr_fun's FROST!");
    println!("   - Used real cryptographic API from production library");
    println!("   - Signature is valid under the shared public key");
    println!("   - No single party knew the full secret key!\n");
    println!("❓ Challenge:");
    println!("   This signature can be used anywhere Schnorr signatures are valid!");
    println!("   Try signing:");
    println!("   • A Nostr event (kind 1 message)");
    println!("   • A Bitcoin transaction (taproot spend)");
    println!("   • Git commits");
    println!("   The same FROST key works for all of them!\n");

    Ok(())
}
