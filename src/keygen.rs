use anyhow::{Context, Result};
use schnorr_fun::frost::{
    self,
    chilldkg::simplepedpop::{self, *},
};
use secp256kfun::prelude::*;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;

const STATE_DIR: &str = ".frost_state";

/// Parse space-separated JSON objects into a Vec
/// Handles compact JSON where objects are separated by spaces
pub fn parse_space_separated_json<T>(data: &str) -> Result<Vec<T>>
where
    T: for<'de> Deserialize<'de>,
{
    let mut objects = Vec::new();
    let mut current_obj = String::new();
    let mut brace_depth = 0;
    let mut in_string = false;
    let mut escape_next = false;

    for ch in data.chars() {
        if escape_next {
            current_obj.push(ch);
            escape_next = false;
            continue;
        }

        match ch {
            '\\' if in_string => {
                escape_next = true;
                current_obj.push(ch);
            }
            '"' => {
                in_string = !in_string;
                current_obj.push(ch);
            }
            '{' if !in_string => {
                brace_depth += 1;
                current_obj.push(ch);
            }
            '}' if !in_string => {
                brace_depth -= 1;
                current_obj.push(ch);

                // Complete object found
                if brace_depth == 0 && !current_obj.trim().is_empty() {
                    let obj: T = serde_json::from_str(current_obj.trim()).context(format!(
                        "Failed to parse JSON object: {}",
                        current_obj.trim()
                    ))?;
                    objects.push(obj);
                    current_obj.clear();
                }
            }
            ' ' | '\t' | '\n' | '\r' if !in_string && brace_depth == 0 => {
                // Skip whitespace between objects
                continue;
            }
            _ => {
                current_obj.push(ch);
            }
        }
    }

    if brace_depth != 0 {
        anyhow::bail!("Unbalanced braces in JSON input");
    }

    if !current_obj.trim().is_empty() {
        anyhow::bail!("Incomplete JSON object at end of input");
    }

    Ok(objects)
}

// JSON structures for copy-paste interface

#[derive(Serialize, Deserialize, Debug)]
pub struct Round1Output {
    pub party_index: u32,
    pub keygen_input: String, // Bincode hex
    #[serde(rename = "type")]
    pub event_type: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Round1Input {
    pub commitments: Vec<CommitmentData>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct CommitmentData {
    pub index: u32,
    pub data: String, // Bincode hex of KeygenInput
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Round2Output {
    pub party_index: u32,
    pub shares: Vec<ShareData>,
    #[serde(rename = "type")]
    pub event_type: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ShareData {
    pub to_index: u32,
    pub share: String, // Bincode hex of secret scalar
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Round2Input {
    pub shares_for_me: Vec<IncomingShare>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct IncomingShare {
    pub from_index: u32,
    pub share: String,
}

// Internal state
#[derive(Serialize, Deserialize)]
struct Round1State {
    my_index: u32,
    threshold: u32,
    n_parties: u32,
    contributor: Contributor,
    share_indices: Vec<String>, // Hex encoded ShareIndex scalars
}

pub fn round1(threshold: u32, n_parties: u32, my_index: u32) -> Result<()> {
    println!("FROST Keygen - Round 1\n");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("Configuration:");
    println!(
        "  Threshold: {} (need {} parties to sign)",
        threshold, threshold
    );
    println!("  Total parties: {}", n_parties);
    println!("  Your index: {}", my_index);
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");

    if threshold > n_parties {
        anyhow::bail!("Threshold cannot exceed number of parties");
    }
    if my_index == 0 || my_index > n_parties {
        anyhow::bail!("Party index must be between 1 and {}", n_parties);
    }

    // Create the FROST instance
    let frost = frost::new_with_deterministic_nonces::<Sha256>();

    // Create share indices for all parties (1-based indices)
    let share_indices: BTreeSet<_> = (1..=n_parties)
        .map(|i| Scalar::from(i).non_zero().expect("nonzero"))
        .collect();

    println!("⚙️  Using schnorr_fun's FROST implementation");
    println!("   Calling: Contributor::gen_keygen_input()\n");

    println!("⚙️  Generating random polynomial...");
    println!(
        "   Degree: t-1 = {} (for threshold {})",
        threshold - 1,
        threshold
    );
    println!("   The polynomial f(x) = a0 + a1*x + a2*x² + ...");
    println!("   where a0 is your secret contribution\n");

    // Generate keygen input as a contributor
    let mut rng = rand::thread_rng();
    let (contributor, keygen_input, secret_shares) = Contributor::gen_keygen_input(
        &frost.schnorr,
        threshold,
        &share_indices,
        my_index - 1, // Contributor uses 0-based indexing
        &mut rng,
    );

    println!("❄️  Generated:");
    println!("   - {} polynomial commitments (public points)", threshold);
    println!("   - Proof of Possession (PoP) signature");
    println!("   - {} secret shares (one for each party)\n", n_parties);

    println!("🧠 What just happened:");
    println!("   1. Generated {} random polynomial coefficients [a₀, a₁, ..., a_{}]", threshold, threshold - 1);
    println!("      • a₀ is your SECRET contribution to the group key");
    println!("      • a₁, a₂, ... are random coefficients\n");
    println!("   2. Created {} commitments: [a₀*G, a₁*G, ..., a_{}*G]", threshold, threshold - 1);
    println!("      • These prove the polynomial without revealing it (safe to share!)");
    println!("      • Everyone combines a₀*G values to get the shared public key\n");
    println!("   3. Evaluated polynomial at {} indices to create secret shares", n_parties);
    println!("      • Party i receives: f(i) = a₀ + a₁*i + a₂*i² + ...");
    println!("      • Each share is a point on your polynomial\n");
    println!("   4. Created Proof-of-Possession (PoP) signature");
    println!("      • This proves you know a₀ (your secret contribution)");
    println!("      • Prevents rogue-key and key-cancellation attacks\n");
    println!("❓ Think about it:");
    println!("   Why is it important to verify Proofs-of-Possession?");
    println!("   What could an attacker do if they could contribute a₀*G");
    println!("   without proving they know a₀?\n");

    // Serialize for output
    let keygen_input_bytes = bincode::serialize(&keygen_input)?;
    let keygen_input_hex = hex::encode(&keygen_input_bytes);

    // Save state for round 2
    fs::create_dir_all(STATE_DIR)?;
    let state = Round1State {
        my_index,
        threshold,
        n_parties,
        contributor,
        share_indices: share_indices
            .iter()
            .map(|s| hex::encode(s.to_bytes()))
            .collect(),
    };
    fs::write(
        format!("{}/round1_state.json", STATE_DIR),
        serde_json::to_string_pretty(&state)?,
    )?;

    // Save keygen shares for round 2
    let shares_map: BTreeMap<String, String> = secret_shares
        .into_iter()
        .map(|(idx, share)| (hex::encode(idx.to_bytes()), hex::encode(share.to_bytes())))
        .collect();
    fs::write(
        format!("{}/my_secret_shares.json", STATE_DIR),
        serde_json::to_string_pretty(&shares_map)?,
    )?;

    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("✉️  Your commitment (copy this JSON):");
    println!("   Note: The CLI accepts space-separated JSON objects.");
    println!("   You can combine outputs from all parties like:");
    println!("   '{{...party1...}} {{...party2...}} {{...party3...}}'\n");

    let output = Round1Output {
        party_index: my_index,
        keygen_input: keygen_input_hex,
        event_type: "keygen_round1".to_string(),
    };

    println!("{}\n", serde_json::to_string_pretty(&output)?);
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("\n➜ Paste this JSON into the webpage");
    println!(
        "➜ Wait for all {} parties to post their commitments",
        n_parties
    );
    println!("➜ Copy the \"all commitments\" JSON from webpage");
    println!("➜ Run: cargo run -- keygen-round2 --data '<JSON>'",);

    Ok(())
}

pub fn round2(data: &str) -> Result<()> {
    println!("FROST Keygen - Round 2\n");

    // Load state
    let state_json = fs::read_to_string(format!("{}/round1_state.json", STATE_DIR))
        .context("Failed to load round 1 state. Did you run keygen-round1?")?;
    let state: Round1State = serde_json::from_str(&state_json)?;

    // Load my keygen shares (to send to other parties)
    let shares_json = fs::read_to_string(format!("{}/my_secret_shares.json", STATE_DIR))?;
    let shares_map: BTreeMap<String, String> = serde_json::from_str(&shares_json)?;

    // Parse input - space-separated Round1Output objects
    let round1_outputs: Vec<Round1Output> = parse_space_separated_json(data)?;

    // Convert to expected format
    let commitments: Vec<CommitmentData> = round1_outputs
        .into_iter()
        .map(|output| CommitmentData {
            index: output.party_index,
            data: output.keygen_input,
        })
        .collect();

    let input = Round1Input { commitments };

    println!(
        " Received {} commitments from other parties\n",
        input.commitments.len()
    );

    println!("⚙️  Using schnorr_fun's FROST coordinator");
    println!("   This aggregates all commitments and validates them\n");

    // Create FROST instance
    let frost = frost::new_with_deterministic_nonces::<Sha256>();

    // Create coordinator to aggregate inputs
    let mut coordinator = Coordinator::new(state.threshold, state.n_parties);

    println!("⚙️  Adding inputs to coordinator...");
    for commit_data in &input.commitments {
        let keygen_input_bytes = hex::decode(&commit_data.data)?;
        let keygen_input: KeygenInput = bincode::deserialize(&keygen_input_bytes)?;

        coordinator
            .add_input(
                &frost.schnorr,
                commit_data.index - 1, // Coordinator uses 0-based indexing
                keygen_input,
            )
            .map_err(|e| anyhow::anyhow!("Failed to add input: {}", e))?;

        println!("    Party {}: Commitment validated", commit_data.index);
    }

    println!("\n❄️  All commitments valid!\n");

    println!("✉️  Your keygen shares to send:");
    println!("🧠 Why send keygen shares?");
    println!("   Each party evaluates their polynomial at ALL {} party indices", state.n_parties);
    println!("   Party i sends f_i(j) to party j");
    println!("   These keygen shares will be combined to create each party's");
    println!("   final secret share (without anyone knowing the full key!)\n");
    println!("⚠️  WARNING: In production, these keygen shares MUST be encrypted!");
    println!("   We're skipping encryption for educational simplicity.\n");
    println!("❓ Think about it:");
    println!("   We're skipping a critical security step here!");
    println!("   What should we do before sending these keygen shares?");
    println!("   (Hint: How do you securely transmit secrets to a recipient?)\n");

    // Create output with shares
    let mut shares = Vec::new();
    for (idx_hex, share_hex) in shares_map {
        let idx_bytes = hex::decode(&idx_hex)?;
        let idx_scalar: Scalar<Public, NonZero> = Scalar::<NonZero>::from_slice(&idx_bytes[..32])
            .expect("share index cant be zero!")
            .public();
        // Extract index value - scalars are big-endian, so small values are in last byte
        let to_index = idx_scalar.to_bytes()[31] as u32;

        println!("   Share for Party {}: <secret scalar>", to_index);

        shares.push(ShareData {
            to_index,
            share: share_hex,
        });
    }

    println!("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!(" Your shares (copy this JSON):\n");

    let output = Round2Output {
        party_index: state.my_index,
        shares,
        event_type: "keygen_round2".to_string(),
    };

    println!("{}\n", serde_json::to_string_pretty(&output)?);
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("\n➜ Paste this JSON into the webpage");
    println!("➜ Wait for all parties to post their shares");
    println!(
        "➜ Copy \"shares for Party {}\" JSON from webpage",
        state.my_index
    );
    println!("➜ Run: cargo run -- keygen-finalize --data '<JSON>'",);

    // Save all commitments for validation
    fs::write(format!("{}/all_commitments.json", STATE_DIR), data)?;

    Ok(())
}

pub fn finalize(data: &str) -> Result<()> {
    println!("FROST Keygen - Finalize\n");

    // Load state
    let state_json = fs::read_to_string(format!("{}/round1_state.json", STATE_DIR))?;
    let state: Round1State = serde_json::from_str(&state_json)?;

    let commitments_json = fs::read_to_string(format!("{}/all_commitments.json", STATE_DIR))?;
    let round1_outputs: Vec<Round1Output> = parse_space_separated_json(&commitments_json)?;
    let commitments: Vec<CommitmentData> = round1_outputs
        .into_iter()
        .map(|output| CommitmentData {
            index: output.party_index,
            data: output.keygen_input,
        })
        .collect();
    let commitments_input = Round1Input { commitments };

    // Parse shares sent to me - space-separated Round2Output objects
    let round2_outputs: Vec<Round2Output> = parse_space_separated_json(data)?;

    // Extract shares sent to my_index
    let mut shares_for_me = Vec::new();
    for output in round2_outputs {
        for share in output.shares {
            if share.to_index == state.my_index {
                shares_for_me.push(IncomingShare {
                    from_index: output.party_index,
                    share: share.share,
                });
            }
        }
    }

    let shares_input = Round2Input { shares_for_me };

    println!(
        " Received {} keygen shares sent to you\n",
        shares_input.shares_for_me.len()
    );

    println!("⚙️  Computing your final secret share:");
    println!("🧠 How it works:");
    println!("   Your final secret share = sum of all keygen shares received");
    println!("   secret_share = f₁({}) + f₂({}) + f₃({}) + ...", state.my_index, state.my_index, state.my_index);
    println!("   ");
    println!("   This is YOUR piece of the distributed private key!");
    println!("   With {} secret shares, you can reconstruct the full key.\n", state.threshold);

    // Collect keygen shares into a vector
    let mut secret_share_inputs = Vec::new();
    for incoming in &shares_input.shares_for_me {
        let share_bytes = hex::decode(&incoming.share)?;
        let share: Scalar<Secret, Zero> = bincode::deserialize(&share_bytes)?;
        secret_share_inputs.push(share);
        println!("   + Party {}'s keygen share", incoming.from_index);
    }

    println!("\n⚙️  Computing shared public key:");
    println!("🧠 How the group public key is created:");
    println!("   PublicKey = sum of all parties' a₀*G commitments");
    println!("   PK = (a₀)₁*G + (a₀)₂*G + (a₀)₃*G + ...");
    println!("   ");
    println!("   Since PK = (a₀)₁ + (a₀)₂ + ... times G,");
    println!("   and the private key = (a₀)₁ + (a₀)₂ + ...,");
    println!("   this IS the public key for the distributed private key!\n");

    // Reconstruct all KeygenInputs to get the aggregated key
    let frost = frost::new_with_deterministic_nonces::<Sha256>();
    let mut coordinator = Coordinator::new(state.threshold, state.n_parties);

    for commit_data in &commitments_input.commitments {
        let keygen_input_bytes = hex::decode(&commit_data.data)?;
        let keygen_input: KeygenInput = bincode::deserialize(&keygen_input_bytes)?;
        coordinator
            .add_input(&frost.schnorr, commit_data.index - 1, keygen_input)
            .map_err(|e| anyhow::anyhow!("Failed to add input: {}", e))?;
    }

    let agg_input = coordinator.finish().context("Coordinator not finished")?;

    // Use SimplePedPop utility functions to properly create and pair the secret share
    let my_share_index = Scalar::<Secret, Zero>::from(state.my_index)
        .public()
        .non_zero()
        .expect("participant index cant be zero");

    let secret_share = simplepedpop::collect_secret_inputs(my_share_index, secret_share_inputs);

    let paired_share = simplepedpop::receive_secret_share(&frost.schnorr, &agg_input, secret_share)
        .map_err(|e| anyhow::anyhow!("Failed to receive secret share: {:?}", e))?;

    let shared_key = agg_input.shared_key();

    // Convert to xonly (EvenY) for BIP340 compatibility
    let xonly_paired_share = paired_share
        .non_zero()
        .context("Paired share is zero")?
        .into_xonly();
    let xonly_shared_key = shared_key
        .non_zero()
        .context("Shared key is zero")?
        .into_xonly();

    // Display clean hex (just the raw bytes, no metadata)
    let final_share_hex = hex::encode(xonly_paired_share.secret_share().to_bytes());
    let public_key_hex = hex::encode(xonly_shared_key.public_key().to_bytes());

    // Save bincode format for loading later (includes type info for deserialization)
    let final_share_bytes = bincode::serialize(&xonly_paired_share)?;
    let public_key_bytes = bincode::serialize(&xonly_shared_key)?;
    fs::write(
        format!("{}/paired_secret_share.bin", STATE_DIR),
        &final_share_bytes,
    )?;
    fs::write(format!("{}/shared_key.bin", STATE_DIR), &public_key_bytes)?;

    println!("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!(" YOUR SECRET SHARE (keep this safe!):");
    println!("  {}\n", final_share_hex);
    println!(" SHARED PUBLIC KEY:");
    println!("  {}\n", public_key_hex);
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("\n❄️  Key generation complete!");
    println!("   Using schnorr_fun's FROST SharedKey and PairedSecretShare");
    println!("   Compare public keys with other tables to verify!\n");

    Ok(())
}
