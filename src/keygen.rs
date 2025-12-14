use crate::storage::{FileStorage, Storage};
use crate::CommandResult;
use anyhow::{Context, Result};
use schnorr_fun::frost::{
    self,
    chilldkg::simplepedpop::{self, *},
};
use secp256kfun::prelude::*;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::collections::{BTreeMap, BTreeSet};

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

pub fn round1_core(
    threshold: u32,
    n_parties: u32,
    my_index: u32,
    storage: &dyn Storage,
) -> Result<CommandResult> {
    let mut out = String::new();

    out.push_str("FROST Keygen - Round 1\n\n");
    out.push_str("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
    out.push_str("Configuration:\n");
    out.push_str(&format!(
        "  Threshold: {} (need {} parties to sign)\n",
        threshold, threshold
    ));
    out.push_str(&format!("  Total parties: {}\n", n_parties));
    out.push_str(&format!("  Your index: {}\n", my_index));
    out.push_str("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n");

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

    out.push_str("⚙️  Using schnorr_fun's FROST implementation\n");
    out.push_str("   Calling: Contributor::gen_keygen_input()\n\n");

    out.push_str("⚙️  Generating random polynomial...\n");
    out.push_str(&format!(
        "   Degree: t-1 = {} (for threshold {})\n",
        threshold - 1,
        threshold
    ));
    out.push_str("   The polynomial f(x) = a0 + a1*x + a2*x² + ...\n");
    out.push_str("   where a0 is your secret contribution\n\n");

    // Generate keygen input as a contributor
    let mut rng = rand::thread_rng();
    let (contributor, keygen_input, secret_shares) = Contributor::gen_keygen_input(
        &frost.schnorr,
        threshold,
        &share_indices,
        my_index - 1, // Contributor uses 0-based indexing
        &mut rng,
    );

    out.push_str("❄️  Generated:\n");
    out.push_str(&format!(
        "   - {} polynomial commitments (public points)\n",
        threshold
    ));
    out.push_str("   - Proof of Possession (PoP) signature\n");
    out.push_str(&format!(
        "   - {} secret shares (one for each party)\n\n",
        n_parties
    ));

    out.push_str("🧠 What just happened:\n");
    out.push_str(&format!(
        "   1. Generated {} random polynomial coefficients [a₀, a₁, ..., a_{}]\n",
        threshold,
        threshold - 1
    ));
    out.push_str("      • a₀ is your SECRET contribution to the group key\n");
    out.push_str("      • a₁, a₂, ... are random coefficients\n\n");
    out.push_str(&format!(
        "   2. Created {} commitments: [a₀*G, a₁*G, ..., a_{}*G]\n",
        threshold,
        threshold - 1
    ));
    out.push_str("      • These prove the polynomial without revealing it (safe to share!)\n");
    out.push_str("      • Everyone combines a₀*G values to get the shared public key\n\n");
    out.push_str(&format!(
        "   3. Evaluated polynomial at {} indices to create secret shares\n",
        n_parties
    ));
    out.push_str("      • Party i receives: f(i) = a₀ + a₁*i + a₂*i² + ...\n");
    out.push_str("      • Each share is a point on your polynomial\n\n");
    out.push_str("   4. Created Proof-of-Possession (PoP) signature\n");
    out.push_str("      • This proves you know a₀ (your secret contribution)\n");
    out.push_str("      • Prevents rogue-key and key-cancellation attacks\n\n");
    out.push_str("❓ Think about it:\n");
    out.push_str("   Why is it important to verify Proofs-of-Possession?\n");
    out.push_str("   What could an attacker do if they could contribute a₀*G\n");
    out.push_str("   without proving they know a₀?\n\n");

    // Serialize for output
    let keygen_input_bytes = bincode::serialize(&keygen_input)?;
    let keygen_input_hex = hex::encode(&keygen_input_bytes);

    // Save state for round 2
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
    storage.write(
        "round1_state.json",
        serde_json::to_string_pretty(&state)?.as_bytes(),
    )?;

    // Save keygen shares for round 2
    let shares_map: BTreeMap<String, String> = secret_shares
        .into_iter()
        .map(|(idx, share)| (hex::encode(idx.to_bytes()), hex::encode(share.to_bytes())))
        .collect();
    storage.write(
        "my_secret_shares.json",
        serde_json::to_string_pretty(&shares_map)?.as_bytes(),
    )?;

    out.push_str("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
    out.push_str("✉️  Your commitment generated!\n\n");

    out.push_str("➜ Paste the result JSON into the webpage\n");
    out.push_str(&format!(
        "➜ Wait for all {} parties to post their commitments\n",
        n_parties
    ));
    out.push_str("➜ Copy the \"all commitments\" JSON from webpage\n");
    out.push_str("➜ Run: yushan keygen-round2 --data '<JSON>'\n");

    // Create JSON result for copy-pasting
    let output = Round1Output {
        party_index: my_index,
        keygen_input: keygen_input_hex,
        event_type: "keygen_round1".to_string(),
    };
    let result = serde_json::to_string(&output)?;

    Ok(CommandResult {
        output: out,
        result,
    })
}

pub fn round1(threshold: u32, n_parties: u32, my_index: u32) -> Result<()> {
    let storage = FileStorage::new(STATE_DIR)?;
    let cmd_result = round1_core(threshold, n_parties, my_index, &storage)?;
    println!("{}", cmd_result.output);
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("📋 Copy this JSON:");
    println!("{}\n", cmd_result.result);
    Ok(())
}

pub fn round2_core(data: &str, storage: &dyn Storage) -> Result<CommandResult> {
    let mut out = String::new();

    out.push_str("FROST Keygen - Round 2\n\n");

    // Load state
    let state_json = String::from_utf8(storage.read("round1_state.json")?)
        .context("Failed to load round 1 state. Did you run keygen-round1?")?;
    let state: Round1State = serde_json::from_str(&state_json)?;

    // Load my keygen shares (to send to other parties)
    let shares_json = String::from_utf8(storage.read("my_secret_shares.json")?)?;
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

    out.push_str(&format!(
        " Received {} commitments from other parties\n\n",
        input.commitments.len()
    ));

    out.push_str("⚙️  Using schnorr_fun's FROST coordinator\n");
    out.push_str("   This aggregates all commitments and validates them\n\n");

    // Create FROST instance
    let frost = frost::new_with_deterministic_nonces::<Sha256>();

    // Create coordinator to aggregate inputs
    let mut coordinator = Coordinator::new(state.threshold, state.n_parties);

    out.push_str("⚙️  Adding inputs to coordinator...\n");
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

        out.push_str(&format!(
            "    Party {}: Commitment validated\n",
            commit_data.index
        ));
    }

    out.push_str("\n❄️  All commitments valid!\n\n");

    out.push_str("✉️  Your keygen shares to send:\n");
    out.push_str("🧠 Why send keygen shares?\n");
    out.push_str(&format!(
        "   Each party evaluates their polynomial at ALL {} party indices\n",
        state.n_parties
    ));
    out.push_str("   Party i sends f_i(j) to party j\n");
    out.push_str("   These keygen shares will be combined to create each party's\n");
    out.push_str("   final secret share (without anyone knowing the full key!)\n\n");
    out.push_str("❓ Think about it:\n");
    out.push_str("   By broadcasting these keygen shares publicly on Nostr, we're\n");
    out.push_str("   making a critical security mistake! Anyone can reconstruct\n");
    out.push_str("   the full private key. What should be done instead?\n\n");

    // Create output with shares
    let mut shares = Vec::new();
    for (idx_hex, share_hex) in shares_map {
        let idx_bytes = hex::decode(&idx_hex)?;
        let idx_scalar: Scalar<Public, NonZero> = Scalar::<NonZero>::from_slice(&idx_bytes[..32])
            .expect("share index cant be zero!")
            .public();
        // Extract index value - scalars are big-endian, so small values are in last byte
        let to_index = idx_scalar.to_bytes()[31] as u32;

        out.push_str(&format!("   Share for Party {}: {}\n", to_index, share_hex));

        shares.push(ShareData {
            to_index,
            share: share_hex,
        });
    }

    out.push_str("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
    out.push_str("✉️  Your shares generated!\n\n");

    out.push_str("➜ Paste the result JSON into the webpage\n");
    out.push_str("➜ Wait for all parties to post their shares\n");
    out.push_str(&format!(
        "➜ Copy \"shares for Party {}\" JSON from webpage\n",
        state.my_index
    ));
    out.push_str("➜ Run: yushan keygen-finalize --data '<JSON>'\n");

    // Save all commitments for validation
    storage.write("all_commitments.json", data.as_bytes())?;

    // Create JSON result for copy-pasting
    let output = Round2Output {
        party_index: state.my_index,
        shares,
        event_type: "keygen_round2".to_string(),
    };
    let result = serde_json::to_string(&output)?;

    Ok(CommandResult {
        output: out,
        result,
    })
}

pub fn round2(data: &str) -> Result<()> {
    let storage = FileStorage::new(STATE_DIR)?;
    let cmd_result = round2_core(data, &storage)?;
    println!("{}", cmd_result.output);
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("📋 Copy this JSON:");
    println!("{}\n", cmd_result.result);
    Ok(())
}

pub fn finalize_core(data: &str, storage: &dyn Storage) -> Result<CommandResult> {
    let mut out = String::new();

    out.push_str("FROST Keygen - Finalize\n\n");

    // Load state
    let state_json = String::from_utf8(storage.read("round1_state.json")?)?;
    let state: Round1State = serde_json::from_str(&state_json)?;

    let commitments_json = String::from_utf8(storage.read("all_commitments.json")?)?;
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

    out.push_str(&format!(
        " Received {} keygen shares sent to you\n\n",
        shares_input.shares_for_me.len()
    ));

    out.push_str("⚙️  Computing your final secret share:\n");
    out.push_str("🧠 How it works:\n");
    out.push_str("   Your final secret share = sum of all keygen shares received\n");
    out.push_str(&format!(
        "   secret_share = f₁({}) + f₂({}) + f₃({}) + ...\n",
        state.my_index, state.my_index, state.my_index
    ));
    out.push_str("   \n");
    out.push_str("   This is YOUR piece of the distributed private key!\n");
    out.push_str(&format!(
        "   With {} secret shares, you can reconstruct the full key.\n\n",
        state.threshold
    ));

    // Collect keygen shares into a vector
    let mut secret_share_inputs = Vec::new();
    for incoming in &shares_input.shares_for_me {
        let share_bytes = hex::decode(&incoming.share)?;
        let share: Scalar<Secret, Zero> = bincode::deserialize(&share_bytes)?;
        secret_share_inputs.push(share);
        out.push_str(&format!(
            "   + Party {}'s keygen share\n",
            incoming.from_index
        ));
    }

    out.push_str("\n⚙️  Computing shared public key:\n");
    out.push_str("🧠 How the group public key is created:\n");
    out.push_str("   PublicKey = sum of all parties' a₀*G commitments\n");
    out.push_str("   PK = (a₀)₁*G + (a₀)₂*G + (a₀)₃*G + ...\n");
    out.push_str("   \n");
    out.push_str("   Since PK = (a₀)₁ + (a₀)₂ + ... times G,\n");
    out.push_str("   and the private key = (a₀)₁ + (a₀)₂ + ...,\n");
    out.push_str("   this IS the public key for the distributed private key!\n\n");

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

    out.push_str("⚙️  Verifying keygen shares against commitments:\n");
    out.push_str("🧠 Critical security check!\n");
    out.push_str("   For each share f_i(j) received from party i:\n");
    out.push_str("   • Verify: f_i(j)*G == C_0 + C_1*j + C_2*j² + ...\n");
    out.push_str("   • Where [C_0, C_1, C_2, ...] are party i's commitments from Round 1\n");
    out.push_str("   • This proves the share is consistent with the polynomial!\n");
    out.push_str("   • Prevents malicious parties from sending bad shares\n\n");

    // Use SimplePedPop utility functions to properly create and pair the secret share
    let my_share_index = Scalar::<Secret, Zero>::from(state.my_index)
        .public()
        .non_zero()
        .expect("participant index cant be zero");

    let secret_share = simplepedpop::collect_secret_inputs(my_share_index, secret_share_inputs);

    out.push_str("⚙️  Calling simplepedpop::receive_secret_share()...\n");
    out.push_str("   This verifies all shares and pairs them with the commitments\n\n");

    let paired_share = simplepedpop::receive_secret_share(&frost.schnorr, &agg_input, secret_share)
        .map_err(|e| anyhow::anyhow!("Share verification failed: {:?}", e))?;

    out.push_str("❄️  All shares verified successfully!\n");
    out.push_str("   Every share is cryptographically valid\n\n");

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
    let final_share_hex = hex::encode(xonly_paired_share.secret_share().share.to_bytes());
    let public_key_hex = hex::encode(xonly_shared_key.public_key().to_bytes());

    // Save bincode format for loading later (includes type info for deserialization)
    let final_share_bytes = bincode::serialize(&xonly_paired_share)?;
    let public_key_bytes = bincode::serialize(&xonly_shared_key)?;
    storage.write("paired_secret_share.bin", &final_share_bytes)?;
    storage.write("shared_key.bin", &public_key_bytes)?;

    out.push_str("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
    out.push_str("❄️  Key generation complete!\n");
    out.push_str("   Compare public keys with other tables to verify!\n\n");

    // Create result with the keys
    let result = format!(
        "Secret Share: {}\nPublic Key: {}",
        final_share_hex, public_key_hex
    );

    Ok(CommandResult {
        output: out,
        result,
    })
}

pub fn finalize(data: &str) -> Result<()> {
    let storage = FileStorage::new(STATE_DIR)?;
    let cmd_result = finalize_core(data, &storage)?;
    println!("{}", cmd_result.output);
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("📋 Your keys:");
    println!("{}\n", cmd_result.result);
    Ok(())
}
