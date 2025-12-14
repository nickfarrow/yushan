use anyhow::Result;
use clap::{Parser, Subcommand};

/// Result from a command, separating educational output from copy-paste result
#[derive(Debug, Clone)]
pub struct CommandResult {
    /// Educational output with explanations (🧠, ⚙️, ❄️, etc.)
    pub output: String,
    /// Clean JSON result for copy-pasting
    pub result: String,
}

mod storage;
mod keygen;
mod signing;

#[derive(Parser)]
#[command(name = "yushan")]
#[command(about = "Educational FROST threshold signature workshop", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Round 1 of keygen: Generate polynomial and commitments
    KeygenRound1 {
        /// Threshold (minimum signers needed)
        #[arg(long)]
        threshold: u32,

        /// Total number of parties
        #[arg(long)]
        n_parties: u32,

        /// Your party index (1-based)
        #[arg(long)]
        my_index: u32,
    },

    /// Round 2 of keygen: Exchange shares
    KeygenRound2 {
        /// JSON with all commitments from round 1 (paste from webpage)
        #[arg(long)]
        data: String,
    },

    /// Finalize keygen: Validate and combine shares
    KeygenFinalize {
        /// JSON with all shares sent to you (paste from webpage)
        #[arg(long)]
        data: String,
    },

    /// Generate nonce for signing session
    SignNonce {
        /// Signing session ID (must be unique per signature)
        #[arg(long)]
        session: String,
    },

    /// Create signature share
    Sign {
        /// Signing session ID
        #[arg(long)]
        session: String,

        /// Message to sign
        #[arg(long)]
        message: String,

        /// JSON with nonces and group key (paste from webpage)
        #[arg(long)]
        data: String,
    },

    /// Combine signature shares into final signature
    Combine {
        /// JSON with all signature shares (includes message, paste from webpage)
        #[arg(long)]
        data: String,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::KeygenRound1 {
            threshold,
            n_parties,
            my_index,
        } => {
            keygen::round1(threshold, n_parties, my_index)?;
        }
        Commands::KeygenRound2 { data } => {
            keygen::round2(&data)?;
        }
        Commands::KeygenFinalize { data } => {
            keygen::finalize(&data)?;
        }
        Commands::SignNonce { session } => {
            signing::generate_nonce(&session)?;
        }
        Commands::Sign {
            session,
            message,
            data,
        } => {
            signing::create_signature_share(&session, &message, &data)?;
        }
        Commands::Combine { data } => {
            signing::combine_signatures(&data)?;
        }
    }

    Ok(())
}
