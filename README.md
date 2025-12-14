# Frosty Taipei

A hands-on FROST threshold signature workshop using schnorr_fun's SimplePedPop protocol.

## What is this?

Educational CLI tool for teaching threshold cryptography at Bitcoin conferences. Participants form tables of 3 and cooperatively generate a 2-of-3 threshold key, then create signatures together.

**No single party ever knows the full secret key.**

## Quick Start

```bash
# Build
cargo build --release

# Keygen (all 3 parties run these)
cargo run -- keygen-round1 --threshold 2 --n-parties 3 --my-index 1
# Copy output, paste into bulletin board or share via terminal
# Then copy space-separated JSON from all parties:
cargo run -- keygen-round2 --my-index 1 --data '{"party_index":1,...} {"party_index":2,...} {"party_index":3,...}'
cargo run -- keygen-finalize --my-index 1 --data '<space-separated shares JSON>'

# Signing (2 parties collaborate)
cargo run -- sign-nonce --my-index 1 --session "msg1"
cargo run -- sign --my-index 1 --session "msg1" --message "Hello FROST!" --data '<nonces JSON>'
cargo run -- combine --message "Hello FROST!" --data '<shares JSON>'
```

**Tip:** The CLI accepts space-separated JSON objects, making it easy to aggregate outputs from multiple parties!

## Features

- ✅ **Real cryptography** - Uses schnorr_fun's FROST SimplePedPop implementation
- ✅ **Educational output** - Explains what's happening at each step
- ✅ **Space-separated JSON** - Simple copy-paste between CLI and web, or CLI-to-CLI
- ✅ **Web bulletin board** - Real-time Nostr coordination with room-based channels
- ✅ **Deterministic nonces** - Seeded by secret share + session ID for safety
- ✅ **BIP340 compatible** - X-only public keys for Bitcoin compatibility

## Learning Goals

Participants will understand:
1. How polynomial secret sharing works (Shamir SSS)
2. How FROST distributes key generation without a trusted dealer
3. Why nonces matter in threshold signatures
4. The relationship between cryptographic theory and production APIs

## Workshop Structure

**Setup** (5 min) - Form tables, build CLI
**Keygen** (25 min) - Generate distributed keys in 3 rounds
**Signing** (20 min) - Create threshold signatures
**Wrap-up** (5 min) - Discuss what you learned

See [`plan.md`](./plan.md) for full workshop flow.

## Architecture

- **CLI** - All cryptographic operations, verbose educational output, space-separated JSON I/O
- **Bulletin board** - HTML interface (`bulletin-board.html`) for coordinating JSON exchange
- **Nostr** - Real-time broadcast channel for table coordination (relays: damus.io, nos.lol, relay.nostr.band)

### Using the Bulletin Board

1. Open `bulletin-board.html` in a web browser
2. Set a room ID (e.g., "table-1") - everyone at your table uses the same room
3. Configure threshold and n_parties (must match across all participants)
4. Run CLI commands, paste JSON output into the board, click "Broadcast to Nostr"
5. Copy aggregated results (space-separated JSON) for next round

The bulletin board is **optional** - you can also copy-paste space-separated JSON directly between terminals!

## Safety Notes

⚠️ **This is for education only!** Do not use for production systems.

- Deterministic nonces require unique session IDs (never reuse!)
- No key backup/recovery mechanism
- Shares stored in `.frost_state/` directory

## Technical Details

**Keygen:** SimplePedPop (Pedersen commitments + proof-of-possession)
**Signing:** FROST with Lagrange coefficient adjustment for signer subsets
**Curve:** secp256k1 (Bitcoin's curve)
**Hashing:** SHA-256

## License

MIT
