# FROST Workshop Plan

## What We're Building

A learning-focused FROST threshold signature workshop for a Bitcoin conference. Participants experience distributed key generation and signing hands-on.

**Architecture:**

- **CLI** (✅ DONE) - Does all crypto, verbose educational output, uses schnorr_fun FROST API
- **HTML bulletin board** (✅ DONE) - Copy-paste interface with Nostr for coordination, space-separated JSON format
- **WASM Web CLI** (✅ DONE) - Full FROST implementation in browser, no installation required
- **Workshop guide** (TODO) - Teaching script with learning objectives

---

## Key Learnings from Implementation

### SimplePedPop Protocol (schnorr_fun)

The keygen flow uses these utility functions:

1. **Round 1**: `Contributor::gen_keygen_input()` → returns `(contributor, KeygenInput, SecretKeygenInput)`
2. **Round 2**: `Coordinator::add_input()` and `coordinator.finish()` → returns `AggKeygenInput`
3. **Finalize**: `simplepedpop::collect_secret_inputs()` + `simplepedpop::receive_secret_share()` → returns `PairedSecretShare`

**Critical**: Must use `receive_secret_share()` to properly validate and pair shares. Don't manually pair!

### Type Conversions

- SimplePedPop returns `SharedKey<Normal, Zero>` and `PairedSecretShare<Normal, Zero>`
- For BIP340 signing, convert with `.non_zero().into_xonly()` to get `EvenY` types
- Do this AFTER validation, save xonly versions for signing

### WASM Architecture

**Storage Abstraction Pattern:**

```rust
// Trait for storage operations
trait Storage {
    fn read(&self, key: &str) -> Result<Vec<u8>>;
    fn write(&self, key: &str, data: &[u8]) -> Result<()>;
}

// Implementations
FileStorage       // Uses std::fs for CLI
LocalStorageImpl  // Uses web_sys::Storage for WASM
```

**Function Structure:**

```rust
// Core logic - storage and I/O agnostic
pub fn round1_core(args..., storage: &dyn Storage) -> Result<String> {
    let mut out = String::new();
    out.push_str("output...");  // Build output string
    storage.write("state.json", data)?;  // Use injected storage
    Ok(out)  // Return output
}

// CLI wrapper
pub fn round1(args...) -> Result<()> {
    let storage = FileStorage::new(STATE_DIR)?;
    let output = round1_core(args..., &storage)?;
    print!("{}", output);  // Print to stdout
    Ok(())
}

// WASM wrapper
#[wasm_bindgen]
pub fn wasm_round1(args...) -> Result<String, JsValue> {
    let storage = LocalStorageImpl;
    round1_core(args..., &storage)  // Return string to JS
        .map_err(|e| JsValue::from_str(&format!("Error: {}", e)))
}
```

**Benefits:**

- Zero code duplication between CLI and WASM
- Core functions are testable in isolation
- Educational output identical in both environments
- Storage backend easily swappable

### JSON Interface

**Format:** Space-separated JSON objects (enables simple aggregation and optional web board usage)

Each phase outputs compact JSON that can be copy-pasted:

- Round 1: `{"party_index": 1, "keygen_input": "hex...", "type": "keygen_round1"}`
- Round 2: `{"party_index": 1, "shares": [{"to_index": 1, "share": "hex..."}], "type": "keygen_round2"}`
- Nonce: `{"party_index": 1, "session": "...", "nonce": "hex...", "type": "signing_nonce"}`
- Sign: `{"party_index": 1, "session": "...", "signature_share": "hex...", "type": "signing_share"}`

**CLI accepts space-separated input:** Multiple JSON objects separated by spaces, e.g.:

```
yushan keygen-round2 --my-index 1 --data '{"party_index":1,...} {"party_index":2,...} {"party_index":3,...}'
```

This makes the bulletin board **optional** - you can coordinate via terminal copy-paste alone!

---

## What's Left to Build

### 1. HTML Bulletin Board (✅ DONE)

**Location:** `bulletin-board.html`

**Features implemented:**

- Room-based Nostr coordination (custom room IDs via `#r` tag)
- Paste boxes for each phase with "Broadcast to Nostr" buttons
- Real-time display of who posted what with timestamps
- **Deduplication rule**: Earliest Nostr event wins (by `created_at`)
- "Copy All" buttons outputting space-separated JSON
- Global config (threshold, n_parties) with update button
- Connection status indicator

**Phases supported:**

1. Keygen Round 1 - commitments from each party
2. Keygen Round 2 - secret shares
3. Signing Nonce - nonces from threshold parties
4. Signing Shares - signature shares

**Usage:** Open `bulletin-board.html` in browser, set room ID, paste CLI output → Broadcast → Copy aggregated results

### 2. Workshop Guide (`GUIDE.md`)

**Structure:**

- **Phase 1: Whiteboard** (20 min) - Explain Shamir SSS, polynomials, commitments
- **Phase 2: Keygen** (30 min) - Walk through 3 rounds with CLI
- **Phase 3: Signing** (20 min) - Nonce → sign → combine
- Learning checkpoints after each phase
- Common issues & debugging tips

---

## Workshop Flow (Refined)

### Setup (5 min)

- Form tables of 3 people
- Open bulletin board: `http://192.168.1.X:8000`
- Create table, get table ID
- Everyone: `git clone && cd yushan && cargo build`

### Keygen (25 min)

**Round 1** (8 min):

```bash
yushan keygen-round1 --threshold 2 --n-parties 3 --my-index <1|2|3>
```

Copy JSON → paste into bulletin board → wait for all 3

**Round 2** (10 min):
Bulletin board shows "Copy all commitments" button → click → get JSON

```bash
yushan keygen-round2 --my-index <N> --data '<JSON>'
```

Paste shares into grid on bulletin board

**Finalize** (7 min):
Bulletin board aggregates shares for each party → "Copy shares for Party N"

```bash
yushan keygen-finalize --my-index <N> --data '<JSON>'
```

Everyone sees their secret share + shared public key (should match!)

### Signing (20 min)

**Nonce** (7 min):
Decide message + which 2 parties will sign

```bash
yushan generate-nonce --session "msg1"
```

Paste nonces into bulletin board

**Sign** (8 min):
Bulletin board shows "Copy nonces" → get JSON

```bash
yushan sign --my-index <N> --session "msg1" --message "Hello!" --data '<JSON>'
```

Paste signature shares

**Combine** (5 min):
Anyone can combine:

```bash
yushan combine --message "Hello!" --data '<shares JSON>'
```

✅ Valid FROST signature!

---

## Design Constraints

### Keep It Simple

- Single HTML file for bulletin board
- No server-side logic
- Nostr is just a message board (earliest event wins)
- Copy-paste forces participants to look at data

### Educational First

- CLI explains every step
- Map whiteboard theory to code
- Show actual schnorr_fun API calls
- Verbose output that teaches

### Conference Reality

- Must work with flaky WiFi
- Failure modes must be clear
- Practice run-through before event
- 3-4 people per table (not whole room)

---

## Success Criteria

Participants leave understanding:

1. How polynomial secret sharing works (Shamir SSS)
2. How FROST distributes key generation (no trusted dealer)
3. Why nonces matter in threshold signing
4. The relationship between theory and Rust API

**Most important: They had fun and built something real together!**

### Completed Enhancements (✅)

**Educational Output:**

- ✅ Enhanced explanations throughout all commands (polynomials, commitments, nonces, Lagrange coefficients)
- ✅ Added "🧠 What/Why" sections explaining the cryptographic concepts
- ✅ Educational questions added to each phase:
  - Round 1: Why verify Proofs-of-Possession?
  - Round 2: **Updated** - Nostr broadcasting security mistake (instead of generic encryption warning)
  - Nonce: Round optimization possibilities (pre-sharing nonces)
  - Signing: Signer selection implications
  - Combine: Challenge to sign Nostr/Bitcoin/Git
- ✅ Consistent emoji design (⚙️ computing, 🧠 learning, ❄️ success, ✉️ sending)
- ✅ Removed all green tick emojis

**Technical Improvements:**

- ✅ Using FROST coordinator API (`verify_and_combine_signature_shares`) for signature combination
- ✅ Clean hex output for display (raw bytes) vs bincode for storage
- ✅ Space-separated JSON format explained in CLI output
- ✅ Message embedded in signature share data (removed from combine command args)
- ✅ Renamed "Secret Shares" to "Keygen Shares" in Round 2 for clarity

**WASM Implementation (✅ COMPLETE):**

- ✅ All 6 CLI commands callable from browser (`/cli.html`)
- ✅ Storage abstraction (FileStorage for CLI, LocalStorage for WASM)
- ✅ Zero code duplication (core functions shared between CLI and WASM)
- ✅ Educational output preserved in browser
- ✅ No installation required - runs entirely in browser
- ✅ Compiles to ~15KB WASM

### Remaining TODOs:

**Workshop Structure:**

1. Introductions (me, Frostsnap, team)
2. FROST & Sovereignty
3. What we're going to be doing
4. Tools and begin

**Polish:**

- More handholding in HTML UI
- Frostsnap branding refinement
- Hosting setup
- Signature verifier (command line or online)
- References section
