# FROST Workshop Plan

## What We're Building

A learning-focused FROST threshold signature workshop for a Bitcoin conference. Participants experience distributed key generation and signing hands-on.

**Architecture:**

- **CLI** (✅ DONE) - Does all crypto, verbose educational output, uses schnorr_fun FROST API
- **HTML bulletin board** (✅ DONE) - Copy-paste interface with Nostr for coordination, space-separated JSON format
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

### JSON Interface

**Format:** Space-separated JSON objects (enables simple aggregation and optional web board usage)

Each phase outputs compact JSON that can be copy-pasted:

- Round 1: `{"party_index": 1, "keygen_input": "hex...", "type": "keygen_round1"}`
- Round 2: `{"party_index": 1, "shares": [{"to_index": 1, "share": "hex..."}], "type": "keygen_round2"}`
- Nonce: `{"party_index": 1, "session": "...", "nonce": "hex...", "type": "signing_nonce"}`
- Sign: `{"party_index": 1, "session": "...", "signature_share": "hex...", "type": "signing_share"}`

**CLI accepts space-separated input:** Multiple JSON objects separated by spaces, e.g.:
```
cargo run -- keygen-round2 --my-index 1 --data '{"party_index":1,...} {"party_index":2,...} {"party_index":3,...}'
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
- Everyone: `git clone && cd frosty-taipei && cargo build`

### Keygen (25 min)

**Round 1** (8 min):

```bash
cargo run -- keygen-round1 --threshold 2 --n-parties 3 --my-index <1|2|3>
```

Copy JSON → paste into bulletin board → wait for all 3

**Round 2** (10 min):
Bulletin board shows "Copy all commitments" button → click → get JSON

```bash
cargo run -- keygen-round2 --my-index <N> --data '<JSON>'
```

Paste shares into grid on bulletin board

**Finalize** (7 min):
Bulletin board aggregates shares for each party → "Copy shares for Party N"

```bash
cargo run -- keygen-finalize --my-index <N> --data '<JSON>'
```

Everyone sees their secret share + shared public key (should match!)

### Signing (20 min)

**Nonce** (7 min):
Decide message + which 2 parties will sign

```bash
cargo run -- sign-nonce --my-index <N> --session "msg1"
```

Paste nonces into bulletin board

**Sign** (8 min):
Bulletin board shows "Copy nonces" → get JSON

```bash
cargo run -- sign --my-index <N> --session "msg1" --message "Hello!" --data '<JSON>'
```

Paste signature shares

**Combine** (5 min):
Anyone can combine:

```bash
cargo run -- combine --message "Hello!" --data '<shares JSON>'
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

### Important TODOs:

Some structure for the session:

1. Introductions (me, Frostsnap, team)
2. FROST & Soveignty
3. What we're going to be doing
4. Tools and begin

- Things printed to the terminal for educational purposes should use serde debug strings. We could even consider whether it is appropriate to use serde everywhere instead of bincode.

- We should print things to the terminal more often, for example, during keygen we should print something like:

```
a_0: ..... (SUPER SECRET)
a_1: ..... (SECRET)

....

Commitments
a_0 \* G = ....

Proof-of-Possession (PoP) - This proves we know our contribution to the group secret, preventing rogue key / key cancellation attacks.

```

I like explanations like:

```

📝 Creating party sign session...
🎯 Computing Lagrange coefficient...
   λ2 allows your share to work with this specific signer subset

✍  Creating signature share...
   Using: sign_session.sign(&paired_share, nonce)
   This computes: s2 = k2 + λ2 * c * secret_share
```

But they're slightly too short and assuming, ok we calculated some lagrange coefficient, but why? Deeper explanations please!

```
✓ Generated NonceKeyPair:
   - Secret nonce (k1, k2) - kept private
   - Public nonce (R1, R2) - shared with others
```

E.g this one should also explain R1 = G \* k1..

- Perhaps to make this even more educational we should ask questions with varying difficulty along the way, maybe one for each command,

* "Why is it important that we produce and verifiy proofs-of-possession? or, "What kind of attacks do these proofs-of-possession prevent?
* "(keygen shares) We're skipping a very important security step here, do you know what it is (encrypting keygen shares to securely transmit them to the recipient)

* Nonce gen: "You may notice that we can generate as many nonces as we like at any time, independent of the message being signed. Rather than taking two rounds to sign (share nonces, then sign), what could we do to make FROST "Round Optimized"?
* Signing, to begin signing you've selected a quorum of nonces to sign under, what downstream implication does this have for the user? (Hint: how could this hinder a user of FROST in a way that's not applicable to script multisig?)
* Combine - Have a go at signing a nostr event, or, sign a bitcoin transaction?

- Use slightly less emojis, but keeping the powerful ones. No green ticks.

- We should use the secp256kfun frost-coordinator to combine the secret shares after signing, not manual as we are here.

- We should explain the "spaced json" data input format where appropriate, since it is non standard? Im finding it easy to work with on the CLI, but is there an easier more standard alternative?

Very final TODOs:

- more handholding in HTML
- Frostsnap branding
- Host
- A command line or online signature verifier
- Nice to have (wasm bindings)
- Nice to have: references
