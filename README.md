# BTC++ Taipei FROST Workshop

A hands-on threshold signature workshop using schnorr_fun's FROST with SimplePedPop distributed key generation.

**No single party ever knows the full secret key.**

## Quick Start

```bash
# Build and install
cargo install --path .

# Keygen (all 3 parties run these with varying indicies)
yushan keygen-round1 --threshold 2 --n-parties 3 --my-index 1
# Copy output, paste into bulletin board or share via terminal
# Then copy space-separated JSON objects from all parties:
yushan keygen-round2 --my-index 1 --data '{"party_index":1,...} {"party_index":2,...} {"party_index":3,...}'
yushan keygen-finalize --my-index 1 --data '<space-separated shares JSON>'

# Signing (2 parties collaborate)
yushan generate-nonce --session "msg1"
yushan sign --session "msg1" --message "Hello FROST!" --data '<nonces JSON>'
yushan combine --data '<shares JSON>'
```

The CLI accepts space-separated JSON objects, making it easy to aggregate outputs from multiple parties.

## Workshop Outline

1. Shamirs Secret Sharing -- whiteboard (~5 mins)
2. What does Distributed Key Generation provide in terms of sovereignty? (~5min)
3. DKG -- Create a 2-of-3 on the whiteboard. Ask three people to give two _nice_ coefficients each. Evaluate keygen shares, constitute into secret shares. (~15min)
4. Hands-on workshop using this repo!
5. Q&A (Frostsnap), closing

## Learning Goals

Participants will delve into:

1. How polynomial secret sharing works (Shamir SSS)
2. How FROST distributes key generation without a trusted dealer
3. How weak schemes can be attacked cryptographically
4. The application of advanced cryptographic theory

The bulletin board is **optional** - you can also copy-paste space-separated JSON directly between terminals!

⚠️ **This is for education only!** Do not use for production systems.
