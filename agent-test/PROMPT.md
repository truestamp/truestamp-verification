<!--
Copyright (c) 2026 Truestamp, Inc.
SPDX-License-Identifier: Apache-2.0
-->

This directory holds Truestamp proofs, each a file whose name ends in `.proof.json`. The
constructions text of a proof is its only documentation: the object in its `constructions`
member or, when that member is a URL, the file here whose name ends that URL. Nothing else
about Truestamp is available to you, and you have no network.

`keyring.json` is Truestamp's keyring. `replay.json` holds the chain and source responses:
it answers each read your verifier makes of a chain or a source, in place of the network. It
holds every read the text needs for these proofs, and may hold others, so a read it does not
hold is one the text does not need. Your verifier's environment is `test`, and its pinned
networks are Stellar `testnet` and Bitcoin `regtest`, for commitments and for entropy alike.

Write `verify.py`, which runs as `python3 verify.py <proof> <keyring> <replay>
[<constructions>]`, where `<constructions>` is the text's file for a proof whose
`constructions` is a URL. It may use Python 3 with `cryptography` and `rfc8785`, and it
reads nothing but its arguments. It prints these lines, each once, in any order, and
exits 0:

- `<pointer> <value>` for each member of the proof whose value a row of the text computes
  from other values of the proof: each hash the text defines, a record hash or a Bitcoin
  `transaction_hash` or `header_hash`, each value of `witness_hashes`, each Merkle root a
  walk computes, each key id, each `tree_size`, each Bitcoin `header_merkle_root` and
  `header_time`, and the members a key event fixes; and for the one member the text fixes as
  a constant, the `height` of a genesis block record. `<pointer>` is the member's JSON
  Pointer (RFC 6901) into the file, such as `/proof/block/block_hash`, and `<value>` is the
  value your verifier computed for that member, in the proof's form for it: lowercase hex, a
  decimal integer with no fraction or exponent, or an RFC 3339 UTC time as the proof writes
  one. A value has its line even when a check of it fails, and a Merkle walk that fails
  gives `none`. A member that several walks compute, as each beacon observation's walk
  computes its block's `merkle_root`, has a line for each distinct value computed, `none`
  among them. There is no such line for a value read from a chain or a source, for a
  `handover_signature`, or for a member the text only bounds or constrains, such as the
  `merkle_root` of a block with no leaves, which no walk computes.
- Of the members a key event fixes: an event that introduces a key has a line at its own
  `key_id` and one at the block record's `signing_key_id`; a prerotation has its line at the
  block record's `signing_key_id`; and a rotation's handover has lines at the event's
  `previous_key_id`, `height` and `previous_block_hash`.
- `digest <hex>`: the 32 bytes the proof's signature signs, in lowercase hex.
- `<pointer> valid` or `<pointer> invalid` for each Ed25519 signature: `/signature/value`
  for the proof's own, and the pointer of each `handover_signature`.
- `keyring match` or `keyring no-match`: whether the proof's `signature.public_key` is a
  key in the keyring.
- `environment <value>`: the proof's `environment` member, or `prod` when it has none.
- `submitted_after <instant>` and `submitted_before <instant>`: the two edges of the
  submission window, each an RFC 3339 UTC time, or `none` for an edge the proof does not
  establish. When any check fails, both are `none`.

Compute every value, and never print one you did not compute. `verify.py` will also run on
flawed proofs of the same shape, each with a replay file of the same form.
