<!--
Copyright (c) 2026 Truestamp, Inc.
SPDX-License-Identifier: Apache-2.0
-->

# Truestamp proof specification

**Status:** draft, and not yet normative. Every section is written except 7.4, which is an
outline. The whole text is under review until it is fixed.
*Proposed* marks a change to the original design that has been accepted but whose bytes are
not yet frozen, and "name *Proposed*" marks a name that is still open.

This document defines a Truestamp proof and how to verify it. Once fixed, it is the only
normative document in this repository. The files under `spec/` and `vectors/` are its
data, and `MANIFEST.sha256` holds their digests; a citation of this document names the
commit and the manifest digest.

## 1. Introduction

A Truestamp proof is one JSON document, signed by Truestamp, that ties a subject to
Truestamp's chain of blocks and to commitments on public blockchains. The subject is an
item (claims a user submitted), an entropy observation, a block, or a beacon value.

A proof establishes that the subject's data existed and is unchanged, and places its
submission in a submission window: after the submitted-after edge and before the
submitted-before edge. A verifier draws both edges from reads of public chains and entropy
sources that it makes during verification (section 11), never from times the proof
carries. A proof does not establish when the data was created, who wrote it, or that any
claim in it is true.

This document is for anyone, human or agent, who writes or audits a verifier, and
Truestamp's own verifier follows it too. Where the constructions text a proof carries
(section 7), the Truestamp whitepaper or any implementation differs from this document,
this document governs.

## 2. Conventions

### 2.1 Requirements language

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT",
"RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be
interpreted as described in BCP 14 (RFC 2119 and RFC 8174) when, and only when, they
appear in all capitals, as shown here.

### 2.2 Notation

- `||` concatenates byte strings, and `0xNN` is the one byte with that value.
- SHA-256 is that of FIPS 180-4. SHA-256d(x) is SHA-256(SHA-256(x)), and rev(x) is x with
  its bytes in reverse order.
- JCS(x) is the UTF-8 encoding of the value x under the JSON Canonicalization Scheme of
  RFC 8785.
- H(p, R) = SHA-256(p || JCS(R)) is the record hash of section 4.1.
- A path such as `/block/record` is a JSON Pointer (RFC 6901) into the proof object, the
  envelope's `proof` member.
- Sizes are in octets. Hex is lowercase unless a pattern class says otherwise.
- In member tables, R means REQUIRED, O means OPTIONAL, and F means the member MUST be
  absent.
- CHECKED, PREIMAGE and the other capitalized treatment names are the value classes of
  section 3.7.

### 2.3 Objects and members

- Every object is closed: it MUST have exactly the members this document lists for it,
  within their presence rules. The only open region is `subject.claims`.
- An OPTIONAL member with no value is absent, never `null`, and presence is key presence.
- Members are listed in JCS order.

### 2.4 Pattern classes

Every value outside `subject.claims` MUST match the class or literal this document gives
for its member. Each pattern below is written bare and MUST match the whole string, as
`\A...\z` does, because PCRE's `$` matches before a final newline and Go's does not.

| Class | Pattern or rule | Used for |
|---|---|---|
| HEX64 | `[0-9a-f]{64}` | every hash, root and path node; `transaction_hash`, `header_hash`, `header_merkle_root`, `prerotation_commitment` |
| KID | `[0-9a-f]{8}` | `signing_key_id`, `key_id`, `previous_key_id`, `active_key_id`, `revoked_key_id` |
| MERKLE_PROOF | the closed object of section 5.2 | every `inclusion_proof` |
| HEXBYTES | `(?:[0-9a-f]{2})+`, capped | `raw_transaction` (at most 1,000 octets), `txoutproof` (at most 1,024) |
| B64U32 | `[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]` | `signature.public_key`; key-event `public_key`, `previous_public_key` |
| B64U64 | `[A-Za-z0-9_-]{85}[AQgw]` | `signature.value`, `handover_signature` |
| TIME | `[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z`, and format(parse(s)) = s | `header_time`, Stellar `closed_at` |
| NISTTIME | TIME with a 3-digit fraction of a second before `Z` | NIST `timeStamp` |
| NISTHEX | `[0-9A-F]{128}` | NIST `outputValue`, as NIST publishes it |
| ULID | `[0-7][0-9A-HJKMNP-TV-Z]{25}` | item `id` |
| UUID7 | `[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}` | block and observation `id` |
| INT | an integer from 0 to 9007199254740991 (MAX_INTEGER) | every number outside `subject.claims` |
| ASCII128, ASCII16 | 1 to 128 (or 16) printable ASCII characters, with no `"` or `\` | `reason`, NIST `version` |
| NETWORK | Stellar `public` or `testnet`; Bitcoin `mainnet`, `testnet` or `regtest` | every `network` |
| ENV | `dev`, `staging` or `test` | `environment` |

The base64url classes are unpadded (RFC 4648 section 5), and the class of the last
character forces the unused bits to zero, so a match is exactly a canonical encoding.
Stock decoders are not canonical: Elixir's `Base.url_decode64` ignores the unused bits,
and Go's `RawURLEncoding.Strict()` skips CR and LF. So an implementation MUST match a
value against its class before it decodes it. The round trip of TIME and NISTTIME rejects
`24:00:00`, February 30 and a seconds value of 60.

### 2.5 Normative references

A verifier depends on these standards, and on nothing of Truestamp's beyond this document
and its data:

| Standard | Used for |
|---|---|
| RFC 8259, JSON | the document, and every file under `spec/` and `vectors/` |
| RFC 8785, the JSON Canonicalization Scheme (JCS) | every record hash, `proof_hash` among them |
| FIPS 180-4, SHA-256 | every hash, and SHA-256d for Bitcoin |
| RFC 8032, Ed25519 (the pure variant) | the proof's signature and every handover signature, checked as section 6.2 says |
| RFC 4648 section 5, base64url without padding | keys and signatures |
| RFC 9162 section 2.1, the Merkle Tree Hash and its inclusion proofs | block and epoch trees (section 5) |
| RFC 6901, JSON Pointer | pointers into the proof, in this document, in reports and in `spec/value-classes.json` |
| RFC 3339, date and time in UTC | TIME and NISTTIME |
| JSON Schema, draft 2020-12 | `spec/schema.json` (section 9) |
| BCP 14 (RFC 2119, RFC 8174) | requirements language (section 2.1) |
| BIP 37 and BIP 144 | the Bitcoin merkleblock, and the transaction serialized without witness data |
| the Bitcoin and Stellar protocols, and NIST's Randomness Beacon | commitments, chain reads and entropy sources |

Any conforming implementation of each standard will do; none of them requires a particular
library. Known answers for JCS, Ed25519 and base64url are among the conformance vectors
(section 13), and those for the Merkle tree live with Truestamp's Merkle library (section
5.1).

## 3. The proof document

### 3.1 The envelope

- The document is an object with exactly two members: `proof`, an object holding all
  signed content, and `signature`.
- `signature` is closed and has exactly three members, all strings:
  - `alg`: the literal `truestamp-ed25519-sha256-jcs`, which names the signing rule of
    section 6.1. A verifier MUST compare it with that literal and MUST NOT select behavior
    by it.
  - `public_key` (K): the 32-octet Ed25519 public key, as B64U32.
  - `value` (V): the 64-octet Ed25519 signature, as B64U64.

  There is no second signature, key id, `proof_hash` or context member.
- **Served form.** Truestamp serves JCS(envelope) as UTF-8 with no trailing newline, at
  most 65,536 octets (MAX_DOCUMENT_OCTETS), with the media type
  `application/vnd.truestamp.proof+json` and the file extension `.proof.json`. A verifier
  MUST accept any formatting of the same JSON value that the parsing rules of section 10.1
  allow.
- **Identity.** A proof is identified by its `proof_hash`, SHA-256(0x50 || JCS(proof)), never by
  the bytes of a file or by its signature string.
- **Sameness.** Files that differ only in formatting, within the parsing rules of
  section 10.1, verify alike, and two proofs are the same exactly when their `proof_hash`
  values are equal. Two files that verify with the same
  `signature.value` carry the same proof value and key.

### 3.2 Members of `proof`

| Member | Presence | Meaning |
|---|---|---|
| `block` | R | BLOCK_NODE: the block that includes the subject; for `block` and `beacon`, the subject itself |
| `commitments` | R | COMMITMENTS for the recomputed `block.block_hash`; only these feed the submitted-before edge |
| `constructions` | O | the text (an object), its reference URL (a string), or absent (section 7) |
| `environment` | O | ENV; present exactly when a non-production environment signed the proof (section 6.4) |
| `format` | R | `"truestamp-proof"` |
| `observations` | `beacon` R, else F | `{"entropy_X": OBSERVATION_SUBJECT}`, with 0 to 3 members |
| `signing_key_event` | O | `{block, commitments}`: the committed block whose key event introduced `signature.public_key`; provenance only; present exactly when that block has a final commitment |
| `subject` | `item` and entropy types R; `block` and `beacon` F | ITEM_SUBJECT or OBSERVATION_SUBJECT |
| `type` | R | `item`, `entropy_nist`, `entropy_stellar`, `entropy_bitcoin`, `block` or `beacon` |
| `version` | R | `1` |
| `witnesses` | `item` R, else F | WITNESSES |

A proof carries none of these: a `generated_at` time, an issuer, a proof-level key id,
its own `proof_hash`, a download variant, a close time for any commitment's ledger or block,
the intermediate hashes a walk computes, or the chain of blocks between `/witnesses/block`
and `/block`.

### 3.3 Block node, key events and genesis

A BLOCK_NODE appears at `/block`, `/witnesses/block` and `/signing_key_event/block`:

```
{
  "block_hash": HEX64,             // CHECKED = H(0x31, record); for type beacon, the beacon value
  "record": {
    "height": INT,                 // 0 at genesis, then one more per block
    "id": UUID7,
    "leaf_count": INT,             // the number of leaves under merkle_root; 0 exactly with the empty root (section 5.4)
    "merkle_root": HEX64,          // at /block, the inclusion target
    "metadata": {} | {"key_event": KEY_EVENT} | {"genesis": GENESIS, "key_event": KEY_EVENT},
    "previous_block_hash": HEX64,  // at genesis, CHECKED = H(0x30, metadata.genesis)
    "signing_key_id": KID          // preimage input only; never selects or validates the signer
  }
}
```

A KEY_EVENT is one of these, by its `type`:

| `type` | Members | Checked wherever it appears |
|---|---|---|
| `genesis` | `key_id`, `prerotation_commitment` (O), `public_key`, `sequence` (0), `type` | `key_id` = the key id of `public_key` = `record.signing_key_id` |
| `rotation` | `handover_signature`, `height`, `key_id`, `prerotation_commitment` (O), `previous_block_hash`, `previous_key_id`, `previous_public_key`, `public_key`, `reason` (ASCII128), `sequence` (at least 1), `type` | as `genesis`, plus `previous_key_id` = the key id of `previous_public_key`, `height` and `previous_block_hash` = those of the block record that carries the event, and `handover_signature` verifies under `previous_public_key` |
| `emergency_rotation` | as `rotation`, with `handover_signature` O | as `rotation`, the signature when present |
| `prerotation` | `active_key_id`, `prerotation_commitment`, `type` | `record.signing_key_id` = `active_key_id`; introduces no key |
| `revocation` | `revoked_key_id`, `type` | introduces no key |

- A key's **key id** is the hex of the first 4 bytes of SHA-256(0x60 || its 32 bytes).
  `prerotation_commitment` is the hex of SHA-256(0x61 || the next key's 32 bytes).
- The **handover signature** is Ed25519 by `previous_public_key` over the 32 bytes of
  H(0x62, the event without `handover_signature`), so the outgoing key endorses every other
  member. Those members include the event's `height` and `previous_block_hash`, which equal the
  carrying block record's, so a handover is valid only at the one place in the chain it was
  signed for.
- The key event at `/signing_key_event/block` MUST be a `genesis`, `rotation` or
  `emergency_rotation`.
- Which key events Truestamp's key chain accepts, and in what order, is Truestamp's own
  policy and outside this document. A verifier MUST check each key event it meets as the
  table says.
- **GENESIS** is `{"bitcoin": {"header_hash": HEX64, "height": INT, "network": NETWORK}}`,
  present only on the genesis block. It names a Bitcoin block that was at least 10 deep on
  the best chain of Truestamp's configured source when the genesis block was made.
- `metadata.genesis` MUST be present exactly when `metadata.key_event` is a `genesis`
  event.

### 3.4 Commitments

COMMITMENTS, at `/commitments` and `/signing_key_event/commitments`, is an object keyed by
chain, with one or two members. Every member of each entry is R. Each entry carries the
epoch whose hash it wrote to its chain, as an EPOCH_NODE, and the inclusion proof of the
block beside these commitments in that epoch's tree.

An EPOCH_NODE mirrors a BLOCK_NODE: a record and its hash.

```
{
  "epoch_hash": HEX64,             // CHECKED = H(0x40, record); the value written to the chain
  "record": {
    "leaf_count": INT,             // the number of leaves under merkle_root (section 5.4)
    "merkle_root": HEX64           // CHECKED = the walk from the block's RECOMPUTED block_hash
  }
}
```

```
"bitcoin": {                        // present only once final: the tip at height + 10 when captured
  "epoch": EPOCH_NODE,              // epoch.epoch_hash is the value in the OP_RETURN output (section 5.4)
  "header_hash": HEX64,             // CHECKED = rev(SHA-256d(first 80 octets of txoutproof))
  "header_merkle_root": HEX64,      // CHECKED = rev(header Merkle root field)
  "header_time": TIME,              // CHECKED = header nTime; display only, never an edge
  "height": INT,                    // chain pointer
  "inclusion_proof": MERKLE_PROOF,  // Walked from the RECOMPUTED block_hash of the block beside these commitments to epoch.record.merkle_root
  "network": NETWORK,
  "raw_transaction": HEXBYTES,      // non-witness serialization, at least one input
  "transaction_hash": HEX64,        // CHECKED = rev(SHA-256d(raw_transaction)); also a chain pointer
  "txoutproof": HEXBYTES            // BIP 37 merkleblock as bitcoind emits it
},
"stellar": {
  "epoch": EPOCH_NODE,              // epoch.epoch_hash equals the transaction's hash memo
  "inclusion_proof": MERKLE_PROOF,  // Walked from the RECOMPUTED block_hash to epoch.record.merkle_root
  "ledger": INT,                    // chain pointer
  "network": "public" | "testnet",
  "transaction_hash": HEX64         // chain pointer
}
```

### 3.5 Entropy objects

An ENTROPY_OBJECT, at `/subject/entropy`, `/witnesses/entropy_X` and
`/observations/entropy_X/entropy`, is exactly the preimage of its `entropy_hash`,
H(0x20, object):

| Source | Object |
|---|---|
| NIST | `{"payload": {"pulse": {"chainIndex": INT, "outputValue": NISTHEX, "pulseIndex": INT, "timeStamp": NISTTIME, "version": ASCII16}}, "source": "nist"}` |
| Stellar | `{"network": NETWORK, "payload": {"closed_at": TIME, "hash": HEX64, "sequence": INT}, "source": "stellar"}` |
| Bitcoin | `{"network": NETWORK, "payload": {"hash": HEX64, "height": INT, "time": INT}, "source": "bitcoin"}` |

### 3.6 Layouts by type

The common members are `block`, `commitments`, `constructions`, `environment`, `format`,
`signing_key_event`, `type` and `version`.

```
item: the common members, plus
  "subject": {                          // ITEM_SUBJECT
    "claims": {...},                    // OPEN; SUBMITTED, never checked as true
    "inclusion_proof": MERKLE_PROOF,    // Walked from the RECOMPUTED item_hash to /block/record/merkle_root
    "item_hash": HEX64,                 // CHECKED = H(0x11, record)
    "record": {"claims_hash": HEX64,    // CHECKED = H(0x10, claims)
               "id": ULID,
               "witness_hashes": {"block": HEX64, "entropy_bitcoin": HEX64, "entropy_nist": HEX64, "entropy_stellar": HEX64}}
  },                                    // witness_hashes: block R; each entropy_X present iff that source had a current observation
  "witnesses": {"block": BLOCK_NODE, "entropy_X": ENTROPY_OBJECT, ...}   // WITNESSES: exactly the names of witness_hashes

entropy_nist | entropy_stellar | entropy_bitcoin: the common members, plus
  "subject": {"entropy": ENTROPY_OBJECT,          // OBSERVATION_SUBJECT; its source matches the type
              "inclusion_proof": MERKLE_PROOF,    // Walked from the RECOMPUTED observation_hash
              "observation_hash": HEX64,          // CHECKED = H(0x21, record)
              "record": {"entropy_hash": HEX64, "id": UUID7}}   // entropy_hash CHECKED = H(0x20, entropy)

block:  the common members only; the subject is block.record, and only the submitted-before edge applies.

beacon: the common members, plus "observations": {"entropy_X": OBSERVATION_SUBJECT, ...}: for each source
        with a leaf in the block, the leaf with the latest source time (ties: the smallest observation_hash).
        An empty object is allowed and leaves the submitted-after edge absent.
```

A block with a single leaf has the proof `{"leaf_index": 0, "path": [], "tree_size": 1}` for
it.

Generation is deterministic: for one block, evidence set, key and constructions mode, the
members `block`, `commitments` and `signing_key_event` are byte-identical across proof
types.

### 3.7 Value classes

A verifier MUST treat each value as its class says.

| Class | Members | Treatment |
|---|---|---|
| PINNED | `format`, `version`, `type`, `environment`, `signature.alg`, `constructions` | compared with pinned values before anything uses them |
| CHECKED | `claims_hash`, `item_hash`, `entropy_hash`, `observation_hash`, every `block_hash`; the genesis `height` and `previous_block_hash`; `witness_hashes` entries; `/block/record/merkle_root` where the `inclusion_proof` of the subject or of an observation walks to it; every `epoch_hash` and every epoch's `record.merkle_root`; every `inclusion_proof` `tree_size` (section 5.4); Bitcoin `transaction_hash`, `header_hash`, `header_merkle_root`, `header_time`; `key_id` where an event introduces a key, and `signing_key_id` where an event introduces a key or is a prerotation; `previous_key_id`, `handover_signature`; a rotation's `height` and `previous_block_hash`, against the block record that carries it | recomputed and compared |
| PATH INPUT | every MERKLE_PROOF `path` node and `leaf_index` | bound by the walk |
| PREIMAGE | every block record's `leaf_count`, and every epoch's `record.leaf_count`; `/block/record/merkle_root` in a `block` proof and in a `beacon` proof with no observations, and the `merkle_root` at `/witnesses/block` and `/signing_key_event/block` (the empty-root rule of section 5.4); the key-event `type` and `public_key`, and a prerotation's `active_key_id`; `raw_transaction`, `txoutproof`; every entropy `source`, and the payload values SOURCES compares (NIST `outputValue`, `timeStamp`; Stellar `hash`, `closed_at`; Bitcoin entropy `height`, `time`) | input to a CHECKED hash or a named check; a payload value is compared with its source only after a read |
| CHAIN POINTER | Stellar `transaction_hash`, `ledger`; Bitcoin commitment `height`; every `network`; NIST `chainIndex`, `pulseIndex`; Stellar `sequence`; Bitcoin entropy `hash`; `genesis.bitcoin` | may cause an offline rejection (POLICY, LINK_CHAIN_ORDER), but supports a pass or an edge only after a read made during verification |
| BLOCK HEIGHT | every other `record.height` | used only by LINK_HEAD and by a rotation's `height` check |
| SUBMITTED | `subject.claims` | bound by `claims_hash`; shown only as the submitter's statement, with bidirectional and zero-width characters escaped |
| RECORDED | ids and their times; the other `previous_block_hash` and `signing_key_id` values; `prerotation_commitment`, `previous_public_key` (only an input to the handover check), `sequence`, `reason`, `revoked_key_id`; NIST `version`; which observation a beacon carries | never a verdict input except where a row above uses it; shown under a provenance heading chosen by attribution |

No value is opaque, and no record contains its own hash. SOURCES and POLICY are steps of
section 10.2, and LINK_CHAIN_ORDER and LINK_HEAD are links of section 10.3.

### 3.8 Size

Measured on JCS(envelope) with the draft text of section 7.3.

**Recipe.** Build each layout with every hash `a` x 64, key ids `a` x 8, K `A` x 43, V and
`handover_signature` `A` x 86, `outputValue` `A` x 128, ids of 26 or 36 characters, TIME
values of 20 characters and NIST `timeStamp` of 24. Serialize the envelope with sorted
keys and no whitespace. The envelope adds 217 octets to |JCS(proof)|.

- **Typical:** subject inclusion proofs of 3 nodes (`leaf_index` 5, `tree_size` 8);
  Stellar and Bitcoin commitment inclusion proofs of 4 and 6 nodes (`leaf_index` 9 and 33,
  `tree_size` 16 and 64); `leaf_count` 8 in every block record but the genesis block's,
  which is 0 under the empty root (section 5.4), and in every epoch record the `tree_size`
  of its entry's proof; a 137-octet raw transaction and a 506-octet
  txoutproof; 155-octet claims; all three witnesses (and observations); both chains at the
  top level; `metadata` `{}`; at `/signing_key_event`, the genesis block (`height` 0, with
  a genesis key event that carries `prerotation_commitment`) and Stellar only; every other
  height 525,600; Stellar `ledger` and `sequence` of 8 digits; NIST `chainIndex` 1 and
  `pulseIndex` of 7 digits; a Bitcoin entropy `time` of 10 digits; `public` and `mainnet`;
  NIST `version` `2.0`; production.
- **Worst:** 20,480-octet claims; paths of 32 nodes with `leaf_index` 2^32 - 1 and
  `tree_size` 2^32; both chains at both positions, with 1,000-octet raw transactions and
  1,024-octet txoutproofs; `emergency_rotation` events with every optional member and a
  128-character reason at all three block positions; every `leaf_count` 2^32 and every
  other integer 16 digits; a 16-character NIST `version`; `testnet` on both chains. This is
  a ceiling over what the schema admits, not a proof Truestamp makes: a key-event block has
  no leaves (section 5.4), so it is never the `/block` of an item or observation proof.

| Proof | Typical, full | Typical, reference | Typical, none | Worst, full |
|---|---|---|---|---|
| item | 15,028 | 7,292 | 7,152 | 54,408 |
| entropy_nist | 13,758 | 6,022 | 5,882 | 32,067 |
| entropy_stellar | 13,666 | 5,930 | 5,790 | 31,947 |
| entropy_bitcoin | 13,646 | 5,910 | 5,770 | 31,934 |
| block | 12,971 | 5,235 | 5,095 | 29,282 |
| beacon | 15,140 | 7,404 | 7,264 | 37,396 |

For items, the served size is at most 33,928 + |JCS(claims)| octets in full mode (26,192 by
reference, 26,052 with none), plus at most 24 octets for `"environment":"staging",`. The
worst staging item is 54,432 octets, under MAX_DOCUMENT_OCTETS, so every committed subject
has a proof that fits.

## 4. The byte-prefix registry

The table of section 4.3 is canonical here, and is also published as `spec/prefixes.json`.
Truestamp's implementations (its server, its CLI and the reference verifiers here) hold it
as compiled constants, each with a test that they equal that file.
The constructions text names bytes only as the table assigns them. A proof never carries a
prefix as data, and a verifier MUST NOT take a prefix from a document.

### 4.1 The rule

```
H(p, R) = SHA-256(p || JCS(R))
```

- `p` is the one byte the table assigns to R's kind. One byte names one construction.
- `R` is a JSON object within the value profile of section 10.1, hashed exactly as carried
  or stored, and never containing its own hash or signature. JCS is injective over that
  profile, so no length framing is needed.
- **Signing.** Three kinds are signed, each with Ed25519 over the 32 bytes of H(p, R): a
  block record, by the key the chain assigns it (a rotation block by the key it introduces);
  a handover, by the outgoing key; and the proof, by the active key. No other record is
  signed. The signer takes a kind and a record and computes H itself; it refuses unsigned
  kinds and never signs bytes a caller hands it. So a signature for one kind never verifies
  for another.

**Outside the rule.**

- **Merkle leaf 0x00 and node 0x01:** SHA-256(0x00 || v) and SHA-256(0x01 || l || r), over
  the 32 bytes each hex value spells. These are the hash primitives of RFC 9162
  section 2.1.1, used as section 5 of this document describes, and every leaf value is
  itself a record hash. The root of the empty tree, SHA-256 of zero
  bytes, has a 0-byte preimage, so it cannot collide with a 33-byte leaf or a 65-byte node
  preimage.
- **Key id 0x60 and prerotation commitment 0x61:** SHA-256 over the 32 raw key bytes, so
  neither depends on how the key is written. The key id is cut to 4 bytes and is only an
  index.
- **Not in the registry:** hashes an outside protocol fixes (Bitcoin's SHA-256d, Stellar
  transaction hashes, the SHA-512 inside Ed25519), and content digests (the constructions
  address, a keyring file, a served proof file), which are never record hashes or leaves
  and are never signed alone.
- **Nothing is reserved.** Every signed message is a prefixed record hash, so `0x7B` is an
  ordinary free byte. Environments are separated by the signed marker and by their own
  keys, not by prefix.

### 4.2 Layout

- The high nibble is the family. The families follow the order in which Truestamp builds
  the values, from the leaves up: items and entropy, then blocks, epochs and proofs. Keys,
  which stand beside that path, come last. Within a family, a value comes before the record
  that contains it (`claims_hash` before `item_hash`).
- 0x00 and 0x01 are where RFC 9162 puts them. The Merkle step runs at both tree levels, so
  it takes no single place in the order.
- A byte never moves, so a new kind takes its family's lowest free low nibble, and a new
  family takes the lowest free high nibble (`0x7_` next).
- From genesis on, a byte MUST NOT be pointed at a different construction.

### 4.3 The table

| Prefix | Family | Construction | Hashed after the prefix | Signed |
|---|---|---|---|---|
| `0x00` | Merkle | leaf | the 32 bytes of the leaf value | never |
| `0x01` | Merkle | node | the 32 bytes of the left child, then of the right | never |
| `0x10` | Items | `claims_hash` | JCS(claims) | never |
| `0x11` | Items | `item_hash` | JCS(item record) | never |
| `0x20` | Entropy | `entropy_hash` | JCS(entropy object) | never |
| `0x21` | Entropy | `observation_hash` | JCS(observation record) | never |
| `0x30` | Blocks | genesis `previous_block_hash` | JCS(genesis object) | never |
| `0x31` | Blocks | `block_hash` | JCS(block record) | yes, by the key the chain assigns |
| `0x40` | Epochs | `epoch_hash` | JCS(epoch record) | never |
| `0x50` | Proofs | `proof_hash` | JCS(proof) | yes, by the active key |
| `0x60` | Keys | `key_id` | the 32 key bytes; the hash cut to 4 bytes | never |
| `0x61` | Keys | `prerotation_commitment` | the 32 bytes of the next key | never |
| `0x62` | Keys | handover | JCS(rotation event without `handover_signature`) | yes, by the outgoing key |

Every other byte is unassigned. The epoch record that 0x40 hashes is carried in every
commitment entry (section 3.4).

## 5. Merkle trees and inclusion proofs

### 5.1 The tree

Truestamp's Merkle trees are those of RFC 9162 section 2.1: the Merkle Tree Hash of RFC
9162 section 2.1.1 over a list of leaf values, with the leaf and node hashes given in
section 4.1 of this document, and no padding. Each leaf value is a 32-byte record hash. A
block's tree holds the `item_hash` and `observation_hash` of everything the block
includes, and an epoch's tree holds the `block_hash` of each block it covers. Truestamp
never commits a tree of more than 2^32 leaves, so every leaf's path fits MAX_PATH_STEPS.

Truestamp orders each tree's leaves by a key, byte-wise, as the library
[truestamp-merkle-elixir](https://github.com/truestamp/truestamp-merkle-elixir) does. A
verifier never needs the keys, because an inclusion proof carries the leaf's position. The
library's `vectors/merkle.json` holds the tree's known answers, and this document does not
copy them.

### 5.2 Inclusion proofs

A MERKLE_PROOF is a closed object:

```
{"leaf_index": INT, "path": [HEX64, ...], "tree_size": INT}
```

- `leaf_index` is the leaf's position, counted from 0, and `tree_size` is the number of
  leaves.
- `path` is RFC 9162's inclusion path: the sibling hashes from the leaf up to the root,
  at most MAX_PATH_STEPS (32) of them.
- Every proof of a leaf's place in the tree above it is an `inclusion_proof`. A subject's
  walks from its recomputed `item_hash` or `observation_hash` to
  `/block/record/merkle_root`. A commitment entry's walks from the recomputed `block_hash`
  of the block beside the commitments to the entry's `epoch.record.merkle_root`.

### 5.3 The walk

merkle_path(start, proof) is the verification of RFC 9162 section 2.1.3.2. Each hash is the
32 bytes its hex spells, and `>> 1` halves an integer, rounding down.

1. If `leaf_index` is not below `tree_size`, or `path` has more than MAX_PATH_STEPS nodes,
   fail.
2. Set fn = `leaf_index`, sn = `tree_size` - 1 and r = SHA-256(0x00 || start).
3. For each node p of `path`, in order:
   1. If sn = 0, fail.
   2. If fn is odd or fn = sn, set r = SHA-256(0x01 || p || r); then, while fn is even
      and not 0, set fn = fn >> 1 and sn = sn >> 1.
      Otherwise, set r = SHA-256(0x01 || r || p).
   3. Set fn = fn >> 1 and sn = sn >> 1.
4. If sn is not 0, fail. The result is r.

A walk that fails gives no root. A verifier MUST start every walk from a value it has
recomputed, never from a carried one.

The walk checks that the path's length fits `leaf_index` and `tree_size`, but not that
`tree_size` is the tree's true size. The same path can reach the same root under other
sizes, and the index can move with the size: in a tree of three leaves, the last leaf's
path also verifies as index 1 of two. So the size is committed and checked separately
(section 5.4).

### 5.4 The committed leaf count

Every tree whose root Truestamp commits also commits its leaf count, as RFC 9162's signed
tree head signs the tree size with the root. Each such tree has a record holding its
`merkle_root` and `leaf_count`, and the record's hash is committed in turn:

| Tree | Its leaves | Record | Record hash | Where the record hash goes |
|---|---|---|---|---|
| block | `item_hash`, `observation_hash` | the block record | `block_hash` = H(0x31, record) | a leaf of an epoch tree |
| epoch | `block_hash` | the epoch record `{leaf_count, merkle_root}` | `epoch_hash` = H(0x40, record) | Stellar and Bitcoin |

At both levels, for each `inclusion_proof` into a tree, a verifier MUST check that the walk
from the recomputed leaf reaches the record's `merkle_root` and that the proof's
`tree_size` equals the record's `leaf_count`.

In every block record, `leaf_count` MUST be 0 exactly when `merkle_root` is the root of the
empty tree, SHA-256 of zero bytes
(`e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`). Genesis and key-event
blocks include nothing, so their trees are empty. The rule holds at every block position,
including a block whose tree no inclusion proof walks into, and `spec/schema.json`
enforces it.

For each commitment entry, a verifier MUST also compute H(0x40, `epoch.record`) and compare
it with `epoch.epoch_hash`. It MUST compare the computed hash with the chain's copy wherever
it holds that copy: always for Bitcoin, and for Stellar when it reads the transaction's hash
memo (section 10.4). In Bitcoin the copy is in the carried `raw_transaction`: exactly one of
its output scripts MUST begin with 0x6a, that script MUST be exactly 0x6a 0x20 followed by
32 bytes, and those 32 bytes are the copy.

An epoch record whose `leaf_count` is not the committed count therefore fails at the
comparison with `epoch_hash`, or at the comparison with the chain's copy once the verifier
holds it. Until its memo has been read, a Stellar entry supports no pass (section 3.7).

## 6. Signing

### 6.1 The rule

Truestamp signs each proof with its active key (section 4.1):

```
M          = JCS(proof)                    proof is the envelope's proof member
proof_hash = SHA-256(0x50 || M)            H(0x50, proof); 32 octets, computed and never carried
S          = Ed25519-Sign(sk, proof_hash)  RFC 8032 section 5.1.6, pure; not Ed25519ph or Ed25519ctx
K, V       = the public key (32 octets) and S (64 octets), as B64U32 and B64U64
```

- The message Ed25519 signs is the 32 octets of `proof_hash`: never M, and never its hex.
- The signature covers every member of `proof`, `constructions` and `environment` among
  them, and nothing outside it. The `signature` object needs no signature of its own:
  `alg` is PINNED (section 3.7), K has one spelling (section 2.4), and Ed25519 hashes the
  public key into every signature, so under the checks of section 6.2 a signature made
  with one key does not verify under another.
- A verifier computes `proof_hash` itself, from the proof value it parsed under section 10.1.
  It MUST NOT take it from the received bytes or from anything the document
  carries. So every formatting of one value verifies alike (section 3.1).
- `alg` names this whole rule, not only its primitive: the canonicalization, the prefix
  byte, `proof_hash`, and pure Ed25519 over it. The registered names `EdDSA`
  (RFC 8037) and `Ed25519` (RFC 9864) mean a signature over the input itself, so they name
  a different computation, and a verifier rejects them (section 3.1). When the
  `constructions` member is absent (section 7.2), `alg` is the only thing in the document
  that names the step that computes `proof_hash`. A change to the computation needs a new literal, which
  verifiers pin before any proof uses it; this document defines no other.
- The signed message is 32 octets whatever the proof's size, so a cloud key service or a
  hardware security module can hold the key and make the signature.

**Key binding.** A signature that verifies shows only that the holder of K signed the
proof, and anyone can sign a document with a key of their own. The proof is Truestamp's
only when K is also one of Truestamp's keys, which a verifier learns from outside the proof
(section 8). A verifier MUST make both checks, in this order:

1. **Key binding** (section 10.2, step 5). The 32 octets K decodes to MUST equal the 32
   octets of a key in the keyring that governs the run (section 8), active or not. The key
   id of K (section 3.3) MAY serve as an index into the keyring, but only the full
   comparison binds. A verifier MUST NOT read a key id the document carries, such as a
   block record's `signing_key_id` or a key event's `key_id`, to choose or to check the
   signer.
2. **The signature** (section 10.2, step 6). V MUST verify under K over `proof_hash`, by the
   strict verification of section 6.2. No option skips this check.

A failure of either ends the run (section 10.2). Only keyless mode, which an external
verifier enters only when asked, skips key binding, and it says so (section 8.3).

- `signing_key_event` (section 3.2) shows how the signing key entered Truestamp's key
  chain. It is provenance only, and never binds the key (section 10.3).
- A proof carries no block signature. A block record's signature is Truestamp's internal
  record, and the proof's own signature covers every block node the proof carries. The
  only other signature in a proof is a rotation's `handover_signature` (section 3.3), which
  a verifier checks as section 6.2 says.

### 6.2 Strict verification

Ed25519 verifiers disagree at the edges: on keys of small order, on encodings that are not
canonical, and on whether the check multiplies by the cofactor. This section fixes one
rule, so that every conforming verifier accepts exactly the same signatures, and each
signature binds one document and one key. It applies to the proof's signature and to every
handover signature.

The constants are those of RFC 8032 section 5.1: p = 2^255 - 19,
L = 2^252 + 27742317777372353535851937790883648493, and B, the base point. [n]P is the
point P added to itself n times. Verify(A, msg, S), where A is the 32 octets of a public
key, msg the 32 octets signed and S the 64 octets of a signature, is:

1. A and S come from strings that matched B64U32 and B64U64 (section 2.4), so their
   base64url spellings are canonical.
2. Read y as the little-endian integer of A with its highest bit cleared. If y is not below
   p, fail.
3. If A is one of SMALL_ORDER_KEYS (below), fail.
4. Decode A as a point, as RFC 8032 section 5.1.3 does. If A is not on the curve, fail.
5. Split S into R, its first 32 octets, and s, its last 32 read as a little-endian integer.
   If s is not below L, fail.
6. Set k = SHA-512(R || A || msg), read as a little-endian integer, mod L.
7. Compute [s]B - [k]A and encode it as RFC 8032 section 5.1.2 does. Pass exactly when
   those 32 octets equal R.

Step 7 is the cofactorless equation [s]B = R + [k]A, with R compared as its encoding.
Comparing encodings gives the same answer as decoding R strictly and comparing points. A
verifier MUST NOT use the cofactored equation [8][s]B = [8]R + [8][k]A, which accepts
signatures this one rejects.

Steps 2 and 3 are the checks of a key's bytes, and a verifier also makes them outside
Verify: on K at ENVELOPE, on each key of a keyring when it loads the keyring, and on each
key event's `public_key` at DERIVE (section 10.2, steps 0, 3 and 9). A rotation's
`previous_public_key` meets them as the A of its handover signature.
Verify itself runs at SIGNATURE, for V under K over `proof_hash` (section 10.2,
step 6), and at DERIVE, for each `handover_signature` under its event's
`previous_public_key` over the 32 bytes of H(0x62, the event without `handover_signature`)
(sections 3.3 and 10.3).

**SMALL_ORDER_KEYS.** A verifier MUST reject these ten encodings in every mode, the keyless
mode included. They are published as `spec/small-order-keys.json`:

```
0100000000000000000000000000000000000000000000000000000000000000   identity
ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f   order 2
0000000000000000000000000000000000000000000000000000000000000000   order 4
0000000000000000000000000000000000000000000000000000000000000080   order 4
26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05   order 8
26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85   order 8
c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a   order 8
c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa   order 8
0100000000000000000000000000000000000000000000000000000000000080   identity, sign bit set
ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff   order 2, sign bit set
```

They are every encoding with y below p of a point whose order divides 8: the eight such
points once each, and the identity and the point of order 2 again with the sign bit set,
which RFC 8032 section 5.1.3 refuses to decode but many libraries accept. Step 2 rejects
every other encoding of such a point.

**Why each check.**

- A key of small order verifies the signature whose R encodes the identity and whose s is
  0: the identity key over every message, and a key of order 2, 4 or 8 over one message in
  2, 4 or 8.
- A key or an R written with y at p or above is a second spelling of one point, so without
  step 2 two different documents could carry one key.
- Without step 5, one signature has a second spelling, with s + L in place of s.
- The cofactored and cofactorless equations disagree on some signatures, so a verifier that
  used the other one would disagree with this document.

**Common libraries (informative).** Two common libraries were tested for this document:
Go's `crypto/ed25519` (Go 1.26), and OpenSSL (3.5), which Erlang/OTP's `:crypto` uses. Both
make steps 4 to 7 as written, and neither makes step 2 or step 3: both accept the identity
key, and the identity written with y = p + 1, with the signature (identity, 0). A verifier
built on either makes steps 2 and 3 itself, before it calls the library. A ZIP-215 verifier
does not conform: it accepts encodings with y at or above p, and uses the cofactored
equation.

A key of mixed order, the sum of a point of order L and a point of small order, passes
steps 2 to 4, and a signature made with it verifies only when k is a multiple of the small
point's order. Every key Truestamp makes, apart from the mixed-order test key of section 9,
which exists only for the agreement cases and which no keyring holds, is [a]B for a scalar
a, so its order is L, and no keyring Truestamp publishes holds a key of mixed order.
Section 13's agreement cases hold every verifier to the same answers for such a key.

### 6.3 Worked example

The example shows the rule of section 6.1 and nothing else. Its object is not a complete
proof: a `block` proof also needs `block` and `commitments` (section 3.2). The input,
indented and out of order:

```
{
  "version": 1,
  "type": "block",
  "format": "truestamp-proof",
  "environment": "test"
}
```

| Quantity | Value |
|---|---|
| M, 76 octets | `{"environment":"test","format":"truestamp-proof","type":"block","version":1}` |
| `proof_hash` | `9f46e27f4a5e1d937189020719959df9d4f7b65948b616d4bde9d187688e21b2` |
| sk, the vector seed | 32 octets of 0x42 |
| A, the public key (VECTOR_KEY) | `2152f8d19b791d24453242e15f2eab6cb7cffa7b6a5ed30097960e069881db12` |
| K | `IVL40Zt5HSRFMkLhXy6rbLfP-ntqXtMAl5YOBpiB2xI` |
| key id of A (section 3.3) | `fbd680e8` |
| S | `90f2b97db826135ef545494d10b053ef7d50aebdda7e200ea278637b2b6e3c055d68df1d552c59dfaeb52367405021c5e957dc585cc6c80fe9eeb2364c03450d` |
| V | `kPK5fbgmE171RUlNELBT731Qrr3afiAOonhjeytuPAVdaN8dVSxZ3661I2dAUCHF6VfcWFzGyA_p7rI2TANFDQ` |

The served document, JCS(envelope), 293 octets:

```
{"proof":{"environment":"test","format":"truestamp-proof","type":"block","version":1},"signature":{"alg":"truestamp-ed25519-sha256-jcs","public_key":"IVL40Zt5HSRFMkLhXy6rbLfP-ntqXtMAl5YOBpiB2xI","value":"kPK5fbgmE171RUlNELBT731Qrr3afiAOonhjeytuPAVdaN8dVSxZ3661I2dAUCHF6VfcWFzGyA_p7rI2TANFDQ"}}
```

Ed25519 signing is deterministic (RFC 8032 section 5.1.6), so anyone holding the seed
reproduces S. Three implementations gave these values: Go's `crypto/ed25519`, Erlang/OTP's
`:crypto`, and the reference arithmetic of RFC 8032 section 6. In each:

- the document still verifies re-indented with CRLF line ends, with its members reordered,
  a string spelled with a `\u` escape and `1.0` for 1;
- S does not verify over M itself, over SHA-256(M), over the hex of `proof_hash`, over
  SHA-256(0x31 || M) or SHA-256(0x62 || M) (the bytes of the other two signed kinds), or
  with `environment` changed to `dev` or removed.

Under section 10.2, a verifier whose E_v is not `test` rejects the document at
ENVIRONMENT. A `test` verifier whose keyring holds VECTOR_KEY passes it at KEY_BINDING and
SIGNATURE, then rejects it at SHAPE with `shape_invalid`, because it is not a complete
proof. `vectors/worked-example.json` holds the values above, and the vector generator
checks this section against it (section 13.2).

**The stranger's recipe.** For a production proof, these lines are steps 1 to 6 of
section 10.2, with the checks of step 3 in its order:

```
doc = parse(file)                                  # the rules of section 10.1
check doc is an object, and keys(doc) == {proof, signature}
check doc.proof is an object
check doc.signature is an object, and keys(doc.signature) == {alg, public_key, value}
check doc.signature.alg == "truestamp-ed25519-sha256-jcs"
check doc.signature.public_key is a string that matches B64U32
A = b64url_decode(doc.signature.public_key)        # 32 octets
check A passes steps 2 and 3 of section 6.2        # y below p, and not in SMALL_ORDER_KEYS
check doc.signature.value is a string that matches B64U64
check "environment" not in doc.proof               # a production proof (section 6.4)
check A equals a key of Truestamp's keyring        # all 32 octets; keyring.json online, the pin offline
proof_hash = SHA-256(0x50 || JCS(doc.proof))
check Verify(A, proof_hash, b64url_decode(doc.signature.value))   # section 6.2; the message is proof_hash's 32 octets
```

Passing these lines shows only that a key in Truestamp's keyring signed the proof. Its
subject, its hashes, its commitments and its submission window are checked by the steps
that follow (section 10.2, steps 7 to 12).

### 6.4 The environment marker

**The marker.** Truestamp's server writes `environment` into every proof it signs outside
production, naming its environment: `dev`, `staging` or `test` (ENV, section 2.4). In
production it writes no marker. The member is inside `proof`, so the signature covers it.

**E_v, the verifier's environment,** is `prod` or an ENV value. It is fixed at
CONFIGURATION (section 10.2, step 0), before the document is read:

- Truestamp's server uses its own environment, and takes no override. Only the test seam
  of its test builds sets E_v (section 13.1).
- The CLI and the reference verifiers in this repository use `prod`, unless the run is
  given `--environment` naming another environment. The option applies to that run only.
- A verifier MUST NOT take E_v from its configuration files, from environment variables,
  from `--base-url` or from the document.

**The check** (ENVIRONMENT, section 10.2, step 4) comes before key binding and the
signature:

- If E_v is `prod`, `environment` MUST be absent.
- Otherwise, `environment` MUST be present, a string, and equal to E_v.

Anything else fails with `environment_mismatch`: a marker under `prod`, whether `"prod"`,
`"production"` or any other; no marker, or another environment's, under a non-production
E_v; and a `null`, a number or any other type. The check can only reject. The member it
lets through is not yet authenticated, and the signature at step 6 confirms it.

**Keys by environment.** Environments never share a key: Truestamp's server refuses to
start with an active key that belongs to another environment, and no production keyring
holds a non-production key. The marker and key binding are therefore independent
barriers. Removing the marker from a staging proof breaks its signature, and a staging
signature over an unmarked proof fails key binding against a production keyring.

- A production keyring is any keyring loaded in a run whose E_v is `prod`, whatever its
  source: the compiled `spec/keyring.production.json`, the keyring read from
  www.truestamp.com, and a supplied keyring, `--keyring FILE` included. When a verifier
  loads a keyring (section 10.2, step 0), it refuses a production keyring that holds a key
  of `spec/keys.nonproduction.json`, so no run whose E_v is `prod` can bind a
  non-production key. It also refuses any keyring that holds VECTOR_KEY when E_v is not
  `test`. Keyless mode binds no key, so it treats VECTOR_KEY as any other key.
- A run of the CLI or of a reference verifier in this repository whose E_v is not `prod`
  MUST NOT use the compiled production keyring or the keyring at www.truestamp.com. Its
  keyring is a supplied keyring (section 8.3): a keyring file (in the CLI,
  `--keyring FILE`), a configured keyring, or, in the CLI, the keyring read from the origin
  an explicit `--base-url` names. Its attribution is then `keyring:<d>` (section 10.5).
  With none of them, and outside keyless mode (section 8.3), the run stops with
  `configuration_error`.

**Reports and messages.** Every report carries E_v as `environment` (section 10.5), and a
verifier that shows a verdict MUST show a non-production E_v beside it. The message of
`environment_mismatch` never quotes the proof's marker. It names the marked environment
only when the marker is `dev`, `staging` or `test`, says production when the proof carries
no marker, and otherwise says that the proof carries a marker that no Truestamp environment
uses. For a staging proof under a production verifier it is: "This proof is marked as
issued by Truestamp's staging environment, which is for testing. It is not a production
proof." Only for a marker of `dev`, `staging` or `test`, the CLI adds a command that works,
such as: "To check it against the staging keyring, run again with --environment staging and
either --keyring FILE or --base-url URL."

## 7. Constructions

### 7.1 What it is, and who it is for

The constructions text is a short list of named rules carried in the proof. It says how
each value is computed from the ones before it, up to the epoch hash Truestamp writes to
Stellar and Bitcoin, and how the two window edges are read. It is documentation: no
verifier interprets it, every verifier has the same rules compiled in, and each only checks
that the text is one it has reviewed (declare and verify).

- **Auditors, lawyers and courts** see from the file alone what was checked and how,
  without trusting Truestamp's software.
- **AI agents** can write a working verifier for the proof in front of them from the proof,
  the keyring and chain data alone (section 7.4).
- **Verifiers written after Truestamp is gone** find a file that explains itself for as long
  as it, the chains and the keyring survive.
- **New implementers** get a one-page map into this document, which the text's
  `specification` row names.

The text is carried rather than only linked, because a self-explaining file cannot be
orphaned by a dead link, and its explanation is signed with everything else. Trust policy
stays outside the proof (which keys and texts are Truestamp's), because a proof cannot
vouch for itself.

### 7.2 Modes

One member, `constructions`, whose JSON type tells the modes apart:

| Mode | `proof.constructions` | Digest d checked |
|---|---|---|
| full (the default) | the object of section 7.3 | SHA-256(JCS(value)) |
| reference | the string `https://www.truestamp.com/.well-known/constructions-<d>.json`, matching `\Ahttps://www\.truestamp\.com/\.well-known/constructions-[0-9a-f]{64}\.json\z` | the 64 hex characters in the URL |
| none | absent | nothing |

A verifier checks the member at SHAPE (section 10.2), after the signature has passed:

1. d MUST be in CONSTRUCTIONS_ACCEPTED (section 9), or the proof fails with
   `construction_mismatch`. A string that does not match the pattern, or a value of any
   other type, fails with `shape_invalid`.
2. A verifier MUST NOT interpret the text or fetch the URL, and MUST NOT read the member
   except at this check. Each of Truestamp's verifiers has a test that asserts this
   (section 10.6).
3. d has no prefix byte. It is a content address, never signed or committed alone, so the
   SHA-256 of the served file equals the hex in its name.
4. The member is inside `proof`, so the signature covers it, and each mode gives its own
   signed document.
5. A proof's verdict never depends on its mode. With `none`, a proof loses only its
   self-description.

### 7.3 The text

The genesis text (*Proposed*): 28 rows, 7,859 octets under JCS, digest
`c4cf75328f76a30992da2f3449e2df28b4197f819d785d2a18aa62a33284f969`. Every value is printable
ASCII with no `"` or `\`. To reproduce the digest, parse the object below, serialize it
with sorted keys and no whitespace (exactly JCS for this object), and hash it:
`hashlib.sha256(json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()).hexdigest()`.

```json
{
  "beacon": "block.block_hash is the beacon value; each member of observations is an entropy leaf of that block, checked as an observation subject; no one, Truestamp included, could compute the value before Submitted after, but Truestamp chooses the block contents after the entropy is public and so can bias it",
  "bitcoin": "raw_transaction is a transaction serialized without witness data (BIP 144 marker, flag and witnesses removed), with at least one input; transaction_hash = rev(SHA-256d(raw_transaction)); exactly one output script begins 0x6a and it is 0x6a 0x20 followed by the 32 bytes epoch.epoch_hash's hex spells, in that order; txoutproof is a BIP 37 merkleblock: an 80-byte header, total_txs, and a partial Merkle tree that places transaction_hash under header_merkle_root; header_hash = rev(SHA-256d(header)) and meets the target in the header nBits; header_merkle_root = rev(the header Merkle root field); header_time = the header nTime; header_hash is the best-chain block at height on network; network is the verifier's pinned Bitcoin network, and nothing in this proof decides it",
  "block_hash": "SHA-256(0x31 || JCS(record))",
  "chain_order": "a Stellar entropy object sequence is below the ledger of a top-level stellar commitment on the same network; a Bitcoin entropy object height is at or below the height of a top-level bitcoin commitment on the same network",
  "checks": "compute each hash this text defines from its preimage as carried and compare it with the value the proof carries for it; every merkle_path, and every comparison of one hash with another, starts from the computed value, never the carried one",
  "claims": "the submitter's statements exactly as submitted, attested as submitted and never as true; hash is lowercase hex of the length hash_type fixes (for example md5 32, sha1 40, sha256 64) and is never recomputed; timestamp is a time the submitter claims and never an edge of the submission window; nonce, if present, is at most 32 random bytes in lowercase hex",
  "claims_hash": "SHA-256(0x10 || JCS(claims))",
  "encoding": "JCS is RFC 8785; hashes, key ids and Bitcoin byte strings are lowercase hex, Bitcoin hashes in the reversed byte order explorers display, except NIST outputValue, which is uppercase hex as NIST publishes it; Ed25519 keys and signatures are unpadded base64url (RFC 4648 section 5); times are RFC 3339 UTC, except the Bitcoin entropy payload time, which is integer Unix seconds; SHA-256d is SHA-256 applied twice; rev reverses byte order; median time past is the median of the header times of a block and the 10 blocks before it",
  "entropy_hash": "SHA-256(0x20 || JCS(entropy object))",
  "environment": "present only outside production, naming the environment that signed the proof (dev, staging or test); a verifier rejects a proof from any environment but its own",
  "epoch_hash": "SHA-256(0x40 || JCS(record)) for the epoch of each commitment entry, whose record holds the epoch tree's merkle_root and leaf_count; epoch_hash is the value written to Stellar and Bitcoin, so the chain commits the tree's leaf count with its root",
  "genesis": "when record.metadata.genesis is present: record.height = 0 and previous_block_hash = SHA-256(0x30 || JCS(metadata.genesis)); genesis.bitcoin names a best-chain Bitcoin block mined before the chain began",
  "handover": "in a rotation or emergency_rotation key_event: previous_key_id is the key id of previous_public_key; height and previous_block_hash equal those of the block record whose metadata carries the key_event; and handover_signature, if present, is Ed25519 by previous_public_key over SHA-256(0x62 || JCS(the key_event without handover_signature))",
  "height": "record.height counts blocks from 0 at genesis; the height of witnesses.block is below the height of block",
  "inclusion": "a subject's merkle_path(item_hash or observation_hash, inclusion_proof) = block.record.merkle_root; each commitment entry's merkle_path(block_hash of the block these commitments belong to, inclusion_proof) = epoch.record.merkle_root; at both levels, inclusion_proof.tree_size = that record's leaf_count; in every block record, leaf_count = 0 exactly when merkle_root is the SHA-256 of zero bytes",
  "item_hash": "SHA-256(0x11 || JCS(record))",
  "key_event": "wherever record.metadata.key_event is present: genesis, rotation and emergency_rotation introduce public_key, and key_id = record.signing_key_id = the key id of public_key, which is hex of the first 4 bytes of SHA-256(0x60 || its 32 bytes); prerotation and revocation introduce no key, and for prerotation record.signing_key_id = active_key_id; signing_key_event.block introduces signature.public_key",
  "keyring": "signature.public_key is Truestamp's only if its 32 bytes equal a key in Truestamp's keyring, published at https://www.truestamp.com/.well-known/keyring.json and with the specification; nothing in this proof decides it",
  "merkle_path": "merkle_path(start, proof) is RFC 9162 section 2.1.3.2 over proof.leaf_index, proof.tree_size and proof.path, a list of hashes: fail unless leaf_index < tree_size and path has at most 32 hashes; set fn = leaf_index, sn = tree_size - 1 and r = SHA-256(0x00 || start); then for each p in path, in order: fail if sn = 0; if fn is odd or fn = sn, set r = SHA-256(0x01 || p || r) and then, while fn is even and not 0, halve fn and sn; if neither, set r = SHA-256(0x01 || r || p); in both cases, then halve fn and sn once; after the last p, fail unless sn = 0; halving rounds down, each hash is the 32 bytes its hex spells, and the result is the final r",
  "observation_hash": "SHA-256(0x21 || JCS(record))",
  "parsing": "the file is one UTF-8 JSON text (RFC 8259) with no duplicate member names or lone surrogates, at most 32 levels deep, whose numbers are read as the nearest binary64 value (underflow gives 0), none an integer above 2^53-1 and below 10^21 in magnitude however written; formatting and member order do not matter, since every hash and the signature use JCS of the parsed values",
  "recorded": "ids, the times inside ids, and every value this text does not derive are Truestamp records bound by these hashes and the signature; they are never a verdict input except as the rows above and the verifier's pins use them",
  "signature": "signature.value is pure Ed25519 (RFC 8032, not Ed25519ph) by signature.public_key over the 32 bytes proof_hash = SHA-256(0x50 || JCS(proof)), where proof is the top-level proof member, and signature.alg names exactly this rule; proof_hash is never carried",
  "specification": "the full rules and a reference verifier are at https://github.com/truestamp/truestamp-verification, which governs wherever this summary differs",
  "stellar": "transaction transaction_hash on network is successful, has memo_type hash with memo = epoch.epoch_hash, and is in ledger ledger; network is the verifier's pinned Stellar network, and nothing in this proof decides it",
  "submitted_after": "the latest of these, each read from its source during verification for an entropy object whose hash matched: a NIST pulse timeStamp, a Stellar ledger closed_at, a Bitcoin block median time past; times carried in this proof are never used; the network of a Stellar or Bitcoin entropy object is the verifier's pinned network for that source, and nothing in this proof decides it",
  "submitted_before": "the earliest of these, each read from its chain during verification for a top-level commitment: the Stellar ledger closed_at, or the median time past of the best-chain Bitcoin block at height + 10, which assumes at least 6 of blocks height + 1 to height + 10 carry honest times; signing_key_event commitments and times carried in this proof are never used",
  "witnesses": "for each name in record.witness_hashes: witness_hashes.block = the block_hash of witnesses.block, and witness_hashes.entropy_X = the entropy_hash of witnesses.entropy_X; witnesses has exactly the names of witness_hashes"
}
```

The `checks` row stops a walk from starting at a carried value (the graft defect), and the
`keyring` row stops a self-signed proof from passing as Truestamp's. The CI of each of
Truestamp's implementations extracts every `SHA-256(0xNN || ...)` in the text and asserts
that the byte and the preimage name match the registry, and that the set of rows equals
this one. Reference mode saves 7,736 octets per proof, and `none` 140 more.

### 7.4 The agent-sufficiency acceptance test

## 8. Verifier roles

A verifier attributes a proof to Truestamp only when K is one of Truestamp's keys
(section 6.1), and it learns which keys those are from outside the proof: from a trust root
that its role fixes before it reads the document (section 10.2, step 0). There are two
roles, Truestamp's own verifier and external verifiers.

### 8.1 Rules for every role

- **Key binding** is the same in every role (section 6.1). Only the keyring that governs
  differs.
- **What a keyring holds.** A keyring of Truestamp's lists every key Truestamp has used and
  not revoked. A key retired by a routine rotation stays in it, so the proofs that key
  signed still bind. A revoked key leaves it, so every proof that key signed fails key
  binding wherever a current keyring governs, whenever it was signed.
- **Attribution and window are separate.** Attribution says who signed the proof. It never
  establishes a submission window, and a window never establishes attribution
  (section 11.5).

### 8.2 Truestamp's own verifier

Truestamp's own verifier is the one Truestamp runs on its servers, for its web pages and
its APIs.

- **Key chain.** Its trust root is its key chain (`key_chain`): the keys that the key events
  of Truestamp's chain introduce, less the keys it has revoked, verified from a pinned
  genesis key before it relies on any of them. Which key events it accepts is Truestamp's
  own policy (section 3.3).
- **Fails closed.** While its key chain is not verified, KEY_BINDING fails with
  `keyring_unavailable` for every proof. A K that is not in the key chain fails with
  `key_binding_failed`. It has no keyless mode, accepts no supplied keyring, and never
  falls back to the compiled pin or to a downloaded keyring.
- **Environment.** Its own, with no override (section 6.4).
- **Labels.** It gives only `failed`, `internally-consistent` and `verified`
  (section 10.5), and has no exit code.
- **Test seam.** These rules describe how Truestamp runs its verifier. Only its test builds
  have a seam, which runs the conformance cases in the role of an external verifier
  (section 13.1).

### 8.3 External verifiers

Every other verifier is external: Truestamp's CLI, the reference verifiers in this
repository, and any verifier someone else writes. Before it reads the document, an external
verifier fixes one keyring for the run:

| Keyring | Used | `trust_root.kind` | When K is not in it |
|---|---|---|---|
| the keyring read in this run from `https://www.truestamp.com/.well-known/keyring.json` | by default, online | `current_keyring` | `key_binding_failed`; after a failed read, `keyring_unavailable` for every K |
| the compiled pin: `spec/keyring.production.json` as built into the verifier | by default, offline, and never online | `compiled_pin` | `key_binding_failed`, with a message to update the verifier or run online |
| a supplied keyring: a file (in the CLI, `--keyring FILE`), a configured keyring, or the keyring read from another origin (in the CLI, `--base-url URL`) | on request | `supplied_keyring` | `key_binding_failed`; after a failed read from another origin, `keyring_unavailable` for every K |
| none: keyless mode (in the CLI, `--no-keyring`) | only on request | `none` | KEY_BINDING is `skip key_binding_not_performed` |

- The attribution each keyring gives when K binds is in section 10.5. For a supplied
  keyring it is `keyring:<d>`, where d is the lowercase hex SHA-256 of the keyring's bytes
  as read: a content digest, outside the registry (section 4.1).
- The downloaded keyring replaces the compiled pin, and does not add to it. Online, a key
  the download lacks does not bind even when the pin holds it, so a key revoked after the
  verifier was built stops binding at once.
- **A failed read.** When the keyring that governs is read online, from www.truestamp.com
  or from the origin `--base-url` names, that read governs and nothing else. A read that
  does not give a keyring passing the load checks of section 10.2, step 0, for any reason
  (a transport failure, an HTTP error, bytes that break section 10.1, or a failed load
  check), is a failed read, and KEY_BINDING fails with `keyring_unavailable` whatever K is.
  The compiled pin governs only an offline run (section 10.2, the external gate). The
  message says that the keyring could not be read. If it mentions an offline run, it says
  that such a run checks only against the keys built into the verifier, and cannot see a
  key revoked since.
- Every keyring is checked when it is loaded (section 10.2, step 0). A keyring file or a
  configured keyring that fails is `configuration_error`, and the run gives no verdict. A
  keyring read online that fails is a failed read, as above.
- **Keyless mode** MUST be requested for the run, and only for the run: a verifier MUST NOT
  take it from its configuration files or from environment variables, as for E_v
  (section 6.4). A verifier MUST NOT enter it by default, or because a keyring cannot be
  read. In keyless mode the verifier still verifies V under K, and with every verdict it
  shows it MUST say in words that the signature was checked only against the key the
  document carries. Its label is `unattributed` unless a row fails.
- **Environments.** A run whose E_v is not `prod` uses a supplied keyring or keyless mode
  (section 6.4), so its best label is `supplied-keyring`.
- **The reference verifiers** in this repository are offline: they make no chain or source
  read (section 10.4). Each compiles in the pin and offers the supplied and keyless modes.
  They confirm that a proof is intact and signed by a key they trust, and draw no
  submission window, so their label for a sound production proof signed by a pinned key is
  `internally-consistent`. The CLI makes those reads online and draws both edges
  (section 11).
- **Trusting the download.** Online, an external verifier trusts the keyring as the origin
  serves it, so whoever can change that response can add a key. A verifier that must not
  depend on the origin runs offline, where the pin governs, or supplies its own keyring.
  Online, a read that fails binds no key.

## 9. What a verifier pins

The pins are a verifier's trust policy, and each is published as a file under `spec/`.

- **Keys:** Truestamp's own verifier uses its verified key chain.
  `spec/keyring.production.json` is compiled into the CLI and the reference verifiers in
  this repository, and the keyring downloaded from www.truestamp.com replaces it online
  (section 10.2, step 0).
  `spec/keys.nonproduction.json` lists the public keys of the dev, test and staging
  environments, with VECTOR_KEY, every other key whose seed this section or the generator
  publishes, and every key such a seed can sign under, among the test keys, and a
  production keyring MUST NOT contain any of them (section 6.4). A verifier MUST validate
  every keyring when it loads it.
- **Literals:** `format`, `version` 1, `signature.alg`, CONSTRUCTIONS_ACCEPTED (the digests
  of the texts under `spec/constructions/`), and `spec/schema.json`: the type registry,
  closed member sets, presence by type and patterns.
- **Networks:** a commitment pin per chain and, separately, an entropy pin per source. No
  account or address is pinned.
- **Sources:** compiled-in defaults, or an operator-pinned Horizon, Esplora or Bitcoin Core
  server (in the CLI, `--horizon URL`, `--esplora URL` and `--bitcoin-core URL`). Every
  Stellar and Bitcoin source's identity is checked before its first read (section 10.2,
  step 0). Regtest has no default. A verifier MUST NOT let a document select a source.

| Constant | Value |
|---|---|
| MAX_READ_OCTETS | 262,144 (for a verifier: 4 x 65,536, room for reformatting) |
| MAX_DOCUMENT_OCTETS | 65,536 (for Truestamp, on JCS(envelope)) |
| MAX_DEPTH | 32, counting the document object as 1 |
| MAX_PATH_STEPS | 32 |
| MAX_INTEGER | 2^53 - 1 = 9007199254740991 |
| CLAIMS_MAX_OCTETS | 20,480 (for Truestamp) |
| RAW_TX_MAX_OCTETS, TXOUTPROOF_MAX_OCTETS | 1,000, 1,024 |
| BITCOIN_MAX_TOTAL_TXS | 16,666 (4,000,000 weight units / (a 60-octet minimum transaction x 4)) |
| BITCOIN_FINALITY, BITCOIN_MEDIAN_SPAN | 10, 11 |
| STELLAR_INDEX_MARGIN | 60 ledgers |
| SMALL_ORDER_KEYS | the ten encodings of section 6.2 |
| VECTOR_KEY | `2152f8d19b791d24453242e15f2eab6cb7cffa7b6a5ed30097960e069881db12`, from the seed of 32 bytes of 0x42; valid only when the verifier's environment is `test` |

VECTOR_KEY signs every sound proof (section 13.3), and every other proof in the vectors
unless its case says otherwise (section 13.2). Two more keys come from published seeds and
sign no proof, only blocks and handovers of the chains the sound proofs are cut from: the
key of the seed of 32 bytes of 0x41, whose key id is `f12cfabb`, and the key of the seed of
32 bytes of 0x43, whose key id is `9602c03e`. A fourth, the key of the seed of 32 bytes of
0x44, whose key id is `d0b1cefe`, signs only the proofs of cases that call for a key other
than VECTOR_KEY (section 13.3). A fifth, whose key id is `5e81cc77`, is the 0x44 key plus a
point of order 8, which signs only the two mixed-order cases; anyone who holds the 0x44 seed
can sign under it (section 6.2). All five are test keys in `spec/keys.nonproduction.json`,
so no production keyring can hold them.

There are no clock tolerances.

**The data files.** These files under `spec/` hold the pins:

| File | Holds |
|---|---|
| `prefixes.json` | the table of section 4.3, keyed by construction name |
| `constants.json` | the constants above, except SMALL_ORDER_KEYS, which has a file of its own |
| `small-order-keys.json` | SMALL_ORDER_KEYS in hex, with each point's order |
| `encodings.json` | the pattern classes of section 2.4 |
| `networks.json` | the network names of each chain |
| `value-classes.json` | the value classes of section 3.7, by JSON Pointer pattern |
| `schema.json` | the closed schema of the envelope and of every type |
| `constructions/c4cf75328f76a30992da2f3449e2df28b4197f819d785d2a18aa62a33284f969.json` | the text of section 7.3, as its exact JCS bytes |
| `keyring.production.json` | the compiled pin of section 8.3, a keyring in the form of section 10.2, step 0 |
| `keys.nonproduction.json` | the public keys of the dev, test and staging environments, as `{keys}`, one object per key: `{environment, key_id, public_key}`, with `public_key` a B64U32 and `key_id` its key id |
| `reason-codes.json` | the table of section 12.1, one object per row, in the table's order |
| `exit-codes.json` | the table of section 12.2, one object per row |

Every file satisfies the parsing rules of section 10.1 and has one canonical form. A
constructions text is its exact JCS bytes, with no final newline, so the SHA-256 of the
file is the hex in its name (section 7.2). Every other file is ASCII, with members in JCS
order, two-space indentation, LF line ends and a final newline. In that form a member is
its name, a colon, one space and its value; an object or array that is not empty puts each
member or element on a line of its own, one level deeper and followed by a comma unless it
is the last, and closes on a line of its own at the indentation of the line that opens it,
while an empty one is `{}` or `[]`; and every name and scalar is written as JCS writes it,
which escapes no character above U+007E, so a value that holds one has no file in this form.
`MANIFEST.sha256` lists the SHA-256 of every file under `spec/` and `vectors/`, one line per
file in the format `sha256sum` reads, sorted by path.

**The schema.** `spec/schema.json` is a JSON Schema (draft 2020-12) of the envelope. It
uses only these keywords, so a verifier can use any conforming validator or interpret the
subset itself: `$schema`, `$defs`, `$ref` (to `#/$defs` only), `allOf`, `if`, `then`,
`else`, `not`, `type`, `const`, `enum`, `properties`, `required`, `additionalProperties`
(only `false`), `minProperties`, `pattern`, `minLength`, `maxLength`, `minimum`,
`maximum`, `items` and `maxItems`, and the boolean schemas `true` and `false`. Each
pattern other than the newline guard `\n`, which appears only under `not`, begins with
`^`, ends with `$`, and is paired with an exact length or with that guard, so a validator
whose `$` also matches before a final newline gives the same answer. Every document this
specification allows satisfies the schema. Three checks of SHAPE are beyond it and are
made in code: `witnesses` has exactly the names of `witness_hashes`, each TIME and
NISTTIME value equals the formatting of its own parse, and the constructions digest is in
CONSTRUCTIONS_ACCEPTED (section 7.2).

**Value classes.** In `spec/value-classes.json`, each member rule maps a JSON Pointer
pattern into the proof, or into the envelope where it says `"document": "envelope"`, to a
class. A segment `*` matches any name, and a segment ending in `*` matches any name that
begins with the rest. A rule applies to the value at its pointer and to everything inside
it; no rule's pointer lies inside another's, and each value meets at most one rule. A rule
with `when` takes its class only where the named condition holds, and otherwise the class
that `otherwise` names.

## 10. The verification algorithm

### 10.1 Parsing

A verifier parses the file as ordinary JSON and works with the values it reads, never with
byte offsets. Formatting is free: whitespace, line ends, member order, the spelling of an
escape and the spelling of a number (`1.0` for `1`) change no result (section 3.1). The
file's bytes face only the six rules below, each chosen so that no two verifiers read one
file differently.

| Rule | Why |
|---|---|
| J1. The file is at most MAX_READ_OCTETS octets. | It bounds all work before anything is authenticated. |
| J2. The file is exactly one JSON text (RFC 8259) in UTF-8: no byte order mark, and nothing after the value but whitespace. | Stock parsers disagree at the edges. |
| J3. The bytes are valid UTF-8, and no string holds an escaped lone surrogate. | Go's `encoding/json` silently replaces both with U+FFFD. |
| J4. No object has two members with the same name, compared as code points after unescaping and with no normalization. | Stock parsers keep the last value, so a reader could see one `proof` while the signature covers another. |
| J5. Every number is read as the nearest binary64 value: one that underflows reads as 0, -0 reads as 0, and one that overflows is rejected. No number's value is an integer of magnitude above MAX_INTEGER and below 10^21, however it is written. | Elixir keeps large integers exact while Go and JavaScript round them, which would split JCS and `proof_hash`. |
| J6. The depth is at most MAX_DEPTH, checked before JCS. The outermost value has depth 1, each object or array is one deeper than the object or array that holds it, and no other value adds a level. | It bounds recursion and the cost of JCS, which grows quadratically with depth. |

- J1 is step READ (section 10.2). A larger file is the bare rejection `input_too_large`, and
  a verifier can decide it after reading MAX_READ_OCTETS + 1 octets.
- J2 to J6 are step PARSE. A file that breaks any of them is the bare rejection
  `malformed_json`, whose `sub_reason` names a rule it breaks: `syntax` (J2),
  `invalid_utf8` or `lone_surrogate` (J3), `duplicate_name` (J4), `number` (J5) or `depth`
  (J6). For a file that breaks more than one, which of them is named is not fixed.
- Every binary64 value of magnitude 2^53 or more is an integer, so J5 rejects every number
  whose magnitude is at least 2^53 and below 10^21: `9007199254740992`,
  `9007199254740992.0`, `9007199254740993e0` and `1e16` among them. It accepts `1e21`, and
  reads `1e-400` as 0.

**The value profile.** J3 to J6, stated for values rather than bytes, are the value
profile. A JSON value is within it when every string in it, member names included, is a
sequence of Unicode scalar values; no object in it has two members with the same name;
every number in it is a binary64 value that is not -0 and is not an integer of magnitude
above MAX_INTEGER and below 10^21; and its depth is at most MAX_DEPTH. Every value parsed
from a file that meets J1 to J6 is within the profile, and so is every record that section
4.1 hashes. JCS is injective over it.

**After the signature.** The rules bind values, not spellings, so for every value v within
the profile, JCS(v) meets J2 to J6 and parses back to v. Let P be the parsed value of
`proof`. JCS(P) is exactly the M the signature covers (section 6.1), and every step from
SIGNATURE on reads P, never the received text. A verifier that parses M again reads the
same values and meets no failure.

A keyring (section 10.2, step 0) is read under these rules too.

### 10.2 Steps

A verifier runs these steps in order. Section 12.1 lists the codes each step can report.

| Step | Name | What it checks |
|---|---|---|
| 0 | CONFIGURATION | E_v, the pins and the keyring that governs, before the file is read |
| 1 | READ | J1 |
| 2 | PARSE | J2 to J6 |
| 3 | ENVELOPE | the envelope of section 3.1, and the bytes of K |
| 4 | ENVIRONMENT | the environment marker, against E_v |
| 5 | KEY_BINDING | K, against the keyring that governs |
| 6 | SIGNATURE | V under K, over `proof_hash` |
| 7 | SHAPE | `format`, `version`, the schema, the checks the schema cannot make, and `constructions` |
| 8 | POLICY | every `network`, against the pins |
| 9 | DERIVE | every recomputation and every link, offline |
| 10 | CHAIN | the chain reads of section 10.4, then KEY_EVENT_COMMITMENT |
| 11 | SOURCES | the entropy reads of section 10.4 |
| 12 | WINDOW | the submission window of section 11 |
| 13 | EXPECTED_HASH | the caller's hash against `claims.hash`, when asked |
| 14 | VERDICT | the label, attribution and window of section 10.5 |

**Rows.** A run that passes steps 0 to 3 gives a report, whose rows (section 10.5) say what
each check found. A row's part is a JSON Pointer into P, or null for a row about no single
member of the proof.

- Each check below names its part, by one rule: the carried value the check finds wrong
  when it fails, which for a recomputation is the declared value, and at SHAPE the member
  it finds missing, extra or malformed.
- Each check reports one row, `pass` when it holds. A check whose input could not be
  computed, such as the OP_RETURN of a transaction that did not parse, is not made and
  reports no row: the row of the check that failed on that input already explains it.
- Rows are in step order. Within a step, they are in the document order of their parts, a
  null part first. Rows that share a part keep the order of their checks: in DERIVE, the
  order of its parts (a) to (e) and of each table's rows, with LINK_INCLUSION's root rows
  at one `merkle_root` in the document order of their inclusion proofs. The one exception
  is KEY_EVENT_COMMITMENT, which ends CHAIN (section 10.3).
- A step's code is that of its first failing row, and the run's code is that of its first
  failing step.

**Document order** is the order in which a depth-first walk of P visits values, each value
before its contents, an object's members in JCS order and an array's elements by index. Of
two parts, the one that is a prefix of the other comes first, and otherwise the first
segment in which they differ decides. A part can name a member that P lacks, and it takes
the place in that order that the member would take.

**The gate.** Steps 0 to 6 are the gate. It opens when each of them passes, the keyless
skip at step 5 included.

- A failure at steps 0 to 3 is a bare rejection. The verifier outputs only
  `{code, message, sub_reason}`, with `sub_reason` only for `malformed_json` and
  `invalid_envelope`, and no report and no verdict.
- A failure at steps 4 to 6 ends the run. The label is `failed`, the attribution `none`,
  and each later step up to EXPECTED_HASH reports one row, `skip prior_failure`, with part
  null.
- So nothing in the proof but its `environment` member is interpreted until the key is
  bound and the signature verified. Truestamp's own verifier checks the key and the
  signature first, and stops if either fails.

**0. CONFIGURATION**, before the file is read. It fixes E_v (section 6.4), the network pins
and sources (section 9), and the keyring that governs key binding, which the verifier's
role decides (section 8). The downloaded keyring governs an external verifier's online run
under E_v `prod` with no supplied keyring and outside keyless mode (section 8.3). The
verifier then reads `https://www.truestamp.com/.well-known/keyring.json` here, and the
keyring it reads replaces the compiled pin for the run. A keyring read online
that fails, from that URL or from the origin `--base-url` names, is no bare rejection: no
key binds, and KEY_BINDING fails with `keyring_unavailable` (section 8.3).

Each keyring the verifier loads, the one it reads online included, MUST pass these checks
(section 9). A keyring is read under section 10.1 and MUST be an object with exactly two
members: `keys`, an array, and `version`, the string `"1.0"`. Each element of `keys` MUST
be an object with exactly `active` (a boolean), `key_id` (KID), `public_key` (B64U32) and
`sequence` (INT), where:

- `key_id` is the key id of `public_key` (section 3.3);
- no two keys share a `key_id` or a `public_key`;
- `public_key` passes the checks of a key's bytes (section 6.2): its y is below
  2^255 - 19, and it is not one of SMALL_ORDER_KEYS;
- no key is VECTOR_KEY unless E_v is `test`;
- in a production keyring (section 6.4), no key is in `spec/keys.nonproduction.json`.

A verifier makes exactly these load checks.

In an online run, the verifier MUST confirm here, before the file is read, the network of
every Stellar and Bitcoin source that serves a commitment pin or an entropy pin, whether a
compiled-in default or one the operator pinned, against its chain's production value, read
by the calls of section 10.4's informative table:

- a Stellar source pinned to `public` MUST give the network passphrase
  `Public Global Stellar Network ; September 2015`;
- a Bitcoin source pinned to `mainnet` MUST give
  `000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f` as the hash of its
  block at height 0;
- a source pinned to any other network MUST NOT give its chain's production value. No test
  network's value is pinned.

An identity read is always made live, to that source, and is never answered from a cache.
An identity read that gets no usable answer (section 10.4) makes each row that source
serves `skip source_unreachable`, and the verifier reads nothing else from that source. If
a row before CHAIN fails, those rows are `skip prior_failure` instead, as the external
gate below says.

Each of these is `configuration_error`:

- a keyring file or a configured keyring that fails a load check above;
- a run whose E_v is not `prod`, that is not keyless and that has no keyring source
  (section 6.4);
- an online run that pins a network, as a commitment pin or an entropy pin, with neither a
  compiled-in default nor an operator-pinned source for it;
- a source whose identity read gives a value the rules above forbid.

It is a bare rejection with no verdict. A verifier that confirms a source's identity later
than step 0 MUST give the output it would give had it confirmed it at step 0.

**1. READ.** J1 (section 10.1), else `input_too_large`.

**2. PARSE.** J2 to J6, else `malformed_json` with its `sub_reason`.

**3. ENVELOPE.** The document MUST be exactly the envelope of section 3.1. Its checks run in
this order, and the first that fails gives `invalid_envelope`, with that check's name as
the `sub_reason`:

1. `document`: the document is an object whose members are exactly `proof` and
   `signature`;
2. `proof`: `proof` is an object;
3. `signature`: `signature` is an object whose members are exactly `alg`, `public_key` and
   `value`;
4. `alg`: `alg` is the string `truestamp-ed25519-sha256-jcs`;
5. `public_key`: `public_key` is a string that matches B64U32, and the 32 octets K decodes
   to pass the checks of a key's bytes (section 6.2);
6. `value`: `value` is a string that matches B64U64.

The message is "This file is not a Truestamp proof." A document in any other layout fails
here, whatever it resembles: a verifier does not try to recognize it.

When steps 0 to 3 pass, each reports one row, `pass`, with part null.

**4. ENVIRONMENT.** The check of section 6.4, else `environment_mismatch`. The step reports
one row, at `/environment`.

**5. KEY_BINDING.** The check of section 6.1, item 1, against the keyring that governs: the
verifier looks for a key whose 32 octets equal the 32 octets K decodes to, and reads no key
id the proof carries. The step reports one row, with part null. When K is found, the row
passes. When it is not, the row fails with `key_binding_failed`. When the keyring that
would govern cannot be used, because the key chain is not verified or an online keyring
read failed, the row fails with `keyring_unavailable` whatever K is (sections 8.2 and
8.3). In keyless mode the row is `skip key_binding_not_performed` (section 8.3).

**6. SIGNATURE.** The check of section 6.1, item 2: the verifier computes `proof_hash` =
SHA-256(0x50 || JCS(P)) and checks V under K over its 32 octets by section 6.2, else
`signature_invalid`. The step reports one row, with part null.

**7. SHAPE**, on P. Its checks run in this order, and the first that fails is the step's
one failing row:

1. `format` MUST be `"truestamp-proof"`, else `unsupported_format` at `/format`.
2. `version` MUST be 1, else `unsupported_version` at `/version`.
3. The document MUST satisfy `spec/schema.json` (section 9), else `shape_invalid`. The
   schema holds the type registry; every closed member set, and presence by type; every
   pattern class, cap and literal; the absence of `null`; one or two entries in each
   COMMITMENTS; each entropy object's `source` against the proof's type or the member's
   name; the key-event member sets, and the three events allowed at
   `/signing_key_event/block`; the genesis pairing of section 3.3, in both directions; and
   the empty-root rule of section 5.4 in every block record, at `/block`,
   `/witnesses/block` and `/signing_key_event/block`.
4. In an item, `/witnesses` MUST have exactly the names of
   `/subject/record/witness_hashes`, else `shape_invalid` at `/witnesses`.
5. Every TIME and NISTTIME value MUST equal the formatting of its own parse, else
   `shape_invalid` at that value.
6. When `constructions` is present, its digest d (section 7.2) MUST be in
   CONSTRUCTIONS_ACCEPTED, else `construction_mismatch` at `/constructions`. Check 3 has
   already failed a value of any other type, and a string that does not match the
   reference pattern, with `shape_invalid`. No other step reads this member.

- The part of a failure at check 3 is the pointer, into P, of the member that is missing,
  extra or forbidden for the type, or else of the value that breaks its rule (for a count,
  the object or array). Its `values` name the rule. A block record that breaks the
  empty-root rule fails at its `merkle_root`.
- When check 3 or check 5 finds several failures, the row is the one whose part comes
  first in document order.
- When SHAPE passes, it reports one row, `pass`, with part null, and the report takes the
  proof's type and subject id (section 10.5).
- A failure at SHAPE ends the run as a failure at the gate does: the label is `failed`,
  and each later step up to EXPECTED_HASH reports one row, `skip prior_failure`, with part
  null.

**8. POLICY**, offline, in every run that reaches it. Each `network` MUST equal the
verifier's pin, else `network_mismatch` at that `network`:

- in each commitment entry, at `/commitments` and `/signing_key_event/commitments`, the
  commitment pin for its chain;
- in each Stellar or Bitcoin entropy object, at `/subject/entropy`, `/witnesses/entropy_X`
  and `/observations/entropy_X/entropy`, the entropy pin for its source;
- in each `metadata.genesis.bitcoin`, at any block position, the Bitcoin commitment pin.

Each comparison reports one row. A proof that passed SHAPE carries every `network` member
(sections 3.3 to 3.5), and a verifier never supplies a network that a proof lacks. A
failure here does not end the run: DERIVE still runs, and the external gate stays closed.

**9. DERIVE**, offline, in every run that reaches it. It recomputes each value that the
constructions text (section 7.3) defines from the preimage P carries, compares it with the
value P carries for it, and checks every link (section 10.3). It makes every check and
does not stop at a failure. A mismatch is `derivation_mismatch` unless its check names
another code. A failing row's `values` hold the constructions row that defines the value,
the declared value and the recomputed value, and each row whose part is a CHECKED value,
other than a row of LINK_HEAD, LINK_KEY_EVENT or LINK_CHAIN_ORDER, also gives a trace row
(section 10.6).

Below, B is each block node P carries (`/block`, `/witnesses/block`,
`/signing_key_event/block`); N is each commitment entry (`/commitments/C` and
`/signing_key_event/commitments/C`, where C is `bitcoin` or `stellar`); and in
`/observations/entropy_X` and `/witnesses/entropy_X`, X is a source, `nist`, `stellar` or
`bitcoin`, for each such member P carries.

(a) **Subject hashes.** Each recomputed hash MUST equal the value at its part.

| Recomputed | In | Part | Row of 7.3 |
|---|---|---|---|
| H(0x10, `/subject/claims`) | `item` | `/subject/record/claims_hash` | `claims_hash` |
| H(0x11, `/subject/record`) | `item` | `/subject/item_hash` | `item_hash` |
| H(0x20, `/subject/entropy`) | the entropy types | `/subject/record/entropy_hash` | `entropy_hash` |
| H(0x21, `/subject/record`) | the entropy types | `/subject/observation_hash` | `observation_hash` |
| H(0x20, `/observations/entropy_X/entropy`) | `beacon` | `/observations/entropy_X/record/entropy_hash` | `entropy_hash` |
| H(0x21, `/observations/entropy_X/record`) | `beacon` | `/observations/entropy_X/observation_hash` | `observation_hash` |

(b) **Block nodes.** For each B:

| Check | Part | Row of 7.3 |
|---|---|---|
| H(0x31, B`/record`) = B`/block_hash` | B`/block_hash` | `block_hash` |
| when B`/record/metadata/genesis` is present: B`/record/height` = 0 | B`/record/height` | `genesis` |
| when B`/record/metadata/genesis` is present: H(0x30, B`/record/metadata/genesis`) = B`/record/previous_block_hash` | B`/record/previous_block_hash` | `genesis` |

Each key event B carries is checked as section 10.3 says, failing with
`key_event_mismatch`.

(c) **Epochs.** For each N, H(0x40, N`/epoch/record`) MUST equal N`/epoch/epoch_hash`, at
that part (row `epoch_hash`). The walk into the epoch is LINK_INCLUSION, in (e).

(d) **Bitcoin evidence.** These checks apply to each Bitcoin entry N, at both positions.
A structural failure is `bitcoin_evidence_invalid`, and an inequality
`derivation_mismatch` (row `bitcoin`):

| Check | Part | Code |
|---|---|---|
| `raw_transaction` is well formed, as below | N`/raw_transaction` | `bitcoin_evidence_invalid` |
| the 32 bytes its OP_RETURN script pushes equal the recomputed `epoch_hash` (section 5.4) | N`/raw_transaction` | `derivation_mismatch` |
| rev(SHA-256d(`raw_transaction`)) = `transaction_hash` | N`/transaction_hash` | `derivation_mismatch` |
| `txoutproof` is well formed, as below | N`/txoutproof` | `bitcoin_evidence_invalid` |
| the one hash it matches equals SHA-256d(`raw_transaction`) | N`/txoutproof` | `derivation_mismatch` |
| rev(SHA-256d(header)) = `header_hash` | N`/header_hash` | `derivation_mismatch` |
| rev(the header's Merkle root field) = `header_merkle_root` | N`/header_merkle_root` | `derivation_mismatch` |
| the header's nTime, formatted as TIME, = `header_time` | N`/header_time` | `derivation_mismatch` |

Apart from the two checks of well-formedness, a check that reads a value out of
`raw_transaction` or `txoutproof` is made only when that structure is well formed. The
`transaction_hash` row is always made, the OP_RETURN row needs a well-formed
`raw_transaction`, and the row of the matched hash and the three header rows need a
well-formed `txoutproof`.

A `raw_transaction` is well formed when:

- it parses completely as a transaction serialized without witness data (BIP 144): the
  version, at least one input, the outputs and the lock time, with every compact size in
  its shortest form and no byte after the lock time;
- it is not exactly 64 octets long, so it cannot pass for an inner node of a Bitcoin
  Merkle tree (CVE-2017-12842);
- exactly one of its output scripts begins with 0x6a, and that script is exactly 0x6a 0x20
  followed by 32 bytes.

A `txoutproof` is well formed when:

- it parses completely as a BIP 37 merkleblock: an 80-octet header; `total_txs`, 4 octets
  little-endian, from 1 to BITCOIN_MAX_TOTAL_TXS; a compact size and that many 32-octet
  hashes; a compact size and that many flag octets; and nothing after, with every compact
  size in its shortest form;
- its partial Merkle tree walks as Bitcoin Core's CPartialMerkleTree walks one: the walk
  uses every hash and every flag bit, the bits after the last one used in the final flag
  octet are zero, and no node has a right child equal to its left (CVE-2012-2459);
- the walk matches exactly one transaction, and the root it gives equals the header's
  Merkle root field;
- the header meets the target its nBits field encodes.

The header's fields are, by octet, the version (0 to 3), the previous block hash (4 to 35),
the Merkle root field (36 to 67), nTime (68 to 71, little-endian Unix seconds), nBits (72
to 75, little-endian) and the nonce (76 to 79). With n the nBits value, e = n >> 24, and
w = n & 0x007fffff, shifted right by 8 x (3 - e) bits when e is at most 3:

- the encoding is negative when w is not 0 and n & 0x00800000 is not 0;
- it overflows when w is not 0 and e > 34, or w > 0xff and e > 33, or w > 0xffff and
  e > 32;
- the target is w when e is at most 3, and w x 256^(e - 3) otherwise.

The header fails when its encoding is negative or overflows, when the target is 0, or when
rev(SHA-256d(header)), read as a big-endian integer, is above the target.

(e) **Links.** LINK_INCLUSION at both tree levels, LINK_WITNESS, LINK_HEAD, LINK_KEY_EVENT
and LINK_CHAIN_ORDER, as section 10.3 says.

**The external gate.** Steps 10 and 11 read chains and sources. The gate is decided once,
when DERIVE ends: it is open when the caller did not ask for an offline run and no row so
far is `fail`. When it is open, both steps run, and a failure at CHAIN does not close it
for SOURCES. When it is closed, each of their rows is `skip prior_failure` when a row so
far is `fail`, or else `skip offline`. Only the caller opens this gate, and
nothing in the document can. A verifier that makes no reads, such as the reference
verifiers in this repository (section 8.3), always runs offline.

**10. CHAIN**, online. The chain reads of section 10.4, for each commitment entry at
`/commitments` and `/signing_key_event/commitments`, and for each `metadata.genesis.bitcoin`
that P carries. A read that contradicts the proof is `chain_mismatch`, and a read that
settles nothing is a skip. CHAIN ends with the KEY_EVENT_COMMITMENT row (section 10.3).

**11. SOURCES**, online. The entropy reads of section 10.4, for `/subject/entropy`, each
`/witnesses/entropy_X` and each `/observations/entropy_X/entropy`. A read that contradicts
the proof is `entropy_mismatch`.

**12. WINDOW.** The submission window, drawn and reported as section 11 says.

**13. EXPECTED_HASH**, with a hash the caller can give (in the CLI,
`--expected-hash HEX`). The step reports one row. When the caller gives no hash, it is
`skip expected_hash_not_checked`, with part null. When the caller gives one, it is at
`/subject/claims/hash`:

- it is `pass` only when the type is `item`, `/subject/claims/hash_type` is one of the
  names below, `/subject/claims/hash` is a string, and the caller's value, lowercased, is
  hex of the length the table gives for that `hash_type` and equals `/subject/claims/hash`;
- such a match, when the `hash_type` is `md5` or `sha1`, is
  `warn expected_hash_weak_algorithm` in place of `pass`, because collisions are practical
  for both, and the label does not change;
- anything else is `fail expected_hash_mismatch`, with `values` saying why: the proof has
  no `hash` of a listed type to compare, the caller's value is not hex of that type's
  length, or the two differ;
- when the attribution is not `truestamp`, the message says that the match is against a
  document not attributed to Truestamp.

After a failure at the gate or at SHAPE, the row is `skip prior_failure`, as for every
later step. No step interprets a member of `claims` but `hash` and `hash_type`; DERIVE only
hashes the object. A verifier that runs this step on a finished report MUST give the report
that the step order gives, its label, run code and edges included (step 14).

| `hash_type` | Hex characters |
|---|---|
| `md5` | 32 |
| `sha1` | 40 |
| `sha224`, `sha3_224` | 56 |
| `sha256`, `sha3_256`, `blake2s` | 64 |
| `sha384`, `sha3_384` | 96 |
| `sha512`, `sha3_512`, `blake2b` | 128 |

**14. VERDICT.** The label, attribution and window fields of section 10.5. When the label
is `failed`, VERDICT sets both edge objects to null, so `window` is `not_established`. It
reports no row.

### 10.3 Links and the key-event row

A link ties one part of a proof to another. The links and the key-event checks are made in
DERIVE (section 10.2, step 9), offline, in every run that reaches it. The key-event row,
KEY_EVENT_COMMITMENT, ends CHAIN (step 10).

**Recomputed values only.** Every walk starts from a value the verifier recomputed
(section 5.3), and every comparison of one hash with another uses the recomputed hash,
never the one the proof carries (section 10.6, rule 4, and the `checks` row of section
7.3). A verifier that walked from a carried value would accept the graft: a genuine
`block_hash`, and the genuine commitment entry that walks it into its epoch, carried beside
a block record whose `merkle_root` covers a forged item. Walking from H(0x31, record)
instead, the graft fails at `/block/block_hash`. If the forger also declares the forged
record's hash there, the epoch walk from that hash misses `epoch.record.merkle_root`.
Changing that root breaks `epoch_hash`, and changing `epoch_hash` breaks its match with
the chain's copy. Each attempt moves the failure one level up. A forger can write a new
epoch hash to a chain, but the submitted-before edge is then that later write's, and
without one of Truestamp's keys the proof is not attributed to Truestamp. A graft cannot
keep the genuine commitment's edge.

**Links.**

| Link | Rule | Part | Failure | Row of 7.3 |
|---|---|---|---|---|
| LINK_INCLUSION | each inclusion proof walks from its recomputed leaf to its record's `merkle_root`, and its `tree_size` equals the record's `leaf_count` | the record's `merkle_root`; the proof's `tree_size` | `derivation_mismatch` | `inclusion` |
| LINK_WITNESS | each `witness_hashes` entry equals the recomputed hash of its witness | `/subject/record/witness_hashes/W` | `derivation_mismatch` | `witnesses` |
| LINK_HEAD | `/witnesses/block/record/height` is below `/block/record/height` | `/witnesses/block/record/height` | `ordering_violation` | `height` |
| LINK_KEY_EVENT | the key event at `/signing_key_event/block` introduces K | that event's `public_key` | `key_event_mismatch` | `key_event` |
| LINK_CHAIN_ORDER | a Stellar entropy `sequence` is below the top-level Stellar `ledger`, and a Bitcoin entropy `height` at most the top-level Bitcoin `height`, on the same network | that `sequence` or `height` | `ordering_violation` | `chain_order` |

**LINK_INCLUSION** covers every inclusion proof, at both tree levels (section 5.4):

| Inclusion proof Q | Leaf v, recomputed | Record R |
|---|---|---|
| `/subject/inclusion_proof`, in an item | H(0x11, `/subject/record`) | `/block/record` |
| `/subject/inclusion_proof`, in an entropy type | H(0x21, `/subject/record`) | `/block/record` |
| `/observations/entropy_X/inclusion_proof` | H(0x21, `/observations/entropy_X/record`) | `/block/record` |
| `/commitments/C/inclusion_proof` | H(0x31, `/block/record`) | `/commitments/C/epoch/record` |
| `/signing_key_event/commitments/C/inclusion_proof` | H(0x31, `/signing_key_event/block/record`) | `/signing_key_event/commitments/C/epoch/record` |

Each Q reports two rows. Both name the `inclusion` row of section 7.3, which defines the
root and the size; the walk itself follows its `merkle_path` row.

1. **The root**, at R`/merkle_root`: merkle_path(v, Q) (section 5.3) MUST succeed and give
   R's `merkle_root`. A walk that fails gives no root, so it fails here too.
2. **The size**, at Q`/tree_size`: Q's `tree_size` MUST equal R's `leaf_count`, whether or
   not the walk succeeded.

The walk checks that a path fits `leaf_index` and `tree_size`, but not that `tree_size` is
the tree's true size, and the index can move with the size: the last of three leaves also
walks, with the same path, as index 1 of two (section 5.3). The committed `leaf_count`
fixes the size, and with it the leaf's position. A record whose `leaf_count` is 0, as in
every genesis and key-event block, fails every inclusion proof into it, because a walk that
succeeds has a `tree_size` of at least 1. In a `beacon`, the root rows of several
observations share the part `/block/record/merkle_root`, in the document order of their Q.

**LINK_WITNESS**, in an item. For each name W of `/subject/record/witness_hashes`, whose
names SHAPE has matched with `/witnesses`, the entry MUST equal H(0x31,
`/witnesses/block/record`) when W is `block`, and H(0x20, `/witnesses/entropy_X`) when W
is `entropy_X`. `/witnesses/block/block_hash` is checked on its own, as a block node
(section 10.2, step 9).

**LINK_HEAD**, in an item. The witness block was the head of Truestamp's chain when the
item was submitted, so its height MUST be below that of the block that includes the item.
Like every link, it never uses a declared value in place of its recomputation (section
10.6, rule 4): the height of a block record that carries `metadata.genesis`, as a genesis
`/witnesses/block` does, is 0 here (section 10.2, step 9 (b)), whatever height it declares.

**LINK_CHAIN_ORDER** pairs each Stellar or Bitcoin entropy object E that P carries, at
`/subject/entropy`, `/witnesses/entropy_X` or `/observations/entropy_X/entropy`, with the
top-level entry of its chain, `/commitments/stellar` or `/commitments/bitcoin`, when their
`network` values are equal:

- Stellar: E`/payload/sequence` MUST be below `/commitments/stellar/ledger`.
- Bitcoin: E`/payload/height` MUST be at most `/commitments/bitcoin/height`.

Every other pair reports no row, including any pair with a
`/signing_key_event/commitments` entry. The link compares chain positions only and uses
no clock (section 11). Bitcoin allows equality so that an entropy block later orphaned at
the entry's height does not fail an honest proof.

**LINK_KEY_EVENT**, when P carries `signing_key_event`. The key event at
`/signing_key_event/block/record/metadata/key_event`, which SHAPE has limited to a
`genesis`, `rotation` or `emergency_rotation`, MUST introduce K: the 32 octets its
`public_key` decodes to MUST equal the 32 octets K decodes to. Its status is set under the
key-history rows below. No order between `/signing_key_event/block` and `/block` is
checked: after a rotation, the proof of an older item is signed by a newer key.

**Key events.** Wherever a block record carries `metadata.key_event`, at any of the three
block positions, DERIVE checks the event as the table of section 3.3 requires. Which events
Truestamp's key chain accepts, and in what order, is outside this document (section 3.3).
With B the block node that carries the event, and E the event's pointer
B`/record/metadata/key_event`, every failure is `key_event_mismatch`:

| Check | Events | Part | Row of 7.3 |
|---|---|---|---|
| `public_key` passes the checks of a key's bytes (section 6.2) | `genesis`, `rotation`, `emergency_rotation` | E`/public_key` | `key_event` |
| `key_id` = the key id of `public_key` | the same | E`/key_id` | `key_event` |
| B`/record/signing_key_id` = the key id of `public_key` | the same | B`/record/signing_key_id` | `key_event` |
| `previous_key_id` = the key id of `previous_public_key` | `rotation`, `emergency_rotation` | E`/previous_key_id` | `handover` |
| `height` = B`/record/height` | the same | E`/height` | `handover` |
| `previous_block_hash` = B`/record/previous_block_hash` | the same | E`/previous_block_hash` | `handover` |
| `handover_signature` verifies strictly (section 6.2) under `previous_public_key`, over the 32 octets of H(0x62, the event without `handover_signature`) | `rotation`, and `emergency_rotation` when it has one | E`/handover_signature` | `handover` |
| B`/record/signing_key_id` = `active_key_id` | `prerotation` | B`/record/signing_key_id` | `key_event` |

- A `revocation` introduces no key, and is not checked.
- A key id is recomputed from a key's 32 octets (section 3.3), and the ids the event and
  the record carry are only compared with it.
- `previous_public_key` is only an input to the handover check (section 3.7). Its bytes
  meet steps 2 and 3 of section 6.2 as the key of the handover signature.
- The `height` and `previous_block_hash` checks bind a handover to its place in the chain.
  The handover signature covers both members, and both MUST equal those of the block
  record that carries the event, so a genuine handover copied into another block record
  fails here, even though its signature still verifies.

**The key-history rows.** LINK_KEY_EVENT and KEY_EVENT_COMMITMENT show where the signing
key came from. They state provenance, never attribution, and never feed the window
(section 11). When P carries no `signing_key_event`, neither row is reported.

- **LINK_KEY_EVENT** fails when the event does not introduce K, in every run. Otherwise it
  is `pass` when the attribution is `truestamp`, and `info not_attributable` when it is
  not.
- **KEY_EVENT_COMMITMENT** is reported when the gate opened, SHAPE passed and P carries
  `signing_key_event`. It is the last row of CHAIN, at `/signing_key_event`. Its inputs are
  the CHAIN rows under `/signing_key_event/commitments` and, for a genesis event, the CHAIN
  row of `/signing_key_event/block/record/metadata/genesis/bitcoin`. Its status is the
  first of these that applies:
  1. the external gate is closed: `skip prior_failure` if a row of POLICY or DERIVE failed,
     else `skip offline`;
  2. an input failed: `fail`, with the code of the first failing input in document order;
  3. an input was skipped: `skip`, with the code of the first skipped input in document
     order;
  4. otherwise: `pass` when the attribution is `truestamp`, else `info not_attributable`.

### 10.4 Chain and source reads

CHAIN (step 10) reads Stellar and Bitcoin for the commitment entries and `genesis.bitcoin`,
and SOURCES (step 11) reads NIST, Stellar and Bitcoin for the entropy objects. After
CONFIGURATION, they are the only steps that read anything outside the document, and they
run only when the external gate of section 10.2 is open. A row's outcome is written as its
status and its code, as in `skip offline` (section 10.5).

**Sources.** Each read goes to a source the verifier pins (section 9), and in an online run
each Stellar and Bitcoin source has its identity confirmed at step 0, before the file is
read (section 10.2):

- for a commitment entry, the source of the verifier's commitment pin for that chain, and
  for `genesis.bitcoin`, the source of its Bitcoin commitment pin;
- for a Stellar or Bitcoin entropy object, the source of the verifier's entropy pin for
  that source, whose network can differ from the commitment pin of the same chain;
- for a NIST entropy object, NIST's Randomness Beacon.

POLICY has already compared every `network` member with these pins, so the verifier's pins
decide which chain and network each read reaches, and nothing in the document does. A
network name means the network of the source pinned for it: Bitcoin's `testnet` is
whichever test network that source serves. No read checks who paid for a transaction
(section 9 pins no account or address): the edges rest on the value the transaction holds,
whoever sent it.

**Answers.** A read has one of three outcomes:

- *found*: the source returned the object asked for;
- *not found*: the source answered that it holds no such object;
- *unreachable*: there is no usable answer, because of a transport failure, a rate limit, a
  cooldown, an operator's switch that turned reads off, or an answer that does not parse,
  lacks a field the read uses, or gives such a field in another form. The row is
  `skip source_unreachable`, and no cache keeps the answer.

An answer that shows a contradiction fails the row, even when it lacks a field that another
check uses.

**Caches.** Every not-found answer MUST come from a live read, never from a cache. A found
answer MAY come from a cache of answers read on the same chain and network, and only when
the answer can no longer change: a read by hash, by Stellar ledger sequence or by NIST
pulse index. The best-chain Bitcoin block at a height g MAY come from a cache only if it was
read while the source's tip was at least g + BITCOIN_FINALITY. The Stellar root, the
Bitcoin tip and every identity read (section 10.2, step 0) are always read live. A verifier
MAY use one answer for every row of a run that needs the same read. These rules apply alike
on every network. A test network that resets can leave a cached answer stale; proofs on a
test network are for testing only.

**Stellar commitment entries.** For each entry at `/commitments/stellar` and
`/signing_key_event/commitments/stellar`, with L its `ledger`:

1. Read the source's root, for `history_latest_ledger` (latest) and `history_elder_ledger`
   (elder, the first ledger the source holds).
2. Read the transaction whose hash is `transaction_hash`.
3. If it is found, each of these MUST hold, or the row fails with `chain_mismatch`:
   - `successful` is true;
   - `memo_type` is `hash`, and the memo is the 32 bytes of H(0x40, `epoch.record`) as the
     verifier computed it, so the chain's copy also fixes the epoch's `leaf_count`
     (section 5.4);
   - the transaction is in ledger L.

   For a top-level entry, then read ledger L. Its `closed_at` is the entry's candidate for
   the submitted-before edge (section 11.1).
4. If it is not found:
   - if L > latest - STELLAR_INDEX_MARGIN, the row is `skip not_yet_indexed`;
   - if L < elder, the row is `skip not_held_by_source`, and its values name elder;
   - otherwise, read ledger L. If it is not found, the row is `skip not_held_by_source`,
     and its values name L. If it is found, the row fails with `chain_mismatch`: the source
     holds the ledger the proof names, and that ledger does not contain the transaction.

**Bitcoin commitment entries.** For each entry at `/commitments/bitcoin` and
`/signing_key_event/commitments/bitcoin`, with h its `height`:

1. Read the tip's height, t.
2. If h > t, the row is `skip not_yet_indexed`. If t < h + BITCOIN_FINALITY, the row is
   `skip chain_not_final`.
3. Read the best-chain block at height h. Its hash MUST equal the `header_hash` the
   verifier computed from the txoutproof's header, and its transaction count MUST equal the
   txoutproof's `total_txs`, or the row fails with `chain_mismatch`.
4. For a top-level entry, then read the best-chain block at height h + BITCOIN_FINALITY.
   Its median time past, the median of the header times of the BITCOIN_MEDIAN_SPAN blocks
   ending at it (the `encoding` row of section 7.3), is the entry's candidate for the
   submitted-before edge (section 11.1). A verifier MAY take it from the source's report of
   that block, such as the `mediantime` of Bitcoin Core and of Esplora.

DERIVE has already checked the carried evidence offline: the transaction and its OP_RETURN
against the computed epoch hash (section 5.4), the txoutproof, and the header against the
target its own nBits encodes (section 10.2, step 9). Item 3 is what places that header on
the best chain. A header that meets only its own target costs almost nothing to make, so a
Bitcoin entry supports no pass until item 3 holds.

**`genesis.bitcoin`.** For each `genesis.bitcoin` the proof carries, at `/block`,
`/witnesses/block` or `/signing_key_event/block`, apply items 1 and 2 of the Bitcoin rule
with h its `height`, then read the hash of the best-chain block at height h. It MUST equal
`genesis.bitcoin.header_hash`, or the row fails with `chain_mismatch`. Nothing else is read
or compared, and the read gives no edge.

**Entropy objects.** SOURCES reads each entropy object whose `entropy_hash` the verifier
recomputed and matched at DERIVE: `/subject/entropy` in an entropy proof, each
`/witnesses/entropy_X` in an item proof, and each `/observations/entropy_X/entropy` in a
beacon proof.

| Source | Read | If found, these MUST equal what was read, or `entropy_mismatch` | Candidate for the submitted-after edge | If not found |
|---|---|---|---|---|
| NIST | the pulse at `chainIndex` and `pulseIndex` | `outputValue`, `timeStamp` | the `timeStamp` read | `skip not_held_by_source` |
| Stellar | the ledger whose sequence is `sequence` | `hash`, `closed_at` | the `closed_at` read | `skip not_yet_indexed` if `sequence` > latest - STELLAR_INDEX_MARGIN, with latest from a live read of the source's root; otherwise `skip not_held_by_source` |
| Bitcoin | the block whose hash is `hash` | `height`, and `time` against the header's nTime | that block's median time past | `skip not_held_by_source` |

- Hashes compare as the bytes they spell, and times as instants.
- The Bitcoin block need not be on the best chain. An honest witness can come from a block
  that was later orphaned. That block was still mined after the blocks before it, so its
  median time past is still a sound candidate, and a source that no longer holds it gives
  `skip not_held_by_source`, never a failure.

**Rows.** CHAIN gives one row for each commitment entry and each `genesis.bitcoin`, and
SOURCES one row for each entropy object, whether or not a read was made. Each row's part is
the pointer of its entry or object, and the rows are in the order of section 10.2, CHAIN
ending with the KEY_EVENT_COMMITMENT row of section 10.3. A row passes only when every check
its rule lists held on answers this run obtained, and, for a top-level entry or an entropy
object, when its candidate was read. A read for a candidate that gives no answer leaves the
row `skip` with that read's code. A read that answers not found where the rules above give
no outcome for that answer, such as a candidate read or a read at a height the tip covers,
leaves the row `skip not_held_by_source`, and its `values` name the read: absence is no
contradiction (section 11.3). A row's `values` give what was read and, where there is one,
its candidate.

**Offline.** In an offline run (section 10.2, the external gate), a verifier:

- runs every step through DERIVE in full, so it can reject a proof on any recomputation,
  and on a CHAIN POINTER through POLICY and LINK_CHAIN_ORDER;
- reports each CHAIN and SOURCES row as `skip offline`, whose message names the read that
  would confirm it, unless a row before CHAIN failed (section 10.2, the external gate);
- draws no edge, so the submitted-before edge is not established, and a run attributed to
  Truestamp ends `internally-consistent`, never `verified` (section 10.5).

Offline checks cannot tell real chain evidence from made-up evidence. A Bitcoin header that
meets only its own target costs almost nothing to make, and a Stellar entry's memo is
unknown until it is read (section 5.4). So a CHAIN POINTER, and a PREIMAGE value that
SOURCES compares, support a CHAIN or SOURCES pass, or an edge, only after a read
(section 3.7):

| Values | Used offline by | Support a pass or an edge |
|---|---|---|
| every `network` (CHAIN POINTER) | POLICY, which compares it with the pin | never: the pin decides which network is read |
| a Stellar commitment entry's `transaction_hash` and `ledger` (CHAIN POINTER) | LINK_CHAIN_ORDER, which uses a top-level `ledger` | only after the transaction read, and the ledger read for an edge |
| a Bitcoin commitment entry's `height` (CHAIN POINTER), `raw_transaction` and `txoutproof` (PREIMAGE) | LINK_CHAIN_ORDER, which uses a top-level `height`; DERIVE, which recomputes from the bytes | only after the read of the best-chain block at `height`, and at `height` + 10 for an edge |
| `genesis.bitcoin` (CHAIN POINTER) | POLICY, which compares its `network` with the pin | only after the read of the best-chain block at its `height` |
| NIST `chainIndex` and `pulseIndex`, Stellar `sequence`, Bitcoin entropy `hash` (CHAIN POINTER) | LINK_CHAIN_ORDER, which uses a Stellar `sequence` | only after the SOURCES read they select |
| NIST `outputValue` and `timeStamp`, Stellar `hash` and `closed_at`, Bitcoin entropy `height` and `time` (PREIMAGE) | DERIVE, as inputs to `entropy_hash`; LINK_CHAIN_ORDER, which uses a Bitcoin entropy `height` | only after the SOURCES read they are compared with |

**Common sources (informative).** Each read above on the servers section 9 names:

| Read | Call, and the fields it uses |
|---|---|
| a Stellar source's identity (section 10.2, step 0) | Horizon `GET /`: `network_passphrase` |
| a Bitcoin source's identity (section 10.2, step 0) | Esplora `GET /block-height/0`; Bitcoin Core `getblockhash 0` |
| the Stellar root | Horizon `GET /`: `history_latest_ledger`, `history_elder_ledger` |
| a Stellar transaction | Horizon `GET /transactions/<hash>`: `successful`, `memo_type`, `memo` (the 32 bytes in standard base64, with padding), `ledger` |
| a Stellar ledger | Horizon `GET /ledgers/<sequence>`: `closed_at`, `hash` |
| the Bitcoin tip | Esplora `GET /blocks/tip/height`; Bitcoin Core `getblockcount` |
| the hash of the best-chain block at a height | Esplora `GET /block-height/<height>`; Bitcoin Core `getblockhash` |
| a Bitcoin block by its hash | Esplora `GET /block/<hash>`: `height`, `timestamp`, `tx_count`, `mediantime`; Bitcoin Core `getblockheader`: `height`, `time`, `nTx`, `mediantime` |
| a NIST pulse | `GET https://beacon.nist.gov/beacon/2.0/chain/<chainIndex>/pulse/<pulseIndex>`: `pulse.outputValue`, `pulse.timeStamp` |

### 10.5 Verdict and report

A bare rejection (section 10.2, the gate) gives no report and no label. Every other run
gives a report. VERDICT (step 14) computes its label and adds no row.

**Statuses.** Each row has one status:

| Status | Meaning |
|---|---|
| `pass` | the check was made, on values this run recomputed or read, and it held |
| `fail` | the check was made and found a contradiction, so the proof fails |
| `skip` | the check was not made, and its code says why; a skip is never a failure |
| `warn` | the check held, with a caution that every surface shows |
| `info` | a statement that is neither a pass nor a failure |

A fault inside the verifier is a `fail` row with the code `internal_error`, never a pass or
a skip. A fault caught before steps 0 to 3 have passed has no report to hold its row, so
the run gives no report.

**Rows.** A row is `{code, message, part, status, step, values}`:

- `code`: a reason code of section 12.1, absent exactly when the status is `pass`;
- `message`: for display only, and never compared;
- `part`: an RFC 6901 pointer into the proof, or null for a row about no single member of
  the proof;
- `status`: one of the five above;
- `step`: the name of its step (section 10.2);
- `values`: values this run computed or read, each value read with its `cached`,
  `fetched_at` and `source`, and no value the proof carries, except that a failed
  comparison also gives the declared value it contradicts, marked as declared, and in
  DERIVE the name of the constructions row that defines it.

Section 10.2 fixes which rows a run reports, their parts and their order.

**Coverage.** The rows show what the run confirmed, what it did not, and why. Once SHAPE
has passed, every commitment entry, `genesis.bitcoin` and entropy object the proof carries
has its own CHAIN or SOURCES row (section 10.4): a read that was not made is a `skip` row
with its code, never a missing row. The trace holds a row for each DERIVE row whose part
is a CHECKED value, other than the link rows section 10.6 leaves out.

**Attribution.** A report's `attribution` says whose key signed the proof, as far as this
run can tell (section 8):

| `attribution` | When |
|---|---|
| `truestamp` | KEY_BINDING and SIGNATURE passed under Truestamp's keys: Truestamp's key chain (`key_chain`), the keyring read from www.truestamp.com in this run (`current_keyring`), or the compiled pin (`compiled_pin`) |
| `keyring:<d>` | KEY_BINDING and SIGNATURE passed under a keyring the operator supplied (`supplied_keyring`), whose digest is d (section 8.3) |
| `unattributed` | the run was keyless (`none`), and SIGNATURE passed |
| `none` | ENVIRONMENT, KEY_BINDING or SIGNATURE failed |

`trust_root` is `{digest, kind, location}`. `digest` is the lowercase hex SHA-256 of the
keyring's bytes, d, or null where no keyring file was used; `kind` is `key_chain`,
`current_keyring`, `compiled_pin`, `supplied_keyring` or `none`, as section 8 assigns them;
and `location` names where the keys came from, a URL or a file, or is null.

**Labels.** A report's `label` is the first of these that applies:

| `label` | When | What it says |
|---|---|---|
| `failed` | any row is `fail` | a check failed, and the row says which |
| `unattributed` | `attribution` is `unattributed` | the proof is intact under the key it carries, which was checked against no keyring, so anyone could have made it (section 8.3) |
| `supplied-keyring` | `attribution` is `keyring:<d>` | the proof is intact and signed by a key in the keyring the operator supplied; this says nothing about Truestamp |
| `internally-consistent` | `attribution` is `truestamp`, and the submitted-before edge is not established | the proof is intact and signed by Truestamp, but no read in this run established its submitted-before edge |
| `verified` | `attribution` is `truestamp`, and the submitted-before edge is established | the proof is intact, signed by Truestamp, and places its subject's submission before an instant read from a public chain in this run |

"Passed", meaning that no row is `fail`, is internal and never output. Outside the test seam
of its test builds, Truestamp's own verifier gives only three of these labels (sections 8.2
and 13.1). A command-line verifier exits with the code section 12.2 gives for its label or
rejection.

**The report.** A report has these members:

| Member | Value |
|---|---|
| `attribution` | as above |
| `code` | the run's code (section 10.2), present exactly when `label` is `failed` |
| `environment` | E_v, the verifier's environment (section 6.4); always present |
| `label` | as above |
| `rows` | the rows, as above |
| `subject_id` | the subject's `id`: `/subject/record/id`, or `/block/record/id` for `block` and `beacon`; null until SHAPE passes |
| `submitted_after`, `submitted_before` | the two edge objects of section 11.5, both null when `label` is `failed` |
| `trust_root` | as above |
| `type` | the proof's `type`; null until SHAPE passes |
| `verified` | true exactly when `label` is `verified` |
| `window` | `established` when `submitted_before` is not null, and otherwise `not_established` |

Every surface's machine output carries `attribution`, `environment`, `label`,
`submitted_after`, `submitted_before`, `trust_root`, `verified` and `window`.

### 10.6 Declare and verify

A proof declares and a verifier verifies; it never obeys. Every value a proof carries is a
declaration, which a verifier checks against the construction this document fixes for its
position in that type of proof, and treats as its value class says (section 3.7). A
document cannot choose a construction, a prefix byte, a member set, a source, a network, a
key or an edge. A member the schema does not list for its position and type fails SHAPE
with `shape_invalid`, so an unknown or misplaced declaration is always a rejection.

**Every declared value is checked.** Every CHECKED value is recomputed from its preimage as
carried, and compared with its declared value, wherever it appears. No value is opaque. A
verifier uses any other carried value only as its class allows (section 3.7). A SUBMITTED
value is shown only as the submitter's statement. Only EXPECTED_HASH interprets one,
reading `hash` and `hash_type` from the claims, and it checks the caller's file against
that statement, never the statement as true.

**The rules.** A verifier MUST follow each of these, and each of Truestamp's verifiers has a
test for each:

1. `constructions` is read once, at SHAPE, and only compared with CONSTRUCTIONS_ACCEPTED
   (section 7.2).
2. Prefix bytes and member sets come only from the verifier's compiled constants, never
   from a document, and the leaf and node bytes 0x00 and 0x01 are used only inside the one
   walk of section 5.3. Each of Truestamp's verifiers also has a lint that forbids reading
   a prefix byte or a member set from a document value.
3. `type`, compared with the closed registry of the schema, is the only member that selects
   what runs, and it selects a whole composition of checks. Every other member that varies
   (an entropy object's `source`, a key event's `type`, the chain of a commitment entry)
   chooses only among the alternatives the schema lists for its position, and each
   alternative is checked in full.
4. Declared values are only compared. No consumer takes a declared value in place of the
   value it declares: each walk starts from a recomputed hash (section 5.3); each link, and
   each chain read, compares recomputed values, such as the recomputed `epoch_hash` or
   `header_hash`; key binding reads no carried key id; and the window takes only instants
   read in this run.
5. PINNED values are compared with their pins before anything uses them.
6. No value the proof carries is ever an edge (section 11).
7. A key-history row, LINK_KEY_EVENT or KEY_EVENT_COMMITMENT (section 10.3), passes only
   when `attribution` is `truestamp`.

**One engine and its trace.** Each verifier derives through one engine. Its trace has one
row for each DERIVE row whose part is a CHECKED value, other than a row of LINK_HEAD,
LINK_KEY_EVENT or LINK_CHAIN_ORDER, in DERIVE's order (section 10.2), so a root that three
beacon walks reach has three trace rows. Membership is fixed by check: the genesis
`height` row of step 9 (b) is a trace row, and LINK_HEAD's row is not, even though its part
is CHECKED when `/witnesses/block` is the genesis block. A trace row is:

```
{"construction": NAME, "declared": VALUE, "inputs": [POINTER, ...], "part": POINTER,
 "recomputed": VALUE, "status": "pass" | "fail"}
```

- `construction`: the name of the row of the constructions text (section 7.3) that
  defines the value;
- `declared`: the value the proof carries;
- `inputs`: the pointers of the values the check reads, for reading only;
- `part`: the part of its DERIVE row;
- `recomputed`: what the check compares `declared` with, as its table defines it: for
  example, the record's `leaf_count` for a `tree_size`, 0 for a genesis `height`, null when
  a walk gives no root, and for a `handover_signature` the hex of the 32 octets it was
  verified over;
- `status`: the status of its DERIVE row, which for a `handover_signature` is the outcome
  of Verify (section 6.2).

Each of Truestamp's verifiers gives its trace on request, and another verifier MAY give
one, in this form (section 13.1). When Truestamp's server generates a proof, it fills every
declared value with the same functions its own verifier uses to recompute it. Conformance
compares traces as section 13.1 says.

## 11. The submission window

The submission window places a subject's submission after the submitted-after edge and
before the submitted-before edge. A verifier draws both edges at WINDOW (step 12), as a
fixed function of the reads it made in this run (section 10.4), over values it recomputed.
A proof never declares a window, and no time it carries is an edge: not `header_time`, not
an entropy payload's `timeStamp`, `closed_at` or `time`, not the time inside an id, and not
`claims.timestamp`. An edge is always a value read in this run, even where SOURCES found
the carried value equal to it. The block at `/witnesses/block` gives neither edge, since no
chain or source holds its time. The verifier's clock is compared with nothing; it only
stamps `fetched_at`.

### 11.1 The submitted-before edge

Every type of proof can have a submitted-before edge. Its candidates come from the CHAIN
rows that passed for the top-level entries, `/commitments/stellar` and
`/commitments/bitcoin`, and the edge is the earliest of them. The entries at
`/signing_key_event/commitments` never give a candidate: they tell where the signing key
came from, not when the subject was submitted.

| Chain | Candidate | `basis` | Stated assumption |
|---|---|---|---|
| Stellar | the `closed_at` read for ledger `ledger` | `stellar_ledger_close_read` | Stellar validators did not set the ledger's close time behind real time; a close time set ahead of real time only makes this edge later |
| Bitcoin | the median time past read for the best-chain block at `height` + 10 | `bitcoin_median_time_read` | at least 6 of blocks height + 1 to height + 10 carry honest times |

Each candidate holds on its own. The subject is the block or is committed into it, the block
is committed into the epoch, and the epoch's hash is in a transaction that the Stellar
ledger or the Bitcoin block holds, so the subject was submitted before that ledger closed or
that block was mined. Blocks `height` + 1 to `height` + 10 were each mined after block
`height`. If at least 6 of them carry honest times, no earlier than when they were mined,
then at least 6 of the 11 header times whose median is the candidate are no earlier than
when block `height` was mined, and so is the median. Median time past is used rather than a
block's own `header_time`, because Bitcoin's two-hour rule limits only how far a header's
time runs ahead of real time, and a miner can set one well behind it.

The earliest candidate is the tightest. An edge drawn from fewer candidates, because a
read was skipped, is later but still holds.

The key that signed a proof, and the block that introduced it, have no bearing on the
window. After a rotation, the proof of an older subject is signed by a newer key and keeps
its window.

### 11.2 The submitted-after edge

Item, entropy and beacon proofs can have a submitted-after edge. A block proof has none,
and its report says so. The candidates come from the SOURCES rows that passed, for entropy
objects whose `entropy_hash` the verifier recomputed and matched, and which it read again
from their source and found equal: an item's witnesses, an entropy proof's subject, and a
beacon's observations. The edge is the latest of them.

| Source | Candidate | `basis` | Stated assumption |
|---|---|---|---|
| NIST | the pulse's `timeStamp`, read | `nist_pulse_time_read` | NIST does not release outputValue before timeStamp |
| Stellar | the ledger's `closed_at`, read | `stellar_ledger_close_read` | the network did not set the close time ahead of real time |
| Bitcoin | the median time past of the witness block, read | `bitcoin_median_time_read` | at least 6 of the 11 header times ending at that block are honest |

Each candidate holds on its own. No one could know an entropy value before its source
published it, and the subject depends on that value: an item's record holds the value's
`entropy_hash` in `witness_hashes`, an entropy proof's subject is the observation of the
value, and a beacon's block holds each observation as a leaf. The witness block and the 10
blocks before it were all mined no later than the witness block. If at least 6 of their
header times are honest, no later than when their blocks were mined, then the median is no
later than the witness block.

The latest candidate is the tightest. An edge drawn from fewer candidates is earlier but
still holds. An item with no entropy witness, and a beacon whose `observations` is empty,
have no submitted-after edge.

### 11.3 Order and absence

LINK_CHAIN_ORDER (section 10.3) checks the order of entropy objects and commitment entries
offline, with no clock.

WINDOW (step 12) gives the first of these rows that applies, with a null `part`:

1. If a row has failed, `skip prior_failure`.
2. If both edges exist and the submitted-after edge is later than the submitted-before
   edge, `fail window_inverted`.
3. If the submitted-before edge does not exist, `info window_not_established`.
4. Otherwise, `pass`.

The row's `values` give every candidate the run read, each edge that exists and, for each
edge that does not, its reason: the `part` and code of each CHAIN or SOURCES row that could
have given a candidate, a list that is empty when the proof carries none, as for a block
proof's submitted-after edge. When that row is `pass` and the time inside the subject's
`id` (`subject_id`, section 10.5) is later than the submitted-before edge, or earlier than
the submitted-after edge, WINDOW adds one row, `info recorded_time_outside_window`, at the
pointer of that `id`. The time is RECORDED, so the row informs and changes no label.

Instants compare exactly, at the precision each source gives: milliseconds for NIST and
for the time inside an id, and seconds for Stellar and Bitcoin.

Absence never fails. An offline run, an unreachable source, history a source no longer
holds, a pointer not yet indexed, or a Bitcoin tip below `height` + 10 leaves an edge
absent, with its reason, and adds no failure. Only a contradiction fails: a read that
differs from the proof (`chain_mismatch`, `entropy_mismatch`), or edges in the wrong order
(`window_inverted`).

### 11.4 Durability

A source can hold only part of a chain's history. The public Horizon that the Stellar
Development Foundation runs keeps about one year, so with default sources an older proof
whose only top-level commitment entry is Stellar's reads `skip not_held_by_source`. Its
window is not established, and it does not fail. A Horizon that keeps full history can still
establish it, and so can a proof of the same subject that carries a Bitcoin entry.

### 11.5 Display

- The report carries exactly two edge objects, `submitted_after` and `submitted_before`.
  Each is null, with its reason in the WINDOW row, or is
  `{assumption, basis, cached, fetched_at, instant, part, source}`. Both are null when the
  label is `failed` (section 10.5).
  - `assumption`: the stated assumption of its row in section 11.1 or 11.2;
  - `basis`: `stellar_ledger_close_read`, `bitcoin_median_time_read` or
    `nist_pulse_time_read`;
  - `cached`, `fetched_at` and `source`: whether the answer of the read that gave the edge
    came from a cache, when that read was made by the verifier's clock, and its source;
  - `instant`: the edge, an RFC 3339 UTC time at its source's precision;
  - `part`: the part of the CHAIN or SOURCES row whose read gave the edge, the commitment
    entry or entropy object.
- Every surface MUST draw the edges only from these two objects, captioned "Submitted
  after" and "Submitted before", and MUST NOT show a window for a run whose label is
  `failed`.
- "Read from <source> in this run" appears only when `cached` is false. Otherwise the edge
  says "read from <source> at <fetched_at>".
- Every other time appears only under "Recorded by Truestamp, not confirmed in this run"
  when `attribution` is `truestamp`, or "Declared by the signer (not attributed to
  Truestamp)" otherwise, and never with a pass status or in an edge's place.
  `claims.timestamp` appears only within the claims, as the submitter's statement
  (section 3.7).
- Attribution and window are separate statements (section 8.1). A run that is not
  attributed to Truestamp can still establish a window, which says the subject was
  submitted before that instant, never that Truestamp attested it.
- A beacon's window reads: "No one, Truestamp included, could compute this value before
  <the submitted-after edge>. Truestamp chooses the block contents and could bias it."

## 12. Reason codes and exit codes

### 12.1 Reason codes

`spec/reason-codes.json` holds the table below, and each of Truestamp's verifiers holds it
as compiled constants, with a test that they equal that file.

- Every report row that does not pass carries exactly one code from the table
  (section 10.5), and a bare rejection carries one of the four codes whose status is
  "bare". No other code is valid.
- The status "bare" marks a code that ends the run in a bare rejection (section 10.2, the
  gate). The other statuses are those of report rows (section 10.5).
- `sub_reason` is present for `malformed_json` (section 10.1) and for `invalid_envelope`
  (section 10.2, step 3), and absent otherwise.
- The run's code, which a report labelled `failed` carries (section 10.5), is chosen from
  its rows as section 10.2 says.
- Conformance compares codes exactly (section 13). A message is for display only: it is
  never compared, and nothing depends on its wording.
- The reasons Truestamp gives for declining to generate a proof are not reason codes.

The table lists the codes in step order. 34 codes.

| Code | Step | Status | Meaning |
|---|---|---|---|
| `configuration_error` | CONFIGURATION | bare | a check of step 0 fails (section 10.2): a keyring file or configured keyring fails its load checks, a run whose environment is not `prod` is not keyless and has no keyring source (section 6.4), an online run pins a network it has no source for, or a source's identity read gives a value step 0 forbids |
| `input_too_large` | READ | bare | the file is over MAX_READ_OCTETS |
| `malformed_json` | PARSE | bare | the file breaks a parsing rule of section 10.1; `sub_reason` names the rule |
| `invalid_envelope` | ENVELOPE | bare | the document is not exactly the envelope of section 3.1: a member missing or extra, `alg` other than the pin, K or V off its class, or K failing the checks of a key's bytes (section 6.2); `sub_reason` names the first check of section 10.2, step 3, that fails |
| `environment_mismatch` | ENVIRONMENT | fail | `environment` fails the check of section 6.4 |
| `keyring_unavailable` | KEY_BINDING | fail | the keyring that would govern cannot be used: Truestamp's key chain is not verified, or an external verifier's online keyring read failed, so no key binds (sections 8.2 and 8.3) |
| `key_binding_failed` | KEY_BINDING | fail | K is not in the keyring that governs (section 6.1); a revoked key is in no current keyring (section 8.1) |
| `key_binding_not_performed` | KEY_BINDING | skip | keyless mode, which the verifier states in words (section 8.3) |
| `signature_invalid` | SIGNATURE | fail | V does not verify under K over `proof_hash` (section 6.1) by the strict rules of section 6.2, including an s that is not below L |
| `unsupported_format` | SHAPE | fail | `format` is not `"truestamp-proof"` |
| `unsupported_version` | SHAPE | fail | `version` is not 1; the only signal of a later format |
| `shape_invalid` | SHAPE | fail | the proof fails a check of SHAPE other than those of `format`, `version` and the constructions digest (section 10.2, step 7) |
| `construction_mismatch` | SHAPE | fail | the constructions digest is not in CONSTRUCTIONS_ACCEPTED |
| `network_mismatch` | POLICY | fail | a `network` differs from the verifier's pin for that chain or source |
| `derivation_mismatch` | DERIVE | fail | a CHECKED value that no key-event check of section 10.3 covers differs from its recomputation (section 10.2, step 9): a record hash; a walk that fails or reaches another root; a `tree_size` that differs from its record's `leaf_count`; an `epoch_hash` that differs from the copy in the carried Bitcoin transaction; the hash a txoutproof matches, or a Bitcoin `transaction_hash`, `header_hash`, `header_merkle_root` or `header_time`; a LINK_WITNESS link |
| `bitcoin_evidence_invalid` | DERIVE | fail | a `raw_transaction` or `txoutproof` that is not well formed, including a header hash above the target its own nBits encodes (section 10.2, step 9) |
| `key_event_mismatch` | DERIVE | fail | a key event fails a check of section 10.3 (its ids, its position, its handover signature, or the checks of its `public_key`'s bytes), or the event at `/signing_key_event/block` does not introduce K (LINK_KEY_EVENT) |
| `ordering_violation` | DERIVE | fail | LINK_HEAD or LINK_CHAIN_ORDER fails (section 10.3) |
| `not_attributable` | DERIVE, CHAIN | info | on LINK_KEY_EVENT or KEY_EVENT_COMMITMENT, in place of `pass` when the attribution is not `truestamp` |
| `offline` | CHAIN, SOURCES | skip | no read was made in this run; the message names the read that would confirm the row |
| `chain_mismatch` | CHAIN | fail | a chain read contradicts the proof (section 10.4) |
| `source_unreachable` | CHAIN, SOURCES | skip | the source gave no usable answer (section 10.4) |
| `not_held_by_source` | CHAIN, SOURCES | skip | the source does not hold the value, and its absence is no contradiction |
| `not_yet_indexed` | CHAIN, SOURCES | skip | the value lies beyond the source's indexed tip, or within STELLAR_INDEX_MARGIN of it |
| `chain_not_final` | CHAIN | skip | the Bitcoin tip is below `height` + BITCOIN_FINALITY |
| `entropy_mismatch` | SOURCES | fail | the pulse, ledger or block read differs from the entropy object |
| `window_not_established` | WINDOW | info | no submitted-before edge was drawn; `values` give the reason for each absent edge |
| `window_inverted` | WINDOW | fail | the submitted-after edge is later than the submitted-before edge |
| `recorded_time_outside_window` | WINDOW | info | the time in a subject's id lies outside an established window |
| `expected_hash_mismatch` | EXPECTED_HASH | fail | the caller gave a hash, and the proof has no `claims.hash` of a listed type to compare it with, or the caller's hash is not hex of that type's length, or it differs from `claims.hash` (section 10.2, step 13) |
| `expected_hash_weak_algorithm` | EXPECTED_HASH | warn | the caller's hash matched, and `claims.hash_type` is `md5` or `sha1`, whose collisions are practical |
| `expected_hash_not_checked` | EXPECTED_HASH | skip | no expected hash was given |
| `prior_failure` | any step after a failure | skip | a row it depends on failed: every later step up to EXPECTED_HASH after a failure at steps 4 to 7 (section 10.2); a CHAIN or SOURCES row, KEY_EVENT_COMMITMENT included, after a failed row before CHAIN (the external gate of section 10.2); and the WINDOW row after any failed row (section 11.3) |
| `internal_error` | any step from ENVIRONMENT on | fail | a fault in the verifier (section 10.5) |

### 12.2 Exit codes

`spec/exit-codes.json` holds this table. A verifier with a command line, such as
Truestamp's CLI and the reference verifiers in this repository, exits with the code for how
its run ended:

| Code | The run |
|---|---|
| 0 | label `verified` |
| 1 | a runtime error outside verification, such as an invalid command line or an input that cannot be read; no report |
| 2 | the verifier stopped on a fault it did not catch, or caught one before steps 0 to 3 passed; no report |
| 3 | label `failed` |
| 4 | a bare rejection other than `configuration_error` |
| 5 | label `unattributed` |
| 6 | label `supplied-keyring` |
| 7 | label `internally-consistent` |
| 8 | `configuration_error` |

- Only 0 says that Truestamp signed the proof and that its submission window is
  established. A script that needs both checks for 0 alone.
- A fault the verifier catches from ENVIRONMENT on is an `internal_error` row, so the run's
  label is `failed` and it exits 3. A fault it catches earlier has no report to hold its
  row, so the run gives no report, and it exits 2.
- Truestamp's own verifier has no command line and no exit code (section 8.2).

## 13. Conformance

### 13.1 What a verifier passes

- A verifier conforms to this document when it gives the expected output for every case in
  `vectors/cases.json` that applies to it. Every offline case applies to every verifier. An
  online case applies to a verifier that makes the reads its replay answers, so the
  reference verifiers in this repository run the offline cases only.
- **Truestamp's own verifier** runs the cases through a test seam, which gives its engine
  the case's configuration exactly as an external verifier takes it. A keyring path or
  `test` is a supplied keyring (`keyring:<d>`), `none` is keyless mode, an absent `keyring`
  is no keyring option, and `unavailable` is an unverified key chain, so every verifier
  gives the same rows for a case. The seam exists only in test builds. In every build
  Truestamp deploys, no request, configuration file or environment variable can replace
  the key chain, choose keyless mode, supply a keyring or set E_v (section 8.2).
- **What is compared.** For a bare rejection, `code`, and `sub_reason` when the code has
  one; each such case breaks one rule, so its `sub_reason` is fixed. Otherwise, the report's `label`, and its
  rows, each reduced to `(code, part, status, step)`, in order: all of them, passes and
  skips included. For an online case, also each edge's instant and basis, or the edge's
  absence. Messages and `values` are never compared, and neither is an exit code, which
  each command-line verifier tests itself (section 12.2).
- **Traces.** Each of Truestamp's verifiers gives its trace (section 10.6) and matches each
  sound case's trace. Another verifier MAY give one, in the same form, and then MUST match
  it. Trace rows are compared in order, each member but `inputs`.
- **Every code.** Every reason code of section 12.1 except `internal_error` has at least one
  case, and each code whose status is "bare" or `fail` has a single-defect case.
  `internal_error` has none: it marks a fault in the verifier, which no input causes in a
  conforming one.
- **Citation.** A claim of conformance names the commit of this repository and the digest
  of `MANIFEST.sha256` whose cases the verifier passed.
- **Beyond the vectors.** Each of Truestamp's verifiers also has the tests that sections 4,
  7.2, 7.3, 10.6 and 12.1 name, and a test that its compiled constants, exit codes and
  accepted constructions digests equal the files under `spec/`. The agent-sufficiency test
  of section 7.4 is separate: it tests the constructions text, not a verifier.

### 13.2 The vectors

These files are under `vectors/`, and `MANIFEST.sha256` holds the digest of each:

| Path | Holds |
|---|---|
| `cases.json` | every case: its proof, its configuration and its expected output |
| `keyring.test.json` | a keyring in the form of section 10.2, step 0, whose one key is VECTOR_KEY, so it is valid only when the verifier's environment is `test` |
| `worked-example.json` | the values of section 6.3, one member each: `proof` (the input), `M`, `proof_hash`, `sk` (in hex), `A`, `K`, `key_id` (the key id of A), `S`, `V` and `document` (the served document) |
| `positive/` | the sound proofs of section 13.3, each as `<name>.proof.json` with its trace as `<name>.trace.json`, where `<name>` is the proof's type, or its type, a hyphen and a variant, such as `beacon-empty`, `block-rotation` or `item-genesis-witness`; a proof file is in the served form of section 3.1, JCS(envelope) in UTF-8 with no final newline, so it is not always ASCII; a trace file is in the canonical form of section 9 |
| `negative/` | each proof and each keyring a case supplies that no other file holds, as `<id>.proof.json` or `<id>.keyring.json`, where `<id>` is the id of a case that uses it; each file is in its usual form, the served form for a proof and the canonical form for a keyring, unless the case concerns the file's bytes (a defect, a reformatting or a size) |
| `corpus/` | known answers for JCS, strict Ed25519 (section 6.2) and base64url; real Bitcoin transactions, merkleblocks and headers for the parsers of section 10.2; and the recorded chain, source and keyring responses that online cases replay |

`cases.json`, `keyring.test.json` and `worked-example.json` are in that canonical form too.

`cases.json` is an array of cases, and the order of the cases carries no meaning. A case
holds:

| Member | Holds |
|---|---|
| `config` | `environment`: the verifier's environment; `expected_hash`, OPTIONAL; `keyring`, OPTIONAL: `test` (`keyring.test.json`), `none` (keyless mode), `unavailable`, or the path of a keyring file, and absent when neither a keyring nor keyless mode is asked for; `networks`: `{commitment, entropy}`, the commitment pin per chain and the entropy pin per source, each an object from the chain's or the source's name to its network; `online`, OPTIONAL: the path of a replay file under `corpus/` |
| `expected` | for a bare rejection, `code`, and `sub_reason` when the code has one; otherwise the report's `label` and `rows`, with `trace`, the path of a trace file, for a case that gives a sound proof's trace, and for an online case its two edges |
| `id` | a name unique in the file |
| `proof` | the path of its proof |

Every path a case holds is relative to `vectors/`.

- A case without `online` runs with the verifier asked to be offline. An online case
  answers each read its replay file holds, of a chain, a source or a keyring, from that
  file in place of the network. The replay file stands as the operator-pinned source for
  each chain and network it answers, so a case that pins such a network, `regtest`
  included, has a source for it (section 10.2, step 0).
- A case whose keyring is `unavailable` is online and runs under `prod`, on an unmarked
  proof signed by VECTOR_KEY. The verifier is given no keyring option, and the replay fails
  its default keyring read at www.truestamp.com. For Truestamp's own verifier, `unavailable`
  is an unverified key chain (section 13.1).
- Every proof in the vectors is marked `test` and signed by VECTOR_KEY, unless its case
  says otherwise (section 6.4).
- There are no Merkle vectors here. The tree's known answers are the Merkle library's
  `vectors/merkle.json` (section 5.1), and the proofs here exercise inclusion proofs inside
  real proofs.
- `generator/generate.exs` writes the vectors. It shares no code with any verifier and has
  its own Merkle walk, so a defect in one cannot hide in both. With `--check` it writes
  nothing: it regenerates every file in memory and compares bytes with the files on disk,
  fails on any file under `vectors/` it does not write and on any entry there that is
  neither a regular file nor a directory, and asserts that section 6.3's
  worked example equals `worked-example.json`. Once the reference verifiers in this
  repository exist, `--check` also runs them over `cases.json`.

### 13.3 The cases

A **single-defect case** makes one check fail and every other check pass. It changes a
sound proof, adjusts every other value so that no other check fails, and signs the result
again with its key, unless the case says it is not signed again. Its part is where
section 10 reports that check. Each class below says what its cases assert.

- **Sound proofs.** Each sound proof passes offline with the keyring `test`: no row fails,
  and the trace matches. Among them are an item with all three witnesses and both
  chains, whose claims hold an md5 `hash`, a `timestamp`, a `nonce`, the numbers 37.7749,
  1e-7 and 5e-324, member names that sort differently by UTF-16 code unit than by code
  point (U+FF5A against U+1F600), and quotes and backslashes; a block proof of the genesis
  block, whose tree is empty (`leaf_count` 0 under the empty root, the accepting side of
  the rule of section 5.4); a proof whose `signing_key_event` block is a rotation with
  `previous_public_key`, `handover_signature` and Bitcoin evidence; a proof of an older
  item signed by the key a later rotation introduced, since no order between the key-event
  block and `/block` is checked; a beacon with three observations and a beacon with none;
  and a subject alone in its block, whose proof is
  `{"leaf_index": 0, "path": [], "tree_size": 1}`.
- **Sameness.** Each sound proof re-indented, with CRLF line ends, a trailing newline,
  members reordered, strings escaped and `1.0` for an integer gives exactly the original's
  rows and trace (section 3.1). Each sound proof in the reference mode and in mode `none`
  gives the original's verdict (section 7.2). `1e-400` in claims is read as 0 and passes.
  A sound proof padded with whitespace to exactly MAX_READ_OCTETS passes, and so does a
  sound item whose claims nest the document to a depth of exactly MAX_DEPTH.
- **READ.** A file of MAX_READ_OCTETS + 1 octets is the bare rejection `input_too_large`.
- **PARSE.** The bare rejection `malformed_json`, with its `sub_reason`: a second `proof`
  member, a duplicate inside `proof`, and a duplicate that differs only in its escapes
  (`duplicate_name`); a lone surrogate escape (`lone_surrogate`); invalid UTF-8
  (`invalid_utf8`); a byte-order mark, and content after the JSON text (`syntax`); the
  integer literals 2^53 and 2^60, `9007199254740992.0`, `9007199254740993e0` and `1e16`,
  and `1e400`, which overflows (`number`); nesting 33 deep (`depth`).
- **ENVELOPE.** The bare rejection `invalid_envelope`, with its `sub_reason`: a document
  that is an array, a member missing or extra in the document, and a `signatures` array in
  place of `signature` (`document`); a `proof` that is not an object (`proof`); a member
  missing or extra in `signature` (`signature`); an `alg` of `Ed25519`, of `EdDSA`, or of
  the pin in other letter case (`alg`); a K or V padded, in the standard alphabet, with
  unused bits set, or with a `\n` escaped onto its end (`public_key` or `value`); and each
  of SMALL_ORDER_KEYS as K, the identity among them, and a K whose y is not below
  2^255 - 19, each with the signature (identity, 0) as V (`public_key`).
- **CONFIGURATION.** The bare rejection `configuration_error`: a keyring holding VECTOR_KEY
  when the verifier's environment is not `test`; a keyring, under `prod`, holding a key of
  `spec/keys.nonproduction.json`; a non-production run that is not keyless and has no
  keyring source (a case with no `keyring`); keyrings that break a load check of section
  10.2, step 0 (a repeated key, a wrong `key_id`, a small-order key, an extra member); and,
  online, a network pinned with no source for it (regtest, which its replay does not
  answer), a source pinned to `public` or `mainnet` whose identity read gives another value,
  and a source pinned to another network whose identity read gives its chain's production
  value.
- **ENVIRONMENT.** `environment_mismatch`: a proof marked `staging` under `prod`; a proof
  with no `environment` under `staging`; an `environment` of `prod`, `production`, `null`
  or a number; and, under `test`, a `test` marker with a `\n` escaped onto its end.
- **KEY_BINDING.** A sound proof signed by a key the keyring lacks fails
  `key_binding_failed`. The keyring `unavailable`, online under `prod`, gives
  `keyring_unavailable` (section 13.2). The keyring `none` gives
  `skip key_binding_not_performed`, the attribution `unattributed`, and otherwise the sound
  proof's rows.
- **SIGNATURE.** `signature_invalid`: a signature over M itself, over SHA-256(M), and over
  the hash of the proof under another signed kind's byte (0x31 or 0x62); an s equal to L,
  and s + L in place of s; `environment` removed or changed after signing, under an
  environment that passes step 4; and K copied from `keyring.test.json` over consistent
  content signed by another key, with the keyring `test` and with none. The cases that
  change `environment` run keyless, since only a run whose environment is `test` may load a
  keyring holding VECTOR_KEY.
- **Mixed-order agreement.** A K that is a valid key plus a point of order 8 passes keyless
  when the challenge k is 0 modulo 8, and fails `signature_invalid` otherwise, in every
  verifier (section 6.2).
- **SHAPE.** `unsupported_format` for another `format`, and `unsupported_version` for a
  `version` other than 1. `construction_mismatch` for a full text with one byte changed,
  with a row missing, or with the two node orders of its `merkle_path` row swapped, and for
  a reference URL whose digest is not accepted. `shape_invalid` for a reference URL on
  another host; an uppercase hash; a `\n` escaped onto the end of any value of a pattern
  class in `proof` other than `environment`; any OPTIONAL member other than `environment`
  as `null`; an observation whose source differs from its type or its name; `witnesses`
  names that differ from `witness_hashes`; a TIME of `24:00:00`, of February 30, or with 60
  seconds; and a `path` of 33 nodes.
- **The empty-root rule (section 5.4).** At each of `/block`, `/witnesses/block` and
  `/signing_key_event/block`, a block record with leaves under the empty root (`leaf_count`
  1 or more) and a block record with no leaves under another root (`leaf_count` 0) each
  fail `shape_invalid` at SHAPE, at that record's `merkle_root`. These are six cases, and
  none needs a walk or a chain read to be rejected.
- **POLICY.** One `network_mismatch` case for each `network` member: in each commitment
  entry at both positions, in each entropy object, and in `genesis.bitcoin`, each against
  the case's pins.
- **Declared values.** One case for each CHECKED value that no key-event check of section
  10.3 covers: the value replaced fails `derivation_mismatch` at its own pointer. So do one
  character of `claims` changed, at `/subject/record/claims_hash`, and a beacon observation
  that is not a leaf of its block, at `/block/record/merkle_root`.
- **Paths.** A `path` node changed, and a `leaf_index` changed so that the walk takes
  another route, each fail `derivation_mismatch` where the walk ends:
  `/block/record/merkle_root` for a subject or an observation, and the entry's
  `epoch/record/merkle_root` for a commitment entry. A `leaf_index` at or past `tree_size`,
  and a `path` one node too long or too short, fail there too, because the walk gives no
  root.
- **The committed leaf count (section 5.4).** At the block level, for a subject and for a
  beacon observation, and at the epoch level, for each chain's entry at both positions:
  - a `tree_size` other than its record's `leaf_count`, whose walk still reaches the root,
    fails `derivation_mismatch` at that `tree_size`; at `/signing_key_event`, where no other
    `tree_size` fits the leaf in its place, these cases first reorder the epoch's leaves;
  - a moved leaf index, the last of three leaves presented as `{"leaf_index": 1,
    "tree_size": 2}` with the same path, whose walk reaches the same root, fails there too;
  - the same lie carried into the record, with the record's hash recomputed: at the block
    level it fails `derivation_mismatch` where each epoch walk from the new `block_hash`
    misses its root; at the epoch level a Bitcoin entry fails `derivation_mismatch`
    offline at its `raw_transaction`, where the new `epoch_hash` differs from the copy the
    transaction holds, and a Stellar entry passes DERIVE and then, online, fails
    `chain_mismatch`, where the memo differs.
- **The graft (section 10.3).** A genuine `block_hash` and Stellar entry kept beside a
  block record whose `merkle_root` covers a forged item, run keyless and signed with a key
  of the case's own, fails `derivation_mismatch` at `/block/block_hash`, and its epoch walk
  from the forged record's hash fails too, with no window. With `block_hash` declared as the
  forged record's hash, it fails only at `/commitments/stellar/epoch/record/merkle_root`,
  where that epoch walk misses the genuine root.
- **Key events.** `key_event_mismatch`, at the part section 10.3 gives each check: a
  handover signature altered and not signed again, at the event's `handover_signature`; a
  wrong `previous_key_id` or `key_id`, at that member; a genesis or rotation block record
  whose `signing_key_id` is not the key id of the event's `public_key`, at the record's
  `signing_key_id`; a prerotation whose `active_key_id` differs from the record's
  `signing_key_id`, at the record's `signing_key_id`; a rotation whose
  `previous_public_key` is the identity, with the handover (identity, 0), at the event's
  `handover_signature`; and a `/signing_key_event/block` whose event introduces a key other
  than K (LINK_KEY_EVENT), at that event's `public_key`.
- **A handover whose position differs (section 3.3).** A rotation event whose handover
  signature is valid, carried in a block record whose `height`, or whose
  `previous_block_hash`, differs from the event's. Each of the two fails
  `key_event_mismatch` at the event's `height` or `previous_block_hash`, at
  `/signing_key_event/block` and at the `/block` of a block proof. They show that a
  handover cannot be moved to another place in the chain.
- **A self-signed key event.** A proof signed by a new key, whose `signing_key_event` block
  carries a genesis event introducing that key, run keyless and offline, gives
  `info not_attributable` at LINK_KEY_EVENT and `skip offline` at KEY_EVENT_COMMITMENT: a
  key event never makes a key Truestamp's.
- **Order.** `ordering_violation`: a witness block at or above the height of `/block`
  (LINK_HEAD); a Stellar entropy `sequence` at or above the top-level Stellar `ledger`, and
  a Bitcoin entropy `height` above the top-level Bitcoin `height`, on the same network
  (LINK_CHAIN_ORDER). A Bitcoin entropy `height` equal to the top-level Bitcoin `height`
  passes.
- **Bitcoin evidence.** An OP_RETURN that pushes another value, with `transaction_hash`
  recomputed, fails `derivation_mismatch` at `/commitments/bitcoin/raw_transaction`, and in
  a separate case at `/signing_key_event/commitments/bitcoin/raw_transaction`.
  `bitcoin_evidence_invalid`: a transaction of exactly 64 octets; a transaction with no
  input; a transaction with two output scripts that begin with 0x6a, and one whose only
  such script is not exactly 0x6a 0x20 and 32 bytes, each at its `raw_transaction`; bytes
  after the transaction or after the merkleblock; a duplicate sibling pair in the partial
  tree; an unused hash or flag bit; `total_txs` of 0 and of BITCOIN_MAX_TOTAL_TXS + 1; a
  header hash above the target its nBits encodes; and an nBits that overflows or is
  negative. A transaction with an input and an exact OP_RETURN output is at least 94
  octets, so the OP_RETURN rule implies the 64-octet rule, and the 64-octet case also lacks
  an OP_RETURN. The 64-octet rule stays, as the guard against CVE-2017-12842.
- **Chain and source reads.** Online, each outcome of section 10.4 from a replay: a Stellar
  entry found and matching, which passes and gives its candidate edge; a memo that
  differs, a transaction that did not succeed, and another ledger (`chain_mismatch`); a
  transaction not found, in each branch of section 10.4 (`not_yet_indexed`;
  `not_held_by_source` below elder, and for a ledger between elder and latest that the
  source does not hold; `chain_mismatch` for a ledger it holds); a candidate read that
  answers not found (`not_held_by_source`); `source_unreachable` for HTTP 429 and 503, for
  an answer that lacks a field the read uses, and on every row a source serves when its
  identity read gets no usable answer; a Bitcoin tip below `height` (`not_yet_indexed`) and
  below `height` + BITCOIN_FINALITY (`chain_not_final`); a best-chain header hash or
  transaction count at `height` that differs, and a `genesis.bitcoin` header hash that
  differs (`chain_mismatch`); for each entropy source, a value that differs
  (`entropy_mismatch`) and a value not found; and KEY_EVENT_COMMITMENT passing, giving
  `info not_attributable` when the run is not attributed to Truestamp, and failing or
  skipping with its first input's code.
- **The window (section 11).** Online: both edges drawn, each case giving their instants
  and bases; the submitted-after edge later than the submitted-before edge
  (`window_inverted`), whose report, labelled `failed`, carries neither edge; the time in a
  subject's id outside an established window (`info recorded_time_outside_window`); and a
  block proof, which has no submitted-after edge. Offline, every sound case gives
  `info window_not_established`.
- **Gates.** After a failure at steps 4 to 6, or at SHAPE, each later step is one row
  `skip prior_failure` with part null. After a failure in POLICY or DERIVE, each online row
  is `skip prior_failure`.
- **EXPECTED_HASH.** A different hash, a hash of the wrong length, and a hash given for a
  proof that is not an item or for an item whose claims have no `hash` of a listed type,
  each fail `expected_hash_mismatch` at `/subject/claims/hash`. A matching hash in capitals
  passes, since the caller's value is lowercased. An md5 match and a sha1 match give
  `warn expected_hash_weak_algorithm`. A run given no hash gives
  `skip expected_hash_not_checked`.
