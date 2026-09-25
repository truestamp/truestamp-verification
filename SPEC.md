<!--
Copyright (c) 2026 Truestamp, Inc.
SPDX-License-Identifier: Apache-2.0
-->

# Truestamp proof specification

**Status:** draft, and not yet normative. Sections 1 to 5, 7.1 to 7.3 and 9 are written,
and the other sections are an outline. The whole text is under review until it is fixed.
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
| MERKLE_PROOF | the closed object of section 5.2 (*Proposed*) | every `inclusion_proof` |
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
| NETWORK | Stellar `public` or `testnet`; Bitcoin `mainnet`, `testnet3`, `testnet4` or `regtest` (never plain `testnet`) | every `network` |
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
| RFC 8785, the JSON Canonicalization Scheme (JCS) | every record hash and the signed digest |
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

  There is no second signature, key id, digest or context member.
- **Served form.** Truestamp serves JCS(envelope) as UTF-8 with no trailing newline, at
  most 65,536 octets (MAX_DOCUMENT_OCTETS), with the media type
  `application/vnd.truestamp.proof+json` and the file extension `.proof.json`. A verifier
  MUST accept any formatting of the same JSON value that the parsing rules of section 10.1
  allow.
- **Identity.** A proof is identified by its digest, SHA-256(0x60 || JCS(proof)), never by
  the bytes of a file or by its signature string.
- **Sameness.** Files that differ only in formatting, within the parsing rules of
  section 10.1, verify alike, and two proofs are the same exactly when their digests are
  equal. Two files that verify with the same
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
the proof digest, a download variant, a close time for any commitment's ledger or block,
the intermediate hashes a walk computes, or the chain of blocks between `/witnesses/block`
and `/block`.

### 3.3 Block node, key events and genesis

A BLOCK_NODE appears at `/block`, `/witnesses/block` and `/signing_key_event/block`:

```
{
  "block_hash": HEX64,             // CHECKED = H(0x30, record); for type beacon, the beacon value
  "record": {
    "height": INT,                 // 0 at genesis, then one more per block
    "id": UUID7,
    "leaf_count": INT,             // Proposed: the number of leaves under merkle_root (section 5.4)
    "merkle_root": HEX64,          // at /block, the inclusion target
    "metadata": {} | {"key_event": KEY_EVENT} | {"genesis": GENESIS, "key_event": KEY_EVENT},
    "previous_block_hash": HEX64,  // at genesis, CHECKED = H(0x31, metadata.genesis)
    "signing_key_id": KID          // preimage input only; never selects or validates the signer
  }
}
```

A KEY_EVENT is one of these, by its `type`:

| `type` | Members | Checked wherever it appears |
|---|---|---|
| `genesis` | `key_id`, `prerotation_commitment` (O), `public_key`, `sequence` (0), `type` | `key_id` = the key id of `public_key` = `record.signing_key_id` |
| `rotation` | `handover_signature`, `key_id`, `prerotation_commitment` (O), `previous_key_id`, `previous_public_key`, `public_key`, `reason` (ASCII128), `sequence` (at least 1), `type` | as `genesis`, plus `previous_key_id` = the key id of `previous_public_key`, and `handover_signature` verifies under `previous_public_key` |
| `emergency_rotation` | as `rotation`, with `handover_signature` O | as `rotation`, the signature when present |
| `prerotation` | `active_key_id`, `prerotation_commitment`, `type` | `record.signing_key_id` = `active_key_id`; introduces no key |
| `revocation` | `revoked_key_id`, `type` | introduces no key |

- A key's **key id** is the hex of the first 4 bytes of SHA-256(0x51 || its 32 bytes).
  `prerotation_commitment` is the hex of SHA-256(0x52 || the next key's 32 bytes).
- The **handover signature** is Ed25519 by `previous_public_key` over the 32 bytes of
  H(0x50, the event without `handover_signature`), so the outgoing key endorses every other
  member.
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

An EPOCH_NODE (*Proposed*) mirrors a BLOCK_NODE: a record and its hash.

```
{
  "epoch_hash": HEX64,             // CHECKED = H(0x80, record); the value written to the chain
  "record": {
    "leaf_count": INT,             // the number of leaves under merkle_root (section 5.4)
    "merkle_root": HEX64           // CHECKED = the walk from the block's RECOMPUTED block_hash
  }
}
```

```
"bitcoin": {                        // present only once final: the tip at height + 10 when captured
  "epoch": EPOCH_NODE,              // Proposed. epoch.epoch_hash is the value in the OP_RETURN output (section 5.4)
  "header_hash": HEX64,             // CHECKED = rev(SHA-256d(first 80 octets of txoutproof))
  "header_merkle_root": HEX64,      // CHECKED = rev(header Merkle root field)
  "header_time": TIME,              // CHECKED = header nTime; display only, never an edge
  "height": INT,                    // chain pointer
  "inclusion_proof": MERKLE_PROOF,  // Proposed. Walked from the RECOMPUTED block_hash of the block beside these commitments to epoch.record.merkle_root
  "network": NETWORK,
  "raw_transaction": HEXBYTES,      // non-witness serialization, at least one input
  "transaction_hash": HEX64,        // CHECKED = rev(SHA-256d(raw_transaction)); also a chain pointer
  "txoutproof": HEXBYTES            // BIP 37 merkleblock as bitcoind emits it
},
"stellar": {
  "epoch": EPOCH_NODE,              // Proposed. epoch.epoch_hash equals the transaction's hash memo
  "inclusion_proof": MERKLE_PROOF,  // Proposed. Walked from the RECOMPUTED block_hash to epoch.record.merkle_root
  "ledger": INT,                    // chain pointer
  "network": "public" | "testnet",
  "transaction_hash": HEX64         // chain pointer
}
```

### 3.5 Entropy objects

An ENTROPY_OBJECT, at `/subject/entropy`, `/witnesses/entropy_X` and
`/observations/entropy_X/entropy`, is exactly the preimage of its `entropy_hash`,
H(0x21, object):

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
    "inclusion_proof": MERKLE_PROOF,    // Proposed. Walked from the RECOMPUTED item_hash to /block/record/merkle_root
    "item_hash": HEX64,                 // CHECKED = H(0x10, record)
    "record": {"claims_hash": HEX64,    // CHECKED = H(0x11, claims)
               "id": ULID,
               "witness_hashes": {"block": HEX64, "entropy_bitcoin": HEX64, "entropy_nist": HEX64, "entropy_stellar": HEX64}}
  },                                    // witness_hashes: block R; each entropy_X present iff that source had a current observation
  "witnesses": {"block": BLOCK_NODE, "entropy_X": ENTROPY_OBJECT, ...}   // WITNESSES: exactly the names of witness_hashes

entropy_nist | entropy_stellar | entropy_bitcoin: the common members, plus
  "subject": {"entropy": ENTROPY_OBJECT,          // OBSERVATION_SUBJECT; its source matches the type
              "inclusion_proof": MERKLE_PROOF,    // Proposed. Walked from the RECOMPUTED observation_hash
              "observation_hash": HEX64,          // CHECKED = H(0x20, record)
              "record": {"entropy_hash": HEX64, "id": UUID7}}   // entropy_hash CHECKED = H(0x21, entropy)

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
| CHECKED | `claims_hash`, `item_hash`, `entropy_hash`, `observation_hash`, every `block_hash`; the genesis `previous_block_hash`; `witness_hashes` entries; `/block/record/merkle_root` where the `inclusion_proof` of the subject or of an observation walks to it; every `epoch_hash` and every epoch's `record.merkle_root`; every `inclusion_proof` `tree_size` (section 5.4); Bitcoin `transaction_hash`, `header_hash`, `header_merkle_root`, `header_time`; `key_id` where an event introduces a key, and `signing_key_id` where an event introduces a key or is a prerotation; `previous_key_id`, `handover_signature` | recomputed and compared |
| PATH INPUT | every MERKLE_PROOF `path` node and `leaf_index` | bound by the walk |
| PREIMAGE | `/block/record/leaf_count` and every epoch's `record.leaf_count`; `/block/record/merkle_root` in a `block` proof and in a `beacon` proof with no observations; the key-event `type` and `public_key`, and a prerotation's `active_key_id`; `raw_transaction`, `txoutproof`; every entropy `source`, and the payload values SOURCES compares (NIST `outputValue`, `timeStamp`; Stellar `hash`, `closed_at`; Bitcoin entropy `height`, `time`) | input to a CHECKED hash or a named check; a payload value is compared with its source only after a read |
| CHAIN POINTER | Stellar `transaction_hash`, `ledger`; Bitcoin commitment `height`; every `network`; NIST `chainIndex`, `pulseIndex`; Stellar `sequence`; Bitcoin entropy `hash`; `genesis.bitcoin` | may cause an offline rejection (POLICY, LINK_CHAIN_ORDER), but supports a pass or an edge only after a read made during verification |
| BLOCK HEIGHT | every `record.height` | 0 at genesis (CHECKED); otherwise used only by LINK_HEAD |
| SUBMITTED | `subject.claims` | bound by `claims_hash`; shown only as the submitter's statement, with bidirectional and zero-width characters escaped |
| RECORDED | ids and their times; the other `previous_block_hash`, `merkle_root`, `leaf_count` and `signing_key_id` values; `prerotation_commitment`, `previous_public_key` (only an input to the handover check), `sequence`, `reason`, `revoked_key_id`; NIST `version`; which observation a beacon carries | never a verdict input except where a row above uses it; shown under a provenance heading chosen by attribution |

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
  `tree_size` 16 and 64); `leaf_count` 8 in every block record, and in every epoch record
  the `tree_size` of its entry's proof; a 137-octet raw transaction and a 506-octet
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
  other integer 16 digits; a 16-character NIST `version`; `testnet` and `testnet4`.

| Proof | Typical, full | Typical, reference | Typical, none | Worst, full |
|---|---|---|---|---|
| item | 14,822 | 7,292 | 7,152 | 53,860 |
| entropy_nist | 13,552 | 6,022 | 5,882 | 31,633 |
| entropy_stellar | 13,460 | 5,930 | 5,790 | 31,513 |
| entropy_bitcoin | 13,440 | 5,910 | 5,770 | 31,501 |
| block | 12,765 | 5,235 | 5,095 | 28,848 |
| beacon | 14,934 | 7,404 | 7,264 | 36,963 |

For items, the served size is at most 33,380 + |JCS(claims)| octets in full mode (25,850 by
reference, 25,710 with none), plus at most 24 octets for `"environment":"staging",`. The
worst staging item is 53,884 octets, under MAX_DOCUMENT_OCTETS, so every committed subject
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
- **Signing.** A kind marked signed is signed with Ed25519 over the 32 bytes of H(p, R).
  The signer takes a kind and a record and computes H itself; it refuses unsigned kinds and
  never signs bytes a caller hands it. So a signature for one kind never verifies for
  another, and the proof is signed like every other record. The active key signs, except
  that a block is signed by the key the chain assigns it (a rotation block by the key it
  introduces) and a handover by the outgoing key.

**Outside the rule.**

- **Merkle leaf 0x00 and node 0x01:** SHA-256(0x00 || v) and SHA-256(0x01 || l || r), over
  the 32 bytes each hex value spells. These are the hash primitives of RFC 9162
  section 2.1.1, used as section 5 of this document describes, and every leaf value is
  itself a record hash. The root of the empty tree, SHA-256 of zero
  bytes, has a 0-byte preimage, so it cannot collide with a 33-byte leaf or a 65-byte node
  preimage.
- **Key id 0x51 and prerotation commitment 0x52:** SHA-256 over the 32 raw key bytes, so
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

- The high nibble is the family. The low nibble counts kinds from 0, with `x0` the
  family's primary construction. A new kind takes its family's lowest free low nibble, and
  a new family takes the lowest free high nibble (`0x9_` next).
- From genesis on, a byte MUST NOT be pointed at a different construction.

### 4.3 The table

| Prefix | Family | Construction | Hashed after the prefix | Signed |
|---|---|---|---|---|
| `0x00` | Merkle | leaf | the 32 bytes of the leaf value | never |
| `0x01` | Merkle | node | the 32 bytes of the left child, then of the right | never |
| `0x10` | Items | `item_hash` | JCS(item record) | yes |
| `0x11` | Items | `claims_hash` | JCS(claims) | never |
| `0x20` | Entropy | `observation_hash` | JCS(observation record) | yes |
| `0x21` | Entropy | `entropy_hash` | JCS(entropy object) | never |
| `0x30` | Blocks | `block_hash` | JCS(block record) | yes, by the key the chain assigns |
| `0x31` | Blocks | genesis `previous_block_hash` | JCS(genesis object) | never |
| `0x40` | Beacon | beacon draw | JCS(draw record) | never |
| `0x50` | Keys | handover | JCS(rotation event without `handover_signature`) | yes, by the outgoing key |
| `0x51` | Keys | `key_id` | the 32 key bytes; the hash cut to 4 bytes | never |
| `0x52` | Keys | `prerotation_commitment` | the 32 bytes of the next key | never |
| `0x60` | Proofs | proof digest | JCS(proof) | yes |
| `0x70` | Commitments | inclusion record | JCS(inclusion record) | yes |
| `0x71` | Commitments | internal epoch record (name *Proposed*) | JCS(internal epoch record) | yes |
| `0x72` | Commitments | external commitment record | JCS(external commitment record) | yes |
| `0x73` | Commitments | commitment evidence record | JCS(evidence record) | yes |
| `0x80` | Epochs | `epoch_hash` (*Proposed*) | JCS(epoch record) | never |

Every other byte is unassigned. The 0x70 to 0x73 records are Truestamp's internal records
and never appear in a proof, so this document lists only their bytes. The epoch record
that 0x80 hashes is a different record, carried in every commitment entry (section 3.4).
The beacon draw appears in no proof.

### 4.4 Beacon draws (0x40)

Each draw record is closed: `beacon` is the block hash in hex, `tool` names the draw,
integers are at most MAX_INTEGER, and `d` is the draw's hash, H(0x40, record), read as an
unsigned 256-bit big-endian integer.

| `tool` | Other members | Result |
|---|---|---|
| `coin_toss` | none | d mod 2 (0 is heads) |
| `dice_roll` | `sides` (at least 2) | 1 + (d mod sides) |
| `integer` | `max`, `min` (min at most max) | min + (d mod (max - min + 1)) |
| `drawing` | `entries`: 1 to 1,000 strings, byte-sorted | the entry at index d mod (number of entries) |
| `lottery` | `count` (1 to `max`), `max` (1 to 1,000), `position` | for i from 0 to max - 1, insert i + 1 at index (d_i mod (i + 1)) of a running list, where d_i is the draw hash of the record with `position` = i; the first `count` values, sorted |

The drawing record carries its entries, so a result can be reproduced from the record
alone.

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

### 5.2 Inclusion proofs (*Proposed*)

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

### 5.4 The committed leaf count (*Proposed*)

Every tree whose root Truestamp commits also commits its leaf count, as RFC 9162's signed
tree head signs the tree size with the root. Each such tree has a record holding its
`merkle_root` and `leaf_count`, and the record's hash is committed in turn:

| Tree | Its leaves | Record | Record hash | Where the record hash goes |
|---|---|---|---|---|
| block | `item_hash`, `observation_hash` | the block record | `block_hash` = H(0x30, record) | a leaf of an epoch tree |
| epoch | `block_hash` | the epoch record `{leaf_count, merkle_root}` | `epoch_hash` = H(0x80, record) | Stellar and Bitcoin |

At both levels, for each `inclusion_proof` into a tree, a verifier MUST check that the walk
from the recomputed leaf reaches the record's `merkle_root` and that the proof's
`tree_size` equals the record's `leaf_count`.

For each commitment entry, a verifier MUST also compute H(0x80, `epoch.record`) and compare
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
### 6.2 Strict verification
### 6.3 Worked example
### 6.4 The environment marker

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

The genesis text (*Proposed*): 28 rows, 7,653 octets under JCS, digest
`f3adb9f89afbf8ed232854bdec4ab19ad39cc010095d46148af7331acd672d96`. Every value is printable
ASCII with no `"` or `\`. To reproduce the digest, parse the object below, serialize it
with sorted keys and no whitespace (exactly JCS for this object), and hash it:
`hashlib.sha256(json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()).hexdigest()`.

```json
{
  "beacon": "block.block_hash is the beacon value; each member of observations is an entropy leaf of that block, checked as an observation subject; no one, Truestamp included, could compute the value before Submitted after, but Truestamp chooses the block contents after the entropy is public and so can bias it",
  "bitcoin": "raw_transaction is a transaction serialized without witness data (BIP 144 marker, flag and witnesses removed), with at least one input; transaction_hash = rev(SHA-256d(raw_transaction)); exactly one output script begins 0x6a and it is 0x6a 0x20 followed by the 32 bytes epoch.epoch_hash's hex spells, in that order; txoutproof is a BIP 37 merkleblock: an 80-byte header, total_txs, and a partial Merkle tree that places transaction_hash under header_merkle_root; header_hash = rev(SHA-256d(header)) and meets the target in the header nBits; header_merkle_root = rev(the header Merkle root field); header_time = the header nTime; header_hash is the best-chain block at height on network; network is the verifier's pinned Bitcoin network, and nothing in this proof decides it",
  "block_hash": "SHA-256(0x30 || JCS(record))",
  "chain_order": "a Stellar entropy object sequence is below the ledger of a top-level stellar commitment on the same network; a Bitcoin entropy object height is at or below the height of a top-level bitcoin commitment on the same network",
  "checks": "compute each hash this text defines from its preimage as carried and compare it with the value the proof carries for it; every merkle_path, and every comparison of one hash with another, starts from the computed value, never the carried one",
  "claims": "the submitter's statements exactly as submitted, attested as submitted and never as true; hash is lowercase hex of the length hash_type fixes (for example md5 32, sha1 40, sha256 64) and is never recomputed; timestamp is a time the submitter claims and never an edge of the submission window; nonce, if present, is at most 32 random bytes in lowercase hex",
  "claims_hash": "SHA-256(0x11 || JCS(claims))",
  "encoding": "JCS is RFC 8785; hashes, key ids and Bitcoin byte strings are lowercase hex, Bitcoin hashes in the reversed byte order explorers display, except NIST outputValue, which is uppercase hex as NIST publishes it; Ed25519 keys and signatures are unpadded base64url (RFC 4648 section 5); times are RFC 3339 UTC, except the Bitcoin entropy payload time, which is integer Unix seconds; SHA-256d is SHA-256 applied twice; rev reverses byte order; median time past is the median of the header times of a block and the 10 blocks before it",
  "entropy_hash": "SHA-256(0x21 || JCS(entropy object))",
  "environment": "present only outside production, naming the environment that signed the proof (dev, staging or test); a verifier rejects a proof from any environment but its own",
  "epoch_hash": "SHA-256(0x80 || JCS(record)) for the epoch of each commitment entry, whose record holds the epoch tree's merkle_root and leaf_count; epoch_hash is the value written to Stellar and Bitcoin, so the chain commits the tree's leaf count with its root",
  "genesis": "when record.metadata.genesis is present: record.height = 0 and previous_block_hash = SHA-256(0x31 || JCS(metadata.genesis)); genesis.bitcoin names a best-chain Bitcoin block mined before the chain began",
  "handover": "in a rotation or emergency_rotation key_event: previous_key_id is the key id of previous_public_key, and handover_signature, if present, is Ed25519 by previous_public_key over SHA-256(0x50 || JCS(the key_event without handover_signature))",
  "height": "record.height counts blocks from 0 at genesis; the height of witnesses.block is below the height of block",
  "inclusion": "a subject's merkle_path(item_hash or observation_hash, inclusion_proof) = block.record.merkle_root; each commitment entry's merkle_path(block_hash of the block these commitments belong to, inclusion_proof) = epoch.record.merkle_root; at both levels, inclusion_proof.tree_size = that record's leaf_count",
  "item_hash": "SHA-256(0x10 || JCS(record))",
  "key_event": "wherever record.metadata.key_event is present: genesis, rotation and emergency_rotation introduce public_key, and key_id = record.signing_key_id = the key id of public_key, which is hex of the first 4 bytes of SHA-256(0x51 || its 32 bytes); prerotation and revocation introduce no key, and for prerotation record.signing_key_id = active_key_id; signing_key_event.block introduces signature.public_key",
  "keyring": "signature.public_key is Truestamp's only if its 32 bytes equal a key in Truestamp's keyring, published at https://www.truestamp.com/.well-known/keyring.json and with the specification; nothing in this proof decides it",
  "merkle_path": "merkle_path(start, proof) is RFC 9162 section 2.1.3.2 over proof.leaf_index, proof.tree_size and proof.path, a list of hashes: fail unless leaf_index < tree_size and path has at most 32 hashes; set fn = leaf_index, sn = tree_size - 1 and r = SHA-256(0x00 || start); then for each p in path, in order: fail if sn = 0; if fn is odd or fn = sn, set r = SHA-256(0x01 || p || r) and then, while fn is even and not 0, halve fn and sn; if neither, set r = SHA-256(0x01 || r || p); in both cases, then halve fn and sn once; after the last p, fail unless sn = 0; halving rounds down, each hash is the 32 bytes its hex spells, and the result is the final r",
  "observation_hash": "SHA-256(0x20 || JCS(record))",
  "parsing": "the file is one UTF-8 JSON text (RFC 8259) with no duplicate member names or lone surrogates, at most 32 levels deep, whose numbers are read as the nearest binary64 value (underflow gives 0), none an integer above 2^53-1 and below 10^21 in magnitude however written; formatting and member order do not matter, since every hash and the signature use JCS of the parsed values",
  "recorded": "ids, the times inside ids, and every value this text does not derive are Truestamp records bound by these hashes and the signature; they are never a verdict input except as the rows above and the verifier's pins use them",
  "signature": "signature.value is pure Ed25519 (RFC 8032, not Ed25519ph) by signature.public_key over the 32 bytes SHA-256(0x60 || JCS(proof)), where proof is the top-level proof member, and signature.alg names exactly this rule; that digest is never carried",
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
this one. Reference mode saves 7,530 octets per proof, and `none` 140 more.

### 7.4 The agent-sufficiency acceptance test

## 8. Verifier roles

Truestamp's own verifier uses its key chain and fails closed. An external verifier uses
the pinned keyring by default, which the keyring downloaded from www.truestamp.com
replaces online, and runs without a keyring only when asked, saying so.

## 9. What a verifier pins

The pins are a verifier's trust policy, and each is published as a file under `spec/`.

- **Keys:** Truestamp's own verifier uses its verified key chain.
  `spec/keyring.production.json` is compiled into the CLI and the reference verifier, and
  the keyring downloaded from www.truestamp.com replaces it online (section 10.2, step 0).
  `spec/keys.nonproduction.json` holds the staging key and the checked-in dev and test
  keys, and a production keyring MUST NOT contain any of them (section 6.4). A verifier
  MUST validate every keyring when it loads it.
- **Literals:** `format`, `version` 1, `signature.alg`, CONSTRUCTIONS_ACCEPTED (the digests
  of the texts under `spec/constructions/`), and `spec/schema.json`: the type registry,
  closed member sets, presence by type and patterns.
- **Networks:** a commitment pin per chain and, separately, an entropy pin per source. No
  account or address is pinned.
- **Sources:** compiled-in defaults, or an operator-pinned Horizon, Esplora or Bitcoin Core
  server (in the CLI, `--horizon URL`, `--esplora URL` and `--bitcoin-core URL`) whose
  identity is checked first. Regtest has no default. A verifier MUST NOT let a document
  select a source.

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
| BITCOIN_POW_FLOOR | per network, the largest target a commitment header's nBits may encode. `mainnet` (*Proposed*): 2^187, compact `0x18080000`, a difficulty of about 1.37 x 10^11, about a thousandth of the 1.33 x 10^14 at height 968,496 (September 2026). `testnet3`, `testnet4` and `regtest`: their consensus proof-of-work limits, `0x1d00ffff`, `0x1d00ffff` and `0x207fffff` |
| STELLAR_INDEX_MARGIN | 60 ledgers |
| SMALL_ORDER_KEYS | the ten encodings of section 6.2 |
| VECTOR_KEY | `2152f8d19b791d24453242e15f2eab6cb7cffa7b6a5ed30097960e069881db12`, from the seed of 32 bytes of 0x42; valid only when the verifier's environment is `test` |

There are no clock tolerances.

**The data files.** These files under `spec/` hold the pins defined so far; the keyrings
and the constructions texts named above are still to come:

| File | Holds |
|---|---|
| `prefixes.json` | the table of section 4.3, keyed by construction name |
| `constants.json` | the constants above, except the two that have files of their own |
| `pow-floor.json` | BITCOIN_POW_FLOOR for each network, as compact nBits and as the 256-bit target in hex |
| `small-order-keys.json` | SMALL_ORDER_KEYS in hex, with each point's order |
| `encodings.json` | the pattern classes of section 2.4 |
| `networks.json` | the network names of each chain |
| `value-classes.json` | the value classes of section 3.7, by JSON Pointer pattern |
| `schema.json` | the closed schema of the envelope and of every type |

Every file satisfies the parsing rules of section 10.1 and has one canonical form: ASCII,
members in JCS order, two-space indentation, LF line ends and a final newline.
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
### 10.2 Steps
### 10.3 Links and the key-event row
### 10.4 Chain and source reads
### 10.5 Verdict and report
### 10.6 Declare and verify

## 11. The submission window

How the submitted-after and submitted-before edges are drawn from values the verifier
recomputes and from the chain and source reads it makes.

## 12. Reason codes and exit codes

## 13. Conformance

The cases in `vectors/cases.json`, what each asserts, and the fixtures every verifier
passes.
