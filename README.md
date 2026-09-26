<!--
Copyright (c) 2026 Truestamp, Inc.
SPDX-License-Identifier: Apache-2.0
-->

# truestamp-verification

The canonical definition of a Truestamp proof and how to verify one: what a proof file
holds, every check a verifier makes, and the known answers a verifier reproduces. Anyone
who writes or audits a verifier, Truestamp's own included, works from this repository.

**Status:** under construction. `SPEC.md` is a draft, and nothing here is normative yet.

## Layout

| Path | What it holds |
|---|---|
| `SPEC.md` | The specification, and the only document in the repository meant to be normative. |
| `spec/` | The data `SPEC.md` defines: the byte-prefix registry, constants, pattern classes, networks, value classes, small-order keys, the JSON Schema of a proof, the accepted constructions text under `spec/constructions/`, the reason and exit codes, the production keyring, which holds no key yet, and the public keys of the non-production environments. |
| `vectors/` | The conformance vectors of `SPEC.md` section 13.2. Today: the worked example of section 6.3 and the test keyring. |
| `MANIFEST.sha256` | The SHA-256 of every file under `spec/` and `vectors/`. |
| `generator/` | The scripts that write derived files: `generate.exs` writes and checks the vectors, and `manifest.exs` writes the manifest. |
| `elixir/` | The Elixir reference verifier, a Mix project. Today it holds the tests that tie `spec/` to `SPEC.md`, and one test of the Merkle library it depends on. |
| `Taskfile.yml` | The checks, run with [Task](https://taskfile.dev). |

Still to come: the production key and the staging key; the rest of `vectors/`, the
conformance cases and their inputs, with known answers for JCS, Ed25519 and base64url; and
reference verifiers in Go and TypeScript beside the Elixir one.

## Standards and dependencies

A verifier needs these standards and this repository's data: JSON (RFC 8259), the JSON
Canonicalization Scheme (RFC 8785), SHA-256 (FIPS 180-4), pure Ed25519 (RFC 8032), unpadded
base64url (RFC 4648 section 5), the Merkle Tree Hash and inclusion proofs of RFC 9162
section 2.1, JSON Pointer (RFC 6901), RFC 3339 times, JSON Schema draft 2020-12, BIP 37
merkleblocks and the transaction serialization without witness data of BIP 144, and, for
the online checks, the Bitcoin and Stellar protocols and NIST's Randomness Beacon.
`SPEC.md` section 2.5 lists them with what each is used for. Any conforming implementation
of each will do; none of them requires a particular library.

A Truestamp Merkle tree is RFC 9162 section 2.1's Merkle Tree Hash over entries sorted by
key. It is the one construction with a Truestamp library, and using that library is
optional: [truestamp-merkle-elixir](https://github.com/truestamp/truestamp-merkle-elixir)
builds the trees, and its `vectors/merkle.json` holds their known answers. This repository
keeps no Merkle vectors of its own: its one Merkle test, and the generator's known answers,
borrow cases from that file and recompute them. The Elixir reference verifier depends on
that library, pinned to a commit.

## Running the checks

The tool versions are in `.tool-versions`. With [mise](https://mise.jdx.dev) installed,
install them (prebuilt Erlang only), then fetch the dependencies:

    MISE_ERLANG_COMPILE=false mise install
    task setup

Then:

    task check       # the CI gate: house style, the vectors, the manifest, formatting,
                     # compile, credo, unused dependencies, tests
    task precommit   # format the sources, then run the same gates
    task generate    # rewrite vectors/ with the generator, then the manifest

## License

Apache-2.0. See `LICENSE`.
