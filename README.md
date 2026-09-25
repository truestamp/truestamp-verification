<!--
Copyright (c) 2026 Truestamp, Inc.
SPDX-License-Identifier: Apache-2.0
-->

# truestamp-verification

The canonical definition of a Truestamp proof and how to verify one: what a proof file
holds, every check a verifier makes, and the known answers a verifier reproduces. Anyone
who writes or audits a verifier, Truestamp's own included, works from this repository.

**Status:** under construction. `SPEC.md` is an outline, and nothing here is normative
yet.

## Layout

| Path | What it holds |
|---|---|
| `SPEC.md` | The specification, and the only normative document in the repository. |
| `elixir/` | The Elixir reference verifier, a Mix project. Today it holds one test of the Merkle library it depends on. |
| `Taskfile.yml` | The checks, run with [Task](https://taskfile.dev). |

Still to come: `spec/`, the data files `SPEC.md` defines (the byte-prefix registry,
constants, schema, reason codes and keyrings); `vectors/`, the conformance cases and
their inputs; `MANIFEST.sha256`, the digest of every file under both; the generator that
writes the vectors; and reference verifiers in Go and TypeScript beside the Elixir one.

## Merkle trees

A Truestamp Merkle tree is RFC 9162 section 2.1's Merkle Tree Hash over entries sorted by
key. Its known answers live with the library that builds it,
[truestamp-merkle-elixir](https://github.com/truestamp/truestamp-merkle-elixir), in its
`vectors/merkle.json`. This repository keeps no Merkle vectors of its own: its one Merkle
test borrows a single case from that file and recomputes it. The Elixir reference verifier
depends on that library, pinned to a commit.

## Running the checks

The tool versions are in `.tool-versions`. With [mise](https://mise.jdx.dev) installed,
install them (prebuilt Erlang only), then fetch the dependencies:

    MISE_ERLANG_COMPILE=false mise install
    task setup

Then:

    task check       # the CI gate: formatting, compile, credo, unused dependencies, tests
    task precommit   # format the sources, then run the same gates

## License

Apache-2.0. See `LICENSE`.
