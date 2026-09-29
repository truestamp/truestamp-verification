<!--
Copyright (c) 2026 Truestamp, Inc.
SPDX-License-Identifier: Apache-2.0
-->

# AGENTS.md

Instructions for AI coding agents that use this repository to build something, or that
change it.

## What this repository is for

It defines a Truestamp proof and how to verify one. It is written so that an agent can
build a working verifier, or a library for verification, in almost any language from
`SPEC.md`, the data under `spec/` and the known answers under `vectors/`, and prove that
code against the conformance cases before anyone relies on it. The reference verifier
under `elixir/` is an example to consult, not a source to translate.

## Sources, in order of authority

1. `SPEC.md` governs. Where anything else in the repository disagrees with it, `SPEC.md`
   is right and the other is a bug.
2. `spec/` holds the data `SPEC.md` defines: the byte-prefix registry, constants, pattern
   and value classes, the JSON Schema of a proof, networks and their default pins, the
   small-order keys, the production keyring (which holds no key yet), the public keys of
   the non-production environments, the accepted constructions text, and the reason and
   exit codes. Read these files rather than copying their values, or test that your
   copies equal them.
3. `vectors/` holds the conformance cases and known answers, among them the test keyring
   `vectors/keyring.test.json`. `MANIFEST.sha256` holds the SHA-256 of every file under
   `spec/` and `vectors/`: `shasum -a 256 -c MANIFEST.sha256`, run from the repository
   root, checks your copy.
4. `elixir/` is the reference verifier, still being built. Read it to settle a question the
   text leaves you unsure of, after reading the section of `SPEC.md` that governs it.
   `elixir/lib/truestamp/verifier.ex` names the module for each step it makes.

## Building a verifier or library

- Read `SPEC.md` sections 2 (conventions), 3 (the proof document), 10 (the verification
  algorithm) and 13 (conformance) first. What you build is an external verifier, so read
  section 8.3, which decides which keyring governs a run, and section 9, the pins. Section
  7.3's constructions text is a one-page map of every value a verifier recomputes.
- Section 10.2 gives the steps in order. An offline verifier still runs every step: CHAIN
  and SOURCES give `skip offline` rows, WINDOW gives `info window_not_established`, and
  EXPECTED_HASH and the label follow, as the `sound-beacon` case shows.
- Use the standards `SPEC.md` section 2.5 lists, from any conforming library, with these
  exceptions:
  - Ed25519 is strict (section 6.2), and many libraries accept signatures the
    specification refuses. Test yours against `vectors/corpus/ed25519.json`.
  - A stock JSON parser accepts input the specification refuses: duplicate member names,
    lone surrogates, too deep a document. Apply section 10.1's rules yourself.
  - Read every JSON number as its nearest binary64 value with a correctly rounded
    conversion (section 10.1, J5). A few proofs under `vectors/negative/` hold number
    literals hundreds of digits long, and the C library's `strtod` on macOS 27 aborts on
    some of them. `elixir/lib/truestamp/verifier/binary64.ex` shows an exact conversion.
  - A stock JSON Schema validator can tell whether SHAPE's schema check passes, but not
    the part its row names, which section 10.2, step 7 fixes.
    `elixir/lib/truestamp/verifier/schema.ex` is a checker that gives it.
- Test the building blocks before the whole:
  - `vectors/corpus/`: JCS under `jcs/`, `ed25519.json`, `base64url.json`, and real
    Bitcoin transactions and merkleblocks under `bitcoin/`;
  - the Merkle tree of section 5, whose known answers are `vectors/merkle.json` in
    [truestamp-merkle-elixir](https://github.com/truestamp/truestamp-merkle-elixir); this
    repository has none of its own;
  - the worked example of section 6.3, in `vectors/worked-example.json`;
  - the item code of section 3.9, in `vectors/item-codes.json`, if you build one.
- Then run every case in `vectors/cases.json`.
  - A case names its files by path relative to `vectors/`: `proof`, and `keyring`,
    `online` and `trace` when present (the member table of section 13.2). `keyring` may
    instead be `test` (the test keyring), `none` (keyless mode) or `unavailable`. A case
    is online exactly when it has `online`. Cases share files, so never build a path from
    a case's id. `elixir/test/support/cases.ex` is one harness.
  - Give your verifier each proof and keyring file as the bytes you read, never as a
    value your harness parsed and wrote again: many cases concern the bytes themselves.
  - `cases.json` is larger than MAX_READ_OCTETS, so read it with an ordinary data reader,
    not through your verifier's own reading step.
  - Every offline case applies to every verifier. An online case applies only to a
    verifier that makes the chain and source reads of section 10.4; its answers are in a
    replay file under `vectors/corpus/replay/`.
  - Section 13.1 says what is compared. For a bare rejection: `code`, and `sub_reason`
    when the code has one. Otherwise: the `label` and every row as (code, part, status,
    step), in order, passes and skips included; for an online case, also each edge's
    instant and basis, compared as instants. Messages, `values` and exit codes are never
    compared.
- Each sound proof under `vectors/positive/` has a trace, `<name>.trace.json` (section
  10.6): one row for each value DERIVE checks, with its construction, declared value,
  inputs, part, recomputed value and status. When a sound proof fails, compare your
  derivation with the trace to find the first value that differs. A verifier that gives a
  trace matches it in order, every member but `inputs`.
- A claim of conformance names the commit of this repository and the digest of
  `MANIFEST.sha256` (`shasum -a 256 MANIFEST.sha256`) whose cases the verifier passed.

## Changing this repository

- Install the tools in `.tool-versions` with `MISE_ERLANG_COMPILE=false mise install`,
  then run `task setup`.
- `task check` is the gate: formatting, house style, the vectors and the manifest,
  compile, credo in strict mode, unused dependencies, and the tests. It passes before any
  change is done.
- Never edit `vectors/` or `MANIFEST.sha256` by hand. After changing `generator/` or
  anything under `spec/`, which the generator reads, run `task generate`, which rewrites
  `vectors/` and the manifest, then `task check`. The generator does not delete a file it
  no longer writes, so delete a stale one yourself.
- The generator and the reference verifier share no code, and neither is written from the
  other, so each checks the other. Keep it that way.
- A change to `SPEC.md` that changes what a verifier does comes with a case in
  `vectors/cases.json` that shows it. When it touches a step the reference verifier makes,
  it also comes with the reference verifier's test of it; an online change comes with its
  replay file.
- `task style` enforces the house style: no em dashes, "commit" and "commitment" for what
  a chain records, "submission window" for the interval a proof establishes, no version
  number in a format's name, and the BCP 14 key words in capitals only in `SPEC.md`.
- Every source file carries the Apache-2.0 header its neighbours carry.
