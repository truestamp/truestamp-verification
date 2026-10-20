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
code against the conformance cases before anyone relies on it. The reference verifier, the
Elixir library `Truestamp.Verify` in
[truestamp-verify-ex](https://github.com/truestamp/truestamp-verify-ex), is an example to
consult, not a source to translate.

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
   root, checks your copy. `agent-test/MANIFEST.sha256` does the same for `agent-test/`,
   run there.
4. The reference verifier is the library `Truestamp.Verify`, in
   [truestamp-verify-ex](https://github.com/truestamp/truestamp-verify-ex). Read it to
   settle a question the text leaves you unsure of, after reading the section of `SPEC.md`
   that governs it: `lib/truestamp/verify/steps/` holds one module for each step of section
   10.2, and its repository has guides and a walkthrough notebook. In a checkout of it,
   `mix deps.get` fetches this repository's vectors into `deps/truestamp_verification`, and
   `mix truestamp.verify FILE` verifies a proof offline. Its standard output is exactly one
   JSON document: the report of section 10.5, with exactly that section's members, or a bare
   rejection's `{code, message, sub_reason}`; on exit 1 or 2 it is empty. `--trace FILE`
   writes the run's trace to FILE, in the form of `vectors/positive/<name>.trace.json`. With
   no option the run is under the environment `prod`, so every vector fails
   `environment_mismatch`; give a vector its case's options, such as `--environment test
   --keyring deps/truestamp_verification/vectors/keyring.test.json`. The command takes no
   network pins. Of the 22 offline cases whose `networks` differ from their environment's
   defaults, 6, the `policy-*-entropy_*` cases, give other rows through it; the other 16 give
   the same rows. To run the cases with their full configuration, network pins included,
   run `MIX_ENV=test mix truestamp.conformance
   deps/truestamp_verification/vectors/cases.json`. It runs every case, each online case
   answered from its replay file. Its standard output is one JSON document: an array with an
   entry `{id, output}` for each case, in the file's order, where `output` is what section
   13.1 compares, a bare rejection's `code` and `sub_reason`, or the `label` and every row as
   `[code, part, status, step]`, with the trace rows but `inputs` for a case that names a
   trace, and an online case's two edges. It compares nothing itself; the verifier's own
   tests compare it with `cases.json`.

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
    some of them. The reference verifier's `lib/truestamp/verify/json/binary64.ex` shows
    an exact conversion.
  - A stock JSON Schema validator can tell whether SHAPE's schema check passes, but not
    the part its row names, which section 10.2, step 7 fixes.
    The reference verifier's `lib/truestamp/verify/schema.ex` is a checker that gives it.
- Test the building blocks before the whole:
  - `vectors/corpus/`: JCS under `jcs/`, `ed25519.json`, `base64url.json`, and real
    Bitcoin transactions and merkleblocks under `bitcoin/`;
  - the Merkle tree of section 5, whose known answers are `vectors/merkle.json` in
    [truestamp-merkle-ex](https://github.com/truestamp/truestamp-merkle-ex); this
    repository has none of its own;
  - the worked example of section 6.3, in `vectors/worked-example.json`;
  - the item code of section 3.9, in `vectors/item-codes.json`, if you build one.
- Then run every case in `vectors/cases.json`.
  - A case names its files by path relative to `vectors/`: `proof`, and `keyring`,
    `online` and `trace` when present (the member table of section 13.2). `keyring` may
    instead be `test` (the test keyring), `none` (keyless mode) or `unavailable`. A case
    is online exactly when it has `online`. Cases share files, so never build a path from
    a case's id. The reference verifier's `Truestamp.Verify.Conformance` is one harness,
    and its output for every case, from `mix truestamp.conformance` (above), is one to diff
    yours against.
  - Give your verifier each proof and keyring file as the bytes you read, never as a
    value your harness parsed and wrote again: many cases concern the bytes themselves.
  - `cases.json` is larger than MAX_READ_OCTETS, so read it with an ordinary data reader,
    not through your verifier's own reading step.
  - Every offline case applies to every verifier. An online case applies only to a
    verifier that makes the chain and source reads of section 10.4; its answers are in a
    replay file under `vectors/corpus/replay/`.
  - An online case can give a Stellar or Bitcoin network several sources, in its config's
    `sources`, with a source policy; the replay's records of that network then name the
    source that answers (section 13.2). Give each named source its own identity read and its
    own reads, run each CHAIN and SOURCES row once per source as if it were the only one, and
    combine the outcomes as section 10.4 says. A case without `sources` has one source per
    network, which every policy treats alike.
  - Section 13.1 says what is compared. For a bare rejection: `code`, and `sub_reason`
    when the code has one. Otherwise: the `label`, the `code` when the case's `expected`
    gives one, and every row as (code, part, status, step), in order, passes and skips
    included; for an online case, also each edge's
    instant and basis, compared as instants. Messages, `values` and exit codes are never
    compared.
- The reference verifier's `livebooks/walkthrough.livemd`, a Livebook notebook, runs the
  verifier over one proof and prints every value the trace holds, each declared value
  beside the value the verifier recomputes, step by step, then the reads and the submission
  window of an online run answered from a replay file; it computes nothing itself. The
  **Run in Livebook** button in the verifier's README opens it in your own Livebook, and
  its first cell installs the verifier and these vectors, each at a pinned commit.
- Each sound proof under `vectors/positive/` has a trace, `<name>.trace.json` (section
  10.6): one row for each DERIVE row whose part is a CHECKED value, other than a row of
  LINK_HEAD, LINK_KEY_EVENT or LINK_CHAIN_ORDER, with its construction,
  declared value, inputs, part, recomputed value and status. When a sound proof fails,
  compare your derivation with the trace to find the first value that differs. A verifier
  that gives a trace matches it in order, every member but `inputs`, for each case whose
  expected output names a trace: the sound cases, their reformatted copies, and five
  passing cases that run a sound proof unchanged (two keyring cases, two expected-hash
  cases and one POLICY case).
- A claim of conformance names the commit of this repository and the digest of
  `MANIFEST.sha256` (`shasum -a 256 MANIFEST.sha256`) whose cases the verifier passed.

## The agent-sufficiency test

`agent-test/` holds the test of `SPEC.md` section 7.4, which asks whether the constructions
text alone is enough to verify a proof. It tests the text, not a verifier: it is no
conformance test, and its expected lines are no substitute for `vectors/cases.json`. A
session of the test is a fresh agent that receives only `agent-test/PROMPT.md` and one
fixture directory under `agent-test/fixtures/`, and writes `verify.py`; nothing else in this
repository is given to it, and it must not be able to read this repository or any Truestamp
source. `agent-test/selftest/verify.py` is the harness's own known-good
script, not an answer key, and no session receives it.

- `elixir agent-test/check.exs PATH/TO/verify.py --only FIXTURE --python PATH/TO/python3`
  (`task agent-test -- PATH/TO/verify.py --only FIXTURE --python PATH/TO/python3`) judges a
  session: it runs the session's script on every run of its fixture in
  `agent-test/runs.txt` and compares its lines with `agent-test/expected/`. Without
  `--only` it runs every fixture's runs. `--python` names the Python the sessions had, which
  must import `cryptography` and `rfc8785`, or the harness stops before any run. A session
  passes only when every run of its fixture exits 0 with exactly its expected lines.
- `sandbox/` runs the test's sessions in Docker Sandboxes, each locked to the Anthropic API
  and judged in a second sandbox, on a Claude subscription: `task agent-test-run -- --model
  MODEL` runs every fixture's sessions and writes a summary, and `task agent-test-smoke`
  checks the sandbox itself (`sandbox/README.md`). Both need `sbx` and start real agent
  sessions, so neither is part of `task check`.
- `elixir agent-test/check.exs --self-test` holds the harness to its known-good script and
  to flawed copies of it, one for each rule the mutants break; `task check` runs it. The
  known-good script uses only Python's standard library, so the self-test needs neither
  package.
- `elixir agent-test/record.exs` records a replay file for a real proof, such as a staging
  one, from real sources; its comment lists the options. Its tests run inside the
  generator, through a stubbed transport.
- The generator derives every expected line itself. In a checkout of truestamp-verify-ex,
  `MIX_ENV=test mix truestamp.agent_lines RUNS_JSON` gives the lines the reference verifier
  computes for each proof a runs file names, and its own tests hold them to
  `agent-test/expected/`.
- Results of the test go to `agent-test/results/<date>-<d>.md`.

## Changing this repository

- Work in a git clone, with git installed: `task style` lists files with `git ls-files`,
  and `task setup` fetches the Merkle library with git. Install the tools in
  `.tool-versions` with `MISE_ERLANG_COMPILE=false mise install`, then run `task setup`.
- `task check` is the gate: formatting, house style, the vectors and the generated files
  under `agent-test/`, the agent-test harness's self-test, the manifest, compile, credo in
  strict mode, unused dependencies, and the tests. It needs the dependencies of `checks/`
  (`task setup`) and `python3` for the harness's self-test. It passes before any change is
  done. A slow test, `checks/test/generator_check_test.exs`, runs the generator's whole
  check on a copy of the repository with broken files; `task test -- --exclude
  generator_check` leaves it out.
- Never edit `vectors/`, the generated files under `agent-test/` (`PROMPT.md`, `runs.txt`,
  `fixtures/`, `mutants/` and `expected/`) or either manifest by hand. After changing
  `generator/`, anything under `spec/`, which the generator reads, or the prompt in
  `SPEC.md` section 7.4, run `task generate`, which rewrites `vectors/`, those files and
  both manifests, then `task check`. After changing a hand-written file under
  `agent-test/`, run `task manifest`. The generator does not delete a file it
  no longer writes, so delete a stale one yourself.
- The generator shares no code with any verifier, and neither is written from the other, so
  a verifier that passes these cases checks the generator as much as the generator checks
  it. Keep it that way.
- This repository depends on no verifier, and a change here lands on its own. Verifiers
  follow it: truestamp-verify-ex pins a commit of this repository, holds its compiled copy
  of `spec/` and its own output to that commit's files, and also runs on a schedule against
  `main` here, so its CI says when it no longer conforms.
- A change to `SPEC.md` that changes what a verifier does comes with a case in
  `vectors/cases.json` that shows it, and an online change with its replay file. Make the
  reference verifier's side of it in truestamp-verify-ex, tested there against a checkout of
  the change (`TRUESTAMP_VERIFICATION`, then `task spec-sync`).
- `task style` enforces the house style: no em dashes, "commit" and "commitment" for what
  a chain records, "submission window" for the interval a proof establishes, no version
  number in a format's name, and the BCP 14 key words in capitals only in `SPEC.md`.
- Every source file carries the Apache-2.0 header its neighbours carry.
