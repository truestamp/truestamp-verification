<!--
Copyright (c) 2026 Truestamp, Inc.
SPDX-License-Identifier: Apache-2.0
-->

# truestamp-verification

The canonical definition of a Truestamp proof and how to verify one: what a proof file
holds, every check a verifier makes, and the known answers a verifier reproduces. Anyone
who writes or audits a verifier, Truestamp's own included, works from this repository.

**Status:** under construction. `SPEC.md` is a draft, and nothing here is normative yet.

## Built for AI agents as well as people

This repository is written so that an AI agent, given only `SPEC.md`, the data under
`spec/` and the known answers under `vectors/`, can derive working code for a Truestamp
verifier, or a library for verification, in almost any language, and prove that code
against the conformance cases before anyone relies on it. A reference verifier is the
worked example an agent consults where the text leaves it unsure: today the Elixir one
under `elixir/`, and later ones in Go and TypeScript. `AGENTS.md` tells an agent how to use,
test and change the repository.

A narrower form of the same aim is the agent-sufficiency test of `SPEC.md` section 7.4,
under `agent-test/`: a fresh agent holding only one proof, its constructions text, a keyring
and recorded chain and source answers writes a verifier that recomputes every value the
constructions text defines for that proof and derives both edges of its submission
window. It tests the constructions text, not a verifier, and gates the acceptance of each
text.

## Layout

| Path | What it holds |
|---|---|
| `SPEC.md` | The specification, and the only document in the repository meant to be normative. |
| `AGENTS.md` | Instructions for AI agents that use the repository to build a verifier or library, or change it. |
| `spec/` | The data `SPEC.md` defines: the byte-prefix registry, constants, pattern classes, networks and the default network pins of each environment, value classes, small-order keys, the JSON Schema of a proof, the accepted constructions text under `spec/constructions/`, the reason and exit codes, the production keyring, which holds no key yet, and the public keys of the non-production environments. |
| `vectors/` | The conformance vectors of `SPEC.md` section 13.2. Today: the worked example of section 6.3, the test keyring; under `positive/` the sound proofs of section 13.3, each `<name>.proof.json`, in the served form of section 3.1, with its trace `<name>.trace.json`, where `<name>` is the proof's type, or its type and a variant, such as `block-rotation`; `cases.json`, the cases of section 13.3, offline and online, each with its configuration and expected output; under `negative/` the files those cases need, `<id>.proof.json` and `<id>.keyring.json`, each named by the id of a case that uses it, though cases share files and each case names its files by path (section 13.2); and under `corpus/` known answers for JCS, Ed25519 and base64url, real Bitcoin transactions, merkleblocks and headers, each with where it came from and what a parser concludes from it, and under `corpus/replay/` the replay file of each online case, the answers to its chain, source and keyring reads, each record of a network the case gives several sources naming the source that answers; and `item-codes.json`, known answers for the item code of section 3.9, which are not conformance cases. |
| `agent-test/` | The agent-sufficiency test of `SPEC.md` section 7.4, which tests the constructions text, not a verifier. The generator writes `PROMPT.md`, the prompt a session receives; under `fixtures/` the six base fixtures, each a directory a session receives whole (its proofs, `keyring.json` and `replay.json`, and for the reference-mode fixture the text); under `mutants/` the flawed copies of each proof; under `expected/` the lines each run must print, every line but the window lines from the reference verifier through `mix truestamp.agent_lines`, and the window lines from the generator's model run online under the run's replay; and `runs.txt`, each run with its files. By hand: `check.exs`, the harness, which runs a session's `verify.py` on every run of its fixture and compares its lines with `expected/` (`--self-test` holds the harness to `selftest/verify.py`, its own known-good script, which is not an answer key and which no session receives, and to flawed copies of it, one for each rule the mutants break); `record.exs`, the replay recorder for a run against a real proof, such as the staging rehearsal's; and, once the test has run, `results/<date>-<d>.md`. `MANIFEST.sha256` there, which `manifest.exs` writes, holds the SHA-256 of every file under `agent-test/` but `results/`. |
| `MANIFEST.sha256` | The SHA-256 of every file under `spec/` and `vectors/`. |
| `generator/` | The scripts that write derived files: `generate.exs` writes and checks the vectors and the generated files under `agent-test/`, from the modules in `generator/lib/`, and with `--check` also runs the reference verifier over every offline case, as its own process through `mix truestamp.conformance`, and fails on any case whose output differs from `cases.json`, naming the case and the first row that differs; and `manifest.exs` writes the two manifests, `MANIFEST.sha256` and `agent-test/MANIFEST.sha256`. `generator/known_answers/` holds known answers the generator's checks read, today `binary64.txt`, JSON numbers and their nearest binary64 values as Python's `float()` gives them, written by `binary64.py` beside it. |
| `elixir/` | The Elixir reference verifier, a Mix project. Today it holds the verifier's building blocks (the strict reader and its exact number conversion, JCS, base64url, the record rule, key ids, strict Ed25519, TIME, the item code of `SPEC.md` section 3.9, and the compiled `spec/` tables); steps 0 to 6 of `SPEC.md` section 10.2, the gate, with the run configuration, whose network pins default to the row of `spec/network-pins.json` for the run's environment, and the keyring loader with the compiled production pin; steps 7 and 8, SHAPE, with the verifier's own checker for `spec/schema.json` and the accepted constructions digests, and POLICY; step 9, DERIVE, every recomputation, key-event check and link through one engine that gives the trace of `SPEC.md` section 10.6, with its own parsers for a Bitcoin transaction and merkleblock; steps 10 to 14 as an offline verifier makes them (CHAIN and SOURCES rows that are skips, WINDOW, EXPECTED_HASH and VERDICT), the report of section 10.5, and the command of section 12.2, `mix truestamp.verify FILE [--keyring FILE | --no-keyring] [--environment NAME] [--expected-hash HEX] [--trace FILE]`, run in `elixir/`, which writes one JSON document to standard output, even on a run that compiles first (the report, with exactly the members of section 10.5, or a bare rejection's `{code, message, sub_reason}`; nothing on exit 1 or 2), writes the trace of section 10.6 to FILE under `--trace FILE`, in the form of `vectors/positive/<name>.trace.json`, and a summary to standard error, and exits with the code of section 12.2; the conformance entry point, `mix truestamp.conformance CASES_JSON`, run in `elixir/` under `MIX_ENV=test`, which runs every offline case of a file in the form of `vectors/cases.json` with its full configuration, network pins included, and writes to standard output one JSON document, an array with an entry `{id, output}` for each offline case in the file's order, where `output` is what section 13.1 compares (a bare rejection's `code` and `sub_reason`, or the label and every row as `[code, part, status, step]`, with the trace rows but `inputs` for a case that names a trace); the agent-test entry point, `mix truestamp.agent_lines RUNS_JSON`, which gives the lines of section 7.4 that the verifier computes for each proof a runs file names, and which the generator runs to write `agent-test/expected/`; the tests of those steps over every offline case, every row and label, with the trace of each case that names one, and the comparison of section 13.1 over every offline case in `elixir/test/conformance_test.exs`; two slow tests, tagged `generator_check`, that break a copy of the repository and require `generate.exs --check` to fail: `elixir/test/conformance_check_test.exs`, which breaks the verifier, and `elixir/test/generator_check_test.exs`, which breaks the files the generator checks; the tests that tie `spec/` to `SPEC.md`; and one test of the Merkle library it depends on. |
| `Taskfile.yml` | The checks, run with [Task](https://taskfile.dev). |
| `.github/workflows/ci.yml` | The CI workflow, which runs `task check`. |

The sound proofs are cut from two modeled Truestamp chains, which commit to a modeled
Bitcoin regtest chain. That chain is a model for the parsers of `SPEC.md` section 10.2 and
for the replays of the online cases, and it is not valid Bitcoin: its transactions spend
SegWit outputs with no witness, and no coinbase carries a witness commitment, so no Bitcoin
node would accept its blocks. The chains' Stellar and NIST values are made up as well. The
generator checks that the model holds together: each header links to the one below it,
each coinbase carries its height as Bitcoin Core writes it, each median time past the model
serves is the median of its header times, every block, ledger and pulse a sound proof names
is the one the model says, and the window each sound proof gets is in order, with the time
in its subject's id inside it. The Bitcoin bytes under `vectors/corpus/bitcoin/` are real
ones.

The online cases apply to a verifier that makes the chain and source reads of `SPEC.md`
section 10.4, such as Truestamp's CLI and its own verifier. Some of them give one Stellar or
Bitcoin network several sources under a source policy (`first`, `at_least n` or `all`,
section 9), so that a verifier checks each read against more than one explorer; each source
is read on its own and section 10.4 combines their outcomes, with `sources_disagree` when
sources that answered conflict and `sources_incomplete` when too few answered. The reference
verifiers here are offline, so they run the offline cases only.

Still to come: the production key and the staging key; and reference verifiers in Go and
TypeScript beside the Elixir one.

## Standards and dependencies

A verifier needs these standards and this repository's data: JSON (RFC 8259), the JSON
Canonicalization Scheme (RFC 8785), SHA-256 (FIPS 180-4), pure Ed25519 (RFC 8032), unpadded
base64url (RFC 4648 section 5), the Merkle Tree Hash and inclusion proofs of RFC 9162
section 2.1, JSON Pointer (RFC 6901), RFC 3339 times, UUIDv7 ids and the time inside one
(RFC 9562), JSON Schema draft 2020-12, BIP 37 merkleblocks and the transaction
serialization without witness data of BIP 144, and, for the online checks, the Bitcoin and
Stellar protocols and NIST's Randomness Beacon.
`SPEC.md` section 2.5 lists them with what each is used for. Any conforming implementation
of each will do; none of them requires a particular library.

A Truestamp Merkle tree is RFC 9162 section 2.1's Merkle Tree Hash over entries sorted by
key. It is the one construction with a Truestamp library, and using that library is
optional: [truestamp-merkle-elixir](https://github.com/truestamp/truestamp-merkle-elixir)
builds the trees, and its `vectors/merkle.json` holds their known answers. This repository
keeps no Merkle vectors of its own: its one Merkle test, and the generator's known answers,
borrow cases from that file and recompute them. The Elixir reference verifier depends on
that library, pinned to a commit.

## Setting up

Clone the repository with git, and keep git installed: `task style` lists the files to
check with `git ls-files`, and `task setup` fetches the Merkle library with git, so a copy
downloaded as a ZIP file does not pass `task check`.

The reference verifier needs Elixir 1.19 or later; CI tests it on Elixir 1.19 with OTP 28
and on Elixir 1.20 with OTP 29. `.tool-versions` pins the tools for local work: Erlang,
Elixir and [Task](https://taskfile.dev).
With [mise](https://mise.jdx.dev) installed, run from the repository root, first to install the tools, with prebuilt Erlang only, then
Hex, rebar and the verifier's dependencies:

    MISE_ERLANG_COMPILE=false mise install
    task setup

`task setup` runs `mix deps.get` in `elixir/`, which fetches the Merkle library from GitHub
at the commit `elixir/mix.exs` pins, and credo. `task check` also needs `python3`, with its
standard library only.

## Verifying a proof

Run the reference verifier in `elixir/`:

    mix truestamp.verify FILE [--keyring FILE | --no-keyring] [--environment NAME]
                              [--expected-hash HEX] [--trace FILE]

- `--environment NAME` is the environment the run accepts, `prod` by default (`SPEC.md`
  section 6.4). A run under any other environment needs `--keyring` or `--no-keyring`.
- `--keyring FILE` supplies a keyring, and `--no-keyring` runs keyless (section 8.3). With
  neither, the production keyring compiled into the verifier governs; it holds no key yet.
- `--expected-hash HEX` compares a hash you hold with the proof's `claims.hash` (section
  10.2, step 13).
- `--trace FILE` writes the trace of section 10.6 to FILE, in the form of
  `vectors/positive/<name>.trace.json`.

Standard output carries one JSON document, the report of section 10.5 or a bare rejection,
and nothing on exit 1 or 2; standard error carries a summary for a person. The exit code is
section 12.2's: 0 `verified`, 3 `failed`, 4 a bare rejection other than
`configuration_error`, 5 `unattributed`, 6 `supplied-keyring`, 7 `internally-consistent`,
8 `configuration_error`, 1 a bad command line or an unreadable input, and 2 a fault in the
verifier that leaves no report. A fault the verifier catches later, from step 4
(ENVIRONMENT) on, is a `failed` report with an `internal_error` row, and exits 3. The
verifier is offline: it reads no chain or source, so it establishes no submission window.
For example, a sound vector:

    cd elixir
    mix truestamp.verify ../vectors/positive/item.proof.json --environment test \
      --keyring ../vectors/keyring.test.json --trace /tmp/item.trace.json

exits 6, `supplied-keyring`, and writes a trace equal to
`vectors/positive/item.trace.json`. `mix help truestamp.verify` describes the command.

## Running the checks

`task check` runs every gate, as CI runs it; `task precommit` formats the sources, then runs
the same gates:

    task check
    task precommit

`task check` checks formatting and the house style (`task style`); runs the generator's
check, which fails unless `vectors/` and the generated files under `agent-test/` are
exactly what it writes, and runs the reference verifier over every offline case and for
the agent test's expected lines; runs the agent-test harness's self-test; checks both
manifests; compiles with warnings as errors; runs credo in strict mode; refuses unused
dependencies; and runs every test. Two slow tests, tagged `generator_check`, run the
generator's check on a broken copy of the repository; `task test -- --exclude
generator_check` runs the rest. `task test` sets `ELIXIR_ERL_OPTIONS=+fnu`, so the VM reads
file names as UTF-8 under any locale, as it does on macOS: on Linux, a test that runs the
verifier under the C locale with a path that is not ASCII needs it.

## Conformance

A verifier conforms when it gives the expected output of every case in `vectors/cases.json`
that applies to it; `SPEC.md` section 13.1 says which apply and what is compared, and
`AGENTS.md` how to run them. A claim of conformance names the commit of this repository and
the digest of `MANIFEST.sha256` whose cases the verifier passed. The first command gives the
digest to cite, and the second checks a copy of `spec/` and `vectors/`:

    shasum -a 256 MANIFEST.sha256
    shasum -a 256 -c MANIFEST.sha256

The reference verifier's output for every offline case, to compare yours with, comes from
this command in `elixir/`; `task check` compares it with `cases.json`:

    MIX_ENV=test mix truestamp.conformance ../vectors/cases.json

## The walkthrough

`elixir/walkthrough.livemd` is a [Livebook](https://livebook.dev) notebook that runs the
reference verifier over one proof and prints every value the trace holds, each declared
value beside the value the verifier recomputes. With Livebook installed, run from the root
of a checkout:

    livebook server elixir/walkthrough.livemd

or open `elixir/walkthrough.livemd` in the Livebook desktop app.

## The agent-sufficiency test

The test of `SPEC.md` section 7.4 needs agent sessions, so `task check` runs only its
harness's self-test. Section 7.4 gives the procedure: two fresh sessions for each fixture
under `agent-test/fixtures/`, each in an empty directory that holds only
`agent-test/PROMPT.md` and the fixture's files, with no network, no Truestamp source, no
project instructions, memory or skills, and Python 3 with `cryptography` and `rfc8785`.
A session must not be able to read this repository or any Truestamp source: this
repository holds the expected lines and a script that passes. A directory made with
`mktemp -d` is outside every checkout, but that is not enough on its own when the agent can
read the rest of the disk, so run the session where it cannot. `sandbox/` does this with
Docker Sandboxes, on a Claude subscription: `task agent-test-run -- --model MODEL` runs the
whole test and summarizes it (`sandbox/README.md`). By hand, from the repository root, for
the fixture `1-item`, `P` is the Python the sessions have and `S` one session's directory:

    P=$(mktemp -d)
    python3 -m venv "$P"
    "$P"/bin/pip install cryptography rfc8785
    S=$(mktemp -d)
    cp agent-test/PROMPT.md agent-test/fixtures/1-item/* "$S"/

Start the session in `$S` with `$P/bin` first on its PATH. It writes `verify.py`. The
harness runs that script on every run of its fixture, the fixture's proofs and their flawed
copies, and compares its lines with `agent-test/expected/`:

    task agent-test -- "$S"/verify.py --only 1-item --python "$P"/bin/python3

A session passes only when every run passes. Write each run of the test to
`agent-test/results/<date>-<d>.md`, where `<d>` is the digest of the constructions text it
tested; section 7.4 says what a result names.

## After a change

- After changing `generator/`, anything under `spec/`, or the prompt in `SPEC.md` section
  7.4: `task generate`, which rewrites `vectors/`, the generated files under `agent-test/`
  and both manifests, then `task check`.
- After changing a hand-written file under `agent-test/`: `task manifest`, then
  `task check`.
- Never edit `vectors/`, the generated files under `agent-test/` or a manifest by hand.
  `AGENTS.md` says more.

## CI

`.github/workflows/ci.yml` runs on every push to `main`, every pull request, and on demand,
on Ubuntu 24.04 with prebuilt Erlang only, in two jobs. Each runs `task setup` and fails if
that changed `elixir/mix.lock`, which means the commit left the lock stale. One job, with
the tools of `.tool-versions` (Elixir 1.20 on OTP 29), then runs `task check`. The other
runs `task check` on Elixir 1.19.3 with OTP 28.1.1: 1.19 is the oldest minor release
`elixir/mix.exs` allows, and 1.19.3 the version tested. Each job caches `elixir/deps` and
`elixir/_build`, keyed on its own tool versions and `elixir/mix.lock`.

## License

Apache-2.0. See `LICENSE`.
