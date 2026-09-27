# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Generator.Cases.Online do
  @moduledoc """
  The online cases SPEC.md 13.3 and the tracker's P6.1 entry call for, which vectors/cases.json
  cannot hold until the form of a replay file under corpus/ is set (SPEC.md 13.2): each with
  the configuration it will run under and the outcome it will expect. No file is written from
  this list. It is the record of what is pending, and the check of every code
  (Generator.Cases) reports each code of codes/0 as pending online rather than failing.

  Unless an entry says otherwise, a case runs under E_v `test` with the keyring `test`, pins
  `regtest` and `testnet` for every chain and source, as the offline cases do, and its replay
  stands as the operator-pinned source for each chain and network it answers (SPEC.md 13.2).
  An online case's `expected` also holds each edge's instant and basis, or its absence
  (SPEC.md 13.1).
  """

  # Each entry: its class, the configuration, the proof, and the expected outcome.
  @pending [
    {"KEY_BINDING",
     "E_v prod; keyring unavailable, so no keyring option; a replay that fails the default " <>
       "keyring read at www.truestamp.com", "an unmarked proof signed by VECTOR_KEY",
     "KEY_BINDING fail keyring_unavailable, part null; each later step up to EXPECTED_HASH " <>
       "skip prior_failure; label failed; both edges null"},
    {"CONFIGURATION",
     "pins regtest for Bitcoin, which the replay does not answer, so the run has no source for it",
     "any sound proof", "the bare rejection configuration_error"},
    {"CONFIGURATION",
     "a Stellar source pinned to public whose identity read gives another network passphrase",
     "any sound proof", "the bare rejection configuration_error"},
    {"CONFIGURATION",
     "a Bitcoin source pinned to mainnet whose block at height 0 is not mainnet's",
     "any sound proof", "the bare rejection configuration_error"},
    {"CONFIGURATION",
     "a Stellar source pinned to testnet whose identity read gives the production passphrase",
     "any sound proof", "the bare rejection configuration_error"},
    {"CONFIGURATION",
     "a Bitcoin source pinned to regtest (or testnet) whose block at height 0 is mainnet's",
     "any sound proof", "the bare rejection configuration_error"},
    {"Chain and source reads", "a source whose identity read gets no usable answer",
     "a sound proof that source serves",
     "every row that source serves skip source_unreachable; no configuration_error"},
    {"Chain and source reads", "the Stellar transaction found and matching, then ledger L read",
     "a sound proof with a top-level Stellar entry",
     "CHAIN pass at /commitments/stellar; the submitted-before edge that ledger's closed_at, " <>
       "basis stellar_ledger_close_read"},
    {"Chain and source reads", "the Stellar transaction found, with a memo that differs",
     "a sound proof with a Stellar entry", "CHAIN fail chain_mismatch at the entry"},
    {"Chain and source reads", "the Stellar transaction found, with successful false",
     "a sound proof with a Stellar entry", "CHAIN fail chain_mismatch at the entry"},
    {"Chain and source reads", "the Stellar transaction found in another ledger",
     "a sound proof with a Stellar entry", "CHAIN fail chain_mismatch at the entry"},
    {"Chain and source reads",
     "the Stellar transaction not found, and L above latest - STELLAR_INDEX_MARGIN",
     "a sound proof with a Stellar entry", "CHAIN skip not_yet_indexed at the entry"},
    {"Chain and source reads", "the Stellar transaction not found, and L below elder",
     "a sound proof with a Stellar entry", "CHAIN skip not_held_by_source at the entry"},
    {"Chain and source reads",
     "the Stellar transaction not found, L between elder and latest - margin, ledger L not found",
     "a sound proof with a Stellar entry", "CHAIN skip not_held_by_source at the entry"},
    {"Chain and source reads",
     "the Stellar transaction not found, L between elder and latest - margin, ledger L found",
     "a sound proof with a Stellar entry", "CHAIN fail chain_mismatch at the entry"},
    {"Chain and source reads",
     "the same four not-found branches on a Stellar testnet source (tracker, D58 item 14)",
     "a sound proof with a Stellar testnet entry", "the outcomes of the public rules above"},
    {"Chain and source reads",
     "a candidate read that answers not found: ledger L after the transaction was found",
     "a sound proof with a top-level Stellar entry",
     "CHAIN skip not_held_by_source at the entry; no submitted-before edge from it"},
    {"Chain and source reads", "a read answered with HTTP 429", "a sound proof",
     "skip source_unreachable on the row that read serves"},
    {"Chain and source reads", "a read answered with HTTP 503", "a sound proof",
     "skip source_unreachable on the row that read serves"},
    {"Chain and source reads", "an answer that does not parse", "a sound proof",
     "skip source_unreachable on the row that read serves"},
    {"Chain and source reads", "an answer that lacks a field the read uses", "a sound proof",
     "skip source_unreachable on the row that read serves"},
    {"Chain and source reads", "a Bitcoin tip below height", "a sound proof with a Bitcoin entry",
     "CHAIN skip not_yet_indexed at the entry"},
    {"Chain and source reads", "a Bitcoin tip at or above height but below height + 10",
     "a sound proof with a Bitcoin entry", "CHAIN skip chain_not_final at the entry"},
    {"Chain and source reads", "a best-chain header hash at height that differs",
     "a sound proof with a Bitcoin entry", "CHAIN fail chain_mismatch at the entry"},
    {"Chain and source reads",
     "a best-chain transaction count at height that differs from total_txs",
     "a sound proof with a Bitcoin entry", "CHAIN fail chain_mismatch at the entry"},
    {"Chain and source reads", "a best-chain hash at genesis.bitcoin's height that differs",
     "a sound proof that carries genesis.bitcoin",
     "CHAIN fail chain_mismatch at that genesis.bitcoin"},
    {"Chain and source reads", "a NIST pulse read whose outputValue or timeStamp differs",
     "a sound proof with a NIST entropy object", "SOURCES fail entropy_mismatch at the object"},
    {"Chain and source reads", "a Stellar ledger read whose hash or closed_at differs",
     "a sound proof with a Stellar entropy object",
     "SOURCES fail entropy_mismatch at the object"},
    {"Chain and source reads", "a Bitcoin block read whose height or time differs",
     "a sound proof with a Bitcoin entropy object",
     "SOURCES fail entropy_mismatch at the object"},
    {"Chain and source reads", "the NIST pulse not found",
     "a sound proof with a NIST entropy object", "SOURCES skip not_held_by_source at the object"},
    {"Chain and source reads",
     "the Stellar ledger not found, sequence above latest - STELLAR_INDEX_MARGIN, and in a " <>
       "second case at or below it", "a sound proof with a Stellar entropy object",
     "SOURCES skip not_yet_indexed, and skip not_held_by_source, at the object"},
    {"Chain and source reads", "the Bitcoin block not found",
     "a sound proof with a Bitcoin entropy object",
     "SOURCES skip not_held_by_source at the object"},
    {"Chain and source reads",
     "every read of /signing_key_event's entries and genesis.bitcoin answered and matching",
     "a sound proof that carries signing_key_event",
     "KEY_EVENT_COMMITMENT info not_attributable at /signing_key_event, the run not being " <>
       "attributed to Truestamp"},
    {"Chain and source reads",
     "a /signing_key_event entry whose read fails, and one whose read skips",
     "a sound proof that carries signing_key_event",
     "KEY_EVENT_COMMITMENT fail, then skip, with the code of its first failing or skipped input"},
    {"The committed leaf count",
     "the epoch-level lie carried into a Stellar entry's record, and the memo read",
     "the record's leaf_count and epoch_hash recomputed, at /commitments/stellar and at " <>
       "/signing_key_event/commitments/stellar",
     "DERIVE passes; CHAIN fail chain_mismatch at the entry, where the memo differs"},
    {"The window", "every read answered and matching", "a sound item with all three witnesses",
     "WINDOW pass; each edge's instant and basis"},
    {"The window", "reads whose submitted-after edge is later than the submitted-before edge",
     "a sound proof", "WINDOW fail window_inverted; label failed; both edges null"},
    {"The window", "an established window that the time in the subject's id lies outside",
     "a sound proof", "WINDOW pass, then info recorded_time_outside_window at the id's pointer"},
    {"The window", "every read answered and matching", "a sound block proof",
     "the submitted-before edge drawn; no submitted-after edge, its reason an empty list"},
    {"Gates", "a CHAIN read that fails", "a sound proof with entropy objects",
     "CHAIN fail chain_mismatch, and SOURCES still read"},
    {"Gates", "a proof with a failure in POLICY or in DERIVE, run online",
     "any single-defect proof of those steps",
     "every CHAIN and SOURCES row skip prior_failure, no read made"}
  ]

  # The codes only an online case can give.
  @codes ~w(keyring_unavailable chain_mismatch source_unreachable not_held_by_source
            not_yet_indexed chain_not_final entropy_mismatch window_inverted
            recorded_time_outside_window)

  @doc "Each pending online case: `{class, configuration, proof, expected}`."
  def pending, do: @pending

  @doc "The reason codes only an online case can give, each pending until the replay format."
  def codes, do: @codes
end
