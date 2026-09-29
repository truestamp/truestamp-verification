# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Truestamp.Verifier.Derive do
  @moduledoc """
  Step 9 of SPEC.md section 10.2, DERIVE, offline, in every run that reaches it, and the one
  engine of section 10.6 that every DERIVE check goes through.

  DERIVE recomputes each value that the constructions text (section 7.3) defines from the
  preimage P carries, compares it with the value P carries for it, and checks every link
  (section 10.3). It makes every check and does not stop at a failure. Its checks are, in
  this order:

  | Part of step 9 | Module |
  |---|---|
  | (a) subject hashes, (b) block nodes, (c) epochs | `Truestamp.Verifier.Derive.Records` |
  | (b) each key event a block node carries (section 10.3) | `Truestamp.Verifier.Derive.KeyEvents`, through `Records` |
  | (d) Bitcoin evidence | `Truestamp.Verifier.Derive.BitcoinEvidence` |
  | (e) LINK_INCLUSION, LINK_WITNESS, LINK_HEAD, LINK_KEY_EVENT, LINK_CHAIN_ORDER | `Truestamp.Verifier.Derive.Links` |

  Each check is a `Truestamp.Verifier.Check` naming its part by section 10.2's one rule: the
  carried value it finds wrong when it fails, which for a recomputation is the declared
  value. A check whose input could not be computed is not made and gives no check (the
  Bitcoin rows that read a structure that is not well formed).

  **The engine.** `engine/1` takes the checks in the order above and gives:

  - the rows: one for each check, in the document order of their parts (`Pointer.sort_by/2`,
    a stable sort), so that rows sharing a part keep the order of their checks: the order of
    parts (a) to (e) and of each table's rows, with LINK_INCLUSION's root rows at one
    `merkle_root` in the document order of their inclusion proofs;
  - the trace: one trace row for each row whose part is a CHECKED value, other than a row of
    LINK_HEAD, LINK_KEY_EVENT or LINK_CHAIN_ORDER, in the same order, so a root that three
    beacon walks reach has three trace rows (section 10.6).

  A mismatch is `derivation_mismatch` unless its check names another code
  (`bitcoin_evidence_invalid`, `key_event_mismatch` or `ordering_violation`).

  **What DERIVE leaves to the later steps.** A failure here does not end the run. The
  external gate (section 10.2) is decided once, when DERIVE ends: it is open when the caller
  did not ask for an offline run and no row so far is `fail`. The reference verifier always
  runs offline (section 8.3), so the run's `external_gate` becomes `:prior_failure` when a
  row so far fails, and `:offline` otherwise; CHAIN and SOURCES then give each of their rows
  that status's `skip`. A run that has already ended passes through unchanged, since its
  DERIVE row is already `skip prior_failure`.

  DERIVE reads P, K (for LINK_KEY_EVENT) and the run's attribution (for the key-history
  row), and nothing else of the run: not `constructions`, which only SHAPE reads (section
  10.6, rule 1).
  """

  alias Truestamp.Verifier.{Check, Pointer, Row, Run}
  alias Truestamp.Verifier.Derive.{BitcoinEvidence, Links, Records}

  @doc "Step 9, DERIVE: every recomputation and every link, with the run's trace."
  @spec derive(Run.t()) :: Run.t()
  def derive(%Run{ended: true} = run), do: run

  def derive(%Run{proof: proof, public_key: public_key, attribution: attribution} = run) do
    {rows, trace} = proof |> checks(public_key, attribution) |> engine()
    run = Enum.reduce(rows, %{run | trace: trace}, &Run.add_row(&2, &1))
    %{run | external_gate: if(Run.failed?(run), do: :prior_failure, else: :offline)}
  end

  @doc """
  Every check of DERIVE for P, in the order of step 9's parts (a) to (e) and of each table's
  rows, before the engine orders them. `public_key` is the 32 octets of K, and `attribution`
  the run's.
  """
  @spec checks(map(), <<_::256>>, String.t()) :: [Check.t()]
  def checks(proof, public_key, attribution) do
    Records.checks(proof) ++
      BitcoinEvidence.checks(proof) ++ Links.checks(proof, public_key, attribution)
  end

  @doc "The one engine: the rows and the trace of `checks`, each in DERIVE's order."
  @spec engine([Check.t()]) :: {[Row.t()], [map()]}
  def engine(checks) do
    ordered = Pointer.sort_by(checks, & &1.part)
    rows = Enum.map(ordered, &Check.row/1)
    trace = for %Check{traced: true} = check <- ordered, do: Check.trace_row(check)
    {rows, trace}
  end
end
