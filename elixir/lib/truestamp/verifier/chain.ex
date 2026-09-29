# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Truestamp.Verifier.Chain do
  @moduledoc """
  Step 10 of SPEC.md section 10.2, CHAIN, as an offline verifier makes it. The reference
  verifier makes no chain read (section 8.3), so the external gate that DERIVE decided is
  always closed, and CHAIN reports what an online run would read without reading it.

  CHAIN gives one row for each commitment entry, at `/commitments/C` and
  `/signing_key_event/commitments/C`, and one for each `metadata.genesis.bitcoin` P carries,
  at any block position (section 10.4, "Rows"), each at the pointer of its entry or object,
  in document order. Then, when P carries `signing_key_event`, CHAIN ends with the
  KEY_EVENT_COMMITMENT row at `/signing_key_event` (section 10.3), which is the one row out
  of document order.

  Every row is a skip, by the run's `external_gate` (section 10.2):

  | `external_gate` | Every row |
  |---|---|
  | `:offline`, no row so far fails | `skip offline`, whose message names the read that would confirm it (section 10.4, "Offline") |
  | `:prior_failure`, a row of POLICY or DERIVE failed | `skip prior_failure` |

  KEY_EVENT_COMMITMENT follows the first item of its list in section 10.3: the external gate
  is closed, so it is `skip prior_failure` when a row of POLICY or DERIVE failed, and
  otherwise `skip offline`. A run that has ended passes through unchanged, since its CHAIN
  row is already `skip prior_failure` with part null; so does a run with no decided gate,
  which only an ended run is. The rows' `values` are empty: an offline row read nothing.
  """

  alias Truestamp.Verifier.{Layout, Pointer, Row, Run}

  @step "CHAIN"

  @doc """
  Step 10, CHAIN: one skip row for each read an online run would make, and
  KEY_EVENT_COMMITMENT.
  """
  @spec chain(Run.t()) :: Run.t()
  def chain(%Run{ended: true} = run), do: run

  def chain(%Run{proof: proof, external_gate: gate} = run)
      when gate in [:offline, :prior_failure] do
    reads =
      proof
      |> entries()
      |> Pointer.sort_by(&elem(&1, 0))
      |> Enum.map(fn {at, read} -> row(gate, Pointer.encode(at), read) end)

    run = Enum.reduce(reads, run, &Run.add_row(&2, &1))

    if is_map(proof["signing_key_event"]),
      do: Run.add_row(run, row(gate, "/signing_key_event", :key_event_commitment)),
      else: run
  end

  # Each entry CHAIN reads, as {pointer, the read that would confirm it}.
  defp entries(proof) do
    commitments =
      for {at, chain, _entry} <- Layout.commitment_entries(proof),
          do: {at, {:commitment, chain, top_level?(at)}}

    genesis = for {at, _bitcoin} <- Layout.genesis_bitcoin(proof), do: {at, :genesis_bitcoin}
    commitments ++ genesis
  end

  defp top_level?(["commitments" | _chain]), do: true
  defp top_level?(_at), do: false

  defp row(:prior_failure, part, _read),
    do: Row.new(@step, :prior_failure, part, "Not read: a check before CHAIN failed.")

  defp row(:offline, part, read),
    do: Row.new(@step, :offline, part, "Offline: no read was made in this run. " <> would(read))

  defp would({:commitment, "stellar", true}) do
    "The read of this Stellar transaction on the pinned network, and of the ledger it names, " <>
      "would confirm this entry and give its candidate for the submitted-before edge."
  end

  defp would({:commitment, "stellar", false}),
    do: "The read of this Stellar transaction on the pinned network would confirm this entry."

  defp would({:commitment, "bitcoin", true}) do
    "The read of the best-chain Bitcoin block at this entry's height on the pinned network, " <>
      "and at that height + 10, would confirm this entry and give its candidate for the " <>
      "submitted-before edge."
  end

  defp would({:commitment, "bitcoin", false}) do
    "The read of the best-chain Bitcoin block at this entry's height on the pinned network " <>
      "would confirm this entry."
  end

  defp would(:genesis_bitcoin) do
    "The read of the best-chain Bitcoin block at this height on the pinned network would " <>
      "confirm the genesis block's Bitcoin block hash."
  end

  defp would(:key_event_commitment) do
    "The chain reads of the signing key event's commitment entries would show where the " <>
      "signing key's key event was committed."
  end
end
