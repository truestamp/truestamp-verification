# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Truestamp.Verifier.Policy do
  @moduledoc """
  Step 8 of SPEC.md section 10.2, POLICY, offline, in every run that reaches it. Each
  `network` member of P must equal the verifier's pin, else `network_mismatch` at that
  `network`:

  | `network` of | Pin |
  |---|---|
  | each commitment entry, at `/commitments` and `/signing_key_event/commitments` | the commitment pin for its chain |
  | each Stellar or Bitcoin entropy object, at `/subject/entropy`, `/witnesses/entropy_X` and `/observations/entropy_X/entropy` | the entropy pin for its source |
  | each `metadata.genesis.bitcoin`, at any block position | the Bitcoin commitment pin |

  The pins are the run's (`Truestamp.Verifier.Config`, section 9): the default row of
  `spec/network-pins.json` for E_v, or pins given in its place. No pin comes from the
  document, and a network the proof lacks is never supplied: SHAPE has held every position
  above to carry one.

  Each comparison reports one row, in the document order of its part. Its `values` hold the
  chain or source its position names, the pin and the pin's kind, and on a failure the
  proof's network under `"declared"` (section 10.5). A failure here does not end the run:
  DERIVE still runs, and the external gate stays closed. A run that has ended passes
  through.
  """

  alias Truestamp.Verifier.{Config, Layout, Pointer, Row, Run}

  @step "POLICY"

  @doc "Step 8, POLICY: one row for each `network` of P, against the run's pins."
  @spec policy(Run.t()) :: Run.t()
  def policy(%Run{ended: true} = run), do: run

  def policy(%Run{proof: proof, config: %Config{networks: pins}} = run) do
    proof
    |> comparisons()
    |> Pointer.sort_by(&elem(&1, 0))
    |> Enum.reduce(run, fn comparison, run -> Run.add_row(run, row(comparison, pins)) end)
  end

  # {pointer of the network, :commitment or :entropy, chain or source, the network}.
  defp comparisons(proof) do
    commitments =
      for {at, chain, entry} <- Layout.commitment_entries(proof),
          do: {at ++ ["network"], :commitment, chain, Map.fetch!(entry, "network")}

    entropy =
      for {at, source, object} <- Layout.entropy_objects(proof),
          source in Layout.chains(),
          do: {at ++ ["network"], :entropy, source, Map.fetch!(object, "network")}

    genesis =
      for {at, bitcoin} <- Layout.genesis_bitcoin(proof),
          do: {at ++ ["network"], :commitment, "bitcoin", Map.fetch!(bitcoin, "network")}

    commitments ++ entropy ++ genesis
  end

  defp row({at, kind, chain, network}, pins) do
    pin = pins |> Map.fetch!(kind) |> Map.fetch!(chain)
    part = Pointer.encode(at)
    values = %{"chain" => chain, "pin" => pin, "pin_kind" => Atom.to_string(kind)}

    if network === pin do
      Row.pass(@step, part, "The #{chain} network is the pinned #{pin}.", values)
    else
      message =
        "This proof names a #{chain} network other than the #{pin} network this run pins " <>
          "for its #{kind} #{noun(kind)}."

      Row.new(@step, :network_mismatch, part, message, Map.put(values, "declared", network))
    end
  end

  defp noun(:commitment), do: "entries"
  defp noun(:entropy), do: "objects"
end
