# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Truestamp.Verifier.Sources do
  @moduledoc """
  Step 11 of SPEC.md section 10.2, SOURCES, as an offline verifier makes it. The reference
  verifier makes no source read (section 8.3), so the external gate that DERIVE decided is
  always closed.

  SOURCES gives one row for each entropy object P carries, NIST's included (section 10.4,
  "Rows"): `/subject/entropy` in an entropy type, each `/witnesses/entropy_X` in an item and
  each `/observations/entropy_X/entropy` in a beacon (`Truestamp.Verifier.Layout`), at the
  pointer of the object, in document order. Every row is `skip offline`, whose message names
  the read that would confirm it, or `skip prior_failure` when a row of POLICY or DERIVE
  failed (the run's `external_gate`, section 10.2). A CHAIN failure would not close the gate
  for SOURCES, but offline no CHAIN row fails. A run that has ended passes through
  unchanged. The rows' `values` are empty: an offline row read nothing.
  """

  alias Truestamp.Verifier.{Layout, Pointer, Row, Run}

  @step "SOURCES"

  @doc "Step 11, SOURCES: one skip row for each entropy object."
  @spec sources(Run.t()) :: Run.t()
  def sources(%Run{ended: true} = run), do: run

  def sources(%Run{proof: proof, external_gate: gate} = run)
      when gate in [:offline, :prior_failure] do
    proof
    |> Layout.entropy_objects()
    |> Pointer.sort_by(&elem(&1, 0))
    |> Enum.reduce(run, fn {at, source, _object}, run ->
      Run.add_row(run, row(gate, Pointer.encode(at), source))
    end)
  end

  defp row(:prior_failure, part, _source),
    do: Row.new(@step, :prior_failure, part, "Not read: a check before CHAIN failed.")

  defp row(:offline, part, source),
    do: Row.new(@step, :offline, part, "Offline: no read was made in this run. " <> would(source))

  defp would("nist") do
    "The read of the NIST Randomness Beacon pulse at this object's chainIndex and pulseIndex " <>
      "would confirm it and give its candidate for the submitted-after edge."
  end

  defp would("stellar") do
    "The read of the Stellar ledger at this object's sequence on the pinned network would " <>
      "confirm it and give its candidate for the submitted-after edge."
  end

  defp would("bitcoin") do
    "The read of the Bitcoin block with this object's hash on the pinned network would " <>
      "confirm it and give its candidate for the submitted-after edge."
  end
end
