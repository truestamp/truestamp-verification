# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Truestamp.Verifier.Window do
  @moduledoc """
  Step 12 of SPEC.md section 10.2, WINDOW: the submission window of section 11, drawn and
  reported. Its edges come only from reads made in this run (section 11), and the reference
  verifier makes none (section 8.3): no CHAIN or SOURCES row passes, so no candidate exists,
  both edges are absent, and the run's `submitted_after` and `submitted_before` stay nil.

  WINDOW gives the first of section 11.3's rows that applies, with a null part:

  1. a row so far has failed: `skip prior_failure`;
  2. both edges exist and are inverted: `fail window_inverted`, which needs both edges, so
     never here;
  3. the submitted-before edge does not exist: `info window_not_established`;
  4. otherwise `pass`, which needs that edge, so never here; nor, then, the row
     `info recorded_time_outside_window`, which only follows a pass.

  The `info window_not_established` row's `values` (section 11.3) hold `candidates`, every
  candidate the run read (none), and `absent`, for each absent edge its reason: the part and
  code of each CHAIN or SOURCES row that could have given a candidate, as
  `{"code", "part"}`. For `submitted_before` those are the CHAIN rows of the top-level
  entries, `/commitments/bitcoin` and `/commitments/stellar` (section 11.1); for
  `submitted_after`, every SOURCES row (section 11.2). A list is empty when the proof
  carries none, as for a block proof's submitted-after edge.

  A run that has ended passes through unchanged: its WINDOW row is already `skip
  prior_failure`.
  """

  alias Truestamp.Verifier.{Row, Run}

  @step "WINDOW"

  # The CHAIN rows whose reads give the submitted-before edge's candidates (section 11.1).
  @top_level ["/commitments/bitcoin", "/commitments/stellar"]

  @doc "Step 12, WINDOW: one row, part null."
  @spec window(Run.t()) :: Run.t()
  def window(%Run{ended: true} = run), do: run

  def window(%Run{} = run) do
    if Run.failed?(run) do
      message = "No window is drawn: a check of this run failed."
      Run.add_row(run, Row.new(@step, :prior_failure, nil, message))
    else
      Run.add_row(run, not_established(run))
    end
  end

  defp not_established(%Run{rows: rows}) do
    before_edge =
      for %Row{step: "CHAIN", part: part} = row <- rows, part in @top_level, do: reason(row)

    after_edge = for %Row{step: "SOURCES"} = row <- rows, do: reason(row)

    values = %{
      "absent" => %{"submitted_after" => after_edge, "submitted_before" => before_edge},
      "candidates" => []
    }

    message =
      "No submitted-before edge was drawn: this run made no chain read, so it establishes " <>
        "no submission window."

    Row.new(@step, :window_not_established, nil, message, values)
  end

  defp reason(%Row{code: code, part: part}),
    do: %{"code" => Atom.to_string(code), "part" => part}
end
