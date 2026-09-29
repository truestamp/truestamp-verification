# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Truestamp.Verifier.Verdict do
  @moduledoc """
  Step 14 of SPEC.md section 10.2, VERDICT: the label, the run's code and the two edges of
  section 10.5. It reports no row.

  The label is the first of these that applies (section 10.5):

  | `label` | When |
  |---|---|
  | `failed` | any row is `fail` |
  | `unattributed` | the attribution is `unattributed` |
  | `supplied-keyring` | the attribution is `keyring:<d>` |
  | `internally-consistent` | the attribution is `truestamp`, and the submitted-before edge is not established |
  | `verified` | the attribution is `truestamp`, and the submitted-before edge is established |

  The run's code is present exactly when the label is `failed`: the code of the first failing
  step, which is the code of that step's first failing row (section 10.2), so the code of the
  first failing row in the run's rows, which are in step order.

  When the label is `failed`, VERDICT sets both edges to null, so `window` is
  `not_established` (D58 item 3). The reference verifier draws no edge in any run (section
  8.3), so its edges are always null and it never gives `verified`; that label stays in the
  table so that VERDICT is the rule of section 10.5 whole.
  """

  alias Truestamp.Verifier.{Row, Run}

  @labels ~w(failed unattributed supplied-keyring internally-consistent verified)

  @doc "The labels of section 10.5, in the order the first that applies is taken."
  @spec labels() :: [String.t()]
  def labels, do: @labels

  @doc "Step 14, VERDICT: the run with its label, its code and its edges set."
  @spec verdict(Run.t()) :: Run.t()
  def verdict(%Run{} = run) do
    case Enum.find(run.rows, &(&1.status == :fail)) do
      %Row{code: code} ->
        %{run | label: "failed", code: code, submitted_after: nil, submitted_before: nil}

      nil ->
        %{run | label: label(run.attribution, run.submitted_before), code: nil}
    end
  end

  defp label("unattributed", _before), do: "unattributed"
  defp label("keyring:" <> _digest, _before), do: "supplied-keyring"
  defp label("truestamp", nil), do: "internally-consistent"
  defp label("truestamp", _before), do: "verified"
end
