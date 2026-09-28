# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Truestamp.Verifier do
  @moduledoc """
  The reference verifier's steps of SPEC.md section 10.2, in order, one function per step:

  | Steps | Module |
  |---|---|
  | 0 to 6, the gate | `Truestamp.Verifier.Gate` |
  | 7 SHAPE | `Truestamp.Verifier.Shape.shape/1` |
  | 8 POLICY | `Truestamp.Verifier.Policy.policy/1` |

  `run/2` makes them over a document's bytes, and `run_file/2` over a file, which the gate
  reads after CONFIGURATION. Each gives what `Truestamp.Verifier.Gate.run/2` gives: a bare
  rejection, an input that cannot be read, or `{:ok, run}`, a `Truestamp.Verifier.Run` with
  the rows of every step it made. A run that ended at the gate or at SHAPE already holds a
  `skip prior_failure` row for each later step up to EXPECTED_HASH.
  """

  alias Truestamp.Verifier.{Config, Gate, Policy, Run, Shape}

  @doc "The steps over the bytes of a document."
  @spec run(Config.t(), binary()) :: Gate.result()
  def run(%Config{} = config, bytes) when is_binary(bytes),
    do: config |> Gate.run(bytes) |> after_gate()

  @doc "The steps over the file at `path`, read only after CONFIGURATION."
  @spec run_file(Config.t(), Path.t()) :: Gate.result()
  def run_file(%Config{} = config, path), do: config |> Gate.run_file(path) |> after_gate()

  defp after_gate({:ok, %Run{} = run}), do: {:ok, run |> Shape.shape() |> Policy.policy()}
  defp after_gate(other), do: other
end
