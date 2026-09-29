# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Truestamp.Verifier.ExitCodes do
  @moduledoc """
  The exit codes of SPEC.md section 12.2, as compiled constants: the table compiled from
  `spec/exit-codes.json`, in its order. A test holds the compiled table equal to that file
  and to SPEC.md's table.

  `code/1` gives the code for how a run of the command ended, each ending named by the
  words of its row, so a row the file changes stops the build:

  | Ending | Row |
  |---|---|
  | `{:label, label}`, one of the five labels of section 10.5 | `label <label>` |
  | `:runtime_error`, an invalid command line or an input that cannot be read, with no report | `a runtime error outside verification` |
  | `:fault`, a fault the verifier did not catch, or caught before steps 0 to 3 passed, with no report | `the verifier stopped on a fault` |
  | `:bare_rejection`, a bare rejection other than `configuration_error` | `a bare rejection other than configuration_error` |
  | `:configuration_error` | `configuration_error` |
  """

  alias Truestamp.Verifier.{SpecFile, Verdict}

  @typedoc "How a run of the command ended."
  @type ending ::
          {:label, String.t()} | :runtime_error | :fault | :bare_rejection | :configuration_error

  @external_resource SpecFile.path("exit-codes.json")
  @table (for %{"code" => code, "run" => run} <- SpecFile.read!("exit-codes.json") do
            {code, run}
          end)

  # The beginning of the row of each ending that is not a label.
  @others [
    runtime_error: "a runtime error outside verification",
    fault: "the verifier stopped on a fault",
    bare_rejection: "a bare rejection other than configuration_error",
    configuration_error: "configuration_error"
  ]

  @codes (for {ending, beginning} <-
                Enum.map(Verdict.labels(), &{{:label, &1}, "label " <> &1}) ++ @others,
              into: %{} do
            case for({code, run} <- @table, String.starts_with?(run, beginning), do: code) do
              [code] ->
                {ending, code}

              found ->
                raise "spec/exit-codes.json: #{inspect(ending)} has the rows #{inspect(found)}"
            end
          end)

  if Enum.sort(Map.values(@codes)) != @table |> Enum.map(&elem(&1, 0)) |> Enum.sort(),
    do: raise("spec/exit-codes.json: a row matches no ending, or two endings share one")

  @doc "The table of section 12.2, as `{code, run}`, in its order."
  @spec table() :: [{non_neg_integer(), String.t()}]
  def table, do: @table

  @doc "The exit code of an ending."
  @spec code(ending()) :: non_neg_integer()
  def code(ending), do: Map.fetch!(@codes, ending)
end
