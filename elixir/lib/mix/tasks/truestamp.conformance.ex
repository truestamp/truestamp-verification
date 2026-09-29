# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Mix.Tasks.Truestamp.Conformance do
  @shortdoc "Runs every offline case of a cases.json and prints what SPEC.md 13.1 compares"

  @moduledoc """
  Runs the reference verifier over the offline cases of a file in the form of
  `vectors/cases.json` (SPEC.md sections 13.1 and 13.2), each with its full configuration,
  its network pins included:

      mix truestamp.conformance CASES_JSON

  Standard output carries one JSON document, written with JCS: an array with one entry per
  offline case, in the file's order, each `{id, output}`, where `output` is what section
  13.1 compares of the case's run: a bare rejection's `code` and `sub_reason`, or the
  report's `label` and its rows reduced to `[code, part, status, step]`, with the trace rows
  but `inputs` for a case whose `expected` names a trace. Online cases are left out, since
  the reference verifier is offline. The entry point compares nothing:
  `generator/generate.exs --check` compares this output with `cases.json`.
  `Truestamp.Verifier.Conformance` describes each output and each exit code.

  The project's `mix.exs` runs this task through an alias that first compiles the project
  with a quiet shell, so a run that compiles writes no compiler line to standard output.
  Both streams are written as raw bytes, so the JSON is UTF-8 whatever the locale.

  From `elixir/`: `MIX_ENV=test mix truestamp.conformance ../vectors/cases.json`.
  """

  use Mix.Task

  alias Mix.Tasks.Truestamp.Verify
  alias Truestamp.Verifier.Conformance

  @requirements ["app.start"]

  @impl Mix.Task
  def run(argv), do: argv |> Conformance.main() |> Verify.finish()
end
