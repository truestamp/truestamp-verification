# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Mix.Tasks.Truestamp.AgentLines do
  @shortdoc "Prints the agent-test lines of SPEC.md 7.4 that the reference verifier computes"

  @moduledoc """
  Gives, for each proof of a runs file, the lines of the agent-sufficiency test (SPEC.md
  section 7.4) that the reference verifier computes, every line but the two window lines:

      mix truestamp.agent_lines RUNS_JSON

  Standard output carries one JSON document, written with JCS: an array with one entry per
  run, in the file's order, each `{id, lines}`, or `{error, id}`. The generator runs it as
  its own process and writes the lines under `agent-test/expected/`.
  `Truestamp.Verifier.AgentLines` describes the runs file, each line and each exit code.

  The project's `mix.exs` runs this task through an alias that first compiles the project
  with a quiet shell, so a run that compiles writes no compiler line to standard output.
  Both streams are written as raw bytes.
  """

  use Mix.Task

  alias Mix.Tasks.Truestamp.Verify
  alias Truestamp.Verifier.AgentLines

  @requirements ["app.start"]

  @impl Mix.Task
  def run(argv), do: argv |> AgentLines.main() |> Verify.finish()
end
