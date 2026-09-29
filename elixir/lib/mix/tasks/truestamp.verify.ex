# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Mix.Tasks.Truestamp.Verify do
  @shortdoc "Verifies a Truestamp proof offline, as SPEC.md section 10 says"

  @moduledoc """
  Verifies a Truestamp proof with the reference verifier, offline (SPEC.md sections 8.3 and
  10.2):

      mix truestamp.verify FILE [--keyring FILE | --no-keyring] [--environment NAME]
                                [--expected-hash HEX] [--trace FILE]

  Standard output carries one JSON document, written with JCS: the report of section 10.5,
  with exactly that section's members, or a bare rejection's `{code, message, sub_reason}`.
  On exit 1 or 2 it carries nothing.
  `--trace FILE` writes the trace of section 10.6 to FILE, in the canonical form of section
  9 that `vectors/positive/<name>.trace.json` is in. Standard error carries the human
  output. Both streams are written as raw bytes, so the JSON is UTF-8 whatever the locale.
  The exit code is section 12.2's. `Truestamp.Verifier.Command` describes each option and
  each output.

  The project's `mix.exs` runs this task through an alias that first compiles the project
  with a quiet shell, so a run that compiles, a first run on a fresh checkout included,
  writes no compiler line to standard output; compiler warnings and errors go to standard
  error.

  To check a vector, give its environment and keyring, as `vectors/cases.json` does:
  `mix truestamp.verify ../vectors/positive/item.proof.json --environment test
  --keyring ../vectors/keyring.test.json`. With no option the run is under E_v `prod`, and
  every vector fails `environment_mismatch`.
  """

  use Mix.Task

  alias Truestamp.Verifier.Command

  @requirements ["app.start"]

  @impl Mix.Task
  def run(argv), do: argv |> Command.main() |> finish()

  @doc """
  Writes an outcome of `Truestamp.Verifier.Command.main/1`, each stream as raw bytes, then
  exits with its code, or returns `:ok` when the code is 0.
  """
  @spec finish(Command.outcome()) :: :ok
  def finish({code, stdout, stderr}) do
    IO.binwrite(:stdio, stdout)
    IO.binwrite(:stderr, stderr)
    if code == 0, do: :ok, else: exit({:shutdown, code})
  end
end
