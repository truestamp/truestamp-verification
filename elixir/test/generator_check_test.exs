# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Truestamp.Verification.GeneratorCheckTest do
  # The generator's check of the files it writes, end to end (SPEC.md 13.2 and 7.4): in a copy
  # of this repository, dependencies and test build included, a file under vectors/ and one
  # under agent-test/expected/ are changed, the prompt every session receives is edited by
  # hand, and a file the generator does not write is added under agent-test/mutants/.
  # `elixir generator/generate.exs --check` then has to exit 1, naming each of those paths,
  # with the closing lines for a stale file and a stray one. The verifier is untouched, so
  # the conformance check passes.
  #
  # It runs the whole generator, so it is slow. It is tagged, so `mix test --exclude
  # generator_check` leaves it out, and `task check` runs it.
  use ExUnit.Case, async: true

  @moduletag :generator_check
  @moduletag timeout: 600_000

  @root Path.expand("../..", __DIR__)

  # The copy: every entry of the repository but its version control and its ignored tmp/,
  # and of elixir/ everything but the build, of which only this test build is copied.
  defp copy do
    copy = Path.join(System.tmp_dir!(), "truestamp-files-#{System.unique_integer([:positive])}")
    on_exit(fn -> File.rm_rf!(copy) end)
    File.mkdir_p!(Path.join([copy, "elixir", "_build"]))

    for entry <- File.ls!(@root),
        entry not in ~w(.git .jj tmp elixir),
        do: File.cp_r!(Path.join(@root, entry), Path.join(copy, entry))

    elixir = Path.join(@root, "elixir")

    for entry <- File.ls!(elixir),
        entry not in ~w(_build erl_crash.dump),
        do: File.cp_r!(Path.join(elixir, entry), Path.join([copy, "elixir", entry]))

    File.cp_r!(Mix.Project.build_path(), Path.join([copy, "elixir", "_build", "test"]))
    copy
  end

  defp append(copy, path, text) do
    full = Path.join(copy, path)
    assert File.regular?(full), "#{path} is not in the copy"
    File.write!(full, File.read!(full) <> text)
  end

  test "generate.exs --check fails on a stale vector, a stale agent-test file and a stray one" do
    elixir = System.find_executable("elixir")
    assert elixir, "elixir is not on PATH"
    copy = copy()

    changed =
      ~w(vectors/worked-example.json agent-test/PROMPT.md agent-test/expected/1-item/item.txt)

    for path <- changed, do: append(copy, path, "\n")

    stray = "agent-test/mutants/1-item/item.stray.proof.json"
    File.write!(Path.join(copy, stray), "{}\n")

    {output, exit_status} =
      System.cmd(
        "sh",
        ["-c", ~s(exec "$0" generator/generate.exs --check </dev/null 2>&1), elixir],
        cd: copy,
        env: [
          {"MIX_ENV", "test"},
          {"MIX_BUILD_PATH", nil},
          {"MIX_BUILD_ROOT", nil},
          {"MIX_DEPS_PATH", nil},
          {"MIX_EXS", nil}
        ]
      )

    assert exit_status == 1, output

    for path <- changed,
        do: assert(output =~ "generate: #{path} differs from what the generator writes", output)

    assert output =~ "generate: #{stray} is not a file the generator writes", output
    assert output =~ "vectors/ or agent-test/ is stale: run `task generate`", output
    assert output =~ "vectors/ or agent-test/ holds files the generator does not write", output
    refute output =~ "The reference verifier does not give the output cases.json expects"
  end
end
