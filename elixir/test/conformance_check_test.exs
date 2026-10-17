# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Truestamp.Verification.ConformanceCheckTest do
  # The generator's conformance check end to end (SPEC.md 13.2, generator/lib/conformance.exs):
  # in a copy of this repository, dependencies and test build included, the reference
  # verifier (the library Truestamp.Verify, from the copy's deps/) is broken so that its
  # conformance entry point runs every case under its environment's default network pins, and `elixir generator/generate.exs --check` then has to exit 1,
  # naming only cases whose pins are not their environment's defaults, the policy-*-entropy_*
  # cases among them, whose rows those pins change, and closing with the line for an output
  # that differs. The vectors of the copy are untouched, so no
  # other check of the generator fails.
  #
  # It runs the whole generator, so it is slow. It is tagged, so `mix test --exclude
  # generator_check` leaves it out, and `task check` runs it.
  use ExUnit.Case, async: true

  alias Truestamp.Verification.Test.StrictJSON

  @moduletag :generator_check
  @moduletag timeout: 600_000

  @root Path.expand("../..", __DIR__)

  # The copy: every entry of the repository but its version control and its ignored tmp/,
  # and of elixir/ everything but the build, of which only this test build is copied.
  defp copy do
    copy = Path.join(System.tmp_dir!(), "truestamp-check-#{System.unique_integer([:positive])}")
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

  # The mutant: the reference verifier's conformance entry point, the library's
  # Truestamp.Verify.Conformance.options/2 in the copy's deps/, passes no network pins, so
  # every case runs under the default pins of its environment in place of its own. The
  # library's build is removed from the copy, so Mix compiles the mutated source.
  defp ignore_network_pins(copy) do
    library = Path.join([copy, "elixir", "deps", "truestamp_verify"])
    path = Path.join([library, "lib", "truestamp", "verify", "conformance.ex"])
    source = File.read!(path)
    pins = "[environment: environment, networks: networks, expected_hash:"
    assert length(String.split(source, pins)) == 2, "the mutant's line is not in #{path}"

    defaults = "[environment: environment, networks: %{}, expected_hash:"
    File.write!(path, String.replace(source, pins, defaults))
    File.rm_rf!(Path.join([copy, "elixir", "_build", "test", "lib", "truestamp_verify"]))
  end

  # The ids of the cases whose network pins are not the defaults of their environment.
  defp pinned_cases(copy) do
    defaults = StrictJSON.read_data!(Path.join([copy, "spec", "network-pins.json"]))

    for %{"id" => id, "config" => config} <-
          StrictJSON.read_data!(Path.join([copy, "vectors", "cases.json"])),
        config["networks"] != defaults[config["environment"]],
        do: id
  end

  test "generate.exs --check fails on a verifier that ignores network pins, naming the cases" do
    elixir = System.find_executable("elixir")
    assert elixir, "elixir is not on PATH"
    copy = copy()
    ignore_network_pins(copy)

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

    named =
      ~r/^generate: case ([^:]+): /m
      |> Regex.scan(output, capture: :all_but_first)
      |> List.flatten()

    # Every case named runs under pins other than its environment's defaults, and among them
    # are the six policy-*-entropy_* cases, whose POLICY rows those pins change. The check
    # runs the online cases too, so online cases whose pins differ are named as well.
    pinned = pinned_cases(copy)
    policy = Enum.filter(pinned, &(&1 =~ ~r/\Apolicy-[a-z]+-entropy_[a-z]+\z/))
    assert length(policy) == 6
    assert named != [] and Enum.all?(named, &(&1 in pinned)), output
    assert Enum.all?(policy, &(&1 in named)), output
    assert output =~ "The reference verifier does not give the output cases.json expects"

    # Only the conformance check fails: generate.exs closes with none of the lines it gives
    # for a file under vectors/ or agent-test/ that is stale, stray or unreadable.
    refute output =~
             ~r/is stale: run|holds files the generator does not write|holds files that cannot be read/
  end
end
