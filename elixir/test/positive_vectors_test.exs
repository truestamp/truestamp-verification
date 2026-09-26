# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Truestamp.Verifier.PositiveVectorsTest do
  # The sound proofs under vectors/positive/ (SPEC.md 13.2), which generator/generate.exs
  # writes and checks. The generator has no schema interpreter, so these tests hold each proof
  # to spec/schema.json with the test suite's own, read it under the parsing rules, and pair it
  # with its trace. The generator's --check rederives everything else.
  use ExUnit.Case, async: true

  alias Truestamp.Verifier.Test.{SchemaSubset, StrictJSON}

  @root Path.expand("../..", __DIR__)
  @dir Path.join(@root, "vectors/positive")
  @files @dir |> Path.join("*") |> Path.wildcard(match_dot: true) |> Enum.sort()
  # Each proof's name (SPEC.md 13.2): its type, or its type, a hyphen and a variant.
  @names %{
    "beacon" => "beacon",
    "beacon-empty" => "beacon",
    "block" => "block",
    "block-emergency-rotation" => "block",
    "block-rotation" => "block",
    "entropy_bitcoin" => "entropy_bitcoin",
    "entropy_nist" => "entropy_nist",
    "entropy_stellar" => "entropy_stellar",
    "item" => "item",
    "item-genesis-witness" => "item",
    "item-rotation-witness" => "item"
  }
  for file <- @files, do: @external_resource(file)

  defp read(path) do
    {:ok, value} = path |> File.read!() |> StrictJSON.decode()
    value
  end

  test "holds one proof and one trace of each name, and nothing else" do
    expected =
      for name <- Map.keys(@names), suffix <- ~w(.proof.json .trace.json), do: name <> suffix

    assert Enum.map(@files, &Path.basename/1) == Enum.sort(expected)
  end

  for {name, type} <- @names do
    @name name
    @type_name type

    test "#{name}.proof.json reads under the parsing rules and satisfies the schema" do
      path = Path.join(@dir, @name <> ".proof.json")
      bytes = File.read!(path)
      document = read(path)
      max = read(Path.join(@root, "spec/constants.json"))["MAX_DOCUMENT_OCTETS"]

      refute String.ends_with?(bytes, "\n")
      assert byte_size(bytes) <= max
      assert document["proof"]["type"] == @type_name
      assert document["proof"]["environment"] == "test"
      assert SchemaSubset.valid?(read(Path.join(@root, "spec/schema.json")), document)
    end

    test "#{name}.trace.json is a list of trace rows, each of which passes" do
      rows = read(Path.join(@dir, @name <> ".trace.json"))

      assert rows != []

      for row <- rows do
        assert Enum.sort(Map.keys(row)) ==
                 ~w(construction declared inputs part recomputed status)

        assert row["status"] == "pass"
        # A handover signature's recomputed value is the hex of the 32 octets it was verified
        # over (SPEC.md 10.6); every other row compares equal values.
        assert row["declared"] == row["recomputed"] or
                 String.ends_with?(row["part"], "/handover_signature")
      end
    end
  end
end
