# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Truestamp.Verifier.PolicyTest do
  # Step 8, POLICY (SPEC.md 10.2 and 9, D74, D75), on every sound value of P, beside the
  # vectors' own cases in shape_policy_cases_test.exs:
  #
  # - one row for each `network` member of P, every one of them, in document order;
  # - each network changed fails at exactly its own row, and each pin changed fails exactly
  #   the rows it governs: a chain's commitment pin its commitment entries (and, for Bitcoin,
  #   each genesis.bitcoin), a source's entropy pin its entropy objects, never the other;
  # - a failure does not end the run, and the pins are the run's, never the document's.
  use ExUnit.Case, async: true

  alias Truestamp.Verifier.{Config, Policy, Row, Run}
  alias Truestamp.Verifier.Test.ProofMutants

  @bases ProofMutants.bases()
  @networks %{"bitcoin" => ~w(mainnet testnet regtest), "stellar" => ~w(public testnet)}

  defp run(proof, pins) do
    config = Config.new!(environment: "test", keyring: :none, networks: pins)

    %Run{
      config: config,
      keyring: nil,
      trust_root: %{digest: nil, kind: :none, location: nil},
      proof: proof,
      rows: [Row.pass("SHAPE", nil, "held")]
    }
  end

  defp policy_rows(proof, pins),
    do:
      proof
      |> run(pins)
      |> Policy.policy()
      |> Map.fetch!(:rows)
      |> tl()
      |> Enum.map(&Row.reduce/1)

  # Every `network` member of P, by the test's own walk: {pointer, kind, chain}.
  defp networks(proof) do
    for {at, value} <- ProofMutants.nodes(proof), List.last(at) == "network", is_binary(value) do
      {at, kind(at), chain(proof, at)}
    end
  end

  defp kind(at) do
    cond do
      "genesis" in at -> :commitment
      "commitments" in at -> :commitment
      true -> :entropy
    end
  end

  defp chain(proof, at) do
    parent = ProofMutants.get(proof, Enum.drop(at, -1))

    cond do
      "genesis" in at -> "bitcoin"
      "commitments" in at -> Enum.at(at, -2)
      true -> parent["source"]
    end
  end

  # The pins under which every network of `proof` passes.
  defp own_pins(proof) do
    base = %{
      commitment: %{"bitcoin" => "regtest", "stellar" => "testnet"},
      entropy: %{"bitcoin" => "regtest", "stellar" => "testnet"}
    }

    Enum.reduce(networks(proof), base, fn {at, kind, chain}, pins ->
      put_in(pins, [kind, chain], ProofMutants.get(proof, at))
    end)
  end

  defp other_network(chain, network), do: @networks[chain] |> List.delete(network) |> hd()

  test "the sound values of P are consistent, one network per pin" do
    for {name, proof} <- @bases do
      pins = own_pins(proof)

      for {at, kind, chain} <- networks(proof) do
        assert ProofMutants.get(proof, at) == pins[kind][chain], "#{name}: #{inspect(at)}"
      end
    end
  end

  test "one pass row for each network member, in document order" do
    for {name, proof} <- @bases do
      rows = policy_rows(proof, own_pins(proof))

      expected =
        for {at, _kind, _chain} <- networks(proof),
            do: [nil, ProofMutants.show(at), "pass", "POLICY"]

      assert rows == expected, name
      assert rows != []
    end
  end

  test "the rows cover commitments at both positions, every entropy object and genesis.bitcoin" do
    parts =
      for {_name, proof} <- @bases,
          [_, part, _, _] <- policy_rows(proof, own_pins(proof)),
          uniq: true,
          do: part

    for part <- ~w(/commitments/bitcoin/network /commitments/stellar/network
                   /signing_key_event/commitments/bitcoin/network
                   /signing_key_event/commitments/stellar/network /subject/entropy/network
                   /witnesses/entropy_bitcoin/network /witnesses/entropy_stellar/network
                   /observations/entropy_bitcoin/entropy/network
                   /observations/entropy_stellar/entropy/network
                   /block/record/metadata/genesis/bitcoin/network
                   /witnesses/block/record/metadata/genesis/bitcoin/network
                   /signing_key_event/block/record/metadata/genesis/bitcoin/network) do
      assert part in parts, part
    end
  end

  test "a network changed fails at exactly its own row" do
    for {name, proof} <- @bases, {at, _kind, chain} <- networks(proof) do
      pins = own_pins(proof)
      mutant = ProofMutants.put(proof, at, other_network(chain, ProofMutants.get(proof, at)))

      for [code, part, status, "POLICY"] <- policy_rows(mutant, pins) do
        if part == ProofMutants.show(at),
          do: assert([code, status] == ["network_mismatch", "fail"], "#{name}: #{part}"),
          else: assert([code, status] == [nil, "pass"], "#{name}: #{part}")
      end
    end
  end

  test "a pin changed fails exactly the rows it governs" do
    for {name, proof} <- @bases, kind <- [:commitment, :entropy], chain <- ~w(bitcoin stellar) do
      own = own_pins(proof)
      pins = update_in(own, [kind, chain], &other_network(chain, &1))
      governed = for {at, ^kind, ^chain} <- networks(proof), do: ProofMutants.show(at)

      for [code, part, status, "POLICY"] <- policy_rows(proof, pins) do
        expected = if part in governed, do: ["network_mismatch", "fail"], else: [nil, "pass"]
        assert [code, status] == expected, "#{name}: #{kind} #{chain} at #{part}"
      end
    end
  end

  test "under staging's default pins, Bitcoin commits to regtest and reads entropy from mainnet" do
    proof = @bases["positive item"]
    pins = Config.default_pins("staging")
    assert pins.commitment["bitcoin"] == "regtest" and pins.entropy["bitcoin"] == "mainnet"

    rows = policy_rows(proof, pins)
    assert ["network_mismatch", "/witnesses/entropy_bitcoin/network", "fail", "POLICY"] in rows
    assert [nil, "/commitments/bitcoin/network", "pass", "POLICY"] in rows

    moved = ProofMutants.put(proof, ~w(witnesses entropy_bitcoin network), "mainnet")
    assert Enum.all?(policy_rows(moved, pins), &match?([nil, _, "pass", _], &1))
  end

  test "a failure does not end the run, and values give the pin and the declared network" do
    proof = @bases["positive item"]
    pins = put_in(own_pins(proof), [:commitment, "stellar"], "public")
    policed = proof |> run(pins) |> Policy.policy()
    refute policed.ended
    assert Run.failed?(policed)

    failed = Enum.filter(policed.rows, &(&1.status == :fail))
    assert failed != []

    for row <- failed do
      assert row.values["pin"] == "public"
      assert row.values["declared"] == "testnet"
    end
  end

  test "an ended run passes through" do
    ended =
      @bases["positive item"] |> run(own_pins(@bases["positive item"])) |> Map.put(:ended, true)

    assert Policy.policy(ended) == ended
  end
end
