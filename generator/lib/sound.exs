# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Generator.Sound do
  @moduledoc """
  The sound shapes the positive proofs must hold, each asserted on its own and read from the
  decoded proofs, so that an edit to the model cannot drop one unseen: every property SPEC.md
  13.3 names for its sound proofs, then the shapes P6.1's cases start from.
  """

  import Generator.Check

  alias Generator.{JCS, Pointer}

  @empty_root "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
  @alone %{"leaf_index" => 0, "path" => [], "tree_size" => 1}

  @doc "The failures over `proofs`, each decoded proof by its name."
  def run(proofs) do
    proofs = Enum.map(proofs, fn {_name, %{proof: proof}} -> proof end)
    items = for %{"type" => "item"} = p <- proofs, full_item?(p), do: p

    List.flatten([
      truth("an item with all three witnesses and both chains", items != []),
      for({label, holds} <- claims_properties(), do: truth(label, Enum.any?(items, holds))),
      truth("one such item whose claims hold all of these", Enum.any?(items, &all_claims?/1)),
      for({label, holds} <- properties(), do: truth(label, Enum.any?(proofs, holds)))
    ])
  end

  defp all_claims?(item),
    do: Enum.all?(claims_properties(), fn {_label, holds} -> holds.(item) end)

  defp full_item?(proof) do
    names = proof |> get("/subject/record/witness_hashes") |> Map.keys() |> Enum.sort()

    names == ~w(block entropy_bitcoin entropy_nist entropy_stellar) and
      proof |> get("/commitments") |> Map.keys() |> Enum.sort() == ~w(bitcoin stellar)
  end

  # SPEC.md 13.3: the claims of that item.
  defp claims_properties do
    [
      {"its claims hold an md5 hash",
       &(claims(&1)["hash_type"] == "md5" and matches?(claims(&1)["hash"], ~r/\A[0-9a-f]{32}\z/))},
      {"its claims hold a timestamp", &is_binary(claims(&1)["timestamp"])},
      {"its claims hold a nonce", &matches?(claims(&1)["nonce"], ~r/\A(?:[0-9a-f]{2}){1,32}\z/)},
      {"its claims hold 37.7749", &(37.7749 in numbers(claims(&1)))},
      {"its claims hold 1e-7", &(1.0e-7 in numbers(claims(&1)))},
      {"its claims hold 5e-324", &(5.0e-324 in numbers(claims(&1)))},
      {"its claims hold the names U+FF5A and U+1F600, which sort one way by UTF-16 code unit " <>
         "and the other by code point", &utf16_order_differs?(claims(&1))},
      {"its claims hold a quote", &Enum.any?(strings(claims(&1)), fn s -> s =~ "\"" end)},
      {"its claims hold a backslash", &Enum.any?(strings(claims(&1)), fn s -> s =~ "\\" end)}
    ]
  end

  defp properties do
    [
      # SPEC.md 13.3.
      {"a block proof of the genesis block, whose tree is empty", &empty_genesis?/1},
      {"a proof whose signing_key_event block is a rotation with previous_public_key, " <>
         "handover_signature and Bitcoin evidence", &rotation_with_bitcoin?/1},
      {"a proof of an older item signed by the key a later rotation introduced", &older_item?/1},
      {"a beacon with three observations", &beacon?(&1, 3)},
      {"a beacon with no observation", &beacon?(&1, 0)},
      {"a subject alone in its block", &(get(&1, "/subject/inclusion_proof") == @alone)},
      # The shapes the cases of SPEC.md 13.3 start from.
      {"a genesis event at /signing_key_event/block",
       &(event(&1, "/signing_key_event/block")["type"] == "genesis")},
      {"a proof whose top-level commitments are Stellar's alone",
       &(get(&1, "/commitments") |> Map.keys() == ["stellar"])},
      {"an item whose /witnesses/block is the genesis block",
       &(event(&1, "/witnesses/block")["type"] == "genesis")},
      {"a block proof of a rotation block",
       &(&1["type"] == "block" and event(&1, "/block")["type"] == "rotation")},
      {"a rotation block that is the last of three leaves at the top level, in both chains",
       &last_of_three?(&1, "/block", "/commitments")},
      {"a rotation block that is the last of three leaves at signing_key_event, in both chains",
       &last_of_three?(&1, "/signing_key_event/block", "/signing_key_event/commitments")},
      {"a subject that is the last of three leaves in its block",
       &last_leaf_of_three?(get(&1, "/subject/inclusion_proof"))},
      {"a beacon observation that is the last of three leaves in its block",
       &Enum.any?(Map.values(&1["observations"] || %{}), fn o ->
         last_leaf_of_three?(o["inclusion_proof"])
       end)},
      {"an emergency_rotation with no handover_signature", &emergency_without_signature?/1}
    ]
  end

  defp get(proof, pointer), do: Pointer.get(proof, pointer)

  defp event(proof, b), do: get(proof, b <> "/record/metadata/key_event") || %{}

  defp claims(proof), do: get(proof, "/subject/claims")

  defp matches?(value, pattern), do: is_binary(value) and value =~ pattern

  # Every number, and every string, in a value, member names included for strings.
  defp numbers(value) when is_number(value), do: [value]
  defp numbers(value) when is_map(value), do: Enum.flat_map(Map.values(value), &numbers/1)
  defp numbers(value) when is_list(value), do: Enum.flat_map(value, &numbers/1)
  defp numbers(_value), do: []

  defp strings(value) when is_binary(value), do: [value]

  defp strings(value) when is_map(value),
    do: Map.keys(value) ++ Enum.flat_map(Map.values(value), &strings/1)

  defp strings(value) when is_list(value), do: Enum.flat_map(value, &strings/1)
  defp strings(_value), do: []

  # UTF-8 bytes sort as code points do, and JCS sorts by UTF-16 code units.
  defp utf16_order_differs?(claims) do
    names = Map.keys(claims)
    "\u{FF5A}" in names and "\u{1F600}" in names and JCS.sort_names(names) != Enum.sort(names)
  end

  defp empty_genesis?(proof) do
    record = get(proof, "/block/record")

    proof["type"] == "block" and record["metadata"]["genesis"] != nil and
      record["leaf_count"] == 0 and record["merkle_root"] == @empty_root
  end

  defp rotation_with_bitcoin?(proof) do
    event = event(proof, "/signing_key_event/block")

    event["type"] == "rotation" and Map.has_key?(event, "previous_public_key") and
      Map.has_key?(event, "handover_signature") and
      Map.has_key?(get(proof, "/signing_key_event/commitments") || %{}, "bitcoin")
  end

  defp older_item?(proof) do
    proof["type"] == "item" and
      event(proof, "/signing_key_event/block")["type"] in ~w(rotation emergency_rotation) and
      get(proof, "/block/record/height") < get(proof, "/signing_key_event/block/record/height")
  end

  defp beacon?(proof, count),
    do: proof["type"] == "beacon" and map_size(proof["observations"]) == count

  defp last_of_three?(proof, b, base) do
    entries = get(proof, base) || %{}

    event(proof, b)["type"] == "rotation" and Enum.sort(Map.keys(entries)) == ~w(bitcoin stellar) and
      Enum.all?(entries, fn {_chain, entry} -> last_leaf_of_three?(entry["inclusion_proof"]) end)
  end

  # SPEC.md 13.3's moved leaf index starts from the last of three leaves, whose walk, with the
  # same path, also reaches the root as index 1 of two.
  defp last_leaf_of_three?(%{"leaf_index" => 2, "tree_size" => 3}), do: true
  defp last_leaf_of_three?(_inclusion_proof), do: false

  defp emergency_without_signature?(proof) do
    Enum.any?(~w(/block /witnesses/block /signing_key_event/block), fn b ->
      event = event(proof, b)
      event["type"] == "emergency_rotation" and not Map.has_key?(event, "handover_signature")
    end)
  end
end
