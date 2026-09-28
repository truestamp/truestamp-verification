# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Truestamp.Verifier.Layout do
  @moduledoc """
  Where P, the parsed value of `proof`, holds each kind of node (SPEC.md sections 3.3 to
  3.6), each with its pointer (`Truestamp.Verifier.Pointer`).

  The positions come from this module's compiled lists and from `type`, never from the names
  a document happens to hold: `type` is the only member that selects what runs (section 10.6,
  rule 3), and the chains and entropy sources are the alternatives the schema lists. Each
  function reads a node only where the layout of P's type puts one, and skips a position P
  leaves empty.

  SHAPE (section 10.2, step 7, check 5) reads the TIME and NISTTIME values of the commitment
  entries and entropy objects after check 3 has held P to the schema, and POLICY (step 8)
  reads their networks.

  | Function | Positions |
  |---|---|
  | `block_nodes/1` | `/block`; `/witnesses/block` in an item; `/signing_key_event/block` |
  | `commitment_entries/1` | `/commitments/C` and `/signing_key_event/commitments/C`, C `bitcoin` or `stellar` |
  | `entropy_objects/1` | `/subject/entropy` in an entropy type; `/witnesses/entropy_X` in an item; `/observations/entropy_X/entropy` in a beacon |
  | `genesis_bitcoin/1` | B`/record/metadata/genesis/bitcoin` for each block node B that carries `metadata.genesis` |
  """

  alias Truestamp.Verifier.Pointer

  # The chains of COMMITMENTS, and the entropy sources, in JCS order (section 3.4 and 3.5).
  @chains ~w(bitcoin stellar)
  @sources ~w(bitcoin nist stellar)
  @genesis_bitcoin ~w(record metadata genesis bitcoin)

  @typedoc "A node of P, at its pointer."
  @type at(node) :: {Pointer.t(), node}

  @doc "The chains a commitment entry can be for, in JCS order."
  @spec chains() :: [String.t()]
  def chains, do: @chains

  @doc "The entropy sources, in JCS order."
  @spec sources() :: [String.t()]
  def sources, do: @sources

  @doc "Every block node P carries, as `{pointer, node}`, in document order."
  @spec block_nodes(map()) :: [at(map())]
  def block_nodes(proof) do
    [
      {["block"], proof["block"]},
      {["signing_key_event", "block"], get(proof, ["signing_key_event", "block"])},
      {["witnesses", "block"], if(item?(proof), do: get(proof, ["witnesses", "block"]))}
    ]
    |> present()
  end

  @doc "Every commitment entry P carries, as `{pointer, chain, entry}`."
  @spec commitment_entries(map()) :: [{Pointer.t(), String.t(), map()}]
  def commitment_entries(proof) do
    for base <- [["commitments"], ["signing_key_event", "commitments"]],
        chain <- @chains,
        entry = get(proof, base ++ [chain]),
        is_map(entry),
        do: {base ++ [chain], chain, entry}
  end

  @doc """
  Every entropy object P carries, as `{pointer, source, object}`, where the source is the
  one its position names: the proof's type for `/subject/entropy`, and the member's name in
  `/witnesses` and `/observations`.
  """
  @spec entropy_objects(map()) :: [{Pointer.t(), String.t(), map()}]
  def entropy_objects(%{"type" => "entropy_" <> source} = proof) when source in @sources,
    do: present_objects([{["subject", "entropy"], source}], proof)

  def entropy_objects(%{"type" => "item"} = proof),
    do: present_objects(for(s <- @sources, do: {["witnesses", "entropy_" <> s], s}), proof)

  def entropy_objects(%{"type" => "beacon"} = proof) do
    positions = for s <- @sources, do: {["observations", "entropy_" <> s, "entropy"], s}
    present_objects(positions, proof)
  end

  def entropy_objects(_proof), do: []

  @doc """
  Every `genesis.bitcoin` object P carries, one for each block node whose record's metadata
  holds `genesis`, as `{pointer, object}`.
  """
  @spec genesis_bitcoin(map()) :: [at(map())]
  def genesis_bitcoin(proof) do
    for {at, node} <- block_nodes(proof),
        bitcoin = get(node, @genesis_bitcoin),
        is_map(bitcoin),
        do: {at ++ @genesis_bitcoin, bitcoin}
  end

  @doc "The value at `pointer` in `value`, or nil where there is none."
  @spec get(term(), Pointer.t()) :: term()
  def get(value, []), do: value
  def get(value, [name | rest]) when is_map(value) and is_binary(name), do: get(value[name], rest)

  def get(value, [index | rest]) when is_list(value) and is_integer(index),
    do: get(Enum.at(value, index), rest)

  def get(_value, _pointer), do: nil

  defp item?(proof), do: proof["type"] == "item"

  defp present(nodes), do: for({at, node} <- nodes, is_map(node), do: {at, node})

  defp present_objects(positions, proof) do
    for {at, source} <- positions,
        object = get(proof, at),
        is_map(object),
        do: {at, source, object}
  end
end
