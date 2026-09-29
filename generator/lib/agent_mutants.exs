# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Generator.AgentTest.Mutants do
  @moduledoc """
  The mutants of the agent-sufficiency test (SPEC.md 7.4): for one proof of a fixture, its
  flawed copies, each `%{flaw, envelope, replay, codes}`, where `envelope` is the mutant's
  decoded envelope (the base's for a mutant that is only a replay), `replay` is the value of
  the mutant's own replay file, or nil when the fixture's replay answers every read of the
  mutant as that file would, and `codes` is the set of reason codes its run fails with, run
  online under its replay with every step made whatever the others give, or `:any` for a
  mutant that changes one carried value and nothing else.

  Every mutant but a `hash.`, `path.<q>.sibling` or `claims` mutant breaks exactly one rule
  of the constructions text: the values that depend on what it changes are made to agree
  again, up to the proof's signature, and its replay answers every read as the modeled chains
  would hold that proof (world/1), but the one read its rule is about. So a verifier that
  skips that rule, and only that rule, passes the mutant: it prints every line of the run
  but the window lines and the lines whose value that rule decides, such as the
  `merkle_root` a range or side mutant's walk reaches, and `/signature/value` for
  `signature_s` and `signature_cofactor`.

  The world a mutant's chain reads come from is the modeled chains with the mutant's own
  blocks and transactions in place of the base's: settle/2 rebuilds each epoch from the
  modeled epoch's leaves with each changed block hash in place, gives every entry of that
  epoch its walk and the new epoch hash, and puts a Bitcoin entry's transaction, pushing that
  hash, in its block, ground again; world/1 then answers each Stellar transaction with the
  epoch hash its entries carry, and each best-chain block at an entry's height with that
  entry's header hash and transaction count. Entries that share a transaction always change
  together, and a block the proof holds at two positions, such as block-rotation's /block
  and /signing_key_event/block, changes at both.
  """

  import Bitwise

  alias Generator.{
    Bitcoin,
    Bytes,
    Case,
    Chain,
    Ed25519,
    Edit,
    Keys,
    Merkle,
    Pointer,
    Registry,
    Regtest,
    Replay,
    Replay.World,
    Seeds,
    Spec
  }

  @positions [
    {"/block", "/commitments"},
    {"/signing_key_event/block", "/signing_key_event/commitments"}
  ]
  @blocks ~w(/block /witnesses/block /signing_key_event/block)

  # The nBits of a mutant whose header does not meet its own target: Bitcoin's difficulty 1,
  # whose target the regtest headers, ground only at regtest's nBits, miss.
  @hard_bits 0x1D00FFFF

  @doc """
  The mutants of the proof `proof`, whose base envelope is `envelope`, in a fixture whose
  replay is the value `replay`: SPEC.md 7.4's list, in its order.
  """
  def all(proof, envelope, replay) do
    base = %{proof: proof, envelope: envelope, replay: replay}

    [
      hashes(base),
      claims(base),
      paths(base),
      tree_sizes(base),
      graft(base),
      empty_roots(base),
      witness_mutants(base),
      key_events(base),
      handovers(base),
      genesis(base),
      bitcoin(base),
      stellar(base),
      payloads(base),
      chain_order(base),
      signatures(base),
      [
        uppercase(base),
        mutant(base, "self_signed", self_signed(proof), ["key_binding_failed"], Seeds.other()),
        signed(base, "staging", Map.put(proof, "environment", "staging"), ["environment_mismatch"])
      ]
    ]
    |> List.flatten()
    |> Enum.map(&own_replay(&1, replay))
  end

  # ---------------------------------------------------------------------------------------
  # Building a mutant

  # A mutant whose proof `mutated` changes one carried value and nothing else: signed again,
  # under the fixture's replay.
  defp signed(base, flaw, mutated, codes),
    do: %{flaw: flaw, envelope: Case.sign(mutated), replay: base.replay, codes: codes}

  # A mutant whose proof `mutated` has its blocks' commitments rebuilt (settle/2), signed
  # again by `seed`, with the replay of its own world.
  defp mutant(base, flaw, mutated, codes, seed \\ Seeds.vector()) do
    settled = settle(base.proof, mutated)
    %{flaw: flaw, envelope: Case.sign(settled, seed), replay: world(settled), codes: codes}
  end

  # A mutant that is only a replay: the base proof, and the replay of its world changed by
  # `break`.
  defp replayed(base, flaw, codes, break),
    do: %{flaw: flaw, envelope: base.envelope, replay: break.(world(base.proof)), codes: codes}

  # The fixture's replay (nil) in place of a mutant's own when it answers every read of the
  # mutant's own exactly as that does.
  defp own_replay(%{replay: replay} = m, fixture) when replay == fixture, do: %{m | replay: nil}

  defp own_replay(%{replay: replay} = m, fixture) do
    held = MapSet.new(fixture["reads"])
    if Enum.all?(replay["reads"], &MapSet.member?(held, &1)), do: %{m | replay: nil}, else: m
  end

  defp slug(pointer), do: String.replace(pointer, "/", ".")

  # ---------------------------------------------------------------------------------------
  # The world of a proof: its epochs, its Bitcoin evidence and the answers to its reads

  @doc """
  `proof`, the base `base` changed in its block records, with the commitments of each block
  position made to agree: each epoch the base's entries sit in rebuilt from the modeled
  epoch's leaves with each position's new block hash in place of its old, every entry of that
  epoch given its walk from its block's new hash and the new epoch, and each Bitcoin entry's
  transaction made to push the new epoch hash, in its block ground again (Generator.Edit).
  The entries are the base's before anything is rebuilt, so the base settles to itself.
  """
  def settle(base, proof) do
    proof =
      Enum.reduce(@positions, proof, fn {b, _entries}, acc ->
        if Pointer.get(acc, b),
          do: Edit.rehash(acc, b <> "/block_hash", "block_hash", b <> "/record"),
          else: acc
      end)

    swaps =
      for {b, _entries} <- @positions, Pointer.get(proof, b), reduce: %{} do
        acc ->
          old = Pointer.get(base, b <> "/block_hash")
          new = Pointer.get(proof, b <> "/block_hash")

          case Map.fetch(acc, old) do
            {:ok, ^new} -> acc
            {:ok, _other} -> raise ArgumentError, "one block of the base changed two ways"
            :error -> Map.put(acc, old, new)
          end
      end

    for {b, entries} <- @positions,
        {chain, _entry} <- Pointer.get(base, entries) || %{},
        reduce: proof do
      acc -> reentry(acc, base, entries <> "/" <> chain, b, swaps)
    end
  end

  defp reentry(proof, base, n, b, swaps) do
    entry = Pointer.get(base, n)
    epoch = Enum.find(epochs(), &(&1.node["epoch_hash"] == entry["epoch"]["epoch_hash"]))
    leaves = Enum.map(epoch.leaves, &Map.get(swaps, &1, &1))
    index = Enum.find_index(leaves, &(&1 == Pointer.get(proof, b <> "/block_hash")))
    bytes = Enum.map(leaves, &Bytes.unhex/1)
    record = Map.put(entry["epoch"]["record"], "merkle_root", Bytes.hex(Merkle.root(bytes)))
    epoch_hash = Bytes.hex(Registry.record_hash("epoch_hash", record))

    proof =
      proof
      |> Edit.put(n, entry)
      |> Edit.put(n <> "/epoch", %{"epoch_hash" => epoch_hash, "record" => record})
      |> Edit.put(n <> "/inclusion_proof", Merkle.proof(index, bytes))

    if String.ends_with?(n, "/bitcoin") and epoch_hash != entry["epoch"]["epoch_hash"],
      do:
        Edit.repush(proof, n, Bytes.unhex(entry["epoch"]["epoch_hash"]), Bytes.unhex(epoch_hash)),
      else: proof
  end

  defp model do
    case Process.get({__MODULE__, :model}) do
      nil ->
        model = Chain.build()
        Process.put({__MODULE__, :model}, model)
        model

      model ->
        model
    end
  end

  defp epochs, do: for({_name, chain} <- model().chains, epoch <- chain.epochs, do: epoch)

  @doc """
  The replay of `proof`'s world: every read a verifier makes online for it (Generator.Replay),
  answered by the model's sources, but that a Stellar transaction's memo is the epoch hash its
  entries in `proof` carry, and a best-chain block at the height of a Bitcoin entry has that
  entry's header hash and transaction count.
  """
  def world(proof) do
    world = World.new(model())

    proof
    |> Replay.reads(Case.pins())
    |> Enum.map(fn {kind, parameters} ->
      answer = agreeing(kind, parameters, World.answer(world, kind, parameters), proof)
      Replay.record(kind, parameters, answer)
    end)
    |> Replay.file()
  end

  defp agreeing("stellar_transaction", %{"hash" => hash}, %{"outcome" => "found"} = answer, proof) do
    case Enum.uniq(
           for {_n, e} <- entries(proof, "stellar"),
               e["transaction_hash"] == hash,
               do: e["epoch"]["epoch_hash"]
         ) do
      [] -> answer
      [memo] -> put_in(answer, ["value", "memo"], memo)
      _several -> raise ArgumentError, "the entries of Stellar transaction #{hash} differ"
    end
  end

  defp agreeing(
         "bitcoin_block_at_height",
         %{"height" => height},
         %{"outcome" => "found"} = answer,
         proof
       ) do
    case Enum.uniq(
           for {_n, e} <- entries(proof, "bitcoin"),
               e["height"] == height,
               do: {e["header_hash"], total(e)}
         ) do
      [] ->
        answer

      [{hash, count}] ->
        Map.update!(
          answer,
          "value",
          &Map.merge(&1, %{"hash" => hash, "transaction_count" => count})
        )

      _several ->
        raise ArgumentError, "the Bitcoin entries at height #{height} hold different blocks"
    end
  end

  defp agreeing(_kind, _parameters, answer, _proof), do: answer

  # Each commitment entry on `chain`, at both positions: `{pointer, entry}`.
  defp entries(proof, chain) do
    for {_b, base} <- @positions,
        entry = Pointer.get(proof, base <> "/" <> chain),
        entry != nil,
        do: {base <> "/" <> chain, entry}
  end

  defp total(entry) do
    <<_header::binary-80, total::little-32, _rest::binary>> = Bytes.unhex(entry["txoutproof"])
    total
  end

  # The replay `replay` with the answer to each read `select` picks changed by `change`, which
  # must change at least one.
  defp break(replay, select, change) do
    reads =
      Enum.map(replay["reads"], fn record ->
        if select.(record["read"]), do: Map.update!(record, "answer", change), else: record
      end)

    if reads == replay["reads"], do: raise(ArgumentError, "a replay mutant changes nothing")
    %{replay | "reads" => reads}
  end

  defp found_value(change),
    do: fn %{"outcome" => "found"} = a -> Map.update!(a, "value", change) end

  # ---------------------------------------------------------------------------------------
  # The groups a mutant changes together

  # The block positions that hold one block, by the first of them: `[[b, ...], ...]`.
  defp block_groups(proof) do
    @blocks
    |> Enum.filter(&Pointer.get(proof, &1))
    |> Enum.group_by(&Pointer.get(proof, &1 <> "/block_hash"))
    |> Map.values()
    |> Enum.sort_by(fn [b | _rest] -> Enum.find_index(@blocks, &(&1 == b)) end)
  end

  # The commitment entries on `chain` that share one transaction, by the first of them.
  defp entry_groups(proof, chain) do
    proof
    |> entries(chain)
    |> Enum.group_by(fn {_n, e} -> e["transaction_hash"] end, fn {n, _e} -> n end)
    |> Map.values()
    |> Enum.sort()
  end

  # The mutant changed at each position of a group, and the group's handovers signed again.
  defp at_each(proof, group, change) do
    proof = Enum.reduce(group, proof, &change.(&2, &1))
    Enum.reduce(group, proof, &Edit.resign(&2, &1 <> "/record/metadata/key_event"))
  end

  # A change to the witness block reaches /block through the item's hashes (Generator.Edit).
  defp through_witness(proof, group) do
    if "/witnesses/block" in group, do: Edit.recommit(proof, "/witnesses/block"), else: proof
  end

  # ---------------------------------------------------------------------------------------
  # hash., claims, path. and tree_size.

  defp hashes(base) do
    k = Bytes.unb64u(base.envelope["signature"]["public_key"])

    for row <- Generator.Derive.trace(base.proof, Generator.Derive.rows(base.proof, k, "none")),
        not String.ends_with?(row["part"], "/handover_signature"),
        Spec.class?("HEX64", Pointer.get(base.proof, row["part"])),
        uniq: true,
        do: signed(base, "hash" <> slug(row["part"]), Edit.flip(base.proof, row["part"]), :any)
  end

  # /block's block_hash in uppercase hex: the value it spells, not the lowercase the text
  # asks for.
  defp uppercase(base) do
    hash = Pointer.get(base.proof, "/block/block_hash")
    upper = Edit.put(base.proof, "/block/block_hash", String.upcase(hash))
    signed(base, "uppercase", upper, ["derivation_mismatch", "shape_invalid"])
  end

  defp claims(%{proof: %{"type" => "item"} = proof} = base),
    do: [
      signed(base, "claims", Edit.flip(proof, "/subject/claims/name"), ["derivation_mismatch"])
    ]

  defp claims(_base), do: []

  @doc "Every inclusion proof `proof` carries, with the leaf its walk starts from, in document order."
  def inclusion_proofs(proof) do
    subject =
      case proof["type"] do
        "item" ->
          [{"/subject/inclusion_proof", {"item_hash", "/subject/record"}}]

        "entropy_" <> _source ->
          [{"/subject/inclusion_proof", {"observation_hash", "/subject/record"}}]

        _other ->
          []
      end

    observations =
      for {name, _o} <- Pointer.get(proof, "/observations") || %{},
          do:
            {"/observations/#{name}/inclusion_proof",
             {"observation_hash", "/observations/#{name}/record"}}

    entries =
      for {b, base} <- @positions,
          {chain, _entry} <- Pointer.get(proof, base) || %{},
          do: {"#{base}/#{chain}/inclusion_proof", {"block_hash", b <> "/record"}}

    Enum.sort_by(subject ++ observations ++ entries, &Pointer.order_key(proof, elem(&1, 0)))
  end

  # For each inclusion proof: its first step taken on the other side, at an index in range,
  # with the path and root a walk from that index whose first step is on the other side
  # reaches where the base's path does not fit it (side/4); its first node changed, when it
  # has one; and its leaf_index at its tree_size, with the path a walk that skips the range
  # check would use in full, and the root that walk reaches carried (range/3).
  defp paths(base) do
    for {q, leaf} <- inclusion_proofs(base.proof) do
      %{"leaf_index" => index, "tree_size" => size, "path" => path} = Pointer.get(base.proof, q)

      side =
        case other_side(index, size) do
          nil -> []
          i -> [side(base, q, leaf, i)]
        end

      sibling =
        if path == [],
          do: [],
          else: [
            signed(base, "path#{slug(q)}.sibling", Edit.flip(base.proof, q <> "/path/0"), :any)
          ]

      side ++ sibling ++ [range(base, q, leaf)]
    end
  end

  @doc """
  The record whose `merkle_root` the walk of the inclusion proof `q` reaches: /block's for a
  subject or a beacon observation, and its epoch's for a commitment entry.
  """
  def root_record(q) do
    case String.replace_suffix(q, "/inclusion_proof", "") do
      "/subject" -> "/block/record"
      "/observations/" <> _name -> "/block/record"
      n -> n <> "/epoch/record"
    end
  end

  # path.<q>.side: leaf_index `i`, whose first step is on the other side of the base index's.
  # Where the walk from `i`, its first step on the other side, starts at the base walk's place,
  # the base path takes that walk to the root the proof carries, and only leaf_index changes;
  # else the leaf sits at that walk's place in a tree built as range/3 builds one. So only the
  # side of the first step fails.
  defp side(base, q, leaf, i) do
    flaw = "path#{slug(q)}.side"
    %{"leaf_index" => index, "tree_size" => size} = Pointer.get(base.proof, q)

    if flipped(i, size) == position(index, size),
      do:
        signed(base, flaw, Edit.put(base.proof, q <> "/leaf_index", i), ["derivation_mismatch"]),
      else: rebuilt(base, flaw, {q, leaf}, i, flipped(i, size))
  end

  # path.<q>.range: the leaf at index tree_size, whose walk, with the range check skipped,
  # reaches the root the proof then carries (rebuilt/5). So only the range check fails.
  defp range(base, q, leaf) do
    size = Pointer.get(base.proof, q <> "/tree_size")
    rebuilt(base, "path#{slug(q)}.range", {q, leaf}, size, position(size, size))
  end

  # The mutant `flaw` whose walk q carries leaf_index `index` and starts at the place `at`,
  # with the path to the root of a tree that holds q's leaf there, and the values that depend
  # on that root made to agree. The walks that must reach the same root, those into /block's
  # record for a subject or an observation, and those of the entries that share q's
  # transaction for an entry, keep their index unless its place in the tree holds or lies
  # under `at`, and then take the first index in range whose place is free; the nodes of
  # every place no leaf decides are those of the base tree where it has one.
  defp rebuilt(base, flaw, {q, leaf}, index, at) do
    proof = base.proof
    size = Pointer.get(proof, q <> "/tree_size")

    together =
      for {other, walk_leaf} <- inclusion_proofs(proof),
          together?(proof, q, other),
          do: {other, walk_leaf}

    known = Enum.reduce(together, %{}, &genuine(proof, &1, &2))
    moved = place(proof, [{q, index, leaf_hex(proof, leaf), at}], together -- [{q, leaf}], size)
    leaves = Map.new(moved, fn {_walk, _i, hex, place} -> {place, Bytes.unhex(hex)} end)
    node = &tree_node(&1, leaves, known)
    root = Bytes.hex(node.([]))

    mutated =
      Enum.reduce(moved, proof, fn {walk, i, _hex, place}, acc ->
        acc
        |> Edit.put(walk <> "/leaf_index", i)
        |> Edit.put(walk <> "/path", path_at(place, node))
      end)

    codes = ["derivation_mismatch"]

    case root_record(q) do
      "/block/record" ->
        mutant(base, flaw, Edit.put(mutated, "/block/record/merkle_root", root), codes)

      _epoch ->
        mutated =
          for {walk, _i, _hex, _place} <- moved, reduce: mutated do
            acc ->
              n = String.replace_suffix(walk, "/inclusion_proof", "")
              acc |> Edit.put(n <> "/epoch/record/merkle_root", root) |> Edit.reepoch(n)
          end

        %{flaw: flaw, envelope: Case.sign(mutated), replay: world(mutated), codes: codes}
    end
  end

  # Whether the walk of `other` must reach the root the walk of `q` reaches: both into
  # /block's record, or both of entries on one chain that share a transaction.
  defp together?(proof, q, other) do
    case {root_record(q), root_record(other)} do
      {"/block/record", "/block/record"} ->
        true

      {"/block/record", _epoch} ->
        false

      {_epoch, "/block/record"} ->
        false

      {a, b} ->
        chain = &(&1 |> String.split("/") |> Enum.at(-2))
        tx = &Pointer.get(proof, String.replace_suffix(&1, "/epoch/record", "/transaction_hash"))
        chain.(a) == chain.(b) and tx.(a) == tx.(b)
    end
  end

  defp leaf_hex(proof, {kind, preimage}),
    do: Bytes.hex(Registry.record_hash(kind, Pointer.get(proof, preimage)))

  # `{walk, index, leaf, place}` for the walk `first` names and each other walk: the others
  # keep their index where its place is free of every place taken so far, or take the first
  # index in range whose place is.
  defp place(proof, first, others, size) do
    start = Enum.map(first, fn {_q, _i, _hex, at} -> at end)
    index_of = &Pointer.get(proof, elem(&1, 0) <> "/leaf_index")

    # The walks whose place is free first, so a walk moves only for want of a place.
    others =
      Enum.sort_by(others, fn walk ->
        Enum.any?(start, &nested?(&1, position(index_of.(walk), size)))
      end)

    {placed, _taken} =
      Enum.map_reduce(others, start, fn
        {walk, leaf}, taken ->
          index = Pointer.get(proof, walk <> "/leaf_index")

          i =
            Enum.find([index | Enum.to_list(0..(size - 1)//1)], fn i ->
              Enum.all?(taken, &(not nested?(&1, position(i, size))))
            end) || raise ArgumentError, "no index in range leaves #{walk} a place of its own"

          {{walk, i, leaf_hex(proof, leaf), position(i, size)}, [position(i, size) | taken]}
      end)

    first ++ placed
  end

  defp nested?(a, b), do: Enum.take(a, length(b)) == b or Enum.take(b, length(a)) == a

  # The place in the tree the walk from index `i` in a tree of `size` starts at, with no range
  # check: the side of each node on its way, from the root down (route/2 reversed).
  defp position(i, size), do: Enum.reverse(route(i, size))

  # The place the walk from index `i` in a tree of `size` starts at when its first step is
  # taken on the other side.
  defp flipped(i, size), do: Enum.reverse(route(i, size, true))

  # The side the walk from index `f` in a tree of `size` is on at each step, from the leaf up,
  # with no range check: :right when the step puts the node on the left, until sn is 0; with
  # `flip`, the first step on the other side.
  defp route(f, size, flip \\ false), do: route(f, size - 1, [], flip)
  defp route(_f, 0, acc, _flip), do: Enum.reverse(acc)

  defp route(f, s, acc, flip) do
    if ((f &&& 1) == 1 or f == s) != flip do
      {f, s} = shift_even(f, s)
      route(f >>> 1, s >>> 1, [:right | acc], false)
    else
      route(f >>> 1, s >>> 1, [:left | acc], false)
    end
  end

  # The base tree's value at every place the walk `{walk, leaf}` passes or takes a node from,
  # added to `known`.
  defp genuine(proof, {walk, leaf}, known) do
    %{"leaf_index" => i, "tree_size" => size, "path" => path} = Pointer.get(proof, walk)
    at = position(i, size)
    start = Registry.hash("merkle_leaf", Bytes.unhex(leaf_hex(proof, leaf)))

    {known, _r} =
      path
      |> Enum.with_index()
      |> Enum.reduce({Map.put(known, at, start), start}, fn {p, t}, {acc, r} ->
        here = Enum.take(at, length(at) - t)
        {up, [side]} = Enum.split(here, -1)
        p = Bytes.unhex(p)

        r =
          if side == :right,
            do: Registry.hash("merkle_node", p <> r),
            else: Registry.hash("merkle_node", r <> p)

        {acc |> Map.put(up ++ [other(side)], p) |> Map.put(up, r), r}
      end)

    known
  end

  defp other(:left), do: :right
  defp other(:right), do: :left

  # The value of the node at `place`: a leaf's, a node above leaves from its two children,
  # else the base tree's there, else a filler.
  defp tree_node(place, leaves, known) do
    cond do
      Map.has_key?(leaves, place) ->
        Registry.hash("merkle_leaf", Map.fetch!(leaves, place))

      Enum.any?(Map.keys(leaves), &(length(&1) > length(place) and nested?(&1, place))) ->
        Registry.hash(
          "merkle_node",
          tree_node(place ++ [:left], leaves, known) <>
            tree_node(place ++ [:right], leaves, known)
        )

      true ->
        Map.get_lazy(known, place, fn -> :crypto.hash(:sha256, "a node") end)
    end
  end

  # The path of the walk that starts at `place`: the node beside it at each step, from the
  # leaf up, in hex.
  defp path_at(place, node) do
    for t <- 0..(length(place) - 1)//1 do
      {up, [side]} = place |> Enum.take(length(place) - t) |> Enum.split(-1)
      Bytes.hex(node.(up ++ [other(side)]))
    end
  end

  # Whether the walk's first step from index `i` in a tree of `size` puts the node on the left.
  defp left?(i, size), do: (i &&& 1) == 1 or i == size - 1

  # The index in range nearest the flipped one whose first step is on the other side of
  # `index`'s, or nil when the tree has none.
  defp other_side(index, size) do
    Enum.find([bxor(index, 1) | Enum.to_list(0..(size - 1)//1)], fn i ->
      i != index and i < size and left?(i, size) != left?(index, size)
    end)
  end

  defp shift_even(f, s) when f != 0 and (f &&& 1) == 0, do: shift_even(f >>> 1, s >>> 1)
  defp shift_even(f, s), do: {f, s}

  # For each inclusion proof, another tree_size whose walk reaches the same root
  # (Generator.Edit.resize/4), so only tree_size = leaf_count fails.
  defp tree_sizes(base) do
    for {q, leaf} <- inclusion_proofs(base.proof),
        do:
          signed(base, "tree_size#{slug(q)}", Edit.resize(base.proof, q, leaf), [
            "derivation_mismatch"
          ])
  end

  # The graft (SPEC.md 10.3): a forged item, its claims' hash of the length its hash_type
  # fixes, with its hashes and the root in /block's record made to agree, beside the genuine
  # block_hash and commitment entries.
  defp graft(%{proof: %{"type" => "item"} = proof} = base) do
    algorithm = %{"md5" => :md5, "sha1" => :sha, "sha256" => :sha256}
    type = Map.fetch!(algorithm, Pointer.get(proof, "/subject/claims/hash_type"))

    forged =
      proof
      |> Edit.put("/subject/claims/hash", Bytes.hex(:crypto.hash(type, "a forged document")))
      |> Edit.put("/subject/claims/name", "a forged item")
      |> Edit.rehash("/subject/record/claims_hash", "claims_hash", "/subject/claims")
      |> Edit.rehash("/subject/item_hash", "item_hash", "/subject/record")
      |> Edit.walk_up(
        Pointer.get(proof, "/subject/inclusion_proof"),
        "/subject/item_hash",
        "/block/record"
      )

    [signed(base, "graft", forged, ["derivation_mismatch"])]
  end

  defp graft(_base), do: []

  # ---------------------------------------------------------------------------------------
  # The empty-root rule, the witnesses and the heights

  # For each block with no leaves: another merkle_root, and a leaf_count of 1 with the empty
  # root kept.
  defp empty_roots(base) do
    for [b | _rest] = group <- block_groups(base.proof),
        Pointer.get(base.proof, b <> "/record/leaf_count") == 0,
        {flaw, change} <- [
          {"empty_root",
           &Edit.put(
             &1,
             &2 <> "/record/merkle_root",
             Bytes.hex(:crypto.hash(:sha256, "another root"))
           )},
          {"leaf_count", &Edit.put(&1, &2 <> "/record/leaf_count", 1)}
        ] do
      mutated = base.proof |> at_each(group, change) |> through_witness(group)
      mutant(base, flaw <> slug(b), mutated, ["shape_invalid"])
    end
  end

  defp witness_mutants(%{proof: %{"type" => "item"} = proof} = base) do
    height = Pointer.get(proof, "/block/record/height")

    at_block =
      proof
      |> Edit.put("/witnesses/block/record/height", height)
      |> Edit.recommit("/witnesses/block")

    unnamed =
      proof
      |> Edit.delete("/subject/record/witness_hashes/entropy_nist")
      |> Edit.reitem()

    [
      mutant(base, "witness_height", at_block, ["ordering_violation"]),
      mutant(base, "witness_names", unnamed, ["shape_invalid"])
    ]
  end

  defp witness_mutants(_base), do: []

  # ---------------------------------------------------------------------------------------
  # Key events

  defp key_events(base) do
    for [b | _rest] = group <- block_groups(base.proof),
        event = Pointer.get(base.proof, b <> "/record/metadata/key_event"),
        event != nil,
        {flaw, change} <- key_event_changes(event, b, base.proof) do
      mutated = base.proof |> at_each(group, change) |> through_witness(group)
      mutant(base, flaw <> slug(b), mutated, ["key_event_mismatch"])
    end
  end

  defp key_event_changes(%{"type" => type}, b, proof)
       when type in ~w(genesis rotation emergency_rotation) do
    e = "/record/metadata/key_event"

    [
      {"key_id", &Edit.flip(&1, &2 <> e <> "/key_id")},
      {"signing_key_id", &Edit.flip(&1, &2 <> "/record/signing_key_id")}
    ] ++
      if(type != "genesis",
        do: [
          {"previous_key_id", &Edit.flip(&1, &2 <> e <> "/previous_key_id")},
          {"handover_height",
           &Edit.put(&1, &2 <> e <> "/height", Pointer.get(&1, &2 <> e <> "/height") + 1)},
          {"handover_previous", &Edit.flip(&1, &2 <> e <> "/previous_block_hash")}
        ],
        else: []
      ) ++
      if(
        b != "/signing_key_event/block" and not same_block?(proof, b, "/signing_key_event/block"),
        do: [{"key_checks", &Edit.introduce(&1, &2, small_order_key())}],
        else: []
      )
  end

  defp key_event_changes(%{"type" => "prerotation"}, _b, _proof),
    do: [{"signing_key_id", &Edit.flip(&1, &2 <> "/record/signing_key_id")}]

  defp key_event_changes(_event, _b, _proof), do: []

  defp same_block?(proof, a, b),
    do:
      Pointer.get(proof, b) != nil and
        Pointer.get(proof, a <> "/block_hash") == Pointer.get(proof, b <> "/block_hash")

  # A key of small order that spec/small-order-keys.json lists, of order 8, unpadded
  # base64url.
  defp small_order_key do
    [hex | _rest] =
      for %{"order" => 8, "hex" => hex} <- Spec.read("small-order-keys.json"), do: hex

    Bytes.b64u(Bytes.unhex(hex))
  end

  # The signing key event: each handover signature altered, and handover_signature taken out
  # of a rotation, each with the hashes above it made to agree; the key event introducing
  # another key than K; and, for self_signed, introducing the other key, which signs.
  defp handovers(base) do
    for [b | _rest] = group <- block_groups(base.proof),
        event = Pointer.get(base.proof, b <> "/record/metadata/key_event"),
        is_binary(event["handover_signature"]) do
      e = "/record/metadata/key_event"
      altered = Enum.reduce(group, base.proof, &Edit.flip(&2, &1 <> e <> "/handover_signature"))

      missing =
        if event["type"] == "rotation",
          do: [
            mutant(
              base,
              "handover_missing" <> slug(b),
              Enum.reduce(group, base.proof, &Edit.delete(&2, &1 <> e <> "/handover_signature")),
              ["shape_invalid"]
            )
          ],
          else: []

      [
        mutant(base, "handover" <> slug(b), through_witness(altered, group), [
          "key_event_mismatch"
        ])
        | missing
      ]
    end ++ ske_key(base)
  end

  defp ske_key(base) do
    case signing_group(base.proof) do
      [] ->
        []

      group ->
        [
          mutant(base, "ske_key", introduce(base.proof, group, Seeds.other()), [
            "key_event_mismatch"
          ])
        ]
    end
  end

  # The proof whose signing key event introduces the other key, which then signs it.
  defp self_signed(proof), do: introduce(proof, signing_group(proof), Seeds.other())

  defp signing_group(proof) do
    Enum.find(block_groups(proof), [], &("/signing_key_event/block" in &1))
  end

  defp introduce(proof, group, seed) do
    public = Bytes.b64u(Keys.public_key(seed))
    at_each(proof, group, &Edit.introduce(&1, &2, public))
  end

  # ---------------------------------------------------------------------------------------
  # Genesis

  defp genesis(base) do
    for b <- @blocks,
        genesis = Pointer.get(base.proof, b <> "/record/metadata/genesis"),
        genesis != nil do
      [
        mutant(
          base,
          "genesis_height" <> slug(b),
          Edit.put(base.proof, b <> "/record/height", 1),
          ["derivation_mismatch"]
        ),
        replayed(
          base,
          "genesis_read" <> slug(b),
          ["chain_mismatch"],
          answer_at(at_height(genesis["bitcoin"]["height"]), &other_hash/1)
        )
      ]
    end
  end

  # A change to a replay: the found answer to `read` changed by `change`.
  defp answer_at(read, change), do: &break(&1, fn r -> r == read end, found_value(change))

  defp at_height(height),
    do: %{"height" => height, "kind" => "bitcoin_block_at_height", "network" => "regtest"}

  defp other_hash(value), do: Map.update!(value, "hash", &flip_hex/1)
  defp one_more(value), do: Map.update!(value, "transaction_count", &(&1 + 1))

  # ---------------------------------------------------------------------------------------
  # Bitcoin evidence and reads

  defp bitcoin(base) do
    groups = entry_groups(base.proof, "bitcoin")

    header_times =
      for {n, _entry} <- entries(base.proof, "bitcoin") do
        time = Pointer.get(base.proof, n <> "/header_time")

        signed(
          base,
          "header_time" <> slug(n),
          Edit.put(base.proof, n <> "/header_time", later(time)),
          ["derivation_mismatch"]
        )
      end

    header_times ++
      for [n | _rest] = group <- groups,
          m <- bitcoin_group(base, n, group),
          do: m
  end

  defp bitcoin_group(base, n, group) do
    entry = Pointer.get(base.proof, n)
    old = Bytes.unhex(entry["epoch"]["epoch_hash"])
    other = :crypto.hash(:sha256, "another value")
    height = entry["height"]
    each = fn change -> Enum.reduce(group, base.proof, &change.(&2, &1)) end

    [
      {"op_return", each.(&Edit.repush(&1, &2, old, other)), ["derivation_mismatch"]},
      {"two_op_returns", each.(&Edit.reblock(&1, &2, retransact(&1, &2, :two_op_returns))),
       ["bitcoin_evidence_invalid"]},
      {"no_input", each.(&Edit.reblock(&1, &2, retransact(&1, &2, :no_input))),
       ["bitcoin_evidence_invalid"]},
      {"witness_data", each.(&Edit.reblock(&1, &2, retransact(&1, &2, :witness_data))),
       ["bitcoin_evidence_invalid"]},
      {"nbits", each.(&hard_header/2), ["bitcoin_evidence_invalid"]},
      {"partial_tree", each.(&other_match/2), ["derivation_mismatch"]}
    ]
    |> Enum.map(fn {flaw, mutated, codes} ->
      %{flaw: flaw <> slug(n), envelope: Case.sign(mutated), replay: world(mutated), codes: codes}
    end)
    |> Kernel.++([
      replayed(
        base,
        "header_at_height" <> slug(n),
        ["chain_mismatch"],
        answer_at(at_height(height), &other_hash/1)
      ),
      replayed(
        base,
        "transaction_count" <> slug(n),
        ["chain_mismatch"],
        answer_at(at_height(height), &one_more/1)
      )
    ])
  end

  # Entry `n`'s transaction serialized with a flaw: a second output whose script begins
  # 0x6a; no input; or in BIP 144's form, with a marker, a flag and a witness for each input.
  defp retransact(proof, n, flaw) do
    tx = parse_transaction(Bytes.unhex(Pointer.get(proof, n <> "/raw_transaction")))

    case flaw do
      :two_op_returns ->
        Bitcoin.transaction(%{tx | outputs: tx.outputs ++ [{0, <<0x6A, 0x04, "more">>}]})

      :no_input ->
        Bitcoin.transaction(%{tx | inputs: []})

      :witness_data ->
        legacy = Bitcoin.transaction(tx)
        <<version::binary-4, body::binary>> = legacy
        body = binary_part(body, 0, byte_size(body) - 4)
        locktime = binary_part(legacy, byte_size(legacy) - 4, 4)
        witness = for _input <- tx.inputs, do: [<<1, 32>>, :crypto.hash(:sha256, "a witness")]
        IO.iodata_to_binary([version, <<0x00, 0x01>>, body, witness, locktime])
    end
  end

  defp parse_transaction(<<version::little-32, rest::binary>>) do
    {inputs, rest} = compact(rest)

    {inputs, rest} =
      Enum.map_reduce(1..inputs//1, rest, fn _i,
                                             <<txid::binary-32, vout::little-32, rest::binary>> ->
        {size, rest} = compact(rest)
        <<script::binary-size(^size), sequence::little-32, rest::binary>> = rest
        {{txid, vout, script, sequence}, rest}
      end)

    {outputs, rest} = compact(rest)

    {outputs, <<locktime::little-32>>} =
      Enum.map_reduce(1..outputs//1, rest, fn _i, <<value::little-64, rest::binary>> ->
        {size, rest} = compact(rest)
        <<script::binary-size(^size), rest::binary>> = rest
        {{value, script}, rest}
      end)

    %{version: version, inputs: inputs, outputs: outputs, locktime: locktime}
  end

  defp compact(<<0xFD, n::little-16, rest::binary>>), do: {n, rest}
  defp compact(<<0xFE, n::little-32, rest::binary>>), do: {n, rest}
  defp compact(<<n, rest::binary>>) when n < 0xFD, do: {n, rest}

  # Entry `n`'s header with nBits whose target its hash misses, and its evidence made to
  # agree.
  defp hard_header(proof, n) do
    <<header::binary-80, _rest::binary>> = Bytes.unhex(Pointer.get(proof, n <> "/txoutproof"))
    <<front::binary-72, _bits::little-32, nonce::binary-4>> = header
    hard = <<front::binary, @hard_bits::little-32, nonce::binary>>
    if Bitcoin.meets_target?(hard), do: raise(ArgumentError, "the hard header meets its target")
    {txids, index} = block_txids(proof, n)

    proof
    |> Edit.put(n <> "/txoutproof", Bytes.hex(Bitcoin.merkleblock(hard, txids, index)))
    |> Edit.put(n <> "/header_hash", Bitcoin.display(Bitcoin.sha256d(hard)))
  end

  # Entry `n`'s merkleblock matching another transaction of its block.
  defp other_match(proof, n) do
    <<header::binary-80, _rest::binary>> = Bytes.unhex(Pointer.get(proof, n <> "/txoutproof"))
    {txids, index} = block_txids(proof, n)
    other = if index == 0, do: 1, else: 0
    Edit.put(proof, n <> "/txoutproof", Bytes.hex(Bitcoin.merkleblock(header, txids, other)))
  end

  # The txids of the modeled block entry `n` sits in, with its own in place, and its index.
  defp block_txids(proof, n) do
    %{txs: txs} = Regtest.block(Edit.regtest(), Pointer.get(proof, n <> "/height"))
    txids = Enum.map(txs, &Bitcoin.txid/1)
    named = Bitcoin.internal(Pointer.get(proof, n <> "/transaction_hash"))

    case Enum.find_index(txids, &(&1 == named)) do
      nil -> raise ArgumentError, "#{n}'s transaction is not in its modeled block"
      index -> {txids, index}
    end
  end

  # ---------------------------------------------------------------------------------------
  # Stellar reads

  defp stellar(base) do
    for [n | _rest] <- entry_groups(base.proof, "stellar"),
        {flaw, change} <- [
          {"stellar_memo", &Map.update!(&1, "memo", fn memo -> flip_hex(memo) end)},
          {"stellar_failed", &Map.put(&1, "successful", false)},
          {"stellar_memo_type", &Map.put(&1, "memo_type", "return")},
          {"stellar_ledger", &Map.update!(&1, "ledger", fn ledger -> ledger + 1 end)}
        ] do
      hash = Pointer.get(base.proof, n <> "/transaction_hash")
      select = &(&1["kind"] == "stellar_transaction" and &1["hash"] == hash)
      replayed(base, flaw <> slug(n), ["chain_mismatch"], &break(&1, select, found_value(change)))
    end
  end

  # ---------------------------------------------------------------------------------------
  # Entropy: the payload a read returns, and the chain order

  defp payloads(base) do
    for pointer <- Replay.entropy_pointers(base.proof),
        %{"source" => source, "payload" => payload} = Pointer.get(base.proof, pointer),
        {field, change} <- payload_changes(source) do
      read = entropy_read(source, payload)

      replayed(
        base,
        "payload#{slug(pointer)}.#{field}",
        ["entropy_mismatch"],
        &break(&1, fn r -> r == read end, found_value(change))
      )
    end
  end

  defp payload_changes("nist"),
    do: [
      {"outputValue", &Map.update!(&1, "outputValue", fn v -> flip_hex(v) end)},
      {"timeStamp", &Map.update!(&1, "timeStamp", fn t -> later(t) end)}
    ]

  defp payload_changes("stellar"),
    do: [
      {"hash", &Map.update!(&1, "hash", fn h -> flip_hex(h) end)},
      {"closed_at", &Map.update!(&1, "closed_at", fn t -> later(t) end)}
    ]

  defp payload_changes("bitcoin"),
    do: [
      {"height", &Map.update!(&1, "height", fn h -> h + 1 end)},
      {"time", &Map.update!(&1, "time", fn t -> t + 1 end)}
    ]

  defp entropy_read("nist", %{"pulse" => pulse}),
    do: %{
      "chainIndex" => pulse["chainIndex"],
      "kind" => "nist_pulse",
      "pulseIndex" => pulse["pulseIndex"]
    }

  defp entropy_read("stellar", payload),
    do: %{"kind" => "stellar_ledger", "network" => "testnet", "sequence" => payload["sequence"]}

  defp entropy_read("bitcoin", payload),
    do: %{"hash" => payload["hash"], "kind" => "bitcoin_block", "network" => "regtest"}

  # Each Stellar or Bitcoin entropy object moved to the first ledger or block the chain order
  # refuses, the top-level commitment's own ledger or the block after its height, with the
  # payload that ledger or block has and the hashes above the object made to agree.
  defp chain_order(base) do
    for pointer <- Replay.entropy_pointers(base.proof),
        %{"source" => source} = Pointer.get(base.proof, pointer),
        top = Pointer.get(base.proof, "/commitments/" <> source),
        top != nil do
      payload =
        case source do
          "stellar" ->
            Chain.stellar_ledger(top["ledger"])

          "bitcoin" ->
            block = Regtest.block(Edit.regtest(), top["height"] + 1)

            %{
              "hash" => Bitcoin.display(block.hash),
              "height" => top["height"] + 1,
              "time" => block.time
            }
        end

      moved = Edit.put(base.proof, pointer <> "/payload", payload)

      mutant(base, "chain_order" <> slug(pointer), rehashed(moved, pointer), [
        "ordering_violation"
      ])
    end
  end

  # The hashes above a changed entropy object at `pointer` made to agree (Generator.Edit).
  defp rehashed(proof, "/witnesses/" <> name), do: Edit.rewitness(proof, name)
  defp rehashed(proof, "/subject/entropy"), do: Edit.resubject(proof)

  defp rehashed(proof, "/observations/" <> rest),
    do: Edit.reobservation(proof, rest |> String.split("/") |> hd())

  # ---------------------------------------------------------------------------------------
  # Signatures

  # V altered and not signed again; V with s + L in place of s, which only a check of s
  # below L refuses; and V made with R plus a point of order 8, which only the cofactorless
  # equation refuses.
  defp signatures(base) do
    envelope = base.envelope
    <<r::binary-32, s::little-256>> = Bytes.unb64u(envelope["signature"]["value"])
    s_plus_l = Bytes.b64u(<<r::binary, s + Ed25519.l()::little-256>>)

    {a, prefix} = Ed25519.expand(Seeds.vector())
    key = Keys.public_key(Seeds.vector())
    message = Registry.record_hash("proof_hash", base.proof)

    nonce =
      Ed25519.scalar(:crypto.hash(:sha512, [prefix, "an R with a point of order 8", message]))

    mixed =
      Ed25519.encode(Ed25519.add(Ed25519.multiply(nonce, Ed25519.base()), Ed25519.torsion()))

    cofactor = Bytes.b64u(Ed25519.sign_as(a, key, {mixed, nonce}, message))

    for {flaw, value} <- [
          {"signature", flip_first(envelope["signature"]["value"])},
          {"signature_s", s_plus_l},
          {"signature_cofactor", cofactor}
        ] do
      %{
        flaw: flaw,
        envelope: put_in(envelope, ["signature", "value"], value),
        replay: base.replay,
        codes: ["signature_invalid"]
      }
    end
  end

  # ---------------------------------------------------------------------------------------
  # Small changes

  defp flip_first(<<first, rest::binary>>),
    do: <<if(first == ?0, do: ?1, else: ?0), rest::binary>>

  defp flip_hex(<<first, rest::binary>>),
    do:
      <<if(first in [?0, ?a, ?A], do: ?1, else: if(first in ?A..?F, do: ?A, else: ?0)),
        rest::binary>>

  # A time one second later, in the spelling it has: RFC 3339 UTC with or without
  # milliseconds.
  defp later(text) do
    {:ok, time, 0} = DateTime.from_iso8601(text)
    time |> DateTime.add(1, :second) |> DateTime.to_iso8601()
  end
end
