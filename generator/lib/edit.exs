# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Generator.Edit do
  @moduledoc """
  Edits of a decoded proof, the `proof` member, by JSON Pointer: the machinery the mutation
  self-test (Generator.Mutations) and the cases of vectors/cases.json (Generator.Cases) make
  their defects with.

  A defect is one changed value, with the values that depend on it made to agree again where
  the proof holds them:

  - a key event's handover, signed again with its outgoing key (resign/2);
  - a record's hash, and the walks of the inclusion proofs above it, up to each epoch's hash
    (rehash/4, recommit/2, walk_up/4, reepoch/2), from an item's claims or record
    (recommit_item/1, reitem/1), a witness entropy object (rewitness/2), an entropy subject
    (resubject/1, reobserve/1), a beacon observation, whose block's tree is built again
    (reobservation/2, retree/1), or a genesis block's `metadata.genesis` (regenesis/2);
  - for a Bitcoin entry, the transaction that carries that hash, put in its regtest block in
    place of the old one, with the block's Merkle root, its header ground again at its own
    nBits, and the merkleblock (repush/4, reblock/3, through Generator.Bitcoin).

  A Stellar entry's copy of the epoch hash is on its chain, which no offline check reads, so
  nothing here changes a Stellar entry's `transaction_hash` or `ledger`.

  recommit/2 makes the entries of one block position agree with that block. Where another
  position's entries hold the same epoch, as the /signing_key_event entries of a proof whose
  /block is h4 hold E2 (Generator.Chain), they keep the old epoch: no offline check compares
  the entries of two positions, but a case that changes a /block record reads more plainly
  from a proof whose /block has an epoch of its own, such as item-rotation-witness (h6, in E3)
  or block (h0, in E1, beside h5 in E2).
  """

  alias Generator.{Bitcoin, Bytes, Chain, Keys, Merkle, Pointer, Registry, Regtest, Seeds}

  @w "/witnesses/block"

  @doc "The value at `pointer`, or nil when there is none."
  def get(proof, pointer), do: Pointer.get(proof, pointer)

  @doc "The proof with the value at `pointer` set to `value`, a member added where it lacks one."
  def put(proof, pointer, value), do: put_at(proof, Pointer.segments(pointer), value)

  defp put_at(_old, [], value), do: value

  defp put_at(map, [name | rest], value) when is_map(map),
    do: Map.put(map, name, put_at(Map.get(map, name), rest, value))

  defp put_at(list, [index | rest], value) when is_list(list),
    do: List.update_at(list, String.to_integer(index), &put_at(&1, rest, value))

  @doc "The proof with the member at `pointer` removed."
  def delete(proof, pointer) do
    {parent, [name]} = Enum.split(Pointer.segments(pointer), -1)
    update_at(proof, parent, &Map.delete(&1, name))
  end

  defp update_at(value, [], fun), do: fun.(value)

  defp update_at(map, [name | rest], fun) when is_map(map),
    do: Map.update!(map, name, &update_at(&1, rest, fun))

  defp update_at(list, [index | rest], fun) when is_list(list),
    do: List.update_at(list, String.to_integer(index), &update_at(&1, rest, fun))

  @doc "A string with its first character changed, within every pattern class it is in."
  def flip(proof, pointer) do
    <<first, rest::binary>> = get(proof, pointer)
    put(proof, pointer, <<if(first == ?0, do: ?1, else: ?0), rest::binary>>)
  end

  @doc "A hex string with one more octet, 00, on its end."
  def append(proof, pointer), do: put(proof, pointer, get(proof, pointer) <> "00")

  @doc "The value at `target` set to H(kind, the value at `preimage`), in hex."
  def rehash(proof, target, kind, preimage),
    do: put(proof, target, Bytes.hex(Registry.record_hash(kind, get(proof, preimage))))

  @doc """
  The key event at block node `b` made to introduce the key `public` (a B64U32), with its
  `key_id` and the record's `signing_key_id` made to agree.
  """
  def introduce(proof, b, public) do
    key_id = Keys.key_id(Bytes.unb64u(public))

    proof
    |> put(b <> "/record/metadata/key_event/public_key", public)
    |> put(b <> "/record/metadata/key_event/key_id", key_id)
    |> put(b <> "/record/signing_key_id", key_id)
  end

  @doc """
  The handover of the event at `e`, when it has one, signed again by its outgoing key, whose
  seed must be one Generator.Seeds knows.
  """
  def resign(proof, e) do
    case get(proof, e) do
      %{"handover_signature" => _signature} = event ->
        message = Registry.record_hash("handover", Map.delete(event, "handover_signature"))
        seed = Seeds.of(Bytes.unb64u(event["previous_public_key"]))
        put(proof, e <> "/handover_signature", Bytes.b64u(Keys.sign(seed, message)))

      _unsigned ->
        proof
    end
  end

  @doc """
  The values above an item's changed claims or record made to agree again: its
  `claims_hash`, its `item_hash`, the root its walk reaches in /block's record, and /block's
  hash and entries (recommit/2).
  """
  def recommit_item(proof) do
    proof
    |> rehash("/subject/record/claims_hash", "claims_hash", "/subject/claims")
    |> reitem()
  end

  @doc """
  The values above an item's changed record made to agree again, its `claims_hash` left as it
  is: its `item_hash`, the root its walk reaches in /block's record, and /block's hash and
  entries.
  """
  def reitem(proof) do
    proof
    |> rehash("/subject/item_hash", "item_hash", "/subject/record")
    |> walk_up(get(proof, "/subject/inclusion_proof"), "/subject/item_hash", "/block/record")
    |> recommit("/block")
  end

  @doc """
  The values above an item's changed witness `entropy_X` made to agree again: its
  `witness_hashes` entry, then everything reitem/1 makes agree.
  """
  def rewitness(proof, name) do
    proof
    |> rehash("/subject/record/witness_hashes/" <> name, "entropy_hash", "/witnesses/" <> name)
    |> reitem()
  end

  @doc """
  The values above an entropy proof's changed subject made to agree again: its
  `entropy_hash`, then everything reobserve/1 makes agree.
  """
  def resubject(proof) do
    proof
    |> rehash("/subject/record/entropy_hash", "entropy_hash", "/subject/entropy")
    |> reobserve()
  end

  @doc """
  The values above an entropy proof's changed subject record made to agree again, its
  `entropy_hash` left as it is: its `observation_hash`, the root its walk reaches in /block's
  record, and /block's hash and entries.
  """
  def reobserve(proof) do
    inclusion = get(proof, "/subject/inclusion_proof")

    proof
    |> rehash("/subject/observation_hash", "observation_hash", "/subject/record")
    |> walk_up(inclusion, "/subject/observation_hash", "/block/record")
    |> recommit("/block")
  end

  @doc """
  The values above a beacon's changed observation `name` made to agree again: its
  `entropy_hash` and `observation_hash`, then everything retree/1 makes agree.
  """
  def reobservation(proof, name) do
    o = "/observations/" <> name

    proof
    |> rehash(o <> "/record/entropy_hash", "entropy_hash", o <> "/entropy")
    |> rehash(o <> "/observation_hash", "observation_hash", o <> "/record")
    |> retree()
  end

  @doc """
  A beacon's /block tree built again from the observations it carries, which must be every
  leaf of the block, each at its `leaf_index`: each inclusion proof and the root made to
  agree, then /block's hash and entries.
  """
  def retree(proof) do
    observations = get(proof, "/observations")
    at = Map.new(observations, fn {name, o} -> {o["inclusion_proof"]["leaf_index"], name} end)
    count = get(proof, "/block/record/leaf_count")
    ^count = map_size(at)
    names = for i <- 0..(count - 1)//1, do: Map.fetch!(at, i)
    leaves = Enum.map(names, &Bytes.unhex(observations[&1]["observation_hash"]))

    names
    |> Enum.with_index()
    |> Enum.reduce(proof, fn {name, i}, acc ->
      put(acc, "/observations/#{name}/inclusion_proof", Merkle.proof(i, leaves))
    end)
    |> put("/block/record/merkle_root", Bytes.hex(Merkle.root(leaves)))
    |> recommit("/block")
  end

  @doc """
  A genesis block record's changed `metadata.genesis` made to agree again: its
  `previous_block_hash`, H(0x30, genesis), then the hashes above the block at `b`
  (recommit/2).
  """
  def regenesis(proof, b) do
    proof
    |> rehash(
      b <> "/record/previous_block_hash",
      "genesis_previous_block_hash",
      b <> "/record/metadata/genesis"
    )
    |> recommit(b)
  end

  @doc """
  The values above a changed block record at `b` made to agree again, up to each epoch's hash
  and a Bitcoin entry's evidence: for the witness block, its hash, the item's `witness_hashes`
  entry, the item's hash and the root its walk reaches, then /block; for /block or
  /signing_key_event/block, its hash and each of its position's entries.
  """
  def recommit(proof, @w) do
    hash = Bytes.hex(Registry.record_hash("block_hash", get(proof, @w <> "/record")))

    proof
    |> put(@w <> "/block_hash", hash)
    |> put("/subject/record/witness_hashes/block", hash)
    |> rehash("/subject/item_hash", "item_hash", "/subject/record")
    |> walk_up(get(proof, "/subject/inclusion_proof"), "/subject/item_hash", "/block/record")
    |> recommit("/block")
  end

  def recommit(proof, b) do
    base = if b == "/block", do: "/commitments", else: "/signing_key_event/commitments"
    proof = rehash(proof, b <> "/block_hash", "block_hash", b <> "/record")

    proof
    |> get(base)
    |> Map.keys()
    |> Enum.reduce(proof, &rewalk(&2, base <> "/" <> &1, b <> "/block_hash"))
  end

  # The epoch of entry `n` made to agree with the block hash at `leaf`: its root, then its hash
  # and a Bitcoin entry's transaction (reepoch/2).
  defp rewalk(proof, n, leaf) do
    proof
    |> walk_up(get(proof, n <> "/inclusion_proof"), leaf, n <> "/epoch/record")
    |> reepoch(n)
  end

  @doc """
  Entry `n`'s `epoch_hash` made to agree with its epoch record, and a Bitcoin entry's
  transaction, which carries that hash, with it (repush/4).
  """
  def reepoch(proof, n) do
    old = Bytes.unhex(get(proof, n <> "/epoch/epoch_hash"))
    proof = rehash(proof, n <> "/epoch/epoch_hash", "epoch_hash", n <> "/epoch/record")
    new = Bytes.unhex(get(proof, n <> "/epoch/epoch_hash"))
    if String.ends_with?(n, "/bitcoin"), do: repush(proof, n, old, new), else: proof
  end

  @doc """
  Entry `n`'s transaction, whose one OP_RETURN pushes the 32 bytes `old`, made to push `new`,
  in its block built again (reblock/3).
  """
  def repush(proof, n, old, new) do
    raw = Bytes.unhex(get(proof, n <> "/raw_transaction"))
    pushed = <<0x6A, 0x20, old::binary>>
    [_one] = :binary.matches(raw, pushed)
    reblock(proof, n, :binary.replace(raw, pushed, <<0x6A, 0x20, new::binary>>))
  end

  @doc """
  Entry `n`'s Bitcoin evidence made to agree with the transaction `raw`, put in place of the
  one the entry names in the regtest block at its height: the transaction's hash, the block's
  Merkle root, its header ground again at its own nBits, and the merkleblock.
  """
  def reblock(proof, n, raw) do
    %{header: header, txs: txs} = Regtest.block(regtest(), get(proof, n <> "/height"))
    named = Bitcoin.internal(get(proof, n <> "/transaction_hash"))
    txids = Enum.map(txs, &Bitcoin.txid/1)
    index = Enum.find_index(txids, &(&1 == named))
    txids = List.replace_at(txids, index, Bitcoin.txid(raw))
    root = Bitcoin.merkle_root(txids)

    <<version::little-32, previous::binary-32, _root::binary-32, time::little-32, bits::little-32,
      _nonce::binary-4>> = header

    header =
      Bitcoin.grind(%{
        version: version,
        previous: previous,
        merkle_root: root,
        time: time,
        bits: bits,
        nonce: 0
      })

    proof
    |> put(n <> "/raw_transaction", Bytes.hex(raw))
    |> put(n <> "/transaction_hash", Bitcoin.display(Bitcoin.txid(raw)))
    |> put(n <> "/txoutproof", Bytes.hex(Bitcoin.merkleblock(header, txids, index)))
    |> put(n <> "/header_hash", Bitcoin.display(Bitcoin.sha256d(header)))
    |> put(n <> "/header_merkle_root", Bitcoin.display(root))
  end

  @doc "The modeled regtest chain the entries point into (Generator.Chain), built once per run."
  def regtest do
    case Process.get({__MODULE__, :regtest}) do
      nil ->
        regtest = Chain.build().regtest
        Process.put({__MODULE__, :regtest}, regtest)
        regtest

      regtest ->
        regtest
    end
  end

  @doc "The record's `merkle_root` set to the root the walk from the value at `leaf` reaches."
  def walk_up(proof, inclusion, leaf, record) do
    {:ok, root} = Merkle.walk(get(proof, leaf), inclusion)
    put(proof, record <> "/merkle_root", root)
  end

  @doc """
  The inclusion proof at `q` given another `tree_size`, or else, for the last leaf, the index
  and size one less, whose walk from the leaf recomputed from `{kind, preimage}` reaches the
  same root. With `move: false` its `leaf_index` stays, and a proof that no other size fits
  raises rather than moving it.
  """
  def resize(proof, q, {kind, preimage}, options \\ []) do
    leaf = Bytes.hex(Registry.record_hash(kind, get(proof, preimage)))
    %{"leaf_index" => index, "tree_size" => size} = inclusion = get(proof, q)
    root = Merkle.walk(leaf, inclusion)

    sizes = for s <- 1..(2 * size), s != size, do: %{inclusion | "tree_size" => s}
    moved = %{inclusion | "leaf_index" => index - 1, "tree_size" => size - 1}
    move? = Keyword.get(options, :move, true) and index == size - 1
    candidates = if move?, do: sizes ++ [moved], else: sizes

    case Enum.find(candidates, &(Merkle.walk(leaf, &1) == root)) do
      nil -> raise ArgumentError, "no other tree_size of #{q} walks to the same root"
      resized -> put(proof, q, resized)
    end
  end

  @doc """
  SPEC.md 13.3's moved leaf index carried into entry `n`'s epoch record: the last of three
  leaves presented as index 1 of two, with the epoch's `leaf_count` and hash made to agree.
  """
  def moved_index(proof, n) do
    proof
    |> put(n <> "/inclusion_proof/leaf_index", 1)
    |> put(n <> "/inclusion_proof/tree_size", 2)
    |> put(n <> "/epoch/record/leaf_count", 2)
    |> rehash(n <> "/epoch/epoch_hash", "epoch_hash", n <> "/epoch/record")
  end

  @doc "The raw transaction at `pointer` with its lock time changed to 0xffffffff."
  def relock(proof, pointer) do
    raw = get(proof, pointer)
    put(proof, pointer, binary_part(raw, 0, byte_size(raw) - 8) <> "ffffffff")
  end

  @doc "Entry `n`'s `transaction_hash` made to agree with its `raw_transaction`."
  def retxid(proof, n) do
    raw = Bytes.unhex(get(proof, n <> "/raw_transaction"))
    put(proof, n <> "/transaction_hash", Bitcoin.display(Bitcoin.txid(raw)))
  end
end
