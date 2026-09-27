# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Generator.Mutations do
  @moduledoc """
  The mutation self-test of check 2: each check Generator.Derive makes can fail at every
  position the coverage table names (Generator.Positive), one mutant per (check, position)
  pair. For each pair, one defect is made in memory in a sound proof that runs the check
  there, the way SPEC.md 13.3's single-defect cases make one, and DERIVE is run again over the
  result:

  - on the sound proof, the check has a row at that position that does not fail;
  - on the mutant, that row fails;
  - it is the only row that fails, or, for a pair not_isolated/0 names, the rows that fail are
    it and exactly the rows listed for it.

  A position is a row's part, and for a root row of LINK_INCLUSION also the inclusion proof
  that walks to it (Generator.Derive.position/1), so where several walks reach one root the
  test says which walk failed.

  A defect is one changed value, with the values that depend on it made to agree again where
  the proof holds them, by the edits of Generator.Edit, which the cases of vectors/cases.json
  make their defects with too.
  """

  import Generator.Check
  import Generator.Edit

  alias Generator.{Bytes, Derive, Keys, Seeds}

  @w "/witnesses/block"
  @ske "/signing_key_event/block"
  @root "/block/record/merkle_root"
  @sources ~w(bitcoin nist stellar)

  # The public key of 32 bytes 0x01 and 0x00 after it: the identity, a small-order key.
  @identity Bytes.b64u(<<1, 0::248>>)

  @doc """
  The pairs whose mutant fails other rows too, each with those rows as `{check, position}`.
  The key at /signing_key_event/block must be K, or LINK_KEY_EVENT fails; and a K that fails
  the checks of a key's bytes is a bare rejection at ENVELOPE (SPEC.md 13.3), so no proof
  that reaches DERIVE holds such a key there with LINK_KEY_EVENT passing.
  """
  def not_isolated do
    public_key = @ske <> "/record/metadata/key_event/public_key"
    %{{:key_public_key, public_key} => [{:key_event_link, public_key}]}
  end

  @doc """
  The failures of the self-test over `proofs`, each decoded proof by its name, in a run whose
  attribution is `attribution`, where `positions` are the coverage table's pairs.
  """
  def run(proofs, attribution, positions) do
    table = mutations()
    pairs = Enum.map(table, fn {check, position, _name, _mutate} -> {check, position} end)

    [
      expect(
        "the (check, position) pairs of the mutation table",
        Enum.sort(pairs),
        Enum.sort(positions)
      )
      | Enum.map(table, &test(proofs, attribution, &1))
    ]
    |> List.flatten()
  end

  defp test(proofs, attribution, {check, position, name, mutate}) do
    %{proof: proof, k: k, rows: rows} = Map.fetch!(proofs, name)
    label = "mutation self-test, #{check} in #{name} at #{inspect(position)}"
    mutant = mutate.(proof)
    here = &(&1.check == check and Derive.position(&1) == position)

    failing =
      for row <- Derive.rows(mutant, k, attribution),
          row.status == "fail",
          do: {row.check, Derive.position(row)}

    [
      truth(
        "#{label}: the sound proof runs the check there and it holds",
        Enum.any?(rows, &(here.(&1) and &1.status != "fail"))
      ),
      truth("#{label}: the mutant differs", mutant != proof),
      truth("#{label}: the check fails there", {check, position} in failing),
      expect(
        "#{label}: the rows that fail",
        Enum.sort(failing),
        Enum.sort([{check, position} | Map.get(not_isolated(), {check, position}, [])])
      )
    ]
  end

  # {check, position, proof, mutation}, one for each pair of the coverage table.
  defp mutations do
    List.flatten([
      subject(),
      Enum.map(@sources, &observation/1),
      block_nodes(),
      introductions(),
      handovers(),
      prerotations(),
      Enum.map(entries(), &entry/1),
      links()
    ])
  end

  # A payload value of each source that only its entropy_hash reads offline.
  defp payload("nist"), do: "/payload/pulse/outputValue"
  defp payload(_stellar_or_bitcoin), do: "/payload/hash"

  # The subject's hashes, and the root and size of its walk.
  defp subject do
    [
      {:claims_hash, "/subject/record/claims_hash", "item",
       &put(&1, "/subject/claims/name", "another name")},
      {:item_hash, "/subject/item_hash", "item", &flip(&1, "/subject/item_hash")},
      {:subject_entropy_hash, "/subject/record/entropy_hash", "entropy_nist",
       &flip(&1, "/subject/entropy" <> payload("nist"))},
      {:subject_observation_hash, "/subject/observation_hash", "entropy_nist",
       &flip(&1, "/subject/observation_hash")},
      {:subject_root, {@root, "/subject/inclusion_proof"}, "item",
       &flip(&1, "/subject/inclusion_proof/path/0")},
      {:subject_tree_size, "/subject/inclusion_proof/tree_size", "item",
       &resize(&1, "/subject/inclusion_proof", {"item_hash", "/subject/record"})}
    ]
  end

  # A beacon observation's hashes, and the root and size of its walk, of which the beacon has
  # three to one root.
  defp observation(source) do
    o = "/observations/entropy_" <> source
    q = o <> "/inclusion_proof"

    [
      {:observation_entropy_hash, o <> "/record/entropy_hash", "beacon",
       &flip(&1, o <> "/entropy" <> payload(source))},
      {:observation_observation_hash, o <> "/observation_hash", "beacon",
       &flip(&1, o <> "/observation_hash")},
      {:observation_root, {@root, q}, "beacon", &flip(&1, q <> "/path/0")},
      {:observation_tree_size, q <> "/tree_size", "beacon",
       &resize(&1, q, {"observation_hash", o <> "/record"})}
    ]
  end

  # Each block position's hash and genesis rows: the genesis block h0 at /block, and the
  # second chain's genesis block k0 at the other two. A genesis height of 1 at
  # /witnesses/block does not fail LINK_HEAD, which compares the recomputed 0 (SPEC.md 10.3).
  defp block_nodes do
    for {b, hash_in, genesis_in} <- [
          {"/block", "block", "block"},
          {@w, "item", "item-genesis-witness"},
          {@ske, "block", "item-genesis-witness"}
        ] do
      r = b <> "/record"

      [
        {:block_hash, b <> "/block_hash", hash_in, &flip(&1, b <> "/block_hash")},
        {:genesis_height, r <> "/height", genesis_in,
         &(&1 |> put(r <> "/height", 1) |> recommit(b))},
        {:genesis_previous_block_hash, r <> "/previous_block_hash", genesis_in,
         &(&1 |> flip(r <> "/previous_block_hash") |> recommit(b))}
      ]
    end
  end

  # The checks of an event that introduces a key, each made at a genesis event, which has no
  # handover: h0 at /block, and k0 at the other two positions.
  defp introductions do
    for {b, name} <- [
          {"/block", "block"},
          {@w, "item-genesis-witness"},
          {@ske, "item-genesis-witness"}
        ] do
      e = b <> "/record/metadata/key_event"
      r = b <> "/record"

      [
        {:key_public_key, e <> "/public_key", name,
         &(&1 |> introduce(b, @identity) |> recommit(b))},
        {:key_id, e <> "/key_id", name, &(&1 |> put(e <> "/key_id", "00000000") |> recommit(b))},
        {:key_signing_key_id, r <> "/signing_key_id", name,
         &(&1 |> put(r <> "/signing_key_id", "00000000") |> recommit(b))}
      ]
    end
  end

  # The checks of a handover: at /block, the emergency rotation h2, which has no signature to
  # sign again, and the rotation h5 for the signature itself; at the other two positions, h5.
  defp handovers do
    for {b, name, signed} <- [
          {"/block", "block-emergency-rotation", "block-rotation"},
          {@w, "item-rotation-witness", "item-rotation-witness"},
          {@ske, "block", "block"}
        ] do
      e = b <> "/record/metadata/key_event"

      [
        {:previous_key_id, e <> "/previous_key_id", name,
         &(&1 |> put(e <> "/previous_key_id", "00000000") |> resign(e) |> recommit(b))},
        {:event_height, e <> "/height", name,
         &(&1 |> put(e <> "/height", 9) |> resign(e) |> recommit(b))},
        {:event_previous_block_hash, e <> "/previous_block_hash", name,
         &(&1 |> flip(e <> "/previous_block_hash") |> resign(e) |> recommit(b))},
        {:handover_signature, e <> "/handover_signature", signed,
         &(&1 |> flip(e <> "/handover_signature") |> recommit(b))}
      ]
    end
  end

  # The prerotation h3, at /block of the empty beacon and as the item's witness block.
  defp prerotations do
    for {b, name} <- [{"/block", "beacon-empty"}, {@w, "item"}] do
      {:prerotation_signing_key_id, b <> "/record/signing_key_id", name,
       &(&1 |> put(b <> "/record/signing_key_id", "00000000") |> recommit(b))}
    end
  end

  # Each commitment entry, with the names of its two LINK_INCLUSION checks and its walk's leaf.
  defp entries do
    for {base, root, size, leaf} <- [
          {"/commitments", :commitment_root, :commitment_tree_size, "/block/record"},
          {"/signing_key_event/commitments", :key_commitment_root, :key_commitment_tree_size,
           @ske <> "/record"}
        ],
        chain <- ~w(bitcoin stellar),
        do: {base <> "/" <> chain, root, size, leaf}
  end

  # An entry's epoch hash, the root and size of the walk into its epoch, and its Bitcoin
  # evidence, in the block proof: its /block is h0, the first of E1's three leaves, and its
  # /signing_key_event/block is h5, the last of E2's.
  defp entry({n, root, size, leaf}) do
    q = n <> "/inclusion_proof"

    [
      {:epoch_hash, n <> "/epoch/epoch_hash", "block", &flip(&1, n <> "/epoch/epoch_hash")},
      {root, {n <> "/epoch/record/merkle_root", q}, "block", &flip(&1, q <> "/path/0")},
      {size, q <> "/tree_size", "block", &resize(&1, q, {"block_hash", leaf})}
      | if(String.ends_with?(n, "/bitcoin"), do: bitcoin(n), else: [])
    ]
  end

  # The Bitcoin evidence of entry `n`. The OP_RETURN's defect is SPEC.md 13.3's moved index
  # carried into the epoch record: the last of three leaves presented as index 1 of two, with
  # the epoch's leaf_count and hash made to agree, so the new hash is not the transaction's
  # copy. h5 is the last of E2's three leaves, at /block in block-rotation and at
  # /signing_key_event/block in every proof of the first chain.
  defp bitcoin(n) do
    raw = n <> "/raw_transaction"
    moved = if String.starts_with?(n, "/commitments"), do: "block-rotation", else: "block"

    [
      # A byte after the lock time, in a block built again around the longer transaction, so
      # the merkleblock still matches it.
      {:raw_transaction_well_formed, raw, "block",
       &reblock(&1, n, Bytes.unhex(get(&1, raw)) <> <<0>>)},
      {:op_return, raw, moved, &moved_index(&1, n)},
      {:transaction_hash, n <> "/transaction_hash", "block", &flip(&1, n <> "/transaction_hash")},
      {:txoutproof_well_formed, n <> "/txoutproof", "block", &append(&1, n <> "/txoutproof")},
      # Another transaction with the same OP_RETURN, which the merkleblock does not match.
      {:matched_hash, n <> "/txoutproof", "block", &(&1 |> relock(raw) |> retxid(n))},
      {:header_hash, n <> "/header_hash", "block", &flip(&1, n <> "/header_hash")},
      {:header_merkle_root, n <> "/header_merkle_root", "block",
       &flip(&1, n <> "/header_merkle_root")},
      {:header_time, n <> "/header_time", "block",
       &put(&1, n <> "/header_time", "2026-09-26T00:00:00Z")}
    ]
  end

  defp links do
    public_key = @ske <> "/record/metadata/key_event/public_key"

    [
      {:witness_block, "/subject/record/witness_hashes/block", "item",
       &(&1
         |> flip(@w <> "/record/id")
         |> rehash(@w <> "/block_hash", "block_hash", @w <> "/record"))},
      {:head, @w <> "/record/height", "item-rotation-witness",
       &(&1
         |> put("/block/record/height", get(&1, @w <> "/record/height"))
         |> recommit("/block"))},
      {:key_event_link, public_key, "item-genesis-witness",
       &(&1 |> introduce(@ske, Bytes.b64u(Keys.public_key(Seeds.genesis()))) |> recommit(@ske))}
      | Enum.map(@sources, &witness_entropy/1) ++ chain_order()
    ]
  end

  defp witness_entropy(source) do
    {:witness_entropy, "/subject/record/witness_hashes/entropy_" <> source, "item",
     &flip(&1, "/witnesses/entropy_" <> source <> payload(source))}
  end

  # The top-level entry of the chain moved onto the entropy object: Stellar's ledger to the
  # object's sequence, and Bitcoin's height to one below the object's.
  defp chain_order do
    stellar =
      for {e, name} <- [
            {"/subject/entropy", "entropy_stellar"},
            {"/witnesses/entropy_stellar", "item"},
            {"/observations/entropy_stellar/entropy", "beacon"}
          ] do
        sequence = e <> "/payload/sequence"

        {:chain_order_stellar, sequence, name,
         &put(&1, "/commitments/stellar/ledger", get(&1, sequence))}
      end

    bitcoin =
      for {e, name} <- [
            {"/subject/entropy", "entropy_bitcoin"},
            {"/witnesses/entropy_bitcoin", "item"},
            {"/observations/entropy_bitcoin/entropy", "beacon"}
          ] do
        height = e <> "/payload/height"

        {:chain_order_bitcoin, height, name,
         &put(&1, "/commitments/bitcoin/height", get(&1, height) - 1)}
      end

    stellar ++ bitcoin
  end
end
