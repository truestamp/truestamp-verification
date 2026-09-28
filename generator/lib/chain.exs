# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Generator.Chain do
  @moduledoc """
  The two Truestamp chains the positive vectors are cut from, built the way Truestamp builds
  one, with every value computed from the values before it. The timeline, all on 2026-09-26
  UTC:

  | Time | Truestamp | Chains and sources |
  |---|---|---|
  | 01:30:00 | | regtest block 200 (genesis.bitcoin of the first chain) |
  | 01:42:00 | | regtest block 212 (genesis.bitcoin of the second chain) |
  | 01:44:00 | h0, genesis of the first chain: key G, no leaves | regtest tip 214 |
  | 01:45:05 | observation N0 of NIST pulse 1,200,015 (01:45:00) | |
  | 01:45:20 | observation S0 of Stellar ledger 1,000,183 (closed 01:45:15) | |
  | 01:45:30 | observation B1 of regtest block 215 (mined 01:45:00) | |
  | 01:46:00 | h1: N0, S0, B1 | |
  | 01:47:00 | h2, emergency rotation from G to H, with no handover signature | |
  | 01:47:10 | epoch E1 = h0, h1, h2 is written to both chains | |
  | 01:47:15 | | Stellar testnet ledger 1,000,207 holds E1's hash |
  | 01:47:30 | h3, prerotation: H names the next key, VECTOR_KEY | |
  | 01:48:00 | | regtest block 218 holds E1's hash |
  | 01:48:05 | observation N1 of NIST pulse 1,200,018 (01:48:00) | |
  | 01:48:35 | observation S1 of Stellar ledger 1,000,222 (closed 01:48:30) | |
  | 01:49:00 | item I submitted, with h3 at the head: witnesses h3, N1, S1, B1 | |
  | 01:50:00 | h4: N1, S1, I | |
  | 01:50:30 | h5, rotation from H to VECTOR_KEY, with H's handover signature | |
  | 01:51:10 | epoch E2 = h3, h4, h5 is written to both chains | |
  | 01:51:15 | | Stellar testnet ledger 1,000,255 holds E2's hash |
  | 01:51:30 | item K submitted, with h5 at the head: witnesses h5, N1, S1, B1 | |
  | 01:52:00 | h6: K alone | regtest block 222 holds E2's hash |
  | 01:52:10 | epoch E3 = h6 is written to Stellar only | |
  | 01:52:15 | | Stellar testnet ledger 1,000,267 holds E3's hash |
  | 01:55:00 | k0, genesis of the second chain: VECTOR_KEY, no leaves | |
  | 01:56:00 | item J submitted, with k0 at the head and no observation yet: witness k0 | |
  | 01:57:00 | k1: J alone | |
  | 01:57:10 | epoch F1 = k0, k1 is written to Stellar only | |
  | 01:57:15 | | Stellar testnet ledger 1,000,327 holds F1's hash; regtest runs on to block 233 |

  Keys (Generator.Seeds): G signs h0 and h1; H, which h2 introduces, signs h2 to h4 and h5's
  handover; VECTOR_KEY, which h5 introduces, signs h5 and h6. So the item I, in h4, is older
  than the rotation whose key signs its proof (SPEC.md 13.3). The second chain begins with
  VECTOR_KEY, whose genesis event commits to H as the next key, and VECTOR_KEY signs k0 and
  k1. VECTOR_KEY signs every proof.

  Positions: h5 is the last of the three leaves of E2, and B1 and I the last of the three
  leaves of h1 and h4, so SPEC.md 13.3's moved leaf index has a sound proof to start from at
  both levels, for an epoch entry, a subject and a beacon observation. S1, the middle leaf of
  h4, is a subject whose leaf_index can take another route.

  Sources: NIST chain 2 gives pulse 1,200,000 at 01:30:00.000 and one a minute after; Stellar
  testnet closes ledger 1,000,000 at 01:30:00 and one every 5 seconds after. A NIST
  outputValue, a Stellar ledger hash and a Stellar transaction hash are SHA-512 or SHA-256 of
  a label, since only the regtest chain is modeled byte for byte (Generator.Regtest).

  Leaves are sorted by key, byte-wise, as Truestamp sorts them: a block's by the id of each
  item or observation, an epoch's by block id. Ids are UUIDv7, with the time of the table in
  their leftmost 48 bits and the rest of their bits from SHA-256 of a label, so the leaves of
  a block fall in time order.
  """

  alias Generator.{Bitcoin, Bytes, Keys, Merkle, Registry, Regtest, Seeds}

  @day 1_790_380_800
  @base 1_790_386_200
  @stellar_network "testnet"
  @bitcoin_network "regtest"
  @wallet "truestamp vectors epoch wallet"
  @fee 1_250
  # The regtest block that holds E1's transaction, whose change E2's transaction spends.
  @first_write 218

  @doc """
  The model: for each chain, its blocks by height, its epochs, the height of the block whose
  key event introduced VECTOR_KEY, and its items and observations by name; and the regtest
  chain.
  """
  def build do
    regtest = Regtest.extend(Regtest.new(), @first_write - 1)
    {first, regtest} = first_chain(regtest)
    {second, regtest} = second_chain(regtest)
    %{chains: %{first: first, second: second}, regtest: Regtest.extend(regtest, 233)}
  end

  defp first_chain(regtest) do
    n0 = observation(nist_entropy("01:45:00"), "01:45:05", "n0")
    s0 = observation(stellar_entropy("01:45:15"), "01:45:20", "s0")
    b1 = observation(bitcoin_entropy(regtest, 215), "01:45:30", "b1")
    h0 = genesis_block(regtest, 200, "01:44:00", Seeds.genesis(), nil, "h0")
    h1 = data_block(h0, [n0, s0, b1], "01:46:00", Seeds.genesis(), "h1")
    h2 = rotation_block(h1, "01:47:00", {Seeds.genesis(), Seeds.emergency()}, 1, false)
    e1_write = {@first_write, &first_block/3}
    {regtest, e1} = write_epoch(regtest, [h0, h1, h2], "01:47:15", e1_write)

    h3 = prerotation_block(h2, "01:47:30", Seeds.emergency(), Seeds.vector())
    n1 = observation(nist_entropy("01:48:00"), "01:48:05", "n1")
    s1 = observation(stellar_entropy("01:48:30"), "01:48:35", "s1")
    witnesses = %{"bitcoin" => b1, "nist" => n1, "stellar" => s1}
    i = item(h3, witnesses, sound_claims(), "01:49:00", "i")
    h4 = data_block(h3, [i, n1, s1], "01:50:00", Seeds.emergency(), "h4")
    h5 = rotation_block(h4, "01:50:30", {Seeds.emergency(), Seeds.vector()}, 2, true)
    regtest = Regtest.extend(regtest, 221)
    {regtest, e2} = write_epoch(regtest, [h3, h4, h5], "01:51:15", {222, &second_block/3})

    k = item(h5, witnesses, claims("an item submitted after the rotation"), "01:51:30", "k")
    h6 = data_block(h5, [k], "01:52:00", Seeds.vector(), "h6")
    {regtest, e3} = write_epoch(regtest, [h6], "01:52:15", nil)

    chain = %{
      blocks: [h0, h1, h2, h3, h4, h5, h6],
      epochs: [e1, e2, e3],
      key_event: 5,
      subjects: %{b1: b1, i: i, k: k, n0: n0, n1: n1, s0: s0, s1: s1}
    }

    {chain, regtest}
  end

  defp second_chain(regtest) do
    k0 = genesis_block(regtest, 212, "01:55:00", Seeds.vector(), Seeds.emergency(), "k0")
    j = item(k0, %{}, claims("the first item of the second chain"), "01:56:00", "j")
    k1 = data_block(k0, [j], "01:57:00", Seeds.vector(), "k1")
    {regtest, f1} = write_epoch(regtest, [k0, k1], "01:57:15", nil)
    {%{blocks: [k0, k1], epochs: [f1], key_event: 0, subjects: %{j: j}}, regtest}
  end

  @doc "The commitments of `block` in `chain`: each chain's entry for it (SPEC.md 3.4)."
  def commitments(chain, block) do
    epoch = Enum.find(chain.epochs, fn e -> block.hash in e.leaves end)
    proof = Merkle.proof(Enum.find_index(epoch.leaves, &(&1 == block.hash)), leaf_bytes(epoch))

    Map.new(epoch.entries, fn {name, entry} ->
      {name, Map.merge(entry, %{"epoch" => epoch.node, "inclusion_proof" => proof})}
    end)
  end

  defp leaf_bytes(%{leaves: leaves}), do: Enum.map(leaves, &Bytes.unhex/1)

  @doc "The MERKLE_PROOF of a leaf, an item or an observation, in the block of `chain` that holds it."
  def inclusion_proof(chain, leaf) do
    block = Enum.find(chain.blocks, fn b -> leaf.hash in b.leaves end)
    Merkle.proof(Enum.find_index(block.leaves, &(&1 == leaf.hash)), leaf_bytes(block))
  end

  # Times: "HH:MM:SS" on the day, as Unix seconds, and in the forms the proof carries.

  defp at(clock) do
    [h, m, s] = clock |> String.split(":") |> Enum.map(&String.to_integer/1)
    @day + h * 3600 + m * 60 + s
  end

  defp time_text(unix), do: unix |> DateTime.from_unix!() |> DateTime.to_iso8601()

  # Ids: a UUIDv7 at a time, with the rest of its bits from a label.

  defp uuid7(unix, label) do
    <<a::12, b::62, _rest::bits>> = :crypto.hash(:sha256, "vectors id " <> label)
    hex = Bytes.hex(<<unix * 1000::48, 7::4, a::12, 2::2, b::62>>)

    Enum.map_join([{0, 8}, {8, 4}, {12, 4}, {16, 4}, {20, 12}], "-", fn {at, n} ->
      binary_part(hex, at, n)
    end)
  end

  # Entropy objects (SPEC.md 3.5), and observations of them. An observation keeps its source
  # and its source time, by which a beacon picks the observation of each source (SPEC.md 3.6).

  defp nist_entropy(clock) do
    %{"payload" => %{"pulse" => nist_pulse(pulse(at(clock)))}, "source" => "nist"}
  end

  @doc """
  The pulse of NIST chain 2 whose `pulseIndex` is `index`, as the model's NIST source gives
  it: one a minute from pulse 1,200,000 at 01:30:00.000.
  """
  def nist_pulse(index) do
    %{
      "chainIndex" => 2,
      "outputValue" => Base.encode16(:crypto.hash(:sha512, "nist chain 2 pulse #{index}")),
      "pulseIndex" => index,
      "timeStamp" => String.replace(time_text(@base + 60 * (index - 1_200_000)), "Z", ".000Z"),
      "version" => "2.0"
    }
  end

  defp stellar_entropy(clock) do
    %{
      "network" => @stellar_network,
      "payload" => stellar_ledger(ledger(clock)),
      "source" => "stellar"
    }
  end

  @doc """
  The Stellar testnet ledger whose sequence is `sequence`, as the model's Stellar source gives
  it: `closed_at`, `hash` and `sequence`, one ledger every 5 seconds from ledger 1,000,000 at
  01:30:00.
  """
  def stellar_ledger(sequence) do
    %{
      "closed_at" => time_text(@base + 5 * (sequence - 1_000_000)),
      "hash" => Bytes.hex(:crypto.hash(:sha256, "stellar testnet ledger #{sequence}")),
      "sequence" => sequence
    }
  end

  @doc """
  What the model's sources hold at its last moment, the time of the regtest tip: the tip's
  height, the first and the latest Stellar ledger, and the first and the latest NIST pulse.
  """
  def sources(model) do
    tip = Regtest.tip(model.regtest)
    now = Regtest.time(tip)

    %{
      bitcoin_tip: tip,
      stellar_elder: 1_000_000,
      stellar_latest: ledger_at(now),
      nist_first: 1_200_000,
      nist_latest: pulse(now)
    }
  end

  defp ledger(clock), do: ledger_at(at(clock))
  defp ledger_at(unix), do: 1_000_000 + div(unix - @base, 5)
  defp pulse(unix), do: 1_200_000 + div(unix - @base, 60)

  defp bitcoin_entropy(regtest, height) do
    block = Regtest.block(regtest, height)

    %{
      "network" => @bitcoin_network,
      "payload" => %{
        "hash" => Bitcoin.display(block.hash),
        "height" => height,
        "time" => block.time
      },
      "source" => "bitcoin"
    }
  end

  defp observation(entropy, clock, label) do
    record = %{
      "entropy_hash" => Bytes.hex(Registry.record_hash("entropy_hash", entropy)),
      "id" => uuid7(at(clock), label)
    }

    hash = Bytes.hex(Registry.record_hash("observation_hash", record))

    %{
      entropy: entropy,
      record: record,
      hash: hash,
      key: record["id"],
      source: entropy["source"],
      source_time: source_time(entropy)
    }
  end

  defp source_time(%{"payload" => %{"pulse" => %{"timeStamp" => time}}}), do: unix(time)
  defp source_time(%{"payload" => %{"closed_at" => time}}), do: unix(time)
  defp source_time(%{"payload" => %{"time" => time}}), do: time

  defp unix(text) do
    {:ok, time, 0} = DateTime.from_iso8601(text)
    DateTime.to_unix(time)
  end

  # The claims of SPEC.md 13.3's sound item: an md5 hash, a timestamp, a nonce, the numbers
  # 37.7749, 1e-7 and 5e-324, names that sort one way by UTF-16 code unit and the other by code
  # point, and quotes and backslashes.
  defp sound_claims do
    %{
      "hash" => Bytes.hex(:crypto.hash(:md5, "Truestamp vectors: the item's document")),
      "hash_type" => "md5",
      "location" => %{"latitude" => 37.7749, "longitude" => -122.4194},
      "name" => ~S(Q3 report "final", saved as C:\reports\q3.pdf),
      "nonce" => Bytes.hex(:crypto.hash(:sha256, "vectors item nonce")),
      "smallest" => 5.0e-324,
      "timestamp" => time_text(at("01:48:50")),
      "tolerance" => 1.0e-7,
      "\u{1F600}" => "grinning face, U+1F600",
      "\uFF5A" => "fullwidth z, U+FF5A"
    }
  end

  # The claims of another item: the sha256 hash of a document, and its name.
  defp claims(name) do
    %{
      "hash" => Bytes.hex(:crypto.hash(:sha256, "Truestamp vectors: " <> name)),
      "hash_type" => "sha256",
      "name" => name
    }
  end

  # An item submitted at `clock` while `witness_block` was the head, witnessing the latest
  # observation of each source in `witnesses`.
  defp item(witness_block, witnesses, claims, clock, label) do
    witness_hashes =
      Map.new(witnesses, fn {source, o} -> {"entropy_" <> source, o.record["entropy_hash"]} end)

    record = %{
      "claims_hash" => Bytes.hex(Registry.record_hash("claims_hash", claims)),
      "id" => uuid7(at(clock), "item " <> label),
      "witness_hashes" => Map.put(witness_hashes, "block", witness_block.hash)
    }

    hash = Bytes.hex(Registry.record_hash("item_hash", record))

    %{
      claims: claims,
      record: record,
      hash: hash,
      key: record["id"],
      witness: witness_block.height,
      witnesses: witnesses
    }
  end

  # Blocks (SPEC.md 3.3). A genesis or key-event block holds no leaves (SPEC.md 5.4).

  # A genesis block whose genesis.bitcoin is the regtest block at `bitcoin_height`, and whose
  # key is that of `seed`. With a `next` seed, its event commits to that seed's key.
  defp genesis_block(regtest, bitcoin_height, clock, seed, next, label) do
    genesis = %{
      "bitcoin" => %{
        "header_hash" => Bitcoin.display(Regtest.block(regtest, bitcoin_height).hash),
        "height" => bitcoin_height,
        "network" => @bitcoin_network
      }
    }

    key = Keys.public_key(seed)

    event = %{
      "key_id" => Keys.key_id(key),
      "public_key" => Bytes.b64u(key),
      "sequence" => 0,
      "type" => "genesis"
    }

    event = if next, do: Map.put(event, "prerotation_commitment", commitment(next)), else: event
    previous = Bytes.hex(Registry.record_hash("genesis_previous_block_hash", genesis))
    metadata = %{"genesis" => genesis, "key_event" => event}
    block(0, clock, [], metadata, previous, key, label)
  end

  defp commitment(seed),
    do: Bytes.hex(Registry.hash("prerotation_commitment", Keys.public_key(seed)))

  defp data_block(previous, leaves, clock, seed, label) do
    key = Keys.public_key(seed)
    block(previous.height + 1, clock, leaves, %{}, previous.hash, key, label)
  end

  defp prerotation_block(previous, clock, active, next) do
    key = Keys.public_key(active)

    event = %{
      "active_key_id" => Keys.key_id(key),
      "prerotation_commitment" => commitment(next),
      "type" => "prerotation"
    }

    height = previous.height + 1
    block(height, clock, [], %{"key_event" => event}, previous.hash, key, "h#{height}")
  end

  # A rotation from the key of one seed to the key of the other, with the outgoing key's
  # handover over the event, which holds the block's height and previous_block_hash (SPEC.md
  # 3.3), or an emergency rotation with none. The block is signed by the key it introduces.
  defp rotation_block(previous, clock, {outgoing_seed, incoming_seed}, sequence, handover?) do
    outgoing = Keys.public_key(outgoing_seed)
    incoming = Keys.public_key(incoming_seed)
    height = previous.height + 1
    type = if handover?, do: "rotation", else: "emergency_rotation"

    event = %{
      "height" => height,
      "key_id" => Keys.key_id(incoming),
      "previous_block_hash" => previous.hash,
      "previous_key_id" => Keys.key_id(outgoing),
      "previous_public_key" => Bytes.b64u(outgoing),
      "public_key" => Bytes.b64u(incoming),
      "reason" => if(handover?, do: "scheduled rotation", else: "emergency rotation"),
      "sequence" => sequence,
      "type" => type
    }

    message = Registry.record_hash("handover", event)

    signed =
      if handover?,
        do: Map.put(event, "handover_signature", Bytes.b64u(Keys.sign(outgoing_seed, message))),
        else: event

    block =
      block(height, clock, [], %{"key_event" => signed}, previous.hash, incoming, "h#{height}")

    if handover?, do: Map.put(block, :handover, Bytes.hex(message)), else: block
  end

  defp block(height, clock, leaves, metadata, previous, key, label) do
    sorted = Enum.sort_by(leaves, & &1.key)
    hashes = Enum.map(sorted, & &1.hash)

    record = %{
      "height" => height,
      "id" => uuid7(at(clock), label),
      "leaf_count" => length(hashes),
      "merkle_root" => Bytes.hex(Merkle.root(Enum.map(hashes, &Bytes.unhex/1))),
      "metadata" => metadata,
      "previous_block_hash" => previous,
      "signing_key_id" => Keys.key_id(key)
    }

    hash = Bytes.hex(Registry.record_hash("block_hash", record))

    %{
      height: height,
      hash: hash,
      leaves: hashes,
      contents: sorted,
      node: %{"block_hash" => hash, "record" => record}
    }
  end

  # An epoch (SPEC.md 3.4 and 5.4), and its writes: to Stellar, and to Bitcoin when `bitcoin`
  # gives the height of the regtest block that holds the write and the function that composes
  # that block's transactions. With no Bitcoin write, the epoch is committed to Stellar only.
  defp write_epoch(regtest, blocks, stellar_clock, bitcoin) do
    leaves = blocks |> Enum.sort_by(& &1.node["record"]["id"]) |> Enum.map(& &1.hash)

    record = %{
      "leaf_count" => length(leaves),
      "merkle_root" => Bytes.hex(Merkle.root(Enum.map(leaves, &Bytes.unhex/1)))
    }

    epoch_hash = Registry.record_hash("epoch_hash", record)

    stellar = %{
      "ledger" => ledger(stellar_clock),
      "network" => @stellar_network,
      "transaction_hash" =>
        Bytes.hex(:crypto.hash(:sha256, "stellar testnet transaction " <> Bytes.hex(epoch_hash)))
    }

    {regtest, entries} =
      case bitcoin do
        nil ->
          {regtest, %{"stellar" => stellar}}

        {height, compose} ->
          {regtest, entry} = write_bitcoin(regtest, height, compose, epoch_hash)
          {regtest, %{"bitcoin" => entry, "stellar" => stellar}}
      end

    node = %{"epoch_hash" => Bytes.hex(epoch_hash), "record" => record}
    {regtest, %{leaves: leaves, node: node, entries: entries}}
  end

  defp write_bitcoin(regtest, height, compose, epoch_hash) do
    {txs, index} = compose.(regtest, height, epoch_hash)
    regtest = Regtest.extend(regtest, height, %{height => txs})
    block = Regtest.block(regtest, height)
    txids = Enum.map(block.txs, &Bitcoin.txid/1)
    transaction = Enum.at(block.txs, index)

    entry = %{
      "header_hash" => Bitcoin.display(block.hash),
      "header_merkle_root" => Bitcoin.display(Bitcoin.merkle_root(txids)),
      "header_time" => time_text(block.time),
      "height" => height,
      "network" => @bitcoin_network,
      "raw_transaction" => Bytes.hex(transaction),
      "transaction_hash" => Bitcoin.display(Bitcoin.txid(transaction)),
      "txoutproof" => Bytes.hex(Bitcoin.merkleblock(block.header, txids, index))
    }

    {regtest, entry}
  end

  # E1's block: the coinbase, a payment, then Truestamp's transaction, which spends the
  # coinbase of block 1 and writes its OP_RETURN first.
  defp first_block(regtest, height, epoch_hash) do
    input = {Regtest.coinbase_txid(regtest, 1), 0}
    change = Regtest.subsidy(1) - @fee

    transaction =
      epoch_transaction(input, [{0, op_return(epoch_hash)}, {change, wallet()}], height)

    {[filler(regtest, 2, height), transaction], 2}
  end

  # E2's block: the coinbase, two payments, Truestamp's transaction, which spends E1's change
  # and writes its OP_RETURN last, then one more payment.
  defp second_block(regtest, height, epoch_hash) do
    [_coinbase, _filler, previous] = Regtest.block(regtest, @first_write).txs
    input = {Bitcoin.txid(previous), 1}
    change = Regtest.subsidy(1) - 2 * @fee

    transaction =
      epoch_transaction(input, [{change, wallet()}, {0, op_return(epoch_hash)}], height)

    fillers = Enum.map(3..5, &filler(regtest, &1, height))
    {List.insert_at(fillers, 2, transaction), 3}
  end

  defp epoch_transaction({txid, vout}, outputs, height) do
    Bitcoin.transaction(%{
      version: 2,
      inputs: [{txid, vout, <<>>, 0xFFFFFFFD}],
      outputs: outputs,
      locktime: height - 1
    })
  end

  defp op_return(epoch_hash), do: <<0x6A, 0x20, epoch_hash::binary-32>>

  defp wallet, do: Regtest.p2wpkh(@wallet)

  # A payment that spends the coinbase of block `source` to a key of its own.
  defp filler(regtest, source, height) do
    Bitcoin.transaction(%{
      version: 2,
      inputs: [{Regtest.coinbase_txid(regtest, source), 0, <<>>, 0xFFFFFFFD}],
      outputs: [{Regtest.subsidy(source) - 1_000, Regtest.p2wpkh("payee #{source}")}],
      locktime: height - 1
    })
  end
end
