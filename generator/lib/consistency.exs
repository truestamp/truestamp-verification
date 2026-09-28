# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Generator.Consistency do
  @moduledoc """
  The model's consistency check. The modeled regtest chain (Generator.Regtest) is not valid
  Bitcoin, and the replays of the online cases are drawn from it and from the model's Stellar
  and NIST sources (Generator.Replay.World), so this check holds the model together, reading
  its bytes with the rederive check's parser (Generator.BitcoinParse):

  - Block 0 is regtest's genesis. Each block from 1 to the tip has an 80-octet header whose
    previous-hash field is the hash of the block below it, whose SHA-256d is the block's hash,
    whose Merkle root field is the root of the block's transactions, computed here, whose
    nTime is the block's time, and which meets the target its nBits encodes; and its first
    transaction is a coinbase whose script signature begins with the block's height exactly as
    Bitcoin Core writes it (BIP 34).
  - Each median time past the model serves, for a block read at its height or by its hash, is
    the median of the nTime fields of the headers of that block and the 10 blocks below it, or
    of every block down to block 0 near the start of the chain, as Bitcoin Core takes it: the
    middle one of the sorted times. Block 0's time is that of regtest's genesis header in the
    known answers (Generator.BitcoinAnswers).
  - For each sound proof, every read a verifier makes online under the pins every sound proof
    passes POLICY under (Generator.Replay.reads/2) is found in the model's sources, and each
    answer agrees with the proof as SPEC.md 10.4 compares them: a Stellar transaction that
    succeeded, with a `hash` memo equal to the epoch hash computed from the entry's record, in
    the entry's `ledger`; a Bitcoin tip at least `height` + BITCOIN_FINALITY, and a block at
    `height` whose hash is that of the header in the entry's txoutproof and whose transaction
    count is its `total_txs`; for each `genesis.bitcoin`, a tip as high and a block at its
    `height` whose hash is its `header_hash`; and for each entropy object, a pulse, ledger or
    block whose values are the object's. So the entropy blocks, each `genesis.bitcoin` and
    each commitment `height` are the blocks the model says.
  - For each sound proof, the window those answers give (SPEC.md 11) has a submitted-before
    edge, the earliest candidate of its top-level commitment entries; it is not inverted, so
    its submitted-after edge, the latest candidate of its entropy objects, when it has one, is
    no later; and the time in the subject's id (`subject_id`, SPEC.md 10.5) lies inside it.
    So a sound proof run online with every read found and matching passes WINDOW with no
    `info recorded_time_outside_window` row.
  - The self-test: each of those checks fails on a model, a proof, or an answer served, with
    one defect made in memory.
  """

  import Bitwise
  import Generator.Check

  alias Generator.{BitcoinAnswers, BitcoinParse, Bytes, Case, Chain, Edit, Pointer, Registry}
  alias Generator.{Parse, Regtest, Replay, Spec}
  alias Generator.Replay.World

  @crockford "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

  @doc "The failures of the consistency check over `files`, every file about to be written."
  def run(files) do
    model = Chain.build()
    proofs = proofs(files)
    served = served(model)

    List.flatten([
      chain(model.regtest),
      median_times(model.regtest, served),
      Enum.map(proofs, fn {name, proof} -> proof(name, proof, served) end),
      self_test(model, proofs)
    ])
  end

  # The model's answer to each read, `served.(kind, parameters)`.
  defp served(model) do
    world = World.new(model)
    &World.answer(world, &1, &2)
  end

  # Each sound proof, decoded, by its file's name.
  defp proofs(files) do
    for {"vectors/positive/" <> name, bytes} <- files,
        String.ends_with?(name, ".proof.json"),
        do: {name, Parse.decode!(bytes)["proof"]}
  end

  # The chain.

  defp chain(regtest) do
    genesis =
      for {1, _previous, _root, _time, 0x207FFFFF, _nonce, hash} <-
            BitcoinAnswers.header_fields(),
          do: hash

    [
      expect("regtest block 0", [BitcoinParse.display(Regtest.block(regtest, 0).hash)], genesis),
      for(height <- 1..Regtest.tip(regtest), do: block(regtest, height))
    ]
  end

  defp block(regtest, height) do
    %{header: header, hash: hash, txs: txs, time: time} = Regtest.block(regtest, height)
    label = "regtest block #{height}"

    case header do
      <<_version::binary-4, previous::binary-32, root::binary-32, ntime::little-32,
        _rest::binary-8>> ->
        [
          expect(
            "#{label}: its header's previous hash",
            previous,
            Regtest.block(regtest, height - 1).hash
          ),
          expect("#{label}: its hash", BitcoinParse.sha256d(header), hash),
          expect(
            "#{label}: its header's Merkle root field",
            root,
            merkle_root(Enum.map(txs, &BitcoinParse.sha256d/1))
          ),
          expect("#{label}: its header's time", ntime, time),
          truth("#{label}: its header meets its target", BitcoinParse.meets_target?(header)),
          expect(
            "#{label}: the height its coinbase gives",
            BitcoinParse.coinbase_height(hd(txs)),
            height
          )
        ]

      _other ->
        ["#{label}: its header is not 80 octets"]
    end
  end

  # The median times past.

  defp median_times(regtest, served) do
    network = Case.pins()["commitment"]["bitcoin"]
    span = Spec.read("constants.json")["BITCOIN_MEDIAN_SPAN"]

    for height <- 0..Regtest.tip(regtest) do
      times = for h <- max(0, height - span + 1)..height, do: header_time(regtest, h)
      median = Enum.at(Enum.sort(times), div(length(times), 2))
      hash = BitcoinParse.display(Regtest.block(regtest, height).hash)

      reads = [
        {"bitcoin_block_at_height", %{"height" => height, "network" => network}},
        {"bitcoin_block", %{"hash" => hash, "network" => network}}
      ]

      for {kind, parameters} <- reads do
        expect(
          "regtest block #{height}: the median time past served for a #{kind} read",
          get_in(served.(kind, parameters), ["value", "median_time_past"]),
          median
        )
      end
    end
  end

  # The nTime of the header of block `height`; block 0's from regtest's genesis header in the
  # known answers, whose hash the chain check holds block 0 to.
  defp header_time(regtest, 0) do
    hash = BitcoinParse.display(Regtest.block(regtest, 0).hash)

    [time] =
      for {1, _previous, _root, time, _bits, _nonce, ^hash} <- BitcoinAnswers.header_fields(),
          do: time

    time
  end

  defp header_time(regtest, height), do: BitcoinParse.time(Regtest.block(regtest, height).header)

  # Bitcoin's Merkle root over txids in internal order: an odd level pairs its last hash with
  # itself.
  defp merkle_root([root]), do: root

  defp merkle_root(level) do
    level
    |> Enum.chunk_every(2)
    |> Enum.map(fn
      [left, right] -> BitcoinParse.sha256d(left <> right)
      [last] -> BitcoinParse.sha256d(last <> last)
    end)
    |> merkle_root()
  end

  # The proofs.

  defp proof(name, proof, served) do
    reads = Replay.reads(proof, Case.pins())
    answers = Map.new(reads, fn {kind, p} = read -> {read, served.(kind, p)} end)
    value = fn read -> get_in(answers, [read, "value"]) || %{} end
    label = "positive/#{name}"

    [
      for {read, answer} <- answers, answer["outcome"] != "found" do
        "#{label}: the model does not hold #{inspect(read)}"
      end,
      entries(label, proof, value),
      genesis(label, proof, value),
      entropy(label, proof, value),
      window(label, proof, value)
    ]
  end

  defp entries(label, proof, value) do
    finality = Spec.read("constants.json")["BITCOIN_FINALITY"]
    pins = Case.pins()["commitment"]

    for base <- ~w(/commitments /signing_key_event/commitments),
        {chain, entry} <- Pointer.get(proof, base) || %{} do
      entry(chain, entry, {"#{label}: #{base}/#{chain}", pins[chain], finality}, value)
    end
  end

  # One commitment entry, labelled `at`, whose chain's pin is `network`.
  defp entry("stellar", entry, {at, network, _finality}, value) do
    read = {"stellar_transaction", %{"hash" => entry["transaction_hash"], "network" => network}}
    epoch_hash = Bytes.hex(Registry.record_hash("epoch_hash", entry["epoch"]["record"]))

    expect(
      "#{at}: the transaction read",
      value.(read),
      %{
        "ledger" => entry["ledger"],
        "memo" => epoch_hash,
        "memo_type" => "hash",
        "successful" => true
      }
    )
  end

  defp entry("bitcoin", entry, {at, network, finality}, value) do
    height = entry["height"]
    block = value.({"bitcoin_block_at_height", %{"height" => height, "network" => network}})
    tip = value.({"bitcoin_tip", %{"network" => network}})["height"]

    {header, total} =
      case Bytes.unhex(entry["txoutproof"]) do
        <<header::binary-80, total::little-32, _rest::binary>> -> {header, total}
        _other -> {<<>>, nil}
      end

    [
      truth("#{at}: the tip is at least height + #{finality}", tip >= height + finality),
      expect(
        "#{at}: the hash of the block at height #{height}",
        block["hash"],
        BitcoinParse.display(BitcoinParse.sha256d(header))
      ),
      expect(
        "#{at}: the transaction count of the block at height #{height}",
        block["transaction_count"],
        total
      )
    ]
  end

  defp genesis(label, proof, value) do
    finality = Spec.read("constants.json")["BITCOIN_FINALITY"]
    network = Case.pins()["commitment"]["bitcoin"]

    for block <- ~w(/block /witnesses/block /signing_key_event/block),
        pointer = block <> "/record/metadata/genesis/bitcoin",
        %{"height" => height} = genesis <- [Pointer.get(proof, pointer)] do
      tip = value.({"bitcoin_tip", %{"network" => network}})["height"]
      read = {"bitcoin_block_at_height", %{"height" => height, "network" => network}}

      [
        truth(
          "#{label}: #{pointer}: the tip is at least height + #{finality}",
          tip >= height + finality
        ),
        expect(
          "#{label}: #{pointer}: the hash of the block at height #{height}",
          value.(read)["hash"],
          genesis["header_hash"]
        )
      ]
    end
  end

  defp entropy(label, proof, value) do
    pins = Case.pins()["entropy"]

    for pointer <- Replay.entropy_pointers(proof) do
      %{"source" => source, "payload" => payload} = Pointer.get(proof, pointer)
      at = "#{label}: #{pointer}: the entropy read"

      case source do
        "nist" ->
          %{"chainIndex" => chain, "pulseIndex" => index} = pulse = payload["pulse"]
          read = {"nist_pulse", %{"chainIndex" => chain, "pulseIndex" => index}}
          expect(at, value.(read), Map.take(pulse, ["outputValue", "timeStamp"]))

        "stellar" ->
          read =
            {"stellar_ledger", %{"network" => pins["stellar"], "sequence" => payload["sequence"]}}

          expect(at, value.(read), Map.take(payload, ["closed_at", "hash"]))

        "bitcoin" ->
          read = {"bitcoin_block", %{"hash" => payload["hash"], "network" => pins["bitcoin"]}}

          expect(
            at,
            Map.take(value.(read), ["height", "time"]),
            Map.take(payload, ["height", "time"])
          )
      end
    end
  end

  # The window of SPEC.md 11 the answers give the proof, each candidate in milliseconds since
  # the Unix epoch, and the time in the subject's id against it.
  defp window(label, proof, value) do
    submitted_before =
      proof |> before_candidates(value) |> Enum.reject(&is_nil/1) |> Enum.min(fn -> nil end)

    submitted_after =
      proof |> after_candidates(value) |> Enum.reject(&is_nil/1) |> Enum.max(fn -> nil end)

    id = id_time(subject_id(proof))

    [
      truth("#{label}: the window has a submitted-before edge", submitted_before != nil),
      truth(
        "#{label}: the window is not inverted",
        in_order?([submitted_after, submitted_before])
      ),
      truth(
        "#{label}: the time in the subject's id lies inside the window",
        is_integer(id) and in_order?([submitted_after, id, submitted_before])
      )
    ]
  end

  # Whether the instants, an absent edge left out, are in order.
  defp in_order?(instants) do
    present = Enum.reject(instants, &is_nil/1)
    present == Enum.sort(present)
  end

  # The candidates of the top-level commitment entries (SPEC.md 11.1).
  defp before_candidates(proof, value) do
    finality = Spec.read("constants.json")["BITCOIN_FINALITY"]
    pins = Case.pins()["commitment"]

    for {chain, entry} <- Pointer.get(proof, "/commitments") || %{} do
      case chain do
        "stellar" ->
          read = %{"network" => pins[chain], "sequence" => entry["ledger"]}
          instant(value.({"stellar_ledger", read})["closed_at"])

        "bitcoin" ->
          read = %{"height" => entry["height"] + finality, "network" => pins[chain]}
          seconds(value.({"bitcoin_block_at_height", read})["median_time_past"])
      end
    end
  end

  # The candidates of the entropy objects (SPEC.md 11.2).
  defp after_candidates(proof, value) do
    pins = Case.pins()["entropy"]

    for pointer <- Replay.entropy_pointers(proof) do
      %{"source" => source, "payload" => payload} = Pointer.get(proof, pointer)

      case source do
        "nist" ->
          read = Map.take(payload["pulse"], ["chainIndex", "pulseIndex"])
          instant(value.({"nist_pulse", read})["timeStamp"])

        "stellar" ->
          read = %{"network" => pins[source], "sequence" => payload["sequence"]}
          instant(value.({"stellar_ledger", read})["closed_at"])

        "bitcoin" ->
          read = %{"hash" => payload["hash"], "network" => pins[source]}
          seconds(value.({"bitcoin_block", read})["median_time_past"])
      end
    end
  end

  defp instant(text) when is_binary(text) do
    {:ok, time, 0} = DateTime.from_iso8601(text)
    DateTime.to_unix(time, :millisecond)
  end

  defp instant(_missing), do: nil

  defp seconds(unix) when is_integer(unix), do: unix * 1000
  defp seconds(_missing), do: nil

  # SPEC.md 10.5's `subject_id`: the subject's id, or /block's for a block or a beacon.
  defp subject_id(%{"type" => type} = proof) when type in ~w(block beacon),
    do: Pointer.get(proof, "/block/record/id")

  defp subject_id(proof), do: Pointer.get(proof, "/subject/record/id")

  # The time inside an id, in milliseconds: the first 48 bits of a UUIDv7, or of a ULID.
  defp id_time(<<head::binary-8, "-", middle::binary-4, "-", _rest::binary>>),
    do: String.to_integer(head <> middle, 16)

  defp id_time(<<time::binary-10, _random::binary-16>>) do
    for <<c <- time>>, reduce: 0 do
      acc -> acc * 32 + elem(:binary.match(@crockford, <<c>>), 0)
    end
  end

  defp id_time(_id), do: nil

  # A ULID's first 10 characters for the time `ms`.
  defp ulid_time(ms),
    do: for(i <- 9..0//-1, into: "", do: binary_part(@crockford, ms >>> (5 * i) &&& 31, 1))

  # The self-test.

  defp self_test(model, proofs) do
    proofs = Map.new(proofs)
    item = Map.fetch!(proofs, "item.proof.json")
    block = Map.fetch!(proofs, "block.proof.json")
    served = served(model)

    chain_mutants = [
      {"a header whose previous hash is not the block below", "its header's previous hash",
       update_block(model, 210, fn b -> %{b | header: previous(b.header, <<7::256>>)} end)},
      {"a coinbase that gives another height", "the height its coinbase gives",
       update_block(model, 215, fn b -> %{b | txs: [coinbase_for(model, 216) | tl(b.txs)]} end)},
      {"a header whose time is not the block's", "its header's time",
       update_block(model, 218, fn b -> %{b | time: b.time + 60} end)},
      {"a block missing a transaction", "its header's Merkle root field",
       update_block(model, 218, fn b -> %{b | txs: Enum.drop(b.txs, -1)} end)},
      {"block 233's coinbase with its height pushed as 01 e9, which Bitcoin Core refuses",
       "the height its coinbase gives",
       update_block(model, 233, fn b -> %{b | txs: [respelled(hd(b.txs)) | tl(b.txs)]} end)}
    ]

    median_mutants = [
      {"a median time past served 60 seconds late at height 222", "the median time past served",
       answer_edit(served, "bitcoin_block_at_height", fn answer, parameters ->
         if parameters["height"] == 222,
           do: update_in(answer, ["value", "median_time_past"], &(&1 + 60)),
           else: answer
       end)}
    ]

    served_mutants = [
      {"the Stellar ledger clock 10 minutes early", "the window is not inverted", item,
       answer_edit(served, "stellar_ledger", fn answer, _parameters ->
         update_in(answer, ["value", "closed_at"], &shift(&1, -600))
       end)}
    ]

    proof_mutants = [
      {"a Bitcoin entropy object's time", "/witnesses/entropy_bitcoin: the entropy read", item,
       "/witnesses/entropy_bitcoin/payload/time", &(&1 + 1)},
      {"a NIST entropy object's outputValue", "/witnesses/entropy_nist: the entropy read", item,
       "/witnesses/entropy_nist/payload/pulse/outputValue", &String.replace(&1, "A", "B")},
      {"a Stellar entropy object's closed_at", "/witnesses/entropy_stellar: the entropy read",
       item, "/witnesses/entropy_stellar/payload/closed_at", fn _t -> "2026-09-26T01:48:25Z" end},
      {"a Bitcoin commitment's height", "the hash of the block at height", item,
       "/commitments/bitcoin/height", &(&1 + 1)},
      {"a Stellar commitment's ledger", "/commitments/stellar: the transaction read", item,
       "/commitments/stellar/ledger", &(&1 + 1)},
      {"a Stellar commitment's transaction_hash", "the model does not hold", item,
       "/commitments/stellar/transaction_hash", &String.replace(&1, "a", "b")},
      {"a genesis.bitcoin's header_hash", "genesis/bitcoin: the hash of the block", block,
       "/block/record/metadata/genesis/bitcoin/header_hash", &String.replace(&1, "0", "1")},
      {"the time in the item's id an hour later", "lies inside the window", item,
       "/subject/record/id",
       fn id -> ulid_time(id_time(id) + 3_600_000) <> binary_part(id, 10, 16) end}
    ]

    [
      for {name, fragment, mutant} <- chain_mutants do
        refused(name, fragment, chain(mutant.regtest))
      end,
      for {name, fragment, mutant} <- median_mutants do
        refused(name, fragment, median_times(model.regtest, mutant))
      end,
      for {name, fragment, proof, mutant} <- served_mutants do
        refused(name, fragment, proof("mutant", proof, mutant))
      end,
      for {name, fragment, proof, pointer, change} <- proof_mutants do
        mutant = Edit.put(proof, pointer, change.(Pointer.get(proof, pointer)))
        refused(name, fragment, proof("mutant", mutant, served))
      end
    ]
  end

  # `served` with each found answer to a read of `kind` passed through `edit`.
  defp answer_edit(served, kind, edit) do
    fn
      ^kind, parameters ->
        case served.(kind, parameters) do
          %{"outcome" => "found"} = answer -> edit.(answer, parameters)
          answer -> answer
        end

      other, parameters ->
        served.(other, parameters)
    end
  end

  # A TIME `seconds` later.
  defp shift(text, seconds) do
    {:ok, time, 0} = DateTime.from_iso8601(text)
    time |> DateTime.add(seconds) |> DateTime.to_iso8601()
  end

  defp refused(name, fragment, failures) do
    truth(
      "the consistency check refuses #{name} (a failure naming #{inspect(fragment)})",
      failures |> List.flatten() |> Enum.any?(&String.contains?(&1, fragment))
    )
  end

  defp update_block(model, height, fun),
    do: %{model | regtest: Map.update!(model.regtest, height, fun)}

  defp previous(<<version::binary-4, _previous::binary-32, rest::binary>>, hash),
    do: version <> hash <> rest

  # The coinbase of block `height`, which the self-test puts in another block.
  defp coinbase_for(model, height), do: hd(Regtest.block(model.regtest, height).txs)

  # A coinbase whose script signature begins with a height pushed as 2 octets, the second
  # 0x00, with the height pushed as the first octet alone: for block 233, 01 e9 in place of
  # 02 e9 00, which CScriptNum reads as -105. Any other coinbase is kept as it is.
  defp respelled(coinbase) do
    case coinbase do
      <<head::binary-41, size, 2, low, 0x00, rest::binary>> when size >= 3 ->
        <<head::binary, size - 1, 1, low, rest::binary>>

      _other ->
        coinbase
    end
  end
end
