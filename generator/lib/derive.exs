# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Generator.Derive do
  @moduledoc """
  DERIVE (SPEC.md 10.2 step 9, and 10.3), recomputed from a proof decoded from its bytes,
  apart from the builder: every row, in DERIVE's order, each with its check, part,
  constructions row, inputs, declared value, recomputed value and status. The rederive check
  runs it over each positive proof: no row may fail, and the trace, the rows whose part is a
  CHECKED value less the link rows SPEC.md 10.6 leaves out, must equal the proof's trace file.

  The status is `pass` or `fail`, except that LINK_KEY_EVENT, when it holds, is `pass` only
  under the attribution `truestamp`, and `info` with the code `not_attributable` under any
  other (SPEC.md 10.3), so the engine takes the run's attribution.

  Rows are sorted by the document order of their parts; rows that share a part keep the order
  of their checks, (a) to (e) and each table's rows, and LINK_INCLUSION's root rows at one
  `merkle_root` follow the document order of their inclusion proofs (SPEC.md 10.2). A row is
  written here as `{check, order, part, construction, inputs}`, where `order` is the section,
  (a) as 1 to (e) as 5, and the row's place in its table.
  """

  import Bitwise

  alias Generator.{BitcoinParse, Bytes, Classes, Keys, Merkle, Pointer, Registry, Spec}

  # Every check, by the name the coverage check uses, in SPEC.md's order.
  @checks ~w(claims_hash item_hash subject_entropy_hash subject_observation_hash
             observation_entropy_hash observation_observation_hash
             block_hash genesis_height genesis_previous_block_hash
             key_public_key key_id key_signing_key_id previous_key_id event_height
             event_previous_block_hash handover_signature prerotation_signing_key_id
             epoch_hash
             raw_transaction_well_formed op_return transaction_hash txoutproof_well_formed
             matched_hash header_hash header_merkle_root header_time
             subject_root subject_tree_size observation_root observation_tree_size
             commitment_root commitment_tree_size key_commitment_root key_commitment_tree_size
             witness_block witness_entropy head key_event_link chain_order_stellar
             chain_order_bitcoin)a

  # The checks whose rows never enter the trace, whatever the class of their part (SPEC.md 10.6).
  @never_traced ~w(head key_event_link chain_order_stellar chain_order_bitcoin)a

  @blocks ~w(/block /witnesses/block /signing_key_event/block)
  @entries ~w(/commitments /signing_key_event/commitments)
  @p Integer.pow(2, 255) - 19
  @l Integer.pow(2, 252) + 27_742_317_777_372_353_535_851_937_790_883_648_493

  @doc "The name of every check DERIVE makes."
  def checks, do: @checks

  @doc """
  A row's position: its part, and for a root row of LINK_INCLUSION also the inclusion proof
  that walks to it, since several walks can share one root (SPEC.md 10.3).
  """
  def position(%{q: ""} = row), do: row.part
  def position(row), do: {row.part, row.q}

  @doc """
  Every DERIVE row of `proof`, whose envelope's K is the 32 octets `k`, in DERIVE's order, in
  a run whose attribution is `attribution` (SPEC.md 10.5).
  """
  def rows(proof, k, attribution) do
    [subjects(proof), blocks(proof), epochs(proof), bitcoin(proof), links(proof, k, attribution)]
    |> List.flatten()
    |> Enum.sort_by(&{doc_key(proof, &1.part), &1.order, doc_key(proof, &1.q)})
  end

  @doc """
  The trace of SPEC.md 10.6: the rows whose part is a CHECKED value, by spec/value-classes.json
  alone, less the rows of LINK_HEAD, LINK_KEY_EVENT and LINK_CHAIN_ORDER.
  """
  def trace(proof, rows) do
    for row <- rows, row.check not in @never_traced, Classes.checked?(proof, row.part) do
      %{
        "construction" => row.construction,
        "declared" => row.declared,
        "inputs" => row.inputs,
        "part" => row.part,
        "recomputed" => row.recomputed,
        "status" => row.status
      }
    end
  end

  defp doc_key(proof, pointer), do: Pointer.order_key(proof, pointer)

  # One row. It passes when the declared value equals the recomputed one, unless `holds` says.
  defp row(proof, {check, order, part, construction, inputs}, recomputed, holds \\ nil) do
    declared = Pointer.get(proof, part)
    holds = if holds == nil, do: declared === recomputed, else: holds

    %{
      check: check,
      order: order,
      part: part,
      q: "",
      construction: construction,
      inputs: Enum.sort_by(inputs, &doc_key(proof, &1)),
      declared: declared,
      recomputed: recomputed,
      status: if(holds, do: "pass", else: "fail"),
      code: nil
    }
  end

  defp get(proof, pointer), do: Pointer.get(proof, pointer)

  defp record_hash(proof, kind, pointer),
    do: Bytes.hex(Registry.record_hash(kind, get(proof, pointer)))

  # (a) Subject hashes: {check, part, the kind and constructions row, the preimage}.

  defp subjects(%{"type" => "item"} = proof) do
    hashes(proof, 1, [
      {:claims_hash, "/subject/record/claims_hash", "claims_hash", "/subject/claims"},
      {:item_hash, "/subject/item_hash", "item_hash", "/subject/record"}
    ])
  end

  defp subjects(%{"type" => "entropy_" <> _source} = proof) do
    hashes(proof, 3, [
      {:subject_entropy_hash, "/subject/record/entropy_hash", "entropy_hash", "/subject/entropy"},
      {:subject_observation_hash, "/subject/observation_hash", "observation_hash",
       "/subject/record"}
    ])
  end

  defp subjects(%{"type" => "beacon", "observations" => observations} = proof) do
    for name <- Map.keys(observations), o = "/observations/" <> name do
      hashes(proof, 5, [
        {:observation_entropy_hash, o <> "/record/entropy_hash", "entropy_hash", o <> "/entropy"},
        {:observation_observation_hash, o <> "/observation_hash", "observation_hash",
         o <> "/record"}
      ])
    end
  end

  defp subjects(_proof), do: []

  defp hashes(proof, first, specs) do
    for {{check, part, kind, input}, n} <- Enum.with_index(specs, first) do
      row(proof, {check, {1, n}, part, kind, [input]}, record_hash(proof, kind, input))
    end
  end

  # (b) Block nodes, and the key event each carries (SPEC.md 10.3).

  defp blocks(proof) do
    for b <- @blocks, get(proof, b) != nil do
      record = b <> "/record"
      [node(proof, b, record), event(proof, record, get(proof, record <> "/metadata/key_event"))]
    end
  end

  defp node(proof, b, record) do
    genesis = record <> "/metadata/genesis"
    hash = record_hash(proof, "block_hash", record)

    block_hash =
      row(proof, {:block_hash, {2, 1}, b <> "/block_hash", "block_hash", [record]}, hash)

    if get(proof, genesis) == nil do
      [block_hash]
    else
      previous = record_hash(proof, "genesis_previous_block_hash", genesis)

      [
        block_hash,
        row(proof, {:genesis_height, {2, 2}, record <> "/height", "genesis", [genesis]}, 0),
        row(
          proof,
          {:genesis_previous_block_hash, {2, 3}, record <> "/previous_block_hash", "genesis",
           [genesis]},
          previous
        )
      ]
    end
  end

  defp event(proof, record, %{"type" => type} = event)
       when type in ~w(genesis rotation emergency_rotation) do
    e = record <> "/metadata/key_event"
    public_key = e <> "/public_key"
    key = decode_key(event["public_key"])
    kid = key && Keys.key_id(key)

    [
      row(
        proof,
        {:key_public_key, {2, 4}, public_key, "key_event", [public_key]},
        nil,
        key?(key)
      ),
      row(proof, {:key_id, {2, 5}, e <> "/key_id", "key_event", [public_key]}, kid),
      row(
        proof,
        {:key_signing_key_id, {2, 6}, record <> "/signing_key_id", "key_event", [public_key]},
        kid
      )
      | handover(proof, record, e, event)
    ]
  end

  defp event(proof, record, %{"type" => "prerotation", "active_key_id" => active}) do
    input = record <> "/metadata/key_event/active_key_id"
    part = record <> "/signing_key_id"
    [row(proof, {:prerotation_signing_key_id, {2, 11}, part, "key_event", [input]}, active)]
  end

  defp event(_proof, _record, _revocation_or_none), do: []

  defp handover(_proof, _record, _e, %{"type" => "genesis"}), do: []

  defp handover(proof, record, e, event) do
    previous_key = e <> "/previous_public_key"
    height = record <> "/height"
    previous_block = record <> "/previous_block_hash"
    previous = decode_key(event["previous_public_key"])

    [
      row(
        proof,
        {:previous_key_id, {2, 7}, e <> "/previous_key_id", "handover", [previous_key]},
        previous && Keys.key_id(previous)
      ),
      row(
        proof,
        {:event_height, {2, 8}, e <> "/height", "handover", [height]},
        get(proof, height)
      ),
      row(
        proof,
        {:event_previous_block_hash, {2, 9}, e <> "/previous_block_hash", "handover",
         [previous_block]},
        get(proof, previous_block)
      )
      | handover_signature(proof, e, event, previous)
    ]
  end

  # Recomputed is the hex of the 32 octets the signature is verified over, and the status is
  # the outcome of Verify (SPEC.md 10.6).
  defp handover_signature(proof, e, %{"handover_signature" => signature} = event, previous) do
    message = Registry.record_hash("handover", Map.delete(event, "handover_signature"))

    spec =
      {:handover_signature, {2, 10}, e <> "/handover_signature", "handover",
       [e, e <> "/previous_public_key"]}

    [row(proof, spec, Bytes.hex(message), verify?(previous, message, signature))]
  end

  defp handover_signature(_proof, _e, _event, _previous), do: []

  # A B64U32 value's 32 octets, or nil.
  defp decode_key(text), do: if(Spec.class?("B64U32", text), do: Bytes.unb64u(text))

  # Steps 2 and 3 of SPEC.md 6.2: y below p, and not one of SMALL_ORDER_KEYS.
  defp key?(nil), do: false

  defp key?(<<head::binary-31, last>> = key) do
    y = :binary.decode_unsigned(<<head::binary, last &&& 0x7F>>, :little)
    small = for %{"hex" => hex} <- Spec.read("small-order-keys.json"), do: hex
    y < @p and Bytes.hex(key) not in small
  end

  # SPEC.md 6.2: the key's bytes, a B64U64 signature whose s is below L, then Ed25519, which
  # makes steps 4 to 7 as written (SPEC.md 6.2, common libraries).
  defp verify?(key, message, text) do
    with true <- key?(key),
         true <- Spec.class?("B64U64", text),
         <<_r::binary-32, s::binary-32>> = signature <- Bytes.unb64u(text),
         true <- :binary.decode_unsigned(s, :little) < @l do
      Keys.verify?(key, message, signature)
    else
      _failure -> false
    end
  end

  # (c) Epochs.

  defp entries(proof) do
    for base <- @entries, chain <- Map.keys(get(proof, base) || %{}), do: base <> "/" <> chain
  end

  defp epochs(proof) do
    for n <- entries(proof) do
      record = n <> "/epoch/record"
      hash = record_hash(proof, "epoch_hash", record)
      row(proof, {:epoch_hash, {3, 1}, n <> "/epoch/epoch_hash", "epoch_hash", [record]}, hash)
    end
  end

  # (d) Bitcoin evidence. A check that reads a value out of raw_transaction or txoutproof is
  # made only when that structure is well formed.

  defp bitcoin(proof) do
    for n <- entries(proof), String.ends_with?(n, "/bitcoin") do
      raw = hexbytes(get(proof, n <> "/raw_transaction"))
      epoch_hash = Registry.record_hash("epoch_hash", get(proof, n <> "/epoch/record"))
      [transaction(proof, n, raw, epoch_hash), txoutproof(proof, n, raw)]
    end
  end

  defp hexbytes(text) do
    case is_binary(text) && Base.decode16(text, case: :lower) do
      {:ok, bytes} -> bytes
      _other -> nil
    end
  end

  defp transaction(proof, n, raw, epoch_hash) do
    part = n <> "/raw_transaction"
    push = if raw, do: BitcoinParse.op_return(raw), else: :error
    txid = raw && BitcoinParse.display(BitcoinParse.sha256d(raw))

    op_return =
      case push do
        {:ok, bytes} ->
          [
            row(
              proof,
              {:op_return, {4, 2}, part, "bitcoin", [part]},
              Bytes.hex(epoch_hash),
              bytes == epoch_hash
            )
          ]

        :error ->
          []
      end

    [
      row(
        proof,
        {:raw_transaction_well_formed, {4, 1}, part, "bitcoin", [part]},
        nil,
        push != :error
      ),
      op_return,
      row(proof, {:transaction_hash, {4, 3}, n <> "/transaction_hash", "bitcoin", [part]}, txid)
    ]
  end

  defp txoutproof(proof, n, raw) do
    part = n <> "/txoutproof"
    parsed = BitcoinParse.merkleblock(hexbytes(get(proof, part)) || <<>>)
    spec = {:txoutproof_well_formed, {4, 4}, part, "bitcoin", [part]}
    well_formed = row(proof, spec, nil, parsed != :error)

    case parsed do
      {:ok, header, hash} -> [well_formed | header_rows(proof, n, header, hash, raw)]
      :error -> [well_formed]
    end
  end

  defp header_rows(proof, n, header, hash, raw) do
    part = n <> "/txoutproof"
    time = header |> BitcoinParse.time() |> DateTime.from_unix!() |> DateTime.to_iso8601()
    root = BitcoinParse.display(BitcoinParse.merkle_root_field(header))
    header_hash = BitcoinParse.display(BitcoinParse.sha256d(header))
    matched = raw != nil and hash == BitcoinParse.sha256d(raw)

    [
      row(
        proof,
        {:matched_hash, {4, 5}, part, "bitcoin", [part, n <> "/raw_transaction"]},
        nil,
        matched
      ),
      row(proof, {:header_hash, {4, 6}, n <> "/header_hash", "bitcoin", [part]}, header_hash),
      row(
        proof,
        {:header_merkle_root, {4, 7}, n <> "/header_merkle_root", "bitcoin", [part]},
        root
      ),
      row(proof, {:header_time, {4, 8}, n <> "/header_time", "bitcoin", [part]}, time)
    ]
  end

  # (e) Links (SPEC.md 10.3).

  defp links(proof, k, attribution) do
    [
      inclusions(proof),
      witnesses(proof),
      head(proof),
      key_event_link(proof, k, attribution),
      chain_order(proof)
    ]
  end

  # LINK_INCLUSION: each inclusion proof Q, the kind and pointer of its leaf's preimage, its
  # record R, and the level that names its two checks.
  defp walks(%{"type" => "item"}),
    do: [{"/subject/inclusion_proof", "item_hash", "/subject/record", "/block/record", :subject}]

  defp walks(%{"type" => "entropy_" <> _source}),
    do: [
      {"/subject/inclusion_proof", "observation_hash", "/subject/record", "/block/record",
       :subject}
    ]

  defp walks(%{"type" => "beacon", "observations" => observations}) do
    for name <- Map.keys(observations) do
      o = "/observations/" <> name
      {o <> "/inclusion_proof", "observation_hash", o <> "/record", "/block/record", :observation}
    end
  end

  defp walks(_proof), do: []

  defp inclusions(proof) do
    commitments =
      for n <- entries(proof) do
        if String.starts_with?(n, "/signing_key_event"),
          do:
            {n <> "/inclusion_proof", "block_hash", "/signing_key_event/block/record",
             n <> "/epoch/record", :key_commitment},
          else:
            {n <> "/inclusion_proof", "block_hash", "/block/record", n <> "/epoch/record",
             :commitment}
      end

    for walk <- walks(proof) ++ commitments, do: inclusion(proof, walk)
  end

  # Two rows: the root, which is null when the walk gives none, and the size (SPEC.md 10.3).
  defp inclusion(proof, {q, kind, leaf, record, level}) do
    root =
      case Merkle.walk(record_hash(proof, kind, leaf), get(proof, q)) do
        {:ok, root} -> root
        :error -> nil
      end

    count = record <> "/leaf_count"
    root_spec = {:"#{level}_root", {5, 1}, record <> "/merkle_root", "inclusion", [q, leaf]}
    size_spec = {:"#{level}_tree_size", {5, 2}, q <> "/tree_size", "inclusion", [count]}
    [%{row(proof, root_spec, root) | q: q}, row(proof, size_spec, get(proof, count))]
  end

  # LINK_WITNESS, in an item.
  defp witnesses(%{"type" => "item"} = proof) do
    for name <- Map.keys(proof["subject"]["record"]["witness_hashes"]) do
      part = "/subject/record/witness_hashes/" <> name

      {check, kind, input} =
        if name == "block",
          do: {:witness_block, "block_hash", "/witnesses/block/record"},
          else: {:witness_entropy, "entropy_hash", "/witnesses/" <> name}

      row(proof, {check, {5, 3}, part, "witnesses", [input]}, record_hash(proof, kind, input))
    end
  end

  defp witnesses(_proof), do: []

  # LINK_HEAD, in an item, on recomputed heights (SPEC.md 10.3 and 10.6 rule 4).
  defp head(%{"type" => "item"} = proof) do
    witness = height(proof, "/witnesses/block/record")
    block = height(proof, "/block/record")
    spec = {:head, {5, 4}, "/witnesses/block/record/height", "height", ["/block/record/height"]}
    [row(proof, spec, block, witness < block)]
  end

  defp head(_proof), do: []

  # A block record's height as a link compares it: 0 when the record carries
  # metadata.genesis, which step 9 (b) recomputes, and otherwise its BLOCK HEIGHT.
  defp height(proof, record) do
    if get(proof, record <> "/metadata/genesis") == nil,
      do: get(proof, record <> "/height"),
      else: 0
  end

  # LINK_KEY_EVENT: the key event at /signing_key_event/block introduces K. It fails when it
  # does not, in every run, and otherwise is a key-history row (SPEC.md 10.3).
  defp key_event_link(%{"signing_key_event" => _event} = proof, k, attribution) do
    part = "/signing_key_event/block/record/metadata/key_event/public_key"
    key = decode_key(get(proof, part))
    spec = {:key_event_link, {5, 5}, part, "key_event", [part]}

    case row(proof, spec, Bytes.b64u(k), key == k) do
      %{status: "pass"} = row when attribution != "truestamp" ->
        [%{row | status: "info", code: "not_attributable"}]

      row ->
        [row]
    end
  end

  defp key_event_link(_proof, _k, _attribution), do: []

  # LINK_CHAIN_ORDER: each Stellar or Bitcoin entropy object against the top-level entry of its
  # chain, on the same network.
  defp chain_order(proof) do
    subject =
      if String.starts_with?(proof["type"], "entropy_"), do: ["/subject/entropy"], else: []

    witnesses =
      for name <- Map.keys(proof["witnesses"] || %{}), name != "block", do: "/witnesses/" <> name

    observations =
      for name <- Map.keys(proof["observations"] || %{}), do: "/observations/#{name}/entropy"

    for e <- subject ++ witnesses ++ observations,
        entropy = get(proof, e),
        entry = get(proof, "/commitments/" <> entropy["source"]),
        entry != nil and entry["network"] == entropy["network"],
        do: chain_row(proof, e, entropy, entry)
  end

  defp chain_row(
         proof,
         e,
         %{"source" => "stellar", "payload" => %{"sequence" => sequence}},
         entry
       ) do
    spec =
      {:chain_order_stellar, {5, 6}, e <> "/payload/sequence", "chain_order",
       ["/commitments/stellar/ledger"]}

    row(proof, spec, entry["ledger"], sequence < entry["ledger"])
  end

  defp chain_row(proof, e, %{"source" => "bitcoin", "payload" => %{"height" => height}}, entry) do
    spec =
      {:chain_order_bitcoin, {5, 6}, e <> "/payload/height", "chain_order",
       ["/commitments/bitcoin/height"]}

    row(proof, spec, entry["height"], height <= entry["height"])
  end
end
