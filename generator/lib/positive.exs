# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Generator.Positive do
  @moduledoc """
  Check 2 for vectors/positive/. Each proof is decoded from the bytes about to be written and
  checked as a sound proof of its type, from those bytes alone:

  - its name: one of those below, each with its type, and its trace beside it (SPEC.md 13.2);
  - the envelope: its members, `alg`, K is VECTOR_KEY, and V verifies over the `proof_hash`
    computed here; the served form and MAX_DOCUMENT_OCTETS are checked with the file forms;
  - the pinned members: `environment` is `test`, `format`, `version`, the type its name gives,
    and the constructions text in full, whose digest is an accepted one;
  - the checks of SHAPE beyond the schema, with the empty-root rule of SPEC.md 5.4 (the Elixir
    tests hold the proofs to spec/schema.json);
  - POLICY, every `network` against the pins below;
  - DERIVE, recomputed by Generator.Derive in a run whose attribution is that of the keyring
    `test` (SPEC.md 13.2): no row fails, LINK_KEY_EVENT is `info not_attributable` there and
    `pass` under the attribution `truestamp`, every row names the row of the constructions
    text that SPEC.md names for its check, read from SPEC.md (Generator.SpecRows), and a row
    of the text the proof carries, and the trace derived here equals the trace file, row for
    row and member for member.

  Across the proofs: those of one block carry byte-identical `block`, `commitments` and
  `signing_key_event` (SPEC.md 3.6); every check DERIVE makes runs at every position a sound
  proof can hold it, and at no other (coverage/1); the proofs hold every sound shape of
  SPEC.md 13.3 (Generator.Sound); and every check can fail at each of those positions
  (Generator.Mutations).
  """

  import Generator.Check

  alias Generator.{Bytes, Derive, JCS, Keys, Mutations, Pointer, Registry, Sound, Spec, SpecRows}

  # Each positive proof's name, and its type.
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

  # The network pins every positive proof passes POLICY under: the commitment pin of each
  # chain, and the entropy pin of each source, which here are the same.
  @pins %{"bitcoin" => "regtest", "stellar" => "testnet"}

  @empty_root "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

  @doc "The failures of check 2 over the positive proofs and traces among `files`."
  def run(files) do
    attribution = attribution(files["vectors/keyring.test.json"])
    {named, reading} = SpecRows.read(Spec.spec_md())

    proofs =
      for {"vectors/positive/" <> name, bytes} <- files,
          String.ends_with?(name, ".proof.json"),
          into: %{},
          do: {String.replace_suffix(name, ".proof.json", ""), decode(bytes, attribution)}

    traces =
      for {"vectors/positive/" <> name, _bytes} <- files,
          String.ends_with?(name, ".trace.json"),
          do: String.replace_suffix(name, ".trace.json", "")

    List.flatten([
      expect("the positive proofs", Enum.sort(Map.keys(proofs)), Enum.sort(Map.keys(@names))),
      expect("the positive traces", Enum.sort(traces), Enum.sort(Map.keys(@names))),
      reading,
      for({name, decoded} <- proofs, do: proof(name, decoded, files, named)),
      sameness(proofs),
      coverage(proofs),
      Sound.run(proofs),
      Mutations.run(proofs, attribution, positions())
    ])
  end

  # SPEC.md 10.5: the attribution of a run under a supplied keyring, keyring:<d>, with d the
  # SHA-256 of the keyring's bytes.
  defp attribution(bytes), do: "keyring:" <> Bytes.hex(:crypto.hash(:sha256, bytes))

  defp decode(bytes, attribution) do
    envelope = JSON.decode!(bytes)
    proof = envelope["proof"]
    k = decode_key(get_in(envelope, ["signature", "public_key"]))
    rows = Derive.rows(proof, k || <<>>, attribution)
    %{bytes: bytes, envelope: envelope, proof: proof, k: k, rows: rows}
  end

  defp decode_key(text), do: if(Spec.class?("B64U32", text), do: Bytes.unb64u(text))

  defp proof(name, decoded, files, named) do
    %{proof: proof, rows: rows} = decoded
    trace = files |> Map.get("vectors/positive/#{name}.trace.json", "null") |> JSON.decode!()

    [
      envelope(name, decoded),
      pinned(name, proof),
      shape(name, proof),
      policy(name, proof),
      for(row <- rows, row.status == "fail", do: failed(name, row)),
      key_history(name, decoded),
      constructions(name, proof, rows, named),
      expect("#{name}: its trace, derived again", trace, Derive.trace(proof, rows)),
      truth("#{name}: its trace has rows", trace != [])
    ]
  end

  defp failed(name, row),
    do:
      "#{name}: DERIVE's #{row.check} fails at #{row.part}: #{inspect(row.declared)} against #{inspect(row.recomputed)}"

  # SPEC.md 10.3 and 10.6 rule 7: LINK_KEY_EVENT holds, and passes only under the attribution
  # truestamp.
  defp key_history(name, %{proof: proof, k: k, rows: rows}) do
    statuses = fn rows ->
      for %{check: :key_event_link} = row <- rows, do: {row.status, row.code}
    end

    [
      expect("#{name}: LINK_KEY_EVENT under the keyring test", statuses.(rows), [
        {"info", "not_attributable"}
      ]),
      expect(
        "#{name}: LINK_KEY_EVENT under the attribution truestamp",
        statuses.(Derive.rows(proof, k || <<>>, "truestamp")),
        [{"pass", nil}]
      )
    ]
  end

  # Every row names the row SPEC.md names for its check, `named`, read from SPEC.md's tables
  # (Generator.SpecRows), and a row of the constructions text the proof carries, which
  # pinned/2 holds to an accepted text's exact bytes. The trace comparison then holds the
  # builder's names to these.
  defp constructions(name, proof, rows, named) do
    names = Map.keys(proof["constructions"] || %{})

    [
      for row <- rows, row.construction != Map.get(named, row.check) do
        "#{name}: DERIVE's #{row.check} at #{row.part} names #{row.construction}, " <>
          "where SPEC.md names #{inspect(Map.get(named, row.check))}"
      end,
      for row <- rows, row.construction not in names do
        "#{name}: DERIVE's #{row.check} at #{row.part} names #{row.construction}, " <>
          "which is not a row of the constructions text"
      end
    ]
  end

  defp envelope(name, %{envelope: envelope, proof: proof, k: k, bytes: bytes}) do
    signature = envelope["signature"]
    value = signature["value"]
    s = if Spec.class?("B64U64", value), do: Bytes.unb64u(value)
    max = Spec.read("constants.json")["MAX_DOCUMENT_OCTETS"]

    [
      expect("#{name}: the envelope's members", Enum.sort(Map.keys(envelope)), [
        "proof",
        "signature"
      ]),
      expect("#{name}: signature's members", Enum.sort(Map.keys(signature)), [
        "alg",
        "public_key",
        "value"
      ]),
      expect("#{name}: alg", signature["alg"], "truestamp-ed25519-sha256-jcs"),
      expect(
        "#{name}: K is VECTOR_KEY",
        k && Bytes.hex(k),
        Spec.read("constants.json")["VECTOR_KEY"]
      ),
      truth("#{name}: V is a B64U64", s != nil),
      truth(
        "#{name}: V verifies under K over proof_hash",
        s != nil and k != nil and Keys.verify?(k, Registry.record_hash("proof_hash", proof), s)
      ),
      truth("#{name}: at most MAX_DOCUMENT_OCTETS", byte_size(bytes) <= max)
    ]
  end

  defp pinned(name, proof) do
    accepted =
      for path <- Path.wildcard(Path.join(Spec.root(), "spec/constructions/*.json")),
          into: %{},
          do: {Path.basename(path, ".json"), File.read!(path)}

    text = proof["constructions"]
    digest = Bytes.hex(:crypto.hash(:sha256, JCS.encode(text)))
    type = Map.get(@names, name)

    [
      expect("#{name}: type", proof["type"], type),
      truth(
        "#{name}: named by its type, or its type, a hyphen and a variant",
        name == type or String.starts_with?(name, "#{type}-")
      ),
      expect("#{name}: environment", proof["environment"], "test"),
      expect("#{name}: format", proof["format"], "truestamp-proof"),
      expect("#{name}: version", proof["version"], 1),
      truth("#{name}: constructions carries the text in full", is_map(text)),
      expect(
        "#{name}: constructions, an accepted text's exact bytes",
        JCS.encode(text),
        accepted[digest]
      )
    ]
  end

  # SHAPE's checks beyond the schema (SPEC.md 9), and the empty-root rule of SPEC.md 5.4.
  defp shape(name, proof) do
    [
      for b <- ~w(/block /witnesses/block /signing_key_event/block),
          record = Pointer.get(proof, b <> "/record"),
          record != nil do
        truth(
          "#{name}: #{b} has leaf_count 0 exactly under the empty root",
          record["leaf_count"] == 0 == (record["merkle_root"] == @empty_root)
        )
      end,
      if(proof["type"] == "item",
        do:
          expect(
            "#{name}: /witnesses has the names of witness_hashes",
            Enum.sort(Map.keys(proof["witnesses"])),
            Enum.sort(Map.keys(proof["subject"]["record"]["witness_hashes"]))
          ),
        else: []
      ),
      for {pointer, class} <- times(proof, "") do
        truth(
          "#{name}: #{pointer} is a #{class} that reads back as itself",
          time?(class, Pointer.get(proof, pointer))
        )
      end
    ]
  end

  # The TIME and NISTTIME values of a proof, outside the claims.
  defp times(map, pointer) when is_map(map) and pointer != "/subject/claims" do
    Enum.flat_map(map, fn {name, value} ->
      case name do
        name when name in ~w(header_time closed_at) -> [{pointer <> "/" <> name, "TIME"}]
        "timeStamp" -> [{pointer <> "/" <> name, "NISTTIME"}]
        _other -> times(value, pointer <> "/" <> name)
      end
    end)
  end

  defp times(_value, _pointer), do: []

  defp time?(class, text) do
    with true <- Spec.class?(class, text),
         {:ok, time, 0} <- DateTime.from_iso8601(text) do
      DateTime.to_iso8601(time) == text
    else
      _failure -> false
    end
  end

  # POLICY: every network against the pin of its chain or source.
  defp policy(name, proof) do
    networks = networks(proof, "")

    [
      truth("#{name}: carries a network", networks != []),
      for {pointer, chain} <- networks do
        expect("#{name}: #{pointer}", Pointer.get(proof, pointer), Map.get(@pins, chain))
      end
    ]
  end

  # Each network member outside the claims, with its chain: an entropy object's source, the
  # Bitcoin of genesis.bitcoin, or the chain a commitment entry is named by.
  defp networks(map, pointer) when is_map(map) and pointer != "/subject/claims" do
    Enum.flat_map(map, fn
      {"network", _value} -> [{pointer <> "/network", chain(map, pointer)}]
      {name, value} -> networks(value, pointer <> "/" <> name)
    end)
  end

  defp networks(_value, _pointer), do: []

  defp chain(%{"source" => source}, _pointer), do: source
  defp chain(_entry, pointer), do: pointer |> String.split("/") |> List.last()

  # SPEC.md 3.6: for one block, key and mode, block, commitments and signing_key_event are
  # byte-identical across proof types. Every proof shares the key and the mode.
  defp sameness(proofs) do
    groups = Enum.group_by(Map.values(proofs), &Pointer.get(&1.proof, "/block/block_hash"))

    [
      truth(
        "some block has proofs of several types",
        Enum.any?(groups, fn {_hash, g} -> length(Enum.uniq_by(g, & &1.proof["type"])) > 1 end)
      ),
      for {hash, group} <- groups, member <- ~w(block commitments signing_key_event) do
        truth("the proofs of block #{hash} carry one #{member}", one?(group, member))
      end
    ]
  end

  defp one?(group, member),
    do: group |> Enum.map(&JCS.encode(&1.proof[member])) |> Enum.uniq() |> length() == 1

  # Every check DERIVE makes runs at every position a sound proof can hold it, and no row runs
  # at a position the table does not name. A position is the row's part, and for a root row of
  # LINK_INCLUSION also the inclusion proof that walks to it (Generator.Derive.position/1).
  defp coverage(proofs) do
    ran =
      for {_name, %{rows: rows}} <- proofs,
          row <- rows,
          into: MapSet.new(),
          do: {row.check, Derive.position(row)}

    table = MapSet.new(positions())

    [
      expect(
        "the checks of the coverage table",
        positions() |> Enum.map(&elem(&1, 0)) |> Enum.uniq() |> Enum.sort(),
        Enum.sort(Derive.checks())
      ),
      expect(
        "the (check, position) pairs no positive proof runs",
        Enum.sort(MapSet.difference(table, ran)),
        []
      ),
      expect(
        "the (check, position) pairs outside the coverage table",
        Enum.sort(MapSet.difference(ran, table)),
        []
      )
    ]
  end

  # Every (check, position) of SPEC.md 10.2 step 9 and 10.3 that a sound proof can hold.
  defp positions do
    List.flatten([
      subject_positions(),
      Enum.map(~w(/block /witnesses/block /signing_key_event/block), &block_positions/1),
      # A prerotation is never at /signing_key_event/block (SPEC.md 3.3).
      for(
        b <- ~w(/block /witnesses/block),
        do: {:prerotation_signing_key_id, b <> "/record/signing_key_id"}
      ),
      Enum.map(entries(), &entry_positions/1),
      link_positions()
    ])
  end

  defp entries do
    for base <- ~w(/commitments /signing_key_event/commitments),
        chain <- ~w(bitcoin stellar),
        do: base <> "/" <> chain
  end

  defp subject_positions do
    [
      {:claims_hash, "/subject/record/claims_hash"},
      {:item_hash, "/subject/item_hash"},
      {:subject_entropy_hash, "/subject/record/entropy_hash"},
      {:subject_observation_hash, "/subject/observation_hash"},
      {:subject_root, {"/block/record/merkle_root", "/subject/inclusion_proof"}},
      {:subject_tree_size, "/subject/inclusion_proof/tree_size"}
      | for source <- ~w(bitcoin nist stellar), o = "/observations/entropy_" <> source do
          [
            {:observation_entropy_hash, o <> "/record/entropy_hash"},
            {:observation_observation_hash, o <> "/observation_hash"},
            {:observation_root, {"/block/record/merkle_root", o <> "/inclusion_proof"}},
            {:observation_tree_size, o <> "/inclusion_proof/tree_size"}
          ]
        end
    ]
  end

  defp block_positions(b) do
    r = b <> "/record"
    e = r <> "/metadata/key_event"

    [
      {:block_hash, b <> "/block_hash"},
      {:genesis_height, r <> "/height"},
      {:genesis_previous_block_hash, r <> "/previous_block_hash"},
      {:key_public_key, e <> "/public_key"},
      {:key_id, e <> "/key_id"},
      {:key_signing_key_id, r <> "/signing_key_id"},
      {:previous_key_id, e <> "/previous_key_id"},
      {:event_height, e <> "/height"},
      {:event_previous_block_hash, e <> "/previous_block_hash"},
      {:handover_signature, e <> "/handover_signature"}
    ]
  end

  defp entry_positions(n) do
    {root, size} =
      if String.starts_with?(n, "/signing_key_event"),
        do: {:key_commitment_root, :key_commitment_tree_size},
        else: {:commitment_root, :commitment_tree_size}

    [
      {:epoch_hash, n <> "/epoch/epoch_hash"},
      {root, {n <> "/epoch/record/merkle_root", n <> "/inclusion_proof"}},
      {size, n <> "/inclusion_proof/tree_size"}
      | if(String.ends_with?(n, "/bitcoin"), do: bitcoin_positions(n), else: [])
    ]
  end

  defp bitcoin_positions(n) do
    [
      {:raw_transaction_well_formed, n <> "/raw_transaction"},
      {:op_return, n <> "/raw_transaction"},
      {:transaction_hash, n <> "/transaction_hash"},
      {:txoutproof_well_formed, n <> "/txoutproof"},
      {:matched_hash, n <> "/txoutproof"},
      {:header_hash, n <> "/header_hash"},
      {:header_merkle_root, n <> "/header_merkle_root"},
      {:header_time, n <> "/header_time"}
    ]
  end

  defp link_positions do
    [
      {:witness_block, "/subject/record/witness_hashes/block"},
      {:head, "/witnesses/block/record/height"},
      {:key_event_link, "/signing_key_event/block/record/metadata/key_event/public_key"},
      for(
        source <- ~w(bitcoin nist stellar),
        do: {:witness_entropy, "/subject/record/witness_hashes/entropy_" <> source}
      ),
      for(
        e <- ~w(/subject/entropy /witnesses/entropy_stellar /observations/entropy_stellar/entropy),
        do: {:chain_order_stellar, e <> "/payload/sequence"}
      ),
      for(
        e <- ~w(/subject/entropy /witnesses/entropy_bitcoin /observations/entropy_bitcoin/entropy),
        do: {:chain_order_bitcoin, e <> "/payload/height"}
      )
    ]
  end
end
