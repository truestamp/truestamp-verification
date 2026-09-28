# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Generator.Proofs do
  @moduledoc """
  The positive proofs of SPEC.md 13.3, cut from Generator.Chain's model, each by its name
  (SPEC.md 13.2): its type, or its type, a hyphen and a variant. Each is marked `test`,
  carries the constructions text in full, and is signed by VECTOR_KEY in the served form of
  SPEC.md 3.1: JCS(envelope), with no final newline.

  | Name | /block | Its subject | /witnesses/block |
  |---|---|---|---|
  | block | h0, genesis | h0 | |
  | beacon | h1 | the observations N0, S0 and B1, the last of the block's three leaves | |
  | entropy_bitcoin | h1 | B1 | |
  | block-emergency-rotation | h2, an emergency rotation with no handover signature | h2 | |
  | beacon-empty | h3, prerotation | no observation | |
  | item | h4 | I | h3, prerotation |
  | entropy_nist | h4 | N1 | |
  | entropy_stellar | h4 | S1, the last of the block's three leaves | |
  | block-rotation | h5, rotation | h5 | |
  | item-rotation-witness | h6 | K, the block's one leaf | h5, rotation |
  | item-genesis-witness | k1 | J, the block's one leaf | k0, genesis |

  Every proof of the first chain carries at `signing_key_event` h5, the rotation that
  introduced VECTOR_KEY, which is the last of the three leaves of its epoch, E2, with the
  entries of both chains. The proof of the second chain carries its genesis block k0 there,
  with Stellar's entry alone, and its own top-level commitments are Stellar's alone too, as
  are those of h6.
  """

  alias Generator.{Bytes, Chain, JCS, Keys, Registry, Seeds, Spec, Trace}

  # Each proof by its name: its type, its chain, the height of its /block, and its subject's
  # name in the chain.
  @proofs %{
    "beacon" => {"beacon", :first, 1, nil},
    "beacon-empty" => {"beacon", :first, 3, nil},
    "block" => {"block", :first, 0, nil},
    "block-emergency-rotation" => {"block", :first, 2, nil},
    "block-rotation" => {"block", :first, 5, nil},
    "entropy_bitcoin" => {"entropy_bitcoin", :first, 1, :b1},
    "entropy_nist" => {"entropy_nist", :first, 4, :n1},
    "entropy_stellar" => {"entropy_stellar", :first, 4, :s1},
    "item" => {"item", :first, 4, :i},
    "item-genesis-witness" => {"item", :second, 1, :j},
    "item-rotation-witness" => {"item", :first, 6, :k}
  }

  @doc "Each positive proof's served bytes and trace rows, by its name, from the model."
  def build(model) do
    constructions = constructions()
    handovers = handovers(model)

    Map.new(@proofs, fn {name, {type, chain, height, subject}} ->
      proof = proof(type, Map.fetch!(model.chains, chain), height, subject, constructions)
      {name, %{document: served(proof), trace: Trace.rows(proof, handovers)}}
    end)
  end

  # The one accepted constructions text, from its file under spec/constructions/.
  defp constructions do
    case Path.wildcard(Path.join(Spec.root(), "spec/constructions/*.json")) do
      [path] -> path |> File.read!() |> Spec.json!(path)
      paths -> raise ArgumentError, "expected one constructions text, found #{length(paths)}"
    end
  end

  # The message each rotation block's handover signed, by the block's hash.
  defp handovers(model) do
    for {_name, chain} <- model.chains,
        b <- chain.blocks,
        Map.has_key?(b, :handover),
        into: %{},
        do: {b.hash, b.handover}
  end

  defp served(proof) do
    seed = Seeds.vector()
    signature = Keys.sign(seed, Registry.record_hash("proof_hash", proof))

    JCS.encode(%{
      "proof" => proof,
      "signature" => %{
        "alg" => "truestamp-ed25519-sha256-jcs",
        "public_key" => Bytes.b64u(Keys.public_key(seed)),
        "value" => Bytes.b64u(signature)
      }
    })
  end

  defp proof(type, chain, height, subject, constructions) do
    block = Enum.at(chain.blocks, height)
    key_event = Enum.at(chain.blocks, chain.key_event)

    Map.merge(members(type, chain, block, subject), %{
      "block" => block.node,
      "commitments" => Chain.commitments(chain, block),
      "constructions" => constructions,
      "environment" => "test",
      "format" => "truestamp-proof",
      "signing_key_event" => %{
        "block" => key_event.node,
        "commitments" => Chain.commitments(chain, key_event)
      },
      "type" => type,
      "version" => 1
    })
  end

  defp members("item", chain, _block, name) do
    item = Map.fetch!(chain.subjects, name)

    witnesses =
      Map.new(item.witnesses, fn {source, observation} ->
        {"entropy_" <> source, observation.entropy}
      end)

    %{
      "subject" => %{
        "claims" => item.claims,
        "inclusion_proof" => Chain.inclusion_proof(chain, item),
        "item_hash" => item.hash,
        "record" => item.record
      },
      "witnesses" => Map.put(witnesses, "block", Enum.at(chain.blocks, item.witness).node)
    }
  end

  defp members("entropy_" <> _source, chain, _block, name),
    do: %{"subject" => subject(chain, Map.fetch!(chain.subjects, name))}

  defp members("block", _chain, _block, nil), do: %{}

  # SPEC.md 3.6: for each source with a leaf in the block, the leaf with the latest source
  # time, ties to the smallest observation_hash.
  defp members("beacon", chain, block, nil) do
    observations =
      block.contents
      |> Enum.filter(&Map.has_key?(&1, :source))
      |> Enum.group_by(& &1.source)
      |> Map.new(fn {source, leaves} ->
        {"entropy_" <> source, subject(chain, Enum.min_by(leaves, &{-&1.source_time, &1.hash}))}
      end)

    %{"observations" => observations}
  end

  # An OBSERVATION_SUBJECT, at /subject or under /observations.
  defp subject(chain, observation) do
    %{
      "entropy" => observation.entropy,
      "inclusion_proof" => Chain.inclusion_proof(chain, observation),
      "observation_hash" => observation.hash,
      "record" => observation.record
    }
  end
end

defmodule Generator.Trace do
  @moduledoc """
  The trace the builder declares for a proof (SPEC.md 10.6, D58 item 7): one row for each
  DERIVE row whose part is a CHECKED value, the genesis height included and the rows of
  LINK_HEAD, LINK_KEY_EVENT and LINK_CHAIN_ORDER left out, each
  `{construction, declared, inputs, part, recomputed, status}`.

  The rows are written out member by member in DERIVE's order, the document order of their
  parts (SPEC.md 10.2), rather than sorted. So the row set, its order, the inputs and the
  construction names are made apart from the rederive check, which derives the trace again
  from the proof's bytes and sorts it by document order. The values are not: but for the
  genesis height, a prerotation's signing key id, a `tree_size` and a handover, a row's
  `recomputed` is the value the builder put in the proof, and every status is `pass`. The
  value check is the rederive check's alone.

  `inputs` are the pointers each check reads to compute `recomputed`, in document order: the
  preimage of a hash, the key a key id is taken from, the record value a key event's height or
  previous_block_hash is compared with, the event and the key a handover is verified with, the
  inclusion proof and the leaf's preimage of a walk, the record's `leaf_count` for a
  `tree_size`, the txoutproof a header value is read from, and `metadata.genesis` for a genesis
  row.
  """

  @doc "The trace rows of `proof`, with `handovers` the message each rotation block signed."
  def rows(proof, handovers) do
    List.flatten([
      node(proof, "/block", walks(proof), handovers),
      commitments(proof, "/commitments", "/block/record"),
      observations(proof),
      node(proof, "/signing_key_event/block", [], handovers),
      commitments(proof, "/signing_key_event/commitments", "/signing_key_event/block/record"),
      subject(proof),
      witnesses(proof, handovers)
    ])
  end

  # The value at a pointer into the proof the builder made.
  defp get(proof, pointer),
    do: pointer |> String.split("/", trim: true) |> Enum.reduce(proof, &Map.get(&2, &1))

  defp row(proof, part, construction, inputs),
    do: row(proof, part, construction, inputs, get(proof, part))

  defp row(proof, part, construction, inputs, recomputed) do
    %{
      "construction" => construction,
      "declared" => get(proof, part),
      "inputs" => inputs,
      "part" => part,
      "recomputed" => recomputed,
      "status" => "pass"
    }
  end

  # A block node: its hash, the genesis height, the roots the subject's walks reach, the key
  # event's members, the genesis previous_block_hash, then the record's signing_key_id.
  defp node(proof, b, roots, handovers) do
    record = b <> "/record"
    genesis = record <> "/metadata/genesis"
    event = get(proof, record <> "/metadata/key_event")
    genesis? = get(proof, genesis) != nil

    [
      row(proof, b <> "/block_hash", "block_hash", [record]),
      if(genesis?, do: row(proof, record <> "/height", "genesis", [genesis], 0), else: []),
      roots,
      event_rows(proof, record, event, Map.get(handovers, get(proof, b <> "/block_hash"))),
      if(genesis?,
        do: row(proof, record <> "/previous_block_hash", "genesis", [genesis]),
        else: []
      ),
      signing_key_id(proof, record, event)
    ]
  end

  defp event_rows(proof, record, %{"type" => "genesis"}, _handover),
    do: [row(proof, record <> "/metadata/key_event/key_id", "key_event", [key(record)])]

  # A rotation, or an emergency rotation, whose handover signature is checked only when it has
  # one (SPEC.md 10.3).
  defp event_rows(proof, record, %{"type" => type} = event, handover)
       when type in ~w(rotation emergency_rotation) do
    e = record <> "/metadata/key_event"

    signature =
      if Map.has_key?(event, "handover_signature"),
        do: [
          row(
            proof,
            e <> "/handover_signature",
            "handover",
            [e, e <> "/previous_public_key"],
            handover
          )
        ],
        else: []

    signature ++
      [
        row(proof, e <> "/height", "handover", [record <> "/height"]),
        row(proof, e <> "/key_id", "key_event", [key(record)]),
        row(proof, e <> "/previous_block_hash", "handover", [record <> "/previous_block_hash"]),
        row(proof, e <> "/previous_key_id", "handover", [e <> "/previous_public_key"])
      ]
  end

  defp event_rows(_proof, _record, _event, _handover), do: []

  defp signing_key_id(proof, record, %{"type" => type})
       when type in ~w(genesis rotation emergency_rotation),
       do: [row(proof, record <> "/signing_key_id", "key_event", [key(record)])]

  defp signing_key_id(proof, record, %{"type" => "prerotation", "active_key_id" => active}) do
    input = record <> "/metadata/key_event/active_key_id"
    [row(proof, record <> "/signing_key_id", "key_event", [input], active)]
  end

  defp signing_key_id(_proof, _record, _event), do: []

  defp key(record), do: record <> "/metadata/key_event/public_key"

  # The walks into /block/record/merkle_root: the subject's, or each observation's.
  defp walks(%{"type" => "block"}), do: []

  defp walks(%{"type" => "beacon"} = proof) do
    for name <- Enum.sort(Map.keys(proof["observations"])) do
      o = "/observations/" <> name
      root(proof, "/block/record", [o <> "/inclusion_proof", o <> "/record"])
    end
  end

  defp walks(proof),
    do: [root(proof, "/block/record", ["/subject/inclusion_proof", "/subject/record"])]

  defp root(proof, record, inputs), do: row(proof, record <> "/merkle_root", "inclusion", inputs)

  defp size(proof, q, record),
    do:
      row(
        proof,
        q <> "/tree_size",
        "inclusion",
        [record <> "/leaf_count"],
        get(proof, record <> "/leaf_count")
      )

  defp commitments(proof, base, leaf) do
    for chain <- Enum.sort(Map.keys(get(proof, base))),
        do: entry(proof, base <> "/" <> chain, leaf)
  end

  defp entry(proof, n, leaf) do
    epoch = [
      row(proof, n <> "/epoch/epoch_hash", "epoch_hash", [n <> "/epoch/record"]),
      root(proof, n <> "/epoch/record", [leaf, n <> "/inclusion_proof"])
    ]

    if String.ends_with?(n, "/bitcoin") do
      epoch ++
        [
          row(proof, n <> "/header_hash", "bitcoin", [n <> "/txoutproof"]),
          row(proof, n <> "/header_merkle_root", "bitcoin", [n <> "/txoutproof"]),
          row(proof, n <> "/header_time", "bitcoin", [n <> "/txoutproof"]),
          size(proof, n <> "/inclusion_proof", n <> "/epoch/record"),
          row(proof, n <> "/transaction_hash", "bitcoin", [n <> "/raw_transaction"])
        ]
    else
      epoch ++ [size(proof, n <> "/inclusion_proof", n <> "/epoch/record")]
    end
  end

  defp observations(%{"observations" => observations} = proof) do
    for name <- Enum.sort(Map.keys(observations)) do
      o = "/observations/" <> name
      observation(proof, o)
    end
  end

  defp observations(_proof), do: []

  defp observation(proof, o) do
    [
      size(proof, o <> "/inclusion_proof", "/block/record"),
      row(proof, o <> "/observation_hash", "observation_hash", [o <> "/record"]),
      row(proof, o <> "/record/entropy_hash", "entropy_hash", [o <> "/entropy"])
    ]
  end

  defp subject(%{"type" => "item"} = proof) do
    names = proof |> get("/subject/record/witness_hashes") |> Map.keys() |> Enum.sort()

    [
      size(proof, "/subject/inclusion_proof", "/block/record"),
      row(proof, "/subject/item_hash", "item_hash", ["/subject/record"]),
      row(proof, "/subject/record/claims_hash", "claims_hash", ["/subject/claims"])
      | for name <- names do
          input = if name == "block", do: "/witnesses/block/record", else: "/witnesses/" <> name
          row(proof, "/subject/record/witness_hashes/" <> name, "witnesses", [input])
        end
    ]
  end

  defp subject(%{"type" => "entropy_" <> _source} = proof), do: observation(proof, "/subject")

  defp subject(_proof), do: []

  defp witnesses(%{"type" => "item"} = proof, handovers),
    do: node(proof, "/witnesses/block", [], handovers)

  defp witnesses(_proof, _handovers), do: []
end
