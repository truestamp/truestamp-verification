# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Generator.Cases.Derive do
  @moduledoc """
  The cases of DERIVE: SPEC.md 13.3's Declared values, Paths, the committed leaf count, the
  graft, Key events, a handover whose position differs, a self-signed key event, Order and
  Bitcoin evidence (its offline cases), with the D58 cases of the tracker's P6.1 entry.

  Each case changes a sound proof, makes the values that depend on the change agree again
  (Generator.Edit), and is signed again by VECTOR_KEY under the keyring `test`, so that one
  DERIVE row fails, at the part SPEC.md 10.2 and 10.3 give its check; the graft, the record
  lies of the committed leaf count, the self-signed key event and the passing Order case say
  what they assert instead. A case that changes a /block record starts, where it can, from a
  proof whose /block has an epoch of its own: item-rotation-witness (h6, alone in E3, which is
  committed to Stellar only) for an item, and block (h0 in E1, beside h5 in E2) for an entry.

  - **Declared values** (`declared-`). Each CHECKED value that no key-event check covers,
    replaced, fails `derivation_mismatch` at its own pointer: the subject's `claims_hash`,
    `item_hash`, `entropy_hash` and `observation_hash`; each beacon observation's
    `entropy_hash` and `observation_hash`, with the block's tree built again from the three
    observations that are its leaves; `block_hash`, the genesis `height` (7, so that at
    /witnesses/block LINK_HEAD, which compares the recomputed 0, passes, D62) and the genesis
    `previous_block_hash` at each block position; `/block/record/merkle_root`; each entry's
    `epoch_hash` and epoch `merkle_root`; each `witness_hashes` entry; and each Bitcoin
    `transaction_hash`, `header_hash`, `header_merkle_root` and `header_time` at both
    positions. So do one character of `claims` changed, at `/subject/record/claims_hash`, and
    a beacon observation that is not a leaf of its block (N1, of h4, in place of N0), at
    `/block/record/merkle_root`. Each `tree_size` is a committed leaf count case.
  - **Paths** (`paths-`). A `path` node changed; a `leaf_index` changed so that the walk takes
    another route to another root; a `leaf_index` equal to `tree_size`; and a `path` one node
    too long and one too short. Each fails `derivation_mismatch` where the walk ends: for the
    subject's walk (item, but entropy_stellar for the changed `leaf_index`, since I is the
    last of h4's three leaves, whose path no other index walks) and an observation's (beacon,
    Stellar's), at `/block/record/merkle_root`; for a top-level entry's (block, Bitcoin's) and a
    signing-key-event entry's (item-genesis-witness, Stellar's, since its leaf k0 has another
    route), at the entry's `epoch/record/merkle_root`.
  - **The committed leaf count** (`leaf_count-`). At the block level for a subject and a
    beacon observation, and at the epoch level for each chain's entry at both positions: a
    `tree_size` other than its record's `leaf_count` whose walk still reaches the root (4, for
    the first or the middle of three leaves; for a subject, S1 of entropy_stellar), and the
    moved leaf index (the last of three leaves presented as `{"leaf_index": 1, "tree_size":
    2}`; for a subject, I of item), each at that `tree_size`, every walk but the moved one's
    keeping its `leaf_index`. A /signing_key_event entry of the sound set walks from h5,
    the last of E2's three leaves, or from k0, the first of F1's two, and neither path fits
    another size, so the `tree_size` lie there starts from block with E2's leaves put in the
    order h5, h3, h4, the root, the epoch hash and the Bitcoin transaction made to agree, and
    h5, now the first of three, walks as index 0 of four. Then the moved index carried into
    its record, whose hash is recomputed: at the block level each epoch walk from the new
    `block_hash` misses its root, two failing rows, and the beacon carries that observation
    alone, since the other two walk only at the true size; at the epoch level a Bitcoin entry
    fails at its `raw_transaction`, whose OP_RETURN still pushes the old `epoch_hash`, and a
    Stellar entry passes offline (its memo read is online, in Generator.Cases.Online).
  - **The graft** (`graft-`). item-rotation-witness with a forged item in place of K in
    /block's record, its genuine `block_hash` and Stellar entry kept, signed by
    Generator.Seeds.other/0 and run keyless, with `signing_key_event` dropped: it fails at
    `/block/block_hash` and where the epoch walk from the forged record's hash misses the root.
    With `block_hash` declared as that hash, it fails only at the epoch walk.
  - **Key events** (`key_events-`), `key_event_mismatch`, at each block position the sound set
    holds the event at. At the rotation h5: its handover signature altered and not signed
    again, and a `previous_public_key` of the identity with the handover (identity, 0), each
    at the event's `handover_signature`; a wrong `key_id` and a wrong `previous_key_id`, the
    handover signed again (at /block, `previous_key_id` on the emergency rotation h2, which has
    no handover); and a record `signing_key_id` that is not the key id of the event's
    `public_key` (packet C3). At a genesis event (h0, k0): a wrong `key_id`; a record
    `signing_key_id` that is not the key id of its `public_key`; and, beyond 13.3's list, at
    /block and /witnesses/block, an event that introduces the identity, at its `public_key` (at
    /signing_key_event that also fails LINK_KEY_EVENT). At the rotation h5 and the emergency
    rotation h2, each at the /block of its block proof: an incoming `public_key` that fails the
    checks of a key's bytes, the identity and a key whose y is not below 2^255 - 19, at that
    `public_key`, with its ids made to agree and h5's handover signed again (D221 item 1). At
    the prerotation h3: an
    `active_key_id` of VECTOR_KEY's id, at the record's `signing_key_id`. And a
    /signing_key_event/block whose genesis event introduces G, not K (LINK_KEY_EVENT), at that
    event's `public_key`.
  - **A handover whose position differs** (`handover_position-`). The rotation h5, its
    handover valid, in a record whose `height` is one more, or whose `previous_block_hash`
    differs, at /signing_key_event/block and at the /block of block-rotation: four cases, at
    the event's `height` or `previous_block_hash`.
  - **A self-signed key event** (`self_signed-`). item-genesis-witness with k0's genesis event
    at /signing_key_event/block introducing the other key, signed by it and run keyless:
    `info not_attributable` at LINK_KEY_EVENT, `skip offline` at KEY_EVENT_COMMITMENT, and the
    label `unattributed`.
  - **Order** (`order-`), `ordering_violation`. /block's height set equal to, and below, the
    witness block's (LINK_HEAD). The top-level Stellar `ledger` set to the entropy `sequence`
    at the subject, a witness and an observation, and one below it at the subject; the
    top-level Bitcoin `height` set one below the entropy `height` at each of the three, which
    fails, and equal to it, which passes (LINK_CHAIN_ORDER). A `ledger` or a commitment
    `height` is a chain pointer that no offline hash covers.
  - **Bitcoin evidence** (`bitcoin-`), offline, in block, each edited transaction put in its
    regtest block built again, so that its `transaction_hash` and the merkleblock agree with
    it. An OP_RETURN that pushes another value, `derivation_mismatch` at `raw_transaction`, at
    /commitments and at /signing_key_event/commitments. Bytes after the transaction and after
    the merkleblock, at both positions, each giving only the rows packet C2 allows. At
    /commitments, `bitcoin_evidence_invalid` at `raw_transaction`: a transaction of exactly
    64 octets (one input, and one output of a 4-octet script that is no OP_RETURN, since no
    64-octet transaction has room for the 34-octet OP_RETURN script), one with no input, one
    with a second OP_RETURN output, one whose OP_RETURN pushes the hash with OP_PUSHDATA1
    (packet C6), one whose 34-octet OP_RETURN script pushes it with 0x1f, the transaction
    serialized with a witness (BIP 144), and one whose 252-octet script signature has its
    compact size in three octets; and at `txoutproof`: the epoch transaction, the last of
    three, repeated as its own right sibling, which keeps the block's root (CVE-2012-2459), an
    unused hash, the last unused flag bit set and the first, a second flag octet of zero, the
    count of hashes in three octets, a merkleblock that matches the second transaction and
    the epoch transaction and one that matches none, `total_txs` of 0 and of
    BITCOIN_MAX_TOTAL_TXS + 1, a header whose hash is above its target, an nBits that
    overflows and one that is negative (Bitcoin Core's 0xff123456 and 0x04923456), and
    regtest's nBits with its sign bit set, 0x20ffffff, under a header whose hash meets the
    target it gives read without its sign, each of the last four with `header_hash` made to
    agree with the edited header (D225 items 7 and 8). The epoch transaction as the last of
    BITCOIN_MAX_TOTAL_TXS in its block, the others standing as hashes, with the block's root,
    its header, `header_hash` and `header_merkle_root` made to agree, passes. Beyond 13.3's
    list, a transaction the merkleblock does not match, with its `transaction_hash`
    recomputed: `derivation_mismatch` at `txoutproof`.

  A case is written here as `{id, the sound proof's name, what it asserts, the edit}`, with the
  case's options after the edit where it has any. What it asserts is `{code, part}`, the one
  failing row, in DERIVE, of a single-defect case; `{:fails, parts}`, exactly these failing
  rows, each `derivation_mismatch` in DERIVE; or `{:passes, rows}`, no failing row, and each
  of `rows` among the rows.
  """

  @behaviour Generator.Cases.Class

  import Generator.Edit

  alias Generator.{Bitcoin, Bytes, Case, Keys, Merkle, Registry, Seeds, Spec}

  @w "/witnesses/block"
  @ske "/signing_key_event/block"
  @root "/block/record/merkle_root"
  @btc "/commitments/bitcoin"
  @dm "derivation_mismatch"
  @kem "key_event_mismatch"
  @ov "ordering_violation"
  @bei "bitcoin_evidence_invalid"
  @sources ~w(bitcoin nist stellar)

  # The public key of 32 bytes 0x01 and 0x00 after it: the identity, a small-order key.
  @identity Bytes.b64u(<<1, 0::248>>)

  # A public key whose y is 2^255 - 19 + 3, not below p: read as y = 3, it is a point on the
  # curve and not of small order, so only the check that y is below p refuses it.
  @y_not_below_p Bytes.b64u(<<Integer.pow(2, 255) - 19 + 3::little-256>>)

  # The sound item whose /block, h6, is alone in its epoch, E3, committed to Stellar only.
  @alone "item-rotation-witness"

  # The entries, each with the words its ids use.
  @entries [
    {"commitments-bitcoin", @btc},
    {"commitments-stellar", "/commitments/stellar"},
    {"signing_key_event-bitcoin", "/signing_key_event/commitments/bitcoin"},
    {"signing_key_event-stellar", "/signing_key_event/commitments/stellar"}
  ]

  # The Bitcoin entries, each with the word its ids use.
  @bitcoin_entries [
    {"commitments", @btc},
    {"signing_key_event", "/signing_key_event/commitments/bitcoin"}
  ]

  # The walks the Paths cases change: {words, proof, inclusion proof, leaf, where it ends}.
  @walks [
    {"subject", "item", "/subject/inclusion_proof", {"item_hash", "/subject/record"}, @root},
    {"observation", "beacon", "/observations/entropy_stellar/inclusion_proof",
     {"observation_hash", "/observations/entropy_stellar/record"}, @root},
    {"commitments-bitcoin", "block", @btc <> "/inclusion_proof", {"block_hash", "/block/record"},
     @btc <> "/epoch/record/merkle_root"},
    {"signing_key_event-stellar", "item-genesis-witness",
     "/signing_key_event/commitments/stellar/inclusion_proof", {"block_hash", @ske <> "/record"},
     "/signing_key_event/commitments/stellar/epoch/record/merkle_root"}
  ]

  # The subject whose leaf_index the Paths cases reroute: the item I is the last of h4's three
  # leaves, whose path no other leaf_index walks, so the reroute takes S1, the middle one.
  @rerouted %{"subject" => {"entropy_stellar", {"observation_hash", "/subject/record"}}}

  # The rotation h5 at each block position.
  @rotations [
    {"block", "/block", "block-rotation"},
    {"witnesses", @w, @alone},
    {"signing_key_event", @ske, "block"}
  ]

  # The genesis blocks: h0 at /block, and k0 at the other two positions.
  @geneses [
    {"block", "/block", "block"},
    {"witnesses", @w, "item-genesis-witness"},
    {"signing_key_event", @ske, "item-genesis-witness"}
  ]

  @impl true
  def codes,
    do: ~w(derivation_mismatch bitcoin_evidence_invalid key_event_mismatch ordering_violation)

  @impl true
  def cases(%{sound: sound}) do
    [
      declared(sound),
      paths(),
      leaf_count(sound),
      graft(),
      key_events(),
      handover_positions(),
      self_signed(),
      order(),
      bitcoin()
    ]
    |> List.flatten()
    |> Enum.map(&build(&1, sound))
  end

  # A case from its row: the sound proof edited, signed with the seed the options give,
  # VECTOR_KEY's unless they give one.
  defp build({id, name, asserts, edit}, sound), do: build({id, name, asserts, edit, []}, sound)

  defp build({id, name, asserts, edit, options}, sound) do
    proof = Map.fetch!(sound, name).proof
    edited = edit.(proof)
    if edited == proof, do: raise(ArgumentError, "case #{id} leaves #{name} as it is")
    {seed, options} = Keyword.pop(options, :seed, Seeds.vector())
    {defect, label} = defect(asserts)
    served = {:served, Case.sign(edited, seed)}
    Case.new(id, Keyword.merge([proof: served, defect: defect, label: label], options))
  end

  defp defect({:fails, parts}),
    do: {{:fails, for(part <- parts, do: {@dm, part, "DERIVE"})}, "failed"}

  defp defect({:passes, rows}), do: {{:passes, rows}, "supplied-keyring"}
  defp defect({code, part}), do: {{:fail, code, part, "DERIVE"}, "failed"}

  # Declared values.

  defp declared(sound) do
    List.flatten([
      subject_values(),
      Enum.map(@sources, &observation_values/1),
      {"declared-observation_not_a_leaf", "beacon", {@dm, @root}, &not_a_leaf(&1, sound)},
      Enum.map(@geneses, &block_values/1),
      {"declared-merkle_root", @alone, {@dm, @root}, &(&1 |> flip(@root) |> recommit("/block"))},
      Enum.map(@entries, &epoch_values/1),
      Enum.map(~w(block entropy_bitcoin entropy_nist entropy_stellar), &witness_value/1),
      bitcoin_values()
    ])
  end

  defp subject_values do
    claims_hash = "/subject/record/claims_hash"
    item_hash = "/subject/item_hash"
    entropy_hash = "/subject/record/entropy_hash"
    observation_hash = "/subject/observation_hash"

    [
      {"declared-claims_hash", @alone, {@dm, claims_hash},
       &(&1 |> flip(claims_hash) |> reitem())},
      {"declared-claims_one_character", "item", {@dm, claims_hash},
       &flip(&1, "/subject/claims/name")},
      {"declared-item_hash", "item", {@dm, item_hash}, &flip(&1, item_hash)},
      {"declared-entropy_hash-subject", "entropy_nist", {@dm, entropy_hash},
       &(&1 |> flip(entropy_hash) |> reobserve())},
      {"declared-observation_hash-subject", "entropy_nist", {@dm, observation_hash},
       &flip(&1, observation_hash)}
    ]
  end

  defp observation_values(source) do
    o = "/observations/entropy_" <> source
    entropy_hash = o <> "/record/entropy_hash"
    observation_hash = o <> "/observation_hash"

    [
      {"declared-entropy_hash-observation-" <> source, "beacon", {@dm, entropy_hash},
       &(&1
         |> flip(entropy_hash)
         |> rehash(observation_hash, "observation_hash", o <> "/record")
         |> retree())},
      {"declared-observation_hash-observation-" <> source, "beacon", {@dm, observation_hash},
       &flip(&1, observation_hash)}
    ]
  end

  # The beacon with N1, an observation that h4 holds, in place of N0, which h1 holds.
  defp not_a_leaf(proof, sound),
    do: put(proof, "/observations/entropy_nist", sound["entropy_nist"].proof["subject"])

  # A block position's hash, in item at /witnesses/block and in block at the others, and its
  # genesis rows, at the genesis blocks.
  defp block_values({words, b, genesis_in}) do
    r = b <> "/record"
    hash_in = if b == @w, do: "item", else: "block"

    # D62: LINK_HEAD compares the genesis witness block's recomputed height, 0, so it passes.
    head =
      if b == @w, do: [present: [{"pass", nil, r <> "/height", "DERIVE"}]], else: []

    [
      {"declared-block_hash-" <> words, hash_in, {@dm, b <> "/block_hash"},
       &flip(&1, b <> "/block_hash")},
      {"declared-genesis_height-" <> words, genesis_in, {@dm, r <> "/height"},
       &(&1 |> put(r <> "/height", 7) |> recommit(b)), head},
      {"declared-genesis_previous_block_hash-" <> words, genesis_in,
       {@dm, r <> "/previous_block_hash"},
       &(&1 |> flip(r <> "/previous_block_hash") |> recommit(b))}
    ]
  end

  defp epoch_values({words, n}) do
    hash = n <> "/epoch/epoch_hash"
    root = n <> "/epoch/record/merkle_root"

    [
      {"declared-epoch_hash-" <> words, "block", {@dm, hash}, &flip(&1, hash)},
      {"declared-epoch_merkle_root-" <> words, "block", {@dm, root},
       &(&1 |> flip(root) |> reepoch(n))}
    ]
  end

  defp witness_value(name) do
    part = "/subject/record/witness_hashes/" <> name
    {"declared-witness_hashes-" <> name, @alone, {@dm, part}, &(&1 |> flip(part) |> reitem())}
  end

  defp bitcoin_values do
    for {position, n} <- @bitcoin_entries,
        member <- ~w(transaction_hash header_hash header_merkle_root header_time) do
      part = n <> "/" <> member
      {"declared-#{member}-#{position}", "block", {@dm, part}, &replace(&1, part)}
    end
  end

  # A declared value replaced: hex with its first character changed, a time with another time.
  defp replace(proof, part) do
    if String.ends_with?(part, "/header_time"),
      do: put(proof, part, "2026-09-26T00:00:00Z"),
      else: flip(proof, part)
  end

  # Paths.

  defp paths do
    for {words, name, q, leaf, part} <- @walks,
        path = q <> "/path",
        {rerouted, rerouted_leaf} = Map.get(@rerouted, words, {name, leaf}),
        {defect, on, edit} <- [
          {"node", name, &flip(&1, path <> "/0")},
          {"leaf_index", rerouted, &reroute(&1, q, rerouted_leaf)},
          {"leaf_index_at_tree_size", name,
           &put(&1, q <> "/leaf_index", get(&1, q <> "/tree_size"))},
          {"path_too_long", name, &put(&1, path, get(&1, path) ++ [get(&1, path <> "/0")])},
          {"path_too_short", name, &put(&1, path, Enum.drop(get(&1, path), -1))}
        ],
        do: {"paths-#{defect}-#{words}", on, {@dm, part}, edit}
  end

  # The inclusion proof at `q` given another leaf_index below its tree_size, whose walk from
  # the leaf recomputed from `{kind, preimage}` takes another route to another root.
  defp reroute(proof, q, {kind, preimage}) do
    leaf = Bytes.hex(Registry.record_hash(kind, get(proof, preimage)))
    %{"leaf_index" => index, "tree_size" => size} = inclusion = get(proof, q)
    {:ok, root} = Merkle.walk(leaf, inclusion)
    others = for i <- 0..(size - 1), i != index, do: %{inclusion | "leaf_index" => i}

    case Enum.find(others, &match?({:ok, other} when other != root, Merkle.walk(leaf, &1))) do
      nil -> raise ArgumentError, "no other leaf_index of #{q} walks to another root"
      rerouted -> put(proof, q, rerouted)
    end
  end

  # The committed leaf count (SPEC.md 5.4).

  defp leaf_count(sound) do
    subject = "/subject/inclusion_proof"
    nist = "/observations/entropy_nist"
    bitcoin = "/observations/entropy_bitcoin/inclusion_proof"
    roots = for c <- ~w(bitcoin stellar), do: "/commitments/#{c}/epoch/record/merkle_root"

    [
      {"leaf_count-tree_size-subject", "entropy_stellar", {@dm, subject <> "/tree_size"},
       &resize(&1, subject, {"observation_hash", "/subject/record"}, move: false)},
      {"leaf_count-moved_index-subject", "item", {@dm, subject <> "/tree_size"},
       &moved(&1, subject)},
      {"leaf_count-record-subject", "item", {:fails, roots},
       &(&1 |> moved(subject) |> recount())},
      {"leaf_count-tree_size-observation", "beacon", {@dm, nist <> "/inclusion_proof/tree_size"},
       &resize(&1, nist <> "/inclusion_proof", {"observation_hash", nist <> "/record"},
         move: false
       )},
      {"leaf_count-moved_index-observation", "beacon", {@dm, bitcoin <> "/tree_size"},
       &moved(&1, bitcoin)},
      {"leaf_count-record-observation", "beacon", {:fails, roots},
       &(&1 |> alone("entropy_bitcoin") |> moved(bitcoin) |> recount())}
      | Enum.flat_map(@entries, &entry_count(&1, sound))
    ]
  end

  # An entry's cases: the tree_size lie, at /commitments from block, whose h0 is the first of
  # E1's three leaves, and at /signing_key_event from block with E2 made to hold its h5 first
  # (first_of_three/2); the moved index, at /commitments from block-rotation, whose h5 is the
  # last of E2's, and at /signing_key_event from block. Then that index carried into the epoch
  # record (Generator.Edit.moved_index/2), which fails a Bitcoin entry at its OP_RETURN and
  # passes a Stellar entry offline.
  defp entry_count({words, n}, sound) do
    q = n <> "/inclusion_proof"
    size = {@dm, q <> "/tree_size"}
    top? = String.starts_with?(n, "/commitments")
    moved_in = if top?, do: "block-rotation", else: "block"
    leaf = if top?, do: "/block/record", else: @ske <> "/record"
    start = if top?, do: & &1, else: &first_of_three(&1, sound)

    record =
      if String.ends_with?(n, "/bitcoin"),
        do: {@dm, n <> "/raw_transaction"},
        else:
          {:passes,
           [
             {"pass", nil, n <> "/epoch/epoch_hash", "DERIVE"},
             {"pass", nil, q <> "/tree_size", "DERIVE"},
             {"skip", "offline", n, "CHAIN"}
           ]}

    [
      {"leaf_count-tree_size-" <> words, "block", size,
       &(&1 |> start.() |> resize(q, {"block_hash", leaf}, move: false))},
      {"leaf_count-moved_index-" <> words, moved_in, size, &moved(&1, q)},
      {"leaf_count-record-" <> words, moved_in, record, &moved_index(&1, n)}
    ]
  end

  # block with E2, which /signing_key_event's entries hold, made to hold its leaves in the
  # order h5, h3, h4: h5, the last of three, fits no other size, and as the first of three its
  # path also walks as index 0 of four. Each entry's inclusion proof, the epoch's root and hash,
  # and the Bitcoin transaction that carries that hash are made to agree. h3 and h4 are the
  # /block of beacon-empty and of item, and the three in their order give the root E2 has.
  defp first_of_three(proof, sound) do
    [h3, h4] = for name <- ~w(beacon-empty item), do: sound[name].proof["block"]["block_hash"]
    h5 = get(proof, @ske <> "/block_hash")
    [held, first] = for order <- [[h3, h4, h5], [h5, h3, h4]], do: Enum.map(order, &Bytes.unhex/1)

    for {_words, n} <- @entries, String.starts_with?(n, "/signing_key_event"), reduce: proof do
      acc ->
        if get(acc, n <> "/epoch/record/merkle_root") != Bytes.hex(Merkle.root(held)),
          do: raise(ArgumentError, "#{n} does not hold E2 as h3, h4, h5")

        acc
        |> put(n <> "/inclusion_proof", Merkle.proof(0, first))
        |> put(n <> "/epoch/record/merkle_root", Bytes.hex(Merkle.root(first)))
        |> reepoch(n)
    end
  end

  # SPEC.md 13.3's moved leaf index: the last of three leaves presented as index 1 of two, with
  # the same path.
  defp moved(proof, q) do
    %{"leaf_index" => 2, "tree_size" => 3} = get(proof, q)
    proof |> put(q <> "/leaf_index", 1) |> put(q <> "/tree_size", 2)
  end

  # /block's record made to carry the moved index's count, with its hash recomputed and the
  # entries that walk from that hash left as they are.
  defp recount(proof),
    do:
      proof
      |> put("/block/record/leaf_count", 2)
      |> rehash("/block/block_hash", "block_hash", "/block/record")

  # A beacon that carries only its observation `name`.
  defp alone(proof, name),
    do: put(proof, "/observations", Map.take(get(proof, "/observations"), [name]))

  # The graft (SPEC.md 10.3).

  defp graft do
    options = [keyring: "none", seed: Seeds.other()]
    root = "/commitments/stellar/epoch/record/merkle_root"

    [
      {"graft-genuine_block_hash", @alone, {:fails, ["/block/block_hash", root]}, &forge/1,
       options},
      {"graft-forged_block_hash", @alone, {@dm, root},
       &(&1 |> forge() |> rehash("/block/block_hash", "block_hash", "/block/record")), options}
    ]
  end

  # A forged item in place of K, with its hashes and the root in /block's record made to agree,
  # and /block's hash and entry kept. signing_key_event goes, since its event introduces
  # VECTOR_KEY and not the forger's key.
  defp forge(proof) do
    proof
    |> put("/subject/claims/hash", Bytes.hex(:crypto.hash(:sha256, "a forged document")))
    |> put("/subject/claims/name", "a forged item")
    |> rehash("/subject/record/claims_hash", "claims_hash", "/subject/claims")
    |> rehash("/subject/item_hash", "item_hash", "/subject/record")
    |> walk_up(get(proof, "/subject/inclusion_proof"), "/subject/item_hash", "/block/record")
    |> delete("/signing_key_event")
  end

  # Key events (SPEC.md 10.3).

  defp key_events do
    List.flatten([
      Enum.map(@rotations, &rotation_events/1),
      Enum.map(@geneses, &genesis_events/1),
      incoming_keys(),
      prerotations(),
      link_key_event()
    ])
  end

  # The checks of the rotation h5 at block position `b`. Each wrong id is written with the
  # handover signed again by the outgoing key, which covers the event's ids and not the
  # record's; at /block, previous_key_id is changed on the emergency rotation h2, which has no
  # handover.
  defp rotation_events({words, b, name}) do
    r = b <> "/record"
    e = r <> "/metadata/key_event"
    signature = e <> "/handover_signature"
    previous_in = if b == "/block", do: "block-emergency-rotation", else: name
    wrong = fn member -> &(&1 |> put(member, "00000000") |> resign(e) |> recommit(b)) end

    [
      {"key_events-handover_signature-" <> words, name, {@kem, signature},
       &(&1 |> flip(signature) |> recommit(b))},
      {"key_events-identity_previous_public_key-" <> words, name, {@kem, signature},
       &(&1 |> identity_handover(e) |> recommit(b))},
      {"key_events-key_id-rotation-" <> words, name, {@kem, e <> "/key_id"},
       wrong.(e <> "/key_id")},
      {"key_events-previous_key_id-" <> words, previous_in, {@kem, e <> "/previous_key_id"},
       wrong.(e <> "/previous_key_id")},
      {"key_events-signing_key_id-rotation-" <> words, name, {@kem, r <> "/signing_key_id"},
       wrong.(r <> "/signing_key_id")}
    ]
  end

  # A rotation whose previous_public_key is the identity, with its previous_key_id made to
  # agree, and the handover signature (identity, 0): R the identity's encoding and s zero.
  defp identity_handover(proof, e) do
    identity = Bytes.unb64u(@identity)

    proof
    |> put(e <> "/previous_public_key", @identity)
    |> put(e <> "/previous_key_id", Keys.key_id(identity))
    |> put(e <> "/handover_signature", Bytes.b64u(identity <> <<0::256>>))
  end

  # The checks of a genesis event at block position `b`. An event that introduces the identity
  # at /signing_key_event also fails LINK_KEY_EVENT, so that case is made at the other two.
  defp genesis_events({words, b, name}) do
    r = b <> "/record"
    e = r <> "/metadata/key_event"
    wrong = fn member -> &(&1 |> put(member, "00000000") |> recommit(b)) end

    small_order =
      if b == @ske,
        do: [],
        else: [
          {"key_events-public_key_small_order-" <> words, name, {@kem, e <> "/public_key"},
           &(&1 |> introduce(b, @identity) |> recommit(b))}
        ]

    [
      {"key_events-key_id-genesis-" <> words, name, {@kem, e <> "/key_id"},
       wrong.(e <> "/key_id")},
      {"key_events-signing_key_id-genesis-" <> words, name, {@kem, r <> "/signing_key_id"},
       wrong.(r <> "/signing_key_id")}
      | small_order
    ]
  end

  # The rotation h5 and the emergency rotation h2, each at /block of its block proof, made to
  # bring in a key that fails the checks of a key's bytes (SPEC.md 6.2), in two forms for each
  # event: the identity, which is one of SMALL_ORDER_KEYS, and a key whose y is not below p.
  # The event's `key_id` and the record's `signing_key_id` are made to agree with that key, and
  # the rotation's handover is signed again by its outgoing key, so only the check of the
  # incoming key's bytes fails.
  defp incoming_keys do
    for {kind, name} <- [
          {"rotation", "block-rotation"},
          {"emergency_rotation", "block-emergency-rotation"}
        ],
        {words, key} <- [{"small_order", @identity}, {"y_not_below_p", @y_not_below_p}] do
      e = "/block/record/metadata/key_event"

      {"key_events-public_key_#{words}-#{kind}-block", name, {@kem, e <> "/public_key"},
       &(&1 |> introduce("/block", key) |> resign(e) |> recommit("/block"))}
    end
  end

  # The prerotation h3, at /block of the empty beacon and as the item's witness block, naming
  # VECTOR_KEY's id as the active key while H's id signs the record.
  defp prerotations do
    active = Keys.key_id(Keys.public_key(Seeds.vector()))

    for {words, b, name} <- [{"block", "/block", "beacon-empty"}, {"witnesses", @w, "item"}] do
      {"key_events-prerotation_active_key_id-" <> words, name,
       {@kem, b <> "/record/signing_key_id"},
       &(&1 |> put(b <> "/record/metadata/key_event/active_key_id", active) |> recommit(b))}
    end
  end

  # k0 at /signing_key_event/block made to introduce G, with its ids made to agree.
  defp link_key_event do
    g = Bytes.b64u(Keys.public_key(Seeds.genesis()))

    {"key_events-link_key_event", "item-genesis-witness",
     {@kem, @ske <> "/record/metadata/key_event/public_key"},
     &(&1 |> introduce(@ske, g) |> recommit(@ske))}
  end

  # A handover whose position differs (SPEC.md 3.3): h5's record moved one height up, or given
  # another previous_block_hash, with its event and handover left as they are.
  defp handover_positions do
    for {words, b, name} <- [
          {"block", "/block", "block-rotation"},
          {"signing_key_event", @ske, "block"}
        ],
        r = b <> "/record",
        {member, edit} <- [
          {"height", &put(&1, r <> "/height", get(&1, r <> "/height") + 1)},
          {"previous_block_hash", &flip(&1, r <> "/previous_block_hash")}
        ] do
      {"handover_position-#{member}-#{words}", name, {@kem, "#{r}/metadata/key_event/#{member}"},
       &(&1 |> edit.() |> recommit(b))}
    end
  end

  # A self-signed key event: k0's genesis event at /signing_key_event/block made to introduce
  # the other key, which signs the proof, in a keyless run.
  defp self_signed do
    other = Bytes.b64u(Keys.public_key(Seeds.other()))

    rows = [
      {"skip", "key_binding_not_performed", nil, "KEY_BINDING"},
      {"info", "not_attributable", @ske <> "/record/metadata/key_event/public_key", "DERIVE"},
      {"skip", "offline", "/signing_key_event", "CHAIN"}
    ]

    {"self_signed-genesis", "item-genesis-witness", {:passes, rows},
     &(&1 |> introduce(@ske, other) |> recommit(@ske)),
     [keyring: "none", seed: Seeds.other(), label: "unattributed"]}
  end

  # Order (SPEC.md 10.3).

  defp order do
    height = @w <> "/record/height"

    List.flatten([
      {"order-head-equal", @alone, {@ov, height}, &head(&1, 0)},
      {"order-head-above", @alone, {@ov, height}, &head(&1, -1)},
      Enum.map(objects("stellar"), &stellar_order(&1, 0)),
      stellar_order(hd(objects("stellar")), -1),
      Enum.map(objects("bitcoin"), &bitcoin_order/1)
    ])
  end

  # The entropy objects of a source, at the subject, a witness and an observation.
  defp objects(source) do
    [
      {"subject", "entropy_" <> source, "/subject/entropy"},
      {"witness", "item", "/witnesses/entropy_" <> source},
      {"observation", "beacon", "/observations/entropy_#{source}/entropy"}
    ]
  end

  # /block's height set to the witness block's, plus `offset`, with /block's hash and entry made
  # to agree.
  defp head(proof, offset) do
    witness = get(proof, @w <> "/record/height")
    proof |> put("/block/record/height", witness + offset) |> recommit("/block")
  end

  # The top-level Stellar ledger set to the entropy sequence, plus `offset`.
  defp stellar_order({words, name, e}, offset) do
    sequence = e <> "/payload/sequence"
    at = if offset == 0, do: "equal", else: "above"

    {"order-stellar_sequence_#{at}-#{words}", name, {@ov, sequence},
     &put(&1, "/commitments/stellar/ledger", get(&1, sequence) + offset)}
  end

  # The top-level Bitcoin height set one below the entropy height, which fails, and equal to
  # it, which passes.
  defp bitcoin_order({words, name, e}) do
    height = e <> "/payload/height"
    set = fn offset -> &put(&1, @btc <> "/height", get(&1, height) + offset) end

    [
      {"order-bitcoin_height_above-" <> words, name, {@ov, height}, set.(-1)},
      {"order-bitcoin_height_equal-" <> words, name, {:passes, [{"pass", nil, height, "DERIVE"}]},
       set.(0)}
    ]
  end

  # Bitcoin evidence (SPEC.md 10.2 step 9 (d)).

  defp bitcoin do
    raw = @btc <> "/raw_transaction"
    txoutproof = @btc <> "/txoutproof"

    List.flatten([
      Enum.map(@bitcoin_entries, &evidence/1),
      for {words, malform} <- transactions() do
        {"bitcoin-raw_transaction_" <> words, "block", {@bei, raw}, &retransact(&1, malform)}
      end,
      for {words, malform} <- transaction_bytes() do
        {"bitcoin-raw_transaction_" <> words, "block", {@bei, raw},
         &reblock(&1, @btc, malform.(raw(&1, @btc)))}
      end,
      for {words, malform} <- merkleblocks() do
        {"bitcoin-txoutproof_" <> words, "block", {@bei, txoutproof}, &remerkle(&1, malform)}
      end,
      {"bitcoin-txoutproof_total_txs_max", "block",
       {:passes, [{"pass", nil, txoutproof, "DERIVE"}]}, &largest_block/1},
      {"bitcoin-unmatched_transaction", "block", {@dm, txoutproof},
       &(&1 |> relock(raw) |> retxid(@btc))}
    ])
  end

  # At each position: an OP_RETURN that pushes another value, and bytes after the transaction
  # and after the merkleblock.
  defp evidence({position, n}) do
    raw = n <> "/raw_transaction"
    other = :crypto.hash(:sha256, "truestamp vectors another OP_RETURN value")

    [
      {"bitcoin-op_return_other_value-" <> position, "block", {@dm, raw},
       &repush(&1, n, Bytes.unhex(get(&1, n <> "/epoch/epoch_hash")), other)},
      {"bitcoin-raw_transaction_trailing_bytes-" <> position, "block", {@bei, raw},
       &reblock(&1, n, raw(&1, n) <> <<0>>)},
      {"bitcoin-txoutproof_trailing_bytes-" <> position, "block", {@bei, n <> "/txoutproof"},
       &append(&1, n <> "/txoutproof")}
    ]
  end

  # E1's transaction at /commitments made malformed by `malform`, over its parse (parse/1), and
  # put in its block built again.
  defp retransact(proof, malform) do
    raw = proof |> raw(@btc) |> parse() |> malform.() |> Bitcoin.transaction()
    reblock(proof, @btc, raw)
  end

  defp transactions do
    [
      {"64_octets", &sixty_four/1},
      {"no_input", &%{&1 | inputs: []}},
      {"two_op_returns", &second_op_return/1},
      {"op_return_pushdata", &pushdata/1},
      {"op_return_other_push", &other_push/1}
    ]
  end

  # Transactions made malformed over their bytes, where the builder writes only the
  # serialization SPEC.md 10.2 step 9 (d) allows: the transaction serialized with a witness
  # (BIP 144), and one whose compact size is not in its shortest form.
  defp transaction_bytes do
    [
      {"witness", &witness/1},
      {"compact_size_not_shortest", &longer_compact_size/1}
    ]
  end

  # The transaction with one output, of a 4-octet script that is no OP_RETURN: 64 octets.
  defp sixty_four(transaction) do
    short = %{transaction | outputs: [{0, <<0x51, 0x51, 0x51, 0x51>>}]}
    64 = byte_size(Bitcoin.transaction(short))
    short
  end

  # The transaction with its OP_RETURN output written twice.
  defp second_op_return(%{outputs: outputs} = transaction) do
    [op_return] = Enum.filter(outputs, &match?({_value, <<0x6A, _::binary>>}, &1))
    %{transaction | outputs: outputs ++ [op_return]}
  end

  # The transaction whose OP_RETURN script pushes its 32 bytes with OP_PUSHDATA1.
  defp pushdata(transaction) do
    outputs =
      Enum.map(transaction.outputs, fn
        {value, <<0x6A, 0x20, hash::binary-32>>} -> {value, <<0x6A, 0x4C, 0x20, hash::binary>>}
        output -> output
      end)

    %{transaction | outputs: outputs}
  end

  # The transaction whose OP_RETURN script is 34 octets, 0x6a and the 32 bytes, as it should be,
  # but pushes them with another opcode, 0x1f, which pushes 31.
  defp other_push(transaction) do
    outputs =
      Enum.map(transaction.outputs, fn
        {value, <<0x6A, 0x20, hash::binary-32>>} -> {value, <<0x6A, 0x1F, hash::binary>>}
        output -> output
      end)

    %{transaction | outputs: outputs}
  end

  # The transaction serialized with its witness (BIP 144): the marker 0x00 and the flag 0x01
  # after the version, and before the lock time a witness for its one input, of one item of 32
  # octets.
  defp witness(<<version::binary-4, rest::binary>>) do
    size = byte_size(rest) - 4
    <<body::binary-size(^size), locktime::binary-4>> = rest
    item = :crypto.hash(:sha256, "truestamp vectors a witness item")
    version <> <<0x00, 0x01>> <> body <> <<1, 32>> <> item <> locktime
  end

  # The transaction with a script signature of 252 octets, whose compact size, 0xfc, is
  # written in three octets, 0xfd 0xfc 0x00: the shortest form of 252 is one octet.
  defp longer_compact_size(raw) do
    %{inputs: [{txid, vout, <<>>, sequence}]} = transaction = parse(raw)
    script = :binary.copy(<<0x51>>, 252)
    bytes = Bitcoin.transaction(%{transaction | inputs: [{txid, vout, script, sequence}]})
    <<head::binary-41, 0xFC, tail::binary>> = bytes
    head <> <<0xFD, 0xFC, 0x00>> <> tail
  end

  # E1's merkleblock at /commitments made malformed by `malform`, over its bytes, with
  # `header_hash` made to agree with the header it then carries, which only the header cases
  # change.
  defp remerkle(proof, malform) do
    txoutproof = @btc <> "/txoutproof"
    bytes = proof |> get(txoutproof) |> Bytes.unhex() |> malform.()
    header_hash = Bitcoin.display(Bitcoin.sha256d(binary_part(bytes, 0, 80)))

    proof
    |> put(txoutproof, Bytes.hex(bytes))
    |> put(@btc <> "/header_hash", header_hash)
  end

  defp merkleblocks do
    max = Spec.read("constants.json")["BITCOIN_MAX_TOTAL_TXS"]

    [
      {"duplicate_pair", &duplicate_pair/1},
      {"unused_hash", &unused_hash/1},
      {"unused_flag_bit", &unused_flag_bit/1},
      {"first_unused_flag_bit", &first_unused_flag_bit/1},
      {"extra_flag_octet", &extra_flag_octet/1},
      {"compact_size_not_shortest", &longer_hash_count/1},
      {"two_matches", &matching(&1, [1, 2])},
      {"no_match", &matching(&1, [])},
      {"total_txs_0", &total_txs(&1, 0)},
      {"total_txs_above_max", &total_txs(&1, max + 1)},
      {"header_above_target", &header_above_target/1},
      {"nbits_overflow", &nbits(&1, 0xFF123456)},
      {"nbits_negative", &nbits(&1, 0x04923456)},
      {"nbits_negative_unsigned_target_met", &negative_met/1}
    ]
  end

  # The merkleblock of E1's block, whose three transactions end with Truestamp's, built over four
  # with the last repeated, which keeps the block's Merkle root, and matching the third: its
  # walk meets a right child equal to its left (CVE-2012-2459).
  defp duplicate_pair(<<header::binary-80, _rest::binary>>) do
    txids = txids(header)
    3 = length(txids)
    Bitcoin.merkleblock(header, txids ++ [List.last(txids)], 2)
  end

  # The txids of the regtest block whose header is `header`.
  defp txids(header) do
    block = regtest() |> Map.values() |> Enum.find(&(&1[:header] == header))
    Enum.map(block.txs, &Bitcoin.txid/1)
  end

  # The merkleblock of E1's block, whose three transactions end with Truestamp's, matching the
  # transactions at `indexes`: the second and Truestamp's, or none, whose walk takes the root
  # alone. Its root is still the header's Merkle root field.
  defp matching(<<header::binary-80, _rest::binary>>, indexes) do
    txids = txids(header)
    3 = length(txids)
    Bitcoin.merkleblock(header, txids, indexes)
  end

  # A merkleblock's parts: its header, total_txs, hashes and flag octets, each compact size
  # below 0xfd.
  defp split(<<header::binary-80, total::little-32, count, rest::binary>>) do
    size = count * 32
    <<hashes::binary-size(^size), flags_count, flags::binary-size(flags_count)>> = rest
    {header, total, for(<<h::binary-32 <- hashes>>, do: h), flags}
  end

  defp join({header, total, hashes, flags}) do
    IO.iodata_to_binary([
      header,
      <<total::little-32>>,
      Bitcoin.compact_size(length(hashes)),
      hashes,
      Bitcoin.compact_size(byte_size(flags)),
      flags
    ])
  end

  defp unused_hash(merkleblock) do
    {header, total, hashes, flags} = split(merkleblock)
    join({header, total, hashes ++ [hd(hashes)], flags})
  end

  # The walk of E1's merkleblock uses four flag bits, 0x0d: the top bit of its one flag octet
  # is unused, and is set.
  defp unused_flag_bit(merkleblock) do
    {header, total, hashes, <<0x0D>>} = split(merkleblock)
    join({header, total, hashes, <<0x8D>>})
  end

  # The first unused bit of the one flag octet, bit 4 after the walk's four, set: 0x1d.
  defp first_unused_flag_bit(merkleblock) do
    {header, total, hashes, <<0x0D>>} = split(merkleblock)
    join({header, total, hashes, <<0x1D>>})
  end

  # A second flag octet, all zero, which the walk does not reach.
  defp extra_flag_octet(merkleblock) do
    {header, total, hashes, flags} = split(merkleblock)
    join({header, total, hashes, flags <> <<0>>})
  end

  # The count of hashes written in three octets, 0xfd and the count little-endian, where its
  # shortest form is one octet.
  defp longer_hash_count(merkleblock) do
    {header, total, hashes, flags} = split(merkleblock)
    longer = <<0xFD, length(hashes)::little-16>>

    IO.iodata_to_binary([
      header,
      <<total::little-32>>,
      longer,
      hashes,
      Bitcoin.compact_size(byte_size(flags)),
      flags
    ])
  end

  defp total_txs(merkleblock, total) do
    {header, _total, hashes, flags} = split(merkleblock)
    join({header, total, hashes, flags})
  end

  # The header with the first nonce, from 0, whose hash is above the target of its nBits.
  defp header_above_target(merkleblock) do
    {<<fields::binary-76, _nonce::binary-4>>, total, hashes, flags} = split(merkleblock)

    header =
      Enum.find_value(Stream.iterate(0, &(&1 + 1)), fn nonce ->
        header = <<fields::binary, nonce::little-32>>
        if not Bitcoin.meets_target?(header), do: header
      end)

    join({header, total, hashes, flags})
  end

  defp nbits(merkleblock, bits) do
    {<<head::binary-72, _bits::binary-4, nonce::binary-4>>, total, hashes, flags} =
      split(merkleblock)

    join({<<head::binary, bits::little-32, nonce::binary>>, total, hashes, flags})
  end

  # The header with regtest's nBits, 0x207fffff, given its sign bit, 0x20ffffff, which SPEC.md
  # 10.2 step 9 (d) reads as negative, and the first nonce, from 0, whose hash meets the target
  # that nBits gives read without its sign, 0x7fffff x 256^29 (Generator.Bitcoin.target/1).
  defp negative_met(merkleblock) do
    {<<fields::binary-72, _bits::binary-4, _nonce::binary-4>>, total, hashes, flags} =
      split(merkleblock)

    header =
      Enum.find_value(Stream.iterate(0, &(&1 + 1)), fn nonce ->
        header = <<fields::binary, 0x20FFFFFF::little-32, nonce::little-32>>
        if Bitcoin.meets_target?(header), do: header
      end)

    join({header, total, hashes, flags})
  end

  # E1's transaction at /commitments in a block of BITCOIN_MAX_TOTAL_TXS transactions, the
  # most a merkleblock may count, as the last of them, after hashes that stand for the others:
  # the block's Merkle root, its header ground again at its own nBits, the merkleblock, and
  # `header_hash` and `header_merkle_root` made to agree. Its merkleblock is well formed.
  defp largest_block(proof) do
    max = Spec.read("constants.json")["BITCOIN_MAX_TOTAL_TXS"]
    txoutproof = @btc <> "/txoutproof"
    <<header::binary-80, _rest::binary>> = proof |> get(txoutproof) |> Bytes.unhex()
    others = for i <- 1..(max - 1), do: :crypto.hash(:sha256, "truestamp vectors tx #{i}")
    txids = others ++ [Bitcoin.txid(raw(proof, @btc))]
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
    |> put(txoutproof, Bytes.hex(Bitcoin.merkleblock(header, txids, max - 1)))
    |> put(@btc <> "/header_hash", Bitcoin.display(Bitcoin.sha256d(header)))
    |> put(@btc <> "/header_merkle_root", Bitcoin.display(root))
  end

  # Edits Generator.Edit does not give.

  defp raw(proof, n), do: Bytes.unhex(get(proof, n <> "/raw_transaction"))

  # One of Generator.Chain's epoch transactions, parsed: one input with an empty script, and
  # outputs whose scripts are shorter than 0xfd octets.
  defp parse(raw) do
    <<version::little-32, 1, txid::binary-32, vout::little-32, 0, sequence::little-32, count,
      rest::binary>> = raw

    {outputs, <<locktime::little-32>>} = outputs(rest, count, [])
    inputs = [{txid, vout, <<>>, sequence}]
    %{version: version, inputs: inputs, outputs: outputs, locktime: locktime}
  end

  defp outputs(rest, 0, outputs), do: {Enum.reverse(outputs), rest}

  defp outputs(<<value::little-64, size, script::binary-size(size), rest::binary>>, count, acc),
    do: outputs(rest, count - 1, [{value, script} | acc])
end
