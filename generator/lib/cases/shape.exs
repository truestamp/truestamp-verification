# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Generator.Cases.Shape do
  @moduledoc """
  The cases of SHAPE and POLICY, the gates, and EXPECTED_HASH: SPEC.md 13.3's SHAPE, the
  empty-root rule, POLICY, Gates (its offline cases) and EXPECTED_HASH.

  Each case changes a sound proof, makes the values that depend on the change agree again
  (Generator.Edit), up to each epoch's hash and a Bitcoin entry's evidence, and signs the result
  again with VECTOR_KEY, unless it says otherwise. So a verifier that let the defect through
  would find nothing else wrong, though a failure at SHAPE ends the run before any of those
  values is checked.

  - **SHAPE** (`shape-`), each with one failing row, at SHAPE:
    - `unsupported_format` at `/format` for the format `truestamp-receipt`, and
      `unsupported_version` at `/version` for the version 2;
    - `construction_mismatch` at `/constructions` for the full text with one byte changed (the
      prefix byte of its `block_hash` row), with its `keyring` row missing, and with the two
      node orders of its `merkle_path` row swapped, and for a reference URL whose digest, that of
      the first of those texts, is not accepted;
    - `shape_invalid` at `/constructions` for a reference URL on another host, and for the
      accepted reference URL with a `\\n` on its end;
    - `shape_invalid` at `/commitments/stellar/transaction_hash` for that hash in capitals, a
      value no offline check recomputes, so that only SHAPE rejects it;
    - `shape_invalid` for a `\\n` on the end of one value of each pattern class of SPEC.md 2.4
      that a proof holds, ENV aside, at that value (@newlines);
    - `shape_invalid` for each optional member other than `environment` as null, at it:
      `constructions`, `signing_key_event`, a rotation's `prerotation_commitment` and an
      emergency rotation's `handover_signature`;
    - `shape_invalid` for an entropy proof's subject whose `source` differs from its type, and
      a beacon observation whose `source` differs from its name, at that `source`; and, beyond
      SPEC.md 13.3's list, an item's witness entropy object whose `source` differs from its
      name, the third place the schema checks a `source`;
    - `shape_invalid` at `/witnesses` for an item missing a witness that `witness_hashes`
      names, and for one with a witness that `witness_hashes` does not name;
    - `shape_invalid` for a Stellar `closed_at` of `24:00:00`, of February 30 and with 60
      seconds, and of February 29 in 1900 and in 2100, which are not leap years, at that
      value; and `0000-02-29T00:00:00Z` passes SHAPE, since TIME covers the years 0000 to
      9999 of the proleptic Gregorian calendar, in which 0000 is a leap year, with every
      row the sound proof's (`shape-time-february_29-0000`);
    - `shape_invalid` at the array for a `path` of 33 nodes, walked from leaf 0 of a tree of
      2^33 leaves with the block record made to agree, so that only its length is wrong.
  - **The empty-root rule** (`empty_root-`): at `/block` (the block proof of the genesis
    block), `/witnesses/block` and `/signing_key_event/block` (the item), a block record with
    `leaf_count` 1 under the empty root, and one with `leaf_count` 0 under another root, each
    `shape_invalid` at that record's `merkle_root`.
  - **POLICY** (`policy-`): one `network_mismatch` case for each `network` member, at it. The
    network of a commitment entry, which no hash covers, and of each `genesis.bitcoin`, with
    the genesis `previous_block_hash` and the hashes above it made to agree, is changed in the
    proof. An entropy object keeps its network, and the case's entropy pin for its source
    changes instead, since in each proof that pin covers that object alone.
  - **Gates** (`gates-`), each run given an expected hash, so that the row of EXPECTED_HASH
    shows whether that step ran. After a failure at ENVIRONMENT (the sound item under
    `staging`, keyless), KEY_BINDING (under the keyring of
    `configuration-nonproduction_key-under-prod`, whose one key is the other published key),
    SIGNATURE (the item's claims `hash` changed, the hashes above it made to agree, and not
    signed again) and SHAPE (the file of `shape-version`), each later step up to EXPECTED_HASH
    is one row `skip prior_failure` with part null. After a failure at POLICY (the file of
    `policy-commitments-bitcoin`) and at DERIVE (the file of `declared-item_hash`, the item's
    `item_hash` changed), each
    CHAIN and SOURCES row, KEY_EVENT_COMMITMENT included, and WINDOW are `skip prior_failure`,
    while EXPECTED_HASH still compares. Every case of SHAPE and POLICY shows the same.
  - **EXPECTED_HASH** (`expected_hash-`), at `/subject/claims/hash`: a different hash, one two
    characters too long and one a character short, a hash given for a block proof and for an
    entropy proof, and for an item whose claims have no `hash` and one whose `hash_type` is not
    listed, each `fail expected_hash_mismatch`; the sha256 hash in capitals passes; the md5
    match and a sha1 match each `warn expected_hash_weak_algorithm`. A run given no hash,
    `skip expected_hash_not_checked`, is every sound case.

  A case that changes a /block record leaves the entries of /signing_key_event, where they hold
  the same epoch, with the old one, which no offline check compares (Generator.Edit). The
  claims cases of EXPECTED_HASH change item-rotation-witness, whose /block, h6, is alone in its
  epoch, E3.

  Some SHAPE cases have knock-on failures (@knock_on): rows their defect by itself also fails
  once the run goes past the SHAPE stop, which the check of Generator.Cases holds them to.
  """

  @behaviour Generator.Cases.Class

  alias Generator.{Bytes, Case, Edit, JCS, Registry, Spec}

  @w "/witnesses/block"
  @k "/signing_key_event/block"
  @event "/record/metadata/key_event"
  @hash "/subject/claims/hash"
  @closed_at "/subject/entropy/payload/closed_at"
  @empty_root "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

  # One value of each pattern class of SPEC.md 2.4 that a proof holds, ENV aside, whose `\n`
  # case is ENVIRONMENT's: the class, the sound proof, the value's pointer, and the values that
  # depend on it (agree/2). The reference URL of SPEC.md 7.2 is in constructions/1.
  @newlines [
    {"hex64", "item-rotation-witness", "/block/record/previous_block_hash", {:block, "/block"}},
    {"kid", "item-rotation-witness", "/block/record/signing_key_id", {:block, "/block"}},
    {"uuid7", "item-rotation-witness", "/block/record/id", {:block, "/block"}},
    {"ulid", "item", "/subject/record/id", :item},
    {"hexbytes", "item", "/commitments/bitcoin/txoutproof", :none},
    {"b64u32", "item", @k <> @event <> "/public_key", {:event, @k}},
    {"b64u64", "item", @k <> @event <> "/handover_signature", {:block, @k}},
    {"ascii128", "item", @k <> @event <> "/reason", {:event, @k}},
    {"time", "item", "/witnesses/entropy_stellar/payload/closed_at",
     {:witness, "entropy_stellar"}},
    {"nisttime", "item", "/witnesses/entropy_nist/payload/pulse/timeStamp",
     {:witness, "entropy_nist"}},
    {"nisthex", "item", "/witnesses/entropy_nist/payload/pulse/outputValue",
     {:witness, "entropy_nist"}},
    {"ascii16", "item", "/witnesses/entropy_nist/payload/pulse/version",
     {:witness, "entropy_nist"}},
    {"network", "item", "/commitments/stellar/network", :none}
  ]

  @k_event @k <> @event

  # The knock-on failures of these cases, by id (Generator.Case's `knock_on`): the rows each
  # also fails past the SHAPE stop, every one caused by the case's own defect.
  @knock_on %{
    # The schema pins `format` and `version` too (check 3).
    "shape-format" => [{"shape_invalid", "/format", "SHAPE"}],
    "shape-version" => [{"shape_invalid", "/version", "SHAPE"}],
    "gates-shape" => [{"shape_invalid", "/version", "SHAPE"}],
    # Neither a reference URL with a `\n` on its end nor null names an accepted text (check 6).
    "shape-newline-reference" => [{"construction_mismatch", "/constructions", "SHAPE"}],
    "shape-null-constructions" => [{"construction_mismatch", "/constructions", "SHAPE"}],
    # A value with a `\n` on its end, or null, fails the check that reads it.
    "shape-newline-hexbytes" => [
      {"bitcoin_evidence_invalid", "/commitments/bitcoin/txoutproof", "DERIVE"}
    ],
    "shape-newline-b64u32" => [
      {"key_event_mismatch", @k_event <> "/key_id", "DERIVE"},
      {"key_event_mismatch", @k_event <> "/public_key", "DERIVE"},
      {"key_event_mismatch", @k_event <> "/public_key", "DERIVE"},
      {"key_event_mismatch", @k <> "/record/signing_key_id", "DERIVE"}
    ],
    "shape-newline-b64u64" => [
      {"key_event_mismatch", @k_event <> "/handover_signature", "DERIVE"}
    ],
    "shape-newline-network" => [
      {"network_mismatch", "/commitments/stellar/network", "POLICY"}
    ],
    "shape-null-signing_key_event" => [
      {"key_event_mismatch", @k_event <> "/public_key", "DERIVE"}
    ],
    "shape-null-handover_signature" => [
      {"key_event_mismatch", "/block" <> @event <> "/handover_signature", "DERIVE"}
    ],
    # A `source` of `bitcoin` whose `network` stays `testnet`, which the bitcoin pin is not.
    "shape-source-type" => [{"network_mismatch", "/subject/entropy/network", "POLICY"}],
    "shape-source-name" => [
      {"network_mismatch", "/observations/entropy_stellar/entropy/network", "POLICY"}
    ],
    "shape-source-witness" => [
      {"network_mismatch", "/witnesses/entropy_stellar/network", "POLICY"}
    ],
    # The missing witness leaves its `witness_hashes` entry nothing to hash.
    "shape-witnesses-missing" => [
      {"derivation_mismatch", "/subject/record/witness_hashes/entropy_nist", "DERIVE"}
    ],
    # A walk of more than MAX_PATH_STEPS nodes gives no root.
    "shape-path-33_nodes" => [{"derivation_mismatch", "/block/record/merkle_root", "DERIVE"}]
  }

  @impl true
  def codes,
    do: ~w(unsupported_format unsupported_version shape_invalid construction_mismatch
         network_mismatch prior_failure expected_hash_mismatch expected_hash_weak_algorithm)

  @impl true
  def cases(%{sound: sound}) do
    cases =
      List.flatten([
        shape(sound),
        empty_root(sound),
        policy(sound),
        gates(sound),
        expected_hash(sound)
      ])

    case Map.keys(@knock_on) -- Enum.map(cases, & &1.id) do
      [] -> Enum.map(cases, &%{&1 | knock_on: Map.get(@knock_on, &1.id, [])})
      ids -> raise ArgumentError, "@knock_on names no case: #{inspect(ids)}"
    end
  end

  # A case whose proof is `proof` signed again with VECTOR_KEY.
  defp signed(id, proof, defect, options \\ []),
    do: Case.new(id, [proof: {:served, Case.sign(proof)}, defect: defect] ++ options)

  defp invalid(id, proof, part),
    do: signed(id, proof, {:fail, "shape_invalid", part, "SHAPE"})

  # The values that depend on an edited one, made to agree again (Generator.Edit).
  defp agree(proof, :none), do: proof
  defp agree(proof, :item), do: Edit.recommit_item(proof)
  defp agree(proof, {:block, b}), do: Edit.recommit(proof, b)

  # A key event's handover covers every other member of the event.
  defp agree(proof, {:event, b}), do: proof |> Edit.resign(b <> @event) |> Edit.recommit(b)

  defp agree(proof, {:witness, name}), do: Edit.rewitness(proof, name)

  # An entropy proof's subject: its hashes, the root its walk reaches, and /block.
  defp agree(proof, :subject), do: Edit.resubject(proof)

  # A beacon observation, whose block's tree holds exactly the beacon's observations, so the
  # tree is built again from them, with every observation's path, and then /block.
  defp agree(proof, {:observation, name}), do: Edit.reobservation(proof, name)

  # A genesis block record's `previous_block_hash`, H(0x30, genesis), and the hashes above it.
  defp agree(proof, {:genesis, b}), do: Edit.regenesis(proof, b)

  # SHAPE.

  defp shape(sound) do
    item = sound["item"].proof
    transaction_hash = "/commitments/stellar/transaction_hash"

    [
      signed(
        "shape-format",
        Edit.put(item, "/format", "truestamp-receipt"),
        {:fail, "unsupported_format", "/format", "SHAPE"}
      ),
      signed(
        "shape-version",
        Edit.put(item, "/version", 2),
        {:fail, "unsupported_version", "/version", "SHAPE"}
      ),
      constructions(item),
      invalid(
        "shape-uppercase_hash",
        Edit.put(item, transaction_hash, String.upcase(Edit.get(item, transaction_hash))),
        transaction_hash
      ),
      newlines(sound),
      nulls(sound),
      sources(sound),
      witnesses(sound),
      times(sound["entropy_stellar"].proof),
      path(sound["item-rotation-witness"].proof)
    ]
  end

  defp constructions(item) do
    text = item["constructions"]
    [digest] = accepted()

    changed =
      Map.update!(text, "block_hash", fn "SHA-256(0x31 || JCS(record))" ->
        "SHA-256(0x32 || JCS(record))"
      end)

    swapped = Map.update!(text, "merkle_path", &swap/1)
    other = Bytes.hex(:crypto.hash(:sha256, JCS.encode(changed)))

    [
      {"shape-constructions-byte_changed", changed, "construction_mismatch"},
      {"shape-constructions-row_missing", Map.delete(text, "keyring"), "construction_mismatch"},
      {"shape-constructions-merkle_path_swapped", swapped, "construction_mismatch"},
      {"shape-reference-not_accepted", reference("www.truestamp.com", other),
       "construction_mismatch"},
      {"shape-reference-other_host", reference("www.truestamp.net", digest), "shape_invalid"},
      {"shape-newline-reference", reference("www.truestamp.com", digest) <> "\n", "shape_invalid"}
    ]
    |> Enum.map(fn {id, value, code} ->
      signed(id, %{item | "constructions" => value}, {:fail, code, "/constructions", "SHAPE"})
    end)
  end

  defp accepted do
    for path <- Path.wildcard(Path.join(Spec.root(), "spec/constructions/*.json")),
        do: Path.basename(path, ".json")
  end

  defp reference(host, digest), do: "https://#{host}/.well-known/constructions-#{digest}.json"

  # The merkle_path row with its two node orders swapped, each of which it holds once.
  defp swap(row) do
    left = "SHA-256(0x01 || p || r)"
    right = "SHA-256(0x01 || r || p)"
    [_] = :binary.matches(row, left)
    [_] = :binary.matches(row, right)
    String.replace(row, [left, right], fn found -> if found == left, do: right, else: left end)
  end

  defp newlines(sound) do
    for {class, name, pointer, agreeing} <- @newlines do
      proof = sound[name].proof
      edited = Edit.put(proof, pointer, Edit.get(proof, pointer) <> "\n")
      invalid("shape-newline-" <> class, agree(edited, agreeing), pointer)
    end
  end

  defp nulls(sound) do
    item = sound["item"].proof
    emergency = sound["block-emergency-rotation"].proof

    [
      {"constructions", item, "/constructions", :none},
      {"signing_key_event", item, "/signing_key_event", :none},
      {"prerotation_commitment", item, @k <> @event <> "/prerotation_commitment", {:event, @k}},
      {"handover_signature", emergency, "/block" <> @event <> "/handover_signature",
       {:block, "/block"}}
    ]
    |> Enum.map(fn {name, proof, pointer, agreeing} ->
      invalid("shape-null-" <> name, proof |> Edit.put(pointer, nil) |> agree(agreeing), pointer)
    end)
  end

  defp sources(sound) do
    subject = "/subject/entropy/source"
    observation = "/observations/entropy_stellar/entropy/source"
    witness = "/witnesses/entropy_stellar/source"

    [
      invalid(
        "shape-source-type",
        sound["entropy_stellar"].proof |> Edit.put(subject, "bitcoin") |> agree(:subject),
        subject
      ),
      invalid(
        "shape-source-name",
        sound["beacon"].proof
        |> Edit.put(observation, "bitcoin")
        |> agree({:observation, "entropy_stellar"}),
        observation
      ),
      invalid(
        "shape-source-witness",
        sound["item"].proof
        |> Edit.put(witness, "bitcoin")
        |> agree({:witness, "entropy_stellar"}),
        witness
      )
    ]
  end

  defp witnesses(sound) do
    item = sound["item"].proof
    nist = Edit.get(item, "/witnesses/entropy_nist")
    extra = Edit.put(sound["item-genesis-witness"].proof, "/witnesses/entropy_nist", nist)

    [
      invalid(
        "shape-witnesses-missing",
        Edit.delete(item, "/witnesses/entropy_nist"),
        "/witnesses"
      ),
      invalid("shape-witnesses-extra", extra, "/witnesses")
    ]
  end

  defp times(proof) do
    <<year::binary-4, date::binary-6, "T", clock::binary-6, seconds::binary-2, "Z">> =
      Edit.get(proof, @closed_at)

    refused =
      [
        {"hour_24", year <> date <> "T24:00:00Z"},
        {"february_30", year <> "-02-30T" <> clock <> seconds <> "Z"},
        {"second_60", year <> date <> "T" <> clock <> "60Z"},
        {"february_29-1900", "1900-02-29T00:00:00Z"},
        {"february_29-2100", "2100-02-29T00:00:00Z"}
      ]
      |> Enum.map(fn {name, time} ->
        invalid(
          "shape-time-" <> name,
          proof |> Edit.put(@closed_at, time) |> agree(:subject),
          @closed_at
        )
      end)

    passed =
      signed(
        "shape-time-february_29-0000",
        proof |> Edit.put(@closed_at, "0000-02-29T00:00:00Z") |> agree(:subject),
        {:passes, [{"pass", nil, nil, "SHAPE"}]},
        same_as: "sound-entropy_stellar",
        label: "supplied-keyring"
      )

    refused ++ [passed]
  end

  # MAX_PATH_STEPS + 1 nodes from leaf 0 of a tree of 2^33 leaves, where each step hashes the
  # node on the right (SPEC.md 5.3), with /block's record made to agree.
  defp path(proof) do
    steps = Spec.read("constants.json")["MAX_PATH_STEPS"] + 1
    size = Integer.pow(2, steps)
    nodes = for i <- 1..steps, do: :crypto.hash(:sha256, <<i>>)
    leaf = Registry.hash("merkle_leaf", Bytes.unhex(proof["subject"]["item_hash"]))
    root = Enum.reduce(nodes, leaf, &Registry.hash("merkle_node", &2 <> &1))
    inclusion = %{"leaf_index" => 0, "path" => Enum.map(nodes, &Bytes.hex/1), "tree_size" => size}

    edited =
      proof
      |> Edit.put("/subject/inclusion_proof", inclusion)
      |> Edit.put("/block/record/leaf_count", size)
      |> Edit.put("/block/record/merkle_root", Bytes.hex(root))
      |> Edit.recommit("/block")

    invalid("shape-path-33_nodes", edited, "/subject/inclusion_proof/path")
  end

  # The empty-root rule, at each block position.

  defp empty_root(sound) do
    other = sound["item"].proof["block"]["record"]["merkle_root"]

    positions = [
      {"block", sound["block"].proof, "/block"},
      {"witnesses_block", sound["item"].proof, @w},
      {"signing_key_event_block", sound["item"].proof, @k}
    ]

    for {name, proof, b} <- positions,
        {variant, member, value} <- [{"leaves", "leaf_count", 1}, {"root", "merkle_root", other}] do
      %{"leaf_count" => 0, "merkle_root" => @empty_root} = Edit.get(proof, b <> "/record")
      edited = proof |> Edit.put("#{b}/record/#{member}", value) |> Edit.recommit(b)
      invalid("empty_root-#{name}-#{variant}", edited, b <> "/record/merkle_root")
    end
  end

  # POLICY.

  defp policy(sound) do
    item = sound["item"].proof

    entries =
      for {id, n, network} <- [
            {"commitments-bitcoin", "/commitments/bitcoin", "mainnet"},
            {"commitments-stellar", "/commitments/stellar", "public"},
            {"signing_key_event-commitments-bitcoin", "/signing_key_event/commitments/bitcoin",
             "mainnet"},
            {"signing_key_event-commitments-stellar", "/signing_key_event/commitments/stellar",
             "public"}
          ] do
        pointer = n <> "/network"
        signed("policy-" <> id, Edit.put(item, pointer, network), mismatch(pointer))
      end

    [entries, entropy(sound), genesis(sound)]
  end

  defp mismatch(pointer), do: {:fail, "network_mismatch", pointer, "POLICY"}

  # Each Stellar and Bitcoin entropy object, against an entropy pin that differs from its
  # network: in each of these proofs the object is the only one of its source.
  defp entropy(sound) do
    for {id, name, e} <- [
          {"subject-entropy_stellar", "entropy_stellar", "/subject/entropy"},
          {"subject-entropy_bitcoin", "entropy_bitcoin", "/subject/entropy"},
          {"witnesses-entropy_stellar", "item", "/witnesses/entropy_stellar"},
          {"witnesses-entropy_bitcoin", "item", "/witnesses/entropy_bitcoin"},
          {"observations-entropy_stellar", "beacon", "/observations/entropy_stellar/entropy"},
          {"observations-entropy_bitcoin", "beacon", "/observations/entropy_bitcoin/entropy"}
        ] do
      %{proof: proof, path: path} = sound[name]
      source = Edit.get(proof, e <> "/source")
      network = if source == "stellar", do: "public", else: "mainnet"

      Case.new("policy-" <> id,
        proof: {:path, path},
        networks: put_in(Case.pins(), ["entropy", source], network),
        defect: mismatch(e <> "/network")
      )
    end
  end

  defp genesis(sound) do
    for {id, name, b} <- [
          {"block-genesis", "block", "/block"},
          {"witnesses_block-genesis", "item-genesis-witness", @w},
          {"signing_key_event_block-genesis", "item-genesis-witness", @k}
        ] do
      pointer = b <> "/record/metadata/genesis/bitcoin/network"
      proof = sound[name].proof |> Edit.put(pointer, "mainnet") |> agree({:genesis, b})
      signed("policy-" <> id, proof, mismatch(pointer))
    end
  end

  # Gates.

  defp gates(sound) do
    %{proof: item, path: path, envelope: envelope} = sound["item"]
    md5 = Edit.get(item, @hash)

    # The claims' hash changed to that of another file, with the hashes above it made to agree,
    # and the proof not signed again; the caller's hash is that other file's.
    other = Bytes.hex(:crypto.hash(:md5, "another file"))
    changed = item |> Edit.put(@hash, other) |> Edit.recommit_item()
    %{"public_key" => k, "value" => v} = envelope["signature"]

    [
      Case.new("gates-environment",
        proof: {:path, path},
        environment: "staging",
        keyring: "none",
        expected_hash: md5,
        defect: {:fail, "environment_mismatch", "/environment", "ENVIRONMENT"}
      ),
      Case.new("gates-key_binding",
        proof: {:path, path},
        keyring: {:path, "negative/configuration-nonproduction_key-under-prod.keyring.json"},
        expected_hash: md5,
        defect: {:fail, "key_binding_failed", nil, "KEY_BINDING"}
      ),
      Case.new("gates-signature",
        proof: {:served, Case.envelope(changed, k, v)},
        expected_hash: other,
        defect: {:fail, "signature_invalid", nil, "SIGNATURE"}
      ),
      Case.new("gates-shape",
        proof: {:path, "negative/shape-version.proof.json"},
        expected_hash: md5,
        defect: {:fail, "unsupported_version", "/version", "SHAPE"}
      ),
      Case.new("gates-policy",
        proof: {:path, "negative/policy-commitments-bitcoin.proof.json"},
        expected_hash: md5,
        defect: mismatch("/commitments/bitcoin/network")
      ),
      Case.new("gates-derive",
        proof: {:path, "negative/declared-item_hash.proof.json"},
        expected_hash: md5,
        defect: {:fail, "derivation_mismatch", "/subject/item_hash", "DERIVE"}
      )
    ]
  end

  # EXPECTED_HASH.

  defp expected_hash(sound) do
    %{proof: item, path: item_path} = sound["item"]
    %{proof: alone, path: alone_path} = sound["item-rotation-witness"]
    md5 = Edit.get(item, @hash)
    sha256 = Edit.get(alone, @hash)
    <<first, rest::binary>> = md5
    different = <<if(first == ?0, do: ?1, else: ?0), rest::binary>>

    # SHA-1 of an empty file, and CRC-32 of one, which no row of SPEC.md 10.2 step 13 lists.
    sha1 = Bytes.hex(:crypto.hash(:sha, ""))
    no_hash = alone |> Edit.delete(@hash) |> Edit.delete("/subject/claims/hash_type")
    crc32 = alone |> Edit.put(@hash, "00000000") |> Edit.put("/subject/claims/hash_type", "crc32")
    weak = alone |> Edit.put(@hash, sha1) |> Edit.put("/subject/claims/hash_type", "sha1")

    [
      mismatch_case("different", {:path, item_path}, different),
      mismatch_case("too_long", {:path, item_path}, md5 <> "00"),
      mismatch_case("too_short", {:path, item_path}, binary_part(md5, 0, 31)),
      mismatch_case("not_item-block", {:path, sound["block"].path}, md5),
      mismatch_case("not_item-entropy_nist", {:path, sound["entropy_nist"].path}, md5),
      mismatch_case("no_hash", served(no_hash), sha256),
      mismatch_case("unlisted_type", served(crc32), "00000000"),
      match_case("capitals", {:path, alone_path}, String.upcase(sha256), "pass", nil),
      match_case("md5", {:path, item_path}, md5, "warn", "expected_hash_weak_algorithm"),
      match_case("sha1", served(weak), sha1, "warn", "expected_hash_weak_algorithm")
    ]
  end

  # An item whose claims changed, with the hashes above them made to agree, signed again.
  defp served(proof), do: {:served, proof |> Edit.recommit_item() |> Case.sign()}

  defp mismatch_case(name, proof, given) do
    Case.new("expected_hash-" <> name,
      proof: proof,
      expected_hash: given,
      defect: {:fail, "expected_hash_mismatch", @hash, "EXPECTED_HASH"}
    )
  end

  defp match_case(name, proof, given, status, code) do
    Case.new("expected_hash-" <> name,
      proof: proof,
      expected_hash: given,
      label: "supplied-keyring",
      defect: {:passes, [{status, code, @hash, "EXPECTED_HASH"}]}
    )
  end
end
