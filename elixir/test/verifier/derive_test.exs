# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Truestamp.Verifier.DeriveTest do
  # Step 9, DERIVE (SPEC.md 10.2), on the sound proofs under vectors/positive/ and mutants of
  # them, beside the vectors' own cases in derive_cases_test.exs:
  #
  # - the committed leaf count (5.4, D44) at the block and the epoch level: a tree_size that
  #   is not the record's leaf_count, and a moved leaf index (the last of three leaves as
  #   index 1 of two, 5.3), each with a walk that still reaches the root;
  # - one test for each rule of 10.6, and one that `constructions` is read only at SHAPE;
  # - the D58 cases for DERIVE: each link at its moved part (item 11), the Bitcoin rows a
  #   malformed structure gives (packet C2), the OP_RETURN rules (packet C6), and a record
  #   whose signing_key_id is not the key id of its event's public_key (packet C3);
  # - what a trace row's `recomputed` is (item 7), and what DERIVE does to the run.
  #
  # DERIVE reads P, K and the attribution, so these runs hold a sound P past SHAPE and POLICY
  # with no signature over it; every mutant is otherwise the sound proof unchanged.
  use ExUnit.Case, async: true

  alias Truestamp.Verifier

  alias Truestamp.Verifier.{
    Base64url,
    Bitcoin,
    Config,
    Derive,
    JCS,
    KeyId,
    Pointer,
    Policy,
    Row,
    Run,
    Shape
  }

  alias Truestamp.Verifier.Test.{Cases, ProofMutants}

  @root Path.expand("../../..", __DIR__)
  @positive ProofMutants.positive()
  @attribution "keyring:0000000000000000000000000000000000000000000000000000000000000000"

  # A run past POLICY holding the sound or mutated `proof`, signed (as far as DERIVE reads)
  # by the key the positive proof carries.
  defp run(name, proof, attribution \\ @attribution) do
    {:ok, key} = Base64url.decode(:b64u32, @positive[name]["signature"]["public_key"])
    run_with_key(key, proof, attribution)
  end

  defp run_with_key(key, proof, attribution) do
    rows = for step <- ~w(CONFIGURATION READ PARSE ENVELOPE), do: Row.pass(step, nil, "held")

    %Run{
      config: Config.new!(environment: "test", keyring: :none),
      keyring: nil,
      trust_root: %{digest: nil, kind: :none, location: nil},
      proof: proof,
      public_key: key,
      attribution: attribution,
      rows: rows
    }
  end

  defp derived(name, proof \\ nil, attribution \\ @attribution),
    do: Derive.derive(run(name, proof || sound(name), attribution))

  defp sound(name), do: @positive[name]["proof"]

  # DERIVE's rows as [code, part, status].
  defp rows(%Run{rows: rows}) do
    for %Row{step: "DERIVE"} = row <- rows do
      [code, part, status, "DERIVE"] = Row.reduce(row)
      [code, part, status]
    end
  end

  defp failing(run), do: for([code, part, "fail"] <- rows(run), do: [code, part])

  defp trace_at(run, part), do: Enum.filter(run.trace, &(&1["part"] == part))

  defp put(proof, at, value), do: ProofMutants.put(proof, at, value)
  defp get(proof, at), do: ProofMutants.get(proof, at)
  defp show(at), do: ProofMutants.show(at)

  # Every inclusion proof of `proof`, as {Q, R, level}, where R is the record Q walks into.
  defp inclusion_proofs(proof) do
    subject =
      case proof["type"] do
        "block" -> []
        "beacon" -> for {name, _} <- proof["observations"], do: ["observations", name]
        _item_or_entropy -> [["subject"]]
      end

    block_level = for at <- subject, do: {at ++ ["inclusion_proof"], ["block", "record"], :block}

    epoch_level =
      for base <- [["commitments"], ["signing_key_event", "commitments"]],
          chain <- ~w(bitcoin stellar),
          is_map(get(proof, base ++ [chain])),
          do: {base ++ [chain, "inclusion_proof"], base ++ [chain, "epoch", "record"], :epoch}

    block_level ++ epoch_level
  end

  # {name, Q, R, level} for each inclusion proof of the positive proofs that `select` keeps.
  defp positions(select) do
    for {name, document} <- @positive,
        {q, r, level} <- inclusion_proofs(document["proof"]),
        select.(get(document["proof"], q)),
        do: {name, q, r, level}
  end

  describe "the committed leaf count (SPEC.md 5.4)" do
    test "a tree_size that is not the record's leaf_count, whose walk still reaches the root" do
      # Index 0 of three leaves walks the same two nodes as index 0 of four, to the same root.
      found = positions(&match?(%{"leaf_index" => 0, "tree_size" => 3}, &1))
      assert Enum.any?(found, &match?({_, _, _, :block}, &1))
      assert Enum.any?(found, &match?({_, _, _, :epoch}, &1))

      for {name, q, r, _level} <- found do
        run = derived(name, put(sound(name), q ++ ["tree_size"], 4))
        size = show(q ++ ["tree_size"])

        assert failing(run) == [["derivation_mismatch", size]], "#{name} #{show(q)}"
        assert [%{"status" => "pass"} | _] = trace_at(run, show(r ++ ["merkle_root"]))

        assert trace_at(run, size) == [
                 %{
                   "construction" => "inclusion",
                   "declared" => 4,
                   "inputs" => [show(r ++ ["leaf_count"])],
                   "part" => size,
                   "recomputed" => 3,
                   "status" => "fail"
                 }
               ]
      end
    end

    test "a moved leaf index, the last of three leaves as index 1 of two, fails at the size" do
      found = positions(&match?(%{"leaf_index" => 2, "tree_size" => 3}, &1))
      assert Enum.any?(found, &match?({_, _, _, :block}, &1))
      assert Enum.any?(found, &match?({_, _, _, :epoch}, &1))

      for {name, q, r, _level} <- found do
        moved = %{get(sound(name), q) | "leaf_index" => 1, "tree_size" => 2}
        run = derived(name, put(sound(name), q, moved))
        root = get(sound(name), r ++ ["merkle_root"])

        # The walk alone accepts the move (5.3), so only the committed count catches it.
        leaf_trace = hd(trace_at(run, show(r ++ ["merkle_root"])))
        assert leaf_trace["recomputed"] == root and leaf_trace["status"] == "pass"
        assert failing(run) == [["derivation_mismatch", show(q ++ ["tree_size"])]], name
      end
    end

    test "the vectors' leaf count cases fail at the part 13.3 gives them" do
      expected = %{
        "leaf_count-tree_size-subject" => "/subject/inclusion_proof/tree_size",
        "leaf_count-moved_index-subject" => "/subject/inclusion_proof/tree_size",
        "leaf_count-tree_size-observation" =>
          "/observations/entropy_nist/inclusion_proof/tree_size",
        "leaf_count-moved_index-observation" =>
          "/observations/entropy_bitcoin/inclusion_proof/tree_size",
        "leaf_count-tree_size-commitments-bitcoin" =>
          "/commitments/bitcoin/inclusion_proof/tree_size",
        "leaf_count-moved_index-commitments-bitcoin" =>
          "/commitments/bitcoin/inclusion_proof/tree_size",
        "leaf_count-tree_size-commitments-stellar" =>
          "/commitments/stellar/inclusion_proof/tree_size",
        "leaf_count-moved_index-commitments-stellar" =>
          "/commitments/stellar/inclusion_proof/tree_size",
        "leaf_count-tree_size-signing_key_event-bitcoin" =>
          "/signing_key_event/commitments/bitcoin/inclusion_proof/tree_size",
        "leaf_count-moved_index-signing_key_event-bitcoin" =>
          "/signing_key_event/commitments/bitcoin/inclusion_proof/tree_size",
        "leaf_count-tree_size-signing_key_event-stellar" =>
          "/signing_key_event/commitments/stellar/inclusion_proof/tree_size",
        "leaf_count-moved_index-signing_key_event-stellar" =>
          "/signing_key_event/commitments/stellar/inclusion_proof/tree_size",
        "leaf_count-record-commitments-bitcoin" => "/commitments/bitcoin/raw_transaction",
        "leaf_count-record-signing_key_event-bitcoin" =>
          "/signing_key_event/commitments/bitcoin/raw_transaction"
      }

      assert_single_failures(expected, "derivation_mismatch")
    end

    test "a record whose leaf_count is 0 fails every inclusion proof into it" do
      name = "item"
      proof = put(sound(name), ["block", "record", "leaf_count"], 0)
      run = derived(name, proof)
      assert ["derivation_mismatch", "/subject/inclusion_proof/tree_size"] in failing(run)
    end
  end

  # Each case of `expected` (id => part) gives exactly one failing row, with `code`, there.
  defp assert_single_failures(expected, code) do
    cases = Map.new(Cases.offline(), &{&1["id"], &1})

    for {id, part} <- expected do
      kase = Map.fetch!(cases, id)
      {:ok, run} = Verifier.run(Cases.config(kase), Cases.proof(kase))
      assert failing(run) == [[code, part]], id
    end
  end

  # Each generator of a comprehension in `ast` that takes a tuple from a document value, as
  # its source text: a lookup, a call of get or of a Map function, or a variable other than
  # the two that hold Layout's compiled positions (`positions` and `nodes`).
  defp pairs_from_document(ast) do
    {_ast, found} =
      Macro.prewalk(ast, [], fn
        {:for, _meta, clauses} = node, found ->
          sources =
            for {:<-, _, [pattern, source]} <- clauses,
                tuple_pattern?(pattern),
                document_value?(source),
                do: Macro.to_string(source)

          {node, found ++ sources}

        node, found ->
          {node, found}
      end)

    found
  end

  defp tuple_pattern?({_first, _second}), do: true
  defp tuple_pattern?({:{}, _meta, _elements}), do: true
  defp tuple_pattern?(_pattern), do: false

  defp document_value?({name, _meta, context}) when is_atom(name) and is_atom(context),
    do: name not in [:positions, :nodes]

  defp document_value?({{:., _, [Access, :get]}, _meta, _args}), do: true
  defp document_value?({{:., _, [{:__aliases__, _, [:Map]}, _fun]}, _meta, _args}), do: true
  defp document_value?({{:., _, [_module, :get]}, _meta, _args}), do: true
  defp document_value?({:get, _meta, args}) when is_list(args), do: true
  defp document_value?(_source), do: false

  describe "the rules of SPEC.md 10.6" do
    test "rule 1: DERIVE gives the same rows and trace whatever `constructions` holds" do
      for name <- ~w(item block-rotation beacon) do
        proof = sound(name)
        base = derived(name)

        url =
          "https://www.truestamp.com/.well-known/constructions-#{String.duplicate("0", 64)}.json"

        for value <- [url, %{"not" => "the text"}, :not_json, nil] do
          other = derived(name, Map.put(proof, "constructions", value))
          assert {other.rows, other.trace} == {base.rows, base.trace}, name
        end

        other = derived(name, Map.delete(proof, "constructions"))
        assert {other.rows, other.trace} == {base.rows, base.trace}
      end
    end

    test "rule 1: no DERIVE module names the `constructions` member" do
      dir = Path.join(@root, "elixir/lib/truestamp/verifier")

      files =
        Path.wildcard(Path.join(dir, "derive.ex")) ++ Path.wildcard(Path.join(dir, "derive/*.ex"))

      assert length(files) == 5

      for file <- files do
        refute File.read!(file) =~ ~s("constructions"), file
      end
    end

    test "rule 2: prefix bytes and member sets come from compiled constants only" do
      files = Path.wildcard(Path.join(@root, "elixir/lib/**/*.ex"))
      read = fn file -> File.read!(file) end

      # Only the registry and the two rules over it take a prefix byte.
      byte_readers =
        for file <- files, read.(file) =~ "Prefixes.byte(", uniq: true, do: Path.basename(file)

      assert Enum.sort(byte_readers) == ~w(key_id.ex record_hash.ex)

      # Every kind a DERIVE module hashes under is an atom written in its source, never one
      # made from a document string, and the leaf and node bytes are the Merkle library's.
      derive = Enum.filter(files, &String.contains?(&1, "/verifier/derive"))

      for file <- derive, source = read.(file) do
        refute source =~ ~r/String\.to_(existing_)?atom|:erlang\.binary_to_atom/, file
        refute source =~ ~r/:merkle_(leaf|node)|<<0x0[01]|<<[01]>>/, file

        for [kind] <- Regex.scan(~r/RecordHash\.hash(?:_hex)?\(([^,]+),/, source) do
          kind = String.trim(kind)
          assert kind =~ ~r/\A:[a-z_]+\z/ or kind == "kind", "#{file}: #{kind}"
        end
      end

      # No member set is read from a document value: DERIVE and Layout take no names from
      # Map.keys, Map.to_list or Map.values, and no comprehension takes {name, value} pairs
      # from a document value, so every position comes from a compiled list.
      members = Enum.filter(files, &(&1 =~ ~r{/verifier/(derive\.ex|derive/|layout\.ex)}))
      assert length(members) == 6

      for file <- members, source = read.(file) do
        refute source =~ ~r/Map\.(keys|to_list|values)\b/, file
        assert pairs_from_document(Code.string_to_quoted!(source)) == [], file
      end
    end

    test "rule 2: the member-set lint finds each way of reading a document's names" do
      for source <- [
            "for {name, _} <- hashes, do: name",
            "for {name, _value} <- proof[\"observations\"], do: name",
            "for {at, source, _} <- Layout.get(proof, at), do: at",
            "for x <- [], {name, _} <- get(proof, [\"witnesses\"]), do: name"
          ] do
        assert [_source] = pairs_from_document(Code.string_to_quoted!(source)), source
      end

      for source <- [
            "for {at, node} <- Layout.block_nodes(proof), do: at",
            "for {at, source} <- positions, do: at",
            "for name <- @witness_names, do: name"
          ] do
        assert pairs_from_document(Code.string_to_quoted!(source)) == [], source
      end
    end

    test "rule 3: `type` selects the whole composition, never the members P holds" do
      # The members of an item and of a beacon relabeled `block` are never read: DERIVE takes
      # its positions from the type.
      for name <- ~w(item beacon entropy_nist) do
        proof = Map.put(sound(name), "type", "block")

        parts = for [_code, part, _status] <- rows(derived(name, proof)), do: part

        refute Enum.any?(
                 parts,
                 &String.starts_with?(&1, ["/subject", "/witnesses", "/observations"])
               )
      end
    end

    test "rule 3: each key event type is checked in full at its position" do
      # A rotation relabeled an emergency rotation still has its handover checked, and fails
      # it, since the signature covers the type; without a handover, the rest still runs.
      name = "block-rotation"
      at = ["block", "record", "metadata", "key_event"]
      event = get(sound(name), at)

      parts = fn run ->
        for [_c, part, _s] <- rows(run), String.starts_with?(part, show(at)), do: part
      end

      emergency = derived(name, put(sound(name), at ++ ["type"], "emergency_rotation"))
      assert parts.(emergency) == parts.(derived(name))

      assert ["key_event_mismatch", show(at ++ ["handover_signature"])] in failing(emergency)

      without =
        put(
          sound(name),
          at,
          Map.delete(%{event | "type" => "emergency_rotation"}, "handover_signature")
        )

      assert parts.(derived(name, without)) ==
               parts.(derived(name)) -- [show(at ++ ["handover_signature"])]
    end

    test "rule 3: only a Bitcoin entry gets the Bitcoin evidence checks" do
      parts = for [_c, part, _s] <- rows(derived("item")), do: part
      assert "/commitments/bitcoin/raw_transaction" in parts
      refute Enum.any?(parts, &String.starts_with?(&1, "/commitments/stellar/raw"))
      refute Enum.any?(parts, &(&1 =~ ~r{^/commitments/stellar/(header|txout|transaction)}))
    end

    test "rule 4: a declared value is only compared, and every consumer takes the recomputed one" do
      # Each replaced value fails at its own part alone: the walks, the witness link and the
      # OP_RETURN comparison that read it take its recomputation instead.
      other = String.duplicate("ab", 32)

      for {name, at} <- [
            {"item", ["block", "block_hash"]},
            {"item", ["subject", "item_hash"]},
            {"item", ["witnesses", "block", "block_hash"]},
            {"item", ["commitments", "bitcoin", "epoch", "epoch_hash"]},
            {"item", ["signing_key_event", "block", "block_hash"]},
            {"beacon", ["observations", "entropy_nist", "observation_hash"]},
            {"entropy_stellar", ["subject", "observation_hash"]}
          ] do
        run = derived(name, put(sound(name), at, other))
        assert failing(run) == [["derivation_mismatch", show(at)]], "#{name} #{show(at)}"
      end
    end

    test "rule 4: a graft fails where 10.3 says, in the vectors" do
      assert_single_failures(
        %{"graft-forged_block_hash" => "/commitments/stellar/epoch/record/merkle_root"},
        "derivation_mismatch"
      )

      kase = Enum.find(Cases.offline(), &(&1["id"] == "graft-genuine_block_hash"))
      {:ok, run} = Verifier.run(Cases.config(kase), Cases.proof(kase))

      assert failing(run) == [
               ["derivation_mismatch", "/block/block_hash"],
               ["derivation_mismatch", "/commitments/stellar/epoch/record/merkle_root"]
             ]
    end

    test "rule 5: a run whose PINNED values failed at SHAPE never reaches DERIVE" do
      skipped =
        Run.end_run(
          Run.add_row(
            run("item", sound("item")),
            Row.new("SHAPE", :unsupported_format, "/format", "no")
          )
        )

      assert Derive.derive(skipped) == skipped

      mutant = put(sound("item"), ["format"], "another-format")
      assert Derive.derive(%{skipped | proof: mutant}) == %{skipped | proof: mutant}
    end

    test "rule 6: DERIVE draws no edge, and sets only its rows, its trace and the external gate" do
      before =
        run(
          "item",
          put(sound("item"), ["commitments", "bitcoin", "header_time"], "1999-01-01T00:00:00Z")
        )

      after_derive = Derive.derive(before)

      assert Map.drop(after_derive, [:rows, :trace, :external_gate]) ==
               Map.drop(before, [:rows, :trace, :external_gate])

      assert failing(after_derive) == [
               ["derivation_mismatch", "/commitments/bitcoin/header_time"]
             ]

      assert after_derive.external_gate == :prior_failure
      assert Derive.derive(run("item", sound("item"))).external_gate == :offline
    end

    test "rule 7: LINK_KEY_EVENT passes only when the attribution is truestamp" do
      part = "/signing_key_event/block/record/metadata/key_event/public_key"
      link = fn run -> run |> rows() |> Enum.filter(&(Enum.at(&1, 1) == part)) |> List.last() end

      assert link.(derived("item", nil, "truestamp")) == [nil, part, "pass"]
      assert link.(derived("item", nil, @attribution)) == ["not_attributable", part, "info"]
      assert link.(derived("item", nil, "unattributed")) == ["not_attributable", part, "info"]

      # An event that introduces another key fails, whatever the attribution.
      another_key = "Ivwpd5Lwtv_Av8_bftsMCqFOAlo2XsDjQuhuOCnLdLY"
      refute another_key == @positive["item"]["signature"]["public_key"]
      other = put(sound("item"), String.split(String.trim_leading(part, "/"), "/"), another_key)

      for attribution <- ["truestamp", @attribution, "unattributed"] do
        assert link.(derived("item", other, attribution)) == ["key_event_mismatch", part, "fail"]
      end

      refute Enum.any?(derived("item", nil, "truestamp").trace, &(&1["part"] == part))
    end

    test "rule 7: LINK_KEY_EVENT compares all 32 octets of the key, never its key id" do
      part = ["signing_key_event", "block", "record", "metadata", "key_event", "public_key"]

      link = fn run ->
        run |> rows() |> Enum.filter(&(Enum.at(&1, 1) == show(part))) |> List.last()
      end

      # Two keys ground to share a key id: the event introduces one, and K is the other.
      {a, b} = key_id_collision()
      assert a != b and KeyId.of(a) == KeyId.of(b)

      event = put(sound("item"), part, Base64url.encode(a))

      for attribution <- ["truestamp", @attribution, "unattributed"] do
        assert link.(Derive.derive(run_with_key(b, event, attribution))) ==
                 ["key_event_mismatch", show(part), "fail"],
               attribution

        assert link.(Derive.derive(run_with_key(a, event, attribution))) !=
                 ["key_event_mismatch", show(part), "fail"],
               attribution
      end

      # The genuine key with its last octet flipped is another key.
      {:ok, genuine} = Base64url.decode(:b64u32, get(sound("item"), part))
      <<head::binary-size(31), last>> = genuine
      flipped = <<head::binary, Bitwise.bxor(last, 1)>>

      for attribution <- ["truestamp", @attribution, "unattributed"] do
        assert link.(Derive.derive(run_with_key(flipped, sound("item"), attribution))) ==
                 ["key_event_mismatch", show(part), "fail"],
               attribution
      end
    end
  end

  # Two 32-octet keys with one key id, found as keyring_load_test.exs finds them. The last
  # octet 0x01 keeps y below p and each key out of SMALL_ORDER_KEYS.
  defp key_id_collision, do: key_id_collision(0, %{})

  defp key_id_collision(n, seen) do
    candidate = <<n::little-64, 0::184, 1>>
    id = KeyId.of(candidate)

    case seen do
      %{^id => earlier} -> {earlier, candidate}
      _other -> key_id_collision(n + 1, Map.put(seen, id, candidate))
    end
  end

  defp block_hash(record),
    do: :sha256 |> :crypto.hash([<<0x31>>, JCS.encode(record)]) |> Base.encode16(case: :lower)

  describe "key events that no case of the vectors takes through DERIVE" do
    test "a revocation, at /block and at /witnesses/block, gives no row under it" do
      for {name, at} <- [
            {"block-rotation", ["block"]},
            {"item-rotation-witness", ["witnesses", "block"]}
          ] do
        event_at = at ++ ["record", "metadata", "key_event"]
        signing_key_id = show(at ++ ["record", "signing_key_id"])
        event = get(sound(name), event_at)
        assert event["type"] == "rotation"

        under = fn run ->
          for [_c, part, _s] <- rows(run),
              part == signing_key_id or String.starts_with?(part, show(event_at) <> "/"),
              do: part
        end

        assert signing_key_id in under.(derived(name))

        revocation = %{"revoked_key_id" => event["previous_key_id"], "type" => "revocation"}
        proof = put(sound(name), event_at, revocation)
        record = get(proof, at ++ ["record"])
        proof = put(proof, at ++ ["block_hash"], block_hash(record))

        run = derived(name, proof)
        assert under.(run) == [], name
        refute Enum.any?(run.trace, &(&1["part"] == signing_key_id)), name
        assert [nil, show(at ++ ["block_hash"]), "pass"] in rows(run), name
      end
    end

    test "an emergency rotation with a valid handover signature passes its handover row" do
      name = "block-rotation"
      at = ["block", "record", "metadata", "key_event"]
      seed = :binary.copy(<<0x43>>, 32)
      {outgoing, _secret} = :crypto.generate_key(:eddsa, :ed25519, seed)

      event = %{get(sound(name), at) | "type" => "emergency_rotation"}
      assert event["previous_public_key"] == Base64url.encode(outgoing)

      unsigned = Map.delete(event, "handover_signature")
      message = :crypto.hash(:sha256, [<<0x62>>, JCS.encode(unsigned)])
      signature = :crypto.sign(:eddsa, :none, message, [seed, :ed25519])
      signed = Map.put(unsigned, "handover_signature", Base64url.encode(signature))
      refute signed["handover_signature"] == get(sound(name), at ++ ["handover_signature"])

      proof = put(sound(name), at, signed)
      proof = put(proof, ["block", "block_hash"], block_hash(get(proof, ["block", "record"])))
      run = derived(name, proof)
      part = show(at ++ ["handover_signature"])

      assert [nil, part, "pass"] in rows(run)

      refute Enum.any?(failing(run), fn [_code, failed] ->
               String.starts_with?(failed, show(at))
             end)

      expected = Base.encode16(message, case: :lower)

      assert [%{"recomputed" => ^expected, "status" => "pass", "declared" => declared}] =
               trace_at(run, part)

      assert declared == signed["handover_signature"]
    end
  end

  describe "LINK_HEAD at a genesis /block (SPEC.md 10.3, D62)" do
    test "counts the /block height as 0, whatever it declares" do
      name = "item-genesis-witness"
      metadata = get(sound(name), ["witnesses", "block", "record", "metadata"])
      assert is_map(metadata["genesis"]) and metadata["key_event"]["type"] == "genesis"

      proof = put(sound(name), ["block", "record", "metadata"], metadata)
      assert get(proof, ["block", "record", "height"]) > 0

      # SHAPE and POLICY pass it, so a run reaches DERIVE with it.
      checked = run(name, proof) |> Shape.shape() |> Policy.policy()
      refute Run.failed?(checked)

      run = Derive.derive(checked)
      part = "/witnesses/block/record/height"
      head = Enum.filter(run.rows, &(&1.part == part and &1.values["construction"] == "height"))

      assert [%Row{status: :fail, code: :ordering_violation, values: values}] = head
      assert values["recomputed"] == 0
      assert values["declared"] == get(proof, ["witnesses", "block", "record", "height"])
      assert ["derivation_mismatch", "/block/record/height"] in failing(run)
    end
  end

  describe "the D58 cases for DERIVE" do
    test "each link fails at its moved part (item 11)" do
      assert_single_failures(
        %{
          "declared-observation_not_a_leaf" => "/block/record/merkle_root",
          "paths-node-commitments-bitcoin" => "/commitments/bitcoin/epoch/record/merkle_root",
          "declared-witness_hashes-block" => "/subject/record/witness_hashes/block",
          "declared-witness_hashes-entropy_nist" => "/subject/record/witness_hashes/entropy_nist",
          "bitcoin-op_return_other_value-commitments" => "/commitments/bitcoin/raw_transaction",
          "bitcoin-op_return_other_value-signing_key_event" =>
            "/signing_key_event/commitments/bitcoin/raw_transaction"
        },
        "derivation_mismatch"
      )

      assert_single_failures(
        %{
          "key_events-link_key_event" =>
            "/signing_key_event/block/record/metadata/key_event/public_key"
        },
        "key_event_mismatch"
      )

      assert_single_failures(
        %{
          "order-head-equal" => "/witnesses/block/record/height",
          "order-stellar_sequence_equal-subject" => "/subject/entropy/payload/sequence",
          "order-bitcoin_height_above-observation" =>
            "/observations/entropy_bitcoin/entropy/payload/height"
        },
        "ordering_violation"
      )
    end

    test "two OP_RETURN outputs and a malformed OP_RETURN script (packet C6)" do
      assert_single_failures(
        %{
          "bitcoin-raw_transaction_two_op_returns" => "/commitments/bitcoin/raw_transaction",
          "bitcoin-raw_transaction_op_return_pushdata" => "/commitments/bitcoin/raw_transaction"
        },
        "bitcoin_evidence_invalid"
      )
    end

    test "a record whose signing_key_id is not the key id of its event's public_key (packet C3)" do
      assert_single_failures(
        %{
          "key_events-signing_key_id-genesis-block" => "/block/record/signing_key_id",
          "key_events-signing_key_id-rotation-block" => "/block/record/signing_key_id",
          "key_events-signing_key_id-rotation-witnesses" =>
            "/witnesses/block/record/signing_key_id",
          "key_events-signing_key_id-genesis-signing_key_event" =>
            "/signing_key_event/block/record/signing_key_id"
        },
        "key_event_mismatch"
      )
    end

    test "a malformed structure gives no row that reads a value out of it (packet C2)" do
      name = "item"
      at = ["commitments", "bitcoin"]
      entry = get(sound(name), at)
      base = rows(derived(name))

      of = fn rows, member ->
        for [_c, part, _s] = row <- rows, part == show(at ++ [member]), do: row
      end

      # A byte after the lock time, with transaction_hash recomputed: the OP_RETURN row goes.
      raw = entry["raw_transaction"] <> "00"
      txid = raw |> Base.decode16!(case: :lower) |> Bitcoin.sha256d() |> Bitcoin.display()

      mutant =
        put(put(sound(name), at ++ ["raw_transaction"], raw), at ++ ["transaction_hash"], txid)

      tx_rows = rows(derived(name, mutant))

      assert of.(tx_rows, "raw_transaction") ==
               [["bitcoin_evidence_invalid", show(at ++ ["raw_transaction"]), "fail"]]

      assert of.(tx_rows, "transaction_hash") == [[nil, show(at ++ ["transaction_hash"]), "pass"]]
      assert length(tx_rows) == length(base) - 1

      # A byte after the merkleblock: the matched hash and the three header rows go.
      proof = put(sound(name), at ++ ["txoutproof"], entry["txoutproof"] <> "00")
      block_rows = rows(derived(name, proof))

      assert of.(block_rows, "txoutproof") ==
               [["bitcoin_evidence_invalid", show(at ++ ["txoutproof"]), "fail"]]

      for member <- ~w(header_hash header_merkle_root header_time),
          do: assert(of.(block_rows, member) == [])

      assert length(block_rows) == length(base) - 4
    end

    test "an OP_RETURN of another value fails at raw_transaction, beside a valid transaction_hash" do
      name = "block"
      at = ["signing_key_event", "commitments", "bitcoin"]
      entry = get(sound(name), at)
      epoch = entry["epoch"]["epoch_hash"]

      raw =
        String.replace(
          entry["raw_transaction"],
          "6a20" <> epoch,
          "6a20" <> String.duplicate("cd", 32)
        )

      assert raw != entry["raw_transaction"]
      txid = raw |> Base.decode16!(case: :lower) |> Bitcoin.sha256d() |> Bitcoin.display()

      proof =
        put(put(sound(name), at ++ ["raw_transaction"], raw), at ++ ["transaction_hash"], txid)

      # Of the transaction's checks only the OP_RETURN row fails, and the txoutproof's
      # matched hash no longer matches the transaction.
      assert failing(derived(name, proof)) == [
               ["derivation_mismatch", show(at ++ ["raw_transaction"])],
               ["derivation_mismatch", show(at ++ ["txoutproof"])]
             ]
    end
  end

  describe "a trace row's recomputed value (D58 item 7)" do
    test "is the record's leaf_count for a tree_size, and 0 for a genesis height" do
      run = derived("item-genesis-witness")
      [size] = trace_at(run, "/subject/inclusion_proof/tree_size")

      assert size["recomputed"] ==
               get(sound("item-genesis-witness"), ["block", "record", "leaf_count"])

      assert [%{"recomputed" => 0, "construction" => "genesis"}] =
               trace_at(run, "/witnesses/block/record/height")
    end

    test "is null when the walk gives no root" do
      q = ["subject", "inclusion_proof"]
      proof = put(sound("item"), q ++ ["leaf_index"], get(sound("item"), q ++ ["tree_size"]))
      run = derived("item", proof)

      assert [%{"recomputed" => nil, "status" => "fail"}] =
               trace_at(run, "/block/record/merkle_root")

      assert failing(run) == [["derivation_mismatch", "/block/record/merkle_root"]]
    end

    test "is the hex of the 32 octets a handover signature was verified over" do
      at = ["block", "record", "metadata", "key_event"]
      event = get(sound("block-rotation"), at)
      bytes = [<<0x62>>, JCS.encode(Map.delete(event, "handover_signature"))]
      expected = :sha256 |> :crypto.hash(bytes) |> Base.encode16(case: :lower)

      assert [%{"recomputed" => ^expected, "status" => "pass", "declared" => declared}] =
               trace_at(derived("block-rotation"), show(at ++ ["handover_signature"]))

      assert declared == event["handover_signature"]
    end
  end

  describe "the engine" do
    test "orders rows by part in document order, keeping the order of checks at one part" do
      for {name, _document} <- @positive do
        run = derived(name)
        parts = for [_code, part, _status] <- rows(run), do: part
        segments = Enum.map(parts, fn part -> part |> String.split("/") |> tl() end)
        assert segments == Pointer.sort_by(segments), name
      end

      # At one part: a genesis witness's height check before LINK_HEAD, a key's bytes before
      # LINK_KEY_EVENT, and each structure's well-formedness before what reads it.
      run = derived("item-genesis-witness")
      height = Enum.filter(run.rows, &(&1.part == "/witnesses/block/record/height"))
      assert Enum.map(height, & &1.values["construction"]) == ["genesis", "height"]

      public_key =
        for %Row{step: "DERIVE", part: "/signing_key_event" <> _ = part} = row <- run.rows,
            String.ends_with?(part, "/key_event/public_key"),
            do: row.status

      assert public_key == [:pass, :info]

      item = derived("item")

      for member <- ~w(raw_transaction txoutproof) do
        messages =
          for %Row{part: "/commitments/bitcoin/" <> ^member} = row <- item.rows, do: row.message

        assert [well_formed, _reads_it] = messages
        assert well_formed =~ "is well formed"
      end
    end

    test "gives a beacon's three walks to one root three trace rows, in the order of their proofs" do
      run = derived("beacon")
      roots = trace_at(run, "/block/record/merkle_root")

      assert Enum.map(roots, &hd(&1["inputs"])) == [
               "/observations/entropy_bitcoin/inclusion_proof",
               "/observations/entropy_nist/inclusion_proof",
               "/observations/entropy_stellar/inclusion_proof"
             ]
    end

    test "an ended run passes through with no trace" do
      ended =
        run("item", sound("item"))
        |> Run.add_row(Row.new("SIGNATURE", :signature_invalid, nil, "no"))
        |> Run.end_run()

      assert Derive.derive(ended) == ended
      assert ended.trace == [] and ended.external_gate == nil
    end
  end
end
