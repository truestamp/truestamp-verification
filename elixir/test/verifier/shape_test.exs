# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Truestamp.Verifier.ShapeTest do
  # Step 7, SHAPE (SPEC.md 10.2), on mutants of every sound value of P (the positive proofs
  # and the samples), beside the vectors' own cases in shape_policy_cases_test.exs:
  #
  # - the tracker's cases (D58, packet C4): a `\n` on any value of a pattern class in `proof`
  #   other than `environment`, and any optional member other than `environment` as null;
  # - the two empty-root mutants (5.4, D56) at each of /block, /witnesses/block and
  #   /signing_key_event/block;
  # - check 5's round trips at every TIME and NISTTIME value, check 4, check 6 in each mode,
  #   the order of the six checks, and what a pass and a failure do to the run;
  # - several failures at once, at check 3 (random mutants with two to four defects) and at
  #   check 5 (every pair of times), where the row is the first in document order;
  # - rules a sound value of P meets in only one way: the events allowed at
  #   /signing_key_event/block, a rotation's sequence, and a right-length value off its
  #   pattern class;
  # - what each row's values hold (SPEC.md 10.5): the run's own values, and a value P
  #   carries only under "declared", in a failing row;
  # - CONSTRUCTIONS_ACCEPTED against spec/constructions/, and that no other step reads the
  #   `constructions` member (7.2, and 10.6 rule 1).
  use ExUnit.Case, async: true

  alias Truestamp.Verifier.{Config, Constructions, JCS, Policy, Row, Run, Shape}
  alias Truestamp.Verifier.Test.{ProofMutants, Samples}

  @root Path.expand("../../..", __DIR__)
  @later ~w(POLICY DERIVE CHAIN SOURCES WINDOW EXPECTED_HASH)

  # A run past SIGNATURE, holding `proof` as P: SHAPE reads nothing else of it.
  defp run(proof) do
    config = Config.new!(environment: "test", keyring: :none)
    rows = for step <- ~w(CONFIGURATION READ PARSE ENVELOPE), do: Row.pass(step, nil, "held")

    %Run{
      config: config,
      keyring: nil,
      trust_root: %{digest: nil, kind: :none, location: nil},
      proof: proof,
      attribution: "unattributed",
      rows: rows
    }
  end

  defp shape_rows(proof), do: proof |> run() |> Shape.shape() |> Map.fetch!(:rows) |> Enum.drop(4)

  # The SHAPE row as [code, part, status].
  defp outcome(proof) do
    [row | _later] = shape_rows(proof)
    assert row.step == "SHAPE"
    [code, part, status, "SHAPE"] = Row.reduce(row)
    [code, part, status]
  end

  defp shape_row(proof) do
    [row | _later] = shape_rows(proof)
    row
  end

  defp fails_at(code, at), do: [Atom.to_string(code), ProofMutants.show(at), "fail"]
  defp passes, do: [nil, nil, "pass"]

  # Document order (SPEC.md 10.2), written here from the text: a prefix first, else the
  # first segment that differs, names by their code units (every name here is ASCII) and
  # indices by value.
  defp earlier?([], _b), do: true
  defp earlier?(_a, []), do: false
  defp earlier?([x | a], [x | b]), do: earlier?(a, b)
  defp earlier?([x | _a], [y | _b]), do: x < y

  defp first_in_document_order(pointers),
    do: Enum.reduce(pointers, &if(earlier?(&1, &2), do: &1, else: &2))

  @bases ProofMutants.bases()

  test "every sound value of P passes, and the samples cover every block position" do
    for {name, proof} <- @bases, do: assert(outcome(proof) == passes(), name)

    positions = @bases |> Map.values() |> Enum.flat_map(&ProofMutants.block_positions/1)

    assert Enum.uniq(positions) |> Enum.sort() == [
             ["block"],
             ["signing_key_event", "block"],
             ["witnesses", "block"]
           ]
  end

  describe "the tracker's cases (D58, packet C4)" do
    test "a \\n on any value of a pattern class in proof, other than environment" do
      mutants =
        for {name, proof} <- @bases,
            {at, mutant} <- ProofMutants.newline_mutants(proof),
            do: {name, at, mutant}

      assert length(mutants) > 1000

      for {name, at, mutant} <- mutants do
        expected =
          if at == ["format"],
            do: fails_at(:unsupported_format, at),
            else: fails_at(:shape_invalid, at)

        assert outcome(mutant) == expected, "#{name}: #{ProofMutants.show(at)}"
      end
    end

    test "the newline mutants reach every pattern class of SPEC.md 2.4 but ENV" do
      reached =
        for {_name, proof} <- @bases,
            {at, _mutant} <- ProofMutants.newline_mutants(proof),
            uniq: true,
            do: at |> Enum.reject(&is_integer/1) |> List.last()

      for member <- ~w(block_hash signing_key_id id raw_transaction txoutproof public_key
                        handover_signature header_time closed_at timeStamp outputValue reason
                        version network constructions format type source) do
        assert member in reached, member
      end

      refute "environment" in reached
    end

    test "any optional member other than environment as null" do
      mutants =
        for {name, proof} <- @bases,
            {at, mutant} <- ProofMutants.null_mutants(proof),
            do: {name, at, mutant}

      reached = mutants |> Enum.map(fn {_n, at, _m} -> List.last(at) end) |> Enum.uniq()

      for member <-
            ~w(constructions signing_key_event entropy_bitcoin entropy_nist entropy_stellar
                        bitcoin stellar key_event prerotation_commitment handover_signature) do
        assert member in reached, member
      end

      for {name, at, mutant} <- mutants do
        assert outcome(mutant) == fails_at(:shape_invalid, at),
               "#{name}: #{ProofMutants.show(at)}"
      end
    end
  end

  describe "the empty-root rule (SPEC.md 5.4)" do
    test "both mutants fail at the record's merkle_root, at every block position" do
      mutants =
        for {name, proof} <- @bases,
            {position, kind, mutant} <- ProofMutants.empty_root_mutants(proof),
            do: {name, position, kind, mutant}

      covered = for {_n, position, kind, _m} <- mutants, uniq: true, do: {position, kind}

      assert Enum.sort(covered) ==
               Enum.sort(
                 for position <- [
                       ["block"],
                       ["witnesses", "block"],
                       ["signing_key_event", "block"]
                     ],
                     kind <- [:leaves_under_empty_root, :no_leaves_under_real_root],
                     do: {position, kind}
               )

      for {name, position, kind, mutant} <- mutants do
        assert outcome(mutant) == fails_at(:shape_invalid, position ++ ~w(record merkle_root)),
               "#{name}: #{kind} at #{ProofMutants.show(position)}"
      end
    end

    test "an empty tree passes: leaf_count 0 under the empty root, at every block position" do
      empty =
        for {name, proof} <- @bases,
            position <- ProofMutants.block_positions(proof),
            ProofMutants.get(proof, position ++ ~w(record leaf_count)) == 0,
            do: {name, position, proof}

      for {name, position, proof} <- empty do
        assert ProofMutants.get(proof, position ++ ~w(record merkle_root)) ==
                 ProofMutants.empty_root(),
               name

        assert outcome(proof) == passes(), "#{name}: #{ProofMutants.show(position)}"
      end

      assert empty |> Enum.map(&elem(&1, 1)) |> Enum.uniq() |> Enum.sort() == [
               ["block"],
               ["signing_key_event", "block"],
               ["witnesses", "block"]
             ]
    end
  end

  describe "check 5, the TIME and NISTTIME round trips" do
    @bad [
      "T24:00:00",
      "-02-30T00:00:00",
      "T00:00:60",
      "1900-02-29T00:00:00",
      "2100-02-29T00:00:00"
    ]

    defp bad_time(value, class) do
      [date, _] = String.split(value, "T")
      [year | _] = String.split(date, "-")

      for bad <- @bad do
        text =
          cond do
            String.starts_with?(bad, "T") -> date <> bad
            String.starts_with?(bad, "-") -> year <> bad
            true -> bad
          end

        if class == :nisttime, do: text <> ".000Z", else: text <> "Z"
      end
    end

    test "each value that does not write back to itself fails at that value" do
      checked =
        for {name, proof} <- @bases,
            {at, class} <- ProofMutants.times(proof),
            text <- bad_time(ProofMutants.get(proof, at), class) do
          mutant = ProofMutants.put(proof, at, text)

          assert outcome(mutant) == fails_at(:shape_invalid, at),
                 "#{name}: #{text} at #{inspect(at)}"

          class_name = if class == :time, do: "TIME", else: "NISTTIME"
          assert shape_row(mutant).values == %{"class" => class_name, "declared" => text}

          {List.last(at), class}
        end

      assert Enum.sort(Enum.uniq(checked)) ==
               [{"closed_at", :time}, {"header_time", :time}, {"timeStamp", :nisttime}]
    end

    test "year 0000 is a leap year, so 0000-02-29 passes" do
      for {name, proof} <- @bases, {at, class} <- ProofMutants.times(proof) do
        text = if class == :time, do: "0000-02-29T00:00:00Z", else: "0000-02-29T00:00:00.000Z"
        assert outcome(ProofMutants.put(proof, at, text)) == passes(), name
      end
    end

    test "of any two, in any sound value of P, the first in document order is the row" do
      pairs =
        for {name, proof} <- @bases,
            times = ProofMutants.times(proof),
            {{a, class_a}, i} <- Enum.with_index(times),
            {b, class_b} <- Enum.drop(times, i + 1) do
          mutant =
            proof
            |> ProofMutants.put(a, "2026-02-30T00:00:00" <> suffix(class_a))
            |> ProofMutants.put(b, "2026-02-30T00:00:00" <> suffix(class_b))

          first = first_in_document_order([b, a])
          assert outcome(mutant) == fails_at(:shape_invalid, first), "#{name}: #{inspect([a, b])}"
          {hd(a), hd(b)}
        end

      # A beacon's /observations sorts between /commitments and /signing_key_event, so there
      # the order of the positions the layout lists is not document order.
      assert {"observations", "signing_key_event"} in pairs
    end

    defp suffix(:time), do: "Z"
    defp suffix(:nisttime), do: ".000Z"
  end

  describe "check 4, the witnesses of an item" do
    test "a witness missing, or one more than witness_hashes names, fails at /witnesses" do
      proof = @bases["positive item"]
      assert Map.has_key?(proof["witnesses"], "entropy_nist")

      missing = ProofMutants.delete(proof, ~w(witnesses entropy_nist))
      assert outcome(missing) == fails_at(:shape_invalid, ["witnesses"])

      extra = ProofMutants.delete(proof, ~w(subject record witness_hashes entropy_nist))
      assert outcome(extra) == fails_at(:shape_invalid, ["witnesses"])

      # The values name the rule, not the names the proof carries (SPEC.md 10.5).
      for mutant <- [missing, extra] do
        assert shape_row(mutant).values == %{"rule" => "witnesses_named_by_witness_hashes"}
      end
    end
  end

  describe "check 6, constructions (SPEC.md 7.2)" do
    setup do
      proof = @bases["positive item"]
      assert is_map(proof["constructions"])
      [digest] = Constructions.accepted()
      url = "https://www.truestamp.com/.well-known/constructions-#{digest}.json"
      %{proof: proof, digest: digest, url: url}
    end

    defp shape_values(proof) do
      [row | _] = shape_rows(proof)
      row.values
    end

    test "CONSTRUCTIONS_ACCEPTED is the digests of the files under spec/constructions/" do
      files = Path.wildcard(Path.join(@root, "spec/constructions/*"), match_dot: true)
      assert files != []

      for file <- files do
        digest = :sha256 |> :crypto.hash(File.read!(file)) |> Base.encode16(case: :lower)
        assert Path.basename(file) == digest <> ".json"
      end

      assert Constructions.accepted() ==
               files |> Enum.map(&Path.basename(&1, ".json")) |> Enum.sort()
    end

    test "each mode that names an accepted text, or none, passes", %{
      proof: p,
      digest: d,
      url: url
    } do
      # Full mode's d is computed, so the row gives it; a reference's d is the proof's, so a
      # pass does not (SPEC.md 10.5).
      assert shape_values(p) == %{"constructions" => "full", "constructions_digest" => d}
      assert shape_values(Map.put(p, "constructions", url)) == %{"constructions" => "reference"}
      assert shape_values(Map.delete(p, "constructions")) == %{"constructions" => "none"}

      for proof <- [p, Map.put(p, "constructions", url), Map.delete(p, "constructions")] do
        assert outcome(proof) == passes()
      end
    end

    test "a full text is checked byte for byte through JCS", %{proof: p} do
      text = p["constructions"]
      [name | _] = Map.keys(text)
      changed = Map.update!(text, name, &(&1 <> " "))

      assert outcome(Map.put(p, "constructions", changed)) ==
               fails_at(:construction_mismatch, ["constructions"])

      row = shape_row(Map.put(p, "constructions", changed))
      computed = :sha256 |> :crypto.hash(JCS.encode(changed)) |> Base.encode16(case: :lower)
      assert row.values == %{"constructions" => "full", "constructions_digest" => computed}
      assert row.message =~ "carries a constructions text"

      assert outcome(Map.put(p, "constructions", Map.delete(text, name))) ==
               fails_at(:construction_mismatch, ["constructions"])

      # Member order is not a byte of the text: JCS sorts it.
      reordered = text |> Enum.reverse() |> Map.new()
      assert JCS.encode(reordered) == JCS.encode(text)
      assert outcome(Map.put(p, "constructions", reordered)) == passes()
    end

    test "a reference to a text not accepted fails construction_mismatch", %{proof: p} do
      other = Samples.hex64("other")
      url = "https://www.truestamp.com/.well-known/constructions-#{other}.json"
      mutant = Map.put(p, "constructions", url)

      assert outcome(mutant) == fails_at(:construction_mismatch, ["constructions"])

      # The URL's d is the proof's, so it is marked as declared, and the message speaks of a
      # reference: the proof carries no text.
      row = shape_row(mutant)
      assert row.values == %{"constructions" => "reference", "declared" => other}
      assert row.message =~ "names by reference a constructions text"
      refute row.message =~ "carries"
    end

    test "any other value fails shape_invalid at check 3", %{proof: p, url: url} do
      for value <- [
            nil,
            1,
            [],
            true,
            String.replace(url, "www.truestamp.com", "truestamp.com"),
            String.upcase(url),
            url <> "\n",
            "http" <> String.trim_leading(url, "https")
          ] do
        assert outcome(Map.put(p, "constructions", value)) ==
                 fails_at(:shape_invalid, ["constructions"]),
               inspect(value)
      end
    end

    test "no module of the verifier but Shape reads the member" do
      files = Path.wildcard(Path.join(@root, "elixir/lib/**/*.ex"))
      assert Path.join(@root, "elixir/lib/truestamp/verifier/shape.ex") in files

      readers =
        for file <- files,
            line <- String.split(File.read!(file), "\n"),
            String.contains?(line, ~s("constructions")),
            not String.contains?(line, ~s|SpecFile.path("constructions")|),
            uniq: true,
            do: Path.basename(file)

      assert readers == ["shape.ex"]
    end

    test "after SHAPE, POLICY gives the same rows whatever the member holds", %{
      proof: p,
      url: url
    } do
      shaped = p |> run() |> Shape.shape()

      rows =
        for value <- [p["constructions"], url, :not_json, nil] do
          %{shaped | proof: Map.put(p, "constructions", value)}
          |> Policy.policy()
          |> Map.fetch!(:rows)
        end

      assert rows |> Enum.uniq() |> length() == 1

      assert %{shaped | proof: Map.delete(p, "constructions")}
             |> Policy.policy()
             |> Map.fetch!(:rows) == hd(rows)
    end
  end

  describe "several failures at check 3 (SPEC.md 10.2, step 7)" do
    # Each generic defect of ProofMutants.defects/1 alone fails first at its own pointer. A
    # mutant here carries two to four of them, at pointers none of which holds another, and
    # its row is at the one that comes first in document order, whichever order the schema
    # meets them in. Defects to `format` and `version` are left out, since they are checks 1
    # and 2, and so are defects to a `type`, the proof's or a key event's, since it chooses
    # the members its object is held to, and so whether a second defect there is one.
    @draws 1500

    defp combinable(proof) do
      for {_about, at, mutant} <- ProofMutants.defects(proof),
          hd(at) not in ~w(format version),
          List.last(at) != "type",
          do: {at, change(at, mutant)}
    end

    # The defect as a change to apply to any value of P: the mutant's value at the pointer,
    # or, where the mutant lacks the member, its deletion.
    defp change(at, mutant) do
      {parent, [last]} = Enum.split(at, -1)

      case ProofMutants.get(mutant, parent) do
        %{^last => value} -> &ProofMutants.put(&1, at, value)
        list when is_list(list) -> &ProofMutants.put(&1, at, Enum.at(list, last))
        %{} -> &ProofMutants.delete(&1, at)
      end
    end

    defp disjoint?(chosen, at),
      do:
        not Enum.any?(chosen, fn {other, _change} -> prefix?(other, at) or prefix?(at, other) end)

    defp prefix?(a, b), do: List.starts_with?(b, a)

    defp draw(defects, count) do
      Enum.reduce_while(Enum.shuffle(defects), [], fn {at, _change} = defect, chosen ->
        chosen = if disjoint?(chosen, at), do: [defect | chosen], else: chosen
        if length(chosen) == count, do: {:halt, chosen}, else: {:cont, chosen}
      end)
    end

    test "the row is at the defect that comes first in document order" do
      :rand.seed(:exsss, {73, 82, 2026})

      bases =
        @bases
        |> Enum.sort()
        |> Enum.map(fn {name, proof} -> {name, proof, combinable(proof)} end)

      drawn =
        for _draw <- 1..@draws do
          {name, proof, defects} = Enum.random(bases)
          chosen = draw(defects, Enum.random(2..4))
          mutant = Enum.reduce(chosen, proof, fn {_at, change}, p -> change.(p) end)
          pointers = Enum.map(chosen, &elem(&1, 0))
          first = first_in_document_order(pointers)

          assert outcome(mutant) == fails_at(:shape_invalid, first),
                 "#{name}: #{inspect(Enum.map(pointers, &ProofMutants.show/1))}"

          length(chosen)
        end

      assert drawn |> Enum.uniq() |> Enum.sort() == [2, 3, 4]
    end
  end

  describe "rules a sound value of P meets in only one way" do
    setup do
      %{proof: @bases["positive item"]}
    end

    test "a prerotation or revocation event at /signing_key_event/block fails at its type", %{
      proof: p
    } do
      event = ~w(signing_key_event block record metadata key_event)
      assert ProofMutants.get(p, event ++ ["type"]) == "rotation"

      for {name, other} <- [
            {"item prerotation at /block", "prerotation"},
            {"item revocation at /block", "revocation"}
          ] do
        replacement =
          ProofMutants.get(@bases["sample " <> name], ~w(block record metadata key_event))

        assert replacement["type"] == other
        mutant = ProofMutants.put(p, event, replacement)
        assert outcome(mutant) == fails_at(:shape_invalid, event ++ ["type"]), other
      end
    end

    test "a rotation or emergency rotation of sequence 0 fails at the sequence" do
      at = ~w(block record metadata key_event sequence)

      for name <- ["positive block-rotation", "positive block-emergency-rotation"] do
        assert ProofMutants.get(@bases[name], at) >= 1, name

        assert outcome(ProofMutants.put(@bases[name], at, 0)) == fails_at(:shape_invalid, at),
               name
      end
    end

    # A value of the right length that breaks its pattern class only by a character.
    test "a right-length value off its pattern class fails at the value", %{proof: p} do
      event = ~w(signing_key_event block record metadata key_event)
      nist = ~w(witnesses entropy_nist payload pulse)

      cases = [
        {~w(block record signing_key_id), ["ABCDEF01", "zzzzzzzz"]},
        {nist ++ ["outputValue"],
         [&String.downcase/1, &String.duplicate("G", String.length(&1))]},
        {nist ++ ["version"], [~s(a"b), "a\\b", "ré"]},
        {event ++ ["public_key"], [&last_character(&1, "B")]},
        {event ++ ["previous_public_key"], [&last_character(&1, "B")]},
        {event ++ ["handover_signature"], [&last_character(&1, "B")]}
      ]

      for {at, bad_values} <- cases, bad <- bad_values do
        value = ProofMutants.get(p, at)
        assert is_binary(value), ProofMutants.show(at)
        bad = if is_function(bad), do: bad.(value), else: bad
        assert String.length(bad) == String.length(value) or List.last(at) == "version"
        assert outcome(ProofMutants.put(p, at, bad)) == fails_at(:shape_invalid, at), bad
      end
    end

    # The last character of B64U32 and B64U64 carries only the bits it may (SPEC.md 2.4):
    # a B there sets a bit that decoding would drop.
    defp last_character(value, last), do: String.slice(value, 0..-2//1) <> last

    test "a time off its pattern fails at check 3, before check 4's /witnesses", %{proof: p} do
      extra = ProofMutants.delete(p, ~w(subject record witness_hashes entropy_stellar))
      assert outcome(extra) == fails_at(:shape_invalid, ["witnesses"])

      for {at, text} <- [
            {~w(commitments bitcoin header_time), "2026-01-01 00:00:00Z"},
            {~w(witnesses entropy_nist payload pulse timeStamp), "2026-01-01 00:00:00.000Z"}
          ] do
        assert is_binary(ProofMutants.get(p, at))
        assert outcome(ProofMutants.put(extra, at, text)) == fails_at(:shape_invalid, at)
      end
    end
  end

  describe "the order of the checks" do
    setup do
      %{proof: @bases["positive item"]}
    end

    test "each check's failure hides the later checks' failures", %{proof: p} do
      bad_schema = put_in(p, ~w(block record height), -1)
      bad_witnesses = ProofMutants.delete(p, ~w(witnesses entropy_nist))
      [{time_at, _} | _] = ProofMutants.times(p)
      bad_time = &ProofMutants.put(&1, time_at, "2026-02-30T00:00:00Z")
      bad_text = &Map.put(&1, "constructions", %{"x" => "y"})

      all =
        p
        |> Map.put("format", "x")
        |> Map.put("version", 2)
        |> then(&put_in(&1, ~w(block record height), -1))

      assert outcome(all) == fails_at(:unsupported_format, ["format"])

      assert outcome(Map.put(bad_schema, "version", 2)) ==
               fails_at(:unsupported_version, ["version"])

      assert outcome(ProofMutants.delete(bad_schema, ~w(witnesses entropy_nist))) ==
               fails_at(:shape_invalid, ~w(block record height))

      assert outcome(bad_time.(bad_witnesses)) == fails_at(:shape_invalid, ["witnesses"])
      assert outcome(bad_text.(bad_time.(p))) == fails_at(:shape_invalid, time_at)
      assert outcome(bad_text.(p)) == fails_at(:construction_mismatch, ["constructions"])
    end

    test "a missing format or version is that check's failure", %{proof: p} do
      assert outcome(Map.delete(p, "format")) == fails_at(:unsupported_format, ["format"])
      assert outcome(Map.delete(p, "version")) == fails_at(:unsupported_version, ["version"])
      assert outcome(Map.put(p, "version", "1")) == fails_at(:unsupported_version, ["version"])

      # An absent member carries no value to declare; a null one declares null, so the two
      # rows differ.
      assert shape_row(Map.delete(p, "format")).values == %{}
      assert shape_row(Map.delete(p, "version")).values == %{}
      assert shape_row(Map.put(p, "format", nil)).values == %{"declared" => nil}
      assert shape_row(Map.put(p, "version", nil)).values == %{"declared" => nil}
    end
  end

  describe "the run" do
    test "a pass gives one row, part null, and the proof's type and subject id" do
      for {name, proof} <- @bases do
        shaped = proof |> run() |> Shape.shape()
        refute shaped.ended
        assert [%Row{step: "SHAPE", status: :pass, part: nil}] = Enum.drop(shaped.rows, 4), name
        assert shaped.type == proof["type"]

        expected =
          if proof["type"] in ~w(block beacon),
            do: proof["block"]["record"]["id"],
            else: proof["subject"]["record"]["id"]

        assert shaped.subject_id == expected

        # The report takes the type and subject id from the run; the row does not copy them.
        values = hd(Enum.drop(shaped.rows, 4)).values
        assert is_binary(JCS.encode(values))
        assert Map.keys(values) -- ["constructions", "constructions_digest"] == [], name
      end
    end

    test "a failure ends the run, a skip prior_failure for each later step" do
      shaped = @bases["positive item"] |> Map.put("version", 2) |> run() |> Shape.shape()
      assert shaped.ended
      assert shaped.attribution == "unattributed"
      assert shaped.type == nil and shaped.subject_id == nil

      assert Enum.map(Enum.drop(shaped.rows, 5), &Row.reduce/1) ==
               for(step <- @later, do: ["prior_failure", nil, "skip", step])

      assert is_binary(JCS.encode(Enum.at(shaped.rows, 4).values))
    end

    test "an ended run passes through" do
      ended = @bases["positive item"] |> run() |> Map.put(:ended, true)
      assert Shape.shape(ended) == ended
    end
  end
end
