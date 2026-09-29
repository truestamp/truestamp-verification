# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Truestamp.Verifier.DeriveCasesTest do
  # Steps 0 to 9 (SPEC.md 10.2), through Truestamp.Verifier.run/2, over every offline case of
  # vectors/cases.json, one test per case, by where the case is decided (Cases.derive_class/1):
  #
  # - :bare, a bare rejection at steps 0 to 3: no run, so nothing of DERIVE;
  # - :gate and :shape, a run that ended before DERIVE: its one DERIVE row is
  #   `skip prior_failure` with part null, as the case expects, the run has no trace, and its
  #   external gate is undecided;
  # - :policy, :derive and :passes, every other case: exactly the expected rows of steps 0
  #   to 9, DERIVE's included, in order (the later steps' rows are
  #   verdict_cases_test.exs's); the external gate `:prior_failure` exactly when a row so
  #   far fails (10.2); for a case that gives a trace, exactly that trace, `inputs`
  #   included (13.1 compares every member but `inputs`, and these match too).
  #
  # In every case with DERIVE rows, the trace is checked against the rows and against
  # spec/value-classes.json (10.6): one trace row for each DERIVE row whose part is CHECKED,
  # other than LINK_HEAD's, in the same order and with the same status, its declared value
  # the value P carries at its part; and each DERIVE row's values are what 10.5 and 10.2
  # step 9 allow, each from where it has to come:
  #
  # - a failing row paired with its trace row (the rows and trace rows of one {part,
  #   construction}, in order) gives that trace row's declared and recomputed values, and a
  #   derivation_mismatch row two values that differ;
  # - an untraced link row gives as declared P's value at its part, and as recomputed the
  #   counted /block height (LINK_HEAD), the top-level Stellar ledger or Bitcoin height
  #   (LINK_CHAIN_ORDER), or the envelope's public key (LINK_KEY_EVENT);
  # - a failing row's declared value is P's value at its part, except the OP_RETURN row's
  #   and the matched hash's, which are the 32 bytes read out of `raw_transaction` or
  #   `txoutproof` (10.2 step 9 (d)), and whose recomputed values are the epoch_hash and the
  #   transaction hash the trace recomputed;
  # - a `refused` value is one of the Ed25519 module's refusals, and a `rule` one of the
  #   rules of SPEC.md 13.2's `fails` names for a raw_transaction, or of the merkleblock's;
  # - every DERIVE row's values, and every trace row, write as JCS.
  use ExUnit.Case, async: true

  alias Truestamp.Verifier
  alias Truestamp.Verifier.Bitcoin.MerkleBlock
  alias Truestamp.Verifier.{Ed25519, JCS, Parser, Pointer, Row, Run}
  alias Truestamp.Verifier.Test.{Cases, StrictJSON, ValueClasses}

  @external_resource Cases.path()

  @through_derive ~w(CONFIGURATION READ PARSE ENVELOPE ENVIRONMENT KEY_BINDING SIGNATURE SHAPE
                     POLICY DERIVE)

  # The row names of the constructions text (SPEC.md 7.3) a DERIVE row may give.
  @constructions ~w(bitcoin block_hash chain_order claims_hash entropy_hash epoch_hash genesis
                    handover height inclusion item_hash key_event observation_hash witnesses)

  @offline Cases.offline()

  @spec_md Path.expand("../SPEC.md", Cases.vectors())
  @external_resource @spec_md

  # The rules SPEC.md 13.2 names for the `fails` of a raw_transaction, read once.
  spec_text = @spec_md |> File.read!() |> String.replace(~r/\s+/, " ")

  [_whole | rules] =
    Regex.run(
      ~r/first rule of a well-formed `raw_transaction` it breaks: `(\w+)`, `(\w+)` or `(\w+)`/,
      spec_text
    )

  @transaction_rules rules

  defp run(kase), do: Verifier.run(Cases.config(kase), Cases.proof(kase))

  # P and the envelope's signature, as the case's bytes hold them.
  defp document(kase) do
    {:ok, %{"proof" => proof, "signature" => signature}} = Parser.decode(Cases.proof(kase))
    {proof, signature}
  end

  defp through_derive(rows), do: Enum.filter(rows, &(List.last(&1) in @through_derive))

  defp derive_rows(%Run{rows: rows}), do: Enum.filter(rows, &(&1.step == "DERIVE"))

  defp segments(part), do: part |> String.split("/") |> tl() |> Enum.map(&unescape/1)
  defp unescape(segment), do: segment |> String.replace("~1", "/") |> String.replace("~0", "~")

  defp get(value, []), do: value
  defp get(value, [name | rest]) when is_map(value), do: get(Map.get(value, name), rest)

  defp get(value, [index | rest]) when is_list(value),
    do: get(Enum.at(value, String.to_integer(index)), rest)

  # The trace 10.6 asks for, from the rows and the published value classes: a row for each
  # DERIVE row whose part is CHECKED, but LINK_HEAD's (the one row named `height`).
  defp expected_trace(run, proof) do
    for row <- derive_rows(run),
        row.part != nil,
        ValueClasses.checked?(proof, segments(row.part)),
        row.values["construction"] != "height",
        do: {row.part, Atom.to_string(row.status)}
  end

  # What a DERIVE row's values may hold (10.5, and 10.2 step 9): its constructions row, and
  # when it fails, the declared value and what it was compared with, or the rule a structure
  # breaks, or the step of 6.2 that refused a key or a signature.
  defp values_allowed?(%Row{status: status, values: values}) when status in [:pass, :info],
    do: Map.keys(values) == ["construction"] and values["construction"] in @constructions

  defp values_allowed?(%Row{status: :fail, values: values} = row) do
    names = values |> Map.keys() |> Enum.sort()

    values["construction"] in @constructions and
      names in [
        ~w(construction declared recomputed),
        ~w(construction rule),
        ~w(construction declared refused),
        ~w(construction declared recomputed refused)
      ] and declared_allowed?(row, values)
  end

  defp values_allowed?(_row), do: false

  defp declared_allowed?(%Row{part: part, code: code}, values) do
    cond do
      code == :bitcoin_evidence_invalid ->
        values["rule"] in ~w(parse length op_return total_txs partial_tree duplicate_pair
                             matches merkle_root target)

      String.ends_with?(part, ["/raw_transaction", "/txoutproof"]) ->
        values["declared"] =~ ~r/\A[0-9a-f]{64}\z/

      true ->
        true
    end
  end

  test "the offline cases fall in every class, and DERIVE fails in some of each code" do
    classes = Enum.frequencies_by(@offline, &Cases.derive_class/1)

    assert classes |> Map.keys() |> Enum.sort() ==
             [:bare, :derive, :gate, :passes, :policy, :shape]

    codes =
      for kase <- @offline,
          [code, _part, "fail", "DERIVE"] <- kase["expected"]["rows"] || [],
          uniq: true,
          do: code

    assert Enum.sort(codes) ==
             ~w(bitcoin_evidence_invalid derivation_mismatch key_event_mismatch
                ordering_violation)
  end

  test "every sound proof under vectors/positive/ has an offline case that gives its trace" do
    traces = for kase <- @offline, trace = kase["expected"]["trace"], uniq: true, do: trace
    files = Path.wildcard(Path.join(Cases.vectors(), "positive/*.trace.json"))
    assert Enum.sort(traces) == Enum.sort(Enum.map(files, &Path.relative_to(&1, Cases.vectors())))
  end

  for kase <- @offline, class = Cases.derive_class(kase) do
    @kase kase

    case class do
      :bare ->
        test "#{kase["id"]}: a bare rejection, so no DERIVE" do
          assert {:rejected, _rejection} = run(@kase)
        end

      ended when ended in [:gate, :shape] ->
        test "#{kase["id"]}: ended at #{ended}, DERIVE skipped" do
          assert {:ok, run} = run(@kase)
          assert Enum.map(run.rows, &Row.reduce/1) == @kase["expected"]["rows"]
          assert [%Row{code: :prior_failure, part: nil}] = derive_rows(run)
          assert run.trace == [] and run.external_gate == nil
        end

      open ->
        test "#{kase["id"]}: #{open}, the rows of steps 0 to 9 and the trace" do
          assert {:ok, run} = run(@kase)
          run = %{run | rows: Enum.filter(run.rows, &(&1.step in @through_derive))}
          {proof, signature} = document(@kase)
          expected = through_derive(@kase["expected"]["rows"])

          assert Enum.map(run.rows, &Row.reduce/1) == expected
          assert expected |> Enum.map(&List.last/1) |> Enum.uniq() == @through_derive
          refute run.ended
          assert Run.failed?(run) == (unquote(open) != :passes)
          assert run.external_gate == if(Run.failed?(run), do: :prior_failure, else: :offline)

          if path = @kase["expected"]["trace"] do
            assert run.trace == StrictJSON.read_data!(Path.join(Cases.vectors(), path))
          end

          assert Enum.map(run.trace, &{&1["part"], &1["status"]}) ==
                   expected_trace(run, proof)

          for row <- run.trace do
            assert row["declared"] == get(proof, segments(row["part"])), row["part"]
            assert Enum.all?(row["inputs"], &(get(proof, segments(&1)) != nil)), row["part"]
            assert row["inputs"] == Enum.sort(row["inputs"], &inputs_order/2)
          end

          assert Enum.all?(derive_rows(run), &values_allowed?/1),
                 inspect(Enum.reject(derive_rows(run), &values_allowed?/1))

          assert_failing_values(run, proof, signature)
          assert unsourced(run, proof, signature) == []
          assert Enum.all?(derive_rows(run), &is_binary(JCS.encode(&1.values)))
          assert Enum.all?(run.trace, &is_binary(JCS.encode(&1)))
        end
    end
  end

  defp inputs_order(a, b), do: Pointer.before_or_same?(segments(a), segments(b))

  # The names a failing row may give under `refused` and `rule`: the Ed25519 module's
  # refusals (SPEC.md 6.2 numbers its steps and names none); for a raw_transaction, the rules
  # SPEC.md 13.2 names for the corpus's `fails`; for a txoutproof, the merkleblock's.
  defp refusals, do: type_atoms(Ed25519, :refusal)
  defp merkle_block_rules, do: type_atoms(MerkleBlock, :rule)

  defp transaction_rules, do: @transaction_rules

  defp type_atoms(module, name) do
    {:ok, types} = Code.Typespec.fetch_types(module)
    specs = for {_kind, {type, ast, []}} <- types, into: %{}, do: {type, ast}
    specs |> Map.fetch!(name) |> atoms(specs) |> Enum.map(&Atom.to_string/1)
  end

  defp atoms({:type, _line, :union, members}, specs),
    do: Enum.flat_map(members, &atoms(&1, specs))

  defp atoms({:atom, _line, atom}, _specs), do: [atom]
  defp atoms({:user_type, _line, name, []}, specs), do: atoms(Map.fetch!(specs, name), specs)

  # Every DERIVE row, a failing one paired with its failing trace row: the rows and trace
  # rows of one {part, construction}, in order. A row with no trace row pairs with nil.
  defp paired(run) do
    traces =
      run.trace
      |> Enum.filter(&(&1["status"] == "fail"))
      |> Enum.group_by(&{&1["part"], &1["construction"]})

    {pairs, left} =
      Enum.map_reduce(derive_rows(run), traces, fn row, left ->
        key = {row.part, row.values["construction"]}

        case {row.status, Map.get(left, key, [])} do
          {:fail, [trace | rest]} -> {{row, trace}, Map.put(left, key, rest)}
          _untraced -> {{row, nil}, left}
        end
      end)

    assert Enum.all?(Map.values(left), &(&1 == [])), inspect(left)
    pairs
  end

  # The OP_RETURN row and the row of the matched hash: their declared value is read out of
  # the part (10.2 step 9 (d)).
  defp read_out?(%Row{code: :derivation_mismatch, part: part}),
    do: String.ends_with?(part, ["/raw_transaction", "/txoutproof"])

  defp read_out?(_row), do: false

  defp link_key_event?(%Row{part: part, values: values}) do
    values["construction"] == "key_event" and String.starts_with?(part, "/signing_key_event/") and
      String.ends_with?(part, "/key_event/public_key") and not Map.has_key?(values, "refused")
  end

  defp counted_height(record),
    do: if(is_map(record["metadata"]["genesis"]), do: 0, else: record["height"])

  defp trace_recomputed(run, part) do
    [%{"recomputed" => recomputed}] = Enum.filter(run.trace, &(&1["part"] == part))
    recomputed
  end

  # What a failing row's `recomputed` has to be, or :none where it gives none.
  defp recomputed_source(_run, _proof, _signature, _row, %{"recomputed" => recomputed}),
    do: {:ok, recomputed}

  defp recomputed_source(run, proof, signature, %Row{part: part} = row, nil) do
    entry = part |> String.split("/") |> Enum.drop(-1) |> Enum.join("/")

    case untraced_kind(row) do
      :head -> {:ok, counted_height(proof["block"]["record"])}
      :stellar_order -> {:ok, proof["commitments"]["stellar"]["ledger"]}
      :bitcoin_order -> {:ok, proof["commitments"]["bitcoin"]["height"]}
      :link_key_event -> {:ok, signature["public_key"]}
      :op_return -> {:ok, trace_recomputed(run, entry <> "/epoch/epoch_hash")}
      :matched_hash -> {:ok, trace_recomputed(run, entry <> "/transaction_hash")}
      {:unknown, _part} -> :none
    end
  end

  # Whether a failing row's `declared` is the value it has to be.
  defp declared_sourced?(proof, %Row{part: part} = row, declared) do
    carried = get(proof, segments(part))

    cond do
      not read_out?(row) -> declared === carried
      not (is_binary(declared) and declared =~ ~r/\A[0-9a-f]{64}\z/) -> false
      String.ends_with?(part, "/raw_transaction") -> String.contains?(carried, "6a20" <> declared)
      true -> String.contains?(carried, reverse_hex(declared))
    end
  end

  defp reverse_hex(hex),
    do:
      hex
      |> Base.decode16!(case: :lower)
      |> :binary.bin_to_list()
      |> Enum.reverse()
      |> :binary.list_to_bin()
      |> Base.encode16(case: :lower)

  # The values of DERIVE rows that do not come from where 10.5 and 10.2 step 9 say, as
  # {part, name, value}; empty when every one does.
  defp unsourced(run, proof, signature) do
    for {row, trace} <- paired(run),
        name <- row.values |> Map.keys() |> Enum.sort(),
        value = row.values[name],
        not sourced?(name, value, {run, proof, signature}, row, trace),
        do: {row.part, name, value}
  end

  defp sourced?("construction", value, _sources, _row, _trace), do: value in @constructions

  defp sourced?("declared", value, {_run, proof, _signature}, row, _trace),
    do: row.status == :fail and declared_sourced?(proof, row, value)

  defp sourced?("recomputed", value, {run, proof, signature}, row, trace),
    do:
      row.status == :fail and recomputed_source(run, proof, signature, row, trace) == {:ok, value}

  defp sourced?("refused", value, _sources, row, _trace),
    do: row.status == :fail and value in refusals()

  defp sourced?("rule", value, _sources, %Row{code: :bitcoin_evidence_invalid} = row, _trace) do
    if String.ends_with?(row.part, "/raw_transaction"),
      do: value in transaction_rules(),
      else: value in merkle_block_rules()
  end

  defp sourced?(_name, _value, _sources, _row, _trace), do: false

  # The values of each failing DERIVE row, against its trace row or its check's source.
  defp assert_failing_values(run, proof, signature) do
    for {%Row{status: :fail} = row, trace} <- paired(run) do
      at = "#{row.part} #{row.values["construction"]}"

      if trace do
        assert row.values["declared"] == trace["declared"], at
        assert Map.fetch(row.values, "recomputed") == {:ok, trace["recomputed"]}, at
      end

      if row.code == :derivation_mismatch,
        do: assert(row.values["declared"] != row.values["recomputed"], at)

      unless Map.has_key?(row.values, "rule") or
               (Map.has_key?(row.values, "refused") and not Map.has_key?(row.values, "recomputed")) do
        source = recomputed_source(run, proof, signature, row, trace)
        assert source != :none, at
        assert Map.fetch(row.values, "recomputed") == source, at
        assert declared_sourced?(proof, row, row.values["declared"]), at
      end
    end
  end

  describe "the values of failing DERIVE rows" do
    test "the cases reach every kind of failing row whose values are checked" do
      kinds =
        for kase <- @offline,
            Cases.derive_class(kase) == :derive,
            {:ok, run} = run(kase),
            {%Row{status: :fail} = row, trace} <- paired(run),
            uniq: true,
            do: kind(row, trace)

      assert Enum.sort(kinds) ==
               Enum.sort([
                 :traced,
                 :head,
                 :stellar_order,
                 :bitcoin_order,
                 :link_key_event,
                 :op_return,
                 :matched_hash,
                 :key_bytes,
                 :rule
               ])
    end

    test "name the refusal and the rule: each case's, and the names SPEC.md and Ed25519 give" do
      assert Enum.sort(refusals()) ==
               ~w(equation not_on_curve s_not_below_l small_order_key y_not_below_p)

      assert transaction_rules() == ~w(parse length op_return)

      corpus =
        for file <- Path.wildcard(Path.join(Cases.vectors(), "corpus/bitcoin/*.json")),
            fails = StrictJSON.read_data!(file)["expected"]["fails"],
            uniq: true,
            do: fails

      assert corpus != [] and corpus -- transaction_rules() == []

      expected = %{
        "key_events-identity_previous_public_key-block" =>
          {"/block/record/metadata/key_event/handover_signature", "refused", "small_order_key"},
        "key_events-public_key_small_order-block" =>
          {"/block/record/metadata/key_event/public_key", "refused", "small_order_key"},
        "key_events-handover_signature-block" =>
          {"/block/record/metadata/key_event/handover_signature", "refused", "equation"},
        "bitcoin-raw_transaction_64_octets" =>
          {"/commitments/bitcoin/raw_transaction", "rule", "length"},
        "bitcoin-raw_transaction_two_op_returns" =>
          {"/commitments/bitcoin/raw_transaction", "rule", "op_return"},
        "bitcoin-raw_transaction_trailing_bytes-commitments" =>
          {"/commitments/bitcoin/raw_transaction", "rule", "parse"},
        "bitcoin-txoutproof_duplicate_pair" =>
          {"/commitments/bitcoin/txoutproof", "rule", "duplicate_pair"},
        "bitcoin-txoutproof_header_above_target" =>
          {"/commitments/bitcoin/txoutproof", "rule", "target"}
      }

      cases = Map.new(@offline, &{&1["id"], &1})

      for {id, {part, name, value}} <- expected do
        {:ok, run} = run(Map.fetch!(cases, id))
        named = for %Row{part: ^part, status: :fail} = row <- run.rows, do: row.values[name]
        assert value in named, "#{id}: #{inspect(named)}"
      end
    end
  end

  # What kind of failing row this is, for the test that the cases reach every kind.
  defp kind(_row, trace) when trace != nil, do: :traced
  defp kind(%Row{values: %{"rule" => _rule}}, nil), do: :rule
  defp kind(%Row{values: %{"refused" => _refused}}, nil), do: :key_bytes
  defp kind(row, nil), do: untraced_kind(row)

  # An untraced row that compares two values: a link row, or a Bitcoin read-out row.
  defp untraced_kind(%Row{part: part, values: values} = row) do
    cond do
      values["construction"] == "height" ->
        :head

      values["construction"] == "chain_order" ->
        if String.ends_with?(part, "/sequence"), do: :stellar_order, else: :bitcoin_order

      link_key_event?(row) ->
        :link_key_event

      read_out?(row) ->
        if String.ends_with?(part, "/raw_transaction"), do: :op_return, else: :matched_hash

      true ->
        {:unknown, part}
    end
  end
end
