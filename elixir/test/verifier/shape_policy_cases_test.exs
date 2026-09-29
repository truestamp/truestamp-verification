# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Truestamp.Verifier.ShapePolicyCasesTest do
  # Steps 0 to 8 (SPEC.md 10.2), through Truestamp.Verifier.run/2 and run_file/2, over every
  # offline case of vectors/cases.json, one test per case, by where the case is decided:
  #
  # - :bare, a bare rejection at steps 0 to 3: exactly its code and sub_reason;
  # - :gate, a failure at steps 4 to 6, and :shape, a failure at SHAPE: every expected row,
  #   SHAPE's and POLICY's included, and the `skip prior_failure` rows of every later step
  #   up to EXPECTED_HASH, since the run ends there;
  # - :policy, a failure at POLICY, and :later, every other case: exactly the expected rows
  #   of steps 0 to 8, with the run still open after POLICY and the proof's type and subject
  #   id taken at SHAPE. DERIVE's rows, which follow, are derive_cases_test.exs's.
  #
  # In every case with a report, each value of every row of steps 0 to 8 is one the run
  # computed or holds, and a value the proof carries appears only under "declared", in a
  # failing row (10.5).
  #
  # Online cases are not the reference verifier's (13.1), so none runs here.
  use ExUnit.Case, async: true

  alias Truestamp.Verifier
  alias Truestamp.Verifier.{Base64url, JCS, KeyId, Parser, RecordHash, Rejection, Row, Run}
  alias Truestamp.Verifier.Schema
  alias Truestamp.Verifier.Test.Cases

  @external_resource Cases.path()

  @through_policy ~w(CONFIGURATION READ PARSE ENVELOPE ENVIRONMENT KEY_BINDING SIGNATURE SHAPE
                     POLICY)

  @offline Cases.offline()

  defp run(kase) do
    config = Cases.config(kase)
    by_bytes = Verifier.run(config, Cases.proof(kase))
    assert Verifier.run_file(config, Path.join(Cases.vectors(), kase["proof"])) == by_bytes
    by_bytes
  end

  defp reduced(%Run{rows: rows}), do: Enum.map(rows, &Row.reduce/1)
  defp values_written?(%Run{rows: rows}), do: Enum.all?(rows, &is_binary(JCS.encode(&1.values)))

  # The rows of steps 0 to 8 of a run that stays open after POLICY.
  defp through_policy(%Run{rows: rows} = run),
    do: %{run | rows: Enum.filter(rows, &(&1.step in @through_policy))}

  defp proof_value(kase) do
    {:ok, %{"proof" => proof}} = Parser.decode(Cases.proof(kase))
    proof
  end

  defp sub_reason(%Rejection{sub_reason: nil}), do: nil
  defp sub_reason(%Rejection{sub_reason: sub_reason}), do: Atom.to_string(sub_reason)

  # Where each value of a row comes from (10.5), by its name: each is recomputed here from
  # the case's configuration and bytes, or is one of the verifier's own words. A name not
  # listed fails, so a value added to a row must say where it comes from.
  @trust_roots ~w(key_chain current_keyring compiled_pin supplied_keyring none)
  @refusals ~w(equation not_on_curve s_not_below_l small_order_key y_not_below_p)

  defp computed?("environment", value, _row, sources), do: value == sources.config.environment
  defp computed?("trust_root", value, _row, _sources), do: value in @trust_roots
  defp computed?("octets", value, _row, sources), do: value == byte_size(sources.bytes)
  defp computed?("key_id", value, _row, sources), do: value == sources.key_id

  defp computed?("proof_hash", value, _row, sources),
    do: value == RecordHash.hash_hex(:proof_hash, sources.proof)

  defp computed?("refused", value, _row, _sources), do: value in @refusals
  defp computed?("declared", _value, row, _sources), do: row.status == :fail

  defp computed?("constructions", value, _row, sources),
    do: value == mode(sources.proof["constructions"])

  defp computed?("constructions_digest", value, _row, %{proof: proof}),
    do: is_map(proof["constructions"]) and value == digest(proof)

  defp computed?("keyword", value, _row, _sources), do: value in ["false" | Schema.keywords()]
  defp computed?("schema", value, _row, _sources), do: String.starts_with?(value, "#/")
  defp computed?("rule", value, _row, _sources), do: value == "witnesses_named_by_witness_hashes"
  defp computed?("class", value, _row, _sources), do: value in ~w(TIME NISTTIME)
  defp computed?("chain", value, _row, _sources), do: value in ~w(bitcoin stellar)
  defp computed?("pin_kind", value, _row, _sources), do: value in ~w(commitment entropy)
  defp computed?("pin", value, row, sources), do: value == pin(sources.config, row.values)
  defp computed?(_name, _value, _row, _sources), do: false

  defp mode(nil), do: "none"
  defp mode(text) when is_map(text), do: "full"
  defp mode(url) when is_binary(url), do: "reference"

  defp digest(proof),
    do: :sha256 |> :crypto.hash(JCS.encode(proof["constructions"])) |> Base.encode16(case: :lower)

  defp pin(config, %{"pin_kind" => kind, "chain" => chain}),
    do: config.networks |> Map.fetch!(String.to_existing_atom(kind)) |> Map.fetch!(chain)

  defp sources(kase) do
    bytes = Cases.proof(kase)
    {:ok, %{"proof" => proof, "signature" => signature}} = Parser.decode(bytes)

    key_id =
      case Base64url.decode(:b64u32, signature["public_key"]) do
        {:ok, key} -> KeyId.of(key)
        _refused -> nil
      end

    %{bytes: bytes, config: Cases.config(kase), key_id: key_id, proof: proof}
  end

  defp unsourced(%Run{rows: rows}, kase) do
    sources = sources(kase)

    for row <- rows,
        {name, value} <- row.values,
        not computed?(name, value, row, sources),
        do: {row.step, row.part, name, value}
  end

  test "the offline cases fall in all five classes" do
    classes = Enum.frequencies_by(@offline, &Cases.step_class/1)
    assert classes |> Map.keys() |> Enum.sort() == [:bare, :gate, :later, :policy, :shape]
    assert Enum.all?(Map.values(classes), &(&1 > 0))
  end

  test "every SHAPE and POLICY reason code has a case here" do
    codes =
      for kase <- @offline,
          [code, _part, "fail", step] <- kase["expected"]["rows"] || [],
          step in ~w(SHAPE POLICY),
          uniq: true,
          do: code

    assert Enum.sort(codes) ==
             ~w(construction_mismatch network_mismatch shape_invalid unsupported_format
                unsupported_version)
  end

  test "the cases reach every value name the check of where values come from knows" do
    names =
      for kase <- @offline,
          Cases.step_class(kase) != :bare,
          {:ok, run} = run(kase),
          row <- through_policy(run).rows,
          name <- Map.keys(row.values),
          uniq: true,
          do: name

    assert Enum.sort(names) ==
             ~w(chain class constructions constructions_digest declared environment key_id
                keyword octets pin pin_kind proof_hash refused rule schema trust_root)
  end

  for kase <- @offline, class = Cases.step_class(kase) do
    @kase kase

    case class do
      :bare ->
        test "#{kase["id"]}: the bare rejection #{kase["expected"]["code"]}" do
          assert {:rejected, %Rejection{} = rejection} = run(@kase)
          assert Atom.to_string(rejection.code) == @kase["expected"]["code"]
          assert sub_reason(rejection) == @kase["expected"]["sub_reason"]
        end

      ended when ended in [:gate, :shape] ->
        test "#{kase["id"]}: ends at #{ended}, every row as expected" do
          assert {:ok, run} = run(@kase)
          assert reduced(run) == @kase["expected"]["rows"]
          assert @kase["expected"]["label"] == "failed"
          assert run.ended
          assert Run.failed?(run)
          assert run.type == nil and run.subject_id == nil
          assert values_written?(run)
          assert unsourced(run, @kase) == []
        end

      open ->
        test "#{kase["id"]}: #{open}, the rows of steps 0 to 8 as expected" do
          assert {:ok, run} = run(@kase)
          run = through_policy(run)

          expected =
            Enum.take_while(@kase["expected"]["rows"], &(List.last(&1) in @through_policy))

          assert expected |> Enum.map(&List.last/1) |> Enum.uniq() == @through_policy
          assert reduced(run) == expected
          refute run.ended
          assert Run.failed?(run) == (unquote(open) == :policy)

          proof = proof_value(@kase)
          assert run.type == proof["type"]
          subject = if proof["type"] in ~w(block beacon), do: "block", else: "subject"
          assert run.subject_id == proof[subject]["record"]["id"]
          assert values_written?(run)
          assert unsourced(run, @kase) == []
        end
    end
  end
end
