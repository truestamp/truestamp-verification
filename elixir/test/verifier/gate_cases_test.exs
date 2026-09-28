# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Truestamp.Verifier.GateCasesTest do
  # Steps 0 to 6 (SPEC.md 10.2) over every offline case of vectors/cases.json, one test per
  # case, in three classes:
  #
  # - a bare rejection (steps 0 to 3): the gate gives exactly its code and sub_reason;
  # - a failure at steps 4 to 6: the gate gives every expected row, the later steps' `skip
  #   prior_failure` rows included, and the run is failed, ended and attributed to none;
  # - any other case: the gate gives exactly the expected rows of steps 0 to 6, and leaves
  #   the run open with the attribution its keyring gives, for the later steps.
  #
  # In the last two, every row's values are JSON values, which JCS writes (section 10.5).
  #
  # Online cases are not the reference verifier's (13.1), so none runs here.
  use ExUnit.Case, async: true

  alias Truestamp.Verifier.{Gate, JCS, Keyring, RecordHash, Rejection, Row, Run}
  alias Truestamp.Verifier.Test.Cases

  @external_resource Cases.path()

  @gate_steps ~w(CONFIGURATION READ PARSE ENVELOPE ENVIRONMENT KEY_BINDING SIGNATURE)

  @offline Cases.offline()

  defp sub_reason(%Rejection{sub_reason: nil}), do: nil
  defp sub_reason(%Rejection{sub_reason: sub_reason}), do: Atom.to_string(sub_reason)

  defp reduced(%Run{rows: rows}), do: Enum.map(rows, &Row.reduce/1)

  defp values_written?(%Run{rows: rows}),
    do: Enum.all?(rows, &is_binary(JCS.encode(&1.values)))

  # Both entry points: over the bytes, and over the file, which is read after step 0. The
  # run's pins are the case's own `networks` (section 13.2), never the defaults of its E_v.
  defp run(kase) do
    config = Cases.config(kase)
    %{"commitment" => commitment, "entropy" => entropy} = kase["config"]["networks"]
    assert config.networks == %{commitment: commitment, entropy: entropy}
    by_bytes = Gate.run(config, Cases.proof(kase))
    assert Gate.run_file(config, Path.join(Cases.vectors(), kase["proof"])) == by_bytes
    by_bytes
  end

  defp attribution(kase) do
    case Cases.config(kase).keyring do
      :none -> "unattributed"
      nil -> "truestamp"
      {:file, _path} -> "keyring:" <> Keyring.digest(Cases.keyring_bytes(kase))
    end
  end

  test "the offline cases fall in all three classes" do
    classes = Enum.frequencies_by(@offline, &Cases.gate_class/1)
    assert Map.keys(classes) |> Enum.sort() == [:bare, :gate, :later]
    assert Enum.all?(Map.values(classes), &(&1 > 0))
  end

  for kase <- @offline, class = Cases.gate_class(kase) do
    @kase kase

    case class do
      :bare ->
        test "#{kase["id"]}: the bare rejection #{kase["expected"]["code"]}" do
          %{"code" => code} = expected = @kase["expected"]
          assert {:rejected, %Rejection{} = rejection} = run(@kase)
          assert Atom.to_string(rejection.code) == code
          assert sub_reason(rejection) == expected["sub_reason"]
          assert rejection.message != ""
        end

      :gate ->
        test "#{kase["id"]}: fails at the gate, every row as expected" do
          assert {:ok, run} = run(@kase)
          assert reduced(run) == @kase["expected"]["rows"]
          assert @kase["expected"]["label"] == "failed"
          assert Run.failed?(run)
          assert run.ended
          assert run.attribution == "none"
          assert values_written?(run)
        end

      :later ->
        test "#{kase["id"]}: passes the gate, the rows of steps 0 to 6 as expected" do
          assert {:ok, run} = run(@kase)
          expected = Enum.take(@kase["expected"]["rows"], length(@gate_steps))
          assert Enum.map(expected, &List.last/1) == @gate_steps
          assert reduced(run) == expected
          refute Run.failed?(run)
          refute run.ended
          assert run.attribution == attribution(@kase)
          assert run.proof_hash == RecordHash.hash(:proof_hash, run.proof)
          assert values_written?(run)
        end
    end
  end
end
