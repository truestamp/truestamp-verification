# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Truestamp.Verifier.ReportCasesTest do
  # Steps 0 to 14 (SPEC.md 10.2) and the report of 10.5, through Truestamp.Verifier.run/2
  # and run_file/2 and through the command (Truestamp.Verifier.Command.execute/3), over every
  # offline case of vectors/cases.json, one test per case. What 13.1 compares of each case,
  # its code and sub_reason, or its label, rows and trace, is conformance_test.exs's; here:
  #
  # - run/2 over the proof's bytes gives exactly what run_file/2 gives over its file;
  # - a bare rejection: the output {code, message, sub_reason} with sub_reason only where
  #   the code has one, and exit code 8 for configuration_error and 4 for the others (12.2);
  # - every other case: for a case whose expected output names a trace, its trace, every
  #   member, `inputs` included (13.1 compares every member but `inputs`, and these match
  #   too), and the command's --trace FILE, byte for byte the case's trace file.
  #
  # And the report as the command writes it, parsed from its stdout, checked against the
  # case, never against Truestamp.Verifier.Report: stdout is JCS of that value and a line
  # feed, with the label's exit code; exactly the members of 10.5; `code` present exactly
  # when the label is `failed`, equal to the first failing row's code; the attribution,
  # E_v, both edges null, `window` not_established and `verified` false; `type` and
  # `subject_id` the proof's once SHAPE passed, else null; `trust_root` that of the case's
  # keyring, from the bytes of the file it names; and each written row exactly
  # {code, message, part, status, step, values}, `code` absent exactly on a pass, reduced
  # to (code, part, status, step) equal to the case's rows, and the report's label the
  # case's.
  #
  # Online cases are not the reference verifier's (13.1), so none runs here.
  use ExUnit.Case, async: true

  alias Truestamp.Verifier
  alias Truestamp.Verifier.{Command, ExitCodes, JCS, Parser, Report}
  alias Truestamp.Verifier.Test.{Cases, StrictJSON}

  @external_resource Cases.path()

  @offline Cases.offline()

  @report_members ~w(attribution environment label rows subject_id submitted_after
                     submitted_before trust_root type verified window)

  @gate_steps ~w(ENVIRONMENT KEY_BINDING SIGNATURE)

  @exit_by_label %{
    "failed" => 3,
    "unattributed" => 5,
    "supplied-keyring" => 6,
    "internally-consistent" => 7,
    "verified" => 0
  }

  defp path(kase), do: Path.join(Cases.vectors(), kase["proof"])

  defp run(kase) do
    config = Cases.config(kase)
    by_bytes = Verifier.run(config, Cases.proof(kase))
    assert Verifier.run_file(config, path(kase)) == by_bytes
    by_bytes
  end

  @compiled_pin Path.expand("../../../spec/keyring.production.json", __DIR__)
  @external_resource @compiled_pin

  defp sha256(bytes), do: :sha256 |> :crypto.hash(bytes) |> Base.encode16(case: :lower)

  defp attribution(kase, rows) do
    gate_failed? =
      Enum.any?(rows, &match?([_code, _part, "fail", step] when step in @gate_steps, &1))

    case {gate_failed?, Cases.config(kase).keyring} do
      {true, _keyring} -> "none"
      {false, :none} -> "unattributed"
      {false, nil} -> "truestamp"
      {false, {:file, path}} -> "keyring:" <> sha256(File.read!(path))
    end
  end

  # SPEC.md 10.5: the trust root of the case's keyring option.
  defp trust_root(kase) do
    case Cases.config(kase).keyring do
      :none ->
        %{"digest" => nil, "kind" => "none", "location" => nil}

      nil ->
        %{
          "digest" => sha256(File.read!(@compiled_pin)),
          "kind" => "compiled_pin",
          "location" => nil
        }

      {:file, path} ->
        %{"digest" => sha256(File.read!(path)), "kind" => "supplied_keyring", "location" => path}
    end
  end

  # SPEC.md 10.5: the proof's type and its subject's id once SHAPE has passed, else null.
  defp type_and_subject_id(kase, rows) do
    if Enum.any?(rows, &match?([nil, _part, "pass", "SHAPE"], &1)) do
      {:ok, %{"proof" => proof}} = Parser.decode(Cases.proof(kase))
      at = if proof["type"] in ~w(block beacon), do: "block", else: "subject"
      {proof["type"], proof[at]["record"]["id"]}
    else
      {nil, nil}
    end
  end

  # A written row: exactly its members, each of its form, reduced as 13.1 reduces it.
  defp written_row(row) do
    members = ~w(message part status step values)
    members = if row["status"] == "pass", do: members, else: ["code" | members]
    assert row |> Map.keys() |> Enum.sort() == Enum.sort(members), inspect(row)
    assert row["status"] in ~w(pass fail skip warn info)
    assert is_binary(row["step"]) and is_binary(row["message"]) and row["message"] != ""
    assert is_map(row["values"])
    assert is_nil(row["part"]) or String.starts_with?(row["part"], "/")
    if row["status"] != "pass", do: assert(is_binary(row["code"]))
    [row["code"], row["part"], row["status"], row["step"]]
  end

  defp temporary_file(name) do
    dir = Path.join(System.tmp_dir!(), "truestamp-verdict-#{System.unique_integer([:positive])}")
    File.mkdir_p!(dir)
    on_exit(fn -> File.rm_rf!(dir) end)
    Path.join(dir, name)
  end

  test "the offline cases give three labels and both kinds of bare rejection" do
    labels = @offline |> Enum.map(& &1["expected"]["label"]) |> Enum.uniq() |> Enum.sort()
    assert labels == [nil, "failed", "supplied-keyring", "unattributed"]

    codes = for kase <- @offline, code = kase["expected"]["code"], uniq: true, do: code
    assert "configuration_error" in codes and length(codes) > 1
  end

  test "the reports' cases cover each trust root the reference verifier offers" do
    kinds =
      for kase <- @offline, kase["expected"]["rows"], uniq: true, do: trust_root(kase)["kind"]

    assert Enum.sort(kinds) == ~w(compiled_pin none supplied_keyring)
  end

  test "every offline case that is not a bare rejection has WINDOW and EXPECTED_HASH rows" do
    for kase <- @offline, rows = kase["expected"]["rows"] do
      steps = Enum.map(rows, &List.last/1)
      assert "WINDOW" in steps and List.last(steps) == "EXPECTED_HASH", kase["id"]
    end
  end

  for kase <- @offline do
    @kase kase

    if kase["expected"]["code"] do
      test "#{kase["id"]}: the bare rejection #{kase["expected"]["code"]}" do
        expected = @kase["expected"]
        assert {:rejected, rejection} = run(@kase)
        output = Report.rejection(rejection)

        assert Map.take(output, ["code", "sub_reason"]) == expected
        assert output |> Map.keys() |> Enum.sort() == Enum.sort(["message" | Map.keys(expected)])

        {code, stdout, stderr} = Command.execute(Cases.config(@kase), path(@kase))

        assert {:ok, ^output} =
                 Parser.decode(IO.iodata_to_binary(stdout) |> String.trim_trailing())

        assert IO.iodata_to_binary(stderr) =~ "No report"

        assert code ==
                 if(expected["code"] == "configuration_error",
                   do: ExitCodes.code(:configuration_error),
                   else: ExitCodes.code(:bare_rejection)
                 )
      end
    else
      test "#{kase["id"]}: every row of steps 0 to 14, the label and the report" do
        expected = @kase["expected"]
        assert {:ok, run} = run(@kase)

        if path = expected["trace"] do
          file = Path.join(Cases.vectors(), path)
          assert run.trace == StrictJSON.read_data!(file)

          written = temporary_file("trace.json")
          {_code, _stdout, _stderr} = Command.execute(Cases.config(@kase), path(@kase), written)
          assert File.read!(written) == File.read!(file)
        end

        {code, stdout, _stderr} = Command.execute(Cases.config(@kase), path(@kase))
        stdout = IO.iodata_to_binary(stdout)
        assert code == Map.fetch!(@exit_by_label, expected["label"])
        assert String.ends_with?(stdout, "}\n")
        assert {:ok, report} = Parser.decode(String.trim_trailing(stdout, "\n"))
        assert JCS.encode(report) <> "\n" == stdout

        failed? = expected["label"] == "failed"
        members = if failed?, do: ["code" | @report_members], else: @report_members
        assert report |> Map.keys() |> Enum.sort() == Enum.sort(members)
        assert report["label"] == expected["label"]

        first_failure = Enum.find(expected["rows"], &match?([_code, _part, "fail", _step], &1))
        assert report["code"] == if(failed?, do: hd(first_failure))
        assert report["attribution"] == attribution(@kase, expected["rows"])
        assert report["environment"] == @kase["config"]["environment"]
        assert report["submitted_after"] == nil and report["submitted_before"] == nil
        assert report["window"] == "not_established"
        assert report["verified"] == false

        assert {report["type"], report["subject_id"]} ==
                 type_and_subject_id(@kase, expected["rows"])

        assert report["trust_root"] == trust_root(@kase)
        assert Enum.map(report["rows"], &written_row/1) == expected["rows"]
      end
    end
  end
end
