# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Truestamp.Verifier.ConformanceTest do
  # The comparison of SPEC.md 13.1 over every offline case of vectors/cases.json, through the
  # conformance entry point (Truestamp.Verifier.Conformance, which `mix truestamp.conformance`
  # runs), one test per case: the document it prints is read back, and each case's entry
  # must be exactly what 13.1 compares of the case's expected output:
  #
  # - a bare rejection: its `code`, and its `sub_reason` when the code has one;
  # - every other case: its `label` and ALL its rows as (code, part, status, step), in
  #   order, passes and skips included; and for a case that names a trace, that trace file's
  #   rows, in order, each with every member but `inputs`.
  #
  # Each case runs with its full configuration, network pins included. Online cases are not
  # the reference verifier's (13.1), so none has an entry. The report and the command over
  # the same cases are report_cases_test.exs's.
  #
  # And the known answers of vectors/item-codes.json (SPEC.md 3.9 and 13.2), one test per
  # row: each derive row's item_hash through ItemCode.from_item_hash/1, and each accepted
  # and refused value through the reader, ItemCode.parse/1. They are not conformance cases
  # (13.1, D77).
  use ExUnit.Case, async: true

  alias Truestamp.Verifier.{Config, Conformance, ItemCode, JCS, Parser, ReasonCodes}
  alias Truestamp.Verifier.Test.{Cases, StrictJSON}

  @external_resource Cases.path()

  @all Cases.all()
  @offline Cases.offline()

  setup_all do
    {code, stdout, stderr} = Conformance.main([Cases.path()])
    stdout = IO.iodata_to_binary(stdout)
    {:ok, document} = stdout |> String.trim_trailing("\n") |> Parser.parse()
    entries = Map.new(document, &{&1["id"], &1["output"]})

    %{
      code: code,
      stdout: stdout,
      stderr: IO.iodata_to_binary(stderr),
      document: document,
      entries: entries
    }
  end

  # What 13.1 compares of a case's expected output.
  defp compared(%{"expected" => %{"code" => code} = expected}) do
    assert Enum.sort(Map.keys(expected)) in [["code"], ["code", "sub_reason"]]
    # 13.1: sub_reason is compared exactly when the code has one.
    assert Map.has_key?(expected, "sub_reason") ==
             (ReasonCodes.sub_reasons(String.to_existing_atom(code)) != [])

    expected
  end

  defp compared(%{"expected" => expected}) do
    output = Map.take(expected, ~w(label rows))

    case expected do
      %{"trace" => path} ->
        trace = StrictJSON.read_data!(Path.join(Cases.vectors(), path))
        Map.put(output, "trace", Enum.map(trace, &Map.delete(&1, "inputs")))

      _no_trace ->
        output
    end
  end

  describe "the entry point" do
    test "prints one JCS document, an entry {id, output} per offline case, in the file's order",
         %{code: code, stdout: stdout, stderr: stderr, document: document} do
      assert code == 0
      assert JCS.encode(document) <> "\n" == stdout
      assert Enum.all?(document, &(&1 |> Map.keys() |> Enum.sort() == ~w(id output)))
      assert Enum.map(document, & &1["id"]) == Enum.map(@offline, & &1["id"])

      online = length(@all) - length(@offline)
      assert online > 0
      assert stderr =~ "Ran the #{length(@offline)} offline cases"
      assert stderr =~ "its #{online} online cases"
    end

    test "prints a trace exactly for the cases that name one, without `inputs`",
         %{entries: entries} do
      for kase <- @offline, output = entries[kase["id"]], Map.has_key?(output, "rows") do
        assert Map.has_key?(output, "trace") == Map.has_key?(kase["expected"], "trace")
        for row <- Map.get(output, "trace", []), do: refute(Map.has_key?(row, "inputs"))
      end

      assert Enum.any?(@offline, &Map.has_key?(&1["expected"], "trace"))
    end

    test "runs each case with its network pins, which change the rows of some cases" do
      pinned =
        for kase <- @offline,
            {:ok, config} = Conformance.config(kase, Cases.vectors()),
            config.networks != Config.default_pins(config.environment),
            do: {kase, config}

      differing =
        for {kase, config} <- pinned,
            defaults = %{config | networks: Config.default_pins(config.environment)},
            output(defaults, kase) != output(config, kase),
            do: kase["id"]

      # Conformance's moduledoc and AGENTS.md say how many: of the 20 offline cases whose
      # pins differ from their environment's defaults, only the 6 policy-*-entropy_* cases
      # give other rows under the defaults, which is what the command runs them with.
      assert length(pinned) == 20
      assert length(differing) == 6
      assert Enum.all?(differing, &(&1 =~ ~r/\Apolicy-[a-z]+-entropy_[a-z]+\z/))

      # The entry point's configuration is the test's own reading of the case (Cases).
      for kase <- @offline,
          do: assert(Conformance.config(kase, Cases.vectors()) == {:ok, Cases.config(kase)})
    end

    test "gives no entry for an online case, and refuses a keyring of `unavailable` offline" do
      [online | _more] = @all -- @offline
      assert Conformance.config(online, Cases.vectors()) == {:ok, :online}

      unavailable = put_in(hd(@offline), ["config", "keyring"], "unavailable")
      assert {:error, message} = Conformance.config(unavailable, Cases.vectors())
      assert message =~ "online"
    end

    test "refuses a case of a form or configuration 13.2 does not give" do
      [kase | _more] = @offline

      for bad <- [
            Map.delete(kase, "expected"),
            Map.put(kase, "extra", 1),
            put_in(kase, ["config", "environment"], "nowhere"),
            put_in(kase, ["config", "networks"], %{"commitment" => %{}}),
            put_in(kase, ["config", "networks", "extra"], %{}),
            put_in(kase, ["config", "networks", "commitment", "bitcoin"], "moon"),
            put_in(kase, ["config", "keyring"], 7),
            put_in(kase, ["config", "extra"], true),
            "not a case"
          ] do
        assert {:error, _message} = Conformance.config(bad, Cases.vectors()), inspect(bad)
      end
    end

    test "an invalid command line or a file that is not an array of cases exits 1, with nothing on stdout" do
      dir =
        Path.join(
          System.tmp_dir!(),
          "truestamp-conformance-#{System.unique_integer([:positive])}"
        )

      File.mkdir_p!(dir)
      on_exit(fn -> File.rm_rf!(dir) end)
      object = Path.join(dir, "object.json")
      File.write!(object, "{}")
      broken = Path.join(dir, "broken.json")
      File.write!(broken, "[")
      bad_case = Path.join(dir, "bad-case.json")
      File.write!(bad_case, ~s([{"id": "x"}]))

      for argv <- [
            [],
            [Cases.path(), Cases.path()],
            [<<0xFF>>],
            [Path.join(dir, "missing.json")],
            [object],
            [broken],
            [bad_case]
          ] do
        {code, stdout, stderr} = Conformance.main(argv)
        assert {code, IO.iodata_to_binary(stdout)} == {1, ""}, inspect(argv)
        assert IO.iodata_to_binary(stderr) =~ Conformance.usage()
      end
    end

    test "a fault inside the entry point exits 2, with nothing on stdout" do
      # A path that is no string reaches String.valid?/1, which raises.
      {code, stdout, stderr} = Conformance.main([123])
      assert {code, IO.iodata_to_binary(stdout)} == {2, ""}
      assert IO.iodata_to_binary(stderr) =~ "A fault inside the conformance entry point: "
    end
  end

  defp output(config, kase) do
    result = Truestamp.Verifier.run_file(config, Path.join(Cases.vectors(), kase["proof"]))
    Conformance.output(result, false)
  end

  describe "the offline cases" do
    for kase <- @offline do
      @kase kase
      test "#{kase["id"]}", %{entries: entries} do
        assert Map.fetch!(entries, @kase["id"]) == compared(@kase)
      end
    end
  end

  # ---------------------------------------------------------------------------------------
  # The known answers of vectors/item-codes.json, which are not conformance cases.

  @codes_path Path.join(Cases.vectors(), "item-codes.json")
  @external_resource @codes_path
  @reasons [:not_ascii, :character, :length, :separator, :check]

  # J1, then J2 to J6, as the verifier reads any file.
  {:ok, bytes} = Parser.read_file(@codes_path)
  {:ok, codes} = Parser.parse(bytes)
  @codes codes

  defp unhex(hex), do: Base.decode16!(hex, case: :lower)

  describe "the item code's derive rows" do
    for {row, index} <- Enum.with_index(@codes["derive"], 1) do
      @row row
      test "derive #{index}: #{row["about"]}" do
        %{"item_code" => code, "item_hash" => hex} = @row
        assert ItemCode.from_item_hash(hex) == {:ok, code}
        assert ItemCode.from_item_hash(unhex(hex)) == {:ok, code}
        # The code is its own one spelling.
        assert ItemCode.parse(code) == {:ok, code}
        assert ItemCode.valid?(code)
      end
    end
  end

  describe "the item code's accepted rows" do
    for {row, index} <- Enum.with_index(@codes["accepted"], 1) do
      @row row
      test "accepted #{index}: #{row["about"]}" do
        input = unhex(@row["input"])
        assert ItemCode.parse(input) == {:ok, @row["item_code"]}
        assert ItemCode.valid?(input)
      end
    end
  end

  describe "the item code's refused rows" do
    for {row, index} <- Enum.with_index(@codes["refused"], 1) do
      @row row
      test "refused #{index}: #{row["about"]}" do
        input = unhex(@row["input"])
        assert {:error, reason} = ItemCode.parse(input)
        assert reason in @reasons
        refute ItemCode.valid?(input)
      end
    end
  end
end
