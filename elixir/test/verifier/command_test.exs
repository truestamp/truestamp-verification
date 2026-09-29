# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Truestamp.Verifier.CommandTest do
  # The command of SPEC.md 12.2, `mix truestamp.verify`: its command line, each exit path
  # (the five labels, both kinds of bare rejection, an invalid command line, an argument
  # that is not UTF-8, an input that cannot be read, a trace file that cannot be written,
  # CONFIGURATION before the proof is read, a fault caught before steps 0 to 3 passed or
  # from ENVIRONMENT on, and a fault no step caught), its machine output (the report of
  # 10.5 written with JCS, with exactly its members; the trace of 10.6 in its own file
  # under --trace FILE; a bare rejection's {code, message, sub_reason}), its human output
  # (the item code of 3.9 from the recomputed item_hash, beside it and nowhere else, 11.5;
  # keyless mode said in words, 8.3; a non-production E_v said, 6.4; no window for a failed
  # run, 11.5; no submitted-after edge for a proof that carries nothing to give one, 11.2),
  # and that it reads no environment variable (6.4, 8.3).
  use ExUnit.Case, async: true

  alias Truestamp.Verifier

  alias Truestamp.Verifier.{
    Command,
    Config,
    ExitCodes,
    ItemCode,
    JCS,
    Parser,
    RecordHash,
    Verdict
  }

  alias Truestamp.Verifier.Test.{Cases, Signing, StrictJSON}

  @report_members ~w(attribution environment label rows subject_id submitted_after
                     submitted_before trust_root type verified window)

  @vectors Cases.vectors()
  @item Path.join(@vectors, "positive/item.proof.json")
  @block Path.join(@vectors, "positive/block.proof.json")
  @test_keyring Path.join(@vectors, "keyring.test.json")

  @source_files ~w(lib/truestamp/verifier/command.ex lib/truestamp/verifier/config.ex
                   lib/mix/tasks/truestamp.verify.ex)

  # A command line run: {exit code, stdout as a binary, stderr as a binary}.
  defp main(argv) do
    {code, stdout, stderr} = Command.main(argv)
    {code, IO.iodata_to_binary(stdout), IO.iodata_to_binary(stderr)}
  end

  defp document(stdout) do
    assert String.ends_with?(stdout, "\n")
    assert {:ok, value} = Parser.decode(String.trim_trailing(stdout, "\n"))
    value
  end

  defp missing, do: Path.join(System.tmp_dir!(), "truestamp-no-such-file.json")

  defp temporary(name, bytes) do
    dir = Path.join(System.tmp_dir!(), "truestamp-command-#{System.unique_integer([:positive])}")
    File.mkdir_p!(dir)
    on_exit(fn -> File.rm_rf!(dir) end)
    path = Path.join(dir, name)
    File.write!(path, bytes)
    path
  end

  # ---------------------------------------------------------------------------------------
  # The command line

  describe "the command line" do
    test "sets each option, in either spelling, and nothing else" do
      assert {:ok, config, "proof.json", "t.json"} =
               Command.parse(
                 ~w(--environment=test proof.json --keyring k.json --expected-hash AB) ++
                   ~w(--trace t.json)
               )

      assert config ==
               Config.new!(
                 environment: "test",
                 keyring: {:file, "k.json"},
                 expected_hash: "AB"
               )

      assert {:ok, config, "p", nil} = Command.parse(~w(p --no-keyring))
      assert config == Config.new!(keyring: :none)

      assert {:ok, _config, "p", "t.json"} = Command.parse(~w(p --trace=t.json))

      assert {:ok, config, "p", nil} = Command.parse(["p"])
      assert config == Config.new!()
      assert config.environment == "prod" and config.keyring == nil
    end

    test "takes every argument after -- as a file" do
      assert {:ok, _config, "--trace", nil} = Command.parse(["--", "--trace"])
    end

    test "refuses --keyring with --no-keyring, in either order (D74)" do
      for argv <- [~w(p --keyring k --no-keyring), ~w(p --no-keyring --keyring k)] do
        assert {:error, message} = Command.parse(argv)
        assert message =~ "--keyring and --no-keyring"
      end
    end

    test "refuses a repeated, unknown, valueless or misvalued option, and no file or two" do
      for argv <- [
            ~w(p --trace --trace),
            ~w(p --environment test --environment test),
            ~w(p --no-keyring --no-keyring),
            ~w(p --keyring a --keyring=b),
            ~w(p --json),
            ~w(p --no-trace),
            ~w(p --no-keyring=true),
            ~w(p --trace),
            ~w(p --keyring),
            ~w(p --keyring --trace),
            ~w(p --environment production),
            ~w(p --environment PROD),
            ~w(--no-keyring),
            ~w(p q)
          ] do
        assert {:error, _message} = Command.parse(argv), inspect(argv)
        assert {1, "", stderr} = main(argv)
        assert stderr =~ Command.usage()
      end
    end

    test "refuses a FILE, --keyring or --expected-hash value that is not valid UTF-8" do
      for argv <- [
            [<<0xFF>>, "--no-keyring"],
            [@item, "--environment", "test", "--keyring", <<"k", 0xFF, ".json">>],
            [@item, "--environment", "test", "--no-keyring", "--expected-hash", <<0xFF, 0xFE>>],
            [@item, "--environment", "test", "--no-keyring", "--expected-hash=" <> <<0xFF>>]
          ] do
        assert {1, "", stderr} = main(argv)
        assert stderr =~ "not valid UTF-8" and stderr =~ Command.usage()
      end
    end

    test "refuses, before the run, a --trace FILE whose directory does not exist" do
      file = Path.join([System.tmp_dir!(), "truestamp-no-such-directory", "t.json"])
      assert {:error, message} = Command.parse([@item, "--no-keyring", "--trace", file])
      assert message =~ "does not exist"
      assert {1, "", stderr} = main([@item, "--no-keyring", "--trace", file])
      assert stderr =~ Command.usage()
      refute File.exists?(file)
    end

    test "reads no environment variable and no application configuration (6.4, 8.3)" do
      root = Path.expand("../..", __DIR__)

      for file <- @source_files do
        {:ok, ast} = root |> Path.join(file) |> File.read!() |> Code.string_to_quoted()

        {_ast, found} =
          Macro.prewalk(ast, [], fn
            {{:., _, [{:__aliases__, _, [:System]}, fun]}, _, _} = node, found
            when fun in [:get_env, :fetch_env, :fetch_env!] ->
              {node, [fun | found]}

            {{:., _, [{:__aliases__, _, [:Application]}, fun]}, _, _} = node, found
            when fun in [:get_env, :fetch_env, :fetch_env!, :get_all_env] ->
              {node, [fun | found]}

            {{:., _, [:os, :getenv]}, _, _} = node, found ->
              {node, [:getenv | found]}

            node, found ->
              {node, found}
          end)

        assert found == [], file
      end
    end
  end

  # ---------------------------------------------------------------------------------------
  # Exit paths (12.2)

  describe "exit codes" do
    test "the label failed exits 3, with the report and its code" do
      {code, stdout, _stderr} = main([@item])
      assert code == 3
      assert %{"label" => "failed", "code" => "environment_mismatch"} = document(stdout)
    end

    test "the label unattributed exits 5" do
      {code, stdout, _stderr} = main([@item, "--environment", "test", "--no-keyring"])
      assert code == 5
      assert %{"label" => "unattributed", "attribution" => "unattributed"} = document(stdout)
    end

    test "the label supplied-keyring exits 6" do
      {code, stdout, _stderr} = main([@item, "--environment", "test", "--keyring", @test_keyring])
      assert code == 6
      assert %{"label" => "supplied-keyring", "attribution" => "keyring:" <> _} = document(stdout)
    end

    test "the label internally-consistent exits 7, and verified exits 0" do
      run = Signing.truestamp_run(Map.delete(Signing.positive("item"), "signing_key_event"))
      assert {7, stdout, _stderr} = Command.outcome({:ok, run}, nil)

      assert %{"label" => "internally-consistent", "window" => "not_established"} =
               report = document(IO.iodata_to_binary(stdout))

      # The compiled pin's trust root (10.5): the SHA-256 of the pin's bytes, and no location.
      pin = File.read!(Path.expand("../../../spec/keyring.production.json", __DIR__))
      digest = :sha256 |> :crypto.hash(pin) |> Base.encode16(case: :lower)

      assert report["trust_root"] ==
               %{"digest" => digest, "kind" => "compiled_pin", "location" => nil}

      assert report["attribution"] == "truestamp"

      edge = %{"basis" => "stellar_ledger_close_read", "instant" => "2026-09-26T01:48:00Z"}
      verified = Verdict.verdict(%{run | submitted_before: edge})
      assert {0, stdout, _stderr} = Command.outcome({:ok, verified}, nil)

      assert %{"label" => "verified", "verified" => true, "window" => "established"} =
               document(IO.iodata_to_binary(stdout))
    end

    test "a bare rejection exits 4, with only {code, message, sub_reason}" do
      path = temporary("array.json", "[]")
      trace = Path.join(Path.dirname(path), "trace.json")
      {code, stdout, stderr} = main([path, "--trace", trace])
      assert code == 4
      assert File.read!(trace) == "[]\n"

      assert %{"code" => "invalid_envelope", "sub_reason" => "document", "message" => _} =
               output = document(stdout)

      assert map_size(output) == 3
      assert stderr =~ "No report and no verdict"

      oversized = temporary("big.json", String.duplicate(" ", 262_145))
      {4, stdout, _stderr} = main([oversized])
      assert document(stdout) |> Map.keys() |> Enum.sort() == ~w(code message)
    end

    test "configuration_error exits 8: no keyring source, and a keyring failing a load check" do
      {code, stdout, _stderr} = main([@item, "--environment", "test"])
      assert code == 8
      assert %{"code" => "configuration_error"} = document(stdout)

      repeated = Path.join(@vectors, "negative/configuration-keyring-repeated_key.keyring.json")
      {code, stdout, _stderr} = main([@item, "--environment", "test", "--keyring", repeated])
      assert code == 8
      assert %{"code" => "configuration_error"} = document(stdout)

      unparsable = temporary("keyring.json", "{")

      assert {8, _stdout, _stderr} =
               main([@item, "--environment", "test", "--keyring", unparsable])
    end

    test "CONFIGURATION comes before the proof is read: a missing proof with no keyring source" do
      assert {8, stdout, _stderr} = main([missing(), "--environment", "test"])
      assert %{"code" => "configuration_error"} = document(stdout)

      unparsable = temporary("keyring.json", "{")

      assert {8, stdout, _stderr} =
               main([missing(), "--environment", "test", "--keyring", unparsable])

      assert %{"code" => "configuration_error"} = document(stdout)
    end

    test "an input that cannot be read exits 1 with no report: the proof, or the keyring" do
      missing = missing()
      assert {1, "", stderr} = main([missing, "--no-keyring"])
      assert stderr =~ "Cannot read"

      assert {1, "", _stderr} = main([@item, "--environment", "test", "--keyring", missing])
      directory = Path.dirname(temporary("x", ""))
      assert {1, "", _stderr} = main([@item, "--environment", "test", "--keyring", directory])
      assert {1, "", _stderr} = main([directory, "--no-keyring"])
    end

    test "a trace file that cannot be written after the run exits 1 with no report" do
      directory = Path.dirname(temporary("x", ""))
      argv = [@item, "--environment", "test", "--no-keyring", "--trace", directory]
      assert {1, "", stderr} = main(argv)
      assert stderr =~ "Cannot write the trace to #{directory}" and stderr =~ "No report"
    end

    test "a fault caught before steps 0 to 3 passed exits 2 with no report" do
      config = %{Config.new!(keyring: :none) | environment: %{}}
      assert {2, "", stderr} = Command.execute(config, @item)
      assert IO.iodata_to_binary(stderr) =~ "fault"
    end

    test "a fault no step caught, while the report is written, exits 2 with no report (12.2)" do
      # No command line makes this configuration: main/1 refuses such a hash (exit 1). The
      # run passes every step, and the report then cannot be written, since EXPECTED_HASH's
      # values echo the caller's value.
      config = %{Config.new!(environment: "test", keyring: :none) | expected_hash: <<0xFF>>}
      assert {:ok, %{label: "failed"}} = Verifier.run_file(config, @item)
      trace = Path.join(Path.dirname(temporary("x", "")), "trace.json")
      assert {2, "", stderr} = Command.execute(config, @item, trace)
      assert IO.iodata_to_binary(stderr) =~ "stopped on a fault before it could give a report"
      refute File.exists?(trace)
    end

    test "a fault caught from ENVIRONMENT on is an internal_error row and exits 3" do
      config = %{Config.new!(environment: "test", keyring: :none) | networks: :not_pins}
      {code, stdout, _stderr} = Command.execute(config, @item)
      assert code == 3
      report = document(IO.iodata_to_binary(stdout))
      assert report["code"] == "internal_error"

      assert Enum.find(report["rows"], &(&1["code"] == "internal_error"))
             |> Map.take(~w(part step)) ==
               %{"part" => nil, "step" => "POLICY"}
    end

    test "each exit code comes from spec/exit-codes.json" do
      assert ExitCodes.code(:fault) == 2 and ExitCodes.code(:runtime_error) == 1
      assert ExitCodes.code(:bare_rejection) == 4 and ExitCodes.code(:configuration_error) == 8
    end
  end

  # ---------------------------------------------------------------------------------------
  # Output

  describe "the machine output" do
    test "is the report, written with JCS; --trace FILE writes the trace in canonical form" do
      argv = [@item, "--environment", "test", "--keyring", @test_keyring]
      {6, plain, _stderr} = main(argv)
      trace = Path.join(Path.dirname(temporary("x", "")), "item.trace.json")
      {6, traced, _stderr} = main(argv ++ ["--trace", trace])

      report = document(plain)
      assert plain == JCS.encode(report) <> "\n"
      assert traced == plain
      assert report |> Map.keys() |> Enum.sort() == @report_members

      expected = File.read!(Path.join(@vectors, "positive/item.trace.json"))
      assert File.read!(trace) == expected
      assert StrictJSON.canonical(StrictJSON.read_data!(trace)) == expected
    end

    test "a run that ended before DERIVE writes an empty trace under --trace FILE" do
      trace = Path.join(Path.dirname(temporary("x", "")), "trace.json")
      {3, stdout, _stderr} = main([@item, "--trace", trace])
      refute Map.has_key?(document(stdout), "trace")
      assert File.read!(trace) == "[]\n"
    end
  end

  describe "the human output" do
    test "prints the item code beside the whole recomputed item_hash, and nowhere else" do
      proof = Signing.positive("item")
      item_hash = RecordHash.hash_hex(:item_hash, proof["subject"]["record"])
      {:ok, item_code} = ItemCode.from_item_hash(item_hash)

      {6, stdout, stderr} = main([@item, "--environment", "test", "--keyring", @test_keyring])

      lines = String.split(stderr, "\n")

      code_line = Enum.find_index(lines, &String.starts_with?(&1, "Item code: #{item_code}"))
      assert code_line
      assert Enum.at(lines, code_line - 1) == "item_hash, recomputed: #{item_hash}"
      assert Enum.count(lines, &String.contains?(&1, item_code)) == 1
      refute Enum.at(lines, code_line) =~ ~r/\b(pass|fail|skip|warn|info)\b/

      refute stdout =~ item_code
      refute Map.has_key?(document(stdout), "item_code")
    end

    test "computes the item code from the recomputed item_hash, never the declared one" do
      path = Path.join(@vectors, "negative/declared-item_hash.proof.json")
      argv = [path, "--environment", "test", "--keyring", @test_keyring]

      {:ok, run} =
        Verifier.run_file(Config.new!(environment: "test", keyring: {:file, @test_keyring}), path)

      %{"declared" => declared, "recomputed" => recomputed} =
        Enum.find(run.trace, &(&1["part"] == "/subject/item_hash"))

      assert declared != recomputed
      {:ok, code} = ItemCode.from_item_hash(recomputed)
      {:ok, declared_code} = ItemCode.from_item_hash(declared)

      {3, _stdout, stderr} = main(argv)
      lines = String.split(stderr, "\n")
      index = Enum.find_index(lines, &(&1 == "item_hash, recomputed: #{recomputed}"))
      assert index
      assert Enum.at(lines, index + 1) =~ "Item code: #{code} "
      refute stderr =~ declared_code
      refute stderr =~ declared
    end

    test "prints no item code for a proof that is not an item, or one that ended before DERIVE" do
      {5, _stdout, stderr} = main([@block, "--environment", "test", "--no-keyring"])
      refute stderr =~ "Item code"

      {3, _stdout, stderr} = main([@item])
      refute stderr =~ "Item code"
    end

    test "says keyless mode in words, and a non-production environment beside the verdict" do
      {5, _stdout, stderr} = main([@item, "--environment", "test", "--no-keyring"])
      assert stderr =~ "Label: unattributed, under the test environment, not production."
      assert stderr =~ "checked only against the key the document carries"
      assert stderr =~ "Environment: test, not production"

      {6, _stdout, stderr} = main([@item, "--environment", "test", "--keyring", @test_keyring])
      refute stderr =~ "checked only against the key the document carries"
    end

    test "says keyless mode in words when the run fails at the gate, before KEY_BINDING runs" do
      {3, _stdout, stderr} = main([@item, "--no-keyring"])
      assert stderr =~ "Code: environment_mismatch"
      refute stderr =~ "Keyless mode:"
      assert stderr =~ "the signature was checked only against the key the document carries"
    end

    test "shows no window for a failed run, and an absent one otherwise" do
      {3, _stdout, stderr} = main([@item])
      refute stderr =~ "Submitted"
      assert stderr =~ "Label: failed. A check failed"

      {5, _stdout, stderr} = main([@item, "--environment", "test", "--no-keyring"])
      assert stderr =~ "Submitted after: not established"
      assert stderr =~ "Submitted before: not established"
      refute stderr =~ "no submitted-after edge"
    end

    test "says a proof with nothing to give a submitted-after edge has none (11.2)" do
      for name <- ~w(block beacon-empty) do
        path = Path.join(@vectors, "positive/#{name}.proof.json")
        {5, _stdout, stderr} = main([path, "--environment", "test", "--no-keyring"])
        assert stderr =~ "Submitted after: none. This proof has no submitted-after edge", name
        refute stderr =~ "Submitted after: not established", name
        assert stderr =~ "Submitted before: not established", name
      end
    end
  end
end
