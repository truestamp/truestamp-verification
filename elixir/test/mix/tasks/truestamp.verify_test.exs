# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Mix.Tasks.Truestamp.VerifyTest do
  # `mix truestamp.verify` writes what Truestamp.Verifier.Command gives, stdout and stderr,
  # as raw bytes, and exits with its code (SPEC.md 12.2): the same bytes on a latin1
  # device, so the JSON stays UTF-8 whatever the locale; and, run as its own process on a
  # build that has to compile, still exactly one JSON document on stdout. Not async: it
  # captures standard error.
  use ExUnit.Case, async: false

  import ExUnit.CaptureIO

  alias Mix.Tasks.Truestamp.Verify
  alias Truestamp.Verifier.{Command, JCS, Parser}
  alias Truestamp.Verifier.Test.Cases

  @item Path.join(Cases.vectors(), "positive/item.proof.json")
  @test_keyring Path.join(Cases.vectors(), "keyring.test.json")
  @project Path.expand("../../..", __DIR__)

  # {what the task wrote to stdout, to stderr, and how it ended}, each device capturing in
  # `encoding`.
  defp task(fun, encoding \\ :unicode) do
    written_err =
      capture_io(:stderr, [encoding: encoding], fn ->
        written_out =
          capture_io([encoding: encoding], fn ->
            ended =
              try do
                fun.()
              catch
                :exit, reason -> {:exit, reason}
              end

            send(self(), {:ended, ended})
          end)

        send(self(), {:stdout, written_out})
      end)

    assert_received {:stdout, written_out}
    assert_received {:ended, ended}
    {written_out, written_err, ended}
  end

  defp temporary_directory(name) do
    dir = Path.join(System.tmp_dir!(), "truestamp-task-#{System.unique_integer([:positive])}")
    on_exit(fn -> File.rm_rf!(dir) end)
    dir = Path.join(dir, name)
    File.mkdir_p!(dir)
    dir
  end

  test "writes the command's output and exits with its code" do
    argv = [@item, "--environment", "test", "--keyring", @test_keyring]
    {6, stdout, stderr} = Command.main(argv)
    {written_out, written_err, ended} = task(fn -> Verify.run(argv) end)
    assert ended == {:exit, {:shutdown, 6}}
    assert written_out == IO.iodata_to_binary(stdout)
    assert written_err == IO.iodata_to_binary(stderr)
  end

  test "an invalid command line exits 1, with the usage on standard error only" do
    {written_out, written_err, ended} = task(fn -> Verify.run(["--json"]) end)
    assert ended == {:exit, {:shutdown, 1}}
    assert written_out == ""
    assert written_err =~ Command.usage()
  end

  test "returns for exit code 0 and exits with every other code of 12.2" do
    # No offline case exits 0 (SPEC.md 13.3), so finish/1 is given each code directly.
    for code <- 0..8 do
      {written_out, written_err, ended} = task(fn -> Verify.finish({code, ["out"], "err"}) end)
      assert {written_out, written_err} == {"out", "err"}
      assert ended == if(code == 0, do: :ok, else: {:exit, {:shutdown, code}})
    end
  end

  test "writes raw bytes, so a report naming a non-ASCII path is UTF-8 JSON on a latin1 device" do
    keyring = Path.join(temporary_directory("clés-鍵"), "k.json")
    File.cp!(@test_keyring, keyring)
    argv = [@item, "--environment", "test", "--keyring", keyring]
    {6, stdout, stderr} = Command.main(argv)

    {written_out, written_err, {:exit, {:shutdown, 6}}} =
      task(fn -> Verify.run(argv) end, :latin1)

    assert written_out == IO.iodata_to_binary(stdout)
    assert written_err == IO.iodata_to_binary(stderr)
    assert {:ok, report} = Parser.decode(String.trim_trailing(written_out, "\n"))
    assert report["trust_root"]["location"] == keyring
    assert written_err =~ "from #{keyring}"
  end

  @tag timeout: 300_000
  test "run as its own process on a build that compiles, stdout is exactly one JSON document" do
    # A copy of this build with the project's compile manifest removed, so the project
    # compiles again, and with the task's own module removed, so Mix has to compile before
    # it can find the task, as on a fresh checkout. The locale is C, and the keyring's
    # path is not ASCII.
    root = temporary_directory("build")
    build = Path.join(root, "test")
    File.cp_r!(Mix.Project.build_path(), build)
    ebin = Path.join(build, "lib/truestamp_verifier/ebin")
    File.rm!(Path.join(build, "lib/truestamp_verifier/.mix/compile.elixir"))
    File.rm!(Path.join(ebin, "Elixir.Mix.Tasks.Truestamp.Verify.beam"))
    File.rm!(Path.join(ebin, "Elixir.Truestamp.Verifier.Command.beam"))

    keyring = Path.join(temporary_directory("clés-鍵"), "k.json")
    File.cp!(@test_keyring, keyring)
    stderr_file = Path.join(root, "stderr.txt")

    {stdout, exit_status} =
      System.cmd(
        "sh",
        [
          "-c",
          ~s(exec mix truestamp.verify "$1" --environment test --keyring "$2" 2>"$3"),
          "sh",
          @item,
          keyring,
          stderr_file
        ],
        cd: @project,
        env: [
          {"MIX_ENV", "test"},
          {"MIX_BUILD_ROOT", root},
          {"MIX_BUILD_PATH", nil},
          {"LC_ALL", "C"},
          {"LANG", nil},
          {"LC_CTYPE", nil}
        ]
      )

    stderr = File.read!(stderr_file)
    assert exit_status == 6, stderr
    assert File.exists?(Path.join(ebin, "Elixir.Mix.Tasks.Truestamp.Verify.beam"))
    assert String.ends_with?(stdout, "}\n") and length(String.split(stdout, "\n")) == 2, stdout
    assert {:ok, report} = Parser.decode(String.trim_trailing(stdout, "\n")), stdout
    assert JCS.encode(report) <> "\n" == stdout
    assert report["label"] == "supplied-keyring"
    assert report["trust_root"]["location"] == keyring
  end
end
