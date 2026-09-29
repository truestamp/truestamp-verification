# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Mix.Tasks.Truestamp.ConformanceTest do
  # `mix truestamp.conformance` writes what Truestamp.Verifier.Conformance gives, stdout and
  # stderr, as raw bytes, and exits with its code: the same bytes on a latin1 device, so the
  # JSON stays UTF-8 whatever the locale; and, run as its own process on a build that has to
  # compile, as generator/generate.exs --check runs it, still exactly one JSON document on
  # stdout. What the document holds is conformance_test.exs's. Not async: it captures
  # standard error.
  use ExUnit.Case, async: false

  import ExUnit.CaptureIO

  alias Mix.Tasks.Truestamp.Conformance, as: ConformanceTask
  alias Truestamp.Verifier.{Conformance, JCS, Parser}
  alias Truestamp.Verifier.Test.Cases

  @project Path.expand("../../..", __DIR__)

  # {what the task wrote to stdout, to stderr, and how it ended}, each device capturing in
  # `encoding`.
  defp task(argv, encoding \\ :unicode) do
    written_err =
      capture_io(:stderr, [encoding: encoding], fn ->
        written_out =
          capture_io([encoding: encoding], fn ->
            ended =
              try do
                ConformanceTask.run(argv)
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

  # A cases file of one offline case, in a directory whose name is not ASCII, whose proof
  # is missing, so its entry is an `error` naming that path.
  defp missing_proof_cases do
    dir = temporary_directory("clés-鍵")
    kase = hd(Cases.offline())
    kase = %{kase | "proof" => "missing.proof.json"} |> put_in(["config", "keyring"], "none")
    path = Path.join(dir, "cases.json")
    File.write!(path, JCS.encode([kase]))
    {path, Path.join(dir, "missing.proof.json")}
  end

  test "writes the entry point's output and returns for exit code 0" do
    argv = [Cases.path()]
    {0, stdout, stderr} = Conformance.main(argv)
    {written_out, written_err, ended} = task(argv)
    assert ended == :ok
    assert written_out == IO.iodata_to_binary(stdout)
    assert written_err == IO.iodata_to_binary(stderr)
  end

  test "an invalid command line exits 1, with the usage on standard error only" do
    {written_out, written_err, ended} = task([])
    assert ended == {:exit, {:shutdown, 1}}
    assert written_out == ""
    assert written_err =~ Conformance.usage()
  end

  test "writes raw bytes, so an entry naming a non-ASCII path is UTF-8 JSON on a latin1 device" do
    {cases, missing} = missing_proof_cases()
    {0, stdout, _stderr} = Conformance.main([cases])
    {written_out, _written_err, :ok} = task([cases], :latin1)
    assert written_out == IO.iodata_to_binary(stdout)
    assert {:ok, [%{"output" => %{"error" => error}}]} = Parser.parse(written_out)
    assert error =~ missing
  end

  @tag timeout: 300_000
  test "run as its own process on a build that compiles, stdout is exactly one JSON document" do
    # A copy of this build with the project's compile manifest removed, so the project
    # compiles again, and with the entry point's own modules removed, so Mix has to compile
    # before it can find the task, as on a fresh checkout. The locale is C.
    root = temporary_directory("build")
    build = Path.join(root, "test")
    File.cp_r!(Mix.Project.build_path(), build)
    ebin = Path.join(build, "lib/truestamp_verifier/ebin")
    File.rm!(Path.join(build, "lib/truestamp_verifier/.mix/compile.elixir"))
    File.rm!(Path.join(ebin, "Elixir.Mix.Tasks.Truestamp.Conformance.beam"))
    File.rm!(Path.join(ebin, "Elixir.Truestamp.Verifier.Conformance.beam"))

    stderr_file = Path.join(root, "stderr.txt")

    {stdout, exit_status} =
      System.cmd(
        "sh",
        ["-c", ~s(exec mix truestamp.conformance "$1" 2>"$2"), "sh", Cases.path(), stderr_file],
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
    assert exit_status == 0, stderr
    assert File.exists?(Path.join(ebin, "Elixir.Mix.Tasks.Truestamp.Conformance.beam"))
    assert String.ends_with?(stdout, "]\n") and length(String.split(stdout, "\n")) == 2
    assert {:ok, document} = Parser.parse(String.trim_trailing(stdout, "\n"))
    {0, expected, _stderr} = Conformance.main([Cases.path()])
    assert stdout == IO.iodata_to_binary(expected)
    assert JCS.encode(document) <> "\n" == stdout
  end
end
