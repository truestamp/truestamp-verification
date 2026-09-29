# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Mix.Tasks.Truestamp.AgentLinesTest do
  # `mix truestamp.agent_lines` writes what Truestamp.Verifier.AgentLines gives, stdout and
  # stderr, as raw bytes, and exits with its code: 0 with the document, 1 for a command line
  # it cannot use, and 2 for a fault inside the entry point; and, run as its own process on a
  # build that has to compile, as generator/generate.exs runs it, still exactly one JSON
  # document on stdout. What the document holds is agent_lines_test.exs's. Not async: it
  # captures standard error.
  use ExUnit.Case, async: false

  import ExUnit.CaptureIO

  alias Mix.Tasks.Truestamp.AgentLines, as: AgentLinesTask
  alias Truestamp.Verifier.{AgentLines, JCS, Parser}
  alias Truestamp.Verifier.Test.Cases

  @project Path.expand("../../..", __DIR__)

  # {what the task wrote to stdout, to stderr, and how it ended}.
  defp task(argv) do
    written_err =
      capture_io(:stderr, fn ->
        written_out =
          capture_io(fn ->
            ended =
              try do
                AgentLinesTask.run(argv)
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

  # A runs file of the sound item under the test keyring, beside copies of both.
  defp runs_file do
    dir = temporary_directory("runs")

    for name <- ["keyring.test.json", "positive/item.proof.json"],
        do: File.cp!(Path.join(Cases.vectors(), name), Path.join(dir, Path.basename(name)))

    run = %{
      "environment" => "test",
      "id" => "item",
      "keyring" => "keyring.test.json",
      "proof" => "item.proof.json"
    }

    path = Path.join(dir, "runs.json")
    File.write!(path, JCS.encode([run]))
    path
  end

  test "writes the entry point's output and returns for exit code 0" do
    argv = [runs_file()]
    {0, stdout, stderr} = AgentLines.main(argv)
    {written_out, written_err, ended} = task(argv)
    assert ended == :ok
    assert written_out == IO.iodata_to_binary(stdout)
    assert written_err == IO.iodata_to_binary(stderr)
  end

  test "an invalid command line exits 1, with the usage on standard error only" do
    {written_out, written_err, ended} = task([])
    assert ended == {:exit, {:shutdown, 1}}
    assert written_out == ""
    assert written_err =~ AgentLines.usage()
  end

  test "a fault inside the entry point exits 2, with nothing on standard output" do
    {written_out, written_err, ended} = task([123])
    assert ended == {:exit, {:shutdown, 2}}
    assert written_out == ""
    assert written_err =~ "A fault inside the agent-test entry point: "
  end

  @tag timeout: 300_000
  test "run as its own process on a build that compiles, stdout is exactly one JSON document" do
    # A copy of this build with the project's compile manifest removed, so the project
    # compiles again, and with the entry point's own modules removed, so Mix has to compile
    # before it can find the task, as on a fresh checkout. The locale is C.
    runs = runs_file()
    root = temporary_directory("build")
    build = Path.join(root, "test")
    File.cp_r!(Mix.Project.build_path(), build)
    ebin = Path.join(build, "lib/truestamp_verifier/ebin")
    File.rm!(Path.join(build, "lib/truestamp_verifier/.mix/compile.elixir"))
    File.rm!(Path.join(ebin, "Elixir.Mix.Tasks.Truestamp.AgentLines.beam"))
    File.rm!(Path.join(ebin, "Elixir.Truestamp.Verifier.AgentLines.beam"))

    stderr_file = Path.join(root, "stderr.txt")

    {stdout, exit_status} =
      System.cmd(
        "sh",
        ["-c", ~s(exec mix truestamp.agent_lines "$1" 2>"$2"), "sh", runs, stderr_file],
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
    assert File.exists?(Path.join(ebin, "Elixir.Mix.Tasks.Truestamp.AgentLines.beam"))
    assert String.ends_with?(stdout, "]\n") and length(String.split(stdout, "\n")) == 2
    assert {:ok, document} = Parser.parse(String.trim_trailing(stdout, "\n"))
    {0, expected, _stderr} = AgentLines.main([runs])
    assert stdout == IO.iodata_to_binary(expected)
    assert JCS.encode(document) <> "\n" == stdout
  end
end
