# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Truestamp.Verification.MixProject do
  use Mix.Project

  # The reference verifier, the library Truestamp.Verify (truestamp-verify-ex), at the
  # commit this repository's checks run. The generator runs its Mix tasks here as their own
  # processes, and test/spec_mirror_test.exs holds the spec data it compiles in to spec/.
  @verify_ref "274cef9e2f127a6a7d41522298d760ab16747679"

  def project do
    [
      app: :truestamp_verification,
      version: "0.1.0",
      elixir: "~> 1.19",
      start_permanent: Mix.env() == :prod,
      elixirc_paths: elixirc_paths(Mix.env()),
      deps: deps(),
      aliases: aliases()
    ]
  end

  defp elixirc_paths(:test), do: ["test/support"]
  defp elixirc_paths(_), do: []

  def application do
    [extra_applications: [:crypto]]
  end

  # `mix truestamp.verify`, `mix truestamp.conformance` and `mix truestamp.agent_lines`
  # compile the project and its dependencies before they run, with a quiet shell and with
  # standard error as the group leader, so a run that compiles writes nothing to standard
  # output, which carries only the task's JSON document. Compiler warnings and errors, and
  # the "==> app" line Mix prints ahead of a dependency's, go to standard error. The tasks
  # come from the library, which keeps Logger's output off standard output while they start.
  defp aliases do
    [
      "truestamp.verify": [&quiet_compile/1, "truestamp.verify"],
      "truestamp.conformance": [&quiet_compile/1, "truestamp.conformance"],
      "truestamp.agent_lines": [&quiet_compile/1, "truestamp.agent_lines"]
    ]
  end

  defp quiet_compile(_args) do
    {shell, group_leader} = {Mix.shell(), Process.group_leader()}
    Mix.shell(Mix.Shell.Quiet)
    Process.group_leader(self(), Process.whereis(:standard_error))

    try do
      Mix.Task.run("compile")
    after
      Process.group_leader(self(), group_leader)
      Mix.shell(shell)
    end
  end

  defp deps do
    [
      # Pinned to a full commit id until the library is published to Hex. It brings the
      # Merkle library, truestamp_merkle, at the commit it pins.
      {:truestamp_verify, github: "truestamp/truestamp-verify-ex", ref: @verify_ref},
      {:credo, "~> 1.7", only: [:dev, :test], runtime: false}
    ]
  end
end
