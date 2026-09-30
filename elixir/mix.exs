# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Truestamp.Verifier.MixProject do
  use Mix.Project

  def project do
    [
      app: :truestamp_verifier,
      version: "0.1.0",
      elixir: "~> 1.19",
      start_permanent: Mix.env() == :prod,
      elixirc_paths: elixirc_paths(Mix.env()),
      deps: deps(),
      aliases: aliases()
    ]
  end

  defp elixirc_paths(:test), do: ["lib", "test/support"]
  defp elixirc_paths(_), do: ["lib"]

  def application do
    [extra_applications: [:crypto]]
  end

  # `mix truestamp.verify`, `mix truestamp.conformance` and `mix truestamp.agent_lines`
  # compile the project and its dependencies before they run, with a quiet shell, with
  # standard error as the group leader and with Logger's default handler writing to standard
  # error, so a run that compiles writes nothing to standard output, which carries only the
  # task's JSON document. Compiler warnings and errors, a dependency's warnings and log
  # lines, and the "==> app" line Mix prints ahead of them go to standard error.
  defp aliases do
    [
      "truestamp.verify": [&quiet_compile/1, "truestamp.verify"],
      "truestamp.conformance": [&quiet_compile/1, "truestamp.conformance"],
      "truestamp.agent_lines": [&quiet_compile/1, "truestamp.agent_lines"]
    ]
  end

  defp quiet_compile(_args) do
    shell = Mix.shell()
    group_leader = Process.group_leader()
    handler = log_to_standard_error()
    Mix.shell(Mix.Shell.Quiet)
    Process.group_leader(self(), Process.whereis(:standard_error))

    try do
      Mix.Task.run("compile")
    after
      Process.group_leader(self(), group_leader)
      Mix.shell(shell)
      restore_log_handler(handler)
    end
  end

  # Logger's default handler writes from its own process, not under this one's group
  # leader, so it is added again with standard error as its device while the build runs.
  defp log_to_standard_error do
    case :logger.get_handler_config(:default) do
      {:ok, %{module: module, config: %{type: :standard_io}} = handler} ->
        :ok = :logger.remove_handler(:default)
        :ok = :logger.add_handler(:default, module, put_in(handler.config.type, :standard_error))
        handler

      _other ->
        nil
    end
  end

  defp restore_log_handler(nil), do: :ok

  defp restore_log_handler(%{module: module} = handler) do
    :ok = :logger.remove_handler(:default)
    :ok = :logger.add_handler(:default, module, handler)
  end

  defp deps do
    [
      # The Merkle tree and inclusion proofs of RFC 9162 section 2.1. Pinned to a full
      # commit id until the library is published to Hex.
      {:truestamp_merkle,
       github: "truestamp/truestamp-merkle-elixir",
       ref: "0862f3e96f670ef605bdfa4077c96039040e585f",
       depth: 1},
      {:credo, "~> 1.7", only: [:dev, :test], runtime: false}
    ]
  end
end
