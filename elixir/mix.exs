# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Truestamp.Verifier.MixProject do
  use Mix.Project

  def project do
    [
      app: :truestamp_verifier,
      version: "0.1.0",
      elixir: "~> 1.20",
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

  # `mix truestamp.verify` compiles the project with a quiet shell before it runs, so a run
  # that compiles writes no compiler line to standard output, which carries only the
  # command's JSON document. Compiler warnings and errors still go to standard error.
  defp aliases, do: ["truestamp.verify": [&quiet_compile/1, "truestamp.verify"]]

  defp quiet_compile(_args) do
    shell = Mix.shell()
    Mix.shell(Mix.Shell.Quiet)

    try do
      Mix.Task.run("compile")
    after
      Mix.shell(shell)
    end
  end

  defp deps do
    [
      # The Merkle tree and inclusion proofs of RFC 9162 section 2.1. Pinned to a full
      # commit id until the library is published to Hex.
      {:truestamp_merkle,
       github: "truestamp/truestamp-merkle-elixir",
       ref: "2ba4a58089c289ca0dfcbce8a893260509b41ab1",
       depth: 1},
      {:credo, "~> 1.7", only: [:dev, :test], runtime: false}
    ]
  end
end
