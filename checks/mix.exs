# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Truestamp.Verification.MixProject do
  use Mix.Project

  # The tests of this repository: that spec/ says what SPEC.md says, that the vectors are laid
  # out and recorded as section 13.2 says, and that the generator's check fails when it must.
  # They depend on no verifier: each verifier holds itself to these files in its own tests.
  def project do
    [
      app: :truestamp_verification,
      version: "0.1.0",
      elixir: "~> 1.19",
      start_permanent: Mix.env() == :prod,
      elixirc_paths: elixirc_paths(Mix.env()),
      deps: deps()
    ]
  end

  defp elixirc_paths(:test), do: ["test/support"]
  defp elixirc_paths(_), do: []

  def application do
    [extra_applications: [:crypto]]
  end

  defp deps do
    [
      # The Merkle tree and inclusion proofs of RFC 9162 section 2.1, which test/merkle_walk_test.exs
      # holds to the RFC. Pinned to a full commit id until it is published to Hex.
      {:truestamp_merkle,
       github: "truestamp/truestamp-merkle-elixir",
       ref: "0c08983854eb7bd24c7aaebb4664da4e5a28f2c0",
       depth: 1},
      {:credo, "~> 1.7", only: [:dev, :test], runtime: false}
    ]
  end
end
