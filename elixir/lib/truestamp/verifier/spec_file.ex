# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Truestamp.Verifier.SpecFile do
  @moduledoc """
  Reads a data file under `spec/` (SPEC.md section 9) at compile time, for the modules that
  hold its contents as compiled constants.

  A file is read under the parsing rules of section 10.1, with `Truestamp.Verifier.Parser`,
  the same reader the verifier applies to a document; a file that breaks them stops the
  build. Each caller names the file with `@external_resource path(name)`, so a change to the
  file recompiles it.
  """

  alias Truestamp.Verifier.Parser

  @spec_dir Path.expand("../../../../spec", __DIR__)

  @doc "The absolute path of `name` under `spec/`."
  @spec path(String.t()) :: Path.t()
  def path(name), do: Path.join(@spec_dir, name)

  @doc "The value of `spec/<name>`, read under section 10.1. Raises when it breaks a rule."
  @spec read!(String.t()) :: Parser.value()
  def read!(name) do
    case name |> path() |> File.read!() |> Parser.decode() do
      {:ok, value} -> value
      {:error, reason} -> raise ArgumentError, "spec/#{name}: #{inspect(reason)}"
    end
  end

  @doc """
  The byte a registry entry writes as `0x` and two lowercase hex digits, as
  `spec/prefixes.json` does. Raises on any other spelling.
  """
  @spec byte!(String.t()) :: byte()
  def byte!(<<"0x", hex::binary-2>> = text) do
    if hex =~ ~r/\A[0-9a-f]{2}\z/,
      do: String.to_integer(hex, 16),
      else: raise(ArgumentError, "not a prefix byte: #{inspect(text)}")
  end

  def byte!(text), do: raise(ArgumentError, "not a prefix byte: #{inspect(text)}")
end
