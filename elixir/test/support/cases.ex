# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Truestamp.Verifier.Test.Cases do
  @moduledoc """
  The cases of `vectors/cases.json` (SPEC.md section 13.2), and each case's configuration
  as the reference verifier takes it (section 13.1): a keyring path or `test` is a supplied
  keyring file, `none` is keyless mode, and an absent `keyring` is no keyring option.

  `cases.json` is read with `Truestamp.Verifier.Test.StrictJSON`, since it is larger than
  MAX_READ_OCTETS, which binds a document, not a data file; a case's proof is handed to the
  verifier as its bytes, so the verifier's own `Parser` reads it.
  """

  alias Truestamp.Verifier.Config
  alias Truestamp.Verifier.Test.StrictJSON

  @vectors Path.expand("../../../vectors", __DIR__)

  @doc "The absolute path of `vectors/`."
  @spec vectors() :: Path.t()
  def vectors, do: @vectors

  @doc "The absolute path of `vectors/cases.json`."
  @spec path() :: Path.t()
  def path, do: Path.join(@vectors, "cases.json")

  @doc "Every case, in the file's order."
  @spec all() :: [map()]
  def all, do: StrictJSON.read_data!(path())

  @doc "Every offline case: one without `online` (section 13.2), which a reference verifier runs."
  @spec offline() :: [map()]
  def offline, do: Enum.reject(all(), &Map.has_key?(&1["config"], "online"))

  @doc "The bytes of the case's proof."
  @spec proof(map()) :: binary()
  def proof(%{"proof" => path}), do: File.read!(Path.join(@vectors, path))

  @doc "The case's configuration, as `Truestamp.Verifier.Config` holds it."
  @spec config(map()) :: Config.t()
  def config(%{"config" => config}) do
    %{"commitment" => commitment, "entropy" => entropy} = Map.fetch!(config, "networks")

    Config.new!(
      environment: Map.fetch!(config, "environment"),
      keyring: keyring(Map.get(config, "keyring")),
      networks: %{commitment: commitment, entropy: entropy},
      expected_hash: Map.get(config, "expected_hash")
    )
  end

  defp keyring(nil), do: nil
  defp keyring("none"), do: :none
  defp keyring("test"), do: {:file, Path.join(@vectors, "keyring.test.json")}
  defp keyring("unavailable"), do: raise(ArgumentError, "an online case's keyring")
  defp keyring(path), do: {:file, Path.join(@vectors, path)}

  @doc """
  Where steps 0 to 6 (the gate, SPEC.md 10.2) decide the case: `:bare` for a bare
  rejection at steps 0 to 3; `:gate` for a report with a failing row at ENVIRONMENT,
  KEY_BINDING or SIGNATURE; `:later` for every other report, whose gate opens.
  """
  @spec gate_class(map()) :: :bare | :gate | :later
  def gate_class(%{"expected" => %{"code" => _code}}), do: :bare

  def gate_class(%{"expected" => %{"rows" => rows}}) do
    failed_at_gate? =
      Enum.any?(rows, fn [_code, _part, status, step] ->
        status == "fail" and step in ~w(ENVIRONMENT KEY_BINDING SIGNATURE)
      end)

    if failed_at_gate?, do: :gate, else: :later
  end

  @doc """
  Where steps 0 to 8 decide the case: `gate_class/1`'s `:bare` and `:gate`, and for a case
  whose gate opens, `:shape` for a failing row at SHAPE, `:policy` for one at POLICY, and
  `:later` for every other.
  """
  @spec step_class(map()) :: :bare | :gate | :shape | :policy | :later
  def step_class(kase) do
    case gate_class(kase) do
      :later -> later_class(kase["expected"]["rows"])
      class -> class
    end
  end

  defp later_class(rows) do
    failing = for [_code, _part, "fail", step] <- rows, do: step

    cond do
      "SHAPE" in failing -> :shape
      "POLICY" in failing -> :policy
      true -> :later
    end
  end

  @doc """
  Where steps 0 to 9 decide the case: `step_class/1`'s `:bare`, `:gate`, `:shape` and
  `:policy`, and for a case whose gate opens and whose POLICY rows all pass, `:derive` for a
  failing row at DERIVE, and `:passes` when no row of steps 0 to 9 fails.
  """
  @spec derive_class(map()) :: :bare | :gate | :shape | :policy | :derive | :passes
  def derive_class(kase) do
    case step_class(kase) do
      :later -> if failing_at?(kase, "DERIVE"), do: :derive, else: :passes
      class -> class
    end
  end

  defp failing_at?(kase, step),
    do: Enum.any?(kase["expected"]["rows"], &match?([_code, _part, "fail", ^step], &1))

  @doc "The bytes of the keyring file the case supplies, or nil for none."
  @spec keyring_bytes(map()) :: binary() | nil
  def keyring_bytes(kase) do
    case config(kase).keyring do
      {:file, path} -> File.read!(path)
      _other -> nil
    end
  end
end
