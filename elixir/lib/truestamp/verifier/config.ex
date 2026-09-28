# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Truestamp.Verifier.Config do
  @moduledoc """
  A run's configuration: what step CONFIGURATION (SPEC.md section 10.2, step 0) fixes
  before the file is read. The command of the reference verifier sets it from its options,
  and nothing else does: no configuration file, environment variable or document sets any
  member (sections 6.4 and 8.3).

  | Member | Option | Default | Holds |
  |---|---|---|---|
  | `environment` | `--environment NAME` | `"prod"` | E_v (section 6.4): `prod`, or an ENV value |
  | `keyring` | `--keyring FILE`, `--no-keyring` | nil | the keyring source (below) |
  | `networks` | none yet | the row of `spec/network-pins.json` for E_v | the network pins (section 9) |
  | `expected_hash` | `--expected-hash HEX` | nil | the caller's hash for EXPECTED_HASH |

  The keyring source is one of:

  - nil, no keyring option: under E_v `prod` the compiled pin governs (section 8.3; the
    reference verifier is offline, so the pin always governs, D31), and under any other E_v
    the run stops at CONFIGURATION with `configuration_error` (section 6.4);
  - `{:file, path}`, `--keyring FILE`: a supplied keyring read from that file;
  - `{:bytes, bytes, location}`: a supplied keyring given as its bytes, a configured
    keyring, with `location` naming where it came from, or nil;
  - `:none`, `--no-keyring`: keyless mode (section 8.3).

  Every run is offline: the reference verifier makes no chain, source or keyring read
  (section 8.3), so there is no online member.

  `networks` is `%{commitment: pins, entropy: pins}`, each pins a map from a chain's name,
  `"bitcoin"` or `"stellar"`, to one of its networks in `spec/networks.json`. POLICY
  (step 8) compares every `network` with them. Without a `networks` option they are the
  default pins of E_v, the row of `spec/network-pins.json` (SPEC.md section 9) for the
  run's environment, whichever order the options come in: under `prod` the production
  networks, and under `dev`, `staging` and `test` the networks those environments use, with
  a Bitcoin entropy pin of `mainnet` under `dev` and `staging` beside a Bitcoin commitment
  pin of `regtest`. A `networks` option gives every pin in place of that row, as a
  conformance case's `networks` does (section 13.2). No document sets a pin.

  Each option may be given once: a repeated option is refused, so two keyring sources, or
  two environments, never resolve by their order.
  """

  alias Truestamp.Verifier.SpecFile

  @external_resource SpecFile.path("encodings.json")
  @environments [
    "prod" | Map.fetch!(Map.fetch!(SpecFile.read!("encodings.json"), "ENV"), "values")
  ]

  @external_resource SpecFile.path("networks.json")
  @networks SpecFile.read!("networks.json")

  # The default pins of each E_v (SPEC.md section 9), as `networks` holds them. A test holds
  # this to spec/network-pins.json and to SPEC.md 9's table.
  @external_resource SpecFile.path("network-pins.json")
  @default_pins Map.new(SpecFile.read!("network-pins.json"), fn {environment, row} ->
                  {environment,
                   %{
                     commitment: Map.fetch!(row, "commitment"),
                     entropy: Map.fetch!(row, "entropy")
                   }}
                end)

  if Enum.sort(Map.keys(@default_pins)) != Enum.sort(@environments),
    do: raise("spec/network-pins.json does not hold one row for each E_v")

  @typedoc "A keyring source (see the module doc)."
  @type keyring ::
          nil | :none | {:file, Path.t()} | {:bytes, binary(), String.t() | nil}

  @typedoc "The pins of one kind: a network for each chain."
  @type pins :: %{String.t() => String.t()}

  @type t :: %__MODULE__{
          environment: String.t(),
          keyring: keyring(),
          networks: %{commitment: pins(), entropy: pins()},
          expected_hash: String.t() | nil
        }

  defstruct environment: "prod",
            keyring: nil,
            networks: Map.fetch!(@default_pins, "prod"),
            expected_hash: nil

  @doc "The values E_v can take: `prod` and the ENV values of `spec/encodings.json`."
  @spec environments() :: [String.t()]
  def environments, do: @environments

  @doc "The networks of each chain, from `spec/networks.json`."
  @spec networks() :: %{String.t() => [String.t()]}
  def networks, do: @networks

  @doc "The default pins of E_v `environment`: its row of `spec/network-pins.json`."
  @spec default_pins(String.t()) :: %{commitment: pins(), entropy: pins()}
  def default_pins(environment) when environment in @environments,
    do: Map.fetch!(@default_pins, environment)

  @doc """
  A configuration from keyword options, each a member above: `{:ok, config}`, or
  `{:error, {:invalid_option, name}}` for an option that is unknown, given more than once,
  or holds a value the member cannot take. Such an error is an invalid command line (exit
  code 1, section 12.2), not a verification result. Without a `networks` option, the pins
  are the default pins of the configured E_v (`default_pins/1`).
  """
  @spec new(keyword()) :: {:ok, t()} | {:error, {:invalid_option, atom()}}
  def new(options \\ []) when is_list(options) do
    with :ok <- once_each(options),
         {:ok, config} <- set(options) do
      if Keyword.has_key?(options, :networks),
        do: {:ok, config},
        else: {:ok, %{config | networks: default_pins(config.environment)}}
    end
  end

  @doc "As `new/1`, raising `ArgumentError` on an invalid option."
  @spec new!(keyword()) :: t()
  def new!(options \\ []) do
    case new(options) do
      {:ok, config} -> config
      {:error, reason} -> raise ArgumentError, inspect(reason)
    end
  end

  defp once_each(options) do
    options
    |> Keyword.keys()
    |> Enum.reduce_while(MapSet.new(), fn name, seen ->
      if MapSet.member?(seen, name),
        do: {:halt, {:error, {:invalid_option, name}}},
        else: {:cont, MapSet.put(seen, name)}
    end)
    |> case do
      {:error, _reason} = error -> error
      _seen -> :ok
    end
  end

  defp set(options) do
    Enum.reduce_while(options, {:ok, %__MODULE__{}}, fn {name, value}, {:ok, config} ->
      if valid?(name, value),
        do: {:cont, {:ok, Map.put(config, name, value)}},
        else: {:halt, {:error, {:invalid_option, name}}}
    end)
  end

  defp valid?(:environment, value), do: value in @environments
  defp valid?(:keyring, value), do: keyring?(value)
  defp valid?(:networks, value), do: networks?(value)
  defp valid?(:expected_hash, value), do: is_nil(value) or is_binary(value)
  defp valid?(_name, _value), do: false

  defp keyring?(nil), do: true
  defp keyring?(:none), do: true
  defp keyring?({:file, path}), do: is_binary(path)
  defp keyring?({:bytes, bytes, location}), do: is_binary(bytes) and location?(location)
  defp keyring?(_value), do: false

  defp location?(location), do: is_nil(location) or is_binary(location)

  defp networks?(%{commitment: commitment, entropy: entropy} = networks)
       when map_size(networks) == 2,
       do: pins?(commitment) and pins?(entropy)

  defp networks?(_value), do: false

  defp pins?(pins) when is_map(pins) do
    Enum.sort(Map.keys(pins)) == Enum.sort(Map.keys(@networks)) and
      Enum.all?(pins, fn {chain, network} -> network in Map.fetch!(@networks, chain) end)
  end

  defp pins?(_value), do: false
end
