# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Truestamp.Verifier.ConfigTest do
  # Truestamp.Verifier.Config: the run configuration step 0 fixes (SPEC.md 10.2), set only
  # from explicit options (sections 6.4 and 8.3).
  use ExUnit.Case, async: true

  alias Truestamp.Verifier.Config
  alias Truestamp.Verifier.Test.StrictJSON

  @root Path.expand("../../..", __DIR__)
  @network_pins Path.join(@root, "spec/network-pins.json")
  @external_resource @network_pins

  test "by default: E_v prod, no keyring option, every pin at its production network" do
    assert {:ok, config} = Config.new()
    assert config.environment == "prod"
    assert config.keyring == nil
    assert config.expected_hash == nil
    pins = %{"bitcoin" => "mainnet", "stellar" => "public"}
    assert config.networks == %{commitment: pins, entropy: pins}
    assert %Config{}.networks == config.networks
  end

  # SPEC.md 9: the default pins follow E_v, from spec/network-pins.json.
  test "the compiled default pins are spec/network-pins.json, one row for each E_v" do
    table = StrictJSON.read_data!(@network_pins)
    assert Enum.sort(Map.keys(table)) == Enum.sort(Config.environments())

    for environment <- Config.environments() do
      %{"commitment" => commitment, "entropy" => entropy} = Map.fetch!(table, environment)
      pins = %{commitment: commitment, entropy: entropy}
      assert Config.default_pins(environment) == pins, environment
      assert Config.new!(environment: environment).networks == pins, environment
    end
  end

  test "a staging run defaults to staging's pins, Bitcoin entropy on mainnet, in any order" do
    staging = %{
      commitment: %{"bitcoin" => "regtest", "stellar" => "testnet"},
      entropy: %{"bitcoin" => "mainnet", "stellar" => "testnet"}
    }

    for options <- [
          [environment: "staging", keyring: {:file, "k.json"}],
          [keyring: {:file, "k.json"}, environment: "staging"],
          [environment: "staging", keyring: :none]
        ] do
      assert Config.new!(options).networks == staging, inspect(options)
    end
  end

  test "a networks option gives every pin in place of the row for E_v, in any order" do
    # Pins equal to neither the prod row nor staging's, so neither default can pass for them.
    networks = %{
      commitment: %{"bitcoin" => "mainnet", "stellar" => "testnet"},
      entropy: %{"bitcoin" => "regtest", "stellar" => "public"}
    }

    refute networks == Config.default_pins("prod")
    refute networks == Config.default_pins("staging")

    for options <- [
          [environment: "staging", networks: networks],
          [networks: networks, environment: "staging"]
        ] do
      assert Config.new!(options).networks == networks, inspect(options)
    end
  end

  test "E_v is prod or an ENV value of spec/encodings.json (SPEC.md 6.4)" do
    assert Config.environments() == ~w(prod dev staging test)

    for environment <- Config.environments() do
      assert {:ok, %Config{environment: ^environment}} = Config.new(environment: environment)
    end

    for bad <- ["production", "PROD", "test\n", "", nil, :prod] do
      assert Config.new(environment: bad) == {:error, {:invalid_option, :environment}}
    end
  end

  test "the keyring source is none, keyless, a file or bytes, one at a time" do
    for keyring <- [nil, :none, {:file, "k.json"}, {:bytes, "{}", nil}, {:bytes, "{}", "here"}] do
      assert {:ok, %Config{keyring: ^keyring}} = Config.new(keyring: keyring)
    end

    for bad <- [:test, {:file, nil}, {:bytes, "{}"}, {:bytes, nil, nil}, [:none, {:file, "k"}]] do
      assert Config.new(keyring: bad) == {:error, {:invalid_option, :keyring}}
    end
  end

  test "each pin names a network of its chain in spec/networks.json" do
    good = %{"bitcoin" => "regtest", "stellar" => "testnet"}
    assert {:ok, _config} = Config.new(networks: %{commitment: good, entropy: good})

    for bad <- [
          %{commitment: good},
          %{commitment: good, entropy: %{"bitcoin" => "regtest"}},
          %{commitment: good, entropy: %{good | "stellar" => "mainnet"}},
          %{commitment: good, entropy: Map.put(good, "nist", "public")},
          %{commitment: good, entropy: good, online: true}
        ] do
      assert Config.new(networks: bad) == {:error, {:invalid_option, :networks}}, inspect(bad)
    end
  end

  test "a non-string expected hash, or a keyring location that is not a string, is refused" do
    for bad <- [5, :hash, ["ab"]] do
      assert Config.new(expected_hash: bad) == {:error, {:invalid_option, :expected_hash}}
    end

    for location <- [5, :here, ["k.json"]] do
      assert Config.new(keyring: {:bytes, "{}", location}) ==
               {:error, {:invalid_option, :keyring}}
    end
  end

  test "a repeated option is refused, so two values never resolve by their order" do
    for options <- [
          [keyring: {:file, "k.json"}, keyring: :none],
          [keyring: :none, keyring: {:file, "k.json"}],
          [keyring: :none, keyring: :none]
        ] do
      assert Config.new(options) == {:error, {:invalid_option, :keyring}}, inspect(options)
    end

    for options <- [
          [environment: "test", environment: "prod"],
          [environment: "test", keyring: :none, environment: "test"]
        ] do
      assert Config.new(options) == {:error, {:invalid_option, :environment}}, inspect(options)
    end

    pins = %{"bitcoin" => "regtest", "stellar" => "testnet"}
    networks = %{commitment: pins, entropy: pins}

    for options <- [
          [networks: networks, networks: Config.default_pins("prod")],
          [networks: networks, environment: "test", networks: networks]
        ] do
      assert Config.new(options) == {:error, {:invalid_option, :networks}}, inspect(options)
    end

    hash = String.duplicate("ab", 32)

    for options <- [
          [expected_hash: hash, expected_hash: nil],
          [expected_hash: hash, keyring: :none, expected_hash: hash]
        ] do
      assert Config.new(options) == {:error, {:invalid_option, :expected_hash}},
             inspect(options)
    end
  end

  test "an unknown option is refused, so nothing but these members configures a run" do
    assert Config.new(online: true) == {:error, {:invalid_option, :online}}
    assert Config.new(keyless: true) == {:error, {:invalid_option, :keyless}}
    assert_raise ArgumentError, fn -> Config.new!(environment: "production") end
  end
end
