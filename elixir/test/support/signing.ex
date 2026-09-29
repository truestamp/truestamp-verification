# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Truestamp.Verifier.Test.Signing do
  @moduledoc """
  Documents signed here, for the tests of the later steps and the command: a sound proof of
  `vectors/positive/`, changed and signed again by a key of a seed, and a run attributed to
  Truestamp, which no shared case gives (SPEC.md 13.3).
  """

  import ExUnit.Assertions

  alias Truestamp.Verifier

  alias Truestamp.Verifier.{
    Base64url,
    Config,
    Gate,
    JCS,
    KeyId,
    Keyring,
    Parser,
    RecordHash,
    Run
  }

  alias Truestamp.Verifier.Test.{Cases, StrictJSON}

  @doc "P of the sound proof `vectors/positive/<name>.proof.json`."
  @spec positive(String.t()) :: map()
  def positive(name) do
    bytes = File.read!(Path.join(Cases.vectors(), "positive/#{name}.proof.json"))
    {:ok, %{"proof" => proof}} = Parser.decode(bytes)
    proof
  end

  @doc "The Ed25519 key pair of the seed of 32 bytes of `seed`."
  @spec key_pair(byte()) :: {binary(), binary()}
  def key_pair(seed), do: :crypto.generate_key(:eddsa, :ed25519, :binary.copy(<<seed>>, 32))

  @doc """
  The served document of `proof`, signed over its proof_hash by the key of `seed` (0x42 is
  VECTOR_KEY's, 0x07 a key no file lists).
  """
  @spec signed(map(), byte()) :: binary()
  def signed(proof, seed) do
    {public, secret} = key_pair(seed)

    signature =
      :crypto.sign(:eddsa, :none, RecordHash.hash(:proof_hash, proof), [secret, :ed25519])

    JCS.encode(%{
      "proof" => proof,
      "signature" => %{
        "alg" => Gate.alg(),
        "public_key" => Base64url.encode(public),
        "value" => Base64url.encode(signature)
      }
    })
  end

  @doc """
  A run of `proof`, unmarked and signed by the key of 0x07, through every step, under E_v
  prod and the real compiled-pin trust root, with only the pin's keys replaced by that key:
  no shared case binds under the compiled pin (13.3), which holds no key yet. The pins are
  the `test` row's, the networks of the modelled chains, and `options` are more
  configuration.
  """
  @spec truestamp_run(map(), keyword()) :: Run.t()
  def truestamp_run(proof, options \\ []) do
    {public, _secret} = key_pair(0x07)

    key = %{
      "active" => true,
      "key_id" => KeyId.of(public),
      "public_key" => Base64url.encode(public),
      "sequence" => 0
    }

    keyring = StrictJSON.canonical(%{"keys" => [key], "version" => "1.0"})
    {:ok, keys} = Keyring.load(keyring, "prod")
    config = Config.new!([networks: Config.default_pins("test")] ++ options)
    {:ok, run} = Gate.configuration(config)
    assert run.trust_root.kind == :compiled_pin
    bytes = proof |> Map.delete("environment") |> signed(0x07)

    {:ok, run} = Gate.read(%{run | keyring: keys}, bytes)
    {:ok, run} = Gate.parse(run, bytes)
    {:ok, run} = Gate.envelope(run)
    Verifier.after_envelope(run)
  end
end
