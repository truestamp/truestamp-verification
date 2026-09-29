# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Truestamp.Verifier.ExpectedHash do
  @moduledoc """
  Step 13 of SPEC.md section 10.2, EXPECTED_HASH: the caller's hash (`--expected-hash HEX`,
  the run's `expected_hash`) against `/subject/claims/hash`. The step reports one row.

  - No hash given: `skip expected_hash_not_checked`, part null.
  - A hash given: one row at `/subject/claims/hash`, whatever the proof holds there:
    - `pass` only when the type is `item`, `/subject/claims/hash_type` is a name of the table
      below, `/subject/claims/hash` is a string, and the caller's value, lowercased, is hex
      of that type's length and equals `/subject/claims/hash`;
    - such a match under `md5` or `sha1` is `warn expected_hash_weak_algorithm` in place of
      `pass`;
    - anything else is `fail expected_hash_mismatch`, never a skip (D58 item 1), with
      `values` saying why under `reason`: `no_listed_hash` (the proof is not an item, or its
      claims have no `hash` of a listed type), `not_hex_of_length` (the caller's value is not
      hex of that type's length) or `differs`.

  When the attribution is not `truestamp`, the message of a match says that it is against a
  document not attributed to Truestamp. No other member of `claims` is read, and the claims
  are never judged true: the step checks the caller's file against the submitter's
  statement (section 10.6).

  After a failure at the gate or at SHAPE the run has ended, and its EXPECTED_HASH row is
  already `skip prior_failure`; such a run passes through unchanged. A failure at POLICY or
  DERIVE does not stop this step.

  **Values** (section 10.5): `expected_hash`, the caller's value lowercased, which the proof
  does not carry; on `not_hex_of_length`, `hex_characters`, the length the table gives; on
  `differs`, `declared`, the `hash` the proof carries, which the failed comparison
  contradicts. A pass or warn row holds no value of the proof.
  """

  alias Truestamp.Verifier.{Layout, Row, Run}

  @step "EXPECTED_HASH"
  @part "/subject/claims/hash"

  # SPEC.md 10.2, step 13: each hash_type and the length of its hex. A test holds this to
  # SPEC.md's table.
  @hex_characters %{
    "md5" => 32,
    "sha1" => 40,
    "sha224" => 56,
    "sha3_224" => 56,
    "sha256" => 64,
    "sha3_256" => 64,
    "blake2s" => 64,
    "sha384" => 96,
    "sha3_384" => 96,
    "sha512" => 128,
    "sha3_512" => 128,
    "blake2b" => 128
  }

  @weak ["md5", "sha1"]

  @doc "The table of step 13: each `hash_type` and the number of hex characters of its hash."
  @spec hex_characters() :: %{String.t() => pos_integer()}
  def hex_characters, do: @hex_characters

  @doc "Step 13, EXPECTED_HASH: one row."
  @spec expected_hash(Run.t()) :: Run.t()
  def expected_hash(%Run{ended: true} = run), do: run

  def expected_hash(%Run{config: %{expected_hash: nil}} = run) do
    message = "No expected hash was given, so the claims' hash was not compared with one."
    Run.add_row(run, Row.new(@step, :expected_hash_not_checked, nil, message))
  end

  def expected_hash(%Run{config: %{expected_hash: given}} = run) when is_binary(given) do
    expected = String.downcase(given, :ascii)
    Run.add_row(run, compare(expected, listed_hash(run.type, run.proof), run.attribution))
  end

  # {hash_type, hash} when the proof is an item whose claims hold a hash of a listed type.
  defp listed_hash("item", proof) do
    hash_type = Layout.get(proof, ["subject", "claims", "hash_type"])
    hash = Layout.get(proof, ["subject", "claims", "hash"])

    if Map.has_key?(@hex_characters, hash_type) and is_binary(hash),
      do: {hash_type, hash},
      else: nil
  end

  defp listed_hash(_type, _proof), do: nil

  defp compare(expected, nil, _attribution) do
    message =
      "An expected hash was given, and this proof has no hash of a listed type to compare " <>
        "it with: it is not an item, or its claims hold no hash of a listed hash_type."

    mismatch(message, expected, "no_listed_hash", %{})
  end

  defp compare(expected, {hash_type, hash}, attribution) do
    length = Map.fetch!(@hex_characters, hash_type)

    cond do
      not hex?(expected, length) ->
        message =
          "The expected hash is not hex of #{length} characters, the length of this " <>
            "proof's hash_type."

        mismatch(message, expected, "not_hex_of_length", %{"hex_characters" => length})

      expected !== hash ->
        message = "The expected hash differs from the hash in this proof's claims."
        mismatch(message, expected, "differs", %{"declared" => hash})

      true ->
        match(hash_type, expected, attribution)
    end
  end

  defp match(hash_type, expected, attribution) when hash_type in @weak do
    message =
      "The expected hash equals the hash in this proof's claims, but its hash_type is " <>
        "#{hash_type}, whose collisions are practical, so a different file can share it." <>
        attributed(attribution)

    Row.new(@step, :expected_hash_weak_algorithm, @part, message, values(expected))
  end

  defp match(_hash_type, expected, attribution) do
    message =
      "The expected hash equals the hash in this proof's claims." <> attributed(attribution)

    Row.pass(@step, @part, message, values(expected))
  end

  defp mismatch(message, expected, reason, values) do
    values = expected |> values() |> Map.put("reason", reason) |> Map.merge(values)
    Row.new(@step, :expected_hash_mismatch, @part, message, values)
  end

  defp values(expected), do: %{"expected_hash" => expected}

  defp attributed("truestamp"), do: ""

  defp attributed(_attribution),
    do: " The match is against a document not attributed to Truestamp."

  defp hex?(value, length),
    do: byte_size(value) == length and value =~ ~r/\A[0-9a-f]+\z/
end
