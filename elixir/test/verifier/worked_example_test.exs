# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Truestamp.Verifier.WorkedExampleTest do
  # The worked example of SPEC.md 6.3, from vectors/worked-example.json: each quantity
  # recomputed with the primitives, the stranger's recipe run on the served document, the
  # reformattings that still verify and the messages that do not.
  use ExUnit.Case, async: true

  alias Truestamp.Verifier.{Base64url, Constants, Ed25519, JCS, KeyId, Parser, RecordHash}

  @root Path.expand("../../..", __DIR__)
  @path Path.join(@root, "vectors/worked-example.json")
  @external_resource @path

  setup_all do
    {:ok, example} = @path |> File.read!() |> Parser.decode()
    {:ok, example: example}
  end

  defp hex(bytes), do: Base.encode16(bytes, case: :lower)
  defp unhex(text), do: Base.decode16!(text, case: :lower)

  test "holds the members SPEC.md 13.2 lists", %{example: example} do
    assert Enum.sort(Map.keys(example)) ==
             Enum.sort(~w(proof M proof_hash sk A K key_id S V document))
  end

  test "M is JCS of the proof, 76 octets, and the corpus pair agrees", %{example: example} do
    m = JCS.encode(example["proof"])
    assert m == example["M"]
    assert byte_size(m) == 76

    corpus = Path.join(@root, "vectors/corpus/jcs/worked-example")
    {:ok, input} = Parser.decode(File.read!(corpus <> ".input.json"))
    assert input == example["proof"]
    assert File.read!(corpus <> ".output.json") == m
  end

  test "proof_hash is H(0x50, proof), and SHA-256(0x50 || M)", %{example: example} do
    assert RecordHash.hash_hex(:proof_hash, example["proof"]) == example["proof_hash"]
    assert hex(:crypto.hash(:sha256, <<0x50>> <> example["M"])) == example["proof_hash"]
  end

  test "A is VECTOR_KEY, the key of the seed sk, K spells it, and its key id", %{
    example: example
  } do
    a = unhex(example["A"])
    {public, _secret} = :crypto.generate_key(:eddsa, :ed25519, unhex(example["sk"]))

    assert public == a
    assert example["A"] == Constants.vector_key()
    assert Base64url.decode(:b64u32, example["K"]) == {:ok, a}
    assert Base64url.encode(a) == example["K"]
    assert KeyId.of(a) == example["key_id"]
    assert Ed25519.check_key_bytes(a) == :ok
  end

  test "V spells S, and S verifies under A over proof_hash's 32 octets", %{example: example} do
    s = unhex(example["S"])
    assert Base64url.decode(:b64u64, example["V"]) == {:ok, s}
    assert Ed25519.verify(unhex(example["A"]), unhex(example["proof_hash"]), s) == :ok
  end

  test "the stranger's recipe passes the served document, of 293 octets", %{example: example} do
    document = example["document"]
    assert byte_size(document) == 293
    assert recipe(document) == :ok

    {:ok, value} = Parser.decode(document)
    assert JCS.encode(value) == document
  end

  test "the document still verifies reformatted, reordered, escaped and with 1.0 for 1", %{
    example: example
  } do
    [proof_text, signature_text] = [example["proof"], signature(example)] |> Enum.map(&loose/1)

    reformatted =
      "{\r\n  \"signature\" : " <>
        signature_text <> " ,\r\n  \"proof\" : " <> proof_text <> "\r\n}\r\n"

    assert reformatted != example["document"]
    assert recipe(reformatted) == :ok
  end

  test "S does not verify over any other message SPEC.md 6.3 names", %{example: example} do
    a = unhex(example["A"])
    s = unhex(example["S"])
    m = example["M"]
    proof_hash = unhex(example["proof_hash"])

    changed = Map.put(example["proof"], "environment", "dev")
    removed = Map.delete(example["proof"], "environment")

    for message <- [
          m,
          :crypto.hash(:sha256, m),
          example["proof_hash"],
          :crypto.hash(:sha256, <<0x31>> <> m),
          :crypto.hash(:sha256, <<0x62>> <> m),
          RecordHash.hash(:block_hash, example["proof"]),
          RecordHash.hash(:handover, example["proof"]),
          RecordHash.hash(:proof_hash, changed),
          RecordHash.hash(:proof_hash, removed)
        ] do
      refute message == proof_hash
      assert Ed25519.verify(a, message, s) == {:error, :equation}
    end
  end

  # The recipe of SPEC.md 6.3, as far as the primitives reach: every check but the keyring
  # lookup and the environment marker, which are steps of P7.2.
  defp recipe(file) do
    with {:ok, %{"proof" => proof, "signature" => signature} = doc} <- Parser.decode(file),
         true <- Enum.sort(Map.keys(doc)) == ["proof", "signature"] and is_map(proof),
         true <- Enum.sort(Map.keys(signature)) == ["alg", "public_key", "value"],
         "truestamp-ed25519-sha256-jcs" <- signature["alg"],
         {:ok, a} <- Base64url.decode(:b64u32, signature["public_key"]),
         :ok <- Ed25519.check_key_bytes(a),
         {:ok, s} <- Base64url.decode(:b64u64, signature["value"]) do
      Ed25519.verify(a, RecordHash.hash(:proof_hash, proof), s)
    end
  end

  defp signature(example) do
    %{
      "alg" => "truestamp-ed25519-sha256-jcs",
      "public_key" => example["K"],
      "value" => example["V"]
    }
  end

  # Members in reverse order, names and string values written with \u escapes, spaces around
  # the punctuation, and each integer as a decimal fraction.
  defp loose(object) do
    members =
      object
      |> Enum.sort(:desc)
      |> Enum.map_join(" , ", fn {name, value} -> escaped(name) <> " : " <> scalar(value) end)

    "{ " <> members <> " }"
  end

  defp scalar(value) when is_integer(value), do: "#{value}.0"
  defp scalar(value) when is_binary(value), do: escaped(value)

  defp escaped(text) do
    body =
      for <<c <- text>>, into: "" do
        "\\u" <> String.pad_leading(Integer.to_string(c, 16), 4, "0")
      end

    "\"" <> body <> "\""
  end
end
