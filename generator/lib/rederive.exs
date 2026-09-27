# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Generator.Rederive do
  @moduledoc """
  Check 2: each file decoded from the bytes about to be written, and every value in it
  derived again from those bytes alone.
  """

  import Generator.Check

  alias Generator.{Bytes, FileForm, JCS, Keys, Positive, Registry, Spec}

  @doc "The failures of check 2 over `files`, each file's bytes by its path."
  def run(files) do
    List.flatten([
      for({path, bytes} <- files, do: form(path, bytes)),
      keyring_test(JSON.decode!(files["vectors/keyring.test.json"])),
      worked_example(JSON.decode!(files["vectors/worked-example.json"])),
      Positive.run(files)
    ])
  end

  # Each file reads back to a value whose form is the file itself: the served form of SPEC.md
  # 3.1 for a proof, and the file form for every other file. A file under negative/ is in the
  # form its case gives it, which Generator.Cases checks, since a case's defect can be in the
  # bytes.
  defp form("vectors/negative/" <> _name, _bytes), do: []

  defp form(path, bytes) do
    if String.ends_with?(path, ".proof.json") do
      [
        truth("#{path} is UTF-8", String.valid?(bytes)),
        expect(
          "#{path} in the served form, JCS(envelope)",
          JCS.encode(JSON.decode!(bytes)),
          bytes
        )
      ]
    else
      expect("#{path} in its form", FileForm.encode(JSON.decode!(bytes)), bytes)
    end
  end

  # SPEC.md 13.2 and 10.2, step 0: a keyring whose one key is VECTOR_KEY.
  defp keyring_test(keyring) do
    [key] = keyring["keys"]
    public = key["public_key"]
    bytes = if Spec.class?("B64U32", public), do: Bytes.unb64u(public)

    [
      expect("keyring.test.json's members", Enum.sort(Map.keys(keyring)), ["keys", "version"]),
      expect("keyring.test.json's version", keyring["version"], "1.0"),
      expect("its key's members", Enum.sort(Map.keys(key)), [
        "active",
        "key_id",
        "public_key",
        "sequence"
      ]),
      truth("its key's active is a boolean", is_boolean(key["active"])),
      truth("its key's sequence is an INT", key["sequence"] in 0..9_007_199_254_740_991//1),
      truth("its key's public_key is a B64U32", bytes != nil),
      expect(
        "its key is VECTOR_KEY",
        bytes && Bytes.hex(bytes),
        Spec.read("constants.json")["VECTOR_KEY"]
      ),
      expect("its key's key_id", bytes && Keys.key_id(bytes), key["key_id"])
    ]
  end

  # SPEC.md 6.1 and 6.3, from worked-example.json alone.
  defp worked_example(example) do
    %{"M" => m, "proof" => proof, "document" => document} = example
    public = Keys.public_key(Bytes.unhex(example["sk"]))
    proof_hash = Registry.hash("proof_hash", m)
    s = if Spec.class?("B64U64", example["V"]), do: Bytes.unb64u(example["V"]), else: <<>>

    [
      expect(
        "worked-example.json's members",
        Enum.sort(Map.keys(example)),
        ~w(A K M S V document key_id proof proof_hash sk)
      ),
      expect("M, the JCS of proof", JCS.encode(proof), m),
      expect("proof_hash, SHA-256(0x50 || M)", Bytes.hex(proof_hash), example["proof_hash"]),
      expect("A, the public key of sk", Bytes.hex(public), example["A"]),
      expect("A, VECTOR_KEY", example["A"], Spec.read("constants.json")["VECTOR_KEY"]),
      expect("K, A in base64url", Bytes.b64u(public), example["K"]),
      truth("K is a B64U32", Spec.class?("B64U32", example["K"])),
      expect("the key id of A", Keys.key_id(public), example["key_id"]),
      expect(
        "S, the signature of sk over proof_hash",
        Keys.sign(Bytes.unhex(example["sk"]), proof_hash),
        Bytes.unhex(example["S"])
      ),
      expect("V, S in base64url", s, Bytes.unhex(example["S"])),
      truth("S verifies under A over proof_hash", Keys.verify?(public, proof_hash, s)),
      expect("the served document, JCS(envelope)", JCS.encode(JSON.decode!(document)), document),
      expect("the document's value", JSON.decode!(document), envelope(example)),
      not_verified(example, public, s),
      reformatted(example, public)
    ]
  end

  defp envelope(example) do
    %{
      "proof" => example["proof"],
      "signature" => %{
        "alg" => "truestamp-ed25519-sha256-jcs",
        "public_key" => example["K"],
        "value" => example["V"]
      }
    }
  end

  # SPEC.md 6.3: S does not verify over these messages.
  defp not_verified(%{"M" => m, "proof" => proof, "proof_hash" => proof_hash}, public, s) do
    for {label, message} <- [
          {"M itself", m},
          {"SHA-256(M)", :crypto.hash(:sha256, m)},
          {"the hex of proof_hash", proof_hash},
          {"SHA-256(0x31 || M)", Registry.hash("block_hash", m)},
          {"SHA-256(0x62 || M)", Registry.hash("handover", m)},
          {"the proof with environment dev",
           Registry.record_hash("proof_hash", %{proof | "environment" => "dev"})},
          {"the proof with environment removed",
           Registry.record_hash("proof_hash", Map.delete(proof, "environment"))}
        ] do
      truth("S does not verify over #{label}", not Keys.verify?(public, message, s))
    end
  end

  # SPEC.md 6.3: the document re-indented with CRLF line ends, its members in reverse order,
  # a string spelled with a \u escape and 1.0 for 1, still verifies.
  defp reformatted(example, public) do
    signature = [
      {"value", example["V"]},
      {"public_key", example["K"]},
      {"alg", "truestamp-ed25519-sha256-jcs"}
    ]

    proof = Enum.sort(example["proof"], :desc)

    text =
      Enum.join(
        [
          "{",
          ~s(  "signature": {),
          members(signature),
          "  },",
          ~s(  "proof": {),
          members(proof),
          "  }",
          "}"
        ],
        "\r\n"
      )

    reread = JSON.decode!(text)["proof"]
    reread_hash = Registry.record_hash("proof_hash", reread)

    [
      truth(
        "the reformatted document spells 1.0 and a \\u escape",
        text =~ ".0," and text =~ "\\u00"
      ),
      expect("the reformatted document's proof, as JCS", JCS.encode(reread), example["M"]),
      truth(
        "the reformatted document verifies",
        Keys.verify?(public, reread_hash, Bytes.unb64u(example["V"]))
      )
    ]
  end

  defp members(pairs),
    do:
      Enum.map_join(pairs, ",\r\n", fn {name, value} -> ~s(    "#{name}": #{respell(value)}) end)

  defp respell(n) when is_integer(n), do: "#{n}.0"

  defp respell(<<first, rest::binary>>) when first in ?a..?z,
    do: ~s("\\u00#{Integer.to_string(first, 16) |> String.downcase()}#{rest}")

  defp respell(text), do: JCS.encode(text)
end
