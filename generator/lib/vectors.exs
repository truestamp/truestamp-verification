# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Generator.Vectors do
  @moduledoc """
  The files under vectors/, each as its path and its bytes:

  - `keyring.test.json` and `worked-example.json` (SPEC.md 13.2), in the file form of
    Generator.FileForm;
  - under `positive/`, for each sound proof, `<name>.proof.json` in the served form of SPEC.md
    3.1 and `<name>.trace.json`, its trace (SPEC.md 10.6) in the file form, where `<name>` is
    its type, or its type, a hyphen and a variant (Generator.Proofs);
  - `cases.json`, under `negative/` the files its cases need, and under `corpus/replay/` the
    replay file of each online case (Generator.Cases), which are built from the files above;
  - under `corpus/`, the known answers for JCS, Ed25519 and base64url (Generator.Corpus), and
    the real Bitcoin bytes under `corpus/bitcoin/` (Generator.RealBitcoin);
  - `item-codes.json`, the known answers for the item code of SPEC.md 3.9, which are not
    cases (Generator.Cases.ItemCodes), built from the sound item proofs.
  """

  alias Generator.{
    Bytes,
    Cases,
    Cases.ItemCodes,
    Chain,
    Corpus,
    FileForm,
    JCS,
    Keys,
    Proofs,
    RealBitcoin,
    Registry
  }

  # SPEC.md 9: VECTOR_KEY is the key of the seed of 32 bytes of 0x42.
  @vector_seed :binary.copy(<<0x42>>, 32)

  # The input of SPEC.md 6.3.
  @example_proof %{
    "environment" => "test",
    "format" => "truestamp-proof",
    "type" => "block",
    "version" => 1
  }

  @doc "Each file's bytes, by its path from the root of the repository."
  def files do
    data =
      Map.new(
        [
          {"vectors/keyring.test.json", keyring_test()},
          {"vectors/worked-example.json", worked_example()}
        ],
        fn {path, value} -> {path, FileForm.encode(value)} end
      )

    Chain.build()
    |> Proofs.build()
    |> Enum.flat_map(fn {name, %{document: document, trace: trace}} ->
      [
        {"vectors/positive/#{name}.proof.json", document},
        {"vectors/positive/#{name}.trace.json", FileForm.encode(trace)}
      ]
    end)
    |> Map.new()
    |> Map.merge(data)
    |> then(&Map.merge(&1, Cases.files(&1)))
    |> then(&Map.merge(&1, Corpus.files(&1)))
    |> then(&Map.merge(&1, ItemCodes.files(&1)))
    |> Map.merge(RealBitcoin.files())
  end

  # SPEC.md 13.2: a keyring in the form of section 10.2, step 0, whose one key is VECTOR_KEY.
  defp keyring_test do
    public = Keys.public_key(@vector_seed)

    %{
      "keys" => [
        %{
          "active" => true,
          "key_id" => Keys.key_id(public),
          "public_key" => Bytes.b64u(public),
          "sequence" => 0
        }
      ],
      "version" => "1.0"
    }
  end

  # SPEC.md 6.1 over the input of 6.3, signed with the vector seed.
  defp worked_example do
    public = Keys.public_key(@vector_seed)
    m = JCS.encode(@example_proof)
    proof_hash = Registry.hash("proof_hash", m)
    s = Keys.sign(@vector_seed, proof_hash)

    signature = %{
      "alg" => "truestamp-ed25519-sha256-jcs",
      "public_key" => Bytes.b64u(public),
      "value" => Bytes.b64u(s)
    }

    %{
      "A" => Bytes.hex(public),
      "K" => Bytes.b64u(public),
      "M" => m,
      "S" => Bytes.hex(s),
      "V" => Bytes.b64u(s),
      "document" => JCS.encode(%{"proof" => @example_proof, "signature" => signature}),
      "key_id" => Keys.key_id(public),
      "proof" => @example_proof,
      "proof_hash" => Bytes.hex(proof_hash),
      "sk" => Bytes.hex(@vector_seed)
    }
  end
end
