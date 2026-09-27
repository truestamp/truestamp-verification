# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Generator.Cases.Parse do
  @moduledoc """
  SPEC.md 13.3's READ and PARSE, each a bare rejection whose file breaks exactly one rule of
  SPEC.md 10.1, so that its `sub_reason` is fixed. Every file but the depth case's is the
  sound item's served bytes with one edit, written as bytes, since the defect is in them, and
  none of those is signed again: PARSE rejects the bytes before any signature is checked. The
  depth case is built as its passing twin, `sameness-max-depth`, is (Generator.Case.nested/2):
  item-rotation-witness with claims one level deeper, the hashes above them made to agree,
  and signed again, so that the two differ only in depth.

  - **READ.** The file padded with spaces to MAX_READ_OCTETS + 1 octets: `input_too_large`.
  - **PARSE.** `malformed_json`, with its `sub_reason`: a second `proof` member, a second
    `type` inside `proof`, and a second `type` spelled with an escape (`duplicate_name`); a lone
    surrogate escape in a claims string (`lone_surrogate`); an octet 0xff in a claims string
    (`invalid_utf8`); a byte-order mark, and a second JSON text after the first (`syntax`);
    in place of the claims number 5e-324, the integer literals 2^53 and 2^60,
    `9007199254740992.0`, `9007199254740993e0`, `1e16`, and `1e400`, which overflows
    (`number`); and claims that nest the document 33 deep (`depth`).
  """

  @behaviour Generator.Cases.Class

  alias Generator.{Case, JCS, Spec}

  @impl true
  def codes, do: ~w(input_too_large malformed_json)

  @impl true
  def cases(%{sound: %{"item" => item} = sound}),
    do: [read(item) | parse(item)] ++ [depth(sound["item-rotation-witness"])]

  defp read(%{bytes: bytes}) do
    max = Spec.read("constants.json")["MAX_READ_OCTETS"]

    Case.new("read-input-too-large",
      proof: {:bytes, bytes <> String.duplicate(" ", max + 1 - byte_size(bytes))},
      defect: {:bare, "input_too_large", nil}
    )
  end

  defp parse(%{bytes: bytes, envelope: envelope}) do
    %{"proof" => proof, "signature" => signature} = envelope
    type = ~s("type":"item")
    hash_type = ~s("hash_type":"md5")
    number = ~s("smallest":5e-324)

    [
      {"parse-duplicate-proof", "duplicate_name",
       ~s({"proof":) <>
         JCS.encode(proof) <>
         ~s(,"proof":) <>
         JCS.encode(proof) <>
         ~s(,"signature":) <> JCS.encode(signature) <> "}"},
      {"parse-duplicate-in-proof", "duplicate_name",
       edit(bytes, type, ~s("type":"item","type":"block"))},
      {"parse-duplicate-escaped", "duplicate_name",
       edit(bytes, type, ~s("type":"item","typ\\u0065":"item"))},
      {"parse-lone-surrogate", "lone_surrogate",
       edit(bytes, hash_type, ~s("hash_type":"md5\\ud800"))},
      {"parse-invalid-utf8", "invalid_utf8",
       edit(bytes, hash_type, ~s("hash_type":"md5) <> <<0xFF>> <> ~s("))},
      {"parse-byte-order-mark", "syntax", <<0xEF, 0xBB, 0xBF>> <> bytes},
      {"parse-content-after", "syntax", bytes <> "{}"},
      {"parse-integer-2-pow-53", "number", edit(bytes, number, ~s("smallest":9007199254740992))},
      {"parse-integer-2-pow-60", "number",
       edit(bytes, number, ~s("smallest":1152921504606846976))},
      {"parse-number-2-pow-53-fraction", "number",
       edit(bytes, number, ~s("smallest":9007199254740992.0))},
      {"parse-number-2-pow-53-plus-1-exponent", "number",
       edit(bytes, number, ~s("smallest":9007199254740993e0))},
      {"parse-number-1e16", "number", edit(bytes, number, ~s("smallest":1e16))},
      {"parse-number-1e400", "number", edit(bytes, number, ~s("smallest":1e400))}
    ]
    |> Enum.map(fn {id, sub_reason, file} ->
      Case.new(id, proof: {:bytes, file}, defect: {:bare, "malformed_json", sub_reason})
    end)
  end

  # Claims one level deeper than sameness-max-depth's, in its served form.
  defp depth(%{proof: proof}) do
    depth = Spec.read("constants.json")["MAX_DEPTH"]

    Case.new("parse-depth-33",
      proof: {:served, proof |> Case.nested(depth + 1) |> Case.sign()},
      defect: {:bare, "malformed_json", "depth"}
    )
  end

  # The bytes with their one copy of `old` replaced by `new`.
  defp edit(bytes, old, new) do
    [_one] = :binary.matches(bytes, old)
    :binary.replace(bytes, old, new)
  end
end
