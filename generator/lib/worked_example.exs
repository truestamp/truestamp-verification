# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Generator.WorkedExample do
  @moduledoc """
  SPEC.md 6.3's worked example, read from the text and compared with worked-example.json.
  """

  import Generator.Check

  alias Generator.Parse

  # Each row of 6.3's table, by the label SPEC.md gives it, and the member of
  # worked-example.json that holds its value.
  defp rows do
    [
      {~r/\AM, (\d+) octets\z/, "M"},
      {~r/\A`proof_hash`\z/, "proof_hash"},
      {~r/\Ask, the vector seed\z/, "sk"},
      {~r/\AA, the public key \(VECTOR_KEY\)\z/, "A"},
      {~r/\AK\z/, "K"},
      {~r/\Akey id of A \(section 3\.3\)\z/, "key_id"},
      {~r/\AS\z/, "S"},
      {~r/\AV\z/, "V"}
    ]
  end

  @doc "The failures of the comparison, for SPEC.md's text and worked-example.json's bytes."
  def run(spec_md, bytes) do
    example = Parse.decode!(bytes)
    [_before, section] = String.split(spec_md, "\n### 6.3 Worked example\n", parts: 2)
    [section, _after] = String.split(section, "\n### 6.4 ", parts: 2)
    List.flatten([input(section, example), table(section, example), document(section, example)])
  end

  defp input(section, example) do
    [_all, text] =
      Regex.run(~r/The input,\s+indented\s+and\s+out\s+of\s+order:\n\n```\n(.*?)\n```/s, section)

    expect("SPEC.md 6.3's input", Parse.decode!(text), example["proof"])
  end

  defp table(section, example) do
    [_before, rest] = String.split(section, "| Quantity | Value |\n|---|---|\n", parts: 2)

    found =
      rest
      |> String.split("\n")
      |> Enum.take_while(&String.starts_with?(&1, "|"))
      |> Enum.map(&row/1)

    [
      expect(
        "SPEC.md 6.3's rows",
        found |> Enum.map(&elem(&1, 0)) |> Enum.sort(),
        rows() |> Enum.map(&elem(&1, 1)) |> Enum.sort()
      ),
      for({member, value, octets} <- found, do: compare(member, value, octets, example))
    ]
  end

  defp row(line) do
    [label, value] = line |> String.trim("|") |> String.split(" | ") |> Enum.map(&String.trim/1)

    case Enum.find_value(rows(), &match_label(&1, label)) do
      {member, octets} -> {member, unquote_value(member, value), octets}
      nil -> {"an unknown row: " <> label, value, []}
    end
  end

  defp match_label({pattern, member}, label) do
    case Regex.run(pattern, label, capture: :all_but_first) do
      nil -> nil
      octets -> {member, octets}
    end
  end

  # sk is written as "32 octets of 0x42"; every other value is in backticks.
  defp unquote_value("sk", value) do
    [count, byte] =
      Regex.run(~r/\A(\d+) octets of 0x([0-9a-f]{2})\z/, value, capture: :all_but_first)

    String.duplicate(byte, String.to_integer(count))
  end

  defp unquote_value(_member, value),
    do: Regex.run(~r/\A`([^`]*)`\z/, value, capture: :all_but_first) |> List.first()

  defp compare(member, value, octets, example) do
    [
      expect("SPEC.md 6.3's #{member}", value, example[member]),
      for(
        count <- octets,
        do:
          expect(
            "SPEC.md 6.3's octet count of #{member}",
            String.to_integer(count),
            byte_size(example[member] || "")
          )
      )
    ]
  end

  defp document(section, example) do
    [_all, count, text] =
      Regex.run(
        ~r/The\s+served\s+document,\s+JCS\(envelope\),\s+(\d+)\s+octets:\n\n```\n(.*?)\n```/s,
        section
      )

    [
      expect("SPEC.md 6.3's served document", text, example["document"]),
      expect(
        "SPEC.md 6.3's octet count of the served document",
        String.to_integer(count),
        byte_size(example["document"])
      )
    ]
  end
end
