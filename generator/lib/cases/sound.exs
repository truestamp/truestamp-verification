# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Generator.Cases.Sound do
  @moduledoc """
  SPEC.md 13.3's sound proofs and Sameness.

  - **Sound proofs.** One case for each positive proof, `sound-<name>`, offline under the
    keyring `test`: no row fails, the label is `supplied-keyring`, LINK_KEY_EVENT is
    `info not_attributable`, every CHAIN and SOURCES row is `skip offline`, WINDOW is
    `info window_not_established`, and the trace is the proof's trace file.
  - **Sameness.** Each sound proof re-indented, with CRLF line ends, a final CRLF, its members
    in reverse order, strings escaped (every `/` as `\\/`, every `a` and every character above
    U+007E as a `\\u` escape, astral characters as surrogate pairs) and every integer written
    with `.0`, gives exactly the sound case's rows and trace (`sameness-format-<name>`). Each
    sound proof in the reference mode and in mode `none`, signed again, gives the sound case's
    rows, so its verdict (`sameness-reference-<name>`, `sameness-none-<name>`). `1e-400` in
    claims reads as 0 and passes (`sameness-underflow`); the sound item padded with spaces to
    exactly MAX_READ_OCTETS passes with its rows and trace (`sameness-max-read-octets`); and a
    sound item whose claims nest the document to a depth of exactly MAX_DEPTH passes
    (`sameness-max-depth`).

  The claims cases change item-rotation-witness, whose /block, h6, is alone in its epoch, E3,
  so the values made to agree stop at E3's Stellar entry (Generator.Edit).
  """

  @behaviour Generator.Cases.Class

  alias Generator.{Case, Edit, JCS, Spec}

  @alone "item-rotation-witness"

  @impl true
  def codes, do: ~w(not_attributable offline window_not_established expected_hash_not_checked)

  @impl true
  def cases(%{sound: sound}) do
    names = sound |> Map.keys() |> Enum.sort()

    List.flatten([
      Enum.map(names, &sound_case(&1, sound[&1])),
      Enum.map(names, &format_case(&1, sound[&1])),
      Enum.map(names, &mode_case(&1, sound[&1], :reference)),
      Enum.map(names, &mode_case(&1, sound[&1], :none)),
      underflow(sound[@alone]),
      max_read_octets(sound["item"]),
      max_depth(sound[@alone])
    ])
  end

  defp sound_case(name, %{proof: proof, path: path}) do
    Case.new("sound-" <> name,
      proof: {:path, path},
      trace: "positive/#{name}.trace.json",
      label: "supplied-keyring",
      defect: {:passes, notes(proof)}
    )
  end

  # The rows every sound proof gives offline under the keyring test, beyond its passes.
  defp notes(proof) do
    [
      {"info", "not_attributable",
       "/signing_key_event/block/record/metadata/key_event/public_key", "DERIVE"},
      {"skip", "offline", "/commitments/stellar", "CHAIN"},
      {"skip", "offline", "/signing_key_event", "CHAIN"},
      {"info", "window_not_established", nil, "WINDOW"},
      {"skip", "expected_hash_not_checked", nil, "EXPECTED_HASH"}
      | for(
          name <- Map.keys(proof["witnesses"] || %{}),
          name != "block",
          do: {"skip", "offline", "/witnesses/" <> name, "SOURCES"}
        )
    ]
  end

  defp same(id, name, proof) do
    Case.new(id,
      proof: proof,
      same_as: "sound-" <> name,
      label: "supplied-keyring",
      defect: {:passes, []}
    )
  end

  defp format_case(name, %{envelope: envelope}) do
    bytes = IO.iodata_to_binary([reformat(envelope, 0), "\r\n"])

    %{
      same("sameness-format-" <> name, name, {:bytes, bytes})
      | trace: "positive/#{name}.trace.json"
    }
  end

  defp mode_case(name, %{proof: proof}, :reference) do
    [digest] = accepted()
    url = "https://www.truestamp.com/.well-known/constructions-#{digest}.json"

    same(
      "sameness-reference-" <> name,
      name,
      {:served, Case.sign(%{proof | "constructions" => url})}
    )
  end

  defp mode_case(name, %{proof: proof}, :none),
    do:
      same(
        "sameness-none-" <> name,
        name,
        {:served, Case.sign(Map.delete(proof, "constructions"))}
      )

  defp accepted do
    for path <- Path.wildcard(Path.join(Spec.root(), "spec/constructions/*.json")),
        do: Path.basename(path, ".json")
  end

  # An item whose claims hold 0, hashed as such, written in its file as 1e-400.
  defp underflow(%{proof: proof}) do
    served =
      proof
      |> Edit.put("/subject/claims/underflow", 0)
      |> Edit.recommit_item()
      |> Case.sign()
      |> Case.served()

    [_one] = :binary.matches(served, ~s("underflow":0))

    Case.new("sameness-underflow",
      proof: {:bytes, :binary.replace(served, ~s("underflow":0), ~s("underflow":1e-400))},
      label: "supplied-keyring",
      defect: {:passes, []}
    )
  end

  defp max_read_octets(%{bytes: bytes}) do
    max = Spec.read("constants.json")["MAX_READ_OCTETS"]
    padded = bytes <> String.duplicate(" ", max - byte_size(bytes))

    %{
      same("sameness-max-read-octets", "item", {:bytes, padded})
      | trace: "positive/item.trace.json"
    }
  end

  # The document is depth 1, proof 2, subject 3 and claims 4, so claims.nest holds the objects
  # at depths 5 to MAX_DEPTH.
  defp max_depth(%{proof: proof}) do
    depth = Spec.read("constants.json")["MAX_DEPTH"]

    Case.new("sameness-max-depth",
      proof: {:served, proof |> Case.nested(depth) |> Case.sign()},
      label: "supplied-keyring",
      defect: {:passes, []}
    )
  end

  # A value written with three spaces of indentation and CRLF line ends, an object's members
  # in reverse JCS order, strings escaped and integers written with a fraction.
  defp reformat(object, level) when is_map(object) and map_size(object) > 0 do
    members =
      for name <- object |> Map.keys() |> JCS.sort_names() |> Enum.reverse() do
        [indent(level + 1), string(name), ": ", reformat(Map.fetch!(object, name), level + 1)]
      end

    ["{\r\n", Enum.intersperse(members, ",\r\n"), "\r\n", indent(level), "}"]
  end

  defp reformat(list, level) when is_list(list) and list != [] do
    elements = Enum.map(list, &[indent(level + 1), reformat(&1, level + 1)])
    ["[\r\n", Enum.intersperse(elements, ",\r\n"), "\r\n", indent(level), "]"]
  end

  defp reformat(text, _level) when is_binary(text), do: string(text)
  defp reformat(n, _level) when is_integer(n), do: "#{n}.0"
  defp reformat(value, _level), do: JCS.encode(value)

  defp indent(level), do: String.duplicate("   ", level)

  defp string(text), do: ["\"", for(<<c::utf8 <- text>>, do: escape(c)), "\""]

  defp escape(?/), do: "\\/"
  defp escape(?a), do: "\\u0061"
  defp escape(?"), do: "\\\""
  defp escape(?\\), do: "\\\\"
  defp escape(c) when c < 0x20 or (c > 0x7E and c < 0x10000), do: unit(c)

  defp escape(c) when c >= 0x10000 do
    c = c - 0x10000
    [unit(0xD800 + Bitwise.bsr(c, 10)), unit(0xDC00 + Bitwise.band(c, 0x3FF))]
  end

  defp escape(c), do: <<c>>

  defp unit(c),
    do: "\\u" <> (c |> Integer.to_string(16) |> String.downcase() |> String.pad_leading(4, "0"))
end
