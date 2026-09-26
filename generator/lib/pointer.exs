# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Generator.Pointer do
  @moduledoc """
  JSON Pointers (RFC 6901) into a proof, and the document order of SPEC.md 10.2: a
  depth-first walk that visits each value before its contents, an object's members in JCS
  order and an array's elements by index. A pointer may name a member the proof lacks, and
  takes the place that member would take.
  """

  @doc "The unescaped reference tokens of `pointer`."
  def segments(""), do: []

  def segments("/" <> rest),
    do:
      rest
      |> String.split("/")
      |> Enum.map(&(&1 |> String.replace("~1", "/") |> String.replace("~0", "~")))

  @doc "The value at `pointer`, or nil when there is none."
  def get(value, pointer), do: Enum.reduce(segments(pointer), value, &child(&2, &1))

  defp child(map, name) when is_map(map), do: Map.get(map, name)
  defp child(list, index) when is_list(list), do: Enum.at(list, String.to_integer(index))
  defp child(_value, _segment), do: nil

  @doc """
  A key whose term order is the document order of pointers into `value`: a pointer that is a
  prefix of another comes first, and otherwise the first segment in which they differ decides,
  by index in an array and by UTF-16 code units in an object, as JCS orders names.
  """
  def order_key(value, pointer), do: key(value, segments(pointer))

  defp key(_value, []), do: []

  defp key(list, [index | rest]) when is_list(list),
    do: [{0, String.to_integer(index)} | key(child(list, index), rest)]

  defp key(value, [name | rest]),
    do: [{1, :unicode.characters_to_binary(name, :utf8, :utf16)} | key(child(value, name), rest)]
end

defmodule Generator.Classes do
  @moduledoc """
  The value class of a pointer into a proof, from spec/value-classes.json alone (SPEC.md 3.7),
  and so whether a DERIVE row's part is a CHECKED value, which puts the row in the trace unless
  its check is one SPEC.md 10.6 leaves out (Generator.Derive.trace/2).
  """

  alias Generator.{Pointer, Spec}

  @doc "Whether the value at `pointer` into `proof` is CHECKED."
  def checked?(proof, pointer), do: class(proof, Pointer.segments(pointer)) == "CHECKED"

  @doc "The class of the value at `segments`, from the one rule that covers it."
  def class(proof, segments) do
    rules =
      for rule <- Spec.read("value-classes.json")["members"],
          Map.get(rule, "document", "proof") == "proof",
          covers?(Pointer.segments(rule["pointer"]), segments),
          do: rule

    case rules do
      [%{"when" => condition} = rule] ->
        if holds?(condition, proof, segments), do: rule["class"], else: rule["otherwise"]

      [rule] ->
        rule["class"]

      other ->
        raise ArgumentError,
              "#{length(other)} value-class rules cover /#{Enum.join(segments, "/")}"
    end
  end

  # A rule covers the value at its pointer and everything inside it.
  defp covers?(pattern, segments) when length(pattern) <= length(segments),
    do: pattern |> Enum.zip(segments) |> Enum.all?(fn {p, s} -> segment?(p, s) end)

  defp covers?(_pattern, _segments), do: false

  defp segment?("*", _segment), do: true

  defp segment?(pattern, segment) do
    if String.ends_with?(pattern, "*"),
      do: String.starts_with?(segment, String.trim_trailing(pattern, "*")),
      else: pattern == segment
  end

  defp holds?("walked", %{"type" => type} = proof, _segments),
    do:
      type in ~w(item entropy_nist entropy_stellar entropy_bitcoin) or
        proof["observations"] not in [nil, %{}]

  defp holds?("genesis_block", proof, segments),
    do: genesis_record?(proof, Enum.drop(segments, -1))

  defp holds?("introduces_key_or_prerotation", proof, segments) do
    record = at(proof, Enum.drop(segments, -1))
    type = get_in(record, ["metadata", "key_event", "type"])
    type in ~w(genesis rotation emergency_rotation prerotation)
  end

  defp holds?("stellar_source", proof, segments),
    do: at(proof, Enum.drop(segments, -2))["source"] == "stellar"

  defp holds?(condition, _proof, _segments),
    do: raise(ArgumentError, "an unknown value-class condition: #{condition}")

  defp genesis_record?(proof, segments),
    do: get_in(at(proof, segments), ["metadata", "genesis"]) != nil

  defp at(proof, segments),
    do: Enum.reduce(segments, proof, fn name, value -> if is_map(value), do: value[name] end)
end
