# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Truestamp.Verifier.Test.StrictJSON do
  @moduledoc """
  Reads a JSON text under the parsing rules J1 to J6 of SPEC.md section 10.1, for the tests
  of the files under `spec/`, and prints a value in the canonical forms those files use.
  """

  @max_read_octets 262_144
  @max_depth 32
  @max_safe_integer 9_007_199_254_740_991
  @float_integer_limit 1.0e21

  # A number decoder cannot throw out of :json, which reports a throw as a syntax error, so it
  # returns this marker and the decoded value is searched for it.
  @bad_number :__strict_json_bad_number__

  @doc "Decodes `bytes`, returning `{:ok, value}` or `{:error, reason}`."
  @spec decode(binary()) :: {:ok, term()} | {:error, atom()}
  def decode(bytes) when byte_size(bytes) > @max_read_octets, do: {:error, :input_too_large}

  def decode(bytes) do
    if String.valid?(bytes), do: decode_valid(bytes), else: {:error, :invalid_utf8}
  end

  defp decode_valid(bytes) do
    decoders = [object_push: &push/3, integer: &integer/1, float: &float/1]

    case JSON.decode(bytes, [], decoders) do
      {value, [], rest} -> one_text(value, rest)
      {:error, _reason} -> {:error, :syntax}
    end
  catch
    {:strict, reason} -> {:error, reason}
  end

  defp one_text(value, rest) do
    cond do
      String.trim(rest, " \t\r\n") != "" -> {:error, :syntax}
      bad_number?(value) -> {:error, :number}
      depth(value) > @max_depth -> {:error, :depth}
      true -> {:ok, value}
    end
  end

  defp bad_number?(@bad_number), do: true

  defp bad_number?(value) when is_map(value),
    do: value |> Map.values() |> Enum.any?(&bad_number?/1)

  defp bad_number?(value) when is_list(value), do: Enum.any?(value, &bad_number?/1)
  defp bad_number?(_value), do: false

  defp push(key, value, acc) do
    if List.keymember?(acc, key, 0), do: throw({:strict, :duplicate_name})
    [{key, value} | acc]
  end

  # An integer outside the safe range is judged, like any number, by its binary64 value.
  defp integer(text) do
    value = String.to_integer(text)
    if abs(value) <= @max_safe_integer, do: value, else: float(text <> ".0")
  end

  defp float(text) do
    case Float.parse(text) do
      {value, ""} -> check_float(value)
      _ -> @bad_number
    end
  end

  defp check_float(value) do
    integral? = value == Float.round(value)

    if integral? and abs(value) > @max_safe_integer and abs(value) < @float_integer_limit,
      do: @bad_number,
      else: value
  end

  # The document itself counts as 1.
  defp depth(value) when is_map(value),
    do: 1 + (value |> Map.values() |> Enum.map(&depth/1) |> Enum.max(fn -> 0 end))

  defp depth(value) when is_list(value),
    do: 1 + (value |> Enum.map(&depth/1) |> Enum.max(fn -> 0 end))

  defp depth(_value), do: 0

  @doc """
  The canonical form of a file under `spec/`: keys sorted, two-space indentation, one member
  or element per line, LF line ends and a final newline.
  """
  @spec canonical(term()) :: binary()
  def canonical(value), do: IO.iodata_to_binary([pretty(value, 0), "\n"])

  defp pretty(map, _level) when map == %{}, do: "{}"

  defp pretty(map, level) when is_map(map) do
    members =
      map
      |> Enum.sort_by(fn {key, _value} -> key end)
      |> Enum.map(fn {key, value} ->
        [indent(level + 1), JSON.encode!(key), ": ", pretty(value, level + 1)]
      end)

    ["{\n", Enum.intersperse(members, ",\n"), "\n", indent(level), "}"]
  end

  defp pretty([], _level), do: "[]"

  defp pretty(list, level) when is_list(list) do
    items = Enum.map(list, &[indent(level + 1), pretty(&1, level + 1)])
    ["[\n", Enum.intersperse(items, ",\n"), "\n", indent(level), "]"]
  end

  defp pretty(scalar, _level), do: JSON.encode!(scalar)

  defp indent(level), do: String.duplicate("  ", level)

  @doc """
  The JCS (RFC 8785) bytes of an object whose names and values are all printable ASCII
  strings, as a constructions text's are: members sorted, no whitespace. For such strings,
  sorting by bytes is JCS's sort by UTF-16 code units, and `JSON.encode!/1` escapes exactly
  what JCS escapes, `"` and `\\`. Any other value raises rather than meet the number
  formatting and escaping JCS gives it.
  """
  @spec jcs(%{optional(String.t()) => String.t()}) :: binary()
  def jcs(object) when is_map(object) do
    members =
      object
      |> Enum.sort_by(fn {name, _value} -> name end)
      |> Enum.map(fn {name, value} -> [ascii_string(name), ":", ascii_string(value)] end)

    IO.iodata_to_binary(["{", Enum.intersperse(members, ","), "}"])
  end

  defp ascii_string(string) when is_binary(string) do
    if string =~ ~r/\A[\x20-\x7e]*\z/,
      do: JSON.encode!(string),
      else: raise(ArgumentError, "not a printable ASCII string: #{inspect(string)}")
  end
end
