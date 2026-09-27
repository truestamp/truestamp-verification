# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Generator.Parse do
  @moduledoc """
  READ and PARSE (SPEC.md 10.1 and 10.2 steps 1 and 2) as the expected-output model
  (Generator.Model) makes them: a file's bytes read to one value under the rules J1 to J6, or
  the bare rejection a verifier gives for them. It is its own reader, written for the model
  and shared with no verifier.

  - J1: more than MAX_READ_OCTETS octets is `input_too_large`.
  - J2 to J6 are `malformed_json`, whose `sub_reason` names the rule: `syntax` (J2),
    `invalid_utf8` or `lone_surrogate` (J3), `duplicate_name` (J4), `number` (J5) or `depth`
    (J6). A file that breaks one rule gives that rule's name; which of several a file that
    breaks more than one gives is not fixed (SPEC.md 10.1), and no case asks.

  A value within the value profile comes back as the generator writes values: objects as
  maps, arrays as lists, strings as UTF-8 binaries, `null` as nil, and a number whose binary64
  value is an integer of magnitude at most MAX_INTEGER as an integer, any other as a float, so
  that `1.0` reads as 1 and -0 as 0.
  """

  @max_read_octets 262_144
  @max_depth 32
  @max_integer 9_007_199_254_740_991
  @float_integer_limit 1.0e21

  @doc """
  `{:ok, value}` for a file that meets J1 to J6, or `{:bare, code, sub_reason}`, with
  `sub_reason` nil for `input_too_large`.
  """
  def read(bytes) when byte_size(bytes) > @max_read_octets, do: {:bare, "input_too_large", nil}

  def read(bytes) do
    if String.valid?(bytes), do: document(bytes), else: malformed("invalid_utf8")
  end

  defp malformed(reason), do: {:bare, "malformed_json", reason}

  defp document(bytes) do
    {value, rest} = value(space(bytes), 1)
    if space(rest) == "", do: {:ok, value}, else: malformed("syntax")
  catch
    {__MODULE__, reason} -> malformed(reason)
  end

  defp fail(reason), do: throw({__MODULE__, reason})

  defp space(<<c, rest::binary>>) when c in [?\s, ?\t, ?\n, ?\r], do: space(rest)
  defp space(rest), do: rest

  # One value, at `depth`: an object or array at a depth above MAX_DEPTH breaks J6.
  defp value(<<c, _rest::binary>>, depth) when c in [?{, ?[] and depth > @max_depth,
    do: fail("depth")

  defp value(<<?{, rest::binary>>, depth), do: object(space(rest), depth, %{})
  defp value(<<?[, rest::binary>>, depth), do: array(space(rest), depth, [])
  defp value(<<?", rest::binary>>, _depth), do: string(rest, [])
  defp value(<<"true", rest::binary>>, _depth), do: {true, rest}
  defp value(<<"false", rest::binary>>, _depth), do: {false, rest}
  defp value(<<"null", rest::binary>>, _depth), do: {nil, rest}
  defp value(<<c, _rest::binary>> = text, _depth) when c == ?- or c in ?0..?9, do: number(text)
  defp value(_text, _depth), do: fail("syntax")

  defp object(<<?}, rest::binary>>, _depth, members) when members == %{}, do: {members, rest}

  defp object(<<?", rest::binary>>, depth, members) do
    {name, rest} = string(rest, [])
    if Map.has_key?(members, name), do: fail("duplicate_name")

    case space(rest) do
      <<?:, rest::binary>> ->
        {member, rest} = value(space(rest), depth + 1)
        next_member(space(rest), depth, Map.put(members, name, member))

      _other ->
        fail("syntax")
    end
  end

  defp object(_text, _depth, _members), do: fail("syntax")

  defp next_member(<<?,, rest::binary>>, depth, members), do: object(space(rest), depth, members)
  defp next_member(<<?}, rest::binary>>, _depth, members), do: {members, rest}
  defp next_member(_text, _depth, _members), do: fail("syntax")

  defp array(<<?], rest::binary>>, _depth, []), do: {[], rest}

  defp array(text, depth, elements) do
    {element, rest} = value(text, depth + 1)

    case space(rest) do
      <<?,, rest::binary>> -> array_element(space(rest), depth, [element | elements])
      <<?], rest::binary>> -> {Enum.reverse([element | elements]), rest}
      _other -> fail("syntax")
    end
  end

  # An element after a comma, which a closing bracket may not replace.
  defp array_element(<<?], _rest::binary>>, _depth, _elements), do: fail("syntax")
  defp array_element(text, depth, elements), do: array(text, depth, elements)

  # A string's characters up to its closing quote, unescaped, as UTF-8.
  defp string(<<?", rest::binary>>, acc), do: {IO.iodata_to_binary(Enum.reverse(acc)), rest}
  defp string(<<?\\, rest::binary>>, acc), do: escape(rest, acc)
  defp string(<<c, _rest::binary>>, _acc) when c < 0x20, do: fail("syntax")
  defp string(<<c::utf8, rest::binary>>, acc), do: string(rest, [<<c::utf8>> | acc])
  defp string(_text, _acc), do: fail("syntax")

  @escapes %{
    ?" => ?",
    ?\\ => ?\\,
    ?/ => ?/,
    ?b => ?\b,
    ?f => ?\f,
    ?n => ?\n,
    ?r => ?\r,
    ?t => ?\t
  }

  defp escape(<<?u, hex::binary-4, rest::binary>>, acc), do: unicode(code(hex), rest, acc)

  defp escape(<<c, rest::binary>>, acc) when is_map_key(@escapes, c),
    do: string(rest, [<<Map.fetch!(@escapes, c)::utf8>> | acc])

  defp escape(_text, _acc), do: fail("syntax")

  # A \u escape: a high surrogate must be followed by a \u escape of a low one, and no low
  # surrogate may stand alone (J3).
  defp unicode(high, <<"\\u", hex::binary-4, rest::binary>>, acc) when high in 0xD800..0xDBFF do
    case code(hex) do
      low when low in 0xDC00..0xDFFF ->
        char = 0x10000 + Bitwise.bsl(high - 0xD800, 10) + (low - 0xDC00)
        string(rest, [<<char::utf8>> | acc])

      _other ->
        fail("lone_surrogate")
    end
  end

  defp unicode(code, _rest, _acc) when code in 0xD800..0xDFFF, do: fail("lone_surrogate")
  defp unicode(code, rest, acc), do: string(rest, [<<code::utf8>> | acc])

  defp code(hex) do
    if hex =~ ~r/\A[0-9a-fA-F]{4}\z/, do: String.to_integer(hex, 16), else: fail("syntax")
  end

  @number ~r/\A-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?\z/

  # A number's literal, read by the grammar of RFC 8259 and then as its nearest binary64
  # value (J5): an overflow, or an integer value of magnitude above MAX_INTEGER and below
  # 10^21, breaks J5.
  defp number(text) do
    {literal, rest} = take_number(text, [])
    if not Regex.match?(@number, literal), do: fail("syntax")

    case Float.parse(literal) do
      {float, ""} -> {binary64(float), rest}
      :error -> fail("number")
    end
  end

  defp take_number(<<c, rest::binary>>, acc) when c in ~c"+-.0123456789eE",
    do: take_number(rest, [c | acc])

  defp take_number(rest, acc), do: {acc |> Enum.reverse() |> List.to_string(), rest}

  defp binary64(float) do
    integral = float == Float.round(float)

    cond do
      integral and abs(float) <= @max_integer -> trunc(float)
      integral and abs(float) < @float_integer_limit -> fail("number")
      true -> float
    end
  end
end
