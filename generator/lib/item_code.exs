# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Generator.ItemCode do
  @moduledoc """
  The item code of SPEC.md 3.9, the generator's own, written from that section and shared
  with no verifier.

  - derive/1 takes the 32 bytes an `item_hash` spells and gives its code: the leftmost 75
    bits as 15 values of 5 bits, most significant first, then the check value, each written
    with the alphabet `0123456789ABCDEFGHJKMNPQRSTVWXYZ`.
  - parse/1 is a reader that takes every permission of section 3.9. It reads only ASCII and
    trims nothing: a value that is not UTF-8, that is longer than 19 characters (counted in
    code points) or that holds a character above U+007F is refused. It reads four groups of
    four symbols, with at most one separator, a space (U+0020), a hyphen or an underscore,
    at each of the three places between the groups and nowhere else. It reads the letters
    `a` to `z` as `A` to `Z` and then `I` and `L`, in either case, as `1` and `O`, in either
    case, as `0`. It neither ignores nor reads as another any other character, so a value
    holding a tab, a line feed or a carriage return is refused. It gives `{:ok, code}`, the
    code in its one spelling, or `:error`, when the value does not have that form or its 16
    symbols' check loop does not end at zero.
  - valid?/1 is section 3.9's test of 16 values: the check loop over all of them ends at
    zero.

  The check loop runs over GF(2^5) with the modulus x^5 + x^2 + 1: m(v) doubles v and, when
  the result is 32 or more, XORs it with 37.
  """

  import Bitwise

  @alphabet "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
  @separators [?-, ?_, ?\s]
  @limit 19

  @doc "The alphabet, a value's symbol being the character at its position."
  def alphabet, do: @alphabet

  @doc "The most characters, counted in code points, a value can hold and still be read."
  def limit, do: @limit

  @doc "The code of the 32 bytes an `item_hash` spells."
  def derive(<<leftmost::75, _rest::181>>) do
    values = for shift <- 70..0//-5, do: leftmost >>> shift &&& 31
    spell(values ++ [check(values)])
  end

  @doc "The check value of 15 values: the loop of section 3.9, step 2, then m once more."
  def check(values), do: values |> loop() |> m()

  @doc "Whether the loop over all 16 values ends at zero."
  def valid?(values) when length(values) == 16, do: loop(values) == 0

  @doc "The loop of section 3.9, step 2: r starts at 0, and each value v sets r to m(r) XOR v."
  def loop(values), do: Enum.reduce(values, 0, fn v, r -> bxor(m(r), v) end)

  @doc "`{:ok, code}` or `:error`, under every permission section 3.9 gives a reader."
  def parse(input) when is_binary(input) do
    with true <- String.valid?(input),
         chars = String.to_charlist(input),
         true <- length(chars) <= @limit,
         true <- Enum.all?(chars, &(&1 < 0x80)),
         {:ok, symbols} <- groups(chars, 4),
         {:ok, values} <- values(symbols),
         true <- valid?(values) do
      {:ok, spell(values)}
    else
      _refused -> :error
    end
  end

  # The symbols of `n` groups of four, the last of them ending the value, with at most one
  # separator after each group but the last. A separator anywhere else stays among the
  # symbols, and values/1 refuses it.
  defp groups(chars, 1) when length(chars) == 4, do: {:ok, chars}

  defp groups([a, b, c, d, separator | rest], n) when n > 1 and separator in @separators,
    do: more([a, b, c, d], rest, n)

  defp groups([a, b, c, d | rest], n) when n > 1, do: more([a, b, c, d], rest, n)
  defp groups(_chars, _n), do: :error

  defp more(group, rest, n) do
    case groups(rest, n - 1) do
      {:ok, symbols} -> {:ok, group ++ symbols}
      :error -> :error
    end
  end

  @doc "The values a 16-character code spells, or `:error` for a character off the alphabet."
  def values(chars) do
    Enum.reduce_while(chars, {:ok, []}, fn char, {:ok, acc} ->
      case :binary.match(@alphabet, <<fold(char)>>) do
        {index, 1} -> {:cont, {:ok, [index | acc]}}
        :nomatch -> {:halt, :error}
      end
    end)
    |> case do
      {:ok, reversed} -> {:ok, Enum.reverse(reversed)}
      :error -> :error
    end
  end

  # An ASCII lowercase letter read as its capital, then I and L as 1 and O as 0. Any other
  # ASCII character is itself; parse/1 has already refused every character above U+007F.
  defp fold(char) when char in ?a..?z, do: fold(char - 32)
  defp fold(?I), do: ?1
  defp fold(?L), do: ?1
  defp fold(?O), do: ?0
  defp fold(char) when char < 0x80, do: char

  defp spell(values), do: for(v <- values, into: "", do: binary_part(@alphabet, v, 1))

  defp m(v) do
    doubled = v <<< 1
    if doubled >= 32, do: bxor(doubled, 37), else: doubled
  end
end
