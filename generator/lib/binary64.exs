# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Generator.Binary64 do
  @moduledoc """
  The generator's own reading of a JSON number: the binary64 value nearest a literal of RFC
  8259's grammar, rounded to nearest with ties to even (SPEC.md 10.1, J5), in integer
  arithmetic alone.

  Float.parse, String.to_float, :erlang.binary_to_float and OTP's JSON all hand a literal to
  the C library's strtod, and macOS 27's aborts the whole VM on some long literals. The
  vectors hold long literals, so every generator read of a file under vectors/ goes through
  Generator.Parse, which reads each number here.

  The work is bounded, so a token of 262,144 digits stays cheap:

  - leading zeros are dropped, and trailing zeros moved into the exponent;
  - an exponent of more than 15 digits, and any value whose decimal point lies more than 309
    places above or 323 places below its first digit, is answered from the exponent alone:
    an overflow above, and a zero below, since 10^309 is past the overflow threshold
    2^1024 - 2^970 and 10^-324 is below half of the smallest subnormal, 2^-1075;
  - of more than 800 significant digits, the first 800 are kept and the rest folded into one
    nonzero digit after them. Every binary64 value has at most 767 significant digits, and
    every point halfway between two neighbours at most 768, so the digits dropped cannot move the
    value across one, and the nonzero digit keeps it on the side of an exact tie it lies on.

  Then the value, an integer of digits times a power of ten, is divided exactly into a 53-bit
  integer and a remainder, which decides the rounding.
  """

  import Bitwise

  @kept 800
  @max_exponent_digits 15

  @doc """
  `{:ok, float}` for a literal of RFC 8259's number grammar, or `:overflow` when its nearest
  binary64 value is an infinity, that is, when its magnitude is at least 2^1024 - 2^970. A
  zero keeps its sign: `-0` and `-1e-400` read as -0.0.
  """
  def read(literal) do
    {negative, unsigned} =
      case literal do
        "-" <> rest -> {true, rest}
        rest -> {false, rest}
      end

    {mantissa, exponent} = split_exponent(unsigned)
    {whole, fraction} = split_point(mantissa)

    case magnitude(whole <> fraction, byte_size(fraction), exponent) do
      :overflow -> :overflow
      {m, q} -> {:ok, float(negative, m, q)}
    end
  end

  @doc "The 16 lowercase hex digits of a float's IEEE 754 bits."
  def bits(float) do
    <<n::64>> = <<float::float-64>>
    n |> Integer.to_string(16) |> String.downcase() |> String.pad_leading(16, "0")
  end

  defp split_exponent(text) do
    case :binary.match(text, ["e", "E"]) do
      {at, 1} -> {binary_part(text, 0, at), binary_part(text, at + 1, byte_size(text) - at - 1)}
      :nomatch -> {text, "0"}
    end
  end

  defp split_point(text) do
    case :binary.match(text, ".") do
      {at, 1} -> {binary_part(text, 0, at), binary_part(text, at + 1, byte_size(text) - at - 1)}
      :nomatch -> {text, ""}
    end
  end

  # The value digits x 10^(exponent - places) as {m, q}, the integer m below 2^53 and the power
  # of two q that scale the binary64 value m x 2^q, or :overflow.
  defp magnitude(digits, places, exponent) do
    trimmed = String.trim_leading(digits, "0")
    significant = String.trim_trailing(trimmed, "0")
    n = byte_size(significant)

    case {n, exponent(exponent)} do
      {0, _exponent} -> {0, 0}
      {_n, :huge} -> :overflow
      {_n, :tiny} -> {0, 0}
      {n, e} -> scaled(significant, n, e - places + byte_size(trimmed) - n)
    end
  end

  # The exponent's value, or :huge or :tiny when it has more than @max_exponent_digits digits.
  defp exponent("-" <> digits), do: exponent(String.trim_leading(digits, "0"), -1)
  defp exponent("+" <> digits), do: exponent(String.trim_leading(digits, "0"), 1)
  defp exponent(digits), do: exponent(String.trim_leading(digits, "0"), 1)

  defp exponent(digits, -1) when byte_size(digits) > @max_exponent_digits, do: :tiny
  defp exponent(digits, 1) when byte_size(digits) > @max_exponent_digits, do: :huge
  defp exponent("", _sign), do: 0
  defp exponent(digits, sign), do: sign * String.to_integer(digits)

  # significant x 10^e, where significant has n digits, the first and last of them nonzero:
  # the value lies in [10^(n + e - 1), 10^(n + e)).
  defp scaled(_significant, n, e) when n + e > 309, do: :overflow
  defp scaled(_significant, n, e) when n + e < -323, do: {0, 0}

  defp scaled(significant, n, e) when n > @kept do
    kept = binary_part(significant, 0, @kept) <> "1"
    exact(String.to_integer(kept), e + n - @kept - 1)
  end

  defp scaled(significant, _n, e), do: exact(String.to_integer(significant), e)

  # d x 10^e as the fraction num / den, rounded to m x 2^q.
  defp exact(d, e) when e >= 0, do: round_fraction(d * Integer.pow(10, e), 1)
  defp exact(d, e), do: round_fraction(d, Integer.pow(10, -e))

  defp round_fraction(num, den) do
    q = max(bit_length(num) - bit_length(den) - 53, -1074)
    {m, r, d} = divide(num, den, q)

    # The quotient is below 2^54, so one more bit of scale brings it below 2^53.
    {m, r, d, q} =
      if m >= 1 <<< 53 do
        {m, r, d} = divide(num, den, q + 1)
        {m, r, d, q + 1}
      else
        {m, r, d, q}
      end

    twice = 2 * r
    m = if twice > d or (twice == d and (m &&& 1) == 1), do: m + 1, else: m
    {m, q} = if m == 1 <<< 53, do: {1 <<< 52, q + 1}, else: {m, q}

    if q > 971, do: :overflow, else: {m, q}
  end

  # num / (den x 2^q) as a quotient, a remainder and the divisor they share.
  defp divide(num, den, q) when q >= 0 do
    d = den <<< q
    {div(num, d), rem(num, d), d}
  end

  defp divide(num, den, q) do
    n = num <<< -q
    {div(n, den), rem(n, den), den}
  end

  defp bit_length(0), do: 0

  defp bit_length(n) do
    <<top, _rest::binary>> = bytes = :binary.encode_unsigned(n)
    (byte_size(bytes) - 1) * 8 + small_bit_length(top)
  end

  defp small_bit_length(0), do: 0
  defp small_bit_length(n), do: 1 + small_bit_length(n >>> 1)

  # m x 2^q, with m below 2^53, as its IEEE 754 bits: a normal value when m is at least 2^52,
  # and otherwise a subnormal, whose q is -1074.
  defp float(negative, m, q) do
    sign = if negative, do: 1, else: 0

    {field, fraction} =
      if m >= 1 <<< 52, do: {q + 1075, m - (1 <<< 52)}, else: {0, m}

    <<value::float-64>> = <<sign::1, field::11, fraction::52>>
    value
  end
end

defmodule Generator.Binary64.KnownAnswers do
  @moduledoc """
  The known-answer check of Generator.Binary64 (check 1 of generate.exs): every literal of
  generator/known_answers/binary64.txt, which Python's float(), correctly rounded, answered
  (generator/known_answers/binary64.py), read to the same bits, or to an overflow where
  Python gave an infinity. Its lines are a literal, a space and the answer; a run of one
  digit written `[d*n]` stands for that digit n times; a line that begins with # is a
  comment.
  """

  import Generator.Check

  alias Generator.{Binary64, Spec}

  @path "generator/known_answers/binary64.txt"
  @run ~r/\[(\d)\*(\d+)\]/
  @number ~r/\A-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?\z/

  # The file holds at least this many answers, so an empty or cut file cannot pass.
  @at_least 5000

  @doc "The failures of the check."
  def run do
    answers =
      for line <- Spec.root() |> Path.join(@path) |> File.read!() |> String.split("\n"),
          line != "" and not String.starts_with?(line, "#"),
          do: String.split(line, " ")

    wrong =
      for fields <- answers, failure = wrong(fields), failure != nil, do: failure

    List.flatten([
      truth(
        "#{@path} holds #{length(answers)} answers, fewer than #{@at_least}",
        length(answers) >= @at_least
      ),
      Enum.take(wrong, 10),
      if(length(wrong) > 10, do: ["#{length(wrong) - 10} more wrong answers"], else: [])
    ])
  end

  defp wrong([spelled, want]) do
    literal =
      Regex.replace(@run, spelled, fn _all, digit, count ->
        String.duplicate(digit, String.to_integer(count))
      end)

    got =
      if Regex.match?(@number, literal),
        do: answer(Binary64.read(literal)),
        else: "not a number of RFC 8259's grammar"

    if got == want, do: nil, else: "#{@path}: #{short(spelled)} reads as #{got}, not #{want}"
  end

  defp wrong(fields),
    do: "#{@path}: a line that is not a literal and an answer: #{inspect(fields)}"

  defp answer(:overflow), do: "overflow"
  defp answer({:ok, float}), do: Binary64.bits(float)

  defp short(text) when byte_size(text) > 60, do: binary_part(text, 0, 60) <> "..."
  defp short(text), do: text
end
