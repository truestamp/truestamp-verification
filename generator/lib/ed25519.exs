# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Generator.Ed25519 do
  @moduledoc """
  Ed25519's point arithmetic (RFC 8032 section 5.1), in extended coordinates (X, Y, Z, T) with
  x = X/Z, y = Y/Z and xy = T/Z, and the strict Verify of SPEC.md 6.2 written on it, step by
  step, apart from :crypto. The mixed-order cases (Generator.Cases.Front) and the Ed25519
  corpus (Generator.Corpus) make signatures no library makes with it: a key of mixed order,
  an R with a component of small order, an R written with y at p or above. The corpus check
  holds each of its signatures to verify/3, and :crypto to the same answer wherever SPEC.md
  6.2 says a common library makes the step that decides.
  """

  import Bitwise

  alias Generator.{Bytes, Keys, Seeds, Spec}

  # RFC 8032 section 5.1: p, the order L of the base point, and d.
  @p Integer.pow(2, 255) - 19
  @l Integer.pow(2, 252) + 27_742_317_777_372_353_535_851_937_790_883_648_493
  @d Integer.mod(
       -121_665 * :binary.decode_unsigned(:crypto.mod_pow(121_666, @p - 2, @p)),
       @p
     )

  @doc "p = 2^255 - 19."
  def p, do: @p

  @doc "L, the order of the base point."
  def l, do: @l

  @doc "The secret scalar a and the prefix of a 32-octet seed (RFC 8032 section 5.1.5)."
  def expand(seed) do
    <<a::little-256, prefix::binary-32>> = :crypto.hash(:sha512, seed)
    {(a &&& (1 <<< 254) - 8) ||| 1 <<< 254, prefix}
  end

  @doc "A 64-octet hash read as a little-endian integer, modulo L."
  def scalar(hash), do: Integer.mod(:binary.decode_unsigned(hash, :little), @l)

  defp f(x), do: Integer.mod(x, @p)

  defp pow(x, e), do: :binary.decode_unsigned(:crypto.mod_pow(f(x), e, @p))

  @doc "The identity point."
  def identity, do: {0, 1, 1, 0}

  @doc "The base point B."
  def base, do: decode!(<<f(4 * pow(5, @p - 2))::little-256>>)

  @doc "P + Q."
  def add({x1, y1, z1, t1}, {x2, y2, z2, t2}) do
    a = f((y1 - x1) * (y2 - x2))
    b = f((y1 + x1) * (y2 + x2))
    c = f(t1 * 2 * @d * t2)
    d = f(z1 * 2 * z2)
    {e, g, h, i} = {b - a, d - c, d + c, b + a}
    {f(e * g), f(h * i), f(g * h), f(e * i)}
  end

  @doc "-P."
  def negate({x, y, z, t}), do: {f(-x), y, z, f(-t)}

  @doc "[n]P."
  def multiply(0, _point), do: identity()

  def multiply(n, point) do
    half = multiply(n >>> 1, point)
    twice = add(half, half)
    if (n &&& 1) == 1, do: add(twice, point), else: twice
  end

  @doc "The 32 octets of a point (RFC 8032 section 5.1.2)."
  def encode({x, y, z, _t}) do
    inverse = pow(z, @p - 2)
    x = f(x * inverse)
    <<f(y * inverse) ||| (x &&& 1) <<< 255::little-256>>
  end

  @doc """
  The point 32 octets encode, as RFC 8032 section 5.1.3 decodes them: `{:ok, point}`, or
  `:error` when y is not below p, when no x fits y, or when x is 0 with the sign bit set.
  """
  def decode(<<n::little-256>>) do
    y = n &&& (1 <<< 255) - 1
    sign = n >>> 255
    x = if y < @p, do: x_of(y)

    cond do
      x == nil -> :error
      x == 0 and sign == 1 -> :error
      (x &&& 1) == sign -> {:ok, {x, y, 1, f(x * y)}}
      true -> {:ok, {f(-x), y, 1, f(-x * y)}}
    end
  end

  # A root x of x^2 = (y^2 - 1) / (d y^2 + 1), or nil when there is none (RFC 8032 section
  # 5.1.3, step 3).
  defp x_of(y) do
    u = f(y * y - 1)
    v = f(@d * y * y + 1)
    x = f(u * pow(v, 3) * pow(u * pow(v, 7), div(@p - 5, 8)))

    cond do
      f(v * x * x) == u -> x
      f(v * x * x + u) == 0 -> f(x * pow(2, div(@p - 1, 4)))
      true -> nil
    end
  end

  defp decode!(bytes) do
    {:ok, point} = decode(bytes)
    point
  end

  @doc """
  Verify(A, msg, S) of SPEC.md 6.2 for the 32 octets of a key, a 32-octet message and the 64
  octets of a signature: `:pass`, or `{:fail, step}` with the step that refuses it. Step 1 is
  the spelling of A and S, which a caller that holds octets has already passed; step 6 cannot
  fail.
  """
  def verify(<<_::binary-32>> = a, <<_::binary-32>> = message, <<r::binary-32, s::little-256>>) do
    <<n::little-256>> = a
    y = n &&& (1 <<< 255) - 1

    small =
      for %{"hex" => hex} <- Spec.read("small-order-keys.json"), do: Bytes.unhex(hex)

    cond do
      y >= @p -> {:fail, 2}
      a in small -> {:fail, 3}
      decode(a) == :error -> {:fail, 4}
      s >= @l -> {:fail, 5}
      true -> equation(a, message, r, s)
    end
  end

  # Steps 6 and 7: k = SHA-512(R || A || msg) mod L, and [s]B - [k]A encoded equals R.
  defp equation(a, message, r, s) do
    {:ok, point} = decode(a)
    k = scalar(:crypto.hash(:sha512, [r, a, message]))
    computed = add(multiply(s, base()), negate(multiply(k, point)))
    if encode(computed) == r, do: :pass, else: {:fail, 7}
  end

  @doc """
  The 64 octets R || S over `message` under the key `key` of scalar `a`, for R the 32 octets
  given, whatever point they encode or fail to: S = r + k a mod L with k = SHA-512(R || key ||
  message) mod L, where [r]B is the point `point` that R is meant to stand for. With `point`
  the identity and R a second spelling of it, [S]B - [k]A is the identity, whose encoding is
  not R.
  """
  def sign_as(a, key, {r_bytes, r}, message) do
    k = scalar(:crypto.hash(:sha512, [r_bytes, key, message]))
    r_bytes <> <<Integer.mod(r + k * a, @l)::little-256>>
  end

  @doc """
  The other key plus the first point of order 8 that spec/small-order-keys.json lists,
  encoded: a key of mixed order, which passes the checks of a key's bytes and under which
  anyone who holds the other seed can sign (SPEC.md 6.2). It is noted as a key built from the
  other seed's key (Generator.Keys.built/2), so the seed check holds it to
  spec/keys.nonproduction.json.
  """
  def mixed_order_key do
    {a, _prefix} = expand(Seeds.other())
    valid = multiply(a, base())
    other = Keys.public_key(Seeds.other())
    if encode(valid) != other, do: raise(ArgumentError, "[a]B is not the other key")
    Keys.built(encode(add(valid, torsion())), Seeds.other())
  end

  @doc "The first point of order 8 that spec/small-order-keys.json lists."
  def torsion do
    [point | _rest] =
      for %{"order" => 8, "hex" => hex} <- Spec.read("small-order-keys.json"),
          do: decode!(Bytes.unhex(hex))

    if encode(multiply(8, point)) != encode(identity()) or
         encode(multiply(4, point)) == encode(identity()),
       do: raise(ArgumentError, "the torsion point is not of order 8")

    point
  end

  @doc """
  A signature over `message` under the mixed-order key, made with the other seed's scalar a
  and R = [r]B for the first r (from the other seed's prefix, a counter octet and the message)
  whose challenge k = SHA-512(R || K || message) mod L satisfies `wanted?`: k a multiple of 8
  gives a signature that verifies, and any other k one that the cofactorless equation
  refuses.
  """
  def sign_mixed(message, wanted?) do
    {a, prefix} = expand(Seeds.other())
    key = mixed_order_key()

    Enum.find_value(0..255, fn counter ->
      r = scalar(:crypto.hash(:sha512, [prefix, <<counter>>, message]))
      encoded = encode(multiply(r, base()))
      k = scalar(:crypto.hash(:sha512, [encoded, key, message]))
      if wanted?.(k), do: encoded <> <<Integer.mod(r + k * a, @l)::little-256>>
    end)
  end
end
