# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Generator.BitcoinParse do
  @moduledoc """
  The rederive check's reading of Bitcoin evidence, written apart from the builder
  (Generator.Bitcoin), as SPEC.md 10.2 step 9 (d) defines it: a transaction serialized without
  witness data, a BIP 37 merkleblock walked as Bitcoin Core's CPartialMerkleTree walks one,
  and the target of a header's nBits. Every compact size must be in its shortest form.
  """

  import Bitwise

  @max_total_txs 16_666

  @doc "SHA-256d: SHA-256 applied twice."
  def sha256d(data), do: :crypto.hash(:sha256, :crypto.hash(:sha256, data))

  @doc "The display hex of an internal-order hash: its bytes reversed, in lowercase hex."
  def display(hash),
    do: hash |> :binary.bin_to_list() |> Enum.reverse() |> :binary.list_to_bin() |> hex()

  defp hex(bytes), do: Base.encode16(bytes, case: :lower)

  @doc "The output scripts of a transaction that parses completely, or `:error`."
  def transaction(<<_version::binary-4, rest::binary>>) do
    with {:ok, inputs, rest} when inputs >= 1 <- compact(rest),
         {:ok, _inputs, rest} <- repeat(rest, inputs, &input/1),
         {:ok, outputs, rest} <- compact(rest),
         {:ok, scripts, <<_locktime::binary-4>>} <- repeat(rest, outputs, &output/1) do
      {:ok, scripts}
    else
      _failure -> :error
    end
  end

  def transaction(_bytes), do: :error

  @doc """
  The 32 bytes a well-formed `raw_transaction` pushes: it parses, is not 64 octets long, and
  exactly one output script begins with 0x6a, which is 0x6a 0x20 and 32 bytes. Else `:error`.
  """
  def op_return(bytes) do
    with {:ok, scripts} <- transaction(bytes),
         true <- byte_size(bytes) != 64,
         [<<0x6A, 0x20, push::binary-32>>] <-
           Enum.filter(scripts, &match?(<<0x6A, _::binary>>, &1)) do
      {:ok, push}
    else
      _failure -> :error
    end
  end

  defp compact(<<n, rest::binary>>) when n < 0xFD, do: {:ok, n, rest}
  defp compact(<<0xFD, n::little-16, rest::binary>>) when n >= 0xFD, do: {:ok, n, rest}
  defp compact(<<0xFE, n::little-32, rest::binary>>) when n > 0xFFFF, do: {:ok, n, rest}
  defp compact(<<0xFF, n::little-64, rest::binary>>) when n > 0xFFFFFFFF, do: {:ok, n, rest}
  defp compact(_bytes), do: :error

  # `count` items read in turn by `read`, each giving `{:ok, item, rest}`.
  defp repeat(bytes, count, read) do
    Enum.reduce_while(1..count//1, {:ok, [], bytes}, fn _n, {:ok, items, rest} ->
      case read.(rest) do
        {:ok, item, rest} -> {:cont, {:ok, [item | items], rest}}
        :error -> {:halt, :error}
      end
    end)
    |> then(fn
      {:ok, items, rest} -> {:ok, Enum.reverse(items), rest}
      :error -> :error
    end)
  end

  defp input(<<_prevout::binary-36, rest::binary>>) do
    with {:ok, size, rest} <- compact(rest),
         <<_script::binary-size(^size), _sequence::binary-4, rest::binary>> <- rest do
      {:ok, nil, rest}
    else
      _failure -> :error
    end
  end

  defp input(_bytes), do: :error

  defp output(<<_value::binary-8, rest::binary>>) do
    with {:ok, size, rest} <- compact(rest),
         <<script::binary-size(^size), rest::binary>> <- rest do
      {:ok, script, rest}
    else
      _failure -> :error
    end
  end

  defp output(_bytes), do: :error

  @doc """
  A well-formed merkleblock's header and the one hash it matches, as `{:ok, header, hash}`, or
  `:error`: it parses completely, with total_txs from 1 to BITCOIN_MAX_TOTAL_TXS; its walk
  uses every hash and every flag bit, leaves the bits after the last one used at zero, finds
  no right child equal to its left, matches exactly one transaction and reaches the header's
  Merkle root field; and the header meets the target its nBits encodes.
  """
  def merkleblock(<<header::binary-80, total::little-32, rest::binary>>)
      when total in 1..@max_total_txs do
    with {:ok, count, rest} <- compact(rest),
         hashes_size = count * 32,
         <<hashes::binary-size(^hashes_size), rest::binary>> <- rest,
         {:ok, flags_size, rest} <- compact(rest),
         <<flags::binary-size(^flags_size)>> <- rest,
         {:ok, root, [hash]} <- walk(total, hashes, flags),
         true <- root == merkle_root_field(header),
         true <- meets_target?(header) do
      {:ok, header, hash}
    else
      _failure -> :error
    end
  end

  def merkleblock(_bytes), do: :error

  @doc "The header's Merkle root field, octets 36 to 67."
  def merkle_root_field(<<_::binary-36, root::binary-32, _::binary-12>>), do: root

  @doc "The header's nTime, octets 68 to 71, little-endian."
  def time(<<_::binary-68, time::little-32, _::binary-8>>), do: time

  @doc "Whether the header's hash, as a big-endian integer, is at most the target of its nBits."
  def meets_target?(<<_::binary-72, bits::little-32, _nonce::binary-4>> = header) do
    case target(bits) do
      {:ok, target} when target > 0 ->
        :binary.decode_unsigned(sha256d(header), :little) <= target

      _other ->
        false
    end
  end

  @doc """
  The target nBits `bits` encodes (SPEC.md 10.2 step 9): `{:ok, target}`, `:negative` or
  `:overflow`.
  """
  def target(bits) do
    exponent = bits >>> 24
    word = bits &&& 0x007FFFFF
    word = if exponent <= 3, do: word >>> (8 * (3 - exponent)), else: word

    cond do
      word != 0 and (bits &&& 0x00800000) != 0 -> :negative
      overflow?(word, exponent) -> :overflow
      exponent <= 3 -> {:ok, word}
      true -> {:ok, word <<< (8 * (exponent - 3))}
    end
  end

  defp overflow?(0, _exponent), do: false
  defp overflow?(_word, exponent) when exponent > 34, do: true
  defp overflow?(word, exponent) when word > 0xFF and exponent > 33, do: true
  defp overflow?(word, exponent) when word > 0xFFFF and exponent > 32, do: true
  defp overflow?(_word, _exponent), do: false

  # TraverseAndExtract over the flag bits, first bit lowest in the first octet.
  defp walk(total, hashes, flags) do
    bits = for <<byte <- flags>>, i <- 0..7, do: (byte >>> i &&& 1) == 1
    state = %{bits: bits, hashes: for(<<h::binary-32 <- hashes>>, do: h), used: 0, matches: []}
    {root, state} = extract(height(total, 0), 0, total, state)

    if root != nil and state.hashes == [] and byte_size(flags) == div(state.used + 7, 8) and
         not Enum.any?(state.bits) do
      {:ok, root, Enum.reverse(state.matches)}
    else
      :error
    end
  end

  defp width(total, height), do: (total + (1 <<< height) - 1) >>> height

  defp height(total, h), do: if(width(total, h) > 1, do: height(total, h + 1), else: h)

  defp extract(_height, _pos, _total, %{bits: []} = state), do: {nil, state}

  defp extract(height, pos, total, %{bits: [bit | bits]} = state) do
    state = %{state | bits: bits, used: state.used + 1}

    if height == 0 or not bit,
      do: take(bit and height == 0, state),
      else: branch(height, pos, total, state)
  end

  defp take(_match, %{hashes: []} = state), do: {nil, state}

  defp take(match, %{hashes: [hash | rest]} = state) do
    state = %{state | hashes: rest}
    {hash, if(match, do: %{state | matches: [hash | state.matches]}, else: state)}
  end

  defp branch(height, pos, total, state) do
    {left, state} = extract(height - 1, pos * 2, total, state)

    if pos * 2 + 1 < width(total, height - 1) do
      {right, state} = extract(height - 1, pos * 2 + 1, total, state)
      {join(left, right, right == left), state}
    else
      {join(left, left, false), state}
    end
  end

  # A right child equal to its left is CVE-2012-2459's duplicate, so the walk gives no root.
  defp join(_left, _right, true), do: nil
  defp join(nil, _right, _duplicate), do: nil
  defp join(_left, nil, _duplicate), do: nil
  defp join(left, right, false), do: sha256d(left <> right)
end
