# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Generator.Bitcoin do
  @moduledoc """
  Bitcoin's byte structures as the builder writes them: a transaction serialized without
  witness data (BIP 144), the block Merkle tree, the BIP 37 merkleblock as Bitcoin Core's
  CPartialMerkleTree builds it, and 80-octet headers ground until they meet the target their
  nBits encodes. A hash is in internal byte order, as SHA-256d gives it, unless its name says
  display, which is the reversed order explorers show.

  The rederive check reads these structures back with a parser of its own
  (Generator.BitcoinParse), and check 1 holds both to known answers from Bitcoin's chains.
  """

  import Bitwise

  @doc "SHA-256d: SHA-256 applied twice."
  def sha256d(data), do: :crypto.hash(:sha256, :crypto.hash(:sha256, data))

  @doc "The bytes in reverse order: internal order to display order, and back."
  def rev(bytes), do: bytes |> :binary.bin_to_list() |> Enum.reverse() |> :binary.list_to_bin()

  @doc "The display hex of an internal-order hash."
  def display(hash), do: hash |> rev() |> Base.encode16(case: :lower)

  @doc "The internal-order hash of a display hex."
  def internal(display), do: display |> Base.decode16!(case: :lower) |> rev()

  @doc "The shortest compact size of `n`."
  def compact_size(n) when n < 0xFD, do: <<n>>
  def compact_size(n) when n <= 0xFFFF, do: <<0xFD, n::little-16>>
  def compact_size(n) when n <= 0xFFFFFFFF, do: <<0xFE, n::little-32>>

  @doc """
  A transaction serialized without witness data. Each input is `{txid, vout, script_sig,
  sequence}`, with the txid in internal order, and each output `{value, script}`.
  """
  def transaction(%{version: version, inputs: inputs, outputs: outputs, locktime: locktime}) do
    IO.iodata_to_binary([
      <<version::little-32>>,
      compact_size(length(inputs)),
      Enum.map(inputs, &input/1),
      compact_size(length(outputs)),
      Enum.map(outputs, &output/1),
      <<locktime::little-32>>
    ])
  end

  defp input({txid, vout, script, sequence}),
    do: [txid, <<vout::little-32>>, script(script), <<sequence::little-32>>]

  defp output({value, script}), do: [<<value::little-64>>, script(script)]

  defp script(bytes), do: [compact_size(byte_size(bytes)), bytes]

  @doc "The txid of a serialized transaction: its SHA-256d, in internal order."
  def txid(transaction), do: sha256d(transaction)

  @doc "The script that pushes `height` as BIP 34 asks, then OP_0, as Bitcoin Core's miner does."
  def coinbase_script(height) when height in 1..16, do: <<0x50 + height, 0x00>>

  def coinbase_script(height) do
    number = script_number(height)
    <<byte_size(number), number::binary, 0x00>>
  end

  # CScriptNum: little-endian, with a zero byte added when the top bit of the last is set.
  defp script_number(n) do
    bytes = :binary.encode_unsigned(n, :little)
    if :binary.last(bytes) >= 0x80, do: bytes <> <<0>>, else: bytes
  end

  @doc "The block Merkle root over `txids`: an odd level pairs its last hash with itself."
  def merkle_root([root]), do: root
  def merkle_root(level), do: level |> parents() |> merkle_root()

  defp parents(level) do
    level
    |> Enum.chunk_every(2)
    |> Enum.map(fn
      [left, right] -> sha256d(left <> right)
      [last] -> sha256d(last <> last)
    end)
  end

  @doc """
  The BIP 37 merkleblock of a block whose header is `header` and whose transactions have
  `txids`, matching only the transaction at `index`: the header, total_txs, the hashes and the
  flag bits of CPartialMerkleTree's TraverseAndBuild.
  """
  def merkleblock(header, txids, index) do
    total = length(txids)
    tree = List.to_tuple(txids)
    {bits, hashes} = traverse(tree_height(total), 0, {tree, total, index})
    flags = pack(bits)

    IO.iodata_to_binary([
      header,
      <<total::little-32>>,
      compact_size(length(hashes)),
      hashes,
      compact_size(byte_size(flags)),
      flags
    ])
  end

  defp width(total, height), do: (total + (1 <<< height) - 1) >>> height

  defp tree_height(total), do: Enum.find(0..32, &(width(total, &1) == 1))

  # One node: its flag bit, then its hash when the walk stops here, or else its children.
  defp traverse(height, pos, {_tree, total, index} = block) do
    parent_of_match = pos <<< height <= index and index < min((pos + 1) <<< height, total)

    if height == 0 or not parent_of_match do
      {[parent_of_match], [node(height, pos, block)]}
    else
      {left_bits, left_hashes} = traverse(height - 1, pos * 2, block)
      {right_bits, right_hashes} = right(height - 1, pos * 2 + 1, block)
      {[true | left_bits ++ right_bits], left_hashes ++ right_hashes}
    end
  end

  defp right(height, pos, {_tree, total, _index} = block) do
    if pos < width(total, height), do: traverse(height, pos, block), else: {[], []}
  end

  defp node(0, pos, {tree, _total, _index}), do: elem(tree, pos)

  defp node(height, pos, {_tree, total, _index} = block) do
    left = node(height - 1, pos * 2, block)

    right =
      if pos * 2 + 1 < width(total, height - 1),
        do: node(height - 1, pos * 2 + 1, block),
        else: left

    sha256d(left <> right)
  end

  # Flag bits packed into octets, the first bit in the lowest bit of the first octet.
  defp pack(bits) do
    bits
    |> Enum.chunk_every(8)
    |> Enum.map(fn chunk ->
      chunk
      |> Enum.with_index()
      |> Enum.reduce(0, fn {bit, i}, acc -> acc ||| flag(bit) <<< i end)
    end)
    |> :binary.list_to_bin()
  end

  defp flag(true), do: 1
  defp flag(false), do: 0

  @doc "An 80-octet header, with `previous` and `merkle_root` in internal order."
  def header(%{version: v, previous: previous, merkle_root: root, time: t, bits: b, nonce: n}),
    do:
      <<v::little-32, previous::binary-32, root::binary-32, t::little-32, b::little-32,
        n::little-32>>

  @doc "The target a positive, in-range nBits `bits` encodes."
  def target(bits) do
    exponent = bits >>> 24
    mantissa = bits &&& 0x7FFFFF

    if exponent <= 3,
      do: mantissa >>> (8 * (3 - exponent)),
      else: mantissa <<< (8 * (exponent - 3))
  end

  @doc "Whether the header's display hash, read as a big-endian integer, is at most its target."
  def meets_target?(<<_::binary-72, bits::little-32, _nonce::binary-4>> = header),
    do: :binary.decode_unsigned(rev(sha256d(header))) <= target(bits)

  @doc "The header of `fields` with the first nonce, counting from 0, that meets its target."
  def grind(fields) do
    Enum.find_value(Stream.iterate(0, &(&1 + 1)), fn nonce ->
      header = header(%{fields | nonce: nonce})
      if meets_target?(header), do: header
    end)
  end
end
