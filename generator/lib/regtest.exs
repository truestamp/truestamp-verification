# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Generator.Regtest do
  @moduledoc """
  The Bitcoin regtest chain the positive vectors point into: a chain of headers from regtest's
  genesis block, each ground to regtest's nBits, so that every hash, height and time a vector
  names belongs to one chain, which the online cases of SPEC.md 13.3 can replay.

  It is a model for the parsers of SPEC.md 10.2 step 9 and for those replays, and it is not
  valid Bitcoin: its transactions spend SegWit outputs with no witness, and no coinbase
  carries a witness commitment. Bitcoin Core would reject its blocks, so no regtest node can
  load them, and the replays of it are drawn from this model, never from a node. The model's
  consistency check (Generator.Consistency) holds it together: each header's previous hash,
  hash, Merkle root, time and target, the height in each coinbase, and the blocks the sound
  proofs name.

  - Block k, from 1 on, is mined at `time(k)`: one block a minute, block 200 at
    2026-09-26T01:30:00Z.
  - Each block holds a coinbase paying the regtest subsidy, with BIP 34's height, and then the
    transactions the caller adds for that height.
  - Every header has version 0x20000000 and nBits 0x207fffff, and the first nonce from 0 whose
    hash meets the target.
  """

  alias Generator.Bitcoin

  # Regtest's genesis block, height 0, in display order.
  @genesis "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206"
  @bits 0x207FFFFF
  @version 0x20000000
  @base_height 200
  @base_time 1_790_386_200
  @halving_interval 150
  # The coinbase pays a P2WPKH output whose key hash is the first 20 bytes of this label's
  # SHA-256: no key is behind it.
  @miner "truestamp vectors regtest miner"

  @doc "The regtest nBits, 0x207fffff."
  def bits, do: @bits

  @doc "The Unix time of block `height`."
  def time(height), do: @base_time + 60 * (height - @base_height)

  @doc "A chain that holds only regtest's genesis block."
  def new, do: %{0 => %{hash: Bitcoin.internal(@genesis), txs: [], time: 1_296_688_602}}

  @doc "The height of the chain's tip."
  def tip(chain), do: chain |> Map.keys() |> Enum.max()

  @doc "The block at `height`: its hash (internal order), header, transactions and time."
  def block(chain, height), do: Map.fetch!(chain, height)

  @doc "The txid of the coinbase of block `height`."
  def coinbase_txid(chain, height),
    do: chain |> block(height) |> Map.fetch!(:txs) |> hd() |> Bitcoin.txid()

  @doc "A pay-to-witness-key-hash script, with the key hash taken from `label`."
  def p2wpkh(label), do: <<0x00, 0x14, binary_part(:crypto.hash(:sha256, label), 0, 20)::binary>>

  @doc """
  The chain mined up to `height`, where `extra` maps a height to the transactions its block
  holds after the coinbase.
  """
  def extend(chain, height, extra \\ %{}) do
    Enum.reduce((tip(chain) + 1)..height//1, chain, fn h, acc ->
      Map.put(acc, h, mine(h, block(acc, h - 1).hash, Map.get(extra, h, [])))
    end)
  end

  defp mine(height, previous, extra) do
    txs = [coinbase(height) | extra]

    header =
      Bitcoin.grind(%{
        version: @version,
        previous: previous,
        merkle_root: txs |> Enum.map(&Bitcoin.txid/1) |> Bitcoin.merkle_root(),
        time: time(height),
        bits: @bits,
        nonce: 0
      })

    %{hash: Bitcoin.sha256d(header), header: header, txs: txs, time: time(height)}
  end

  defp coinbase(height) do
    Bitcoin.transaction(%{
      version: 2,
      inputs: [{<<0::256>>, 0xFFFFFFFF, Bitcoin.coinbase_script(height), 0xFFFFFFFF}],
      outputs: [{subsidy(height), p2wpkh(@miner)}],
      locktime: 0
    })
  end

  @doc "The regtest subsidy of the block at `height`, in satoshis."
  def subsidy(height), do: div(5_000_000_000, Integer.pow(2, div(height, @halving_interval)))
end
