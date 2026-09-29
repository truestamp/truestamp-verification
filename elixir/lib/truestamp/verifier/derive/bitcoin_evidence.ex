# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Truestamp.Verifier.Derive.BitcoinEvidence do
  @moduledoc """
  The Bitcoin evidence of DERIVE (SPEC.md section 10.2, step 9 (d)), for each Bitcoin entry
  N, at `/commitments/bitcoin` and `/signing_key_event/commitments/bitcoin`. A structural
  failure is `bitcoin_evidence_invalid`, and an inequality `derivation_mismatch`, all under
  the constructions row `bitcoin`:

  | Check | Part | Code | Traced |
  |---|---|---|---|
  | `raw_transaction` is well formed (`Truestamp.Verifier.Bitcoin.Transaction`) | N`/raw_transaction` | `bitcoin_evidence_invalid` | no |
  | the 32 bytes its OP_RETURN script pushes equal the recomputed `epoch_hash` (section 5.4) | N`/raw_transaction` | `derivation_mismatch` | no |
  | rev(SHA-256d(`raw_transaction`)) = `transaction_hash` | N`/transaction_hash` | `derivation_mismatch` | yes |
  | `txoutproof` is well formed (`Truestamp.Verifier.Bitcoin.MerkleBlock`) | N`/txoutproof` | `bitcoin_evidence_invalid` | no |
  | the one hash it matches equals SHA-256d(`raw_transaction`) | N`/txoutproof` | `derivation_mismatch` | no |
  | rev(SHA-256d(header)) = `header_hash` | N`/header_hash` | `derivation_mismatch` | yes |
  | rev(the header's Merkle root field) = `header_merkle_root` | N`/header_merkle_root` | `derivation_mismatch` | yes |
  | the header's nTime, formatted as TIME, = `header_time` | N`/header_time` | `derivation_mismatch` | yes |

  Apart from the two checks of well-formedness, a check that reads a value out of
  `raw_transaction` or `txoutproof` is made only when that structure is well formed (D58,
  packet C2): the `transaction_hash` row is always made, the OP_RETURN row needs a
  well-formed `raw_transaction`, and the row of the matched hash and the three header rows
  need a well-formed `txoutproof`. A check not made reports no row: the well-formedness row
  that failed already explains it (section 10.2, "Rows").

  `raw_transaction` and `txoutproof` are PREIMAGE (section 3.7), so their rows give no trace
  row. The OP_RETURN is compared with the `epoch_hash` this run recomputed from
  N`/epoch/record`, never with the one N carries (section 10.6, rule 4). Hashes in `declared`
  and `recomputed` are in display order, except the OP_RETURN's 32 bytes and the epoch hash,
  which are in the order they are pushed and written.
  """

  alias Truestamp.Verifier.{Bitcoin, Check, Layout, Pointer, RecordHash, TIME}
  alias Truestamp.Verifier.Bitcoin.{MerkleBlock, Transaction}

  @construction "bitcoin"

  @doc "The checks of (d) for each Bitcoin entry P carries, each entry's in the table's order."
  @spec checks(map()) :: [Check.t()]
  def checks(proof) do
    for {at, "bitcoin", entry} <- Layout.commitment_entries(proof),
        check <- entry(at, entry),
        do: check
  end

  defp entry(at, entry) do
    raw = Base.decode16!(entry["raw_transaction"], case: :lower)
    txid = Bitcoin.sha256d(raw)
    epoch_hash = RecordHash.hash_hex(:epoch_hash, entry["epoch"]["record"])
    transaction = Transaction.parse(raw)
    merkle_block = entry["txoutproof"] |> Base.decode16!(case: :lower) |> MerkleBlock.parse()

    Enum.concat([
      [well_formed(at ++ ["raw_transaction"], "raw_transaction", transaction)],
      op_return(at, transaction, epoch_hash),
      [transaction_hash(at, entry, txid)],
      [well_formed(at ++ ["txoutproof"], "txoutproof", merkle_block)],
      from_txoutproof(at, entry, merkle_block, txid)
    ])
  end

  defp well_formed(part, member, {:ok, _structure}) do
    %Check{
      part: part,
      construction: @construction,
      inputs: [part],
      declared: nil,
      outcome: :pass,
      traced: false,
      message: "The #{member} is well formed."
    }
  end

  defp well_formed(part, member, {:error, rule}) do
    %Check{
      part: part,
      construction: @construction,
      inputs: [part],
      declared: nil,
      outcome: {:fail, :bitcoin_evidence_invalid},
      traced: false,
      values: %{"rule" => Atom.to_string(rule)},
      message:
        "The #{member} at #{Pointer.encode(part)} is not well formed: it breaks the rule " <>
          "#{rule |> Atom.to_string() |> String.replace("_", " ")}."
    }
  end

  defp op_return(at, {:ok, pushed}, epoch_hash) do
    part = at ++ ["raw_transaction"]

    [
      Check.equal(
        part,
        @construction,
        [at ++ ["epoch", "record"], part],
        Bitcoin.hex(pushed),
        epoch_hash,
        traced: false,
        noun: "The epoch hash the transaction's OP_RETURN holds"
      )
    ]
  end

  defp op_return(_at, {:error, _rule}, _epoch_hash), do: []

  defp transaction_hash(at, entry, txid) do
    Check.equal(
      at ++ ["transaction_hash"],
      @construction,
      [at ++ ["raw_transaction"]],
      entry["transaction_hash"],
      Bitcoin.display(txid),
      noun: "The transaction_hash"
    )
  end

  defp from_txoutproof(at, entry, {:ok, block}, txid) do
    header = block.header
    {:ok, time} = TIME.format(:time, Bitcoin.header_time(header))

    matched =
      Check.equal(
        at ++ ["txoutproof"],
        @construction,
        [at ++ ["raw_transaction"], at ++ ["txoutproof"]],
        Bitcoin.display(block.matched),
        Bitcoin.display(txid),
        traced: false,
        noun: "The transaction hash the txoutproof matches"
      )

    [
      matched,
      header(at, entry, "header_hash", Bitcoin.header_hash(header)),
      header(at, entry, "header_merkle_root", Bitcoin.header_merkle_root(header)),
      header(at, entry, "header_time", time)
    ]
  end

  defp from_txoutproof(_at, _entry, {:error, _rule}, _txid), do: []

  # A header value, recomputed from the txoutproof's header.
  defp header(at, entry, member, recomputed) do
    Check.equal(at ++ [member], @construction, [at ++ ["txoutproof"]], entry[member], recomputed,
      noun: "The #{member}"
    )
  end
end
