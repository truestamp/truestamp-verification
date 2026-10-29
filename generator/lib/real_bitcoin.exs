# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Generator.RealBitcoin do
  @moduledoc """
  Real Bitcoin bytes for the parsers of SPEC.md 10.2 step 9 (d), which the generator writes
  under vectors/corpus/bitcoin/ (SPEC.md 13.2). Unlike the modeled regtest chain
  (Generator.Regtest), which is not valid Bitcoin, each of these came from a real chain: the
  genesis blocks of mainnet and regtest as Bitcoin Core writes them, two mainnet blocks, and
  a block of the regtest chain of Truestamp's staging environment, which a Bitcoin Core node
  mined. Each file is one transaction, merkleblock or header, named
  `<network>-<height>-<what>.json`, in the canonical form of SPEC.md 9:

  - `about`: what the object is, and what a parser concludes from it, in words;
  - `block_hash`, `height` and `network`: the block it belongs to, the hash in display order;
  - `expected`: what a parser concludes, kept here by hand from the sources, never computed;
  - `hex`: the bytes;
  - `kind`: `header`, `merkleblock` or `transaction`;
  - `source`: where the bytes came from.

  `expected` holds, for a transaction, `transaction_hash`, rev(SHA-256d) of the bytes, and
  `well_formed`, whether it is a well-formed `raw_transaction`, with `op_return`, the 32 bytes
  its OP_RETURN pushes, when it is, and `fails` when it is not, the first of the three rules
  it breaks: `parse` (it is not a transaction serialized without witness data), `length` (it
  is 64 octets long) or `op_return` (no single output script begins with 0x6a and is exactly
  0x6a 0x20 and 32 bytes). For a merkleblock it holds `well_formed`, `matched` (the one hash
  it matches), `total_txs`, and the header's `header_hash`, `header_merkle_root` and
  `header_time`; for a header, those three and `meets_target`. Hashes are in display order,
  as a proof's members are, so a merkleblock's `matched` is the `transaction_hash` of the
  transaction it matches.

  A transaction serialized with its witness (BIP 144) is written twice: as it is, in
  `<what>-witness.json`, which a parser refuses, and without its witness, in `<what>.json`.
  The check strips the witness itself, and holds the result to the merkleblock that matches
  it.

  The check derives every `expected` value again from the file's bytes, with the rederive
  check's own parser (Generator.BitcoinParse), and ties the files of a block together: each
  header's hash is the block's, each merkleblock matches a transaction of the block, each
  witness form strips to the form without its witness, a coinbase's script signature begins
  with the block's height (BIP 34), and the headers at height 0 give the block-0 hashes of
  SPEC.md 10.2 step 0: mainnet's, and a regtest one that is not mainnet's.
  """

  import Generator.Check

  alias Generator.{Bitcoin, BitcoinAnswers, BitcoinParse, Bytes, FileForm, Parse, Regtest, Replay}

  # The bytes of each block's files, in hex, from the sources `source` names.

  @block_540107_coinbase "02000000010000000000000000000000000000000000000000000000000000000000000000ffffff" <>
                           "ff4b03cb3d08042467905b642f4254432e434f4d2ffabe6d6d61ea3fdfc3d238e128fb27c97f95d4" <>
                           "bd49881fcf8784fc34ae86bcb827505eba0100000000000000300f894eba58000000000000ffffff" <>
                           "ff03b203c64a0000000016001497cfc76442fe717f2a3f0cc9c175f7561b66199700000000000000" <>
                           "00266a24aa21a9ed7c6e421f55cf406e383b46d829600dee545f127de76bb3ec4dc8fea7ea96d709" <>
                           "00000000000000002952534b424c4f434b3ae3fc068128effed4a212959a1f8fde5d7caa01226071" <>
                           "d40c530b99f90e099ed500000000"

  @block_540107_transaction "010000000001015f2c275470bfc27a732270ed6b9030bb5e93a3b530bcfc14907888c0508703b300" <>
                              "00000017160014aa94bdb05cda3cb788b59f7f5980dee90c73be0cfdffffff028e82510000000000" <>
                              "17a91498c114ad7f5b555131bd7517783dd24af37d5be3870000000000000000226a202eae7f097b" <>
                              "71495b28239701f285dbec344206fdf795a2a4deb3b3722e5b36dd02473044022008476cd06f7b97" <>
                              "44810237d8fadd67ea041ebac9f09e8e9628016e32d1cbc4380220536d311db4fb667b6a8f89a22e" <>
                              "4e9ca3289b09543ddb396ee7a132703f251e2c01210256c3b756a7f12c05ed79c076c5609fed8ad6" <>
                              "25ff95f812b1053957a29bfb206eca3d0800"

  @block_540107_coinbase_merkleblock "00000020a1d2b3b757ad55fa1c670f9f59372a2a26f1a85197711e00000000000000000070be58da" <>
                                       "7ef0a754ef5947910fa1bb0c19160d641cf212ae46ba53e0327233bc2367905b2dd729174c3ae2db" <>
                                       "e600000009ed63f57d1bc7b1f402b96bbd4801631bd7dc6d78a41b515e39d8211d83a70153e59763" <>
                                       "99fa0eaf6ca8e75fafed0ed991b788b0a7f091eeeef57d3bffdaf58606154af9121a3126dcc45a4b" <>
                                       "1e0fc11b0ace780b016dcb9ba55d9a6a60ba15353c6ffd8ba356efc66a431fa01084728a37911cb2" <>
                                       "95535208429ff4dcb109c05d2ee8759477a555ba80193f8c38668cf3026aa84c70967dbcfac7e80a" <>
                                       "c46d1763ab87ced4711f04e46b4e32cf7cbb414773dcbba2d51e76e17fb98289a8127a3d8fbeec0c" <>
                                       "a73021092632c1fa2438d965f5408cd45d8a249cc1c16c34ab02f10a1022672d82da0215c345042a" <>
                                       "4c70ac9f541dddd2c06c9a37372b2b4d19dfbaf63d7284cd177ae2b4e41956a535f3c23300f03ab1" <>
                                       "466057c432e0ba567208a8d7f803ff0100"

  @block_540107_merkleblock "00000020a1d2b3b757ad55fa1c670f9f59372a2a26f1a85197711e00000000000000000070be58da" <>
                              "7ef0a754ef5947910fa1bb0c19160d641cf212ae46ba53e0327233bc2367905b2dd729174c3ae2db" <>
                              "e6000000095627d7e54b46cd2dd8323df28a0b26efc3d76933bf3d91c3ffe1257894f03a07f4bbcb" <>
                              "c5adee207c35e7263697c9ee252fdffc691dbc2ff41049690ce19f3d7931f9b942a7e2b4ded13db6" <>
                              "d3f35bea6ad58c20cd4621900675d67ecbebc275a4ae7e727b2da2dbbcbde74080adcc57b7b760d3" <>
                              "55591b4b7b269cb4cc7c2e5d6ac451c24513f05eb78094465de875c635413db7347b06b1cc196345" <>
                              "5e2bb2acee13ea6790987f1a3e693e27de54990deab370b854d197424d5e8ecf76d21de25dd998da" <>
                              "b1432243bcf7158c3be95e3711ea5ceb086f5ea60f7361147fb706674c288b5b96063146189ff01e" <>
                              "cbf09e7723dbb5384f51c891e2f7b435bcb62fb2a694dde73179909f84bea73c011d6a3892ed038d" <>
                              "b31ef31ab91d8eee6878c7aa19036d2d00"

  @block_540107_last_transaction "0100000001b51a86687d999e613822e11603025b4c39e7141846aa08bfc8ab83dbe3194cec000000" <>
                                   "006a473044022014781fe9b58d8ae05e5037a40b93f513ebbf898671735e2ec55996028dfe015a02" <>
                                   "2046061d1b11e3a641253d75c10e0251f77d51970c90519efbf91569f363255011012103bc359c08" <>
                                   "9f1e1f1e9078b55eae3ffbdd01e21acc3d32a5fdd9bcdd8fa1af1264feffffff02a0860100000000" <>
                                   "0017a9143326bba18854e7a2040c0ea8541bc72ec0ee67998793491200000000001976a91482dacc" <>
                                   "29a6ba492ac6431d2a4fe54bb790f97d1688ac9b3d0800"

  @block_540107_last_merkleblock "00000020a1d2b3b757ad55fa1c670f9f59372a2a26f1a85197711e00000000000000000070be58da" <>
                                   "7ef0a754ef5947910fa1bb0c19160d641cf212ae46ba53e0327233bc2367905b2dd729174c3ae2db" <>
                                   "e6000000065627d7e54b46cd2dd8323df28a0b26efc3d76933bf3d91c3ffe1257894f03a079903fa" <>
                                   "c096e31d14e6f68def84f05dc79e1f2fc6a683e7181ec26f8b5eb1a7a6026024240b6963660fabff" <>
                                   "9593abe079ab4e5c6f6c68d7bbc0a9feb2e95a20b95ebb070cc7b43cf85adf94581de5cfef0b49f0" <>
                                   "e05288da3c34cf2d4dd6c564f826af3b523239239cd1100ca7b954b0b056ef2238ba6df4f72272a0" <>
                                   "fdeb75d055e55427a1b7aba0fda24d8b40ba5ed8a8f2b26e3ce64ba5b67ba29d3168cf979c02d52d"

  @block_932662_transaction "020000000001026814730123c5ca79b263e726d8233bbec21b870a8e00fcb88d3700983928dde600" <>
                              "00000000ffffffff477b73d2cde2b49fd3f0cba7534dd6a0d518c8f916df6fc276bd6d4ea919a1b7" <>
                              "0200000000ffffffff03d0810d0000000000160014f2eac266f2864cdde4f505da86d5bd76274ab6" <>
                              "570000000000000000366a344249513a746f3a555344542854524f4e293a54564a52366176615238" <>
                              "5a4a527869427773736d7077646877426350453277524a5342010000000000001600140725c3b8b8" <>
                              "4fd2114ca6e20a412fcf00ba1f2d5002483045022100f58ccf2dd0dc8300017a6252fc2615a3fb1e" <>
                              "3baf73381fbaf4e2bfc2d674933b022020e942a514f55a2ba692c27a4697003b4dea871a4455f45d" <>
                              "6d041f49acb399490121028ebbd2d9dda7e2a4a637e3b373d6413a8e9b233d254776c60c772aa568" <>
                              "a956ed02483045022100ebd43c873d28f88e7374cd23abb61a80ab4c301c2a2ae66dd97dbc576012" <>
                              "700f02207785cd142f1c91855de393b7521f33d722704c28874731af79d9fe0a201aa5360121028e" <>
                              "bbd2d9dda7e2a4a637e3b373d6413a8e9b233d254776c60c772aa568a956ed00000000"

  @block_932662_merkleblock "00600720d3467a0e99a5ac21dd64c3840a6615eee614e4f41778000000000000000000005a8ffd73" <>
                              "58cd60220c358ea3bf03ea6c45ff96c5c066fef3fe31bcc247c5dc7fa2b56b69f2eb011745ba8553" <>
                              "9c0c00000de1cfb5e8c3316d7865baa5414bb2d9f4b3c0c8061f1e68f0f09ed2ea8735679bbff756" <>
                              "8b276152041cc653bdb7415d5457243e94b71f28cdb541ed7bb0c7f5072a0247d38599159b6a2f68" <>
                              "937a0bfc33b05b95f76e331df04cdbf83a537e82b35bc7e60f2e995f5a345e0d505aac1ef21c26a5" <>
                              "c3d7a250c8476658757628002408531e04641d5202e55db59125f44b3ae7d81776e5149e1b760afc" <>
                              "87272137786b438ecdd465ce8a2a40554bb22013da5422f6af5e4000ce7976e043b8aa03dcab47f5" <>
                              "e09ee97bde9b8cbdf6033217cae7492bc0ab10b2227f53ded7a1dce8bfd9b60dbcefdbbb43eff525" <>
                              "85873c726b677203e01315326ad6f211bc6940742e436d3f7ce4f929825ee9de1dfdc85f640432f1" <>
                              "baa5aaf21590b1cb6476de65a5f6d3356a4d09394726dfe42fa004e4238048fb6481035ef37303b9" <>
                              "0fb04b3a5abc00ce643d091005647333805b6a4e1cab96bacad7ab96285410801fbc51c1326ad801" <>
                              "69004d39775b47b5d03be7f674f61eb864a6724f4c2495c1dc0c18a9f0667ee429a5e7f73b1a4af0" <>
                              "a596dffd6d9319fe730e1216d223d342ff07ba157b045ffb0000"

  @staging_56062_transaction "02000000000102c29ce2cc348705cc69dce93987f69a0bb070d7ff0ea533e6189dfac83ddde9f200" <>
                               "00000000fdffffff1a14a7f457ea5bafbfc733b68cccce5dc507aac02bc6420d43976d1170fb8ee8" <>
                               "0000000000fdffffff0260c30000000000002251204499254275e5b05118d50c7f6ec0026619de4c" <>
                               "261d170c2556038b3fbcc9fda20000000000000000226a201706e3d19201b806508fb177a212e748" <>
                               "f59a20c152c588fef942814b772345f40140e0e45126670b83a39975b5170c47272b7eeff079020d" <>
                               "5fbdfde9957caa054ec546a5658bcba4d2c62c8e9e768d7deadd2d1113b4f339225ff9affb4e618d" <>
                               "193d0140228642e0f3cb18c48e122cfc2885249e12cb962d9d3ac40dd1e190dd554355190831451e" <>
                               "124f3ad57c03449d87445686a37e02b569d3ca686fcd8bffdc645d6b00000000"

  @staging_56062_merkleblock "00000020796b397a8d3de8fbb61d93f50a9e515da6afe164448a1a9165781aeffb54f04b92d70aec" <>
                               "14fd5afc3e18c6472eaea25cd690a2f8d06ea4bda3b299b55f94308b2ab9996affff7f2000000000" <>
                               "0200000002f73b5d2a3fa35f56dd8a2770523cc5726b3943b2bcf9a38afd0743956ff48e00958e27" <>
                               "2a0882e1637b5dbae3c0fd77a875933089775d5f4011b72fcda332be3e0105"

  @doc "Each block the corpus draws from, with its files, each `{what, kind, bytes, expected, about}`."
  def blocks do
    [genesis(), regtest_genesis(), block_540107(), block_932662(), staging_56062()]
  end

  # Mainnet's genesis block, from its fields and its one transaction (Generator.BitcoinAnswers).
  defp genesis do
    coinbase = BitcoinAnswers.genesis_transaction()
    header = header("000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f")
    txid = "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b"

    %{
      network: "mainnet",
      height: 0,
      block_hash: "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f",
      merkle_root: txid,
      time: "2009-01-03T18:15:05Z",
      total_txs: 1,
      source:
        "Bitcoin Core, src/kernel/chainparams.cpp: mainnet's genesis block. The merkleblock " <>
          "is built from its one transaction, as Bitcoin Core's CPartialMerkleTree builds one.",
      files: [
        {"header", :header, header, %{},
         "The header of mainnet's genesis block. Its hash is the value a source pinned to " <>
           "mainnet gives for its block at height 0 (SPEC.md 10.2, step 0), and it meets the " <>
           "target its nBits encodes."},
        {"coinbase", :transaction, coinbase,
         %{"fails" => "op_return", "transaction_hash" => txid, "well_formed" => false},
         "The one transaction of mainnet's genesis block, serialized without witness data. " <>
           "It parses, but no output script begins with 0x6a, so it is not a well-formed " <>
           "raw_transaction."},
        {"merkleblock", :merkleblock, Bitcoin.merkleblock(header, [Bitcoin.internal(txid)], 0),
         %{"matched" => txid},
         "A merkleblock of mainnet's genesis block that matches its one transaction: " <>
           "total_txs 1, one hash and one flag bit, so the header's Merkle root field is " <>
           "that transaction's hash."}
      ]
    }
  end

  defp regtest_genesis do
    %{
      network: "regtest",
      height: 0,
      block_hash: "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206",
      merkle_root: "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b",
      time: "2011-02-02T23:16:42Z",
      total_txs: 1,
      source: "Bitcoin Core, src/kernel/chainparams.cpp: regtest's genesis block.",
      files: [
        {"header", :header,
         header("0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206"), %{},
         "The header of regtest's genesis block: mainnet's genesis transaction under " <>
           "another time, nBits and nonce. Its hash is the value a regtest source gives for " <>
           "its block at height 0, which is not mainnet's (SPEC.md 10.2, step 0)."}
      ]
    }
  end

  defp block_540107 do
    %{
      network: "mainnet",
      height: 540_107,
      block_hash: "00000000000000000021868c2cefc52a480d173c849412fe81c4e5ab806f94ab",
      merkle_root: "bc337232e053ba46ae12f21c640d16190cbba10f914759ef54a7f07eda58be70",
      time: "2018-09-05T23:30:43Z",
      total_txs: 230,
      source:
        "Mainnet block 540107, whole, in btcd's test file testdata/block-" <>
          "00000000000000000021868c2cefc52a480d173c849412fe81c4e5ab806f94ab.blk " <>
          "(github.com/btcsuite/btcd/wire/v2 v2.0.1); mempool.space's Esplora API gave the " <>
          "same hash for height 540107 on 2026-09-27. Each merkleblock is built from the " <>
          "block's 230 transactions, as Bitcoin Core's CPartialMerkleTree builds one.",
      files: [
        {"coinbase", :transaction, Bytes.unhex(@block_540107_coinbase),
         %{
           "fails" => "op_return",
           "transaction_hash" =>
             "5301a7831d21d8395e511ba4786ddcd71b630148bd6bb902f4b1c71b7df563ed",
           "well_formed" => false
         },
         "The coinbase of block 540107, without its witness. It parses, and its one output " <>
           "script that begins with 0x6a is the witness commitment, 0x6a 0x24 and 36 bytes, " <>
           "so it is not a well-formed raw_transaction. Its script signature begins with the " <>
           "block's height, 540107 (BIP 34)."},
        {"coinbase-merkleblock", :merkleblock, Bytes.unhex(@block_540107_coinbase_merkleblock),
         %{"matched" => "5301a7831d21d8395e511ba4786ddcd71b630148bd6bb902f4b1c71b7df563ed"},
         "A merkleblock of block 540107 that matches its coinbase, the first of its 230 " <>
           "transactions."},
        {"transaction-witness", :transaction, Bytes.unhex(@block_540107_transaction),
         %{
           "fails" => "parse",
           "transaction_hash" =>
             "250b6178cd88d653a64167752beb5e3b451b2ac121b7309e11271adad8493720",
           "well_formed" => false
         },
         "The transaction at index 173 of block 540107's 230, counting the coinbase as 0, " <>
           "serialized with its witness (BIP 144). After the version, its marker octet 0x00 " <>
           "reads as a count of no inputs, so it is not a transaction serialized without " <>
           "witness data, and the SHA-256d of these bytes is its witness hash, not its txid."},
        {"transaction", :transaction, {:stripped, Bytes.unhex(@block_540107_transaction)},
         %{
           "op_return" => "2eae7f097b71495b28239701f285dbec344206fdf795a2a4deb3b3722e5b36dd",
           "transaction_hash" =>
             "5de21dd276cf8e5e4d4297d154b870b3ea0d9954de273e693e1a7f989067ea13",
           "well_formed" => true
         },
         "The same transaction without its witness: one input and two outputs, the second " <>
           "exactly 0x6a 0x20 and 32 bytes. It is a well-formed raw_transaction, whose " <>
           "OP_RETURN pushes op_return."},
        {"merkleblock", :merkleblock, Bytes.unhex(@block_540107_merkleblock),
         %{"matched" => "5de21dd276cf8e5e4d4297d154b870b3ea0d9954de273e693e1a7f989067ea13"},
         "A merkleblock of block 540107 that matches the transaction at index 173 of its " <>
           "230, counting the coinbase as 0."},
        {"last-transaction", :transaction, Bytes.unhex(@block_540107_last_transaction),
         %{
           "fails" => "op_return",
           "transaction_hash" =>
             "9c97cf68319da27bb6a54be63c6eb2f2a8d85eba408b4da2fda0abb7a12754e5",
           "well_formed" => false
         },
         "The last transaction of block 540107, at index 229 of its 230, counting the coinbase " <>
           "as 0. It has no witness, so these are its bytes as the block holds them: one input " <>
           "and two outputs, a P2SH script and a P2PKH script. It parses, but no output script " <>
           "begins with 0x6a, so it is not a well-formed raw_transaction."},
        {"last-merkleblock", :merkleblock, Bytes.unhex(@block_540107_last_merkleblock),
         %{"matched" => "9c97cf68319da27bb6a54be63c6eb2f2a8d85eba408b4da2fda0abb7a12754e5"},
         "A merkleblock of block 540107 that matches its last transaction, at index 229 of " <>
           "its 230, counting the coinbase as 0: 6 hashes and 2 flag octets. Three levels of " <>
           "a tree of 230 have an odd width, 115, 29 and 15 nodes at heights 1, 3 and 4, and " <>
           "the walk to index 229 passes through the last node of each, so the nodes above " <>
           "them, at heights 2, 4 and 5, have no right child and pair that node's hash with " <>
           "itself. A parser that walks it as Bitcoin Core's CPartialMerkleTree does finds it " <>
           "well formed, with total_txs 230, matching that transaction and reaching the " <>
           "header's Merkle root field."}
      ]
    }
  end

  defp block_932662 do
    txid = "2400287675586647c850a2d7c3a5261cf21eac5a500d5e345a5f992e0fe6c75b"

    %{
      network: "mainnet",
      height: 932_662,
      block_hash: "0000000000000000000004fe7503727513a5a4b28db703b6496d4bb600f5495f",
      merkle_root: "7fdcc547c2bc31fef3fe66c0c596ff456cea03bfa38e350c2260cd5873fd8f5a",
      time: "2026-01-17T16:15:30Z",
      total_txs: 3228,
      source:
        "A mainnet transaction and the txoutproof a public block explorer gave for it, " <>
          "kept by a test of Truestamp's app; mempool.space's Esplora API placed the " <>
          "transaction in this block, at this height, on 2026-09-27.",
      files: [
        {"transaction-witness", :transaction, Bytes.unhex(@block_932662_transaction),
         %{
           "fails" => "parse",
           "transaction_hash" =>
             "342bf12a519fa573af00f6288b0849fa872b44d67d315d53ff3c07bfcdbec21a",
           "well_formed" => false
         },
         "A transaction of block 932662, serialized with its witness (BIP 144), so not a " <>
           "transaction serialized without witness data."},
        {"transaction", :transaction, {:stripped, Bytes.unhex(@block_932662_transaction)},
         %{"fails" => "op_return", "transaction_hash" => txid, "well_formed" => false},
         "The same transaction without its witness. It parses, and its one output script " <>
           "that begins with 0x6a pushes 52 bytes (0x6a 0x34), so it is not a well-formed " <>
           "raw_transaction."},
        {"merkleblock", :merkleblock, Bytes.unhex(@block_932662_merkleblock),
         %{"matched" => txid},
         "The merkleblock a public block explorer gave for that transaction, in a block of " <>
           "3,228: 13 hashes and 4 flag octets."}
      ]
    }
  end

  defp staging_56062 do
    txid = "3ebe32a3cd2fb711405f5d7789309375a877fdc0e3ba5d7b63e182082a278e95"

    %{
      network: "regtest",
      height: 56_062,
      block_hash: "5423a2f4345d3cc36a8dbe7c2d04f201f042e6c7e1952b7f70354d23fa87e77d",
      merkle_root: "8b30945fb599b2a3bda46ed0f8a290d65ca2ae2e47c6183efc5afd14ec0ad792",
      time: "2026-09-03T18:15:06Z",
      total_txs: 2,
      source:
        "The regtest chain of Truestamp's staging environment, mined by its Bitcoin Core " <>
          "node: the raw_transaction and txoutproof of the Bitcoin commitment at " <>
          "/commitments/0 of a staging proof of 2026-09-03, in the layout proofs had then.",
      files: [
        {"transaction-witness", :transaction, Bytes.unhex(@staging_56062_transaction),
         %{
           "fails" => "parse",
           "transaction_hash" =>
             "c2d620100ffac24315194590245e4ccbe874575e65848ddbc8b9f92d5a7dae9d",
           "well_formed" => false
         },
         "The transaction of a Bitcoin commitment of Truestamp's staging environment, " <>
           "serialized with its witness (BIP 144), so not a transaction serialized without " <>
           "witness data."},
        {"transaction", :transaction, {:stripped, Bytes.unhex(@staging_56062_transaction)},
         %{
           "op_return" => "1706e3d19201b806508fb177a212e748f59a20c152c588fef942814b772345f4",
           "transaction_hash" => txid,
           "well_formed" => true
         },
         "The same transaction without its witness: two inputs and two outputs, the second " <>
           "exactly 0x6a 0x20 and 32 bytes. It is a well-formed raw_transaction, whose " <>
           "OP_RETURN pushes op_return."},
        {"merkleblock", :merkleblock, Bytes.unhex(@staging_56062_merkleblock),
         %{"matched" => txid},
         "The merkleblock the staging node's gettxoutproof gave for that transaction, in a " <>
           "block of 2: the coinbase's hash and the transaction's."}
      ]
    }
  end

  # A header of check 1 (Generator.BitcoinAnswers), by its hash.
  defp header(hash) do
    {version, previous, root, time, bits, nonce, ^hash} =
      Enum.find(BitcoinAnswers.header_fields(), &(elem(&1, 6) == hash))

    Bitcoin.header(%{
      version: version,
      previous: Bitcoin.internal(previous),
      merkle_root: Bitcoin.internal(root),
      time: time,
      bits: bits,
      nonce: nonce
    })
  end

  @doc "The files under vectors/corpus/bitcoin/, by their paths."
  def files do
    for block <- blocks(), {what, kind, bytes, expected, about} <- block.files, into: %{} do
      bytes = with {:stripped, witness} <- bytes, do: strip!(witness)

      value = %{
        "about" => about,
        "block_hash" => block.block_hash,
        "expected" => Map.merge(block_facts(kind, block), expected),
        "height" => block.height,
        "hex" => Bytes.hex(bytes),
        "kind" => Atom.to_string(kind),
        "network" => block.network,
        "source" => block.source
      }

      {"vectors/corpus/bitcoin/#{block.network}-#{block.height}-#{what}.json",
       FileForm.encode(value)}
    end
  end

  # What a header, or a merkleblock's header, gives: the block's own facts.
  defp block_facts(:transaction, _block), do: %{}

  defp block_facts(kind, block) do
    header = %{
      "header_hash" => block.block_hash,
      "header_merkle_root" => block.merkle_root,
      "header_time" => block.time
    }

    case kind do
      :header -> Map.put(header, "meets_target", true)
      :merkleblock -> Map.merge(header, %{"total_txs" => block.total_txs, "well_formed" => true})
    end
  end

  # The transaction without its witness: the version, the inputs, the outputs and the lock
  # time of a transaction serialized with a witness (BIP 144), or :error. It is written apart
  # from the parser, and the check holds what it gives to the merkleblock that matches it.
  defp strip(<<version::binary-4, 0x00, 0x01, rest::binary>>) do
    with {:ok, inputs, count, rest} <- items(rest, &input/1),
         {:ok, outputs, _outputs, rest} <- items(rest, &output/1),
         {:ok, <<locktime::binary-4>>} <- witnesses(rest, count) do
      {:ok, IO.iodata_to_binary([version, inputs, outputs, locktime])}
    else
      _failure -> :error
    end
  end

  defp strip(_bytes), do: :error

  defp strip!(bytes) do
    {:ok, stripped} = strip(bytes)
    stripped
  end

  # A compact size and that many items, each read by `read`: `{:ok, spelled, count, rest}`,
  # where `spelled` is the bytes of the compact size and the items.
  defp items(bytes, read) do
    with {:ok, count, after_count} <- compact(bytes),
         {:ok, rest} <- repeat(after_count, count, read) do
      {:ok, binary_part(bytes, 0, byte_size(bytes) - byte_size(rest)), count, rest}
    end
  end

  defp repeat(bytes, 0, _read), do: {:ok, bytes}

  defp repeat(bytes, count, read) do
    with {:ok, rest} <- read.(bytes), do: repeat(rest, count - 1, read)
  end

  defp input(<<_prevout::binary-36, rest::binary>>) do
    with {:ok, rest} <- sized(rest),
         <<_sequence::binary-4, rest::binary>> <- rest do
      {:ok, rest}
    else
      _failure -> :error
    end
  end

  defp input(_bytes), do: :error

  defp output(<<_value::binary-8, rest::binary>>), do: sized(rest)
  defp output(_bytes), do: :error

  # One witness stack for each input: a compact size and that many sized items.
  defp witnesses(bytes, 0), do: {:ok, bytes}

  defp witnesses(bytes, inputs) do
    with {:ok, count, rest} <- compact(bytes),
         {:ok, rest} <- repeat(rest, count, &sized/1) do
      witnesses(rest, inputs - 1)
    end
  end

  # A compact size and that many octets.
  defp sized(bytes) do
    with {:ok, size, rest} <- compact(bytes),
         <<_item::binary-size(^size), rest::binary>> <- rest do
      {:ok, rest}
    else
      _failure -> :error
    end
  end

  defp compact(<<n, rest::binary>>) when n < 0xFD, do: {:ok, n, rest}
  defp compact(<<0xFD, n::little-16, rest::binary>>) when n >= 0xFD, do: {:ok, n, rest}
  defp compact(<<0xFE, n::little-32, rest::binary>>) when n > 0xFFFF, do: {:ok, n, rest}
  defp compact(_bytes), do: :error

  # The check.

  @doc """
  The failures of the check of the files under vectors/corpus/bitcoin/ among `files`, every
  file about to be written.
  """
  def check(files) do
    entries =
      for {"vectors/corpus/bitcoin/" <> name, bytes} <- Enum.sort(files),
          do: {name, Parse.decode!(bytes)}

    names =
      for block <- blocks(), {what, _kind, _bytes, _expected, _about} <- block.files do
        "#{block.network}-#{block.height}-#{what}.json"
      end

    [
      expect(
        "the files under corpus/bitcoin/",
        Enum.map(entries, &elem(&1, 0)),
        Enum.sort(names)
      ),
      Enum.map(entries, &file/1),
      entries
      |> Enum.group_by(fn {_name, value} -> {value["network"], value["height"]} end)
      |> Enum.map(&block/1)
    ]
    |> List.flatten()
  end

  defp file({name, value}) do
    label = "corpus/bitcoin/#{name}"
    bytes = Bytes.unhex(value["hex"])

    [
      expect(
        "#{label}: its members",
        value |> Map.keys() |> Enum.sort(),
        ~w(about block_hash expected height hex kind network source)
      ),
      truth(
        "#{label}: its name begins with its network and height",
        String.starts_with?(name, "#{value["network"]}-#{value["height"]}-")
      ),
      truth(
        "#{label}: its network is a Bitcoin network",
        value["network"] in Generator.Spec.read("networks.json")["bitcoin"]
      ),
      expect("#{label}: what a parser concludes", derive(value["kind"], bytes), value["expected"])
    ]
  end

  defp derive("transaction", bytes) do
    hash = BitcoinParse.display(BitcoinParse.sha256d(bytes))

    case BitcoinParse.op_return(bytes) do
      {:ok, push} ->
        %{"op_return" => Bytes.hex(push), "transaction_hash" => hash, "well_formed" => true}

      :error ->
        %{"fails" => fails(bytes), "transaction_hash" => hash, "well_formed" => false}
    end
  end

  defp derive("merkleblock", <<_header::binary-80, total::little-32, _rest::binary>> = bytes) do
    case BitcoinParse.merkleblock(bytes) do
      {:ok, header, hash} ->
        header
        |> header_facts()
        |> Map.merge(%{
          "matched" => BitcoinParse.display(hash),
          "total_txs" => total,
          "well_formed" => true
        })

      :error ->
        %{"well_formed" => false}
    end
  end

  defp derive("header", <<_::binary-80>> = header),
    do: Map.put(header_facts(header), "meets_target", BitcoinParse.meets_target?(header))

  defp derive(kind, _bytes), do: {:no_such_kind, kind}

  defp fails(bytes) do
    cond do
      BitcoinParse.transaction(bytes) == :error -> "parse"
      byte_size(bytes) == 64 -> "length"
      true -> "op_return"
    end
  end

  defp header_facts(header) do
    %{
      "header_hash" => BitcoinParse.display(BitcoinParse.sha256d(header)),
      "header_merkle_root" => BitcoinParse.display(BitcoinParse.merkle_root_field(header)),
      "header_time" =>
        header |> BitcoinParse.time() |> DateTime.from_unix!() |> DateTime.to_iso8601()
    }
  end

  # The files of one block, tied together.
  defp block({{network, height}, entries}) do
    label = "the files of #{network} block #{height}"
    by_name = Map.new(entries, fn {name, value} -> {name, value} end)
    bytes = fn name -> with %{"hex" => hex} <- by_name[name], do: Bytes.unhex(hex) end
    [block_hash | _] = hashes = Enum.map(entries, fn {_name, value} -> value["block_hash"] end)

    transactions =
      for {_name, %{"kind" => "transaction", "expected" => e}} <- entries,
          do: e["transaction_hash"]

    [
      expect("#{label}: one block hash", Enum.uniq(hashes), [block_hash]),
      for {name, %{"kind" => kind, "expected" => e}} <- entries, kind in ~w(header merkleblock) do
        [
          expect("#{label}: the header of #{name}", e["header_hash"], block_hash),
          if(kind == "merkleblock",
            do:
              truth(
                "#{label}: #{name} matches a transaction of the block",
                e["matched"] in transactions
              ),
            else: []
          )
        ]
      end,
      for {name, _value} <- entries, String.ends_with?(name, "-witness.json") do
        stripped = String.replace_suffix(name, "-witness.json", ".json")

        expect(
          "#{label}: #{name} without its witness",
          strip(bytes.(name)),
          {:ok, bytes.(stripped)}
        )
      end,
      for {name, _value} <- entries, String.ends_with?(name, "-coinbase.json"), height > 0 do
        expect(
          "#{label}: the height #{name} gives (BIP 34)",
          BitcoinParse.coinbase_height(bytes.(name)),
          height
        )
      end,
      identity(label, network, height, block_hash)
    ]
  end

  # The block-0 hashes of SPEC.md 10.2 step 0: mainnet's, and regtest's, which is not it.
  defp identity(label, "mainnet", 0, hash),
    do: expect("#{label}: mainnet's block-0 hash", hash, Replay.production()["bitcoin"])

  defp identity(label, "regtest", 0, hash) do
    [
      expect("#{label}: regtest's block-0 hash", hash, Bitcoin.display(Regtest.new()[0].hash)),
      truth("#{label}: not mainnet's", hash != Replay.production()["bitcoin"])
    ]
  end

  defp identity(_label, _network, _height, _hash), do: []
end
