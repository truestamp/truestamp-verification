# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Generator.KnownAnswers do
  @moduledoc """
  Check 1: each primitive against answers that do not come from the generator.
  """

  import Bitwise
  import Generator.Check

  alias Generator.{BitcoinAnswers, Bytes, Derive, JCS, Keys, Merkle, Registry, Spec}

  @vector_key "2152f8d19b791d24453242e15f2eab6cb7cffa7b6a5ed30097960e069881db12"

  # RFC 8032 section 5.1: p and d, for the decoding of step 4 of SPEC.md 6.2.
  @p Integer.pow(2, 255) - 19
  @d Integer.mod(-121_665 * :binary.decode_unsigned(:crypto.mod_pow(121_666, @p - 2, @p)), @p)

  # A member that holds a key, and its value's JSON string literal, as a file's bytes spell it.
  @key_member ~r/"(?:previous_)?public_key"\s*:\s*("(?:[^"\\]++|\\.)*+")/

  # RFC 8785 section 3.2.2: a JSON text, and its JCS.
  @rfc8785_input ~S({
    "numbers": [333333333.33333329, 1E30, 4.50, 2e-3, 0.000000000000000000000000001],
    "string": "\u20ac$\u000F\u000aA'\u0042\u0022\u005c\\\"\/",
    "literals": [null, true, false]
  })
  @rfc8785_output ~S({"literals":[null,true,false],"numbers":[333333333.3333333,1e+30,4.5,0.002,1e-27],"string":") <>
                    "\u20ac" <> ~S($\u000f\nA'B\"\\\\\"/"})

  # RFC 8785 section 3.2.3: an object's members, in the order the RFC lists them, and its JCS.
  @rfc8785_sorting {[
                      {"\u20ac", "Euro Sign"},
                      {"\r", "Carriage Return"},
                      {"\uFB33", "Hebrew Letter Dalet With Dagesh"},
                      {"1", "One"},
                      {"\u{1F600}", "Emoji: Grinning Face"},
                      {"\u0080", "Control"},
                      {"\u00F6", "Latin Small Letter O With Diaeresis"}
                    ],
                    ~s({"\\r":"Carriage Return","1":"One","\u0080":"Control",) <>
                      ~s("\u00F6":"Latin Small Letter O With Diaeresis","\u20ac":"Euro Sign",) <>
                      ~s("\u{1F600}":"Emoji: Grinning Face","\uFB33":"Hebrew Letter Dalet With Dagesh"})}

  # RFC 8785 appendix B: binary64 values by their bits, and the JCS of each. Its NaN and
  # Infinity rows are left out, since JSON has neither.
  @rfc8785_numbers [
    {"0000000000000000", "0"},
    {"8000000000000000", "0"},
    {"0000000000000001", "5e-324"},
    {"8000000000000001", "-5e-324"},
    {"7fefffffffffffff", "1.7976931348623157e+308"},
    {"ffefffffffffffff", "-1.7976931348623157e+308"},
    {"4340000000000000", "9007199254740992"},
    {"c340000000000000", "-9007199254740992"},
    {"4430000000000000", "295147905179352830000"},
    {"44b52d02c7e14af5", "9.999999999999997e+22"},
    {"44b52d02c7e14af6", "1e+23"},
    {"44b52d02c7e14af7", "1.0000000000000001e+23"},
    {"444b1ae4d6e2ef4e", "999999999999999700000"},
    {"444b1ae4d6e2ef4f", "999999999999999900000"},
    {"444b1ae4d6e2ef50", "1e+21"},
    {"3eb0c6f7a0b5ed8c", "9.999999999999997e-7"},
    {"3eb0c6f7a0b5ed8d", "0.000001"},
    {"41b3de4355555553", "333333333.3333332"},
    {"41b3de4355555554", "333333333.33333325"},
    {"41b3de4355555555", "333333333.3333333"},
    {"41b3de4355555556", "333333333.3333334"},
    {"41b3de4355555557", "333333333.33333343"},
    {"becbf647612f3696", "-0.0000033333333333333333"},
    {"43143ff3c1cb0959", "1424953923781206.2"}
  ]

  # The trees leaf-0 to leaf-8 of the Merkle library's vectors/merkle.json (truestamp-merkle-
  # elixir at 2ba4a58089c2): the root over the leaf values SHA-256("leaf1") to
  # SHA-256("leaf<n>"), for n from 0.
  @roots [
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "e6f3e0324c47532b4584166b9cdcbfb5f1dceaac9b097512d0e9e8501977daa0",
    "5d3d9c89b11a0055ba0e43c2aaf4d3814717c01a8079bc1d05db80c41852b0f5",
    "f078fbabd10cf51db1dc3552d960996e0fdae24ca5559d3aec20bf04cb65c441",
    "1d8219ac8846f635dab3201c241583de32a73ca2f1b361cec04a419ae7806324",
    "3d7804d812524d931d28e05e6ee06d73a1f4c8c3a4f47a4210b14af54794b6fa",
    "eeb8408c501ba0bd6ad670d40a2252226bff000f8551ba513bee7e5ff6675bd9",
    "df96a3ff1e450beeb5dc7e83e77f9a9f93508f4316d20c842a529c07fd82590f",
    "1c24772836336888fb591f49966a0e0c11a9d9a894e4ae6c478615f08f0ac30e"
  ]

  # The same file's paths, as {tree size, leaf index, path}.
  @paths [
    {3, 0,
     [
       "d78acbc356fa171ce40bb72ffa74cbde06c36aefc2678a9af18d3975581e969f",
       "1b7d5497f79500701b2e5c8ff00010666252817d012db3d84e2a641492a68eb8"
     ]},
    {3, 1,
     [
       "e6f3e0324c47532b4584166b9cdcbfb5f1dceaac9b097512d0e9e8501977daa0",
       "1b7d5497f79500701b2e5c8ff00010666252817d012db3d84e2a641492a68eb8"
     ]},
    {3, 2, ["5d3d9c89b11a0055ba0e43c2aaf4d3814717c01a8079bc1d05db80c41852b0f5"]},
    {5, 4, ["1d8219ac8846f635dab3201c241583de32a73ca2f1b361cec04a419ae7806324"]}
  ]

  @doc "The failures of check 1."
  def run, do: registry() ++ keys() ++ jcs() ++ merkle() ++ BitcoinAnswers.run()

  @doc """
  RFC 8785's own examples, which the JCS corpus quotes (Generator.Corpus): section 3.2.2's
  input and output, section 3.2.3's names, and appendix B's binary64 values, each `{bits,
  text}`.
  """
  def rfc8785,
    do: %{
      example: {@rfc8785_input, @rfc8785_output},
      sorting: @rfc8785_sorting,
      numbers: @rfc8785_numbers
    }

  # The registry kept here is spec/prefixes.json's, byte for byte.
  defp registry do
    from_file =
      Map.new(Spec.read("prefixes.json"), fn {kind, %{"byte" => "0x" <> byte}} ->
        {kind, String.to_integer(byte, 16)}
      end)

    expect("the registry against spec/prefixes.json", Registry.bytes(), from_file)
  end

  @doc """
  The failures of the seed check, which runs after every other: each seed the run derived a
  key from or signed with, whose bytes are published, gives a key that
  spec/keys.nonproduction.json lists as a test key, and so does each key the run built from a
  seed's key by point arithmetic (Generator.Keys.built/2). As a backstop that needs no such
  note, every `public_key` and `previous_public_key` in `files`, the files about to be written
  under vectors/, that passes the checks of a key's bytes (SPEC.md 6.2, steps 2 to 4) is one
  spec/keys.nonproduction.json lists.
  """
  def seeds(files) do
    listed =
      for %{"environment" => "test", "public_key" => public} <-
            Spec.read("keys.nonproduction.json")["keys"],
          do: public

    derived =
      for seed <- Keys.seeds_used(),
          public = Bytes.b64u(Keys.public_key(seed)),
          public not in listed,
          do:
            "the generator derives #{public} from a seed spec/keys.nonproduction.json does not list"

    built =
      for {public, seed} <- Keys.keys_built(),
          public = Bytes.b64u(public),
          public not in listed do
        "the generator builds #{public} from the key #{Bytes.b64u(Keys.public_key(seed))} " <>
          "by point arithmetic, and spec/keys.nonproduction.json does not list it"
      end

    derived ++ built ++ unlisted(files)
  end

  # Each key a file under vectors/ holds that passes steps 2 to 4 of SPEC.md 6.2 and that
  # spec/keys.nonproduction.json does not list, once, with the first file that holds it.
  defp unlisted(files) do
    listed = for key <- Spec.read("keys.nonproduction.json")["keys"], do: key["public_key"]

    held =
      for {path, bytes} <- Enum.sort(files),
          text <- key_values(bytes),
          Spec.class?("B64U32", text),
          text not in listed,
          key = Bytes.unb64u(text),
          Derive.key_bytes?(key) and on_curve?(key),
          do: {text, path}

    for {text, path} <- Enum.uniq_by(held, &elem(&1, 0)) do
      "#{path} holds the key #{text}, which passes the checks of a key's bytes (SPEC.md 6.2, " <>
        "steps 2 to 4), and spec/keys.nonproduction.json does not list it"
    end
  end

  # Every value of a public_key or previous_public_key member in `bytes`: those of the JSON
  # the bytes parse to, and those the bytes themselves spell, so a file that does not parse,
  # or that repeats a name, hides none.
  defp key_values(bytes) do
    parsed =
      case JSON.decode(bytes) do
        {:ok, value} -> key_members(value)
        {:error, _reason} -> []
      end

    spelled =
      for [_member, literal] <- Regex.scan(@key_member, bytes),
          {:ok, text} <- [JSON.decode(literal)],
          do: text

    parsed ++ spelled
  end

  defp key_members(value) when is_map(value) do
    Enum.flat_map(value, fn
      {name, member} when name in ["public_key", "previous_public_key"] ->
        [member | key_members(member)]

      {_name, member} ->
        key_members(member)
    end)
  end

  defp key_members(value) when is_list(value), do: Enum.flat_map(value, &key_members/1)
  defp key_members(_scalar), do: []

  # Step 4 of SPEC.md 6.2: the 32 octets decode as a point on the curve, as RFC 8032 section
  # 5.1.3 decodes them, for octets whose y is below p (step 2).
  defp on_curve?(<<n::little-256>>) do
    y = n &&& (1 <<< 255) - 1
    u = Integer.mod(y * y - 1, @p)
    v = Integer.mod(@d * y * y + 1, @p)
    x = Integer.mod(u * pow(v, 3) * pow(u * pow(v, 7), div(@p - 5, 8)), @p)

    cond do
      Integer.mod(v * x * x, @p) == u -> x != 0 or n >>> 255 == 0
      Integer.mod(v * x * x + u, @p) == 0 -> true
      true -> false
    end
  end

  defp pow(x, e), do: :binary.decode_unsigned(:crypto.mod_pow(Integer.mod(x, @p), e, @p))

  # VECTOR_KEY from its seed, and the key id of every key spec/keys.nonproduction.json lists.
  defp keys do
    vector = Bytes.hex(Keys.public_key(:binary.copy(<<0x42>>, 32)))

    [
      expect("VECTOR_KEY from the seed", vector, @vector_key),
      expect(
        "VECTOR_KEY in spec/constants.json",
        Spec.read("constants.json")["VECTOR_KEY"],
        @vector_key
      )
      | for %{"key_id" => key_id, "public_key" => public} <-
              Spec.read("keys.nonproduction.json")["keys"] do
          expect("the key id of #{public}", Keys.key_id(Bytes.unb64u(public)), key_id)
        end
    ]
    |> List.flatten()
  end

  defp jcs do
    List.flatten([
      expect(
        "JCS of RFC 8785 section 3.2.2",
        JCS.encode(JSON.decode!(@rfc8785_input)),
        @rfc8785_output
      ),
      # RFC 8785 section 3.2.3: names sorted by UTF-16 code units, and U+0080 written as is.
      expect(
        "JCS of RFC 8785 section 3.2.3",
        JCS.encode(Map.new(elem(@rfc8785_sorting, 0))),
        elem(@rfc8785_sorting, 1)
      ),
      # SPEC.md 13.3: names that sort one way by UTF-16 code unit and the other by code point.
      expect(
        "JCS of U+FF5A and U+1F600",
        JCS.encode(%{"\uFF5A" => 1, "\u{1F600}" => 2}),
        ~s({"\u{1F600}":2,"\uFF5A":1})
      ),
      # ECMAScript's JSON.stringify escapes these, and writes U+007F and U+2028 as they are.
      expect(
        "JCS of a string with control characters",
        JCS.encode("\u0001\b\t\n\f\r\u001f\u007f\u2028\"\\/"),
        ~S("\u0001\b\t\n\f\r\u001f) <> "\u007f\u2028" <> ~S(\"\\/")
      ),
      for {bits, text} <- @rfc8785_numbers do
        <<n::float-64>> = Bytes.unhex(bits)
        expect("JCS of the binary64 #{bits}", JCS.encode(n), text)
      end,
      # The numbers of SPEC.md 13.3's sound item, 1.0 for 1, and the largest INT.
      for {n, text} <- [
            {37.7749, "37.7749"},
            {1.0e-7, "1e-7"},
            {1.0, "1"},
            {9_007_199_254_740_991, "9007199254740991"}
          ] do
        expect("JCS of #{inspect(n)}", JCS.encode(n), text)
      end
    ])
  end

  defp merkle do
    leaves = for i <- 1..8, do: :crypto.hash(:sha256, "leaf#{i}")
    tree = &Enum.take(leaves, &1)
    last = Bytes.hex(Enum.at(leaves, 2))
    node01 = Bytes.hex(Merkle.root(tree.(2)))
    root3 = {:ok, Enum.at(@roots, 3)}

    List.flatten([
      for {root, n} <- Enum.with_index(@roots) do
        expect("MTH of #{n} leaves", Bytes.hex(Merkle.root(tree.(n))), root)
      end,
      for {n, index, path} <- @paths do
        expect("the path of leaf #{index} of #{n}", Merkle.proof(index, tree.(n))["path"], path)
      end,
      # SPEC.md 5.3: the walk, and the moved index it cannot catch alone. The last of three
      # leaves also walks to the root as index 1 of two.
      expect("the walk of leaf 2 of 3", Merkle.walk(last, proof(2, [node01], 3)), root3),
      expect(
        "the walk of leaf 2 of 3 as leaf 1 of 2",
        Merkle.walk(last, proof(1, [node01], 2)),
        root3
      ),
      # Leaf 1 of one and leaf 2 of two reach a root in every step of the walk but the first.
      for {label, walk} <- [
            {"leaf 1 of a tree of one", proof(1, [], 1)},
            {"leaf 2 of a tree of two", proof(2, [node01], 2)},
            {"a path one node short", proof(2, [], 3)},
            {"a path one node long", proof(2, [node01, node01], 3)},
            {"a path that is short for its tree size", proof(2, [node01], 4)},
            {"a path of 33 nodes", proof(0, List.duplicate(node01, 33), Integer.pow(2, 33))}
          ] do
        expect("no root from #{label}", Merkle.walk(last, walk), :error)
      end,
      walk_every_leaf(leaves)
    ])
  end

  defp proof(index, path, size), do: %{"leaf_index" => index, "path" => path, "tree_size" => size}

  # Every leaf of every tree of 1 to 64 leaves walks to the tree's root, and a changed path
  # node leads elsewhere.
  defp walk_every_leaf(leaves) do
    values = leaves ++ for(i <- 9..64, do: :crypto.hash(:sha256, "leaf#{i}"))

    for n <- 1..64 do
      tree = Enum.take(values, n)
      root = {:ok, Bytes.hex(Merkle.root(tree))}
      for index <- 0..(n - 1), do: leaf_walks(tree, index, root, "leaf #{index} of #{n}")
    end
  end

  defp leaf_walks(tree, index, root, label) do
    start = Bytes.hex(Enum.at(tree, index))
    proof = Merkle.proof(index, tree)

    [
      expect("the walk of #{label}", Merkle.walk(start, proof), root),
      changed_node(start, proof, root, label)
    ]
  end

  defp changed_node(_start, %{"path" => []}, _root, _label), do: []

  defp changed_node(start, %{"path" => [first | rest]} = proof, root, label) do
    changed = Bytes.hex(:crypto.hash(:sha256, first))
    walk = Merkle.walk(start, %{proof | "path" => [changed | rest]})
    truth("a changed path node of #{label} leads elsewhere", walk != root)
  end
end

defmodule Generator.BitcoinAnswers do
  @moduledoc """
  Check 1 for Bitcoin: the builder (Generator.Bitcoin) and the rederive check's parser
  (Generator.BitcoinParse) against answers from Bitcoin's own chains and from Bitcoin Core's
  tests, and against each other.
  """

  import Generator.Check

  alias Generator.{Bitcoin, BitcoinParse, Bytes}

  # Mainnet's genesis block: its one transaction, serialized, and the pieces it is made of.
  @coinbase "01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff" <>
              "4d04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c" <>
              "6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73" <>
              "ffffffff0100f2052a01000000434104678afdb0fe5548271967f1a67130b7105cd6a828e03909" <>
              "a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf1" <>
              "1d5fac00000000"
  @coinbase_script_sig "04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e" <>
                         "63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420" <>
                         "666f722062616e6b73"
  @coinbase_output "4104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc" <>
                     "3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac"
  @genesis_txid "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b"

  # Mainnet block 100,000: its four txids, its Merkle root and its header.
  @block_100000_txids [
    "8c14f0db3df150123e6f3dbbf30f8b955a8249b62ac1d1ff16284aefa3d06d87",
    "fff2525b8931402dd09222c50775608f75787bd2b87e56995a7bdd30f79702c4",
    "6359f0868171b1d194cbee1af2f16ea598ae8fad666d9b012c8ed2b79a236ec4",
    "e9a66845e05d5abc0ad04ec80f774a7e585c6e8db975962d069a522137b80c1d"
  ]
  @block_100000_root "f3e94742aca4b5ef85488dc37c06c3282295ffec960994b2c0d5ac2a25a95766"
  @block_100000_previous "000000000002d01c1fccc21636b607dfd930d31d01c3a62104612a1719011250"
  @block_100000_hash "000000000003ba27aa200b1cecaad478d2b00432346c3f1f3986da1afd33e506"

  # Each header: {version, previous, Merkle root, time, nBits, nonce, its hash}, in display hex.
  @headers [
    {1, String.duplicate("0", 64), @genesis_txid, 1_231_006_505, 0x1D00FFFF, 2_083_236_893,
     "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"},
    {1, String.duplicate("0", 64), @genesis_txid, 1_296_688_602, 0x207FFFFF, 2,
     "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206"},
    {1, @block_100000_previous, @block_100000_root, 1_293_623_863, 0x1B04864C, 274_148_111,
     @block_100000_hash}
  ]

  # nBits and the target each encodes, from Bitcoin Core's SetCompact tests
  # (src/test/arith_uint256_tests.cpp).
  @targets [
    {0x00123456, {:ok, 0}},
    {0x01003456, {:ok, 0}},
    {0x02000056, {:ok, 0}},
    {0x04000000, {:ok, 0}},
    {0x00923456, {:ok, 0}},
    {0x01803456, {:ok, 0}},
    {0x01123456, {:ok, 0x12}},
    {0x01FEDCBA, :negative},
    {0x02123456, {:ok, 0x1234}},
    {0x03123456, {:ok, 0x123456}},
    {0x04123456, {:ok, 0x12345600}},
    {0x04923456, :negative},
    {0x05009234, {:ok, 0x92340000}},
    {0x20123456, {:ok, 0x123456 * Integer.pow(256, 29)}},
    {0xFF123456, :overflow},
    {0x1D00FFFF, {:ok, 0xFFFF * Integer.pow(2, 208)}},
    {0x207FFFFF, {:ok, 0x7FFFFF * Integer.pow(256, 29)}}
  ]

  @doc "The failures of check 1 for Bitcoin."
  def run, do: List.flatten([transaction(), merkle(), headers(), targets(), partial_trees()])

  @doc "Mainnet's genesis transaction, serialized."
  def genesis_transaction, do: Bytes.unhex(@coinbase)

  @doc """
  The headers check 1 builds, each `{version, previous, Merkle root, time, nBits, nonce,
  hash}`, the hashes in display hex: mainnet's genesis, regtest's genesis and mainnet block
  100,000.
  """
  def header_fields, do: @headers

  # The builder writes mainnet's genesis transaction from its pieces, and the parser reads it.
  defp transaction do
    built =
      Bitcoin.transaction(%{
        version: 1,
        inputs: [{<<0::256>>, 0xFFFFFFFF, Bytes.unhex(@coinbase_script_sig), 0xFFFFFFFF}],
        outputs: [{5_000_000_000, Bytes.unhex(@coinbase_output)}],
        locktime: 0
      })

    [
      expect("the genesis transaction, written", Bytes.hex(built), @coinbase),
      expect("its txid", Bitcoin.display(Bitcoin.txid(built)), @genesis_txid),
      expect(
        "its txid, by the parser",
        BitcoinParse.display(BitcoinParse.sha256d(built)),
        @genesis_txid
      ),
      expect(
        "its output scripts, read",
        BitcoinParse.transaction(built),
        {:ok, [Bytes.unhex(@coinbase_output)]}
      ),
      expect("no OP_RETURN in it", BitcoinParse.op_return(built), :error),
      expect(
        "a transaction cut short",
        BitcoinParse.transaction(binary_part(built, 0, 100)),
        :error
      ),
      expect("a byte after the lock time", BitcoinParse.transaction(built <> <<0>>), :error),
      expect("BIP 34's height 1", Bitcoin.coinbase_script(1), <<0x51, 0x00>>),
      expect("BIP 34's height 200", Bitcoin.coinbase_script(200), <<0x02, 0xC8, 0x00, 0x00>>),
      expect(
        "BIP 34's height 100000",
        Bitcoin.coinbase_script(100_000),
        <<0x03, 0xA0, 0x86, 0x01, 0x00>>
      )
    ]
  end

  defp merkle do
    txids = Enum.map(@block_100000_txids, &Bitcoin.internal/1)
    [a, b, c, _d] = txids
    three = Bitcoin.sha256d(Bitcoin.sha256d(a <> b) <> Bitcoin.sha256d(c <> c))

    [
      expect(
        "the Merkle root of block 100,000",
        Bitcoin.display(Bitcoin.merkle_root(txids)),
        @block_100000_root
      ),
      expect(
        "the Merkle root of three, the last paired with itself",
        Bitcoin.merkle_root([a, b, c]),
        three
      ),
      expect("the Merkle root of one", Bitcoin.merkle_root([a]), a)
    ]
  end

  defp headers do
    for {version, previous, root, time, bits, nonce, hash} <- @headers do
      header =
        Bitcoin.header(%{
          version: version,
          previous: Bitcoin.internal(previous),
          merkle_root: Bitcoin.internal(root),
          time: time,
          bits: bits,
          nonce: nonce
        })

      [
        expect("the hash of header #{hash}", Bitcoin.display(Bitcoin.sha256d(header)), hash),
        truth("header #{hash} meets its target, for the builder", Bitcoin.meets_target?(header)),
        truth(
          "header #{hash} meets its target, for the parser",
          BitcoinParse.meets_target?(header)
        ),
        another_nonce(header, bits, hash),
        expect("the time of header #{hash}", BitcoinParse.time(header), time),
        expect(
          "the Merkle root field of header #{hash}",
          BitcoinParse.display(BitcoinParse.merkle_root_field(header)),
          root
        )
      ]
    end
  end

  # Half of all nonces meet regtest's target, so only a mainnet header shows that the target
  # is checked: with the next nonce its hash is far above it.
  defp another_nonce(_header, 0x207FFFFF, _hash), do: []

  defp another_nonce(<<head::binary-76, nonce::little-32>>, _bits, hash) do
    changed = head <> <<nonce + 1::little-32>>

    [
      truth(
        "header #{hash} with the next nonce misses its target, for the builder",
        not Bitcoin.meets_target?(changed)
      ),
      truth(
        "header #{hash} with the next nonce misses its target, for the parser",
        not BitcoinParse.meets_target?(changed)
      )
    ]
  end

  defp targets do
    for {bits, target} <- @targets do
      builder =
        if match?({:ok, _}, target),
          do: [expect("the builder's target of #{bits}", {:ok, Bitcoin.target(bits)}, target)],
          else: []

      [expect("the parser's target of #{bits}", BitcoinParse.target(bits), target) | builder]
    end
  end

  # The builder's merkleblock of each leaf of trees of 1 to 24 transactions, read back by the
  # parser: the root is the tree's, the one match is the leaf, and a flag bit or hash too many
  # is refused.
  defp partial_trees do
    for total <- 1..24, index <- 0..(total - 1) do
      txids = for i <- 1..total, do: :crypto.hash(:sha256, "tx #{i}")
      root = Bitcoin.merkle_root(txids)

      header =
        Bitcoin.grind(%{
          version: 4,
          previous: <<0::256>>,
          merkle_root: root,
          time: 0,
          bits: 0x207FFFFF,
          nonce: 0
        })

      block = Bitcoin.merkleblock(header, txids, index)
      label = "the merkleblock of leaf #{index} of #{total}"

      [
        expect(label, BitcoinParse.merkleblock(block), {:ok, header, Enum.at(txids, index)}),
        expect("#{label}, with a byte after it", BitcoinParse.merkleblock(block <> <<0>>), :error)
      ]
    end
  end
end
