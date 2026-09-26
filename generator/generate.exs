# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

# The vector generator of SPEC.md 13.2. It writes the files under vectors/ and checks them.
#
#     elixir generator/generate.exs            # write the files under vectors/
#     elixir generator/generate.exs --check    # write nothing, and fail unless vectors/ holds
#                                              # exactly the files the first form writes
#
# Every run makes two checks before it writes or compares anything, and a failure in either
# writes nothing:
#
#   1. Known answers. Each primitive the generator uses (the byte registry, key ids, JCS, the
#      Merkle Tree Hash, inclusion paths and the walk of SPEC.md 5.3) is run against answers
#      that do not come from the generator: kept by hand in this file from RFC 8785 and from
#      the Merkle library's vectors/merkle.json, or read from the files under spec/. A
#      primitive that changes breaks this table instead of quietly publishing new bytes.
#   2. Re-derivation. Each file is decoded from the bytes about to be written, and every value
#      in it is derived again from those bytes alone, never from the values that built it.
#
# Then SPEC.md 6.3's worked example is read from the text and compared, value by value, with
# worked-example.json.
#
# The generator shares no code with any verifier in this repository. It uses only Elixir,
# :crypto and the data files under spec/, with its own JCS and its own Merkle walk, so a
# defect in one cannot hide in both.

defmodule Generator.Check do
  @moduledoc """
  A check gives a list of failure messages, empty when it holds.
  """

  @doc "No failure when `actual` is exactly `expected`, compared with `===`."
  def expect(_label, actual, expected) when actual === expected, do: []

  def expect(label, actual, expected),
    do: ["#{label}: got #{inspect(actual)}, expected #{inspect(expected)}"]

  @doc "No failure when `holds` is `true`."
  def truth(_label, true), do: []
  def truth(label, _holds), do: [label]
end

defmodule Generator.Spec do
  @moduledoc """
  The repository's root, SPEC.md and the data files under spec/.
  """

  @doc "The root of the repository."
  def root, do: Path.expand("..", __DIR__)

  @doc "The text of SPEC.md."
  def spec_md, do: root() |> Path.join("SPEC.md") |> File.read!()

  @doc "The value of the file `name` under spec/."
  def read(name), do: root() |> Path.join("spec/" <> name) |> File.read!() |> JSON.decode!()

  @doc "Whether `value` is a string of the pattern class `class` (SPEC.md 2.4)."
  def class?(class, value) do
    %{"pattern" => pattern} = Map.fetch!(read("encodings.json"), class)
    is_binary(value) and value =~ Regex.compile!("\\A(?:" <> pattern <> ")\\z")
  end
end

defmodule Generator.Bytes do
  @moduledoc """
  Lowercase hex and unpadded base64url (RFC 4648 section 5).
  """

  def hex(bytes), do: Base.encode16(bytes, case: :lower)
  def unhex(text), do: Base.decode16!(text, case: :lower)
  def b64u(bytes), do: Base.url_encode64(bytes, padding: false)
  def unb64u(text), do: Base.url_decode64!(text, padding: false)
end

defmodule Generator.JCS do
  @moduledoc """
  The JSON Canonicalization Scheme of RFC 8785: member names sorted by their UTF-16 code
  units, strings escaped as ECMAScript's JSON.stringify escapes them, and numbers written as
  ECMAScript's Number.prototype.toString writes them. Integers are limited to the range of
  the INT class, since only those are exact in binary64.
  """

  @max_integer 9_007_199_254_740_991

  @doc "The JCS bytes of `value`."
  def encode(value), do: value |> value() |> IO.iodata_to_binary()

  @doc "Member names in JCS order."
  def sort_names(names),
    do: Enum.sort_by(names, &:unicode.characters_to_binary(&1, :utf8, :utf16))

  @doc "A string as JCS writes it, quotes included."
  def string(text) do
    if not String.valid?(text), do: raise(ArgumentError, "not UTF-8: #{inspect(text)}")
    ["\"", for(<<char::utf8 <- text>>, do: escape(char)), "\""]
  end

  defp value(nil), do: "null"
  defp value(true), do: "true"
  defp value(false), do: "false"
  defp value(text) when is_binary(text), do: string(text)
  defp value(n) when is_integer(n) and abs(n) <= @max_integer, do: Integer.to_string(n)
  defp value(n) when is_float(n), do: number(n)

  defp value(list) when is_list(list),
    do: ["[", Enum.intersperse(Enum.map(list, &value/1), ","), "]"]

  defp value(object) when is_map(object) do
    members =
      for name <- sort_names(Map.keys(object)),
          do: [string(name), ":", value(Map.fetch!(object, name))]

    ["{", Enum.intersperse(members, ","), "}"]
  end

  defp escape(?"), do: "\\\""
  defp escape(?\\), do: "\\\\"
  defp escape(?\b), do: "\\b"
  defp escape(?\t), do: "\\t"
  defp escape(?\n), do: "\\n"
  defp escape(?\f), do: "\\f"
  defp escape(?\r), do: "\\r"

  defp escape(char) when char < 0x20,
    do:
      "\\u" <> (char |> Integer.to_string(16) |> String.downcase() |> String.pad_leading(4, "0"))

  defp escape(char), do: <<char::utf8>>

  # Number::toString of ECMAScript: with k the count of the shortest digits that read back as
  # the value, and the value = 0.d1...dk x 10^n.
  defp number(n) when n == 0, do: "0"
  defp number(n) when n < 0, do: ["-", number(-n)]

  defp number(n) do
    {digits, point} = shortest(n)
    format(digits, byte_size(digits), point)
  end

  defp format(digits, k, n) when k <= n and n <= 21, do: [digits, String.duplicate("0", n - k)]

  defp format(digits, k, n) when 0 < n and n <= 21,
    do: [binary_part(digits, 0, n), ".", binary_part(digits, n, k - n)]

  defp format(digits, _k, n) when -6 < n and n <= 0,
    do: ["0.", String.duplicate("0", -n), digits]

  defp format(<<first::binary-size(1)>>, 1, n), do: [first, "e", exponent(n - 1)]

  defp format(<<first::binary-size(1), rest::binary>>, _k, n),
    do: [first, ".", rest, "e", exponent(n - 1)]

  defp exponent(e) when e < 0, do: Integer.to_string(e)
  defp exponent(e), do: "+" <> Integer.to_string(e)

  # OTP's shortest round-trip form, "I.F" or "I.Fe<exponent>", as the digits of 0.d1...dk and
  # the place n of the point, with no leading or trailing zero digit.
  defp shortest(n) do
    [mantissa | exponent] = n |> :erlang.float_to_binary([:short]) |> String.split("e")
    [whole | fraction] = String.split(mantissa, ".")
    point = byte_size(whole) + Enum.sum(Enum.map(exponent, &String.to_integer/1))
    digits = whole <> Enum.join(fraction)
    trimmed = String.trim_leading(digits, "0")
    {String.trim_trailing(trimmed, "0"), point - (byte_size(digits) - byte_size(trimmed))}
  end
end

defmodule Generator.FileForm do
  @moduledoc """
  The form of every file under vectors/, the one SPEC.md 9 gives the files under spec/:
  ASCII, members in JCS order, two-space indentation, LF line ends and a final newline.
  """

  alias Generator.JCS

  @doc "The bytes of the file that holds `value`."
  def encode(value) do
    text = IO.iodata_to_binary([pretty(value, 0), "\n"])

    if text =~ ~r/\A[\x20-\x7e\n]*\z/,
      do: text,
      else: raise(ArgumentError, "not printable ASCII: #{inspect(value)}")
  end

  defp pretty(object, _level) when object == %{}, do: "{}"

  defp pretty(object, level) when is_map(object) do
    members =
      for name <- JCS.sort_names(Map.keys(object)) do
        [indent(level + 1), JCS.string(name), ": ", pretty(Map.fetch!(object, name), level + 1)]
      end

    ["{\n", Enum.intersperse(members, ",\n"), "\n", indent(level), "}"]
  end

  defp pretty([], _level), do: "[]"

  defp pretty(list, level) when is_list(list) do
    elements = Enum.map(list, &[indent(level + 1), pretty(&1, level + 1)])
    ["[\n", Enum.intersperse(elements, ",\n"), "\n", indent(level), "]"]
  end

  defp pretty(scalar, _level), do: JCS.encode(scalar)

  defp indent(level), do: String.duplicate("  ", level)
end

defmodule Generator.Registry do
  @moduledoc """
  The byte-prefix registry of SPEC.md 4.3, kept by hand, and the hashes it names.
  """

  alias Generator.JCS

  @bytes %{
    "merkle_leaf" => 0x00,
    "merkle_node" => 0x01,
    "claims_hash" => 0x10,
    "item_hash" => 0x11,
    "entropy_hash" => 0x20,
    "observation_hash" => 0x21,
    "genesis_previous_block_hash" => 0x30,
    "block_hash" => 0x31,
    "epoch_hash" => 0x40,
    "proof_hash" => 0x50,
    "key_id" => 0x60,
    "prerotation_commitment" => 0x61,
    "handover" => 0x62
  }

  @doc "Each construction's byte, by the name spec/prefixes.json gives it."
  def bytes, do: @bytes

  @doc "SHA-256(p || data), with p the byte of `kind`."
  def hash(kind, data), do: :crypto.hash(:sha256, [Map.fetch!(@bytes, kind), data])

  @doc "The record hash H(p, R) of SPEC.md 4.1."
  def record_hash(kind, record), do: hash(kind, JCS.encode(record))
end

defmodule Generator.Keys do
  @moduledoc """
  Ed25519 keys and signatures (RFC 8032, pure), and the key id of SPEC.md 3.3.
  """

  alias Generator.{Bytes, Registry}

  @doc "The public key of a 32-byte seed."
  def public_key(seed) do
    {public, _secret} = :crypto.generate_key(:eddsa, :ed25519, seed)
    public
  end

  @doc "The signature of `message` under the key of `seed`."
  def sign(seed, message), do: :crypto.sign(:eddsa, :none, message, [seed, :ed25519])

  @doc "Whether `signature` verifies under `public` over `message`."
  def verify?(public, message, signature),
    do: :crypto.verify(:eddsa, :none, message, signature, [public, :ed25519])

  @doc "The hex of the first 4 bytes of SHA-256(0x60 || the key)."
  def key_id(public), do: "key_id" |> Registry.hash(public) |> binary_part(0, 4) |> Bytes.hex()
end

defmodule Generator.Merkle do
  @moduledoc """
  The Merkle Tree Hash and inclusion paths of RFC 9162 section 2.1, over 32-byte leaf values,
  and the walk merkle_path(start, proof) of SPEC.md 5.3.
  """

  import Bitwise

  alias Generator.{Bytes, Registry}

  @max_path_steps 32

  @doc "MTH(D[n]): the root of the tree whose leaves are `leaves`, in that order."
  def root([]), do: :crypto.hash(:sha256, "")
  def root([leaf]), do: Registry.hash("merkle_leaf", leaf)

  def root(leaves) do
    {left, right} = Enum.split(leaves, split(length(leaves)))
    Registry.hash("merkle_node", root(left) <> root(right))
  end

  @doc "The MERKLE_PROOF of the leaf at `index`, with its path in hex from the leaf up."
  def proof(index, leaves) do
    path = index |> path(leaves) |> Enum.map(&Bytes.hex/1)
    %{"leaf_index" => index, "path" => path, "tree_size" => length(leaves)}
  end

  # PATH(m, D[n]) of RFC 9162 section 2.1.3.1.
  defp path(0, [_leaf]), do: []

  defp path(index, leaves) do
    k = split(length(leaves))
    {left, right} = Enum.split(leaves, k)

    if index < k,
      do: path(index, left) ++ [root(right)],
      else: path(index - k, right) ++ [root(left)]
  end

  # The largest power of two below n, for n of 2 or more.
  defp split(n), do: split(n, 1)
  defp split(n, k) when k * 2 < n, do: split(n, k * 2)
  defp split(_n, k), do: k

  @doc """
  merkle_path(start, proof) of SPEC.md 5.3, from the hex of a leaf value: `{:ok, root_hex}`,
  or `:error` for a walk that gives no root.
  """
  def walk(start, %{"leaf_index" => index, "path" => path, "tree_size" => size}) do
    if index >= size or length(path) > @max_path_steps do
      :error
    else
      path
      |> Enum.map(&Bytes.unhex/1)
      |> Enum.reduce_while(
        {index, size - 1, Registry.hash("merkle_leaf", Bytes.unhex(start))},
        &step/2
      )
      |> finish()
    end
  end

  # Step 3, for one node p, with f and s standing for 5.3's fn and sn.
  defp step(_p, {_f, 0, _r}), do: {:halt, :error}

  defp step(p, {f, s, r}) when (f &&& 1) == 1 or f == s do
    {f, s} = shift_even(f, s)
    {:cont, {f >>> 1, s >>> 1, Registry.hash("merkle_node", p <> r)}}
  end

  defp step(p, {f, s, r}), do: {:cont, {f >>> 1, s >>> 1, Registry.hash("merkle_node", r <> p)}}

  defp shift_even(f, s) when f != 0 and (f &&& 1) == 0, do: shift_even(f >>> 1, s >>> 1)
  defp shift_even(f, s), do: {f, s}

  defp finish({_f, 0, r}), do: {:ok, Bytes.hex(r)}
  defp finish(_state), do: :error
end

defmodule Generator.Vectors do
  @moduledoc """
  The files under vectors/, each as its path and its value.
  """

  alias Generator.{Bytes, FileForm, JCS, Keys, Registry}

  # SPEC.md 9: VECTOR_KEY is the key of the seed of 32 bytes of 0x42.
  @vector_seed :binary.copy(<<0x42>>, 32)

  # The input of SPEC.md 6.3.
  @example_proof %{
    "environment" => "test",
    "format" => "truestamp-proof",
    "type" => "block",
    "version" => 1
  }

  @doc "Each file's bytes, by its path from the root of the repository."
  def files do
    Map.new(
      [
        {"vectors/keyring.test.json", keyring_test()},
        {"vectors/worked-example.json", worked_example()}
      ],
      fn {path, value} -> {path, FileForm.encode(value)} end
    )
  end

  # SPEC.md 13.2: a keyring in the form of section 10.2, step 0, whose one key is VECTOR_KEY.
  defp keyring_test do
    public = Keys.public_key(@vector_seed)

    %{
      "keys" => [
        %{
          "active" => true,
          "key_id" => Keys.key_id(public),
          "public_key" => Bytes.b64u(public),
          "sequence" => 0
        }
      ],
      "version" => "1.0"
    }
  end

  # SPEC.md 6.1 over the input of 6.3, signed with the vector seed.
  defp worked_example do
    public = Keys.public_key(@vector_seed)
    m = JCS.encode(@example_proof)
    proof_hash = Registry.hash("proof_hash", m)
    s = Keys.sign(@vector_seed, proof_hash)

    signature = %{
      "alg" => "truestamp-ed25519-sha256-jcs",
      "public_key" => Bytes.b64u(public),
      "value" => Bytes.b64u(s)
    }

    %{
      "A" => Bytes.hex(public),
      "K" => Bytes.b64u(public),
      "M" => m,
      "S" => Bytes.hex(s),
      "V" => Bytes.b64u(s),
      "document" => JCS.encode(%{"proof" => @example_proof, "signature" => signature}),
      "key_id" => Keys.key_id(public),
      "proof" => @example_proof,
      "proof_hash" => Bytes.hex(proof_hash),
      "sk" => Bytes.hex(@vector_seed)
    }
  end
end

defmodule Generator.KnownAnswers do
  @moduledoc """
  Check 1: each primitive against answers that do not come from the generator.
  """

  import Generator.Check

  alias Generator.{Bytes, JCS, Keys, Merkle, Registry, Spec}

  @vector_key "2152f8d19b791d24453242e15f2eab6cb7cffa7b6a5ed30097960e069881db12"

  # RFC 8785 section 3.2.2: a JSON text, and its JCS.
  @rfc8785_input ~S({
    "numbers": [333333333.33333329, 1E30, 4.50, 2e-3, 0.000000000000000000000000001],
    "string": "\u20ac$\u000F\u000aA'\u0042\u0022\u005c\\\"\/",
    "literals": [null, true, false]
  })
  @rfc8785_output ~S({"literals":[null,true,false],"numbers":[333333333.3333333,1e+30,4.5,0.002,1e-27],"string":") <>
                    "\u20ac" <> ~S($\u000f\nA'B\"\\\\\"/"})

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
  def run, do: registry() ++ keys() ++ jcs() ++ merkle()

  # The registry kept here is spec/prefixes.json's, byte for byte.
  defp registry do
    from_file =
      Map.new(Spec.read("prefixes.json"), fn {kind, %{"byte" => "0x" <> byte}} ->
        {kind, String.to_integer(byte, 16)}
      end)

    expect("the registry against spec/prefixes.json", Registry.bytes(), from_file)
  end

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
        JCS.encode(%{
          "\u20ac" => "Euro Sign",
          "\r" => "Carriage Return",
          "\uFB33" => "Hebrew Letter Dalet With Dagesh",
          "1" => "One",
          "\u{1F600}" => "Emoji: Grinning Face",
          "\u0080" => "Control",
          "\u00F6" => "Latin Small Letter O With Diaeresis"
        }),
        ~s({"\\r":"Carriage Return","1":"One","\u0080":"Control",) <>
          ~s("\u00F6":"Latin Small Letter O With Diaeresis","\u20ac":"Euro Sign",) <>
          ~s("\u{1F600}":"Emoji: Grinning Face","\uFB33":"Hebrew Letter Dalet With Dagesh"})
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

defmodule Generator.Rederive do
  @moduledoc """
  Check 2: each file decoded from the bytes about to be written, and every value in it
  derived again from those bytes alone.
  """

  import Generator.Check

  alias Generator.{Bytes, FileForm, JCS, Keys, Registry, Spec}

  @doc "The failures of check 2 over `files`, each file's bytes by its path."
  def run(files) do
    List.flatten([
      for({path, bytes} <- files, do: form(path, bytes)),
      keyring_test(JSON.decode!(files["vectors/keyring.test.json"])),
      worked_example(JSON.decode!(files["vectors/worked-example.json"]))
    ])
  end

  # Each file reads back to a value whose form is the file itself.
  defp form(path, bytes),
    do: expect("#{path} in its form", FileForm.encode(JSON.decode!(bytes)), bytes)

  # SPEC.md 13.2 and 10.2, step 0: a keyring whose one key is VECTOR_KEY.
  defp keyring_test(keyring) do
    [key] = keyring["keys"]
    public = key["public_key"]
    bytes = if Spec.class?("B64U32", public), do: Bytes.unb64u(public)

    [
      expect("keyring.test.json's members", Enum.sort(Map.keys(keyring)), ["keys", "version"]),
      expect("keyring.test.json's version", keyring["version"], "1.0"),
      expect("its key's members", Enum.sort(Map.keys(key)), [
        "active",
        "key_id",
        "public_key",
        "sequence"
      ]),
      truth("its key's active is a boolean", is_boolean(key["active"])),
      truth("its key's sequence is an INT", key["sequence"] in 0..9_007_199_254_740_991//1),
      truth("its key's public_key is a B64U32", bytes != nil),
      expect(
        "its key is VECTOR_KEY",
        bytes && Bytes.hex(bytes),
        Spec.read("constants.json")["VECTOR_KEY"]
      ),
      expect("its key's key_id", bytes && Keys.key_id(bytes), key["key_id"])
    ]
  end

  # SPEC.md 6.1 and 6.3, from worked-example.json alone.
  defp worked_example(example) do
    %{"M" => m, "proof" => proof, "document" => document} = example
    public = Keys.public_key(Bytes.unhex(example["sk"]))
    proof_hash = Registry.hash("proof_hash", m)
    s = if Spec.class?("B64U64", example["V"]), do: Bytes.unb64u(example["V"]), else: <<>>

    [
      expect(
        "worked-example.json's members",
        Enum.sort(Map.keys(example)),
        ~w(A K M S V document key_id proof proof_hash sk)
      ),
      expect("M, the JCS of proof", JCS.encode(proof), m),
      expect("proof_hash, SHA-256(0x50 || M)", Bytes.hex(proof_hash), example["proof_hash"]),
      expect("A, the public key of sk", Bytes.hex(public), example["A"]),
      expect("A, VECTOR_KEY", example["A"], Spec.read("constants.json")["VECTOR_KEY"]),
      expect("K, A in base64url", Bytes.b64u(public), example["K"]),
      truth("K is a B64U32", Spec.class?("B64U32", example["K"])),
      expect("the key id of A", Keys.key_id(public), example["key_id"]),
      expect(
        "S, the signature of sk over proof_hash",
        Keys.sign(Bytes.unhex(example["sk"]), proof_hash),
        Bytes.unhex(example["S"])
      ),
      expect("V, S in base64url", s, Bytes.unhex(example["S"])),
      truth("S verifies under A over proof_hash", Keys.verify?(public, proof_hash, s)),
      expect("the served document, JCS(envelope)", JCS.encode(JSON.decode!(document)), document),
      expect("the document's value", JSON.decode!(document), envelope(example)),
      not_verified(example, public, s),
      reformatted(example, public)
    ]
  end

  defp envelope(example) do
    %{
      "proof" => example["proof"],
      "signature" => %{
        "alg" => "truestamp-ed25519-sha256-jcs",
        "public_key" => example["K"],
        "value" => example["V"]
      }
    }
  end

  # SPEC.md 6.3: S does not verify over these messages.
  defp not_verified(%{"M" => m, "proof" => proof, "proof_hash" => proof_hash}, public, s) do
    for {label, message} <- [
          {"M itself", m},
          {"SHA-256(M)", :crypto.hash(:sha256, m)},
          {"the hex of proof_hash", proof_hash},
          {"SHA-256(0x31 || M)", Registry.hash("block_hash", m)},
          {"SHA-256(0x62 || M)", Registry.hash("handover", m)},
          {"the proof with environment dev",
           Registry.record_hash("proof_hash", %{proof | "environment" => "dev"})},
          {"the proof with environment removed",
           Registry.record_hash("proof_hash", Map.delete(proof, "environment"))}
        ] do
      truth("S does not verify over #{label}", not Keys.verify?(public, message, s))
    end
  end

  # SPEC.md 6.3: the document re-indented with CRLF line ends, its members in reverse order,
  # a string spelled with a \u escape and 1.0 for 1, still verifies.
  defp reformatted(example, public) do
    signature = [
      {"value", example["V"]},
      {"public_key", example["K"]},
      {"alg", "truestamp-ed25519-sha256-jcs"}
    ]

    proof = Enum.sort(example["proof"], :desc)

    text =
      Enum.join(
        [
          "{",
          ~s(  "signature": {),
          members(signature),
          "  },",
          ~s(  "proof": {),
          members(proof),
          "  }",
          "}"
        ],
        "\r\n"
      )

    reread = JSON.decode!(text)["proof"]
    reread_hash = Registry.record_hash("proof_hash", reread)

    [
      truth(
        "the reformatted document spells 1.0 and a \\u escape",
        text =~ ".0," and text =~ "\\u00"
      ),
      expect("the reformatted document's proof, as JCS", JCS.encode(reread), example["M"]),
      truth(
        "the reformatted document verifies",
        Keys.verify?(public, reread_hash, Bytes.unb64u(example["V"]))
      )
    ]
  end

  defp members(pairs),
    do:
      Enum.map_join(pairs, ",\r\n", fn {name, value} -> ~s(    "#{name}": #{respell(value)}) end)

  defp respell(n) when is_integer(n), do: "#{n}.0"

  defp respell(<<first, rest::binary>>) when first in ?a..?z,
    do: ~s("\\u00#{Integer.to_string(first, 16) |> String.downcase()}#{rest}")

  defp respell(text), do: JCS.encode(text)
end

defmodule Generator.WorkedExample do
  @moduledoc """
  SPEC.md 6.3's worked example, read from the text and compared with worked-example.json.
  """

  import Generator.Check

  # Each row of 6.3's table, by the label SPEC.md gives it, and the member of
  # worked-example.json that holds its value.
  defp rows do
    [
      {~r/\AM, (\d+) octets\z/, "M"},
      {~r/\A`proof_hash`\z/, "proof_hash"},
      {~r/\Ask, the vector seed\z/, "sk"},
      {~r/\AA, the public key \(VECTOR_KEY\)\z/, "A"},
      {~r/\AK\z/, "K"},
      {~r/\Akey id of A \(section 3\.3\)\z/, "key_id"},
      {~r/\AS\z/, "S"},
      {~r/\AV\z/, "V"}
    ]
  end

  @doc "The failures of the comparison, for SPEC.md's text and worked-example.json's bytes."
  def run(spec_md, bytes) do
    example = JSON.decode!(bytes)
    [_before, section] = String.split(spec_md, "\n### 6.3 Worked example\n", parts: 2)
    [section, _after] = String.split(section, "\n### 6.4 ", parts: 2)
    List.flatten([input(section, example), table(section, example), document(section, example)])
  end

  defp input(section, example) do
    [_all, text] =
      Regex.run(~r/The input,\s+indented\s+and\s+out\s+of\s+order:\n\n```\n(.*?)\n```/s, section)

    expect("SPEC.md 6.3's input", JSON.decode!(text), example["proof"])
  end

  defp table(section, example) do
    [_before, rest] = String.split(section, "| Quantity | Value |\n|---|---|\n", parts: 2)

    found =
      rest
      |> String.split("\n")
      |> Enum.take_while(&String.starts_with?(&1, "|"))
      |> Enum.map(&row/1)

    [
      expect(
        "SPEC.md 6.3's rows",
        found |> Enum.map(&elem(&1, 0)) |> Enum.sort(),
        rows() |> Enum.map(&elem(&1, 1)) |> Enum.sort()
      ),
      for({member, value, octets} <- found, do: compare(member, value, octets, example))
    ]
  end

  defp row(line) do
    [label, value] = line |> String.trim("|") |> String.split(" | ") |> Enum.map(&String.trim/1)

    case Enum.find_value(rows(), &match_label(&1, label)) do
      {member, octets} -> {member, unquote_value(member, value), octets}
      nil -> {"an unknown row: " <> label, value, []}
    end
  end

  defp match_label({pattern, member}, label) do
    case Regex.run(pattern, label, capture: :all_but_first) do
      nil -> nil
      octets -> {member, octets}
    end
  end

  # sk is written as "32 octets of 0x42"; every other value is in backticks.
  defp unquote_value("sk", value) do
    [count, byte] =
      Regex.run(~r/\A(\d+) octets of 0x([0-9a-f]{2})\z/, value, capture: :all_but_first)

    String.duplicate(byte, String.to_integer(count))
  end

  defp unquote_value(_member, value),
    do: Regex.run(~r/\A`([^`]*)`\z/, value, capture: :all_but_first) |> List.first()

  defp compare(member, value, octets, example) do
    [
      expect("SPEC.md 6.3's #{member}", value, example[member]),
      for(
        count <- octets,
        do:
          expect(
            "SPEC.md 6.3's octet count of #{member}",
            String.to_integer(count),
            byte_size(example[member] || "")
          )
      )
    ]
  end

  defp document(section, example) do
    [_all, count, text] =
      Regex.run(
        ~r/The\s+served\s+document,\s+JCS\(envelope\),\s+(\d+)\s+octets:\n\n```\n(.*?)\n```/s,
        section
      )

    [
      expect("SPEC.md 6.3's served document", text, example["document"]),
      expect(
        "SPEC.md 6.3's octet count of the served document",
        String.to_integer(count),
        byte_size(example["document"])
      )
    ]
  end
end

alias Generator.{KnownAnswers, Rederive, Spec, Vectors, WorkedExample}

mode =
  case System.argv() do
    [] ->
      :write

    ["--check"] ->
      :check

    _other ->
      IO.puts(:stderr, "usage: elixir generator/generate.exs [--check]")
      System.halt(2)
  end

root = Spec.root()
files = Vectors.files()

failures =
  KnownAnswers.run() ++
    Rederive.run(files) ++
    WorkedExample.run(Spec.spec_md(), files["vectors/worked-example.json"])

if failures != [] do
  Enum.each(failures, &IO.puts(:stderr, "generate: " <> &1))
  IO.puts(:stderr, "generate: #{length(failures)} failed checks, so nothing was written.")
  System.halt(1)
end

case mode do
  :write ->
    for {path, bytes} <- files do
      File.mkdir_p!(Path.dirname(Path.join(root, path)))
      File.write!(Path.join(root, path), bytes)
    end

    IO.puts("Wrote the #{map_size(files)} files under vectors/.")

  :check ->
    on_disk =
      root
      |> Path.join("vectors/**/*")
      |> Path.wildcard(match_dot: true)
      |> Enum.filter(&File.regular?/1)
      |> Enum.map(&Path.relative_to(&1, root))

    # A file that differs or is missing is fixed by writing vectors/ again. A file that
    # cannot be read, or that the generator does not write, is not, so each gets its own
    # message.
    results =
      Enum.map(files, fn {path, bytes} ->
        case File.read(Path.join(root, path)) do
          {:ok, ^bytes} ->
            :ok

          {:ok, _other} ->
            {:stale, "#{path} differs from what the generator writes"}

          {:error, :enoent} ->
            {:stale, "#{path} is missing"}

          {:error, reason} ->
            {:unreadable, "#{path} cannot be read: #{:file.format_error(reason)}"}
        end
      end)

    stale = for {:stale, line} <- results, do: line
    unreadable = for {:unreadable, line} <- results, do: line

    stray =
      for path <- on_disk -- Map.keys(files), do: "#{path} is not a file the generator writes"

    Enum.each(stale ++ unreadable ++ stray, &IO.puts(:stderr, "generate: " <> &1))

    if stale != [] do
      IO.puts(:stderr, "vectors/ is stale: run `task generate` and commit the result.")
    end

    if unreadable != [] do
      IO.puts(
        :stderr,
        "vectors/ holds files that cannot be read: make each one a readable file, " <>
          "then run `task generate`."
      )
    end

    if stray != [] do
      IO.puts(
        :stderr,
        "vectors/ holds files the generator does not write: delete each one, " <>
          "or have the generator write it."
      )
    end

    if stale == [] and unreadable == [] and stray == [] do
      IO.puts(
        "vectors/ holds the #{map_size(files)} files the generator writes, and its checks pass."
      )
    else
      System.halt(1)
    end
end
