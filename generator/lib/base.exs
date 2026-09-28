# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

# The primitives every part of the generator uses: checks, the files under spec/, hex and
# base64url, JCS, the byte registry, Ed25519 and key ids, the Merkle tree with its own walk,
# and the file form SPEC.md 9 gives the files under spec/ (every file under vectors/ takes it
# too, except the proofs, which are in the served form of SPEC.md 3.1). Check 1 of generate.exs holds each to known answers.

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

  The files under spec/ are the one place the generator reads with OTP's JSON, which hands
  every number to the C library's strtod, and macOS 27's strtod aborts the whole VM on some
  long literals. Those files hold short numbers only, and json!/2 refuses a text with a number
  of more than 30 significant digits before OTP's JSON sees it. Every file the generator
  writes is read by its own reader instead (Generator.Parse).
  """

  import Generator.Check

  # The most significant digits a number read by OTP's JSON may have: the digits of its
  # mantissa, the zeros that lead it aside.
  @max_digits 30

  @doc "The root of the repository, two levels above this file in generator/lib/."
  def root, do: Path.expand("../..", __DIR__)

  @doc "The text of SPEC.md."
  def spec_md, do: root() |> Path.join("SPEC.md") |> File.read!()

  @doc "The value of the file `name` under spec/, read once per run."
  def read(name) do
    case Process.get({__MODULE__, name}) do
      nil ->
        value = root() |> Path.join("spec/" <> name) |> File.read!() |> json!("spec/" <> name)
        Process.put({__MODULE__, name}, value)
        value

      value ->
        value
    end
  end

  @doc """
  The value of `bytes`, a file under spec/ named by `where`, read by OTP's JSON, once no
  number in it has more than 30 significant digits.
  """
  def json!(bytes, where) do
    case long_numbers(bytes) do
      [] ->
        JSON.decode!(bytes)

      [digits | _more] ->
        raise ArgumentError,
              "#{where} holds a number of #{digits} digits, more than the #{@max_digits} " <>
                "OTP's JSON may read here: its strtod aborts on some long numbers on macOS 27"
    end
  end

  @doc """
  The count of significant digits of each number outside a string in `bytes` that has more
  than 30, in order: the digits of its mantissa, the zeros that lead it aside.
  """
  def long_numbers(bytes), do: scan(bytes, [])

  defp scan(<<>>, found), do: Enum.reverse(found)
  defp scan(<<?", rest::binary>>, found), do: rest |> skip_string() |> scan(found)

  defp scan(<<c, _rest::binary>> = text, found) when c == ?- or c in ?0..?9 do
    {token, rest} = token(text, [])
    [mantissa | _exponent] = String.split(token, ["e", "E"])
    count = mantissa |> String.replace(~r/[^0-9]/, "") |> String.trim_leading("0") |> byte_size()
    scan(rest, if(count > @max_digits, do: [count | found], else: found))
  end

  defp scan(<<_c, rest::binary>>, found), do: scan(rest, found)

  defp skip_string(<<?\\, _escaped, rest::binary>>), do: skip_string(rest)
  defp skip_string(<<?", rest::binary>>), do: rest
  defp skip_string(<<_c, rest::binary>>), do: skip_string(rest)
  defp skip_string(<<>>), do: <<>>

  defp token(<<c, rest::binary>>, acc) when c in ~c"+-.0123456789eE", do: token(rest, [c | acc])
  defp token(rest, acc), do: {acc |> Enum.reverse() |> List.to_string(), rest}

  @doc """
  The failures of the check of the files OTP's JSON reads: no file under spec/ holds a number
  of more than 30 significant digits, and the scan finds each such number and passes a number
  of 30, a string of digits, and a number whose many digits are zeros that lead it.
  """
  def number_check do
    {files, _others} = Generator.Files.entries(root(), "spec")

    [
      for path <- files,
          digits = long_numbers(File.read!(Path.join(root(), path))),
          digits != [] do
        "#{path} holds numbers of #{inspect(digits)} digits, more than #{@max_digits}"
      end,
      expect(
        "the scan for long numbers",
        long_numbers(
          ~s({"a": [1234567890123456789012345678901, 123456789012345678901234567890e5], ) <>
            ~s("b\\"": "1234567890123456789012345678901", "c": -0.0000000000000000000000000000001, ) <>
            ~s("d": -1.234567890123456789012345678901e-7})
        ),
        [31, 31]
      )
    ]
    |> List.flatten()
  end

  @doc "Whether `value` is a string of the pattern class `class` (SPEC.md 2.4)."
  def class?(class, value) do
    %{"pattern" => pattern} = Map.fetch!(read("encodings.json"), class)
    is_binary(value) and value =~ Regex.compile!("\\A(?:" <> pattern <> ")\\z")
  end
end

defmodule Generator.Files do
  @moduledoc """
  The entries under a directory of the repository, listed with File.lstat so that no link is
  followed: its regular files, and every other entry that is not a directory, such as a
  symbolic link, which --check and the manifest refuse.
  """

  @doc """
  `{files, others}` under the directory `dir` of `root`: the regular files, and the other
  entries that are not directories, as `{path, type}`. Paths are relative to `root`, sorted.
  """
  def entries(root, dir) do
    {files, others} = root |> walk(dir) |> Enum.split_with(&match?({_path, :regular}, &1))
    {files |> Enum.map(&elem(&1, 0)) |> Enum.sort(), Enum.sort(others)}
  end

  defp walk(root, path) do
    case File.lstat(Path.join(root, path)) do
      {:ok, %File.Stat{type: :directory}} ->
        root |> Path.join(path) |> File.ls!() |> Enum.flat_map(&walk(root, Path.join(path, &1)))

      {:ok, %File.Stat{type: type}} ->
        [{path, type}]

      {:error, :enoent} ->
        []
    end
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
  The form SPEC.md 9 gives the files under spec/, which every file under vectors/ takes
  except the proofs (those are in the served form of SPEC.md 3.1): ASCII, members in JCS
  order, two-space indentation, LF line ends and a final newline. A member is its name, a
  colon, one space and its value; an object or array that is not empty puts each member or
  element on a line of its own, one level deeper, and closes on a line of its own at the
  indentation of the line that opens it; an empty one is `{}` or `[]`; and every name and
  scalar is as JCS writes it, which escapes no character above U+007E, so a value that holds
  one is refused.
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

defmodule Generator.Seeds do
  @moduledoc """
  The seeds of the keys the generator uses, each 32 octets, all of them published (SPEC.md 9):
  VECTOR_KEY's, which signs every sound proof and every other proof unless its case says
  otherwise; those of the two keys that sign only blocks and handovers of the first modeled
  chain, its genesis key G and the key H an emergency rotation introduces; and the other key's,
  which signs only the proofs of the cases that call for a key other than VECTOR_KEY. The
  mixed-order cases sign under a fifth key, the other key plus a point of order 8, built from
  it by point arithmetic (Generator.Cases.Front). spec/keys.nonproduction.json lists each key
  as a test key, and the seed check fails on a key the generator derives from a seed, or
  builds from a seed's key, that that file does not list.
  """

  alias Generator.Keys

  @vector :binary.copy(<<0x42>>, 32)
  @genesis :binary.copy(<<0x41>>, 32)
  @emergency :binary.copy(<<0x43>>, 32)
  @other :binary.copy(<<0x44>>, 32)

  @doc "The seed of VECTOR_KEY, 32 octets of 0x42."
  def vector, do: @vector

  @doc "The seed of G, 32 octets of 0x41."
  def genesis, do: @genesis

  @doc "The seed of H, 32 octets of 0x43."
  def emergency, do: @emergency

  @doc "The seed of the other key, 32 octets of 0x44."
  def other, do: @other

  @doc "The seed whose public key is the 32 octets `public`, or nil."
  def of(public),
    do: Enum.find([@vector, @genesis, @emergency, @other], &(Keys.public_key(&1) == public))
end

defmodule Generator.Keys do
  @moduledoc """
  Ed25519 keys and signatures (RFC 8032, pure), and the key id of SPEC.md 3.3. Each seed a key
  is derived from, or a signature made with, and each key built from a seed's key by point
  arithmetic, is noted for the run, so that the seed check can hold it to
  spec/keys.nonproduction.json.
  """

  alias Generator.{Bytes, Registry}

  @doc "The public key of a 32-byte seed."
  def public_key(seed) do
    note(seed)
    {public, _secret} = :crypto.generate_key(:eddsa, :ed25519, seed)
    public
  end

  @doc "The signature of `message` under the key of `seed`."
  def sign(seed, message) do
    note(seed)
    :crypto.sign(:eddsa, :none, message, [seed, :ed25519])
  end

  @doc "Every seed this run has derived a key from or signed with."
  def seeds_used, do: Process.get({__MODULE__, :seeds}, MapSet.new())

  defp note(seed), do: Process.put({__MODULE__, :seeds}, MapSet.put(seeds_used(), seed))

  @doc """
  Notes `public`, a key built from the key of `seed` by point arithmetic rather than derived
  from a seed, such as that key plus a point of small order, under which anyone holding the
  seed can sign; gives `public`. The seed check holds it to spec/keys.nonproduction.json as it
  does a derived key.
  """
  def built(public, seed) do
    note(seed)
    Process.put({__MODULE__, :built}, Map.put(keys_built(), public, seed))
    public
  end

  @doc "Every key this run has built from a seed's key, with that seed (built/2)."
  def keys_built, do: Process.get({__MODULE__, :built}, %{})

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
