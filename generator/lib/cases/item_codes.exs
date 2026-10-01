# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Generator.Cases.ItemCodes do
  @moduledoc """
  `vectors/item-codes.json`, the known answers for the item code of SPEC.md 3.9, and their
  checks. They are not cases: no proof carries an item code, no row of cases.json holds one,
  and a claim of conformance does not depend on them (SPEC.md 13.1). So this module is not a
  class of Generator.Cases.Class, and cases.json is the same with it or without it.

  The file is in the canonical form, an object with three members:

  - `derive`: `{about, item_code, item_hash}`, and `proof` too for a row whose `item_hash`
    is the recomputed `item_hash` of a sound item proof under positive/, the path of that
    proof. The rows are every sound item proof's; the hashes of 32 zero bytes and of 32
    bytes of 0xff; the SHA-256 of the ASCII texts `illustrative item_hash 1` and
    `illustrative item_hash 3`; and three hashes whose leftmost 75 bits are the values 0 to
    14, 15 to 29 and 17 to 31, then zero bits, so that the codes use every symbol.
  - `accepted`: `{about, input, item_code}`, a value that a reader taking every permission
    of section 3.9 reads, and the code it reads it as.
  - `refused`: `{about, input}`, a value every reader refuses.

  `input` is the value's bytes in hex, since the canonical form is ASCII and some values hold
  a control character, a character above U+007E or bytes that are not UTF-8; a row whose
  bytes are not UTF-8 says so in its `about`. Every accepted value is at most 19 characters,
  counted in code points, and one is exactly 19, the longest form section 3.9 lets a reader
  read: four groups of four with one separator at each of the three places between them.

  The accepted rows hold the bare code; lowercase and mixed case; one hyphen, underscore or
  space at every place between the groups; separators at only some of those places, and
  different separators at different places; and `O`, `I` and `L` read as `0`, `1` and `1`,
  in both cases. The refused rows hold, among others: the code without the check's final m,
  what a derivation that leaves it out gives for the handoff's first hash; a separator
  before the first symbol, after the last, inside a group, and two together between groups;
  a tab, a line feed and a carriage return, which section 3.9 does not let a reader ignore;
  a `U` in place of each of the 32 symbols, each in a derive row's code; stray whitespace (a
  vertical tab, a form feed, U+3000, U+2009, U+0085, a tab, a line feed) before the first
  symbol and after the last, since common trim functions remove it; the Unicode dashes
  U+2010 to U+2015 and U+2212 and the no-break spaces U+00A0 and U+202F between the groups;
  a value of 20 characters that would read with one character fewer; and values that are not
  UTF-8.

  The check reads the file back from the bytes about to be written: each group is present and
  not empty; every derive row's code is its hash's, and a row that names a proof has that
  proof's recomputed `item_hash`; every sound item proof has a row, and the rows' codes use
  every symbol; the four known answers of the item-id handoff, kept here by hand, are rows;
  every accepted value reads as its code, a code of a derive row, and every refused value is
  refused; the rows named below by hand are in their groups; for every value v from 0 to
  31, reading `U` as v's symbol makes some refused value a code, so a reader that reads `U`
  as any symbol, or any unknown character as 0, fails a row; and at every derive row's code,
  each single wrong symbol and each exchange of two different symbols, at any distance, is
  refused.
  """

  import Bitwise
  import Generator.Check

  alias Generator.{Bytes, FileForm, ItemCode, Parse, Registry}

  @path "vectors/item-codes.json"
  @canonical ~r/\A[0-9A-HJKMNP-TV-Z]{16}\z/
  @code "9WBPKNV7SCP87VZW"

  # Whitespace a common trim function removes, which section 3.9 does not let a reader
  # ignore, each with its name, placed before the first symbol and after the last.
  @stray [
    {"a vertical tab (U+000B)", "\v"},
    {"a form feed (U+000C)", "\f"},
    {"an ideographic space (U+3000)", "\u3000"},
    {"a thin space (U+2009)", "\u2009"},
    {"a next line (U+0085)", "\u0085"},
    {"a tab (U+0009)", "\t"},
    {"a line feed (U+000A)", "\n"}
  ]

  # The Unicode dashes and no-break spaces, each placed between the groups of four.
  @unicode_separators [
    {"a hyphen (U+2010)", "\u2010"},
    {"a non-breaking hyphen (U+2011)", "\u2011"},
    {"a figure dash (U+2012)", "\u2012"},
    {"an en dash (U+2013)", "\u2013"},
    {"an em dash (U+2014)", "\u2014"},
    {"a horizontal bar (U+2015)", "\u2015"},
    {"a minus sign (U+2212)", "\u2212"},
    {"a no-break space (U+00A0)", "\u00A0"},
    {"a narrow no-break space (U+202F)", "\u202F"}
  ]

  # Values the file holds, named here by hand so that dropping a row fails the check.
  @required_accepted [
    "9WBPKNV7SCP87VZW",
    "9wbpknv7scp87vzw",
    "9wBpKnV7sCp87vZw",
    "9WBP-KNV7-SCP8-7VZW",
    "9WBP_KNV7_SCP8_7VZW",
    "9WBP KNV7 SCP8 7VZW",
    "9WBP-KNV7SCP87VZW",
    "9WBPKNV7 SCP8_7VZW",
    "9WBP-KNV7_SCP8 7VZW",
    "JZ2ZSDZSZM5VDO73",
    "jz2zsdzszm5vdo73",
    "OI23456789ABCDE4",
    "OL23456789ABCDE4",
    "oi23456789abcde4",
    "ol23456789abcde4"
  ]

  # What the handoff says a derivation without the final m gives for its first hash.
  @without_final_m "9WBPKNV7SCP87VZE"

  @required_refused [
                      "9WBUKNV7SCP87VZW",
                      "9WBPKNV7SCP87VZX",
                      @without_final_m,
                      "9WBPKNV7SCP8V7ZW",
                      "9WBPKNV7SCP87VWZ",
                      "9WBPKNV7SCP87VZ",
                      "9WBPKNV7SCP87VZW0",
                      " 9WBPKNV7SCP87VZW",
                      "-9WBP-KNV7-SCP8-7VZW",
                      "_9WBPKNV7SCP87VZW",
                      "9WBPKNV7SCP87VZW ",
                      "9WBP-KNV7-SCP8-7VZW-",
                      "9WBPKNV7SCP87VZW_",
                      "9WB-PKNV7SCP87VZW",
                      "9WBP KNV7 SC P8 7VZW",
                      "9WBPKNV7--SCP87VZW",
                      "9WBP- KNV7SCP87VZW",
                      "9WBP-KNV7-SCP8--7VZW",
                      "9WBPKNV7SCP87VZW\n",
                      "9WBPKNV7SCP87VZW\r\n",
                      "9WBPKNV7\nSCP87VZW",
                      "9WBPKNV7\rSCP87VZW",
                      "9WBP\tKNV7SCP87VZW",
                      "9WBP\tKNV7\tSCP8\t7VZW",
                      "0\u013123456789ABCDE4",
                      "9WBPKNV7\u017FCP87VZW",
                      "9WBPKNV7SCP87VZW\xFF",
                      "9WBPKNV7SCP87VZW\xC0\x80",
                      "",
                      " - _ "
                    ] ++
                      Enum.flat_map(@stray, fn {_name, c} ->
                        [c <> "9WBPKNV7SCP87VZW", "9WBPKNV7SCP87VZW" <> c]
                      end) ++
                      Enum.map(@unicode_separators, fn {_name, c} ->
                        Enum.join(["9WBP", "KNV7", "SCP8", "7VZW"], c)
                      end)

  # The four known answers of the item-id handoff's section 2.1, each hash in hex and its
  # code, kept by hand and never computed here.
  @handoff [
    {"4f1769d767cb2c83eff1c48165939090d42fac433c5eabe6f02c5cf9d025181b", "9WBPKNV7SCP87VZW"},
    {"97c5fcb7f9fd0bb680eb7b302f6826a16a2e21c32695ff82ed827b6748c86b95", "JZ2ZSDZSZM5VD073"},
    {String.duplicate("0", 64), "0000000000000000"},
    {String.duplicate("f", 64), "ZZZZZZZZZZZZZZZN"}
  ]

  @doc "The file, by its path, for `files` built so far, the sound proofs among them."
  def files(files), do: %{@path => FileForm.encode(value(files))}

  defp value(files),
    do: %{"accepted" => accepted(), "derive" => derive(files), "refused" => refused(files)}

  # Derive.

  defp derive(files) do
    positive =
      for {"vectors/positive/" <> name, bytes} <- Enum.sort(files),
          String.ends_with?(name, ".proof.json"),
          %{"proof" => %{"type" => "item"} = proof} <- [Parse.decode!(bytes)] do
        hash = recomputed(proof)

        %{
          "about" => "the recomputed item_hash of positive/#{name}",
          "item_code" => ItemCode.derive(hash),
          "item_hash" => Bytes.hex(hash),
          "proof" => "positive/#{name}"
        }
      end

    others =
      [
        {"the SHA-256 of the ASCII text `illustrative item_hash 1`",
         :crypto.hash(:sha256, "illustrative item_hash 1")},
        {"the SHA-256 of the ASCII text `illustrative item_hash 3`",
         :crypto.hash(:sha256, "illustrative item_hash 3")},
        {"32 zero bytes", <<0::256>>},
        {"32 bytes of 0xff", :binary.copy(<<0xFF>>, 32)},
        {"a hash whose leftmost 75 bits are the values 0 to 14, then zero bits", leftmost(0..14)},
        {"a hash whose leftmost 75 bits are the values 15 to 29, then zero bits",
         leftmost(15..29)},
        {"a hash whose leftmost 75 bits are the values 17 to 31, then zero bits",
         leftmost(17..31)}
      ]

    positive ++
      for {about, hash} <- others do
        %{"about" => about, "item_code" => ItemCode.derive(hash), "item_hash" => Bytes.hex(hash)}
      end
  end

  # SPEC.md 3.6: item_hash = H(0x11, record), from the record, never the carried value.
  defp recomputed(%{"subject" => %{"record" => record}}),
    do: Registry.record_hash("item_hash", record)

  # 32 bytes whose leftmost 75 bits are the 15 values of `range`, 5 bits each.
  defp leftmost(range) do
    n = Enum.reduce(range, 0, fn v, acc -> acc <<< 5 ||| v end)
    <<n::75, 0::181>>
  end

  # Parse.

  defp accepted do
    code = @code
    o_code = "JZ2ZSDZSZM5VD073"
    one_code = "0123456789ABCDE4"

    rows = [
      {"the code itself", code, code},
      {"lowercase", "9wbpknv7scp87vzw", code},
      {"mixed case", "9wBpKnV7sCp87vZw", code},
      {"a hyphen between every two groups of four, 19 characters", "9WBP-KNV7-SCP8-7VZW", code},
      {"an underscore between every two groups of four", "9WBP_KNV7_SCP8_7VZW", code},
      {"a space between every two groups of four", "9WBP KNV7 SCP8 7VZW", code},
      {"lowercase, with a space between every two groups", "9wbp knv7 scp8 7vzw", code},
      {"lowercase, with a hyphen between every two groups", "9wbp-knv7-scp8-7vzw", code},
      {"mixed case, with an underscore between every two groups", "9wBp_KnV7_sCp8_7vZw", code},
      {"a hyphen between the first two groups only", "9WBP-KNV7SCP87VZW", code},
      {"an underscore between the middle two groups only", "9WBPKNV7_SCP87VZW", code},
      {"a space between the last two groups only", "9WBPKNV7SCP8 7VZW", code},
      {"a space and an underscore between the last three groups", "9WBPKNV7 SCP8_7VZW", code},
      {"a hyphen, an underscore and a space between the groups", "9WBP-KNV7_SCP8 7VZW", code},
      {"a space, a hyphen and an underscore between the groups", "9WBP KNV7-SCP8_7VZW", code},
      {"O for 0", "JZ2ZSDZSZM5VDO73", o_code},
      {"lowercase, with o for 0", "jz2zsdzszm5vdo73", o_code},
      {"O for 0, with a hyphen between every two groups", "JZ2Z-SDZS-ZM5V-DO73", o_code},
      {"O for 0 and I for 1", "OI23456789ABCDE4", one_code},
      {"O for 0 and L for 1", "OL23456789ABCDE4", one_code},
      {"lowercase, with o for 0 and i for 1", "oi23456789abcde4", one_code},
      {"lowercase, with o for 0 and l for 1", "ol23456789abcde4", one_code},
      {"mixed case, with o for 0 and I for 1", "oI23456789aBcDe4", one_code},
      {"mixed case, with O for 0 and l for 1", "Ol23456789AbCdE4", one_code},
      {"lowercase, with o for 0, i for 1 and a space between every two groups",
       "oi23 4567 89ab cde4", one_code}
    ]

    for {about, input, item_code} <- rows,
        do: %{"about" => about, "input" => Bytes.hex(input), "item_code" => item_code}
  end

  defp refused(files) do
    %{"proof" => %{"subject" => %{"record" => record} = subject}} =
      Parse.decode!(Map.fetch!(files, "vectors/positive/item.proof.json"))

    id = record["id"]
    code = @code

    rows =
      [
        {"a U, which is not in the alphabet", "9WBUKNV7SCP87VZW"},
        {"a lowercase u", "9wbuknv7scp87vzw"},
        {"one wrong symbol, the check symbol", "9WBPKNV7SCP87VZX"},
        {"the code without the check's final m: what a derivation that leaves out the final m " <>
           "gives for the item_hash whose code is 9WBPKNV7SCP87VZW", @without_final_m},
        {"one wrong symbol, the first", "8WBPKNV7SCP87VZW"},
        {"two neighbours exchanged", "9WBPKNV7SCP8V7ZW"},
        {"two neighbours exchanged across the boundary of two groups of four",
         "9WBPKNV7SCP78VZW"},
        {"the last data symbol exchanged with the check symbol", "9WBPKNV7SCP87VWZ"},
        {"15 symbols, the code without its check symbol", "9WBPKNV7SCP87VZ"},
        {"17 symbols, the code and one more", "9WBPKNV7SCP87VZW0"},
        {"15 letters and a space", "blockchain proof"},
        {"17 letters and a space", "notarized contract"},
        {"periods between the groups of four", "9WBP.KNV7.SCP8.7VZW"},
        {"slashes between the groups of four", "9WBP/KNV7/SCP8/7VZW"},
        {"a space before the first symbol", " " <> code},
        {"a hyphen before the first symbol, with a hyphen between every two groups",
         "-9WBP-KNV7-SCP8-7VZW"},
        {"an underscore before the first symbol", "_" <> code},
        {"a space after the last symbol", code <> " "},
        {"a hyphen after the last symbol, with a hyphen between every two groups",
         "9WBP-KNV7-SCP8-7VZW-"},
        {"an underscore after the last symbol", code <> "_"},
        {"a hyphen inside the first group", "9WB-PKNV7SCP87VZW"},
        {"a space inside the third group, with a space between every two groups",
         "9WBP KNV7 SC P8 7VZW"},
        {"two hyphens together between the middle two groups", "9WBPKNV7--SCP87VZW"},
        {"a hyphen and a space together between the first two groups", "9WBP- KNV7SCP87VZW"},
        {"separators alone, one between every two empty groups", "---"},
        {"20 characters, a hyphen between every two groups and one more before the last group",
         "9WBP-KNV7-SCP8--7VZW"},
        {"a trailing carriage return and line feed", code <> "\r\n"},
        {"a line feed between the middle two groups", "9WBPKNV7\nSCP87VZW"},
        {"a carriage return between the middle two groups", "9WBPKNV7\rSCP87VZW"},
        {"a tab between the first two groups", "9WBP\tKNV7SCP87VZW"},
        {"a tab between every two groups", "9WBP\tKNV7\tSCP8\t7VZW"},
        {"a vertical tab (U+000B) between the middle two groups", "9WBPKNV7\vSCP87VZW"},
        {"a form feed (U+000C) between the middle two groups", "9WBPKNV7\fSCP87VZW"},
        {"a thin space (U+2009) between the middle two groups", "9WBPKNV7\u2009SCP87VZW"},
        {"an ideographic space (U+3000) between the middle two groups", "9WBPKNV7\u3000SCP87VZW"},
        {"a dotless i (U+0131), whose Unicode uppercase is I, for 1", "0\u013123456789ABCDE4"},
        {"a long s (U+017F), whose Unicode uppercase is S", "9WBPKNV7\u017FCP87VZW"},
        {"the code, then the byte 0xFF, so the value is not UTF-8", code <> <<0xFF>>},
        {"the code, then the bytes 0xC0 0x80, an overlong NUL, so the value is not UTF-8",
         code <> <<0xC0, 0x80>>},
        {"a UUID, the id of positive/item.proof.json", id},
        {"26 symbols, the 128 bits of that id in the alphabet, two zero bits first",
         in_alphabet_128(id)},
        {"an item_hash, the one of positive/item.proof.json", subject["item_hash"]},
        {"the empty value", ""},
        {"separators alone", " - _ "}
      ] ++ stray_rows(code) ++ unicode_separator_rows() ++ u_rows()

    for {about, input} <- rows, do: %{"about" => about, "input" => Bytes.hex(input)}
  end

  defp stray_rows(code) do
    Enum.flat_map(@stray, fn {name, c} ->
      [
        {"#{name} before the first symbol", c <> code},
        {"#{name} after the last symbol", code <> c}
      ]
    end)
  end

  defp unicode_separator_rows do
    for {name, c} <- @unicode_separators,
        do: {"#{name} between the groups of four", Enum.join(["9WBP", "KNV7", "SCP8", "7VZW"], c)}
  end

  # A U in place of each symbol of the alphabet, in the code of the derive row whose leftmost
  # 75 bits hold that symbol's value: 0 to 14, 15 to 29, or 17 to 31 for 30 and 31.
  defp u_rows do
    alphabet = ItemCode.alphabet()

    for v <- 0..31 do
      first = first_of(v)
      code = ItemCode.derive(leftmost(first..(first + 14)))
      symbol = binary_part(alphabet, v, 1)
      i = v - first
      ^symbol = binary_part(code, i, 1)
      u = binary_part(code, 0, i) <> "U" <> binary_part(code, i + 1, 15 - i)
      {"a U in place of the symbol #{symbol} of #{code}", u}
    end
  end

  # The first value of the derive row whose code holds value v: 0 to 14, 15 to 29, 17 to 31.
  defp first_of(v) when v < 15, do: 0
  defp first_of(v) when v < 30, do: 15
  defp first_of(_v), do: 17

  # The 128 bits of a UUID's 32 hex digits as 26 symbols of the alphabet, two zero bits first.
  defp in_alphabet_128(uuid) do
    <<n::128>> = uuid |> String.replace("-", "") |> Bytes.unhex()
    alphabet = ItemCode.alphabet()
    for shift <- 125..0//-5, into: "", do: binary_part(alphabet, n >>> shift &&& 31, 1)
  end

  # The checks.

  @doc "The failures of the item-code checks, over `files`, every file about to be written."
  def check(files) do
    file = Parse.decode!(Map.fetch!(files, @path))
    groups = ~w(accepted derive refused)

    case file do
      %{
        "accepted" => [_ | _] = accepted,
        "derive" => [_ | _] = derive,
        "refused" => [_ | _] = refused
      }
      when map_size(file) == 3 ->
        List.flatten([
          expect("item-codes.json's members", Enum.sort(Map.keys(file)), groups),
          check_derive(derive, files),
          check_handoff(derive),
          check_accepted(accepted, derive),
          check_refused(refused),
          check_limit(refused),
          check_required(accepted, refused),
          check_u(refused),
          for(%{"item_code" => code} <- derive, do: check_guarantees(code))
        ])

      _other ->
        ["item-codes.json: the members #{inspect(groups)}, each a non-empty array"]
    end
  end

  defp check_derive(rows, files) do
    items =
      for {"vectors/positive/" <> name, bytes} <- files,
          String.ends_with?(name, ".proof.json"),
          %{"proof" => %{"type" => "item"}} <- [Parse.decode!(bytes)],
          do: "positive/" <> name

    [
      expect(
        "item-codes.json: a derive row for each sound item proof",
        rows |> Enum.map(& &1["proof"]) |> Enum.reject(&is_nil/1) |> Enum.sort(),
        Enum.sort(items)
      ),
      truth(
        "item-codes.json: no two derive rows share a hash",
        rows |> Enum.map(& &1["item_hash"]) |> Enum.uniq() |> length() == length(rows)
      ),
      expect(
        "item-codes.json: the derive rows' codes use every symbol of the alphabet",
        rows |> Enum.flat_map(&String.graphemes(&1["item_code"])) |> Enum.uniq() |> Enum.sort(),
        ItemCode.alphabet() |> String.graphemes() |> Enum.sort()
      ),
      for row <- rows do
        %{"item_code" => code, "item_hash" => hex} = row
        label = "item-codes.json derive #{hex}"

        members =
          if Map.has_key?(row, "proof"),
            do: ~w(about item_code item_hash proof),
            else: ~w(about item_code item_hash)

        [
          expect("#{label}: its members", Enum.sort(Map.keys(row)), members),
          truth("#{label}: a HEX64", hex =~ ~r/\A[0-9a-f]{64}\z/),
          expect("#{label}: its code", ItemCode.derive(Bytes.unhex(hex)), code),
          truth("#{label}: its code in its one spelling", code =~ @canonical),
          proof_hash(label, row, files)
        ]
      end
    ]
  end

  defp proof_hash(_label, row, _files) when not is_map_key(row, "proof"), do: []

  defp proof_hash(label, %{"item_hash" => hex, "proof" => path}, files) do
    %{"proof" => proof} = Parse.decode!(Map.fetch!(files, "vectors/" <> path))
    expect("#{label}: the recomputed item_hash of #{path}", Bytes.hex(recomputed(proof)), hex)
  end

  defp check_handoff(rows) do
    by_hash = Map.new(rows, &{&1["item_hash"], &1["item_code"]})
    {first, _code} = hd(@handoff)
    <<n::75, _rest::181>> = Bytes.unhex(first)
    values = for shift <- 70..0//-5, do: n >>> shift &&& 31
    loop_only = values ++ [ItemCode.loop(values)]

    [
      expect(
        "item-codes.json: a derivation without the final m, for the handoff's first hash",
        for(v <- loop_only, into: "", do: binary_part(ItemCode.alphabet(), v, 1)),
        @without_final_m
      )
      | for(
          {hash, code} <- @handoff,
          do: expect("item-codes.json: the handoff's known answer #{hash}", by_hash[hash], code)
        )
    ]
  end

  defp check_accepted(rows, derive) do
    codes = MapSet.new(derive, & &1["item_code"])
    inputs = Enum.map(rows, &Bytes.unhex(&1["input"]))

    [
      truth("item-codes.json: no two accepted values are the same", Enum.uniq(inputs) == inputs),
      expect(
        "item-codes.json: the longest accepted value, in code points",
        inputs |> Enum.map(&code_points/1) |> Enum.max(),
        ItemCode.limit()
      ),
      for row <- rows do
        %{"about" => about, "input" => hex, "item_code" => code} = row
        input = Bytes.unhex(hex)
        label = "item-codes.json accepted #{inspect(input)}"

        [
          expect("#{label}: its members", Enum.sort(Map.keys(row)), ~w(about input item_code)),
          expect("#{label}: read as its code", ItemCode.parse(input), {:ok, code}),
          truth("#{label}: a code of a derive row", MapSet.member?(codes, code)),
          truth(
            "#{label}: at most #{ItemCode.limit()} characters",
            code_points(input) <= ItemCode.limit()
          ),
          utf8_said(label, input, about)
        ]
      end
    ]
  end

  defp check_refused(rows) do
    inputs = Enum.map(rows, &Bytes.unhex(&1["input"]))

    [
      truth("item-codes.json: no two refused values are the same", Enum.uniq(inputs) == inputs),
      for row <- rows do
        %{"about" => about} = row
        input = Bytes.unhex(row["input"])
        label = "item-codes.json refused #{inspect(input)}"

        [
          expect("#{label}: its members", Enum.sort(Map.keys(row)), ~w(about input)),
          expect("#{label}: refused", ItemCode.parse(input), :error),
          utf8_said(label, input, about)
        ]
      end
    ]
  end

  # A value that is not UTF-8 says so in its about, as SPEC.md 13.2 has it.
  defp utf8_said(label, input, about) do
    truth(
      "#{label}: UTF-8, or its about says it is not",
      String.valid?(input) != String.contains?(about, "not UTF-8")
    )
  end

  # Some refused value is one character over the limit, and reads with one character gone.
  defp check_limit(rows) do
    over =
      for %{"input" => hex} <- rows,
          input = Bytes.unhex(hex),
          String.valid?(input),
          code_points(input) == ItemCode.limit() + 1,
          chars = String.to_charlist(input),
          Enum.any?(0..(length(chars) - 1), fn i ->
            match?({:ok, _}, ItemCode.parse(List.to_string(List.delete_at(chars, i))))
          end),
          do: input

    truth(
      "item-codes.json: a refused value of #{ItemCode.limit() + 1} characters reads with one gone",
      over != []
    )
  end

  defp check_required(accepted, refused) do
    present = fn rows -> MapSet.new(rows, &Bytes.unhex(&1["input"])) end
    accepted = present.(accepted)
    refused = present.(refused)

    [
      for(
        input <- @required_accepted,
        do:
          truth("item-codes.json: #{inspect(input)} is accepted", MapSet.member?(accepted, input))
      ),
      for(
        input <- @required_refused,
        do: truth("item-codes.json: #{inspect(input)} is refused", MapSet.member?(refused, input))
      )
    ]
  end

  # For every value v, reading U as v's symbol makes some refused value a code, so no reader
  # that silently reads U as a symbol, or reads any unknown character as 0, passes the rows.
  defp check_u(rows) do
    inputs = Enum.map(rows, &Bytes.unhex(&1["input"]))
    alphabet = ItemCode.alphabet()

    for v <- 0..31 do
      symbol = binary_part(alphabet, v, 1)

      truth(
        "item-codes.json: reading U as #{symbol} makes some refused value a code",
        Enum.any?(inputs, &match?({:ok, _}, ItemCode.parse(String.replace(&1, "U", symbol))))
      )
    end
  end

  defp code_points(input), do: input |> String.to_charlist() |> length()

  # SPEC.md 3.9: the check catches every single wrong symbol and every exchange of two
  # different symbols, at any distance.
  defp check_guarantees(code) do
    symbols = String.graphemes(code)
    alphabet = String.graphemes(ItemCode.alphabet())

    substitutions =
      for i <- 0..15,
          other <- alphabet,
          other != Enum.at(symbols, i),
          do: symbols |> List.replace_at(i, other) |> Enum.join()

    exchanges =
      for i <- 0..14,
          j <- (i + 1)..15,
          Enum.at(symbols, i) != Enum.at(symbols, j),
          do:
            symbols
            |> List.replace_at(i, Enum.at(symbols, j))
            |> List.replace_at(j, Enum.at(symbols, i))
            |> Enum.join()

    missed = Enum.reject(substitutions ++ exchanges, &(ItemCode.parse(&1) == :error))

    expect(
      "item-codes.json: every single wrong symbol and exchange at #{code} refused",
      missed,
      []
    )
  end
end
