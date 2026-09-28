# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Generator.Corpus do
  @moduledoc """
  The known answers under vectors/corpus/ (SPEC.md 13.2) for JCS, strict Ed25519 and
  base64url, and their checks. The real Bitcoin bytes under corpus/bitcoin/ are
  Generator.RealBitcoin's, and the replay files under corpus/replay/ Generator.Replay's.

  - `jcs/<name>.input.json` and `jcs/<name>.output.json`: a JSON text whose value is within
    the value profile of SPEC.md 10.1, and the exact bytes of JCS of that value, with no final
    newline. Both files are their bytes, so neither is in the canonical form. Each output is
    kept here by hand, never computed. The `rfc8785-` pairs are RFC 8785's own examples:
    section 3.2.2's input and output, section 3.2.3's names, and appendix B's numbers, each
    spelled in the input with 17 significant digits, less the five rows whose value is an
    integer of magnitude above MAX_INTEGER and below 10^21, which J5 refuses. They are quoted
    from RFC 8785, "JSON Canonicalization Scheme (JCS)", by A. Rundgren, B. Jordan and
    S. Erdtman (June 2020). The others hold the number forms and the UTF-16 order SPEC.md
    depends on, the escapes JCS writes and those it does not, and the input of SPEC.md 6.3,
    whose output is its M.
  - `ed25519.json`, in the canonical form of SPEC.md 9: an array of Verify's cases (SPEC.md
    6.2), each `{about, id, message, public_key, signature, step, verify}`: the 32 octets of
    `message` in hex, the key as a B64U32 and the signature as a B64U64, both canonical, so
    step 1 passes, and `verify` `pass`, or `fail` with `step` the first step that refuses it.
    Every key is one spec/keys.nonproduction.json lists, or one that fails a check of a key's
    bytes or step 4.
  - `base64url.json`, in the canonical form: an array of spellings of the classes B64U32 and
    B64U64 (SPEC.md 2.4), each `{class, octets, text}` for a canonical spelling, or `{class,
    refused, text}` for a spelling the class refuses, where `refused` names its flaw and, when
    a decoder that allows the flaw reads it to the octets of a canonical spelling,
    `canonical` is that spelling.

  The check reads each file back from the bytes about to be written: every JCS input reads
  under J1 to J6, the generator's JCS of its value is its output, byte for byte, and the
  output reads back to the same value; the worked example's output is M of
  worked-example.json. Each Ed25519 case gives its verdict under Generator.Ed25519.verify/3,
  step by step, and the same pass or fail under the model's Verify (Generator.Derive.verify?/3,
  which calls :crypto for steps 4 to 7); a case whose `about` says what a verifier that skips
  steps 2 and 3 gives, as OpenSSL and Go's crypto/ed25519 do (SPEC.md 6.2, common libraries),
  says what OpenSSL itself gives, through :crypto; and a case whose `about` names another lax
  verifier, one that reduces s modulo L, decodes R and compares points, or uses the
  cofactored equation, is accepted by it, modeled here. The case whose R is one bit off
  (`step_7-r_sign_bit_flipped`) has [s]B - [k]A encode to R with its sign bit flipped, so a
  verifier that compares only 31 octets of R, or ignores that bit, accepts it; the case whose
  off-curve key comes with s = L (`step_4-not_on_curve-s_equal_l`) has an s at L or above,
  so the order of steps 4 and 5 decides which one refuses it. Each base64url spelling is on
  its class or off it as it says, a canonical one decodes to its octets and back, and a
  refused one with a `canonical` spelling reads to that spelling's octets once its flaw is
  allowed.
  """

  import Bitwise
  import Generator.Check

  alias Generator.{Bytes, Derive, Ed25519, FileForm, JCS, Keys, KnownAnswers, Parse, Seeds, Spec}

  @alphabet "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
  @max_integer 9_007_199_254_740_991

  @doc "The corpus files but the real Bitcoin bytes, by their paths, for `files` built so far."
  def files(files) do
    example = Parse.decode!(Map.fetch!(files, "vectors/worked-example.json"))

    jcs =
      Enum.flat_map(jcs(), fn {name, input, output} ->
        [
          {"vectors/corpus/jcs/#{name}.input.json", input},
          {"vectors/corpus/jcs/#{name}.output.json", output}
        ]
      end)

    Map.new([
      {"vectors/corpus/ed25519.json", FileForm.encode(ed25519(example))},
      {"vectors/corpus/base64url.json", FileForm.encode(base64url(example))}
      | jcs
    ])
  end

  # JCS.

  # Each pair: its name, the input text and the output, kept by hand.
  defp jcs do
    %{example: {rfc_input, rfc_output}, sorting: {_members, sorting}, numbers: numbers} =
      KnownAnswers.rfc8785()

    # Appendix B's values within the value profile, and each spelled with 17 significant
    # digits, which read back to the same binary64.
    numbers = Enum.reject(numbers, fn {bits, _text} -> j5_gap?(bits) end)

    spelled =
      for {bits, _text} <- numbers do
        <<n::float-64>> = Bytes.unhex(bits)
        :erlang.float_to_binary(n, [{:scientific, 16}])
      end

    [
      {"rfc8785-example", rfc_input, rfc_output},
      {"rfc8785-sorting", sorting_input(), sorting},
      {"rfc8785-numbers", "[\n  " <> Enum.join(spelled, ",\n  ") <> "\n]\n",
       "[" <> Enum.map_join(numbers, ",", &elem(&1, 1)) <> "]"},
      {"worked-example",
       ~s({\n  "version": 1,\n  "type": "block",\n  "format": "truestamp-proof",\n) <>
         ~s(  "environment": "test"\n}\n),
       ~s({"environment":"test","format":"truestamp-proof","type":"block","version":1})},
      {"numbers",
       "[1.0, -0, 4.50, 1E30, 1e21, 1E+21, 1e-6, 1e-7, 37.7749, 5e-324, 1e-400, " <>
         "9007199254740991, -9007199254740991, 0.1, 123.456e3, 100e-2, 0.000001]\n",
       "[1,0,4.5,1e+30,1e+21,1e+21,0.000001,1e-7,37.7749,5e-324,0,9007199254740991," <>
         "-9007199254740991,0.1,123456,1,0.000001]"},
      {"utf16-order",
       ~S({"\uff5a": "fullwidth z", "\ud83d\ude00": "grinning face", "z": "latin z", ) <>
         ~S("\u00e9": "e with acute", "Z": "capital z", "zz": "two z"}),
       ~s({"Z":"capital z","z":"latin z","zz":"two z","\u00E9":"e with acute",) <>
         ~s("\u{1F600}":"grinning face","\uFF5A":"fullwidth z"})},
      {"escapes",
       ~S(["\u0000\u0001\b\t\n\u000B\f\r\u001F", "\u007F\u0080\u2028\u2029", "\"\\\/", ) <>
         ~S("\ud83d\ude00", "\u00E9", ") <> "\u00E9" <> ~S("]),
       ~S(["\u0000\u0001\b\t\n\u000b\f\r\u001f",") <>
         "\u007F\u0080\u2028\u2029" <>
         ~S(","\"\\/",") <> "\u{1F600}" <> ~S(",") <> "\u00E9" <> ~S(",") <> "\u00E9" <> ~S("])},
      {"whitespace",
       "{\r\n\t\"b\" : [ 1 , 2 ,\r\n  3 ] ,\r\n\t\"a\" : { \"d\" : true , \"c\" : null }\r\n}\r\n",
       ~S({"a":{"c":null,"d":true},"b":[1,2,3]})},
      {"empty-and-literals",
       ~S({"values": [null, true, false, 0, -0.0], "string": "", "object": {}, "array": [[], {}]}),
       ~S({"array":[[],{}],"object":{},"string":"","values":[null,true,false,0,0]})}
    ]
  end

  # RFC 8785 section 3.2.3's input, as the RFC writes it.
  defp sorting_input do
    ~S"""
    {
      "\u20ac": "Euro Sign",
      "\r": "Carriage Return",
      "\ufb33": "Hebrew Letter Dalet With Dagesh",
      "1": "One",
      "\ud83d\ude00": "Emoji: Grinning Face",
      "\u0080": "Control",
      "\u00f6": "Latin Small Letter O With Diaeresis"
    }
    """
  end

  # J5 refuses a value that is an integer of magnitude above MAX_INTEGER and below 10^21.
  defp j5_gap?(bits) do
    <<n::float-64>> = Bytes.unhex(bits)
    n == Float.round(n) and abs(n) > @max_integer and abs(n) < 1.0e21
  end

  # Ed25519.

  defp ed25519(example) do
    message = Bytes.unhex(example["proof_hash"])
    zeros = <<0::256>>
    ones = :binary.copy(<<0xFF>>, 32)
    vector = Keys.public_key(Seeds.vector())
    v = Bytes.unb64u(example["V"])
    <<r::binary-32, s::little-256>> = v
    identity = <<1, 0::248, 0::256>>
    {a, _prefix} = Ed25519.expand(Seeds.vector())
    mixed = Ed25519.mixed_order_key()

    List.flatten([
      {"pass-vector_key", vector, message, v, :pass,
       "The worked example of SPEC.md 6.3: VECTOR_KEY over proof_hash."},
      {"pass-seed_41", Keys.public_key(Seeds.genesis()), zeros, Keys.sign(Seeds.genesis(), zeros),
       :pass, "The key of the seed of 32 bytes of 0x41 over 32 zero octets."},
      {"pass-seed_43", Keys.public_key(Seeds.emergency()), ones,
       Keys.sign(Seeds.emergency(), ones), :pass,
       "The key of the seed of 32 bytes of 0x43 over 32 octets of 0xff."},
      {"pass-seed_44", Keys.public_key(Seeds.other()), message, Keys.sign(Seeds.other(), message),
       :pass, "The key of the seed of 32 bytes of 0x44 over the worked example's proof_hash."},
      {"pass-mixed_order-k_multiple_of_8", mixed, message,
       Ed25519.sign_mixed(message, &(rem(&1, 8) == 0)), :pass,
       "The mixed-order test key of SPEC.md 9, the 0x44 key plus a point of order 8, with a " <>
         "challenge k that is a multiple of 8, so the point of order 8 drops out of [k]A."},
      for {id, key, about} <- [
            {"step_2-identity-y_p_plus_1", <<Ed25519.p() + 1::little-256>>,
             "The identity written with y = p + 1, and the signature (identity, 0)."},
            {"step_2-y_p", <<Ed25519.p()::little-256>>,
             "A key written with y = p, a second spelling of y = 0, and the signature " <>
               "(identity, 0)."},
            {"step_2-y_max", <<(1 <<< 255) - 1::little-256>>,
             "A key written with y = 2^255 - 1, a second spelling of y = 18, and the " <>
               "signature (identity, 0)."}
          ] do
        {id, key, message, identity, {:fail, 2},
         about <> " " <> lax_sentence(key, message, identity)}
      end,
      for {%{"hex" => hex, "order" => order}, i} <-
            Enum.with_index(Spec.read("small-order-keys.json")) do
        key = Bytes.unhex(hex)

        {"step_3-small_order-#{i}", key, message, identity, {:fail, 3},
         "The key at index #{i} of spec/small-order-keys.json, of order #{order}, and the " <>
           "signature (identity, 0). " <> lax_sentence(key, message, identity)}
      end,
      {"step_4-not_on_curve", off_curve(), message, identity, {:fail, 4},
       "A key whose y is below p and on no point of the curve: no x satisfies the curve's " <>
         "equation for it."},
      {"step_4-not_on_curve-s_equal_l", off_curve(), message,
       binary_part(identity, 0, 32) <> <<Ed25519.l()::little-256>>, {:fail, 4},
       "The key of step_4-not_on_curve, and the signature (identity, L), whose s " <>
         "step 5 refuses. Step 4 comes first and refuses the key, so the first step " <>
         "that refuses it is 4: a verifier that checks s before the key names step 5."},
      {"step_5-s_equal_l", vector, message, r <> <<Ed25519.l()::little-256>>, {:fail, 5},
       "The worked example's signature with s replaced by L."},
      {"step_5-s_plus_l", vector, message, r <> <<s + Ed25519.l()::little-256>>, {:fail, 5},
       "The worked example's signature with s + L in place of s, a second spelling of it: " <>
         "a verifier that reduces s modulo L accepts it."},
      {"step_7-other_message", vector, zeros, v, {:fail, 7},
       "The worked example's signature, checked over 32 zero octets rather than proof_hash."},
      {"step_7-other_key", vector, message, Keys.sign(Seeds.other(), message), {:fail, 7},
       "A signature by the key of the seed of 32 bytes of 0x44, checked under VECTOR_KEY."},
      {"step_7-r_not_canonical", vector, message,
       Ed25519.sign_as(a, vector, {<<Ed25519.p() + 1::little-256>>, 0}, message), {:fail, 7},
       "R is the identity written with y = p + 1, and s = k a, so [s]B - [k]A is the " <>
         "identity, whose encoding is not R. A verifier that decodes R and compares points " <>
         "accepts it."},
      {"step_7-r_small_order_component", vector, message, small_order_r(a, vector, message),
       {:fail, 7},
       "R is [r]B plus a point of order 8, and s = r + k a, so [s]B - [k]A is [r]B, not R. " <>
         "The cofactored equation accepts it."},
      {"step_7-r_sign_bit_flipped", vector, message, sign_bit_flipped(a, vector, message),
       {:fail, 7},
       "R is the encoding of [r]B with its sign bit, bit 255, flipped, and s = r + k a " <>
         "for that R, so [s]B - [k]A is [r]B, whose encoding differs from R in that one " <>
         "bit. A verifier that compares only the first 31 octets of R, or that ignores " <>
         "its sign bit, accepts it."},
      {"step_7-mixed_order-k_not_multiple_of_8", mixed, message,
       Ed25519.sign_mixed(message, &(rem(&1, 8) != 0)), {:fail, 7},
       "The mixed-order test key with a challenge k that is not a multiple of 8. The " <>
         "cofactored equation accepts it."}
    ])
    |> Enum.map(fn {id, key, m, signature, verdict, about} ->
      Map.merge(
        %{
          "about" => about,
          "id" => id,
          "message" => Bytes.hex(m),
          "public_key" => Bytes.b64u(key),
          "signature" => Bytes.b64u(signature)
        },
        case verdict do
          :pass -> %{"verify" => "pass"}
          {:fail, step} -> %{"step" => step, "verify" => "fail"}
        end
      )
    end)
  end

  # What a verifier gives that skips the checks of a key's bytes, steps 2 and 3, as OpenSSL
  # and Go's crypto/ed25519 do (SPEC.md 6.2, common libraries), said as the sentence a case's
  # `about` ends with.
  @lax "A verifier that skips steps 2 and 3, as OpenSSL and Go's crypto/ed25519 do,"

  defp lax_sentence(key, message, signature) do
    case lax(key, message, signature) do
      :pass -> "#{@lax} passes it."
      {:fail, 4} -> "#{@lax} refuses it at step 4."
      {:fail, step} -> "#{@lax} refuses it at step #{step} over this message."
    end
  end

  # The verdict is OpenSSL's own, through :crypto. A refusal is named by the step of SPEC.md
  # 6.2 at which such a verifier refuses: step 4 when no point has the key's y, read modulo p,
  # step 5 when s is not below L, and otherwise the equation of step 7, over k = SHA-512(R ||
  # A || msg) with A as given.
  defp lax(<<n::little-256>> = key, message, <<_r::binary-32, s::little-256>> = signature) do
    y = Integer.mod(n &&& (1 <<< 255) - 1, Ed25519.p())

    cond do
      :crypto.verify(:eddsa, :none, message, signature, [key, :ed25519]) -> :pass
      Ed25519.decode(<<y::little-256>>) == :error -> {:fail, 4}
      s >= Ed25519.l() -> {:fail, 5}
      true -> {:fail, 7}
    end
  end

  # The first key, counting y up from 2 with the sign bit clear, that encodes no point.
  defp off_curve do
    Enum.find_value(2..1000, fn y ->
      key = <<y::little-256>>
      if Ed25519.decode(key) == :error, do: key
    end)
  end

  # R = [r]B + T, with T the first point of order 8 in spec/small-order-keys.json, and s = r +
  # k a mod L, r from the vector seed's prefix and the message.
  defp small_order_r(a, key, message) do
    {_a, prefix} = Ed25519.expand(Seeds.vector())
    r = Ed25519.scalar(:crypto.hash(:sha512, [prefix, "small order component", message]))
    point = Ed25519.add(Ed25519.multiply(r, Ed25519.base()), Ed25519.torsion())
    Ed25519.sign_as(a, key, {Ed25519.encode(point), r}, message)
  end

  # R = the encoding of [r]B with bit 255 flipped, and s = r + k a mod L for that R, r from the
  # vector seed's prefix and the message.
  defp sign_bit_flipped(a, key, message) do
    {_a, prefix} = Ed25519.expand(Seeds.vector())
    r = Ed25519.scalar(:crypto.hash(:sha512, [prefix, "sign bit", message]))

    Ed25519.sign_as(
      a,
      key,
      {flip(Ed25519.encode(Ed25519.multiply(r, Ed25519.base()))), r},
      message
    )
  end

  # 32 octets with bit 255, the sign bit of a point's encoding, flipped.
  defp flip(<<n::little-256>>), do: <<bxor(n, 1 <<< 255)::little-256>>

  # base64url.

  defp base64url(example) do
    zeros = fn n -> <<0::size(n * 8)>> end
    ones = fn n -> :binary.copy(<<0xFF>>, n) end

    canonical = [
      {"B64U32", Keys.public_key(Seeds.vector()), :all},
      {"B64U32", Keys.public_key(Seeds.genesis()), :some},
      {"B64U32", zeros.(32), :some},
      {"B64U32", ones.(32), :some},
      {"B64U64", Bytes.unb64u(example["V"]), :all},
      {"B64U64", <<1, 0::248, 0::256>>, :some},
      {"B64U64", zeros.(64), :some},
      {"B64U64", ones.(64), :some}
    ]

    List.flatten([
      for {class, octets, flaws} <- canonical do
        text = Bytes.b64u(octets)

        [
          %{"class" => class, "octets" => Bytes.hex(octets), "text" => text}
          | for {flaw, spelling, same?} <- flaws(text, flaws) do
              refused = %{"class" => class, "refused" => flaw, "text" => spelling}
              if same?, do: Map.put(refused, "canonical", text), else: refused
            end
        ]
      end,
      for(class <- ~w(B64U32 B64U64), do: %{"class" => class, "refused" => "empty", "text" => ""})
    ])
  end

  # A canonical spelling's flawed spellings, each `{flaw, spelling, same?}`, where same? says
  # that a decoder that allows the flaw reads the spelling to the canonical octets.
  defp flaws(text, which) do
    standard = text |> String.replace("-", "+") |> String.replace("_", "/")
    {head, last} = String.split_at(text, -1)
    {index, 1} = :binary.match(@alphabet, last)

    all = [
      {"padded", text <> String.duplicate("=", rem(4 - rem(byte_size(text), 4), 4)), true},
      {"standard_alphabet", standard, true},
      {"unused_bits", head <> binary_part(@alphabet, index + 1, 1), true},
      {"trailing_newline", text <> "\n", true},
      {"embedded_crlf",
       binary_part(text, 0, 40) <> "\r\n" <> binary_part(text, 40, byte_size(text) - 40), true},
      {"leading_space", " " <> text, true},
      {"too_short", head, false},
      {"too_long", text <> "A", false},
      {"other_character",
       binary_part(text, 0, 10) <> "." <> binary_part(text, 11, byte_size(text) - 11), false}
    ]

    all
    |> Enum.filter(fn {flaw, spelling, _same?} ->
      (which == :all or flaw in ~w(padded standard_alphabet unused_bits)) and
        spelling != text
    end)
  end

  # The checks.

  @doc "The failures of the corpus checks, over `files`, every file about to be written."
  def check(files) do
    List.flatten([
      check_jcs(files),
      check_ed25519(Parse.decode!(Map.fetch!(files, "vectors/corpus/ed25519.json"))),
      check_base64url(Parse.decode!(Map.fetch!(files, "vectors/corpus/base64url.json")))
    ])
  end

  defp check_jcs(files) do
    pairs =
      for {"vectors/corpus/jcs/" <> name, bytes} <- files, into: %{} do
        [stem, part, "json"] = String.split(name, ".")
        {{stem, part}, bytes}
      end

    stems = pairs |> Map.keys() |> Enum.map(&elem(&1, 0)) |> Enum.uniq() |> Enum.sort()
    m = Parse.decode!(Map.fetch!(files, "vectors/worked-example.json"))["M"]

    [
      expect(
        "the JCS pairs",
        Enum.sort(Map.keys(pairs)),
        for(s <- stems, p <- ~w(input output), do: {s, p})
      ),
      expect(
        "the output of the worked example, M",
        Map.get(pairs, {"worked-example", "output"}),
        m
      ),
      for stem <- stems do
        input = Map.get(pairs, {stem, "input"}, "")
        output = Map.get(pairs, {stem, "output"}, "")

        case Parse.read(input) do
          {:ok, value} ->
            [
              expect("JCS of jcs/#{stem}.input.json", JCS.encode(value), output),
              expect("jcs/#{stem}.output.json read back", Parse.read(output), {:ok, value})
            ]

          other ->
            ["jcs/#{stem}.input.json does not read under J1 to J6: #{inspect(other)}"]
        end
      end
    ]
  end

  defp check_ed25519(cases) do
    ids = Enum.map(cases, & &1["id"])

    [
      expect("Ed25519 case ids that repeat", ids -- Enum.uniq(ids), []),
      for c <- cases do
        label = "ed25519 case #{c["id"]}"
        key = Bytes.unb64u(c["public_key"])
        message = Bytes.unhex(c["message"])
        signature = Bytes.unb64u(c["signature"])

        verdict =
          case c do
            %{"verify" => "pass"} = pass when not is_map_key(pass, "step") -> :pass
            %{"verify" => "fail", "step" => step} -> {:fail, step}
            _other -> :malformed
          end

        [
          truth(
            "#{label}: its key is a canonical B64U32",
            Spec.class?("B64U32", c["public_key"])
          ),
          truth(
            "#{label}: its signature is a canonical B64U64",
            Spec.class?("B64U64", c["signature"])
          ),
          expect("#{label}: its message's length", byte_size(message), 32),
          expect(
            "#{label}: its verdict, step by step",
            Ed25519.verify(key, message, signature),
            verdict
          ),
          expect(
            "#{label}: its verdict under the model's Verify",
            Derive.verify?(key, message, c["signature"]),
            verdict == :pass
          ),
          lax_checks(label, c["about"], key, message, signature)
        ]
      end
    ]
  end

  # What each lax verifier a case's `about` names gives: one that skips steps 2 and 3, which
  # is OpenSSL itself, and each that accepts it: one that reduces s modulo L, one that decodes
  # R and compares points, and one that uses the cofactored equation.
  defp lax_checks(label, about, key, message, <<r::binary-32, s::little-256>> = signature) do
    [
      if(String.contains?(about, @lax),
        do:
          truth(
            "#{label}: its about says what a verifier that skips steps 2 and 3 gives",
            String.ends_with?(about, lax_sentence(key, message, signature))
          ),
        else: []
      ),
      if(about =~ "reduces s modulo L",
        do:
          expect(
            "#{label}: with s reduced modulo L",
            Ed25519.verify(key, message, r <> <<Integer.mod(s, Ed25519.l())::little-256>>),
            :pass
          ),
        else: []
      ),
      if(about =~ "decodes R and compares points",
        do:
          truth(
            "#{label}: R read with y reduced modulo p is [s]B - [k]A",
            decodes_r?(key, message, signature)
          ),
        else: []
      ),
      if(about =~ "cofactored equation accepts",
        do: truth("#{label}: [8][s]B = [8]R + [8][k]A", cofactored?(key, message, signature)),
        else: []
      ),
      if(about =~ "differs from R in that one bit",
        do:
          expect(
            "#{label}: [s]B - [k]A encoded, with bit 255 flipped",
            flip(Ed25519.encode(combination(key, message, signature))),
            r
          ),
        else: []
      ),
      if(about =~ "whose s step 5 refuses",
        do: truth("#{label}: s is not below L", s >= Ed25519.l()),
        else: []
      )
    ]
  end

  # [s]B - [k]A for a key that decodes, with k = SHA-512(R || A || message) mod L.
  defp combination(key, message, <<r::binary-32, s::little-256>>) do
    {:ok, a} = Ed25519.decode(key)
    k = Ed25519.scalar(:crypto.hash(:sha512, [r, key, message]))
    Ed25519.add(Ed25519.multiply(s, Ed25519.base()), Ed25519.negate(Ed25519.multiply(k, a)))
  end

  defp decodes_r?(key, message, <<r::binary-32, _s::binary>> = signature),
    do: lenient_r(r) == Ed25519.encode(combination(key, message, signature))

  defp cofactored?(key, message, <<r::binary-32, _s::binary>> = signature) do
    {:ok, point} = Ed25519.decode(r)
    eight = &Ed25519.encode(Ed25519.multiply(8, &1))
    eight.(combination(key, message, signature)) == eight.(point)
  end

  # The encoding of the point R names once its y is reduced modulo p.
  defp lenient_r(<<n::little-256>>) do
    y = Integer.mod(n &&& (1 <<< 255) - 1, Ed25519.p())
    {:ok, point} = Ed25519.decode(<<y ||| (n >>> 255) <<< 255::little-256>>)
    Ed25519.encode(point)
  end

  defp check_base64url(spellings) do
    for s <- spellings do
      %{"class" => class, "text" => text} = s
      label = "base64url #{class} #{inspect(text)}"

      case s do
        %{"octets" => octets} ->
          [
            truth("#{label}: on its class", Spec.class?(class, text)),
            expect("#{label}: its octets", Bytes.hex(Bytes.unb64u(text)), octets),
            expect("#{label}: its octets spelled again", Bytes.b64u(Bytes.unhex(octets)), text),
            expect("#{label}: its members", Enum.sort(Map.keys(s)), ~w(class octets text))
          ]

        %{"refused" => flaw} ->
          [
            truth("#{label}: off its class", not Spec.class?(class, text)),
            same_octets(label, flaw, text, s["canonical"])
          ]
      end
    end
  end

  # A refused spelling read by a decoder that allows its flaw gives the canonical octets.
  defp same_octets(_label, _flaw, _text, nil), do: []

  defp same_octets(label, flaw, text, canonical) do
    allowed =
      case flaw do
        "padded" -> String.trim_trailing(text, "=")
        "standard_alphabet" -> text |> String.replace("+", "-") |> String.replace("/", "_")
        "unused_bits" -> clear_unused(text)
        "trailing_newline" -> String.trim_trailing(text, "\n")
        "embedded_crlf" -> String.replace(text, "\r\n", "")
        "leading_space" -> String.trim_leading(text, " ")
      end

    expect("#{label}: read with its flaw allowed", allowed, canonical)
  end

  # The spelling with the unused bits of its last character cleared.
  defp clear_unused(text) do
    {head, last} = String.split_at(text, -1)
    {index, 1} = :binary.match(@alphabet, last)
    bits = rem(byte_size(text) * 6, 8)
    head <> binary_part(@alphabet, index &&& bnot((1 <<< bits) - 1), 1)
  end
end
