# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Generator.Cases.Front do
  @moduledoc """
  The cases of the steps before SHAPE: SPEC.md 13.3's ENVELOPE, CONFIGURATION (its offline
  cases), ENVIRONMENT, KEY_BINDING (its offline cases), SIGNATURE and Mixed-order agreement.
  Every case starts from the sound item, `positive/item.proof.json`, and unless it says
  otherwise runs under E_v `test` with the keyring `test` and the pins of
  Generator.Case.pins/0.

  - **ENVELOPE**, each the bare rejection `invalid_envelope`, its `sub_reason` in its id
    (`envelope-<sub_reason>-...`): a document that is an array; a document missing
    `signature`, missing `proof`, with an extra `proof_hash`, and with a `signatures` array in
    place of `signature` (`document`); a `proof` that is a string, and that is null (`proof`);
    a `signature` missing `alg`, with an extra `key_id`, and that is an array (`signature`);
    an `alg` of `Ed25519`, of `EdDSA`, and the pin in capitals (`alg`); K and V each padded,
    in the standard alphabet, with its unused bits set, and with a newline on its end
    (`public_key`, `value`), the newline written escaped, as JCS writes it; each of
    SMALL_ORDER_KEYS as K, `envelope-public_key-small_order-<i>` for the key at index i of
    spec/small-order-keys.json, and K with y = 2^255 - 19 + 1, the identity written with y
    at p or above, each with the signature (identity, 0) (`public_key`). The signature covers
    only `proof`, so no ENVELOPE case signs again.
  - **CONFIGURATION**, offline, each the bare rejection `configuration_error`, decided before
    the file is read: the keyring `test`, which holds VECTOR_KEY, under `staging`, over the
    sound item marked `staging`; under `prod`, a keyring holding only the other key, a key of
    spec/keys.nonproduction.json, over the sound item unmarked, without `signing_key_event`
    and signed by that key; under `test`, no keyring option, which is no keyring source
    (`keyring` absent), over the sound item; and under `test`, over the sound item, keyrings
    that hold VECTOR_KEY and break one load check of SPEC.md 10.2 step 0: a repeated key, a
    wrong `key_id`, a small-order key (the identity), a key whose y is not below 2^255 - 19,
    an extra member in the keyring and in a key, a `version` other than `"1.0"`, and a file
    with a duplicate member name, which breaks J4. So a verifier that let a keyring through
    would bind K and pass the proof, which is sound under that keyring. The online cases are
    in Generator.Cases.Online.
  - **ENVIRONMENT**, `environment_mismatch` at `/environment`, each proof the sound item with
    its marker changed and signed again with VECTOR_KEY. A run whose E_v is not `test` cannot
    load a keyring holding VECTOR_KEY, so it is keyless, where KEY_BINDING and SIGNATURE would
    pass: a proof marked `staging` under `prod`; no `environment` under `staging`; `dev` under
    `staging`; `prod`, `production`, null and the number 1 under `prod`; and under `test` with
    the keyring `test`, null, the number 1, and `test` with a newline on its end. A marker that
    is no ENV value would fail SHAPE too, its knock-on failure, but ENVIRONMENT sees it first
    and ends the run.
  - **A precedence case**, `environment-staging-under-prod-compiled_pin`: the proof marked
    `staging` under `prod` again, with no keyring option, where the compiled pin governs and
    holds no key, so KEY_BINDING would fail too. It carries two defects, and shows that
    ENVIRONMENT, which comes first (SPEC.md 10.2), is the one that reports. It is not a
    single-defect case, and the check of every code does not count it.
  - **KEY_BINDING**, offline: `key_binding_failed` for the sound item under a keyring that
    holds only the other key, for the sound item without `signing_key_event` signed by the
    other key under the keyring `test`, and, under `prod` with no keyring option, for the
    sound item unmarked, where the compiled pin governs and holds no key. The keyring `none`
    gives `skip key_binding_not_performed`, the label `unattributed`, and otherwise the sound
    item's rows under the keyring `test`, every one of them, which its `same_as` holds it to
    (`key_binding-none`), and the sound item's trace. A supplied keyring holding VECTOR_KEY with `"active": false`,
    sequence 0, beside the other key, active, sequence 1, as a routine rotation leaves it,
    binds K over the sound item: KEY_BINDING passes, the label is `supplied-keyring`, and
    every row is the sound item's, which its `same_as` holds it to, and so is the trace
    (`key_binding-inactive_key`), since a key binds active or not (SPEC.md 6.1). The keyring
    `unavailable` is online (Generator.Cases.Online).
  - **SIGNATURE**, `signature_invalid`, K VECTOR_KEY: V a signature by VECTOR_KEY over M
    itself, over SHA-256(M), over the hex of `proof_hash` (SPEC.md 6.3), and over the hash of
    the proof under 0x31 and under 0x62; V with s equal to L, and with s + L in place of s;
    `environment` removed after signing, under `prod`, and changed to `dev` after signing,
    under `dev`, each keyless; and V a signature by the other key over the sound item, whose
    `signing_key_event` introduces K, with the keyring `test` and keyless; and, keyless over
    the sound item without `signing_key_event`, whose event would introduce a key other than
    K, with V VECTOR_KEY's signature over it, K the first key, counting y up from 2 with the
    sign bit clear, that decodes to no point (`signature-key_not_on_curve-keyless`): its y is
    below p and it
    is none of SMALL_ORDER_KEYS, so it passes ENVELOPE, whose checks of a key's bytes do not
    decode the point, and fails at step 4 of Verify (SPEC.md 6.2). The case's builder refuses
    a K that is on the curve or that fails the checks of a key's bytes, and one whose V has an
    s at L or above, so the failure is step 4's alone.
  - **Mixed-order agreement**, keyless, over the sound item without `signing_key_event`, K
    the other key plus the point of order 8 at index 4 of spec/small-order-keys.json, which
    passes the checks of a key's bytes. With R = [r]B, k = SHA-512(R || K || proof_hash) mod L
    and s = r + k a mod L, where a is the other key's scalar, the first r (from the other
    seed's prefix, a counter octet and `proof_hash`) whose k is 0 modulo 8 gives a signature
    that passes, label `unattributed` (`mixed_order-k_multiple_of_8`), and the first whose k
    is not gives `signature_invalid` (`mixed_order-k_not_multiple_of_8`). The key and the
    signatures come from the generator's Ed25519 point arithmetic (Generator.Ed25519), which
    checks the key against the other key's public key and the point's order. Anyone who
    holds the other seed can sign under this K, choosing r as these cases do, so it is a
    published test key too, key id `5e81cc77`, and the seed check
    (Generator.KnownAnswers.seeds/1) fails the run unless spec/keys.nonproduction.json lists
    it.

  A proof file shared by several cases belongs to the first, and the others name it; so does
  the keyring holding only the other key, which `configuration-nonproduction_key-under-prod`
  writes. The array document and the keyring with a duplicate name are written as bytes;
  every other file is a value, in its form.
  """

  @behaviour Generator.Cases.Class

  alias Generator.{Bytes, Case, Derive, Ed25519, Edit, FileForm, JCS, Keys, Registry, Seeds}
  alias Generator.Spec

  @capitals String.upcase("truestamp-ed25519-sha256-jcs")
  @alphabet "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"

  # RFC 8032 section 5.1: p, and the order L of the base point.
  @p Integer.pow(2, 255) - 19
  @l Integer.pow(2, 252) + 27_742_317_777_372_353_535_851_937_790_883_648_493

  # The files that several cases share, each written by the first case named here.
  @staging "negative/configuration-vector_key-under-staging.proof.json"
  @other_keyring "negative/configuration-nonproduction_key-under-prod.keyring.json"
  @unmarked "negative/environment-absent-under-staging.proof.json"
  @by_other "negative/signature-other_key-keyring_test.proof.json"

  @impl true
  def codes,
    do: ~w(configuration_error invalid_envelope environment_mismatch key_binding_failed
         key_binding_not_performed signature_invalid)

  @impl true
  def cases(%{sound: %{"item" => item}}) do
    List.flatten([
      envelope(item),
      configuration(item),
      environment(item),
      key_binding(item),
      signature(item),
      mixed_order(item)
    ])
  end

  # ENVELOPE.

  defp envelope(%{envelope: envelope, proof: proof}) do
    %{"signature" => signature} = envelope
    %{"public_key" => k, "value" => v} = signature
    identity = identity_signature()

    List.flatten([
      {"document-array", "document", {:bytes, JCS.encode([envelope])}},
      {"document-missing-signature", "document", Map.delete(envelope, "signature")},
      {"document-missing-proof", "document", Map.delete(envelope, "proof")},
      {"document-extra-proof_hash", "document",
       Map.put(envelope, "proof_hash", Bytes.hex(Registry.record_hash("proof_hash", proof)))},
      {"document-signatures-array", "document", %{"proof" => proof, "signatures" => [signature]}},
      {"proof-string", "proof", %{envelope | "proof" => JCS.encode(proof)}},
      {"proof-null", "proof", %{envelope | "proof" => nil}},
      {"signature-missing-alg", "signature", signed(envelope, Map.delete(signature, "alg"))},
      {"signature-extra-key_id", "signature",
       signed(envelope, Map.put(signature, "key_id", Keys.key_id(Bytes.unb64u(k))))},
      {"signature-array", "signature", signed(envelope, [signature])},
      for {name, alg} <- [{"ed25519", "Ed25519"}, {"eddsa", "EdDSA"}, {"capitals", @capitals}] do
        {"alg-" <> name, "alg", signed(envelope, %{signature | "alg" => alg})}
      end,
      for {name, text} <- spellings(k) do
        {"public_key-" <> name, "public_key", Case.envelope(proof, text, v)}
      end,
      for {name, text} <- spellings(v) do
        {"value-" <> name, "value", Case.envelope(proof, k, text)}
      end,
      for {%{"hex" => hex}, i} <- Enum.with_index(Spec.read("small-order-keys.json")) do
        {"public_key-small_order-#{i}", "public_key",
         Case.envelope(proof, Bytes.b64u(Bytes.unhex(hex)), identity)}
      end,
      {"public_key-y_not_below_p", "public_key",
       Case.envelope(proof, Bytes.b64u(<<@p + 1::little-256>>), identity)}
    ])
    |> Enum.map(fn {id, sub_reason, file} ->
      Case.new("envelope-" <> id,
        proof: proof_file(file),
        defect: {:bare, "invalid_envelope", sub_reason}
      )
    end)
  end

  defp signed(envelope, signature), do: %{envelope | "signature" => signature}

  # A case's proof: an envelope in the served form, or a file given as bytes or by its path.
  defp proof_file({form, _file} = file) when form in [:bytes, :path], do: file
  defp proof_file(envelope), do: {:served, envelope}

  # A K or V off its class: padded, in the standard alphabet, with its unused bits set, and
  # with a newline on its end. Each spelling decodes, in a decoder that allows it, to the
  # same octets.
  defp spellings(text) do
    standard = text |> String.replace("-", "+") |> String.replace("_", "/")
    if standard == text, do: raise(ArgumentError, "#{text} has no - or _ to respell")
    {head, last} = String.split_at(text, -1)
    {index, 1} = :binary.match(@alphabet, last)

    [
      {"padded", text <> String.duplicate("=", rem(4 - rem(byte_size(text), 4), 4))},
      {"standard_alphabet", standard},
      {"unused_bits", head <> binary_part(@alphabet, index + 1, 1)},
      {"newline", text <> "\n"}
    ]
  end

  # The signature (identity, 0): R the encoding of the identity, and s zero.
  defp identity_signature, do: Bytes.b64u(<<1, 0::248, 0::256>>)

  # CONFIGURATION.

  defp configuration(%{proof: proof, path: path}) do
    bare = {:bare, "configuration_error", nil}
    other = Keys.public_key(Seeds.other())

    unmarked_other =
      proof
      |> Map.delete("environment")
      |> Map.delete("signing_key_event")
      |> Case.sign(Seeds.other())

    [
      Case.new("configuration-vector_key-under-staging",
        proof: {:served, proof |> Edit.put("/environment", "staging") |> Case.sign()},
        environment: "staging",
        defect: bare
      ),
      Case.new("configuration-nonproduction_key-under-prod",
        proof: {:served, unmarked_other},
        environment: "prod",
        keyring: {:value, keyring([key(other, 0)])},
        defect: bare
      ),
      Case.new("configuration-no_keyring_source",
        proof: {:path, path},
        keyring: nil,
        defect: bare
      )
      | for {name, keyring} <- broken_keyrings(other) do
          Case.new("configuration-keyring-" <> name,
            proof: {:path, path},
            keyring: keyring,
            defect: bare
          )
        end
    ]
  end

  # Keyrings that each break one load check of SPEC.md 10.2 step 0, beside VECTOR_KEY.
  defp broken_keyrings(other) do
    vector = key(Keys.public_key(Seeds.vector()), 0)
    one = keyring([vector])
    text = FileForm.encode(one)
    version = ~s(  "version": "1.0"\n)
    [_once] = :binary.matches(text, version)

    [
      {"repeated_key", {:value, keyring([vector, %{vector | "sequence" => 1}])}},
      {"wrong_key_id", {:value, keyring([%{vector | "key_id" => Keys.key_id(other)}])}},
      {"small_order_key", {:value, keyring([vector, key(<<1, 0::248>>, 1)])}},
      {"y_not_below_p", {:value, keyring([vector, key(<<@p + 1::little-256>>, 1)])}},
      {"extra_member", {:value, Map.put(one, "comment", "a member no keyring has")}},
      {"key_extra_member", {:value, keyring([Map.put(vector, "environment", "test")])}},
      {"version", {:value, %{one | "version" => "2.0"}}},
      {"duplicate_name",
       {:bytes, :binary.replace(text, version, ~s(  "version": "1.0",\n) <> version)}}
    ]
  end

  defp keyring(keys), do: %{"keys" => keys, "version" => "1.0"}

  defp key(public, sequence) do
    %{
      "active" => true,
      "key_id" => Keys.key_id(public),
      "public_key" => Bytes.b64u(public),
      "sequence" => sequence
    }
  end

  # ENVIRONMENT.

  defp environment(%{proof: proof}) do
    marked = fn marker -> {:served, proof |> Edit.put("/environment", marker) |> Case.sign()} end
    null = "negative/environment-null-under-test.proof.json"
    number = "negative/environment-number-under-test.proof.json"
    {code, part, step} = mismatch = {"environment_mismatch", "/environment", "ENVIRONMENT"}

    # A marker that is no ENV value also fails SHAPE's schema, at the marker.
    not_env = [knock_on: [{"shape_invalid", "/environment", "SHAPE"}]]

    # The compiled pin holds no key, so KEY_BINDING would fail too.
    precedence = [defect: {:precedes, mismatch, [{"key_binding_failed", nil, "KEY_BINDING"}]}]

    [
      {"staging-under-prod", {:path, @staging}, "prod", "none", []},
      {"staging-under-prod-compiled_pin", {:path, @staging}, "prod", nil, precedence},
      {"absent-under-staging", {:served, proof |> Map.delete("environment") |> Case.sign()},
       "staging", "none", []},
      {"dev-under-staging", marked.("dev"), "staging", "none", []},
      {"prod-under-prod", marked.("prod"), "prod", "none", not_env},
      {"production-under-prod", marked.("production"), "prod", "none", not_env},
      {"null-under-test", marked.(nil), "test", "test", not_env},
      {"null-under-prod", {:path, null}, "prod", "none", not_env},
      {"number-under-test", marked.(1), "test", "test", not_env},
      {"number-under-prod", {:path, number}, "prod", "none", not_env},
      {"test_newline-under-test", marked.("test\n"), "test", "test", not_env}
    ]
    |> Enum.map(fn {id, file, ev, keyring, options} ->
      single = [proof: file, environment: ev, keyring: keyring, defect: {:fail, code, part, step}]
      Case.new("environment-" <> id, Keyword.merge(single, options))
    end)
  end

  # KEY_BINDING.

  defp key_binding(%{proof: proof, path: path}) do
    failed = {:fail, "key_binding_failed", nil, "KEY_BINDING"}
    other = proof |> Map.delete("signing_key_event") |> Case.sign(Seeds.other())

    [
      Case.new("key_binding-failed-keyring_lacks_key",
        proof: {:path, path},
        keyring: {:path, @other_keyring},
        defect: failed
      ),
      Case.new("key_binding-failed-other_key", proof: {:served, other}, defect: failed),
      Case.new("key_binding-failed-compiled_pin",
        proof: {:path, @unmarked},
        environment: "prod",
        keyring: nil,
        defect: failed
      ),
      # SPEC.md 6.1: a key binds active or not, so every row is the sound item's.
      Case.new("key_binding-inactive_key",
        proof: {:path, path},
        keyring: {:value, inactive_keyring()},
        label: "supplied-keyring",
        trace: Case.trace_path(path),
        same_as: "sound-item",
        defect: {:passes, [{"pass", nil, nil, "KEY_BINDING"}]}
      ),
      # SPEC.md 13.3's "otherwise the sound proof's rows": every row but KEY_BINDING's is the
      # sound item's under the keyring test.
      Case.new("key_binding-none",
        proof: {:path, path},
        keyring: "none",
        label: "unattributed",
        trace: Case.trace_path(path),
        same_as: {"sound-item", except: ["KEY_BINDING"]},
        defect: {:passes, [{"skip", "key_binding_not_performed", nil, "KEY_BINDING"}]}
      )
    ]
  end

  # VECTOR_KEY retired, `"active": false`, beside the other key, active, as a routine rotation
  # leaves a keyring (SPEC.md 8.1).
  defp inactive_keyring do
    vector = %{key(Keys.public_key(Seeds.vector()), 0) | "active" => false}
    keyring = keyring([vector, key(Keys.public_key(Seeds.other()), 1)])

    unless Enum.map(keyring["keys"], & &1["active"]) == [false, true],
      do: raise(ArgumentError, "the keyring must hold VECTOR_KEY inactive beside an active key")

    keyring
  end

  # SIGNATURE.

  defp signature(%{proof: proof, envelope: envelope}) do
    m = JCS.encode(proof)
    vector = Seeds.vector()
    k = envelope["signature"]["public_key"]
    over = fn message -> Case.envelope(proof, k, Bytes.b64u(Keys.sign(vector, message))) end
    by_other = sign_as(proof, k, Seeds.other())

    [
      {"over-m", over.(m), "test", "test"},
      {"over-sha256_m", over.(:crypto.hash(:sha256, m)), "test", "test"},
      {"over-proof_hash_hex", over.(Bytes.hex(Registry.hash("proof_hash", m))), "test", "test"},
      {"over-block_hash_byte", over.(Registry.hash("block_hash", m)), "test", "test"},
      {"over-handover_byte", over.(Registry.hash("handover", m)), "test", "test"},
      {"s_equal_l", with_s(envelope, fn _s -> @l end), "test", "test"},
      {"s_plus_l", with_s(envelope, &(&1 + @l)), "test", "test"},
      {"environment-removed", unsigned(envelope, &Map.delete(&1, "environment")), "prod", "none"},
      {"environment-changed", unsigned(envelope, &Map.put(&1, "environment", "dev")), "dev",
       "none"},
      {"other_key-keyring_test", by_other, "test", "test"},
      {"other_key-keyless", {:path, @by_other}, "test", "none"},
      {"key_not_on_curve-keyless", off_curve(Map.delete(proof, "signing_key_event")), "test",
       "none"}
    ]
    |> Enum.map(fn {id, file, ev, keyring} ->
      Case.new("signature-" <> id,
        proof: proof_file(file),
        environment: ev,
        keyring: keyring,
        defect: {:fail, "signature_invalid", nil, "SIGNATURE"}
      )
    end)
  end

  # The envelope of `proof` with V VECTOR_KEY's signature over it and K the first key,
  # counting y up from 2 with the sign bit clear, that decodes to no point: it passes the
  # checks of a key's bytes, so ENVELOPE, and Verify refuses it at step 4 (SPEC.md 6.2). V's
  # s is below L, so no step after 4 could refuse it first.
  defp off_curve(proof) do
    value = Case.sign(proof)["signature"]["value"]
    key = 2..1000 |> Enum.map(&<<&1::little-256>>) |> Enum.find(&(Ed25519.decode(&1) == :error))
    <<_r::binary-32, s::little-256>> = Bytes.unb64u(value)

    cond do
      not Derive.key_bytes?(key) ->
        raise(ArgumentError, "the key fails the checks of a key's bytes")

      Ed25519.verify(key, <<0::256>>, Bytes.unb64u(value)) != {:fail, 4} ->
        raise(ArgumentError, "Verify does not refuse the key at step 4")

      s >= @l ->
        raise(ArgumentError, "V's s is not below L")

      true ->
        Case.envelope(proof, Bytes.b64u(key), value)
    end
  end

  # The envelope with the s of its V replaced by fun.(s).
  defp with_s(%{"signature" => %{"value" => value}} = envelope, fun) do
    <<r::binary-32, s::little-256>> = Bytes.unb64u(value)
    put_in(envelope, ["signature", "value"], Bytes.b64u(<<r::binary, fun.(s)::little-256>>))
  end

  # The envelope with its proof changed after signing, and not signed again.
  defp unsigned(envelope, change), do: Map.update!(envelope, "proof", change)

  # K the string `k`, over a signature by the key of `seed`.
  defp sign_as(proof, k, seed) do
    value = Keys.sign(seed, Registry.record_hash("proof_hash", proof))
    Case.envelope(proof, k, Bytes.b64u(value))
  end

  # Mixed-order agreement.

  defp mixed_order(%{proof: proof}) do
    proof = Map.delete(proof, "signing_key_event")
    message = Registry.record_hash("proof_hash", proof)
    key = Bytes.b64u(Ed25519.mixed_order_key())

    envelope = fn wanted? ->
      Case.envelope(proof, key, Bytes.b64u(Ed25519.sign_mixed(message, wanted?)))
    end

    [
      Case.new("mixed_order-k_multiple_of_8",
        proof: {:served, envelope.(&(rem(&1, 8) == 0))},
        keyring: "none",
        label: "unattributed",
        defect:
          {:passes,
           [
             {"skip", "key_binding_not_performed", nil, "KEY_BINDING"},
             {"pass", nil, nil, "SIGNATURE"}
           ]}
      ),
      Case.new("mixed_order-k_not_multiple_of_8",
        proof: {:served, envelope.(&(rem(&1, 8) != 0))},
        keyring: "none",
        defect: {:fail, "signature_invalid", nil, "SIGNATURE"}
      )
    ]
  end
end
