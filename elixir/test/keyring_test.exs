# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Truestamp.Verifier.KeyringTest do
  # spec/keyring.production.json, the compiled pin of SPEC.md 8.3, held to the keyring form
  # and the load checks of section 10.2, step 0, which are read from SPEC.md; and
  # spec/keys.nonproduction.json, the non-production keys the last check refuses. The pin
  # holds no key yet, so the checks are also run on keyrings built here, one that passes and
  # one that breaks each check.
  use ExUnit.Case, async: true

  import Bitwise

  alias Truestamp.Verifier.Test.StrictJSON

  @root Path.expand("../..", __DIR__)
  @spec_md Path.join(@root, "SPEC.md")
  @keyring Path.join(@root, "spec/keyring.production.json")
  @external_resource @spec_md
  @external_resource @keyring

  @p Integer.pow(2, 255) - 19

  defp spec_md, do: File.read!(@spec_md)

  defp read(name) do
    {:ok, value} = @root |> Path.join("spec/" <> name) |> File.read!() |> StrictJSON.decode()
    value
  end

  # Section 10.2, step 0: a keyring's two members, the string `version` holds, and each key's
  # members with their classes, read from the paragraph that states them.
  defp form do
    [_before, rest] =
      String.split(spec_md(), "A keyring is read under section 10.1 and", parts: 2)

    [paragraph, _after] = String.split(rest, ", where:\n", parts: 2)

    [keys, version, literal] =
      Regex.run(
        ~r/exactly two\s+members: `(\w+)`, an array, and `(\w+)`, the string `"([^"`]+)"`/,
        paragraph,
        capture: :all_but_first
      )

    [_keyring, element] = String.split(paragraph, "Each element of `#{keys}`", parts: 2)

    members =
      ~r/`(\w+)` \(([^)]+)\)/
      |> Regex.scan(element, capture: :all_but_first)
      |> Map.new(fn [member, class] -> {member, class} end)

    %{keys: keys, version: version, literal: literal, members: members}
  end

  # The bulleted load checks that follow the form, whitespace collapsed.
  defp load_check_bullets do
    [_before, rest] = String.split(spec_md(), "`sequence` (INT), where:\n\n", parts: 2)

    [list, _after] =
      String.split(rest, "\n\nA verifier makes exactly these load checks.", parts: 2)

    list
    |> String.split(~r/^- /m, trim: true)
    |> Enum.map(
      &(&1
        |> String.replace(~r/\s+/, " ")
        |> String.trim()
        |> String.trim_trailing(";")
        |> String.trim_trailing("."))
    )
  end

  describe "keyring.production.json" do
    test "is a keyring in the form of section 10.2, step 0, and passes its load checks under prod" do
      {:ok, keyring} = @keyring |> File.read!() |> StrictJSON.decode()
      assert load(keyring, "prod") == :ok
    end
  end

  describe "keys.nonproduction.json" do
    test "lists each key once, with its environment and key id, in order" do
      %{"keys" => keys} = file = read("keys.nonproduction.json")
      assert Map.keys(file) == ["keys"]
      environments = read("encodings.json")["ENV"]["values"]

      for key <- keys do
        assert members?(key, ["environment", "key_id", "public_key"]), inspect(key)
        assert key["environment"] in environments, inspect(key)
        assert class?("B64U32", key["public_key"]), inspect(key)
        assert key["key_id"] == key_id(decode(key["public_key"])), inspect(key)
        assert key_bytes?(decode(key["public_key"])), inspect(key)
      end

      pairs = Enum.map(keys, &{&1["key_id"], &1["public_key"]})
      assert unique?(pairs)
      assert keys == Enum.sort_by(keys, &{&1["environment"], &1["key_id"]})
    end

    test "holds VECTOR_KEY among the test keys" do
      vector = read("constants.json")["VECTOR_KEY"]

      assert %{"environment" => "test"} =
               Enum.find(read("keys.nonproduction.json")["keys"], fn key ->
                 hex(decode(key["public_key"])) == vector
               end)
    end

    # Section 9 publishes the seed of each key the vectors use, and the key id of each but
    # VECTOR_KEY, whose value the constants table gives.
    test "holds the key of every seed SPEC.md publishes among the test keys" do
      text = String.replace(spec_md(), ~r/\s+/, " ")

      seeds =
        ~r/the seed of 32 bytes of 0x([0-9A-F]{2})/
        |> Regex.scan(text, capture: :all_but_first)
        |> Enum.map(fn [byte] -> String.to_integer(byte, 16) end)
        |> Enum.uniq()

      ids =
        ~r/the seed of 32 bytes of 0x([0-9A-F]{2}), whose key id is `([0-9a-f]{8})`/
        |> Regex.scan(text, capture: :all_but_first)
        |> Map.new(fn [byte, key_id] -> {String.to_integer(byte, 16), key_id} end)

      assert Enum.sort(seeds) == [0x41, 0x42, 0x43]
      assert Enum.sort(Map.keys(ids)) == [0x41, 0x43]

      test_keys =
        for %{"environment" => "test"} = key <- read("keys.nonproduction.json")["keys"], do: key

      for seed <- seeds do
        {public, _secret} = :crypto.generate_key(:eddsa, :ed25519, :binary.copy(<<seed>>, 32))
        listed = Enum.find(test_keys, &(&1["public_key"] == b64u(public)))
        assert listed, "the key of the seed of 0x#{Integer.to_string(seed, 16)}"
        assert listed["key_id"] == Map.get(ids, seed, key_id(public))
      end
    end
  end

  describe "the load checks of section 10.2, step 0" do
    test "are the ones SPEC.md lists, made here in that order" do
      assert load_check_bullets() == [
               "`key_id` is the key id of `public_key` (section 3.3)",
               "no two keys share a `key_id` or a `public_key`",
               "`public_key` passes the checks of a key's bytes (section 6.2): its y is below " <>
                 "2^255 - 19, and it is not one of SMALL_ORDER_KEYS",
               "no key is VECTOR_KEY unless E_v is `test`",
               "in a production keyring (section 6.4), no key is in `spec/keys.nonproduction.json`"
             ]

      assert form().members == %{
               "active" => "a boolean",
               "key_id" => "KID",
               "public_key" => "B64U32",
               "sequence" => "INT"
             }
    end

    test "pass sound keyrings in every environment" do
      [one, two] = [key(1), key(2)]

      for keyring <- [
            keyring([]),
            keyring([entry(one)]),
            keyring([entry(one, active: false), entry(two, sequence: 1)]),
            # A number's spelling changes no value (section 10.1), so 1.0 is the INT 1.
            keyring([entry(one, sequence: 1.0)])
          ],
          env <- ["prod" | read("encodings.json")["ENV"]["values"]] do
        assert load(keyring, env) == :ok, "#{env}: #{inspect(keyring)}"
      end
    end

    test "refuse a keyring that breaks one, with that check" do
      [one, two] = [key(1), key(2)]
      sound = keyring([entry(one)])

      vector =
        "constants.json" |> read() |> Map.fetch!("VECTOR_KEY") |> Base.decode16!(case: :lower)

      identity = "small-order-keys.json" |> read() |> hd() |> Map.fetch!("hex")

      for {defect, keyring, error} <- [
            {"a member beside keys and version", Map.put(sound, "expires", 1), :members},
            {"no version", Map.delete(sound, "version"), :members},
            {"a keyring that is an array", [entry(one)], :members},
            {"version 1.0 as a number", Map.put(sound, "version", 1.0), :version},
            {"version \"1\"", Map.put(sound, "version", "1"), :version},
            {"keys as an object", Map.put(sound, "keys", %{}), :keys},
            {"a key with a member more", keyring([Map.put(entry(one), "revoked", false)]),
             :key_members},
            {"a key without its sequence", keyring([Map.delete(entry(one), "sequence")]),
             :key_members},
            {"active as a string", keyring([entry(one, active: "true")]), {:class, "active"}},
            {"an uppercase key id", keyring([entry(one, key_id: String.upcase(key_id(one)))]),
             {:class, "key_id"}},
            {"a padded key", keyring([entry(one, public_key: b64u(one) <> "=")]),
             {:class, "public_key"}},
            {"a key in standard base64", keyring([entry(one, public_key: Base.encode64(one))]),
             {:class, "public_key"}},
            {"a key with nonzero unused bits",
             keyring([entry(one, public_key: binary_part(b64u(one), 0, 42) <> "B")]),
             {:class, "public_key"}},
            {"sequence -1", keyring([entry(one, sequence: -1)]), {:class, "sequence"}},
            {"sequence 1.5", keyring([entry(one, sequence: 1.5)]), {:class, "sequence"}},
            {"a key id of another key", keyring([entry(one, key_id: key_id(two))]), :key_id},
            {"a key id hashed without the prefix byte",
             keyring([entry(one, key_id: :sha256 |> :crypto.hash(one) |> hex8())]), :key_id},
            {"one key twice", keyring([entry(one), entry(one, sequence: 1)]), :unique},
            {"the identity", keyring([entry(Base.decode16!(identity, case: :lower))]),
             :key_bytes},
            {"a key written with y = p", keyring([entry(<<@p::little-256>>)]), :key_bytes},
            {"a key written with y = p + 1", keyring([entry(<<@p + 1::little-256>>)]),
             :key_bytes},
            {"VECTOR_KEY", keyring([entry(vector)]), :vector_key},
            {"a non-production key", keyring([entry(nonproduction("dev"))]), :nonproduction}
          ] do
        assert load(keyring, "prod") == {:error, error}, defect
      end
    end

    test "allow a non-production key only when the verifier's environment is not prod" do
      keyring = keyring([entry(nonproduction("dev"))])

      for env <- ["prod" | read("encodings.json")["ENV"]["values"]] do
        expected = if env == "prod", do: {:error, :nonproduction}, else: :ok
        assert load(keyring, env) == expected, env
      end
    end

    test "allow VECTOR_KEY only when the verifier's environment is test" do
      vector =
        "constants.json" |> read() |> Map.fetch!("VECTOR_KEY") |> Base.decode16!(case: :lower)

      keyring = keyring([entry(vector)])

      for env <- ["prod" | read("encodings.json")["ENV"]["values"]] do
        expected = if env == "test", do: :ok, else: {:error, :vector_key}
        assert load(keyring, env) == expected, env
      end
    end
  end

  # The load checks of section 10.2, step 0, in the order SPEC.md lists them, after the form:
  # :ok, or {:error, check} for the first check the keyring fails.
  defp load(keyring, env) do
    %{keys: keys, version: version, literal: literal, members: members} = form()

    with :ok <- check(members?(keyring, [keys, version]), :members),
         :ok <- check(keyring[version] == literal, :version),
         :ok <- check(is_list(keyring[keys]), :keys),
         :ok <- all(keyring[keys], &key_form(&1, members)),
         pairs = Enum.map(keyring[keys], &{&1["key_id"], decode(&1["public_key"])}),
         :ok <- all(pairs, fn {id, bytes} -> check(id == key_id(bytes), :key_id) end),
         :ok <- check(unique?(pairs), :unique),
         :ok <- all(pairs, fn {_id, bytes} -> check(key_bytes?(bytes), :key_bytes) end),
         :ok <- all(pairs, fn {_id, bytes} -> check(vector_allowed?(bytes, env), :vector_key) end) do
      all(pairs, fn {_id, bytes} -> check(nonproduction_allowed?(bytes, env), :nonproduction) end)
    end
  end

  # Section 6.4: VECTOR_KEY only under test, and no non-production key under prod.
  defp vector_allowed?(bytes, env),
    do: env == "test" or hex(bytes) != read("constants.json")["VECTOR_KEY"]

  defp nonproduction_allowed?(bytes, env) do
    env != "prod" or
      b64u(bytes) not in Enum.map(read("keys.nonproduction.json")["keys"], & &1["public_key"])
  end

  # The bytes of the first key keys.nonproduction.json lists for an environment.
  defp nonproduction(environment) do
    read("keys.nonproduction.json")["keys"]
    |> Enum.find(&(&1["environment"] == environment))
    |> Map.fetch!("public_key")
    |> decode()
  end

  defp check(true, _error), do: :ok
  defp check(false, error), do: {:error, error}

  defp all(list, fun), do: Enum.find(Enum.map(list, fun), :ok, &(&1 != :ok))

  defp members?(object, names),
    do: is_map(object) and Enum.sort(Map.keys(object)) == Enum.sort(names)

  defp key_form(key, members) do
    with :ok <- check(members?(key, Map.keys(members)), :key_members) do
      all(Enum.sort(members), fn {member, class} ->
        check(class?(class, key[member]), {:class, member})
      end)
    end
  end

  defp class?("a boolean", value), do: is_boolean(value)

  defp class?(class, value) do
    case Map.fetch!(read("encodings.json"), class) do
      %{"pattern" => pattern} ->
        is_binary(value) and value =~ Regex.compile!("\\A(?:" <> pattern <> ")\\z")

      %{"minimum" => minimum, "maximum" => maximum} ->
        is_number(value) and value >= minimum and value <= maximum and trunc(value) == value
    end
  end

  # A B64U32 value, which class?/2 has matched, so its spelling is canonical.
  defp decode(public_key), do: Base.url_decode64!(public_key, padding: false)

  defp unique?(pairs) do
    {ids, keys} = Enum.unzip(pairs)
    ids == Enum.uniq(ids) and keys == Enum.uniq(keys)
  end

  # Section 6.2, steps 2 and 3: y below p, and not one of SMALL_ORDER_KEYS.
  defp key_bytes?(bytes) do
    y = :binary.decode_unsigned(bytes, :little) &&& Integer.pow(2, 255) - 1
    small_order = Enum.map(read("small-order-keys.json"), & &1["hex"])
    y < @p and hex(bytes) not in small_order
  end

  # Section 3.3: the hex of the first 4 bytes of SHA-256(0x60 || the key), with the byte taken
  # from the registry.
  defp key_id(bytes) do
    "0x" <> byte = read("prefixes.json")["key_id"]["byte"]
    :sha256 |> :crypto.hash(Base.decode16!(byte, case: :lower) <> bytes) |> hex8()
  end

  defp hex8(digest), do: digest |> binary_part(0, 4) |> hex()
  defp hex(bytes), do: Base.encode16(bytes, case: :lower)
  defp b64u(bytes), do: Base.url_encode64(bytes, padding: false)

  defp key(n) do
    {public, _secret} = :crypto.generate_key(:eddsa, :ed25519, :binary.copy(<<n>>, 32))
    public
  end

  defp keyring(keys), do: %{"keys" => keys, "version" => "1.0"}

  defp entry(bytes, overrides \\ []) do
    Map.merge(
      %{
        "active" => true,
        "key_id" => key_id(bytes),
        "public_key" => b64u(bytes),
        "sequence" => 0
      },
      Map.new(overrides, fn {name, value} -> {Atom.to_string(name), value} end)
    )
  end
end
