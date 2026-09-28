# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Truestamp.Verifier.GateTest do
  # Steps 0 to 6 of SPEC.md 10.2 on documents built here, for what the shared cases do not
  # pin: the order of the ENVELOPE checks when several fail, the environment_mismatch
  # message (6.4, never quoting the marker), a supplied keyring under prod (6.4, a production
  # keyring), a key bound under the compiled pin, an inactive key binding, a key off the curve
  # passing ENVELOPE and failing SIGNATURE, the step order and the rows a failure ends the run
  # with, reading the file only after step 0, and proof_hash taken from the parsed value.
  use ExUnit.Case, async: true

  alias Truestamp.Verifier.{
    Base64url,
    Config,
    Ed25519,
    Gate,
    JCS,
    KeyId,
    Keyring,
    Parser,
    ReasonCodes,
    RecordHash,
    Rejection,
    Row,
    Run
  }

  alias Truestamp.Verifier.Test.{Cases, StrictJSON}

  @root Path.expand("../../..", __DIR__)
  @spec_md Path.join(@root, "SPEC.md")
  @external_resource @spec_md

  # ---------------------------------------------------------------------------------------
  # Helpers

  defp key_pair(seed) do
    {public, secret} = :crypto.generate_key(:eddsa, :ed25519, :binary.copy(<<seed>>, 32))
    {public, secret}
  end

  # A document whose signature is made over proof_hash by the key of `seed` (0x42 is
  # VECTOR_KEY's, 0x44 another test key's, 0x07 a key no file lists).
  defp signed(proof, seed \\ 0x42) do
    {public, secret} = key_pair(seed)

    signature =
      :crypto.sign(:eddsa, :none, RecordHash.hash(:proof_hash, proof), [secret, :ed25519])

    %{
      "proof" => proof,
      "signature" => %{
        "alg" => Gate.alg(),
        "public_key" => Base64url.encode(public),
        "value" => Base64url.encode(signature)
      }
    }
  end

  defp proof(fields \\ %{}),
    do: Map.merge(%{"format" => "truestamp-proof", "type" => "block", "version" => 1}, fields)

  # A keyring of the keys of `seeds`, each a seed, active, or `{seed, active}`.
  defp keyring_bytes(seeds) do
    keys =
      for {spec, sequence} <- Enum.with_index(seeds) do
        {seed, active} = if is_tuple(spec), do: spec, else: {spec, true}
        {public, _secret} = key_pair(seed)

        %{
          "active" => active,
          "key_id" => KeyId.of(public),
          "public_key" => Base64url.encode(public),
          "sequence" => sequence
        }
      end

    StrictJSON.canonical(%{"keys" => keys, "version" => "1.0"})
  end

  defp config(options), do: Config.new!(options)

  defp gate(options, document) when is_map(document) or is_list(document),
    do: Gate.run(config(options), JCS.encode(document))

  defp reduced(%Run{rows: rows}), do: Enum.map(rows, &Row.reduce/1)

  defp steps(%Run{rows: rows}), do: Enum.map(rows, & &1.step)

  defp row(%Run{rows: rows}, step), do: Enum.find(rows, &(&1.step == step))

  defp spec_text, do: @spec_md |> File.read!() |> String.replace(~r/\s+/, " ")

  # ---------------------------------------------------------------------------------------
  # Step names and the rows that end a run

  describe "the steps" do
    test "are SPEC.md 10.2's table, in order" do
      names =
        ~r/^\| (\d+) \| ([A-Z_]+) \|/m
        |> Regex.scan(File.read!(@spec_md), capture: :all_but_first)
        |> Enum.map(fn [number, name] -> {String.to_integer(number), name} end)
        |> Enum.uniq()

      assert Enum.map(names, &elem(&1, 0)) == Enum.to_list(0..14)
      assert Enum.map(names, &elem(&1, 1)) == Run.steps()
    end

    test "a run ended at SHAPE gets skip prior_failure up to EXPECTED_HASH, part null" do
      {:ok, run} =
        gate([keyring: :none, environment: "test"], signed(proof(%{"environment" => "test"})))

      shape = Row.new("SHAPE", :shape_invalid, "/type", "made here")
      run = run |> Run.add_row(shape) |> Run.end_run()

      assert Enum.drop(reduced(run), 8) ==
               for(
                 step <- ~w(POLICY DERIVE CHAIN SOURCES WINDOW EXPECTED_HASH),
                 do: ["prior_failure", nil, "skip", step]
               )

      assert run.ended
    end
  end

  # ---------------------------------------------------------------------------------------
  # 0. CONFIGURATION

  describe "CONFIGURATION" do
    test "under prod with no keyring option, the compiled pin governs" do
      assert {:ok, run} = Gate.configuration(config([]))
      digest = Keyring.digest(File.read!(Path.join(@root, "spec/keyring.production.json")))
      assert run.trust_root == %{digest: digest, kind: :compiled_pin, location: nil}
      assert %Keyring{keys: []} = run.keyring
      assert reduced(run) == [[nil, nil, "pass", "CONFIGURATION"]]
    end

    test "the row's values hold strings, so a report writes them" do
      for {options, kind} <- [
            {[], "compiled_pin"},
            {[environment: "test", keyring: :none], "none"},
            {[environment: "staging", keyring: {:bytes, keyring_bytes([0x07]), nil}],
             "supplied_keyring"}
          ] do
        {:ok, run} = Gate.configuration(config(options))
        [row] = run.rows
        environment = Keyword.get(options, :environment, "prod")
        assert row.values == %{"environment" => environment, "trust_root" => kind}
        assert is_binary(JCS.encode(row.values))
      end
    end

    test "under any other E_v with no keyring option, configuration_error, no sub_reason" do
      for environment <- ~w(dev staging test) do
        assert {:rejected, %Rejection{code: :configuration_error, sub_reason: nil} = rejection} =
                 Gate.configuration(config(environment: environment))

        assert rejection.message =~ "--keyring FILE"
      end
    end

    test "keyless mode is allowed under every E_v, and no keyring governs" do
      for environment <- Config.environments() do
        assert {:ok, run} = Gate.configuration(config(environment: environment, keyring: :none))
        assert run.keyring == nil
        assert run.trust_root == %{digest: nil, kind: :none, location: nil}
      end
    end

    test "a keyring file loaded under prod is a production keyring, so a test key is refused" do
      bytes = keyring_bytes([0x07, 0x44])
      options = [keyring: {:bytes, bytes, "keyring.json"}]

      assert {:rejected, %Rejection{code: :configuration_error} = rejection} =
               Gate.configuration(config(options))

      assert rejection.message =~ "non-production"
      assert {:ok, run} = Gate.configuration(config([environment: "staging"] ++ options))

      assert run.trust_root == %{
               digest: Keyring.digest(bytes),
               kind: :supplied_keyring,
               location: "keyring.json"
             }
    end

    test "the vector case: --keyring FILE under prod holding a key of keys.nonproduction.json" do
      path =
        Path.join(
          Cases.vectors(),
          "negative/configuration-nonproduction_key-under-prod.keyring.json"
        )

      assert {:rejected, %Rejection{code: :configuration_error}} =
               Gate.configuration(config(keyring: {:file, path}))

      assert {:ok, %Run{trust_root: %{kind: :supplied_keyring, location: ^path}}} =
               Gate.configuration(config(environment: "test", keyring: {:file, path}))
    end

    test "a keyring file that cannot be read at all is no verification result" do
      path = Path.join(@root, "no-such-keyring.json")

      assert Gate.configuration(config(keyring: {:file, path})) ==
               {:error, {:unreadable, path, :enoent}}
    end

    test "a keyring over MAX_READ_OCTETS is configuration_error" do
      bytes = keyring_bytes([0x07]) <> String.duplicate(" ", 262_144)

      assert {:rejected, %Rejection{code: :configuration_error}} =
               Gate.configuration(config(keyring: {:bytes, bytes, nil}))
    end

    # Section 10.1 binds a keyring too, and a keyring that fails its load is
    # configuration_error (12.1), never READ's input_too_large.
    test "a keyring FILE over MAX_READ_OCTETS is configuration_error" do
      # Outside the repository, so that no file of this test is ever tracked.
      dir = Path.join(System.tmp_dir!(), "gate-test-#{System.unique_integer([:positive])}")
      File.mkdir_p!(dir)
      on_exit(fn -> File.rm_rf!(dir) end)

      bytes = keyring_bytes([0x07])
      path = Path.join(dir, "keyring.json")
      limit = Parser.max_read_octets()
      File.write!(path, bytes <> String.duplicate(" ", limit + 1 - byte_size(bytes)))
      assert File.stat!(path).size == limit + 1

      for environment <- ["prod", "staging"] do
        assert {:rejected, %Rejection{code: :configuration_error} = rejection} =
                 Gate.configuration(config(environment: environment, keyring: {:file, path}))

        assert rejection.message =~ "#{limit} octets"
      end

      File.write!(path, bytes <> String.duplicate(" ", limit - byte_size(bytes)))
      assert {:ok, _run} = Gate.configuration(config(keyring: {:file, path}))
    end

    test "comes before the file is read" do
      missing = Path.join(@root, "no-such-proof.json")

      assert {:rejected, %Rejection{code: :configuration_error}} =
               Gate.run_file(config(environment: "test"), missing)

      assert Gate.run_file(config([]), missing) == {:error, {:unreadable, missing, :enoent}}
    end
  end

  # ---------------------------------------------------------------------------------------
  # 1. READ and 2. PARSE

  describe "READ and PARSE" do
    test "J1 over the bytes and over a file: MAX_READ_OCTETS passes, one more does not" do
      document = JCS.encode(signed(proof()))
      pad = fn n -> document <> String.duplicate(" ", n - byte_size(document)) end

      assert {:ok, _run} = Gate.run(config(keyring: :none), pad.(262_144))

      assert {:rejected, %Rejection{code: :input_too_large, sub_reason: nil}} =
               Gate.run(config(keyring: :none), pad.(262_145))

      path = Path.join(Cases.vectors(), "negative/read-input-too-large.proof.json")

      assert {:rejected, %Rejection{code: :input_too_large}} =
               Gate.run_file(config(keyring: :none), path)
    end

    test "J2 to J6 give malformed_json with the rule" do
      for {bytes, rule} <- [
            {"{", :syntax},
            {<<0xFF>>, :invalid_utf8},
            {~s({"proof":{},"proof":{}}), :duplicate_name},
            {~s("\\ud800"), :lone_surrogate},
            {"9007199254740992", :number},
            {String.duplicate("[", 33) <> String.duplicate("]", 33), :depth}
          ] do
        assert {:rejected, %Rejection{code: :malformed_json, sub_reason: ^rule}} =
                 Gate.run(config(keyring: :none), bytes)
      end
    end
  end

  # ---------------------------------------------------------------------------------------
  # 3. ENVELOPE

  describe "ENVELOPE" do
    test "its checks are SPEC.md 10.2 step 3's, in order, and invalid_envelope's sub_reasons" do
      [_before, section] = String.split(File.read!(@spec_md), "**3. ENVELOPE.**", parts: 2)
      [list, _after] = String.split(section, "The message is", parts: 2)
      named = ~r/^\d\. `(\w+)`:/m |> Regex.scan(list, capture: :all_but_first) |> List.flatten()

      assert Enum.map(Gate.envelope_checks(), &Atom.to_string/1) == named
      assert Gate.envelope_checks() == ReasonCodes.sub_reasons(:invalid_envelope)
      assert Gate.alg() == "truestamp-ed25519-sha256-jcs"
      assert spec_text() =~ "`alg`: `alg` is the string `#{Gate.alg()}`"
    end

    test "the first check that fails names the sub_reason, when several fail" do
      good = signed(proof())
      signature = good["signature"]
      bad_k = %{signature | "public_key" => signature["public_key"] <> "\n"}
      bad_kv = %{bad_k | "value" => "x"}

      cases = [
        {[good], :document},
        {%{"proof" => 1, "signature" => 1}, :proof},
        {%{"proof" => %{}, "signature" => []}, :signature},
        {%{"proof" => %{}, "signature" => Map.delete(signature, "alg")}, :signature},
        {%{"proof" => %{}, "signature" => %{bad_kv | "alg" => "EdDSA"}}, :alg},
        {%{"proof" => %{}, "signature" => bad_kv}, :public_key},
        {%{"proof" => %{}, "signature" => %{signature | "value" => signature["value"] <> "\n"}},
         :value}
      ]

      for {document, sub_reason} <- cases do
        assert {:rejected, %Rejection{code: :invalid_envelope, sub_reason: ^sub_reason} = r} =
                 gate([keyring: :none], document),
               inspect({document, sub_reason})

        assert r.message == "This file is not a Truestamp proof."
      end
    end

    test "a signatures array and a top-level array are document" do
      good = signed(proof())

      for document <- [
            [good],
            [],
            %{"proof" => good["proof"], "signatures" => [good["signature"]]}
          ] do
        assert {:rejected, %Rejection{code: :invalid_envelope, sub_reason: :document}} =
                 gate([keyring: :none], document)
      end
    end

    test "a K that matches B64U32 but fails the checks of a key's bytes is public_key" do
      good = signed(proof())

      for k <- [<<1, 0::248>>, <<Integer.pow(2, 255) - 18::little-256>>] do
        document = put_in(good, ["signature", "public_key"], Base64url.encode(k))

        assert {:rejected, %Rejection{sub_reason: :public_key}} =
                 gate([keyring: :none], document)
      end
    end

    test "a passing envelope gives P, K and V to the later steps" do
      document = signed(proof())
      {public, _secret} = key_pair(0x42)
      {:ok, run} = gate([keyring: :none], document)
      assert run.proof == document["proof"]
      assert run.public_key == public
      assert {:ok, run.signature} == Base64url.decode(:b64u64, document["signature"]["value"])

      assert Enum.take(reduced(run), 4) ==
               for(step <- ~w(CONFIGURATION READ PARSE ENVELOPE), do: [nil, nil, "pass", step])
    end
  end

  # ---------------------------------------------------------------------------------------
  # 4. ENVIRONMENT

  describe "ENVIRONMENT" do
    # {E_v, the marker (:absent for none), whether the check passes}
    @table [
      {"prod", :absent, true},
      {"prod", "staging", false},
      {"prod", "prod", false},
      {"prod", "production", false},
      {"prod", nil, false},
      {"test", "test", true},
      {"staging", "staging", true},
      {"dev", "dev", true},
      {"staging", :absent, false},
      {"staging", "dev", false},
      {"test", "test\n", false},
      {"test", "TEST", false},
      {"test", 1, false},
      {"test", nil, false},
      {"test", ["test"], false},
      {"test", %{"test" => true}, false}
    ]

    test "passes exactly as section 6.4 says, one row at /environment" do
      for {e_v, marker, passes?} <- @table do
        fields = if marker == :absent, do: %{}, else: %{"environment" => marker}
        {:ok, run} = gate([environment: e_v, keyring: :none], signed(proof(fields)))
        row = row(run, "ENVIRONMENT")
        assert row.part == "/environment"
        assert row.status == if(passes?, do: :pass, else: :fail), inspect({e_v, marker})
        assert row.code == if(passes?, do: nil, else: :environment_mismatch)
      end
    end

    test "a failure ends the run: KEY_BINDING to EXPECTED_HASH are skip prior_failure" do
      {:ok, run} = gate([keyring: :none], signed(proof(%{"environment" => "staging"})))

      assert reduced(run) ==
               Enum.map(~w(CONFIGURATION READ PARSE ENVELOPE), &[nil, nil, "pass", &1]) ++
                 [["environment_mismatch", "/environment", "fail", "ENVIRONMENT"]] ++
                 Enum.map(
                   ~w(KEY_BINDING SIGNATURE SHAPE POLICY DERIVE CHAIN SOURCES WINDOW EXPECTED_HASH),
                   &["prior_failure", nil, "skip", &1]
                 )

      assert run.ended
      assert run.attribution == "none"
      assert run.proof_hash == nil
    end

    test "the message for a staging proof under prod is SPEC.md 6.4's" do
      [quoted] =
        Regex.run(
          ~r/For a staging proof under a production verifier it is: "([^"]+)"/,
          spec_text(),
          capture: :all_but_first
        )

      assert String.starts_with?(Gate.environment_message("prod", {:ok, "staging"}), quoted)
    end

    test "the message never quotes a marker it does not name" do
      unknown = [
        "prod",
        "production",
        "zq-unknown-marker",
        "Staging",
        "test\n",
        "",
        nil,
        7,
        [],
        %{}
      ]

      for e_v <- Config.environments(), marker <- unknown do
        message = Gate.environment_message(e_v, {:ok, marker})

        assert message ==
                 "This proof carries an environment marker that no Truestamp environment uses."

        refute message =~ "zq-unknown-marker"
      end
    end

    test "the message names a dev, staging or test marker, and says production for none" do
      for e_v <- Config.environments(), marker <- ~w(dev staging test), marker != e_v do
        message = Gate.environment_message(e_v, {:ok, marker})
        assert message =~ "Truestamp's #{marker} environment"
        assert message =~ "--environment #{marker}"
      end

      for e_v <- ~w(dev staging test) do
        message = Gate.environment_message(e_v, :error)
        assert message =~ "production proof"
        assert message =~ e_v
      end
    end

    test "the row's values hold the declared marker, which the message leaves out" do
      {:ok, run} =
        gate(
          [environment: "test", keyring: :none],
          signed(proof(%{"environment" => "zq-marker"}))
        )

      row = row(run, "ENVIRONMENT")
      assert row.values == %{"environment" => "test", "declared" => "zq-marker"}
      refute row.message =~ "zq-marker"
    end
  end

  # ---------------------------------------------------------------------------------------
  # 5. KEY_BINDING and 6. SIGNATURE

  describe "KEY_BINDING" do
    test "a supplied keyring holding K binds it, and the attribution is keyring:<d>" do
      bytes = keyring_bytes([0x07, 0x44])
      {public, _secret} = key_pair(0x44)
      options = [environment: "test", keyring: {:bytes, bytes, nil}]
      {:ok, run} = gate(options, signed(proof(%{"environment" => "test"}), 0x44))

      assert Enum.drop(reduced(run), 4) == [
               [nil, "/environment", "pass", "ENVIRONMENT"],
               [nil, nil, "pass", "KEY_BINDING"],
               [nil, nil, "pass", "SIGNATURE"]
             ]

      assert run.bound_key.public_key == public
      assert run.attribution == "keyring:" <> Keyring.digest(bytes)
      assert row(run, "KEY_BINDING").message == "The key this proof carries is in the keyring."
      refute run.ended
    end

    # SPEC.md 6.1: K binds to a key of the keyring that governs, active or not (8.1).
    test "an inactive key binds, and the proof it signed passes the gate" do
      bytes = keyring_bytes([0x07, {0x44, false}])
      {public, _secret} = key_pair(0x44)
      options = [environment: "test", keyring: {:bytes, bytes, nil}]
      {:ok, run} = gate(options, signed(proof(%{"environment" => "test"}), 0x44))

      assert Enum.drop(reduced(run), 4) == [
               [nil, "/environment", "pass", "ENVIRONMENT"],
               [nil, nil, "pass", "KEY_BINDING"],
               [nil, nil, "pass", "SIGNATURE"]
             ]

      assert %{public_key: ^public, active: false} = run.bound_key
      assert run.attribution == "keyring:" <> Keyring.digest(bytes)
      refute run.ended
    end

    # No shared case binds under the compiled pin (13.3), which holds no key yet, so this
    # binds a key that exists only here (the 0x07 seed's, as D69 does) under the real
    # compiled-pin trust root: only run.keyring is replaced.
    test "a key bound under the compiled pin is attributed to truestamp" do
      {public, _secret} = key_pair(0x07)
      {:ok, run} = Gate.configuration(config([]))
      assert run.trust_root.kind == :compiled_pin
      {:ok, keyring} = Keyring.load(keyring_bytes([0x07]), "prod")
      bytes = JCS.encode(signed(proof(), 0x07))

      {:ok, run} = Gate.read(%{run | keyring: keyring}, bytes)
      {:ok, run} = Gate.parse(run, bytes)
      {:ok, run} = Gate.envelope(run)
      run = run |> Gate.environment() |> Gate.key_binding() |> Gate.signature()

      assert reduced(run) ==
               Enum.map(~w(CONFIGURATION READ PARSE ENVELOPE), &[nil, nil, "pass", &1]) ++
                 [
                   [nil, "/environment", "pass", "ENVIRONMENT"],
                   [nil, nil, "pass", "KEY_BINDING"],
                   [nil, nil, "pass", "SIGNATURE"]
                 ]

      assert run.bound_key.public_key == public
      assert run.attribution == "truestamp"
      assert run.trust_root.kind == :compiled_pin
      refute run.ended
    end

    # SPEC.md 8.3: a keyring the operator supplies is attributed to its digest under every
    # E_v, prod included, never to truestamp (section 10.5).
    test "a supplied keyring under prod binds K, and the attribution is keyring:<d>" do
      bytes = keyring_bytes([0x07])
      location = "operator-keyring.json"
      {public, _secret} = key_pair(0x07)
      {:ok, run} = gate([keyring: {:bytes, bytes, location}], signed(proof(), 0x07))

      assert run.trust_root == %{
               kind: :supplied_keyring,
               digest: Keyring.digest(bytes),
               location: location
             }

      assert reduced(run) ==
               Enum.map(~w(CONFIGURATION READ PARSE ENVELOPE), &[nil, nil, "pass", &1]) ++
                 [
                   [nil, "/environment", "pass", "ENVIRONMENT"],
                   [nil, nil, "pass", "KEY_BINDING"],
                   [nil, nil, "pass", "SIGNATURE"]
                 ]

      assert run.bound_key.public_key == public
      assert run.attribution == "keyring:" <> Keyring.digest(bytes)
      refute run.ended
    end

    test "a K the keyring lacks fails key_binding_failed, and SIGNATURE is not made" do
      options = [environment: "test", keyring: {:bytes, keyring_bytes([0x07]), nil}]
      {:ok, run} = gate(options, signed(proof(%{"environment" => "test"}), 0x44))
      assert row(run, "KEY_BINDING").code == :key_binding_failed

      assert row(run, "KEY_BINDING").message ==
               "The key this proof carries is not in the supplied keyring."

      assert row(run, "SIGNATURE").code == :prior_failure
      assert run.proof_hash == nil
      assert run.attribution == "none"
    end

    test "under the compiled pin, the message says to update the verifier or run online" do
      {:ok, run} = gate([], signed(proof(), 0x07))
      row = row(run, "KEY_BINDING")
      assert row.code == :key_binding_failed
      assert row.message =~ "The key this proof carries is not among the keys built into"
      assert row.message =~ "update the verifier"
      assert row.message =~ "online"
    end

    test "keyless mode skips key binding, says so, and still checks the signature" do
      {:ok, run} = gate([keyring: :none], signed(proof()))
      row = row(run, "KEY_BINDING")
      assert {row.status, row.code, row.part} == {:skip, :key_binding_not_performed, nil}
      assert row.message =~ "only against the key the document carries"
      assert row(run, "SIGNATURE").status == :pass
      assert run.attribution == "unattributed"
    end

    # D58 item 13: keyless mode binds no key, so it treats VECTOR_KEY as any other key.
    test "keyless under prod treats VECTOR_KEY as any other key" do
      {:ok, run} = gate([keyring: :none], signed(proof(), 0x42))
      refute run.ended
      assert run.attribution == "unattributed"
    end
  end

  describe "SIGNATURE" do
    test "proof_hash is computed from P, so the worked example verifies in any formatting" do
      example = StrictJSON.read_data!(Path.join(Cases.vectors(), "worked-example.json"))

      options = [
        environment: "test",
        keyring: {:file, Path.join(Cases.vectors(), "keyring.test.json")}
      ]

      {:ok, %{"signature" => signature}} = Parser.parse(example["document"])

      # Re-indented with CRLF line ends, members reordered, a string escaped, 1.0 for 1.
      reformatted =
        ~s({\r\n  "signature" : ) <>
          JCS.encode(signature) <>
          ~s(,\r\n  "proof": {"version": 1.0, "type": "bl\\u006fck", ) <>
          ~s("format": "truestamp-proof", "environment": "test"}\r\n}\r\n)

      refute reformatted == example["document"]

      for bytes <- [example["document"], reformatted] do
        {:ok, run} = Gate.run(config(options), bytes)
        assert run.proof_hash == Base.decode16!(example["proof_hash"], case: :lower)
        assert row(run, "SIGNATURE").status == :pass
        assert row(run, "SIGNATURE").values == %{"proof_hash" => example["proof_hash"]}
      end
    end

    test "a proof changed after signing, or signed over M itself, is signature_invalid" do
      document = signed(proof(%{"environment" => "test"}))
      changed = put_in(document, ["proof", "environment"], "dev")
      {:ok, run} = gate([environment: "dev", keyring: :none], changed)
      assert row(run, "SIGNATURE").code == :signature_invalid
      assert run.attribution == "none"
      assert run.ended

      {_public, secret} = key_pair(0x42)
      over_m = :crypto.sign(:eddsa, :none, JCS.encode(document["proof"]), [secret, :ed25519])
      document = put_in(document, ["signature", "value"], Base64url.encode(over_m))
      {:ok, run} = gate([environment: "test", keyring: :none], document)
      assert row(run, "SIGNATURE").code == :signature_invalid
      assert row(run, "SIGNATURE").values["refused"] == "equation"
    end

    # D74: the checks of a key's bytes do not decode the point (6.2), so a K off the curve
    # passes ENVELOPE and fails at SIGNATURE, at step 4 of Verify.
    test "a K off the curve passes ENVELOPE and, keyless, fails signature_invalid" do
      k = <<2, 0::248>>
      assert Ed25519.check_key_bytes(k) == :ok
      assert Ed25519.decode_point(k) == {:error, :not_on_curve}

      document =
        proof(%{"environment" => "test"})
        |> signed()
        |> put_in(["signature", "public_key"], Base64url.encode(k))

      {:ok, run} = gate([environment: "test", keyring: :none], document)

      assert reduced(run) ==
               Enum.map(~w(CONFIGURATION READ PARSE ENVELOPE), &[nil, nil, "pass", &1]) ++
                 [
                   [nil, "/environment", "pass", "ENVIRONMENT"],
                   ["key_binding_not_performed", nil, "skip", "KEY_BINDING"],
                   ["signature_invalid", nil, "fail", "SIGNATURE"]
                 ] ++
                 Enum.map(
                   ~w(SHAPE POLICY DERIVE CHAIN SOURCES WINDOW EXPECTED_HASH),
                   &["prior_failure", nil, "skip", &1]
                 )

      assert row(run, "ENVELOPE").values == %{"key_id" => KeyId.of(k)}
      assert row(run, "SIGNATURE").values["refused"] == "not_on_curve"
      assert run.attribution == "none"
      assert run.ended
    end

    test "the gate's rows are in step order, one per step" do
      {:ok, run} = gate([keyring: :none], signed(proof()))
      assert steps(run) == Enum.take(Run.steps(), 7)
    end
  end

  # ---------------------------------------------------------------------------------------
  # Rows and rejections refuse codes that do not mean what they say

  describe "Row and Rejection" do
    test "a row takes its status from section 12.1, and refuses bare and unknown codes" do
      assert Row.new("SIGNATURE", :signature_invalid, nil, "m").status == :fail
      assert Row.new("KEY_BINDING", :key_binding_not_performed, nil, "m").status == :skip
      assert Row.pass("READ", nil, "m").code == nil
      assert_raise ArgumentError, fn -> Row.new("READ", :input_too_large, nil, "m") end
      assert_raise ArgumentError, fn -> Row.new("READ", :no_such_code, nil, "m") end
    end

    test "a rejection is bare, with a sub_reason exactly when its code lists them" do
      assert %Rejection{sub_reason: :alg} = Rejection.invalid_envelope(:alg)
      assert_raise ArgumentError, fn -> Rejection.invalid_envelope(:proof_hash) end
      assert_raise ArgumentError, fn -> Rejection.new(:malformed_json, "m") end
      assert_raise ArgumentError, fn -> Rejection.new(:configuration_error, "m", :keyring) end
      assert_raise ArgumentError, fn -> Rejection.new(:environment_mismatch, "m") end
    end
  end
end
