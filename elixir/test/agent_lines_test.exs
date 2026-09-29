# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Truestamp.Verifier.AgentLinesTest do
  # The agent-test entry point (SPEC.md 7.4): the lines it gives for a proof are the sound
  # proof's trace, proof_hash, Verify of each signature, the keyring lookup and the marker,
  # each computed whatever the others give; and its command line refuses what it cannot use.
  use ExUnit.Case, async: true

  alias Truestamp.Verifier.{AgentLines, Base64url, JCS, KeyId}
  alias Truestamp.Verifier.Test.{Cases, Signing, StrictJSON}

  @keyring "keyring.test.json"

  defp directory do
    dir = Path.join(System.tmp_dir!(), "agent-lines-#{System.unique_integer([:positive])}")
    File.mkdir_p!(dir)
    on_exit(fn -> File.rm_rf!(dir) end)
    File.cp!(Path.join(Cases.vectors(), @keyring), Path.join(dir, @keyring))
    dir
  end

  # The lines for the document `bytes` under the keyring file `keyring` in `dir`.
  defp lines(dir, bytes, keyring \\ @keyring) do
    File.write!(Path.join(dir, "proof.json"), bytes)
    run = %{"environment" => "test", "keyring" => keyring, "proof" => "proof.json"}
    AgentLines.lines(run, dir)
  end

  defp item_bytes, do: File.read!(Path.join(Cases.vectors(), "positive/item.proof.json"))

  defp document(bytes) do
    {:ok, document} = StrictJSON.decode(bytes)
    document
  end

  test "the sound item gives its trace, its digest, each signature valid, a match and test" do
    trace = StrictJSON.read_data!(Path.join(Cases.vectors(), "positive/item.trace.json"))

    {handovers, values} =
      Enum.split_with(trace, &String.ends_with?(&1["part"], "/handover_signature"))

    proof = document(item_bytes())["proof"]
    digest = :crypto.hash(:sha256, [<<0x50>>, JCS.encode(proof)]) |> Base.encode16(case: :lower)

    expected =
      Enum.map(values, fn row ->
        value =
          if is_integer(row["recomputed"]),
            do: Integer.to_string(row["recomputed"]),
            else: row["recomputed"]

        "/proof#{row["part"]} #{value}"
      end) ++
        Enum.map(handovers, &"/proof#{&1["part"]} valid") ++
        ["digest " <> digest, "/signature/value valid", "keyring match", "environment test"]

    assert handovers != []
    assert {:ok, lines} = lines(directory(), item_bytes())
    assert Enum.sort(lines) == Enum.sort(Enum.uniq(expected))
  end

  test "a signature altered and not signed again is invalid, and every other line stays" do
    dir = directory()
    {:ok, sound} = lines(dir, item_bytes())

    altered =
      update_in(document(item_bytes()), ["signature", "value"], fn <<c, rest::binary>> ->
        <<if(c == ?0, do: ?1, else: ?0), rest::binary>>
      end)

    {:ok, lines} = lines(dir, JCS.encode(altered))

    assert "/signature/value invalid" in lines
    assert lines -- ["/signature/value invalid"] == sound -- ["/signature/value valid"]
  end

  test "a key the keyring lacks is no-match, and its signature still valid" do
    dir = directory()
    {public, _secret} = Signing.key_pair(0x44)

    keyring = %{
      "keys" => [
        %{
          "active" => true,
          "key_id" => KeyId.of(public),
          "public_key" => Base64url.encode(public),
          "sequence" => 0
        }
      ],
      "version" => "1.0"
    }

    File.write!(Path.join(dir, "other.json"), JCS.encode(keyring))
    {:ok, lines} = lines(dir, item_bytes(), "other.json")

    assert "keyring no-match" in lines
    assert "/signature/value valid" in lines
  end

  test "a walk that gives no root is none, with the other lines still computed" do
    dir = directory()
    proof = put_in(Signing.positive("item"), ["subject", "inclusion_proof", "leaf_index"], 3)
    {:ok, lines} = lines(dir, Signing.signed(proof, 0x42))

    assert "/proof/block/record/merkle_root none" in lines
    assert "/proof/subject/inclusion_proof/tree_size 3" in lines
    assert "/signature/value valid" in lines
  end

  test "a staging marker is its own line, and a proof with none is prod" do
    dir = directory()
    staging = Signing.signed(Map.put(Signing.positive("item"), "environment", "staging"), 0x42)
    production = Signing.signed(Map.delete(Signing.positive("item"), "environment"), 0x42)

    assert {:ok, lines} = lines(dir, staging)
    assert "environment staging" in lines
    assert {:ok, lines} = lines(dir, production)
    assert "environment prod" in lines
  end

  test "a handover altered is invalid at its pointer" do
    dir = directory()
    e = ["signing_key_event", "block", "record", "metadata", "key_event", "handover_signature"]

    proof =
      update_in(Signing.positive("item"), e, fn <<c, rest::binary>> ->
        <<if(c == ?0, do: ?1, else: ?0), rest::binary>>
      end)

    {:ok, lines} = lines(dir, Signing.signed(proof, 0x42))

    assert "/proof/signing_key_event/block/record/metadata/key_event/handover_signature invalid" in lines
  end

  test "a proof that fails SHAPE still gets its lines when DERIVE can read it" do
    dir = directory()
    {:ok, sound} = lines(dir, item_bytes())
    bad = Signing.signed(Map.put(Signing.positive("item"), "format", "other"), 0x42)
    {:ok, lines} = lines(dir, bad)

    changed = ["digest", "/signature/value"]

    keep =
      &Enum.reject(&1, fn line -> Enum.any?(changed, fn c -> String.starts_with?(line, c) end) end)

    assert keep.(lines) == keep.(sound)
    assert "/signature/value valid" in lines

    # An empty-root rule broken in the witness block: SHAPE's schema refuses it, and the line
    # at the block's hash is still the hash of the record it carries.
    w = ["witnesses", "block", "record", "merkle_root"]
    proof = put_in(Signing.positive("item"), w, String.duplicate("ab", 32))
    {:ok, lines} = lines(dir, Signing.signed(proof, 0x42))
    record = get_in(proof, ["witnesses", "block", "record"])
    hash = :crypto.hash(:sha256, [<<0x31>>, JCS.encode(record)]) |> Base.encode16(case: :lower)
    assert "/proof/witnesses/block/block_hash #{hash}" in lines
  end

  test "a proof whose layout DERIVE cannot read, or that cannot be read, is an error entry" do
    dir = directory()
    unreadable = Signing.signed(Map.put(Signing.positive("item"), "block", "not a block"), 0x42)
    assert {:error, "SHAPE fails: shape_invalid" <> why} = lines(dir, unreadable)
    assert why =~ "DERIVE cannot read it"

    runs = [
      %{
        "environment" => "test",
        "id" => "missing",
        "keyring" => @keyring,
        "proof" => "missing.json"
      }
    ]

    File.write!(Path.join(dir, "runs.json"), JCS.encode(runs))
    assert {0, stdout, _stderr} = AgentLines.main([Path.join(dir, "runs.json")])

    assert {:ok, [%{"error" => _why, "id" => "missing"}]} =
             stdout |> IO.iodata_to_binary() |> StrictJSON.decode()
  end

  test "a Bitcoin entry whose header misses its target keeps the lines of its header" do
    dir = directory()
    {:ok, sound} = lines(dir, item_bytes())
    at = ["commitments", "bitcoin", "txoutproof"]
    proof = Signing.positive("item")

    <<front::binary-72, _bits::binary-4, rest::binary>> =
      proof |> get_in(at) |> Base.decode16!(case: :lower)

    hard = front <> <<0xFF, 0xFF, 0x00, 0x1D>> <> rest
    <<header::binary-80, _proof::binary>> = hard
    proof = put_in(proof, at, Base.encode16(hard, case: :lower))
    {:ok, lines} = lines(dir, Signing.signed(proof, 0x42))

    hash =
      :crypto.hash(:sha256, :crypto.hash(:sha256, header))
      |> :binary.bin_to_list()
      |> Enum.reverse()
      |> :binary.list_to_bin()
      |> Base.encode16(case: :lower)

    n = "/proof/commitments/bitcoin/"
    assert "#{n}header_hash #{hash}" in lines
    assert Enum.find(sound, &String.starts_with?(&1, n <> "header_merkle_root ")) in lines
    assert Enum.find(sound, &String.starts_with?(&1, n <> "header_time ")) in lines
  end

  test "a fault inside the entry point exits 2, with nothing on stdout" do
    # A path that is no string reaches String.valid?/1, which raises.
    {code, stdout, stderr} = AgentLines.main([123])
    assert {code, IO.iodata_to_binary(stdout)} == {2, ""}
    assert IO.iodata_to_binary(stderr) =~ "A fault inside the agent-test entry point: "
  end

  test "a command line or a runs file it cannot use exits 1, with nothing on standard output" do
    dir = directory()
    path = Path.join(dir, "runs.json")

    assert {1, "", _stderr} = AgentLines.main([])

    for runs <- [
          %{},
          [%{"environment" => "test", "id" => "x", "keyring" => @keyring}],
          [
            %{
              "environment" => "test",
              "extra" => 1,
              "id" => "x",
              "keyring" => @keyring,
              "proof" => "p"
            }
          ],
          [%{"environment" => "production", "id" => "x", "keyring" => @keyring, "proof" => "p"}]
        ] do
      File.write!(path, JCS.encode(runs))
      assert {1, "", _stderr} = AgentLines.main([path])
    end
  end
end
