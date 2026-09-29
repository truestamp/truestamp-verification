# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Truestamp.Verifier.OfflineStepsTest do
  # Steps 10 to 14 of SPEC.md 10.2 (CHAIN, SOURCES, WINDOW, EXPECTED_HASH, VERDICT) as the
  # offline reference verifier makes them, and the fault rule of 10.5 and 12.2, on runs built
  # here from the sound proofs, for what the shared cases do not pin: KEY_EVENT_COMMITMENT's
  # absence without signing_key_event, CHAIN and SOURCES under each state of the external
  # gate, WINDOW's values, each branch of EXPECTED_HASH and its message, the labels no shared
  # case reaches (internally-consistent, and verified, 13.3), the run's code with several
  # failing rows, and a fault caught at each point.
  use ExUnit.Case, async: true

  alias Truestamp.Verifier

  alias Truestamp.Verifier.{Chain, Config, ExpectedHash, Gate, Row, Run, Sources, Verdict, Window}

  import Truestamp.Verifier.Test.Signing, only: [positive: 1, signed: 2, truestamp_run: 1]

  @root Path.expand("../../..", __DIR__)
  @gate_steps ~w(ENVIRONMENT KEY_BINDING SIGNATURE)
  @spec_md Path.join(@root, "SPEC.md")
  @external_resource @spec_md

  # ---------------------------------------------------------------------------------------
  # Helpers

  # A keyless run of `proof`, signed by VECTOR_KEY under E_v test, through steps 0 to 3 and
  # then each later step before `before`.
  defp run_until(proof, before, options \\ []) do
    config = Config.new!(Keyword.merge([environment: "test", keyring: :none], options))
    {:ok, run} = Gate.admit(config, signed(proof, 0x42))

    Verifier.steps_after_envelope()
    |> Enum.take_while(fn {name, _function} -> name != before end)
    |> Enum.reduce(run, fn {name, function}, run -> Verifier.step(run, name, function) end)
  end

  defp step_rows(%Run{rows: rows}, step), do: for(%Row{step: ^step} = row <- rows, do: row)

  defp reduced(rows), do: Enum.map(rows, &Row.reduce/1)

  # ---------------------------------------------------------------------------------------
  # 10. CHAIN

  describe "CHAIN" do
    test "offline: one skip offline row per entry in document order, KEY_EVENT_COMMITMENT last" do
      run = run_until(positive("item"), "SOURCES")

      assert reduced(step_rows(run, "CHAIN")) ==
               Enum.map(
                 ~w(/commitments/bitcoin /commitments/stellar
                    /signing_key_event/commitments/bitcoin
                    /signing_key_event/commitments/stellar /signing_key_event),
                 &["offline", &1, "skip", "CHAIN"]
               )

      assert Enum.all?(step_rows(run, "CHAIN"), &(&1.values == %{}))
    end

    test "gives no KEY_EVENT_COMMITMENT row when the proof carries no signing_key_event" do
      run = run_until(Map.delete(positive("block"), "signing_key_event"), "SOURCES")
      parts = run |> step_rows("CHAIN") |> Enum.map(& &1.part)
      assert parts != [] and "/signing_key_event" not in parts
      refute Enum.any?(parts, &String.starts_with?(&1, "/signing_key_event"))
    end

    test "after a failure at POLICY or DERIVE: skip prior_failure at each part" do
      run = run_until(positive("item"), "CHAIN")
      failed = %{run | external_gate: :prior_failure}

      assert failed |> Chain.chain() |> step_rows("CHAIN") |> Enum.map(&{&1.code, &1.status}) ==
               List.duplicate({:prior_failure, :skip}, 5)
    end

    test "each offline message names the read that would confirm its row (10.4, 12.1)" do
      # Each CHAIN and SOURCES row of the sound proofs, by the kind of its part: what its
      # message names, and what it never names.
      rows =
        for name <- ~w(item block block-rotation beacon entropy_bitcoin entropy_nist
                       entropy_stellar),
            row <- run_until(positive(name), "WINDOW").rows,
            row.step in ~w(CHAIN SOURCES),
            do: {offline_kind(name, row.part), row}

      kinds = rows |> Enum.map(&elem(&1, 0)) |> Enum.uniq() |> Enum.sort()

      assert kinds ==
               Enum.sort(~w(bitcoin_entry stellar_entry key_event_bitcoin_entry
                            key_event_stellar_entry genesis key_event_commitment
                            nist_entropy stellar_entropy bitcoin_entropy)a)

      for {kind, row} <- rows do
        assert row.code == :offline
        {names, never} = offline_words(kind)
        for word <- names, do: assert(row.message =~ word, "#{row.part}: #{word}")
        for word <- never, do: refute(row.message =~ word, "#{row.part}: #{word}")
      end
    end

    test "a run with no decided external gate is a fault, caught as internal_error" do
      run = %{run_until(positive("item"), "CHAIN") | external_gate: nil}
      assert_raise FunctionClauseError, fn -> Chain.chain(run) end

      run = Verifier.step(run, "CHAIN", &Chain.chain/1)
      assert [%Row{code: :internal_error, part: nil, status: :fail}] = step_rows(run, "CHAIN")
      assert run.ended
    end
  end

  # The kind of a CHAIN or SOURCES row of the sound proof `name` at `part`.
  defp offline_kind(_name, "/commitments/bitcoin"), do: :bitcoin_entry
  defp offline_kind(_name, "/commitments/stellar"), do: :stellar_entry
  defp offline_kind(_name, "/signing_key_event/commitments/bitcoin"), do: :key_event_bitcoin_entry
  defp offline_kind(_name, "/signing_key_event/commitments/stellar"), do: :key_event_stellar_entry
  defp offline_kind(_name, "/signing_key_event"), do: :key_event_commitment
  defp offline_kind("entropy_" <> source, "/subject/entropy"), do: entropy_kind(source)

  defp offline_kind(_name, part) do
    case Regex.run(~r{/genesis/bitcoin$|entropy_(nist|stellar|bitcoin)}, part) do
      [_genesis] -> :genesis
      [_entropy, source] -> entropy_kind(source)
    end
  end

  defp entropy_kind("nist"), do: :nist_entropy
  defp entropy_kind("stellar"), do: :stellar_entropy
  defp entropy_kind("bitcoin"), do: :bitcoin_entropy

  # {what the message names, what it never names}.
  defp offline_words(:stellar_entry),
    do: {["Offline", "Stellar transaction", "submitted-before edge"], ["Bitcoin", "NIST"]}

  defp offline_words(:bitcoin_entry),
    do: {["Offline", "Bitcoin block", "submitted-before edge"], ["Stellar", "NIST"]}

  defp offline_words(:key_event_stellar_entry),
    do: {["Offline", "Stellar transaction"], ["Bitcoin", "NIST", "edge"]}

  defp offline_words(:key_event_bitcoin_entry),
    do: {["Offline", "Bitcoin block"], ["Stellar", "NIST", "edge"]}

  defp offline_words(:genesis),
    do: {["Offline", "Bitcoin block", "genesis block"], ["Stellar", "NIST", "edge"]}

  defp offline_words(:key_event_commitment),
    do: {["Offline", "signing key event", "commitment entries"], ["NIST", "edge"]}

  defp offline_words(:nist_entropy),
    do:
      {["Offline", "NIST Randomness Beacon pulse", "submitted-after edge"],
       ["Stellar", "Bitcoin"]}

  defp offline_words(:stellar_entropy),
    do: {["Offline", "Stellar ledger", "submitted-after edge"], ["Bitcoin", "NIST"]}

  defp offline_words(:bitcoin_entropy),
    do: {["Offline", "Bitcoin block", "submitted-after edge"], ["Stellar", "NIST"]}

  # ---------------------------------------------------------------------------------------
  # 11. SOURCES

  describe "SOURCES" do
    test "one row per entropy object, NIST's included, in document order" do
      assert run_until(positive("item"), "WINDOW") |> step_rows("SOURCES") |> reduced() ==
               Enum.map(
                 ~w(/witnesses/entropy_bitcoin /witnesses/entropy_nist /witnesses/entropy_stellar),
                 &["offline", &1, "skip", "SOURCES"]
               )

      assert run_until(positive("entropy_nist"), "WINDOW") |> step_rows("SOURCES") |> reduced() ==
               [["offline", "/subject/entropy", "skip", "SOURCES"]]

      assert run_until(positive("beacon-empty"), "WINDOW") |> step_rows("SOURCES") == []
    end

    test "after a failure at POLICY or DERIVE: skip prior_failure" do
      run = %{run_until(positive("beacon"), "SOURCES") | external_gate: :prior_failure}
      rows = run |> Sources.sources() |> step_rows("SOURCES")
      assert length(rows) == 3 and Enum.all?(rows, &(&1.code == :prior_failure))
    end
  end

  # ---------------------------------------------------------------------------------------
  # 12. WINDOW

  describe "WINDOW" do
    test "offline, the reason for each absent edge is its CHAIN and SOURCES rows" do
      [row] = run_until(positive("item"), "EXPECTED_HASH") |> step_rows("WINDOW")
      assert {row.code, row.part, row.status} == {:window_not_established, nil, :info}

      reason = &%{"code" => "offline", "part" => &1}

      assert row.values == %{
               "absent" => %{
                 "submitted_after" =>
                   Enum.map(
                     ~w(/witnesses/entropy_bitcoin /witnesses/entropy_nist
                        /witnesses/entropy_stellar),
                     reason
                   ),
                 "submitted_before" =>
                   Enum.map(~w(/commitments/bitcoin /commitments/stellar), reason)
               },
               "candidates" => []
             }
    end

    test "a block proof's submitted-after edge has an empty list of reasons" do
      [row] = run_until(positive("block"), "EXPECTED_HASH") |> step_rows("WINDOW")
      assert row.values["absent"]["submitted_after"] == []
      assert length(row.values["absent"]["submitted_before"]) == 2
    end

    test "after any failed row: skip prior_failure, whatever step failed" do
      run = run_until(positive("item"), "WINDOW")
      failing = Row.new("SOURCES", :entropy_mismatch, "/witnesses/entropy_nist", "made here")
      [row] = run |> Run.add_row(failing) |> Window.window() |> step_rows("WINDOW")
      assert {row.code, row.part, row.status} == {:prior_failure, nil, :skip}
    end
  end

  # ---------------------------------------------------------------------------------------
  # 13. EXPECTED_HASH

  describe "EXPECTED_HASH" do
    # The item proof's claims hold an md5 hash; the rotation-witness item's a sha256 hash.
    @md5 "69e3941192b086bfdc0e4e120c18ff12"

    defp expected_row(proof, expected_hash) do
      [row] =
        proof
        |> run_until("EXPECTED_HASH", expected_hash: expected_hash)
        |> ExpectedHash.expected_hash()
        |> step_rows("EXPECTED_HASH")

      row
    end

    defp claims(proof, fields),
      do: update_in(proof, ["subject", "claims"], &Map.merge(&1, fields))

    test "with no hash given: skip expected_hash_not_checked, part null" do
      row = expected_row(positive("item"), nil)
      assert {row.code, row.part, row.status} == {:expected_hash_not_checked, nil, :skip}
    end

    test "each branch, at /subject/claims/hash, with values saying why" do
      sha256 = positive("item-rotation-witness")["subject"]["claims"]["hash"]

      branches = [
        {positive("item-rotation-witness"), sha256, nil, nil},
        {positive("item-rotation-witness"), String.upcase(sha256), nil, nil},
        {positive("item"), @md5, :expected_hash_weak_algorithm, nil},
        {claims(positive("item"), %{"hash_type" => "sha1", "hash" => String.duplicate("a", 40)}),
         String.duplicate("A", 40), :expected_hash_weak_algorithm, nil},
        {positive("item"), "0" <> String.slice(@md5, 1..-1//1), :expected_hash_mismatch,
         "differs"},
        {positive("item"), @md5 <> "00", :expected_hash_mismatch, "not_hex_of_length"},
        {positive("item"), String.duplicate("g", 32), :expected_hash_mismatch,
         "not_hex_of_length"},
        {positive("block"), @md5, :expected_hash_mismatch, "no_listed_hash"},
        {positive("entropy_nist"), @md5, :expected_hash_mismatch, "no_listed_hash"},
        {claims(positive("item"), %{"hash_type" => "crc32"}), @md5, :expected_hash_mismatch,
         "no_listed_hash"},
        {claims(positive("item"), %{"hash_type" => "MD5"}), @md5, :expected_hash_mismatch,
         "no_listed_hash"},
        {claims(positive("item"), %{"hash" => 7}), @md5, :expected_hash_mismatch,
         "no_listed_hash"},
        {update_in(positive("item"), ["subject", "claims"], &Map.delete(&1, "hash")), @md5,
         :expected_hash_mismatch, "no_listed_hash"},
        # Only the caller's value is lowercased: a proof's hash in capitals never matches.
        {claims(positive("item"), %{"hash" => String.upcase(@md5)}), @md5,
         :expected_hash_mismatch, "differs"}
      ]

      for {proof, given, code, reason} <- branches do
        row = expected_row(proof, given)

        assert {row.code, row.part, row.values["reason"]} ==
                 {code, "/subject/claims/hash", reason}

        assert row.values["expected_hash"] == String.downcase(given)
      end
    end

    test "a failed comparison gives the declared hash; a match gives no value of the proof" do
      mismatch = expected_row(positive("item"), String.duplicate("0", 32))
      assert mismatch.values["declared"] == @md5

      assert expected_row(positive("item"), @md5).values == %{"expected_hash" => @md5}

      too_short = expected_row(positive("item"), "abc")

      assert too_short.values["hex_characters"] == 32 and
               not Map.has_key?(too_short.values, "declared")
    end

    test "a match not attributed to Truestamp says so; one attributed to Truestamp does not" do
      assert expected_row(positive("item"), @md5).message =~ "not attributed to Truestamp"

      proof = Map.delete(positive("item-rotation-witness"), "signing_key_event")
      sha256 = proof["subject"]["claims"]["hash"]
      base = truestamp_run(proof)

      run = %{
        base
        | config: %{base.config | expected_hash: sha256},
          rows: Enum.reject(base.rows, &(&1.step == "EXPECTED_HASH"))
      }

      [row] = run |> ExpectedHash.expected_hash() |> step_rows("EXPECTED_HASH")
      assert row.status == :pass and run.attribution == "truestamp"
      refute row.message =~ "not attributed"
    end

    test "a failure at POLICY or DERIVE does not stop it; a failure at SHAPE does" do
      run = run_until(positive("item"), "EXPECTED_HASH", expected_hash: @md5)
      policy = Row.new("POLICY", :network_mismatch, "/commitments/bitcoin/network", "made here")

      [row] =
        run |> Run.add_row(policy) |> ExpectedHash.expected_hash() |> step_rows("EXPECTED_HASH")

      assert row.code == :expected_hash_weak_algorithm

      ended =
        run_until(Map.put(positive("item"), "version", 2), "EXPECTED_HASH", expected_hash: @md5)

      assert [%Row{code: :prior_failure, part: nil}] = step_rows(ended, "EXPECTED_HASH")
      assert ExpectedHash.expected_hash(ended) == ended
    end

    test "the table of hash types is SPEC.md 10.2 step 13's" do
      spec = File.read!(@spec_md)
      [_before, after_heading] = String.split(spec, "| `hash_type` | Hex characters |", parts: 2)
      [table | _rest] = String.split(after_heading, "\n\n", parts: 2)

      rows =
        for [names, length] <-
              Regex.scan(~r/^\| (.+) \| (\d+) \|$/m, table, capture: :all_but_first),
            name <- Regex.scan(~r/`(\w+)`/, names, capture: :all_but_first) |> List.flatten(),
            into: %{},
            do: {name, String.to_integer(length)}

      assert map_size(rows) == 12
      assert ExpectedHash.hex_characters() == rows
    end
  end

  # ---------------------------------------------------------------------------------------
  # 14. VERDICT

  describe "VERDICT" do
    test "internally-consistent: attributed to Truestamp under the compiled pin, no edge" do
      run = truestamp_run(Map.delete(positive("item"), "signing_key_event"))

      assert run.attribution == "truestamp"
      refute Run.failed?(run)
      assert run.label == "internally-consistent" and run.code == nil
      assert run.submitted_before == nil
    end

    test "under Truestamp's key, a key event that does not introduce K fails the run" do
      run = truestamp_run(positive("item"))

      assert run.attribution == "truestamp"
      assert {run.label, run.code} == {"failed", :key_event_mismatch}

      assert [%Row{code: :prior_failure, status: :skip}] =
               Enum.filter(run.rows, &(&1.part == "/signing_key_event"))
    end

    test "verified, once a submitted-before edge exists; failed nulls both edges" do
      run = truestamp_run(Map.delete(positive("item"), "signing_key_event"))
      edge = %{"basis" => "stellar_ledger_close_read", "instant" => "2026-09-26T01:48:00Z"}

      assert Verdict.verdict(%{run | submitted_before: edge}).label == "verified"

      failing = Row.new("CHAIN", :chain_mismatch, "/commitments/stellar", "made here")

      failed =
        Verdict.verdict(%{
          Run.add_row(run, failing)
          | submitted_before: edge,
            submitted_after: edge
        })

      assert {failed.label, failed.code} == {"failed", :chain_mismatch}
      assert failed.submitted_before == nil and failed.submitted_after == nil
    end

    test "unattributed and supplied-keyring follow the attribution" do
      run = run_until(positive("block"), "VERDICT") |> Verdict.verdict()
      assert {run.attribution, run.label} == {"unattributed", "unattributed"}

      keyring = {:file, Path.join(@root, "vectors/keyring.test.json")}
      run = run_until(positive("block"), "VERDICT", keyring: keyring) |> Verdict.verdict()
      assert "keyring:" <> _digest = run.attribution
      assert run.label == "supplied-keyring"
    end

    test "the run's code is its first failing row's, in step order, not the last or the rarest" do
      run = run_until(positive("item"), "VERDICT", expected_hash: "00")
      policy = Row.new("POLICY", :network_mismatch, "/commitments/bitcoin/network", "made here")
      rows = Enum.flat_map(run.rows, &if(&1.step == "POLICY", do: [&1, policy], else: [&1]))
      failed = Verdict.verdict(%{run | rows: rows})
      assert failed.code == :network_mismatch

      assert Verdict.verdict(run).code == :expected_hash_mismatch
    end
  end

  # ---------------------------------------------------------------------------------------
  # Faults (SPEC.md 10.5 and 12.2)

  describe "a fault" do
    test "caught at ENVIRONMENT is an internal_error row, the attribution none, the run ended" do
      config = Config.new!(environment: "test", keyring: :none)
      {:ok, admitted} = Gate.admit(config, signed(positive("item"), 0x42))

      for fault <- [
            fn _run -> raise "boom" end,
            fn _run -> throw(:boom) end,
            fn _run -> exit(:boom) end
          ] do
        run = Verifier.step(admitted, "ENVIRONMENT", fault)

        assert [%Row{code: :internal_error, part: nil, status: :fail} = row] =
                 step_rows(run, "ENVIRONMENT")

        assert Map.keys(row.values) == ~w(kind module)
        assert row.values["kind"] in ~w(error throw exit)
        assert row.values["module"] == if(row.values["kind"] == "error", do: "RuntimeError")
        assert row.message =~ "stopped step ENVIRONMENT"
        refute row.message =~ "boom"
        assert run.attribution == "none" and run.ended

        assert run.rows |> Enum.drop(5) |> reduced() ==
                 for(
                   step <-
                     ~w(KEY_BINDING SIGNATURE SHAPE POLICY DERIVE CHAIN SOURCES WINDOW EXPECTED_HASH),
                   do: ["prior_failure", nil, "skip", step]
                 )

        run = Verdict.verdict(run)
        assert {run.label, run.code} == {"failed", :internal_error}
      end
    end

    test "at ENVIRONMENT, KEY_BINDING or SIGNATURE, from the real steps, is caught there" do
      keyring = {:file, Path.join(@root, "vectors/keyring.test.json")}

      # Each run is admitted, then broken so that one gate step raises on it: ENVIRONMENT
      # reads the proof, KEY_BINDING the carried key under a keyring, and SIGNATURE, after
      # the signature verifies, the trust root's kind.
      for {step, options, break} <- [
            {"ENVIRONMENT", [], &%{&1 | proof: []}},
            {"KEY_BINDING", [keyring: keyring], &%{&1 | public_key: :not_a_key}},
            {"SIGNATURE", [], &%{&1 | trust_root: %{&1.trust_root | kind: :not_a_kind}}}
          ] do
        config = Config.new!(Keyword.merge([environment: "test", keyring: :none], options))
        {:ok, admitted} = Gate.admit(config, signed(positive("item"), 0x42))
        run = Verifier.after_envelope(break.(admitted))

        later = ~w(ENVIRONMENT KEY_BINDING SIGNATURE SHAPE POLICY DERIVE CHAIN SOURCES WINDOW
                   EXPECTED_HASH) |> Enum.drop_while(&(&1 != step)) |> tl()

        {before, from_fault} =
          run.rows
          |> reduced()
          |> Enum.split_while(&(&1 != ["internal_error", nil, "fail", step]))

        refute Enum.any?(before, &(Enum.at(&1, 2) == "fail"))
        assert length(before) == 4 + Enum.find_index(@gate_steps, &(&1 == step))

        assert from_fault ==
                 [["internal_error", nil, "fail", step]] ++
                   for(later_step <- later, do: ["prior_failure", nil, "skip", later_step])

        assert [%Row{code: :internal_error, part: nil}] = step_rows(run, step)
        assert {run.label, run.code, run.attribution} == {"failed", :internal_error, "none"}
      end
    end

    test "gives only the fault's kind and module, never a value of the proof it met" do
      run = run_until(positive("item"), "SHAPE")
      claims = positive("item")["subject"]["claims"]

      faulted =
        Verifier.step(run, "SHAPE", fn run ->
          {:claims, _claims} = run.proof["subject"]["claims"]
          run
        end)

      [row] = step_rows(faulted, "SHAPE")
      assert row.values == %{"kind" => "error", "module" => "MatchError"}
      refute row.message =~ claims["hash"]
      assert row.message =~ "MatchError"
    end

    test "caught at DERIVE keeps the attribution and discards the step's partial rows" do
      run = run_until(positive("item"), "DERIVE")

      faulted =
        Verifier.step(run, "DERIVE", fn run ->
          partial = Run.add_row(run, Row.pass("DERIVE", "/subject/item_hash", "partial"))
          send(self(), {:partial, partial})
          raise "a fault after a partial row"
        end)

      assert_received {:partial, %Run{rows: [_ | _] = partial_rows}}
      assert Enum.any?(partial_rows, &(&1.message == "partial"))
      refute Enum.any?(faulted.rows, &(&1.message == "partial"))
      assert faulted.attribution == "unattributed"
      assert [%Row{code: :internal_error}] = step_rows(faulted, "DERIVE")
      assert [%Row{code: :prior_failure, part: nil}] = step_rows(faulted, "CHAIN")
    end

    test "from a configuration no command line makes: at POLICY, a failed report" do
      config = %{Config.new!(environment: "test", keyring: :none) | networks: :not_pins}
      assert {:ok, run} = Verifier.run(config, signed(positive("item"), 0x42))
      assert [%Row{code: :internal_error}] = step_rows(run, "POLICY")
      assert run.label == "failed" and run.code == :internal_error
    end

    test "before steps 0 to 3 have passed gives no report" do
      config = %{Config.new!(keyring: :none) | environment: %{}}
      assert {:fault, description} = Verifier.run(config, signed(positive("item"), 0x42))
      assert description =~ "Protocol.UndefinedError"
    end
  end
end
