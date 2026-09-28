# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Generator.Model.Online do
  @moduledoc """
  The online part of the expected-output model (Generator.Model), for a case whose `config`
  names a replay file (SPEC.md 13.2). The file answers every read the run makes, and stands as
  the operator-pinned source for each Stellar and Bitcoin network whose identity read it holds.
  Like the rest of the model it is the generator's own reading of SPEC.md, shared with no
  verifier:

  - Step 0 (SPEC.md 10.2): for each Stellar and Bitcoin network the case pins, as a
    commitment pin or an entropy pin, the source's identity read, every one of them made
    (bad_identities/1). A value step 0 forbids is `configuration_error`, and so is regtest
    with no identity read, since regtest has no default source. An identity read with no
    usable answer makes each row that source serves `skip source_unreachable`, and nothing
    else is read from it. Under E_v `prod` with no keyring option, the keyring read at
    www.truestamp.com (keyring/1), which Generator.Model then loads: a read that does not give
    a keyring passing the load checks, for any reason, binds no key.
  - CHAIN (step 10), by SPEC.md 10.4: each commitment entry, each `genesis.bitcoin`, and the
    status of KEY_EVENT_COMMITMENT from its inputs (SPEC.md 10.3). A top-level entry's row
    that passes carries its candidate for the submitted-before edge.
  - SOURCES (step 11): each entropy object, whose row that passes carries its candidate for
    the submitted-after edge.
  - WINDOW (step 12), by SPEC.md 11: its row, the `info recorded_time_outside_window` row,
    and the two edges, each the earliest or the latest candidate, and of candidates at one
    instant the first in row order.

  An outcome is `{status, code, candidate}`, where candidate is nil or `%{basis, instant,
  part}`, `instant` the time read at its source's precision (SPEC.md 11.5): a Stellar
  `closed_at` and a NIST `timeStamp` as read, and a Bitcoin median time past, the source's
  report of it (SPEC.md 10.4 and 13.2), formatted as TIME.

  The case cannot be built, and the model raises, when the run makes a read its replay does
  not hold, since a verifier making that read finds no answer (SPEC.md 13.2), and when the
  case pins a network other than regtest whose identity read the replay does not hold, since
  a verifier would then read that network from a compiled-in default source.
  """

  alias Generator.{BitcoinParse, Bytes, JCS, Parse, Pointer, Registry, Spec}

  @keyring_url "https://www.truestamp.com/.well-known/keyring.json"
  @top ~w(/commitments/bitcoin /commitments/stellar)
  @crockford "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

  @doc """
  The replay `config` names, read from `files`, with the case's pins, or nil for an offline
  case: `%{path, answers, pins, sources}`, where `answers` maps each read to its answer.
  """
  def replay(config, files) do
    case Map.fetch(config, "online") do
      :error ->
        nil

      {:ok, path} ->
        bytes =
          Map.get(files, "vectors/" <> path) ||
            raise ArgumentError,
                  "the online case's replay #{path} is no file the generator writes"

        %{"reads" => records} = Parse.decode!(bytes)

        %{
          path: path,
          answers: Map.new(records, &{&1["read"], &1["answer"]}),
          pins: Map.fetch!(config, "networks"),
          sources: %{}
        }
    end
  end

  # Step 0.

  @doc """
  Step 0's identity reads for the replay `online`: `{:ok, online}`, with each pinned Stellar
  and Bitcoin network's source `:ok` or `:unreachable`, or `:error`, `configuration_error`,
  when step 0 refuses any of them. An offline case, nil, has no source to confirm.
  """
  def sources(nil), do: {:ok, nil}

  def sources(online) do
    states = identities(online)

    if Enum.any?(states, &match?({_source, :error}, &1)),
      do: :error,
      else: {:ok, %{online | sources: Map.new(states)}}
  end

  @doc """
  Each pinned Stellar and Bitcoin network, `{chain, network}`, whose identity read step 0
  refuses, in the order the model makes them: a value step 0 forbids, or regtest with no
  identity read. Every pinned network's read is made, none stopping the others.
  """
  def bad_identities(online), do: for({source, :error} <- identities(online), do: source)

  # Each pinned network's source and the state its identity read gives it.
  defp identities(%{pins: pins} = online) do
    for chain <- ~w(bitcoin stellar),
        network <- Enum.uniq([pins["commitment"][chain], pins["entropy"][chain]]),
        network != nil,
        do: {{chain, network}, identity(online, {chain, network})}
  end

  defp identity(online, {chain, network}) do
    read = %{"kind" => chain <> "_identity", "network" => network}

    case Map.fetch(online.answers, read) do
      {:ok, %{"outcome" => "found", "value" => value}} ->
        if allowed?(chain, network, value), do: :ok, else: :error

      {:ok, _no_usable_answer} ->
        :unreachable

      :error when network == "regtest" ->
        :error

      :error ->
        raise ArgumentError,
              "#{online.path} holds no identity read of #{chain} #{network}, which its case " <>
                "pins, so a verifier would read that network from a default source"
    end
  end

  # SPEC.md 10.2 step 0: a source pinned to a chain's production network gives that chain's
  # production value, and a source pinned to any other network does not.
  defp allowed?(chain, network, value) do
    {production_network, field, production_value} = production(chain)
    given = value[field]

    if network == production_network,
      do: given == production_value,
      else: given != production_value
  end

  @doc """
  The production network of `chain`, the field of its identity read, and the value step 0 pins
  for it, read from SPEC.md's text.
  """
  def production("stellar") do
    [_all, passphrase] =
      Regex.run(~r/pinned to `public` M[U]ST give the network passphrase\s+`([^`]+)`/, spec_md())

    {"public", "network_passphrase", passphrase}
  end

  def production("bitcoin") do
    [_all, hash] = Regex.run(~r/pinned to `mainnet` M[U]ST give\s+`([0-9a-f]{64})`/, spec_md())
    {"mainnet", "hash", hash}
  end

  defp spec_md do
    case Process.get({__MODULE__, :spec_md}) do
      nil ->
        text = Spec.spec_md()
        Process.put({__MODULE__, :spec_md}, text)
        text

      text ->
        text
    end
  end

  @doc """
  The keyring read at www.truestamp.com: `{:ok, bytes}`, JCS of the keyring the replay gives,
  which the load checks then judge, or `:failed` when it gives none.
  """
  def keyring(online) do
    case ask(online, %{"kind" => "keyring", "url" => @keyring_url}) do
      %{"outcome" => "found", "value" => %{"keyring" => keyring}} -> {:ok, JCS.encode(keyring)}
      _no_keyring -> :failed
    end
  end

  # CHAIN.

  @doc "The outcome of the CHAIN row at `part`, a commitment entry or a `genesis.bitcoin`."
  def chain(proof, part, online) do
    {chain, read} =
      cond do
        String.ends_with?(part, "/genesis/bitcoin") -> {"bitcoin", &genesis/2}
        String.ends_with?(part, "/bitcoin") -> {"bitcoin", &bitcoin/2}
        true -> {"stellar", &stellar/2}
      end

    at = %{
      online: online,
      network: online.pins["commitment"][chain],
      part: part,
      top?: part in @top
    }

    case Map.fetch!(online.sources, {chain, at.network}) do
      :unreachable -> skip("source_unreachable")
      :ok -> read.(Pointer.get(proof, part), at)
    end
  end

  # A Stellar commitment entry (SPEC.md 10.4).
  defp stellar(entry, at) do
    read = %{
      "hash" => entry["transaction_hash"],
      "kind" => "stellar_transaction",
      "network" => at.network
    }

    case ask(at.online, read) do
      %{"outcome" => "found", "value" => transaction} -> transaction(entry, transaction, at)
      %{"outcome" => "not_found"} -> no_transaction(entry["ledger"], at)
      _unreachable -> skip("source_unreachable")
    end
  end

  # Item 2: the transaction found. Its memo is compared with the epoch hash computed here.
  defp transaction(entry, found, at) do
    epoch_hash = Bytes.hex(Registry.record_hash("epoch_hash", entry["epoch"]["record"]))

    holds? =
      found["successful"] == true and found["memo_type"] == "hash" and
        same_bytes?(found["memo"], epoch_hash) and found["ledger"] == entry["ledger"]

    cond do
      not holds? -> fail("chain_mismatch")
      at.top? -> candidate(ledger(at.network, entry["ledger"]), at, &stellar_edge/1)
      true -> pass()
    end
  end

  # Item 3: the transaction not found, then the source's root, then ledger L.
  defp no_transaction(ledger, at) do
    with {:ok, root} <- root(at) do
      cond do
        ledger > root["latest"] - margin() -> skip("not_yet_indexed")
        ledger < root["elder"] -> skip("not_held_by_source")
        true -> held_ledger(ledger, at)
      end
    end
  end

  defp root(at) do
    case ask(at.online, %{"kind" => "stellar_root", "network" => at.network}) do
      %{"outcome" => "found", "value" => root} -> {:ok, root}
      _unreachable -> skip("source_unreachable")
    end
  end

  defp held_ledger(ledger, at) do
    case ask(at.online, ledger(at.network, ledger)) do
      %{"outcome" => "found"} -> fail("chain_mismatch")
      %{"outcome" => "not_found"} -> skip("not_held_by_source")
      _unreachable -> skip("source_unreachable")
    end
  end

  # A Bitcoin commitment entry: its block on the best chain, whose hash is the one computed
  # here from the txoutproof's header, and whose transaction count is its `total_txs`.
  defp bitcoin(entry, at) do
    with {:ok, block} <- best_chain(entry["height"], at) do
      <<header::binary-80, total::little-32, _rest::binary>> = Bytes.unhex(entry["txoutproof"])
      computed = BitcoinParse.display(BitcoinParse.sha256d(header))
      holds? = same_bytes?(block["hash"], computed) and block["transaction_count"] == total

      cond do
        not holds? -> fail("chain_mismatch")
        at.top? -> candidate(at_height(at.network, entry["height"] + finality()), at, &btc_edge/1)
        true -> pass()
      end
    end
  end

  # A genesis.bitcoin: items 1 and 2 of the Bitcoin rule, then the hash at its height.
  defp genesis(genesis, at) do
    with {:ok, block} <- best_chain(genesis["height"], at) do
      if same_bytes?(block["hash"], genesis["header_hash"]),
        do: pass(),
        else: fail("chain_mismatch")
    end
  end

  # Items 1 to 3 of the Bitcoin rule: the tip, then the best-chain block at `height`.
  defp best_chain(height, at) do
    case ask(at.online, %{"kind" => "bitcoin_tip", "network" => at.network}) do
      %{"outcome" => "found", "value" => %{"height" => tip}} -> covered(height, tip, at)
      _unreachable -> skip("source_unreachable")
    end
  end

  defp covered(height, tip, _at) when height > tip, do: skip("not_yet_indexed")

  defp covered(height, tip, at) do
    if tip < height + finality(), do: skip("chain_not_final"), else: block_at(height, at)
  end

  defp block_at(height, at) do
    case ask(at.online, at_height(at.network, height)) do
      %{"outcome" => "found", "value" => block} -> {:ok, block}
      %{"outcome" => "not_found"} -> skip("not_held_by_source")
      _unreachable -> skip("source_unreachable")
    end
  end

  # The read of a top-level entry's candidate: a read that answers not found leaves the row
  # `skip not_held_by_source` (SPEC.md 10.4, Rows).
  defp candidate(read, at, edge) do
    case ask(at.online, read) do
      %{"outcome" => "found", "value" => value} -> pass(Map.put(edge.(value), :part, at.part))
      %{"outcome" => "not_found"} -> skip("not_held_by_source")
      _unreachable -> skip("source_unreachable")
    end
  end

  defp stellar_edge(value), do: %{basis: "stellar_ledger_close_read", instant: value["closed_at"]}

  defp btc_edge(value),
    do: %{basis: "bitcoin_median_time_read", instant: bitcoin_time(value["median_time_past"])}

  @doc """
  KEY_EVENT_COMMITMENT's status and code (SPEC.md 10.3) when the external gate is open, from
  its input rows in document order and the run's attribution.
  """
  def key_event_commitment(inputs, attribution) do
    failed = Enum.find(inputs, &(&1.status == "fail"))
    skipped = Enum.find(inputs, &(&1.status == "skip"))

    cond do
      failed != nil -> {"fail", failed.code}
      skipped != nil -> {"skip", skipped.code}
      attribution == "truestamp" -> {"pass", nil}
      true -> {"info", "not_attributable"}
    end
  end

  # SOURCES.

  @doc "The outcome of the SOURCES row at `part`, an entropy object."
  def source(proof, part, online) do
    %{"payload" => payload, "source" => source} = Pointer.get(proof, part)
    at = %{online: online, network: online.pins["entropy"][source], part: part}

    if source != "nist" and Map.fetch!(online.sources, {source, at.network}) == :unreachable,
      do: skip("source_unreachable"),
      else: entropy(source, payload, at)
  end

  defp entropy("nist", %{"pulse" => pulse}, at) do
    read = %{
      "chainIndex" => pulse["chainIndex"],
      "kind" => "nist_pulse",
      "pulseIndex" => pulse["pulseIndex"]
    }

    equal? = fn read ->
      same_bytes?(read["outputValue"], pulse["outputValue"]) and
        same_instant?(read["timeStamp"], pulse["timeStamp"])
    end

    edge = &%{basis: "nist_pulse_time_read", instant: &1["timeStamp"]}
    compare(read, at, {equal?, edge}, fn -> skip("not_held_by_source") end)
  end

  defp entropy("stellar", payload, at) do
    equal? = fn read ->
      same_bytes?(read["hash"], payload["hash"]) and
        same_instant?(read["closed_at"], payload["closed_at"])
    end

    absent = fn -> absent_ledger(payload["sequence"], at) end
    compare(ledger(at.network, payload["sequence"]), at, {equal?, &stellar_edge/1}, absent)
  end

  defp entropy("bitcoin", payload, at) do
    read = %{"hash" => payload["hash"], "kind" => "bitcoin_block", "network" => at.network}
    equal? = &(&1["height"] == payload["height"] and &1["time"] == payload["time"])
    compare(read, at, {equal?, &btc_edge/1}, fn -> skip("not_held_by_source") end)
  end

  defp compare(read, at, {equal?, edge}, absent) do
    case ask(at.online, read) do
      %{"outcome" => "found", "value" => value} ->
        if equal?.(value),
          do: pass(Map.put(edge.(value), :part, at.part)),
          else: fail("entropy_mismatch")

      %{"outcome" => "not_found"} ->
        absent.()

      _unreachable ->
        skip("source_unreachable")
    end
  end

  # A Stellar entropy ledger not found: not yet indexed within the margin of the latest ledger
  # a live read of the source's root gives, and otherwise not held.
  defp absent_ledger(sequence, at) do
    with {:ok, root} <- root(at) do
      if sequence > root["latest"] - margin(),
        do: skip("not_yet_indexed"),
        else: skip("not_held_by_source")
    end
  end

  # WINDOW.

  @doc """
  WINDOW's rows, each `{status, code, part}`, and the edges `%{submitted_after,
  submitted_before}` (SPEC.md 11): from `befores` and `afters`, the candidates of the CHAIN and
  SOURCES rows that passed, in row order; `failed?`, whether a row has failed; and the pointer
  and value of the subject's id.
  """
  def window(befores, afters, failed?, {id_part, id}) do
    edges = %{
      submitted_after: edge(afters, :latest),
      submitted_before: edge(befores, :earliest)
    }

    {rows(edges, failed?, {id_part, id_time(id)}), edges}
  end

  defp rows(_edges, true, _id), do: [{"skip", "prior_failure", nil}]

  defp rows(%{submitted_before: nil}, false, _id),
    do: [{"info", "window_not_established", nil}]

  defp rows(%{submitted_after: earlier, submitted_before: later}, false, {id_part, id}) do
    cond do
      earlier != nil and ms(earlier) > ms(later) ->
        [{"fail", "window_inverted", nil}]

      id > ms(later) or (earlier != nil and id < ms(earlier)) ->
        [{"pass", nil, nil}, {"info", "recorded_time_outside_window", id_part}]

      true ->
        [{"pass", nil, nil}]
    end
  end

  # The earliest or the latest candidate, or nil when there is none: of candidates at that
  # instant, the first in row order (SPEC.md 11.1 and 11.2).
  defp edge([], _which), do: nil

  defp edge(candidates, which) do
    instants = Enum.map(candidates, &ms/1)
    extreme = if which == :earliest, do: Enum.min(instants), else: Enum.max(instants)
    Enum.find(candidates, &(ms(&1) == extreme))
  end

  # An instant in milliseconds since the Unix epoch, compared exactly (SPEC.md 11.3).
  defp ms(%{instant: text}), do: ms(text)

  defp ms(text) when is_binary(text) do
    {:ok, time, 0} = DateTime.from_iso8601(text)
    DateTime.to_unix(time, :millisecond)
  end

  # The time inside an id, in milliseconds: the first 48 bits of a UUIDv7, or of a ULID.
  defp id_time(<<head::binary-8, "-", middle::binary-4, "-", _rest::binary>>),
    do: String.to_integer(head <> middle, 16)

  defp id_time(<<time::binary-10, _random::binary-16>>) do
    for <<c <- time>>, reduce: 0 do
      acc -> acc * 32 + elem(:binary.match(@crockford, <<c>>), 0)
    end
  end

  # Reads and answers.

  defp ledger(network, sequence),
    do: %{"kind" => "stellar_ledger", "network" => network, "sequence" => sequence}

  defp at_height(network, height),
    do: %{"height" => height, "kind" => "bitcoin_block_at_height", "network" => network}

  # The answer the replay gives the read, which it must hold.
  defp ask(online, read) do
    case Map.fetch(online.answers, read) do
      {:ok, answer} ->
        answer

      :error ->
        raise ArgumentError,
              "#{online.path} holds no answer to #{inspect(read)}, a read its case makes"
    end
  end

  defp pass(candidate \\ nil), do: {"pass", nil, candidate}
  defp skip(code), do: {"skip", code, nil}
  defp fail(code), do: {"fail", code, nil}

  # Hashes compare as the bytes they spell, and times as instants (SPEC.md 10.4).
  defp same_bytes?(a, b) when is_binary(a) and is_binary(b) do
    with {:ok, x} <- Base.decode16(a, case: :mixed),
         {:ok, y} <- Base.decode16(b, case: :mixed) do
      x == y
    else
      :error -> false
    end
  end

  defp same_bytes?(_a, _b), do: false

  defp same_instant?(a, b) when is_binary(a) and is_binary(b), do: ms(a) == ms(b)
  defp same_instant?(_a, _b), do: false

  defp bitcoin_time(unix), do: unix |> DateTime.from_unix!() |> DateTime.to_iso8601()

  defp finality, do: Spec.read("constants.json")["BITCOIN_FINALITY"]
  defp margin, do: Spec.read("constants.json")["STELLAR_INDEX_MARGIN"]
end
