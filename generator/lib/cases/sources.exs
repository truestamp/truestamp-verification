# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Generator.Cases.Sources do
  @moduledoc """
  The online cases of several sources for one network (SPEC.md 9, 10.4 and 13.3): each names,
  in its `sources`, two or three sources for Stellar `testnet` or for `regtest`, `a`, `b` and
  `c`, under a policy, and its replay answers each read of that network once for each source,
  each record naming its source (SPEC.md 13.2). Every other network has one source, as in
  Generator.Cases.Online, whose world and pins these cases share: each runs under E_v `test`
  with the keyring `test`, over a sound proof as it is, so its attribution is `keyring:<d>`
  and a run with no failure is labelled `supplied-keyring`. Each named source answers as the
  world answers, then as the case changes it, and a read of a source whose identity read is
  not found with a value step 0 allows is dropped, as the replay form requires.

  The proofs: the sound item, whose entries at both positions are E2's (Stellar ledger
  1,000,255, Bitcoin height 222) and whose witnesses are NIST pulse 1,200,018, Stellar ledger
  1,000,222 and regtest block 215; and item-rotation-witness, whose only top-level entry is
  E3's Stellar one (ledger 1,000,267), so its submitted-before edge rests on that row alone,
  with E2's entries at /signing_key_event and the item's witnesses.

  - Under `all`: every source passing alike, over the item with two sources for each chain,
    so that both edges rest on two sources; over item-rotation-witness with two Stellar
    sources, `b`'s memo differing (a pass beside a fail) and `b`'s ledger 1,000,267 closing a
    second later (two candidates at different instants), each `skip sources_disagree`, `b`'s
    transaction read timing out (`skip sources_incomplete`), of three, `b`'s memo differing
    and `c`'s transaction read timing out (`skip sources_disagree`), both memos differing
    (`fail chain_mismatch`), and `a`'s memo differing beside `b`'s transaction read timing out
    (`skip sources_incomplete`); over the item with two regtest sources, both tips below height
    222 (`skip not_yet_indexed`) and tips of 233 and 232, a block apart and both final, which
    pass with one candidate; and over the item with two Stellar sources, `b`'s ledger
    1,000,222, an entropy witness, with another hash (`skip sources_disagree` at SOURCES).
  - Under `at_least 2` of three Stellar sources, over item-rotation-witness: `c`'s
    transaction read unreachable, which passes on `a` and `b`, and `a`'s and `b`'s memos
    differing beside it (`fail chain_mismatch`).
  - Under `first`, over item-rotation-witness with two Stellar sources: `a`'s transaction read
    unreachable; `a` a source that keeps less history, whose root's elder is ledger 1,000,268
    and which holds none of the transactions and ledgers the proof names; and `a`'s identity
    read unreachable, each passing on `b`; `a`'s memo differing, which fails the row, with `b`
    holding only its identity read, so that a verifier that asks `b` finds no answer; and both
    transaction reads unreachable (`skip source_unreachable`). Over the item with two regtest
    sources, `a`'s tip below height 222 and `b`'s at 222 (`skip sources_incomplete`).
  - At CONFIGURATION, over the item with two regtest sources, `b`'s identity read giving
    mainnet's block-0 hash while `a`'s is regtest's: the bare rejection `configuration_error`,
    with a replay of identity reads alone.

  Every other online case has one source for each network; Generator.Cases checks that each
  gives its output again with one named source for each, under each policy.
  """

  @behaviour Generator.Cases.Class

  alias Generator.{Case, Chain, Edit, Replay, Spec}
  alias Generator.Replay.World

  @codes ~w(sources_disagree sources_incomplete)

  @alone "item-rotation-witness"
  @ske "/signing_key_event"
  @top_stellar "/commitments/stellar"
  @top_bitcoin "/commitments/bitcoin"
  @ske_bitcoin "/signing_key_event/commitments/bitcoin"
  @witness_stellar "/witnesses/entropy_stellar"

  @stellar {"stellar", "testnet"}
  @regtest {"bitcoin", "regtest"}

  # Rows of CHAIN, SOURCES and WINDOW, each {status, code, part, step}.
  @kec_info {"info", "not_attributable", @ske, "CHAIN"}
  @window_prior {"skip", "prior_failure", nil, "WINDOW"}
  @window_none {"info", "window_not_established", nil, "WINDOW"}

  # The edges the world gives, each {basis, instant}.
  @s222 {"stellar_ledger_close_read", "2026-09-26T01:48:30Z"}
  @s255 {"stellar_ledger_close_read", "2026-09-26T01:51:15Z"}
  @s267 {"stellar_ledger_close_read", "2026-09-26T01:52:15Z"}
  @n018 {"nist_pulse_time_read", "2026-09-26T01:48:00.000Z"}

  @impl true
  def codes, do: @codes

  @impl true
  def cases(%{sound: sound}) do
    world = World.new(Chain.build())

    List.flatten([
      all(sound, world),
      at_least(sound, world),
      first(sound, world),
      configuration(sound, world)
    ])
  end

  # Under `all`.

  defp all(sound, world) do
    %{proof: item, path: item_path} = sound["item"]
    %{proof: alone, path: alone_path} = sound[@alone]
    t3 = transaction(alone, @top_stellar)
    l3 = ledger(Edit.get(alone, @top_stellar <> "/ledger"))
    h = Edit.get(item, @top_bitcoin <> "/height")
    other = hex("an epoch hash no epoch has")
    memo = &%{&1 | "memo" => other}
    two = ~w(a b)
    on_alone = &replay(world, alone, %{@stellar => &1}, &2)
    tips = fn a, b -> %{{"a", tip()} => tip_at(world, a), {"b", tip()} => tip_at(world, b)} end

    bitcoin_skips = fn code ->
      [
        {"skip", code, @top_bitcoin, "CHAIN"},
        {"skip", code, @ske_bitcoin, "CHAIN"},
        {"skip", code, @ske, "CHAIN"}
      ]
    end

    [
      passes("sources-all-agree", item_path,
        sources: %{@stellar => {"all", two}, @regtest => {"all", two}},
        replay: replay(world, item, %{@stellar => two, @regtest => two}, %{}),
        edges: {@s222, @s255},
        rows: [@kec_info]
      ),
      no_edge("sources-all-pass_and_fail", alone_path, "sources_disagree",
        sources: %{@stellar => {"all", two}},
        replay: on_alone.(two, %{{"b", t3} => memo})
      ),
      # Two sources that give one ledger different close times: one of them is wrong, which is
      # the point of the case, and SPEC.md 10.4 compares the candidates the sources give.
      no_edge("sources-all-different_candidates", alone_path, "sources_disagree",
        sources: %{@stellar => {"all", two}},
        replay: on_alone.(two, %{{"b", l3} => &%{&1 | "closed_at" => "2026-09-26T01:52:16Z"}})
      ),
      no_edge("sources-all-pass_and_unreachable", alone_path, "sources_incomplete",
        sources: %{@stellar => {"all", two}},
        replay: on_alone.(two, %{{"b", t3} => unreachable("timeout")})
      ),
      no_edge("sources-all-conflict_and_unreachable", alone_path, "sources_disagree",
        sources: %{@stellar => {"all", ~w(a b c)}},
        replay: on_alone.(~w(a b c), %{{"b", t3} => memo, {"c", t3} => unreachable("timeout")})
      ),
      mismatch("sources-all-every_fail", alone_path,
        sources: %{@stellar => {"all", two}},
        replay: on_alone.(two, %{{"a", t3} => memo, {"b", t3} => memo})
      ),
      # One fail, below the two that `all` asks for, and no pass: neither a disagreement nor a
      # failure (SPEC.md 10.4).
      no_edge("sources-all-fail_and_unreachable", alone_path, "sources_incomplete",
        sources: %{@stellar => {"all", two}},
        replay: on_alone.(two, %{{"a", t3} => memo, {"b", t3} => unreachable("timeout")})
      ),
      passes("sources-all-every_not_yet_indexed", item_path,
        sources: %{@regtest => {"all", two}},
        replay: replay(world, item, %{@regtest => two}, tips.(h - 1, h - 1)),
        edges: {@s222, @s255},
        rows: bitcoin_skips.("not_yet_indexed")
      ),
      # Tips of 233, the world's, and 232: a source a block behind another is no disagreement,
      # and both cover height 222 + BITCOIN_FINALITY, the candidate's block (SPEC.md 10.4).
      passes("sources-all-lagging_tips", item_path,
        sources: %{@regtest => {"all", two}},
        replay:
          replay(world, item, %{@regtest => two}, tips.(h + finality() + 1, h + finality())),
        edges: {@s222, @s255},
        rows: [@kec_info]
      ),
      passes("sources-all-entropy_disagree", item_path,
        sources: %{@stellar => {"all", two}},
        replay:
          replay(world, item, %{@stellar => two}, %{
            {"b", entropy_ledger(item, @witness_stellar)} =>
              &%{&1 | "hash" => hex("a ledger no source closed")}
          }),
        edges: {@n018, @s255},
        rows: [@kec_info, {"skip", "sources_disagree", @witness_stellar, "SOURCES"}]
      )
    ]
  end

  # Under `at_least 2` of three.

  defp at_least(sound, world) do
    %{proof: alone, path: alone_path} = sound[@alone]
    t3 = transaction(alone, @top_stellar)
    three = ~w(a b c)
    memo = &%{&1 | "memo" => hex("an epoch hash no epoch has")}
    sources = %{@stellar => {{"at_least", 2}, three}}

    [
      passes("sources-at_least_2-one_unreachable", alone_path,
        sources: sources,
        replay:
          replay(world, alone, %{@stellar => three}, %{{"c", t3} => unreachable("HTTP 503")}),
        edges: {@s222, @s267},
        rows: [@kec_info]
      ),
      mismatch("sources-at_least_2-two_fail", alone_path,
        sources: sources,
        replay:
          replay(world, alone, %{@stellar => three}, %{
            {"a", t3} => memo,
            {"b", t3} => memo,
            {"c", t3} => unreachable("HTTP 503")
          })
      )
    ]
  end

  # Under `first`.

  defp first(sound, world) do
    %{proof: item, path: item_path} = sound["item"]
    %{proof: alone, path: alone_path} = sound[@alone]
    t3 = transaction(alone, @top_stellar)
    l3 = Edit.get(alone, @top_stellar <> "/ledger")
    h = Edit.get(item, @top_bitcoin <> "/height")
    two = ~w(a b)
    sources = %{@stellar => {"first", two}}
    on_alone = &replay(world, alone, %{@stellar => two}, &1)
    world_root = World.answer(world, "stellar_root", %{"network" => "testnet"})

    # A source that keeps less history: its first ledger is L + 1, past ledger L of
    # /commitments/stellar, so it holds no transaction and no ledger the proof names.
    shallow =
      Map.new([
        {{"a", root()}, put_in(world_root, ["value", "elder"], l3 + 1)},
        {{"a", t3}, not_found()},
        {{"a", transaction(alone, "/signing_key_event/commitments/stellar")}, not_found()},
        {{"a", ledger(l3)}, not_found()},
        {{"a", entropy_ledger(alone, @witness_stellar)}, not_found()}
      ])

    [
      passes("sources-first-past_unreachable", alone_path,
        sources: sources,
        replay: on_alone.(%{{"a", t3} => unreachable("HTTP 429")}),
        edges: {@s222, @s267},
        rows: [@kec_info]
      ),
      passes("sources-first-past_not_held", alone_path,
        sources: sources,
        replay: on_alone.(shallow),
        edges: {@s222, @s267},
        rows: [@kec_info]
      ),
      passes("sources-first-past_identity_unreachable", alone_path,
        sources: sources,
        replay: on_alone.(%{{"a", identity(@stellar)} => unreachable("timeout")}),
        edges: {@s222, @s267},
        rows: [@kec_info]
      ),
      mismatch("sources-first-stops_at_fail", alone_path,
        sources: sources,
        replay:
          replay(
            world,
            alone,
            %{@stellar => two},
            %{{"a", t3} => &%{&1 | "memo" => hex("an epoch hash no epoch has")}},
            only_identity: ["b"]
          )
      ),
      no_edge("sources-first-every_unreachable", alone_path, "source_unreachable",
        sources: sources,
        replay:
          on_alone.(%{{"a", t3} => unreachable("timeout"), {"b", t3} => unreachable("HTTP 503")})
      ),
      passes("sources-first-mixed_skips", item_path,
        sources: %{@regtest => {"first", two}},
        replay:
          replay(world, item, %{@regtest => two}, %{
            {"a", tip()} => tip_at(world, h - 1),
            {"b", tip()} => tip_at(world, h)
          }),
        edges: {@s222, @s255},
        rows: [
          {"skip", "sources_incomplete", @top_bitcoin, "CHAIN"},
          {"skip", "sources_incomplete", @ske_bitcoin, "CHAIN"},
          {"skip", "sources_incomplete", @ske, "CHAIN"}
        ]
      )
    ]
  end

  # At CONFIGURATION: one of two regtest sources on mainnet.

  defp configuration(sound, world) do
    %{proof: item, path: item_path} = sound["item"]
    two = ~w(a b)

    [
      Case.new("sources-configuration-regtest-mainnet_block0",
        proof: {:path, item_path},
        sources: config(%{@regtest => {"all", two}}),
        replay:
          replay(
            world,
            item,
            %{@regtest => two},
            %{{"b", identity(@regtest)} => found(%{"hash" => Replay.production()["bitcoin"]})},
            identities_only: true
          ),
        defect: {:bare, "configuration_error", nil}
      )
    ]
  end

  # Case builders.

  # A case with no failing row, labelled supplied-keyring, whose rows of CHAIN, SOURCES and
  # WINDOW that do not pass are `rows`.
  defp passes(id, path, options) do
    {rows, options} = Keyword.pop!(options, :rows)
    {sources, options} = Keyword.pop!(options, :sources)

    Case.new(
      id,
      [
        proof: {:path, path},
        sources: config(sources),
        defect: {:passes, rows},
        label: "supplied-keyring",
        online_rows: rows
      ] ++ options
    )
  end

  # item-rotation-witness's /commitments/stellar skipped with `code`, so that no
  # submitted-before edge is drawn.
  defp no_edge(id, path, code, options) do
    passes(
      id,
      path,
      [
        edges: {@s222, nil},
        rows: [{"skip", code, @top_stellar, "CHAIN"}, @kec_info, @window_none]
      ] ++ options
    )
  end

  # One CHAIN failure, chain_mismatch at /commitments/stellar, labelled failed, with both edges
  # null.
  defp mismatch(id, path, options) do
    {sources, options} = Keyword.pop!(options, :sources)

    Case.new(
      id,
      [
        proof: {:path, path},
        sources: config(sources),
        defect: {:fail, "chain_mismatch", @top_stellar, "CHAIN"},
        label: "failed",
        edges: {nil, nil},
        online_rows: [{"fail", "chain_mismatch", @top_stellar, "CHAIN"}, @kec_info, @window_prior]
      ] ++ options
    )
  end

  # A case's `sources` (SPEC.md 13.2): each network `{chain, network}` with `{policy, names}`,
  # where the policy is "first", "all" or {"at_least", n}.
  defp config(sources) do
    Enum.reduce(sources, %{}, fn {{chain, network}, {policy, names}}, config ->
      set =
        case policy do
          {"at_least", n} -> %{"policy" => "at_least", "required" => n, "sources" => names}
          policy -> %{"policy" => policy, "sources" => names}
        end

      Map.update(config, chain, %{network => set}, &Map.put(&1, network, set))
    end)
  end

  # Replays.

  # The replay of `proof` run online under the pins of Generator.Case.pins/0, with each read of
  # a network `named` gives names, `%{{chain, network} => names}`, answered once for each name,
  # and each other read once, from the world; then `changes`, each by `{name, read}` with name
  # nil for a network's one source: an answer puts it, and a function passes the world's found
  # value through it. `only_identity` names sources whose reads but their identity read are
  # dropped, and `identities_only` keeps the identity reads alone. Last, every read of a source
  # whose identity read is not found with a value step 0 allows is dropped (SPEC.md 13.2).
  defp replay(world, proof, named, changes, options \\ []) do
    only_identity = Keyword.get(options, :only_identity, [])

    answers =
      for {kind, parameters} = read <- Replay.reads(proof, Case.pins()),
          name <- names(named, kind, parameters),
          into: %{},
          do: {{name, read}, World.answer(world, kind, parameters)}

    answers = Enum.reduce(changes, answers, &put(&2, &1, world))

    records =
      for {{name, {kind, parameters}} = key, answer} <- answers,
          identity?(kind) or
            (not Keyword.get(options, :identities_only, false) and name not in only_identity),
          sourced?(answers, key),
          do: Replay.record(kind, parameters, answer, name)

    {:value, Replay.file(records)}
  end

  defp names(named, kind, %{"network" => network}) do
    {chain, _parameters, _fields, _outcomes} = Map.fetch!(Replay.kinds(), kind)
    Map.get(named, {chain, network}, [nil])
  end

  defp names(_named, _kind, _parameters), do: [nil]

  defp put(answers, {{_name, {kind, parameters}} = key, edit}, world) when is_function(edit, 1),
    do: Map.put(answers, key, update_in(World.answer(world, kind, parameters), ["value"], edit))

  defp put(answers, {key, answer}, _world), do: Map.put(answers, key, answer)

  defp identity?(kind), do: kind in ~w(bitcoin_identity stellar_identity)

  # Whether the replay form lets a replay holding `answers` hold the read of `key`.
  defp sourced?(answers, {name, {kind, %{"network" => network}}}) do
    {chain, _parameters, _fields, _outcomes} = Map.fetch!(Replay.kinds(), kind)

    case Map.get(answers, {name, identity({chain, network})}) do
      _identity when kind in ~w(bitcoin_identity stellar_identity) -> true
      %{"outcome" => "found", "value" => value} -> Replay.allowed?(chain, network, value)
      _no_usable_answer -> false
    end
  end

  defp sourced?(_answers, _key), do: true

  # Reads, each `{kind, parameters}`.

  defp identity({chain, network}), do: {chain <> "_identity", %{"network" => network}}
  defp root, do: {"stellar_root", %{"network" => "testnet"}}
  defp tip, do: {"bitcoin_tip", %{"network" => "regtest"}}
  defp ledger(sequence), do: {"stellar_ledger", %{"network" => "testnet", "sequence" => sequence}}

  defp transaction(proof, n),
    do:
      {"stellar_transaction",
       %{"hash" => Edit.get(proof, n <> "/transaction_hash"), "network" => "testnet"}}

  defp entropy_ledger(proof, e), do: ledger(Edit.get(proof, e <> "/payload/sequence"))

  # Answers.

  defp tip_at(world, height),
    do:
      put_in(
        World.answer(world, "bitcoin_tip", %{"network" => "regtest"}),
        ["value", "height"],
        height
      )

  defp found(value), do: %{"outcome" => "found", "value" => value}
  defp not_found, do: %{"outcome" => "not_found"}
  defp unreachable(reason), do: %{"outcome" => "unreachable", "reason" => reason}

  defp hex(label), do: Base.encode16(:crypto.hash(:sha256, label), case: :lower)

  defp finality, do: Spec.read("constants.json")["BITCOIN_FINALITY"]
end
