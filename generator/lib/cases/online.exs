# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Generator.Cases.Online do
  @moduledoc """
  The online cases: SPEC.md 13.3's KEY_BINDING and CONFIGURATION cases that are online, Chain
  and source reads, the committed leaf count's Stellar record lies, the window, and the
  online gates. Each has a replay file, `corpus/replay/<id>.json` in the form of SPEC.md 13.2
  (Generator.Replay), which answers every read the run makes and stands as the
  operator-pinned source for each Stellar and Bitcoin network whose identity read it holds.
  Each network here has one source; the cases of several sources for one network are
  Generator.Cases.Sources's.

  Unless a case says otherwise it runs under E_v `test` with the keyring `test`, pins regtest
  and testnet for every chain and source (Generator.Case.pins/0), and its proof is a sound
  proof as it is; one window case changes the proof, and writes its own file. Its replay is
  built from the model's world (Generator.Replay.World): every
  read Generator.Replay.reads/2 says a verifier makes for that proof when each answer is found
  and matches, each pinned network's identity read among them, answered as the world answers
  it, then only what the case changes. A read of a network whose identity read is not found
  with a value step 0 allows is dropped, as the replay form requires. So a replay can hold a
  read the run does not make, as SPEC.md 13.2 allows, and the model raises when the run makes
  one the replay does not hold. A Bitcoin block's median time past is only the source's report
  of it (D66).

  What each case asserts is stated by hand from SPEC.md 10.2 to 11: its defect, its label,
  its two edges, and every row of CHAIN, SOURCES and WINDOW that does not pass
  (Generator.Case's `edges` and `online_rows`), which the model's output must equal. The runs
  are under the keyring `test`, so their attribution is `keyring:<d>`: KEY_EVENT_COMMITMENT is
  `info not_attributable` when every input passes, and a run with no failure is labelled
  `supplied-keyring`, never `verified`, which needs Truestamp's keys.

  The world's instants (Generator.Chain), all on 2026-09-26: Stellar testnet closes ledger
  1,000,000 at 01:30:00 and one every 5 seconds after, NIST chain 2 gives pulse 1,200,000 at
  01:30:00.000 and one a minute after, and regtest mines block 200 at 01:30:00 and one a
  minute after, so the median time past of block h is the time of block h - 5. The Stellar
  source holds ledgers 1,000,000 to 1,000,396, and the regtest tip is 233. The sound proofs'
  entries: the item's, at both positions, are E2's (Stellar ledger 1,000,255, Bitcoin height
  222); item-rotation-witness has E3's Stellar entry (ledger 1,000,267) at /commitments and
  E2's at /signing_key_event; block and beacon have E1's (ledger 1,000,207, height 218) at
  /commitments and E2's at /signing_key_event, and block's genesis.bitcoin is regtest block
  200; item-genesis-witness has F1's Stellar entry (ledger 1,000,327) at both positions and
  genesis.bitcoin block 212 at /witnesses/block and /signing_key_event/block. The item's
  witnesses are NIST pulse 1,200,018, Stellar ledger 1,000,222 and regtest block 215, and the
  time in its id is 01:49:00.

  - **KEY_BINDING** (`key_binding-unavailable-`), under `prod` with the keyring `unavailable`,
    on the sound item unmarked, signed by VECTOR_KEY (the file of
    `environment-absent-under-staging`): the replay's keyring read at www.truestamp.com is
    unreachable, or found with a keyring that fails a load check under `prod`, the test
    keyring, whose one key is VECTOR_KEY. Each fails `keyring_unavailable` at KEY_BINDING,
    every later step is `skip prior_failure`, and both edges are null. The replay holds the
    identity reads and the keyring read, since the run reads nothing more.
  - **CONFIGURATION** (`configuration-online-`), each the bare rejection
    `configuration_error`, its replay holding identity reads alone, exactly one of which step
    0 refuses: regtest pinned with no identity read of it, so no source, over the sound item,
    the one case whose `no_source` names a network; a Stellar source pinned to
    `public` that gives the testnet passphrase, and a Bitcoin source pinned to `mainnet` that
    gives regtest's block-0 hash, each over block-rotation with that chain's entries on that
    network, signed again, and both of that chain's pins on it; and a Stellar testnet source
    that gives the production passphrase, and a regtest source that gives mainnet's block-0
    hash, over the sound item.
  - **Chain and source reads** (`reads-`):
    - an identity read unreachable, for Bitcoin and for Stellar, over the item: every row
      that source serves is `skip source_unreachable`, KEY_EVENT_COMMITMENT skips with it,
      and the edges come from the other sources;
    - a Stellar entry, at item-rotation-witness's /commitments, its only top-level entry:
      found and matching, which passes and gives the submitted-before edge; a memo that
      differs, a `memo_type` of `return` with the right memo, a transaction that did not
      succeed, and another ledger (`chain_mismatch`); not found, with the root's latest
      STELLAR_INDEX_MARGIN - 1 ledgers past L (`not_yet_indexed`), with a ledger L the source
      does not hold (`not_held_by_source`), and with ledger L held and the latest
      STELLAR_INDEX_MARGIN past it (`chain_mismatch`); and found, with ledger L, the candidate
      read, not found (`not_held_by_source`). The skips leave no submitted-before edge. The
      root's elder is tried at block's /commitments, L 1,000,207, below the ledger of the
      /signing_key_event transaction that run finds: an elder of L + 1
      (`not_held_by_source`), and an elder of L itself, with ledger L held (`chain_mismatch`).
      Every Stellar source here is on `testnet`, so these are the not-found branches on a
      test network (D58 item 14);
    - the commitment pin and the entropy pin of Stellar on different networks, `public` and
      `testnet` (split_pins/2): every row passes, and a verifier that sends a read to the
      other pin's source finds no answer;
    - one unreachable read of each kind: the Stellar root with the transaction found, a read
      the run does not make, so the row passes; the root with the transaction not found; the
      transaction; ledger L; the Bitcoin tip (item); the block at /commitments/bitcoin's
      height (block); a Bitcoin entropy block by its hash, and a NIST pulse (item);
    - Bitcoin: over the item, whose two entries share height h, 222, a tip of h - 1
      (`not_yet_indexed`), of h and of h + BITCOIN_FINALITY - 1 (`chain_not_final`), and of
      h + BITCOIN_FINALITY, where the entries are final, every row passes and the Bitcoin
      candidate is read; over block, at
      /commitments/bitcoin's height 218, a header hash and a transaction count that differ
      (`chain_mismatch`), a best-chain block not found at a height the tip covers, and not
      found at 228, the candidate read (`not_held_by_source`); and genesis.bitcoin's block 200
      with another hash (`chain_mismatch`);
    - entropy: each field a SOURCES read compares, changed (`entropy_mismatch`): a NIST
      `outputValue` (item) and a `timeStamp` 1 ms later (entropy_nist), a Stellar `hash`
      (beacon) and a `closed_at` a second later (item), and a Bitcoin `height`
      (entropy_bitcoin) and `time` (item); and each object not found, over the item: NIST and
      Bitcoin (`not_held_by_source`), and Stellar, with the root's latest
      STELLAR_INDEX_MARGIN - 1 ledgers past its sequence (`not_yet_indexed`), exactly
      STELLAR_INDEX_MARGIN past it and with the world's root (`not_held_by_source`);
    - KEY_EVENT_COMMITMENT: every input found and matching, over item-genesis-witness, whose
      inputs include its genesis event's genesis.bitcoin (`info not_attributable`); the
      /signing_key_event Stellar memo differing (item-rotation-witness) and the genesis
      block's hash differing (item-genesis-witness), which fail it with `chain_mismatch`; a
      tip of 231, which skips it with `chain_not_final` (item-rotation-witness); and both of
      the first and the last at once, which fails it, since a failed input comes before a
      skipped one whatever their order.
  - **The committed leaf count** (`leaf_count-record-...-online`): the files of
    `leaf_count-record-commitments-stellar` and `leaf_count-record-signing_key_event-stellar`,
    whose Stellar epoch record carries the moved index, pass DERIVE, and online the memo the
    world holds differs from the recomputed epoch hash: `chain_mismatch` at the entry, and at
    /signing_key_event KEY_EVENT_COMMITMENT fails too. Their replays are the world's,
    unchanged.
  - **The window** (`window-`): every read found and matching over the item, both edges
    Stellar's; over block, a submitted-before edge and no submitted-after edge; ledger
    1,000,255 closed at 01:45:00, before the submitted-after edge (`fail window_inverted`,
    both edges null); ledger 1,000,255 closed at 01:48:45, before the time in the item's id,
    and block 215's median time past at 01:49:30, after it, each `info
    recorded_time_outside_window` at `/subject/record/id`; the same median time past later
    than the id over item-rotation-witness, with no submitted-before edge, which gives no
    such row; ledger 1,000,255 closed at 01:49:00, the id's own time, which gives none
    either; item-rotation-witness with the time in its id set to 01:49:00.250, the hashes
    above its record made to agree and signed again, and ledger 1,000,267 closed at 01:49:00
    with a memo of the new epoch hash, which gives the row, since the time inside an id
    compares to the millisecond (SPEC.md 11.3); over entropy_nist, ledger 1,000,255 closed at
    01:48:00, the instant of its NIST pulse, so that the two edges are one instant, which is
    not inverted; and block 232's median time past at 01:51:15, the close of ledger
    1,000,255, so that the two candidates of the submitted-before edge tie and the first in
    row order, /commitments/bitcoin's, gives it; and block 215's median time past at
    01:48:30, the close of ledger 1,000,222, so that the two latest candidates of the
    submitted-after edge tie and the first in row order, /witnesses/entropy_bitcoin's, gives
    it. Seven of these cases hold answers that could not come from a real chain (the
    millisecond case holds two), and each case says so where it is built.
  - **Gates** (`gates-online-`): a CHAIN failure (beacon, /commitments/stellar's memo) with
    every SOURCES row still read and passing; and the files of `gates-policy`'s POLICY
    failure and `gates-derive`'s DERIVE failure, run online, whose every CHAIN and SOURCES
    row is `skip prior_failure`, with a replay of identity reads alone, so that any other read
    the run made would have no answer.
  """

  @behaviour Generator.Cases.Class

  alias Generator.{Case, Chain, Edit, Parse, Replay, Spec}
  alias Generator.Replay.World

  @codes ~w(keyring_unavailable chain_mismatch source_unreachable not_held_by_source
            not_yet_indexed chain_not_final entropy_mismatch window_inverted
            recorded_time_outside_window)

  @keyring_url "https://www.truestamp.com/.well-known/keyring.json"
  @testnet_passphrase "Test SDF Network ; September 2015"
  @unmarked "negative/environment-absent-under-staging.proof.json"
  @alone "item-rotation-witness"
  @ske "/signing_key_event"
  @top_stellar "/commitments/stellar"
  @top_bitcoin "/commitments/bitcoin"
  @ske_stellar "/signing_key_event/commitments/stellar"
  @ske_bitcoin "/signing_key_event/commitments/bitcoin"

  # Rows of CHAIN, SOURCES and WINDOW, each {status, code, part, step}.
  @kec_info {"info", "not_attributable", @ske, "CHAIN"}
  @window_prior {"skip", "prior_failure", nil, "WINDOW"}
  @window_none {"info", "window_not_established", nil, "WINDOW"}

  # The edges the world gives, each {basis, instant}.
  @s207 {"stellar_ledger_close_read", "2026-09-26T01:47:15Z"}
  @s222 {"stellar_ledger_close_read", "2026-09-26T01:48:30Z"}
  @s255 {"stellar_ledger_close_read", "2026-09-26T01:51:15Z"}
  @s267 {"stellar_ledger_close_read", "2026-09-26T01:52:15Z"}
  @s327 {"stellar_ledger_close_read", "2026-09-26T01:57:15Z"}
  @n018 {"nist_pulse_time_read", "2026-09-26T01:48:00.000Z"}
  @b228 {"bitcoin_median_time_read", "2026-09-26T01:53:00Z"}
  @b232 {"bitcoin_median_time_read", "2026-09-26T01:57:00Z"}

  @impl true
  def codes, do: @codes

  @impl true
  def cases(%{sound: sound, files: files}) do
    world = World.new(Chain.build())

    List.flatten([
      key_binding(world, files),
      configuration(sound, world),
      identity_reads(sound, world),
      stellar(sound, world),
      split_pins(sound, world),
      unreachable_reads(sound, world),
      bitcoin(sound, world),
      entropy(sound, world),
      key_event_commitment(sound, world),
      leaf_count(sound, world),
      window(sound, world),
      gates(sound, world)
    ])
  end

  # KEY_BINDING.

  defp key_binding(world, files) do
    test_keyring = Parse.decode!(Map.fetch!(files, "vectors/keyring.test.json"))

    for {name, answer} <- [
          {"unreachable", unreachable("HTTP 503")},
          {"load_check", found(%{"keyring" => test_keyring})}
        ] do
      Case.new("key_binding-unavailable-" <> name,
        proof: {:path, @unmarked},
        environment: "prod",
        keyring: "unavailable",
        replay: identities(world, Case.pins(), %{keyring() => answer}),
        defect: {:fail, "keyring_unavailable", nil, "KEY_BINDING"},
        label: "failed",
        edges: {nil, nil},
        online_rows: [
          {"skip", "prior_failure", nil, "CHAIN"},
          {"skip", "prior_failure", nil, "SOURCES"},
          @window_prior
        ]
      )
    end
  end

  # CONFIGURATION.

  defp configuration(sound, world) do
    %{path: item} = sound["item"]
    rotation = sound["block-rotation"].proof
    production = Replay.production()
    regtest_block0 = World.answer(world, "bitcoin_identity", %{"network" => "regtest"})
    pins = Case.pins()
    public = on_network(pins, "stellar", "public")
    mainnet = on_network(pins, "bitcoin", "mainnet")
    passphrase = fn text -> found(%{"network_passphrase" => text}) end

    [
      {"no_source-regtest", {:path, item}, pins, %{identity("bitcoin", "regtest") => :none},
       no_source: {"bitcoin", "regtest"}},
      {"public-other_passphrase", {:served, networks(rotation, "stellar", "public")}, public,
       %{identity("stellar", "public") => passphrase.(@testnet_passphrase)}, []},
      {"mainnet-other_block0", {:served, networks(rotation, "bitcoin", "mainnet")}, mainnet,
       %{identity("bitcoin", "mainnet") => regtest_block0}, []},
      {"testnet-production_passphrase", {:path, item}, pins,
       %{identity("stellar", "testnet") => passphrase.(production["stellar"])}, []},
      {"regtest-mainnet_block0", {:path, item}, pins,
       %{identity("bitcoin", "regtest") => found(%{"hash" => production["bitcoin"]})}, []}
    ]
    |> Enum.map(fn {id, proof, pins, changes, options} ->
      Case.new(
        "configuration-online-" <> id,
        [
          proof: proof,
          networks: pins,
          replay: identities(world, pins, changes),
          defect: {:bare, "configuration_error", nil}
        ] ++ options
      )
    end)
  end

  # Both pins of `chain` on `network`.
  defp on_network(pins, chain, network),
    do: pins |> put_in(["commitment", chain], network) |> put_in(["entropy", chain], network)

  # A proof whose entries of `chain`, at both positions, are on `network`, signed again: an
  # entry's network is covered by no hash.
  defp networks(proof, chain, network) do
    [@top_stellar, @ske_stellar, @top_bitcoin, @ske_bitcoin]
    |> Enum.filter(&String.ends_with?(&1, "/" <> chain))
    |> Enum.reduce(proof, &Edit.put(&2, &1 <> "/network", network))
    |> Case.sign()
  end

  # Chain and source reads: an identity read unreachable.

  defp identity_reads(sound, world) do
    %{proof: item, path: path} = sound["item"]

    [
      passes("reads-identity-bitcoin-unreachable", path,
        replay: replay(world, item, %{identity("bitcoin", "regtest") => unreachable("timeout")}),
        edges: {@s222, @s255},
        rows: [
          {"skip", "source_unreachable", @top_bitcoin, "CHAIN"},
          {"skip", "source_unreachable", @ske_bitcoin, "CHAIN"},
          {"skip", "source_unreachable", @ske, "CHAIN"},
          {"skip", "source_unreachable", "/witnesses/entropy_bitcoin", "SOURCES"}
        ]
      ),
      passes("reads-identity-stellar-unreachable", path,
        replay: replay(world, item, %{identity("stellar", "testnet") => unreachable("HTTP 503")}),
        edges: {@n018, @b232},
        rows: [
          {"skip", "source_unreachable", @top_stellar, "CHAIN"},
          {"skip", "source_unreachable", @ske_stellar, "CHAIN"},
          {"skip", "source_unreachable", @ske, "CHAIN"},
          {"skip", "source_unreachable", "/witnesses/entropy_stellar", "SOURCES"}
        ]
      )
    ]
  end

  # Chain and source reads: a Stellar commitment entry, at item-rotation-witness's
  # /commitments, its only top-level entry, E3's in ledger 1,000,267.

  defp stellar(sound, world) do
    %{proof: proof, path: path} = sound[@alone]
    %{proof: block, path: block_path} = sound["block"]
    t3 = transaction(proof, @top_stellar)
    l3 = Edit.get(proof, @top_stellar <> "/ledger")
    t1 = transaction(block, @top_stellar)
    l1 = Edit.get(block, @top_stellar <> "/ledger")
    world_root = World.answer(world, "stellar_root", %{"network" => "testnet"})
    root = fn change -> update_in(world_root, ["value"], change) end
    other = hex("an epoch hash no epoch has")
    run = &replay(world, proof, &1)

    [
      passes("reads-stellar-found", path,
        replay: run.(%{}),
        edges: {@s222, @s267},
        rows: [@kec_info]
      ),
      mismatch("reads-stellar-memo_differs", path, run.(%{t3 => &%{&1 | "memo" => other}})),
      mismatch(
        "reads-stellar-memo_type_return",
        path,
        run.(%{t3 => &%{&1 | "memo_type" => "return"}})
      ),
      mismatch(
        "reads-stellar-not_successful",
        path,
        run.(%{t3 => &%{&1 | "successful" => false}})
      ),
      mismatch("reads-stellar-other_ledger", path, run.(%{t3 => &%{&1 | "ledger" => l3 + 1}})),
      no_edge("reads-stellar-not_found-not_yet_indexed", path, "not_yet_indexed",
        replay:
          run.(%{t3 => not_found(), root() => root.(&%{&1 | "latest" => l3 + margin() - 1})})
      ),
      passes("reads-stellar-not_found-below_elder", block_path,
        replay:
          replay(world, block, %{t1 => not_found(), root() => root.(&%{&1 | "elder" => l1 + 1})}),
        edges: {nil, @b228},
        rows: [{"skip", "not_held_by_source", @top_stellar, "CHAIN"}, @kec_info]
      ),
      mismatch(
        "reads-stellar-not_found-elder_at_ledger",
        block_path,
        replay(world, block, %{t1 => not_found(), root() => root.(&%{&1 | "elder" => l1})})
      ),
      no_edge("reads-stellar-not_found-ledger_not_held", path, "not_held_by_source",
        replay: run.(%{t3 => not_found(), root() => world_root, ledger(l3) => not_found()})
      ),
      mismatch(
        "reads-stellar-not_found-ledger_held",
        path,
        run.(%{
          t3 => not_found(),
          root() => root.(&%{&1 | "latest" => l3 + margin()}),
          ledger(l3) => :world
        })
      ),
      no_edge("reads-stellar-ledger_not_found", path, "not_held_by_source",
        replay: run.(%{ledger(l3) => not_found()})
      )
    ]
  end

  # Chain and source reads: the commitment pin and the entropy pin of Stellar on different
  # networks. The item's Stellar commitment entries, at both positions, are on `public`, signed
  # again, and its Stellar witness stays on `testnet`. The public source answers as the world's
  # testnet source does, but for its identity, the production passphrase. So the replay holds
  # the public transactions and the public ledger L, and the testnet ledger of the witness, and
  # a verifier that sends a read to the other pin's source finds no answer.

  defp split_pins(sound, world) do
    %{proof: item} = sound["item"]
    pins = put_in(Case.pins(), ["commitment", "stellar"], "public")
    proof = networks(item, "stellar", "public")

    [
      Case.new("reads-stellar-commitment_public-entropy_testnet",
        proof: {:served, proof},
        networks: pins,
        replay: replay(world, proof["proof"], %{}, pins),
        defect: {:passes, [@kec_info]},
        label: "supplied-keyring",
        edges: {@s222, @s255},
        online_rows: [@kec_info]
      )
    ]
  end

  # One CHAIN failure, chain_mismatch at the /commitments/stellar of the proof at `path`.
  defp mismatch(id, path, replay) do
    fails_one(id, path, {"chain_mismatch", @top_stellar, "CHAIN"},
      replay: replay,
      rows: [{"fail", "chain_mismatch", @top_stellar, "CHAIN"}, @kec_info, @window_prior]
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

  # Chain and source reads: one unreachable read of each kind.

  defp unreachable_reads(sound, world) do
    %{proof: alone, path: alone_path} = sound[@alone]
    %{proof: item, path: item_path} = sound["item"]
    %{proof: block, path: block_path} = sound["block"]
    t3 = transaction(alone, @top_stellar)
    l3 = Edit.get(alone, @top_stellar <> "/ledger")
    nist = "/witnesses/entropy_nist"
    btc = "/witnesses/entropy_bitcoin"

    [
      %{
        passes("reads-unreachable-stellar_root-transaction_found", alone_path,
          replay: replay(world, alone, %{root() => unreachable("HTTP 503")}),
          edges: {@s222, @s267},
          rows: [@kec_info]
        )
        | same_as: "reads-stellar-found"
      },
      no_edge("reads-unreachable-stellar_root", alone_path, "source_unreachable",
        replay: replay(world, alone, %{t3 => not_found(), root() => unreachable("HTTP 429")})
      ),
      no_edge("reads-unreachable-stellar_transaction", alone_path, "source_unreachable",
        replay: replay(world, alone, %{t3 => unreachable("timeout")})
      ),
      no_edge("reads-unreachable-stellar_ledger", alone_path, "source_unreachable",
        replay: replay(world, alone, %{ledger(l3) => unreachable("HTTP 503")})
      ),
      passes("reads-unreachable-bitcoin_tip", item_path,
        replay: replay(world, item, %{tip() => unreachable("connection refused")}),
        edges: {@s222, @s255},
        rows: [
          {"skip", "source_unreachable", @top_bitcoin, "CHAIN"},
          {"skip", "source_unreachable", @ske_bitcoin, "CHAIN"},
          {"skip", "source_unreachable", @ske, "CHAIN"}
        ]
      ),
      passes("reads-unreachable-bitcoin_block_at_height", block_path,
        replay: replay(world, block, %{at(218) => unreachable("HTTP 503")}),
        edges: {nil, @s207},
        rows: [{"skip", "source_unreachable", @top_bitcoin, "CHAIN"}, @kec_info]
      ),
      passes("reads-unreachable-bitcoin_block", item_path,
        replay: replay(world, item, %{by_hash(item, btc) => unreachable("timeout")}),
        edges: {@s222, @s255},
        rows: [@kec_info, {"skip", "source_unreachable", btc, "SOURCES"}]
      ),
      passes("reads-unreachable-nist_pulse", item_path,
        replay: replay(world, item, %{pulse(item, nist) => unreachable("HTTP 503")}),
        edges: {@s222, @s255},
        rows: [@kec_info, {"skip", "source_unreachable", nist, "SOURCES"}]
      )
    ]
  end

  # Chain and source reads: Bitcoin commitment entries and genesis.bitcoin.

  defp bitcoin(sound, world) do
    %{proof: item, path: item_path} = sound["item"]
    %{proof: block, path: block_path} = sound["block"]
    world_tip = World.answer(world, "bitcoin_tip", %{"network" => "regtest"})
    other = Edit.get(block, @ske_bitcoin <> "/header_hash")
    genesis = "/block/record/metadata/genesis/bitcoin"
    h = Edit.get(item, @top_bitcoin <> "/height")

    tip_case = fn id, tip, code ->
      rows =
        if code == nil,
          do: [@kec_info],
          else: [
            {"skip", code, @top_bitcoin, "CHAIN"},
            {"skip", code, @ske_bitcoin, "CHAIN"},
            {"skip", code, @ske, "CHAIN"}
          ]

      passes(id, item_path,
        replay: replay(world, item, %{tip() => put_in(world_tip, ["value", "height"], tip)}),
        edges: {@s222, @s255},
        rows: rows
      )
    end

    block_case = fn id, part, change ->
      fails_one(id, block_path, {"chain_mismatch", part, "CHAIN"},
        replay: replay(world, block, change),
        rows: [{"fail", "chain_mismatch", part, "CHAIN"}, @kec_info, @window_prior]
      )
    end

    absent_case = fn id, height ->
      passes(id, block_path,
        replay: replay(world, block, %{at(height) => not_found()}),
        edges: {nil, @s207},
        rows: [{"skip", "not_held_by_source", @top_bitcoin, "CHAIN"}, @kec_info]
      )
    end

    [
      tip_case.("reads-bitcoin-tip_below_height", h - 1, "not_yet_indexed"),
      tip_case.("reads-bitcoin-tip_at_height", h, "chain_not_final"),
      tip_case.("reads-bitcoin-tip_not_final", h + finality() - 1, "chain_not_final"),
      tip_case.("reads-bitcoin-tip_final", h + finality(), nil),
      block_case.("reads-bitcoin-header_hash_differs", @top_bitcoin, %{
        at(218) => &%{&1 | "hash" => other}
      }),
      block_case.("reads-bitcoin-transaction_count_differs", @top_bitcoin, %{
        at(218) => &%{&1 | "transaction_count" => &1["transaction_count"] + 1}
      }),
      block_case.("reads-bitcoin-genesis_hash_differs", genesis, %{
        at(200) => &%{&1 | "hash" => other}
      }),
      absent_case.("reads-bitcoin-block_not_found", 218),
      absent_case.("reads-bitcoin-candidate_not_found", 228)
    ]
  end

  # Chain and source reads: entropy objects.

  defp entropy(sound, world) do
    %{proof: item, path: item_path} = sound["item"]
    world_root = World.answer(world, "stellar_root", %{"network" => "testnet"})
    nist = "/witnesses/entropy_nist"
    stellar = "/witnesses/entropy_stellar"
    btc = "/witnesses/entropy_bitcoin"
    s1 = entropy_ledger(item, stellar)
    sequence = Edit.get(item, stellar <> "/payload/sequence")
    latest = fn latest -> put_in(world_root, ["value", "latest"], latest) end

    differs = fn id, name, e, {read, change} ->
      %{proof: proof, path: path} = sound[name]

      fails_one(id, path, {"entropy_mismatch", e, "SOURCES"},
        replay: replay(world, proof, %{read.(proof, e) => change}),
        rows: [@kec_info, {"fail", "entropy_mismatch", e, "SOURCES"}, @window_prior]
      )
    end

    absent = fn id, e, changes, {code, edges} ->
      passes(id, item_path,
        replay: replay(world, item, changes),
        edges: edges,
        rows: [@kec_info, {"skip", code, e, "SOURCES"}]
      )
    end

    [
      differs.("reads-entropy-nist-output_value_differs", "item", nist, {
        &pulse/2,
        &%{&1 | "outputValue" => String.duplicate("AB", 64)}
      }),
      differs.("reads-entropy-nist-time_stamp_differs", "entropy_nist", "/subject/entropy", {
        &pulse/2,
        &%{&1 | "timeStamp" => String.replace(&1["timeStamp"], ".000Z", ".001Z")}
      }),
      differs.(
        "reads-entropy-stellar-hash_differs",
        "beacon",
        "/observations/entropy_stellar/entropy",
        {&entropy_ledger/2, &%{&1 | "hash" => hex("a ledger no source closed")}}
      ),
      differs.("reads-entropy-stellar-closed_at_differs", "item", stellar, {
        &entropy_ledger/2,
        &%{&1 | "closed_at" => "2026-09-26T01:48:31Z"}
      }),
      differs.("reads-entropy-bitcoin-height_differs", "entropy_bitcoin", "/subject/entropy", {
        &by_hash/2,
        &%{&1 | "height" => &1["height"] + 1}
      }),
      differs.("reads-entropy-bitcoin-time_differs", "item", btc, {
        &by_hash/2,
        &%{&1 | "time" => &1["time"] + 1}
      }),
      absent.(
        "reads-entropy-nist-not_found",
        nist,
        %{pulse(item, nist) => not_found()},
        {"not_held_by_source", {@s222, @s255}}
      ),
      absent.(
        "reads-entropy-stellar-not_found-not_yet_indexed",
        stellar,
        %{s1 => not_found(), root() => latest.(sequence + margin() - 1)},
        {"not_yet_indexed", {@n018, @s255}}
      ),
      absent.(
        "reads-entropy-stellar-not_found-at_margin",
        stellar,
        %{s1 => not_found(), root() => latest.(sequence + margin())},
        {"not_held_by_source", {@n018, @s255}}
      ),
      absent.(
        "reads-entropy-stellar-not_found-not_held",
        stellar,
        %{s1 => not_found(), root() => world_root},
        {"not_held_by_source", {@n018, @s255}}
      ),
      absent.(
        "reads-entropy-bitcoin-not_found",
        btc,
        %{by_hash(item, btc) => not_found()},
        {"not_held_by_source", {@s222, @s255}}
      )
    ]
  end

  # Chain and source reads: KEY_EVENT_COMMITMENT.

  defp key_event_commitment(sound, world) do
    %{proof: genesis, path: genesis_path} = sound["item-genesis-witness"]
    %{proof: alone, path: alone_path} = sound[@alone]
    ske_genesis = "/signing_key_event/block/record/metadata/genesis/bitcoin"
    witness_genesis = "/witnesses/block/record/metadata/genesis/bitcoin"
    memo = %{transaction(alone, @ske_stellar) => &%{&1 | "memo" => hex("another epoch")}}
    world_tip = World.answer(world, "bitcoin_tip", %{"network" => "regtest"})
    not_final = %{tip() => put_in(world_tip, ["value", "height"], 231)}
    ske_fails = [{"chain_mismatch", @ske_stellar, "CHAIN"}, {"chain_mismatch", @ske, "CHAIN"}]

    [
      passes("reads-key_event_commitment-not_attributable", genesis_path,
        replay: replay(world, genesis, %{}),
        edges: {nil, @s327},
        rows: [@kec_info]
      ),
      fails("reads-key_event_commitment-fail-stellar", alone_path, ske_fails,
        replay: replay(world, alone, memo),
        rows: rows(ske_fails) ++ [@window_prior]
      ),
      fails(
        "reads-key_event_commitment-fail-genesis",
        genesis_path,
        [
          {"chain_mismatch", ske_genesis, "CHAIN"},
          {"chain_mismatch", witness_genesis, "CHAIN"},
          {"chain_mismatch", @ske, "CHAIN"}
        ],
        replay:
          replay(world, genesis, %{
            at(212) => &%{&1 | "hash" => Edit.get(alone, @ske_bitcoin <> "/header_hash")}
          })
      ),
      passes("reads-key_event_commitment-skip", alone_path,
        replay: replay(world, alone, not_final),
        edges: {@s222, @s267},
        rows: [
          {"skip", "chain_not_final", @ske_bitcoin, "CHAIN"},
          {"skip", "chain_not_final", @ske, "CHAIN"}
        ]
      ),
      fails("reads-key_event_commitment-fail_after_skip", alone_path, ske_fails,
        replay: replay(world, alone, Map.merge(not_final, memo)),
        rows:
          [{"skip", "chain_not_final", @ske_bitcoin, "CHAIN"} | rows(ske_fails)] ++
            [@window_prior]
      )
    ]
  end

  # The committed leaf count: the Stellar record lies of Generator.Cases.Derive, run online.
  # Each keeps the transactions of the sound proof it comes from, so its replay is that
  # proof's, from the world: block-rotation's, and block's, which `window-block` writes.

  defp leaf_count(sound, world) do
    ske_fails = [{"chain_mismatch", @ske_stellar, "CHAIN"}, {"chain_mismatch", @ske, "CHAIN"}]

    [
      fails_one(
        "leaf_count-record-commitments-stellar-online",
        "negative/leaf_count-record-commitments-stellar.proof.json",
        {"chain_mismatch", @top_stellar, "CHAIN"},
        replay: replay(world, sound["block-rotation"].proof, %{}),
        rows: [{"fail", "chain_mismatch", @top_stellar, "CHAIN"}, @kec_info, @window_prior]
      ),
      fails(
        "leaf_count-record-signing_key_event-stellar-online",
        "negative/leaf_count-record-signing_key_event-stellar.proof.json",
        ske_fails,
        replay: {:path, "corpus/replay/window-block.json"}
      )
    ]
  end

  # The window.

  defp window(sound, world) do
    %{proof: item, path: item_path} = sound["item"]
    %{proof: block, path: block_path} = sound["block"]
    %{proof: nist, path: nist_path} = sound["entropy_nist"]
    %{proof: alone, path: alone_path} = sound[@alone]
    l255 = ledger(Edit.get(item, @top_stellar <> "/ledger"))
    b215 = by_hash(item, "/witnesses/entropy_bitcoin")
    b232 = at(Edit.get(item, @top_bitcoin <> "/height") + finality())
    closed = fn at -> %{l255 => &%{&1 | "closed_at" => at}} end
    median = fn read, at -> %{read => &%{&1 | "median_time_past" => unix(at)}} end
    outside = {"info", "recorded_time_outside_window", "/subject/record/id", "WINDOW"}

    # item-rotation-witness with the time in its id set to 01:49:00.250, and the hashes above
    # its record made to agree: h6, whose one leaf the item is, and E3, which h6 is alone in
    # and only its Stellar entry commits, so no other entry holds the old epoch.
    later_id =
      alone
      |> Edit.put(
        "/subject/record/id",
        id_at(Edit.get(alone, "/subject/record/id"), "2026-09-26T01:49:00.250Z")
      )
      |> Edit.reitem()

    [
      passes("window-established", item_path,
        replay: replay(world, item, %{}),
        edges: {@s222, @s255},
        rows: [@kec_info]
      ),
      passes("window-block", block_path,
        replay: replay(world, block, %{}),
        edges: {nil, @s207},
        rows: [@kec_info]
      ),
      # Deliberately impossible on a real chain: ledger 1,000,255 closes at 01:45:00, before
      # ledger 1,000,222, which the same replay closes at 01:48:30, though Stellar close times
      # never go backwards. That is how this case gets an inverted window from a sound proof,
      # and SPEC.md 11.3 judges the edges as read.
      fails_one("window-inverted", item_path, {"window_inverted", nil, "WINDOW"},
        replay: replay(world, item, closed.("2026-09-26T01:45:00Z")),
        rows: [@kec_info, {"fail", "window_inverted", nil, "WINDOW"}]
      ),
      # Deliberately impossible on a real chain: ledger 1,000,255 closes at 01:48:45, 15 s
      # after ledger 1,000,222, which is 33 ledgers earlier, though Stellar closes each ledger
      # in whole seconds after the one before it. That is how this case puts the
      # submitted-before edge just before the id, and SPEC.md 11.3 judges the edges as read.
      passes("window-id_later_than_submitted_before", item_path,
        replay: replay(world, item, closed.("2026-09-26T01:48:45Z")),
        edges: {@s222, {"stellar_ledger_close_read", "2026-09-26T01:48:45Z"}},
        rows: [@kec_info, outside]
      ),
      # Deliberately impossible on a real chain: block 215's median time past, 01:49:30, is
      # later than the block's own time, 01:45:00, and a block's median time past is never
      # later than its own time. That is how this case puts the id before the submitted-after
      # edge, and a verifier takes the median time past as the source reports it (SPEC.md
      # 13.2).
      passes("window-id_earlier_than_submitted_after", item_path,
        replay: replay(world, item, median.(b215, "2026-09-26T01:49:30Z")),
        edges: {{"bitcoin_median_time_read", "2026-09-26T01:49:30Z"}, @s255},
        rows: [@kec_info, outside]
      ),
      # Deliberately impossible on a real chain, as above: block 215's median time past,
      # 01:52:00, is later than its own time. Over item-rotation-witness, whose id is 01:51:30,
      # with ledger 1,000,267 not found there is no submitted-before edge, so the WINDOW row is
      # not `pass` and no row reports the id outside the window (SPEC.md 11.3).
      passes("window-id_earlier_than_submitted_after-not_established", alone_path,
        replay:
          replay(
            world,
            alone,
            Map.merge(
              median.(by_hash(alone, "/witnesses/entropy_bitcoin"), "2026-09-26T01:52:00Z"),
              %{ledger(Edit.get(alone, @top_stellar <> "/ledger")) => not_found()}
            )
          ),
        edges: {{"bitcoin_median_time_read", "2026-09-26T01:52:00Z"}, nil},
        rows: [{"skip", "not_held_by_source", @top_stellar, "CHAIN"}, @kec_info, @window_none]
      ),
      # Deliberately impossible on a real chain, as above: ledger 1,000,255 closes at 01:49:00,
      # 30 s after ledger 1,000,222, 33 ledgers earlier. That is how this case puts the
      # submitted-before edge exactly on the id.
      passes("window-id_on_submitted_before", item_path,
        replay: replay(world, item, closed.("2026-09-26T01:49:00Z")),
        edges: {@s222, {"stellar_ledger_close_read", "2026-09-26T01:49:00Z"}},
        rows: [@kec_info]
      ),
      # Deliberately impossible on a real chain: ledger 1,000,267 closes at 01:49:00, 30 s
      # after ledger 1,000,222, which is 45 ledgers earlier, though Stellar closes each ledger
      # in whole seconds after the one before it. That is how this case puts the time in the
      # id, 01:49:00.250, a fraction of a second after the submitted-before edge, which a
      # verifier that compared id times in whole seconds would miss (SPEC.md 11.3). Also
      # impossible: the Stellar transaction keeps the hash the unchanged proof carried, and
      # the replay answers it with the new epoch hash as its memo, which the model's chain
      # would not give; no verifier recomputes a Stellar transaction's hash.
      passes(
        "window-id_milliseconds_after_submitted_before",
        {:served, Case.sign(later_id)},
        replay:
          replay(world, later_id, %{
            ledger(Edit.get(later_id, @top_stellar <> "/ledger")) =>
              &%{&1 | "closed_at" => "2026-09-26T01:49:00Z"},
            transaction(later_id, @top_stellar) =>
              &%{&1 | "memo" => Edit.get(later_id, @top_stellar <> "/epoch/epoch_hash")}
          }),
        edges: {@s222, {"stellar_ledger_close_read", "2026-09-26T01:49:00Z"}},
        rows: [@kec_info, outside]
      ),
      # The NIST pulse's instant, 01:48:00.000, and the ledger's, 01:48:00, are one instant at
      # different precisions, so the window has no width and is not inverted (SPEC.md 11.3).
      passes("window-edges_at_one_instant", nist_path,
        replay:
          replay(world, nist, %{
            ledger(Edit.get(nist, @top_stellar <> "/ledger")) =>
              &%{&1 | "closed_at" => "2026-09-26T01:48:00Z"}
          }),
        edges: {@n018, {"stellar_ledger_close_read", "2026-09-26T01:48:00Z"}},
        rows: [@kec_info, outside]
      ),
      # Block 232's median time past at 01:51:15, the close of ledger 1,000,255: the two
      # candidates of the submitted-before edge tie, and the first in row order,
      # /commitments/bitcoin's, gives the edge and its basis (SPEC.md 11.1).
      passes("window-submitted_before_tie", item_path,
        replay: replay(world, item, median.(b232, "2026-09-26T01:51:15Z")),
        edges: {@s222, {"bitcoin_median_time_read", "2026-09-26T01:51:15Z"}},
        rows: [@kec_info]
      ),
      # Deliberately impossible on a real chain, as above: block 215's median time past,
      # 01:48:30, the close of ledger 1,000,222, is later than its own time. The two latest
      # candidates of the submitted-after edge tie, and the first in row order,
      # /witnesses/entropy_bitcoin's, gives the edge and its basis (SPEC.md 11.2).
      passes("window-submitted_after_tie", item_path,
        replay: replay(world, item, median.(b215, "2026-09-26T01:48:30Z")),
        edges: {{"bitcoin_median_time_read", "2026-09-26T01:48:30Z"}, @s255},
        rows: [@kec_info]
      )
    ]
  end

  # Gates.

  defp gates(sound, world) do
    %{proof: beacon, path: beacon_path} = sound["beacon"]
    policy = "gates-online-policy"

    skipped =
      for {part, step} <- [
            {@top_bitcoin, "CHAIN"},
            {@top_stellar, "CHAIN"},
            {@ske_bitcoin, "CHAIN"},
            {@ske_stellar, "CHAIN"},
            {@ske, "CHAIN"},
            {"/witnesses/entropy_bitcoin", "SOURCES"},
            {"/witnesses/entropy_nist", "SOURCES"},
            {"/witnesses/entropy_stellar", "SOURCES"},
            {nil, "WINDOW"}
          ],
          do: {"skip", "prior_failure", part, step}

    [
      fails_one(
        "gates-online-chain_failure",
        beacon_path,
        {"chain_mismatch", @top_stellar, "CHAIN"},
        replay:
          replay(world, beacon, %{
            transaction(beacon, @top_stellar) => &%{&1 | "memo" => hex("another epoch")}
          }),
        rows: [{"fail", "chain_mismatch", @top_stellar, "CHAIN"}, @kec_info, @window_prior]
      ),
      fails_one(
        policy,
        "negative/policy-commitments-bitcoin.proof.json",
        {"network_mismatch", @top_bitcoin <> "/network", "POLICY"},
        replay: identities(world, Case.pins(), %{}),
        rows: skipped
      ),
      fails_one(
        "gates-online-derive",
        "negative/declared-item_hash.proof.json",
        {"derivation_mismatch", "/subject/item_hash", "DERIVE"},
        replay: {:path, "corpus/replay/#{policy}.json"},
        rows: skipped
      )
    ]
  end

  # Case builders.

  # A case with no failing row, labelled supplied-keyring, whose rows of CHAIN, SOURCES and
  # WINDOW that do not pass are `rows`, and whose proof is the file at `path` or the envelope
  # `{:served, envelope}`.
  defp passes(id, path, options) do
    {rows, options} = Keyword.pop!(options, :rows)

    Case.new(
      id,
      [
        proof: if(is_binary(path), do: {:path, path}, else: path),
        defect: {:passes, rows},
        label: "supplied-keyring",
        online_rows: rows
      ] ++ options
    )
  end

  # A single-defect case whose one failing row is `{code, part, step}`, labelled failed, with
  # both edges null.
  defp fails_one(id, path, {code, part, step}, options) do
    {rows, options} = Keyword.pop!(options, :rows)

    Case.new(
      id,
      [
        proof: {:path, path},
        defect: {:fail, code, part, step},
        label: "failed",
        edges: {nil, nil},
        online_rows: rows
      ] ++ options
    )
  end

  # A case whose failing rows, each `{code, part, step}`, are `failing`, all of CHAIN, with
  # KEY_EVENT_COMMITMENT the last: labelled failed, with both edges null, and, unless the
  # options give them, its rows of CHAIN, SOURCES and WINDOW that do not pass those rows and
  # WINDOW's `skip prior_failure`.
  defp fails(id, path, failing, options) do
    {rows, options} = Keyword.pop(options, :rows, rows(failing) ++ [@window_prior])

    Case.new(
      id,
      [
        proof: {:path, path},
        defect: {:fails, failing},
        label: "failed",
        edges: {nil, nil},
        online_rows: rows
      ] ++ options
    )
  end

  defp rows(failing), do: for({code, part, step} <- failing, do: {"fail", code, part, step})

  # Replays.

  # The replay of `proof` run online under `pins`, those of Generator.Case.pins/0 unless given,
  # from the world (answer/3), then `changes` (change/3).
  defp replay(world, proof, changes, pins \\ Case.pins()) do
    proof
    |> Replay.reads(pins)
    |> Map.new(fn {kind, parameters} = read -> {read, answer(world, kind, parameters)} end)
    |> change(world, changes)
  end

  # The world's answer to a read. The world has no Stellar `public` source, so a read of one is
  # answered as the testnet source answers it, and its identity read with the production
  # passphrase.
  defp answer(_world, "stellar_identity", %{"network" => "public"}),
    do: found(%{"network_passphrase" => Replay.production()["stellar"]})

  defp answer(world, kind, %{"network" => "public"} = parameters),
    do: World.answer(world, kind, %{parameters | "network" => "testnet"})

  defp answer(world, kind, parameters), do: World.answer(world, kind, parameters)

  # A replay of the identity reads of `pins` alone, from the world, then `changes`. The world
  # answers regtest and testnet only, so `changes` answers any other network's.
  defp identities(world, pins, changes) do
    answers =
      for chain <- ~w(bitcoin stellar),
          network <- Enum.uniq([pins["commitment"][chain], pins["entropy"][chain]]),
          {kind, parameters} = read = identity(chain, network),
          not Map.has_key?(changes, read),
          into: %{},
          do: {read, World.answer(world, kind, parameters)}

    change(answers, world, changes)
  end

  # Each change, by its read: an answer puts it; :world puts the world's; :none drops the
  # read; a function passes the world's found value through it. Then every read of a Stellar
  # or Bitcoin network whose identity read is not found with a value step 0 allows is dropped
  # (SPEC.md 13.2).
  defp change(answers, world, changes) do
    answers = Enum.reduce(changes, answers, &put(&2, &1, world))

    records =
      for {{kind, parameters} = read, answer} <- answers,
          sourced?(answers, read),
          do: Replay.record(kind, parameters, answer)

    {:value, Replay.file(records)}
  end

  defp put(answers, {read, :none}, _world), do: Map.delete(answers, read)

  defp put(answers, {{kind, parameters} = read, :world}, world),
    do: Map.put(answers, read, World.answer(world, kind, parameters))

  defp put(answers, {{kind, parameters} = read, edit}, world) when is_function(edit, 1),
    do: Map.put(answers, read, update_in(World.answer(world, kind, parameters), ["value"], edit))

  defp put(answers, {read, answer}, _world), do: Map.put(answers, read, answer)

  # Whether the replay form lets a replay holding `answers` hold `read`.
  defp sourced?(answers, {kind, %{"network" => network}}) do
    {chain, _parameters, _fields, _outcomes} = Map.fetch!(Replay.kinds(), kind)

    case Map.get(answers, identity(chain, network)) do
      _identity when kind in ~w(bitcoin_identity stellar_identity) -> true
      %{"outcome" => "found", "value" => value} -> Replay.allowed?(chain, network, value)
      _no_usable_answer -> false
    end
  end

  defp sourced?(_answers, _read), do: true

  # Reads, each `{kind, parameters}`.

  defp identity(chain, network), do: {chain <> "_identity", %{"network" => network}}
  defp keyring, do: {"keyring", %{"url" => @keyring_url}}
  defp root, do: {"stellar_root", %{"network" => "testnet"}}
  defp tip, do: {"bitcoin_tip", %{"network" => "regtest"}}
  defp ledger(sequence), do: {"stellar_ledger", %{"network" => "testnet", "sequence" => sequence}}

  defp at(height),
    do: {"bitcoin_block_at_height", %{"height" => height, "network" => "regtest"}}

  defp transaction(proof, n),
    do:
      {"stellar_transaction",
       %{"hash" => Edit.get(proof, n <> "/transaction_hash"), "network" => "testnet"}}

  # The read of the entropy object at `e`.
  defp pulse(proof, e),
    do:
      {"nist_pulse", Map.take(Edit.get(proof, e <> "/payload/pulse"), ~w(chainIndex pulseIndex))}

  defp entropy_ledger(proof, e), do: ledger(Edit.get(proof, e <> "/payload/sequence"))

  defp by_hash(proof, e),
    do:
      {"bitcoin_block",
       %{"hash" => Edit.get(proof, e <> "/payload/hash"), "network" => "regtest"}}

  # The UUIDv7 `id` with the instant `time` in its leftmost 48 bits, its first 12 hex digits,
  # as milliseconds since the Unix epoch (SPEC.md 11.3), and every other bit kept.
  defp id_at(<<_head::binary-8, "-", _middle::binary-4, rest::binary>>, time) do
    {:ok, instant, 0} = DateTime.from_iso8601(time)

    <<head::binary-8, middle::binary-4>> =
      instant
      |> DateTime.to_unix(:millisecond)
      |> Integer.to_string(16)
      |> String.downcase()
      |> String.pad_leading(12, "0")

    head <> "-" <> middle <> rest
  end

  # Answers.

  defp found(value), do: %{"outcome" => "found", "value" => value}
  defp not_found, do: %{"outcome" => "not_found"}
  defp unreachable(reason), do: %{"outcome" => "unreachable", "reason" => reason}

  defp hex(label), do: Base.encode16(:crypto.hash(:sha256, label), case: :lower)

  # A TIME as Unix seconds, as a Bitcoin time is written in a replay.
  defp unix(time) do
    {:ok, instant, 0} = DateTime.from_iso8601(time)
    DateTime.to_unix(instant)
  end

  defp finality, do: Spec.read("constants.json")["BITCOIN_FINALITY"]
  defp margin, do: Spec.read("constants.json")["STELLAR_INDEX_MARGIN"]
end
