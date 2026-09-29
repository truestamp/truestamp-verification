# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Generator.Model do
  @moduledoc """
  The expected-output model: what a conforming verifier gives for a case of
  vectors/cases.json, computed by the generator's own model of the verification steps of
  SPEC.md 10.2, shared with no verifier. It extends the DERIVE engine (Generator.Derive),
  which gives step 9's rows, with every other step:

  - CONFIGURATION (step 0) from the case's `config`: E_v, the network pins and the keyring
    that governs, with the load checks of step 0 on every keyring loaded; an absent `keyring`
    under `prod` is the compiled pin, spec/keyring.production.json, offline, and online the
    keyring read at www.truestamp.com, which binds no key when the read fails for any reason
    (`keyring_unavailable`); the keyring `unavailable` is that failed read, and a case that
    names it with a replay whose keyring read succeeds raises. An online case, whose `online`
    names its replay file, also has step 0's identity reads (Generator.Model.Online).
  - READ and PARSE (steps 1 and 2) by the model's own reader (Generator.Parse), and ENVELOPE
    (step 3) in its order of six checks. A failure at steps 0 to 3 is a bare rejection,
    `{:bare, code, sub_reason}`.
  - ENVIRONMENT, KEY_BINDING and SIGNATURE (steps 4 to 6), the gate; SHAPE (step 7), with the
    schema interpreted by Generator.Schema; POLICY (step 8) against the case's pins; DERIVE
    (step 9), each failing row with the code SPEC.md 10.2 and 10.3 give its check.
  - The external gate, decided once when DERIVE ends: open when the case is online and no row
    so far fails. Open, CHAIN, SOURCES and WINDOW are the reads of the case's replay
    (Generator.Model.Online), and a failure at CHAIN leaves SOURCES open. Closed, every CHAIN
    row, the KEY_EVENT_COMMITMENT row included, and every SOURCES row is `skip prior_failure`
    after a failed row and `skip offline` otherwise, and WINDOW is `skip prior_failure` after a
    failed row and `info window_not_established` otherwise, since no edge is drawn.
  - EXPECTED_HASH (step 13) with the case's `expected_hash`, or `skip expected_hash_not_checked`
    without one; VERDICT (step 14) gives the label from the rows, the attribution and the
    submitted-before edge, and sets both edges to null when the label is `failed`.
  - A failure at steps 4 to 7 ends the run: each later step up to EXPECTED_HASH gives one row,
    `skip prior_failure`, with part null.

  past/3 runs a case again with no such stop, for the check of Generator.Cases that looks past
  it: every check of steps 4 to 7 is made whatever fails before it, SHAPE gives a row for each
  failure of each of its checks, and the steps after SHAPE run as if it had passed. The failure
  it looked past keeps the external gate closed, so such a run reads nothing.

  A report is `%{label, attribution, rows, trace, online, submitted_after,
  submitted_before}`, each row `%{code, part, status, step}` in the order of SPEC.md 10.2,
  `trace` the trace of SPEC.md 10.6 (Generator.Derive.trace/2), nil when DERIVE did not run,
  `online` whether the case is online, and each edge nil or `%{basis, instant, part}`.
  """

  alias Generator.{Bytes, Derive, JCS, Keys, Parse, Pointer, Registry, Schema, Spec}
  alias Generator.Model.Online

  @steps ~w(CONFIGURATION READ PARSE ENVELOPE ENVIRONMENT KEY_BINDING SIGNATURE SHAPE POLICY
            DERIVE CHAIN SOURCES WINDOW EXPECTED_HASH)
  @alg "truestamp-ed25519-sha256-jcs"
  @blocks ~w(/block /witnesses/block /signing_key_event/block)
  @entries ~w(/commitments /signing_key_event/commitments)

  # SPEC.md 10.2 step 13: the hex characters of each hash_type's hash.
  @hash_lengths %{
    "md5" => 32,
    "sha1" => 40,
    "sha224" => 56,
    "sha3_224" => 56,
    "sha256" => 64,
    "sha3_256" => 64,
    "blake2s" => 64,
    "sha384" => 96,
    "sha3_384" => 96,
    "sha512" => 128,
    "sha3_512" => 128,
    "blake2b" => 128
  }

  @doc "The number of hex characters SPEC.md 10.2 step 13 fixes for a hash of `hash_type`, or nil."
  def hash_length(hash_type), do: Map.get(@hash_lengths, hash_type)

  # The code a failing DERIVE row gives, by its check (SPEC.md 10.2 step 9 and 10.3); every
  # check this does not name gives derivation_mismatch.
  @derive_codes %{
    raw_transaction_well_formed: "bitcoin_evidence_invalid",
    txoutproof_well_formed: "bitcoin_evidence_invalid",
    key_public_key: "key_event_mismatch",
    key_id: "key_event_mismatch",
    key_signing_key_id: "key_event_mismatch",
    previous_key_id: "key_event_mismatch",
    event_height: "key_event_mismatch",
    event_previous_block_hash: "key_event_mismatch",
    handover_signature: "key_event_mismatch",
    prerotation_signing_key_id: "key_event_mismatch",
    key_event_link: "key_event_mismatch",
    head: "ordering_violation",
    chain_order_stellar: "ordering_violation",
    chain_order_bitcoin: "ordering_violation"
  }

  @doc "Every step's name, in the order of SPEC.md 10.2."
  def steps, do: @steps

  @doc """
  The output for the file `bytes` under the case configuration `config` (the `config` member
  of a case, with string names), where `files` holds every file under vectors/ by its path
  from the repository's root: `{:bare, code, sub_reason}` or `{:report, report}`.
  """
  def run(bytes, config, files), do: run(bytes, config, files, false)

  @doc """
  The output of run/3 with no stop at steps 4 to 7, as if each failure there had passed: the
  gate's three rows, a SHAPE row for each failure of each of its checks, and every later step.
  A case that fails at steps 0 to 3 gives the same bare rejection.
  """
  def past(bytes, config, files), do: run(bytes, config, files, true)

  defp run(bytes, config, files, past?) do
    with {:ok, run} <- configure(config, files),
         {:ok, document} <- Parse.read(bytes),
         :ok <- envelope(document) do
      {:report, report(document, Map.put(run, :past, past?))}
    end
  end

  @doc "A case's `expected` member for an output of run/3 (SPEC.md 13.1 and 13.2)."
  def expected({:bare, code, nil}), do: %{"code" => code}
  def expected({:bare, code, sub_reason}), do: %{"code" => code, "sub_reason" => sub_reason}

  def expected({:report, report}) do
    expected = %{"label" => report.label, "rows" => Enum.map(report.rows, &compared/1)}

    if report.online,
      do:
        Map.merge(expected, %{
          "submitted_after" => edge(report.submitted_after),
          "submitted_before" => edge(report.submitted_before)
        }),
      else: expected
  end

  @doc "An edge as SPEC.md 13.1 compares it: nil, or its `basis` and `instant`."
  def edge(nil), do: nil
  def edge(%{basis: basis, instant: instant}), do: %{"basis" => basis, "instant" => instant}

  @doc "A row as SPEC.md 13.1 compares it: `[code, part, status, step]`."
  def compared(row), do: [row.code, row.part, row.status, row.step]

  # Step 0.

  defp configure(config, files) do
    ev = Map.fetch!(config, "environment")

    if ev not in ["prod" | Spec.read("encodings.json")["ENV"]["values"]],
      do: raise(ArgumentError, "#{inspect(ev)} is no verifier's environment (SPEC.md 6.4)")

    with {:ok, online} <- Online.sources(Online.replay(config, files)),
         {:ok, trust} <- trust(Map.get(config, "keyring"), ev, files, online) do
      {:ok,
       %{
         ev: ev,
         pins: Map.fetch!(config, "networks"),
         trust: trust,
         expected_hash: Map.get(config, "expected_hash"),
         online: online
       }}
    else
      :error -> {:bare, "configuration_error", nil}
    end
  end

  # The keyring that governs: keyless mode, a supplied keyring (`test` or a file's path under
  # vectors/), or with no keyring option under prod the compiled pin offline and the keyring
  # read at www.truestamp.com online, and under any other E_v nothing, which is
  # configuration_error (SPEC.md 6.4 and 8.3). The keyring `unavailable` is no keyring option
  # under prod, online, with that read failing (SPEC.md 13.2).
  defp trust("none", _ev, _files, _online), do: {:ok, :keyless}

  defp trust(option, "prod", _files, online)
       when option in [nil, "unavailable"] and online != nil do
    case Online.keyring(online) do
      :failed -> {:ok, :unavailable}
      {:ok, bytes} -> current(load(bytes, "prod"), option, online)
    end
  end

  defp trust("unavailable", _ev, _files, _online),
    do: raise(ArgumentError, "the keyring unavailable is an online run under prod (SPEC.md 13.2)")

  defp trust(nil, "prod", _files, nil) do
    bytes = Spec.root() |> Path.join("spec/keyring.production.json") |> File.read!()
    with {:ok, keys} <- load(bytes, "prod"), do: {:ok, {:pin, keys}}
  end

  defp trust(nil, _ev, _files, _online), do: :error

  defp trust("test", ev, files, _online),
    do: supplied(Map.fetch!(files, "vectors/keyring.test.json"), ev)

  defp trust(path, ev, files, _online), do: supplied(Map.fetch!(files, "vectors/" <> path), ev)

  # The keyring read online: a keyring that fails a load check is a failed read.
  defp current(:error, _option, _online), do: {:ok, :unavailable}
  defp current({:ok, keys}, nil, _online), do: {:ok, {:current, keys}}

  defp current({:ok, _keys}, "unavailable", online),
    do:
      raise(
        ArgumentError,
        "the keyring unavailable, but #{online.path} gives a keyring that passes the load checks"
      )

  defp supplied(bytes, ev) do
    with {:ok, keys} <- load(bytes, ev) do
      {:ok, {:supplied, "keyring:" <> Bytes.hex(:crypto.hash(:sha256, bytes)), keys}}
    end
  end

  # The load checks of SPEC.md 10.2 step 0, after the parsing rules: the keys' 32 octets each,
  # or :error.
  defp load(bytes, ev) do
    with {:ok, %{"keys" => keys, "version" => "1.0"} = keyring} when map_size(keyring) == 2 <-
           Parse.read(bytes),
         true <- is_list(keys) and Enum.all?(keys, &key_form?/1),
         publics = Enum.map(keys, &Bytes.unb64u(&1["public_key"])),
         true <- unique?(Enum.map(keys, & &1["key_id"])) and unique?(publics),
         true <- Enum.all?(publics, &Derive.key_bytes?/1),
         true <- ev == "test" or vector_key() not in publics,
         true <- ev != "prod" or not Enum.any?(publics, &nonproduction?/1) do
      {:ok, publics}
    else
      _failure -> :error
    end
  end

  defp key_form?(%{"active" => active, "key_id" => key_id, "public_key" => public} = key) do
    map_size(key) == 4 and is_boolean(active) and Spec.class?("KID", key_id) and
      Spec.class?("B64U32", public) and int?(key["sequence"]) and
      Keys.key_id(Bytes.unb64u(public)) == key_id
  end

  defp key_form?(_other), do: false

  defp int?(n), do: is_integer(n) and n in 0..9_007_199_254_740_991//1

  defp unique?(values), do: length(Enum.uniq(values)) == length(values)

  defp vector_key, do: Bytes.unhex(Spec.read("constants.json")["VECTOR_KEY"])

  defp nonproduction?(public) do
    listed = for key <- Spec.read("keys.nonproduction.json")["keys"], do: key["public_key"]
    Bytes.b64u(public) in listed
  end

  # Step 3: the first of the six checks that fails names the sub_reason.
  defp envelope(document) do
    signature = if is_map(document), do: document["signature"], else: nil

    checks = [
      {"document", fn -> is_map(document) and members(document) == ~w(proof signature) end},
      {"proof", fn -> is_map(document["proof"]) end},
      {"signature",
       fn -> is_map(signature) and members(signature) == ~w(alg public_key value) end},
      {"alg", fn -> signature["alg"] === @alg end},
      {"public_key", fn -> key?(signature["public_key"]) end},
      {"value", fn -> Spec.class?("B64U64", signature["value"]) end}
    ]

    case Enum.find(checks, fn {_name, check} -> not check.() end) do
      nil -> :ok
      {name, _check} -> {:bare, "invalid_envelope", name}
    end
  end

  defp members(object), do: object |> Map.keys() |> Enum.sort()

  defp key?(text), do: Spec.class?("B64U32", text) and Derive.key_bytes?(Bytes.unb64u(text))

  # Steps 4 to 14.

  defp report(document, run) do
    proof = document["proof"]
    k = Bytes.unb64u(document["signature"]["public_key"])
    opening = for step <- ~w(CONFIGURATION READ PARSE ENVELOPE), do: row("pass", nil, nil, step)

    gate = [
      environment(proof, run.ev),
      key_binding(k, run.trust),
      signature(document, k)
    ]

    case {Enum.split_while(gate, &(&1.status != "fail")), run.past} do
      {{passed, [failed | _later]}, false} -> stopped(opening ++ passed ++ [failed], "none", run)
      _passed_or_past -> shaped(document, k, run, opening ++ gate, attribution(run.trust))
    end
  end

  defp row(status, code, part, step), do: %{code: code, part: part, status: status, step: step}

  defp check(true, _code, part, step), do: row("pass", nil, part, step)
  defp check(false, code, part, step), do: row("fail", code, part, step)

  # A run that a failure at steps 4 to 7 ended: each later step up to EXPECTED_HASH gives one
  # row, skip prior_failure, with part null.
  defp stopped(rows, attribution, run) do
    last = List.last(rows).step
    later = @steps |> Enum.drop_while(&(&1 != last)) |> Enum.drop(1)
    skipped = for step <- later, do: row("skip", "prior_failure", nil, step)

    %{
      label: "failed",
      attribution: attribution,
      rows: rows ++ skipped,
      trace: nil,
      online: run.online != nil,
      submitted_after: nil,
      submitted_before: nil
    }
  end

  defp attribution(:keyless), do: "unattributed"
  defp attribution({:supplied, digest, _keys}), do: digest
  defp attribution({:pin, _keys}), do: "truestamp"
  defp attribution({:current, _keys}), do: "truestamp"
  defp attribution(:unavailable), do: "none"

  # SPEC.md 6.4.
  defp environment(proof, "prod"),
    do:
      check(
        not Map.has_key?(proof, "environment"),
        "environment_mismatch",
        "/environment",
        "ENVIRONMENT"
      )

  defp environment(proof, ev),
    do:
      check(
        Map.get(proof, "environment") === ev,
        "environment_mismatch",
        "/environment",
        "ENVIRONMENT"
      )

  defp key_binding(_k, :keyless), do: row("skip", "key_binding_not_performed", nil, "KEY_BINDING")

  defp key_binding(_k, :unavailable),
    do: row("fail", "keyring_unavailable", nil, "KEY_BINDING")

  defp key_binding(k, {_kind, _digest, keys}),
    do: check(k in keys, "key_binding_failed", nil, "KEY_BINDING")

  defp key_binding(k, {_kind, keys}),
    do: check(k in keys, "key_binding_failed", nil, "KEY_BINDING")

  defp signature(%{"proof" => proof, "signature" => %{"value" => value}}, k) do
    proof_hash = Registry.record_hash("proof_hash", proof)
    check(Derive.verify?(k, proof_hash, value), "signature_invalid", nil, "SIGNATURE")
  end

  defp shaped(%{"proof" => proof} = document, k, run, rows, attribution) do
    case {shape(document, run.past), run.past} do
      {[], _past} ->
        derived(proof, k, run, rows ++ [row("pass", nil, nil, "SHAPE")], attribution)

      {[{code, part} | _later], false} ->
        stopped(rows ++ [row("fail", code, part, "SHAPE")], attribution, run)

      {failures, true} ->
        shape = for {code, part} <- failures, do: row("fail", code, part, "SHAPE")
        derived(proof, k, run, rows ++ shape, attribution)
    end
  end

  # Step 7, its checks in order, each giving its failures in document order: the first failure
  # of the first check that fails is the step's one failing row, and no later check is made.
  # Past a stop, every check is made, and each distinct failure is a row.
  defp shape(%{"proof" => proof} = document, past?) do
    checks = [
      fn -> if proof["format"] !== "truestamp-proof", do: [{"unsupported_format", "/format"}] end,
      fn -> if proof["version"] !== 1, do: [{"unsupported_version", "/version"}] end,
      fn -> schema(document) end,
      fn -> witnesses(proof) end,
      fn -> times(proof) end,
      fn -> constructions(proof) end
    ]

    if past?,
      do: checks |> Enum.flat_map(&(&1.() || [])) |> Enum.uniq(),
      else: Enum.find_value(checks, [], & &1.())
  end

  # Check 3: each failure of spec/schema.json, a schema of the envelope, in document order.
  # ENVELOPE has passed the signature member, so every failure is in P.
  defp schema(%{"proof" => proof} = document) do
    case Schema.failures(document) do
      [] ->
        nil

      failures ->
        for("/proof" <> part <- failures, do: part)
        |> Enum.uniq()
        |> Enum.sort_by(&Pointer.order_key(proof, &1))
        |> Enum.map(&{"shape_invalid", &1})
    end
  end

  # Check 4.
  defp witnesses(%{"type" => "item"} = proof) do
    names = proof["witnesses"] |> Map.keys() |> Enum.sort()
    hashes = proof["subject"]["record"]["witness_hashes"] |> Map.keys() |> Enum.sort()
    if names != hashes, do: [{"shape_invalid", "/witnesses"}]
  end

  defp witnesses(_proof), do: nil

  # Check 5: each TIME or NISTTIME value, outside the claims, that is not the formatting of its
  # own parse, in document order.
  defp times(proof) do
    case for(
           {pointer, class} <- time_values(proof, ""),
           not time?(class, Pointer.get(proof, pointer)),
           do: pointer
         ) do
      [] ->
        nil

      parts ->
        parts |> Enum.sort_by(&Pointer.order_key(proof, &1)) |> Enum.map(&{"shape_invalid", &1})
    end
  end

  defp time_values(map, pointer) when is_map(map) and pointer != "/subject/claims" do
    Enum.flat_map(map, fn
      {name, _value} when name in ~w(header_time closed_at) -> [{pointer <> "/" <> name, :time}]
      {"timeStamp", _value} -> [{pointer <> "/timeStamp", :nist}]
      {name, value} -> time_values(value, pointer <> "/" <> name)
    end)
  end

  defp time_values(list, pointer) when is_list(list) do
    list
    |> Enum.with_index()
    |> Enum.flat_map(fn {value, i} -> time_values(value, "#{pointer}/#{i}") end)
  end

  defp time_values(_value, _pointer), do: []

  @time ~r/\A(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(\.\d{3})?Z\z/

  # A time the round trip keeps: a real date, an hour below 24, and a minute and a second
  # below 60 (SPEC.md 2.4).
  defp time?(class, text) do
    with true <- is_binary(text),
         [_all | fields] <- Regex.run(@time, text),
         {clock, fraction} = Enum.split(fields, 6),
         true <- class == :nist == (fraction != []) do
      [y, m, d, h, min, s] = Enum.map(clock, &String.to_integer/1)
      Calendar.ISO.valid_date?(y, m, d) and h < 24 and min < 60 and s < 60
    else
      _failure -> false
    end
  end

  # Check 6.
  defp constructions(%{"constructions" => value}) do
    accepted =
      for path <- Path.wildcard(Path.join(Spec.root(), "spec/constructions/*.json")),
          do: Path.basename(path, ".json")

    if digest(value) not in accepted, do: [{"construction_mismatch", "/constructions"}]
  end

  defp constructions(_none), do: nil

  defp digest(text) when is_binary(text), do: text |> String.slice(-69, 64)
  defp digest(object), do: Bytes.hex(:crypto.hash(:sha256, JCS.encode(object)))

  defp derived(proof, k, run, rows, attribution) do
    policy = policy(proof, run.pins)
    derive = Derive.rows(proof, k, attribution)
    derive_rows = Enum.map(derive, &derive_row/1)
    failed = Enum.any?(rows ++ policy ++ derive_rows, &(&1.status == "fail"))
    {reads, edges} = reads(proof, run, failed, attribution)
    rows = rows ++ policy ++ derive_rows ++ reads ++ [expected_hash(proof, run.expected_hash)]
    label = label(rows, attribution, edges)

    # VERDICT: a report labelled failed shows no window (SPEC.md 10.2 step 14).
    edges =
      if label == "failed", do: %{submitted_after: nil, submitted_before: nil}, else: edges

    Map.merge(edges, %{
      label: label,
      attribution: attribution,
      rows: rows,
      trace: Derive.trace(proof, derive),
      online: run.online != nil
    })
  end

  defp label(rows, attribution, edges) do
    cond do
      Enum.any?(rows, &(&1.status == "fail")) -> "failed"
      attribution == "unattributed" -> "unattributed"
      String.starts_with?(attribution, "keyring:") -> "supplied-keyring"
      edges.submitted_before != nil -> "verified"
      true -> "internally-consistent"
    end
  end

  # Steps 10 to 12, with the external gate decided once, when DERIVE ends: open when the case
  # is online and no row so far has failed (SPEC.md 10.2).
  defp reads(proof, %{online: online}, false, attribution) when online != nil,
    do: open(proof, online, attribution)

  defp reads(proof, _run, failed, _attribution) do
    closed = if failed, do: "prior_failure", else: "offline"

    window =
      if failed,
        do: row("skip", "prior_failure", nil, "WINDOW"),
        else: row("info", "window_not_established", nil, "WINDOW")

    {chain(proof, closed) ++ sources(proof, closed) ++ [window],
     %{submitted_after: nil, submitted_before: nil}}
  end

  # The gate open: each CHAIN and SOURCES row read from the replay, in document order,
  # KEY_EVENT_COMMITMENT from its inputs, and WINDOW from the candidates of the rows that
  # passed (Generator.Model.Online).
  defp open(proof, online, attribution) do
    chain =
      for part <- in_order(proof, entries(proof) ++ genesis_bitcoin(proof)),
          do: {part, Online.chain(proof, part, online)}

    sources =
      for part <- in_order(proof, entropy_objects(proof)),
          do: {part, Online.source(proof, part, online)}

    chain_rows = Enum.map(chain, &read_row(&1, "CHAIN"))
    source_rows = Enum.map(sources, &read_row(&1, "SOURCES"))
    rows = chain_rows ++ key_event_commitment(proof, chain_rows, attribution) ++ source_rows
    failed? = Enum.any?(rows, &(&1.status == "fail"))

    {window, edges} =
      Online.window(candidates(chain), candidates(sources), failed?, subject_id(proof))

    window_rows = for {status, code, part} <- window, do: row(status, code, part, "WINDOW")
    {rows ++ window_rows, edges}
  end

  defp in_order(proof, parts), do: Enum.sort_by(parts, &Pointer.order_key(proof, &1))

  defp read_row({part, {status, code, _candidate}}, step), do: row(status, code, part, step)

  defp candidates(outcomes),
    do: for({_part, {"pass", nil, candidate}} <- outcomes, candidate != nil, do: candidate)

  # KEY_EVENT_COMMITMENT, the last row of CHAIN, from the CHAIN rows under
  # /signing_key_event/commitments and, for a genesis event, that of its genesis.bitcoin
  # (SPEC.md 10.3).
  defp key_event_commitment(%{"signing_key_event" => _event}, chain_rows, attribution) do
    inputs =
      Enum.filter(chain_rows, fn row ->
        String.starts_with?(row.part, "/signing_key_event/commitments/") or
          row.part == "/signing_key_event/block/record/metadata/genesis/bitcoin"
      end)

    {status, code} = Online.key_event_commitment(inputs, attribution)
    [row(status, code, "/signing_key_event", "CHAIN")]
  end

  defp key_event_commitment(_proof, _chain_rows, _attribution), do: []

  # SPEC.md 10.5's `subject_id`, by its pointer: the subject's id, or /block's for a block or a
  # beacon.
  defp subject_id(%{"type" => type} = proof) when type in ~w(block beacon),
    do: {"/block/record/id", Pointer.get(proof, "/block/record/id")}

  defp subject_id(proof), do: {"/subject/record/id", Pointer.get(proof, "/subject/record/id")}

  # Step 8: every network against its pin, in document order.
  defp policy(proof, pins) do
    commitment = Map.fetch!(pins, "commitment")
    entropy = Map.fetch!(pins, "entropy")

    entries =
      for n <- entries(proof), do: {n <> "/network", Map.fetch!(commitment, chain(n))}

    objects =
      for e <- entropy_objects(proof),
          %{"source" => source, "network" => _network} <- [Pointer.get(proof, e)],
          do: {e <> "/network", Map.fetch!(entropy, source)}

    genesis =
      for g <- genesis_bitcoin(proof), do: {g <> "/network", Map.fetch!(commitment, "bitcoin")}

    (entries ++ objects ++ genesis)
    |> Enum.map(fn {pointer, pin} ->
      check(Pointer.get(proof, pointer) === pin, "network_mismatch", pointer, "POLICY")
    end)
    |> in_document_order(proof)
  end

  defp in_document_order(rows, proof), do: Enum.sort_by(rows, &Pointer.order_key(proof, &1.part))

  defp chain(n), do: n |> String.split("/") |> List.last()

  defp entries(proof) do
    for base <- @entries,
        name <- Map.keys(Pointer.get(proof, base) || %{}),
        do: base <> "/" <> name
  end

  defp entropy_objects(proof) do
    subject =
      if String.starts_with?(proof["type"], "entropy_"), do: ["/subject/entropy"], else: []

    witnesses =
      for name <- Map.keys(proof["witnesses"] || %{}), name != "block", do: "/witnesses/" <> name

    observations =
      for name <- Map.keys(proof["observations"] || %{}), do: "/observations/#{name}/entropy"

    subject ++ witnesses ++ observations
  end

  defp genesis_bitcoin(proof) do
    for b <- @blocks,
        Pointer.get(proof, b <> "/record/metadata/genesis") != nil,
        do: b <> "/record/metadata/genesis/bitcoin"
  end

  defp derive_row(%{status: "fail", check: check, part: part}),
    do: row("fail", Map.get(@derive_codes, check, "derivation_mismatch"), part, "DERIVE")

  defp derive_row(%{status: status, code: code, part: part}),
    do: row(status, code, part, "DERIVE")

  # Step 10, offline: one row for each commitment entry and each genesis.bitcoin, in document
  # order, then KEY_EVENT_COMMITMENT when the proof carries signing_key_event.
  defp chain(proof, closed) do
    rows =
      (entries(proof) ++ genesis_bitcoin(proof))
      |> Enum.map(&row("skip", closed, &1, "CHAIN"))
      |> in_document_order(proof)

    if Map.has_key?(proof, "signing_key_event"),
      do: rows ++ [row("skip", closed, "/signing_key_event", "CHAIN")],
      else: rows
  end

  # Step 11, offline: one row for each entropy object, in document order.
  defp sources(proof, closed) do
    proof
    |> entropy_objects()
    |> Enum.map(&row("skip", closed, &1, "SOURCES"))
    |> in_document_order(proof)
  end

  # Step 13.
  defp expected_hash(_proof, nil),
    do: row("skip", "expected_hash_not_checked", nil, "EXPECTED_HASH")

  defp expected_hash(proof, given) do
    part = "/subject/claims/hash"
    claims = if proof["type"] == "item", do: Pointer.get(proof, "/subject/claims"), else: %{}

    case {matched?(claims, String.downcase(given)), claims["hash_type"]} do
      {true, weak} when weak in ~w(md5 sha1) ->
        row("warn", "expected_hash_weak_algorithm", part, "EXPECTED_HASH")

      {true, _strong} ->
        row("pass", nil, part, "EXPECTED_HASH")

      {false, _hash_type} ->
        row("fail", "expected_hash_mismatch", part, "EXPECTED_HASH")
    end
  end

  # The caller's lowercased hash is hex of the length its hash_type gives, and equals the
  # claims' hash.
  defp matched?(%{"hash_type" => hash_type, "hash" => hash}, value) when is_binary(hash) do
    length = Map.get(@hash_lengths, hash_type)
    length != nil and byte_size(value) == length and value =~ ~r/\A[0-9a-f]*\z/ and value == hash
  end

  defp matched?(_claims, _value), do: false
end
