# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Generator.Replay do
  @moduledoc """
  The replay file of an online case (SPEC.md 13.2): the answers a verifier's reads get, one
  answer per read, recorded at the level of the read and never as a service's web exchange.
  A replay file is `corpus/replay/<id>.json`, where `<id>` is the id of a case that names it,
  in the canonical form of SPEC.md 9. Its form, which validate/1 checks:

  - The file is an object whose one member, `reads`, is an array of records, each
    `{answer, read}`, no two with the same `read`. The order carries no meaning; the
    generator writes them by `kind`, then in the byte order of JCS(read).
  - `read` names the read: `kind`, then `network` for a read of a Stellar or Bitcoin source,
    then the read's parameters, each as the proof spells the value it comes from. So a
    verifier finds its answer by building the same object and comparing values.
  - `answer` is `{outcome: "found", value}`, `{outcome: "not_found"}` or `{outcome:
    "unreachable", reason}`, where `reason` is for people and changes nothing. An identity
    read, the Stellar root, the Bitcoin tip and the keyring are found or unreachable, never
    not found.
  - The parameters of each kind of read, and the fields of a found answer's `value`, each
    with its class, are those of SPEC.md 13.2's table, which spec_table/1 reads from SPEC.md
    and holds @kinds to. A value holds exactly the fields SPEC.md 10.4 and 10.2 step 0 use
    for its kind, and one record answers every use of its read, so its value holds every
    field any use of that kind needs. Nothing in it is of any service's API: hashes are HEX64
    in the order the proof spells them (a Bitcoin block's hash in display order), `memo` the
    32 bytes in hex, and Bitcoin times and heights INT, `time` and `median_time_past` in Unix
    seconds. A Bitcoin block's median time past is only ever the source's report of it, so a
    verifier under test takes it from the replay. `keyring` is the keyring read, any JSON
    value the canonical form of SPEC.md 9 can hold, which the verifier's load checks then
    judge, and the `url` of a keyring read is `https://<host>/.well-known/keyring.json` for
    the host of the origin read from.
  - Every read of an online case is answered from its file, and the file stands as the
    operator-pinned source for each Stellar or Bitcoin network whose identity read it holds.
    Every other read of a Stellar or Bitcoin network is held only when the identity read of
    that network is found with a value SPEC.md 10.2 step 0 allows for the network, so a
    verifier that reads past a failed identity read finds no answer. A read the file does not
    hold is not an answer: the test that runs the case fails. A verifier makes only the reads
    of SPEC.md 10.2 step 0 and 10.4, and need not make every read the file holds.

  The replay files are the online cases' (Generator.Cases.Online), each built from the model's
  sources (Generator.Replay.World), and the check holds every one to the form. Each run also
  builds, in memory, the replay of the sound item run online under the pins every sound proof
  passes POLICY under (example/1), and holds each rule of the form to a mutant of it that the
  rule refuses.
  """

  import Generator.Check

  alias Generator.{Case, Chain, JCS, Parse, Pointer, Spec}
  alias Generator.Replay.World

  @keyring_url "https://<host>/.well-known/keyring.json"
  @host ~S"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)*"
  @max_integer 9_007_199_254_740_991
  @found ~w(found unreachable)
  @all ~w(found not_found unreachable)
  @table "| `kind` | Parameters | Fields of `value` |"

  # Each kind: its chain (nil for NIST and the keyring), its parameters, the fields of a found
  # answer, and its outcomes. A field that `{:only_when, class, field, values}` names is in a
  # value exactly when that value's `field` is one of `values`.
  @kinds %{
    "bitcoin_block" =>
      {"bitcoin", %{"hash" => "HEX64"},
       %{"height" => "INT", "median_time_past" => "INT", "time" => "INT"}, @all},
    "bitcoin_block_at_height" =>
      {"bitcoin", %{"height" => "INT"},
       %{"hash" => "HEX64", "median_time_past" => "INT", "transaction_count" => "INT"}, @all},
    "bitcoin_identity" => {"bitcoin", %{}, %{"hash" => "HEX64"}, @found},
    "bitcoin_tip" => {"bitcoin", %{}, %{"height" => "INT"}, @found},
    "keyring" => {nil, %{"url" => {:url, @keyring_url}}, %{"keyring" => :any}, @found},
    "nist_pulse" =>
      {nil, %{"chainIndex" => "INT", "pulseIndex" => "INT"},
       %{"outputValue" => "NISTHEX", "timeStamp" => "NISTTIME"}, @all},
    "stellar_identity" => {"stellar", %{}, %{"network_passphrase" => "ASCII128"}, @found},
    "stellar_ledger" =>
      {"stellar", %{"sequence" => "INT"}, %{"closed_at" => "TIME", "hash" => "HEX64"}, @all},
    "stellar_root" => {"stellar", %{}, %{"elder" => "INT", "latest" => "INT"}, @found},
    "stellar_transaction" =>
      {"stellar", %{"hash" => "HEX64"},
       %{
         "ledger" => "INT",
         "memo" => {:only_when, "HEX64", "memo_type", ~w(hash return)},
         "memo_type" => {:enum, ~w(none text id hash return)},
         "successful" => :boolean
       }, @all}
  }

  # The production network of each chain, whose identity value SPEC.md 10.2 step 0 pins.
  @production %{"bitcoin" => "mainnet", "stellar" => "public"}

  @doc "The kinds of read, each with its chain, parameters, fields and outcomes."
  def kinds, do: @kinds

  @doc """
  The identity values SPEC.md 10.2 step 0 pins, read from its text: Stellar's production
  network passphrase and the hash of mainnet's block at height 0.
  """
  def production do
    text = Spec.spec_md()

    [_all, passphrase] =
      Regex.run(~r/pinned to `public` M[U]ST give the network passphrase\s+`([^`]+)`/, text)

    [_all, hash] = Regex.run(~r/pinned to `mainnet` M[U]ST give\s+`([0-9a-f]{64})`/, text)
    %{"bitcoin" => hash, "stellar" => passphrase}
  end

  @doc "A record: the read `{kind, parameters}` and its answer."
  def record(kind, parameters, answer),
    do: %{"answer" => answer, "read" => Map.put(parameters, "kind", kind)}

  @doc "A replay file's value, its records by kind, then in the byte order of JCS(read)."
  def file(records),
    do: %{"reads" => Enum.sort_by(records, &{&1["read"]["kind"], JCS.encode(&1["read"])})}

  # SPEC.md 13.2's table of the kinds of read.

  @doc """
  The failures of SPEC.md 13.2's table of the kinds of read, in the text `spec_md`, against
  the validator's copy of it, @kinds: the same kinds, and for each the same parameters and
  the same fields of a found answer, each with the same class. In the table each parameter
  and field is written `` `name` (class) ``, where the class is a class of SPEC.md 2.4, `a
  boolean`, `one of` the values it lists, a URL of the form it gives, or `any JSON value`; a
  field that is present only when another field has one of some values says so after its
  class; and `network` alone is a network of the kind's chain.
  """
  def spec_table(spec_md) do
    spec = spec_md |> table_rows(@table) |> Map.new(&table_row/1)

    ours =
      Map.new(@kinds, fn {kind, {chain, parameters, fields, _outcomes}} ->
        parameters =
          if chain, do: Map.put(parameters, "network", {:network, chain}), else: parameters

        {kind, {parameters, fields}}
      end)

    List.flatten([
      expect(
        "the kinds of read in SPEC.md 13.2's table",
        spec |> Map.keys() |> Enum.sort(),
        ours |> Map.keys() |> Enum.sort()
      ),
      for {kind, {parameters, fields}} <- Enum.sort(ours), Map.has_key?(spec, kind) do
        {spec_parameters, spec_fields} = Map.fetch!(spec, kind)

        [
          expect("SPEC.md 13.2's table: the parameters of #{kind}", spec_parameters, parameters),
          expect("SPEC.md 13.2's table: the fields of #{kind}", spec_fields, fields)
        ]
      end
    ])
  end

  # The rows of the table whose header line is `header`, each as its cells.
  defp table_rows(text, header) do
    case String.split(text, "\n" <> header <> "\n", parts: 2) do
      [_before, rest] ->
        rest
        |> String.split("\n")
        |> Enum.drop(1)
        |> Enum.take_while(&String.starts_with?(&1, "|"))
        |> Enum.map(fn row ->
          row
          |> String.trim()
          |> String.trim("|")
          |> String.split(" | ")
          |> Enum.map(&String.trim/1)
        end)

      _missing ->
        []
    end
  end

  @item ~r/`([A-Za-z_]+)`(?: \(((?:[^()])*)\))?/

  defp table_row([kind_cell, parameters_cell, fields_cell]) do
    kind = String.trim(kind_cell, "`")

    chain =
      Enum.find(~w(bitcoin stellar), &String.starts_with?(kind, &1 <> "_"))

    {kind, {cell(parameters_cell, chain), cell(fields_cell, chain)}}
  end

  defp table_row(cells), do: {Enum.join(cells, " | "), :unreadable}

  # A cell's names and classes: every item it holds, `name` or `name` (class), with nothing
  # between them but ", ".
  defp cell(text, chain) do
    items = Regex.scan(@item, text)

    if Enum.map_join(items, ", ", &hd/1) == text,
      do: Map.new(items, &item(&1, chain)),
      else: %{text => :unreadable}
  end

  defp item([_all, "network"], chain), do: {"network", {:network, chain}}
  defp item([_all, name], _chain), do: {name, :no_class}
  defp item([_all, name, inside], _chain), do: {name, class(inside)}

  defp class("one of " <> _values = inside), do: {:enum, backticked(inside)}
  defp class("`https://" <> _rest = inside), do: {:url, hd(backticked(inside))}
  defp class("any JSON value" <> _rest), do: :any

  defp class(inside) do
    [first | _notes] = String.split(inside, ", ")
    class = if first == "a boolean", do: :boolean, else: first

    case Regex.run(~r/present only when `([a-z_]+)` is (.+)\z/, inside) do
      [_all, field, values] -> {:only_when, class, field, backticked(values)}
      nil -> class
    end
  end

  defp backticked(text), do: for([_all, value] <- Regex.scan(~r/`([^`]+)`/, text), do: value)

  # The form.

  @doc "The failures of the form of the replay file whose value is `value`, labelled `label`."
  def validate(value, label \\ "replay") do
    case value do
      %{"reads" => reads} when is_list(reads) and map_size(value) == 1 ->
        records = Enum.with_index(reads)

        List.flatten([
          Enum.map(records, fn {r, i} -> record_form("#{label}: record #{i}", r) end),
          unique(label, reads),
          sources(label, reads)
        ])

      _other ->
        ["#{label}: not an object whose one member is the array reads"]
    end
  end

  defp record_form(label, %{"answer" => answer, "read" => %{"kind" => kind} = read} = record)
       when map_size(record) == 2 do
    case Map.fetch(@kinds, kind) do
      {:ok, {chain, parameters, fields, outcomes}} ->
        [read_form(label, read, chain, parameters), answer_form(label, answer, fields, outcomes)]

      :error ->
        ["#{label}: its read's kind #{inspect(kind)} is no kind of read"]
    end
  end

  defp record_form(label, _record),
    do: ["#{label}: not an object of exactly answer and read, with read's kind"]

  defp read_form(label, read, chain, parameters) do
    names = if chain, do: Map.put(parameters, "network", {:network, chain}), else: parameters

    [
      expect(
        "#{label}: its read's members",
        read |> Map.keys() |> Enum.sort(),
        Enum.sort(["kind" | Map.keys(names)])
      ),
      for {name, class} <- names, Map.has_key?(read, name), not valid?(class, read[name]) do
        "#{label}: its read's #{name} is not #{describe(class)}"
      end
    ]
  end

  defp answer_form(label, %{"outcome" => outcome} = answer, fields, outcomes) do
    cond do
      outcome not in outcomes ->
        ["#{label}: its outcome #{inspect(outcome)} is not one of #{inspect(outcomes)}"]

      outcome == "found" ->
        found(label, answer, fields)

      outcome == "not_found" ->
        expect("#{label}: a not_found answer's members", Map.keys(answer), ["outcome"])

      outcome == "unreachable" ->
        [
          expect(
            "#{label}: an unreachable answer's members",
            answer |> Map.keys() |> Enum.sort(),
            ["outcome", "reason"]
          ),
          truth("#{label}: its reason is an ASCII128", valid?("ASCII128", answer["reason"]))
        ]
    end
  end

  defp answer_form(label, _answer, _fields, _outcomes),
    do: ["#{label}: its answer is not an object with an outcome"]

  defp found(label, %{"value" => value} = answer, fields)
       when is_map(value) and map_size(answer) == 2 do
    fields =
      for {name, class} <- fields, present?(class, value), into: %{} do
        case class do
          {:only_when, class, _field, _values} -> {name, class}
          class -> {name, class}
        end
      end

    [
      expect(
        "#{label}: its value's members",
        value |> Map.keys() |> Enum.sort(),
        fields |> Map.keys() |> Enum.sort()
      ),
      for {name, class} <- fields, Map.has_key?(value, name), not valid?(class, value[name]) do
        "#{label}: its value's #{name} is not #{describe(class)}"
      end
    ]
  end

  defp found(label, _answer, _fields),
    do: ["#{label}: a found answer is not exactly an outcome and an object value"]

  defp present?({:only_when, _class, field, values}, value), do: value[field] in values
  defp present?(_class, _value), do: true

  defp valid?("INT", n), do: is_integer(n) and n in 0..@max_integer
  defp valid?("TIME", text), do: time?(text, false)
  defp valid?("NISTTIME", text), do: time?(text, true)
  defp valid?(:boolean, value), do: is_boolean(value)
  defp valid?(:any, _value), do: true
  defp valid?({:enum, values}, value), do: value in values

  defp valid?({:url, template}, value) do
    [head, tail] = String.split(template, "<host>")
    pattern = Regex.compile!("\\A" <> Regex.escape(head) <> @host <> Regex.escape(tail) <> "\\z")
    is_binary(value) and value =~ pattern
  end

  defp valid?({:network, chain}, value),
    do: value in Map.fetch!(Spec.read("networks.json"), chain)

  defp valid?(class, value), do: Spec.class?(class, value)

  defp describe({:network, chain}), do: "a #{chain} network"
  defp describe({:url, template}), do: "a URL of the form #{template}"
  defp describe({:enum, values}), do: "one of #{inspect(values)}"
  defp describe(class), do: inspect(class)

  @time ~r/\A(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(\.\d{3})?Z\z/

  # A TIME or NISTTIME that the round trip of SPEC.md 2.4 keeps.
  defp time?(text, nist?) do
    with true <- is_binary(text),
         [_all | fields] <- Regex.run(@time, text),
         {clock, fraction} = Enum.split(fields, 6),
         true <- nist? == (fraction != []) do
      [y, m, d, h, min, s] = Enum.map(clock, &String.to_integer/1)
      Calendar.ISO.valid_date?(y, m, d) and h < 24 and min < 60 and s < 60
    else
      _failure -> false
    end
  end

  defp unique(label, reads) do
    keys = for %{"read" => read} <- reads, do: read

    for read <- Enum.uniq(keys -- Enum.uniq(keys)),
        do: "#{label}: the read #{inspect(read)} is held more than once"
  end

  # Each read of a Stellar or Bitcoin network other than its identity read is held only when
  # the file holds that identity read, found with a value step 0 allows.
  defp sources(label, reads) do
    identities =
      for %{"read" => %{"kind" => kind, "network" => network}, "answer" => answer} <- reads,
          kind in ~w(bitcoin_identity stellar_identity),
          into: %{},
          do: {{String.replace_suffix(kind, "_identity", ""), network}, answer}

    for %{"read" => %{"kind" => kind, "network" => network}} <- reads,
        {chain, _parameters, _fields, _outcomes} = Map.get(@kinds, kind, {nil, nil, nil, nil}),
        chain != nil,
        not String.ends_with?(kind, "_identity"),
        uniq: true do
      source(
        Map.get(identities, {chain, network}),
        "#{label}: it holds a #{kind} read of #{chain} #{network}",
        {chain, network}
      )
    end
  end

  # The failure of a read of the source `{chain, network}`, given the file's answer to that
  # source's identity read (nil when the file does not hold it), or [] when that answer is
  # found with a value step 0 allows.
  defp source(nil, label, _source), do: "#{label} but not that source's identity read"

  defp source(%{"outcome" => "found", "value" => value}, label, {chain, network}) do
    if allowed?(chain, network, value),
      do: [],
      else: "#{label}, whose identity read gives a value step 0 forbids"
  end

  defp source(_identity, label, _source),
    do: "#{label}, whose identity read gets no usable answer"

  @doc "Whether an identity read's found `value` is one step 0 allows for `chain` and `network`."
  def allowed?(chain, network, value) do
    production = production()[chain]
    given = value[if(chain == "bitcoin", do: "hash", else: "network_passphrase")]
    if network == @production[chain], do: given == production, else: given != production
  end

  # The reads a verifier makes.

  @doc """
  The reads a verifier makes online for `proof`, the decoded `proof` member, under the network
  pins `pins` (a case's `networks`), when every answer is found and matches (SPEC.md 10.2
  step 0 and 10.4): each pinned Stellar and Bitcoin network's identity; for each commitment
  entry, the Stellar transaction, or the Bitcoin tip and the block at `height`, and for a
  top-level entry the read of its candidate, ledger `ledger` or the block at `height` +
  BITCOIN_FINALITY; for each `genesis.bitcoin`, the tip and the block at its `height`; and for
  each entropy object, its pulse, ledger or block. The Stellar root is read only when a
  transaction, or an entropy object's ledger, is not found, and the keyring only under E_v
  `prod` with no keyring option, which no sound case is.
  """
  def reads(proof, pins) do
    finality = Spec.read("constants.json")["BITCOIN_FINALITY"]

    identities =
      for chain <- ~w(bitcoin stellar),
          network <- Enum.uniq([pins["commitment"][chain], pins["entropy"][chain]]),
          network != nil,
          do: {chain <> "_identity", %{"network" => network}}

    entries =
      for base <- ~w(/commitments /signing_key_event/commitments),
          {chain, entry} <- Pointer.get(proof, base) || %{},
          read <-
            entry_reads(chain, entry, pins["commitment"][chain], base == "/commitments", finality),
          do: read

    genesis =
      for block <- ~w(/block /witnesses/block /signing_key_event/block),
          %{"height" => height} <- [
            Pointer.get(proof, block <> "/record/metadata/genesis/bitcoin")
          ],
          network = pins["commitment"]["bitcoin"],
          read <- [
            {"bitcoin_tip", %{"network" => network}},
            {"bitcoin_block_at_height", %{"height" => height, "network" => network}}
          ],
          do: read

    entropy =
      for pointer <- entropy_pointers(proof),
          %{"source" => source} = object = Pointer.get(proof, pointer),
          do: entropy_read(source, object, pins["entropy"][source])

    Enum.uniq(identities ++ entries ++ genesis ++ entropy)
  end

  defp entry_reads("stellar", entry, network, top?, _finality) do
    [
      {"stellar_transaction", %{"hash" => entry["transaction_hash"], "network" => network}}
      | if(top?,
          do: [{"stellar_ledger", %{"network" => network, "sequence" => entry["ledger"]}}],
          else: []
        )
    ]
  end

  defp entry_reads("bitcoin", entry, network, top?, finality) do
    height = entry["height"]

    [
      {"bitcoin_tip", %{"network" => network}},
      {"bitcoin_block_at_height", %{"height" => height, "network" => network}}
      | if(top?,
          do: [
            {"bitcoin_block_at_height", %{"height" => height + finality, "network" => network}}
          ],
          else: []
        )
    ]
  end

  @doc "The pointers of the entropy objects `proof` carries, sorted."
  def entropy_pointers(proof) do
    witnesses =
      for {"entropy_" <> _source = name, _object} <- Pointer.get(proof, "/witnesses") || %{},
          do: "/witnesses/" <> name

    observations =
      for {name, _observation} <- Pointer.get(proof, "/observations") || %{},
          do: "/observations/#{name}/entropy"

    subject = if Pointer.get(proof, "/subject/entropy"), do: ["/subject/entropy"], else: []
    Enum.sort(subject ++ witnesses ++ observations)
  end

  defp entropy_read("nist", %{"payload" => %{"pulse" => pulse}}, _network),
    do:
      {"nist_pulse", %{"chainIndex" => pulse["chainIndex"], "pulseIndex" => pulse["pulseIndex"]}}

  defp entropy_read("stellar", %{"payload" => payload}, network),
    do: {"stellar_ledger", %{"network" => network, "sequence" => payload["sequence"]}}

  defp entropy_read("bitcoin", %{"payload" => payload}, network),
    do: {"bitcoin_block", %{"hash" => payload["hash"], "network" => network}}

  @doc """
  The replay of the sound item, `positive/item.proof.json` in `files`, run online under the
  pins every sound proof passes POLICY under, from the model's sources: every read of reads/2
  found.
  """
  def example(files) do
    %{"proof" => proof} = Parse.decode!(Map.fetch!(files, "vectors/positive/item.proof.json"))
    world = World.new(Chain.build())

    proof
    |> reads(Case.pins())
    |> Enum.map(fn {kind, parameters} ->
      record(kind, parameters, World.answer(world, kind, parameters))
    end)
    |> file()
  end

  # The check.

  @doc """
  The failures of the replay checks over `files`: the example holds to the form, every read in
  it is found, and each rule of the form refuses a mutant of it; and each replay file under
  vectors/corpus/replay/ holds to the form.
  """
  def check(files) do
    example = example(files)
    spec_md = Spec.spec_md()

    renamed =
      String.replace(
        spec_md,
        "`median_time_past` (INT), `transaction_count` (INT)",
        "`mediantime` (INT), `transaction_count` (INT)"
      )

    staging = keyring_read("https://staging.truestamp.com/.well-known/keyring.json")

    List.flatten([
      spec_table(spec_md),
      truth(
        "SPEC.md 13.2's table check refuses a field of bitcoin_block_at_height renamed",
        renamed != spec_md and
          Enum.any?(
            spec_table(renamed),
            &String.contains?(&1, "the fields of bitcoin_block_at_height")
          )
      ),
      expect(
        "the replay form, on a keyring read of another host",
        validate(%{example | "reads" => [staging | example["reads"]]}, "keyring"),
        []
      ),
      validate(example, "the sound item's replay"),
      for %{"read" => read, "answer" => answer} <- example["reads"],
          answer["outcome"] != "found" do
        "the sound item's replay: the model does not hold #{inspect(read)}"
      end,
      Enum.map(mutants(example), fn {name, fragment, mutant} ->
        failures = validate(mutant, "mutant")

        truth(
          "the replay form refuses #{name} (a failure naming #{inspect(fragment)})",
          Enum.any?(failures, &String.contains?(&1, fragment))
        )
      end),
      for {"vectors/corpus/replay/" <> name, bytes} <- files do
        validate(Parse.decode!(bytes), "corpus/replay/" <> name)
      end
    ])
  end

  # A mutant of the example for each rule of the form, with a fragment the failure it gives
  # names.
  defp mutants(%{"reads" => reads} = example) do
    at = fn kind -> Enum.find_index(reads, &(&1["read"]["kind"] == kind)) end
    edit = fn kind, fun -> %{example | "reads" => List.update_at(reads, at.(kind), fun)} end
    production = production()

    [
      {"a member beside reads", "not an object whose one member", Map.put(example, "note", "x")},
      {"reads that is not an array", "not an object whose one member", %{"reads" => %{}}},
      {"a record with a third member", "not an object of exactly answer and read",
       edit.("bitcoin_tip", &Map.put(&1, "note", "x"))},
      {"a read of no kind", "is no kind of read",
       edit.("bitcoin_tip", &put_in(&1, ["read", "kind"], "bitcoin_mempool"))},
      {"a read without its parameter", "its read's members",
       edit.("stellar_transaction", &update_in(&1, ["read"], fn r -> Map.delete(r, "hash") end))},
      {"a read with an extra parameter", "its read's members",
       edit.("bitcoin_tip", &put_in(&1, ["read", "height"], 1))},
      {"a parameter of the wrong class", "its read's hash is not",
       edit.(
         "stellar_transaction",
         &update_in(&1, ["read", "hash"], fn h -> String.upcase(h) end)
       )},
      {"a network of another chain", "its read's network is not",
       edit.("bitcoin_tip", &put_in(&1, ["read", "network"], "public"))},
      {"an outcome the kind does not have", "is not one of",
       edit.("bitcoin_tip", &put_in(&1, ["answer"], %{"outcome" => "not_found"}))},
      {"an outcome that is no outcome", "is not one of",
       edit.("stellar_ledger", &put_in(&1, ["answer", "outcome"], "timeout"))},
      {"a found answer without a field", "its value's members",
       edit.(
         "stellar_ledger",
         &update_in(&1, ["answer", "value"], fn v -> Map.delete(v, "closed_at") end)
       )},
      {"a found answer with an extra field", "its value's members",
       edit.(
         "stellar_ledger",
         &put_in(&1, ["answer", "value", "fetched_at"], "2026-09-26T02:03:00Z")
       )},
      {"a TIME the round trip does not keep", "its value's closed_at is not",
       edit.(
         "stellar_ledger",
         &put_in(&1, ["answer", "value", "closed_at"], "2026-09-26T24:00:00Z")
       )},
      {"a NISTTIME without its fraction", "its value's timeStamp is not",
       edit.("nist_pulse", &put_in(&1, ["answer", "value", "timeStamp"], "2026-09-26T01:48:00Z"))},
      {"a found answer without its value", "a found answer is not exactly",
       edit.("bitcoin_tip", &put_in(&1, ["answer"], %{"outcome" => "found"}))},
      {"a not_found answer with a value", "a not_found answer's members",
       edit.("stellar_ledger", &put_in(&1, ["answer", "outcome"], "not_found"))},
      {"an unreachable answer without a reason", "an unreachable answer's members",
       edit.("stellar_ledger", &put_in(&1, ["answer"], %{"outcome" => "unreachable"}))},
      {"a memo beside a memo_type that has none", "its value's members",
       edit.("stellar_transaction", &put_in(&1, ["answer", "value", "memo_type"], "text"))},
      {"a read held twice", "is held more than once", %{"reads" => [hd(reads) | reads]}},
      {"a read of a source without its identity read", "but not that source's identity read",
       %{"reads" => Enum.reject(reads, &(&1["read"]["kind"] == "bitcoin_identity"))}},
      {"reads of a source whose identity read is unreachable", "gets no usable answer",
       edit.(
         "bitcoin_identity",
         &put_in(&1, ["answer"], %{"outcome" => "unreachable", "reason" => "HTTP 503"})
       )},
      {"reads of a regtest source that gives mainnet's block-0 hash", "a value step 0 forbids",
       edit.("bitcoin_identity", &put_in(&1, ["answer", "value", "hash"], production["bitcoin"]))},
      {"a keyring read over http", "its read's url is not",
       %{"reads" => [keyring_read("http://www.truestamp.com/.well-known/keyring.json") | reads]}},
      {"a keyring read at another path", "its read's url is not",
       %{"reads" => [keyring_read("https://www.truestamp.com/keyring.json") | reads]}}
    ]
  end

  defp keyring_read(url),
    do: record("keyring", %{"url" => url}, %{"outcome" => "unreachable", "reason" => "HTTP 503"})
end

defmodule Generator.Replay.World do
  @moduledoc """
  The answers of the model's sources (Generator.Chain) at its last moment, the time of the
  regtest tip, for any read of the replay form: the Stellar testnet source, whose ledgers run
  from 1,000,000 to the latest; the regtest source, whose blocks run from regtest's genesis to
  the tip; and NIST chain 2, whose pulses run from 1,200,000 to the latest. A read of a value
  in range is found, one out of range not found, and a read of a source the model has not,
  such as mainnet or the keyring, raises.
  """

  alias Generator.{Bitcoin, Chain, Regtest}

  @median_span 11

  @doc "The world of `model`, the value of Generator.Chain.build/0."
  def new(model) do
    %{
      model: model,
      sources: Chain.sources(model),
      transactions:
        for(
          {_name, chain} <- model.chains,
          epoch <- chain.epochs,
          do: {epoch.entries["stellar"], epoch.node["epoch_hash"]}
        )
    }
  end

  @doc "The answer to the read `{kind, parameters}`."
  def answer(world, kind, %{"network" => network} = parameters)
      when kind in ~w(stellar_identity bitcoin_identity) do
    case {kind, network} do
      {"stellar_identity", "testnet"} ->
        found(%{"network_passphrase" => "Test SDF Network ; September 2015"})

      {"bitcoin_identity", "regtest"} ->
        found(%{"hash" => Bitcoin.display(Regtest.block(world.model.regtest, 0).hash)})

      _other ->
        raise ArgumentError, "the model has no source for #{inspect(parameters)}"
    end
  end

  def answer(world, "stellar_root", %{"network" => "testnet"}),
    do: found(%{"elder" => world.sources.stellar_elder, "latest" => world.sources.stellar_latest})

  def answer(world, "stellar_transaction", %{"network" => "testnet", "hash" => hash}) do
    case Enum.find(world.transactions, fn {entry, _epoch_hash} ->
           entry["transaction_hash"] == hash
         end) do
      {entry, epoch_hash} ->
        found(%{
          "ledger" => entry["ledger"],
          "memo" => epoch_hash,
          "memo_type" => "hash",
          "successful" => true
        })

      nil ->
        not_found()
    end
  end

  def answer(world, "stellar_ledger", %{"network" => "testnet", "sequence" => sequence}) do
    if sequence in world.sources.stellar_elder..world.sources.stellar_latest,
      do: found(Map.delete(Chain.stellar_ledger(sequence), "sequence")),
      else: not_found()
  end

  def answer(world, "bitcoin_tip", %{"network" => "regtest"}),
    do: found(%{"height" => world.sources.bitcoin_tip})

  def answer(world, "bitcoin_block_at_height", %{"network" => "regtest", "height" => height}) do
    if height in 0..world.sources.bitcoin_tip do
      block = Regtest.block(world.model.regtest, height)

      found(%{
        "hash" => Bitcoin.display(block.hash),
        "median_time_past" => median_time_past(world, height),
        "transaction_count" => length(block.txs)
      })
    else
      not_found()
    end
  end

  def answer(world, "bitcoin_block", %{"network" => "regtest", "hash" => hash}) do
    case Enum.find(world.model.regtest, fn {_height, block} ->
           Bitcoin.display(block.hash) == hash
         end) do
      {height, block} ->
        found(%{
          "height" => height,
          "median_time_past" => median_time_past(world, height),
          "time" => block.time
        })

      nil ->
        not_found()
    end
  end

  def answer(world, "nist_pulse", %{"chainIndex" => 2, "pulseIndex" => index}) do
    if index in world.sources.nist_first..world.sources.nist_latest do
      pulse = Chain.nist_pulse(index)
      found(Map.take(pulse, ["outputValue", "timeStamp"]))
    else
      not_found()
    end
  end

  def answer(_world, kind, parameters),
    do: raise(ArgumentError, "the model has no source for #{kind} #{inspect(parameters)}")

  # The median of the header times of the BITCOIN_MEDIAN_SPAN blocks ending at `height`, or of
  # all of them below that span, as Bitcoin Core takes it: the middle of the sorted times.
  defp median_time_past(world, height) do
    times =
      for h <- max(0, height - @median_span + 1)..height,
          do: Regtest.block(world.model.regtest, h).time

    Enum.at(Enum.sort(times), div(length(times), 2))
  end

  defp found(value), do: %{"outcome" => "found", "value" => value}
  defp not_found, do: %{"outcome" => "not_found"}
end
