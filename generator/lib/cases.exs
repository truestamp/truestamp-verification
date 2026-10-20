# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Generator.Case do
  @moduledoc """
  One case of vectors/cases.json as a class module states it, and the helpers class modules
  build cases with (SPEC.md 13.2 and 13.3).

  A case is made with new/2, from its id and these options:

  - `proof`, its file: `{:served, envelope}` writes `negative/<id>.proof.json` in the served
    form of SPEC.md 3.1, JCS(envelope); `{:bytes, bytes}` writes those bytes there as they are,
    for a file whose defect is its bytes (not UTF-8, not one JSON text, over MAX_READ_OCTETS,
    or formatted otherwise); `{:path, path}` names a file another case or a sound proof already
    has, such as `positive/item.proof.json`, and writes nothing.
  - `environment`, E_v: `"test"` unless given.
  - `keyring`: `"test"` unless given; `"none"` (keyless mode); `nil`, for no keyring option;
    `{:value, keyring}` writes `negative/<id>.keyring.json` in the canonical form of SPEC.md 9;
    `{:bytes, bytes}` writes those bytes there as they are; `{:path, path}` names a keyring
    file another case has. `"unavailable"` is online, under `prod`: no keyring option, with
    the replay failing the keyring read at www.truestamp.com (SPEC.md 13.2).
  - `networks`: the pins of pins/0 unless given, in the form `{"commitment": {chain: network},
    "entropy": {chain: network}}`.
  - `expected_hash`: the caller's hash, or nil for none.
  - `defect`, what the case says it asserts, stated by hand from SPEC.md 13.3's wording, which
    the generator holds the model's output to:
    - `{:bare, code, sub_reason}`: a bare rejection, `sub_reason` nil for a code without one;
    - `{:fail, code, part, step}`: a single-defect case, whose one failing row this is;
    - `{:fails, [{code, part, step}, ...]}`: exactly these failing rows, in this order, for a
      case SPEC.md does not make single-defect (the graft's first form);
    - `{:passes, [{status, code, part, step}, ...]}`: no row fails, and each row listed is
      among the rows;
    - `{:precedes, {code, part, step}, [{code, part, step}, ...]}`: a precedence case, whose one
      failing row is the first, at steps 4 to 7, and which carries a second defect, the rows
      listed, that the run past that stop also fails: it shows that SPEC.md 10.2's order
      decides which check reports, and is not a single-defect case.
    `{:bare, ...}` and `{:fail, ...}` are the single-defect cases that SPEC.md 13.1's check of
    every code counts.
  - `knock_on`: for a case whose run stops at steps 4 to 7, where a failure ends the run,
    whatever the form of its defect, the rows, each `{code, part, step}`, that its defect by
    itself also fails once the run goes past that stop (Generator.Model.past/3): a marker that
    is no ENV value also fails SHAPE, a value with a `\n` on its end also fails the check that
    reads it. The check of Generator.Cases holds the run past the stop to exactly these rows
    beyond the one it stops at, so no second defect hides behind the stop.
  - `label`: the label the case says its report has, checked when given.
  - `trace`: the path of the trace file the report's trace must equal, for a sound proof, for
    its reformatted copies, and for a passing case that runs a sound proof unchanged (the
    keyring cases `key_binding-inactive_key` and `key_binding-none`, the expected-hash cases
    `expected_hash-md5` and `expected_hash-capitals`, and the POLICY case
    `policy-block-genesis-staging_pins-regtest`); it becomes the `trace` member of the case's
    `expected`, and SPEC.md 13.1 compares the trace of each case that names one.
  - `same_as`: the id of a case whose rows this case's rows must equal, as SPEC.md 13.3's
    sameness cases say; or `{id, except: steps}`, where the rows of the steps named may differ
    and every other row must equal that case's, each step keeping its number of rows, as for
    the keyring `none`, which gives "otherwise the sound proof's rows".
  - `present`: rows, each `{status, code, part, step}`, that must be among the report's rows
    whatever the defect, for a row SPEC.md names beside the one that fails (D62's passing
    LINK_HEAD at a genesis witness block whose `height` is declared wrong).
  - `replay`, for an online case: `{:value, replay}` writes `corpus/replay/<id>.json`, the
    replay file of SPEC.md 13.2, in the canonical form of SPEC.md 9; `{:path, path}` names
    one another case has. The case's `config` then has `online`, its path.
  - `no_source`, for the one online case whose point is a network with no source (SPEC.md
    13.2): that network, `{chain, network}`, which the case pins and whose identity read its
    replay does not hold. Every other online case's replay holds the identity read of each
    source of each network it pins.
  - `sources`, for an online case with several sources for a network (SPEC.md 9 and 13.2):
    its config's `sources`, `{chain: {network: {policy, required, sources}}}`, whose names its
    replay's records of that network carry; nil for one source per network.
  - `edges`, for an online case that gives a report: `{submitted_after, submitted_before}`,
    each nil or `{basis, instant}`, stated by hand, which the report's edges must equal
    (SPEC.md 13.1).
  - `online_rows`, for an online case that gives a report: every row of CHAIN, SOURCES and
    WINDOW that does not pass, each `{status, code, part, step}`, in order, stated by hand,
    which the report's must equal.

  Every proof in the vectors is marked `test` and signed by VECTOR_KEY unless its case says
  otherwise (SPEC.md 13.2): sign/2 signs with VECTOR_KEY unless given another seed of
  Generator.Seeds, and Generator.Seeds.other/0 is the published key for cases that call for a
  key other than VECTOR_KEY.
  """

  alias Generator.{Bytes, Edit, JCS, Keys, Registry, Seeds}

  @enforce_keys [:id, :proof, :defect]
  defstruct [
    :id,
    :proof,
    :defect,
    :expected_hash,
    :label,
    :trace,
    :same_as,
    :class,
    :replay,
    :edges,
    :online_rows,
    :no_source,
    :sources,
    present: [],
    knock_on: [],
    environment: "test",
    keyring: "test",
    networks: nil
  ]

  @pins %{
    "commitment" => %{"bitcoin" => "regtest", "stellar" => "testnet"},
    "entropy" => %{"bitcoin" => "regtest", "stellar" => "testnet"}
  }

  @doc """
  The network pins every sound proof passes POLICY under: the commitment pin of each chain,
  and the entropy pin of each source that has a network, which here are the same. They are
  the `test` row of SPEC.md 9's default pins, which Generator.Cases checks
  spec/network-pins.json against.
  """
  def pins, do: @pins

  @doc "A case: its id and the options above."
  def new(id, options), do: struct!(__MODULE__, [id: id, networks: @pins] ++ options)

  @doc """
  The envelope of `proof` signed by the key of `seed` (VECTOR_KEY's unless given), with K that
  key (SPEC.md 6.1).
  """
  def sign(proof, seed \\ Seeds.vector()) do
    signature = Keys.sign(seed, Registry.record_hash("proof_hash", proof))
    envelope(proof, Bytes.b64u(Keys.public_key(seed)), Bytes.b64u(signature))
  end

  @doc "The envelope of `proof` with the strings `public_key` as K and `value` as V."
  def envelope(proof, public_key, value) do
    %{
      "proof" => proof,
      "signature" => %{
        "alg" => "truestamp-ed25519-sha256-jcs",
        "public_key" => public_key,
        "value" => value
      }
    }
  end

  @doc "The served form of an envelope, JCS(envelope) (SPEC.md 3.1)."
  def served(envelope), do: JCS.encode(envelope)

  @doc """
  `count` nested objects, each but the innermost holding the next as its one member, `nest`:
  at claims, which is at depth 4 of the document, `nest(n)` puts the innermost at depth n + 4.
  """
  def nest(1), do: %{}
  def nest(count) when count > 1, do: %{"nest" => nest(count - 1)}

  @doc """
  The item `proof` with claims whose `nest` puts the document's innermost object at depth
  `depth`, and the hashes above the claims made to agree (Generator.Edit.recommit_item/1): the
  passing case at MAX_DEPTH and the failing one a level deeper differ only in depth.
  """
  def nested(proof, depth),
    do: proof |> Edit.put("/subject/claims/nest", nest(depth - 4)) |> Edit.recommit_item()

  @doc "The path under vectors/ of the case's proof file."
  def proof_path(%__MODULE__{proof: {:path, path}}), do: path
  def proof_path(%__MODULE__{id: id}), do: "negative/#{id}.proof.json"

  @doc """
  The path under vectors/ of the trace file of the sound proof at `proof_path`, a path under
  positive/: `<name>.proof.json` gives `<name>.trace.json`.
  """
  def trace_path("positive/" <> _rest = proof_path),
    do: String.replace_suffix(proof_path, ".proof.json", ".trace.json")

  @doc "The path under vectors/ of the case's keyring file, or its `keyring` member."
  def keyring_member(%__MODULE__{keyring: {:path, path}}), do: path

  def keyring_member(%__MODULE__{keyring: {_form, _keyring}, id: id}),
    do: "negative/#{id}.keyring.json"

  def keyring_member(%__MODULE__{keyring: keyring}), do: keyring

  @doc "The path under vectors/ of the case's replay file, or nil for an offline case."
  def replay_path(%__MODULE__{replay: {:path, path}}), do: path
  def replay_path(%__MODULE__{replay: {:value, _replay}, id: id}), do: "corpus/replay/#{id}.json"
  def replay_path(%__MODULE__{replay: nil}), do: nil

  @doc "Whether the case is a single-defect case (SPEC.md 13.1's check of every code)."
  def single_defect?(%__MODULE__{defect: defect}),
    do: elem(defect, 0) in [:bare, :fail]
end

defmodule Generator.Cases.Class do
  @moduledoc """
  A class module: one file under generator/lib/cases/ that states the cases of some classes of
  SPEC.md 13.3.

  - cases/1 takes the context of Generator.Cases.context/1 and gives its cases
    (Generator.Case), in the order they take in vectors/cases.json.
  - codes/0 gives the reason codes its classes cover, each with a case, and each code whose
    status is bare or fail with a single-defect case (SPEC.md 13.1).
  """

  @callback cases(map()) :: [struct()]
  @callback codes() :: [String.t()]
end

defmodule Generator.Cases do
  @moduledoc """
  vectors/cases.json and the files under vectors/negative/ (SPEC.md 13.2 and 13.3): the cases
  each class module states (Generator.Cases.Class), with each case's expected output computed
  by the model (Generator.Model), and the checks of them.

  The files:

  - `cases.json`, in the canonical form of SPEC.md 9: an array of the cases, in the order of
    the class modules below and of each module's cases, an order that carries no meaning
    (SPEC.md 13.2). A case's members, in JCS order, are
    `config`, `expected`, `id` and `proof`. `config` holds `environment`, `expected_hash` when
    the case gives one, `keyring` unless the case asks for neither a keyring nor keyless mode,
    `networks`, `{"commitment": {chain: network}, "entropy": {chain: network}}`, and for an
    online case `online`, the path of its replay file, and `sources` when it names several
    sources for a network. `expected` holds, for a bare rejection, `code`, and `sub_reason`
    when the code has one; otherwise the report's `label`, its
    `rows`, each `[code, part, status, step]` in the order of SPEC.md 10.2, passes and skips
    included, for a sound proof, its reformatted copies and a passing case that runs a sound
    proof unchanged `trace`, the path of the trace file, and for an online case `submitted_after` and `submitted_before`, each null or
    `{basis, instant}`. Every path is relative to vectors/.
  - under `negative/`, `<id>.proof.json`, the proof file of a case that does not name one
    already written, and `<id>.keyring.json`, the keyring file a case supplies. A proof file
    is in the served form of SPEC.md 3.1, and a keyring file in the canonical form, unless the
    case concerns the file's bytes: a defect, a reformatting or a size. A proof file's name
    says what a verifier is given, a file offered as a proof, and not that it parses, so a file
    that is not UTF-8, not one JSON text or over MAX_READ_OCTETS keeps the same name.
  - under `corpus/replay/`, `<id>.json`, the replay file of an online case that does not name
    one already written, in the canonical form (Generator.Replay).

  The checks, from the files about to be written: cases.json reads back to the ids and
  configurations the modules state; each case's expected output, derived again from its proof
  file's bytes and its configuration as cases.json holds them, with its replay file for an
  online case, equals the case's `expected`; the model's output is what the case says it
  asserts (Generator.Case), so a single-defect case has exactly its one failing row, and an
  online case has the edges and the rows of CHAIN, SOURCES and WINDOW it states; a case whose
  run stops at steps 4 to 7, where a failure ends the run, whatever the form of its defect, is
  run again past that stop as if its check had passed (Generator.Model.past/3), and the rows
  that fail beyond the run's own are exactly its knock-on failures and, for a precedence case,
  the defect it states behind the first, so no second defect hides behind a stop; a trace
  named is the model's trace; every file under negative/ and corpus/replay/ belongs to a case,
  is in its form and holds bytes no other file under vectors/ holds, so a case that needs
  another's file names it; an online case's replay holds the identity read of every source of
  every Stellar and Bitcoin network the case pins, but for the one case whose `no_source`
  names regtest, whose replay lacks that read; a case's `sources` is in the form of SPEC.md
  13.2, beside `online`, for networks the case pins, and its replay's records name a source
  exactly for those networks, each one of the names given; an online case that is the bare
  rejection `configuration_error` has exactly one identity read step 0 refuses, every pinned
  source's read made; every online case without `sources` gives its expected output again
  with one named source for each network it pins, under each policy (one_source/2, which
  refuses a second source that answers otherwise); and every reason code but `internal_error`
  has a case, each code whose status is bare or fail a single-defect case (SPEC.md 13.1),
  reported per code, and a code that lacks either fails the check; the sub_reasons the bare
  cases give are exactly those spec/reason-codes.json lists for their codes; and
  spec/network-pins.json holds SPEC.md 9's
  table of default network pins, a row for each E_v, each network one of its chain's, the
  `prod` row the production networks and the `test` row the pins of Generator.Case.pins/0;
  and every place spec/schema.json gives the class UUID7 has a SHAPE case of a `\\n` on the
  end of its value, a failure the schema no longer gives with that place's `$ref` taken out.
  A code the online classes name (Generator.Cases.Online and Generator.Cases.Sources) must be
  one only an online run reaches: no offline case gives it, and it is a code of CHAIN, SOURCES
  or WINDOW alone, or `keyring_unavailable`, whose keyring read is online.
  """

  import Generator.Check

  alias Generator.{Case, FileForm, JCS, Model, Parse, Pointer, Schema, Spec}
  alias Generator.Model.Online, as: OnlineModel

  # The class modules of the online cases, whose codes only an online run reaches. They are
  # loaded after this module, which calls them only as class modules.
  @online Generator.Cases.Online
  @sources Generator.Cases.Sources

  # The class modules, in the order of their classes in SPEC.md 13.3.
  @classes [
    Generator.Cases.Sound,
    Generator.Cases.Parse,
    Generator.Cases.Front,
    Generator.Cases.Shape,
    Generator.Cases.Derive,
    @online,
    @sources
  ]

  @config_members ~w(environment expected_hash keyring networks online sources)
  @id ~r/\A[a-z0-9_]+(?:-[a-z0-9_]+)*\z/

  # The steps whose failure ends the run (SPEC.md 10.2), and those only an online run reaches.
  @stops ~w(ENVIRONMENT KEY_BINDING SIGNATURE SHAPE)
  @online_steps ~w(CHAIN SOURCES WINDOW)

  @doc "The class modules, in their order in vectors/cases.json."
  def classes, do: @classes

  @doc """
  The context a class module's cases/1 takes, from `files`, the files under vectors/ written
  so far: `sound`, each sound proof by its name as `%{proof, envelope, bytes, path}`, where
  `proof` is the decoded `proof` member and `path` the file's path under vectors/; and `files`.
  """
  def context(files) do
    sound =
      for {"vectors/positive/" <> name, bytes} <- files,
          String.ends_with?(name, ".proof.json"),
          into: %{} do
        envelope = Parse.decode!(bytes)
        path = "positive/" <> name
        name = String.replace_suffix(name, ".proof.json", "")
        {name, %{proof: envelope["proof"], envelope: envelope, bytes: bytes, path: path}}
      end

    %{sound: sound, files: files}
  end

  @doc "Every case the class modules state, each with its class module, over `files`."
  def definitions(files) do
    context = context(files)

    for class <- @classes, definition <- class.cases(context), do: %{definition | class: class}
  end

  @doc """
  vectors/cases.json and the files under vectors/negative/, by their paths, for `files`, the
  files under vectors/ written so far, keyring.test.json and the sound proofs among them.
  """
  def files(files) do
    definitions = definitions(files)
    negative = Map.new(Enum.flat_map(definitions, &negative_files/1))
    all = Map.merge(files, negative)
    cases = Enum.map(definitions, &json(&1, all))
    Map.put(negative, "vectors/cases.json", FileForm.encode(cases))
  end

  defp negative_files(definition),
    do: for({path, _form, bytes} <- owned(definition), do: {"vectors/" <> path, bytes})

  # The files the case's definition writes, each `{path, form, bytes}` with its path under
  # vectors/, and its form: `:served`, `:canonical`, or `:bytes` for a file given as bytes.
  defp owned(definition),
    do: proof_file(definition) ++ keyring_file(definition) ++ replay_file(definition)

  defp proof_file(%{proof: {:served, envelope}} = definition),
    do: [{Case.proof_path(definition), :served, Case.served(envelope)}]

  defp proof_file(%{proof: {:bytes, bytes}} = definition),
    do: [{Case.proof_path(definition), :bytes, bytes}]

  defp proof_file(_named), do: []

  defp keyring_file(%{keyring: {:value, keyring}} = definition),
    do: [{Case.keyring_member(definition), :canonical, FileForm.encode(keyring)}]

  defp keyring_file(%{keyring: {:bytes, bytes}} = definition),
    do: [{Case.keyring_member(definition), :bytes, bytes}]

  defp keyring_file(_named_or_none), do: []

  defp replay_file(%{replay: {:value, replay}} = definition),
    do: [{Case.replay_path(definition), :canonical, FileForm.encode(replay)}]

  defp replay_file(_named_or_none), do: []

  defp json(definition, files) do
    config = config(definition)
    proof = Case.proof_path(definition)

    bytes =
      Map.get(files, "vectors/" <> proof) ||
        raise ArgumentError, "case #{definition.id} names #{proof}, which no case writes"

    output = Model.run(bytes, config, files)

    %{
      "config" => config,
      "expected" => expected(output, definition.trace),
      "id" => definition.id,
      "proof" => proof
    }
  end

  defp config(definition) do
    [
      {"environment", definition.environment},
      {"expected_hash", definition.expected_hash},
      {"keyring", Case.keyring_member(definition)},
      {"networks", definition.networks},
      {"online", Case.replay_path(definition)},
      {"sources", definition.sources}
    ]
    |> Enum.reject(fn {_name, value} -> value == nil end)
    |> Map.new()
  end

  defp expected(output, nil), do: Model.expected(output)
  defp expected(output, trace), do: Map.put(Model.expected(output), "trace", trace)

  @doc """
  `{failures, report}` of the checks over `files`, every file about to be written under
  vectors/, where `report` gives each reason code's coverage, one line per code.
  """
  def check(files) do
    definitions = definitions(files)
    cases = Parse.decode!(Map.fetch!(files, "vectors/cases.json"))
    by_id = Map.new(cases, &{&1["id"], &1})

    results =
      for definition <- definitions do
        json = Map.get(by_id, definition.id, %{})
        output = rederive(json, files)
        {definition, output, case_checks(definition, json, output, {files, by_id})}
      end

    {coverage_failures, report} = coverage(for {d, output, _failures} <- results, do: {d, output})

    online =
      for definition <- definitions,
          definition.replay != nil,
          do: {definition.no_source, Map.get(by_id, definition.id, %{})}

    failures =
      List.flatten([
        expect(
          "the ids of cases.json, in order",
          Enum.map(cases, & &1["id"]),
          Enum.map(definitions, & &1.id)
        ),
        ids(definitions),
        for(
          class <- @classes,
          not Enum.any?(definitions, &(&1.class == class)),
          do: "#{inspect(class)} states no case"
        ),
        Enum.map(results, &elem(&1, 2)),
        negative(files, definitions),
        replay_sources(online, files),
        replay_sources_self_test(files),
        Enum.map(cases, &sources_form/1),
        configuration_identities(online, files),
        configuration_identities_self_test(online, files),
        one_source(cases, files),
        one_source_self_test(by_id, files),
        replay_reads_self_test(by_id, files),
        default_pins(),
        uuid7_newlines(definitions, files),
        coverage_failures
      ])

    {failures, report}
  end

  # SPEC.md 13.3's SHAPE case of a `\n` on the end of a value, at every place spec/schema.json
  # gives the class UUID7: for each schema whose `$ref` is `#/$defs/UUID7`, a case that fails
  # shape_invalid at SHAPE at a value with a `\n` on its end, a failure that spec/schema.json
  # gives and no longer gives with that one `$ref` taken out. So taking out the case of a
  # place, such as `shape-newline-item-id`, fails this check.
  defp uuid7_newlines(definitions, files) do
    root = Spec.read("schema.json")
    places = Schema.refs(root, "#/$defs/UUID7")

    newlines =
      for %{defect: {:fail, "shape_invalid", part, "SHAPE"}} = definition <- definitions,
          bytes = Map.get(files, "vectors/" <> Case.proof_path(definition)),
          is_binary(bytes),
          document = Parse.decode!(bytes),
          value = Pointer.get(document["proof"], part),
          is_binary(value) and String.ends_with?(value, "\n"),
          do: {document, "/proof" <> part}

    [
      truth("spec/schema.json gives the class UUID7 somewhere", places != []),
      for {path, pointer} <- places do
        without = Schema.without(root, path)

        truth(
          "a SHAPE case of a `\\n` on the end of the UUID7 at spec/schema.json##{pointer}",
          Enum.any?(newlines, fn {document, at} ->
            at in Schema.failures(document, root) and
              at not in Schema.failures(document, without)
          end)
        )
      end
    ]
  end

  # SPEC.md 9's default network pins. spec/network-pins.json has a row for `prod` and for each
  # ENV value, each in the form of a case's `networks`, with a pin for Bitcoin and for Stellar
  # and every network one of its chain's in spec/networks.json; each row is the row of
  # SPEC.md 9's table for its E_v; the `prod` row pins each chain's production network, the
  # first spec/networks.json lists; and the `test` row is Generator.Case.pins/0, under which
  # every sound proof passes POLICY, so a case that gives those pins gives the default ones.
  defp default_pins do
    file = "spec/network-pins.json"
    table = Spec.read("network-pins.json")
    networks = Spec.read("networks.json")
    production = Map.new(networks, fn {chain, [first | _others]} -> {chain, first} end)
    evs = ["prod" | Spec.read("encodings.json")["ENV"]["values"]]

    List.flatten([
      expect("the rows of #{file}", Enum.sort(Map.keys(table)), Enum.sort(evs)),
      Enum.map(table, &pins_row(&1, networks, file)),
      expect("#{file}, SPEC.md 9's table", table, spec_pins()),
      expect("#{file}, prod", table["prod"], %{
        "commitment" => production,
        "entropy" => production
      }),
      expect("#{file}, test", table["test"], Case.pins())
    ])
  end

  defp pins_row({ev, row}, networks, file) do
    [
      expect("#{file}, #{ev}: its pins", Enum.sort(Map.keys(row)), ~w(commitment entropy)),
      for {pin, by_chain} <- row do
        [
          expect(
            "#{file}, #{ev} #{pin}: its chains",
            Enum.sort(Map.keys(by_chain)),
            ~w(bitcoin stellar)
          ),
          for {chain, network} <- by_chain do
            truth(
              "#{file}, #{ev} #{pin} #{chain}: #{inspect(network)} is no network of that chain",
              network in Map.get(networks, chain, [])
            )
          end
        ]
      end
    ]
  end

  # SPEC.md 9's table of default network pins, read from the text: each row's E_v, then its
  # commitment pins and its entropy pins, each cell `Stellar <network>, Bitcoin <network>`.
  defp spec_pins do
    header = "| E_v | Commitment pins | Entropy pins |\n|---|---|---|\n"
    [_before, rest] = String.split(Spec.spec_md(), header, parts: 2)

    rest
    |> String.split("\n")
    |> Enum.take_while(&String.starts_with?(&1, "|"))
    |> Map.new(fn line ->
      [ev, commitment, entropy] =
        line |> String.trim("|") |> String.split("|") |> Enum.map(&String.trim/1)

      {String.trim(ev, "`"), %{"commitment" => cell(commitment), "entropy" => cell(entropy)}}
    end)
  end

  defp cell(text) do
    [[_, stellar, bitcoin]] = Regex.scan(~r/\AStellar `([a-z]+)`, Bitcoin `([a-z]+)`\z/, text)
    %{"bitcoin" => bitcoin, "stellar" => stellar}
  end

  # SPEC.md 13.2: an online case's replay holds the identity read of every Stellar and Bitcoin
  # network the case pins, as a commitment pin or an entropy pin, so no verifier falls back on
  # a compiled-in default source that another verifier lacks. The one exception is the case
  # whose point is a network with no source, which names that network with `no_source`: it is
  # regtest, the one network with no default source (SPEC.md 9), the case pins it, its replay
  # does not hold its identity read, and the case is the bare rejection configuration_error.
  # Each online case is `{no_source, json}`, `json` its case in cases.json.
  defp replay_sources(online, files),
    do: online |> Enum.map(&replay_source(&1, files)) |> List.flatten()

  defp replay_source({no_source, %{"id" => id, "config" => %{"online" => path}} = json}, files) do
    case Map.fetch(files, "vectors/" <> path) do
      {:ok, bytes} ->
        replay = Parse.decode!(bytes)
        held = held_identities(replay)
        pinned = pinned_networks(json)
        named = json["config"]["sources"] || %{}

        missing =
          for {chain, network} = source <- pinned,
              name <- get_in(named, [chain, network, "sources"]) || [nil],
              identity_key(source, name) not in held,
              source != no_source do
            "case #{id}: its replay holds no identity read of #{chain} #{network}" <>
              "#{from(name)}, which it pins"
          end

        [
          missing,
          no_source(id, no_source, {pinned, held}, json["expected"]),
          record_sources(id, replay, named)
        ]

      :error ->
        ["case #{id}: its replay #{path} is no file the generator writes"]
    end
  end

  # A case whose cases.json entry has no replay: its config check reports it.
  defp replay_source(_case, _files), do: []

  # Each source whose identity read `replay` holds: a network's one source as
  # `{chain, network}`, and a named source as `{chain, network, name}`.
  defp held_identities(replay) do
    for %{"read" => %{"kind" => kind, "network" => network}} = record <- replay["reads"] || [],
        kind in ~w(bitcoin_identity stellar_identity),
        do:
          identity_key({String.replace_suffix(kind, "_identity", ""), network}, record["source"])
  end

  defp identity_key(source, nil), do: source
  defp identity_key({chain, network}, name), do: {chain, network, name}

  defp from(nil), do: ""
  defp from(name), do: " from the source #{name}"

  # SPEC.md 13.2: a replay record names its source exactly when it reads a Stellar or Bitcoin
  # network the case's `sources` names, and the name is one of those given for that network.
  defp record_sources(id, replay, named) do
    for %{"read" => %{"kind" => kind} = read} = record <- replay["reads"] || [],
        chain = chain_of(kind),
        chain != nil,
        names = get_in(named, [chain, read["network"], "sources"]),
        failure <- [record_source(names, record["source"])],
        failure != nil,
        uniq: true do
      "case #{id}: a record of its replay of #{chain} #{read["network"]} #{failure}"
    end
  end

  # The chain of a kind of read: `bitcoin` or `stellar`, by its name, or nil for NIST and the
  # keyring, as SPEC.md 13.2's table names the kinds.
  defp chain_of(kind), do: Enum.find(~w(bitcoin stellar), &String.starts_with?(kind, &1 <> "_"))

  defp record_source(nil, nil), do: nil
  defp record_source(nil, _name), do: "names a source, but its sources do not name the network"
  defp record_source(_names, nil), do: "names no source, but its sources name the network"

  defp record_source(names, name),
    do: if(name in names, do: nil, else: "names #{inspect(name)}, no source of the network")

  # SPEC.md 13.2: a case's `sources`, only beside `online`, is
  # `{chain: {network: {policy, required, sources}}}` for networks the case pins: `sources`
  # one or more names, each an ASCII16 and no two the same; `policy` first, at_least or all;
  # and `required`, an INT from 1 to the number of names, exactly when `policy` is at_least.
  defp sources_form(%{"config" => %{"sources" => sources} = config, "id" => id} = json) do
    label = "case #{id}: its sources"
    pinned = pinned_networks(json)

    [
      truth("#{label} are given offline", Map.has_key?(config, "online")),
      truth("#{label}: not an object of chains", is_map(sources) and sources != %{}),
      for(
        {chain, by_network} <- if(is_map(sources), do: sources, else: %{}),
        do: chain_sources("#{label}, #{chain}", chain, by_network, pinned)
      )
    ]
  end

  defp sources_form(_json), do: []

  defp chain_sources(label, chain, by_network, pinned)
       when is_map(by_network) and by_network != %{} do
    for {network, set} <- by_network,
        do: source_set("#{label} #{network}", {chain, network} in pinned, set)
  end

  defp chain_sources(label, _chain, _by_network, _pinned),
    do: ["#{label}: not an object of networks"]

  defp source_set(label, pinned?, %{"policy" => policy, "sources" => names} = set)
       when is_list(names) do
    members = if policy == "at_least", do: ~w(policy required sources), else: ~w(policy sources)

    [
      truth("#{label}: a network the case does not pin", pinned?),
      expect("#{label}: its members", set |> Map.keys() |> Enum.sort(), members),
      truth("#{label}: its policy", policy in ~w(first at_least all)),
      truth("#{label}: no source", names != []),
      truth("#{label}: a name that is no ASCII16", Enum.all?(names, &Spec.class?("ASCII16", &1))),
      expect("#{label}: names given twice", names -- Enum.uniq(names), []),
      if(policy == "at_least",
        do: truth("#{label}: its required", set["required"] in 1..length(names)//1),
        else: []
      )
    ]
  end

  defp source_set(label, _pinned?, _set),
    do: ["#{label}: not an object of policy and sources, and required"]

  # Each Stellar and Bitcoin network the case pins, as a commitment pin or an entropy pin.
  defp pinned_networks(%{"config" => config}) do
    for {_pin, by_chain} <- config["networks"] || %{},
        {chain, network} <- by_chain,
        chain in ~w(bitcoin stellar),
        uniq: true,
        do: {chain, network}
  end

  defp no_source(_id, nil, _networks, _expected), do: []

  defp no_source(id, {chain, network} = source, {pinned, held}, expected) do
    label = "case #{id}: its point is #{chain} #{network} with no source"

    [
      truth("#{label}, but only regtest has no default source (SPEC.md 9)", network == "regtest"),
      truth("#{label}, but it does not pin that network", source in pinned),
      truth("#{label}, but its replay holds that network's identity read", source not in held),
      expect("#{label}: its expected output", expected, %{"code" => "configuration_error"})
    ]
  end

  # replay_sources/2 against cases made in memory, each pinning regtest and testnet, with a
  # replay of the identity reads of both: it passes a case whose replay holds each, and a case
  # whose `no_source` is regtest and whose replay lacks regtest's read; it refuses a replay
  # without the identity read of Stellar testnet, which has sources, even in that case; a
  # replay without regtest's in a case whose `no_source` does not name it, even when the case
  # expects configuration_error; and a case whose `no_source` is regtest but whose replay holds
  # regtest's read, or whose expected output is not configuration_error.
  defp replay_sources_self_test(files) do
    reads = [
      %{
        "answer" => %{"outcome" => "found", "value" => %{"hash" => String.duplicate("0f", 32)}},
        "read" => %{"kind" => "bitcoin_identity", "network" => "regtest"}
      },
      %{
        "answer" => %{"outcome" => "unreachable", "reason" => "HTTP 503"},
        "read" => %{"kind" => "stellar_identity", "network" => "testnet"}
      }
    ]

    path = "corpus/replay/self-test.json"
    all = FileForm.encode(%{"reads" => reads})

    without = fn kind ->
      FileForm.encode(%{"reads" => Enum.reject(reads, &(&1["read"]["kind"] == kind))})
    end

    run = fn no_source, expected, replay ->
      json = %{
        "config" => %{"networks" => Case.pins(), "online" => path},
        "expected" => expected,
        "id" => "self-test"
      }

      replay_sources([{no_source, json}], Map.put(files, "vectors/" <> path, replay))
    end

    report = %{"label" => "verified", "rows" => []}
    bare = %{"code" => "configuration_error"}
    regtest = {"bitcoin", "regtest"}

    [
      expect(
        "the replay check, on a replay that holds each pinned network's identity read",
        run.(nil, report, all),
        []
      ),
      expect(
        "the replay check, on the case whose point is regtest with no source",
        run.(regtest, bare, without.("bitcoin_identity")),
        []
      ),
      truth(
        "the replay check refuses a replay without the identity read of Stellar testnet",
        run.(nil, report, without.("stellar_identity")) != [] and
          run.(regtest, bare, without.("stellar_identity")) != []
      ),
      truth(
        "the replay check refuses a replay without the identity read of regtest in a case " <>
          "whose no_source does not name regtest, even one that expects configuration_error",
        run.(nil, report, without.("bitcoin_identity")) != [] and
          run.(nil, bare, without.("bitcoin_identity")) != []
      ),
      truth(
        "the replay check refuses a case whose no_source is regtest when its replay holds " <>
          "regtest's identity read, or when it expects a report",
        run.(regtest, bare, all) != [] and
          run.(regtest, report, without.("bitcoin_identity")) != []
      )
    ]
  end

  # SPEC.md 13.3's online CONFIGURATION cases are single-defect: of the identity reads of the
  # networks such a case pins, each one made whatever the others give, step 0 refuses exactly
  # one (Generator.Model.Online.bad_identities/1), a value it forbids or, for the case whose
  # `no_source` names it, regtest with no source.
  defp configuration_identities(online, files) do
    for {no_source, %{"config" => %{"online" => _path} = config, "id" => id} = json} <- online,
        json["expected"] == %{"code" => "configuration_error"},
        refused = OnlineModel.bad_identities(OnlineModel.replay(config, files)),
        label = "case #{id}: the identity reads step 0 refuses",
        failure <-
          if(no_source,
            do: expect(label, refused, [no_source]),
            else: expect("#{label}, how many", length(refused), 1)
          ),
        do: failure
  end

  # configuration_identities/2 against copies of two online CONFIGURATION cases, each with a
  # second defect made in its replay: the case of a Stellar testnet source that gives the
  # production passphrase, with regtest's identity read dropped as well, and the case of
  # regtest with no source, with the Stellar testnet source giving the production passphrase
  # as well. Each is refused, and each case as it is passes.
  defp configuration_identities_self_test(online, files) do
    by_id = Map.new(online, fn {_no_source, json} = pair -> {json["id"], pair} end)

    for {id, second} <- [
          {"configuration-online-testnet-production_passphrase", :drop_regtest},
          {"configuration-online-no_source-regtest", :production_passphrase}
        ],
        do: one_refusal_self_test(id, Map.get(by_id, id), second, files)
  end

  defp one_refusal_self_test(id, nil, _second, _files),
    do: ["cases.json has no online case #{id} for the one-refusal self-test"]

  defp one_refusal_self_test(id, {_no_source, json} = pair, second, files) do
    path = "vectors/" <> json["config"]["online"]
    %{"reads" => reads} = Parse.decode!(Map.fetch!(files, path))
    twice = FileForm.encode(%{"reads" => Enum.flat_map(reads, &second_defect(&1, second))})

    [
      expect(
        "the one-refusal check, on #{id} as it is",
        configuration_identities([pair], files),
        []
      ),
      truth(
        "the one-refusal check refuses #{id} with a second defect, #{second}",
        configuration_identities([pair], Map.put(files, path, twice)) != []
      )
    ]
  end

  # A replay record with a second step-0 defect made in it: regtest's identity read dropped, or
  # the Stellar testnet source giving the production passphrase.
  defp second_defect(%{"read" => %{"kind" => "bitcoin_identity"}}, :drop_regtest), do: []

  defp second_defect(
         %{"read" => %{"kind" => "stellar_identity"}} = record,
         :production_passphrase
       ) do
    {_network, _field, production} = OnlineModel.production("stellar")
    [put_in(record, ["answer", "value", "network_passphrase"], production)]
  end

  defp second_defect(record, _second), do: [record]

  # A case cannot be built when its run makes a read its replay does not hold (SPEC.md 13.2).
  # The replay of `window-established`, the sound item online with every read found, less one
  # read the run makes, the ledger whose close time is its submitted-before edge, makes the
  # model raise, and so does that replay less the identity read of Stellar testnet, a network
  # with default sources; less the identity read of regtest, which has none, the run is the
  # bare rejection configuration_error; and the replay as it is gives the case's output.
  defp replay_reads_self_test(by_id, files) do
    case Map.fetch(by_id, "window-established") do
      {:ok, %{"config" => %{"online" => path} = config, "proof" => proof}} ->
        bytes = Map.fetch!(files, "vectors/" <> proof)
        %{"reads" => reads} = Parse.decode!(Map.fetch!(files, "vectors/" <> path))

        run = fn drop ->
          replay = FileForm.encode(%{"reads" => Enum.reject(reads, &drop.(&1["read"]))})

          try do
            Model.run(bytes, config, Map.put(files, "vectors/" <> path, replay))
          rescue
            error in ArgumentError -> {:raised, Exception.message(error)}
          end
        end

        [
          expect(
            "the model, on window-established's replay as it is",
            Model.expected(run.(fn _read -> false end)),
            by_id["window-established"]["expected"]
          ),
          truth(
            "the model refuses a replay without a read the run makes",
            match?(
              {:raised, "corpus/replay/window-established.json holds no answer" <> _rest},
              run.(
                &(&1 == %{
                    "kind" => "stellar_ledger",
                    "network" => "testnet",
                    "sequence" => 1_000_255
                  })
              )
            )
          ),
          truth(
            "the model refuses a replay without the identity read of Stellar testnet",
            match?({:raised, _message}, run.(&(&1["kind"] == "stellar_identity")))
          ),
          expect(
            "the model, on a replay without the identity read of regtest",
            run.(&(&1["kind"] == "bitcoin_identity")),
            {:bare, "configuration_error", nil}
          )
        ]

      _missing ->
        ["cases.json has no online case window-established for the replay self-test"]
    end
  end

  # SPEC.md 10.4: one source behaves as no `sources`. Each online case without `sources`, run
  # again with each Stellar and Bitcoin network it pins given one named source, `only`, under
  # each policy, and its replay's records of those networks naming it, gives its expected
  # output exactly. A network the case pins with no identity read stays without one, so the
  # case whose point is regtest with no source is still configuration_error.
  @policies [
    %{"policy" => "first"},
    %{"policy" => "all"},
    %{"policy" => "at_least", "required" => 1}
  ]

  @one_source "corpus/replay/one-source-check.json"

  defp one_source(cases, files) do
    for %{"config" => %{"online" => _path} = config} = json <- cases,
        not Map.has_key?(config, "sources"),
        policy <- @policies,
        failure <- one_source_run(json, policy, nil, files),
        do: failure
  end

  # One case run again with one named source for each network it pins, under `policy`, and,
  # when `second` is `{name, read, answer}`, a second source of that name under it, whose
  # records copy the first's but for its answer to `read`.
  defp one_source_run(
         %{"config" => config, "id" => id, "proof" => proof} = json,
         policy,
         second,
         files
       ) do
    pinned = pinned_networks(json)
    names = if second, do: ["only", elem(second, 0)], else: ["only"]

    sources =
      Enum.reduce(pinned, %{}, fn {chain, network}, sources ->
        Map.update(
          sources,
          chain,
          %{network => Map.put(policy, "sources", names)},
          &Map.put(&1, network, Map.put(policy, "sources", names))
        )
      end)

    %{"reads" => reads} = Parse.decode!(Map.fetch!(files, "vectors/" <> config["online"]))

    named = Enum.flat_map(reads, &name_records(&1, pinned, names, second))

    run = config |> Map.put("sources", sources) |> Map.put("online", @one_source)
    replay = FileForm.encode(%{"reads" => named})

    output =
      try do
        Model.expected(
          Model.run(
            Map.fetch!(files, "vectors/" <> proof),
            run,
            Map.put(files, "vectors/" <> @one_source, replay)
          )
        )
      rescue
        error in ArgumentError -> {:raised, Exception.message(error)}
      end

    expect(
      "case #{id}: its output with one named source for each network, under " <>
        policy["policy"],
      output,
      json["expected"]
    )
  end

  # A record of a network in `pinned` once for each of `names`, each naming its source, and any
  # other record as it is.
  defp name_records(%{"read" => read} = record, pinned, names, second) do
    if {chain_of(read["kind"]), read["network"]} in pinned,
      do: for(name <- names, do: name_record(record, name, second)),
      else: [record]
  end

  defp name_record(record, name, {name, read, answer}) do
    if record["read"] == read,
      do: %{record | "answer" => answer} |> Map.put("source", name),
      else: Map.put(record, "source", name)
  end

  defp name_record(record, name, _second), do: Map.put(record, "source", name)

  # one_source/2 compares outputs: window-established, given under `all` a second regtest
  # source whose tip is unreachable, gives sources_incomplete where its one source passed, and
  # the check refuses it; with one named source, it holds.
  defp one_source_self_test(by_id, files) do
    case Map.fetch(by_id, "window-established") do
      {:ok, json} ->
        tip = %{"kind" => "bitcoin_tip", "network" => "regtest"}
        all = %{"policy" => "all"}
        unreachable = %{"outcome" => "unreachable", "reason" => "timeout"}

        [
          expect(
            "the one-source check, on window-established",
            one_source_run(json, all, nil, files),
            []
          ),
          truth(
            "the one-source check refuses window-established with a second regtest source " <>
              "whose tip is unreachable",
            one_source_run(json, all, {"second", tip, unreachable}, files) != []
          )
        ]

      :error ->
        ["cases.json has no online case window-established for the one-source self-test"]
    end
  end

  # The case's output, derived again from its proof file's bytes and its configuration as
  # cases.json holds them, or nil when cases.json cannot say.
  defp rederive(%{"proof" => proof, "config" => config}, files) when is_binary(proof) do
    case Map.fetch(files, "vectors/" <> proof) do
      {:ok, bytes} -> Model.run(bytes, config, files)
      :error -> nil
    end
  end

  defp rederive(_json, _files), do: nil

  defp ids(definitions) do
    ids = Enum.map(definitions, & &1.id)

    [
      expect("case ids that repeat", ids -- Enum.uniq(ids), []),
      for(
        id <- ids,
        not Regex.match?(@id, id),
        do: "case id #{inspect(id)} is not of the form of #{inspect(@id.source)}"
      )
    ]
  end

  defp case_checks(definition, json, output, {files, by_id}) do
    label = "case #{definition.id}"

    if output == nil do
      ["#{label}: cases.json has no such case, or its proof file is missing"]
    else
      [
        expect(
          "#{label}: its members",
          json |> Map.keys() |> Enum.sort(),
          ~w(config expected id proof)
        ),
        expect("#{label}: its config", json["config"], config(definition)),
        truth(
          "#{label}: its config's members",
          Enum.all?(Map.keys(json["config"]), &(&1 in @config_members))
        ),
        expect("#{label}: its proof", json["proof"], Case.proof_path(definition)),
        same(
          "#{label}: its expected output, derived again",
          json["expected"],
          expected(output, definition.trace)
        ),
        defect(label, definition.defect, output),
        past(label, definition, {json, output}, files),
        report_checks(label, definition, output, {files, by_id}),
        online(label, definition, output)
      ]
    end
  end

  # SPEC.md 13.3's rule that every check but the case's own passes, past a stop: for a case
  # whose run stops at steps 4 to 7, whatever the form of its defect, the run made again with
  # no stop, as if the failing check had passed, fails beyond that row exactly the case's
  # knock-on failures, and for a precedence case the rows it states behind the first, in any
  # order.
  defp past(label, definition, {json, output}, files) do
    case {stop(output), definition.knock_on ++ behind(definition.defect)} do
      {nil, []} ->
        []

      {nil, _rows} ->
        ["#{label}: it states rows past a stop, but its run does not stop at steps 4 to 7"]

      {stated, rows} ->
        bytes = Map.fetch!(files, "vectors/" <> json["proof"])
        beyond = failing(Model.past(bytes, json["config"], files)) -- [stated]
        expected = for {code, part, step} <- rows, do: [code, part, "fail", step]

        expect(
          "#{label}: the rows that fail past its stop, beyond its own",
          Enum.sort(beyond),
          Enum.sort(expected)
        )
    end
  end

  # Where the model's run stops: its first failing row, when that row is at steps 4 to 7.
  defp stop(output) do
    case failing(output) do
      [[_code, _part, "fail", step] = first | _later] when step in @stops -> first
      _other -> nil
    end
  end

  defp behind({:precedes, _first, behind}), do: behind
  defp behind(_defect), do: []

  # What the case says it asserts, against the model's output.
  defp defect(label, {:bare, code, sub_reason}, output),
    do: expect("#{label}: a bare rejection", output, {:bare, code, sub_reason})

  defp defect(label, {:fail, code, part, step}, output),
    do: expect("#{label}: its one failing row", failing(output), [[code, part, "fail", step]])

  defp defect(label, {:fails, rows}, output) do
    expected = for {code, part, step} <- rows, do: [code, part, "fail", step]
    expect("#{label}: its failing rows", failing(output), expected)
  end

  defp defect(label, {:precedes, {code, part, step}, _behind}, output),
    do: expect("#{label}: its first failing row", failing(output), [[code, part, "fail", step]])

  defp defect(label, {:passes, rows}, output) do
    present = present(output)

    [
      expect("#{label}: its failing rows", failing(output), []),
      for {status, code, part, step} <- rows, [code, part, status, step] not in present do
        "#{label}: no row #{inspect([code, part, status, step])}"
      end
    ]
  end

  defp failing({:report, report}),
    do: for(row <- report.rows, row.status == "fail", do: Model.compared(row))

  defp failing(output), do: {:not_a_report, output}

  defp present({:report, report}), do: Enum.map(report.rows, &Model.compared/1)
  defp present(_output), do: []

  defp report_checks(label, definition, {:report, report}, {files, by_id}) do
    [
      if(definition.label,
        do: expect("#{label}: its label", report.label, definition.label),
        else: []
      ),
      if(definition.trace,
        do:
          expect(
            "#{label}: its trace",
            report.trace,
            Parse.decode!(Map.get(files, "vectors/" <> definition.trace, "null"))
          ),
        else: []
      ),
      same_as(label, definition, report, by_id),
      for {status, code, part, step} <- definition.present,
          [code, part, status, step] not in present({:report, report}) do
        "#{label}: no row #{inspect([code, part, status, step])}"
      end
    ]
  end

  defp report_checks(label, definition, _bare, _context) do
    for {option, value} <- [
          label: definition.label,
          trace: definition.trace,
          same_as: definition.same_as,
          present: if(definition.present != [], do: definition.present),
          edges: definition.edges,
          online_rows: definition.online_rows
        ],
        value != nil,
        do: "#{label}: #{option} is given for a bare rejection"
  end

  # An online case that gives a report: the edges it states and every row of CHAIN, SOURCES
  # and WINDOW that does not pass, against the model's (SPEC.md 13.1). An offline case states
  # neither.
  defp online(label, %{replay: nil} = definition, _output) do
    for {option, value} <- [
          edges: definition.edges,
          online_rows: definition.online_rows,
          no_source: definition.no_source
        ],
        value != nil,
        do: "#{label}: #{option} is given for an offline case"
  end

  defp online(label, definition, {:report, report}) do
    stated =
      for {status, code, part, step} <- definition.online_rows || [],
          do: [code, part, status, step]

    unsettled =
      for row <- report.rows,
          row.step in @online_steps,
          row.status != "pass",
          do: Model.compared(row)

    [
      truth(
        "#{label}: it states its edges and its online rows",
        definition.edges != nil and definition.online_rows != nil
      ),
      expect(
        "#{label}: its edges",
        {Model.edge(report.submitted_after), Model.edge(report.submitted_before)},
        stated_edges(definition.edges)
      ),
      expect(
        "#{label}: its rows of CHAIN, SOURCES and WINDOW that do not pass",
        unsettled,
        stated
      )
    ]
  end

  defp online(_label, _definition, _bare), do: []

  defp stated_edges({submitted_after, submitted_before}),
    do: {stated_edge(submitted_after), stated_edge(submitted_before)}

  defp stated_edges(nil), do: nil

  defp stated_edge(nil), do: nil
  defp stated_edge({basis, instant}), do: %{"basis" => basis, "instant" => instant}

  defp same_as(_label, %{same_as: nil}, _report, _by_id), do: []

  defp same_as(label, %{same_as: {other, except: steps}}, report, by_id) do
    case Map.get(by_id, other) do
      %{"expected" => %{"rows" => rows}} ->
        actual = Enum.map(report.rows, &Model.compared/1)

        [
          expect(
            "#{label}: the steps of its rows, those of #{other}",
            Enum.map(actual, &List.last/1),
            Enum.map(rows, &List.last/1)
          ),
          same(
            "#{label}: its rows outside #{inspect(steps)}, those of #{other}",
            %{"rows" => Enum.reject(actual, &(List.last(&1) in steps))},
            %{"rows" => Enum.reject(rows, &(List.last(&1) in steps))}
          )
        ]

      _other ->
        ["#{label}: same_as names #{other}, which is no case that gives a report"]
    end
  end

  defp same_as(label, %{same_as: other}, report, by_id) do
    case Map.get(by_id, other) do
      %{"expected" => %{"rows" => rows}} ->
        same(
          "#{label}: its rows, those of #{other}",
          %{"rows" => Enum.map(report.rows, &Model.compared/1)},
          %{"rows" => rows}
        )

      _other ->
        ["#{label}: same_as names #{other}, which is no case that gives a report"]
    end
  end

  # expect/3 for an expected output, which names the first row that differs rather than
  # printing every row.
  defp same(label, actual, expected) when actual == expected, do: expect(label, actual, expected)

  defp same(label, %{"rows" => actual} = a, %{"rows" => expected} = e) do
    case Enum.find_index(Enum.zip(actual, expected), fn {x, y} -> x != y end) do
      nil when length(actual) != length(expected) ->
        ["#{label}: #{length(actual)} rows, expected #{length(expected)}"]

      nil ->
        expect(label, Map.delete(a, "rows"), Map.delete(e, "rows"))

      i ->
        [
          "#{label}: row #{i} is #{inspect(Enum.at(actual, i))}, expected #{inspect(Enum.at(expected, i))}"
        ]
    end
  end

  defp same(label, actual, expected), do: expect(label, actual, expected)

  # Every file under negative/ and corpus/replay/ is a case's, in its form: a served proof is
  # JCS(envelope), and a keyring or a replay value is in the canonical form. A file given as
  # bytes keeps them. And no two files under vectors/ hold the same bytes when one of them is
  # a case's: a case that needs a file another has names it, and an edit that changes nothing
  # gives a sound proof's bytes.
  defp negative(files, definitions) do
    owned = Map.new(Enum.flat_map(definitions, &forms/1))

    forms =
      for {path, bytes} <- files, owned?(path) do
        case Map.get(owned, path) do
          nil -> "#{path} belongs to no case"
          :served -> form(path, bytes, &JCS.encode/1)
          :canonical -> form(path, bytes, &FileForm.encode/1)
          :bytes -> []
        end
      end

    [forms, duplicates(files)]
  end

  defp duplicates(files) do
    for {_bytes, [_, _ | _] = paths} <- Enum.group_by(files, &elem(&1, 1), &elem(&1, 0)),
        Enum.any?(paths, &owned?/1) do
      "#{Enum.join(Enum.sort(paths), " and ")} hold the same bytes"
    end
  end

  # A file that only a case's definition writes.
  defp owned?(path),
    do:
      String.starts_with?(path, "vectors/negative/") or
        String.starts_with?(path, "vectors/corpus/replay/")

  defp forms(definition),
    do: for({path, form, _bytes} <- owned(definition), do: {"vectors/" <> path, form})

  defp form(path, bytes, encode) do
    if String.valid?(bytes),
      do: expect("#{path} in its form", encode.(Parse.decode!(bytes)), bytes),
      else: ["#{path} is not UTF-8"]
  end

  # SPEC.md 13.1: every reason code but internal_error has a case, and each code whose status
  # is bare or fail a single-defect case.
  defp coverage(results) do
    table = Spec.read("reason-codes.json")
    codes = for %{"code" => code} <- table, code != "internal_error", do: code
    statuses = Map.new(table, &{&1["code"], &1["status"]})
    given = given(results)
    single = for {d, _output} <- results, Case.single_defect?(d), do: defect_code(d.defect)
    owners = Enum.flat_map(@classes, & &1.codes())

    lines =
      for code <- codes do
        count = Enum.count(given, &(&1 == code))
        needs_single = statuses[code] in ~w(bare fail)
        state(code, count, needs_single and code not in single)
      end

    failures =
      [
        expect(
          "the codes the class modules cover",
          Enum.sort(Enum.uniq(owners)),
          Enum.sort(codes)
        ),
        expect("codes named by more than one owner", Enum.sort(owners -- Enum.uniq(owners)), []),
        online_only(given(for {d, output} <- results, d.replay == nil, do: {d, output}), table),
        sub_reasons(results, table),
        for({:missing, line} <- lines, do: line)
      ]

    {failures, for({_state, line} <- lines, do: line)}
  end

  # SPEC.md 12.1: the sub_reasons spec/reason-codes.json lists for a code are exactly those
  # its bare cases give, so every name has a case and no case gives a name the file lacks.
  defp sub_reasons(results, table) do
    listed =
      for %{"code" => code, "sub_reasons" => names} <- table, name <- names, do: {code, name}

    given =
      for {_d, {:bare, code, sub}} <- results, sub != nil, uniq: true, do: {code, sub}

    expect(
      "the sub_reasons of the bare cases, against those spec/reason-codes.json lists",
      Enum.sort(given),
      Enum.sort(listed)
    )
  end

  # Each code the online classes name is one only an online run reaches: no offline case gives
  # it, and it is a code only an online run gives.
  defp online_only(offline, table) do
    codes = Enum.flat_map([@online, @sources], & &1.codes())

    [
      for code <- codes, code in offline do
        "cases: #{code} is an online class's, but an offline case gives it"
      end,
      for code <- codes, not online_only?(code, table) do
        "cases: #{code} is an online class's, but an offline run can reach it"
      end
    ]
  end

  # A code only an online run gives: keyring_unavailable, whose keyring read is online, or a
  # code whose every step is CHAIN, SOURCES or WINDOW, which an offline run closes.
  defp online_only?("keyring_unavailable", _table), do: true

  defp online_only?(code, table) do
    case Enum.find(table, &(&1["code"] == code)) do
      %{"step" => steps} -> Enum.all?(String.split(steps, ", "), &(&1 in @online_steps))
      nil -> false
    end
  end

  defp given(results) do
    Enum.flat_map(results, fn
      {_d, {:bare, code, _sub}} ->
        [code]

      {_d, {:report, report}} ->
        report.rows |> Enum.map(& &1.code) |> Enum.reject(&is_nil/1) |> Enum.uniq()

      {_d, nil} ->
        []
    end)
  end

  defp defect_code({:bare, code, _sub}), do: code
  defp defect_code({:fail, code, _part, _step}), do: code

  # A code with no case, or with a status of bare or fail and no single-defect case, fails the
  # check, whichever class module owns it.
  defp state(code, count, lacks_single) do
    cond do
      count == 0 -> {:missing, "cases: #{code} has no case"}
      lacks_single -> {:missing, "cases: #{code} has no single-defect case"}
      true -> {:covered, "cases: #{code}: covered, in #{count} cases"}
    end
  end
end
