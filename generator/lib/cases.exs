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
    file another case has. `"unavailable"` is online, and waits for the replay format.
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
  - `trace`: the path of the trace file the report's trace must equal, for a sound proof and
    for its reformatted copies; it becomes the `trace` member of the case's `expected`.
  - `same_as`: the id of a case whose rows this case's rows must equal, as SPEC.md 13.3's
    sameness cases say; or `{id, except: steps}`, where the rows of the steps named may differ
    and every other row must equal that case's, each step keeping its number of rows, as for
    the keyring `none`, which gives "otherwise the sound proof's rows".
  - `present`: rows, each `{status, code, part, step}`, that must be among the report's rows
    whatever the defect, for a row SPEC.md names beside the one that fails (D62's passing
    LINK_HEAD at a genesis witness block whose `height` is declared wrong).

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
  and the entropy pin of each source that has a network, which here are the same.
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

  @doc "The path under vectors/ of the case's keyring file, or its `keyring` member."
  def keyring_member(%__MODULE__{keyring: {:path, path}}), do: path

  def keyring_member(%__MODULE__{keyring: {_form, _keyring}, id: id}),
    do: "negative/#{id}.keyring.json"

  def keyring_member(%__MODULE__{keyring: keyring}), do: keyring

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
    status is bare or fail with a single-defect case (SPEC.md 13.1). While cases/1 gives no
    case, the check of every code reports these codes as pending on the module rather than
    failing.
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
    and `networks`, `{"commitment": {chain: network}, "entropy": {chain: network}}`; no case
    here is online. `expected` holds, for a bare rejection, `code`, and `sub_reason` when the
    code has one; otherwise the report's `label`, its `rows`, each `[code, part, status,
    step]` in the order of SPEC.md 10.2, passes and skips included, and for a sound proof and
    its reformatted copies `trace`, the path of the trace file. Every path is relative to
    vectors/.
  - under `negative/`, `<id>.proof.json`, the proof file of a case that does not name one
    already written, and `<id>.keyring.json`, the keyring file a case supplies. A proof file
    is in the served form of SPEC.md 3.1, and a keyring file in the canonical form, unless the
    case concerns the file's bytes: a defect, a reformatting or a size. A proof file's name
    says what a verifier is given, a file offered as a proof, and not that it parses, so a file
    that is not UTF-8, not one JSON text or over MAX_READ_OCTETS keeps the same name.

  The checks, from the files about to be written: cases.json reads back to the ids and
  configurations the modules state; each case's expected output, derived again from its proof
  file's bytes and its configuration as cases.json holds them, equals the case's `expected`;
  the model's output is what the case says it asserts (Generator.Case), so a single-defect
  case has exactly its one failing row; a case whose run stops at steps 4 to 7, where a
  failure ends the run, whatever the form of its defect, is run again past that stop as if its
  check had passed (Generator.Model.past/3), and the rows that fail beyond the run's own are
  exactly its knock-on failures and, for a precedence case, the defect it states behind the
  first, so no second defect hides behind a stop; a trace named is the model's trace; every
  file under negative/ belongs to a case, is in its form and holds bytes no other file under
  vectors/ holds, so a case that needs another's file names it; and every reason code but
  `internal_error` has a case, each code whose status is bare or fail a single-defect case
  (SPEC.md 13.1), reported per code as covered, or pending: online, where only an online case
  can give it (Generator.Cases.Online), or on a class module that has no cases yet. A code the
  online list names must be one only an online run reaches: no offline case gives it, and it
  is a code of CHAIN, SOURCES or WINDOW alone, or `keyring_unavailable`, whose keyring read is
  online.
  """

  import Generator.Check

  alias Generator.{Case, FileForm, JCS, Model, Spec}
  alias Generator.Cases.Online

  # The class modules, in the order of their classes in SPEC.md 13.3.
  @classes [
    Generator.Cases.Sound,
    Generator.Cases.Parse,
    Generator.Cases.Front,
    Generator.Cases.Shape,
    Generator.Cases.Derive
  ]

  @config_members ~w(environment expected_hash keyring networks online)
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
        envelope = JSON.decode!(bytes)
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

  defp negative_files(definition) do
    proof =
      case definition.proof do
        {:served, envelope} -> [{Case.proof_path(definition), Case.served(envelope)}]
        {:bytes, bytes} -> [{Case.proof_path(definition), bytes}]
        {:path, _path} -> []
      end

    keyring =
      case definition.keyring do
        {:value, keyring} -> [{Case.keyring_member(definition), FileForm.encode(keyring)}]
        {:bytes, bytes} -> [{Case.keyring_member(definition), bytes}]
        _named -> []
      end

    for {path, bytes} <- proof ++ keyring, do: {"vectors/" <> path, bytes}
  end

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
      {"networks", definition.networks}
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
    cases = JSON.decode!(Map.fetch!(files, "vectors/cases.json"))
    by_id = Map.new(cases, &{&1["id"], &1})

    results =
      for definition <- definitions do
        json = Map.get(by_id, definition.id, %{})
        output = rederive(json, files)
        {definition, output, case_checks(definition, json, output, {files, by_id})}
      end

    {coverage_failures, report} = coverage(for {d, output, _failures} <- results, do: {d, output})

    failures =
      List.flatten([
        expect(
          "the ids of cases.json, in order",
          Enum.map(cases, & &1["id"]),
          Enum.map(definitions, & &1.id)
        ),
        ids(definitions),
        Enum.map(results, &elem(&1, 2)),
        negative(files, definitions),
        coverage_failures
      ])

    {failures, report}
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
        report_checks(label, definition, output, {files, by_id})
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
            JSON.decode!(Map.get(files, "vectors/" <> definition.trace, "null"))
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
          present: if(definition.present != [], do: definition.present)
        ],
        value != nil,
        do: "#{label}: #{option} is given for a bare rejection"
  end

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

  # Every file under negative/ is a case's, in its form: a served proof is JCS(envelope), and a
  # keyring value is in the canonical form. A file given as bytes keeps them. And no two files
  # under vectors/ hold the same bytes when one of them is under negative/: a case that needs a
  # file another has names it, and an edit that changes nothing gives a sound proof's bytes.
  defp negative(files, definitions) do
    owned = Map.new(Enum.flat_map(definitions, &forms/1))

    forms =
      for {"vectors/negative/" <> _name = path, bytes} <- files do
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
        Enum.any?(paths, &String.starts_with?(&1, "vectors/negative/")) do
      "#{Enum.join(Enum.sort(paths), " and ")} hold the same bytes"
    end
  end

  defp forms(definition) do
    proof =
      case definition.proof do
        {:served, _envelope} -> [{Case.proof_path(definition), :served}]
        {:bytes, _bytes} -> [{Case.proof_path(definition), :bytes}]
        {:path, _path} -> []
      end

    keyring =
      case definition.keyring do
        {:value, _keyring} -> [{Case.keyring_member(definition), :canonical}]
        {:bytes, _bytes} -> [{Case.keyring_member(definition), :bytes}]
        _named -> []
      end

    for {path, form} <- proof ++ keyring, do: {"vectors/" <> path, form}
  end

  defp form(path, bytes, encode) do
    if String.valid?(bytes),
      do: expect("#{path} in its form", encode.(JSON.decode!(bytes)), bytes),
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
    pending = pending(results)
    owners = Enum.flat_map(@classes, & &1.codes()) ++ Online.codes()

    lines =
      for code <- codes do
        count = Enum.count(given, &(&1 == code))
        needs_single = statuses[code] in ~w(bare fail)
        state(code, count, needs_single and code not in single, pending)
      end

    failures =
      [
        expect(
          "the codes the class modules and the online list cover",
          Enum.sort(Enum.uniq(owners)),
          Enum.sort(codes)
        ),
        expect("codes named by more than one owner", Enum.sort(owners -- Enum.uniq(owners)), []),
        for code <- Online.codes(),
            not Enum.any?(Online.pending(), fn {_class, _config, _proof, expected} ->
              expected =~ code
            end) do
          "cases: #{code} is pending online, but no pending online case gives it"
        end,
        online_only(given, table),
        for({:missing, line} <- lines, do: line)
      ]

    {failures, for({_state, line} <- lines, do: line)}
  end

  # Each code the online list names is one only an online run reaches: no offline case gives
  # it, and every case here is offline; and it is a code only an online run gives.
  defp online_only(given, table) do
    [
      for code <- Online.codes(), code in given do
        "cases: #{code} is in the online list, but an offline case gives it"
      end,
      for code <- Online.codes(), not online_only?(code, table) do
        "cases: #{code} is in the online list, but an offline run can reach it"
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

  # Each code a class module with no cases yet owns, with that module.
  defp pending(results) do
    filled = results |> Enum.map(fn {d, _output} -> d.class end) |> Enum.uniq()

    for class <- @classes,
        class not in filled,
        code <- class.codes(),
        into: %{},
        do: {code, class}
  end

  defp state(code, count, lacks_single, pending) do
    cond do
      count > 0 and not lacks_single ->
        {:covered, "cases: #{code}: covered, in #{count} cases"}

      code in Online.codes() ->
        {:online, "cases: #{code}: pending online, until the replay format is set"}

      Map.has_key?(pending, code) ->
        {:class, "cases: #{code}: pending, #{inspect(pending[code])} has no cases yet"}

      count > 0 ->
        {:missing, "cases: #{code} has no single-defect case"}

      true ->
        {:missing, "cases: #{code} has no case"}
    end
  end
end
