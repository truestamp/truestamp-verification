# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Generator.AgentTest do
  @moduledoc """
  The files of the agent-sufficiency test that the generator writes under agent-test/
  (SPEC.md 7.4), from the sound proofs under vectors/positive/:

  - `PROMPT.md`: the prompt, read from the fenced block of SPEC.md 7.4, under a license
    comment;
  - under `fixtures/<fixture>/`, the six base fixtures, each the directory a session
    receives: its proofs, `keyring.json` (the bytes of vectors/keyring.test.json),
    `replay.json`, and for the reference-mode fixture the text as `constructions-<d>.json`;
  - under `mutants/<fixture>/`, the flawed copies of each proof, `<name>.<flaw>.proof.json`,
    in the fixture's file form, and `<name>.<flaw>.replay.json`, the replay of its own of each
    mutant whose reads the fixture's replay does not answer;
  - under `expected/<fixture>/`, `<run>.txt`, the expected lines of each run, sorted by their
    bytes, one per line;
  - `runs.txt`: each run, `<fixture>/<run> <proof> <keyring> <replay> [<constructions>]`,
    with every path relative to agent-test/, after a license comment.

  The expected lines, every one the generator's own. Every line but the two window lines it
  derives from the proof and the keyring (`own_lines/2`: its DERIVE engine's trace,
  `proof_hash`, Verify, the keyring lookup and the marker). The two window lines come from
  its model of the verification steps (Generator.Model) run online under the run's replay,
  with the fixture's keyring, E_v `test` and the pins every sound proof passes POLICY under,
  which gives the edges, both null when the label is `failed`. No verifier runs here: a
  verifier's own tests hold its lines to these files.

  The checks, whose failures stop the run before anything is written: every replay holds
  to the replay form (Generator.Replay); the model's run of each base proof passes with a
  submitted-before edge, and with a submitted-after edge unless the proof is a block proof,
  and its run of each mutant is `failed`; the reformatted fixture gives exactly the lines of
  the served one; every mutant differs from its base in its proof bytes or has a replay of
  its own, and fails with its rule's codes; each range mutant's walk, with the range check
  skipped, reaches the root it carries, each side mutant's index is in range and its walk
  with the first step on the other side reaches the root it carries, and the graft's claims
  hash has the length its hash_type fixes; and SPEC.md 7.4 holds one fenced prompt.
  """

  import Generator.Check

  alias Generator.{
    AgentTest.Mutants,
    Bitcoin,
    Bytes,
    Case,
    Cases.Sound,
    Chain,
    Derive,
    FileForm,
    JCS,
    Merkle,
    Model,
    Model.Online,
    Parse,
    Pointer,
    Registry,
    Replay,
    Replay.World,
    Spec
  }

  @dir "agent-test"
  @environment "test"

  # Each base fixture: its directory, its proofs by their names under vectors/positive/, and
  # its file form.
  @fixtures [
    {"1-item", ~w(item), :served},
    {"2-item-reformatted", ~w(item), :reformatted},
    {"3-item-reference", ~w(item), :reference},
    {"4-entropy", ~w(entropy_bitcoin entropy_nist entropy_stellar), :served},
    {"5-block", ~w(block block-rotation), :served},
    {"6-beacon", ~w(beacon), :served}
  ]

  # The paths under agent-test/ the generator owns: every file under them is one it writes.
  @owned_dirs ~w(fixtures mutants expected)
  @owned_files ~w(PROMPT.md runs.txt)

  @header "# Copyright (c) 2026 Truestamp, Inc.\n# SPDX-License-Identifier: Apache-2.0\n"

  @doc "The base fixtures: `{directory, proof names, file form}`."
  def fixtures, do: @fixtures

  @doc "The directories and files under agent-test/ the generator owns."
  def owned, do: {@owned_dirs, @owned_files}

  @doc """
  `{files, failures}`: every file the generator writes under agent-test/, by its path from the
  root of the repository, built from `vectors`, the files under vectors/ by their paths, and
  the failures of its checks.
  """
  def build(vectors) do
    sound = sound(vectors)
    keyring = Map.fetch!(vectors, "vectors/keyring.test.json")
    fixtures = Enum.map(@fixtures, &fixture(&1, sound, keyring))
    runs = Enum.flat_map(fixtures, & &1.runs)
    inputs = inputs(fixtures)

    case prompt(Spec.spec_md()) do
      {:ok, prompt} ->
        derived = derived(inputs, runs)
        expected = Map.new(runs, &{&1.id, expected(&1, derived, inputs)})
        files = files(prompt, inputs, runs, expected)
        {files, checks(fixtures, runs, derived, inputs, expected)}

      {:error, failure} ->
        {%{}, [failure]}
    end
  end

  # The sound proofs, by name: the decoded envelope and the served bytes.
  defp sound(vectors) do
    for {"vectors/positive/" <> file, bytes} <- vectors,
        String.ends_with?(file, ".proof.json"),
        into: %{},
        do: {String.replace_suffix(file, ".proof.json", ""), Parse.decode!(bytes)}
  end

  # ---------------------------------------------------------------------------------------
  # The fixtures and their runs

  # A fixture: its directory, its files (path under agent-test/ to bytes), and its runs.
  defp fixture({dir, names, form}, sound, keyring) do
    base = "fixtures/#{dir}/"

    bases =
      for name <- names do
        envelope = base_envelope(Map.fetch!(sound, name), form)
        %{name: name, envelope: envelope, bytes: written(envelope, form)}
      end

    replay = replay(Enum.map(bases, & &1.envelope["proof"]))
    text = if form == :reference, do: [constructions()], else: []

    files =
      Map.new(
        [{base <> "keyring.json", keyring}, {base <> "replay.json", replay}] ++
          for({digest, bytes} <- text, do: {base <> "constructions-#{digest}.json", bytes}) ++
          for(b <- bases, do: {base <> b.name <> ".proof.json", b.bytes})
      )

    constructions = for {digest, _bytes} <- text, do: base <> "constructions-#{digest}.json"

    runs =
      Enum.flat_map(bases, fn b ->
        run = %{
          id: "#{dir}/#{b.name}",
          fixture: dir,
          name: b.name,
          flaw: nil,
          proof: base <> b.name <> ".proof.json",
          keyring: base <> "keyring.json",
          replay: base <> "replay.json",
          replay_bytes: nil,
          constructions: constructions,
          bytes: b.bytes,
          base_bytes: b.bytes,
          form: form,
          codes: nil,
          envelope: b.envelope,
          base_envelope: b.envelope,
          type: b.envelope["proof"]["type"]
        }

        [run | mutant_runs(run, b.envelope, form, replay)]
      end)

    %{dir: dir, files: files, runs: runs}
  end

  defp base_envelope(envelope, :reference) do
    [{digest, _bytes}] = [constructions()]
    url = "https://www.truestamp.com/.well-known/constructions-#{digest}.json"
    Case.sign(%{envelope["proof"] | "constructions" => url})
  end

  defp base_envelope(envelope, _form), do: envelope

  defp written(envelope, :reformatted), do: Sound.reformatted(envelope)
  defp written(envelope, _form), do: Case.served(envelope)

  # The one accepted text, as its digest and its exact bytes.
  defp constructions do
    [path] = Path.wildcard(Path.join(Spec.root(), "spec/constructions/*.json"))
    {Path.basename(path, ".json"), File.read!(path)}
  end

  # The replay of a fixture: every read a verifier makes online for any of its proofs, under
  # the pins every sound proof passes POLICY under, answered by the model's sources.
  defp replay(proofs) do
    world = World.new(Chain.build())

    proofs
    |> Enum.flat_map(&Replay.reads(&1, Case.pins()))
    |> Enum.uniq()
    |> Enum.map(fn {kind, parameters} ->
      Replay.record(kind, parameters, World.answer(world, kind, parameters))
    end)
    |> Replay.file()
    |> FileForm.encode()
  end

  # ---------------------------------------------------------------------------------------
  # The mutants

  # Each mutant of the base run `run` (Generator.AgentTest.Mutants): a proof of its own, in
  # the fixture's file form, when its envelope is not the base's, and a replay of its own
  # when the fixture's does not answer it.
  defp mutant_runs(run, envelope, form, replay) do
    dir = "mutants/#{run.fixture}/"

    for m <- Mutants.all(envelope["proof"], envelope, Parse.decode!(replay)) do
      name = "#{run.name}.#{m.flaw}"
      own? = m.envelope != envelope

      %{
        run
        | id: "#{run.fixture}/#{name}",
          flaw: m.flaw,
          codes: m.codes,
          envelope: m.envelope,
          proof: if(own?, do: dir <> name <> ".proof.json", else: run.proof),
          bytes: if(own?, do: written(m.envelope, form), else: run.bytes),
          replay: if(m.replay, do: dir <> name <> ".replay.json", else: run.replay),
          replay_bytes: m.replay && FileForm.encode(m.replay)
      }
    end
  end

  # ---------------------------------------------------------------------------------------
  # The files a run needs, the lines derived, and the expected lines

  # Every input file under agent-test/: the fixtures' files, and each mutant's proof and
  # replay of its own.
  defp inputs(fixtures) do
    fixed = for fixture <- fixtures, file <- fixture.files, into: %{}, do: file

    mutants =
      for fixture <- fixtures,
          run <- fixture.runs,
          run.flaw != nil,
          file <- input(run),
          into: %{},
          do: file

    Map.merge(fixed, mutants)
  end

  defp input(run) do
    proof = if run.bytes != run.base_bytes, do: [{run.proof, run.bytes}], else: []
    replay = if run.replay_bytes, do: [{run.replay, run.replay_bytes}], else: []
    proof ++ replay
  end

  # The lines the generator derives for every run, by id, each once.
  defp derived(inputs, runs) do
    Map.new(runs, fn run ->
      lines = own_lines(Map.fetch!(inputs, run.proof), Map.fetch!(inputs, run.keyring))
      {run.id, Enum.uniq(lines)}
    end)
  end

  # A run's expected lines: those it derives, and the model's window lines, sorted by bytes.
  defp expected(run, derived, inputs) do
    report = model(run, inputs)

    window = [
      "submitted_after " <> instant(report.submitted_after),
      "submitted_before " <> instant(report.submitted_before)
    ]

    (Map.fetch!(derived, run.id) ++ window) |> Enum.uniq() |> Enum.sort()
  end

  defp instant(nil), do: "none"
  defp instant(%{instant: instant}), do: instant

  # The model's report of the run online under its replay: E_v test, the fixture's keyring
  # and the pins every sound proof passes POLICY under. The model reads a case's files by
  # their paths under vectors/, so the run's keyring and replay are handed to it so.
  defp model(run, inputs) do
    {config, files} = model_input(run, inputs)
    {:report, report} = Model.run(Map.fetch!(inputs, run.proof), config, files)
    report
  end

  defp model_input(run, inputs) do
    files = %{
      "vectors/agent-test/keyring.json" => Map.fetch!(inputs, run.keyring),
      "vectors/agent-test/replay.json" => Map.fetch!(inputs, run.replay)
    }

    config = %{
      "environment" => @environment,
      "keyring" => "agent-test/keyring.json",
      "networks" => Case.pins(),
      "online" => "agent-test/replay.json"
    }

    {config, files}
  end

  # ---------------------------------------------------------------------------------------
  # The files

  defp files(prompt, inputs, runs, expected) do
    runs_txt =
      [
        @header,
        "# Each run of the agent-sufficiency test (SPEC.md 7.4): its id, which names its\n",
        "# expected lines, expected/<id>.txt, then its proof, keyring, replay and, for a proof\n",
        "# in reference mode, its constructions text, each a path relative to agent-test/.\n",
        for run <- runs do
          [Enum.join([run.id, run.proof, run.keyring, run.replay | run.constructions], " "), "\n"]
        end
      ]
      |> IO.iodata_to_binary()

    expected_files =
      for {id, lines} <- expected, into: %{} do
        {"expected/#{id}.txt", Enum.map_join(lines, &(&1 <> "\n"))}
      end

    inputs
    |> Map.merge(expected_files)
    |> Map.put("PROMPT.md", prompt)
    |> Map.put("runs.txt", runs_txt)
    |> Map.new(fn {path, bytes} -> {"#{@dir}/#{path}", bytes} end)
  end

  @doc """
  `{:ok, bytes}`, the bytes of agent-test/PROMPT.md: a license comment, then the one fenced
  `text` block of SPEC.md 7.4 in the text `spec_md`, or `{:error, failure}`.
  """
  def prompt(spec_md) do
    section =
      case String.split(spec_md, "\n### 7.4 ", parts: 2) do
        [_before, rest] -> rest |> String.split("\n## 8. ", parts: 2) |> hd()
        _missing -> ""
      end

    case Regex.scan(~r/\n```text\n(.*?)\n```\n/s, section) do
      [[_all, text]] ->
        {:ok,
         "<!--\nCopyright (c) 2026 Truestamp, Inc.\nSPDX-License-Identifier: Apache-2.0\n-->\n\n" <>
           text <> "\n"}

      found ->
        {:error,
         "agent-test: SPEC.md 7.4 holds #{length(found)} fenced text blocks, not one prompt"}
    end
  end

  # ---------------------------------------------------------------------------------------
  # The checks

  defp checks(fixtures, runs, derived, inputs, expected) do
    by_id = Map.new(runs, &{&1.id, &1})

    List.flatten([
      line_checks(runs, derived, expected),
      for {path, bytes} <- inputs, String.ends_with?(path, "replay.json") do
        Replay.validate(Parse.decode!(bytes), "agent-test/" <> path)
      end,
      base_checks(fixtures, runs),
      mutant_checks(runs, derived, inputs, by_id),
      for(run <- runs, do: file_form(run)),
      inventory(runs),
      truth("agent-test: every run's id is unique", map_size(by_id) == length(runs))
    ])
  end

  # Each run draws its window as it should, and fixture 2 gives the lines of fixture 1.
  defp line_checks(runs, derived, expected) do
    [
      for(run <- runs, do: window_check(run, Map.fetch!(expected, run.id))),
      for run <- runs, run.fixture == "1-item" do
        same_lines(
          expected,
          run.id,
          String.replace_prefix(run.id, "1-item/", "2-item-reformatted/")
        )
      end,
      for(run <- runs, do: gate_lines(run, Map.fetch!(derived, run.id)))
    ]
  end

  # Each base proof has mutants, and its commitments settle to themselves.
  defp base_checks(fixtures, runs) do
    for fixture <- fixtures, run <- fixture.runs, run.flaw == nil do
      [
        truth(
          "agent-test #{run.id}: the fixture holds mutants of its proof",
          Enum.any?(runs, &(&1.fixture == run.fixture and &1.name == run.name and &1.flaw))
        ),
        expect(
          "agent-test #{run.id}: its commitments settle to themselves",
          Mutants.settle(run.envelope["proof"], run.envelope["proof"]),
          run.envelope["proof"]
        )
      ]
    end
  end

  # Each mutant differs from its base and fails with its rule's codes; the hash, signature
  # and graft mutants show their flaw in their lines.
  defp mutant_checks(runs, derived, inputs, by_id) do
    [
      for run <- runs, run.flaw != nil do
        [
          truth(
            "agent-test #{run.id}: it differs from its base in its proof or its replay",
            run.bytes != run.base_bytes or run.replay_bytes != nil
          ),
          isolated(run, inputs)
        ]
      end,
      hash_mutants(runs, derived),
      for(
        run <- runs,
        run.flaw in ~w(signature signature_s signature_cofactor),
        do: signature_only(run, by_id, derived)
      ),
      for(run <- runs, run.flaw == "graft", do: grafted(run, derived)),
      for(run <- runs, run.flaw && kind(run.flaw) == "path.range", do: ranged(run)),
      for(run <- runs, run.flaw && kind(run.flaw) == "path.side", do: in_range(run))
    ]
  end

  # The inclusion proof a path. mutant's flaw names: `path<q>.<change>`, each `.` of <q>
  # written `/` again.
  defp walked(%{flaw: "path" <> rest}) do
    {slug, _change} = rest |> String.split(".") |> Enum.split(-1)
    Enum.join(slug, "/")
  end

  # A range mutant's leaf_index is its tree_size, and its walk from the leaf it recomputes,
  # with the range check skipped, reaches the root its record carries: so only that check
  # fails it.
  defp ranged(run) do
    proof = run.envelope["proof"]
    q = walked(run)
    {_q, {kind, preimage}} = List.keyfind(Mutants.inclusion_proofs(proof), q, 0)
    leaf = Bytes.hex(Registry.record_hash(kind, Pointer.get(proof, preimage)))
    %{"leaf_index" => index, "tree_size" => size} = inclusion = Pointer.get(proof, q)
    root = Pointer.get(proof, Mutants.root_record(q) <> "/merkle_root")

    truth(
      "agent-test #{run.id}: its leaf_index is its tree_size, and its walk with the range " <>
        "check skipped reaches the root it carries",
      index == size and Merkle.walk(leaf, inclusion, range: false) == {:ok, root}
    )
  end

  # A side mutant's leaf_index is below its tree_size, so no range check refuses it, and its
  # walk from the leaf it recomputes, its first step on the other side, reaches the root its
  # record carries: so only the side of that step fails it.
  defp in_range(run) do
    proof = run.envelope["proof"]
    q = walked(run)
    {_q, {kind, preimage}} = List.keyfind(Mutants.inclusion_proofs(proof), q, 0)
    leaf = Bytes.hex(Registry.record_hash(kind, Pointer.get(proof, preimage)))
    %{"leaf_index" => index, "tree_size" => size} = inclusion = Pointer.get(proof, q)
    root = Pointer.get(proof, Mutants.root_record(q) <> "/merkle_root")

    [
      truth("agent-test #{run.id}: its leaf_index is below its tree_size", index < size),
      truth(
        "agent-test #{run.id}: its walk with the first step on the other side reaches the " <>
          "root it carries",
        Merkle.walk(leaf, inclusion, flip: true) == {:ok, root}
      )
    ]
  end

  # A base run's window lines are both instants, but a block proof's submitted-after edge; a
  # mutant's are both none.
  defp window_check(%{flaw: nil} = run, lines) do
    after_line = Enum.find(lines, &String.starts_with?(&1, "submitted_after "))
    before_line = Enum.find(lines, &String.starts_with?(&1, "submitted_before "))

    [
      truth(
        "agent-test #{run.id}: a submitted-before edge",
        before_line != "submitted_before none"
      ),
      truth(
        "agent-test #{run.id}: a submitted-after edge exactly when it is no block proof",
        after_line == "submitted_after none" == (run.type == "block")
      )
    ]
  end

  defp window_check(run, lines) do
    truth(
      "agent-test #{run.id}: a mutant draws no window",
      "submitted_after none" in lines and "submitted_before none" in lines
    )
  end

  defp same_lines(expected, a, b),
    do:
      expect(
        "agent-test: #{b} gives the lines of #{a}",
        Map.fetch!(expected, b),
        Map.fetch!(expected, a)
      )

  # A mutant fails with exactly the reason codes it names: the model's run with no stop at
  # the gate or SHAPE (Generator.Model.past/3), and every CHAIN and SOURCES read under its
  # replay, each made whatever the others give, so a flaw that also broke a chain read, or a
  # link, shows. One that changes one carried value only must fail somewhere.
  defp isolated(run, inputs) do
    got = failing_codes(run, inputs)

    case run.codes do
      :any ->
        truth("agent-test #{run.id}: it fails a check", got != [])

      codes ->
        expect("agent-test #{run.id}: the reason codes it fails with", got, Enum.sort(codes))
    end
  end

  @doc false
  def failing_codes(run, inputs) do
    {config, files} = model_input(run, inputs)
    bytes = Map.fetch!(inputs, run.proof)
    {:report, report} = Model.past(bytes, config, files)
    offline = for row <- report.rows, row.status == "fail", do: row.code

    {:ok, online} = config |> Online.replay(files) |> Online.sources()
    {:ok, %{"proof" => proof}} = Parse.read(bytes)

    chain =
      for part <- entry_parts(proof) ++ genesis_parts(proof),
          {"fail", code, _candidate} <- [Online.chain(proof, part, online)],
          do: code

    sources =
      for part <- Replay.entropy_pointers(proof),
          {"fail", code, _candidate} <- [Online.source(proof, part, online)],
          do: code

    Enum.sort(Enum.uniq(offline ++ chain ++ sources))
  end

  defp entry_parts(proof) do
    for base <- ~w(/commitments /signing_key_event/commitments),
        {chain, _entry} <- Pointer.get(proof, base) || %{},
        do: "#{base}/#{chain}"
  end

  defp genesis_parts(proof) do
    for b <- ~w(/block /witnesses/block /signing_key_event/block),
        part = b <> "/record/metadata/genesis/bitcoin",
        Pointer.get(proof, part) != nil,
        do: part
  end

  # Every run's signature is valid, its key in the keyring and its environment test, but the
  # mutant whose flaw is that line's.
  defp gate_lines(run, lines) do
    signature =
      if run.flaw in ~w(signature signature_s signature_cofactor), do: "invalid", else: "valid"

    keyring = if run.flaw == "self_signed", do: "no-match", else: "match"
    environment = if run.flaw == "staging", do: "staging", else: "test"

    for line <- [
          "/signature/value " <> signature,
          "keyring " <> keyring,
          "environment " <> environment
        ],
        line not in lines,
        do: "agent-test #{run.id}: its lines lack `#{line}`"
  end

  # The hash mutants of a proof are one for each hash line of its base whose carried value is
  # a HEX64, and each one's line at its pointer differs from the value the mutant carries.
  defp hash_mutants(runs, derived) do
    for base <- runs, base.flaw == nil do
      proof = base.envelope["proof"]

      wanted =
        for line <- Map.fetch!(derived, base.id),
            "/proof" <> part <- [hd(String.split(line, " "))],
            not String.ends_with?(part, "/handover_signature"),
            Spec.class?("HEX64", Pointer.get(proof, part)),
            into: MapSet.new(),
            do: part

      mutants =
        for run <- runs,
            run.fixture == base.fixture and run.name == base.name,
            match?("hash." <> _p, run.flaw),
            do: run

      made = MapSet.new(mutants, &hashed_part/1)

      [
        expect(
          "agent-test #{base.id}: its hash mutants' pointers",
          Enum.sort(made),
          Enum.sort(wanted)
        ),
        for run <- mutants do
          part = hashed_part(run)
          carried = Pointer.get(run.envelope["proof"], part)

          truth(
            "agent-test #{run.id}: its line at #{part} is not the value it carries",
            "/proof#{part} #{carried}" not in Map.fetch!(derived, run.id)
          )
        end
      ]
    end
  end

  # The pointer a hash mutant's flaw names: its `.` written `/` again.
  defp hashed_part(%{flaw: "hash" <> slug}), do: String.replace(slug, ".", "/")

  # A signature mutant's lines are its base's but for /signature/value.
  defp signature_only(run, by_id, derived) do
    base = Map.fetch!(by_id, "#{run.fixture}/#{run.name}")
    strip = &Enum.reject(&1, fn line -> String.starts_with?(line, "/signature/value ") end)

    expect(
      "agent-test #{run.id}: its lines but /signature/value are its base's",
      Enum.sort(strip.(Map.fetch!(derived, run.id))),
      Enum.sort(strip.(Map.fetch!(derived, base.id)))
    )
  end

  # The graft's walk reaches the root of its changed /block record, whose hash is not the
  # block_hash beside it: its claims_hash, item_hash and root lines are the values it carries,
  # and its block_hash line is not.
  defp grafted(run, derived) do
    proof = run.envelope["proof"]
    lines = Map.fetch!(derived, run.id)
    line = &"/proof#{&1} #{Pointer.get(proof, &1)}"

    carried =
      for part <- ~w(/subject/record/claims_hash /subject/item_hash /block/record/merkle_root),
          line.(part) not in lines,
          do: "agent-test #{run.id}: its line at #{part} is not the value it carries"

    %{"hash" => hash, "hash_type" => type} = proof["subject"]["claims"]

    [
      carried,
      truth(
        "agent-test #{run.id}: its block_hash line is not the value it carries",
        line.("/block/block_hash") not in lines
      ),
      truth(
        "agent-test #{run.id}: its claims hash is lowercase hex of the length its hash_type " <>
          "(#{type}) fixes",
        Regex.match?(~r/\A[0-9a-f]+\z/, hash) and String.length(hash) == Model.hash_length(type)
      )
    ]
  end

  # Each proof file in its fixture's form: fixture 2's reformatted (Generator.Cases.Sound),
  # never the served form; every other fixture's served; and fixture 3's in reference mode,
  # naming the text beside it, whose bytes are those of spec/constructions/, while every other
  # fixture's proofs carry the text in full.
  defp file_form(run) do
    {:ok, envelope} = Parse.read(run.bytes)
    constructions = envelope["proof"]["constructions"]

    form =
      case run.form do
        :reformatted ->
          truth(
            "agent-test #{run.id}: its proof is in the reformatted form",
            run.bytes == Sound.reformatted(envelope) and run.bytes != Case.served(envelope)
          )

        _served ->
          truth(
            "agent-test #{run.id}: its proof is in the served form",
            run.bytes == Case.served(envelope)
          )
      end

    mode =
      case {run.form, run.constructions} do
        {:reference, [path]} ->
          [{digest, bytes}] = [constructions()]

          truth(
            "agent-test #{run.id}: its proof names the text beside it, in reference mode",
            constructions == "https://www.truestamp.com/.well-known/constructions-#{digest}.json" and
              Path.basename(path) == "constructions-#{digest}.json" and
              Bytes.hex(:crypto.hash(:sha256, bytes)) == digest
          )

        {_form, []} ->
          truth("agent-test #{run.id}: its proof carries the text in full", is_map(constructions))

        _other ->
          "agent-test #{run.id}: it is given a text beside it, though it is not in reference mode"
      end

    [form, mode]
  end

  # The mutants by kind, known answers: a kind dropped, or runs left out, changes a count.
  @kinds %{
    "chain_order" => 10,
    "claims" => 3,
    "empty_root" => 13,
    "genesis_height" => 1,
    "genesis_read" => 1,
    "graft" => 3,
    "handover" => 9,
    "handover_height" => 9,
    "handover_missing" => 9,
    "handover_previous" => 9,
    "hash" => 195,
    "header_at_height" => 12,
    "header_time" => 18,
    "key_checks" => 1,
    "key_id" => 10,
    "leaf_count" => 13,
    "nbits" => 12,
    "no_input" => 12,
    "op_return" => 12,
    "partial_tree" => 12,
    "path.range" => 45,
    "path.sibling" => 45,
    "path.side" => 45,
    "payload" => 30,
    "previous_key_id" => 9,
    "self_signed" => 9,
    "signature" => 9,
    "signature_cofactor" => 9,
    "signature_s" => 9,
    "signing_key_id" => 13,
    "ske_key" => 9,
    "staging" => 9,
    "stellar_failed" => 12,
    "stellar_ledger" => 12,
    "stellar_memo" => 12,
    "stellar_memo_type" => 12,
    "transaction_count" => 12,
    "tree_size" => 45,
    "two_op_returns" => 12,
    "uppercase" => 9,
    "witness_data" => 12,
    "witness_height" => 3,
    "witness_names" => 3
  }

  @doc "A mutant's kind: its flaw up to the first `.`, and a `path.` mutant's last part too."
  def kind("path." <> _rest = flaw), do: "path." <> (flaw |> String.split(".") |> List.last())
  def kind(flaw), do: flaw |> String.split(".") |> hd()

  defp inventory(runs) do
    got = runs |> Enum.reject(&is_nil(&1.flaw)) |> Enum.frequencies_by(&kind(&1.flaw))
    expect("agent-test: the mutants of each kind", got, @kinds)
  end

  @doc """
  The lines of SPEC.md 7.4 but the window lines for the proof file `bytes` and the keyring
  file `keyring`, as the generator derives them itself: its DERIVE engine's trace, `proof_hash`,
  Verify of the proof's signature, the keyring lookup and the marker.
  """
  def own_lines(bytes, keyring) do
    {:ok, envelope} = Parse.read(bytes)
    proof = envelope["proof"]
    k = Bytes.unb64u(envelope["signature"]["public_key"])
    trace = Derive.trace(proof, Derive.rows(proof, k, "none"))

    {handovers, values} =
      Enum.split_with(trace, &String.ends_with?(&1["part"], "/handover_signature"))

    proof_hash = Registry.record_hash("proof_hash", proof)
    {:ok, %{"keys" => keys}} = Parse.read(keyring)

    Enum.map(values, &"/proof#{&1["part"]} #{spelled(&1["recomputed"])}") ++
      headers(proof, values) ++
      [
        "digest " <> Bytes.hex(proof_hash),
        "/signature/value " <>
          validity(Derive.verify?(k, proof_hash, envelope["signature"]["value"]))
      ] ++
      Enum.map(handovers, &"/proof#{&1["part"]} #{validity(&1["status"] == "pass")}") ++
      [
        "keyring " <>
          if(Enum.any?(keys, &(Bytes.unb64u(&1["public_key"]) == k)),
            do: "match",
            else: "no-match"
          ),
        "environment " <> Map.get(proof, "environment", "prod")
      ]
  end

  # The header lines of each Bitcoin entry whose trace holds none, because its txoutproof is
  # not well formed: those of its first 80 octets, when it has them.
  defp headers(proof, values) do
    traced = MapSet.new(values, & &1["part"])

    for n <- ~w(/commitments/bitcoin /signing_key_event/commitments/bitcoin),
        hex = Pointer.get(proof, n <> "/txoutproof"),
        is_binary(hex) and not MapSet.member?(traced, n <> "/header_hash"),
        {:ok, <<header::binary-80, _rest::binary>>} <- [Base.decode16(hex, case: :lower)],
        <<_::binary-36, root::binary-32, time::little-32, _::binary-8>> = header,
        {member, value} <- [
          {"header_hash", Bitcoin.display(Bitcoin.sha256d(header))},
          {"header_merkle_root", Bitcoin.display(root)},
          {"header_time", time |> DateTime.from_unix!() |> DateTime.to_iso8601()}
        ],
        do: "/proof#{n}/#{member} #{value}"
  end

  defp spelled(nil), do: "none"
  defp spelled(value) when is_binary(value), do: value
  defp spelled(value) when is_integer(value), do: Integer.to_string(value)

  defp validity(true), do: "valid"
  defp validity(false), do: "invalid"
end
