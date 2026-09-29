# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

# The harness of the agent-sufficiency test (SPEC.md 7.4).
#
#     elixir agent-test/check.exs VERIFY_PY --only FIXTURE [--python PYTHON]
#     elixir agent-test/check.exs VERIFY_PY [--python PYTHON]
#     elixir agent-test/check.exs --self-test
#
# The first form judges a session: it runs the session's verify.py, unchanged, on every run of
# its fixture in agent-test/runs.txt, each as `PYTHON VERIFY_PY <proof> <keyring> <replay>
# [<constructions>]` with the run's files, and compares its standard output with
# agent-test/expected/<run>.txt as sets of lines. The second runs it on every run of every
# fixture. A run passes only when it exits 0 within its time and prints exactly those lines,
# none missing and none extra. Two window lines (`submitted_after` and `submitted_before`), or
# two `header_time` lines at one pointer, that name the same instant are the same line,
# whatever RFC 3339 spelling each uses (SPEC.md 11.3). It prints each failing run with the
# lines missing and the lines extra, and the last lines of its standard error, then a count,
# and exits 0 only when every run passes. Standard input is closed, and the runs go in
# parallel.
#
# PYTHON is `python3` on PATH unless given. Before any run, it must import the packages the
# prompt promises a session, cryptography and rfc8785, or the harness stops, naming them, so a
# missing package is never read as a failure of the text.
#
# --self-test holds the harness to its own known-good script, agent-test/selftest/verify.py,
# which is not an answer key (no session receives it) and uses only the standard library:
# that script must pass every run; a copy of it with its BREAK line set to each flaw below
# that skips a rule must fail exactly the runs of every fixture that the flaw shows in, each
# only in its window lines, but for the lines whose value that rule decides, and one set to a
# flaw that prints a line wrong exactly those of its fixture; a script that never ends must
# fail by its timeout; the comparison must treat two spellings of one instant as one line and
# anything else, a millisecond included, as a difference; runs.txt must name exactly
# the runs expected/ holds, and every file under fixtures/ and mutants/; and the command line
# itself, run as its own process, must exit 0 for the known-good script, 1 for a flawed one,
# and 1, naming the packages, under a Python that lacks them. It exits 0 only when every one
# of those holds.
#
# The files it reads are plain text, never JSON: runs.txt, whose lines are `<fixture>/<run>
# <proof> <keyring> <replay> [<constructions>]` with each path relative to agent-test/ and
# lines beginning with # left out, and the expected files, one line each.

defmodule AgentTest.Check do
  @moduledoc false

  @dir __DIR__
  @timeout 60_000
  @packages ~w(cryptography rfc8785)

  # Each flaw the self-test sets in a copy of the known-good script, the runs it runs on, and
  # which of them it must fail: the base proofs (:base), every run (:all), none (:none), or
  # the mutants of the kinds it names (a mutant's kind is its flaw up to the first `.`, and a
  # `path.` mutant's last part too), but those it names as failing another check the flaw
  # leaves in place, or the mutants it names.
  #
  # A flaw that skips one rule runs on every run of every fixture (:every), and is isolated:
  # each run it fails must differ from the expected lines only in the window lines, and in the
  # lines it names, whose value the skipped rule decides, and must draw a submitted-before
  # edge. So every mutant of its kinds, in every fixture, breaks that one rule and nothing else:
  # a verifier that skips it passes the proof. A flaw that prints a line wrong runs on one
  # fixture. `nogate` computes every value and fails no mismatch, so a hash mutant still fails
  # where its value also reaches a chain read or a handover; `carried_start` walks from each
  # carried block hash, as a verifier with the graft defect does (SPEC.md 10.3), so it takes
  # the graft for sound, and it prints the walks from the carried value for every mutant whose
  # carried block hash is not the computed one.
  defp flaws do
    [
      {"echo", "1-item",
       {:kinds, ~w(claims genesis_height graft handover_height handover_previous hash header_time
           key_id path.range path.sibling path.side previous_key_id signing_key_id tree_size
           uppercase)}, nil},
      {"nogate", "1-item",
       {:kinds_except,
        ~w(claims graft handover_height handover_previous hash header_time key_id path.range
           path.sibling path.side previous_key_id signing_key_id tree_size uppercase),
        ~w(hash.commitments.bitcoin.epoch.record.merkle_root
           hash.commitments.stellar.epoch.record.merkle_root
           hash.signing_key_event.block.record.metadata.key_event.previous_block_hash
           hash.signing_key_event.commitments.bitcoin.epoch.record.merkle_root
           hash.signing_key_event.commitments.stellar.epoch.record.merkle_root)}, nil},
      {"carried_start", "1-item",
       {:flaws, ~w(graft uppercase hash.block.block_hash hash.block.record.merkle_root
           hash.signing_key_event.block.block_hash
           hash.signing_key_event.block.record.metadata.key_event.previous_block_hash
           hash.witnesses.block.block_hash)}, nil},
      {"signature", :every, {:kinds, ~w(signature signature_cofactor signature_s)}, []},
      {"memo", :every, {:kinds, ~w(stellar_memo)}, []},
      {"stellar_tx", :every, {:kinds, ~w(stellar_failed stellar_ledger stellar_memo_type)}, []},
      {"environment", :every, {:kinds, ~w(staging)}, []},
      {"keyring", :every, {:kinds, ~w(self_signed)}, []},
      {"link_key", :every, {:kinds, ~w(ske_key)}, []},
      {"handover", :every, {:kinds, ~w(handover)}, []},
      {"handover_required", :every, {:kinds, ~w(handover_missing)}, []},
      {"handover_fields", :every, {:kinds, ~w(handover_height handover_previous)}, []},
      {"key_ids", :every, {:kinds, ~w(key_id previous_key_id signing_key_id)}, []},
      {"key_checks", :every, {:kinds, ~w(key_checks)}, []},
      {"strict_s", :every, {:kinds, ~w(signature_s)}, ["/signature/value "]},
      {"cofactored", :every, {:kinds, ~w(signature_cofactor)}, ["/signature/value "]},
      {"tree_size", :every, {:kinds, ~w(tree_size)}, []},
      {"range", :every, {:kinds, ~w(path.range)}, ["/merkle_root "]},
      {"side", :every, {:kinds, ~w(path.side)}, ["/merkle_root "]},
      {"empty_root", :every, {:kinds, ~w(empty_root leaf_count)}, []},
      {"witness_height", :every, {:kinds, ~w(witness_height)}, []},
      {"witness_names", :every, {:kinds, ~w(witness_names)}, []},
      {"chain_order", :every, {:kinds, ~w(chain_order)}, []},
      {"payload", :every, {:kinds, ~w(payload)}, []},
      {"op_return", :every, {:kinds, ~w(op_return)}, []},
      {"two_op_returns", :every, {:kinds, ~w(two_op_returns)}, []},
      {"no_input", :every, {:kinds, ~w(no_input)}, []},
      {"witness_data", :every, {:kinds, ~w(witness_data)}, []},
      {"nbits", :every, {:kinds, ~w(nbits)}, []},
      {"partial_tree", :every, {:kinds, ~w(partial_tree)}, []},
      {"header_at_height", :every, {:kinds, ~w(header_at_height)}, []},
      {"transaction_count", :every, {:kinds, ~w(transaction_count)}, []},
      {"header_time", :every, {:kinds, ~w(header_time)}, []},
      {"genesis_height", :every, {:kinds, ~w(genesis_height)}, []},
      {"genesis_read", :every, {:kinds, ~w(genesis_read)}, []},
      {"ske_chain", :every, {:ske_chain}, []},
      {"uppercase", :every, {:kinds, ~w(uppercase)}, []},
      {"window_second", "1-item", :base, nil},
      {"instant_format", "1-item", :none, nil},
      {"extra", "1-item", :all, nil},
      {"exit", "1-item", :all, nil}
    ]
  end

  # The mutants a script that skips the chain reads of /signing_key_event/commitments passes
  # and must fail: those that break only such a read.
  @ske_reads ~w(header_at_height transaction_count stellar_memo stellar_failed
                stellar_memo_type stellar_ledger)

  defp fails?(:base, flaw), do: flaw == nil
  defp fails?(:all, _flaw), do: true
  defp fails?(:none, _flaw), do: false
  defp fails?({:kinds, kinds}, flaw), do: flaw != nil and kind(flaw) in kinds

  defp fails?({:flaws, flaws}, flaw), do: flaw in flaws

  defp fails?({:kinds_except, kinds, others}, flaw),
    do: fails?({:kinds, kinds}, flaw) and flaw not in others

  defp fails?({:ske_chain}, flaw),
    do: flaw != nil and kind(flaw) in @ske_reads and String.contains?(flaw, ".signing_key_event.")

  @doc false
  def kind("path." <> _rest = flaw), do: "path." <> (flaw |> String.split(".") |> List.last())
  def kind(flaw), do: flaw |> String.split(".") |> hd()

  # ---------------------------------------------------------------------------------------
  # The command line

  def main(["--self-test"]), do: self_test()

  def main([script | options]) do
    case options(options, %{only: nil, python: nil}) do
      {:ok, %{only: only, python: python}} ->
        python = interpreter(python || "python3")
        runs = if only, do: Enum.filter(runs(), &(&1.fixture == only)), else: runs()
        if runs == [], do: halt("agent-test: no run of a fixture #{only}")
        preflight(python)
        check(script, runs, python)

      :error ->
        usage()
    end
  end

  def main(_argv), do: usage()

  # A Python by its path, or by its name on PATH.
  defp interpreter(python) do
    found =
      if String.contains?(python, "/"),
        do: if(File.regular?(python), do: Path.expand(python)),
        else: System.find_executable(python)

    found || halt("agent-test: #{python} is not a program this harness can run")
  end

  defp options([], acc), do: {:ok, acc}

  defp options(["--only", fixture | rest], %{only: nil} = acc),
    do: options(rest, %{acc | only: fixture})

  defp options(["--python", python | rest], %{python: nil} = acc),
    do: options(rest, %{acc | python: python})

  defp options(_other, _acc), do: :error

  defp usage do
    halt(
      "Usage: elixir agent-test/check.exs VERIFY_PY --only FIXTURE [--python PYTHON]\n" <>
        "       elixir agent-test/check.exs VERIFY_PY [--python PYTHON]\n" <>
        "       elixir agent-test/check.exs --self-test"
    )
  end

  defp halt(message) do
    IO.puts(:stderr, message)
    System.halt(1)
  end

  # The packages the prompt promises a session: the harness stops unless `python` imports
  # them, so a run is never failed for a package the machine lacks.
  defp preflight(python) do
    case System.cmd(python, ["-c", "import " <> Enum.join(@packages, ", ")],
           stderr_to_stdout: true
         ) do
      {_output, 0} ->
        :ok

      {_output, _code} ->
        halt(
          "agent-test: #{python} cannot import #{Enum.join(@packages, " and ")}, which the " <>
            "prompt promises a session (SPEC.md 7.4): install them, or give --python a Python " <>
            "that has them, the Python the sessions had."
        )
    end
  end

  # ---------------------------------------------------------------------------------------
  # The runs and their expected lines

  @doc false
  def runs do
    @dir
    |> Path.join("runs.txt")
    |> File.read!()
    |> String.split("\n", trim: true)
    |> Enum.reject(&String.starts_with?(&1, "#"))
    |> Enum.map(fn line ->
      [id, proof, keyring, replay | constructions] = String.split(line, " ")
      [fixture, name] = String.split(id, "/", parts: 2)

      %{
        id: id,
        fixture: fixture,
        flaw: flaw(name),
        paths: [proof, keyring, replay | constructions],
        files: Enum.map([proof, keyring, replay | constructions], &Path.join(@dir, &1))
      }
    end)
  end

  # A run's flaw: what follows its proof's name, or nil for a base proof.
  defp flaw(name) do
    case String.split(name, ".", parts: 2) do
      [_name] -> nil
      [_name, flaw] -> flaw
    end
  end

  defp expected(run),
    do: @dir |> Path.join("expected/#{run.id}.txt") |> File.read!() |> lines()

  # ---------------------------------------------------------------------------------------
  # Running a script

  defp check(script, runs, python) do
    script = Path.expand(script)
    unless File.regular?(script), do: halt("agent-test: #{script} is not a file")
    results = run_all(script, runs, python)

    for {run, {:fail, why}} <- results do
      IO.puts("FAIL #{run.id}")
      Enum.each(why, &IO.puts("  " <> &1))
    end

    passed = Enum.count(results, &match?({_run, :pass}, &1))
    IO.puts("#{passed} of #{length(results)} runs pass.")
    if passed != length(results), do: System.halt(1)
  end

  @doc false
  def run_all(script, runs, python, timeout \\ @timeout) do
    runs
    |> Task.async_stream(&{&1, judge(python, script, &1, timeout)},
      max_concurrency: System.schedulers_online(),
      timeout: :infinity
    )
    |> Enum.map(fn {:ok, result} -> result end)
  end

  defp judge(python, script, run, timeout) do
    case execute(python, [script | run.files], timeout) do
      {:ok, 0, stdout, _stderr} -> compare(lines(stdout), expected(run))
      {:ok, code, _stdout, stderr} -> {:fail, ["exit #{code}" | last_lines(stderr)]}
      {:timeout, stderr} -> {:fail, ["no exit within #{timeout} ms" | last_lines(stderr)]}
    end
  end

  defp last_lines(stderr) do
    stderr |> String.split("\n", trim: true) |> Enum.take(-5) |> Enum.map(&("stderr: " <> &1))
  end

  # A path under the system's temporary directory that no other run of the harness, in this
  # process or another, can hold: the OS process id and random bytes.
  defp temporary(prefix) do
    random = Base.encode16(:crypto.strong_rand_bytes(8), case: :lower)
    Path.join(System.tmp_dir!(), "#{prefix}-#{System.pid()}-#{random}")
  end

  # Runs `program` with `args`, standard input closed and standard error to a file of its
  # own: `{:ok, status, stdout, stderr}`, or `{:timeout, stderr}` after `timeout`, when the
  # process is killed.
  defp execute(program, args, timeout) do
    stderr = temporary("agent-test-stderr")
    sh = System.find_executable("sh")

    port =
      Port.open({:spawn_executable, sh}, [
        :binary,
        :exit_status,
        args: ["-c", ~s(exec "$0" "$@" </dev/null 2>"$AGENT_TEST_STDERR"), program | args],
        env: [{~c"AGENT_TEST_STDERR", String.to_charlist(stderr)}]
      ])

    result = collect(port, [], System.monotonic_time(:millisecond) + timeout)
    written = read(stderr)
    File.rm(stderr)

    case result do
      {:ok, status, stdout} -> {:ok, status, stdout, written}
      :timeout -> {:timeout, written}
    end
  end

  defp read(path) do
    case File.read(path) do
      {:ok, text} -> text
      {:error, _reason} -> ""
    end
  end

  defp collect(port, acc, deadline) do
    left = max(deadline - System.monotonic_time(:millisecond), 0)

    receive do
      {^port, {:data, data}} -> collect(port, [acc, data], deadline)
      {^port, {:exit_status, status}} -> {:ok, status, IO.iodata_to_binary(acc)}
    after
      left ->
        case Port.info(port, :os_pid) do
          {:os_pid, pid} -> System.cmd("kill", ["-9", Integer.to_string(pid)])
          nil -> :ok
        end

        Port.close(port)
        :timeout
    end
  end

  # ---------------------------------------------------------------------------------------
  # Comparing

  # The lines of `text`, each by its normal form (normal/1), as it was written.
  @doc false
  def lines(text) do
    text |> String.split("\n") |> Enum.reject(&(&1 == "")) |> Map.new(&{normal(&1), &1})
  end

  # A window line or a `header_time` line naming an instant, spelled as an instant in
  # milliseconds; every other line as it is.
  @doc false
  def normal(line) do
    with [key, value] <- String.split(line, " ", parts: 2),
         true <- key in ["submitted_after", "submitted_before"] or timed?(key),
         {:ok, time, _offset} <- DateTime.from_iso8601(value) do
      "#{key} @#{DateTime.to_unix(time, :millisecond)}"
    else
      _other -> line
    end
  end

  defp timed?(key), do: String.starts_with?(key, "/") and String.ends_with?(key, "/header_time")

  @doc false
  def compare(actual, expected) do
    missing = for {line, written} <- expected, not Map.has_key?(actual, line), do: written
    extra = for {line, written} <- actual, not Map.has_key?(expected, line), do: written

    if missing == [] and extra == [],
      do: :pass,
      else:
        {:fail,
         Enum.map(Enum.sort(missing), &("missing: " <> &1)) ++
           Enum.map(Enum.sort(extra), &("extra: " <> &1))}
  end

  # ---------------------------------------------------------------------------------------
  # The self-test

  defp self_test do
    known_good = Path.join(@dir, "selftest/verify.py")
    python = System.find_executable("python3") || halt("agent-test: python3 is not on PATH")
    runs = runs()
    tmp = temporary("agent-test-self")
    File.mkdir_p!(tmp)

    failures =
      try do
        List.flatten([
          inventory(runs),
          good(known_good, runs, python),
          Enum.map(flaws(), &flawed(&1, known_good, runs, python, tmp)),
          hang(tmp, hd(runs), python),
          comparison(),
          command_line(known_good, python, tmp)
        ])
      after
        File.rm_rf!(tmp)
      end

    Enum.each(failures, &IO.puts(:stderr, "agent-test self-test: " <> &1))

    if failures == [] do
      IO.puts(
        "agent-test: the harness passes its known-good script on all #{length(runs)} runs, " <>
          "fails each of its #{length(flaws())} flawed copies on exactly the runs its flaw " <>
          "shows in, the #{Enum.count(flaws(), &(elem(&1, 1) == :every))} that skip a rule " <>
          "on every fixture and through the window alone, stops a script that never ends, " <>
          "compares as it should, holds every run and file, and exits as it should."
      )
    else
      IO.puts(:stderr, "agent-test: the harness's self-test fails: fix agent-test/check.exs.")
      System.halt(1)
    end
  end

  # runs.txt names exactly the runs expected/ holds, each once, and every file under
  # fixtures/ and mutants/, and every file it names exists.
  defp inventory(runs) do
    ids = Enum.map(runs, & &1.id)
    named = runs |> Enum.flat_map(& &1.paths) |> MapSet.new()

    held =
      for path <- Path.wildcard(Path.join(@dir, "expected/**/*.txt")),
          into: MapSet.new(),
          do:
            path
            |> Path.relative_to(Path.join(@dir, "expected"))
            |> String.replace_suffix(".txt", "")

    files =
      for dir <- ~w(fixtures mutants),
          path <- Path.wildcard(Path.join([@dir, dir, "**", "*"])),
          File.regular?(path),
          do: Path.relative_to(path, @dir)

    [
      if(length(Enum.uniq(ids)) != length(ids), do: "runs.txt names a run twice", else: []),
      for(
        id <- Enum.sort(MapSet.difference(held, MapSet.new(ids))),
        do: "runs.txt leaves out the run #{id}, which expected/ holds"
      ),
      for(
        id <- Enum.sort(MapSet.difference(MapSet.new(ids), held)),
        do: "expected/ holds no lines for the run #{id}"
      ),
      for(
        file <- Enum.sort(files),
        not MapSet.member?(named, file),
        do: "no run is given #{file}"
      ),
      for(
        path <- Enum.sort(named),
        not File.regular?(Path.join(@dir, path)),
        do: "runs.txt names #{path}, which is not a file"
      )
    ]
  end

  defp good(script, runs, python) do
    for {run, {:fail, why}} <- run_all(script, runs, python) do
      "the known-good script fails #{run.id}: #{Enum.join(Enum.take(why, 4), "; ")}"
    end
  end

  # A copy of the known-good script with the flaw set must fail exactly the runs, of its
  # fixture or of every fixture, that the flaw's prediction names, and an isolated flaw must
  # fail each of them only as isolated/2 allows.
  defp flawed({flaw, scope, prediction, isolation}, known_good, runs, python, tmp) do
    runs = in_scope(runs, scope)

    case break(known_good, flaw, tmp) do
      {:ok, path} ->
        results = run_all(path, runs, python)
        failed = for {run, {:fail, _why}} <- results, into: MapSet.new(), do: run.id
        predicted = for run <- runs, fails?(prediction, run.flaw), into: MapSet.new(), do: run.id

        [
          shows_nothing(flaw, scope, prediction, predicted),
          for(
            id <- Enum.sort(MapSet.difference(predicted, failed)),
            do: "the flaw #{flaw} passes #{id}, which it must fail"
          ),
          for(
            id <- Enum.sort(MapSet.difference(failed, predicted)),
            do: "the flaw #{flaw} fails #{id}, which it must pass"
          ),
          through_window(flaw, isolation, results, predicted)
        ]

      :error ->
        "the known-good script does not hold exactly one line BREAK = \"\""
    end
  end

  defp in_scope(runs, :every), do: runs
  defp in_scope(runs, fixture), do: Enum.filter(runs, &(&1.fixture == fixture))

  defp shows_nothing(flaw, scope, prediction, predicted) do
    where = if scope == :every, do: "any fixture", else: scope

    if MapSet.size(predicted) == 0 and prediction != :none,
      do: "the flaw #{flaw} predicts no failing run of #{where}, so it shows nothing",
      else: []
  end

  # For an isolated flaw, each predicted run it fails other than isolated/2 allows.
  defp through_window(_flaw, nil, _results, _predicted), do: []

  defp through_window(flaw, named, results, predicted) do
    for {run, {:fail, why}} <- results,
        MapSet.member?(predicted, run.id),
        problem = isolated(why, named),
        problem != nil,
        do: "the flaw #{flaw} fails #{run.id} #{problem}, not through its window alone"
  end

  # nil when a run's failure, the lines `why` names, shows the skipped rule alone: it differs
  # from the expected lines only in the window lines and the lines holding one of `named`, and
  # draws a submitted-before edge, so the flawed copy passed the proof; else what else it shows.
  @doc false
  def isolated(why, named) do
    other = Enum.reject(why, &allowed?(diff_line(&1), named))
    drawn = Enum.any?(why, &drawn?/1)

    cond do
      other != [] -> "with #{Enum.join(Enum.take(other, 2), "; ")}"
      not drawn -> "with no submitted-before edge drawn"
      true -> nil
    end
  end

  defp allowed?(nil, _named), do: false

  defp allowed?(line, named),
    do:
      String.starts_with?(line, ["submitted_after ", "submitted_before "]) or
        Enum.any?(named, &String.contains?(line, &1))

  defp drawn?("extra: submitted_before " <> instant), do: instant != "none"
  defp drawn?(_entry), do: false

  defp diff_line("missing: " <> line), do: line
  defp diff_line("extra: " <> line), do: line
  defp diff_line(_other), do: nil

  # The known-good script with its BREAK line set to `flaw`, written under `tmp`.
  defp break(known_good, flaw, tmp) do
    text = File.read!(known_good)

    case :binary.matches(text, ~s(\nBREAK = ""\n)) do
      [_one] ->
        path = Path.join(tmp, "verify-#{flaw}.py")
        File.write!(path, String.replace(text, ~s(\nBREAK = ""\n), ~s(\nBREAK = "#{flaw}"\n)))
        {:ok, path}

      _other ->
        :error
    end
  end

  # A script that never ends fails by its timeout.
  defp hang(tmp, run, python) do
    path = Path.join(tmp, "hang.py")
    File.write!(path, "import time\ntime.sleep(600)\n")

    case run_all(path, [run], python, 1_000) do
      [{_run, {:fail, ["no exit within 1000 ms" | _stderr]}}] -> []
      other -> "a script that never ends gives #{inspect(other)}, not a timeout"
    end
  end

  # Two spellings of one instant are one line, in a window line or a header_time line; a
  # different instant, a millisecond apart included, none, another pointer, or any other
  # difference is not.
  defp comparison do
    same = lines("a b\nsubmitted_before 2026-09-26T01:48:00Z\n")

    cases = [
      {"the same instant with milliseconds", "a b\nsubmitted_before 2026-09-26T01:48:00.000Z\n",
       :pass},
      {"the same instant with an offset", "a b\nsubmitted_before 2026-09-26T01:48:00+00:00\n",
       :pass},
      {"the lines in another order, repeated",
       "submitted_before 2026-09-26T01:48:00Z\na b\na b\n", :pass},
      {"another instant", "a b\nsubmitted_before 2026-09-26T01:48:01Z\n", :fail},
      {"an instant a millisecond later", "a b\nsubmitted_before 2026-09-26T01:48:00.001Z\n",
       :fail},
      {"none for an instant", "a b\nsubmitted_before none\n", :fail},
      {"a line missing", "a b\n", :fail},
      {"a line extra", "a b\nc d\nsubmitted_before 2026-09-26T01:48:00Z\n", :fail},
      {"a line with a space more", "a b \nsubmitted_before 2026-09-26T01:48:00Z\n", :fail}
    ]

    time = "/proof/commitments/bitcoin/header_time"
    same_time = lines("#{time} 2026-09-26T01:52:00Z\n")

    times = [
      {"a header_time with an offset", "#{time} 2026-09-26T01:52:00+00:00\n", :pass},
      {"a header_time with milliseconds", "#{time} 2026-09-26T01:52:00.000Z\n", :pass},
      {"a header_time a second later", "#{time} 2026-09-26T01:52:01Z\n", :fail},
      {"the header_time at another pointer",
       "/proof/signing_key_event/commitments/bitcoin/header_time 2026-09-26T01:52:00Z\n", :fail}
    ]

    for {name, text, want, expected} <-
          Enum.map(cases, fn {n, text, want} -> {n, text, want, same} end) ++
            Enum.map(times, fn {n, text, want} -> {n, text, want, same_time} end),
        got = if(compare(lines(text), expected) == :pass, do: :pass, else: :fail),
        got != want,
        do: "the comparison gives #{got} for #{name}, not #{want}"
  end

  # The session form, run as its own process on fixture 1-item: exit 0 for the known-good
  # script and 1 for a copy that exits 1, under a Python that has the packages (a wrapper
  # that answers the package check and runs every script with python3); and exit 1, naming
  # the packages, under one that lacks them.
  defp command_line(known_good, python, tmp) do
    elixir = System.find_executable("elixir") || halt("agent-test: elixir is not on PATH")
    {:ok, exits} = break(known_good, "exit", tmp)
    has = wrapper(tmp, "has-packages", 0, python)
    lacks = wrapper(tmp, "lacks-packages", 1, python)

    session = fn script, interpreter ->
      System.cmd(
        elixir,
        [Path.join(@dir, "check.exs"), script, "--only", "1-item", "--python", interpreter],
        stderr_to_stdout: true
      )
    end

    [
      case session.(known_good, has) do
        {_output, 0} -> []
        {output, code} -> "the known-good script's session exits #{code}: #{last(output)}"
      end,
      case session.(exits, has) do
        {_output, 1} -> []
        {output, code} -> "a failing session exits #{code}, not 1: #{last(output)}"
      end,
      case session.(known_good, lacks) do
        {output, 1} ->
          if String.contains?(output, "cannot import cryptography and rfc8785"),
            do: [],
            else: "a Python without the packages stops the harness without naming them"

        {output, code} ->
          "a Python without the packages gives exit #{code}, not 1: #{last(output)}"
      end
    ]
  end

  # A Python for the package check: `-c` exits with `code`, and anything else runs python3.
  defp wrapper(tmp, name, code, python) do
    path = Path.join(tmp, name)

    File.write!(path, """
    #!/bin/sh
    if [ "$1" = "-c" ]; then exit #{code}; fi
    exec "#{python}" "$@"
    """)

    File.chmod!(path, 0o755)
    path
  end

  defp last(output),
    do: output |> String.split("\n", trim: true) |> Enum.take(-3) |> Enum.join(" | ")
end

AgentTest.Check.main(System.argv())
