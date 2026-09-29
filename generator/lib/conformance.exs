# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Generator.Conformance do
  @moduledoc """
  The check of --check that runs the reference verifier over cases.json (SPEC.md 13.1 and
  13.2). The generator shares no code with the verifier, so it runs it as its own process:
  `mix truestamp.conformance <root>/vectors/cases.json` in elixir/, under MIX_ENV=test,
  which runs each offline case with its full configuration, network pins included, and
  prints, as one JSON document, an array with an entry `{id, output}` per offline case in
  the file's order. The verifier's standard error passes through to this run's.

  The check reads that document with the generator's own reader (Generator.Parse), and
  holds it to cases.json and the trace files as they stand under vectors/, read the same
  way. Each offline case, and no other, has one entry, in the file's order, whose `output`
  is exactly what SPEC.md 13.1 compares:

  - for a bare rejection, `code`, and `sub_reason` when the case has one;
  - otherwise `label` and `rows`, every row `[code, part, status, step]`, in order, and for a
    case whose `expected` names a trace, `trace`: the rows of that trace file, in order, each
    with every member but `inputs`.

  A case that differs gives one failure, naming its id and the first thing that differs, in
  the order code, sub_reason, rows, label, trace: a member, or the first row or trace row
  that differs, by its number counted from 1, with both values. The rows come before the
  label, since a label that differs follows from a row that does.

  The check proves that it can fail: once the verifier's output matches, it compares that
  output with hand-mutated copies of cases.json's expected output (a row's status, code,
  part and step, each changed alone; a row too many; a trace row's recomputed value, part
  and status, each changed alone; a label; a bare case's code changed and its code lost; a
  sub_reason), and with the output mutated (a case left out, two cases exchanged, a member
  added to a report that names no trace, a member dropped: a report's label, a traced
  case's trace and a bare case's sub_reason; an entry for an id that is no offline case,
  and an entry given twice), and each must give exactly one failure, naming the case and
  what its name says: for a row, its number, and for a member, the member.

  The mix child runs with its standard input closed, so a Mix that would ask a question
  (to install Hex, say) fails at once instead of waiting for an answer.

  Each failure has a kind, which run/1 gives with them: `:vectors`, when cases.json or a
  trace file under vectors/ cannot be read as the check needs; `:no_output`, when the
  verifier gave no output the check can use (mix missing or failing, or a document of the
  wrong form); `:mismatch`, when its output differs from cases.json's; and `:self_test`,
  when the check fails to refuse one of its own mutants. closing/1 gives the line that fits
  each kind.
  """

  alias Generator.{JCS, Parse}

  @task "truestamp.conformance"

  @doc """
  The check over the vectors under `root`: `{:ok, summary}`, a line that counts what it
  compared, or `{kind, failures}`, each failure a line, of one of the kinds above.
  """
  def run(root) do
    # The self-test runs only once the real comparison passes, since its mutants are made
    # from output that matches.
    with {:ok, expected} <- tagged(:vectors, expected(root)),
         {:ok, actual} <- tagged(:no_output, verifier(root)),
         {:mismatch, []} <- {:mismatch, compare(actual, expected)},
         {:self_test, []} <- {:self_test, self_test(actual, expected)} do
      {:ok, summary(expected)}
    end
  end

  defp tagged(_kind, {:ok, value}), do: {:ok, value}
  defp tagged(kind, {:error, failure}), do: {kind, [failure]}

  @doc "The line that closes a run whose failures are of `kind`."
  def closing(:vectors),
    do:
      "The conformance check could not read the expected output under vectors/, so it " <>
        "compared nothing: the lines above name the file."

  def closing(:no_output),
    do:
      "The reference verifier gave no output the conformance check can use, so it compared " <>
        "nothing: run `task setup`, then check that `mix truestamp.conformance` runs in elixir/."

  def closing(:mismatch),
    do:
      "The reference verifier does not give the output cases.json expects: fix the " <>
        "verifier or the generator, whichever is wrong."

  def closing(:self_test),
    do:
      "The verifier gives the output cases.json expects, but the conformance check does not " <>
        "refuse its own mutants, so it cannot be trusted to fail: fix generator/lib/conformance.exs."

  # ---------------------------------------------------------------------------------------
  # What cases.json expects

  @doc """
  `{:ok, entries}`, each offline case of `vectors/cases.json` under `root` as
  `{id, output}` with the output SPEC.md 13.1 compares, in the file's order, or
  `{:error, failure}`.
  """
  def expected(root) do
    case read(root, "cases.json") do
      {:ok, cases} when is_list(cases) -> offline(root, cases)
      {:ok, _value} -> {:error, "vectors/cases.json is not an array of cases"}
      error -> error
    end
  end

  defp offline(root, cases) do
    cases
    |> Enum.reject(&Map.has_key?(&1["config"], "online"))
    |> Enum.reduce_while({:ok, []}, fn kase, {:ok, entries} ->
      case output(root, kase["expected"]) do
        {:ok, output} -> {:cont, {:ok, [{kase["id"], output} | entries]}}
        {:error, failure} -> {:halt, {:error, "case #{kase["id"]}: #{failure}"}}
      end
    end)
    |> case do
      {:ok, entries} -> {:ok, Enum.reverse(entries)}
      error -> error
    end
  end

  defp output(_root, %{"code" => _code} = expected),
    do: {:ok, Map.take(expected, ~w(code sub_reason))}

  defp output(root, %{"label" => label, "rows" => rows} = expected) do
    output = %{"label" => label, "rows" => rows}

    case expected do
      %{"trace" => path} ->
        with {:ok, trace} <- read(root, path),
             do: {:ok, Map.put(output, "trace", Enum.map(trace, &Map.delete(&1, "inputs")))}

      _no_trace ->
        {:ok, output}
    end
  end

  defp output(_root, _expected),
    do: {:error, "its expected output is of no form SPEC.md 13.2 gives"}

  defp read(root, path) do
    with {:ok, bytes} <- File.read(Path.join([root, "vectors", path])),
         {:ok, value} <- Parse.decode(bytes) do
      {:ok, value}
    else
      {:error, reason} -> {:error, "vectors/#{path} cannot be read: #{inspect(reason)}"}
    end
  end

  # ---------------------------------------------------------------------------------------
  # What the reference verifier gives

  # The verifier's document, read with the generator's reader, as entries {id, output}.
  defp verifier(root) do
    dir = Path.join(root, "elixir")
    cases = Path.join([root, "vectors", "cases.json"])

    with {:ok, mix} <- mix(),
         {:ok, stdout} <- command(mix, dir, cases),
         {:ok, document} <- document(stdout) do
      entries(document)
    end
  end

  defp mix do
    case System.find_executable("mix") do
      nil -> {:error, "mix is not on PATH, so the reference verifier cannot run"}
      mix -> {:ok, mix}
    end
  end

  # System.cmd leaves the child's standard input open, and Mix asks on it, for one, whether
  # to install Hex, so an answer never comes and the run waits for ever. Through sh, with
  # standard input from /dev/null, such a question reads end of file and mix exits.
  defp command(mix, dir, cases) do
    argv = ["-c", ~s(exec "$0" "$@" </dev/null), mix, @task, cases]

    case System.cmd("sh", argv, cd: dir, env: [{"MIX_ENV", "test"}]) do
      {stdout, 0} ->
        {:ok, stdout}

      {_stdout, code} ->
        {:error,
         "`mix #{@task}` in elixir/ exited #{code}, so the reference verifier gave no output; " <>
           "its standard error, above, says why (run `task setup` if its dependencies are missing)"}
    end
  end

  defp document(stdout) do
    case Parse.decode(stdout) do
      {:ok, document} ->
        {:ok, document}

      {:error, reason} ->
        {:error,
         "`mix #{@task}` wrote a standard output that is not one JSON text (#{reason}): " <>
           inspect(String.slice(stdout, 0, 200))}
    end
  end

  defp entries(document) when is_list(document) do
    if Enum.all?(document, &entry?/1),
      do: {:ok, Enum.map(document, &{&1["id"], &1["output"]})},
      else: {:error, "`mix #{@task}` wrote entries that are not each {id, output}"}
  end

  defp entries(_document), do: {:error, "`mix #{@task}` wrote a document that is not an array"}

  defp entry?(%{"id" => id, "output" => output} = entry),
    do: is_binary(id) and is_map(output) and map_size(entry) == 2

  defp entry?(_entry), do: false

  # ---------------------------------------------------------------------------------------
  # The comparison

  @doc """
  The failures of comparing the verifier's entries, `actual`, with cases.json's, `expected`:
  one for each case left out, given twice, given that is no offline case, or out of the
  file's order, and one for each case whose output differs, naming the first difference.
  """
  def compare(actual, expected) do
    actual_ids = Enum.map(actual, &elem(&1, 0))
    expected_ids = Enum.map(expected, &elem(&1, 0))
    outputs = Map.new(actual)

    missing = for id <- expected_ids -- actual_ids, do: "case #{id}: the verifier gives no entry"

    repeated =
      for id <- Enum.uniq(actual_ids -- Enum.uniq(actual_ids)),
          do: "case #{id}: the verifier gives more than one entry"

    extra =
      for id <- Enum.uniq(actual_ids) -- expected_ids,
          do: "case #{id}: the verifier gives an entry, and cases.json has no offline case #{id}"

    order =
      if missing == [] and repeated == [] and extra == [] and actual_ids != expected_ids do
        {id, _position} =
          actual_ids |> Enum.zip(expected_ids) |> Enum.find(fn {a, b} -> a != b end)

        ["case #{id}: the verifier gives it out of cases.json's order"]
      else
        []
      end

    differing =
      for {id, output} <- expected,
          Map.has_key?(outputs, id),
          difference = difference(outputs[id], output),
          do: "case #{id}: #{difference}"

    missing ++ repeated ++ extra ++ order ++ differing
  end

  # The first difference between the verifier's output and the expected one, or nil.
  defp difference(same, same), do: nil

  defp difference(actual, expected) do
    names = Map.keys(actual) ++ Map.keys(expected)

    names
    |> Enum.uniq()
    |> Enum.sort_by(&Enum.find_index(~w(code sub_reason rows label trace), fn n -> n == &1 end))
    |> Enum.find_value(&member(&1, Map.fetch(actual, &1), Map.fetch(expected, &1)))
  end

  defp member(_name, same, same), do: nil

  defp member(name, {:ok, _value}, :error),
    do: "the verifier gives #{name}, which cases.json does not"

  defp member(name, :error, {:ok, _value}), do: "the verifier gives no #{name}"

  defp member(name, {:ok, actual}, {:ok, expected})
       when name in ~w(rows trace) and is_list(actual),
       do: first_row(if(name == "rows", do: "row", else: "trace row"), actual, expected)

  defp member(name, {:ok, actual}, {:ok, expected}),
    do: "#{name}: the verifier gives #{show(actual)}, cases.json #{show(expected)}"

  defp first_row(noun, actual, expected) do
    count = max(length(actual), length(expected))

    Enum.find_value(0..(count - 1)//1, fn index ->
      case {Enum.fetch(actual, index), Enum.fetch(expected, index)} do
        {same, same} ->
          nil

        {{:ok, a}, {:ok, e}} ->
          "#{noun} #{index + 1}: the verifier gives #{show(a)}, cases.json #{show(e)}"

        {{:ok, a}, :error} ->
          "#{noun} #{index + 1}: the verifier gives #{show(a)}, cases.json no such row"

        {:error, {:ok, e}} ->
          "#{noun} #{index + 1}: the verifier gives no such row, cases.json #{show(e)}"
      end
    end)
  end

  # A value as JCS writes it, which is how the verifier printed it.
  defp show(value) do
    JCS.encode(value)
  rescue
    _error -> inspect(value)
  end

  # ---------------------------------------------------------------------------------------
  # The check's own test

  # Each mutant, of the expected output or of the verifier's, must give exactly one failure,
  # holding every fragment listed.
  defp self_test(actual, expected) do
    for {what, mutant_actual, mutant_expected, fragments} <- mutants(actual, expected),
        failures = compare(mutant_actual, mutant_expected),
        not (length(failures) == 1 and Enum.all?(fragments, &String.contains?(hd(failures), &1))) do
      "the conformance check does not refuse #{what}: it gives #{inspect(failures)}"
    end
  end

  defp mutants(actual, expected) do
    {report_id, report} = find(expected, &Map.has_key?(&1, "rows"))

    {untraced_id, _untraced} =
      find(expected, &(Map.has_key?(&1, "rows") and not Map.has_key?(&1, "trace")))

    {bare_id, _bare} = find(expected, &Map.has_key?(&1, "sub_reason"))
    {traced_id, traced} = find(expected, &Map.has_key?(&1, "trace"))
    middle = div(length(report["rows"]), 2)
    trace_middle = div(length(traced["trace"]), 2)
    [first, second | _rest] = actual
    unknown = "no-such-case-mutant"

    row = fn column, change ->
      edit(expected, report_id, fn output ->
        update_in(output, ["rows", Access.at(middle)], &List.update_at(&1, column, change))
      end)
    end

    trace_row = fn member, change ->
      edit(expected, traced_id, fn output ->
        update_in(output, ["trace", Access.at(trace_middle), member], change)
      end)
    end

    row_fragments = [report_id, "row #{middle + 1}:"]
    trace_fragments = [traced_id, "trace row #{trace_middle + 1}:"]

    [
      {"an expected row's status changed", actual, row.(2, &flip/1), row_fragments},
      {"an expected row's code changed", actual, row.(0, &changed/1), row_fragments},
      {"an expected row's part changed", actual, row.(1, &changed/1), row_fragments},
      {"an expected row's step changed", actual, row.(3, &changed/1), row_fragments},
      {"an expected row too many", actual,
       edit(expected, report_id, fn output ->
         Map.update!(output, "rows", &(&1 ++ [List.last(&1)]))
       end), [report_id, "row #{length(report["rows"]) + 1}:"]},
      {"an expected trace row's recomputed value changed", actual,
       trace_row.("recomputed", &changed/1), trace_fragments},
      {"an expected trace row's part changed", actual, trace_row.("part", &changed/1),
       trace_fragments},
      {"an expected trace row's status changed", actual, trace_row.("status", &flip/1),
       trace_fragments},
      {"a hand-mutated expected label", actual,
       edit(expected, report_id, &Map.update!(&1, "label", fn label -> label <> "-mutant" end)),
       [report_id, "label:"]},
      {"a hand-mutated expected sub_reason", actual,
       edit(expected, bare_id, &Map.update!(&1, "sub_reason", fn s -> s <> "_mutant" end)),
       [bare_id, "sub_reason:"]},
      {"a bare case's expected code changed", actual,
       edit(expected, bare_id, &Map.update!(&1, "code", fn code -> code <> "_mutant" end)),
       [bare_id, "code: the verifier gives"]},
      {"an expected code lost", actual, edit(expected, bare_id, &Map.delete(&1, "code")),
       [bare_id, "the verifier gives code, which cases.json does not"]},
      {"a case the verifier leaves out", tl(actual), expected, [elem(first, 0), "no entry"]},
      {"two cases the verifier exchanges", [second, first | tl(tl(actual))], expected,
       [elem(second, 0), "order"]},
      {"a member the verifier adds", edit(actual, untraced_id, &Map.put(&1, "trace", [])),
       expected, [untraced_id, "the verifier gives trace, which cases.json does not"]},
      {"a label the verifier drops", edit(actual, report_id, &Map.delete(&1, "label")), expected,
       [report_id, "the verifier gives no label"]},
      {"a trace the verifier drops", edit(actual, traced_id, &Map.delete(&1, "trace")), expected,
       [traced_id, "the verifier gives no trace"]},
      {"a sub_reason the verifier drops", edit(actual, bare_id, &Map.delete(&1, "sub_reason")),
       expected, [bare_id, "the verifier gives no sub_reason"]},
      {"an entry the verifier gives for an id that is no offline case",
       [{unknown, elem(first, 1)} | actual], expected,
       [unknown, "cases.json has no offline case"]},
      {"an entry the verifier gives twice", [first | actual], expected,
       [elem(first, 0), "more than one entry"]}
    ]
  end

  defp find(entries, predicate),
    do: Enum.find(entries, fn {_id, output} -> predicate.(output) end)

  defp edit(entries, id, fun),
    do:
      Enum.map(entries, fn
        {^id, output} -> {id, fun.(output)}
        entry -> entry
      end)

  defp flip("pass"), do: "fail"
  defp flip(_status), do: "pass"

  # A value other than `value`: a string with a suffix, an integer one more, and a string
  # for anything else.
  defp changed(value) when is_binary(value), do: value <> "-mutant"
  defp changed(value) when is_integer(value), do: value + 1
  defp changed(_value), do: "mutant"

  defp summary(expected) do
    bare = Enum.count(expected, fn {_id, output} -> Map.has_key?(output, "code") end)

    rows =
      expected
      |> Enum.map(fn {_id, output} -> length(Map.get(output, "rows", [])) end)
      |> Enum.sum()

    traces =
      expected
      |> Enum.map(fn {_id, output} -> Map.get(output, "trace") end)
      |> Enum.reject(&is_nil/1)

    "The reference verifier gives the expected output of every offline case, all " <>
      "#{length(expected)}: #{bare} bare rejections, #{length(expected) - bare} reports of " <>
      "#{rows} rows, and #{length(traces)} traces of #{traces |> Enum.map(&length/1) |> Enum.sum()} rows."
  end
end
