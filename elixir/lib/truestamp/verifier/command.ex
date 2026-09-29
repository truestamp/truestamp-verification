# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Truestamp.Verifier.Command do
  @moduledoc """
  The command of the reference verifier (SPEC.md section 12.2), which `mix truestamp.verify`
  runs:

      mix truestamp.verify FILE [--keyring FILE | --no-keyring] [--environment NAME]
                                [--expected-hash HEX] [--trace FILE]

  | Option | Sets |
  |---|---|
  | `--keyring FILE` | a supplied keyring, read from FILE (section 8.3) |
  | `--no-keyring` | keyless mode, for this run only (section 8.3) |
  | `--environment NAME` | E_v, `prod` by default (section 6.4) |
  | `--expected-hash HEX` | the caller's hash for EXPECTED_HASH (section 10.2, step 13) |
  | `--trace FILE` | writes the trace of section 10.6 to FILE |

  Each option is given at most once, and `--keyring` with `--no-keyring` is refused (D74).
  A value option takes the next argument, or its value after `=`. An argument that is not
  valid UTF-8 is refused, as is a `--trace` FILE whose directory does not exist. Nothing
  else sets the run: no configuration file and no environment variable is read, so keyless
  mode and E_v are only ever asked for on the command line (sections 6.4 and 8.3). The run
  is always offline.

  **Output.** Standard output carries the machine output: one JSON document, written with
  JCS and a final line feed. For a run that passed steps 0 to 3 it is the report of section
  10.5 (`Truestamp.Verifier.Report`), with exactly that section's members; for a bare
  rejection it is only `{code, message, sub_reason}`. Under `--trace FILE`, whenever
  standard output carries a document, FILE holds the run's trace in the canonical form of
  section 9, as `vectors/positive/<name>.trace.json` is: an empty list when the run ended
  before DERIVE, a bare rejection's included. Standard error carries the human output: the
  label and what it says, the attribution, the trust root, E_v (a non-production E_v said
  so, section 6.4), in keyless mode that the signature was checked only against the key the
  document carries (section 8.3), the type and subject id, the edges (never for a `failed`
  run, section 11.5, and for a proof that carries nothing that could give a submitted-after
  edge, that it has none, section 11.2), and every row that does not pass. For an item proof
  whose DERIVE ran, it prints the item code of section 3.9 beside the whole recomputed
  `item_hash`, captioned as the item code: never in its place, never with a status, and
  never in the report (section 11.5).

  **Exit codes** (`Truestamp.Verifier.ExitCodes`, section 12.2): the label's code for a
  report; 4 for a bare rejection other than `configuration_error`, and 8 for that; 1, with
  no report, for a runtime error outside verification: an invalid command line, an input
  that cannot be read, a document or keyring file missing or not a file (section 10.2, step
  0), or a `--trace` FILE that cannot be written; and 2, with no report, for a fault caught
  before steps 0 to 3 passed, or one no step caught, which includes a fault at VERDICT or
  while the report is written. A fault caught at any of steps 4 to 13 is an
  `internal_error` row, so its run is `failed` and exits 3.

  `main/1` gives `{exit_code, stdout, stderr}` and writes to neither stream, so a test can
  run it; the only file it writes is the `--trace` FILE.
  """

  alias Truestamp.Verifier
  alias Truestamp.Verifier.{Config, ExitCodes, ItemCode, Rejection, Report, Row, Run}

  @usage "Usage: mix truestamp.verify FILE [--keyring FILE | --no-keyring] " <>
           "[--environment NAME] [--expected-hash HEX] [--trace FILE]"

  @value_options %{
    "--keyring" => :keyring,
    "--environment" => :environment,
    "--expected-hash" => :expected_hash,
    "--trace" => :trace
  }
  @flag_options %{"--no-keyring" => :no_keyring}

  @typedoc "What a run of the command gives: its exit code and what it writes to each stream."
  @type outcome :: {non_neg_integer(), iodata(), iodata()}

  @doc "The usage line."
  @spec usage() :: String.t()
  def usage, do: @usage

  @doc """
  Runs the command over `argv`: `{exit_code, stdout, stderr}`. A fault that no step caught
  gives exit code 2 and no report.
  """
  @spec main([String.t()]) :: outcome()
  def main(argv) when is_list(argv) do
    case parse(argv) do
      {:ok, config, path, trace} -> execute(config, path, trace)
      {:error, message} -> {ExitCodes.code(:runtime_error), "", [message, "\n", @usage, "\n"]}
    end
  end

  @doc """
  Runs the steps of section 10.2 over the file at `path` under `config` and gives the
  command's outcome, as `main/1` does after reading its command line, writing the trace to
  the file `trace` when it is not nil. A fault that no step caught, at VERDICT or while the
  report is written among them, gives exit code 2 and no report (section 12.2).
  """
  @spec execute(Config.t(), Path.t(), Path.t() | nil) :: outcome()
  def execute(%Config{} = config, path, trace \\ nil) do
    config |> Verifier.run_file(path) |> outcome(trace)
  catch
    kind, reason -> fault(Exception.format_banner(kind, reason, __STACKTRACE__))
  end

  # ---------------------------------------------------------------------------------------
  # The command line

  @doc """
  Reads a command line: `{:ok, config, path, trace}`, where `trace` is the `--trace` FILE or
  nil, or `{:error, message}` for an invalid one (exit code 1).
  """
  @spec parse([String.t()]) ::
          {:ok, Config.t(), Path.t(), Path.t() | nil} | {:error, String.t()}
  def parse(argv) do
    with :ok <- utf8(argv),
         {:ok, options, paths} <- options(argv, [], []),
         {:ok, path} <- one_path(paths),
         {:ok, keyring} <- keyring(options),
         {:ok, config} <- config(options, keyring),
         {:ok, trace} <- trace(options) do
      {:ok, config, path, trace}
    end
  end

  # A file name or hash that is not valid UTF-8 cannot be named in a report (section 10.5).
  defp utf8(argv) do
    if Enum.all?(argv, &String.valid?/1),
      do: :ok,
      else: {:error, "An argument is not valid UTF-8."}
  end

  defp options([], options, paths), do: {:ok, Enum.reverse(options), Enum.reverse(paths)}
  defp options(["--" | rest], options, paths), do: options([], options, Enum.reverse(rest, paths))

  defp options(["--" <> _ = argument | rest], options, paths) do
    with {:ok, name, value, rest} <- option(argument, rest),
         :ok <- once(name, options, argument),
         do: options(rest, [{name, value} | options], paths)
  end

  defp options([path | rest], options, paths), do: options(rest, options, [path | paths])

  defp option(argument, rest) do
    case String.split(argument, "=", parts: 2) do
      [flag] when is_map_key(@flag_options, flag) ->
        {:ok, @flag_options[flag], true, rest}

      [flag, _value] when is_map_key(@flag_options, flag) ->
        {:error, "#{flag} takes no value."}

      [name, value] when is_map_key(@value_options, name) ->
        {:ok, @value_options[name], value, rest}

      [name] when is_map_key(@value_options, name) ->
        next_value(name, rest)

      _unknown ->
        {:error, "Unknown option: #{argument}"}
    end
  end

  defp next_value(name, ["--" <> _ | _rest]), do: {:error, "#{name} needs a value."}
  defp next_value(name, []), do: {:error, "#{name} needs a value."}
  defp next_value(name, [value | rest]), do: {:ok, @value_options[name], value, rest}

  defp once(name, options, argument) do
    if Keyword.has_key?(options, name),
      do: {:error, "#{argument} is given more than once."},
      else: :ok
  end

  defp one_path([path]), do: {:ok, path}
  defp one_path([]), do: {:error, "No proof file was given."}
  defp one_path(_paths), do: {:error, "Give exactly one proof file."}

  defp keyring(options) do
    case {Keyword.fetch(options, :keyring), Keyword.has_key?(options, :no_keyring)} do
      {{:ok, _path}, true} -> {:error, "--keyring and --no-keyring cannot both be given."}
      {{:ok, path}, false} -> {:ok, {:file, path}}
      {:error, true} -> {:ok, :none}
      {:error, false} -> {:ok, nil}
    end
  end

  defp config(options, keyring) do
    settings =
      [keyring: keyring] ++
        for {name, value} <- options, name in [:environment, :expected_hash], do: {name, value}

    case Config.new(settings) do
      {:ok, config} -> {:ok, config}
      {:error, {:invalid_option, :environment}} -> {:error, environment_error()}
      {:error, {:invalid_option, name}} -> {:error, "Invalid option: #{name}"}
    end
  end

  defp environment_error,
    do: "--environment takes one of: " <> Enum.join(Config.environments(), ", ") <> "."

  # The trace file is an output that cannot be written when its directory does not exist,
  # which is refused before the run; any other failure to write it is found after the run.
  defp trace(options) do
    case Keyword.fetch(options, :trace) do
      :error ->
        {:ok, nil}

      {:ok, file} ->
        if File.dir?(Path.dirname(file)),
          do: {:ok, file},
          else: {:error, "--trace names a file in a directory that does not exist: #{file}"}
    end
  end

  # ---------------------------------------------------------------------------------------
  # The outcome

  @doc """
  The command's outcome for what `Truestamp.Verifier.run_file/2` gave: the exit code, the
  JSON document for standard output (the report, or a bare rejection's output), and the
  human output for standard error. When `trace` is a file, it writes the run's trace there
  (`Truestamp.Verifier.Report.trace_file/1`) whenever standard output carries a document;
  a file that cannot be written gives exit code 1 and no report.
  """
  @spec outcome(Verifier.result(), Path.t() | nil) :: outcome()
  def outcome({:ok, %Run{label: label} = run}, trace) do
    report = Report.encode(Report.report(run))
    write_trace(trace, run.trace, {ExitCodes.code({:label, label}), report, human(run)})
  end

  def outcome({:rejected, %Rejection{} = rejection}, trace) do
    ending =
      if rejection.code == :configuration_error, do: :configuration_error, else: :bare_rejection

    output = Report.encode(Report.rejection(rejection))
    write_trace(trace, [], {ExitCodes.code(ending), output, rejected(rejection)})
  end

  def outcome({:error, {:unreadable, path, reason}}, _trace) do
    message = "Cannot read #{path}: #{:file.format_error(reason)}. No report."
    {ExitCodes.code(:runtime_error), "", [message, "\n"]}
  end

  def outcome({:fault, description}, _trace), do: fault(description)

  defp write_trace(nil, _trace, outcome), do: outcome

  defp write_trace(file, trace, outcome) do
    case File.write(file, Report.trace_file(trace)) do
      :ok ->
        outcome

      {:error, reason} ->
        message = "Cannot write the trace to #{file}: #{:file.format_error(reason)}. No report."
        {ExitCodes.code(:runtime_error), "", [message, "\n"]}
    end
  end

  defp fault(description) do
    message = "The verifier stopped on a fault before it could give a report: #{description}"
    {ExitCodes.code(:fault), "", [message, "\n"]}
  end

  # ---------------------------------------------------------------------------------------
  # Human output

  defp rejected(%Rejection{code: code, sub_reason: sub_reason, message: message}) do
    reason = if sub_reason, do: " (#{sub_reason})", else: ""
    ["Rejected: #{code}#{reason}. #{message}\n", "No report and no verdict.\n"]
  end

  @doc """
  The human output of a run that gave a report: the lines described in the module doc,
  each ending in a line feed.
  """
  @spec human(Run.t()) :: [String.t()]
  def human(%Run{} = run) do
    List.flatten([
      "Label: #{run.label}#{beside(run.config.environment)}. #{says(run.label)}\n",
      code_line(run),
      "Attribution: #{run.attribution}\n",
      trust_root_line(run.trust_root),
      environment_line(run.config.environment),
      keyless_line(run.trust_root.kind),
      subject_lines(run),
      item_code_lines(run),
      window_lines(run),
      rows_lines(run.rows)
    ])
  end

  # SPEC.md 6.4: a non-production E_v is shown beside the verdict.
  defp beside("prod"), do: ""
  defp beside(environment), do: ", under the #{environment} environment, not production"

  defp says("failed"), do: "A check failed, and its row says which."

  defp says("unattributed") do
    "The proof is intact under the key it carries, which was checked against no keyring, " <>
      "so anyone could have made it."
  end

  defp says("supplied-keyring") do
    "The proof is intact and signed by a key in the keyring the operator supplied; this " <>
      "says nothing about Truestamp."
  end

  defp says("internally-consistent") do
    "The proof is intact and signed by Truestamp, but no read in this run established its " <>
      "submitted-before edge."
  end

  defp says("verified") do
    "The proof is intact, signed by Truestamp, and its submission is placed before an " <>
      "instant read from a public chain in this run."
  end

  defp code_line(%Run{code: nil}), do: []
  defp code_line(%Run{code: code}), do: "Code: #{code}\n"

  defp trust_root_line(%{kind: kind, location: location, digest: digest}) do
    where = if location, do: ", from #{location}", else: ""
    sha = if digest, do: ", SHA-256 #{digest}", else: ""
    "Trust root: #{kind}#{where}#{sha}\n"
  end

  defp environment_line("prod"), do: "Environment: prod\n"

  defp environment_line(environment),
    do: "Environment: #{environment}, not production: this run checks #{environment} proofs.\n"

  defp keyless_line(:none),
    do: "Keyless: the signature was checked only against the key the document carries.\n"

  defp keyless_line(_kind), do: []

  defp subject_lines(%Run{type: nil}), do: []

  defp subject_lines(%Run{type: type, subject_id: id}),
    do: ["Type: #{type}\n", "Subject id: #{id}\n"]

  # SPEC.md 3.9 and 11.5: from the recomputed item_hash only, the trace's, beside it.
  defp item_code_lines(%Run{type: "item", trace: trace}) do
    with %{"recomputed" => item_hash} <- Enum.find(trace, &(&1["part"] == "/subject/item_hash")),
         {:ok, code} <- ItemCode.from_item_hash(item_hash) do
      [
        "item_hash, recomputed: #{item_hash}\n",
        "Item code: #{code} (a short name for this item; only the whole item_hash identifies it)\n"
      ]
    else
      _none -> []
    end
  end

  defp item_code_lines(_run), do: []

  defp window_lines(%Run{label: "failed"}), do: []

  defp window_lines(%Run{rows: rows}) do
    [
      submitted_after_line(Enum.find(rows, &(&1.step == "WINDOW"))),
      "Submitted before: not established in this run, which read no chain or source.\n"
    ]
  end

  # SPEC.md 11.2 and 11.3: WINDOW's reasons for an absent submitted-after edge are empty
  # exactly when the proof carries nothing that could give one, as a block proof does.
  defp submitted_after_line(%Row{values: %{"absent" => %{"submitted_after" => []}}}) do
    "Submitted after: none. This proof has no submitted-after edge: it carries no entropy " <>
      "object that could give one (SPEC.md section 11.2).\n"
  end

  defp submitted_after_line(_row),
    do: "Submitted after: not established in this run, which read no chain or source.\n"

  defp rows_lines(rows) do
    counts = Enum.frequencies_by(rows, & &1.status)

    summary =
      Enum.map_join([:pass, :fail, :skip, :warn, :info], ", ", &"#{Map.get(counts, &1, 0)} #{&1}")

    [
      "Rows: #{length(rows)} (#{summary})\n"
      | for(row <- rows, row.status != :pass, do: line(row))
    ]
  end

  defp line(%Row{} = row) do
    at = if row.part, do: " at #{row.part}", else: ""
    "  #{row.status} #{row.step} #{row.code}#{at}: #{row.message}\n"
  end
end
