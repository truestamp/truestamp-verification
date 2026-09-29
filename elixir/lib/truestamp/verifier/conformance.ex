# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Truestamp.Verifier.Conformance do
  @moduledoc """
  The conformance entry point of the reference verifier (SPEC.md section 13.1), which
  `mix truestamp.conformance` runs:

      mix truestamp.conformance CASES_JSON

  It reads `CASES_JSON`, a file in the form of `vectors/cases.json` (section 13.2), and runs
  every offline case with its full configuration: its environment, its keyring, its
  `expected_hash` and its network pins, which the run takes in place of the default pins of
  its environment. The command of section 12.2, `mix truestamp.verify`, takes no network
  pins, so it runs a case under its environment's default pins. Of the 20 offline cases
  whose pins differ from those defaults, 6, the `policy-*-entropy_*` cases, give other rows
  through it; the other 14 give the same rows. The reference verifier is offline, so an online case (one with
  `online`) is not run and has no entry (section 13.1). Every path a case holds is read
  relative to the directory that holds `CASES_JSON`.

  **Output.** Standard output carries one JSON document, written with JCS and a final line
  feed, as raw bytes: an array with one entry per offline case, in the file's order, each
  `{id, output}`, where `output` holds what section 13.1 compares:

  - for a bare rejection, `code`, and `sub_reason` when the code has one;
  - for a report, `label` and `rows`, each row reduced to `[code, part, status, step]`, in
    order, and, for a case whose `expected` names a trace, `trace`: the run's trace rows,
    in order, each with every member but `inputs`;
  - for a run that gives neither, `error`, which says why: a proof or keyring file that
    cannot be read, or a fault caught before steps 0 to 3 passed. No conforming case
    gives one.

  The entry point reads nothing of a case's `expected` but whether it names a trace, which
  decides whether section 13.1 compares one. It compares nothing itself:
  `generator/generate.exs --check` compares its output with `cases.json`, and
  `test/conformance_test.exs` does too. Standard error carries one line that counts the
  cases run and those left out.

  **Exit codes.** 0 when the document is written, whatever the cases give; 1, with nothing
  on standard output, for an invalid command line or a `CASES_JSON` that cannot be read, is
  not JSON, or holds a case whose form or configuration section 13.2 does not allow; and 2,
  with nothing on standard output, for a fault inside the entry point.

  `main/1` gives `{exit_code, stdout, stderr}` and writes to neither stream, so a test can
  run it.
  """

  alias Truestamp.Verifier
  alias Truestamp.Verifier.{Config, JCS, Parser, Rejection, Row, Run}

  @usage "Usage: mix truestamp.conformance CASES_JSON"

  @typedoc "What a run of the entry point gives: its exit code and what it writes to each stream."
  @type outcome :: {non_neg_integer(), iodata(), iodata()}

  @doc "The usage line."
  @spec usage() :: String.t()
  def usage, do: @usage

  @doc "Runs the entry point over `argv`: `{exit_code, stdout, stderr}`."
  @spec main([String.t()]) :: outcome()
  def main(argv) when is_list(argv) do
    with {:ok, path} <- one_path(argv),
         {:ok, cases} <- read(path),
         {:ok, runs} <- configured(cases, Path.dirname(path)) do
      entries = for {kase, config} <- runs, do: entry(kase, config, Path.dirname(path))
      online = length(cases) - length(runs)

      summary =
        "Ran the #{length(runs)} offline cases of #{path}; " <>
          "left out its #{online} online cases, which an offline verifier does not run.\n"

      {0, [JCS.encode(entries), "\n"], summary}
    else
      {:error, message} -> {1, "", [message, "\n", @usage, "\n"]}
    end
  catch
    kind, reason ->
      banner = Exception.format_banner(kind, reason, __STACKTRACE__)
      {2, "", ["A fault inside the conformance entry point: ", banner, "\n"]}
  end

  defp one_path([path]) do
    if String.valid?(path), do: {:ok, path}, else: {:error, "The path is not valid UTF-8."}
  end

  defp one_path(_argv), do: {:error, "Give exactly one cases file."}

  # cases.json is larger than MAX_READ_OCTETS, which binds a document, not a data file, so
  # it is read under J2 to J6 alone.
  defp read(path) do
    with {:ok, bytes} <- file(path),
         {:ok, value} <- parse(path, bytes) do
      if is_list(value),
        do: {:ok, value},
        else: {:error, "#{path} is not an array of cases (SPEC.md 13.2)."}
    end
  end

  defp file(path) do
    case File.read(path) do
      {:ok, bytes} -> {:ok, bytes}
      {:error, reason} -> {:error, "#{path} cannot be read: #{:file.format_error(reason)}"}
    end
  end

  defp parse(path, bytes) do
    case Parser.parse(bytes) do
      {:ok, value} -> {:ok, value}
      {:error, {:malformed_json, why}} -> {:error, "#{path} is not JSON a verifier reads: #{why}"}
    end
  end

  # Each offline case with its configuration, in the file's order; the first case whose
  # form or configuration is not one section 13.2 allows refuses the whole file.
  defp configured(cases, vectors) do
    Enum.reduce_while(cases, {:ok, []}, fn kase, {:ok, runs} ->
      case config(kase, vectors) do
        {:ok, :online} -> {:cont, {:ok, runs}}
        {:ok, config} -> {:cont, {:ok, [{kase, config} | runs]}}
        {:error, message} -> {:halt, {:error, message}}
      end
    end)
    |> case do
      {:ok, runs} -> {:ok, Enum.reverse(runs)}
      error -> error
    end
  end

  @doc """
  The configuration a case's run takes (section 13.2), with its paths relative to `vectors`:
  `{:ok, config}`, `{:ok, :online}` for an online case, which this verifier does not run, or
  `{:error, message}` for a case whose form or configuration section 13.2 does not allow.
  A keyring path or `test` is a supplied keyring file, `none` is keyless mode, and an absent
  `keyring` is no keyring option (section 13.1); `networks` gives every pin.
  """
  @spec config(term(), Path.t()) :: {:ok, Config.t() | :online} | {:error, String.t()}
  def config(
        %{"id" => id, "proof" => proof, "config" => config, "expected" => expected} = kase,
        vectors
      )
      when is_binary(id) and is_binary(proof) and is_map(config) and is_map(expected) and
             map_size(kase) == 4 do
    if Map.has_key?(config, "online"),
      do: {:ok, :online},
      else: offline_config(id, config, vectors)
  end

  def config(kase, _vectors),
    do: {:error, "Not a case of SPEC.md 13.2: #{kase |> inspect() |> String.slice(0, 200)}"}

  @members ~w(environment expected_hash keyring networks)

  defp offline_config(id, config, vectors) do
    with :ok <- members(id, config),
         {:ok, keyring} <- keyring(id, Map.get(config, "keyring"), vectors),
         {:ok, networks} <- networks(id, Map.get(config, "networks")),
         {:ok, config} <-
           Config.new(
             environment: Map.get(config, "environment"),
             keyring: keyring,
             networks: networks,
             expected_hash: Map.get(config, "expected_hash")
           ) do
      {:ok, config}
    else
      {:error, {:invalid_option, name}} -> {:error, "Case #{id}: an invalid #{name}."}
      {:error, message} -> {:error, message}
    end
  end

  defp members(id, config) do
    case Map.keys(config) -- @members do
      [] -> :ok
      others -> {:error, "Case #{id}: config holds #{inspect(others)}, which 13.2 does not."}
    end
  end

  defp keyring(_id, nil, _vectors), do: {:ok, nil}
  defp keyring(_id, "none", _vectors), do: {:ok, :none}
  defp keyring(_id, "test", vectors), do: {:ok, {:file, Path.join(vectors, "keyring.test.json")}}

  defp keyring(id, "unavailable", _vectors),
    do: {:error, "Case #{id}: the keyring unavailable belongs to an online case (13.2)."}

  defp keyring(_id, path, vectors) when is_binary(path),
    do: {:ok, {:file, Path.join(vectors, path)}}

  defp keyring(id, _value, _vectors), do: {:error, "Case #{id}: an invalid keyring."}

  defp networks(_id, %{"commitment" => commitment, "entropy" => entropy} = networks)
       when map_size(networks) == 2,
       do: {:ok, %{commitment: commitment, entropy: entropy}}

  defp networks(id, _value), do: {:error, "Case #{id}: an invalid networks."}

  # One case's entry: its id and what section 13.1 compares of its run.
  defp entry(%{"id" => id, "proof" => proof, "expected" => expected}, config, vectors) do
    result = Verifier.run_file(config, Path.join(vectors, proof))
    %{"id" => id, "output" => output(result, Map.has_key?(expected, "trace"))}
  end

  @doc """
  What section 13.1 compares of a run's result: a bare rejection's `code` and `sub_reason`,
  or a report's `label` and reduced `rows`, with its `trace` rows, each without `inputs`,
  when `trace?`; an `error` for a result that is neither.
  """
  @spec output(Verifier.result(), boolean()) :: map()
  def output({:rejected, %Rejection{code: code, sub_reason: sub_reason}}, _trace?) do
    output = %{"code" => Atom.to_string(code)}
    if sub_reason, do: Map.put(output, "sub_reason", Atom.to_string(sub_reason)), else: output
  end

  def output({:ok, %Run{} = run}, trace?) do
    output = %{"label" => run.label, "rows" => Enum.map(run.rows, &Row.reduce/1)}

    if trace?,
      do: Map.put(output, "trace", Enum.map(run.trace, &Map.delete(&1, "inputs"))),
      else: output
  end

  def output({:error, {:unreadable, path, reason}}, _trace?),
    do: %{"error" => "#{path} cannot be read: #{inspect(reason)}"}

  def output({:fault, description}, _trace?),
    do: %{"error" => "a fault before steps 0 to 3 passed: #{description}"}
end
