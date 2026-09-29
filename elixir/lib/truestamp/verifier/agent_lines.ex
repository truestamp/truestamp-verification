# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Truestamp.Verifier.AgentLines do
  @moduledoc """
  The agent-test entry point of the reference verifier (SPEC.md section 7.4), which
  `mix truestamp.agent_lines` runs:

      mix truestamp.agent_lines RUNS_JSON

  It gives, for each proof a run names, the lines of section 7.4 that the reference verifier
  computes, every line but the two window lines, which the generator writes itself from the
  answers it recorded, since this verifier is offline (section 8.3). The generator writes
  these lines under `agent-test/expected/`.

  `RUNS_JSON` is an array of runs, each `{environment, id, keyring, proof}`: `proof` and
  `keyring` are paths relative to the directory that holds `RUNS_JSON`, and `environment` is
  the E_v the keyring is loaded under (section 10.2, step 0). Each run is admitted through
  steps 0 to 3 as any run is.

  **The lines.** Each is computed by the verifier's own functions, in the order below, and
  each of them is computed whatever the others give: section 7.4's lines are values, not a
  verdict, so no failure at the gate or at SHAPE stops the next. A proof that fails SHAPE
  gets its lines too, as for a mutant that breaks the empty-root rule, when DERIVE can read
  it; one whose layout DERIVE cannot read is an error entry. The run reads nothing the
  verifier does not already compute.

  - For each trace row of DERIVE's engine (section 10.6) but a handover signature's,
    `<pointer> <value>`: `/proof` followed by the row's part, then its recomputed value as
    the proof spells that member, a string as it is, an integer in decimal, and `none` for a
    walk that gives no root.
  - For each Bitcoin commitment entry whose `txoutproof` is not well formed, so that the
    trace holds no row for its header, as when the header misses its own target: the
    `header_hash`, `header_merkle_root` and `header_time` of its first 80 octets, the header,
    when it has them. A value is computed whatever a check of it gives, so these lines are
    there for a header that fails its check as for one that passes.
  - `digest <hex>`: `proof_hash`, SHA-256(0x50 || JCS(P)), as SIGNATURE computes it.
  - `/signature/value valid` or `/signature/value invalid`: V under K over `proof_hash`, by
    the strict Verify of section 6.2.
  - For each handover signature's trace row, its pointer and `valid` or `invalid`, the
    outcome of Verify that the row records.
  - `keyring match` or `keyring no-match`: whether K's 32 octets are a key of the keyring
    the run loaded, as KEY_BINDING looks it up.
  - `environment <value>`: the proof's `environment` member, which ENVIRONMENT reads, or
    `prod` when the proof carries none.

  A line repeated, as the root that several beacon walks reach, is given once.

  **Output.** Standard output carries one JSON document, written with JCS and a final line
  feed: an array with one entry per run, in the file's order, each `{id, lines}`, or
  `{error, id}` for a run whose proof cannot be read, is refused at steps 0 to 3, or fails
  SHAPE with a layout DERIVE cannot read. The entry point compares nothing.

  **Exit codes.** 0 when the document is written; 1, with nothing on standard output, for
  an invalid command line or a `RUNS_JSON` that cannot be read, is not JSON, or holds a run
  of another form; and 2, with nothing on standard output, for a fault inside the entry
  point.

  `main/1` gives `{exit_code, stdout, stderr}` and writes to neither stream, so a test can
  run it.
  """

  alias Truestamp.Verifier.{
    Bitcoin,
    Config,
    Derive,
    Ed25519,
    Gate,
    JCS,
    Keyring,
    Parser,
    RecordHash,
    Rejection,
    Run,
    Shape,
    TIME
  }

  @usage "Usage: mix truestamp.agent_lines RUNS_JSON"
  @members ~w(environment id keyring proof)

  @typedoc "What a run of the entry point gives: its exit code and what it writes to each stream."
  @type outcome :: {non_neg_integer(), iodata(), iodata()}

  @doc "The usage line."
  @spec usage() :: String.t()
  def usage, do: @usage

  @doc "Runs the entry point over `argv`: `{exit_code, stdout, stderr}`."
  @spec main([String.t()]) :: outcome()
  def main(argv) when is_list(argv) do
    with {:ok, path} <- one_path(argv),
         {:ok, runs} <- read(path) do
      dir = Path.dirname(path)
      entries = Enum.map(runs, &entry(&1, dir))
      summary = "Gave the agent-test lines of the #{length(runs)} runs of #{path}.\n"
      {0, [JCS.encode(entries), "\n"], summary}
    else
      {:error, message} -> {1, "", [message, "\n", @usage, "\n"]}
    end
  catch
    kind, reason ->
      banner = Exception.format_banner(kind, reason, __STACKTRACE__)
      {2, "", ["A fault inside the agent-test entry point: ", banner, "\n"]}
  end

  defp one_path([path]) do
    if String.valid?(path), do: {:ok, path}, else: {:error, "The path is not valid UTF-8."}
  end

  defp one_path(_argv), do: {:error, "Give exactly one runs file."}

  defp read(path) do
    with {:ok, bytes} <- file(path),
         {:ok, value} <- parse(path, bytes),
         :ok <- runs(path, value) do
      {:ok, value}
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

  defp runs(path, runs) when is_list(runs) do
    case Enum.find(runs, &(not run?(&1))) do
      nil ->
        :ok

      run ->
        {:error,
         "#{path} holds a run that is not {environment, id, keyring, proof}: " <>
           (run |> inspect() |> String.slice(0, 200))}
    end
  end

  defp runs(path, _value), do: {:error, "#{path} is not an array of runs."}

  defp run?(run) when is_map(run) do
    Enum.sort(Map.keys(run)) == @members and Enum.all?(@members, &is_binary(run[&1])) and
      run["environment"] in Config.environments()
  end

  defp run?(_run), do: false

  defp entry(%{"id" => id} = run, dir) do
    case lines(run, dir) do
      {:ok, lines} -> %{"id" => id, "lines" => lines}
      {:error, why} -> %{"error" => why, "id" => id}
    end
  end

  @doc """
  The lines of section 7.4 for the proof and keyring `run` names, with paths relative to
  `dir`: `{:ok, lines}`, or `{:error, why}` for a proof that cannot be read, is refused at
  steps 0 to 3, or fails SHAPE with a layout DERIVE cannot read.
  """
  @spec lines(map(), Path.t()) :: {:ok, [String.t()]} | {:error, String.t()}
  def lines(%{"environment" => environment, "keyring" => keyring, "proof" => proof}, dir) do
    config =
      Config.new!(environment: environment, keyring: {:file, Path.join(dir, keyring)})

    with {:ok, run} <- admitted(Gate.admit_file(config, Path.join(dir, proof))) do
      case shaped(run) do
        :ok -> {:ok, compute(run)}
        {:error, why} -> unshaped(run, why)
      end
    end
  end

  # A proof that fails SHAPE: its lines when DERIVE can read it, else the SHAPE failure.
  defp unshaped(run, why) do
    {:ok, compute(run)}
  rescue
    _fault -> {:error, why <> ", and DERIVE cannot read it"}
  end

  defp admitted({:ok, %Run{} = run}), do: {:ok, run}
  defp admitted({:rejected, %Rejection{code: code}}), do: {:error, "refused: #{code}"}

  defp admitted({:error, {:unreadable, path, reason}}),
    do: {:error, "#{path}: #{inspect(reason)}"}

  defp shaped(run) do
    case Enum.find(Shape.shape(run).rows, &(&1.step == "SHAPE")) do
      %{status: :pass} -> :ok
      row -> {:error, "SHAPE fails: #{row.code} at #{inspect(row.part)}"}
    end
  end

  defp compute(%Run{proof: proof, public_key: k, signature: v, keyring: keyring}) do
    {_rows, trace} = proof |> Derive.checks(k, "none") |> Derive.engine()
    {handovers, values} = Enum.split_with(trace, &handover?/1)
    proof_hash = RecordHash.hash(:proof_hash, proof)

    lines =
      Enum.map(values, &"/proof#{&1["part"]} #{spelled(&1["recomputed"])}") ++
        headers(proof, values) ++
        [
          "digest " <> Base.encode16(proof_hash, case: :lower),
          "/signature/value " <> validity(Ed25519.verify(k, proof_hash, v) == :ok)
        ] ++
        Enum.map(handovers, &"/proof#{&1["part"]} #{validity(&1["status"] == "pass")}") ++
        [
          "keyring " <> if(Keyring.find(keyring, k), do: "match", else: "no-match"),
          "environment " <> environment(proof)
        ]

    Enum.uniq(lines)
  end

  defp handover?(row), do: String.ends_with?(row["part"], "/handover_signature")

  # The header lines of each Bitcoin entry whose trace holds none, from the first 80 octets
  # of its txoutproof.
  defp headers(proof, values) do
    traced = MapSet.new(values, & &1["part"])

    for base <- ["commitments", "signing_key_event"],
        at =
          if(base == "commitments",
            do: ["commitments", "bitcoin"],
            else: ["signing_key_event", "commitments", "bitcoin"]
          ),
        %{"txoutproof" => hex} when is_binary(hex) <- [get_in(proof, at)],
        n = "/" <> Enum.join(at, "/"),
        not MapSet.member?(traced, n <> "/header_hash"),
        {:ok, <<header::binary-80, _rest::binary>>} <- [Base.decode16(hex, case: :lower)],
        {:ok, time} = TIME.format(:time, Bitcoin.header_time(header)),
        {member, value} <- [
          {"header_hash", Bitcoin.header_hash(header)},
          {"header_merkle_root", Bitcoin.header_merkle_root(header)},
          {"header_time", time}
        ],
        do: "/proof#{n}/#{member} #{value}"
  end

  defp spelled(nil), do: "none"
  defp spelled(value) when is_binary(value), do: value
  defp spelled(value) when is_integer(value), do: Integer.to_string(value)

  defp validity(true), do: "valid"
  defp validity(false), do: "invalid"

  defp environment(proof) do
    case Map.fetch(proof, "environment") do
      :error -> "prod"
      {:ok, marker} when is_binary(marker) -> marker
    end
  end
end
