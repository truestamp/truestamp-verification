# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Truestamp.Verifier.Shape do
  @moduledoc """
  Step 7 of SPEC.md section 10.2, SHAPE, on P, the parsed value of `proof`. Its checks run
  in this order, and the first that fails is the step's one failing row:

  | Check | Holds when | Else, at |
  |---|---|---|
  | 1 | `format` is `"truestamp-proof"` | `unsupported_format`, `/format` |
  | 2 | `version` is 1 | `unsupported_version`, `/version` |
  | 3 | P satisfies `spec/schema.json` (`Truestamp.Verifier.Schema`) | `shape_invalid`, the first failure's part in document order |
  | 4 | in an item, `/witnesses` has exactly the names of `/subject/record/witness_hashes` | `shape_invalid`, `/witnesses` |
  | 5 | every TIME and NISTTIME value equals the formatting of its own parse | `shape_invalid`, the first such value in document order |
  | 6 | when `constructions` is present, its digest d is in CONSTRUCTIONS_ACCEPTED | `construction_mismatch`, `/constructions` |

  Check 3's part is the pointer of the member that is missing, extra or forbidden for the
  type, or else of the value that breaks its rule (for a count, the object or array); a
  block record that breaks the empty-root rule of section 5.4 fails at its `merkle_root`,
  and one that breaks the genesis pairing of section 3.3 at its key event's `type`, or at
  the missing `metadata.key_event` when `genesis` stands alone. Checks 1 and 2 come first,
  so an absent `format` or `version` is that check's failure, not the schema's.

  Check 5 reads the TIME values (`header_time` of each Bitcoin commitment entry, `closed_at`
  of each Stellar entropy object) and the NISTTIME values (`timeStamp` of each NIST entropy
  object) at the positions `Truestamp.Verifier.Layout` gives, after check 3 has held each to
  its pattern.

  **Constructions** (section 7.2). Check 6 is the one place any step reads `constructions`.
  Its JSON type tells the mode: an object is the full text, whose d is SHA-256(JCS(value));
  a string is a reference, whose d is the 64 hex characters of its URL, and check 3 has
  already failed a string off the reference pattern, and a value of any other type, with
  `shape_invalid`; absent is mode none, which checks nothing. The text is never
  interpreted and the URL never fetched.

  When SHAPE passes it reports one row, `pass`, with part null, and the run takes the proof's
  type and subject id (section 10.5): `/subject/record/id`, or `/block/record/id` for `block`
  and `beacon`. A failure ends the run as a failure at the gate does: each later step up to
  EXPECTED_HASH reports one row `skip prior_failure`, with part null
  (`Truestamp.Verifier.Run.end_run/1`). A run that has already ended passes through.

  **Values** (section 10.5). A row's `values` hold what this run computed or holds, and a
  value the proof carries only under `"declared"`, in a failing row:

  | Row | `values` |
  |---|---|
  | pass | `constructions`, the mode; in full mode also `constructions_digest`, the d it computed |
  | check 1 or 2 | `declared`, the `format` or `version` P carries, when it carries one |
  | check 3 | `keyword` and `schema`, the rule broken and where it sits in the schema |
  | check 4 | `rule`, which names the rule; never the names P carries |
  | check 5 | `class`, TIME or NISTTIME, and `declared`, the value |
  | check 6 | `constructions`, the mode; in full mode `constructions_digest`, the d it computed, and in reference mode `declared`, the d of the URL |

  The type and subject id are the run's, for the report, not a row's.
  """

  alias Truestamp.Verifier.{Constructions, JCS, Layout, Pointer, Row, Run, Schema, TIME}

  @format "truestamp-proof"
  @version 1

  # SPEC.md 7.2: the reference mode's URL, with d between these two.
  @reference_prefix "https://www.truestamp.com/.well-known/constructions-"
  @reference_suffix ".json"

  @step "SHAPE"

  # What a check-4 failure's `values` name: the rule, never the names the proof carries.
  @witness_rule "witnesses_named_by_witness_hashes"

  @typep failure :: {atom(), Pointer.t(), String.t(), map()}

  @doc "Step 7, SHAPE: the six checks above, in order, on the run's P."
  @spec shape(Run.t()) :: Run.t()
  def shape(%Run{ended: true} = run), do: run

  def shape(%Run{proof: proof} = run) when is_map(proof) do
    with nil <- format(proof),
         nil <- version(proof),
         nil <- schema(proof),
         nil <- witnesses(proof),
         nil <- times(proof),
         {:ok, constructions} <- constructions(proof) do
      pass(run, proof, constructions)
    else
      {code, part, message, values} -> fail(run, code, part, message, values)
    end
  end

  defp pass(run, proof, constructions) do
    type = Map.fetch!(proof, "type")
    subject_id = subject_id(type, proof)
    message = "The proof has the shape of a #{type} proof."
    row = Row.pass(@step, nil, message, constructions)
    Run.add_row(%{run | type: type, subject_id: subject_id}, row)
  end

  defp fail(run, code, part, message, values) do
    row = Row.new(@step, code, Pointer.encode(part), message, values)
    run |> Run.add_row(row) |> Run.end_run()
  end

  defp subject_id(type, proof) when type in ["block", "beacon"],
    do: Layout.get(proof, ["block", "record", "id"])

  defp subject_id(_type, proof), do: Layout.get(proof, ["subject", "record", "id"])

  # 1. format
  @spec format(map()) :: failure() | nil
  defp format(proof) do
    unless Map.get(proof, "format") === @format do
      message = "This proof's format is not \"#{@format}\", the only format this verifier reads."
      {:unsupported_format, ["format"], message, declared(proof, "format")}
    end
  end

  # 2. version
  @spec version(map()) :: failure() | nil
  defp version(proof) do
    unless Map.get(proof, "version") === @version do
      message =
        "This proof's version is not #{@version}, the only version this verifier reads; a " <>
          "later format may need a later verifier."

      {:unsupported_version, ["version"], message, declared(proof, "version")}
    end
  end

  defp declared(proof, member) do
    case Map.fetch(proof, member) do
      {:ok, value} -> %{"declared" => value}
      :error -> %{}
    end
  end

  # 3. the schema
  @spec schema(map()) :: failure() | nil
  defp schema(proof) do
    case Schema.proof_failures(proof) do
      [] ->
        nil

      [%{part: part, keyword: keyword, schema: location} | _later] ->
        message =
          "This proof does not have the layout of a Truestamp proof at " <>
            "#{Pointer.encode(part)}: it breaks the rule #{location}."

        {:shape_invalid, part, message, %{"keyword" => keyword, "schema" => location}}
    end
  end

  # 4. the witnesses of an item
  @spec witnesses(map()) :: failure() | nil
  defp witnesses(%{"type" => "item"} = proof) do
    witnesses = proof |> Map.fetch!("witnesses") |> Map.keys() |> Enum.sort()

    names =
      proof |> Layout.get(["subject", "record", "witness_hashes"]) |> Map.keys() |> Enum.sort()

    unless witnesses == names do
      message = "The item's witnesses are not exactly the ones its witness_hashes name."
      {:shape_invalid, ["witnesses"], message, %{"rule" => @witness_rule}}
    end
  end

  defp witnesses(_proof), do: nil

  # 5. the TIME and NISTTIME round trips
  @spec times(map()) :: failure() | nil
  defp times(proof) do
    failing =
      for {at, class} <- time_positions(proof),
          text = Layout.get(proof, at),
          match?({:error, _flaw}, TIME.parse(class, text)),
          do: {at, class}

    case Pointer.first_by(failing, &elem(&1, 0)) do
      nil ->
        nil

      {at, class} ->
        message =
          "The time at #{Pointer.encode(at)} names no instant: it does not write back to " <>
            "itself as #{class_name(class)}."

        values = %{"class" => class_name(class), "declared" => Layout.get(proof, at)}
        {:shape_invalid, at, message, values}
    end
  end

  defp time_positions(proof) do
    header_times =
      for {at, "bitcoin", _entry} <- Layout.commitment_entries(proof),
          do: {at ++ ["header_time"], :time}

    entropy_times =
      for {at, source, _object} <- Layout.entropy_objects(proof),
          {member, class} <- entropy_time(source),
          do: {at ++ member, class}

    header_times ++ entropy_times
  end

  defp entropy_time("stellar"), do: [{["payload", "closed_at"], :time}]
  defp entropy_time("nist"), do: [{["payload", "pulse", "timeStamp"], :nisttime}]
  defp entropy_time("bitcoin"), do: []

  defp class_name(:time), do: "TIME"
  defp class_name(:nisttime), do: "NISTTIME"

  # 6. constructions: the only read of the member in any step (SPEC.md 7.2 and 10.6, rule 1).
  @spec constructions(map()) :: {:ok, map()} | failure()
  defp constructions(proof) do
    case Map.fetch(proof, "constructions") do
      :error -> {:ok, %{"constructions" => "none"}}
      {:ok, text} when is_map(text) -> full(sha256_hex(JCS.encode(text)))
      {:ok, url} when is_binary(url) -> reference(reference_digest(url))
    end
  end

  # Full mode: this run computed d, so the row gives it, pass or fail.
  defp full(digest) do
    values = %{"constructions" => "full", "constructions_digest" => digest}

    if Constructions.accepted?(digest) do
      {:ok, values}
    else
      message =
        "This proof carries a constructions text this verifier has not accepted, so it " <>
          "cannot vouch for the proof's explanation of itself."

      {:construction_mismatch, ["constructions"], message, values}
    end
  end

  # Reference mode: d is the proof's, so only a failure gives it, marked as declared
  # (section 10.5).
  defp reference(digest) do
    if Constructions.accepted?(digest) do
      {:ok, %{"constructions" => "reference"}}
    else
      message =
        "This proof names by reference a constructions text this verifier has not " <>
          "accepted, so it cannot vouch for the proof's explanation of itself."

      {:construction_mismatch, ["constructions"], message,
       %{"constructions" => "reference", "declared" => digest}}
    end
  end

  # Check 3 has held the string to the reference pattern, so d is the 64 characters between
  # the prefix and the suffix.
  defp reference_digest(url) do
    <<@reference_prefix, digest::binary-size(64), @reference_suffix>> = url
    digest
  end

  defp sha256_hex(bytes), do: :sha256 |> :crypto.hash(bytes) |> Base.encode16(case: :lower)
end
