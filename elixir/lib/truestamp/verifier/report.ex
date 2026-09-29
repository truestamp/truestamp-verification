# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Truestamp.Verifier.Report do
  @moduledoc """
  The report of SPEC.md section 10.5, and the output of a bare rejection (section 10.2, the
  gate), as JSON values that `Truestamp.Verifier.JCS` writes.

  **The report** of a run that passed steps 0 to 3 and VERDICT (`report/1`) has exactly the
  members of section 10.5's table:

  | Member | Value |
  |---|---|
  | `attribution` | `truestamp`, `keyring:<d>`, `unattributed` or `none` |
  | `code` | the run's code, present exactly when `label` is `failed` |
  | `environment` | E_v |
  | `label` | the label VERDICT gave |
  | `rows` | every row, `{code, message, part, status, step, values}`, with `code` absent exactly when the status is `pass` |
  | `subject_id` | the subject's `id`, null until SHAPE passes |
  | `submitted_after`, `submitted_before` | the two edge objects of section 11.5, null here, since the reference verifier draws no edge, and always null when `label` is `failed` |
  | `trust_root` | `{digest, kind, location}` |
  | `type` | the proof's `type`, null until SHAPE passes |
  | `verified` | true exactly when `label` is `verified` |
  | `window` | `established` when `submitted_before` is not null, else `not_established` |

  **The trace** (`trace_file/1`, the command's `--trace FILE`) is its own document, never a
  member of the report: the run's trace of section 10.6, one trace row for each DERIVE row
  whose part is a CHECKED value, other than a row of LINK_HEAD, LINK_KEY_EVENT or
  LINK_CHAIN_ORDER, in DERIVE's order, written in the canonical form of section 9
  (`Truestamp.Verifier.CanonicalForm`) as `vectors/positive/<name>.trace.json` is; an
  empty list when the run ended before DERIVE.

  **A bare rejection** (`rejection/1`) is only `{code, message, sub_reason}`, with
  `sub_reason` present only for `malformed_json` and `invalid_envelope`: no report and no
  verdict.

  The item code of section 3.9 is never a member or a row of a report (section 11.5).
  """

  alias Truestamp.Verifier.{CanonicalForm, JCS, Rejection, Row, Run}

  @doc "The report of `run`, after VERDICT, as a JSON value."
  @spec report(Run.t()) :: map()
  def report(%Run{label: label} = run) when is_binary(label) do
    %{
      "attribution" => run.attribution,
      "environment" => run.config.environment,
      "label" => label,
      "rows" => Enum.map(run.rows, &row/1),
      "subject_id" => run.subject_id,
      "submitted_after" => run.submitted_after,
      "submitted_before" => run.submitted_before,
      "trust_root" => trust_root(run.trust_root),
      "type" => run.type,
      "verified" => label == "verified",
      "window" => if(run.submitted_before, do: "established", else: "not_established")
    }
    |> put_code(run)
  end

  @doc """
  A trace (section 10.6) as the command's `--trace FILE` writes it: the canonical form of
  section 9, the form of `vectors/positive/<name>.trace.json`.
  """
  @spec trace_file([map()]) :: binary()
  def trace_file(trace) when is_list(trace), do: CanonicalForm.encode(trace)

  @doc "A report row, `{code, message, part, status, step, values}`, `code` absent on a pass."
  @spec row(Row.t()) :: map()
  def row(%Row{} = row) do
    written = %{
      "message" => row.message,
      "part" => row.part,
      "status" => Atom.to_string(row.status),
      "step" => row.step,
      "values" => row.values
    }

    if row.code, do: Map.put(written, "code", Atom.to_string(row.code)), else: written
  end

  @doc "The output of a bare rejection: `{code, message, sub_reason}`."
  @spec rejection(Rejection.t()) :: map()
  def rejection(%Rejection{code: code, message: message, sub_reason: sub_reason}) do
    written = %{"code" => Atom.to_string(code), "message" => message}
    if sub_reason, do: Map.put(written, "sub_reason", Atom.to_string(sub_reason)), else: written
  end

  @doc "`value` written with JCS, and a final line feed."
  @spec encode(map()) :: binary()
  def encode(value) when is_map(value), do: JCS.encode(value) <> "\n"

  defp put_code(report, %Run{label: "failed", code: code}) when is_atom(code) and code != nil,
    do: Map.put(report, "code", Atom.to_string(code))

  defp put_code(report, %Run{code: nil}), do: report

  defp trust_root(%{digest: digest, kind: kind, location: location}),
    do: %{"digest" => digest, "kind" => Atom.to_string(kind), "location" => location}
end
