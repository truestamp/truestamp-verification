# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Truestamp.Verifier.Row do
  @moduledoc """
  A report row, `{code, message, part, status, step, values}` (SPEC.md section 10.5):

  - `code`: a reason code of section 12.1, nil exactly when the status is `:pass`;
  - `message`: for display only, and never compared;
  - `part`: an RFC 6901 pointer into the proof, or nil for a row about no single member;
  - `status`: `:pass`, `:fail`, `:skip`, `:warn` or `:info`;
  - `step`: the name of its step (section 10.2), such as `"KEY_BINDING"`;
  - `values`: what this run computed or read, and, for a failed comparison, the declared
    value it contradicts, under `"declared"`. Each is a JSON value, a string where the run
    holds an atom, so a report writes it with `Truestamp.Verifier.JCS`.

  `new/5` refuses a row whose code is not in the table of section 12.1, or whose status
  differs from the one the table gives its code, so no row can carry a code that does not
  mean what its status says.

  `reduce/1` gives what conformance compares (section 13.1): `[code, part, status, step]`,
  with the code and status as strings, as `vectors/cases.json` writes them.
  """

  alias Truestamp.Verifier.ReasonCodes

  @typedoc "A row status (section 10.5)."
  @type status :: :pass | :fail | :skip | :warn | :info

  @type t :: %__MODULE__{
          code: ReasonCodes.code() | nil,
          message: String.t(),
          part: String.t() | nil,
          status: status(),
          step: String.t(),
          values: map()
        }

  @enforce_keys [:code, :message, :part, :status, :step, :values]
  defstruct [:code, :message, :part, :status, :step, :values]

  @doc "A `pass` row of `step` at `part`."
  @spec pass(String.t(), String.t() | nil, String.t(), map()) :: t()
  def pass(step, part, message, values \\ %{}), do: new(step, nil, part, message, values)

  @doc """
  A row of `step` with `code`, at `part`: its status is the one section 12.1 gives the code.
  Raises `ArgumentError` for a code the table lacks, or a status the table does not give it.
  """
  @spec new(String.t(), ReasonCodes.code() | nil, String.t() | nil, String.t(), map()) :: t()
  def new(step, code, part, message, values \\ %{})

  def new(step, nil, part, message, values),
    do: build(step, nil, part, :pass, message, values)

  def new(step, code, part, message, values) do
    unless ReasonCodes.code?(code),
      do: raise(ArgumentError, "#{inspect(code)} is not a reason code of SPEC.md 12.1")

    case ReasonCodes.status(code) do
      :bare -> raise ArgumentError, "#{code} ends a run in a bare rejection, not a row"
      status -> build(step, code, part, status, message, values)
    end
  end

  defp build(step, code, part, status, message, values)
       when is_binary(step) and (is_nil(part) or is_binary(part)) and is_binary(message) and
              is_map(values),
       do: %__MODULE__{
         code: code,
         message: message,
         part: part,
         status: status,
         step: step,
         values: values
       }

  @doc "What conformance compares of a row: `[code, part, status, step]` (section 13.1)."
  @spec reduce(t()) :: [String.t() | nil]
  def reduce(%__MODULE__{} = row) do
    code = if row.code, do: Atom.to_string(row.code)
    [code, row.part, Atom.to_string(row.status), row.step]
  end
end
