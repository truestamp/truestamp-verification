# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Truestamp.Verifier.Rejection do
  @moduledoc """
  A bare rejection (SPEC.md section 10.2, the gate): a failure at steps 0 to 3, which gives
  only `{code, message, sub_reason}`, with no report and no verdict.

  The code is one of the four whose status is "bare" in section 12.1: `configuration_error`,
  `input_too_large`, `malformed_json` or `invalid_envelope`. `sub_reason` is present for
  `malformed_json` and `invalid_envelope` only, and is one of the names
  `Truestamp.Verifier.ReasonCodes.sub_reasons/1` lists for the code (section 12.1). `new/3`
  refuses anything else.
  """

  alias Truestamp.Verifier.{Parser, ReasonCodes}

  @type t :: %__MODULE__{
          code: ReasonCodes.code(),
          message: String.t(),
          sub_reason: atom() | nil
        }

  @enforce_keys [:code, :message, :sub_reason]
  defstruct [:code, :message, :sub_reason]

  @doc """
  A bare rejection with `code` and `message`, and `sub_reason` when the code has one.
  Raises `ArgumentError` for a code that is not bare, or a `sub_reason` the code does not
  list, or a missing one.
  """
  @spec new(ReasonCodes.code(), String.t(), atom() | nil) :: t()
  def new(code, message, sub_reason \\ nil) when is_binary(message) do
    unless ReasonCodes.code?(code) and ReasonCodes.status(code) == :bare,
      do: raise(ArgumentError, "#{inspect(code)} is not a bare code of SPEC.md 12.1")

    listed = ReasonCodes.sub_reasons(code)

    unless (listed == [] and is_nil(sub_reason)) or sub_reason in listed,
      do: raise(ArgumentError, "#{inspect(sub_reason)} is not a sub_reason of #{code}")

    %__MODULE__{code: code, message: message, sub_reason: sub_reason}
  end

  @doc "`configuration_error`, with `message` saying which check of step 0 failed."
  @spec configuration_error(String.t()) :: t()
  def configuration_error(message), do: new(:configuration_error, message)

  @doc "`input_too_large` (step READ, J1)."
  @spec input_too_large() :: t()
  def input_too_large,
    do:
      new(
        :input_too_large,
        "The file is larger than #{Parser.max_read_octets()} octets, the most a verifier reads."
      )

  @doc "`malformed_json` with the rule the file breaks (step PARSE, J2 to J6)."
  @spec malformed_json(Parser.sub_reason()) :: t()
  def malformed_json(sub_reason),
    do: new(:malformed_json, "The file is not JSON that every verifier reads alike.", sub_reason)

  @doc "`invalid_envelope` with the first check of step 3 that fails (section 10.2)."
  @spec invalid_envelope(atom()) :: t()
  def invalid_envelope(sub_reason),
    do: new(:invalid_envelope, "This file is not a Truestamp proof.", sub_reason)
end
