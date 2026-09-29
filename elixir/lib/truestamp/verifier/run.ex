# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Truestamp.Verifier.Run do
  @moduledoc """
  The state of a run (SPEC.md section 10.2): the rows so far and what the later steps read.
  CONFIGURATION (`Truestamp.Verifier.Gate.configuration/1`) creates the run from a
  `Truestamp.Verifier.Config`. Steps 1 to 3 each take it and give `{:ok, run}`, with their
  row added, or a bare rejection. Steps 4 to 13 (`Truestamp.Verifier.Gate`,
  `Truestamp.Verifier.Shape`, `Truestamp.Verifier.Policy`, `Truestamp.Verifier.Derive`,
  `Truestamp.Verifier.Chain`, `Truestamp.Verifier.Sources`, `Truestamp.Verifier.Window` and
  `Truestamp.Verifier.ExpectedHash`) take it and give it back with their rows added, and
  VERDICT (`Truestamp.Verifier.Verdict`) sets its label. So a run that reaches the caller
  has passed steps 0 to 3.

  | Member | Holds | Set at |
  |---|---|---|
  | `config` | the `Truestamp.Verifier.Config` of the run | CONFIGURATION |
  | `keyring` | the `Truestamp.Verifier.Keyring` that governs, or nil in keyless mode | CONFIGURATION |
  | `trust_root` | `%{digest, kind, location}` of section 10.5 | CONFIGURATION |
  | `document` | the parsed document | PARSE |
  | `proof` | P, the parsed value of `proof` | ENVELOPE |
  | `public_key`, `signature` | the 32 octets of K and the 64 of V | ENVELOPE |
  | `bound_key` | the keyring's key K bound to, or nil | KEY_BINDING |
  | `proof_hash` | the 32 octets of SHA-256(0x50 \\|\\| JCS(P)) | SIGNATURE |
  | `attribution` | nil until the gate is decided, then as section 10.5 says | SIGNATURE, or the step that ends the run |
  | `type`, `subject_id` | the proof's `type` and its subject's `id` (section 10.5), nil until SHAPE passes | SHAPE |
  | `trace` | the trace of section 10.6: one trace row for each DERIVE row whose part is a CHECKED value, other than a row of LINK_HEAD, LINK_KEY_EVENT or LINK_CHAIN_ORDER, in DERIVE's order; empty until DERIVE runs | DERIVE |
  | `external_gate` | the external gate of section 10.2, decided once when DERIVE ends: `:prior_failure` when a row so far fails, else `:offline`, since every run of the reference verifier is offline; nil in a run that ended before DERIVE | DERIVE |
  | `rows` | the `Truestamp.Verifier.Row`s so far, in step order | every step |
  | `ended` | whether a failure ended the run | a failure at steps 4 to 7, or a caught fault from ENVIRONMENT on |
  | `label`, `code` | the label of section 10.5, and the run's code when the label is `failed` (section 10.2: the code of its first failing row), else nil | VERDICT |
  | `submitted_after`, `submitted_before` | the two edge objects of section 11.5; always nil, since the reference verifier draws no edge (section 8.3) | VERDICT |

  A failure at steps 4 to 6, or at SHAPE, ends the run (section 10.2): `end_run/1` then adds
  one row `skip prior_failure`, with part null, for each later step up to EXPECTED_HASH,
  and every step function passes an ended run through unchanged. A fault the verifier
  catches at any of steps 4 to 13 ends the run the same way, after its `internal_error` row
  (`Truestamp.Verifier.step/3`), and those later rows are exempt from section 10.5's
  coverage rule and section 10.3's KEY_EVENT_COMMITMENT rule (section 10.5).
  """

  alias Truestamp.Verifier.{Config, Keyring, Row}

  @steps ~w(CONFIGURATION READ PARSE ENVELOPE ENVIRONMENT KEY_BINDING SIGNATURE SHAPE POLICY
            DERIVE CHAIN SOURCES WINDOW EXPECTED_HASH VERDICT)

  # VERDICT reports no row (section 10.2, step 14), so rows stop at EXPECTED_HASH.
  @row_steps @steps -- ["VERDICT"]

  @typedoc "`trust_root` of section 10.5: `kind` is `compiled_pin`, `supplied_keyring` or `none`."
  @type trust_root :: %{
          digest: String.t() | nil,
          kind: :compiled_pin | :supplied_keyring | :none,
          location: String.t() | nil
        }

  @type t :: %__MODULE__{
          config: Config.t(),
          keyring: Keyring.t() | nil,
          trust_root: trust_root(),
          document: term(),
          proof: map() | nil,
          public_key: <<_::256>> | nil,
          signature: <<_::512>> | nil,
          bound_key: Keyring.key() | nil,
          proof_hash: <<_::256>> | nil,
          attribution: String.t() | nil,
          type: String.t() | nil,
          subject_id: String.t() | nil,
          trace: [map()],
          external_gate: :offline | :prior_failure | nil,
          rows: [Row.t()],
          ended: boolean(),
          label: String.t() | nil,
          code: atom() | nil,
          submitted_after: map() | nil,
          submitted_before: map() | nil
        }

  @enforce_keys [:config, :keyring, :trust_root]
  defstruct [
    :config,
    :keyring,
    :trust_root,
    document: nil,
    proof: nil,
    public_key: nil,
    signature: nil,
    bound_key: nil,
    proof_hash: nil,
    attribution: nil,
    type: nil,
    subject_id: nil,
    trace: [],
    external_gate: nil,
    rows: [],
    ended: false,
    label: nil,
    code: nil,
    submitted_after: nil,
    submitted_before: nil
  ]

  @doc "The steps of section 10.2, 0 to 14, by name, in order."
  @spec steps() :: [String.t()]
  def steps, do: @steps

  @doc "The run with `row` added after its rows."
  @spec add_row(t(), Row.t()) :: t()
  def add_row(%__MODULE__{rows: rows} = run, %Row{} = row), do: %{run | rows: rows ++ [row]}

  @doc "Whether any row so far is `fail`."
  @spec failed?(t()) :: boolean()
  def failed?(%__MODULE__{rows: rows}), do: Enum.any?(rows, &(&1.status == :fail))

  @doc """
  Ends the run after a failure at steps 4 to 7, or after a fault caught at any of steps 4 to
  13: one row `skip prior_failure`, part null, for each step after the last row's up to
  EXPECTED_HASH (sections 10.2 and 10.5).
  """
  @spec end_run(t()) :: t()
  def end_run(%__MODULE__{rows: rows} = run) do
    last = List.last(rows).step
    later = @row_steps |> Enum.drop_while(&(&1 != last)) |> tl()

    skips =
      for step <- later do
        Row.new(step, :prior_failure, nil, "Not made: a check of an earlier step failed.")
      end

    %{run | rows: rows ++ skips, ended: true}
  end
end
