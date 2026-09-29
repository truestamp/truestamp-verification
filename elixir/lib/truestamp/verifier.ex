# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Truestamp.Verifier do
  @moduledoc """
  The reference verifier's steps of SPEC.md section 10.2, in order, one function per step:

  | Steps | Module |
  |---|---|
  | 0 to 6, the gate | `Truestamp.Verifier.Gate` |
  | 7 SHAPE | `Truestamp.Verifier.Shape.shape/1` |
  | 8 POLICY | `Truestamp.Verifier.Policy.policy/1` |
  | 9 DERIVE | `Truestamp.Verifier.Derive.derive/1` |
  | 10 CHAIN | `Truestamp.Verifier.Chain.chain/1` |
  | 11 SOURCES | `Truestamp.Verifier.Sources.sources/1` |
  | 12 WINDOW | `Truestamp.Verifier.Window.window/1` |
  | 13 EXPECTED_HASH | `Truestamp.Verifier.ExpectedHash.expected_hash/1` |
  | 14 VERDICT | `Truestamp.Verifier.Verdict.verdict/1` |

  `Truestamp.Verifier.Report` writes a run as the report of section 10.5, and
  `mix truestamp.verify` (`Truestamp.Verifier.Command`) is the command of section 12.2.

  `run/2` makes the steps over a document's bytes, and `run_file/2` over a file, which the
  gate reads after CONFIGURATION. Each gives:

  - `{:ok, run}`: steps 0 to 3 passed, so there is a report. The `Truestamp.Verifier.Run`
    holds the rows of every step, its trace and its label. A run that ended at the gate or at
    SHAPE holds a `skip prior_failure` row, part null, for each later step up to
    EXPECTED_HASH;
  - `{:rejected, rejection}`: a bare rejection at steps 0 to 3;
  - `{:error, {:unreadable, path, reason}}`: a document or keyring file that cannot be read
    (exit code 1, section 12.2);
  - `{:fault, description}`: a fault caught before steps 0 to 3 passed, which has no report to
    hold its row, so the run gives no report (sections 10.5 and 12.2, exit code 2).

  **Faults** (sections 10.5 and 12.2). A fault the verifier catches from ENVIRONMENT on is a
  `fail` row with the code `internal_error`, never a pass or a skip: `step/3` makes each of
  steps 4 to 13, and when one raises, throws or exits, it gives the run as it stood before
  that step with one `internal_error` row of that step, part null, and ends the run as a
  failure at the gate does (section 10.5), so each later step up to EXPECTED_HASH is one row
  `skip prior_failure`, part null. Those later rows are exempt from section 10.5's coverage
  rule and from section 10.3's KEY_EVENT_COMMITMENT rule, so a fault at DERIVE leaves CHAIN
  one part-null row. A fault at ENVIRONMENT, KEY_BINDING or SIGNATURE is a failure of that
  step, so the attribution is `none` (section 10.5). The label is then `failed`, with the
  run's code that of its first failing row. The row's `values` hold only the fault's `kind`
  (`error`, `throw` or `exit`) and, for an error, the `module` of its exception, so no value
  the proof carries reaches the report (section 10.5).

  VERDICT is not guarded: a fault after EXPECTED_HASH, the last step that reports rows, or
  while the report is written, gives no report, and the command exits 2 (section 12.2).
  """

  alias Truestamp.Verifier.{
    Chain,
    Config,
    Derive,
    ExpectedHash,
    Gate,
    Policy,
    Rejection,
    Row,
    Run,
    Shape,
    Sources,
    Verdict,
    Window
  }

  @typedoc "What a run of the steps gives (see the module doc)."
  @type result ::
          {:ok, Run.t()}
          | {:rejected, Rejection.t()}
          | {:error, {:unreadable, Path.t(), term()}}
          | {:fault, String.t()}

  @typedoc "A step from ENVIRONMENT on, as `step/3` makes it."
  @type step :: {String.t(), (Run.t() -> Run.t())}

  # The steps whose failure gives the attribution `none` (section 10.5).
  @gate_steps ~w(ENVIRONMENT KEY_BINDING SIGNATURE)

  @doc "The steps over the bytes of a document."
  @spec run(Config.t(), binary()) :: result()
  def run(%Config{} = config, bytes) when is_binary(bytes),
    do: after_admission(admitted(fn -> Gate.admit(config, bytes) end))

  @doc "The steps over the file at `path`, read only after CONFIGURATION."
  @spec run_file(Config.t(), Path.t()) :: result()
  def run_file(%Config{} = config, path),
    do: after_admission(admitted(fn -> Gate.admit_file(config, path) end))

  @doc "Steps 4 to 13, each in section 10.2's order, as `{name, function}`."
  @spec steps_after_envelope() :: [step()]
  def steps_after_envelope do
    [
      {"ENVIRONMENT", &Gate.environment/1},
      {"KEY_BINDING", &Gate.key_binding/1},
      {"SIGNATURE", &Gate.signature/1},
      {"SHAPE", &Shape.shape/1},
      {"POLICY", &Policy.policy/1},
      {"DERIVE", &Derive.derive/1},
      {"CHAIN", &Chain.chain/1},
      {"SOURCES", &Sources.sources/1},
      {"WINDOW", &Window.window/1},
      {"EXPECTED_HASH", &ExpectedHash.expected_hash/1}
    ]
  end

  @doc """
  Steps 4 to 14 on a run that has passed steps 0 to 3: each step of
  `steps_after_envelope/0` through `step/3`, then VERDICT.
  """
  @spec after_envelope(Run.t()) :: Run.t()
  def after_envelope(%Run{} = run) do
    steps_after_envelope()
    |> Enum.reduce(run, fn {name, function}, run -> step(run, name, function) end)
    |> Verdict.verdict()
  end

  @doc """
  Makes step `name` by `function` on `run`, catching a fault: when `function` raises, throws
  or exits, the result is `run` with one `internal_error` row of step `name`, part null, and
  the run ended (see the module doc). A run that has already ended passes through unchanged,
  since its later rows are already `skip prior_failure`.
  """
  @spec step(Run.t(), String.t(), (Run.t() -> Run.t())) :: Run.t()
  def step(%Run{ended: true} = run, _name, _function), do: run

  def step(%Run{} = run, name, function) do
    function.(run)
  catch
    kind, reason -> fault(run, name, kind, fault_module(kind, reason, __STACKTRACE__))
  end

  defp fault(run, name, kind, module) do
    what = if module, do: "#{kind} #{module}", else: Atom.to_string(kind)

    message =
      "A fault inside the verifier (#{what}) stopped step #{name}, so this run cannot pass."

    values = %{"kind" => Atom.to_string(kind), "module" => module}
    row = Row.new(name, :internal_error, nil, message, values)
    run = if name in @gate_steps, do: %{run | attribution: "none"}, else: run
    run |> Run.add_row(row) |> Run.end_run()
  end

  # The module of an error's exception, never its message or the terms it holds, which can
  # be values of the proof; a throw or an exit has none.
  defp fault_module(:error, reason, stacktrace),
    do: inspect(Exception.normalize(:error, reason, stacktrace).__struct__)

  defp fault_module(_kind, _reason, _stacktrace), do: nil

  # Steps 0 to 3, with a fault caught there given as {:fault, description}.
  defp admitted(admit) do
    admit.()
  catch
    kind, reason -> {:fault, Exception.format_banner(kind, reason, __STACKTRACE__)}
  end

  defp after_admission({:ok, %Run{} = run}), do: {:ok, after_envelope(run)}
  defp after_admission(other), do: other
end
