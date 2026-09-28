# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Truestamp.Verifier.Gate do
  @moduledoc """
  Steps 0 to 6 of SPEC.md section 10.2, the gate, one function per step in the spec's order:

  | Step | Function | On failure |
  |---|---|---|
  | 0 CONFIGURATION | `configuration/1` | bare rejection `configuration_error` |
  | 1 READ | `read/2` | bare rejection `input_too_large` |
  | 2 PARSE | `parse/2` | bare rejection `malformed_json`, with its `sub_reason` |
  | 3 ENVELOPE | `envelope/1` | bare rejection `invalid_envelope`, with its `sub_reason` |
  | 4 ENVIRONMENT | `environment/1` | row `fail environment_mismatch`, and the run ends |
  | 5 KEY_BINDING | `key_binding/1` | row `fail key_binding_failed`, and the run ends |
  | 6 SIGNATURE | `signature/1` | row `fail signature_invalid`, and the run ends |

  Steps 0 to 3 give `{:ok, run}` or `{:rejected, rejection}` (a
  `Truestamp.Verifier.Rejection`); each that passes adds one row `pass` with part null.
  Steps 4 to 6 take a `Truestamp.Verifier.Run` and give it back with their one row added.
  A failure at any of them sets the attribution `none` and ends the run
  (`Truestamp.Verifier.Run.end_run/1`): each later step up to EXPECTED_HASH gets one row
  `skip prior_failure`, part null, and every step function passes an ended run through.
  When SIGNATURE passes, the gate is open and the run carries its attribution (section
  10.5): `truestamp` under the compiled pin, `keyring:<d>` under a supplied keyring, and
  `unattributed` in keyless mode.

  `run/2` makes the seven steps over a document's bytes, and `run_file/2` over a file, which
  it reads only after CONFIGURATION, as step 0 requires. A keyring file or a document file
  that cannot be read at all gives `{:error, {:unreadable, path, reason}}`: that is an input
  that cannot be read (exit code 1, section 12.2), not a verification result.

  The reference verifier is offline (section 8.3), so no keyring is read online here, and
  KEY_BINDING never gives `keyring_unavailable`: with no keyring option under E_v `prod`, the
  compiled pin governs.
  """

  alias Truestamp.Verifier.{
    Base64url,
    Config,
    Ed25519,
    KeyId,
    Keyring,
    Parser,
    ReasonCodes,
    RecordHash,
    Rejection,
    Row,
    Run
  }

  @typedoc "What the gate gives."
  @type result ::
          {:ok, Run.t()}
          | {:rejected, Rejection.t()}
          | {:error, {:unreadable, Path.t(), term()}}

  # SPEC.md 3.1: the literal `signature.alg` must equal, compared and never used to select.
  @alg "truestamp-ed25519-sha256-jcs"

  # SPEC.md 10.2, step 3: the checks of ENVELOPE, in order, each named by its sub_reason.
  @envelope_checks [:document, :proof, :signature, :alg, :public_key, :value]

  if @envelope_checks != ReasonCodes.sub_reasons(:invalid_envelope),
    do: raise("the ENVELOPE checks differ from invalid_envelope's sub_reasons")

  @known_environments Config.environments() -- ["prod"]

  @doc "The literal `signature.alg` must equal (section 3.1)."
  @spec alg() :: String.t()
  def alg, do: @alg

  @doc "The checks of ENVELOPE, in the order step 3 makes them, by their `sub_reason`."
  @spec envelope_checks() :: [atom()]
  def envelope_checks, do: @envelope_checks

  @doc "Steps 0 to 6 over the bytes of a document."
  @spec run(Config.t(), binary()) :: result()
  def run(%Config{} = config, bytes) when is_binary(bytes) do
    with {:ok, run} <- configuration(config), do: after_configuration(run, bytes)
  end

  @doc """
  Steps 0 to 6 over the file at `path`: CONFIGURATION first, then the file is read, at most
  MAX_READ_OCTETS + 1 octets of it (section 10.1, J1).
  """
  @spec run_file(Config.t(), Path.t()) :: result()
  def run_file(%Config{} = config, path) do
    with {:ok, run} <- configuration(config) do
      case Parser.read_file(path) do
        {:ok, bytes} -> after_configuration(run, bytes)
        {:error, :input_too_large} -> {:rejected, Rejection.input_too_large()}
        {:error, {:unreadable, reason}} -> {:error, {:unreadable, path, reason}}
      end
    end
  end

  defp after_configuration(run, bytes) do
    with {:ok, run} <- read(run, bytes),
         {:ok, run} <- parse(run, bytes),
         {:ok, run} <- envelope(run) do
      {:ok, run |> environment() |> key_binding() |> signature()}
    end
  end

  # ---------------------------------------------------------------------------------------
  # 0. CONFIGURATION

  @doc """
  Step 0, CONFIGURATION: fixes E_v and the keyring that governs, before the file is read.

  - `--no-keyring`: keyless mode; no keyring governs, under any E_v (section 8.3).
  - No keyring option under E_v `prod`: the compiled pin governs, loaded through the load
    checks under `prod` (the reference verifier is offline, D31).
  - No keyring option under any other E_v: `configuration_error`, since such a run must not
    use the compiled pin (section 6.4).
  - A supplied keyring, a file or bytes: loaded through the load checks under E_v, so under
    `prod` it is a production keyring (section 6.4); a failed check is
    `configuration_error`.
  """
  @spec configuration(Config.t()) :: result()
  def configuration(%Config{} = config) do
    with {:ok, keyring, trust_root} <- governing_keyring(config) do
      run = %Run{config: config, keyring: keyring, trust_root: trust_root}
      kind = Atom.to_string(trust_root.kind)
      values = %{"environment" => config.environment, "trust_root" => kind}
      message = "E_v is #{config.environment}, and #{governs(trust_root.kind)}."
      {:ok, Run.add_row(run, Row.pass("CONFIGURATION", nil, message, values))}
    end
  end

  defp governs(:compiled_pin), do: "the compiled pin governs key binding"
  defp governs(:supplied_keyring), do: "the supplied keyring governs key binding"
  defp governs(:none), do: "the run is keyless: no keyring governs key binding"

  defp governing_keyring(%Config{keyring: :none}),
    do: {:ok, nil, %{digest: nil, kind: :none, location: nil}}

  defp governing_keyring(%Config{keyring: nil, environment: "prod"}),
    do: load(Keyring.compiled_pin(), "prod", nil, :compiled_pin)

  defp governing_keyring(%Config{keyring: nil, environment: environment}) do
    {:rejected,
     Rejection.configuration_error(
       "A run whose environment is #{environment} checks proofs of that environment against " <>
         "a supplied keyring, and none was given: run again with --keyring FILE, or with " <>
         "--no-keyring to check the signature only against the key the document carries."
     )}
  end

  defp governing_keyring(%Config{keyring: {:file, path}, environment: environment}) do
    case Parser.read_file(path) do
      {:ok, bytes} -> load(bytes, environment, path, :supplied_keyring)
      {:error, :input_too_large} -> {:rejected, keyring_refused({:json, :input_too_large})}
      {:error, {:unreadable, reason}} -> {:error, {:unreadable, path, reason}}
    end
  end

  defp governing_keyring(%Config{keyring: {:bytes, bytes, location}, environment: environment}),
    do: load(bytes, environment, location, :supplied_keyring)

  defp load(bytes, environment, location, kind) do
    case Keyring.load(bytes, environment, location) do
      {:ok, keyring} ->
        {:ok, keyring, %{digest: keyring.digest, kind: kind, location: location}}

      {:error, failure} ->
        {:rejected, keyring_refused(failure)}
    end
  end

  defp keyring_refused(failure) do
    Rejection.configuration_error(
      "The keyring fails a load check, so the run gives no verdict: " <>
        Keyring.describe(failure) <> "."
    )
  end

  # ---------------------------------------------------------------------------------------
  # 1. READ

  @doc "Step 1, READ: J1 (section 10.1), else `input_too_large`."
  @spec read(Run.t(), binary()) :: {:ok, Run.t()} | {:rejected, Rejection.t()}
  def read(%Run{} = run, bytes) when is_binary(bytes) do
    case Parser.read(bytes) do
      :ok ->
        values = %{"octets" => byte_size(bytes)}

        {:ok,
         Run.add_row(run, Row.pass("READ", nil, "The file is within the read limit.", values))}

      {:error, :input_too_large} ->
        {:rejected, Rejection.input_too_large()}
    end
  end

  # ---------------------------------------------------------------------------------------
  # 2. PARSE

  @doc "Step 2, PARSE: J2 to J6 (section 10.1), else `malformed_json` with its `sub_reason`."
  @spec parse(Run.t(), binary()) :: {:ok, Run.t()} | {:rejected, Rejection.t()}
  def parse(%Run{} = run, bytes) when is_binary(bytes) do
    case Parser.parse(bytes) do
      {:ok, document} ->
        row = Row.pass("PARSE", nil, "The file is one JSON text that every verifier reads alike.")
        {:ok, Run.add_row(%{run | document: document}, row)}

      {:error, {:malformed_json, sub_reason}} ->
        {:rejected, Rejection.malformed_json(sub_reason)}
    end
  end

  # ---------------------------------------------------------------------------------------
  # 3. ENVELOPE

  @doc """
  Step 3, ENVELOPE: the document is exactly the envelope of section 3.1. The checks run in
  the order of `envelope_checks/0`, and the first that fails gives `invalid_envelope` with
  its name as the `sub_reason`:

  1. `document`: an object whose members are exactly `proof` and `signature`;
  2. `proof`: `proof` is an object;
  3. `signature`: an object whose members are exactly `alg`, `public_key` and `value`;
  4. `alg`: `alg` is the string `truestamp-ed25519-sha256-jcs`;
  5. `public_key`: a string that matches B64U32, whose 32 octets K pass the checks of a
     key's bytes (section 6.2);
  6. `value`: a string that matches B64U64.

  A B64U32 or B64U64 string is matched against its class before it is decoded, so every
  spelling but the canonical one fails (section 2.4).
  """
  @spec envelope(Run.t()) :: {:ok, Run.t()} | {:rejected, Rejection.t()}
  def envelope(%Run{document: document} = run) do
    with :ok <- check(:document, envelope_document?(document)),
         %{"proof" => proof, "signature" => signature} = document,
         :ok <- check(:proof, is_map(proof)),
         :ok <- check(:signature, signature_object?(signature)),
         :ok <- check(:alg, Map.fetch!(signature, "alg") === @alg),
         {:ok, public_key} <- public_key(Map.fetch!(signature, "public_key")),
         {:ok, value} <- decode(:value, :b64u64, Map.fetch!(signature, "value")) do
      values = %{"key_id" => KeyId.of(public_key)}
      row = Row.pass("ENVELOPE", nil, "The document is a proof envelope.", values)
      run = %{run | proof: proof, public_key: public_key, signature: value}
      {:ok, Run.add_row(run, row)}
    else
      {:error, check} -> {:rejected, Rejection.invalid_envelope(check)}
    end
  end

  defp check(_name, true), do: :ok
  defp check(name, false), do: {:error, name}

  defp envelope_document?(%{"proof" => _, "signature" => _} = document),
    do: map_size(document) == 2

  defp envelope_document?(_document), do: false

  defp signature_object?(%{"alg" => _, "public_key" => _, "value" => _} = signature),
    do: map_size(signature) == 3

  defp signature_object?(_signature), do: false

  defp public_key(text) do
    with {:ok, octets} <- decode(:public_key, :b64u32, text) do
      case Ed25519.check_key_bytes(octets) do
        :ok -> {:ok, octets}
        {:error, _refusal} -> {:error, :public_key}
      end
    end
  end

  defp decode(name, class, text) do
    case Base64url.decode(class, text) do
      {:ok, octets} -> {:ok, octets}
      :error -> {:error, name}
    end
  end

  # ---------------------------------------------------------------------------------------
  # 4. ENVIRONMENT

  @doc """
  Step 4, ENVIRONMENT: the check of section 6.4, one row at `/environment`. Under E_v `prod`
  the member is absent; under any other E_v it is present, a string, and equal to E_v.
  Anything else is `environment_mismatch`, whose message never quotes the marker
  (`environment_message/2`).
  """
  @spec environment(Run.t()) :: Run.t()
  def environment(%Run{ended: true} = run), do: run

  def environment(%Run{config: %Config{environment: e_v}, proof: proof} = run) do
    marker = Map.fetch(proof, "environment")
    values = %{"environment" => e_v}

    if environment_passes?(e_v, marker) do
      Run.add_row(run, Row.pass("ENVIRONMENT", "/environment", passes(e_v), values))
    else
      message = environment_message(e_v, marker)
      values = declared(values, marker)
      row = Row.new("ENVIRONMENT", :environment_mismatch, "/environment", message, values)
      gate_failure(run, row)
    end
  end

  # A failed comparison gives the declared value it contradicts (section 10.5), in `values`
  # only, never in the message.
  defp declared(values, {:ok, marker}), do: Map.put(values, "declared", marker)
  defp declared(values, :error), do: values

  defp environment_passes?("prod", :error), do: true
  defp environment_passes?(e_v, {:ok, e_v}) when e_v != "prod", do: true
  defp environment_passes?(_e_v, _marker), do: false

  defp passes("prod"), do: "The proof carries no environment marker: a production proof."
  defp passes(e_v), do: "The proof is marked as issued by Truestamp's #{e_v} environment."

  @doc """
  The message of `environment_mismatch` for E_v `e_v` and the marker as `Map.fetch/2` gives
  it (`:error` when the proof carries none). It never quotes the marker: it names the
  marked environment only when the marker is `dev`, `staging` or `test`, says production
  when there is no marker, and otherwise says that the proof carries a marker no Truestamp
  environment uses (section 6.4). Only for a known marker does it add the options that
  check the proof against that environment's keyring.
  """
  @spec environment_message(String.t(), {:ok, term()} | :error) :: String.t()
  def environment_message(e_v, :error) do
    "This proof carries no environment marker, so it is a production proof, and this run " <>
      "checks proofs of Truestamp's #{e_v} environment. To check it as a production proof, " <>
      "run again without --environment."
  end

  def environment_message("prod", {:ok, marker}) when marker in @known_environments do
    "This proof is marked as issued by Truestamp's #{marker} environment, which is for " <>
      "#{purpose(marker)}. It is not a production proof. " <> hint(marker)
  end

  def environment_message(e_v, {:ok, marker}) when marker in @known_environments do
    "This proof is marked as issued by Truestamp's #{marker} environment, and this run " <>
      "checks proofs of its #{e_v} environment. " <> hint(marker)
  end

  def environment_message(_e_v, {:ok, _marker}),
    do: "This proof carries an environment marker that no Truestamp environment uses."

  defp purpose("dev"), do: "development"
  defp purpose(_marker), do: "testing"

  defp hint(marker) do
    "To check it against the #{marker} keyring, run again with --environment #{marker} " <>
      "and --keyring FILE."
  end

  # ---------------------------------------------------------------------------------------
  # 5. KEY_BINDING

  @doc """
  Step 5, KEY_BINDING: the check of section 6.1, item 1, one row with part null. The run
  looks for a key of the keyring that governs whose 32 octets equal K's, and reads no key id
  the proof carries. Found, the row passes; not found, it fails `key_binding_failed`. In
  keyless mode the row is `skip key_binding_not_performed` (section 8.3).
  """
  @spec key_binding(Run.t()) :: Run.t()
  def key_binding(%Run{ended: true} = run), do: run

  def key_binding(%Run{keyring: nil} = run) do
    message =
      "Keyless mode: the signature is checked only against the key the document carries, " <>
        "which no keyring binds, so anyone could have made this proof."

    Run.add_row(run, Row.new("KEY_BINDING", :key_binding_not_performed, nil, message))
  end

  def key_binding(%Run{keyring: keyring, public_key: public_key} = run) do
    values = %{"key_id" => KeyId.of(public_key)}

    case Keyring.find(keyring, public_key) do
      nil ->
        message = not_bound(run.trust_root.kind)
        gate_failure(run, Row.new("KEY_BINDING", :key_binding_failed, nil, message, values))

      key ->
        row =
          Row.pass("KEY_BINDING", nil, "The key this proof carries is in the keyring.", values)

        Run.add_row(%{run | bound_key: key}, row)
    end
  end

  defp not_bound(:compiled_pin) do
    "The key this proof carries is not among the keys built into this verifier. If " <>
      "Truestamp introduced it after this verifier was built, update the verifier, or check " <>
      "the proof online."
  end

  defp not_bound(:supplied_keyring),
    do: "The key this proof carries is not in the supplied keyring."

  # ---------------------------------------------------------------------------------------
  # 6. SIGNATURE

  @doc """
  Step 6, SIGNATURE: the check of section 6.1, item 2, one row with part null. The run
  computes `proof_hash` = SHA-256(0x50 || JCS(P)) itself, from P as parsed, and checks V
  under K over its 32 octets by the strict rule of section 6.2, else `signature_invalid`.
  """
  @spec signature(Run.t()) :: Run.t()
  def signature(%Run{ended: true} = run), do: run

  def signature(%Run{proof: proof, public_key: public_key, signature: value} = run) do
    proof_hash = RecordHash.hash(:proof_hash, proof)
    values = %{"proof_hash" => Base.encode16(proof_hash, case: :lower)}
    run = %{run | proof_hash: proof_hash}

    case Ed25519.verify(public_key, proof_hash, value) do
      :ok ->
        row = Row.pass("SIGNATURE", nil, "The signature verifies under the key.", values)
        Run.add_row(%{run | attribution: attribution(run)}, row)

      {:error, refusal} ->
        message = "The signature does not verify under the key over this proof's proof_hash."
        values = Map.put(values, "refused", Atom.to_string(refusal))
        gate_failure(run, Row.new("SIGNATURE", :signature_invalid, nil, message, values))
    end
  end

  defp attribution(%Run{trust_root: %{kind: :compiled_pin}}), do: "truestamp"
  defp attribution(%Run{trust_root: %{kind: :supplied_keyring, digest: d}}), do: "keyring:" <> d
  defp attribution(%Run{trust_root: %{kind: :none}}), do: "unattributed"

  # A failure at steps 4 to 6 ends the run with the attribution `none` (section 10.5).
  defp gate_failure(run, row),
    do: %{run | attribution: "none"} |> Run.add_row(row) |> Run.end_run()
end
