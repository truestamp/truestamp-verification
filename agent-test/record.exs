# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

# The replay recorder of the agent-sufficiency test (SPEC.md 7.4), for a run against a real
# proof, such as the staging rehearsal's:
#
#     elixir agent-test/record.exs PROOF OUT --environment NAME
#         --source CHAIN:NETWORK=KIND:URL ...
#         [--nist URL] [--keyring-origin URL] [--keyring-out FILE]
#
# It reads PROOF under the parsing rules of SPEC.md 10.1, takes the pins of NAME from
# spec/network-pins.json, makes every read SPEC.md 10.2 step 0 and 10.4 give for the proof,
# against the sources given, and writes the replay file to OUT, in the replay form and the
# canonical form of SPEC.md 13.2 and 9. Generator.Recorder (generator/lib/recorder.exs) says
# which reads it makes and how it records each answer; the generator's checks test it through
# a stubbed transport, never the network.
#
# - `--source CHAIN:NETWORK=KIND:URL`, once for each Stellar and Bitcoin network the pins
#   name: KIND is `horizon` for Stellar, and `esplora` or `core` for Bitcoin, whose URL may
#   carry a Bitcoin Core RPC user and password. For example, under `staging`:
#   `--source stellar:testnet=horizon:https://horizon-testnet.stellar.org`,
#   `--source bitcoin:regtest=core:http://user:password@host:18443` and
#   `--source bitcoin:mainnet=esplora:https://blockstream.info/api`.
# - `--nist URL`: the NIST beacon, `https://beacon.nist.gov` unless given.
# - `--keyring-origin URL`: records the keyring read at URL/.well-known/keyring.json, such as
#   `https://staging.truestamp.com`, the address of staging's keyring (D66).
# - `--keyring-out FILE`: also writes the keyring that read gave to FILE, in the canonical
#   form, for the session's keyring.json.
#
# It prints one line per read, with its outcome, and exits 1 on a command line it cannot use.

for file <-
      ~w(base binary64 ed25519 bitcoin regtest chain pointer edit proofs bitcoin_parse
               derive parse schema model_online model cases cases/sound cases/parse cases/front
               cases/shape cases/derive known_answers corpus item_code cases/item_codes replay
               cases/online real_bitcoin consistency vectors sound mutations spec_rows positive
               rederive worked_example agent_test recorder) do
  Code.require_file("../generator/lib/#{file}.exs", __DIR__)
end

alias Generator.{FileForm, Parse, Recorder, Spec}

usage = fn message ->
  IO.puts(:stderr, message)

  IO.puts(
    :stderr,
    "Usage: elixir agent-test/record.exs PROOF OUT --environment NAME " <>
      "--source CHAIN:NETWORK=KIND:URL ... [--nist URL] [--keyring-origin URL] " <>
      "[--keyring-out FILE]"
  )

  System.halt(1)
end

{options, arguments, invalid} =
  OptionParser.parse(System.argv(),
    strict: [
      environment: :string,
      source: :keep,
      nist: :string,
      keyring_origin: :string,
      keyring_out: :string
    ]
  )

if invalid != [], do: usage.("Options it does not know: #{inspect(invalid)}")

[proof_path, out] =
  case arguments do
    [_proof, _out] = two -> two
    _other -> usage.("Give a proof and an output file.")
  end

pins =
  case Map.fetch(Spec.read("network-pins.json"), options[:environment] || "") do
    {:ok, pins} -> pins
    :error -> usage.("--environment names no row of spec/network-pins.json.")
  end

sources =
  for text <- Keyword.get_values(options, :source), into: %{} do
    case Regex.run(~r/\A(stellar|bitcoin):([a-z]+)=(horizon|esplora|core):(.+)\z/, text) do
      [_all, chain, network, kind, url] ->
        kind = %{"core" => :core, "esplora" => :esplora, "horizon" => :horizon}[kind]
        {{chain, network}, {kind, url}}

      nil ->
        usage.("--source #{text} is not CHAIN:NETWORK=KIND:URL.")
    end
  end

proof =
  case Parse.read(File.read!(proof_path)) do
    {:ok, %{"proof" => proof}} when is_map(proof) -> proof
    _other -> usage.("#{proof_path} is not a proof a verifier reads.")
  end

replay =
  Recorder.record(proof,
    pins: pins,
    sources: sources,
    nist: options[:nist] || "https://beacon.nist.gov",
    keyring: options[:keyring_origin],
    transport: Recorder.http_transport()
  )

File.write!(out, FileForm.encode(replay))

# The replay form of SPEC.md 13.2, such as a keyring read over https, held to the file written.
case Generator.Replay.validate(replay, out) do
  [] ->
    :ok

  failures ->
    Enum.each(failures, &IO.puts(:stderr, &1))
    IO.puts(:stderr, "#{out} was written, but it does not hold to the replay form.")
    System.halt(1)
end

for %{"read" => read, "answer" => answer} <- replay["reads"] do
  IO.puts("#{answer["outcome"]}: #{inspect(read)}")
end

if path = options[:keyring_out] do
  case Enum.find(replay["reads"], &(&1["read"]["kind"] == "keyring")) do
    %{"answer" => %{"outcome" => "found", "value" => %{"keyring" => keyring}}} ->
      File.write!(path, FileForm.encode(keyring))

    _none ->
      IO.puts(:stderr, "No keyring was read, so #{path} was not written.")
  end
end
