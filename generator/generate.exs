# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

# The vector generator of SPEC.md 13.2. It writes the files under vectors/ and checks them.
#
#     elixir generator/generate.exs            # write the files under vectors/
#     elixir generator/generate.exs --check    # write nothing, and fail unless vectors/ holds
#                                              # exactly the files the first form writes
#
# The files: keyring.test.json and worked-example.json, and under positive/ the sound proofs
# of SPEC.md 13.3, each <name>.proof.json in the served form of SPEC.md 3.1, with its trace,
# <name>.trace.json, where <name> is its type, or its type, a hyphen and a variant
# (lib/vectors.exs). The proofs are cut from two modeled chains (lib/chain.exs and
# lib/regtest.exs) and assembled in lib/proofs.exs. Then cases.json, the cases of SPEC.md 13.3,
# offline and online, under negative/ the proof and keyring files its cases need, and under
# corpus/replay/ the replay file of each online case (lib/cases.exs), each case stated by a
# class module under lib/cases/ and its expected output computed by the generator's own model
# of the verification steps (lib/model.exs, with lib/parse.exs and lib/schema.exs, the DERIVE
# engine of lib/derive.exs, and for an online case the reads of lib/model_online.exs, answered
# from its replay). Last, under corpus/, the known answers for JCS, Ed25519 and base64url
# (lib/corpus.exs, with the point arithmetic of lib/ed25519.exs) and the real Bitcoin bytes
# (lib/real_bitcoin.exs).
#
# Every run makes these checks before it writes or compares anything, and a failure in any
# writes nothing:
#
#   1. Known answers. Each primitive the generator uses (the byte registry, key ids, JCS, the
#      Merkle Tree Hash, inclusion paths and the walk of SPEC.md 5.3, Bitcoin's
#      transactions, Merkle trees, merkleblocks, headers and targets, and the reading of a
#      JSON number as its nearest binary64 value) is run against answers that do not come
#      from the generator: kept by hand from RFC 8785, from the Merkle library's
#      vectors/merkle.json, from Bitcoin's chains and from Bitcoin Core's tests, computed by
#      Python's float() (known_answers/binary64.txt), or read from the files under spec/. A
#      primitive that changes breaks this table instead of quietly publishing new bytes
#      (lib/known_answers.exs, lib/binary64.exs). The generator reads every number itself,
#      since the C library's strtod aborts the VM on some long numbers on macOS 27, and the
#      vectors hold long numbers: only the files under spec/ are read with OTP's JSON, and
#      the check fails on a number of more than 30 significant digits in any of them.
#   2. Re-derivation. Each file is decoded from the bytes about to be written, and every value
#      in it is derived again from those bytes alone, never from the values that built them.
#      For a positive proof that is every DERIVE row, recomputed by an engine of its own
#      (lib/derive.exs, lib/pointer.exs, lib/bitcoin_parse.exs), each naming the row of the
#      constructions text that SPEC.md's own tables name for its check (lib/spec_rows.exs),
#      and its trace, derived again and compared with the trace file (lib/rederive.exs,
#      lib/positive.exs). Across the proofs, every check runs at every position a sound proof
#      can hold it, the proofs hold every sound shape of SPEC.md 13.3 (lib/sound.exs), and at
#      each of those positions the check fails on a proof with one defect made in memory
#      (lib/mutations.exs), made with the edits of lib/edit.exs.
#   3. The cases. Each case's expected output is derived again from its proof file's bytes and
#      its configuration as cases.json holds them, an online case's from its replay file; the
#      model's output is what the case says it asserts, so a single-defect case has exactly its
#      one failing row, an online case has the edges and the rows of CHAIN, SOURCES and WINDOW
#      it states by hand, and a case that stops the run at steps 4 to 7, run again past that
#      stop, fails nothing more than the knock-on failures it states; a trace a case names is
#      the model's trace; every file under negative/ and corpus/replay/ belongs to a case, in
#      its form, and holds bytes no other file under vectors/ holds; an online case's replay
#      holds the identity read of each network the case pins, but for the one case whose
#      `no_source` names regtest, an online configuration_error case has exactly one identity
#      read step 0 refuses, and a case whose run makes a read its replay does not hold cannot
#      be built; the codes of the online cases (lib/cases/online.exs) are codes only an online
#      run reaches; and every reason code but internal_error has a case, each bare or fail
#      code a single-defect case, and a code that lacks either fails. The run prints each
#      code's line. Last, spec/network-pins.json holds SPEC.md 9's table of default network
#      pins, a row for each E_v, its `prod` row the production networks and its `test` row
#      the pins the sound proofs pass POLICY under.
#   4. The corpus. Each JCS input reads under J1 to J6 and gives its output byte for byte;
#      each Ed25519 case gives its verdict, step by step, under the generator's own Verify and
#      the same pass or fail under the model's, and what its `about` says a verifier that
#      skips steps 2 and 3 gives is OpenSSL's own verdict; each base64url spelling is on its
#      class or off it as it says (lib/corpus.exs); and every conclusion a Bitcoin file
#      states is derived again from its bytes by the rederive check's parser, with the files
#      of a block tied together (lib/real_bitcoin.exs).
#   5. The model and the replay form. The modeled regtest chain holds together, each median
#      time past the model serves is the median of its header times, every read a verifier
#      makes online for a sound proof is answered by the model's sources and agrees with the
#      proof, and the window those answers give each sound proof is in order, with the time
#      in its subject's id inside it (lib/consistency.exs). SPEC.md 13.2's table of the kinds
#      of read is the validator's, and the sound item's replay, built in memory from the
#      model, holds to the replay form of SPEC.md 13.2, whose every rule refuses a mutant of
#      it, and so does every replay file under corpus/replay/ (lib/replay.exs). Each of these
#      checks also refuses a model, a proof, an answer or a table with one defect.
#
# Then SPEC.md 6.3's worked example is read from the text and compared, value by value, with
# worked-example.json (lib/worked_example.exs). Last, every seed the run derived a key from
# or signed with must give a key that spec/keys.nonproduction.json lists, and so must every
# key the run built from a seed's key by point arithmetic, and every public_key and
# previous_public_key in the files that passes SPEC.md 6.2's checks of a key's bytes, steps 2
# to 4, whether or not the run noted it (lib/known_answers.exs).
#
# The generator shares no code with any verifier in this repository. It uses only Elixir,
# :crypto, the data files under spec/ and its known answers under known_answers/, with its
# own JSON reader, its own JCS and its own Merkle walk, so a defect in one cannot hide in
# both.

for file <- ~w(base binary64 ed25519 bitcoin regtest chain pointer edit proofs bitcoin_parse
               derive parse schema model_online model cases cases/sound cases/parse cases/front
               cases/shape cases/derive known_answers corpus replay cases/online real_bitcoin
               consistency vectors sound mutations spec_rows positive rederive worked_example) do
  Code.require_file("lib/#{file}.exs", __DIR__)
end

alias Generator.{Cases, Consistency, Corpus, Files, KnownAnswers, RealBitcoin, Rederive, Replay}
alias Generator.{Spec, Vectors, WorkedExample}

mode =
  case System.argv() do
    [] ->
      :write

    ["--check"] ->
      :check

    _other ->
      IO.puts(:stderr, "usage: elixir generator/generate.exs [--check]")
      System.halt(2)
  end

root = Spec.root()
files = Vectors.files()

{case_failures, coverage} = Cases.check(files)

failures =
  KnownAnswers.run() ++
    Rederive.run(files) ++
    case_failures ++
    Corpus.check(files) ++
    RealBitcoin.check(files) ++
    Replay.check(files) ++
    Consistency.run(files) ++
    WorkedExample.run(Spec.spec_md(), files["vectors/worked-example.json"]) ++
    KnownAnswers.seeds(files)

if failures != [] do
  Enum.each(failures, &IO.puts(:stderr, "generate: " <> &1))
  IO.puts(:stderr, "generate: #{length(failures)} failed checks, so nothing was written.")
  System.halt(1)
end

# SPEC.md 13.1's check of every code: each code covered, and in how many cases.
Enum.each(coverage, &IO.puts/1)

case mode do
  :write ->
    # A write would follow a link out of vectors/, so this form refuses the entries --check
    # refuses, those that are neither a regular file nor a directory, and writes nothing.
    case Files.entries(root, "vectors") do
      {_files, []} ->
        :ok

      {_files, others} ->
        for {path, type} <- others do
          IO.puts(:stderr, "generate: #{path} is not a regular file (#{type})")
        end

        IO.puts(:stderr, "generate: delete each such entry, then run it again.")
        System.halt(1)
    end

    for {path, bytes} <- files do
      File.mkdir_p!(Path.dirname(Path.join(root, path)))
      File.write!(Path.join(root, path), bytes)
    end

    IO.puts("Wrote the #{map_size(files)} files under vectors/.")

  :check ->
    # Listed without following links: an entry that is neither a regular file nor a
    # directory, a symbolic link among them, is never a file the generator writes.
    {on_disk, others} = Files.entries(root, "vectors")

    # A file that differs or is missing is fixed by writing vectors/ again. A file that
    # cannot be read, or that the generator does not write, is not, so each gets its own
    # message.
    results =
      Enum.map(files, fn {path, bytes} ->
        case File.read(Path.join(root, path)) do
          {:ok, ^bytes} ->
            :ok

          {:ok, _other} ->
            {:stale, "#{path} differs from what the generator writes"}

          {:error, :enoent} ->
            {:stale, "#{path} is missing"}

          {:error, reason} ->
            {:unreadable, "#{path} cannot be read: #{:file.format_error(reason)}"}
        end
      end)

    stale = for {:stale, line} <- results, do: line
    unreadable = for {:unreadable, line} <- results, do: line

    stray =
      for(path <- on_disk -- Map.keys(files), do: "#{path} is not a file the generator writes") ++
        for {path, type} <- others,
            do: "#{path} is not a regular file the generator writes (#{type})"

    Enum.each(stale ++ unreadable ++ stray, &IO.puts(:stderr, "generate: " <> &1))

    if stale != [] do
      IO.puts(:stderr, "vectors/ is stale: run `task generate` and commit the result.")
    end

    if unreadable != [] do
      IO.puts(
        :stderr,
        "vectors/ holds files that cannot be read: make each one a readable file, " <>
          "then run `task generate`."
      )
    end

    if stray != [] do
      IO.puts(
        :stderr,
        "vectors/ holds files the generator does not write: delete each one, " <>
          "or have the generator write it."
      )
    end

    if stale == [] and unreadable == [] and stray == [] do
      IO.puts(
        "vectors/ holds the #{map_size(files)} files the generator writes, and its checks pass."
      )
    else
      System.halt(1)
    end
end
