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
# lib/regtest.exs) and assembled in lib/proofs.exs. Then cases.json, the offline cases of
# SPEC.md 13.3, and under negative/ the proof and keyring files its cases need (lib/cases.exs),
# each case stated by a class module under lib/cases/ and its expected output computed by the
# generator's own model of the verification steps (lib/model.exs, with lib/parse.exs and
# lib/schema.exs, and the DERIVE engine of lib/derive.exs).
#
# Every run makes these checks before it writes or compares anything, and a failure in any
# writes nothing:
#
#   1. Known answers. Each primitive the generator uses (the byte registry, key ids, JCS, the
#      Merkle Tree Hash, inclusion paths and the walk of SPEC.md 5.3, and Bitcoin's
#      transactions, Merkle trees, merkleblocks, headers and targets) is run against answers
#      that do not come from the generator: kept by hand from RFC 8785, from the Merkle
#      library's vectors/merkle.json, from Bitcoin's chains and from Bitcoin Core's tests, or
#      read from the files under spec/. A primitive that changes breaks this table instead of
#      quietly publishing new bytes (lib/known_answers.exs).
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
#      its configuration as cases.json holds them; the model's output is what the case says it
#      asserts, so a single-defect case has exactly its one failing row, and a case that stops
#      the run at steps 4 to 7, run again past that stop, fails nothing more than the knock-on
#      failures it states; a trace a case names is the model's trace; every file under
#      negative/ belongs to a case, in its form, and holds bytes no other file under vectors/
#      holds; and every reason code but internal_error has a case, each bare or fail code a
#      single-defect case, or is reported as pending: online, until the replay format is set
#      (lib/cases/online.exs), where only a code no offline run reaches may be, or on a class
#      module with no cases yet. The run prints each code's line.
#
# Then SPEC.md 6.3's worked example is read from the text and compared, value by value, with
# worked-example.json (lib/worked_example.exs). Last, every seed the run derived a key from
# or signed with must give a key that spec/keys.nonproduction.json lists, and so must every
# key the run built from a seed's key by point arithmetic, and every public_key and
# previous_public_key in the files that passes SPEC.md 6.2's checks of a key's bytes, steps 2
# to 4, whether or not the run noted it (lib/known_answers.exs).
#
# The generator shares no code with any verifier in this repository. It uses only Elixir,
# :crypto and the data files under spec/, with its own JCS and its own Merkle walk, so a
# defect in one cannot hide in both.

for file <- ~w(base bitcoin regtest chain pointer edit proofs bitcoin_parse derive parse
               schema model cases/online cases cases/sound cases/parse cases/front cases/shape
               cases/derive vectors known_answers sound mutations spec_rows positive rederive
               worked_example) do
  Code.require_file("lib/#{file}.exs", __DIR__)
end

alias Generator.{Cases, Files, KnownAnswers, Rederive, Spec, Vectors, WorkedExample}

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
    WorkedExample.run(Spec.spec_md(), files["vectors/worked-example.json"]) ++
    KnownAnswers.seeds(files)

if failures != [] do
  Enum.each(failures, &IO.puts(:stderr, "generate: " <> &1))
  IO.puts(:stderr, "generate: #{length(failures)} failed checks, so nothing was written.")
  System.halt(1)
end

# SPEC.md 13.1's check of every code: each code covered, or pending.
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
