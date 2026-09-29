# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

# Writes the two manifests, each the SHA-256 of every file it covers, one line per file in the
# format sha256sum reads ("<hex>  <path>"), sorted by path:
#
# - MANIFEST.sha256, at the root, over every file under spec/ and vectors/, with paths from
#   the root. A claim of conformance cites its digest (SPEC.md 13.1), and the app's sync takes
#   exactly those two directories, so it lists nothing else.
# - agent-test/MANIFEST.sha256, over every file under agent-test/ but results/ and the
#   manifest itself, with paths from agent-test/, so `shasum -a 256 -c MANIFEST.sha256` run
#   there checks a copy. An edit to the harness, or a result written, never changes the digest
#   a conformance claim cites.
#
# With --check, it changes nothing and fails unless each manifest already says exactly that.
# Either form fails, and writes nothing, when a directory it covers holds an entry that is
# neither a regular file nor a directory, such as a symbolic link, since the manifest could
# not say what it holds.
#
#     elixir generator/manifest.exs
#     elixir generator/manifest.exs --check

Code.require_file("lib/base.exs", __DIR__)

defmodule Generator.Manifest do
  @moduledoc false

  alias Generator.Files

  # Each manifest: its path from the root, the prefix its paths drop, the directories it
  # covers, the paths under them it leaves out, and how it names what it covers.
  def manifests do
    [
      %{
        path: "MANIFEST.sha256",
        base: "",
        dirs: ~w(spec vectors),
        left_out: [],
        covers: "spec/ and vectors/"
      },
      %{
        path: "agent-test/MANIFEST.sha256",
        base: "agent-test/",
        dirs: ~w(agent-test),
        left_out: ["agent-test/results/", "agent-test/MANIFEST.sha256"],
        covers: "agent-test/ but results/"
      }
    ]
  end

  # `{:ok, paths, text}` for `manifest`, or `{:error, others}`, the entries under its
  # directories that are neither regular files nor directories.
  def expected(root, manifest) do
    listed = for dir <- manifest.dirs, do: Files.entries(root, dir)

    case Enum.flat_map(listed, &elem(&1, 1)) do
      [] ->
        paths =
          listed
          |> Enum.flat_map(&elem(&1, 0))
          |> Enum.reject(&left_out?(&1, manifest.left_out))
          |> Enum.sort()

        {:ok, paths, IO.iodata_to_binary(Enum.map(paths, &line(root, manifest.base, &1)))}

      others ->
        {:error, others}
    end
  end

  defp left_out?(path, prefixes), do: Enum.any?(prefixes, &String.starts_with?(path, &1))

  defp line(root, base, path) do
    digest = :crypto.hash(:sha256, File.read!(Path.join(root, path)))
    [Base.encode16(digest, case: :lower), "  ", String.replace_prefix(path, base, ""), "\n"]
  end
end

root = Path.expand("..", __DIR__)
built = for m <- Generator.Manifest.manifests(), do: {m, Generator.Manifest.expected(root, m)}

case for({_m, {:error, others}} <- built, other <- others, do: other) do
  [] ->
    :ok

  others ->
    for {path, type} <- others do
      IO.puts(:stderr, "manifest: #{path} is not a regular file or a directory (#{type})")
    end

    IO.puts(:stderr, "manifest: replace each with a regular file, or delete it.")
    System.halt(1)
end

case System.argv() do
  ["--check"] ->
    stale =
      Enum.reject(built, fn {m, {:ok, paths, text}} ->
        matches? = File.read(Path.join(root, m.path)) == {:ok, text}

        if matches?,
          do: IO.puts("#{m.path} matches the #{length(paths)} files under #{m.covers}.")

        matches?
      end)

    for {m, _built} <- stale do
      IO.puts(:stderr, "#{m.path} is stale: run `task manifest` and commit the result.")
    end

    if stale != [], do: System.halt(1)

  [] ->
    for {m, {:ok, paths, text}} <- built do
      File.write!(Path.join(root, m.path), text)
      IO.puts("Wrote #{m.path} for #{length(paths)} files.")
    end
end
