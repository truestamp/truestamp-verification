# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

# Writes MANIFEST.sha256: the SHA-256 of every file under spec/ and vectors/, one line per
# file in the format sha256sum reads ("<hex>  <path>"), sorted by path. With --check, it
# changes nothing and fails unless the file already says exactly that. Either form fails,
# and writes nothing, when spec/ or vectors/ holds an entry that is neither a regular file
# nor a directory, such as a symbolic link, since the manifest could not say what it holds.
#
#     elixir generator/manifest.exs
#     elixir generator/manifest.exs --check

Code.require_file("lib/base.exs", __DIR__)

root = Path.expand("..", __DIR__)
manifest = Path.join(root, "MANIFEST.sha256")
listed = for dir <- ~w(spec vectors), do: Generator.Files.entries(root, dir)
paths = Enum.flat_map(listed, &elem(&1, 0))

case Enum.flat_map(listed, &elem(&1, 1)) do
  [] ->
    :ok

  others ->
    for {path, type} <- others do
      IO.puts(:stderr, "manifest: #{path} is not a regular file or a directory (#{type})")
    end

    IO.puts(:stderr, "manifest: replace each with a regular file, or delete it.")
    System.halt(1)
end

expected =
  paths
  |> Enum.sort()
  |> Enum.map(fn path ->
    digest = :crypto.hash(:sha256, File.read!(Path.join(root, path)))
    [Base.encode16(digest, case: :lower), "  ", path, "\n"]
  end)
  |> IO.iodata_to_binary()

case System.argv() do
  ["--check"] ->
    case File.read(manifest) do
      {:ok, ^expected} ->
        IO.puts("MANIFEST.sha256 matches the #{length(paths)} files under spec/ and vectors/.")

      _ ->
        IO.puts(:stderr, "MANIFEST.sha256 is stale: run `task manifest` and commit the result.")
        System.halt(1)
    end

  [] ->
    File.write!(manifest, expected)
    IO.puts("Wrote MANIFEST.sha256 for #{length(paths)} files.")
end
