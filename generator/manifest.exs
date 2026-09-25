# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

# Writes MANIFEST.sha256: the SHA-256 of every file under spec/ and vectors/, one line per
# file in the format sha256sum reads ("<hex>  <path>"), sorted by path. With --check, it
# changes nothing and fails unless the file already says exactly that.
#
#     elixir generator/manifest.exs
#     elixir generator/manifest.exs --check

root = Path.expand("..", __DIR__)
manifest = Path.join(root, "MANIFEST.sha256")

paths =
  for dir <- ~w(spec vectors),
      path <- Path.wildcard(Path.join([root, dir, "**", "*"]), match_dot: true),
      File.regular?(path),
      do: Path.relative_to(path, root)

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
