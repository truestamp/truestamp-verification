# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Truestamp.Verification.SpecMirrorTest do
  # The reference verifier, the library Truestamp.Verify at the commit mix.exs pins, compiles
  # in a mirror of spec/ (its priv/spec/), so the data it checks against is the data of the
  # commit it cites (SPEC.md 13.1). This test holds that mirror to this repository's spec/:
  # the same files, byte for byte, and no other. A change under spec/ therefore lands with a
  # library commit that mirrors it, and every check here runs the verifier on this data.
  use ExUnit.Case, async: true

  @spec_dir Path.expand("../../spec", __DIR__)

  defp files(dir) do
    dir
    |> Path.join("**/*")
    |> Path.wildcard(match_dot: true)
    |> Enum.reject(&File.dir?/1)
    |> Enum.map(&Path.relative_to(&1, dir))
    |> Enum.sort()
  end

  test "the library's priv/spec/ is spec/, file for file and byte for byte" do
    mirror = Application.app_dir(:truestamp_verify, "priv/spec")
    assert files(mirror) == files(@spec_dir)

    for file <- files(@spec_dir) do
      assert File.read!(Path.join(mirror, file)) == File.read!(Path.join(@spec_dir, file)),
             "the library's priv/spec/#{file} differs from spec/#{file}"
    end
  end
end
