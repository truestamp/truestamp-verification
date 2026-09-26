# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Generator.SpecRows do
  @moduledoc """
  The row of the constructions text (SPEC.md 7.3) that SPEC.md names for each check DERIVE
  makes, read from the text of SPEC.md by the checker alone: the "Row of 7.3" column of the
  tables of section 10.2 step 9 (a) and (b) and of section 10.3's links and key events, and
  the row that step 9 (c) and (d) each name in prose. The builder's names never enter it, so
  a check that names a real row of the text, but not the one SPEC.md gives it, fails.

  What is kept here is only where SPEC.md names each check's row: a table and the row's place
  in it, a link by its name, or a paragraph by its opening. The names are read.
  """

  import Generator.Check

  alias Generator.Derive

  # Each table, by the section it is in, its header and the count of its rows.
  @tables %{
    subject: {:derive, "| Recomputed | In | Part | Row of 7.3 |", 6},
    block: {:derive, "| Check | Part | Row of 7.3 |", 3},
    links: {:links, "| Link | Rule | Part | Failure | Row of 7.3 |", 5},
    key_events: {:links, "| Check | Events | Part | Row of 7.3 |", 8}
  }

  @bitcoin ~w(raw_transaction_well_formed op_return transaction_hash txoutproof_well_formed
              matched_hash header_hash header_merkle_root header_time)a

  @inclusion ~w(subject_root subject_tree_size observation_root observation_tree_size
                commitment_root commitment_tree_size key_commitment_root
                key_commitment_tree_size)a

  # Where SPEC.md names each check's row: {table, the row's place in it, from 1}, {:link, the
  # link's name in 10.3's links table}, or {:prose, the opening of a paragraph of step 9}.
  @where Map.merge(
           %{
             claims_hash: {:subject, 1},
             item_hash: {:subject, 2},
             subject_entropy_hash: {:subject, 3},
             subject_observation_hash: {:subject, 4},
             observation_entropy_hash: {:subject, 5},
             observation_observation_hash: {:subject, 6},
             block_hash: {:block, 1},
             genesis_height: {:block, 2},
             genesis_previous_block_hash: {:block, 3},
             key_public_key: {:key_events, 1},
             key_id: {:key_events, 2},
             key_signing_key_id: {:key_events, 3},
             previous_key_id: {:key_events, 4},
             event_height: {:key_events, 5},
             event_previous_block_hash: {:key_events, 6},
             handover_signature: {:key_events, 7},
             prerotation_signing_key_id: {:key_events, 8},
             epoch_hash: {:prose, "(c) **Epochs.**"},
             witness_block: {:link, "LINK_WITNESS"},
             witness_entropy: {:link, "LINK_WITNESS"},
             head: {:link, "LINK_HEAD"},
             key_event_link: {:link, "LINK_KEY_EVENT"},
             chain_order_stellar: {:link, "LINK_CHAIN_ORDER"},
             chain_order_bitcoin: {:link, "LINK_CHAIN_ORDER"}
           },
           Map.new(
             Enum.map(@bitcoin, &{&1, {:prose, "(d) **Bitcoin evidence.**"}}) ++
               Enum.map(@inclusion, &{&1, {:link, "LINK_INCLUSION"}})
           )
         )

  @doc """
  `{rows, failures}` for the text `spec_md`: each check's row by the check's name, nil where
  SPEC.md names none, and the failures of the reading.
  """
  def read(spec_md) do
    sections = %{
      derive: section(spec_md, "**9. DERIVE**", "**10. CHAIN**"),
      links: section(spec_md, "### 10.3 ", "### 10.4 ")
    }

    tables =
      Map.new(@tables, fn {name, {section, header, _count}} ->
        {name, table(Map.fetch!(sections, section), header)}
      end)

    rows = Map.new(@where, fn {check, where} -> {check, name(where, tables, sections)} end)

    failures =
      List.flatten([
        expect(
          "the checks whose row of 7.3 is read from SPEC.md",
          @where |> Map.keys() |> Enum.sort(),
          Enum.sort(Derive.checks())
        ),
        for {name, {_section, header, count}} <- @tables do
          expect("the rows of SPEC.md's table #{header}", length(Map.fetch!(tables, name)), count)
        end,
        for({check, nil} <- rows, do: "SPEC.md names no row of 7.3 for #{check}")
      ])

    {rows, failures}
  end

  # The text from the line that begins with `first` up to the line that begins with `last`,
  # or "" when either is missing.
  defp section(text, first, last) do
    with [_before, rest] <- String.split(text, "\n" <> first, parts: 2),
         [inside, _after] <- String.split(rest, "\n" <> last, parts: 2) do
      first <> inside
    else
      _missing -> ""
    end
  end

  # The rows of the table whose header line is `header`, each as its cells.
  defp table(text, header) do
    case String.split(text, "\n" <> header <> "\n", parts: 2) do
      [_before, rest] ->
        rest
        |> String.split("\n")
        |> Enum.drop(1)
        |> Enum.take_while(&String.starts_with?(&1, "|"))
        |> Enum.map(&cells/1)

      [_text] ->
        []
    end
  end

  defp cells(line), do: line |> String.trim("|") |> String.split("|") |> Enum.map(&String.trim/1)

  # The bare name of the row a locator points to, or nil.
  defp name({:prose, opening}, _tables, sections) do
    paragraph =
      sections.derive |> String.split("\n\n") |> Enum.find("", &String.starts_with?(&1, opening))

    case Regex.scan(~r/\(row `([a-z_]+)`\)/, paragraph, capture: :all_but_first) do
      [[row]] -> row
      _none_or_several -> nil
    end
  end

  defp name({:link, link}, tables, _sections) do
    case for([^link | _rest] = cells <- tables.links, do: cells) do
      [cells] -> bare(List.last(cells))
      _none_or_several -> nil
    end
  end

  defp name({table, place}, tables, _sections) do
    case tables |> Map.fetch!(table) |> Enum.at(place - 1) do
      nil -> nil
      cells -> bare(List.last(cells))
    end
  end

  # A cell that holds one construction name in backticks, as that name.
  defp bare(cell) do
    case Regex.run(~r/\A`([a-z_]+)`\z/, cell, capture: :all_but_first) do
      [name] -> name
      nil -> nil
    end
  end
end
