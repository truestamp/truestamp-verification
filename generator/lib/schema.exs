# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Generator.Schema do
  @moduledoc """
  SHAPE's check 3 (SPEC.md 10.2 step 7) as the expected-output model makes it: the document
  against spec/schema.json, interpreted here over the keywords SPEC.md 9 allows and no other,
  giving the part of every failure by SHAPE's rule:

  - a member that is missing (`required`), extra (`additionalProperties`) or forbidden for the
    type (a property whose schema is `false`) fails at its own pointer, where the proof would
    hold it;
  - a count (`minProperties`, `maxItems`) fails at the object or array;
  - any other rule (`type`, `const`, `enum`, `pattern`, a length, a bound, `not`, the schema
    `false`) fails at the value that breaks it.

  `if` is evaluated for its outcome only, and then `then` or `else` applies; a keyword that
  constrains one JSON type ignores values of the others, as JSON Schema says. Patterns are run
  as written: each is paired with an exact length or the newline guard (SPEC.md 9), so PCRE's
  `$`, which also matches before a final newline, gives the same answer. A length counts code
  points.
  """

  alias Generator.Spec

  @keywords ~w($schema $defs $ref allOf if then else not type const enum properties required
               additionalProperties minProperties pattern minLength maxLength minimum maximum
               items maxItems)

  @doc """
  The pointers, into `value`, of every failure of spec/schema.json over it, in no set order.
  """
  def failures(value) do
    root = Spec.read("schema.json")
    check(root, value, "", root)
  end

  defp check(true, _value, _pointer, _root), do: []
  defp check(false, _value, pointer, _root), do: [pointer]

  defp check(schema, value, pointer, root) when is_map(schema) do
    case Map.keys(schema) -- @keywords do
      [] -> Enum.flat_map(schema, &keyword(&1, schema, value, pointer, root))
      other -> raise ArgumentError, "a schema keyword outside SPEC.md 9's list: #{inspect(other)}"
    end
  end

  defp keyword({"$ref", "#/$defs/" <> name}, _schema, value, pointer, root),
    do: check(Map.fetch!(root["$defs"], name), value, pointer, root)

  defp keyword({"allOf", schemas}, _schema, value, pointer, root),
    do: Enum.flat_map(schemas, &check(&1, value, pointer, root))

  defp keyword({"if", condition}, schema, value, pointer, root) do
    branch = if check(condition, value, pointer, root) == [], do: "then", else: "else"
    check(Map.get(schema, branch, true), value, pointer, root)
  end

  defp keyword({"not", inner}, _schema, value, pointer, root),
    do: if(check(inner, value, pointer, root) == [], do: [pointer], else: [])

  defp keyword({"type", type}, _schema, value, pointer, _root),
    do: unless_holds(Enum.any?(List.wrap(type), &type?(&1, value)), pointer)

  defp keyword({"const", const}, _schema, value, pointer, _root),
    do: unless_holds(equal?(value, const), pointer)

  defp keyword({"enum", values}, _schema, value, pointer, _root),
    do: unless_holds(Enum.any?(values, &equal?(value, &1)), pointer)

  # additionalProperties is only ever false, and refuses the members its sibling properties
  # does not name.
  defp keyword({"additionalProperties", false}, schema, value, pointer, _root) do
    allowed = Map.keys(Map.get(schema, "properties", %{}))

    if is_map(value),
      do: for(name <- Map.keys(value), name not in allowed, do: child(pointer, name)),
      else: []
  end

  defp keyword({name, _rule} = rule, _schema, value, pointer, root)
       when name in ~w(properties required minProperties),
       do: if(is_map(value), do: object(rule, value, pointer, root), else: [])

  defp keyword({name, rule}, _schema, value, pointer, root) when name in ~w(items maxItems),
    do: if(is_list(value), do: array(name, rule, value, pointer, root), else: [])

  defp keyword({name, rule}, _schema, value, pointer, _root)
       when name in ~w(pattern minLength maxLength),
       do: if(is_binary(value), do: string(name, rule, value, pointer), else: [])

  defp keyword({name, bound}, _schema, value, pointer, _root) when name in ~w(minimum maximum),
    do: if(is_number(value), do: bound(name, bound, value, pointer), else: [])

  # $schema, $defs, and then and else, which apply through if.
  defp keyword(_other, _schema, _value, _pointer, _root), do: []

  defp unless_holds(true, _pointer), do: []
  defp unless_holds(false, pointer), do: [pointer]

  defp object({"properties", properties}, value, pointer, root) do
    for {name, schema} <- properties,
        Map.has_key?(value, name),
        failure <- check(schema, Map.fetch!(value, name), child(pointer, name), root),
        do: failure
  end

  defp object({"required", names}, value, pointer, _root),
    do: for(name <- names, not Map.has_key?(value, name), do: child(pointer, name))

  defp object({"minProperties", count}, value, pointer, _root),
    do: unless_holds(map_size(value) >= count, pointer)

  defp array("items", schema, value, pointer, root) do
    value
    |> Enum.with_index()
    |> Enum.flat_map(fn {element, i} -> check(schema, element, "#{pointer}/#{i}", root) end)
  end

  defp array("maxItems", count, value, pointer, _root),
    do: unless_holds(length(value) <= count, pointer)

  defp string("pattern", pattern, value, pointer),
    do: unless_holds(Regex.match?(regex(pattern), value), pointer)

  defp string("minLength", count, value, pointer),
    do: unless_holds(length(String.to_charlist(value)) >= count, pointer)

  defp string("maxLength", count, value, pointer),
    do: unless_holds(length(String.to_charlist(value)) <= count, pointer)

  defp bound("minimum", bound, value, pointer), do: unless_holds(value >= bound, pointer)
  defp bound("maximum", bound, value, pointer), do: unless_holds(value <= bound, pointer)

  defp child(pointer, name),
    do: pointer <> "/" <> (name |> String.replace("~", "~0") |> String.replace("/", "~1"))

  defp type?("object", value), do: is_map(value)
  defp type?("array", value), do: is_list(value)
  defp type?("string", value), do: is_binary(value)
  defp type?("boolean", value), do: is_boolean(value)
  defp type?("null", value), do: value == nil
  defp type?("number", value), do: is_number(value)

  defp type?("integer", value),
    do: is_integer(value) or (is_float(value) and value == trunc(value))

  # JSON equality: numbers by value, and every other value exactly.
  defp equal?(a, b) when is_number(a) and is_number(b), do: a == b
  defp equal?(a, b), do: a === b

  defp regex(pattern) do
    case Process.get({__MODULE__, pattern}) do
      nil ->
        regex = Regex.compile!(pattern, "u")
        Process.put({__MODULE__, pattern}, regex)
        regex

      regex ->
        regex
    end
  end
end
