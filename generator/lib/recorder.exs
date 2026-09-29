# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0

defmodule Generator.Recorder do
  @moduledoc """
  The replay recorder of SPEC.md 7.4: for any proof, the answers to the reads a verifier makes
  online (SPEC.md 10.2 step 0, and 10.4), recorded in the replay form of SPEC.md 13.2
  (Generator.Replay), from the sources it is given. `agent-test/record.exs` runs it against
  real sources for the staging rehearsal; its checks, check/1, answer every read from a
  stubbed transport and never reach the network.

  The reads, in the order a verifier makes them:

  - the identity read of each Stellar and Bitcoin network the pins name, as a commitment pin
    or an entropy pin; a source whose identity read gets no answer step 0 allows is read no
    further, since the replay form holds no other read of it;
  - the keyring read at `<origin>/.well-known/keyring.json`, when given the origin of a
    keyring, such as staging's (D66);
  - for each commitment entry, at `/commitments` and `/signing_key_event/commitments`: a
    Stellar entry's transaction, then for a top-level entry ledger `ledger`, or, when the
    transaction is not found, the source's root, then ledger `ledger` when it lies between
    the elder ledger and the latest less STELLAR_INDEX_MARGIN; a Bitcoin entry's tip, then,
    when the tip covers `height` + BITCOIN_FINALITY, the best-chain block at `height`, and
    for a top-level entry the one at `height` + BITCOIN_FINALITY;
  - for each `genesis.bitcoin`, the tip, then the best-chain block at its `height` when the
    tip covers it;
  - for each entropy object: its NIST pulse, its Stellar ledger, and when that ledger is not
    found the source's root, or its Bitcoin block by hash.

  For each read it fetches every field of the read's kind, so one record answers every use
  of its read: a best-chain block at a height gives its hash, median time past and
  transaction count wherever it is read. It keeps the first answer to a read it meets again
  and does not make that read twice. An answer is `found` when the source gives every field,
  each in its class, `not_found` when the source answers that it holds no such object (an
  HTTP 404, Esplora's 400 for a hash it does not know, or Bitcoin Core's errors -8 and -5),
  and `unreachable` otherwise, with a `reason` fitted to ASCII128: every byte outside
  printable ASCII, and every `"` and `\\`, made a `?`, cut to 128 characters, and `no answer`
  when nothing is left. An identity read, the Stellar root, the Bitcoin tip and the keyring
  read are never not found: a 404 there is unreachable.

  Sources, one per pinned network: `{:horizon, url}` for Stellar; `{:esplora, url}` or
  `{:core, url}` for Bitcoin, where a Bitcoin Core URL may carry its RPC user and password;
  and a NIST base URL, `https://beacon.nist.gov` unless given. The calls are those of SPEC.md
  10.4's informative table. A transport is a function from a request `%{method, url, body,
  headers}` to `{:ok, status, body}` or `{:error, reason}`; http_transport/0 is OTP's :httpc,
  with the system's certificates.
  """

  import Generator.Check

  alias Generator.{Bytes, Chain, JCS, Parse, Pointer, Replay, Spec}
  alias Generator.Replay.World

  @blocks ~w(/block /witnesses/block /signing_key_event/block)
  @entries ~w(/commitments /signing_key_event/commitments)
  @nist "https://beacon.nist.gov"

  @doc """
  The replay value for `proof`, the decoded `proof` member, under `options`: `pins` (a case's
  `networks`), `sources` (`{chain, network}` to a source), `transport`, and optionally
  `nist` and `keyring` (an origin URL). Raises when a pinned Stellar or Bitcoin network has
  no source.
  """
  def record(proof, options) do
    pins = Keyword.fetch!(options, :pins)

    state = %{
      answers: %{},
      order: [],
      usable: %{},
      pins: pins,
      sources: Keyword.fetch!(options, :sources),
      nist: Keyword.get(options, :nist, @nist),
      transport: Keyword.fetch!(options, :transport)
    }

    state =
      state
      |> identities()
      |> keyring(Keyword.get(options, :keyring))
      |> commitments(proof)
      |> geneses(proof)
      |> entropy(proof)

    state.order
    |> Enum.reverse()
    |> Enum.map(&%{"answer" => Map.fetch!(state.answers, &1), "read" => &1})
    |> Replay.file()
  end

  # Step 0: each pinned network's identity read.
  defp identities(state) do
    for chain <- ~w(bitcoin stellar),
        network <- Enum.uniq([state.pins["commitment"][chain], state.pins["entropy"][chain]]),
        network != nil,
        reduce: state do
      state ->
        unless Map.has_key?(state.sources, {chain, network}),
          do: raise(ArgumentError, "no source is given for #{chain} #{network}, which is pinned")

        {answer, state} = ask(state, %{"kind" => chain <> "_identity", "network" => network})

        usable? =
          match?(%{"outcome" => "found"}, answer) and
            Replay.allowed?(chain, network, answer["value"])

        %{state | usable: Map.put(state.usable, {chain, network}, usable?)}
    end
  end

  defp keyring(state, nil), do: state

  defp keyring(state, origin) do
    url = String.trim_trailing(origin, "/") <> "/.well-known/keyring.json"
    {_answer, state} = ask(state, %{"kind" => "keyring", "url" => url})
    state
  end

  # CHAIN: every commitment entry at both positions.
  defp commitments(state, proof) do
    for base <- @entries,
        {chain, entry} <- Enum.sort(Pointer.get(proof, base) || %{}),
        reduce: state do
      state ->
        network = state.pins["commitment"][chain]

        if usable?(state, chain, network),
          do: entry(state, chain, network, entry, base == "/commitments"),
          else: state
    end
  end

  defp entry(state, "stellar", network, entry, top?) do
    read = %{
      "hash" => entry["transaction_hash"],
      "kind" => "stellar_transaction",
      "network" => network
    }

    case ask(state, read) do
      {%{"outcome" => "found"}, state} when top? ->
        state |> ask(ledger(network, entry["ledger"])) |> elem(1)

      {%{"outcome" => "not_found"}, state} ->
        absent_transaction(state, network, entry["ledger"])

      {_answer, state} ->
        state
    end
  end

  defp entry(state, "bitcoin", network, entry, top?) do
    height = entry["height"]

    case covered(state, network, height) do
      {true, state} ->
        {_answer, state} = ask(state, at_height(network, height))

        if top?,
          do: state |> ask(at_height(network, height + finality())) |> elem(1),
          else: state

      {false, state} ->
        state
    end
  end

  # SPEC.md 10.4 item 3: the transaction not found, then the root, then ledger L when it lies
  # between elder and latest less the margin.
  defp absent_transaction(state, network, ledger) do
    case ask(state, %{"kind" => "stellar_root", "network" => network}) do
      {%{"outcome" => "found", "value" => %{"elder" => elder, "latest" => latest}}, state} ->
        if ledger > latest - margin() or ledger < elder,
          do: state,
          else: state |> ask(ledger(network, ledger)) |> elem(1)

      {_answer, state} ->
        state
    end
  end

  # Items 1 and 2 of the Bitcoin rule: the tip, and whether it covers `height` +
  # BITCOIN_FINALITY.
  defp covered(state, network, height) do
    case ask(state, %{"kind" => "bitcoin_tip", "network" => network}) do
      {%{"outcome" => "found", "value" => %{"height" => tip}}, state} ->
        {tip >= height + finality(), state}

      {_answer, state} ->
        {false, state}
    end
  end

  defp geneses(state, proof) do
    network = state.pins["commitment"]["bitcoin"]

    for b <- @blocks,
        %{"height" => height} <- [Pointer.get(proof, b <> "/record/metadata/genesis/bitcoin")],
        usable?(state, "bitcoin", network),
        reduce: state do
      state ->
        case covered(state, network, height) do
          {true, state} -> state |> ask(at_height(network, height)) |> elem(1)
          {false, state} -> state
        end
    end
  end

  # SOURCES: every entropy object.
  defp entropy(state, proof) do
    for pointer <- Replay.entropy_pointers(proof), reduce: state do
      state -> entropy_read(state, Pointer.get(proof, pointer))
    end
  end

  defp entropy_read(state, %{"source" => "nist", "payload" => %{"pulse" => pulse}}) do
    read = %{
      "chainIndex" => pulse["chainIndex"],
      "kind" => "nist_pulse",
      "pulseIndex" => pulse["pulseIndex"]
    }

    state |> ask(read) |> elem(1)
  end

  defp entropy_read(state, %{"source" => "stellar", "payload" => payload}) do
    network = state.pins["entropy"]["stellar"]

    if usable?(state, "stellar", network) do
      case ask(state, ledger(network, payload["sequence"])) do
        {%{"outcome" => "not_found"}, state} ->
          state |> ask(%{"kind" => "stellar_root", "network" => network}) |> elem(1)

        {_answer, state} ->
          state
      end
    else
      state
    end
  end

  defp entropy_read(state, %{"source" => "bitcoin", "payload" => payload}) do
    network = state.pins["entropy"]["bitcoin"]
    read = %{"hash" => payload["hash"], "kind" => "bitcoin_block", "network" => network}
    if usable?(state, "bitcoin", network), do: state |> ask(read) |> elem(1), else: state
  end

  defp usable?(state, chain, network), do: Map.get(state.usable, {chain, network}, false)

  defp ledger(network, sequence),
    do: %{"kind" => "stellar_ledger", "network" => network, "sequence" => sequence}

  defp at_height(network, height),
    do: %{"height" => height, "kind" => "bitcoin_block_at_height", "network" => network}

  defp finality, do: Spec.read("constants.json")["BITCOIN_FINALITY"]
  defp margin, do: Spec.read("constants.json")["STELLAR_INDEX_MARGIN"]

  # The answer to `read`: the first one recorded, or a fetched one, recorded.
  defp ask(state, read) do
    case Map.fetch(state.answers, read) do
      {:ok, answer} ->
        {answer, state}

      :error ->
        answer = checked(read["kind"], fetch(state, read))

        {answer,
         %{state | answers: Map.put(state.answers, read, answer), order: [read | state.order]}}
    end
  end

  # A found answer that breaks the form is no usable answer (SPEC.md 10.4).
  defp checked(kind, %{"outcome" => "found"} = answer) do
    case Replay.answer_failures(kind, answer) do
      [] -> answer
      _failures -> unreachable("an answer whose fields are missing or of another form")
    end
  end

  defp checked(_kind, answer), do: answer

  # ---------------------------------------------------------------------------------------
  # The calls of each kind of read

  defp fetch(state, %{"kind" => "keyring", "url" => url}) do
    with {:ok, body} <- get(state, url, :never) do
      case Parse.read(body) do
        {:ok, keyring} -> found(%{"keyring" => keyring})
        _other -> unreachable("a keyring that is not JSON a verifier reads")
      end
    end
  end

  defp fetch(state, %{"kind" => "nist_pulse"} = read) do
    url = "#{state.nist}/beacon/2.0/chain/#{read["chainIndex"]}/pulse/#{read["pulseIndex"]}"

    with {:ok, %{"pulse" => pulse}} <- json(state, url, :maybe) do
      found(Map.take(pulse, ["outputValue", "timeStamp"]))
    end
  end

  defp fetch(state, %{"kind" => "stellar_" <> _rest, "network" => network} = read) do
    {:horizon, url} = Map.fetch!(state.sources, {"stellar", network})
    horizon(state, String.trim_trailing(url, "/"), read)
  end

  defp fetch(state, %{"kind" => "bitcoin_" <> _rest, "network" => network} = read) do
    case Map.fetch!(state.sources, {"bitcoin", network}) do
      {:esplora, url} -> esplora(state, String.trim_trailing(url, "/"), read)
      {:core, url} -> core(state, url, read)
    end
  end

  defp horizon(state, url, %{"kind" => "stellar_identity"}) do
    with {:ok, root} <- json(state, url <> "/", :never),
         do: found(Map.take(root, ["network_passphrase"]))
  end

  defp horizon(state, url, %{"kind" => "stellar_root"}) do
    with {:ok, root} <- json(state, url <> "/", :never) do
      found(%{"elder" => root["history_elder_ledger"], "latest" => root["history_latest_ledger"]})
    end
  end

  defp horizon(state, url, %{"kind" => "stellar_transaction", "hash" => hash}) do
    with {:ok, tx} <- json(state, "#{url}/transactions/#{hash}", :maybe),
         {:ok, value} <- memo(tx, Map.take(tx, ["ledger", "memo_type", "successful"])),
         do: found(value)
  end

  defp horizon(state, url, %{"kind" => "stellar_ledger", "sequence" => sequence}) do
    with {:ok, ledger} <- json(state, "#{url}/ledgers/#{sequence}", :maybe),
         do: found(Map.take(ledger, ["closed_at", "hash"]))
  end

  # A transaction's memo, the 32 bytes in hex, when its memo_type is hash or return, whose
  # memo Horizon gives in standard base64.
  defp memo(%{"memo_type" => type} = tx, value) when type in ~w(hash return) do
    case Base.decode64(to_string(tx["memo"])) do
      {:ok, <<memo::binary-32>>} -> {:ok, Map.put(value, "memo", Bytes.hex(memo))}
      _other -> unreachable("a memo that is not 32 bytes in base64")
    end
  end

  defp memo(_tx, value), do: {:ok, value}

  defp esplora(state, url, %{"kind" => "bitcoin_identity"}) do
    with {:ok, hash} <- get(state, url <> "/block-height/0", :never),
         do: found(%{"hash" => String.trim(hash)})
  end

  defp esplora(state, url, %{"kind" => "bitcoin_tip"}) do
    with {:ok, text} <- get(state, url <> "/blocks/tip/height", :never) do
      case Integer.parse(String.trim(text)) do
        {height, ""} -> found(%{"height" => height})
        _other -> unreachable("a tip height that is not an integer")
      end
    end
  end

  defp esplora(state, url, %{"kind" => "bitcoin_block_at_height", "height" => height}) do
    with {:ok, hash} <- get(state, "#{url}/block-height/#{height}", :maybe),
         {:ok, block} <- json(state, "#{url}/block/#{String.trim(hash)}", :never) do
      found(%{
        "hash" => String.trim(hash),
        "median_time_past" => block["mediantime"],
        "transaction_count" => block["tx_count"]
      })
    end
  end

  defp esplora(state, url, %{"kind" => "bitcoin_block", "hash" => hash}) do
    with {:ok, block} <- json(state, "#{url}/block/#{hash}", :maybe) do
      found(%{
        "height" => block["height"],
        "median_time_past" => block["mediantime"],
        "time" => block["timestamp"]
      })
    end
  end

  defp core(state, url, %{"kind" => "bitcoin_identity"}) do
    with {:ok, hash} <- rpc(state, url, "getblockhash", [0], :never), do: found(%{"hash" => hash})
  end

  defp core(state, url, %{"kind" => "bitcoin_tip"}) do
    with {:ok, height} <- rpc(state, url, "getblockcount", [], :never),
         do: found(%{"height" => height})
  end

  defp core(state, url, %{"kind" => "bitcoin_block_at_height", "height" => height}) do
    with {:ok, hash} <- rpc(state, url, "getblockhash", [height], :maybe),
         {:ok, header} <- rpc(state, url, "getblockheader", [hash], :never) do
      found(%{
        "hash" => hash,
        "median_time_past" => header["mediantime"],
        "transaction_count" => header["nTx"]
      })
    end
  end

  defp core(state, url, %{"kind" => "bitcoin_block", "hash" => hash}) do
    with {:ok, header} <- rpc(state, url, "getblockheader", [hash], :maybe) do
      found(%{
        "height" => header["height"],
        "median_time_past" => header["mediantime"],
        "time" => header["time"]
      })
    end
  end

  # A GET whose body is a JSON object, read by the generator's own reader. `absent` is
  # `:maybe` for a read that can be not found, and `:never` for one that cannot.
  defp json(state, url, absent) do
    with {:ok, body} <- get(state, url, absent) do
      case Parse.read(body) do
        {:ok, value} when is_map(value) -> {:ok, value}
        _other -> unreachable("an answer that is not a JSON object")
      end
    end
  end

  defp get(state, url, absent) do
    request = %{method: :get, url: url, body: nil, headers: []}
    answered(state.transport.(request), absent, [404, 400])
  end

  # A Bitcoin Core JSON-RPC call; errors -8 (a height out of range) and -5 (no such block)
  # are not found.
  defp rpc(state, url, method, params, absent) do
    body =
      JCS.encode(%{"id" => "record", "jsonrpc" => "1.0", "method" => method, "params" => params})

    %URI{userinfo: userinfo} = uri = URI.parse(url)

    headers =
      [{"content-type", "application/json"}] ++
        if userinfo,
          do: [{"authorization", "Basic " <> Base.encode64(URI.decode(userinfo))}],
          else: []

    request = %{
      method: :post,
      url: URI.to_string(%{uri | userinfo: nil}),
      body: body,
      headers: headers
    }

    with {:ok, text} <- answered(state.transport.(request), :never, [], true) do
      case Parse.read(text) do
        {:ok, %{"error" => nil, "result" => result}} ->
          {:ok, result}

        {:ok, %{"error" => %{"code" => code}}} when code in [-8, -5] and absent == :maybe ->
          not_found()

        {:ok, %{"error" => %{"code" => code}}} ->
          unreachable("Bitcoin Core error #{code}")

        _other ->
          unreachable("an answer that is not a JSON-RPC response")
      end
    end
  end

  # The transport's answer: its body on HTTP 200, not found on one of `absent_codes` when
  # the read can be not found, and unreachable otherwise. Bitcoin Core answers an RPC error
  # with HTTP 404 or 500 and a JSON body, so `rpc?` passes those bodies on.
  defp answered(answer, absent, absent_codes, rpc? \\ false)
  defp answered({:ok, 200, body}, _absent, _codes, _rpc?), do: {:ok, body}

  defp answered({:ok, status, body}, _absent, _codes, true) when status in [404, 500],
    do: {:ok, body}

  defp answered({:ok, status, body}, :maybe, codes, rpc?) do
    if status in codes, do: not_found(), else: answered({:ok, status, body}, :never, codes, rpc?)
  end

  defp answered({:ok, status, _body}, _absent, _codes, _rpc?), do: unreachable("HTTP #{status}")
  defp answered({:error, reason}, _absent, _codes, _rpc?), do: unreachable(describe(reason))

  defp describe(reason) when is_binary(reason), do: reason
  defp describe(reason), do: inspect(reason)

  defp found(value), do: %{"outcome" => "found", "value" => value}
  defp not_found, do: %{"outcome" => "not_found"}
  defp unreachable(reason), do: %{"outcome" => "unreachable", "reason" => fit(reason)}

  @doc """
  `reason` fitted to ASCII128: each byte outside printable ASCII, and each `"` and `\\`, made
  a `?`, surrounding spaces trimmed, cut to 128 characters, and `no answer` when nothing is
  left.
  """
  def fit(reason) do
    text =
      for(<<b <- reason>>,
        into: "",
        do: if(b in 0x20..0x7E and b not in [?", ?\\], do: <<b>>, else: "?")
      )
      |> String.trim()

    text = binary_part(text, 0, min(byte_size(text), 128))
    if text == "", do: "no answer", else: text
  end

  @doc """
  A transport over OTP's :httpc, verifying each server's certificate against the system's
  certificates, with a timeout of 30 seconds.
  """
  def http_transport do
    {:ok, _apps} = Application.ensure_all_started([:inets, :ssl])

    fn %{method: method, url: url, body: body, headers: headers} ->
      headers = for {name, value} <- headers, do: {to_charlist(name), to_charlist(value)}

      ssl = [
        verify: :verify_peer,
        cacerts: :public_key.cacerts_get(),
        customize_hostname_check: [match_fun: :public_key.pkix_verify_hostname_match_fun(:https)]
      ]

      request =
        case method do
          :get -> {to_charlist(url), headers}
          :post -> {to_charlist(url), headers, ~c"application/json", body}
        end

      case :httpc.request(method, request, [timeout: 30_000, ssl: ssl], body_format: :binary) do
        {:ok, {{_version, status, _phrase}, _headers, response}} -> {:ok, status, response}
        {:error, reason} -> {:error, inspect(reason)}
      end
    end
  end

  # ---------------------------------------------------------------------------------------
  # The checks, over a stubbed transport

  @horizon "https://horizon.stub"
  @esplora "https://esplora.stub"
  @core "http://user:secret@core.stub:18443"
  @nist_stub "https://nist.stub"
  @staging "https://staging.stub"

  @doc """
  The failures of the recorder's checks. Every read is answered by a stub built from the
  model's sources (Generator.Replay.World), which raises on any request it does not know, so
  no check reaches the network:

  - the sound item recorded through a Horizon, an Esplora and a NIST stub is exactly the
    replay the model gives it (Generator.Replay.example/1), and so is the same through a
    Bitcoin Core stub;
  - every sound proof's recording holds to the replay form, whose found answers hold every
    field of their kind, and holds every read a verifier makes for it;
  - the Bitcoin tip, read for several entries, is fetched once, and its first answer kept;
  - a Stellar transaction not found leads to the root read, and records not found;
  - an HTTP 503 is unreachable, with the reason `HTTP 503`;
  - a transport failure whose reason is long and holds quotes, backslashes and bytes
    outside ASCII gives a reason that is an ASCII128;
  - given staging's origin, the keyring read at its address, found with its keyring;
  - an identity read with no usable answer leaves its source read no further, and so does a
    regtest identity read that gives mainnet's genesis block;
  - a found answer that lacks a field is unreachable;
  - an entropy block no source knows is not found, through Esplora's 400 and through Bitcoin
    Core's error -5, and a block height Bitcoin Core refuses with error -8 is not found;
  - a Stellar entropy ledger not found leads to the root read;
  - a transaction not found whose ledger lies within STELLAR_INDEX_MARGIN of the latest, or
    below the elder ledger, gets no ledger read;
  - a transport failure whose reason is only spaces gives the reason `no answer`.
  """
  def check(files) do
    world = World.new(Chain.build())

    sound =
      for {"vectors/positive/" <> name, bytes} <- files,
          String.ends_with?(name, ".proof.json"),
          into: %{},
          do: {String.replace_suffix(name, ".proof.json", ""), Parse.decode!(bytes)["proof"]}

    item = Map.fetch!(sound, "item")
    keyring = Map.fetch!(files, "vectors/keyring.test.json")
    stub = fn request -> respond(world, keyring, request) end

    record = fn proof, overrides, options ->
      record(proof, options(stub_with(stub, overrides), options))
    end

    example = Replay.example(files)
    esplora = record.(item, %{}, [])
    core = record.(item, %{}, core: true)

    List.flatten([
      expect("the recorder: the sound item's replay", esplora, example),
      expect("the recorder: the sound item's replay through Bitcoin Core", core, example),
      for {name, proof} <- Enum.sort(sound) do
        replay = record.(proof, %{}, [])
        held = MapSet.new(replay["reads"], & &1["read"])

        [
          Replay.validate(replay, "the recorder: #{name}"),
          for {kind, parameters} <- Replay.reads(proof, Generator.Case.pins()),
              not MapSet.member?(held, Map.put(parameters, "kind", kind)) do
            "the recorder: #{name}'s replay lacks the read #{kind} #{inspect(parameters)}"
          end
        ]
      end,
      tip_once(stub, item),
      transaction_not_found(stub, item),
      http_503(stub, item),
      messy_reason(stub, item),
      keyring_read(stub, item, keyring),
      no_identity(stub, item),
      mainnet_identity(stub, item),
      missing_field(stub, item),
      unknown_block(stub, item),
      height_refused(stub, item),
      entropy_ledger_not_found(stub, item),
      within_margin(stub, item),
      below_elder(stub, item),
      blank_reason(stub, item)
    ])
  end

  defp options(transport, options) do
    bitcoin = if options[:core], do: {:core, @core}, else: {:esplora, @esplora}

    [
      pins: Generator.Case.pins(),
      sources: %{
        {"stellar", "testnet"} => {:horizon, @horizon},
        {"bitcoin", "regtest"} => bitcoin
      },
      nist: @nist_stub,
      transport: transport,
      keyring: options[:keyring]
    ]
  end

  # The stub with some URLs answered otherwise: `overrides` maps a URL to a response or to a
  # function of the stub's own response.
  defp stub_with(stub, overrides) do
    fn request ->
      case Map.fetch(overrides, request.url) do
        {:ok, override} when is_function(override, 1) -> override.(stub.(request))
        {:ok, response} -> response
        :error -> stub.(request)
      end
    end
  end

  defp read_of(replay, read), do: Enum.find(replay["reads"], &(&1["read"] == read))

  defp tip_once(stub, item) do
    counter = make_ref()
    Process.put(counter, 0)

    counting = fn {:ok, 200, body} ->
      calls = Process.get(counter) + 1
      Process.put(counter, calls)
      {:ok, 200, if(calls == 1, do: body, else: "999999")}
    end

    replay =
      record(item, options(stub_with(stub, %{"#{@esplora}/blocks/tip/height" => counting}), []))

    tip = read_of(replay, %{"kind" => "bitcoin_tip", "network" => "regtest"})

    [
      expect("the recorder: the tip is fetched once", Process.get(counter), 1),
      truth(
        "the recorder: the tip's first answer is kept",
        tip["answer"]["value"]["height"] != 999_999
      )
    ]
  end

  defp transaction_not_found(stub, item) do
    hash = item["commitments"]["stellar"]["transaction_hash"]
    url = "#{@horizon}/transactions/#{hash}"
    replay = record(item, options(stub_with(stub, %{url => {:ok, 404, "{}"}}), []))
    read = %{"hash" => hash, "kind" => "stellar_transaction", "network" => "testnet"}

    [
      expect(
        "the recorder: a transaction not found",
        read_of(replay, read)["answer"],
        not_found()
      ),
      truth(
        "the recorder: a transaction not found leads to the root read",
        read_of(replay, %{"kind" => "stellar_root", "network" => "testnet"}) != nil
      ),
      Replay.validate(replay, "the recorder, a transaction not found")
    ]
  end

  defp http_503(stub, item) do
    sequence = item["commitments"]["stellar"]["ledger"]
    url = "#{@horizon}/ledgers/#{sequence}"
    replay = record(item, options(stub_with(stub, %{url => {:ok, 503, "busy"}}), []))
    read = ledger("testnet", sequence)

    expect(
      "the recorder: an HTTP 503",
      read_of(replay, read)["answer"],
      %{"outcome" => "unreachable", "reason" => "HTTP 503"}
    )
  end

  defp messy_reason(stub, item) do
    pulse = item["witnesses"]["entropy_nist"]["payload"]["pulse"]
    url = "#{@nist_stub}/beacon/2.0/chain/#{pulse["chainIndex"]}/pulse/#{pulse["pulseIndex"]}"
    messy = "  a \"quoted\" \\ reason, é, " <> String.duplicate("x", 300)
    replay = record(item, options(stub_with(stub, %{url => {:error, messy}}), []))

    read = %{
      "chainIndex" => pulse["chainIndex"],
      "kind" => "nist_pulse",
      "pulseIndex" => pulse["pulseIndex"]
    }

    answer = read_of(replay, read)["answer"]

    [
      expect("the recorder: an unreachable answer's outcome", answer["outcome"], "unreachable"),
      truth(
        "the recorder: a messy reason is fitted to ASCII128",
        Spec.class?("ASCII128", answer["reason"])
      ),
      truth(
        "the recorder: the fitted reason keeps its start",
        String.starts_with?(answer["reason"], "a ?quoted? ? reason, ??, xxx")
      ),
      Replay.validate(replay, "the recorder, a messy reason")
    ]
  end

  defp keyring_read(stub, item, keyring) do
    replay = record(item, options(stub, keyring: @staging))
    read = %{"kind" => "keyring", "url" => @staging <> "/.well-known/keyring.json"}

    [
      expect(
        "the recorder: staging's keyring read",
        read_of(replay, read)["answer"],
        found(%{"keyring" => Parse.decode!(keyring)})
      ),
      Replay.validate(replay, "the recorder, staging's keyring")
    ]
  end

  defp no_identity(stub, item) do
    replay =
      record(
        item,
        options(stub_with(stub, %{"#{@esplora}/block-height/0" => {:ok, 503, ""}}), [])
      )

    bitcoin =
      for %{"read" => %{"kind" => "bitcoin_" <> _rest} = read} <- replay["reads"], do: read

    [
      expect(
        "the recorder: a source whose identity read gets no answer is read no further",
        bitcoin,
        [%{"kind" => "bitcoin_identity", "network" => "regtest"}]
      ),
      Replay.validate(replay, "the recorder, no identity")
    ]
  end

  defp mainnet_identity(stub, item) do
    mainnet = Replay.production()["bitcoin"]

    replay =
      record(
        item,
        options(stub_with(stub, %{"#{@esplora}/block-height/0" => {:ok, 200, mainnet}}), [])
      )

    bitcoin =
      for %{"read" => %{"kind" => "bitcoin_" <> _rest} = read} <- replay["reads"], do: read

    expect(
      "the recorder: a regtest identity read that gives mainnet's genesis is read no further",
      bitcoin,
      [%{"kind" => "bitcoin_identity", "network" => "regtest"}]
    )
  end

  # The item with its Bitcoin witness naming a block no source knows.
  defp unknown_entropy(item) do
    hash = Bytes.hex(:crypto.hash(:sha256, "a block no source knows"))
    {put_in(item, ["witnesses", "entropy_bitcoin", "payload", "hash"], hash), hash}
  end

  defp unknown_block(stub, item) do
    {proof, hash} = unknown_entropy(item)
    read = %{"hash" => hash, "kind" => "bitcoin_block", "network" => "regtest"}

    for {via, options} <- [{"Esplora", []}, {"Bitcoin Core", [core: true]}] do
      replay = record(proof, options(stub, options))

      [
        expect(
          "the recorder: an entropy block no source knows, through #{via}",
          read_of(replay, read)["answer"],
          not_found()
        ),
        Replay.validate(replay, "the recorder, an unknown block through #{via}")
      ]
    end
  end

  defp height_refused(stub, item) do
    height = item["commitments"]["bitcoin"]["height"]

    refusing = &refuse_height(&1, height, stub)
    replay = record(item, options(refusing, core: true))

    expect(
      "the recorder: a height Bitcoin Core refuses with error -8",
      read_of(replay, at_height("regtest", height))["answer"],
      not_found()
    )
  end

  # The stub, but that Bitcoin Core refuses getblockhash at `height` with error -8.
  defp refuse_height(%{method: :post, body: body} = request, height, stub) do
    if match?(%{"method" => "getblockhash", "params" => [^height]}, Parse.decode!(body)) do
      error = %{"code" => -8, "message" => "Block height out of range"}
      {:ok, 500, JCS.encode(%{"error" => error, "id" => "record", "result" => nil})}
    else
      stub.(request)
    end
  end

  defp refuse_height(request, _height, stub), do: stub.(request)

  defp entropy_ledger_not_found(stub, item) do
    sequence = item["witnesses"]["entropy_stellar"]["payload"]["sequence"]
    url = "#{@horizon}/ledgers/#{sequence}"
    replay = record(item, options(stub_with(stub, %{url => {:ok, 404, "{}"}}), []))

    [
      expect(
        "the recorder: a Stellar entropy ledger not found",
        read_of(replay, ledger("testnet", sequence))["answer"],
        not_found()
      ),
      truth(
        "the recorder: a Stellar entropy ledger not found leads to the root read",
        read_of(replay, %{"kind" => "stellar_root", "network" => "testnet"}) != nil
      )
    ]
  end

  defp within_margin(stub, item) do
    %{"ledger" => sequence, "transaction_hash" => hash} = item["commitments"]["stellar"]

    near = fn {:ok, 200, body} ->
      root = Parse.decode!(body)
      {:ok, 200, JCS.encode(%{root | "history_latest_ledger" => sequence + 1})}
    end

    overrides = %{"#{@horizon}/transactions/#{hash}" => {:ok, 404, "{}"}, "#{@horizon}/" => near}
    replay = record(item, options(stub_with(stub, overrides), []))

    [
      truth(
        "the recorder: a transaction not found within the margin leads to the root read",
        read_of(replay, %{"kind" => "stellar_root", "network" => "testnet"}) != nil
      ),
      truth(
        "the recorder: a transaction not found within the margin gets no ledger read",
        read_of(replay, ledger("testnet", sequence)) == nil
      )
    ]
  end

  # SPEC.md 10.4 item 3's other bound: a transaction not found whose ledger lies below the
  # elder ledger Horizon holds gets no ledger read either.
  defp below_elder(stub, item) do
    %{"ledger" => sequence, "transaction_hash" => hash} = item["commitments"]["stellar"]

    elder = fn {:ok, 200, body} ->
      root = Parse.decode!(body)
      {:ok, 200, JCS.encode(%{root | "history_elder_ledger" => sequence + 1})}
    end

    overrides = %{"#{@horizon}/transactions/#{hash}" => {:ok, 404, "{}"}, "#{@horizon}/" => elder}
    replay = record(item, options(stub_with(stub, overrides), []))

    [
      truth(
        "the recorder: a transaction not found below the elder ledger leads to the root read",
        read_of(replay, %{"kind" => "stellar_root", "network" => "testnet"}) != nil
      ),
      truth(
        "the recorder: a transaction not found below the elder ledger gets no ledger read",
        read_of(replay, ledger("testnet", sequence)) == nil
      )
    ]
  end

  defp blank_reason(stub, item) do
    pulse = item["witnesses"]["entropy_nist"]["payload"]["pulse"]
    url = "#{@nist_stub}/beacon/2.0/chain/#{pulse["chainIndex"]}/pulse/#{pulse["pulseIndex"]}"
    replay = record(item, options(stub_with(stub, %{url => {:error, "   "}}), []))

    read = %{
      "chainIndex" => pulse["chainIndex"],
      "kind" => "nist_pulse",
      "pulseIndex" => pulse["pulseIndex"]
    }

    expect(
      "the recorder: a reason of only spaces",
      read_of(replay, read)["answer"],
      %{"outcome" => "unreachable", "reason" => "no answer"}
    )
  end

  defp missing_field(stub, item) do
    sequence = item["witnesses"]["entropy_stellar"]["payload"]["sequence"]
    url = "#{@horizon}/ledgers/#{sequence}"

    lacking = fn {:ok, 200, body} ->
      {:ok, 200, body |> Parse.decode!() |> Map.delete("closed_at") |> JCS.encode()}
    end

    replay = record(item, options(stub_with(stub, %{url => lacking}), []))

    expect(
      "the recorder: a found answer that lacks a field",
      read_of(replay, ledger("testnet", sequence))["answer"]["outcome"],
      "unreachable"
    )
  end

  # The stub: each service's answers from the model's sources, in each service's own form. A
  # request it does not know raises, so no check can reach the network.
  defp respond(world, keyring, %{method: :get, url: url}) do
    cond do
      rest = under(url, @horizon) -> horizon_stub(world, rest)
      rest = under(url, @esplora) -> esplora_stub(world, rest)
      pulse = under(url, @nist_stub <> "/beacon/2.0/chain/2/pulse/") -> nist_stub(world, pulse)
      url == @staging <> "/.well-known/keyring.json" -> {:ok, 200, keyring}
      true -> raise ArgumentError, "the recorder's stub knows no request for #{url}"
    end
  end

  defp respond(world, _keyring, %{method: :post, url: "http://core.stub:18443"} = request) do
    unless {"authorization", "Basic " <> Base.encode64("user:secret")} in request.headers,
      do:
        raise(ArgumentError, "the recorder's Core stub was called without the URL's credentials")

    %{"method" => method, "params" => params} = Parse.decode!(request.body)

    case core_result(world, method, params) do
      {:ok, value} ->
        {:ok, 200, JCS.encode(%{"error" => nil, "id" => "record", "result" => value})}

      {:error, code} ->
        error = %{"code" => code, "message" => "no"}
        {:ok, 500, JCS.encode(%{"error" => error, "id" => "record", "result" => nil})}
    end
  end

  defp respond(_world, _keyring, request),
    do: raise(ArgumentError, "the recorder's stub knows no request #{inspect(request)}")

  defp horizon_stub(world, "/") do
    ok(%{
      "history_elder_ledger" => world.sources.stellar_elder,
      "history_latest_ledger" => world.sources.stellar_latest,
      "network_passphrase" => "Test SDF Network ; September 2015"
    })
  end

  defp horizon_stub(world, "/transactions/" <> hash) do
    case World.answer(world, "stellar_transaction", %{"hash" => hash, "network" => "testnet"}) do
      %{"outcome" => "found", "value" => tx} ->
        ok(Map.merge(tx, %{"id" => hash, "memo" => Base.encode64(Bytes.unhex(tx["memo"]))}))

      _not_found ->
        {:ok, 404, "{}"}
    end
  end

  defp horizon_stub(world, "/ledgers/" <> sequence) do
    sequence = String.to_integer(sequence)

    world
    |> World.answer("stellar_ledger", %{"network" => "testnet", "sequence" => sequence})
    |> body_of(&Map.put(&1, "sequence", sequence))
  end

  defp esplora_stub(world, "/blocks/tip/height"),
    do: {:ok, 200, Integer.to_string(world.sources.bitcoin_tip)}

  defp esplora_stub(world, "/block-height/" <> height) do
    case block_at(world, String.to_integer(height)) do
      %{"outcome" => "found", "value" => %{"hash" => hash}} -> {:ok, 200, hash}
      _not_found -> {:ok, 404, "Block not found"}
    end
  end

  defp esplora_stub(world, "/block/" <> hash) do
    case block(world, hash) do
      nil ->
        {:ok, 400, "Block not found"}

      block ->
        ok(%{
          "height" => block.height,
          "mediantime" => block.mtp,
          "timestamp" => block.time,
          "tx_count" => block.count
        })
    end
  end

  defp nist_stub(world, pulse) do
    world
    |> World.answer("nist_pulse", %{"chainIndex" => 2, "pulseIndex" => String.to_integer(pulse)})
    |> body_of(&%{"pulse" => &1})
  end

  defp core_result(world, "getblockcount", []), do: {:ok, world.sources.bitcoin_tip}

  defp core_result(world, "getblockhash", [height]) do
    case block_at(world, height) do
      %{"outcome" => "found", "value" => %{"hash" => hash}} -> {:ok, hash}
      _not_found -> {:error, -8}
    end
  end

  defp core_result(world, "getblockheader", [hash]) do
    case block(world, hash) do
      nil ->
        {:error, -5}

      block ->
        {:ok,
         %{
           "height" => block.height,
           "mediantime" => block.mtp,
           "nTx" => block.count,
           "time" => block.time
         }}
    end
  end

  # The rest of `url` after `prefix`, or nil.
  defp under(url, prefix) do
    case String.split(url, prefix, parts: 2) do
      ["", rest] when rest != "" -> rest
      _other -> nil
    end
  end

  defp ok(value), do: {:ok, 200, JCS.encode(value)}

  defp body_of(%{"outcome" => "found", "value" => value}, shape), do: ok(shape.(value))
  defp body_of(_not_found, _shape), do: {:ok, 404, "{}"}

  defp block_at(world, height),
    do:
      World.answer(world, "bitcoin_block_at_height", %{"height" => height, "network" => "regtest"})

  # A regtest block by its hash: its height, median time past, header time and transaction
  # count, or nil.
  defp block(world, hash) do
    case World.answer(world, "bitcoin_block", %{"hash" => hash, "network" => "regtest"}) do
      %{"outcome" => "found", "value" => value} ->
        %{"value" => %{"transaction_count" => count}} = block_at(world, value["height"])

        %{
          height: value["height"],
          mtp: value["median_time_past"],
          time: value["time"],
          count: count
        }

      _not_found ->
        nil
    end
  end
end
