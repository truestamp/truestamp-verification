#!/usr/bin/env python3
# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0
"""The agent-test harness's known-good script, on the libraries a session is promised.

A library pre-flight for the agent-sufficiency test (SPEC.md 7.4), and NOT an answer key: no
session receives it. It is agent-test/selftest/verify.py with only its primitives changed:
Ed25519 verification is cryptography's (Ed25519PublicKey.from_public_bytes(...).verify),
and JCS is rfc8785.dumps. SHA-256 is still hashlib's and base64 the standard library's.

This is plain.py: it trusts the libraries. It has none of the known-good script's own key
checks, s-below-L check or cofactorless equation, and none of its own number formatting or
key sorting. Run it only inside a judge sandbox (sandbox/judge.sbxenv.yaml), whose Python
has cryptography 50.0.2 and rfc8785 0.1.4:

    python3 plain.py <proof> <keyring> <replay> [<constructions>]
"""

import base64
import hashlib
import json
import re
import sys
from datetime import datetime, timezone

import rfc8785
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

# The self-test rewrites this line to break the script on purpose; as written, it is right.
BREAK = ""

MAX_INTEGER = 2**53 - 1
FINALITY = 10
MARGIN = 60
MAX_TOTAL_TXS = 16666
EMPTY_ROOT = hashlib.sha256(b"").hexdigest()
PINS = {"stellar": "testnet", "bitcoin": "regtest"}
PRODUCTION = {
    "stellar": ("network_passphrase", "Public Global Stellar Network ; September 2015"),
    "bitcoin": ("hash", "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"),
}
PREFIX = {
    "claims_hash": 0x10,
    "item_hash": 0x11,
    "entropy_hash": 0x20,
    "observation_hash": 0x21,
    "genesis": 0x30,
    "block_hash": 0x31,
    "epoch_hash": 0x40,
    "proof_hash": 0x50,
    "key_id": 0x60,
    "handover": 0x62,
}


class Refused(Exception):
    pass


# --- JSON and JCS ------------------------------------------------------------------------


def number(text):
    value = float(text)
    if value != value or value in (float("inf"), float("-inf")):
        raise Refused("a number that overflows")
    if value.is_integer() and abs(value) <= MAX_INTEGER:
        return int(value)
    if value.is_integer() and abs(value) < 1e21:
        raise Refused("an integer above MAX_INTEGER")
    return value


def unique(pairs):
    names = [name for name, _value in pairs]
    if len(names) != len(set(names)):
        raise Refused("a duplicate member name")
    return dict(pairs)


def read_json(path):
    with open(path, "rb") as file:
        text = file.read().decode("utf-8")
    return json.loads(
        text,
        object_pairs_hook=unique,
        parse_float=number,
        parse_int=number,
        parse_constant=lambda name: (_ for _ in ()).throw(Refused(name)),
    )


def jcs(value):
    return rfc8785.dumps(value)


def record_hash(kind, record):
    return hashlib.sha256(bytes([PREFIX[kind]]) + jcs(record)).hexdigest()


def sha256d(data):
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def get(value, pointer):
    for name in pointer.split("/")[1:]:
        if isinstance(value, list):
            value = value[int(name)] if name.isdigit() and int(name) < len(value) else None
        elif isinstance(value, dict):
            value = value.get(name)
        else:
            return None
    return value


def b64u(text, octets):
    classes = {32: r"[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]", 64: r"[A-Za-z0-9_-]{85}[AQgw]"}
    if not isinstance(text, str) or not re.fullmatch(classes[octets], text):
        raise Refused("not canonical base64url")
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def time_text(unix):
    return datetime.fromtimestamp(unix, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def ms(text):
    match = re.fullmatch(r"(\d{4})-(\d\d)-(\d\d)T(\d\d):(\d\d):(\d\d)(\.(\d{3}))?Z", text)
    if not match:
        raise Refused("not a time")
    y, mo, d, h, mi, s = (int(match.group(i)) for i in range(1, 7))
    moment = datetime(y, mo, d, h, mi, s, tzinfo=timezone.utc)
    return int(moment.timestamp()) * 1000 + int(match.group(8) or 0)


def same_bytes(a, b):
    try:
        return bytes.fromhex(a) == bytes.fromhex(b)
    except (TypeError, ValueError):
        return False


# --- Ed25519, from cryptography ----------------------------------------------------------


def public_key(key):
    try:
        return Ed25519PublicKey.from_public_bytes(key)
    except ValueError:
        return None


def event_key_ok(key):
    return public_key(key) is not None


def verify(key, message, signature):
    k = public_key(key)
    if k is None:
        return False
    try:
        k.verify(signature, message)
        return True
    except InvalidSignature:
        return False


def key_id(key):
    return hashlib.sha256(bytes([PREFIX["key_id"]]) + key).digest()[:4].hex()


# --- Merkle (SPEC.md 5.3) ----------------------------------------------------------------


def merkle_path(start, proof, flip=False):
    """The root the walk reaches, or None; with `flip`, its first step on the other side."""
    index, size, path = proof["leaf_index"], proof["tree_size"], proof["path"]
    if (index >= size and BREAK != "range") or len(path) > 32:
        return None
    fn, sn = index, size - 1
    r = hashlib.sha256(b"\x00" + bytes.fromhex(start)).digest()
    for step, node in enumerate(path):
        p = bytes.fromhex(node)
        if sn == 0:
            return None
        if bool(fn & 1 or fn == sn) != (flip and step == 0):
            r = hashlib.sha256(b"\x01" + p + r).digest()
            while fn & 1 == 0 and fn != 0:
                fn, sn = fn >> 1, sn >> 1
        else:
            r = hashlib.sha256(b"\x01" + r + p).digest()
        fn, sn = fn >> 1, sn >> 1
    return r.hex() if sn == 0 else None


# --- Bitcoin (SPEC.md 10.2 step 9 (d)) ---------------------------------------------------


def compact(data, i):
    if i >= len(data):
        raise Refused("short")
    first = data[i]
    if first < 0xFD:
        return first, i + 1
    width = {0xFD: 2, 0xFE: 4, 0xFF: 8}[first]
    if i + 1 + width > len(data):
        raise Refused("short")
    value = int.from_bytes(data[i + 1 : i + 1 + width], "little")
    if value < {2: 0xFD, 4: 0x10000, 8: 0x100000000}[width]:
        raise Refused("a compact size not in its shortest form")
    return value, i + 1 + width


def take(data, i, count):
    if i + count > len(data):
        raise Refused("short")
    return data[i : i + count], i + count


def op_return(raw):
    """The 32 bytes the one OP_RETURN of a well-formed raw transaction pushes, or None."""
    try:
        i = 4
        witnessed = BREAK == "witness_data" and raw[4:6] == b"\x00\x01"
        if witnessed:
            i = 6
        inputs, i = compact(raw, i)
        if inputs == 0 and BREAK != "no_input":
            return None
        for _ in range(inputs):
            _outpoint, i = take(raw, i, 36)
            size, i = compact(raw, i)
            _script, i = take(raw, i, size)
            _sequence, i = take(raw, i, 4)
        outputs, i = compact(raw, i)
        scripts = []
        for _ in range(outputs):
            _value, i = take(raw, i, 8)
            size, i = compact(raw, i)
            script, i = take(raw, i, size)
            scripts.append(script)
        if witnessed:
            for _ in range(inputs):
                items, i = compact(raw, i)
                for _ in range(items):
                    size, i = compact(raw, i)
                    _item, i = take(raw, i, size)
        _lock, i = take(raw, i, 4)
        if i != len(raw) or len(raw) == 64:
            return None
        returns = [script for script in scripts if script[:1] == b"\x6a"]
        if BREAK == "two_op_returns":
            returns = returns[:1]
        if len(returns) != 1 or len(returns[0]) != 34 or returns[0][1] != 0x20:
            return None
        return returns[0][2:]
    except Refused:
        return None


def merkleblock(data):
    """(header, total, matched) for a well-formed merkleblock, or None."""
    try:
        header, i = take(data, 0, 80)
        total_bytes, i = take(data, i, 4)
        total = int.from_bytes(total_bytes, "little")
        if not 1 <= total <= MAX_TOTAL_TXS:
            return None
        count, i = compact(data, i)
        hashes = []
        for _ in range(count):
            node, i = take(data, i, 32)
            hashes.append(node)
        flag_count, i = compact(data, i)
        flags, i = take(data, i, flag_count)
        if i != len(data) or count > total:
            return None
    except Refused:
        return None
    bits = [(flags[j // 8] >> (j % 8)) & 1 for j in range(len(flags) * 8)]
    state = {"bits": 0, "hashes": 0, "matched": []}

    def width(height):
        return (total + (1 << height) - 1) >> height

    def walk(height, position):
        if state["bits"] >= len(bits):
            raise Refused("flags used up")
        flag = bits[state["bits"]]
        state["bits"] += 1
        if height == 0 or not flag:
            if state["hashes"] >= len(hashes):
                raise Refused("hashes used up")
            node = hashes[state["hashes"]]
            state["hashes"] += 1
            if height == 0 and flag:
                state["matched"].append(node)
            return node
        left = walk(height - 1, position * 2)
        if position * 2 + 1 < width(height - 1):
            right = walk(height - 1, position * 2 + 1)
            if right == left:
                raise Refused("a duplicate sibling pair")
        else:
            right = left
        return sha256d(left + right)

    height = 0
    while width(height) > 1:
        height += 1
    try:
        root = walk(height, 0)
    except Refused:
        return None
    used = state["bits"]
    if state["hashes"] != len(hashes) or (used + 7) // 8 != len(flags):
        return None
    if any(bits[used:]):
        return None
    if len(state["matched"]) != 1 or root != header[36:68]:
        return None
    n = int.from_bytes(header[72:76], "little")
    e, w = n >> 24, n & 0x007FFFFF
    if e <= 3:
        w >>= 8 * (3 - e)
    negative = w != 0 and n & 0x00800000
    overflow = w != 0 and (e > 34 or (w > 0xFF and e > 33) or (w > 0xFFFF and e > 32))
    target = w if e <= 3 else w * 256 ** (e - 3)
    missed = negative or overflow or target == 0 or int.from_bytes(sha256d(header), "little") > target
    if missed and BREAK != "nbits":
        return None
    return header, total, state["matched"][0]


# --- The verifier ------------------------------------------------------------------------


class Run:
    def __init__(self, proof, k):
        self.proof = proof
        self.k = k
        self.lines = []
        self.failed = False

    def fail(self, holds):
        if not holds:
            self.failed = True

    def value(self, pointer, computed, rule=None):
        """A hash line: the value computed for the member at `pointer`, compared with it."""
        carried = get(self.proof, pointer)
        if BREAK == "uppercase" and isinstance(carried, str) and re.fullmatch("[0-9A-Fa-f]{64}", carried):
            carried = carried.lower()
        if BREAK != "nogate" and not (rule is not None and BREAK == rule):
            self.fail(computed is not None and computed == carried)
        shown = carried if BREAK == "echo" else computed
        self.lines.append("/proof%s %s" % (pointer, "none" if shown is None else shown))


def derive(run):
    proof = run.proof
    kind = proof["type"]
    heights = {}

    if kind == "item":
        run.value("/subject/record/claims_hash", record_hash("claims_hash", proof["subject"]["claims"]))
        run.value("/subject/item_hash", record_hash("item_hash", proof["subject"]["record"]))
    elif kind.startswith("entropy_"):
        run.value("/subject/record/entropy_hash", record_hash("entropy_hash", proof["subject"]["entropy"]))
        run.value("/subject/observation_hash", record_hash("observation_hash", proof["subject"]["record"]))
    for name in sorted(proof.get("observations", {})):
        o = "/observations/" + name
        run.value(o + "/record/entropy_hash", record_hash("entropy_hash", get(proof, o + "/entropy")))
        run.value(o + "/observation_hash", record_hash("observation_hash", get(proof, o + "/record")))

    block_hashes = {}
    for b in ("/block", "/witnesses/block", "/signing_key_event/block"):
        node = get(proof, b)
        if node is None:
            continue
        record = node["record"]
        block_hashes[b] = record_hash("block_hash", record)
        run.value(b + "/block_hash", block_hashes[b], "carried_start")
        if BREAK == "carried_start":
            block_hashes[b] = node["block_hash"]
        run.fail(BREAK == "empty_root" or (record["leaf_count"] == 0) == (record["merkle_root"] == EMPTY_ROOT))
        heights[b] = record["height"]
        if "genesis" in record["metadata"]:
            heights[b] = 0
            run.value(b + "/record/height", 0, "genesis_height")
            run.value(b + "/record/previous_block_hash", record_hash("genesis", record["metadata"]["genesis"]))
        event = record["metadata"].get("key_event")
        if event is not None:
            key_event(run, b, record, event)

    for base, b in (("/commitments", "/block"), ("/signing_key_event/commitments", "/signing_key_event/block")):
        for chain in sorted(get(proof, base) or {}):
            n = "%s/%s" % (base, chain)
            entry = get(proof, n)
            epoch_hash = record_hash("epoch_hash", entry["epoch"]["record"])
            run.value(n + "/epoch/epoch_hash", epoch_hash)
            inclusion(run, block_hashes.get(b), n + "/inclusion_proof", n + "/epoch/record")
            run.fail(entry["network"] == PINS[chain])
            if chain == "bitcoin":
                bitcoin(run, n, entry, epoch_hash)

    if kind == "item":
        inclusion(run, record_hash("item_hash", proof["subject"]["record"]), "/subject/inclusion_proof", "/block/record")
        for name in sorted(proof["subject"]["record"]["witness_hashes"]):
            if name == "block":
                hash = block_hashes.get("/witnesses/block")
            else:
                hash = record_hash("entropy_hash", get(proof, "/witnesses/" + name))
            run.value("/subject/record/witness_hashes/" + name, hash)
        run.fail(BREAK == "witness_height" or heights["/witnesses/block"] < heights["/block"])
        names = set(proof["subject"]["record"]["witness_hashes"])
        run.fail(BREAK == "witness_names" or names == set(proof["witnesses"]))
    elif kind.startswith("entropy_"):
        inclusion(run, record_hash("observation_hash", proof["subject"]["record"]), "/subject/inclusion_proof", "/block/record")
    for name in sorted(proof.get("observations", {})):
        o = "/observations/" + name
        inclusion(run, record_hash("observation_hash", get(proof, o + "/record")), o + "/inclusion_proof", "/block/record")

    event = get(proof, "/signing_key_event/block/record/metadata/key_event")
    if event is not None:
        run.fail(BREAK == "link_key" or (b64u(event.get("public_key"), 32) == run.k if "public_key" in event else False))

    for pointer in entropy_pointers(proof):
        entropy = get(proof, pointer)
        if entropy["source"] != "nist":
            run.fail(entropy["network"] == PINS[entropy["source"]])
        top = get(proof, "/commitments/" + entropy["source"])
        if top is not None and entropy["source"] == "stellar" and top["network"] == entropy["network"]:
            run.fail(BREAK == "chain_order" or entropy["payload"]["sequence"] < top["ledger"])
        if top is not None and entropy["source"] == "bitcoin" and top["network"] == entropy["network"]:
            run.fail(BREAK == "chain_order" or entropy["payload"]["height"] <= top["height"])
    for b in ("/block", "/witnesses/block", "/signing_key_event/block"):
        genesis = get(proof, b + "/record/metadata/genesis/bitcoin")
        if genesis is not None:
            run.fail(genesis["network"] == PINS["bitcoin"])
    return block_hashes


def key_event(run, b, record, event):
    e = b + "/record/metadata/key_event"
    kind = event["type"]
    if kind in ("genesis", "rotation", "emergency_rotation"):
        public = b64u(event["public_key"], 32)
        run.fail(event_key_ok(public))
        run.value(e + "/key_id", key_id(public), "key_ids")
        run.value(b + "/record/signing_key_id", key_id(public), "key_ids")
    if kind in ("rotation", "emergency_rotation"):
        previous = b64u(event["previous_public_key"], 32)
        run.value(e + "/previous_key_id", key_id(previous), "key_ids")
        run.value(e + "/height", record["height"], "handover_fields")
        run.value(e + "/previous_block_hash", record["previous_block_hash"], "handover_fields")
        if "handover_signature" in event:
            unsigned = {name: value for name, value in event.items() if name != "handover_signature"}
            message = bytes.fromhex(record_hash("handover", unsigned))
            valid = verify(previous, message, b64u(event["handover_signature"], 64))
            run.fail(valid or BREAK == "handover")
            run.lines.append("/proof%s/handover_signature %s" % (e, "valid" if valid else "invalid"))
        elif kind == "rotation":
            run.fail(BREAK == "handover_required")
    if kind == "prerotation":
        run.value(b + "/record/signing_key_id", event["active_key_id"], "key_ids")


def inclusion(run, leaf, q, record):
    proof = get(run.proof, q)
    root = merkle_path(leaf, proof) if leaf is not None else None
    carried = get(run.proof, record + "/merkle_root")
    if BREAK == "side" and leaf is not None and root != carried and merkle_path(leaf, proof, True) == carried:
        root = carried
    run.value(record + "/merkle_root", root)
    run.value(q + "/tree_size", get(run.proof, record + "/leaf_count"), "tree_size")


def bitcoin(run, n, entry, epoch_hash):
    raw = bytes.fromhex(entry["raw_transaction"])
    pushed = op_return(raw)
    run.fail(pushed is not None and (pushed.hex() == epoch_hash or BREAK == "op_return"))
    txid = sha256d(raw)
    run.value(n + "/transaction_hash", txid[::-1].hex())
    txoutproof = bytes.fromhex(entry["txoutproof"])
    parsed = merkleblock(txoutproof)
    run.fail(parsed is not None)
    if parsed is not None:
        run.fail(parsed[2] == txid or BREAK == "partial_tree")
    if len(txoutproof) >= 80:
        header = txoutproof[:80]
        run.value(n + "/header_hash", sha256d(header)[::-1].hex())
        run.value(n + "/header_merkle_root", header[36:68][::-1].hex())
        run.value(n + "/header_time", time_text(int.from_bytes(header[68:72], "little")), "header_time")


def entropy_pointers(proof):
    pointers = []
    if get(proof, "/subject/entropy") is not None:
        pointers.append("/subject/entropy")
    pointers += ["/witnesses/" + n for n in sorted(proof.get("witnesses", {})) if n != "block"]
    pointers += ["/observations/%s/entropy" % n for n in sorted(proof.get("observations", {}))]
    return sorted(pointers)


# --- The reads (SPEC.md 10.4) and the window (SPEC.md 11) ---------------------------------


class Replay:
    def __init__(self, path):
        self.answers = {}
        for record in read_json(path)["reads"]:
            self.answers[json.dumps(record["read"], sort_keys=True)] = record["answer"]

    def ask(self, **read):
        key = json.dumps(read, sort_keys=True)
        if key not in self.answers:
            raise Refused("the replay holds no answer to %s" % key)
        return self.answers[key]

    def usable(self, chain):
        answer = self.ask(kind=chain + "_identity", network=PINS[chain])
        field, production = PRODUCTION[chain]
        return answer["outcome"] == "found" and answer["value"][field] != production


def chain_entry(replay, run, entry, chain, top, block_hash):
    """('pass', candidate or None), ('fail', None) or ('skip', None)."""
    if not replay.usable(chain):
        return "skip", None
    network = PINS[chain]
    if chain == "stellar":
        answer = replay.ask(kind="stellar_transaction", network=network, hash=entry["transaction_hash"])
        if answer["outcome"] == "found":
            tx = answer["value"]
            epoch_hash = record_hash("epoch_hash", entry["epoch"]["record"])
            memo_ok = BREAK == "memo" or same_bytes(tx.get("memo"), epoch_hash)
            rest_ok = BREAK == "stellar_tx" or (tx["successful"] is True and tx["memo_type"] == "hash" and tx["ledger"] == entry["ledger"])
            if not (memo_ok and rest_ok):
                return "fail", None
            if not top:
                return "pass", None
            ledger = replay.ask(kind="stellar_ledger", network=network, sequence=entry["ledger"])
            if ledger["outcome"] != "found":
                return "skip", None
            return "pass", ledger["value"]["closed_at"]
        if answer["outcome"] == "not_found":
            root = replay.ask(kind="stellar_root", network=network)
            if root["outcome"] != "found":
                return "skip", None
            latest, elder = root["value"]["latest"], root["value"]["elder"]
            if entry["ledger"] > latest - MARGIN or entry["ledger"] < elder:
                return "skip", None
            ledger = replay.ask(kind="stellar_ledger", network=network, sequence=entry["ledger"])
            return ("fail", None) if ledger["outcome"] == "found" else ("skip", None)
        return "skip", None
    parsed = merkleblock(bytes.fromhex(entry["txoutproof"]))
    header_hash = sha256d(parsed[0])[::-1].hex()
    status, block = best_chain(replay, entry["height"])
    if status != "pass":
        return status, None
    hash_ok = BREAK == "header_at_height" or same_bytes(block["hash"], header_hash)
    count_ok = BREAK == "transaction_count" or block["transaction_count"] == parsed[1]
    if not (hash_ok and count_ok):
        return "fail", None
    if not top:
        return "pass", None
    later = replay.ask(kind="bitcoin_block_at_height", network=network, height=entry["height"] + FINALITY)
    if later["outcome"] != "found":
        return "skip", None
    return "pass", time_text(later["value"]["median_time_past"])


def best_chain(replay, height):
    tip = replay.ask(kind="bitcoin_tip", network=PINS["bitcoin"])
    if tip["outcome"] != "found" or height > tip["value"]["height"] or tip["value"]["height"] < height + FINALITY:
        return "skip", None
    block = replay.ask(kind="bitcoin_block_at_height", network=PINS["bitcoin"], height=height)
    return ("pass", block["value"]) if block["outcome"] == "found" else ("skip", None)


def source(replay, entropy):
    """('pass', candidate), ('fail', None) or ('skip', None)."""
    kind = entropy["source"]
    payload = entropy["payload"]
    if kind == "nist":
        pulse = payload["pulse"]
        answer = replay.ask(kind="nist_pulse", chainIndex=pulse["chainIndex"], pulseIndex=pulse["pulseIndex"])
        if answer["outcome"] != "found":
            return "skip", None
        read = answer["value"]
        equal = BREAK == "payload" or (same_bytes(read["outputValue"], pulse["outputValue"]) and ms(read["timeStamp"]) == ms(pulse["timeStamp"]))
        return ("pass", read["timeStamp"]) if equal else ("fail", None)
    if not replay.usable(kind):
        return "skip", None
    if kind == "stellar":
        answer = replay.ask(kind="stellar_ledger", network=PINS["stellar"], sequence=payload["sequence"])
        if answer["outcome"] != "found":
            return "skip", None
        read = answer["value"]
        equal = BREAK == "payload" or (same_bytes(read["hash"], payload["hash"]) and ms(read["closed_at"]) == ms(payload["closed_at"]))
        return ("pass", read["closed_at"]) if equal else ("fail", None)
    answer = replay.ask(kind="bitcoin_block", network=PINS["bitcoin"], hash=payload["hash"])
    if answer["outcome"] != "found":
        return "skip", None
    read = answer["value"]
    equal = BREAK == "payload" or (read["height"] == payload["height"] and read["time"] == payload["time"])
    return ("pass", time_text(read["median_time_past"])) if equal else ("fail", None)


def window(replay, run, block_hashes):
    proof = run.proof
    befores, afters = [], []
    for base, b in (("/commitments", "/block"), ("/signing_key_event/commitments", "/signing_key_event/block")):
        for chain in sorted(get(proof, base) or {}):
            if BREAK == "ske_chain" and base != "/commitments":
                continue
            status, candidate = chain_entry(replay, run, get(proof, "%s/%s" % (base, chain)), chain, base == "/commitments", block_hashes.get(b))
            run.fail(status != "fail")
            if candidate is not None:
                befores.append(candidate)
    for b in ("/block", "/witnesses/block", "/signing_key_event/block"):
        genesis = get(proof, b + "/record/metadata/genesis/bitcoin")
        if genesis is not None and replay.usable("bitcoin"):
            status, block = best_chain(replay, genesis["height"])
            run.fail(status != "pass" or BREAK == "genesis_read" or same_bytes(block["hash"], genesis["header_hash"]))
    for pointer in entropy_pointers(proof):
        status, candidate = source(replay, get(proof, pointer))
        run.fail(status != "fail")
        if candidate is not None:
            afters.append(candidate)
    after = max(afters, key=ms) if afters else None
    before = min(befores, key=ms) if befores else None
    if after is not None and before is not None:
        run.fail(ms(after) <= ms(before))
    return after, before


def main(argv):
    proof_path, keyring_path, replay_path = argv[1], argv[2], argv[3]
    document = read_json(proof_path)
    proof, signature = document["proof"], document["signature"]
    k = b64u(signature["public_key"], 32)
    v = b64u(signature["value"], 64)
    run = Run(proof, k)

    environment = proof.get("environment", "prod")
    run.fail(environment == "test" or BREAK == "environment")
    keys = [b64u(key["public_key"], 32) for key in read_json(keyring_path)["keys"]]
    run.fail(k in keys or BREAK == "keyring")
    constructions = proof.get("constructions")
    if isinstance(constructions, str):
        if len(argv) < 5 or not constructions.endswith("/" + argv[4].rsplit("/", 1)[-1]):
            raise Refused("a proof in reference mode, with no file of its text")
        with open(argv[4], "rb") as file:
            digest = hashlib.sha256(file.read()).hexdigest()
        run.fail(constructions.endswith("constructions-%s.json" % digest))
    digest = hashlib.sha256(bytes([PREFIX["proof_hash"]]) + jcs(proof)).digest()
    valid = verify(k, digest, v)
    run.fail(valid or BREAK == "signature")
    run.fail(proof["format"] == "truestamp-proof" and proof["version"] == 1)

    block_hashes = derive(run)
    after = before = None
    if not run.failed:
        after, before = window(Replay(replay_path), run, block_hashes)
    if run.failed:
        after = before = None

    if BREAK == "window_second" and before is not None:
        before = time_text(ms(before) // 1000 + 1)
    if BREAK == "instant_format" and before is not None:
        before = before.replace("Z", "+00:00")

    lines = run.lines + [
        "digest " + digest.hex(),
        "/signature/value " + ("valid" if valid else "invalid"),
        "keyring " + ("match" if k in keys else "no-match"),
        "environment " + environment,
        "submitted_after " + (after or "none"),
        "submitted_before " + (before or "none"),
    ]
    if BREAK == "instant_format":
        lines = [line.replace("Z", "+00:00") if "/header_time " in line else line for line in lines]
    if BREAK == "extra":
        lines.append("an extra line")
    for line in sorted(set(lines)):
        print(line)
    return 1 if BREAK == "exit" else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
