#!/usr/bin/env python3
# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Run the agent-sufficiency test (SPEC.md 7.4) on a model: every session, then a summary.

    python3 sandbox/run-test.py --model MODEL [--sessions 2] [--fixtures all]
        [--parallel 6] [--minutes 90] [--out DIR] [--no-agent]

It runs run-session.py for each fixture and session, several at a time, each in its own
sandboxes, and then writes DIR/summary.md:
- a table of every session: outcome, runs passed, time, turns, tool calls, edits after
  writing, output tokens and the list-price estimate;
- the totals;
- what fixes the run (the agent-test manifest's digest, the constructions text, the image,
  the versions and the model).

A run of the test that gates a text needs two sessions per base fixture on the model it
names, and its record goes to agent-test/results/<date>-<digest>.md (SPEC.md 7.4, Results):
the summary is its draft. It exits 0 only when every session passes.
"""

import argparse
import concurrent.futures
import json
import os
import re
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
FIXTURES = sorted(os.listdir(os.path.join(REPO, "agent-test", "fixtures")))


def label(model):
    # A sandbox name takes letters, digits, hyphens and periods.
    return re.sub(r"[^a-z0-9.-]+", "-", model.lower().removeprefix("claude-")).strip("-")


def session(fixture, n, a, out):
    target = os.path.join(out, f"{fixture}-{n}")
    args = [sys.executable, os.path.join(HERE, "run-session.py"), "--fixture", fixture,
            "--session", f"{label(a.model)}-{n}", "--model", a.model, "--out", target,
            "--minutes", str(a.minutes)]
    if a.no_agent:
        args.append("--no-agent")
    with open(target + ".log", "w") as log:
        subprocess.run(args, stdout=log, stderr=subprocess.STDOUT, check=False)
    try:
        return fixture, n, json.load(open(os.path.join(target, "summary.json")))
    except (OSError, ValueError):
        return fixture, n, {"outcome": "no summary"}


def tool_names(target):
    names = []
    try:
        for line in open(os.path.join(target, "transcript.jsonl"), encoding="utf-8", errors="replace"):
            if line.startswith("{"):
                e = json.loads(line)
                if e.get("type") == "assistant":
                    names += [c["name"] for c in e.get("message", {}).get("content", [])
                              if c.get("type") == "tool_use"]
    except (OSError, ValueError):
        pass
    return names


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", required=True)
    ap.add_argument("--sessions", type=int, default=2)
    ap.add_argument("--fixtures", default="all")
    ap.add_argument("--parallel", type=int, default=6)
    ap.add_argument("--minutes", type=int, default=90)
    ap.add_argument("--out")
    ap.add_argument("--no-agent", action="store_true")
    a = ap.parse_args()

    fixtures = FIXTURES if a.fixtures == "all" else a.fixtures.split(",")
    unknown = sorted(set(fixtures) - set(FIXTURES))
    if unknown:
        sys.exit(f"no such fixture: {', '.join(unknown)}; the fixtures are {', '.join(FIXTURES)}")
    out = os.path.abspath(a.out or os.path.join(
        REPO, "tmp", "agent-test-runs", time.strftime("%Y-%m-%d-%H%M") + "-" + label(a.model)))
    os.makedirs(out, exist_ok=True)
    jobs = [(f, n) for n in range(1, a.sessions + 1) for f in fixtures]
    print(f"{len(jobs)} sessions on {a.model}, {a.parallel} at a time, into {out}")

    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=a.parallel) as pool:
        for f, n, s in pool.map(lambda j: session(j[0], j[1], a, out), jobs):
            results.append((f, n, s))
            print(f"  {f}-{n}: {s.get('outcome')} {(s.get('judge_tail') or [''])[-1]}")

    rows, first = [], next((s for _, _, s in results if s.get("versions")), {})
    tokens = cost = seconds = 0
    for f, n, s in sorted(results):
        r = s.get("result") or {}
        u = r.get("usage") or {}
        names = tool_names(os.path.join(out, f"{f}-{n}"))
        edits = sum(1 for x in names[names.index("Write") + 1:] if x in ("Write", "Edit")) if "Write" in names else "-"
        tokens += u.get("output_tokens") or 0
        cost += r.get("total_cost_usd") or 0
        seconds += s.get("session_seconds") or 0
        runs = (s.get("judge_tail") or ["-"])[-1].replace(" runs pass.", "")
        rows.append(f"| {f} | {n} | {'yes' if s.get('outcome') == 'pass' else 'no: ' + str(s.get('outcome'))} | "
                    f"{runs} | {s.get('session_seconds', '-')} s | {r.get('num_turns') or '-'} | {len(names)} | "
                    f"{edits} | {u.get('output_tokens') or '-'} | {r.get('total_cost_usd') or 0:.2f} |")
    passed = sum(1 for _, _, s in results if s.get("outcome") == "pass")
    fixed = [
        f"- **Model:** `{a.model}`" + (" (no agent: the harness's own script stood in)" if a.no_agent else ""),
        f"- **Agent-test manifest digest:** `{first.get('agent_test_manifest_sha256', '-')}`",
        f"- **Constructions text:** `{', '.join(first.get('constructions') or ['-'])}`",
        f"- **Image:** `{first.get('template', '-')}`",
        f"- **Versions:** {json.dumps(first.get('versions') or {})}",
    ]
    summary = "\n".join([
        f"# Agent-test run on {a.model}, {time.strftime('%Y-%m-%d %H:%M')}", "",
        f"**{passed} of {len(results)} sessions passed.** Each session's files, transcript and "
        "judge output are in its own directory beside this file.", "",
        *fixed, "",
        "| Fixture | Session | Passed | Runs | Time | Turns | Tool calls | Edits after writing | Output tokens | List price (USD) |",
        "|---|---|---|---|---|---|---|---|---|---|",
        *rows, "",
        f"In all: {seconds} s of session time, {tokens:,} output tokens, and a list-price "
        f"estimate of {cost:.2f} USD, drawn on the subscription rather than billed.", "",
    ])
    with open(os.path.join(out, "summary.md"), "w") as fh:
        fh.write(summary)
    print(f"{passed} of {len(results)} sessions passed; the summary is {os.path.join(out, 'summary.md')}")
    sys.exit(0 if passed == len(results) else 1)


if __name__ == "__main__":
    main()
