<!--
Copyright (c) 2026 Truestamp, Inc.
SPDX-License-Identifier: Apache-2.0
-->

# The agent test's sandbox

A session of the agent-sufficiency test (`SPEC.md` 7.4) is a fresh agent in an empty
directory. It has no network, no Truestamp source, no project instructions, no memory and no
skills, and it has Python 3 with `cryptography` and `rfc8785`. This directory builds that
place with [Docker Sandboxes](https://docs.docker.com/ai/sandboxes/) (`sbx`), locally, for
Claude Code signed in with a Claude subscription.

| File | What it is |
|---|---|
| `agent-test.sbxenv.yaml` | The environment file: the built-in `claude` agent, the kit below, the session's directory as the only workspace, skills off, and `lockdown.py` run once the sandbox exists. |
| `kits/agent-test/` | A mixin kit. It installs `cryptography` and `rfc8785` from hash-pinned wheels (`files/home/agent-test/requirements.txt`), and turns off Claude Code's updater, telemetry and error reports. |
| `lockdown.py` | It denies the sandbox every host but `api.anthropic.com` and `platform.claude.com`, and asks the policy engine about every host again to check it did. |
| `smoke.py` | The smoke test below. |
| `judge.sbxenv.yaml` | The judge's environment file: the same sandbox, with the session's directory as the workspace and `agent-test/` mounted read-only beside it. |
| `sbx-python` | A Python for the harness that runs `python3` in a judge sandbox. |
| `run-session.py` | Runs one session end to end: its directory, its sandbox, `claude -p`, the judge, and a record of both. |
| `run-test.py` | Runs the whole test on a model, every fixture's sessions several at a time, and writes a summary (`task agent-test-run`). |
| `preflight/` | `plain.py` and `complete.py`, the harness's known-good script on `cryptography` and `rfc8785` (the library pre-flight below). |

## Running the test again

From the repository root, once the steps under "Before the first run" are done:

    task agent-test-smoke
    task agent-test-run -- --model claude-opus-5-5

The first checks the sandbox itself (the smoke test below). The second runs the whole test,
two sessions per base fixture, six at a time. Each session is `run-session.py`'s, so each
has its own sandboxes and its own directory under `tmp/agent-test-runs/<date>-<model>/`.
It then writes `summary.md` there:
- every session's outcome, runs passed, time, turns, tool calls, edits after writing,
  output tokens and list-price estimate;
- the totals;
- what fixes the run: the agent-test manifest's digest, the constructions text, the image
  and the versions.

It exits 0 only when every session passes.

- **Another model:** `--model` takes any model Claude Code accepts, for example
  `claude-sonnet-5-5`.
- **Fewer sessions:** `--sessions 1 --fixtures 1-item,4-entropy` runs one session each on
  those two fixtures; `--parallel` sets how many run at once.
- **Testing the procedure:** `--no-agent` runs everything but the agent, with the harness's
  own script standing in, and uses no subscription.
- **A run that gates a text** (SPEC.md 7.4, Where it gates) needs two sessions on every
  fixture. Its record goes in `agent-test/results/<date>-<digest>.md` (7.4, Results);
  `summary.md` is its draft. `agent-test/results/2026-09-30-c0d70826….md` is the first.
  A run on another model for information only belongs in a section of its own.

A rerun is the same test in everything but the sessions themselves, so any difference comes
from the model:
- the prompt, fixtures, broken versions, expected lines and judge are pinned by
  `agent-test/MANIFEST.sha256`;
- the image, which brings Python and Claude Code, is pinned by digest in both environment
  files;
- the packages are pinned by hash;
- each sandbox, a session's and a judge's, has 4 CPUs and 4 GB, the `cpus` and `memory`
  defaults of both environment files. The runner passes neither, and every recorded run
  used them.

To move to a newer image, change its digest in both files, run `task agent-test-smoke`, and
let the summary record the new versions.

## Before the first run

- `sbx` installed, and signed in to Docker (`sbx login`).
- Your Claude subscription's login stored in `sbx`. Run `sbx run claude` once and sign in
  with `/login`. `sbx secret ls` then shows `anthropic` as `(oauth configured)`. `sbx`
  keeps the real token on the host; a sandbox only ever holds a placeholder, which its
  proxy swaps for the token on the way out. Never store an Anthropic API key with
  `sbx secret set anthropic`: a session would then bill per use, and `smoke.py` refuses to
  pass.
- `python3` on the host, for `lockdown.py` and `smoke.py`, with its standard library only.

## The smoke test

    python3 sandbox/smoke.py [--keep]

It builds one sandbox over a fresh empty directory, checks it, and removes it (unless
`--keep`). It uses the smallest model, a few cents of subscription usage. Every check must
hold:

1. **The subscription, and no API key anywhere.**
   - `sbx`'s only `anthropic` secret is the OAuth login.
   - `claude auth status` says `claude.ai`.
   - No `ANTHROPIC_API_KEY`, `ANTHROPIC_AUTH_TOKEN` or `CLAUDE_CODE_OAUTH_TOKEN` is set.
   - The credential file holds only the login's placeholders.
   - The session's init event reports `apiKeySource` `none`.
2. **Anthropic only.**
   - `lockdown.py`'s check holds.
   - PyPI, GitHub and an unknown host are refused from inside, and `pip` cannot download.
   - After lockdown, the policy log shows no other host allowed.
3. **The packages:** `cryptography` 50.0.2 and `rfc8785` 0.1.4.
4. **A clean session.** `claude -p` runs in the directory with only Bash, Read, Edit and
   Write, and no MCP servers, skills, commands or plugins of yours, and it reads the
   directory's file.
   - Canaries are planted where Claude Code would find instructions or skills: your
     `CLAUDE.md`, a `CLAUDE.md` and an `AGENTS.md` above the workspace, and a user skill.
     The session never repeats their word.
   - The same session run without the flags does repeat it, so that check could fail.

## How it is built, and why

- **The lockdown is per sandbox.** A rule scoped to one sandbox can only narrow what the
  global policy and the agent's kit allow. A deny of `**` also denies the API, since a deny
  beats every allow. So `lockdown.py` denies each host the sandbox is allowed, but the two
  it keeps. Your global policy and your other sandboxes are left as they are.
- **What it keeps.** `platform.claude.com` stays open with the API because it serves the
  OAuth token endpoint, where the login is renewed if a session outlives its access token.
- **The packages are installed at creation,** while the kit's PyPI hosts are still allowed.
  The lockdown runs once creation ends, before any session starts. So the only traffic
  before it is the install and the built-in kit's own `apt-get update`.
- **`sbx`'s MCP gateway** (`mcp-gateway.docker.internal`) answers outside the policy engine.
  With no MCP server registered with `sbx` (`sbx mcp ls`), it serves nothing. A session also
  runs with `--strict-mcp-config` and no servers.
- **The host's SSH agent.** `sbx` forwards it into every exec, outside the network policy,
  and its only switch, `ssh.agentForwardingEnabled`, is global. So every session and judged
  run unsets `SSH_AUTH_SOCK` first, and `smoke.py` checks that a session's shell finds no
  agent. A script that set the variable again could still reach it. The recorded runs
  leave the setting on, since the agent only signs and never gives out a key, and the
  lockdown lets nothing out but Anthropic's two hosts. A run whose prompt or fixtures are not
  this repository's own should turn it off first, which closes that too.
- **The session's flags.** `sbx`'s built-in kit starts Claude Code with permissions
  bypassed. A session is started by hand instead, with the flags `smoke.py` shows:
  - `--safe-mode`, `--disable-slash-commands` and `--setting-sources ''`, so nothing of
    yours loads;
  - `--strict-mcp-config` with no servers;
  - `--tools` and `--allowedTools` with the four tools;
  - `--permission-mode dontAsk`;
  - `--output-format stream-json --verbose`, which is the transcript.
- **The workspace** is the session's own directory, outside any repository, mounted at the
  same path. The session writes `verify.py` there, so the host reads it directly.

The skills Docker publishes for `sbx` are in `.claude/skills/` for agents working in this
repository (`.claude/skills/SOURCES.md`). None reaches a session.

## Running a session

    python3 sandbox/run-session.py --fixture 1-item --session 1 \
      --model claude-opus-5-5 --out /abs/dir/for/this/session

It does, in order:
1. **The directory.** A fresh one outside any repository gets `PROMPT.md` and the fixture's
   files, and nothing else.
2. **The sandbox.** It is made from `agent-test.sbxenv.yaml`, and `lockdown.py` must hold.
3. **The session.** `claude -p` runs with the prompt's exact words, the text after
   `PROMPT.md`'s license comment, and the clean flags. Its whole transcript streams to
   `transcript.jsonl` on the host, and the session is stopped after `--minutes` (90).
4. **The judge.** The session's `verify.py` is judged in a fresh judge sandbox with
   `--only` its fixture.
5. **The record.** The output directory keeps:
   - the transcript;
   - the session's files as it left them;
   - both network logs and the judge's output;
   - `summary.json`: the outcome, the time, turns, tool calls and token usage, and what
     fixes the run (the agent-test manifest's digest, the constructions text, the
     image's digest, and the Claude Code, Python and package versions).

   Both sandboxes are removed unless `--keep`.

`--no-agent` tests the runner itself, with the harness's own known-good script standing in
for the session's.

## Judging a session

A session's `verify.py` is judged inside a sandbox, never on the host, under the Python and
packages the session had. The harness runs on the host as always; only Python runs inside.

    sbx env create --auto-approve --name ts-judge-NAME \
      --env-arg workspace=/abs/session/dir sandbox/judge.sbxenv.yaml
    export SBX_JUDGE_SANDBOX=ts-judge-NAME
    sandbox/sbx-python -c pass     # starts the sandbox before the parallel runs
    elixir agent-test/check.exs /abs/session/dir/verify.py --only FIXTURE \
      --python "$PWD/sandbox/sbx-python"
    sbx rm --force ts-judge-NAME

- **The sandbox.** `judge.sbxenv.yaml` is `agent-test.sbxenv.yaml` with one more mount:
  `agent-test/` (the `agent_test` argument, `../agent-test` from the file unless given),
  read-only. Both mounts are at their host paths, because the harness gives each run the
  absolute paths of its files and of `verify.py`. The kit and `lockdown.py` are the same, so
  the sandbox reaches only the Anthropic API while it judges, and no agent runs in it.
  `sbx` forwards the host's SSH agent into every exec, and its only switch
  (`ssh.agentForwardingEnabled`) is global, so the wrapper unsets `SSH_AUTH_SOCK` for each
  run; a script that set it again could still reach the agent's socket.
- **`sbx-python`** runs `sbx exec -w DIR SANDBOX python3 ARGS...`, with the sandbox named by
  `SBX_JUDGE_SANDBOX` and `DIR` the `agent-test/` beside it (`SBX_JUDGE_WORKDIR` to change
  it), and exits with python's exit code. Standard output and error pass through; standard
  input does not, and the harness closes it anyway. The harness's package check runs through
  it too, so it asks the sandbox's Python; an unknown sandbox reads as a Python without the
  packages, and the harness stops.
- **A run that never ends.** The harness stops a run at its 60 seconds with `kill -9` of the
  Python it was given. Killing `sbx exec` on the host, by any signal, does not stop the
  command it started: that runs on to its end in the sandbox. So `sbx-python` notes the
  run's process group in the sandbox and starts a watcher on the host. When `sbx-python` is
  killed before the run ends, the watcher kills that process group with a second
  `sbx exec`, and the `sbx exec` left on the host. The sandbox's `timeout` also kills a run
  after `SBX_JUDGE_LIMIT` seconds (300). Checked with the harness's own never-ends check
  (a script that sleeps 600 seconds, stopped at 1000 ms): it fails as "no exit within 1000
  ms", and within a few seconds nothing of it is left, in the sandbox or on the host.
- **Time.** `sbx exec` costs about 0.45 s a call; a run of the known-good script takes
  0.03 s of Python in the sandbox and about 0.5 s through `sbx-python`. The harness runs 16
  at once on this machine, so all 758 runs take about 2 minutes (115 to 123 s over four
  judgings), and one fixture's 91 to 233 runs 15 to 40 s.
- **Proved** with the standard-library known-good script, `agent-test/selftest/verify.py`,
  copied into a scratch session directory: 758 of 758 runs pass, as on the host. While it
  judged, `lockdown.py` held for the sandbox, and from inside PyPI, files.pythonhosted.org,
  GitHub and example.com answered 403 and `pip download` found nothing.
- **P9** judges each session this way: once a session ends, a fresh `ts-judge-` sandbox
  over its directory, the harness with `--only` its fixture, the log kept with the
  results, and the sandbox removed. The session's own sandbox is not reused.
- The judge mounts `expected/` with the rest of `agent-test/`, so a `verify.py` could read
  it, as it could on the host. The prompt tells a session its script reads nothing but its
  arguments; a transcript shows whether one did otherwise.

## Library pre-flight

No verifier built on `cryptography` and `rfc8785`, what a session is promised, had been
judged before. `preflight/plain.py` is the known-good script with only its primitives
changed: Ed25519 through `Ed25519PublicKey.from_public_bytes(...).verify` and JCS through
`rfc8785.dumps`, with none of its own key checks, s check, cofactorless equation, number
formatting or key sorting. `preflight/complete.py` is `plain.py` with the key checks added
back. Each was judged over every fixture in a judge sandbox (`cryptography` 50.0.2 on
OpenSSL 4.0.3, `rfc8785` 0.1.4, Python 3.14.4).

| Script | Runs passed |
|---|---|
| `agent-test/selftest/verify.py` (standard library) | 758 of 758 |
| `preflight/plain.py` | 757 of 758 |
| `preflight/complete.py` | 758 of 758 |

- **The one failure of `plain.py`** is `5-block/block.key_checks.block`: it draws a window
  (`submitted_before 2026-09-26T01:47:15Z`) where both edges must be `none`. The mutant's
  `/block` genesis event introduces the order-8 key `26e8958f...fc05`, and no library looks
  at it: the key is never used to verify, and `from_public_bytes` checks only its length.
  The text decides it in `key_event` ("genesis, rotation and emergency_rotation introduce
  public_key, which passes the key checks") and in `signature` ("the key checks refuse a
  key whose y is at or above 2^255 - 19, and every encoding of a point of small order
  (order dividing 8)"). A fresh agent reading the text would know to add the check, since
  it is named and no library call reaches that key. What the text does not give is the list
  of small-order encodings: an agent must derive them, or check that 8 times the point is
  the identity with arithmetic of its own. The mutant's key is the best-known one.
- **The library also takes small-order keys when it verifies.** `cryptography` accepts every
  small-order encoding and y = p + 1 in `from_public_bytes`, and its `verify` accepts a
  forged signature under each of the 14 small-order encodings (the 10 with y below p and the
  4 with y at or above p), given a message whose hash is a multiple of the point's order.
  No mutant tests
  that (step 3 refuses such a `signature.public_key` before any value is computed, SPEC.md
  7.4), but `complete.py` applies the key checks to every key it verifies with, as the
  text's strict Ed25519 requires.
- **What the libraries keep themselves.** `cryptography` refuses s + L (`signature_s`) and
  uses the cofactorless equation (`signature_cofactor`): `plain.py` passes all 27 signature
  mutants. `rfc8785.dumps` gives the known-good script's bytes for every one of the 1031
  JSON files under `fixtures/` and `mutants/`, including fixture 1's `5e-324`, `1e-7`,
  `37.7749` and its UTF-16 key order (U+1F600 before U+FF5A), and it refuses integers above
  2^53 - 1, NaN and lone surrogates. So no JCS difference fails a run.

