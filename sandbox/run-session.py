#!/usr/bin/env python3
# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Run one session of the agent-sufficiency test (SPEC.md 7.4) in a sandbox, then judge it.

    python3 sandbox/run-session.py --fixture 1-item --session 1 --model MODEL --out DIR
        [--minutes 90] [--keep] [--no-agent]

1. A fresh directory outside any repository gets PROMPT.md and the fixture's files, and
   nothing else.
2. A sandbox is made over it from agent-test.sbxenv.yaml; lockdown.py runs before anything
   else and must hold.
3. `claude -p` runs inside with the prompt's exact words and the clean flags, and its whole
   transcript streams to DIR/transcript.jsonl on the host. It is stopped after --minutes.
4. The session's verify.py is judged in a separate sandbox (judge.sbxenv.yaml) with
   `check.exs --only FIXTURE --python sandbox/sbx-python`, never on the host.
5. DIR keeps the transcript, the session's files, both network logs, the judge's output and
   summary.json (usage, time, the outcome). Both sandboxes are removed unless --keep.

--no-agent does everything but run claude, to test the runner itself: the harness's own
known-good script stands in for the session's verify.py.
"""

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
AGENT_TEST = os.path.join(REPO, "agent-test")
SESSION_ENV = os.path.join(HERE, "agent-test.sbxenv.yaml")
JUDGE_ENV = os.path.join(HERE, "judge.sbxenv.yaml")
FLAGS = [
    "--safe-mode", "--disable-slash-commands", "--strict-mcp-config",
    "--mcp-config", '{"mcpServers":{}}', "--setting-sources", "",
    "--tools", "Bash,Read,Edit,Write", "--allowedTools", "Bash,Read,Edit,Write",
    "--permission-mode", "dontAsk", "--no-session-persistence",
    "--output-format", "stream-json", "--verbose",
]
# sbx sets a placeholder GH_TOKEN and forwards the host's SSH agent into every exec.
CLEAN_ENV = "unset GH_TOKEN SSH_AUTH_SOCK SSH_AUTH_SOCK_GATEWAY; "


def run(args, **kw):
    kw.setdefault("capture_output", True)
    kw.setdefault("text", True)
    return subprocess.run(args, check=False, **kw)


def shell_quote(s):
    return "'" + s.replace("'", "'\"'\"'") + "'"


def prompt_words(path):
    # PROMPT.md is its license comment, then the prompt's exact words (SPEC.md 7.4).
    text = open(path, encoding="utf-8").read()
    end = text.find("-->")
    return text[end + 3:].strip() + "\n" if text.lstrip().startswith("<!--") else text


def create(env_file, name, workspace, log):
    made = run(["sbx", "env", "create", "--auto-approve", "--name", name,
                "--env-arg", f"workspace={workspace}", env_file])
    with open(log, "w") as f:
        f.write(made.stdout + made.stderr)
    held = made.returncode == 0 and "lockdown: " + name + " reaches only" in made.stdout + made.stderr
    return made.returncode == 0, held


def remove(env_file, name):
    if run(["sbx", "env", "rm", "--force", "--name", name, env_file]).returncode != 0:
        run(["sbx", "rm", "--force", name])


def events(path):
    out = []
    for line in open(path, encoding="utf-8", errors="replace"):
        line = line.strip()
        if line.startswith("{"):
            try:
                out.append(json.loads(line))
            except ValueError:
                pass
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--fixture", required=True)
    ap.add_argument("--session", required=True)
    ap.add_argument("--model", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--minutes", type=int, default=90)
    ap.add_argument("--keep", action="store_true")
    ap.add_argument("--no-agent", action="store_true")
    a = ap.parse_args()

    fixture_dir = os.path.join(AGENT_TEST, "fixtures", a.fixture)
    if not os.path.isdir(fixture_dir):
        sys.exit(f"no fixture {a.fixture}")
    out = os.path.abspath(a.out)
    os.makedirs(out, exist_ok=True)
    tag = f"{a.fixture}-{a.session}".replace(".", "-")
    name, judge = f"ts-p9-{tag}", f"ts-p9-judge-{tag}"
    summary = {"fixture": a.fixture, "session": a.session, "model": a.model,
               "started": time.strftime("%Y-%m-%dT%H:%M:%S%z")}

    # What fixes this run, so a later one can be compared with it: the agent-test manifest
    # covers the prompt, the fixtures, the broken versions, the expected lines and the judge.
    import hashlib, re
    summary["agent_test_manifest_sha256"] = hashlib.sha256(
        open(os.path.join(AGENT_TEST, "MANIFEST.sha256"), "rb").read()).hexdigest()
    summary["constructions"] = sorted(
        f for f in os.listdir(os.path.join(AGENT_TEST, "fixtures", "3-item-reference"))
        if f.startswith("constructions-"))
    summary["template"] = re.search(r"^\s*template:\s*(\S+)", open(SESSION_ENV).read(), re.M).group(1)

    # 1. The session's directory.
    work = tempfile.mkdtemp(prefix=f"truestamp-agent-test-{tag}-")
    shutil.copy(os.path.join(AGENT_TEST, "PROMPT.md"), work)
    for f in sorted(os.listdir(fixture_dir)):
        shutil.copy(os.path.join(fixture_dir, f), work)
    summary["workspace"] = work
    summary["workspace_files"] = sorted(os.listdir(work))

    try:
        # 2. The session's sandbox.
        ok, held = create(SESSION_ENV, name, work, os.path.join(out, "session-create.log"))
        summary["lockdown_held"] = held
        if not (ok and held):
            summary["outcome"] = "sandbox not made or not locked down"
            return
        with open(os.path.join(out, "prompt.txt"), "w", encoding="utf-8") as f:
            f.write(prompt_words(os.path.join(work, "PROMPT.md")))
        run(["sbx", "cp", os.path.join(out, "prompt.txt"), f"{name}:/tmp/prompt.txt"])
        versions = run(["sbx", "exec", name, "sh", "-c",
                        "claude --version | cut -d' ' -f1; python3 -c 'import sys, importlib.metadata as m; "
                        "print(sys.version.split()[0], m.version(\"cryptography\"), m.version(\"rfc8785\"))'"])
        v = versions.stdout.split()
        summary["versions"] = dict(zip(["claude_code", "python", "cryptography", "rfc8785"], v))

        # 3. The session.
        transcript = os.path.join(out, "transcript.jsonl")
        command = (CLEAN_ENV + 'claude -p "$(cat /tmp/prompt.txt)" --model ' + shell_quote(a.model)
                   + " " + " ".join(shell_quote(x) for x in FLAGS) + " < /dev/null")
        if a.no_agent:
            # The harness's own known-good script stands in for a session's, so the judge runs.
            command = CLEAN_ENV + "echo '{\"type\":\"result\",\"subtype\":\"no-agent\"}'"
            shutil.copy(os.path.join(AGENT_TEST, "selftest", "verify.py"), work)
        t0 = time.time()
        with open(transcript, "w") as tf, open(os.path.join(out, "session-stderr.txt"), "w") as ef:
            proc = subprocess.Popen(["sbx", "exec", "-w", work, name, "sh", "-c", command],
                                    stdout=tf, stderr=ef, stdin=subprocess.DEVNULL)
            try:
                proc.wait(timeout=a.minutes * 60)
                summary["stopped_at_limit"] = False
            except subprocess.TimeoutExpired:
                summary["stopped_at_limit"] = True
                run(["sbx", "exec", "-u", "root", name, "sh", "-c", "pkill -f '[c]laude -p'"])
                proc.kill()
                proc.wait()
        summary["session_seconds"] = round(time.time() - t0)
        summary["session_exit"] = proc.returncode

        evs = events(transcript)
        init = next((e for e in evs if e.get("type") == "system" and e.get("subtype") == "init"), {})
        result = next((e for e in reversed(evs) if e.get("type") == "result"), {})
        summary["init"] = {k: init.get(k) for k in ("model", "apiKeySource", "tools", "mcp_servers",
                                                   "skills", "slash_commands", "cwd")}
        summary["init"]["plugins"] = [p.get("name") for p in init.get("plugins", [])]
        summary["result"] = {k: result.get(k) for k in ("subtype", "is_error", "num_turns",
                                                       "duration_ms", "duration_api_ms",
                                                       "total_cost_usd", "usage", "modelUsage")}
        summary["tool_calls"] = sum(1 for e in evs if e.get("type") == "assistant"
                                    for c in e.get("message", {}).get("content", [])
                                    if c.get("type") == "tool_use")
        with open(os.path.join(out, "session-policy-log.json"), "w") as f:
            f.write(run(["sbx", "policy", "log", name, "--json"]).stdout)

        # The session's files, as it left them.
        files = os.path.join(out, "session-files")
        shutil.copytree(work, files, dirs_exist_ok=True)
        summary["session_files"] = sorted(os.listdir(work))
        verify = os.path.join(work, "verify.py")
        if not os.path.isfile(verify):
            summary["outcome"] = "no verify.py"
            return

        # 4. The judge.
        ok, held = create(JUDGE_ENV, judge, work, os.path.join(out, "judge-create.log"))
        summary["judge_lockdown_held"] = held
        if not (ok and held):
            summary["outcome"] = "judge sandbox not made or not locked down"
            return
        env = dict(os.environ, SBX_JUDGE_SANDBOX=judge)
        wrapper = os.path.join(HERE, "sbx-python")
        run([wrapper, "-c", "pass"], env=env)
        judged = run(["elixir", "agent-test/check.exs", verify, "--only", a.fixture,
                      "--python", wrapper], cwd=REPO, env=env)
        with open(os.path.join(out, "judge.log"), "w") as f:
            f.write(judged.stdout + judged.stderr)
        with open(os.path.join(out, "judge-policy-log.json"), "w") as f:
            f.write(run(["sbx", "policy", "log", judge, "--json"]).stdout)
        summary["judge_exit"] = judged.returncode
        summary["judge_tail"] = (judged.stdout + judged.stderr).strip().splitlines()[-5:]
        summary["outcome"] = "pass" if judged.returncode == 0 else "fail"
    finally:
        if not a.keep:
            remove(SESSION_ENV, name)
            remove(JUDGE_ENV, judge)
        summary["finished"] = time.strftime("%Y-%m-%dT%H:%M:%S%z")
        with open(os.path.join(out, "summary.json"), "w") as f:
            json.dump(summary, f, indent=1)
        print(json.dumps({k: summary.get(k) for k in ("outcome", "session_seconds", "tool_calls",
                                                       "judge_exit")}, indent=1))
        print(f"everything is in {out}")


if __name__ == "__main__":
    main()
