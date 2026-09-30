#!/usr/bin/env python3
# Copyright (c) 2026 Truestamp, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Deny one Docker Sandboxes sandbox every host but Anthropic's API and login, then check it did.

    python3 sandbox/lockdown.py SANDBOX

A per-sandbox rule can only narrow what the global policy and the agent's kit allow, and a
deny of "**" also denies the API itself, since a deny beats every allow. So this reads the
sandbox's effective rules, denies each allowed host but KEEP for this sandbox alone, and
then asks the policy engine (`sbx policy check`) about every allowed host again: KEEP must
be allowed and everything else denied. The global policy, and every other sandbox, is left
as it was. It exits 0 only when the check holds.
"""

import json
import subprocess
import sys

# The API, and the host of its OAuth token endpoint, where sbx's proxy renews the
# subscription's login when a session outlives its access token.
KEEP = {"api.anthropic.com:443", "platform.claude.com:443"}
# Hosts a session must never reach, checked whether a rule names them or not.
PROBES = ["example.com:443", "pypi.org:443", "github.com:443", "8.8.8.8:53"]


def sbx(*args):
    return subprocess.run(["sbx", *args], capture_output=True, text=True, check=False)


def allowed_resources(sandbox):
    run = sbx("policy", "ls", sandbox, "--json")
    if run.returncode != 0:
        sys.exit(f"lockdown: sbx policy ls {sandbox} failed: {run.stderr.strip()}")
    allowed = set()
    for rule in json.loads(run.stdout).get("rules", []):
        if rule.get("resource_type") == "network" and rule.get("decision") == "allow":
            allowed.update(rule.get("resources", []))
    return allowed


def host_of(resource):
    # "pypi.org:443" -> "pypi.org"; a CIDR or a bare pattern stays as it is.
    host, sep, port = resource.rpartition(":")
    return host if sep and port.isdigit() else resource


def concrete(resource):
    # A host the pattern matches, for `sbx policy check`: "**.github.com:443" -> "x.github.com:443".
    return resource.replace("**", "x").replace("*", "x").replace("?", "x")


def allowed(sandbox, resource):
    run = sbx("policy", "check", "network", "--sandbox", sandbox, resource)
    return run.stdout.lstrip().startswith("Allowed")


def main():
    if len(sys.argv) != 2:
        sys.exit("usage: lockdown.py SANDBOX")
    sandbox = sys.argv[1]
    keep_hosts = {host_of(k) for k in KEEP}

    deny = sorted({host_of(r) for r in allowed_resources(sandbox)} - keep_hosts)
    if deny:
        run = sbx("policy", "deny", "network", "--sandbox", sandbox, ",".join(deny))
        if run.returncode != 0:
            sys.exit(f"lockdown: sbx policy deny failed: {run.stderr.strip()}")

    problems = []
    for resource in sorted(allowed_resources(sandbox) | set(PROBES) | KEEP):
        want = resource in KEEP
        if allowed(sandbox, concrete(resource)) != want:
            problems.append(f"{resource} is {'denied' if want else 'allowed'}")

    if problems:
        sys.exit("lockdown: " + sandbox + ": " + "; ".join(problems))
    print(f"lockdown: {sandbox} reaches only {', '.join(sorted(KEEP))} ({len(deny)} hosts denied)")


if __name__ == "__main__":
    main()
