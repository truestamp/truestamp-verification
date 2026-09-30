<!--
Copyright (c) 2026 Truestamp, Inc.
SPDX-License-Identifier: Apache-2.0
-->

# Skills kept in this repository

Skills for agents that work in this repository, published by Docker for its Sandboxes
(`sbx`), which run the agent test's sessions (`sandbox/`). Each directory is kept exactly
as published, under the Apache License 2.0, so it is outside the house-style check
(`task style`). To update one, fetch the new commit's files in place and change its line
here.

| Skill | Source | Commit |
|---|---|---|
| `docker-sandboxes-lifecycle` | [docker/skills](https://github.com/docker/skills) v0.3.1 | `8afc2c6ef4e0ec2ea8e4ba024d0b884ea930b926` |
| `docker-sandboxes-network-credentials` | docker/skills v0.3.1 | the same |
| `docker-sandboxes-env` | docker/skills v0.3.1 | the same |
| `docker-sandboxes-kits` | docker/skills v0.3.1 | the same |
| `docker-destructive-guardrails` | docker/skills v0.3.1 | the same |
| `kit-author` | [docker/sbx-kits-contrib](https://github.com/docker/sbx-kits-contrib) `skills/kit-author` | `c7a99a0b4b61a666661714e859609087c3880624` |

None of them reaches a session of the agent test: a session runs outside this repository,
with skills off (SPEC.md 7.4).
