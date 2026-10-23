---
description: Scan your Claude Code history for personal data sent over the network and for pages that asked the agent to identify you
allowed-tools: ["Bash(node:*)"]
---

Audit output:

!`node "${CLAUDE_PLUGIN_ROOT}/doxguard.mjs" audit $ARGUMENTS`

Summarize the result for the user in a few lines: how many outbound calls would have been stopped, where they went, and how many pages asked the agent to identify the user. If any flagged call went to a domain the user clearly owns, suggest adding it to `allow_domains` in `~/.config/doxguard/config.json`.
