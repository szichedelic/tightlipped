---
description: Create the tightlipped config and show what it protects
allowed-tools: ["Bash(node:*)"]
---

!`node "${CLAUDE_PLUGIN_ROOT}/tightlipped.mjs" init $ARGUMENTS`

Show the user the output above. Then tell them they can edit `~/.config/tightlipped/config.json` to change the mode (off, log, ask, block), add phones, names or other strings to protect, and allowlist domains or tools. Changes apply on the next tool call.
