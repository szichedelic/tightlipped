# Fast path for every network-capable tool call: grep the hook payload against
# cached patterns and exit unless something might match. Node only runs on a hit.
#
# hooks.json sources this file (`set -- pre; . guard.sh`) so it runs inside the
# shell Claude Code already started instead of paying for a second one.
root=${CLAUDE_PLUGIN_ROOT:-${0%/*}/..}
cfg=${TIGHTLIPPED_CONFIG:-$HOME/.config/tightlipped/config.json}
state=${TIGHTLIPPED_STATE:-$HOME/.local/state/tightlipped}
needles=$state/needles-$1

if [ ! -f "$needles" ] || [ "$cfg" -nt "$needles" ]; then
  node "$root/tightlipped.mjs" build-cache 2>/dev/null || exit 0
fi
[ -s "$needles" ] || exit 0

# Claude Code sends the payload as one line of JSON, so grep prints all of it on a
# match and nothing otherwise. That saves buffering it with cat first.
input=$(command grep -iEf "$needles") || exit 0
printf '%s' "$input" | exec node "$root/tightlipped.mjs" "$1"
