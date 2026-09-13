#!/bin/sh
# Fail when a systemd directive is present in one of the shipped Debian units
# but absent from the unit the NixOS module renders, or the reverse.
#
# Compare directive names only. Nix derives ports and paths from
# `services.scrip.settings`; the Debian units use fixed values. Names are
# case-sensitive because systemd ignores incorrectly capitalized directives.
#
#   scripts/unit-drift.sh <dir holding the rendered nix units>
#
# Produce that directory with:
#   nix build --no-link --print-out-paths .#checks.<system>.module
#
# Directives missing from both versions still need manual review.
set -u

nixdir="${1:-}"
[ -n "$nixdir" ] || {
  echo "usage: $0 <dir holding the rendered nix units>" >&2
  exit 2
}
cd "$(dirname "$0")/.." >/dev/null || exit 1

# NixOS puts this in every unit it generates (PATH, LOCALE_ARCHIVE, TZDIR).
# There is nothing for a static Debian unit to match it with.
nix_only_ok='Environment'

tmp=$(mktemp -d) || exit 1
trap 'rm -rf "$tmp"' EXIT
rc=0

keys() { # keys <unit file> <section>
  sed -n "/^\[$2\]/,/^\[/p" "$1" |
    grep -oE '^[A-Za-z][A-Za-z0-9_]*=' | tr -d '=' | sort -u
}

for unit in scrip.service scrip-firewall.service; do
  [ -f "$nixdir/$unit" ] || {
    echo "unit drift: $nixdir/$unit is missing; rebuild the check output" >&2
    exit 2
  }
  for sec in Unit Service; do
    keys "deploy/$unit" "$sec" >"$tmp/deb"
    keys "$nixdir/$unit" "$sec" >"$tmp/nix"
    for k in $(comm -23 "$tmp/deb" "$tmp/nix"); do
      echo "drift: $unit [$sec] ${k}= in deploy/ but not in nix/module.nix"
      rc=1
    done
    for k in $(comm -13 "$tmp/deb" "$tmp/nix"); do
      case " $nix_only_ok " in *" $k "*) continue ;; esac
      echo "drift: $unit [$sec] ${k}= in nix/module.nix but not in deploy/"
      rc=1
    done
  done
done

[ "$rc" -eq 0 ] && echo "unit drift: deploy/ and nix/module.nix agree on every directive"
exit "$rc"
