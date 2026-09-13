#!/bin/sh
# Run what CI runs, before you push. Mirrors .github/workflows/ci.yml.
#
#   scripts/check.sh          fmt, clippy, tests, workflow lint
#   scripts/check.sh --full   the above plus cargo-deny and a short fuzz smoke
#
# Tools that are not installed are fetched through nix-shell when nix is
# available. Anything that cannot run is reported as skipped, never as a pass.
set -u
cd "$(dirname "$0")/.." || exit 1

full=0
[ "${1:-}" = "--full" ] && full=1

failed=''
skipped=''

bold() { printf '\n\033[1m== %s ==\033[0m\n' "$1"; }
note_fail() { printf '\033[31m%s failed\033[0m\n' "$1"; failed="$failed  $1
"; }
note_skip() { skipped="$skipped  $1
"; }

step() {                                  # step <label> <cmd...>
  label="$1"; shift
  bold "$label"
  "$@" || note_fail "$label"
}

# Run a command that needs an external tool, pulling it from nix if needed.
tooled() {                                # tooled <label> <binary> <nixpkg> <cmd...>
  label="$1"; bin="$2"; pkg="$3"; shift 3
  if command -v "$bin" >/dev/null 2>&1; then
    step "$label" "$@"
  elif command -v nix-shell >/dev/null 2>&1; then
    bold "$label (via nix-shell -p $pkg)"
    nix-shell -p "$pkg" --run "$*" || note_fail "$label"
  else
    note_skip "$label (no $bin, no nix-shell)"
  fi
}

step "cargo fmt"    cargo fmt --check
step "cargo clippy" cargo clippy --all-targets -- -D warnings
step "cargo test"   cargo test --locked
# cargo fuzz has no --locked flag, so check the fuzz lockfile separately.
step "fuzz lockfile" sh -c 'cd fuzz && cargo metadata --locked --format-version 1 >/dev/null'

tooled "actionlint" actionlint actionlint actionlint

# Compare directive names in the rendered NixOS units with the Debian units.
# Requires Nix; skip when unavailable. CI builds the same output with
# `nix flake check`.
if command -v nix >/dev/null 2>&1; then
  bold "unit drift (deploy/ vs nix/module.nix)"
  # Keep stderr visible for build progress and failure details.
  drift_out=$(nix build --no-link --print-out-paths \
    ".#checks.$(nix eval --impure --raw --expr builtins.currentSystem).module")
  if [ -n "$drift_out" ]; then
    scripts/unit-drift.sh "$drift_out" || note_fail "unit drift"
  else
    note_skip "unit drift (could not build the rendered units)"
  fi
else
  note_skip "unit drift (no nix)"
fi

# Match CI's MSRV job to rust-version in Cargo.toml; skip without rustup.
msrv=$(grep -m1 '^rust-version' Cargo.toml | cut -d'"' -f2)
if command -v rustup >/dev/null 2>&1; then
  step "msrv build ($msrv)" rustup run "$msrv" cargo build --locked
else
  note_skip "msrv build ($msrv) (no rustup; CI covers it)"
fi

if [ "$full" = 1 ]; then
  tooled "cargo-deny" cargo-deny cargo-deny cargo deny check
  # CI builds and tests the image on every PR. Include the slower local build
  # only with --full.
  engine=''
  for e in podman docker; do
    command -v "$e" >/dev/null 2>&1 && { engine="$e"; break; }
  done
  if [ -n "$engine" ]; then
    bold "container image ($engine)"
    if "$engine" build -f Containerfile -t scrip:check . >/dev/null; then
      CONTAINER_ENGINE="$engine" scripts/container-smoke.sh scrip:check \
        || note_fail "container smoke"
    else
      note_fail "container build"
    fi
  else
    note_skip "container image (no podman or docker)"
  fi
  if command -v cargo-fuzz >/dev/null 2>&1 && cargo +nightly --version >/dev/null 2>&1; then
    bold "fuzz smoke (10s per target)"
    for t in $(cd fuzz && cargo fuzz list); do
      echo "-- $t"
      (cd fuzz && cargo +nightly fuzz run "$t" -- -max_total_time=10) || note_fail "fuzz $t"
    done
  else
    note_skip "fuzz smoke (needs nightly + cargo-fuzz; CI covers it)"
  fi
else
  note_skip "cargo-deny and fuzz smoke (pass --full to include them)"
fi

echo
[ -n "$skipped" ] && printf '\033[33mskipped:\033[0m\n%s' "$skipped"
if [ -n "$failed" ]; then
  printf '\033[31mfailed:\033[0m\n%s' "$failed"
  exit 1
fi
printf '\033[32mall checks passed\033[0m\n'
