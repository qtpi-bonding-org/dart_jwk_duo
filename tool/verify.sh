#!/usr/bin/env bash
# Local platform verification for dart_jwk_duo. Not CI: run it by hand.
#   tool/verify.sh host|ios|android|linux|all
# Env: IOS_SIM_ID, ANDROID_AVD, ANDROID_HOME, ANDROID_NDK_HOME, VERIFY_LOG_DIR,
#      ANDROID_EMU_PORT (even, default 5584).
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
sibling="$(cd "$root/.." && pwd)/rust_jwk_duo"
logdir="${VERIFY_LOG_DIR:-$PWD/.verify-logs}"
mkdir -p "$logdir"
sim_started="" emu_pid="" emu_serial="" tmp_copy=""

die() { echo "verify: $*" >&2; return 1; }
need() { command -v "$1" >/dev/null 2>&1 || die "missing prerequisite: $1 ($2)"; }

# Run a command with all output in a log; keep its own exit status.
step() { # name log cmd...
  local name="$1" log="$2"; shift 2
  echo "  - $name (log: $log)"
  local rc=0
  "$@" >"$log" 2>&1 || rc=$?
  if [ "$rc" -ne 0 ]; then
    echo "  FAILED: $name (exit $rc). Last lines:" >&2
    tr '\r' '\n' <"$log" | tail -15 | sed 's/^/    /' >&2
  fi
  return "$rc"
}

# Print the test runner's last pass/fail line; the log is the proof.
passline() { # log
  tr '\r' '\n' <"$1" | sed 's/\x1b\[[0-9;]*m//g' | grep -E 'All tests passed|Some tests failed' | tail -1
}

cleanup() {
  if [ -n "$emu_pid" ] && kill -0 "$emu_pid" 2>/dev/null; then
    "$ANDROID_HOME/platform-tools/adb" -s "$emu_serial" emu kill >/dev/null 2>&1 || true
    for _ in $(seq 30); do kill -0 "$emu_pid" 2>/dev/null || break; sleep 1; done
    kill "$emu_pid" 2>/dev/null || true
  fi
  if [ -n "$sim_started" ]; then xcrun simctl shutdown "$sim_started" >/dev/null 2>&1 || true; fi
  if [ -n "$tmp_copy" ]; then rm -rf "$tmp_copy"; fi
}
trap cleanup EXIT

copy_vectors() { (cd "$root/example/conformance_app" && tool/copy_conformance.sh); }

verify_host() {
  need dart "Dart SDK" || return 1
  need cargo "rustup toolchain" || return 1
  cd "$root"
  step "dart analyze" "$logdir/host-analyze.log" dart analyze || return 1
  step "dart test" "$logdir/host.log" dart test || return 1
  passline "$logdir/host.log"
}

verify_ios() {
  need xcrun "Xcode" || return 1
  need flutter "Flutter SDK" || return 1
  need rustup "rustup" || return 1
  local id="${IOS_SIM_ID:-}" devices
  if [ -z "$id" ]; then
    devices="$(xcrun simctl list devices available)"
    id="$(printf '%s\n' "$devices" | grep -m1 'iPhone' | sed -E 's/.*\(([0-9A-F-]{36})\).*/\1/' || true)"
  fi
  [ -n "$id" ] || die "no available iPhone simulator (set IOS_SIM_ID)" || return 1
  step "rustup targets (ios)" "$logdir/ios-targets.log" \
    rustup target add --toolchain stable aarch64-apple-ios-sim x86_64-apple-ios aarch64-apple-ios || return 1
  copy_vectors >"$logdir/ios-vectors.log" 2>&1 || { cat "$logdir/ios-vectors.log" >&2; return 1; }
  if xcrun simctl list devices | grep "$id" | grep -q Booted; then
    echo "  - simulator $id already booted (left running)"
  else
    step "boot simulator $id" "$logdir/ios-boot.log" xcrun simctl bootstatus "$id" -b || { xcrun simctl shutdown "$id" >/dev/null 2>&1 || true; return 1; }
    sim_started="$id"
  fi
  cd "$root/example/conformance_app"
  step "flutter test integration_test -d $id" "$logdir/ios.log" flutter test integration_test -d "$id" || return 1
  passline "$logdir/ios.log"
}

verify_android() {
  export ANDROID_HOME="${ANDROID_HOME:-$HOME/Library/Android/sdk}"
  [ -d "$ANDROID_HOME" ] || die "Android SDK not found at $ANDROID_HOME (set ANDROID_HOME)" || return 1
  if [ -z "${ANDROID_NDK_HOME:-}" ]; then
    ANDROID_NDK_HOME="$(ls -d "$ANDROID_HOME"/ndk/*/ 2>/dev/null | sort -V | tail -1 || true)"
    ANDROID_NDK_HOME="${ANDROID_NDK_HOME%/}"
  fi
  [ -n "$ANDROID_NDK_HOME" ] && [ -d "$ANDROID_NDK_HOME" ] || die "no NDK under $ANDROID_HOME/ndk (set ANDROID_NDK_HOME)" || return 1
  export ANDROID_NDK_HOME
  local emulator="$ANDROID_HOME/emulator/emulator" adb="$ANDROID_HOME/platform-tools/adb"
  [ -x "$emulator" ] || die "emulator not found at $emulator" || return 1
  [ -x "$adb" ] || die "adb not found at $adb" || return 1
  need flutter "Flutter SDK" || return 1
  need rustup "rustup" || return 1
  need cargo-ndk "cargo install cargo-ndk" || return 1
  local avd="${ANDROID_AVD:-}"
  [ -n "$avd" ] || avd="$("$emulator" -list-avds | head -1 || true)"
  [ -n "$avd" ] || die "no AVD (create one or set ANDROID_AVD)" || return 1
  # Explicit --toolchain: a rust-toolchain.toml override in the cwd makes plain
  # `rustup target add` target a different toolchain than the one the hook
  # builds with, failing later with "can't find crate for core".
  step "rustup targets (android)" "$logdir/android-targets.log" \
    rustup target add --toolchain stable x86_64-linux-android aarch64-linux-android armv7-linux-androideabi || return 1
  copy_vectors >"$logdir/android-vectors.log" 2>&1 || { cat "$logdir/android-vectors.log" >&2; return 1; }
  local port="${ANDROID_EMU_PORT:-5584}"
  emu_serial="emulator-$port"
  echo "  - booting AVD $avd as $emu_serial (log: $logdir/android-emulator.log)"
  "$emulator" -avd "$avd" -port "$port" -no-window -no-audio -no-boot-anim -no-snapshot-save \
    -gpu swiftshader_indirect >"$logdir/android-emulator.log" 2>&1 &
  emu_pid=$!
  local booted=""
  for _ in $(seq 300); do
    kill -0 "$emu_pid" 2>/dev/null || die "emulator exited early; see $logdir/android-emulator.log" || return 1
    booted="$("$adb" -s "$emu_serial" shell getprop sys.boot_completed 2>/dev/null | tr -d '\r' || true)"
    [ "$booted" = 1 ] && break
    sleep 2
  done
  [ "$booted" = 1 ] || die "emulator did not finish booting in 600s" || return 1
  cd "$root/example/conformance_app"
  step "flutter test integration_test -d $emu_serial" "$logdir/android.log" flutter test integration_test -d "$emu_serial" || return 1
  passline "$logdir/android.log"
}

# Runs the dart:3.11 linux/amd64 suite against a throwaway copy of both repos.
# Mounting the real checkout leaves Linux hook output in .dart_tool and
# rust/target, which then breaks the macOS `dart test` ("Running build hooks failed").
verify_linux() {
  need docker "Docker" || return 1
  docker info >/dev/null 2>&1 || die "docker daemon is not running" || return 1
  [ -d "$sibling" ] || die "sibling repo not found at $sibling" || return 1
  need rsync "rsync" || return 1
  tmp_copy="$(mktemp -d "${TMPDIR:-/tmp}/dart_jwk_duo_linux.XXXXXX")"
  local ex=(--exclude .git --exclude .dart_tool --exclude target --exclude build --exclude venv)
  rsync -a "${ex[@]}" "$root/" "$tmp_copy/dart_jwk_duo/"
  rsync -a "${ex[@]}" "$sibling/" "$tmp_copy/rust_jwk_duo/"
  step "docker dart:3.11 linux/amd64: dart test" "$logdir/linux.log" \
    docker run --rm --platform linux/amd64 -v "$tmp_copy:/src" -w /src/dart_jwk_duo dart:3.11 bash -c \
    'apt-get update && apt-get install -y curl build-essential && curl -sSf --retry 3 https://sh.rustup.rs | sh -s -- -y && . $HOME/.cargo/env && dart pub get && dart test' || return 1
  passline "$logdir/linux.log"
}

usage() { echo "usage: tool/verify.sh host|ios|android|linux|all" >&2; exit 2; }

[ $# -eq 1 ] || usage
case "$1" in host|ios|android|linux) platforms=("$1") ;; all) platforms=(host ios android linux) ;; *) usage ;; esac

failed=()
for p in "${platforms[@]}"; do
  echo "== $p"
  if "verify_$p"; then echo "== $p: PASS"; else echo "== $p: FAIL" >&2; failed+=("$p"); fi
  cleanup; emu_pid="" sim_started="" tmp_copy=""
done
if [ ${#failed[@]} -gt 0 ]; then echo "verify: FAILED: ${failed[*]}" >&2; exit 1; fi
echo "verify: all passed (${platforms[*]})"
