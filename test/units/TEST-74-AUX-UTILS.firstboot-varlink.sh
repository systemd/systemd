#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh

# Tests the io.systemd.FirstBoot Varlink interface, which applies settings the way the command line tool
# does. We only operate on a root directory here, so the testbed is left alone.

if ! command -v systemd-firstboot >/dev/null; then
    echo "systemd-firstboot not found, skipping the test"
    exit 77
fi

for tool in varlinkctl jq; do
    if ! command -v "$tool" >/dev/null; then
        echo "$tool not found, skipping the test"
        exit 77
    fi
done

at_exit() {
    set +e
    [[ -n "${ROOT:-}" ]] && rm -rf "$ROOT"
}

trap at_exit EXIT

ROOT="$(mktemp -d /var/tmp/firstboot-varlink.XXXXXXXXXX)"

FIRSTBOOT="$(command -v systemd-firstboot)"
VARLINK_TARGETS=("$FIRSTBOOT")
if [[ -S /run/systemd/io.systemd.FirstBoot ]]; then
    VARLINK_TARGETS+=(/run/systemd/io.systemd.FirstBoot)
fi

configure() {
    varlinkctl call "${1:?}" io.systemd.FirstBoot.Configure "${2:?}"
}

# Expects the call to succeed and the specified settings, and no others, to be reported as applied
expect_applied() {
    local target="${1:?}" parameters="${2:?}" out
    shift 2

    out="$(configure "$target" "$parameters")"
    [[ "$(jq -c '.applied | sort' <<<"$out")" == "$(jq -cn '$ARGS.positional | sort' --args "$@")" ]]
}

# Expects the call to fail, with the specified text in the output. Invalid parameters are reported as
# '{"parameter":"NAME"}', which never occurs in the input.
expect_error() {
    local target="${1:?}" error="${2:?}" parameters="${3:?}" out

    if out="$(configure "$target" "$parameters" 2>&1)"; then
        echo "Unexpected success: $out"
        return 1
    fi
    [[ "$out" == *"$error"* ]]
}

# shellcheck disable=SC2016
HASHED='$y$j9T$CUiPhA.Hy6ijhLYMo9YTD0$hxJc7ahdrOLojG3Ltd2SE0M02ZU5ZiUoGMNLyr3SWO0'


for target in "${VARLINK_TARGETS[@]}"; do
    rm -rf "$ROOT"
    mkdir -p "$ROOT/bin"
    touch "$ROOT/bin/fooshell"

    expect_applied "$target" "$(jq -cn --arg root "$ROOT" --arg hashed "$HASHED" '{
        root: $root,
        settings: {
            locale: "C.UTF-8",
            localeMessages: "en_US.UTF-8",
            hostname: "varlinkbox",
            timezone: "Europe/Berlin",
            machineId: "0e1d84a8a1d84c6e9b2d2f0f8f1a2b3c",
            machineTags: ["foo", "bar", "foo", "quux=1"],
            rootPasswordHashed: $hashed,
            rootShell: "/bin/fooshell",
            kernelCommandLine: "firstboot.varlink=1"
        }
    }')" locale localeMessages hostname timezone machineId machineTags rootPasswordHashed rootShell kernelCommandLine

    # Debian and Ubuntu build with /etc/default/locale instead of /etc/locale.conf
    LOCALE_FILE="$ROOT/etc/locale.conf"
    [[ -e "$LOCALE_FILE" ]] || LOCALE_FILE="$ROOT/etc/default/locale"
    grep "LANG=C.UTF-8" "$LOCALE_FILE"
    grep "LC_MESSAGES=en_US.UTF-8" "$LOCALE_FILE"
    [[ "$(cat "$ROOT/etc/hostname")" == "varlinkbox" ]]
    [[ "$(readlink "$ROOT/etc/localtime")" == */Europe/Berlin ]]
    [[ "$(cat "$ROOT/etc/machine-id")" == "0e1d84a8a1d84c6e9b2d2f0f8f1a2b3c" ]]
    # The tags are deduplicated and sorted, like on the command line
    grep '^TAGS="bar:foo:quux=1"$' "$ROOT/etc/machine-info"
    [[ "$(awk -F: '/^root/ { print $2; }' "$ROOT/etc/shadow")" == "$HASHED" ]]
    [[ "$(awk -F: '/^root/ { print $7; }' "$ROOT/etc/passwd")" == "/bin/fooshell" ]]
    [[ "$(cat "$ROOT/etc/kernel/cmdline")" == "firstboot.varlink=1" ]]

    # Settings that are configured already are not overwritten, unless force is set, like on the command line.
    # The reply tells what was written: the hostname is configured already, the keymap is not.
    expect_applied "$target" "$(jq -cn --arg root "$ROOT" '{root: $root, settings: {hostname: "otherbox", keymap: "us"}}')" keymap
    [[ "$(cat "$ROOT/etc/hostname")" == "varlinkbox" ]]
    grep "KEYMAP=us" "$ROOT/etc/vconsole.conf"
    expect_applied "$target" "$(jq -cn --arg root "$ROOT" '{root: $root, settings: {hostname: "otherbox", keymap: "de"}}')"
    [[ "$(cat "$ROOT/etc/hostname")" == "varlinkbox" ]]
    grep "KEYMAP=us" "$ROOT/etc/vconsole.conf"
    expect_applied "$target" "$(jq -cn --arg root "$ROOT" '{root: $root, settings: {hostname: "otherbox", keymap: "de"}, force: true}')" hostname keymap
    [[ "$(cat "$ROOT/etc/hostname")" == "otherbox" ]]
    grep "KEYMAP=de" "$ROOT/etc/vconsole.conf"

    # What is refused
    expect_error "$target" NoSettings "$(jq -cn --arg root "$ROOT" '{root: $root}')"
    expect_error "$target" NoSettings "$(jq -cn --arg root "$ROOT" '{root: $root, settings: {}}')"
    expect_error "$target" '"parameter":"root"' "$(jq -cn '{root: "relative/path", settings: {hostname: "x"}}')"
    expect_error "$target" '"parameter":"root"' "$(jq -cn --arg root "$ROOT/missing" '{root: $root, settings: {hostname: "x"}}')"
    expect_error "$target" '"parameter":"image"' "$(jq -cn --arg root "$ROOT" '{root: $root, image: "/missing.raw", settings: {hostname: "x"}}')"
    expect_error "$target" '"parameter":"hostname"' "$(jq -cn --arg root "$ROOT" '{root: $root, settings: {hostname: "-foo-"}}')"
    expect_error "$target" '"parameter":"timezone"' "$(jq -cn --arg root "$ROOT" '{root: $root, settings: {timezone: "Nowhere/Nothing"}}')"
    expect_error "$target" '"parameter":"keymap"' "$(jq -cn --arg root "$ROOT" '{root: $root, settings: {keymap: "../keymap"}}')"
    expect_error "$target" '"parameter":"locale"' "$(jq -cn --arg root "$ROOT" '{root: $root, settings: {locale: "not a locale"}}')"
    expect_error "$target" '"parameter":"localeMessages"' "$(jq -cn --arg root "$ROOT" '{root: $root, settings: {localeMessages: "not a locale"}}')"
    expect_error "$target" '"parameter":"machineTags"' "$(jq -cn --arg root "$ROOT" '{root: $root, settings: {machineTags: ["no spaces"]}}')"
    expect_error "$target" '"parameter":"machineTags"' "$(jq -cn --arg root "$ROOT" '{root: $root, settings: {machineTags: ["a=1", "a=2"]}}')"
    expect_error "$target" '"parameter":"rootShell"' "$(jq -cn --arg root "$ROOT" '{root: $root, settings: {rootShell: "sh"}}')"
    expect_error "$target" '"parameter":"rootShell"' "$(jq -cn --arg root "$ROOT" '{root: $root, settings: {rootShell: "/bin/missing"}}')"
    expect_error "$target" '"parameter":"rootPasswordHashed"' "$(jq -cn --arg root "$ROOT" '{root: $root, settings: {rootPassword: "a", rootPasswordHashed: "b"}}')"
    expect_error "$target" '"parameter":"imagePolicy"' "$(jq -cn --arg root "$ROOT" '{root: $root, imagePolicy: "bogus=foo", settings: {hostname: "x"}}')"
    expect_error "$target" '"parameter":"machineId"' "$(jq -cn --arg root "$ROOT" '{root: $root, settings: {machineId: "00000000000000000000000000000000"}}')"
    expect_error "$target" '"parameter":"machineId"' "$(jq -cn --arg root "$ROOT" '{root: $root, settings: {machineId: "not-an-id"}}')"
    # The machine ID may only be set on the host with force, like on the command line
    expect_error "$target" '"parameter":"machineId"' "$(jq -cn '{settings: {machineId: "0e1d84a8a1d84c6e9b2d2f0f8f1a2b3c"}}')"
done

# Configuring systems is reserved to root. The socket is not connectable for others, and the service drops
# connections of unprivileged clients even if they manage to talk to it, e.g. by spawning it themselves.
if command -v setpriv >/dev/null && id testuser >/dev/null 2>&1; then
    chmod 0755 "$ROOT"
    PARAMETERS="$(jq -cn --arg root "$ROOT" '{root: $root, settings: {hostname: "foo"}}')"

    if [[ -S /run/systemd/io.systemd.FirstBoot ]]; then
        if OUT="$(setpriv --reuid=testuser --regid=testuser --clear-groups \
                varlinkctl call /run/systemd/io.systemd.FirstBoot io.systemd.FirstBoot.Configure "$PARAMETERS" 2>&1)"; then
            echo "Unexpected success: $OUT"
            exit 1
        fi
        [[ "$OUT" == *"Permission denied"* ]]
    fi

    if OUT="$(setpriv --reuid=testuser --regid=testuser --clear-groups \
            varlinkctl call "$FIRSTBOOT" io.systemd.FirstBoot.Configure "$PARAMETERS" 2>&1)"; then
        echo "Unexpected success: $OUT"
        exit 1
    fi
    [[ "$OUT" == *"Operation not permitted"* ]]
    [[ "$(cat "$ROOT/etc/hostname")" == "otherbox" ]]
fi
