#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh

# Tests the io.systemd.FirstBoot Varlink interface, which applies settings the way the command line tool
# does. We only operate on a root directory here, so the testbed is left alone. Disk images need loop
# devices, hence that part lives in TEST-87-AUX-UTILS-VM.firstboot-varlink.sh.

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

# The directory or image to operate on is passed as file descriptor, PUSH_FD is what to pass along, if
# anything. The parameters refer to it by index, i.e. 0.
configure() {
    varlinkctl ${PUSH_FD:+--push-fd="$PUSH_FD"} call "${1:?}" io.systemd.FirstBoot.Configure "${2:?}"
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

ROOT_PARAMS='{rootFileDescriptor: 0}'

# shellcheck disable=SC2016
HASHED='$y$j9T$CUiPhA.Hy6ijhLYMo9YTD0$hxJc7ahdrOLojG3Ltd2SE0M02ZU5ZiUoGMNLyr3SWO0'

for target in "${VARLINK_TARGETS[@]}"; do
    rm -rf "$ROOT"
    mkdir -p "$ROOT/bin"
    touch "$ROOT/bin/fooshell"
    PUSH_FD="$ROOT"

    expect_applied "$target" "$(jq -cn --arg hashed "$HASHED" '{
        rootFileDescriptor: 0,
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
    expect_applied "$target" "$(jq -cn "$ROOT_PARAMS"' + {settings: {hostname: "otherbox", keymap: "us"}}')" keymap
    [[ "$(cat "$ROOT/etc/hostname")" == "varlinkbox" ]]
    grep "KEYMAP=us" "$ROOT/etc/vconsole.conf"
    expect_applied "$target" "$(jq -cn "$ROOT_PARAMS"' + {settings: {hostname: "otherbox", keymap: "de"}}')"
    [[ "$(cat "$ROOT/etc/hostname")" == "varlinkbox" ]]
    grep "KEYMAP=us" "$ROOT/etc/vconsole.conf"
    expect_applied "$target" "$(jq -cn "$ROOT_PARAMS"' + {settings: {hostname: "otherbox", keymap: "de"}, force: true}')" hostname keymap
    [[ "$(cat "$ROOT/etc/hostname")" == "otherbox" ]]
    grep "KEYMAP=de" "$ROOT/etc/vconsole.conf"

    # What is refused
    expect_error "$target" NoSettings "$(jq -cn "$ROOT_PARAMS")"
    expect_error "$target" NoSettings "$(jq -cn "$ROOT_PARAMS"' + {settings: {}}')"
    expect_error "$target" '"parameter":"hostname"' "$(jq -cn "$ROOT_PARAMS"' + {settings: {hostname: "-foo-"}}')"
    expect_error "$target" '"parameter":"timezone"' "$(jq -cn "$ROOT_PARAMS"' + {settings: {timezone: "Nowhere/Nothing"}}')"
    expect_error "$target" '"parameter":"keymap"' "$(jq -cn "$ROOT_PARAMS"' + {settings: {keymap: "../keymap"}}')"
    expect_error "$target" '"parameter":"locale"' "$(jq -cn "$ROOT_PARAMS"' + {settings: {locale: "not a locale"}}')"
    expect_error "$target" '"parameter":"localeMessages"' "$(jq -cn "$ROOT_PARAMS"' + {settings: {localeMessages: "not a locale"}}')"
    expect_error "$target" '"parameter":"machineTags"' "$(jq -cn "$ROOT_PARAMS"' + {settings: {machineTags: ["no spaces"]}}')"
    expect_error "$target" '"parameter":"machineTags"' "$(jq -cn "$ROOT_PARAMS"' + {settings: {machineTags: ["a=1", "a=2"]}}')"
    expect_error "$target" '"parameter":"rootShell"' "$(jq -cn "$ROOT_PARAMS"' + {settings: {rootShell: "sh"}}')"
    expect_error "$target" '"parameter":"rootShell"' "$(jq -cn "$ROOT_PARAMS"' + {settings: {rootShell: "/bin/missing"}}')"
    expect_error "$target" '"parameter":"rootPasswordHashed"' "$(jq -cn "$ROOT_PARAMS"' + {settings: {rootPassword: "a", rootPasswordHashed: "b"}}')"
    expect_error "$target" '"parameter":"imagePolicy"' "$(jq -cn "$ROOT_PARAMS"' + {imagePolicy: "bogus=foo", settings: {hostname: "x"}}')"
    expect_error "$target" '"parameter":"machineId"' "$(jq -cn "$ROOT_PARAMS"' + {settings: {machineId: "00000000000000000000000000000000"}}')"
    expect_error "$target" '"parameter":"machineId"' "$(jq -cn "$ROOT_PARAMS"' + {settings: {machineId: "not-an-id"}}')"
    # The same fd cannot be both
    expect_error "$target" '"parameter":"imageFileDescriptor"' "$(jq -cn "$ROOT_PARAMS"' + {imageFileDescriptor: 0, settings: {hostname: "x"}}')"
    # A directory is not an image
    expect_error "$target" '"parameter":"imageFileDescriptor"' "$(jq -cn '{imageFileDescriptor: 0, settings: {hostname: "x"}}')"
    # Something that is not a directory is not a root directory, and neither is an fd that was not passed
    PUSH_FD=/dev/null
    expect_error "$target" '"parameter":"rootFileDescriptor"' "$(jq -cn "$ROOT_PARAMS"' + {settings: {hostname: "x"}}')"
    PUSH_FD=
    expect_error "$target" '"parameter":"rootFileDescriptor"' "$(jq -cn "$ROOT_PARAMS"' + {settings: {hostname: "x"}}')"
    # The machine ID may only be set on the host with force, like on the command line. The host's root
    # directory passed as fd means the host, too.
    expect_error "$target" '"parameter":"machineId"' "$(jq -cn '{settings: {machineId: "0e1d84a8a1d84c6e9b2d2f0f8f1a2b3c"}}')"
    PUSH_FD=/
    expect_error "$target" '"parameter":"machineId"' "$(jq -cn "$ROOT_PARAMS"' + {settings: {machineId: "0e1d84a8a1d84c6e9b2d2f0f8f1a2b3c"}}')"
    PUSH_FD=
done

# Configuring systems is reserved to root. The socket is not connectable for others, and the service drops
# connections of unprivileged clients even if they manage to talk to it, e.g. by spawning it themselves.
if command -v setpriv >/dev/null && id testuser >/dev/null 2>&1; then
    chmod 0755 "$ROOT"
    PARAMETERS="$(jq -cn "$ROOT_PARAMS"' + {settings: {hostname: "foo"}}')"

    if [[ -S /run/systemd/io.systemd.FirstBoot ]]; then
        if OUT="$(setpriv --reuid=testuser --regid=testuser --clear-groups \
                varlinkctl --push-fd="$ROOT" call /run/systemd/io.systemd.FirstBoot io.systemd.FirstBoot.Configure "$PARAMETERS" 2>&1)"; then
            echo "Unexpected success: $OUT"
            exit 1
        fi
        [[ "$OUT" == *"Permission denied"* ]]
    fi

    if OUT="$(setpriv --reuid=testuser --regid=testuser --clear-groups \
            varlinkctl --push-fd="$ROOT" call "$FIRSTBOOT" io.systemd.FirstBoot.Configure "$PARAMETERS" 2>&1)"; then
        echo "Unexpected success: $OUT"
        exit 1
    fi
    [[ "$OUT" == *"Operation not permitted"* ]]
    [[ "$(cat "$ROOT/etc/hostname")" == "otherbox" ]]
fi
