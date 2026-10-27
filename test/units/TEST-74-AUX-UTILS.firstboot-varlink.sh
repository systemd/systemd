#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

# shellcheck source=test/units/test-control.sh
. "$(dirname "$0")"/test-control.sh
# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh

# Tests the io.systemd.FirstBoot Varlink interface, which applies settings the way the command line tool
# does. Only a root directory is operated on here, so the testbed is left alone. Disk images need loop
# devices, hence that part lives in TEST-87-AUX-UTILS-VM.firstboot-varlink.sh.

for tool in systemd-firstboot varlinkctl jq; do
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
SOCKET=/run/systemd/io.systemd.FirstBoot
TARGET=

# The test cases run against a directly spawned instance, and against the socket activated service
TARGETS=("$FIRSTBOOT")
[[ -S "$SOCKET" ]] && TARGETS+=("$SOCKET")

# shellcheck disable=SC2016
HASHED='$y$j9T$CUiPhA.Hy6ijhLYMo9YTD0$hxJc7ahdrOLojG3Ltd2SE0M02ZU5ZiUoGMNLyr3SWO0'

# Starts over with an empty root directory, containing only a shell to configure for root
fresh_root() {
    rm -rf "$ROOT"
    mkdir -p "$ROOT/bin"
    touch "$ROOT/bin/fooshell"
}

# Calls Configure on $TARGET, passing the root directory, or whatever the caller wants instead, as fd #0
configure() {
    local parameters="${1:?}" fd="${2:-$ROOT}"

    varlinkctl --push-fd="$fd" call "$TARGET" io.systemd.FirstBoot.Configure "$parameters"
}

# Expects the call to succeed and the listed settings, and no others, to be reported as applied
expect_applied() {
    local parameters="${1:?}"
    shift

    assert_eq "$(configure "$parameters" | jq -c '.applied | sort')" "$(jq -cn '$ARGS.positional | sort' --args "$@")"
}

# Expects the call to be refused as InvalidParameter naming the specified field
expect_invalid_parameter() {
    local parameters="${1:?}" field="${2:?}" fd="${3:-$ROOT}"

    varlinkctl --push-fd="$fd" call --graceful=org.varlink.service.InvalidParameter \
        "$TARGET" io.systemd.FirstBoot.Configure "$parameters" \
        | jq -e --arg f "$field" '.parameter == $f' >/dev/null
}

# Expects the call to be refused with the specified error
expect_error() {
    local parameters="${1:?}" error="${2:?}"

    assert_in "$error" "$(configure "$parameters" 2>&1 || :)"
}

locale_file() {
    # Debian and Ubuntu build with /etc/default/locale instead of /etc/locale.conf
    if [[ -e "$ROOT/etc/locale.conf" ]]; then
        echo "$ROOT/etc/locale.conf"
    else
        echo "$ROOT/etc/default/locale"
    fi
}

testcase_configure() {
    for TARGET in "${TARGETS[@]}"; do
        fresh_root

        expect_applied "$(jq -cn --arg hashed "$HASHED" '{
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

        assert_in "LANG=C.UTF-8" "$(cat "$(locale_file)")"
        assert_in "LC_MESSAGES=en_US.UTF-8" "$(cat "$(locale_file)")"
        assert_eq "$(cat "$ROOT/etc/hostname")" varlinkbox
        assert_in "/Europe/Berlin$" "$(readlink "$ROOT/etc/localtime")"
        assert_eq "$(cat "$ROOT/etc/machine-id")" 0e1d84a8a1d84c6e9b2d2f0f8f1a2b3c
        # The tags are deduplicated and sorted, like on the command line
        assert_eq "$(cat "$ROOT/etc/machine-info")" 'TAGS="bar:foo:quux=1"'
        assert_eq "$(awk -F: '/^root/ { print $2; }' "$ROOT/etc/shadow")" "$HASHED"
        assert_eq "$(awk -F: '/^root/ { print $7; }' "$ROOT/etc/passwd")" /bin/fooshell
        assert_eq "$(cat "$ROOT/etc/kernel/cmdline")" firstboot.varlink=1
    done
}

testcase_force() {
    for TARGET in "${TARGETS[@]}"; do
        fresh_root

        expect_applied '{"rootFileDescriptor":0,"settings":{"hostname":"varlinkbox"}}' hostname

        # Settings that are configured already are skipped, and hence not reported, unless force is set
        expect_applied '{"rootFileDescriptor":0,"settings":{"hostname":"otherbox","keymap":"us"}}' keymap
        assert_eq "$(cat "$ROOT/etc/hostname")" varlinkbox
        assert_in "KEYMAP=us" "$(cat "$ROOT/etc/vconsole.conf")"

        expect_applied '{"rootFileDescriptor":0,"settings":{"hostname":"otherbox","keymap":"de"},"force":true}' hostname keymap
        assert_eq "$(cat "$ROOT/etc/hostname")" otherbox
        assert_in "KEYMAP=de" "$(cat "$ROOT/etc/vconsole.conf")"

        # A message locale equal to the locale is not written, and hence not reported either
        expect_applied '{"rootFileDescriptor":0,"settings":{"locale":"C.UTF-8","localeMessages":"C.UTF-8"}}' locale
        assert_in "LANG=C.UTF-8" "$(cat "$(locale_file)")"
        assert_not_in "LC_MESSAGES=" "$(cat "$(locale_file)")"
    done
}

testcase_invalid_settings() {
    for TARGET in "${TARGETS[@]}"; do
        fresh_root

        expect_error '{"rootFileDescriptor":0,"settings":{}}' NoSettings
        # An all-zero machine ID means "not set", like on the command line
        expect_error '{"rootFileDescriptor":0,"settings":{"machineId":"00000000000000000000000000000000"}}' NoSettings

        expect_invalid_parameter '{"rootFileDescriptor":0,"settings":{"hostname":"-foo-"}}' hostname
        expect_invalid_parameter '{"rootFileDescriptor":0,"settings":{"timezone":"Nowhere/Nothing"}}' timezone
        expect_invalid_parameter '{"rootFileDescriptor":0,"settings":{"keymap":"../keymap"}}' keymap
        expect_invalid_parameter '{"rootFileDescriptor":0,"settings":{"locale":"not a locale"}}' locale
        expect_invalid_parameter '{"rootFileDescriptor":0,"settings":{"localeMessages":"not a locale"}}' localeMessages
        expect_invalid_parameter '{"rootFileDescriptor":0,"settings":{"machineTags":["no spaces"]}}' machineTags
        expect_invalid_parameter '{"rootFileDescriptor":0,"settings":{"machineTags":["a=1","a=2"]}}' machineTags
        expect_invalid_parameter '{"rootFileDescriptor":0,"settings":{"rootShell":"sh"}}' rootShell
        expect_invalid_parameter '{"rootFileDescriptor":0,"settings":{"rootShell":"/bin/missing"}}' rootShell
        expect_invalid_parameter '{"rootFileDescriptor":0,"imagePolicy":"bogus=foo","settings":{"hostname":"x"}}' imagePolicy

        # Malformed values are caught while parsing the settings object, and reported as such
        expect_invalid_parameter '{"rootFileDescriptor":0,"settings":{"machineId":"not-an-id"}}' settings
        expect_invalid_parameter '{"rootFileDescriptor":0,"settings":{"rootPassword":"a","rootPasswordHashed":"b"}}' settings
    done
}

testcase_targets() {
    local null_fd

    for TARGET in "${TARGETS[@]}"; do
        fresh_root

        # Only one of a root directory and a disk image can be operated on
        expect_error '{"rootFileDescriptor":0,"imageFileDescriptor":0,"settings":{"hostname":"x"}}' ConflictingTargets

        # A character device is neither a root directory nor an image, even when writable
        exec {null_fd}<>/dev/null
        expect_invalid_parameter '{"rootFileDescriptor":0,"settings":{"hostname":"x"}}' rootFileDescriptor "$null_fd"
        expect_invalid_parameter '{"imageFileDescriptor":0,"settings":{"hostname":"x"}}' imageFileDescriptor "$null_fd"
        exec {null_fd}>&-

        # An index nothing was passed for
        expect_invalid_parameter '{"rootFileDescriptor":1,"settings":{"hostname":"x"}}' rootFileDescriptor

        # The machine ID may only be set on the host with force, like on the command line, and the host's
        # root directory passed as fd counts as the host
        expect_invalid_parameter '{"settings":{"machineId":"0e1d84a8a1d84c6e9b2d2f0f8f1a2b3c"}}' machineId
        expect_invalid_parameter '{"rootFileDescriptor":0,"settings":{"machineId":"0e1d84a8a1d84c6e9b2d2f0f8f1a2b3c"}}' machineId /
    done
}

testcase_no_credentials() {
    # Unlike on the command line, settings are never picked up from credentials, those belong to the
    # service. The spawned binary inherits our environment, hence this can only be checked with that target.
    TARGET="$FIRSTBOOT"
    fresh_root
    mkdir "$ROOT/creds"
    echo credbox >"$ROOT/creds/firstboot.hostname"

    CREDENTIALS_DIRECTORY="$ROOT/creds" expect_applied '{"rootFileDescriptor":0,"settings":{"keymap":"us"}}' keymap
    test ! -e "$ROOT/etc/hostname"
}

testcase_unprivileged() {
    local parameters='{"rootFileDescriptor":0,"settings":{"hostname":"foo"}}'

    if ! command -v setpriv >/dev/null || ! id testuser >/dev/null 2>&1; then
        echo "setpriv or testuser not available, skipping"
        return 0
    fi

    fresh_root
    chmod 0755 "$ROOT"

    # The socket is not connectable for others
    if [[ -S "$SOCKET" ]]; then
        assert_in "Permission denied" "$(setpriv --reuid=testuser --regid=testuser --clear-groups \
            varlinkctl --push-fd="$ROOT" call "$SOCKET" io.systemd.FirstBoot.Configure "$parameters" 2>&1 || :)"
    fi

    # The service drops connections of unprivileged clients even if they manage to talk to it, e.g. by
    # spawning it themselves
    assert_in "Operation not permitted" "$(setpriv --reuid=testuser --regid=testuser --clear-groups \
        varlinkctl --push-fd="$ROOT" call "$FIRSTBOOT" io.systemd.FirstBoot.Configure "$parameters" 2>&1 || :)"
    test ! -e "$ROOT/etc/hostname"
}

run_testcases
