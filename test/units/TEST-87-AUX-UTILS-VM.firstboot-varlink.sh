#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

# shellcheck source=test/units/test-control.sh
. "$(dirname "$0")"/test-control.sh
# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh

# Tests the disk image side of the io.systemd.FirstBoot Varlink interface, which needs loop devices. The
# root directory side is covered by TEST-74-AUX-UTILS.firstboot-varlink.sh.

for tool in systemd-firstboot varlinkctl jq systemd-repart systemd-dissect; do
    if ! command -v "$tool" >/dev/null; then
        echo "$tool not found, skipping the test"
        exit 77
    fi
done

if [[ ! -e /dev/loop-control ]]; then
    echo "No loop devices, skipping the test"
    exit 77
fi

at_exit() {
    set +e
    [[ -n "${WORK:-}" ]] && rm -rf "$WORK"
}

trap at_exit EXIT

WORK="$(mktemp -d /var/tmp/firstboot-varlink.XXXXXXXXXX)"
IMAGE="$WORK/image.raw"
FIRSTBOOT="$(command -v systemd-firstboot)"
SOCKET=/run/systemd/io.systemd.FirstBoot
TARGET=

# The test cases run against a directly spawned instance, and against the socket activated service
TARGETS=("$FIRSTBOOT")
[[ -S "$SOCKET" ]] && TARGETS+=("$SOCKET")

# An image that looks enough like an OS to be accepted, with nothing configured in it
make_image() {
    mkdir -p "$WORK/defs"
    cat >"$WORK/defs/10-root.conf" <<DEFEOF
[Partition]
Type=root
Format=ext4
SizeMinBytes=32M
SizeMaxBytes=32M
CopyFiles=/usr/lib/os-release:/usr/lib/os-release
MakeDirectories=/etc
DEFEOF

    rm -f "$IMAGE"
    systemd-repart --empty=create --size=auto --dry-run=no --offline=yes --definitions="$WORK/defs" "$IMAGE"
}

# Calls Configure on $TARGET, passing the specified fd as fd #0
configure() {
    local fd="${1:?}" parameters="${2:?}"

    varlinkctl --push-fd="$fd" call "$TARGET" io.systemd.FirstBoot.Configure "$parameters"
}

# Expects the call to succeed and the listed settings, and no others, to be reported as applied
expect_applied() {
    local fd="${1:?}" parameters="${2:?}"
    shift 2

    assert_eq "$(configure "$fd" "$parameters" | jq -c '.applied | sort')" "$(jq -cn '$ARGS.positional | sort' --args "$@")"
}

# Expects the call to be refused as InvalidParameter naming the specified field
expect_invalid_parameter() {
    local fd="${1:?}" parameters="${2:?}" field="${3:?}"

    varlinkctl --push-fd="$fd" call --graceful=org.varlink.service.InvalidParameter \
        "$TARGET" io.systemd.FirstBoot.Configure "$parameters" \
        | jq -e --arg f "$field" '.parameter == $f' >/dev/null
}

testcase_image() {
    local image_fd

    for TARGET in "${TARGETS[@]}"; do
        make_image

        # The image needs to be writable, hence open it ourselves, --push-fd=PATH would open it read-only
        exec {image_fd}<>"$IMAGE"
        expect_applied "$image_fd" '{"imageFileDescriptor":0,"settings":{"hostname":"imagebox","machineId":"4d9cc1f4c0b24a0e9c33c2b5d6e4f7a8"}}' hostname machineId
        # The second call finds the hostname configured already
        expect_applied "$image_fd" '{"imageFileDescriptor":0,"settings":{"hostname":"otherbox","timezone":"Europe/Berlin"}}' timezone
        exec {image_fd}>&-

        assert_eq "$(systemd-dissect --copy-from "$IMAGE" etc/hostname)" imagebox
        assert_eq "$(systemd-dissect --copy-from "$IMAGE" etc/machine-id)" 4d9cc1f4c0b24a0e9c33c2b5d6e4f7a8
        assert_in "/Europe/Berlin$" "$(systemd-dissect --with "$IMAGE" readlink etc/localtime)"
    done
}

testcase_bad_image_fd() {
    local fd

    for TARGET in "${TARGETS[@]}"; do
        make_image

        # A read-only fd is refused, we'd write into the image after all
        exec {fd}<"$IMAGE"
        expect_invalid_parameter "$fd" '{"imageFileDescriptor":0,"settings":{"hostname":"x"}}' imageFileDescriptor
        exec {fd}>&-

        # A character device is not an image, even when writable
        exec {fd}<>/dev/null
        expect_invalid_parameter "$fd" '{"imageFileDescriptor":0,"settings":{"hostname":"x"}}' imageFileDescriptor
        exec {fd}>&-
    done
}

run_testcases
