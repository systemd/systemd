#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

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
VARLINK_TARGETS=("$FIRSTBOOT")
if [[ -S /run/systemd/io.systemd.FirstBoot ]]; then
    VARLINK_TARGETS+=(/run/systemd/io.systemd.FirstBoot)
fi

# The image is passed as file descriptor, PUSH_FD is what to pass along. The parameters refer to it by
# index, i.e. 0.
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

make_image() {
    rm -f "$IMAGE"
    systemd-repart --empty=create --size=auto --dry-run=no --offline=yes --definitions="$WORK/defs" "$IMAGE"
}

# The image needs to look like an OS, or it is refused
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

for target in "${VARLINK_TARGETS[@]}"; do
    make_image

    # The image needs to be writable, hence open it ourselves, --push-fd=PATH would open it read-only
    exec {IMAGE_FD}<>"$IMAGE"
    PUSH_FD="$IMAGE_FD"
    expect_applied "$target" "$(jq -cn '{imageFileDescriptor: 0, settings: {hostname: "imagebox", machineId: "4d9cc1f4c0b24a0e9c33c2b5d6e4f7a8"}}')" hostname machineId
    # The second call finds the hostname configured already
    expect_applied "$target" "$(jq -cn '{imageFileDescriptor: 0, settings: {hostname: "otherbox", timezone: "Europe/Berlin"}}')" timezone
    exec {IMAGE_FD}>&-

    [[ "$(systemd-dissect --copy-from "$IMAGE" etc/hostname)" == "imagebox" ]]
    [[ "$(systemd-dissect --copy-from "$IMAGE" etc/machine-id)" == "4d9cc1f4c0b24a0e9c33c2b5d6e4f7a8" ]]
    [[ "$(systemd-dissect --copy-from "$IMAGE" etc/localtime)" == */Europe/Berlin ]] || systemd-dissect --with "$IMAGE" readlink etc/localtime | grep Europe/Berlin

    # A read-only fd is refused, we'd write into the image after all
    exec {IMAGE_FD}<"$IMAGE"
    PUSH_FD="$IMAGE_FD"
    expect_error "$target" '"parameter":"imageFileDescriptor"' "$(jq -cn '{imageFileDescriptor: 0, settings: {hostname: "x"}}')"
    exec {IMAGE_FD}>&-

    # A directory is not an image
    PUSH_FD="$WORK"
    expect_error "$target" '"parameter":"imageFileDescriptor"' "$(jq -cn '{imageFileDescriptor: 0, settings: {hostname: "x"}}')"
    PUSH_FD=
done
