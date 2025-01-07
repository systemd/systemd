#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -euxo pipefail

DM_NAME="integrity_test"
DM_NODE="/dev/mapper/${DM_NAME}"
DM_SERVICE="systemd-integritysetup@${DM_NAME}.service"
FS_UUID="01234567-ffff-eeee-eeee-0123456789ab"

TMP_DIR=
LOOP=

cleanup() (
    set +e

    if [[ -n "${LOOP}" ]]; then
        losetup -d "${LOOP}"
    fi

    if [[ -n "${TMP_DIR}" ]]; then
        rm -rf "${TMP_DIR}"
    fi

    rm -rf /run/udev/rules.d/
    udevadm control --reload
)

trap cleanup EXIT

udevadm settle

# Enable debugging logs for loop and dm block devices.
mkdir -p /run/udev/rules.d/
cat >/run/udev/rules.d/00-integrity-test.rules <<EOF
SUBSYSTEM=="block", KERNEL=="loop*|dm-*", OPTIONS="log_level=debug"
EOF

# FIXME:
# There is no ordering restriction between underlying loopback block devices and DM devices.
# Hence, we may get wrong device node symlinks. To workaround that issue, let's decrease the
# priority for loopback block devices.
cat >/run/udev/rules.d/99-priority.rules <<EOF
SUBSYSTEM=="block", KERNEL=="loop*", OPTIONS="link_priority=-200"
EOF

udevadm control --reload

TMP_DIR="$(mktemp -d -t -p / integrity.tmp.XXXXXX)"
dd if=/dev/zero of="${TMP_DIR}/image" bs=1048576 count=64
dd if=/dev/zero of="${TMP_DIR}/data" bs=1048576 count=64
LOOP="$(losetup --show -f "${TMP_DIR}/image")"
udevadm wait --timeout=30 --settle "${LOOP}"

test_cleanup() (
    set +e

    if [[ -e "/run/systemd/generator/${DM_SERVICE}" ]]; then
        systemctl stop "${DM_SERVICE}"
    elif [[ -e "${DM_NODE}" ]]; then
        integritysetup close "${DM_NAME}"
    fi

    udevadm wait --timeout=30 --settle --removed "${DM_NODE}"

    # Clear integritytab.
    rm -f /etc/integritytab

    # Make the generator to re-run.
    systemctl daemon-reload
)

test_one() {
    local algorithm="${1?}"
    local separate_data="${2?}"
    local data_option

    trap test_cleanup RETURN

    if [[ "${separate_data}" == 1 ]]; then
        data_option="--data-device=${TMP_DIR}/data"
    else
        data_option=""
    fi

    integritysetup format "${LOOP}" --batch-mode -I "${algorithm}" "${data_option}"
    integritysetup open -I "${algorithm}" "${LOOP}" "${DM_NAME}" "${data_option}"
    udevadm wait --timeout=30 --settle "${DM_NODE}"
    mkfs.ext4 -U "${FS_UUID}" "${DM_NODE}"
    # Wait for synthetic events being processed.
    udevadm settle
    integritysetup close "${DM_NAME}"
    udevadm wait --timeout=30 --settle --removed "${DM_NODE}"

    # Create integritytab.
    if [[ "${separate_data}" == 1 ]]; then
        data_option=",data-device=${TMP_DIR}/data"
    else
        data_option=""
    fi
    cat >"/etc/integritytab" <<EOF
${DM_NAME} ${LOOP} - integrity-algorithm=${algorithm}${data_option}
EOF

    # Make the generator to re-run.
    systemctl daemon-reload

    # Check for existence of the unit file.
    [[ -e "/run/systemd/generator/${DM_SERVICE}" ]]

    # Make sure we are in a consistent state, e.g. not already active before we start.
    [[ "$(systemctl is-active "${DM_SERVICE}")" == inactive ]]
    systemctl start "${DM_SERVICE}"
    udevadm wait --timeout=30 --settle "${DM_NODE}"

    # Check the signature on the FS to ensure we can retrieve it and that is matches.
    [[ "$(blkid -U "${FS_UUID}")" == "${DM_NODE}" ]]
}

for a in crc32c crc32 xxhash64 sha1 sha256; do
    test_one "$a" 0
    test_one "$a" 1
done

touch /testok
