#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -euxo pipefail

export DM_NAME="integrity_test"
export FULL_DM_DEV_NAME="/dev/mapper/${DM_NAME}"
export FS_UUID="01234567-ffff-eeee-eeee-0123456789ab"
export GEN="/var/run/systemd/generator"

image_dir=""

cleanup()
{
    if [ -z "${image_dir}" ]; then
        return
    fi

    if [ -f "${image_dir}/image" ]; then
        if [ -e "${FULL_DM_DEV_NAME}" ]; then
            integritysetup close "${DM_NAME}"
        fi
        losetup -d "${loop}"
    fi

    rm -rf "${image_dir}"
}

trap cleanup EXIT

build_integrity_tab()
{
cat << _EOL > "/etc/integritytab"
${DM_NAME} ${loop} - integrity-algorithm=$1
_EOL
}

image_dir="$(mktemp -d -t -p / integrity.tmp.XXXXXX)"
if [ -z "${image_dir}" ] || [ ! -d "${image_dir}" ]; then
    echo "mktemp under / failed"
    exit 1
fi

dd if=/dev/zero of="${image_dir}/image" bs=1048576 count=64 || exit 1
dd if=/dev/zero of="${image_dir}/data" bs=1048576 count=64 || exit 1
loop="$(losetup --show -f "${image_dir}/image")"

if [[ ! -e ${loop} ]]; then
    echo "Loopback device created not found!"
    exit 1
fi

# Do one iteration with a separate data device, to test those branches
separate_data=1

for algorithm in crc32c crc32 sha1 sha256
do
    if [ "${separate_data}" -eq 1 ]; then
        data_option="--data-device=${image_dir}/data"
    else
        data_option=""
    fi
    integritysetup format "${loop}" --batch-mode -I "${algorithm}" "${data_option}" || exit 1
    integritysetup open -I "${algorithm}" "${loop}" "${DM_NAME}" "${data_option}" || exit 1
    mkfs.ext4 -U "${FS_UUID}" "${FULL_DM_DEV_NAME}" || exit 1

    # Give userspace time to handle udev events for new FS showing up ...
    udevadm settle

    integritysetup close "${DM_NAME}" || exit 1

    # create integritytab, generate units, start service
    if [ "${separate_data}" -eq 1 ]; then
        data_option=",data-device=${image_dir}/data"
    else
        data_option=""
    fi
    build_integrity_tab "${algorithm}${data_option}"

    # Cause the generator to re-run
    systemctl daemon-reload || exit 1

    # Check for existence of unit files...
    if [[ ! -e "/run/systemd/generator/systemd-integritysetup@${DM_NAME}.service" ]]; then
        echo "Service file does not exist!"
        exit 1
    fi

    # Make sure we are in a consistent state, e.g. not already active before we start
    systemctl stop systemd-integritysetup@"${DM_NAME}".service || exit 1
    systemctl start systemd-integritysetup@"${DM_NAME}".service || exit 1

    # Check the signature on the FS to ensure we can retrieve it and that is matches
    if [ -e "${FULL_DM_DEV_NAME}" ]; then
        # If a separate device is used for the metadata storage, then blkid will return one of the loop devices
        if [ "${separate_data}" -eq 1 ]; then
            dev_name="$(integritysetup status ${DM_NAME} | grep '^\s*device:' | awk '{print $2}')"
        else
            dev_name="${FULL_DM_DEV_NAME}"
        fi
        if [ "${dev_name}" != "$(blkid -U "${FS_UUID}")" ]; then
            echo "Failed to locate FS with matching UUID!"
            exit 1
        fi
    else
        echo "Failed to bring up integrity device!"
        exit 1
    fi

    systemctl stop systemd-integritysetup@"${DM_NAME}".service || exit 1

    if [ -e "${FULL_DM_DEV_NAME}" ]; then
        echo "Expecting ${FULL_DM_DEV_NAME} to not exist after stopping unit!"
        exit 1
    fi

    separate_data=0
done

echo OK >/testok
