#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh

ENTRY_ID=systemd-bls-dtb-test.conf
DTB_REL=/EFI/Linux/systemd-bls-dtb-test.dtb
DTB_SHA256=baf3185dbc6812caeda3fe9fcaa356a28ae00bf9b7befcf1b9501814d96d059b
DTB_BASE64=0A3+7QAAAHMAAAA4AAAAZAAAACgAAAARAAAAEAAAAAAAAAALAAAALAAAAAAAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAMAAAANAAAAAHN5c3RlbWQsdGVzdAAAAAAAAAACAAAACWNvbXBhdGlibGUAAAAAAA==

case "$REBOOT_COUNT" in
    0)
        if [[ ! -x /usr/lib/systemd/systemd-pcrlock ]]; then
            echo "systemd-pcrlock not found, skipping BLS DeviceTree measurement test" | tee --append /skipped
            exit 77
        fi

        # This test explicitly requests UEFI and a TPM, so failures here must not be skipped.
        [[ -d /sys/firmware/efi ]]
        systemd-analyze has-tpm2
        bootctl status | grep -F "Secure Boot: disabled" >/dev/null

        esp="$(bootctl --print-esp-path)"
        current_uki="$(bootctl --print-stub-path)"
        [[ "$current_uki" == "$esp/"* ]]
        linux_path="/${current_uki#"$esp/"}"

        mkdir -p "$esp/EFI/Linux" "$esp/loader/entries"
        printf %s "$DTB_BASE64" | base64 --decode >"$esp$DTB_REL"
        assert_eq "$(sha256sum "$esp$DTB_REL" | cut -d ' ' -f 1)" "$DTB_SHA256"

        cat >"$esp/loader/entries/$ENTRY_ID" <<EOF
title systemd BLS DeviceTree measurement test
linux $linux_path
options selinux=0
devicetree $DTB_REL
EOF

        bootctl set-oneshot "$ENTRY_ID"
        systemctl_final reboot
        exec sleep infinity
        ;;
    1)
        esp="$(bootctl --print-esp-path)"
        bootctl list --json=short | jq -e --arg id "$ENTRY_ID" \
            'any(.[]; .id == $id and .isSelected == true)' >/dev/null

        pcrlog="$(/usr/lib/systemd/systemd-pcrlock --pcr=12 --json=short log)"
        jq -e --arg hash "$DTB_SHA256" --arg name "${DTB_REL##*/}" '
            ([.log[] | select(
                .pcr == 12 and
                .event == "event-tag" and
                .sha256 == $hash and
                (.description | contains("systemd: devicetree")) and
                (.description | contains($name))
            )] | length) == 1 and
            any(.pcrs[]; .pcr == 12 and .hashMatchesEventLog == true)
        ' <<<"$pcrlog"

        rm -f "$esp/loader/entries/$ENTRY_ID" "$esp$DTB_REL"
        touch /testok
        ;;
    *)
        assert_not_reached
        ;;
esac
