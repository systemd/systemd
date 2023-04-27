#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

systemctl log-level info

DUMMY_DMESG="$(mktemp)"
cat >"${DUMMY_DMESG[@]}" <<\EOF
6,17159,5340096332127,-;usb 1-4: USB disconnect, device number 124
6,17160,5340109662397,-;input: WH-1000XM3 (AVRCP) as /devices/virtual/input/input293
6,17161,5343126458360,-;loop0: detected capacity change from 0 to 3145728
6,17162,5343126766065,-; loop0: p1 p2
6,17163,5343126815038,-;EXT4-fs (loop0p1): mounted filesystem with ordered data mode. Quota mode: none.
6,17164,5343158037334,-;EXT4-fs (loop0p1): unmounting filesystem.
6,17165,5343158072598,-;loop0: detected capacity change from 0 to 3145728
6,17166,5343158073563,-; loop0: p1 p2
6,17167,5343158074325,-; loop0: p1 p2
6,17168,5343158140859,-;EXT4-fs (loop0p1): mounted filesystem with ordered data mode. Quota mode: none.
6,17169,5343158182977,-;EXT4-fs (loop0p1): unmounting filesystem.
6,17170,5343158700241,-;loop0: detected capacity change from 0 to 3145728
6,17171,5343158700439,-; loop0: p1 p2
6,17172,5343158701120,-; loop0: p1 p2
EOF
DUMMY_DMESG_COUNT="$(wc -l <"$DUMMY_DMESG")"

# The dmesg- filename contains the backend-type and the Common Platform Error Record, CPER,
# record id, a 64-bit number.
#
# Files are processed in reverse lexigraphical order so as to properly reconstruct original dmesg.

prepare_efi_logs() {
    local timestamp="${1:?}"
    local chunk filename

    rm -fr /sys/fs/pstore/*
    rm -fr /var/lib/systemd/pstore/*

    # For the EFI backend, the 3 least significant digits of record id encodes a
    # "count" number, the next 2 least significant digits for the dmesg part
    # (chunk) number, and the remaining digits as the timestamp.  See
    # linux/drivers/firmware/efi/efi-pstore.c in efi_pstore_write().
    chunk=0
    # The sed in the process substitution below just reverses the file
    while read -r line; do
        filename="$(printf "dmesg-efi-%0.10d%0.2d%0.3d" "$timestamp" "$chunk" "$DUMMY_DMESG_COUNT")"
        echo "$line" >"/sys/fs/pstore/$filename"
        chunk=$((chunk + 1))
    done < <(sed '1!G;h;$!d' "$DUMMY_DMESG")
}

prepare_erst_logs() {
    local id filename

    # For the ERST backend, the record is a monotonically increasing number, seeded as
    # a timestamp. See linux/drivers/acpi/apei/erst.c in erst_writer().
    id=0
    # The sed in the process substitution below just reverses the file
    while read -r line; do
        filename="$(printf "dmesg-erst-%0.16d" "$id")"
        echo "$line" >"/sys/fs/pstore/$filename"
        id=$((id + 1))
    done < <(sed '1!G;h;$!d' "$DUMMY_DMESG")
}

prepare_pstore_config() {
    local storage="${1:?}"
    local unlink="${2:?}"

    systemctl stop systemd-pstore

    mkdir -p /run/systemd/pstore.conf.d
    cat >"/run/systemd/pstore.conf.d/99-test.conf" <<EOF
[PStore]
Storage=$storage
Unlink=$unlink
EOF

    systemd-analyze cat-config systemd/pstore.conf | grep "$storage"
    systemd-analyze cat-config systemd/pstore.conf | grep "$unlink"
}

file_count() {
    find "${1:?}" -type f | wc -l
}

# To avoid having to depend on the VM providing the pstore, let's simulate
# it using a simple bind mount
PSTORE_DIR="$(mktemp -d)"
mount --bind "${PSTORE_DIR:?}" "/sys/fs/pstore"

# systemd-pstore is a no-op with Storage=none
for unlink in yes no; do
    : "Backend: N/A; Storage: none; Unlink: $unlink"
    timestamp="$(date +"%s")"
    prepare_pstore_config "none" "$unlink"
    prepare_efi_logs "$timestamp"
    old_count="$(file_count /sys/fs/pstore/)"
    systemctl start systemd-pstore
    [[ "$(file_count /sys/fs/pstore)" -ge "$old_count" ]]
    [[ "$(file_count /var/lib/systemd/pstore/)" -eq 0 ]]

    : "Backend: EFI; Storage: external; Unlink: $unlink"
    timestamp="$(date +"%s")"
    prepare_pstore_config "external" "$unlink"
    prepare_efi_logs "$timestamp"
    [[ "$unlink" == yes ]] && exp_count=0 || exp_count="$(file_count /sys/fs/pstore/)"
    systemctl start systemd-pstore
    [[ "$(file_count /sys/fs/pstore)" -ge "$exp_count" ]]
    [[ "$(file_count /var/lib/systemd/pstore/)" -ne 0 ]]
    # We always log to journal
    diff "$DUMMY_DMESG" <(journalctl -o cat -u systemd-pstore --output-fields=FILE --cursor-file=/tmp/journal.cursor | sed "/^$/d")
    filename="$(printf "/var/lib/systemd/pstore/%s/%0.3d/dmesg.txt" "$timestamp" "$DUMMY_DMESG_COUNT")"
    diff "$DUMMY_DMESG" "$filename"

    : "Backend: EFI; Storage: journal; Unlink: $unlink"
    # FIXME: with Storage=journal systemd-pstore complains in journal:
    # [    7.386342] H systemd-pstore[885]: PStore dmesg-efi-168262866400014.
    # [    7.386499] H systemd-pstore[885]: Failed to open file /var/lib/systemd/pstore/1682628664/014/dmesg.txt: Operation not permitted
    timestamp="$(date +"%s")"
    prepare_pstore_config "journal" "$unlink"
    prepare_efi_logs "$timestamp"
    [[ "$unlink" == yes ]] && exp_count=0 || exp_count="$(file_count /sys/fs/pstore/)"
    journalctl -q -n 0 --cursor-file=/tmp/journal.cursor
    systemctl start systemd-pstore
    [[ "$(file_count /sys/fs/pstore)" -ge "$exp_count" ]]
    [[ "$(file_count /var/lib/systemd/pstore/)" -eq 0 ]]
    diff "$DUMMY_DMESG" <(journalctl -o cat -u systemd-pstore --output-fields=FILE --cursor-file=/tmp/journal.cursor | sed "/^$/d")

    : "Backend: ERST; Storage: external; Unlink: $unlink"
    timestamp="$(date +"%s")"
    prepare_pstore_config "external" "$unlink"
    prepare_erst_logs "$timestamp"
    [[ "$unlink" == yes ]] && exp_count=0 || exp_count="$(file_count /sys/fs/pstore/)"
    systemctl start systemd-pstore
    [[ "$(file_count /sys/fs/pstore)" -ge "$exp_count" ]]
    [[ "$(file_count /var/lib/systemd/pstore/)" -ne 0 ]]
    # We always log to journal
    diff "$DUMMY_DMESG" <(journalctl -o cat -u systemd-pstore --output-fields=FILE --cursor-file=/tmp/journal.cursor | sed "/^$/d")
    filename="$(printf "/var/lib/systemd/pstore/%s/%0.3d/dmesg.txt" "$timestamp" "$DUMMY_DMESG_COUNT")"
    diff "$DUMMY_DMESG" "$filename"

    : "Backend: ERST; Storage: journal; Unlink: $unlink"
    timestamp="$(date +"%s")"
    prepare_pstore_config "journal" "$unlink"
    prepare_erst_logs "$timestamp"
    [[ "$unlink" == yes ]] && exp_count=0 || exp_count="$(file_count /sys/fs/pstore/)"
    journalctl -q -n 0 --cursor-file=/tmp/journal.cursor
    systemctl start systemd-pstore
    [[ "$(file_count /sys/fs/pstore)" -ge "$exp_count" ]]
    [[ "$(file_count /var/lib/systemd/pstore/)" -eq 0 ]]
    diff "$DUMMY_DMESG" <(journalctl -o cat -u systemd-pstore --output-fields=FILE --cursor-file=/tmp/journal.cursor | sed "/^$/d")
done

# TODO:
#   - multiple split dmesg files
#   - non-dmesg files

touch /testok
