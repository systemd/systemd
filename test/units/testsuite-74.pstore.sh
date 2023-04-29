#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

systemctl log-level info

if systemd-detect-virt -cq; then
    echo "Running in a container, skipping the systemd-pstore test..."
    exit 0
fi

DUMMY_DMESG_1="$(mktemp)"
cat >"$DUMMY_DMESG_1" <<\EOF
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

DUMMY_DMESG_2="$(mktemp)"
cat >"$DUMMY_DMESG_2" <<\EOF
Nechť již hříšné saxofony ďáblů rozezvučí síň úděsnými tóny waltzu, tanga a quickstepu.
Příliš žluťoučký kůň úpěl ďábelské ódy.
Zvlášť zákeřný učeň s ďolíčky běží podél zóny úlů.
Vyciď křišťálový nůž, ó učiň úděsné líbivým!
Loď čeří kýlem tůň obzvlášť v Grónské úžině
Ó, náhlý déšť již zvířil prach a čilá laň teď běží s houfcem gazel k úkrytům.
Vypätá dcéra grófa Maxwella s IQ nižším ako kôň núti čeľaď hrýzť hŕbu jabĺk.
Kŕdeľ šťastných ďatľov učí pri ústí Váhu mĺkveho koňa obhrýzať kôru a žrať čerstvé mäso.
Stróż pchnął kość w quiz gędźb vel fax myjń.
Portez ce vieux whisky au juge blond qui fume!
EOF

file_count() { find "${1:?}" -type f | wc -l; }
file_size() { wc -l <"${1:?}"; }
random_efi_timestamp() { printf "%0.10d" "$((1000000000 + RANDOM))"; }

# The dmesg- filename contains the backend-type and the Common Platform Error Record, CPER,
# record id, a 64-bit number.
#
# Files are processed in reverse lexigraphical order so as to properly reconstruct original dmesg.

prepare_efi_logs() {
    local file="${1:?}"
    local timestamp="${2:?}"
    local chunk count filename

    # For the EFI backend, the 3 least significant digits of record id encodes a
    # "count" number, the next 2 least significant digits for the dmesg part
    # (chunk) number, and the remaining digits as the timestamp.  See
    # linux/drivers/firmware/efi/efi-pstore.c in efi_pstore_write().
    count="$(file_size "$file")"
    chunk=0
    # The sed in the process substitution below just reverses the file
    while read -r line; do
        filename="$(printf "dmesg-efi-%0.10d%0.2d%0.3d" "$timestamp" "$chunk" "$count")"
        echo "$line" >"/sys/fs/pstore/$filename"
        chunk=$((chunk + 1))
    done < <(sed '1!G;h;$!d' "$file")

    if [[ "$chunk" -eq 0 ]]; then
        echo >&2 "No dmesg-efi files were created"
        exit 1
    fi
}

prepare_erst_logs() {
    local file="${1:?}"
    local start_id="${2:?}"
    local id filename

    # For the ERST backend, the record is a monotonically increasing number, seeded as
    # a timestamp. See linux/drivers/acpi/apei/erst.c in erst_writer().
    id="$start_id"
    # The sed in the process substitution below just reverses the file
    while read -r line; do
        filename="$(printf "dmesg-erst-%0.16d" "$id")"
        echo "$line" >"/sys/fs/pstore/$filename"
        id=$((id + 1))
    done < <(sed '1!G;h;$!d' "$file")

    if [[ "$id" -eq "$start_id" ]]; then
        echo >&2 "No dmesg-erst files were created"
        exit 1
    fi

    # ID of the last dmesg file will be the ID of the erst subfolder
    echo "$((id - 1))"
}

prepare_pstore_config() {
    local storage="${1:?}"
    local unlink="${2:?}"

    systemctl stop systemd-pstore

    rm -fr /sys/fs/pstore/* /var/lib/systemd/pstore/*

    mkdir -p /run/systemd/pstore.conf.d
    cat >"/run/systemd/pstore.conf.d/99-test.conf" <<EOF
[PStore]
Storage=$storage
Unlink=$unlink
EOF

    systemd-analyze cat-config systemd/pstore.conf | grep "$storage"
    systemd-analyze cat-config systemd/pstore.conf | grep "$unlink"
}

start_pstore() {
    rm -f /tmp/journal.cursor
    journalctl -q -n 0 --cursor-file=/tmp/journal.cursor
    systemctl start systemd-pstore
    journalctl --sync
}

# To avoid having to depend on the VM providing the pstore, let's simulate
# it using a simple bind mount
PSTORE_DIR="$(mktemp -d)"
mount --bind "${PSTORE_DIR:?}" "/sys/fs/pstore"

# systemd-pstore is a no-op with Storage=none
for unlink in yes no; do
    : "Backend: N/A; Storage: none; Unlink: $unlink"
    timestamp="$(random_efi_timestamp)"
    prepare_pstore_config "none" "$unlink"
    prepare_efi_logs "$DUMMY_DMESG_1" "$timestamp"
    old_count="$(file_count /sys/fs/pstore/)"
    start_pstore
    [[ "$(file_count /sys/fs/pstore)" -ge "$old_count" ]]
    [[ "$(file_count /var/lib/systemd/pstore/)" -eq 0 ]]

    : "Backend: EFI; Storage: external; Unlink: $unlink"
    timestamp="$(random_efi_timestamp)"
    prepare_pstore_config "external" "$unlink"
    prepare_efi_logs "$DUMMY_DMESG_1" "$timestamp"
    [[ "$unlink" == yes ]] && exp_count=0 || exp_count="$(file_count /sys/fs/pstore/)"
    start_pstore
    [[ "$(file_count /sys/fs/pstore)" -ge "$exp_count" ]]
    [[ "$(file_count /var/lib/systemd/pstore/)" -ne 0 ]]
    # We always log to journal
    diff "$DUMMY_DMESG_1" <(journalctl -o cat --output-fields=FILE --cursor-file=/tmp/journal.cursor | sed "/^$/d")
    filename="$(printf "/var/lib/systemd/pstore/%s/%0.3d/dmesg.txt" "$timestamp" "$(file_size "$DUMMY_DMESG_1")")"
    diff "$DUMMY_DMESG_1" "$filename"

    : "Backend: EFI; Storage: external; Unlink: $unlink; multiple dmesg files"
    timestamp_1="$(random_efi_timestamp)"
    timestamp_2="$((timestamp_1 + 1))"
    prepare_pstore_config "external" "$unlink"
    prepare_efi_logs "$DUMMY_DMESG_1" "$timestamp_1"
    prepare_efi_logs "$DUMMY_DMESG_2" "$timestamp_2"
    # Add one "random" (non-dmesg) file as well
    echo "hello world" >/sys/fs/pstore/foo.bar
    [[ "$unlink" == yes ]] && exp_count=0 || exp_count="$(file_count /sys/fs/pstore/)"
    start_pstore
    [[ "$(file_count /sys/fs/pstore)" -ge "$exp_count" ]]
    [[ "$(file_count /var/lib/systemd/pstore/)" -ne 0 ]]
    filename_1="$(printf "/var/lib/systemd/pstore/%s/%0.3d/dmesg.txt" "$timestamp_1" "$(file_size "$DUMMY_DMESG_1")")"
    diff "$DUMMY_DMESG_1" "$filename_1"
    filename_2="$(printf "/var/lib/systemd/pstore/%s/%0.3d/dmesg.txt" "$timestamp_2" "$(file_size "$DUMMY_DMESG_2")")"
    diff "$DUMMY_DMESG_2" "$filename_2"
    grep "hello world" "/var/lib/systemd/pstore/foo.bar"

    : "Backend: EFI; Storage: journal; Unlink: $unlink"
    timestamp="$(random_efi_timestamp)"
    prepare_pstore_config "journal" "$unlink"
    prepare_efi_logs "$DUMMY_DMESG_1" "$timestamp"
    [[ "$unlink" == yes ]] && exp_count=0 || exp_count="$(file_count /sys/fs/pstore/)"
    start_pstore
    [[ "$(file_count /sys/fs/pstore)" -ge "$exp_count" ]]
    [[ "$(file_count /var/lib/systemd/pstore/)" -eq 0 ]]
    diff "$DUMMY_DMESG_1" <(journalctl -o cat --output-fields=FILE --cursor-file=/tmp/journal.cursor | sed "/^$/d")

    : "Backend: ERST; Storage: external; Unlink: $unlink"
    prepare_pstore_config "external" "$unlink"
    last_id="$(prepare_erst_logs "$DUMMY_DMESG_1" 0)"
    [[ "$unlink" == yes ]] && exp_count=0 || exp_count="$(file_count /sys/fs/pstore/)"
    start_pstore
    [[ "$(file_count /sys/fs/pstore)" -ge "$exp_count" ]]
    [[ "$(file_count /var/lib/systemd/pstore/)" -ne 0 ]]
    # We always log to journal
    diff "$DUMMY_DMESG_1" <(journalctl -o cat --output-fields=FILE --cursor-file=/tmp/journal.cursor | sed "/^$/d")
    filename="$(printf "/var/lib/systemd/pstore/%0.16d/dmesg.txt" "$last_id")"
    diff "$DUMMY_DMESG_1" "$filename"

    : "Backend: ERST; Storage: external; Unlink: $unlink; multiple dmesg files"
    prepare_pstore_config "external" "$unlink"
    last_id_1="$(prepare_erst_logs "$DUMMY_DMESG_1" 0)"
    last_id_2="$(prepare_erst_logs "$DUMMY_DMESG_2" "$((last_id_1 + 10))")"
    # Add one "random" (non-dmesg) file as well
    echo "hello world" >/sys/fs/pstore/foo.bar
    [[ "$unlink" == yes ]] && exp_count=0 || exp_count="$(file_count /sys/fs/pstore/)"
    start_pstore
    [[ "$(file_count /sys/fs/pstore)" -ge "$exp_count" ]]
    [[ "$(file_count /var/lib/systemd/pstore/)" -ne 0 ]]
    filename_1="$(printf "/var/lib/systemd/pstore/%0.16d/dmesg.txt" "$last_id_1")"
    diff "$DUMMY_DMESG_1" "$filename_1"
    filename_2="$(printf "/var/lib/systemd/pstore/%0.16d/dmesg.txt" "$last_id_2")"
    diff "$DUMMY_DMESG_2" "$filename_2"
    grep "hello world" "/var/lib/systemd/pstore/foo.bar"

    : "Backend: ERST; Storage: journal; Unlink: $unlink"
    prepare_pstore_config "journal" "$unlink"
    last_id="$(prepare_erst_logs "$DUMMY_DMESG_1" 0)"
    [[ "$unlink" == yes ]] && exp_count=0 || exp_count="$(file_count /sys/fs/pstore/)"
    start_pstore
    [[ "$(file_count /sys/fs/pstore)" -ge "$exp_count" ]]
    [[ "$(file_count /var/lib/systemd/pstore/)" -eq 0 ]]
    diff "$DUMMY_DMESG_1" <(journalctl -o cat --output-fields=FILE --cursor-file=/tmp/journal.cursor | sed "/^$/d")
done
