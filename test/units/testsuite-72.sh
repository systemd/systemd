#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# -*- mode: shell-script; indent-tabs-mode: nil; sh-basic-offset: 4; -*-
# ex: ts=8 sw=4 sts=4 et filetype=sh
set -eux
set -o pipefail

SYSUPDATE=/lib/systemd/systemd-sysupdate
SECTOR_SIZES="512 4096"
BACKING_FILE=/var/tmp/72-joined.raw
export SYSTEMD_ESP_PATH=/var/tmp/72-esp
export SYSTEMD_XBOOTLDR_PATH=/var/tmp/72-xbootldr
export SYSTEMD_PAGER=cat
export SYSTEMD_LOG_LEVEL=debug

if ! test -x "$SYSUPDATE"; then
    echo "no systemd-sysupdate" >/skipped
    exit 0
fi

# Loopback devices may not be supported. They are used because sfdisk cannot
# change the sector size of a file, and we want to test both 512 and 4096 byte
# sectors. If loopback devices are not supported, we can only test one sector
# size, and the underlying device is likely to have a sector size of 512 bytes.
if ! losetup --find >/dev/null 2>&1; then
    echo "No loopback device support"
    SECTOR_SIZES="512"
fi

trap cleanup ERR
cleanup() {
    set +o pipefail
    blockdev="$( losetup --list --output NAME,BACK-FILE | grep $BACKING_FILE | cut -d' ' -f1)"
    [ -n "$blockdev" ] && losetup --detach "$blockdev"
    rm -f "$BACKING_FILE"
    rm -rf /var/tmp/72-{dirs,defs,source,xbootldr,esp}
    rm -f /testok
}

new_version() {
    # Inputs:
    # $1: sector size
    # $2: version

    # Create a pair of random partition payloads, and compress one
    dd if=/dev/urandom of="/var/tmp/72-source/part1-$2.raw" bs="$1" count=2048
    dd if=/dev/urandom of="/var/tmp/72-source/part2-$2.raw" bs="$1" count=2048
    gzip -k -f "/var/tmp/72-source/part2-$2.raw"

    # Create a random "UKI" payload
    echo $RANDOM >"/var/tmp/72-source/uki-$2.efi"

    # Create a random extra payload
    echo $RANDOM >"/var/tmp/72-source/uki-extra-$2.efi"

    # Create tarball of a directory
    mkdir -p "/var/tmp/72-source/dir-$2"
    echo $RANDOM >"/var/tmp/72-source/dir-$2/foo.txt"
    echo $RANDOM >"/var/tmp/72-source/dir-$2/bar.txt"
    tar --numeric-owner -C "/var/tmp/72-source/dir-$2/" -czf "/var/tmp/72-source/dir-$2.tar.gz" .

    ( cd /var/tmp/72-source/ && sha256sum uki* part* dir-*.tar.gz >SHA256SUMS )
}

update_now() {
    # Update to newest version. First there should be an update ready, then we
    # do the update, and then there should not be any ready anymore

    "$SYSUPDATE" --definitions=/var/tmp/72-defs --verify=no check-new
    "$SYSUPDATE" --definitions=/var/tmp/72-defs --verify=no update
    ( ! "$SYSUPDATE" --definitions=/var/tmp/72-defs --verify=no check-new )
}

verify_version() {
    # Inputs:
    # $1: block device
    # $2: sector size
    # $3: version
    # $4: partition number of part1
    # $5: partition number of part2

    gpt_reserved_sectors=$(( 1024 * 1024 / $2 ))
    part1_offset=$(( ( $4 - 1 ) * 2048 + gpt_reserved_sectors ))
    part2_offset=$(( ( $5 - 1 ) * 2048 + gpt_reserved_sectors ))

    # Check the partitions
    dd if="$1" bs="$2" skip="$part1_offset" count=2048 | cmp "/var/tmp/72-source/part1-$3.raw"
    dd if="$1" bs="$2" skip="$part2_offset" count=2048 | cmp "/var/tmp/72-source/part2-$3.raw"

    # Check the UKI
    cmp "/var/tmp/72-source/uki-$3.efi" "/var/tmp/72-xbootldr/EFI/Linux/uki_$3+3-0.efi"
    test -z "$(ls -A /var/tmp/72-esp/EFI/Linux)"

    # Check the extra efi
    cmp "/var/tmp/72-source/uki-extra-$3.efi" "/var/tmp/72-xbootldr/EFI/Linux/uki_$3.efi.extra.d/extra.addon.efi"

    # Check the directories
    cmp "/var/tmp/72-source/dir-$3/foo.txt" /var/tmp/72-dirs/current/foo.txt
    cmp "/var/tmp/72-source/dir-$3/bar.txt" /var/tmp/72-dirs/current/bar.txt
}

for sector_size in $SECTOR_SIZES ; do
    # Disk size of:
    # - 1MB for GPT
    # - 4 partitions of 2048 sectors each
    # - 1MB for backup GPT
    disk_size=$(( sector_size * 2048 * 4 + 1024 * 1024 * 2 ))
    rm -f "$BACKING_FILE"
    truncate -s "$disk_size" "$BACKING_FILE"

    if losetup --find >/dev/null 2>&1; then
        # shellcheck disable=SC2086
        blockdev="$(losetup --find --show --sector-size $sector_size $BACKING_FILE)"
    else
        blockdev="$BACKING_FILE"
    fi

    sfdisk "$blockdev" <<EOF
label: gpt
unit: sectors
sector-size: $sector_size

size=2048, type=4f68bce3-e8cd-4db1-96e7-fbcaf984b709, name=_empty
size=2048, type=4f68bce3-e8cd-4db1-96e7-fbcaf984b709, name=_empty
size=2048, type=2c7357ed-ebd2-46d9-aec1-23d437ec2bf5, name=_empty
size=2048, type=2c7357ed-ebd2-46d9-aec1-23d437ec2bf5, name=_empty
EOF

    rm -rf /var/tmp/72-dirs
    mkdir -p /var/tmp/72-dirs

    rm -rf /var/tmp/72-defs
    mkdir -p /var/tmp/72-defs

    cat >/var/tmp/72-defs/01-first.conf <<EOF
[Source]
Type=regular-file
Path=/var/tmp/72-source
MatchPattern=part1-@v.raw

[Target]
Type=partition
Path=$blockdev
MatchPattern=part1-@v
MatchPartitionType=root-x86-64
EOF

    cat >/var/tmp/72-defs/02-second.conf <<EOF
[Source]
Type=regular-file
Path=/var/tmp/72-source
MatchPattern=part2-@v.raw.gz

[Target]
Type=partition
Path=$blockdev
MatchPattern=part2-@v
MatchPartitionType=root-x86-64-verity
EOF

    cat >/var/tmp/72-defs/03-third.conf <<EOF
[Source]
Type=directory
Path=/var/tmp/72-source
MatchPattern=dir-@v

[Target]
Type=directory
Path=/var/tmp/72-dirs
CurrentSymlink=/var/tmp/72-dirs/current
MatchPattern=dir-@v
InstancesMax=3
EOF

    cat >/var/tmp/72-defs/04-fourth.conf <<EOF
[Source]
Type=regular-file
Path=/var/tmp/72-source
MatchPattern=uki-@v.efi

[Target]
Type=regular-file
Path=/EFI/Linux
PathRelativeTo=boot
MatchPattern=uki_@v+@l-@d.efi \
            uki_@v+@l.efi \
            uki_@v.efi
Mode=0444
TriesLeft=3
TriesDone=0
InstancesMax=2
EOF

    cat >/var/tmp/72-defs/05-fifth.conf <<EOF
[Source]
Type=regular-file
Path=/var/tmp/72-source
MatchPattern=uki-extra-@v.efi

[Target]
Type=regular-file
Path=/EFI/Linux
PathRelativeTo=boot
MatchPattern=uki_@v.efi.extra.d/extra.addon.efi
Mode=0444
InstancesMax=2
EOF

    rm -rf /var/tmp/72-esp /var/tmp/72-xbootldr
    mkdir -p /var/tmp/72-esp/EFI/Linux /var/tmp/72-xbootldr/EFI/Linux

    rm -rf /var/tmp/72-source
    mkdir -p /var/tmp/72-source

    # Install initial version and verify
    new_version "$sector_size" v1
    update_now
    verify_version "$blockdev" "$sector_size" v1 1 3

    # Create second version, update and verify that it is added
    new_version "$sector_size" v2
    update_now
    verify_version "$blockdev" "$sector_size" v2 2 4

    # Create third version, update and verify it replaced the first version
    new_version "$sector_size" v3
    update_now
    verify_version "$blockdev" "$sector_size" v3 1 3
    test ! -f "/var/tmp/72-xbootldr/EFI/Linux/uki_v1+3-0.efi"
    test ! -f "/var/tmp/72-xbootldr/EFI/Linux/uki_v1.efi.extra.d/extra.addon.efi"
    test ! -d "/var/tmp/72-xbootldr/EFI/Linux/uki_v1.efi.extra.d"

    # Create fourth version, and update through a file:// URL. This should be
    # almost as good as testing HTTP, but is simpler for us to set up. file:// is
    # abstracted in curl for us, and since our main goal is to test our own code
    # (and not curl) this test should be quite good even if not comprehensive. This
    # will test the SHA256SUMS logic at least (we turn off GPG validation though,
    # see above)
    new_version "$sector_size" v4

    cat >/var/tmp/72-defs/02-second.conf <<EOF
[Source]
Type=url-file
Path=file:///var/tmp/72-source
MatchPattern=part2-@v.raw.gz

[Target]
Type=partition
Path=$blockdev
MatchPattern=part2-@v
MatchPartitionType=root-x86-64-verity
EOF

    cat >/var/tmp/72-defs/03-third.conf <<EOF
[Source]
Type=url-tar
Path=file:///var/tmp/72-source
MatchPattern=dir-@v.tar.gz

[Target]
Type=directory
Path=/var/tmp/72-dirs
CurrentSymlink=/var/tmp/72-dirs/current
MatchPattern=dir-@v
InstancesMax=3
EOF

    update_now
    verify_version "$blockdev" "$sector_size" v4 2 4

    # Cleanup
    [ -b "$blockdev" ] && losetup --detach "$blockdev"
    rm "$BACKING_FILE"
done

rm -r /var/tmp/72-{dirs,defs,source,xbootldr,esp}

touch /testok
