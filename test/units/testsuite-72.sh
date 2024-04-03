#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# -*- mode: shell-script; indent-tabs-mode: nil; sh-basic-offset: 4; -*-
# ex: ts=8 sw=4 sts=4 et filetype=sh
set -eux
set -o pipefail

SYSUPDATE=/lib/systemd/systemd-sysupdate
SECTOR_SIZES=(512 4096)
WORKDIR="$(mktemp -d /var/tmp/test-72-XXXXXX)"
BACKING_FILE="$WORKDIR/joined.raw"
export SYSTEMD_ESP_PATH="$WORKDIR/esp"
export SYSTEMD_XBOOTLDR_PATH="$WORKDIR/xbootldr"
export SYSTEMD_PAGER=cat
export SYSTEMD_LOG_LEVEL=debug

if [[ ! -x "$SYSUPDATE" ]]; then
    echo "no systemd-sysupdate" >/skipped
    exit 77
fi

# Loopback devices may not be supported. They are used because sfdisk cannot
# change the sector size of a file, and we want to test both 512 and 4096 byte
# sectors. If loopback devices are not supported, we can only test one sector
# size, and the underlying device is likely to have a sector size of 512 bytes.
if [[ ! -e /dev/loop-control ]]; then
    echo "No loopback device support"
    SECTOR_SIZES=(512)
fi

at_exit() {
    set +e

    losetup -n --output NAME --associated "$BACKING_FILE" | while read -r loop_dev; do
        losetup --detach "$loop_dev"
    done

    rm -rf "$WORKDIR"
}

trap at_exit EXIT

new_version() {
    local sector_size="${1:?}"
    local version="${2:?}"

    # Create a pair of random partition payloads, and compress one
    dd if=/dev/urandom of="$WORKDIR/source/part1-$version.raw" bs="$sector_size" count=2048
    dd if=/dev/urandom of="$WORKDIR/source/part2-$version.raw" bs="$sector_size" count=2048
    gzip -k -f "$WORKDIR/source/part2-$version.raw"

    # Create a random "UKI" payload
    echo $RANDOM >"$WORKDIR/source/uki-$version.efi"

    # Create a random extra payload
    echo $RANDOM >"$WORKDIR/source/uki-extra-$version.efi"

    # Create tarball of a directory
    mkdir -p "$WORKDIR/source/dir-$version"
    echo $RANDOM >"$WORKDIR/source/dir-$version/foo.txt"
    echo $RANDOM >"$WORKDIR/source/dir-$version/bar.txt"
    tar --numeric-owner -C "$WORKDIR/source/dir-$version/" -czf "$WORKDIR/source/dir-$version.tar.gz" .

    (cd "$WORKDIR/source" && sha256sum uki* part* dir-*.tar.gz >SHA256SUMS)
}

update_now() {
    # Update to newest version. First there should be an update ready, then we
    # do the update, and then there should not be any ready anymore

    "$SYSUPDATE" --definitions="$WORKDIR/defs" --verify=no check-new
    "$SYSUPDATE" --definitions="$WORKDIR/defs" --verify=no update
    (! "$SYSUPDATE" --definitions="$WORKDIR/defs" --verify=no check-new)
}

verify_version() {
    local block_device="${1:?}"
    local sector_size="${2:?}"
    local version="${3:?}"
    local part1_number="${4:?}"
    local part2_number="${5:?}"
    local gpt_reserved_sectors part1_offset part2_offset

    gpt_reserved_sectors=$((1024 * 1024 / sector_size))
    part1_offset=$(((part1_number - 1) * 2048 + gpt_reserved_sectors))
    part2_offset=$(((part2_number - 1) * 2048 + gpt_reserved_sectors))

    # Check the partitions
    dd if="$block_device" bs="$sector_size" skip="$part1_offset" count=2048 | cmp "$WORKDIR/source/part1-$version.raw"
    dd if="$block_device" bs="$sector_size" skip="$part2_offset" count=2048 | cmp "$WORKDIR/source/part2-$version.raw"

    # Check the UKI
    cmp "$WORKDIR/source/uki-$version.efi" "$WORKDIR/xbootldr/EFI/Linux/uki_$version+3-0.efi"
    test -z "$(ls -A "$WORKDIR/esp/EFI/Linux")"

    # Check the extra efi
    cmp "$WORKDIR/source/uki-extra-$version.efi" "$WORKDIR/xbootldr/EFI/Linux/uki_$version.efi.extra.d/extra.addon.efi"

    # Check the directories
    cmp "$WORKDIR/source/dir-$version/foo.txt" "$WORKDIR/dirs/current/foo.txt"
    cmp "$WORKDIR/source/dir-$version/bar.txt" "$WORKDIR/dirs/current/bar.txt"
}

for sector_size in "${SECTOR_SIZES[@]}"; do
    # Disk size of:
    # - 1MB for GPT
    # - 4 partitions of 2048 sectors each
    # - 1MB for backup GPT
    disk_size=$((sector_size * 2048 * 4 + 1024 * 1024 * 2))
    rm -f "$BACKING_FILE"
    truncate -s "$disk_size" "$BACKING_FILE"

    if [[ -e /dev/loop-control ]]; then
        blockdev="$(losetup --find --show --sector-size "$sector_size" "$BACKING_FILE")"
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

    for d in "dirs" "defs"; do
        rm -rf "${WORKDIR:?}/$d"
        mkdir -p "$WORKDIR/$d"
    done

    cat >"$WORKDIR/defs/01-first.conf" <<EOF
[Source]
Type=regular-file
Path=$WORKDIR/source
MatchPattern=part1-@v.raw

[Target]
Type=partition
Path=$blockdev
MatchPattern=part1-@v
MatchPartitionType=root-x86-64
EOF

    cat >"$WORKDIR/defs/02-second.conf" <<EOF
[Source]
Type=regular-file
Path=$WORKDIR/source
MatchPattern=part2-@v.raw.gz

[Target]
Type=partition
Path=$blockdev
MatchPattern=part2-@v
MatchPartitionType=root-x86-64-verity
EOF

    cat >"$WORKDIR/defs/03-third.conf" <<EOF
[Source]
Type=directory
Path=$WORKDIR/source
MatchPattern=dir-@v

[Target]
Type=directory
Path=$WORKDIR/dirs
CurrentSymlink=$WORKDIR/dirs/current
MatchPattern=dir-@v
InstancesMax=3
EOF

    cat >"$WORKDIR/defs/04-fourth.conf" <<EOF
[Source]
Type=regular-file
Path=$WORKDIR/source
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

    cat >"$WORKDIR/defs/05-fifth.conf" <<EOF
[Source]
Type=regular-file
Path=$WORKDIR/source
MatchPattern=uki-extra-@v.efi

[Target]
Type=regular-file
Path=/EFI/Linux
PathRelativeTo=boot
MatchPattern=uki_@v.efi.extra.d/extra.addon.efi
Mode=0444
InstancesMax=2
EOF

    rm -rf "${WORKDIR:?}"/{esp,xbootldr,source}
    mkdir -p "$WORKDIR"/{source,esp/EFI/Linux,xbootldr/EFI/Linux}

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
    test ! -f "$WORKDIR/xbootldr/EFI/Linux/uki_v1+3-0.efi"
    test ! -f "$WORKDIR/xbootldr/EFI/Linux/uki_v1.efi.extra.d/extra.addon.efi"
    test ! -d "$WORKDIR/xbootldr/EFI/Linux/uki_v1.efi.extra.d"

    # Create fourth version, and update through a file:// URL. This should be
    # almost as good as testing HTTP, but is simpler for us to set up. file:// is
    # abstracted in curl for us, and since our main goal is to test our own code
    # (and not curl) this test should be quite good even if not comprehensive. This
    # will test the SHA256SUMS logic at least (we turn off GPG validation though,
    # see above)
    new_version "$sector_size" v4

    cat >"$WORKDIR/defs/02-second.conf" <<EOF
[Source]
Type=url-file
Path=file://$WORKDIR/source
MatchPattern=part2-@v.raw.gz

[Target]
Type=partition
Path=$blockdev
MatchPattern=part2-@v
MatchPartitionType=root-x86-64-verity
EOF

    cat >"$WORKDIR/defs/03-third.conf" <<EOF
[Source]
Type=url-tar
Path=file://$WORKDIR/source
MatchPattern=dir-@v.tar.gz

[Target]
Type=directory
Path=$WORKDIR/dirs
CurrentSymlink=$WORKDIR/dirs/current
MatchPattern=dir-@v
InstancesMax=3
EOF

    update_now
    verify_version "$blockdev" "$sector_size" v4 2 4

    # Cleanup
    [[ -b "$blockdev" ]] && losetup --detach "$blockdev"
    rm "$BACKING_FILE"
done

touch /testok
