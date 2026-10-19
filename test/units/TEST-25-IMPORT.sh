#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

export SYSTEMD_PAGER=cat

dd if=/dev/urandom of=/var/tmp/testimage.raw bs=$((1024*1024+7)) count=5

# Test import
machinectl import-raw /var/tmp/testimage.raw
machinectl image-status testimage
test -f /var/lib/machines/testimage.raw
cmp /var/tmp/testimage.raw /var/lib/machines/testimage.raw

# Test export
machinectl export-raw testimage /var/tmp/testimage2.raw
cmp /var/tmp/testimage.raw /var/tmp/testimage2.raw
rm /var/tmp/testimage2.raw

# Test compressed export (gzip)
machinectl export-raw testimage /var/tmp/testimage2.raw.gz
gunzip /var/tmp/testimage2.raw.gz
cmp /var/tmp/testimage.raw /var/tmp/testimage2.raw
rm /var/tmp/testimage2.raw

# Test clone
printf 'hash\n' >/var/lib/machines/testimage.roothash
printf 'verity\n' >/var/lib/machines/testimage.verity
printf 'tpmstate\n' >/var/lib/machines/testimage.raw.tpmstate
machinectl clone testimage testimage3
test -f /var/lib/machines/testimage3.raw
test -f /var/lib/machines/testimage3.roothash
test -f /var/lib/machines/testimage3.verity
test -f /var/lib/machines/testimage3.raw.tpmstate
machinectl image-status testimage3
test -f /var/lib/machines/testimage.raw
test -f /var/lib/machines/testimage.roothash
test -f /var/lib/machines/testimage.verity
test -f /var/lib/machines/testimage.raw.tpmstate
machinectl image-status testimage
cmp /var/tmp/testimage.raw /var/lib/machines/testimage.raw
cmp /var/tmp/testimage.raw /var/lib/machines/testimage3.raw
grep -Fx hash /var/lib/machines/testimage3.roothash
grep -Fx verity /var/lib/machines/testimage3.verity
grep -Fx tpmstate /var/lib/machines/testimage3.raw.tpmstate

# Test removal
machinectl remove testimage
test ! -f /var/lib/machines/testimage.raw
test ! -f /var/lib/machines/testimage.roothash
test ! -f /var/lib/machines/testimage.verity
test ! -f /var/lib/machines/testimage.raw.tpmstate
(! machinectl image-status testimage)

# Test export of clone
machinectl export-raw testimage3 /var/tmp/testimage3.raw
cmp /var/tmp/testimage.raw /var/tmp/testimage3.raw
rm /var/tmp/testimage3.raw

# Test rename
machinectl rename testimage3 testimage4
test -f /var/lib/machines/testimage4.raw
test -f /var/lib/machines/testimage4.roothash
test -f /var/lib/machines/testimage4.verity
test -f /var/lib/machines/testimage4.raw.tpmstate
machinectl image-status testimage4
test ! -f /var/lib/machines/testimage3.raw
test ! -f /var/lib/machines/testimage3.roothash
test ! -f /var/lib/machines/testimage3.verity
test ! -f /var/lib/machines/testimage3.raw.tpmstate
(! machinectl image-status testimage3)
cmp /var/tmp/testimage.raw /var/lib/machines/testimage4.raw
grep -Fx hash /var/lib/machines/testimage4.roothash
grep -Fx verity /var/lib/machines/testimage4.verity
grep -Fx tpmstate /var/lib/machines/testimage4.raw.tpmstate

# Test export of rename
machinectl export-raw testimage4 /var/tmp/testimage4.raw
cmp /var/tmp/testimage.raw /var/tmp/testimage4.raw
rm /var/tmp/testimage4.raw

# Test removal
machinectl remove testimage4
test ! -f /var/lib/machines/testimage4.raw
test ! -f /var/lib/machines/testimage4.roothash
test ! -f /var/lib/machines/testimage4.verity
test ! -f /var/lib/machines/testimage4.raw.tpmstate
(! machinectl image-status testimage4)

# → And now, let's test directory trees ← #

# Set up a directory we can import
mkdir -p /var/tmp/scratch
mv /var/tmp/testimage.raw /var/tmp/scratch/
touch /var/tmp/scratch/anotherfile
mkdir -p /var/tmp/scratch/adirectory
echo "piep" >/var/tmp/scratch/adirectory/athirdfile

# Test import-fs
machinectl import-fs /var/tmp/scratch/
test -d /var/lib/machines/scratch
machinectl image-status scratch

# Test export-tar
machinectl export-tar scratch /var/tmp/scratch.tar.gz
test -f /var/tmp/scratch.tar.gz
mkdir -p /var/tmp/extract
(cd /var/tmp/extract ; tar xzf /var/tmp/scratch.tar.gz)
diff -r /var/tmp/scratch/ /var/tmp/extract/
rm -rf /var/tmp/extract

# Test import-tar
machinectl import-tar /var/tmp/scratch.tar.gz scratch2
test -d /var/lib/machines/scratch2
machinectl image-status scratch2
diff -r /var/tmp/scratch/ /var/lib/machines/scratch2

# Test removal
machinectl remove scratch
test ! -f /var/lib/machines/scratch
(! machinectl image-status scratch)

# Test clone
machinectl clone scratch2 scratch3
test -d /var/lib/machines/scratch2
machinectl image-status scratch2
test -d /var/lib/machines/scratch3
machinectl image-status scratch3
diff -r /var/tmp/scratch/ /var/lib/machines/scratch3

# Test removal
machinectl remove scratch2
test ! -f /var/lib/machines/scratch2
(! machinectl image-status scratch2)

# Test rename
machinectl rename scratch3 scratch4
test -d /var/lib/machines/scratch4
machinectl image-status scratch4
test ! -f /var/lib/machines/scratch3
(! machinectl image-status scratch3)
diff -r /var/tmp/scratch/ /var/lib/machines/scratch4

# Test removal
machinectl remove scratch4
test ! -f /var/lib/machines/scratch4
(! machinectl image-status scratch4)

# Test import-tar hyphen/stdin pipe behavior
# shellcheck disable=SC2002
cat /var/tmp/scratch.tar.gz | machinectl import-tar - scratch5
test -d /var/lib/machines/scratch5
machinectl image-status scratch5
diff -r /var/tmp/scratch/ /var/lib/machines/scratch5

# Test export-tar hyphen/stdout pipe behavior
mkdir -p /var/tmp/extract
machinectl export-tar scratch5 - | tar xvf - -C /var/tmp/extract/
diff -r /var/tmp/scratch/ /var/tmp/extract/
rm -rf /var/tmp/extract

rm -rf /var/tmp/scratch

# Test removal
machinectl remove scratch5
test ! -f /var/lib/machines/scratch5
(! machinectl image-status scratch5)

# → Now, let's test explicit compression selection and verification of the decoded data ← #

IMPORT=/usr/lib/systemd/systemd-import
PULL=/usr/lib/systemd/systemd-pull
COMPDIR=/var/tmp/compression
rm -rf "$COMPDIR"
mkdir -p "$COMPDIR/root"

# Start with a fixed header, so that the random data cannot accidentally begin with a compression magic
{ echo "systemd-import-test"; dd if=/dev/urandom bs=4096 count=64 status=none; } >"$COMPDIR/payload.raw"
PAYLOAD_HASH="$(sha256sum "$COMPDIR/payload.raw" | cut -d' ' -f1)"
WRONG_HASH=0000000000000000000000000000000000000000000000000000000000000000

# Invalid arguments are refused
(! "$IMPORT" raw --compression=foobar --direct "$COMPDIR/payload.raw" "$COMPDIR/out.raw")
(! "$IMPORT" raw --verify-decoded=abcd --direct "$COMPDIR/payload.raw" "$COMPDIR/out.raw")
(! "$PULL" raw --compression=foobar --verify=no --direct "file://$COMPDIR/payload.raw" "$COMPDIR/out.raw")
(! "$PULL" raw --verify-decoded=abcd --verify=no --direct "file://$COMPDIR/payload.raw" "$COMPDIR/out.raw")
(! "$PULL" oci --verify-decoded="$PAYLOAD_HASH" foo/bar)
(! "$PULL" oci --compression=gzip foo/bar)
test ! -e "$COMPDIR/out.raw"

# Uncompressed input, with "none" and "auto", with and without (empty, i.e. reset) decoded digest
for c in none auto; do
    "$IMPORT" raw --compression="$c" --verify-decoded="$PAYLOAD_HASH" --direct "$COMPDIR/payload.raw" "$COMPDIR/out.raw"
    cmp "$COMPDIR/payload.raw" "$COMPDIR/out.raw"
    rm "$COMPDIR/out.raw"
    "$IMPORT" raw --compression="$c" --verify-decoded="$WRONG_HASH" --verify-decoded= --direct "$COMPDIR/payload.raw" "$COMPDIR/out.raw"
    cmp "$COMPDIR/payload.raw" "$COMPDIR/out.raw"
    rm "$COMPDIR/out.raw"
    "$PULL" raw --compression="$c" --verify=no --verify-decoded="$PAYLOAD_HASH" --direct "file://$COMPDIR/payload.raw" "$COMPDIR/out.raw"
    cmp "$COMPDIR/payload.raw" "$COMPDIR/out.raw"
    rm "$COMPDIR/out.raw"
done

for c in gzip xz zstd bzip2 lz4; do
    if ! command -v "$c" >/dev/null; then
        echo "$c not available, skipping."
        continue
    fi

    case "$c" in
        gzip)  ext=gz;  other=xz ;;
        xz)    ext=xz;  other=gzip ;;
        zstd)  ext=zst; other=gzip ;;
        bzip2) ext=bz2; other=gzip ;;
        lz4)   ext=lz4; other=gzip ;;
    esac

    # Skip algorithms the tools have not been built with
    if ! "$IMPORT" --compression="$c" --help >/dev/null; then
        echo "$c not supported by systemd-import, skipping."
        continue
    fi

    "$c" -q -c "$COMPDIR/payload.raw" >"$COMPDIR/payload.raw.$ext"
    ENCODED_HASH="$(sha256sum "$COMPDIR/payload.raw.$ext" | cut -d' ' -f1)"

    # Autodetection and the explicitly specified algorithm both decompress the data
    for m in auto "$c"; do
        "$IMPORT" raw --compression="$m" --direct "$COMPDIR/payload.raw.$ext" "$COMPDIR/out.raw"
        cmp "$COMPDIR/payload.raw" "$COMPDIR/out.raw"
        rm "$COMPDIR/out.raw"

        "$PULL" raw --compression="$m" --verify=no --direct "file://$COMPDIR/payload.raw.$ext" "$COMPDIR/out.raw"
        cmp "$COMPDIR/payload.raw" "$COMPDIR/out.raw"
        rm "$COMPDIR/out.raw"
    done

    # With "none" no decompression takes place, the data is taken as is
    "$IMPORT" raw --compression=none --direct "$COMPDIR/payload.raw.$ext" "$COMPDIR/out.raw"
    cmp "$COMPDIR/payload.raw.$ext" "$COMPDIR/out.raw"
    rm "$COMPDIR/out.raw"
    "$PULL" raw --compression=none --verify=no --direct "file://$COMPDIR/payload.raw.$ext" "$COMPDIR/out.raw"
    cmp "$COMPDIR/payload.raw.$ext" "$COMPDIR/out.raw"
    rm "$COMPDIR/out.raw"

    # If a different algorithm is specified, it is strictly used, and hence decoding fails
    (! "$IMPORT" raw --compression="$other" --direct "$COMPDIR/payload.raw.$ext" "$COMPDIR/out.raw")
    rm -f "$COMPDIR/out.raw"
    (! "$PULL" raw --compression="$other" --verify=no --direct "file://$COMPDIR/payload.raw.$ext" "$COMPDIR/out.raw")
    rm -f "$COMPDIR/out.raw"

    # --verify-decoded= checks the decompressed data, not the data as downloaded
    "$IMPORT" raw --image-root="$COMPDIR/root" --compression="$c" --verify-decoded="$PAYLOAD_HASH" "$COMPDIR/payload.raw.$ext" good
    cmp "$COMPDIR/payload.raw" "$COMPDIR/root/good.raw"
    rm "$COMPDIR/root/good.raw"
    (! "$IMPORT" raw --image-root="$COMPDIR/root" --verify-decoded="$ENCODED_HASH" "$COMPDIR/payload.raw.$ext" bad)
    test ! -e "$COMPDIR/root/bad.raw"
    (! "$IMPORT" raw --image-root="$COMPDIR/root" --verify-decoded="$WRONG_HASH" "$COMPDIR/payload.raw.$ext" bad)
    test ! -e "$COMPDIR/root/bad.raw"
    # … unless no decompression takes place, in which case the encoded and decoded data are the same
    "$IMPORT" raw --image-root="$COMPDIR/root" --compression=none --verify-decoded="$ENCODED_HASH" "$COMPDIR/payload.raw.$ext" good
    cmp "$COMPDIR/payload.raw.$ext" "$COMPDIR/root/good.raw"
    rm "$COMPDIR/root/good.raw"

    # systemd-pull's --verify= covers the downloaded data, --verify-decoded= the decompressed data
    "$PULL" raw --image-root="$COMPDIR/root" --keep-download=no --settings=no --roothash=no --roothash-signature=no --verity=no \
            --compression="$c" --verify="$ENCODED_HASH" --verify-decoded="$PAYLOAD_HASH" "file://$COMPDIR/payload.raw.$ext" good
    cmp "$COMPDIR/payload.raw" "$COMPDIR/root/good.raw"
    rm "$COMPDIR/root/good.raw"
    (! "$PULL" raw --image-root="$COMPDIR/root" --keep-download=no --settings=no --roothash=no --roothash-signature=no --verity=no \
               --verify="$ENCODED_HASH" --verify-decoded="$ENCODED_HASH" "file://$COMPDIR/payload.raw.$ext" bad)
    test ! -e "$COMPDIR/root/bad.raw"
    (! "$PULL" raw --image-root="$COMPDIR/root" --keep-download=no --settings=no --roothash=no --roothash-signature=no --verity=no \
               --verify=no --verify-decoded="$WRONG_HASH" "file://$COMPDIR/payload.raw.$ext" bad)
    test ! -e "$COMPDIR/root/bad.raw"
done

# The same for tarballs, where the decoded digest covers the uncompressed tar stream
mkdir -p "$COMPDIR/tree/adirectory"
echo "waldo" >"$COMPDIR/tree/adirectory/afile"
tar cf "$COMPDIR/tree.tar" -C "$COMPDIR/tree" .
TAR_HASH="$(sha256sum "$COMPDIR/tree.tar" | cut -d' ' -f1)"
gzip -c "$COMPDIR/tree.tar" >"$COMPDIR/tree.tar.gz"

"$IMPORT" tar --image-root="$COMPDIR/root" --compression=gzip --verify-decoded="$TAR_HASH" "$COMPDIR/tree.tar.gz" good
diff -r "$COMPDIR/tree" "$COMPDIR/root/good"
rm -rf "$COMPDIR/root/good"
(! "$IMPORT" tar --image-root="$COMPDIR/root" --compression=xz "$COMPDIR/tree.tar.gz" bad)
test ! -e "$COMPDIR/root/bad"
(! "$IMPORT" tar --image-root="$COMPDIR/root" --verify-decoded="$WRONG_HASH" "$COMPDIR/tree.tar.gz" bad)
test ! -e "$COMPDIR/root/bad"

"$PULL" tar --image-root="$COMPDIR/root" --keep-download=no --settings=no --verify=no --compression=gzip --verify-decoded="$TAR_HASH" "file://$COMPDIR/tree.tar.gz" good
diff -r "$COMPDIR/tree" "$COMPDIR/root/good"
rm -rf "$COMPDIR/root/good"
(! "$PULL" tar --image-root="$COMPDIR/root" --keep-download=no --settings=no --verify=no --compression=xz "file://$COMPDIR/tree.tar.gz" bad)
test ! -e "$COMPDIR/root/bad"
(! "$PULL" tar --image-root="$COMPDIR/root" --keep-download=no --settings=no --verify=no --verify-decoded="$WRONG_HASH" "file://$COMPDIR/tree.tar.gz" bad)
test ! -e "$COMPDIR/root/bad"

rm -rf "$COMPDIR"

touch /testok
