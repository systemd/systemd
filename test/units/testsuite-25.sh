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
machinectl clone testimage testimage3
test -f /var/lib/machines/testimage3.raw
machinectl image-status testimage3
test -f /var/lib/machines/testimage.raw
machinectl image-status testimage
cmp /var/tmp/testimage.raw /var/lib/machines/testimage.raw
cmp /var/tmp/testimage.raw /var/lib/machines/testimage3.raw

# Test removal
machinectl remove testimage
test ! -f /var/lib/machines/testimage.raw
(! machinectl image-status testimage)

# Test export of clone
machinectl export-raw testimage3 /var/tmp/testimage3.raw
cmp /var/tmp/testimage.raw /var/tmp/testimage3.raw
rm /var/tmp/testimage3.raw

# Test rename
machinectl rename testimage3 testimage4
test -f /var/lib/machines/testimage4.raw
machinectl image-status testimage4
test ! -f /var/lib/machines/testimage3.raw
(! machinectl image-status testimage3)
cmp /var/tmp/testimage.raw /var/lib/machines/testimage4.raw

# Test export of rename
machinectl export-raw testimage4 /var/tmp/testimage4.raw
cmp /var/tmp/testimage.raw /var/tmp/testimage4.raw
rm /var/tmp/testimage4.raw

# Test removal
machinectl remove testimage4
test ! -f /var/lib/machines/testimage4.raw
(! machinectl image-status testimage4)

# → And now, let's test directory trees ← #

# Set up a directory we can import
mkdir /var/tmp/scratch
mv /var/tmp/testimage.raw /var/tmp/scratch/
touch /var/tmp/scratch/anotherfile
mkdir /var/tmp/scratch/adirectory
echo "piep" >/var/tmp/scratch/adirectory/athirdfile

# Test import-fs
machinectl import-fs /var/tmp/scratch/
test -d /var/lib/machines/scratch
machinectl image-status scratch

# Test export-tar
machinectl export-tar scratch /var/tmp/scratch.tar.gz
test -f /var/tmp/scratch.tar.gz
mkdir /var/tmp/extract
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

echo OK >/testok

exit 0
