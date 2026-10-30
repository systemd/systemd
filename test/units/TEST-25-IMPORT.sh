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

# → systemd-pull can extract a range of the decoded data ← #

PAYLOAD_SIZE="$(stat -c %s "$COMPDIR/payload.raw")"
dd if="$COMPDIR/payload.raw" of="$COMPDIR/slice.raw" iflag=skip_bytes,count_bytes skip=1000 count=5000 status=none
dd if="$COMPDIR/payload.raw" of="$COMPDIR/tail.raw" iflag=skip_bytes skip=1000 status=none
dd if="$COMPDIR/payload.raw" of="$COMPDIR/head.raw" iflag=count_bytes count=5000 status=none
dd if="$COMPDIR/payload.raw" of="$COMPDIR/end.raw" iflag=skip_bytes skip=$((PAYLOAD_SIZE - 10)) status=none
SLICE_HASH="$(sha256sum "$COMPDIR/slice.raw" | cut -d' ' -f1)"

# --verify-decoded= covers just the range
"$PULL" raw --verify=no --direct --source-offset=1000 --source-size=5000 --verify-decoded="$SLICE_HASH" "file://$COMPDIR/payload.raw" "$COMPDIR/out.raw"
cmp "$COMPDIR/slice.raw" "$COMPDIR/out.raw"
rm "$COMPDIR/out.raw"
(! "$PULL" raw --verify=no --direct --source-offset=1000 --source-size=5000 --verify-decoded="$PAYLOAD_HASH" "file://$COMPDIR/payload.raw" "$COMPDIR/out.raw")
rm -f "$COMPDIR/out.raw"

# Without a size the range extends to the end, without an offset it starts at the beginning
"$PULL" raw --verify=no --direct --source-offset=1000 "file://$COMPDIR/payload.raw" "$COMPDIR/out.raw"
cmp "$COMPDIR/tail.raw" "$COMPDIR/out.raw"
rm "$COMPDIR/out.raw"
"$PULL" raw --verify=no --direct --source-size=5000 "file://$COMPDIR/payload.raw" "$COMPDIR/out.raw"
cmp "$COMPDIR/head.raw" "$COMPDIR/out.raw"
rm "$COMPDIR/out.raw"

# A range ending right at the end of the data is fine, one extending beyond it is refused
"$PULL" raw --verify=no --direct --source-offset=$((PAYLOAD_SIZE - 10)) --source-size=10 "file://$COMPDIR/payload.raw" "$COMPDIR/out.raw"
cmp "$COMPDIR/end.raw" "$COMPDIR/out.raw"
rm "$COMPDIR/out.raw"
(! "$PULL" raw --verify=no --direct --source-offset=$((PAYLOAD_SIZE - 10)) --source-size=11 "file://$COMPDIR/payload.raw" "$COMPDIR/out.raw")
rm -f "$COMPDIR/out.raw"
(! "$PULL" raw --verify=no --direct --source-offset=$((PAYLOAD_SIZE + 1)) "file://$COMPDIR/payload.raw" "$COMPDIR/out.raw")
rm -f "$COMPDIR/out.raw"

# The range refers to the decoded data, hence works the same for compressed downloads
if command -v gzip >/dev/null; then
    gzip -c "$COMPDIR/payload.raw" >"$COMPDIR/payload-range.raw.gz"
    "$PULL" raw --verify=no --direct --compression=gzip --source-offset=1000 --source-size=5000 --verify-decoded="$SLICE_HASH" "file://$COMPDIR/payload-range.raw.gz" "$COMPDIR/out.raw"
    cmp "$COMPDIR/slice.raw" "$COMPDIR/out.raw"
    rm "$COMPDIR/out.raw"
fi

# Once the range is acquired the rest of the download is skipped, unless it is needed for verification
SYSTEMD_LOG_LEVEL=debug "$PULL" raw --verify=no --direct --source-size=5000 "file://$COMPDIR/payload.raw" "$COMPDIR/out.raw" 2>"$COMPDIR/pull.log"
cmp "$COMPDIR/head.raw" "$COMPDIR/out.raw"
rm "$COMPDIR/out.raw"
grep -F "Acquired requested range" "$COMPDIR/pull.log" >/dev/null
SYSTEMD_LOG_LEVEL=debug "$PULL" raw --verify="$PAYLOAD_HASH" --direct --source-size=5000 "file://$COMPDIR/payload.raw" "$COMPDIR/out.raw" 2>"$COMPDIR/pull.log"
cmp "$COMPDIR/head.raw" "$COMPDIR/out.raw"
rm "$COMPDIR/out.raw"
(! grep -F "Acquired requested range" "$COMPDIR/pull.log")

# Ranges make no sense for tarballs and OCI images, and are refused
(! "$PULL" tar --verify=no --direct --source-offset=1000 "file://$COMPDIR/tree.tar" "$COMPDIR/tardir") |& \
    grep -F "not supported for tar images" >/dev/null
(! "$PULL" tar --verify=no --direct --source-size=1000 "file://$COMPDIR/tree.tar" "$COMPDIR/tardir") |& \
    grep -F "not supported for tar images" >/dev/null
test ! -e "$COMPDIR/tardir"
(! "$PULL" oci --direct --source-offset=1000 foo/bar "$COMPDIR/ocidir") |& grep -F "not supported for OCI images" >/dev/null
(! "$PULL" oci --direct --source-size=1000 foo/bar "$COMPDIR/ocidir") |& grep -F "not supported for OCI images" >/dev/null

# Ranges are only supported in --direct mode, and must not overflow
(! "$PULL" raw --image-root="$COMPDIR/root" --verify=no --source-offset=1000 "file://$COMPDIR/payload.raw" bad)
test ! -e "$COMPDIR/root/bad.raw"
(! "$PULL" raw --verify=no --direct --source-offset=18446744073709551615 --source-size=2 "file://$COMPDIR/payload.raw" "$COMPDIR/out.raw")
test ! -e "$COMPDIR/out.raw"

# → For unencoded data systemd-pull asks HTTP servers for just the range, and cuts it out itself if they
#   do not honour the request ← #

# A minimal HTTP server, where the first path component selects how range requests are handled: "honour"
# returns the requested range, "ignore" always the whole file, and "bogus" a range at the wrong offset. Each
# request is logged with its "Range:" header.
RANGE_LOG="$COMPDIR/range.log"
cat >"$COMPDIR/range-server.py" <<'EOF'
import http.server, os, re, sys

port, root, log = int(sys.argv[1]), sys.argv[2], sys.argv[3]

class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        mode, _, name = self.path.lstrip('/').partition('/')
        rng = self.headers.get('Range')
        with open(log, 'a') as f:
            print(mode, name, rng or '-', file=f)

        try:
            with open(os.path.join(root, os.path.basename(name)), 'rb') as f:
                data = f.read()
        except FileNotFoundError:
            self.send_error(404)
            return

        m = re.fullmatch(r'bytes=(\d+)-(\d*)', rng or '')
        if mode == 'ignore' or not m:
            self.send_response(200)
            chunk = data
        else:
            start = int(m.group(1))
            end = int(m.group(2)) if m.group(2) else len(data) - 1
            chunk = data[start:end + 1]
            if mode == 'bogus':
                start += 1
            self.send_response(206)
            self.send_header('Content-Range', f'bytes {start}-{start + len(chunk) - 1}/{len(data)}')
        self.send_header('Content-Length', str(len(chunk)))
        self.end_headers()
        self.wfile.write(chunk)

http.server.HTTPServer(('127.0.0.1', port), Handler).serve_forever()
EOF
systemd-run --unit=test-25-range-server -p Type=exec python3 "$COMPDIR/range-server.py" 8025 "$COMPDIR" "$RANGE_LOG"
timeout 30 bash -c 'until curl -sf -o /dev/null http://127.0.0.1:8025/ignore/head.raw; do sleep .5; done'
URL=http://127.0.0.1:8025

for mode in honour ignore; do
    : >"$RANGE_LOG"
    "$PULL" raw --verify=no --compression=none --direct --source-offset=1000 --source-size=5000 --verify-decoded="$SLICE_HASH" "$URL/$mode/payload.raw" "$COMPDIR/out.raw"
    cmp "$COMPDIR/slice.raw" "$COMPDIR/out.raw"
    rm "$COMPDIR/out.raw"
    grep -x "$mode payload.raw bytes=1000-5999" "$RANGE_LOG" >/dev/null

    : >"$RANGE_LOG"
    "$PULL" raw --verify=no --compression=none --direct --source-offset=1000 "$URL/$mode/payload.raw" "$COMPDIR/out.raw"
    cmp "$COMPDIR/tail.raw" "$COMPDIR/out.raw"
    rm "$COMPDIR/out.raw"
    grep -x "$mode payload.raw bytes=1000-" "$RANGE_LOG" >/dev/null
done

# A range starting elsewhere than requested is refused
(! "$PULL" raw --verify=no --compression=none --direct --source-offset=1000 --source-size=5000 "$URL/bogus/payload.raw" "$COMPDIR/out.raw")
rm -f "$COMPDIR/out.raw"

# No range is requested if the data might be encoded, or if the download is verified as a whole
: >"$RANGE_LOG"
"$PULL" raw --verify=no --direct --source-offset=1000 --source-size=5000 "$URL/honour/payload.raw" "$COMPDIR/out.raw"
cmp "$COMPDIR/slice.raw" "$COMPDIR/out.raw"
rm "$COMPDIR/out.raw"
"$PULL" raw --verify="$PAYLOAD_HASH" --compression=none --direct --source-offset=1000 --source-size=5000 "$URL/honour/payload.raw" "$COMPDIR/out.raw"
cmp "$COMPDIR/slice.raw" "$COMPDIR/out.raw"
rm "$COMPDIR/out.raw"
(! grep -v -x "honour payload.raw -" "$RANGE_LOG")

systemctl stop test-25-range-server

rm -rf "$COMPDIR"

# → Now, let's test --checksum-file=, i.e. whether the downloaded file is treated as checksum file ← #

CFDIR=/var/tmp/checksum-file
rm -rf "$CFDIR"
mkdir -p "$CFDIR"

pull_cf() {
    # Downloads the specified file from $CFDIR with checksum verification, in the specified --checksum-file= mode
    local fn="${1:?}" mode="${2:?}"

    rm -f "$CFDIR/out"
    if [[ "$mode" == default ]]; then
        "$PULL" raw --verify=checksum --direct "file://$CFDIR/$fn" "$CFDIR/out" || return
    else
        "$PULL" raw --verify=checksum --checksum-file="$mode" --direct "file://$CFDIR/$fn" "$CFDIR/out" || return
    fi
    cmp "$CFDIR/$fn" "$CFDIR/out"
}

# Invalid arguments are refused, and so is the switch for tar and OCI images
(! "$PULL" raw --verify=no --checksum-file=foobar --direct "file://$CFDIR/foo" "$CFDIR/out")
(! "$PULL" tar --verify=no --checksum-file=yes "file://$CFDIR/foo.tar" foo) |& grep -F "not supported for tar images" >/dev/null
(! "$PULL" tar --verify=no --checksum-file=no "file://$CFDIR/foo.tar" foo) |& grep -F "not supported for tar images" >/dev/null
(! "$PULL" oci --checksum-file=yes foo/bar) |& grep -F "not supported for OCI images" >/dev/null
(! "$PULL" oci --checksum-file=no foo/bar) |& grep -F "not supported for OCI images" >/dev/null
# … and so are target ranges, which only make sense for raw images
(! "$PULL" tar --verify=no --direct --offset=4096 "file://$CFDIR/foo.tar" "$CFDIR/out") |& grep -F "not supported for tar images" >/dev/null
(! "$PULL" tar --verify=no --size-max=4096 "file://$CFDIR/foo.tar" foo) |& grep -F "not supported for tar images" >/dev/null
(! "$PULL" oci --direct --offset=4096 foo/bar "$CFDIR/out") |& grep -F "not supported for OCI images" >/dev/null
(! "$PULL" oci --size-max=4096 foo/bar) |& grep -F "not supported for OCI images" >/dev/null
test ! -e "$CFDIR/out"

# A file whose name doesn't suggest it is a checksum file, which hence needs a checksum file covering it,
# unless we are told it is a checksum file itself
dd if=/dev/urandom of="$CFDIR/data.manifest" bs=1024 count=4 status=none
for m in default auto no; do
    (! pull_cf data.manifest "$m")
done
pull_cf data.manifest yes
# … with a matching checksum file it's accepted in all modes
(cd "$CFDIR" && sha256sum data.manifest >SHA256SUMS)
for m in default auto no yes; do
    pull_cf data.manifest "$m"
done
# … with a non-matching checksum file it's refused, unless it's not checked against it at all
echo "0000000000000000000000000000000000000000000000000000000000000000  data.manifest" >"$CFDIR/SHA256SUMS"
for m in default auto no; do
    (! pull_cf data.manifest "$m")
done
pull_cf data.manifest yes
rm "$CFDIR/SHA256SUMS"

# A file whose name suggests it is a checksum file, which hence is not checked against a checksum file,
# unless we are told it is not a checksum file
(cd "$CFDIR" && sha256sum data.manifest >data.sha256)
for m in default auto yes; do
    pull_cf data.sha256 "$m"
done
(! pull_cf data.sha256 no)
# … with a matching checksum file (both the suse-style and ubuntu-style name) it's accepted in all modes
(cd "$CFDIR" && sha256sum data.sha256 >data.sha256.sha256)
for m in default auto no yes; do
    pull_cf data.sha256 "$m"
done
mv "$CFDIR/data.sha256.sha256" "$CFDIR/SHA256SUMS"
for m in default auto no yes; do
    pull_cf data.sha256 "$m"
done
# … with a non-matching checksum file it's only refused if we are told it is not a checksum file
echo "0000000000000000000000000000000000000000000000000000000000000000  data.sha256" >"$CFDIR/SHA256SUMS"
for m in default auto yes; do
    pull_cf data.sha256 "$m"
done
(! pull_cf data.sha256 no)

# SHA256SUMS is a checksum file by its name. If we are told it is not, it'd have to be verified against
# itself, which is refused.
(cd "$CFDIR" && sha256sum data.manifest >SHA256SUMS)
for m in default auto yes; do
    pull_cf SHA256SUMS "$m"
done
(! pull_cf SHA256SUMS no) |& grep -F "Cannot verify checksum/signature files via themselves" >/dev/null

rm -rf "$CFDIR"

touch /testok
