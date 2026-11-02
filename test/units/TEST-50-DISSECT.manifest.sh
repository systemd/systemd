#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh

# Tests for systemd-manifest: generation and verification of file manifests in all formats, the field
# selection, hash algorithm selection, and PKCS#7 signing.

ROOT="$(mktemp -d /tmp/manifest-tool-test.XXXXXX)"
WORK="$(mktemp -d /tmp/manifest-tool-work.XXXXXX)"

at_exit() {
    set +e
    rm -rf "$ROOT" "$WORK"
    if [[ -n "${VOA_OS:-}" ]]; then
        rm -rf "/etc/voa/$VOA_OS/manifest" "/run/voa/$VOA_OS/manifest"
    fi
}

trap at_exit EXIT

# Same fixture as the --manifest test in TEST-50-DISSECT.dissect.sh: every inode type, plus hardlinks
echo -n "hello world" >"$ROOT/regular.txt"
: >"$ROOT/empty.txt"
mkdir "$ROOT/subdir"
echo -n "nested" >"$ROOT/subdir/nested.txt"
ln -s regular.txt "$ROOT/symlink"
mkfifo "$ROOT/fifo"
mknod "$ROOT/chardev" c 1 3
mknod "$ROOT/blockdev" b 7 0
echo -n "hardlinked content" >"$ROOT/hardlink_a"
ln "$ROOT/hardlink_a" "$ROOT/hardlink_b"
mkdir "$ROOT/dir with space"
echo -n "x" >"$ROOT/dir with space/file#with glob*.txt"
chmod 0644 "$ROOT/regular.txt" "$ROOT/empty.txt" "$ROOT/subdir/nested.txt" "$ROOT/hardlink_a"
chmod 0755 "$ROOT/subdir"
chmod 0600 "$ROOT/fifo"
chmod 0666 "$ROOT/chardev" "$ROOT/blockdev"

: "Generation in all formats, byte-identical to systemd-dissect where it has the same mode"
systemd-manifest make "$ROOT" >"$WORK/Uapi16Manifest"
systemd-dissect --uapi16 "$ROOT" | cmp - "$WORK/Uapi16Manifest"

systemd-manifest make --format=mtree "$ROOT" >"$WORK/tree.mtree"
systemd-dissect --mtree "$ROOT" | cmp - "$WORK/tree.mtree"
systemd-manifest make --format=mtree --field=-hash "$ROOT" | cmp - <(systemd-dissect --mtree --mtree-hash=no "$ROOT")

systemd-manifest make --format=list "$ROOT" >"$WORK/list"
systemd-dissect --list "$ROOT" | cmp - "$WORK/list"

# Inodes other than regular files are skipped silently, hence no --graceful needed
systemd-manifest make --format=sha256sums "$ROOT" >"$WORK/SHA256SUMS"
# Only the six regular files are listed
test "$(wc -l <"$WORK/SHA256SUMS")" -eq 6
# ... and coreutils agrees with us
(cd "$ROOT" && sha256sum -c "$WORK/SHA256SUMS")

: "The uapi16 default is the same as the explicit format, and output is stable"
systemd-manifest make --format=uapi16 "$ROOT" | cmp - "$WORK/Uapi16Manifest"

: "Verification round trips, from a file, from stdin, and with no arguments at all"
systemd-manifest verify --verify-signature=no "$ROOT" "$WORK/Uapi16Manifest"
systemd-manifest verify --verify-signature=no "$ROOT" <"$WORK/Uapi16Manifest"
systemd-manifest verify --verify-signature=no "$ROOT" - <"$WORK/Uapi16Manifest"
systemd-manifest verify "$ROOT" "$WORK/SHA256SUMS"
systemd-manifest verify --format=sha256sums "$ROOT" <"$WORK/SHA256SUMS"
systemd-manifest verify --format=list "$ROOT" "$WORK/list"
(cd "$ROOT" && systemd-manifest make | systemd-manifest verify --verify-signature=no)
(cd "$ROOT" && systemd-manifest make --format=sha256sums | systemd-manifest verify --format=sha256sums)
(cd "$ROOT" && systemd-manifest make --format=list | systemd-manifest verify --format=list)

: "mtree cannot be verified"
(! systemd-manifest verify "$ROOT" "$WORK/tree.mtree")
(! systemd-manifest verify --format=mtree "$ROOT" <"$WORK/tree.mtree")

: "Field selection"
systemd-manifest make --field=size,hash "$ROOT" | tr -d '\036' >"$WORK/minimal.jsonl"
# No mode/uid/gid/inodeToken anywhere, but sizes and hashes
(! grep -F '"mode"' "$WORK/minimal.jsonl")
(! grep -F '"uid"' "$WORK/minimal.jsonl")
(! grep -F '"inodeToken"' "$WORK/minimal.jsonl")
grep -F '"sha256"' "$WORK/minimal.jsonl" >/dev/null
# Type is always included
jq -s -e '.[] | select(.name == "subdir") | .type == "dir"' "$WORK/minimal.jsonl" >/dev/null
# mtime is opt-in
systemd-manifest make --field=+mtime "$ROOT" | tr -d '\036' | jq -s -e '.[] | select(.name == "regular.txt") | has("mTimeNSec")' >/dev/null
systemd-manifest make "$ROOT" | tr -d '\036' | jq -s -e '.[] | select(.name == "regular.txt") | has("mTimeNSec") | not' >/dev/null
systemd-manifest make --format=mtree --field=+mtime "$ROOT" | grep -F " time=" >/dev/null
systemd-manifest make --format=mtree --field=none "$ROOT" | grep -F "./regular.txt type=file" >/dev/null
(! systemd-manifest make --format=mtree --field=none "$ROOT" | grep -F "mode=")
(! systemd-manifest make --field=foobar "$ROOT")
# sha256sums needs the hash field
(! systemd-manifest make --graceful --format=sha256sums --field=-hash "$ROOT")

: "Hash algorithm selection"
systemd-manifest make --format=mtree --hash=sha512 "$ROOT" | grep -F " sha512sum=$(sha512sum "$ROOT/regular.txt" | cut -d' ' -f1)" >/dev/null
systemd-manifest make --format=mtree --hash=sha256 "$ROOT" | cmp - "$WORK/tree.mtree"
# Only mtree supports anything but SHA256
(! systemd-manifest make --graceful --format=sha256sums --hash=sha512 "$ROOT")
(! systemd-manifest make --hash=sha512 "$ROOT")
(! systemd-manifest verify --format=sha256sums --hash=sha512 "$ROOT" "$WORK/SHA256SUMS")
(! systemd-manifest verify --verify-signature=no --hash=sha512 "$ROOT" "$WORK/Uapi16Manifest")

: "Mismatches are detected and reported"
cp -a "$ROOT" "$WORK/broken"
echo -n "HELLO WORLD" >"$WORK/broken/regular.txt"
chmod 0600 "$WORK/broken/subdir/nested.txt"
echo -n "extra" >"$WORK/broken/extra.txt"
rm "$WORK/broken/empty.txt"
rm "$WORK/broken/hardlink_b"
echo -n "hardlinked content" >"$WORK/broken/hardlink_b"
chmod 0644 "$WORK/broken/hardlink_b"
ln -sfn empty.txt "$WORK/broken/symlink"
rm "$WORK/broken/fifo"
: >"$WORK/broken/fifo"

set +o pipefail
systemd-manifest verify --verify-signature=no "$WORK/broken" "$WORK/Uapi16Manifest" 2>&1 | tee "$WORK/uapi16.log"
set -o pipefail
grep -F "empty.txt: Listed in manifest, but missing in tree." "$WORK/uapi16.log"
# Only what the manifest lists is checked, additional files in the tree are fine
(! grep -F "extra.txt" "$WORK/uapi16.log")
grep -F "regular.txt: Hash mismatch." "$WORK/uapi16.log"
grep -F "subdir/nested.txt: Expected access mode 00644, but found 00600." "$WORK/uapi16.log"
grep -F "hardlink_b: Inode token 1 in manifest already used by a different inode, not a hardlink." "$WORK/uapi16.log"
grep -F "symlink: Symlink target mismatch." "$WORK/uapi16.log"
grep -F "fifo: Expected inode type 'fifo', but found 'reg'." "$WORK/uapi16.log"
grep -F "Found 6 mismatches between manifest and directory tree." "$WORK/uapi16.log"
(! systemd-manifest verify --verify-signature=no "$WORK/broken" "$WORK/Uapi16Manifest")

# Only checking contents ignores the mode change and the hardlink
set +o pipefail
systemd-manifest verify --verify-signature=no --field=size,hash "$WORK/broken" "$WORK/Uapi16Manifest" 2>&1 | tee "$WORK/uapi16-content.log"
set -o pipefail
grep -F "Found 3 mismatches between manifest and directory tree." "$WORK/uapi16-content.log"
(! grep -F "nested.txt: " "$WORK/uapi16-content.log")

set +o pipefail
systemd-manifest verify "$WORK/broken" "$WORK/SHA256SUMS" 2>&1 | tee "$WORK/sums.log"
set -o pipefail
grep -F "regular.txt: Hash mismatch." "$WORK/sums.log"
grep -F "empty.txt: Listed in manifest, but missing in tree." "$WORK/sums.log"
(! grep -F "extra.txt" "$WORK/sums.log")
(! grep -F "fifo" "$WORK/sums.log")
grep -F "Found 2 mismatches between manifest and directory tree." "$WORK/sums.log"

set +o pipefail
systemd-manifest verify --format=list "$WORK/broken" "$WORK/list" 2>&1 | tee "$WORK/list.log"
set -o pipefail
grep -F "empty.txt: Listed in manifest, but missing in tree." "$WORK/list.log"
(! grep -F "extra.txt" "$WORK/list.log")
grep -F "Found 1 mismatches between manifest and directory tree." "$WORK/list.log"

: "Garbage is refused"
(! echo "garbage" | systemd-manifest verify "$ROOT")
(! echo "not-a-hash  regular.txt" | systemd-manifest verify --format=sha256sums "$ROOT")
(! echo "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855  /etc/passwd" | systemd-manifest verify --format=sha256sums "$ROOT")
(! echo "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855  ../empty.txt" | systemd-manifest verify --format=sha256sums "$ROOT")
(! echo "../empty.txt" | systemd-manifest verify --format=list "$ROOT")

: "Objects of unknown media type are ignored"
# (They must come before the trailer object though, which terminates the manifest.)
{ head -n -1 "$WORK/Uapi16Manifest"; printf '\036{"mediaType":"application/vnd.example.unknown","foo":"bar"}\n'; tail -n 1 "$WORK/Uapi16Manifest"; } | systemd-manifest verify --verify-signature=no "$ROOT"
# ... and data after the trailer is refused
(! { cat "$WORK/Uapi16Manifest"; printf '\036{"mediaType":"application/vnd.example.unknown","foo":"bar"}\n'; } | systemd-manifest verify --verify-signature=no "$ROOT")

: "File names needing escaping in SHA256SUMS"
mkdir "$WORK/escape"
printf 'x' >"$WORK/escape/a
b"
printf 'y' >"$WORK/escape/back\\slash"
systemd-manifest make --format=sha256sums "$WORK/escape" >"$WORK/escape.sums"
grep -F '\2d711642b726b04401627ca9fbac32f5c8530fb1903cc4db02258717921a4881  a\nb' "$WORK/escape.sums"
(cd "$WORK/escape" && sha256sum -c "$WORK/escape.sums")
systemd-manifest verify --format=sha256sums "$WORK/escape" "$WORK/escape.sums"

: "Joining: a tree and the same tree with more files added does not conflict"
JROOT="$WORK/join-root"
cp -a "$ROOT" "$JROOT"
systemd-manifest make "$JROOT" "$WORK/join-a.Uapi16Manifest"
echo -n "added" >"$JROOT/added.txt"
mkdir -p "$JROOT/subdir/deeper"
echo -n "deep" >"$JROOT/subdir/deeper/file.txt"
ln -s ../regular.txt "$JROOT/subdir/link"
echo -n "pair" >"$JROOT/new_hardlink_a"
ln "$JROOT/new_hardlink_a" "$JROOT/new_hardlink_b"
systemd-manifest make "$JROOT" "$WORK/join-b.Uapi16Manifest"

# Note that these manifests are unsigned: join never requires (or checks) signatures
(! jq --seq -e 'select(.mediaType == "application/vnd.uapi.16.signature")' "$WORK/join-a.Uapi16Manifest" >/dev/null)
systemd-manifest join "$WORK/join-a.Uapi16Manifest" "$WORK/join-b.Uapi16Manifest" "$WORK/join-ab.Uapi16Manifest"
systemd-manifest verify --verify-signature=no "$JROOT" "$WORK/join-ab.Uapi16Manifest"
# B is a superset of A, hence the result is exactly B: same order, same inode token numbering
cmp "$WORK/join-ab.Uapi16Manifest" "$WORK/join-b.Uapi16Manifest"
# The order of the inputs does not matter
systemd-manifest join "$WORK/join-b.Uapi16Manifest" "$WORK/join-a.Uapi16Manifest" - | cmp - "$WORK/join-b.Uapi16Manifest"
# Joining a manifest with itself (or with nothing) results in the very same manifest
systemd-manifest join "$WORK/join-a.Uapi16Manifest" "$WORK/join-a.Uapi16Manifest" - | cmp - "$WORK/join-a.Uapi16Manifest"
systemd-manifest join "$WORK/join-a.Uapi16Manifest" - | cmp - "$WORK/join-a.Uapi16Manifest"
# The output may be one of the inputs
cp "$WORK/join-a.Uapi16Manifest" "$WORK/join-inplace.Uapi16Manifest"
systemd-manifest join "$WORK/join-inplace.Uapi16Manifest" "$WORK/join-b.Uapi16Manifest" "$WORK/join-inplace.Uapi16Manifest"
cmp "$WORK/join-inplace.Uapi16Manifest" "$WORK/join-b.Uapi16Manifest"

: "Joining: disjoint trees with the same top-level inode"
JDISJ="$WORK/join-disjoint"
mkdir -p "$JDISJ/one" "$JDISJ/two" "$JDISJ/three" "$JDISJ/all"
for d in one two three; do
    mkdir "$JDISJ/$d/$d" "$JDISJ/all/$d"
    echo -n "$d" >"$JDISJ/$d/$d/file"
    echo -n "$d" >"$JDISJ/all/$d/file"
done
chmod 0755 "$JDISJ"/*
systemd-manifest make "$JDISJ/one" "$WORK/join-one.Uapi16Manifest"
systemd-manifest make "$JDISJ/two" "$WORK/join-two.Uapi16Manifest"
systemd-manifest make "$JDISJ/three" "$WORK/join-three.Uapi16Manifest"
systemd-manifest join "$WORK/join-three.Uapi16Manifest" "$WORK/join-one.Uapi16Manifest" "$WORK/join-two.Uapi16Manifest" "$WORK/join-all.Uapi16Manifest"
systemd-manifest verify --verify-signature=no "$JDISJ/all" "$WORK/join-all.Uapi16Manifest"
systemd-manifest make "$JDISJ/all" | cmp - "$WORK/join-all.Uapi16Manifest"

: "Joining: hardlink groups are combined transitively"
JHL="$WORK/join-hardlinks"
for d in xy yz ya xyz xya; do
    mkdir -p "$JHL/$d"
    echo -n "linked" >"$JHL/$d/y"
    chmod 0644 "$JHL/$d/y"
done
chmod 0755 "$JHL"/*
ln "$JHL/xy/y" "$JHL/xy/x"
ln "$JHL/yz/y" "$JHL/yz/z"
ln "$JHL/xyz/y" "$JHL/xyz/x"
ln "$JHL/xyz/y" "$JHL/xyz/z"
# Here the new name sorts before "y", i.e. it is seen first and initially gets a hardlink group of its own
ln "$JHL/ya/y" "$JHL/ya/a"
ln "$JHL/xya/y" "$JHL/xya/x"
ln "$JHL/xya/y" "$JHL/xya/a"
for d in xy yz ya xyz xya; do
    systemd-manifest make "$JHL/$d" "$WORK/join-hl-$d.Uapi16Manifest"
done
systemd-manifest join "$WORK/join-hl-xy.Uapi16Manifest" "$WORK/join-hl-yz.Uapi16Manifest" "$WORK/join-hl-xyz-joined.Uapi16Manifest"
[[ "$(jq --seq -r 'select(.name) | .inodeToken | tostring' "$WORK/join-hl-xyz-joined.Uapi16Manifest" | sort -u)" == "1" ]]
cmp "$WORK/join-hl-xyz-joined.Uapi16Manifest" "$WORK/join-hl-xyz.Uapi16Manifest"
systemd-manifest join "$WORK/join-hl-xy.Uapi16Manifest" "$WORK/join-hl-ya.Uapi16Manifest" - | cmp - "$WORK/join-hl-xya.Uapi16Manifest"
systemd-manifest join "$WORK/join-hl-ya.Uapi16Manifest" "$WORK/join-hl-xy.Uapi16Manifest" - | cmp - "$WORK/join-hl-xya.Uapi16Manifest"
# Differences in hardlink information never conflict, groups are merged
JHL2="$WORK/join-hardlinks-copy"
cp -a "$ROOT" "$JHL2"
rm "$JHL2/hardlink_b"
cp -a "$ROOT/hardlink_a" "$JHL2/hardlink_b"
ln "$JHL2/regular.txt" "$JHL2/regular_link.txt"
systemd-manifest make "$JHL2" "$WORK/join-hl-copy.Uapi16Manifest"
systemd-manifest join "$WORK/Uapi16Manifest" "$WORK/join-hl-copy.Uapi16Manifest" "$WORK/join-hl-copy-joined.Uapi16Manifest"
[[ "$(jq --seq -r 'select(.name == "hardlink_a" or .name == "hardlink_b") | .inodeToken | tostring' "$WORK/join-hl-copy-joined.Uapi16Manifest" | sort -u | wc -l)" == "1" ]]
[[ "$(jq --seq -r 'select(.name == "regular.txt" or .name == "regular_link.txt") | .inodeToken | tostring' "$WORK/join-hl-copy-joined.Uapi16Manifest" | sort -u | wc -l)" == "1" ]]

: "Joining: objects are sorted, whatever order the inputs list them in"
printf '\036{"mediaType":"application/vnd.uapi.16.manifest","mode":493}\n\036{"name":"b","size":0}\n\036{"name":"a/x","size":1}\n\036{"name":"a-b","size":2}\n\036{"mode":493,"name":"a","type":"dir"}\n\036{"mediaType":"application/vnd.uapi.16.trailer"}\n' >"$WORK/join-unsorted.Uapi16Manifest"
systemd-manifest join "$WORK/join-unsorted.Uapi16Manifest" - >"$WORK/join-sorted.Uapi16Manifest"
[[ "$(jq --seq -r 'select(.name) | .name' "$WORK/join-sorted.Uapi16Manifest" | tr '\n' ' ')" == "a a/x a-b b " ]]
# The result is canonical, i.e. joining it again changes nothing
systemd-manifest join "$WORK/join-sorted.Uapi16Manifest" - | cmp - "$WORK/join-sorted.Uapi16Manifest"
# Parent directories that no input lists are not made up
printf '\036{"mediaType":"application/vnd.uapi.16.manifest","mode":493}\n\036{"name":"p/q/r","size":0}\n\036{"mediaType":"application/vnd.uapi.16.trailer"}\n' >"$WORK/join-noparent.Uapi16Manifest"
[[ "$(systemd-manifest join "$WORK/join-noparent.Uapi16Manifest" - | jq --seq -r 'select(.name) | .name')" == "p/q/r" ]]
# Extension fields count too, and are retained
printf '\036{"mediaType":"application/vnd.uapi.16.manifest","mode":493}\n\036{"name":"b","size":0,"fooBar":"baz"}\n\036{"mediaType":"application/vnd.uapi.16.trailer"}\n' >"$WORK/join-ext.Uapi16Manifest"
systemd-manifest join "$WORK/join-ext.Uapi16Manifest" - | jq --seq -e 'select(.name == "b") | .fooBar == "baz"' >/dev/null
(! systemd-manifest join "$WORK/join-unsorted.Uapi16Manifest" "$WORK/join-ext.Uapi16Manifest" -)

: "Joining: conflicts are refused"
join_conflict() {
    local d="$WORK/join-conflict"

    rm -rf "$d"
    cp -a "$ROOT" "$d"
    "$@"
    systemd-manifest make "$d" "$WORK/join-conflict.Uapi16Manifest"
    (! systemd-manifest join "$WORK/Uapi16Manifest" "$WORK/join-conflict.Uapi16Manifest" "$WORK/join-conflict-out.Uapi16Manifest")
    # Nothing is written on failure
    [[ ! -e "$WORK/join-conflict-out.Uapi16Manifest" ]]
}
join_conflict eval 'echo -n "HELLO WORLD" >"$d/regular.txt"'
join_conflict chmod 0600 "$WORK/join-conflict/regular.txt"
join_conflict eval 'rm "$d/empty.txt" && mkdir "$d/empty.txt"'
join_conflict ln -sfn empty.txt "$WORK/join-conflict/symlink"
join_conflict chmod 0750 "$WORK/join-conflict"
set +o pipefail
systemd-manifest join "$WORK/Uapi16Manifest" "$WORK/join-conflict.Uapi16Manifest" - 2>&1 >/dev/null | tee "$WORK/join-conflict.log"
set -o pipefail
grep -F "Definition of top-level inode in '$WORK/join-conflict.Uapi16Manifest' conflicts with the one in '$WORK/Uapi16Manifest' (differing fields: mode)." "$WORK/join-conflict.log"

: "Joining: if objects only differ in their modification time, the newest wins"
# Modification times of directories change when files are added, hence this is the same as the case above
cp -a "$ROOT" "$WORK/join-mtime"
systemd-manifest make --field=+mtime "$WORK/join-mtime" "$WORK/join-mtime-a.Uapi16Manifest"
echo -n "added" >"$WORK/join-mtime/added.txt"
systemd-manifest make --field=+mtime "$WORK/join-mtime" "$WORK/join-mtime-b.Uapi16Manifest"
(! cmp "$WORK/join-mtime-a.Uapi16Manifest" "$WORK/join-mtime-b.Uapi16Manifest")
systemd-manifest join "$WORK/join-mtime-a.Uapi16Manifest" "$WORK/join-mtime-b.Uapi16Manifest" - | cmp - "$WORK/join-mtime-b.Uapi16Manifest"
systemd-manifest join "$WORK/join-mtime-b.Uapi16Manifest" "$WORK/join-mtime-a.Uapi16Manifest" - | cmp - "$WORK/join-mtime-b.Uapi16Manifest"
# Also for regular files, in either direction
touch -d @1000000000 "$WORK/join-mtime/regular.txt"
systemd-manifest make --field=+mtime "$WORK/join-mtime" "$WORK/join-mtime-old.Uapi16Manifest"
touch -d @2000000000 "$WORK/join-mtime/regular.txt"
systemd-manifest make --field=+mtime "$WORK/join-mtime" "$WORK/join-mtime-new.Uapi16Manifest"
systemd-manifest join "$WORK/join-mtime-old.Uapi16Manifest" "$WORK/join-mtime-new.Uapi16Manifest" - | cmp - "$WORK/join-mtime-new.Uapi16Manifest"
systemd-manifest join "$WORK/join-mtime-new.Uapi16Manifest" "$WORK/join-mtime-old.Uapi16Manifest" - | cmp - "$WORK/join-mtime-new.Uapi16Manifest"
# An object without modification time loses against one with
systemd-manifest join "$WORK/join-mtime-old.Uapi16Manifest" "$WORK/Uapi16Manifest" - |
    jq --seq -e 'select(.name == "regular.txt") | .mTimeNSec == 1000000000000000000' >/dev/null
systemd-manifest join "$WORK/Uapi16Manifest" "$WORK/join-mtime-old.Uapi16Manifest" - |
    jq --seq -e 'select(.name == "regular.txt") | .mTimeNSec == 1000000000000000000' >/dev/null
# Any other difference still conflicts, even if the modification time differs too
echo -n "HELLO WORLD" >"$WORK/join-mtime/regular.txt"
systemd-manifest make --field=+mtime "$WORK/join-mtime" "$WORK/join-mtime-changed.Uapi16Manifest"
(! systemd-manifest join "$WORK/join-mtime-old.Uapi16Manifest" "$WORK/join-mtime-changed.Uapi16Manifest" -)

: "Joining: invalid invocations"
(! systemd-manifest join)
(! systemd-manifest join "$WORK/join-a.Uapi16Manifest")
(! systemd-manifest join "$WORK/does-not-exist.Uapi16Manifest" -)
(! systemd-manifest join --format=mtree "$WORK/join-a.Uapi16Manifest" -)
(! systemd-manifest join --field=size "$WORK/join-a.Uapi16Manifest" -)
(! systemd-manifest join --hash=sha512 "$WORK/join-a.Uapi16Manifest" -)
(! systemd-manifest join --verify-signature=yes "$WORK/join-a.Uapi16Manifest" -)
(! systemd-manifest join --verify-signature=no "$WORK/join-a.Uapi16Manifest" -)
(! systemd-manifest join --voa-context=foo "$WORK/join-a.Uapi16Manifest" -)
(! echo garbage | systemd-manifest join /dev/stdin -)

: "Signing"
if [[ -f /usr/share/mkosi.key && -f /usr/share/mkosi.crt ]] && command -v openssl >/dev/null; then
    # We sign if (and only if) a private key is specified, which requires a certificate, but not the other way round
    (! systemd-manifest make --private-key=/usr/share/mkosi.key "$ROOT")
    (! systemd-manifest make --certificate=/usr/share/mkosi.crt "$ROOT")
    (! systemd-manifest make --format=mtree --private-key=/usr/share/mkosi.key --certificate=/usr/share/mkosi.crt "$ROOT")
    (! tr -d '\036' <"$WORK/Uapi16Manifest" | jq -s -e '.[] | select(.mediaType == "application/vnd.uapi.16.signature")' >/dev/null)

    systemd-manifest make --private-key=/usr/share/mkosi.key --certificate=/usr/share/mkosi.crt "$ROOT" >"$WORK/Signed"

    # The signature object precedes the trailer, and carries our certificate's fingerprint
    signature_object() { tr -d '\036' <"$1" | tail -n2 | head -n1; }
    signature_object "$WORK/Signed" | jq -e '.mediaType == "application/vnd.uapi.16.signature" and .mechanism == "pkcs7"' >/dev/null
    FINGERPRINT="$(openssl x509 -in /usr/share/mkosi.crt -outform DER | sha256sum | cut -d' ' -f1)"
    signature_object "$WORK/Signed" | jq -e --arg fp "$FINGERPRINT" '.key == $fp' >/dev/null

    # Everything before the signature object is what was signed
    signed_payload() {
        python3 - "$1" "$2" <<'EOF'
import sys
data = open(sys.argv[1], 'rb').read()
records = data.split(b'\x1e')[1:]
open(sys.argv[2], 'wb').write(b'\x1e' + b'\x1e'.join(records[:-2]))
EOF
    }
    signature_object "$WORK/Signed" | jq -r '.data' | base64 -d >"$WORK/Signed.p7s"
    signed_payload "$WORK/Signed" "$WORK/Signed.payload"
    openssl smime -verify -binary -inform DER -in "$WORK/Signed.p7s" -content "$WORK/Signed.payload" -certfile /usr/share/mkosi.crt -noverify -out /dev/null
    openssl cms -verify -binary -inform DER -in "$WORK/Signed.p7s" -content "$WORK/Signed.payload" -certfile /usr/share/mkosi.crt -noverify -out /dev/null

    # Verifies with the certificate, or without verification, fails with a different one or when tampered with
    systemd-manifest verify --certificate=/usr/share/mkosi.crt "$ROOT" "$WORK/Signed"
    systemd-manifest verify --certificate=/usr/share/mkosi.crt "$ROOT" <"$WORK/Signed"
    systemd-manifest verify --verify-signature=no "$ROOT" "$WORK/Signed"
    # Without --certificate= the VOA hierarchy is consulted, which carries no certificate yet
    (! systemd-manifest verify "$ROOT" "$WORK/Signed")
    (! systemd-manifest verify --verify-signature=no --certificate=/usr/share/mkosi.crt "$ROOT" "$WORK/Signed")
    (! systemd-manifest verify --format=sha256sums --verify-signature=yes "$ROOT" "$WORK/SHA256SUMS")
    # The certificate in the VOA hierarchy, for the default context or the one selected explicitly
    VOA_OS="$(. /etc/os-release; echo "${ID:-linux}")"
    mkdir -p "/run/voa/$VOA_OS/manifest/default/x509" "/run/voa/$VOA_OS/manifest/test50/x509"
    cp /usr/share/mkosi.crt "/run/voa/$VOA_OS/manifest/default/x509/mkosi-certificate.pem"
    systemd-manifest verify "$ROOT" "$WORK/Signed"
    (! systemd-manifest verify "$ROOT" "$WORK/Uapi16Manifest")
    (! systemd-manifest verify --voa-context=test50 "$ROOT" "$WORK/Signed")
    mv "/run/voa/$VOA_OS/manifest/default/x509/mkosi-certificate.pem" "/run/voa/$VOA_OS/manifest/test50/x509/"
    systemd-manifest verify --voa-context=test50 "$ROOT" "$WORK/Signed"
    (! systemd-manifest verify "$ROOT" "$WORK/Signed")
    # A mask in any load path hides the certificate in all of them
    mkdir -p "/etc/voa/$VOA_OS/manifest/test50/x509"
    ln -s /dev/null "/etc/voa/$VOA_OS/manifest/test50/x509/mkosi-certificate.pem"
    (! systemd-manifest verify --voa-context=test50 "$ROOT" "$WORK/Signed")
    rm -r "/etc/voa/$VOA_OS/manifest" "/run/voa/$VOA_OS/manifest"
    (! systemd-manifest verify --certificate=/usr/share/mkosi.crt "$ROOT" "$WORK/Uapi16Manifest")
    # With --field=none the tree check ignores the size, hence only the signature check can catch the modification
    sed 's/"size":11/"size":12/' "$WORK/Signed" | systemd-manifest verify --verify-signature=no --field=none "$ROOT"
    (! sed 's/"size":11/"size":12/' "$WORK/Signed" | systemd-manifest verify --certificate=/usr/share/mkosi.crt --field=none "$ROOT")

    openssl req -x509 -newkey rsa:2048 -nodes -keyout "$WORK/other.key" -out "$WORK/other.crt" -subj /CN=other -days 2 2>/dev/null
    (! systemd-manifest verify --certificate="$WORK/other.crt" "$ROOT" "$WORK/Signed")

    # Join never verifies its inputs, not even signed ones, and drops their signatures. The output is only
    # signed if a private key is specified.
    sed 's/"data":"./"data":"A/' "$WORK/Signed" >"$WORK/SignedBroken"
    (! systemd-manifest verify --certificate=/usr/share/mkosi.crt "$ROOT" "$WORK/SignedBroken")
    systemd-manifest join "$WORK/SignedBroken" "$WORK/Signed" "$WORK/JoinedUnsigned"
    cmp "$WORK/JoinedUnsigned" "$WORK/Uapi16Manifest"
    # Signed and unsigned inputs may be mixed
    systemd-manifest join "$WORK/Signed" "$WORK/Uapi16Manifest" - | cmp - "$WORK/Uapi16Manifest"
    systemd-manifest join "$WORK/Uapi16Manifest" "$WORK/Signed" - | cmp - "$WORK/Uapi16Manifest"
    (! jq --seq -e 'select(.mediaType == "application/vnd.uapi.16.signature")' "$WORK/JoinedUnsigned" >/dev/null)
    (! systemd-manifest join --certificate=/usr/share/mkosi.crt "$WORK/Signed" -)
    (! systemd-manifest join --private-key=/usr/share/mkosi.key "$WORK/Signed" -)
    systemd-manifest join --private-key=/usr/share/mkosi.key --certificate=/usr/share/mkosi.crt "$WORK/join-a.Uapi16Manifest" "$WORK/join-b.Uapi16Manifest" "$WORK/JoinedSigned"
    # Joining a single input signs, re-signs or unsigns a manifest
    systemd-manifest join --private-key=/usr/share/mkosi.key --certificate=/usr/share/mkosi.crt "$WORK/Uapi16Manifest" "$WORK/Resigned"
    systemd-manifest verify --certificate=/usr/share/mkosi.crt "$ROOT" "$WORK/Resigned"
    systemd-manifest join "$WORK/Resigned" - | cmp - "$WORK/Uapi16Manifest"
    systemd-manifest join --private-key="$WORK/other.key" --certificate="$WORK/other.crt" "$WORK/Signed" "$WORK/ResignedOther"
    systemd-manifest verify --certificate="$WORK/other.crt" "$ROOT" "$WORK/ResignedOther"
    (! systemd-manifest verify --certificate=/usr/share/mkosi.crt "$ROOT" "$WORK/ResignedOther")
    systemd-manifest join "$WORK/ResignedOther" - | cmp - "$WORK/Uapi16Manifest"
    # ... and brings it into canonical form along the way
    systemd-manifest join --private-key=/usr/share/mkosi.key --certificate=/usr/share/mkosi.crt "$WORK/join-unsorted.Uapi16Manifest" "$WORK/UnsortedSigned"
    systemd-manifest join "$WORK/UnsortedSigned" - | cmp - "$WORK/join-sorted.Uapi16Manifest"
    systemd-manifest verify --certificate=/usr/share/mkosi.crt "$JROOT" "$WORK/JoinedSigned"
    (! systemd-manifest verify --certificate="$WORK/other.crt" "$JROOT" "$WORK/JoinedSigned")

    # Objects between the signature object and the trailer are not covered by the signature and ignored
    { head -c -"$(tr -d '\036' <"$WORK/Signed" | tail -n1 | wc -c)" "$WORK/Signed" | head -c -1; printf '\036{"mediaType":"application/x-test-extra","name":"extra.txt"}\n\036{"mediaType":"application/vnd.uapi.16.trailer"}\n'; } | systemd-manifest verify --certificate=/usr/share/mkosi.crt "$ROOT"

    # A colored rendering carries the signature over the color-free bytes
    SYSTEMD_COLORS=1 systemd-manifest make --json=pretty --private-key=/usr/share/mkosi.key --certificate=/usr/share/mkosi.crt "$ROOT" >"$WORK/Colored"
    grep -c $'\e' "$WORK/Colored" >/dev/null
    sed 's/\x1b\[[0-9;]*m//g' "$WORK/Colored" | systemd-manifest verify --certificate=/usr/share/mkosi.crt "$ROOT"

    # Ed25519 keys work too, but only with OpenSSL >= 3.2, see uapi16_signer_new(). OpenSSL's legacy PKCS7
    # tooling cannot handle EdDSA, hence cross-check with the CMS tooling only, which is the same wire format.
    openssl req -x509 -newkey ed25519 -nodes -keyout "$WORK/ed25519.key" -out "$WORK/ed25519.crt" -subj /CN=ed25519 -days 2 2>/dev/null
    if systemd-analyze compare-versions "$(openssl version | cut -d' ' -f2)" ge 3.2; then
        systemd-manifest make --private-key="$WORK/ed25519.key" --certificate="$WORK/ed25519.crt" "$ROOT" >"$WORK/SignedEd25519"
        signature_object "$WORK/SignedEd25519" | jq -e '.mechanism == "pkcs7"' >/dev/null
        signature_object "$WORK/SignedEd25519" | jq -r '.data' | base64 -d >"$WORK/SignedEd25519.p7s"
        signed_payload "$WORK/SignedEd25519" "$WORK/SignedEd25519.payload"
        openssl cms -verify -binary -inform DER -in "$WORK/SignedEd25519.p7s" -content "$WORK/SignedEd25519.payload" -certfile "$WORK/ed25519.crt" -noverify -out /dev/null
        openssl cms -cmsout -print -inform DER -in "$WORK/SignedEd25519.p7s" | grep -E "algorithm: (sha512|ED25519)" >/dev/null

        systemd-manifest verify --certificate="$WORK/ed25519.crt" "$ROOT" "$WORK/SignedEd25519"
        systemd-manifest verify --certificate="$WORK/ed25519.crt" "$ROOT" <"$WORK/SignedEd25519"
        (! systemd-manifest verify --certificate=/usr/share/mkosi.crt "$ROOT" "$WORK/SignedEd25519")
        (! systemd-manifest verify --certificate="$WORK/ed25519.crt" "$ROOT" "$WORK/Signed")
        (! sed 's/"size":11/"size":12/' "$WORK/SignedEd25519" | systemd-manifest verify --certificate="$WORK/ed25519.crt" --field=none "$ROOT")
    else
        (! systemd-manifest make --private-key="$WORK/ed25519.key" --certificate="$WORK/ed25519.crt" "$ROOT")
    fi

    # Ed448 is not supported for signing
    openssl req -x509 -newkey ed448 -nodes -keyout "$WORK/ed448.key" -out "$WORK/ed448.crt" -subj /CN=ed448 -days 2 2>/dev/null
    (! systemd-manifest make --private-key="$WORK/ed448.key" --certificate="$WORK/ed448.crt" "$ROOT")
else
    echo "No mkosi key/certificate or openssl available, skipping signing tests"
fi

: "Inaccessible inodes and metadata make generation fail, unless --graceful is used"
GRACE="$WORK/graceful"
mkdir "$GRACE" "$GRACE/locked"
echo -n "public" >"$GRACE/readable.txt"
echo -n "secret" >"$GRACE/unreadable.txt"
chown -R testuser: "$GRACE"
chmod 0000 "$GRACE/locked" "$GRACE/unreadable.txt"
chmod 0755 "$WORK"
(! runas testuser systemd-manifest make "$GRACE")
(! runas testuser systemd-manifest make --format=mtree "$GRACE")
(! runas testuser systemd-manifest make --format=sha256sums "$GRACE")
(! runas testuser systemd-manifest make --format=list "$GRACE")
runas testuser systemd-manifest make --graceful "$GRACE" >"$WORK/graceful.manifest"
jq --seq -s -e '.[] | select(.name == "readable.txt") | has("sha256")' "$WORK/graceful.manifest" >/dev/null
jq --seq -s -e '.[] | select(.name == "unreadable.txt") | has("sha256") | not' "$WORK/graceful.manifest" >/dev/null
(! jq --seq -s -e '.[] | select(.name == "locked")' "$WORK/graceful.manifest" >/dev/null)
runas testuser systemd-manifest make --graceful --format=mtree "$GRACE" >/dev/null
runas testuser systemd-manifest make --graceful --format=sha256sums "$GRACE" >/dev/null
runas testuser systemd-manifest make --graceful --format=list "$GRACE" >/dev/null
# The top-level inode must be covered even in graceful mode
(! runas testuser systemd-manifest make --graceful "$GRACE/locked")

: "File contents that cannot be read make verification fail"
HASHFAIL="$WORK/hashfail"
mkdir "$HASHFAIL"
echo -n "secret" >"$HASHFAIL/unreadable.txt"
chown -R testuser: "$HASHFAIL"
chmod 0000 "$HASHFAIL/unreadable.txt"
systemd-manifest make "$HASHFAIL" >"$WORK/hashfail.manifest"
runas testuser systemd-manifest verify --verify-signature=no --field=size "$HASHFAIL" "$WORK/hashfail.manifest"
(! runas testuser systemd-manifest verify --verify-signature=no --field=hash "$HASHFAIL" "$WORK/hashfail.manifest")
(! runas testuser systemd-manifest verify --verify-signature=no "$HASHFAIL" "$WORK/hashfail.manifest")

: "Help and introspection work"
systemd-manifest --help >/dev/null
systemd-manifest --version >/dev/null
systemd-manifest make --help >/dev/null
