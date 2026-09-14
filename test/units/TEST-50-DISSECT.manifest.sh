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

systemd-manifest make --format=sha256sums "$ROOT" >"$WORK/SHA256SUMS"
# Only the six regular files are listed
test "$(wc -l <"$WORK/SHA256SUMS")" -eq 6
# ... and coreutils agrees with us
(cd "$ROOT" && sha256sum -c "$WORK/SHA256SUMS")

: "The uapi16 default is the same as the explicit format, and output is stable"
systemd-manifest make --format=uapi16 "$ROOT" | cmp - "$WORK/Uapi16Manifest"

: "Verification round trips, from a file, from stdin, and with no arguments at all"
systemd-manifest verify --verify=no "$ROOT" "$WORK/Uapi16Manifest"
systemd-manifest verify --verify=no "$ROOT" <"$WORK/Uapi16Manifest"
systemd-manifest verify --verify=no "$ROOT" - <"$WORK/Uapi16Manifest"
systemd-manifest verify "$ROOT" "$WORK/SHA256SUMS"
systemd-manifest verify --format=sha256sums "$ROOT" <"$WORK/SHA256SUMS"
systemd-manifest verify --format=list "$ROOT" "$WORK/list"
(cd "$ROOT" && systemd-manifest make | systemd-manifest verify)
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
jq -e 'select(.name == "subdir") | .type == "dir"' "$WORK/minimal.jsonl" >/dev/null
# mtime is opt-in
systemd-manifest make --field=+mtime "$ROOT" | tr -d '\036' | jq -e 'select(.name == "regular.txt") | has("mTimeNSec")' >/dev/null
systemd-manifest make "$ROOT" | tr -d '\036' | jq -e 'select(.name == "regular.txt") | has("mTimeNSec") | not' >/dev/null
systemd-manifest make --format=mtree --field=+mtime "$ROOT" | grep -F " time=" >/dev/null
systemd-manifest make --format=mtree --field=none "$ROOT" | grep -F "./regular.txt type=file" >/dev/null
(! systemd-manifest make --format=mtree --field=none "$ROOT" | grep -F "mode=")
(! systemd-manifest make --field=foobar "$ROOT")
# sha256sums needs the hash field
(! systemd-manifest make --format=sha256sums --field=-hash "$ROOT")

: "Hash algorithm selection"
systemd-manifest make --format=mtree --hash=sha512 "$ROOT" | grep -F " sha512sum=$(sha512sum "$ROOT/regular.txt" | cut -d' ' -f1)" >/dev/null
systemd-manifest make --format=sha256sums --hash=sha512 "$ROOT" >"$WORK/SHA512SUMS"
(cd "$ROOT" && sha512sum -c "$WORK/SHA512SUMS")
systemd-manifest verify --format=sha256sums --hash=sha512 "$ROOT" "$WORK/SHA512SUMS"
(! systemd-manifest verify --format=sha256sums --hash=sha256 "$ROOT" "$WORK/SHA512SUMS")
# UAPI.16 only knows SHA256
(! systemd-manifest make --hash=sha512 "$ROOT")
(! systemd-manifest verify --verify=no --hash=sha512 "$ROOT" "$WORK/Uapi16Manifest")

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
systemd-manifest verify --verify=no "$WORK/broken" "$WORK/Uapi16Manifest" 2>&1 | tee "$WORK/uapi16.log"
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
(! systemd-manifest verify --verify=no "$WORK/broken" "$WORK/Uapi16Manifest")

# Only checking contents ignores the mode change and the hardlink
set +o pipefail
systemd-manifest verify --verify=no --field=size,hash "$WORK/broken" "$WORK/Uapi16Manifest" 2>&1 | tee "$WORK/uapi16-content.log"
set -o pipefail
grep -F "Found 3 mismatches between manifest and directory tree." "$WORK/uapi16-content.log"
(! grep -F "nested.txt" "$WORK/uapi16-content.log")

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
{ cat "$WORK/Uapi16Manifest"; printf '\036{"mediaType":"application/vnd.example.unknown","foo":"bar"}\n'; } | systemd-manifest verify --verify=no "$ROOT"

: "File names needing escaping in SHA256SUMS"
mkdir "$WORK/escape"
printf 'x' >"$WORK/escape/a
b"
printf 'y' >"$WORK/escape/back\\slash"
systemd-manifest make --format=sha256sums "$WORK/escape" >"$WORK/escape.sums"
grep -F '\2d711642b726b04401627ca9fbac32f5c8530fb1903cc4db02258717921a4881  a\nb' "$WORK/escape.sums"
(cd "$WORK/escape" && sha256sum -c "$WORK/escape.sums")
systemd-manifest verify --format=sha256sums "$WORK/escape" "$WORK/escape.sums"

: "Signing"
if [[ -f /usr/share/mkosi.key && -f /usr/share/mkosi.crt ]] && command -v openssl >/dev/null; then
    # We sign if (and only if) a private key is specified, which requires a certificate, but not the other way round
    (! systemd-manifest make --private-key=/usr/share/mkosi.key "$ROOT")
    (! systemd-manifest make --certificate=/usr/share/mkosi.crt "$ROOT")
    (! systemd-manifest make --format=mtree --private-key=/usr/share/mkosi.key --certificate=/usr/share/mkosi.crt "$ROOT")
    (! tr -d '\036' <"$WORK/Uapi16Manifest" | jq -e 'select(.mediaType == "application/vnd.uapi.16.signature")' >/dev/null)

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
    systemd-manifest verify --verify=no "$ROOT" "$WORK/Signed"
    # Without --certificate= the VOA hierarchy is consulted, which carries no certificate yet
    (! systemd-manifest verify "$ROOT" "$WORK/Signed")
    (! systemd-manifest verify --verify=no --certificate=/usr/share/mkosi.crt "$ROOT" "$WORK/Signed")
    (! systemd-manifest verify --format=sha256sums --verify=yes "$ROOT" "$WORK/SHA256SUMS")
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
    (! sed 's/"size":11/"size":12/' "$WORK/Signed" | systemd-manifest verify --certificate=/usr/share/mkosi.crt "$ROOT")

    openssl req -x509 -newkey rsa:2048 -nodes -keyout "$WORK/other.key" -out "$WORK/other.crt" -subj /CN=other -days 2 2>/dev/null
    (! systemd-manifest verify --certificate="$WORK/other.crt" "$ROOT" "$WORK/Signed")

    # Objects between the signature object and the trailer are not covered by the signature and ignored
    { head -c -"$(tr -d '\036' <"$WORK/Signed" | tail -n1 | wc -c)" "$WORK/Signed" | head -c -1; printf '\036{"mediaType":"application/x-test-extra","name":"extra.txt"}\n\036{"mediaType":"application/vnd.uapi.16.trailer"}\n'; } | systemd-manifest verify --certificate=/usr/share/mkosi.crt "$ROOT"

    # A colored rendering carries the signature over the color-free bytes
    SYSTEMD_COLORS=1 systemd-manifest make --json=pretty --private-key=/usr/share/mkosi.key --certificate=/usr/share/mkosi.crt "$ROOT" >"$WORK/Colored"
    grep -c $'\e' "$WORK/Colored" >/dev/null
    sed 's/\x1b\[[0-9;]*m//g' "$WORK/Colored" | systemd-manifest verify --certificate=/usr/share/mkosi.crt "$ROOT"

    # Ed25519 keys work too. OpenSSL's legacy PKCS7 tooling cannot handle EdDSA, hence cross-check with the
    # CMS tooling only, which is the same wire format.
    openssl req -x509 -newkey ed25519 -nodes -keyout "$WORK/ed25519.key" -out "$WORK/ed25519.crt" -subj /CN=ed25519 -days 2 2>/dev/null
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
    (! sed 's/"size":11/"size":12/' "$WORK/SignedEd25519" | systemd-manifest verify --certificate="$WORK/ed25519.crt" "$ROOT")

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
jq --seq -e 'select(.name == "readable.txt") | has("sha256")' "$WORK/graceful.manifest" >/dev/null
jq --seq -e 'select(.name == "unreadable.txt") | has("sha256") | not' "$WORK/graceful.manifest" >/dev/null
(! jq --seq -e 'select(.name == "locked")' "$WORK/graceful.manifest" >/dev/null)
runas testuser systemd-manifest make --graceful --format=mtree "$GRACE" >/dev/null
runas testuser systemd-manifest make --graceful --format=sha256sums "$GRACE" >/dev/null
runas testuser systemd-manifest make --graceful --format=list "$GRACE" >/dev/null
# The top-level inode must be covered even in graceful mode
(! runas testuser systemd-manifest make --graceful "$GRACE/locked")

: "Help and introspection work"
systemd-manifest --help >/dev/null
systemd-manifest --version >/dev/null
systemd-manifest make --help >/dev/null
