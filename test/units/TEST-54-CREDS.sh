#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# shellcheck disable=SC2016
set -eux

# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh

systemd-analyze log-level debug

run_with_cred_compare() (
    local cred="${1:?}"
    local exp="${2?}"
    local log_file
    shift 2

    log_file="$(mktemp)"
    # shellcheck disable=SC2064
    trap "rm -f '$log_file'" RETURN

    set -o pipefail
    systemd-run -p SetCredential="$cred" --wait --pipe -- systemd-creds "$@" | tee "$log_file"
    diff "$log_file" <(echo -ne "$exp")
)

test_mount_with_credential() {
    local credfile tmpdir unit
    credfile="/tmp/mount-cred"
    tmpdir="/tmp/test-54-mount"
    unit=$(systemd-escape --suffix mount --path "$tmpdir")

    echo foo >"$credfile"
    mkdir -p "$tmpdir"

    # Set up test mount unit
    cat >/run/systemd/system/"$unit" <<EOF
[Mount]
What=tmpfs
Where=$tmpdir
Type=thisisatest
LoadCredential=loadcred:$credfile
EOF

    # Set up test mount type
    cat >/usr/sbin/mount.thisisatest <<EOF
#!/usr/bin/env bash
# Mount after verifying credential file content
if [ \$(cat \${CREDENTIALS_DIRECTORY}/loadcred) = "foo" ]; then
    mount -t tmpfs \$1 \$2
fi
EOF
    chmod +x /usr/sbin/mount.thisisatest

    # Verify mount succeeds
    systemctl daemon-reload
    systemctl start "$unit"
    systemctl --no-pager show -p SubState --value "$unit" | grep -q mounted

    # Verify mount fails with different credential file content
    echo bar >"$credfile"
    (! systemctl restart "$unit")

    # Stop unit and delete files
    systemctl stop "$unit"
    rm -f "$credfile" /run/systemd/system/"$unit" /usr/sbin/mount.thisisatest
    rm -rf "$tmpdir"
}

# Sanity checks
#
# Create a dummy "full" disk (similar to /dev/full) to check out-of-space
# scenarios
mkdir /tmp/full
mount -t tmpfs -o size=1,nr_inodes=1 tmpfs /tmp/full

# verb: setup
# Run this first, otherwise any encrypted credentials wouldn't be decryptable
# as we regenerate the host key
rm -fv /var/lib/systemd/credential.secret
systemd-creds setup
test -e /var/lib/systemd/credential.secret
rm -fv /var/lib/systemd/credential.secret

# Prepare a couple of dummy credentials for the cat/list verbs
CRED_DIR="$(mktemp -d)"
ENC_CRED_DIR="$(mktemp -d)"
echo foo >"$CRED_DIR/secure-or-weak"
echo foo >"$CRED_DIR/insecure"
echo foo | systemd-creds --name="encrypted" encrypt - "$ENC_CRED_DIR/encrypted"
echo foo | systemd-creds encrypt - "$ENC_CRED_DIR/encrypted-unnamed"
chmod -R 0400 "$CRED_DIR" "$ENC_CRED_DIR"
chmod -R 0444 "$CRED_DIR/insecure"
mkdir /tmp/empty/

systemd-creds --system
systemd-creds --no-pager --help
systemd-creds --version
systemd-creds has-tpm2 || :
systemd-creds has-tpm2 -q || :

# verb: list
systemd-creds list --system
ENCRYPTED_CREDENTIALS_DIRECTORY="$ENC_CRED_DIR" CREDENTIALS_DIRECTORY="$CRED_DIR" systemd-creds list --no-legend
ENCRYPTED_CREDENTIALS_DIRECTORY="$ENC_CRED_DIR" CREDENTIALS_DIRECTORY="$CRED_DIR" systemd-creds list --json=pretty | jq
ENCRYPTED_CREDENTIALS_DIRECTORY="$ENC_CRED_DIR" CREDENTIALS_DIRECTORY="$CRED_DIR" systemd-creds list --json=short | jq
ENCRYPTED_CREDENTIALS_DIRECTORY="$ENC_CRED_DIR" CREDENTIALS_DIRECTORY="$CRED_DIR" systemd-creds list --json=off
ENCRYPTED_CREDENTIALS_DIRECTORY="/tmp/empty/" CREDENTIALS_DIRECTORY="/tmp/empty/" systemd-creds list

# verb: cat
for cred in secure-or-weak insecure encrypted encrypted-unnamed; do
    ENCRYPTED_CREDENTIALS_DIRECTORY="$ENC_CRED_DIR" CREDENTIALS_DIRECTORY="$CRED_DIR" systemd-creds cat "$cred"
done
run_with_cred_compare "mycred:" "" cat mycred
run_with_cred_compare "mycred:\n" "\n" cat mycred
run_with_cred_compare "mycred:foo" "foo" cat mycred
run_with_cred_compare "mycred:foo" "foofoofoo" cat mycred mycred mycred
# Note: --newline= does nothing when stdout is not a tty, which is the case here
run_with_cred_compare "mycred:foo" "foo" --newline=yes cat mycred
run_with_cred_compare "mycred:foo" "foo" --newline=no cat mycred
run_with_cred_compare "mycred:foo" "foo" --newline=auto cat mycred
run_with_cred_compare "mycred:foo" "foo" --transcode=no cat mycred
run_with_cred_compare "mycred:foo" "foo" --transcode=0 cat mycred
run_with_cred_compare "mycred:foo" "foo" --transcode=false cat mycred
run_with_cred_compare "mycred:foo" "Zm9v" --transcode=base64 cat mycred
run_with_cred_compare "mycred:Zm9v" "foo" --transcode=unbase64 cat mycred
run_with_cred_compare "mycred:Zm9v" "foofoofoo" --transcode=unbase64 cat mycred mycred mycred
run_with_cred_compare "mycred:Zm9vCg==" "foo\n" --transcode=unbase64 cat mycred
run_with_cred_compare "mycred:hello world" "68656c6c6f20776f726c64" --transcode=hex cat mycred
run_with_cred_compare "mycred:68656c6c6f20776f726c64" "hello world" --transcode=unhex cat mycred
run_with_cred_compare "mycred:68656c6c6f20776f726c64" "hello worldhello world" --transcode=unhex cat mycred mycred
run_with_cred_compare "mycred:68656c6c6f0a776f726c64" "hello\nworld" --transcode=unhex cat mycred
run_with_cred_compare 'mycred:{ "foo" : "bar", "baz" : [ 3, 4 ] }' '{"foo":"bar","baz":[3,4]}\n' --json=short cat mycred
systemd-run -p SetCredential='mycred:{ "foo" : "bar", "baz" : [ 3, 4 ] }' --wait --pipe -- systemd-creds --json=pretty cat mycred | jq

# verb: encrypt/decrypt
echo "According to all known laws of aviation..." >/tmp/cred.orig
systemd-creds --with-key=host encrypt /tmp/cred.orig /tmp/cred.enc
systemd-creds decrypt /tmp/cred.enc /tmp/cred.dec
diff /tmp/cred.orig /tmp/cred.dec
rm -f /tmp/cred.{enc,dec}
# --pretty
cred_name="fo'''o''bar"
cred_option="$(systemd-creds --pretty --name="$cred_name" encrypt /tmp/cred.orig -)"
mkdir -p /run/systemd/system
cat >/run/systemd/system/test-54-pretty-cred.service <<EOF
[Service]
Type=oneshot
${cred_option:?}
ExecStart=bash -c "diff <(systemd-creds cat \"$cred_name\") /tmp/cred.orig"
EOF
systemctl daemon-reload
systemctl start test-54-pretty-cred
rm /run/systemd/system/test-54-pretty-cred.service
# Credential validation: name
systemd-creds --name="foo" -H encrypt /tmp/cred.orig /tmp/cred.enc
(! systemd-creds decrypt /tmp/cred.enc /tmp/cred.dec)
(! systemd-creds --name="bar" decrypt /tmp/cred.enc /tmp/cred.dec)
systemd-creds --name="" decrypt /tmp/cred.enc /tmp/cred.dec
diff /tmp/cred.orig /tmp/cred.dec
rm -f /tmp/cred.dec
systemd-creds --name="foo" decrypt /tmp/cred.enc /tmp/cred.dec
diff /tmp/cred.orig /tmp/cred.dec
rm -f /tmp/cred.{enc,dec}
# Credential validation: time
systemd-creds --not-after="+1d" encrypt /tmp/cred.orig /tmp/cred.enc
(! systemd-creds --timestamp="+2d" decrypt /tmp/cred.enc /tmp/cred.dec)
systemd-creds decrypt /tmp/cred.enc /tmp/cred.dec
diff /tmp/cred.orig /tmp/cred.dec
rm -f /tmp/cred.{enc,dec}

(! unshare -m bash -exc "mount -t tmpfs tmpfs /run/credentials && systemd-creds list")
(! unshare -m bash -exc "mount -t tmpfs tmpfs /run/credentials && systemd-creds --system list")
(! CREDENTIALS_DIRECTORY="" systemd-creds list)
(! systemd-creds --system --foo)
(! systemd-creds --system -@)
(! systemd-creds --system --json=)
(! systemd-creds --system --json="")
(! systemd-creds --system --json=foo)
(! systemd-creds --system cat)
(! systemd-creds --system cat "")
(! systemd-creds --system cat this-should-not-exist)
(! systemd-run -p SetCredential=mycred:foo --wait --pipe -- systemd-creds --transcode= cat mycred)
(! systemd-run -p SetCredential=mycred:foo --wait --pipe -- systemd-creds --transcode="" cat mycred)
(! systemd-run -p SetCredential=mycred:foo --wait --pipe -- systemd-creds --transcode=foo cat mycred)
(! systemd-run -p SetCredential=mycred:foo --wait --pipe -- systemd-creds --newline=foo cat mycred)
(! systemd-run -p SetCredential=mycred:notbase64 --wait --pipe -- systemd-creds --transcode=unbase64 cat mycred)
(! systemd-run -p SetCredential=mycred:nothex --wait --pipe -- systemd-creds --transcode=unhex cat mycred)
(! systemd-run -p SetCredential=mycred:a --wait --pipe -- systemd-creds --transcode=unhex cat mycred)
(! systemd-run -p SetCredential=mycred:notjson --wait --pipe -- systemd-creds --json=short cat mycred)
(! systemd-run -p SetCredential=mycred:notjson --wait --pipe -- systemd-creds --json=pretty cat mycred)
(! systemd-creds encrypt /foo/bar/baz -)
(! systemd-creds decrypt /foo/bar/baz -)
(! systemd-creds decrypt / -)
(! systemd-creds encrypt / -)
(! echo foo | systemd-creds --with-key=foo encrypt - -)
(! echo {0..20} | systemd-creds decrypt - -)
(! systemd-creds --not-after= encrypt /tmp/cred.orig /tmp/cred.enc)
(! systemd-creds --not-after="" encrypt /tmp/cred.orig /tmp/cred.enc)
(! systemd-creds --not-after="-1d" encrypt /tmp/cred.orig /tmp/cred.enc)
(! systemd-creds --timestamp= encrypt /tmp/cred.orig /tmp/cred.enc)
(! systemd-creds --timestamp="" encrypt /tmp/cred.orig /tmp/cred.enc)
(! dd if=/dev/zero count=2M | systemd-creds --with-key=tpm2-absent encrypt - /dev/null)
(! dd if=/dev/zero count=2M | systemd-creds --with-key=tpm2-absent decrypt - /dev/null)
(! echo foo | systemd-creds encrypt - /tmp/full/foo)
(! echo foo | systemd-creds encrypt - - | systemd-creds decrypt - /tmp/full/foo)

# Verify that the creds are properly loaded and we can read them from the service's unpriv user
systemd-run -p LoadCredential=passwd:/etc/passwd \
    -p LoadCredential=shadow:/etc/shadow \
    -p SetCredential=dog:wuff \
    -p DynamicUser=1 \
    --unit=test-54-unpriv.service \
    --wait \
    --pipe \
    cat '${CREDENTIALS_DIRECTORY}/passwd' '${CREDENTIALS_DIRECTORY}/shadow' '${CREDENTIALS_DIRECTORY}/dog' \
    >/tmp/ts54-concat
(cat /etc/passwd /etc/shadow && echo -n wuff) | cmp /tmp/ts54-concat
rm /tmp/ts54-concat

# Test that SetCredential= acts as fallback for LoadCredential=
echo piff >/tmp/ts54-fallback
[ "$(systemd-run -p LoadCredential=paff:/tmp/ts54-fallback -p SetCredential=paff:poff --pipe --wait systemd-creds cat paff)" = "piff" ]
rm /tmp/ts54-fallback
[ "$(systemd-run -p LoadCredential=paff:/tmp/ts54-fallback -p SetCredential=paff:poff --pipe --wait systemd-creds cat paff)" = "poff" ]

if systemd-detect-virt -q -c ; then
    expected_credential=mynspawncredential
    expected_value=strangevalue
elif [ -d /sys/firmware/qemu_fw_cfg/by_name ]; then
    # Verify that passing creds through kernel cmdline works
    [ "$(systemd-creds --system cat kernelcmdlinecred)" = "uff" ]
    [ "$(systemd-creds --system cat waldi)" = "woooofffwufffwuff" ]

    # And that it also works via SMBIOS
    [ "$(systemd-creds --system cat smbioscredential)" = "magicdata" ]
    [ "$(systemd-creds --system cat binarysmbioscredential)" = "magicbinarydata" ]

    # If we aren't run in nspawn, we are run in qemu
    systemd-detect-virt -q -v
    expected_credential=myqemucredential
    expected_value=othervalue

    # Verify that writing a sysctl via the kernel cmdline worked
    [ "$(cat /proc/sys/kernel/domainname)" = "sysctltest" ]

    # Verify that creating a user via sysusers via the kernel cmdline worked
    grep -q ^credtestuser: /etc/passwd

    # Verify that writing a file via tmpfiles worked
    [ "$(cat /tmp/sourcedfromcredential)" = "tmpfilessecret" ]
    [ "$(cat /etc/motd.d/50-provision.conf)" = "hello" ]
    [ "$(cat /etc/issue.d/50-provision.conf)" = "welcome" ]

    # Verify that adding a unit and drop-in via credentials worked
    systemctl start my-service
    test -f /tmp/unit-cred
    test -f /tmp/unit-dropin
    test -f /tmp/unit-named-dropin
else
    echo "qemu_fw_cfg support missing in kernel. Sniff!"
    expected_credential=""
    expected_value=""
fi

if [ "$expected_credential" != "" ] ; then
    # If this test is run in nspawn a credential should have been passed to us. See test/TEST-54-CREDS/test.sh
    [ "$(systemd-creds --system cat "$expected_credential")" = "$expected_value" ]

    # Test that propagation from system credential to service credential works
    [ "$(systemd-run -p LoadCredential="$expected_credential" --pipe --wait systemd-creds cat "$expected_credential")" = "$expected_value" ]

    # Check it also works, if we rename it while propagating it
    [ "$(systemd-run -p LoadCredential=miau:"$expected_credential" --pipe --wait systemd-creds cat miau)" = "$expected_value" ]

    # Combine it with a fallback (which should have no effect, given the cred should be passed down)
    [ "$(systemd-run -p LoadCredential="$expected_credential" -p SetCredential="$expected_credential":zzz --pipe --wait systemd-creds cat "$expected_credential")" = "$expected_value" ]

    # This should succeed
    systemd-run -p AssertCredential="$expected_credential" -p Type=oneshot true

    # And this should fail
    (! systemd-run -p AssertCredential="undefinedcredential" -p Type=oneshot true)
fi

# Verify that the creds are immutable
(! systemd-run -p LoadCredential=passwd:/etc/passwd \
    -p DynamicUser=1 \
    --unit=test-54-immutable-touch.service \
    --wait \
    touch '${CREDENTIALS_DIRECTORY}/passwd')
(! systemd-run -p LoadCredential=passwd:/etc/passwd \
    -p DynamicUser=1 \
    --unit=test-54-immutable-rm.service \
    --wait \
    rm '${CREDENTIALS_DIRECTORY}/passwd')

# Check directory-based loading
mkdir -p /tmp/ts54-creds/sub
echo -n a >/tmp/ts54-creds/foo
echo -n b >/tmp/ts54-creds/bar
echo -n c >/tmp/ts54-creds/baz
echo -n d >/tmp/ts54-creds/sub/qux
systemd-run -p LoadCredential=cred:/tmp/ts54-creds \
    -p DynamicUser=1 \
    --unit=test-54-dir.service \
    --wait \
    --pipe \
    cat '${CREDENTIALS_DIRECTORY}/cred_foo' \
        '${CREDENTIALS_DIRECTORY}/cred_bar' \
        '${CREDENTIALS_DIRECTORY}/cred_baz' \
        '${CREDENTIALS_DIRECTORY}/cred_sub_qux' >/tmp/ts54-concat
cmp /tmp/ts54-concat <(echo -n abcd)
rm /tmp/ts54-concat
rm -rf /tmp/ts54-creds

# Check that globs work as expected
mkdir -p /run/credstore
echo -n a >/run/credstore/test.creds.first
# Make sure that when multiple credentials of the same name are found, the first one is used (/etc/credstore
# is searched before /run/credstore).
echo -n ignored >/run/credstore/test.creds.second
mkdir -p /etc/credstore
echo -n b >/etc/credstore/test.creds.second
echo -n c >/etc/credstore/test.creds.third
# Credential name cannot contain ':'
echo -n hoge >/etc/credstore/test.creds.hoge:invalid

# Check if credentials with invalid names are not imported.
systemd-run -p "ImportCredential=test.creds.*" \
            --unit=test-54-ImportCredential.service \
            -p DynamicUser=1 \
            --wait \
            --pipe \
            test ! -e '${CREDENTIALS_DIRECTORY}/test.creds.hoge:invalid'

# Check if credentials with invalid names are not imported (with renaming).
systemd-run -p "ImportCredentialEx=test.creds.*:renamed.creds." \
            --unit=test-54-ImportCredential.service \
            -p DynamicUser=1 \
            --wait \
            --pipe \
            test ! -e '${CREDENTIALS_DIRECTORY}/renamed.creds.hoge:invalid'

# Check that all valid credentials are imported.
systemd-run -p "ImportCredential=test.creds.*" \
            --unit=test-54-ImportCredential.service \
            -p DynamicUser=1 \
            --wait \
            --pipe \
            cat '${CREDENTIALS_DIRECTORY}/test.creds.first' \
                '${CREDENTIALS_DIRECTORY}/test.creds.second' \
                '${CREDENTIALS_DIRECTORY}/test.creds.third' >/tmp/ts54-concat
cmp /tmp/ts54-concat <(echo -n abc)

# Check that ImportCredentialEx= works without renaming.
systemd-run -p "ImportCredentialEx=test.creds.*" \
            --unit=test-54-ImportCredential.service \
            -p DynamicUser=1 \
            --wait \
            --pipe \
            cat '${CREDENTIALS_DIRECTORY}/test.creds.first' \
                '${CREDENTIALS_DIRECTORY}/test.creds.second' \
                '${CREDENTIALS_DIRECTORY}/test.creds.third' >/tmp/ts54-concat
cmp /tmp/ts54-concat <(echo -n abc)

# Check that renaming with globs works as expected.
systemd-run -p "ImportCredentialEx=test.creds.*:renamed.creds." \
            --unit=test-54-ImportCredential.service \
            -p DynamicUser=1 \
            --wait \
            --pipe \
            cat '${CREDENTIALS_DIRECTORY}/renamed.creds.first' \
                '${CREDENTIALS_DIRECTORY}/renamed.creds.second' \
                '${CREDENTIALS_DIRECTORY}/renamed.creds.third' >/tmp/ts54-concat
cmp /tmp/ts54-concat <(echo -n abc)

# Check that renaming without globs works as expected.
systemd-run -p "ImportCredentialEx=test.creds.first:renamed.creds.first" \
            --unit=test-54-ImportCredential.service \
            -p DynamicUser=1 \
            --wait \
            --pipe \
            cat '${CREDENTIALS_DIRECTORY}/renamed.creds.first' >/tmp/ts54-concat
cmp /tmp/ts54-concat <(echo -n a)

# Test that multiple renames are processed in the correct order.
systemd-run -p "ImportCredentialEx=test.creds.first:renamed.creds.first" \
            -p "ImportCredentialEx=test.creds.second:renamed.creds.first" \
            --unit=test-54-ImportCredential.service \
            -p DynamicUser=1 \
            --wait \
            --pipe \
            cat '${CREDENTIALS_DIRECTORY}/renamed.creds.first' >/tmp/ts54-concat
cmp /tmp/ts54-concat <(echo -n a)

# Test that a credential can be imported multiple times with different names.
systemd-run -p "ImportCredentialEx=test.creds.first" \
            -p "ImportCredentialEx=test.creds.first:renamed.creds.first" \
            -p "ImportCredentialEx=test.creds.first:renamed.creds.second" \
            --unit=test-54-ImportCredential.service \
            -p DynamicUser=1 \
            --wait \
            --pipe \
            cat '${CREDENTIALS_DIRECTORY}/test.creds.first' \
                '${CREDENTIALS_DIRECTORY}/renamed.creds.first' \
                '${CREDENTIALS_DIRECTORY}/renamed.creds.second' >/tmp/ts54-concat
cmp /tmp/ts54-concat <(echo -n aaa)

# Now test encrypted credentials (only supported when built with OpenSSL though)
if systemctl --version | grep -q -- +OPENSSL ; then
    echo -n $RANDOM >/tmp/test-54-plaintext
    systemd-creds encrypt --name=test-54 /tmp/test-54-plaintext /tmp/test-54-ciphertext
    systemd-creds decrypt --name=test-54 /tmp/test-54-ciphertext | cmp /tmp/test-54-plaintext

    systemd-run -p LoadCredentialEncrypted=test-54:/tmp/test-54-ciphertext \
        --wait \
        --pipe \
        cat '${CREDENTIALS_DIRECTORY}/test-54' | cmp /tmp/test-54-plaintext

    echo -n $RANDOM >/tmp/test-54-plaintext
    systemd-creds encrypt --name=test-54 /tmp/test-54-plaintext /tmp/test-54-ciphertext
    systemd-creds decrypt --name=test-54 /tmp/test-54-ciphertext | cmp /tmp/test-54-plaintext

    systemd-run -p SetCredentialEncrypted=test-54:"$(cat /tmp/test-54-ciphertext)" \
        --wait \
        --pipe \
        cat '${CREDENTIALS_DIRECTORY}/test-54' | cmp /tmp/test-54-plaintext

    rm /tmp/test-54-plaintext /tmp/test-54-ciphertext
fi

# https://github.com/systemd/systemd/issues/27275
systemd-run -p DynamicUser=yes -p 'LoadCredential=os:/etc/os-release' \
            -p 'ExecStartPre=true' \
            -p 'ExecStartPre=systemd-creds cat os' \
            --unit=test-54-exec-start-pre.service \
            --wait \
            --pipe \
            true | cmp /etc/os-release

# https://github.com/systemd/systemd/issues/31194
systemd-run -p DynamicUser=yes -p 'LoadCredential=os:/etc/os-release' \
            -p 'ExecStartPost=systemd-creds cat os' \
            --unit=test-54-exec-start-post.service \
            --service-type=oneshot --wait --pipe \
            true | cmp /etc/os-release

# https://github.com/systemd/systemd/pull/24734#issuecomment-1925440546
# Also ExecStartPre= should be able to update creds
dd if=/dev/urandom of=/tmp/cred-huge bs=600K count=1
chmod 777 /tmp/cred-huge
systemd-run -p ProtectSystem=full \
            -p 'LoadCredential=huge:/tmp/cred-huge' \
            -p 'ExecStartPre=true' \
            -p 'ExecStartPre=bash -c "echo fresh >/tmp/cred-huge"' \
            --unit=test-54-huge-cred.service \
            --wait --pipe \
            systemd-creds cat huge | cmp - <(echo "fresh")
rm /tmp/cred-huge

echo stable >/tmp/cred-stable
systemd-run -p 'LoadCredential=stable:/tmp/cred-stable' \
            -p 'ExecStartPost=systemd-creds cat stable' \
            --unit=test-54-stable.service \
            --service-type=oneshot --wait --pipe \
            bash -c "echo bogus >/tmp/cred-stable" | cmp - <(echo "stable")
assert_eq "$(cat /tmp/cred-stable)" "bogus"
rm /tmp/cred-stable

if ! systemd-detect-virt -q -c ; then
    # Validate that the credential we inserted via the initrd logic arrived
    test "$(systemd-creds cat --system myinitrdcred)" = "guatemala"

    # Check that the fstab credential logic worked
    test -d /injected
    grep -q /injected /proc/self/mountinfo

    # Make sure the getty generator processed the credentials properly
    systemctl -P Wants show getty.target | grep -q container-getty@idontexist.service
fi

# Decrypt/encrypt via varlink

echo '{"data":"Zm9vYmFyCg=="}' > /tmp/vlcredsdata

varlinkctl call /run/systemd/io.systemd.Credentials io.systemd.Credentials.Encrypt "$(cat /tmp/vlcredsdata)" | \
    varlinkctl call --json=short /run/systemd/io.systemd.Credentials io.systemd.Credentials.Decrypt > /tmp/vlcredsdata2

cmp /tmp/vlcredsdata /tmp/vlcredsdata2
rm /tmp/vlcredsdata /tmp/vlcredsdata2

clean_usertest() {
    rm -f /tmp/usertest.data /tmp/usertest.data /tmp/brummbaer.data
}

trap clean_usertest EXIT
dd if=/dev/urandom of=/tmp/usertest.data bs=4096 count=1

systemd-creds encrypt --user /tmp/usertest.data /tmp/usertest.cred

systemd-creds decrypt --user /tmp/usertest.cred - | cmp /tmp/usertest.data

# Decryption must fail if it's not done in user context
(! systemd-creds decrypt /tmp/usertest.cred - )

# Decryption must also fail if a different user is used
(! systemd-creds decrypt --user --uid=65534 /tmp/usertest.cred - )

# Try the reverse
systemd-creds encrypt --user --uid=65534 /tmp/usertest.data /tmp/usertest.cred
(! systemd-creds decrypt --user /tmp/usertest.cred - )
systemd-creds decrypt --user --uid=65534 /tmp/usertest.cred - | cmp /tmp/usertest.data

systemd-creds encrypt --user /tmp/usertest.data /tmp/usertest.creds --name=mytest

# Make sure we actually can decode this in user context
systemctl start user@0.service
XDG_RUNTIME_DIR=/run/user/0 systemd-run --pipe --user --unit=waldi.service -p LoadCredentialEncrypted=mytest:/tmp/usertest.creds cat /run/user/0/credentials/waldi.service/mytest | cmp /tmp/usertest.data

# Test mount unit with credential
test_mount_with_credential

# Fully unpriv operation
dd if=/dev/urandom of=/tmp/brummbaer.data bs=4096 count=1
run0 -u testuser --pipe mkdir -p /home/testuser/.config/credstore.encrypted
run0 -u testuser --pipe systemd-creds encrypt --user --name=brummbaer - /home/testuser/.config/credstore.encrypted/brummbaer < /tmp/brummbaer.data
run0 -u testuser --pipe systemd-run --user --pipe -p ImportCredential=brummbaer systemd-creds cat brummbaer | cmp /tmp/brummbaer.data

systemd-analyze log-level info

touch /testok
