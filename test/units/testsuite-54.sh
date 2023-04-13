#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# shellcheck disable=SC2016
set -eux

systemd-analyze log-level debug

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
( cat /etc/passwd /etc/shadow && echo -n wuff ) | cmp /tmp/ts54-concat
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
    ( ! systemd-run -p AssertCredential="undefinedcredential" -p Type=oneshot true )
fi

# Verify that the creds are immutable
(! systemd-run -p LoadCredential=passwd:/etc/passwd \
    -p DynamicUser=1 \
    --unit=test-54-immutable-touch.service \
    --wait \
    touch '${CREDENTIALS_DIRECTORY}/passwd' )
(! systemd-run -p LoadCredential=passwd:/etc/passwd \
    -p DynamicUser=1 \
    --unit=test-54-immutable-rm.service \
    --wait \
    rm '${CREDENTIALS_DIRECTORY}/passwd' )

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

systemd-analyze log-level info

echo OK >/testok

exit 0
