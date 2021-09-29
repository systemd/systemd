#!/usr/bin/env bash
# shellcheck disable=SC2016
set -eux

systemd-analyze log-level debug

# Verify that the creds are properly loaded and we can read them from the service's unpriv user
systemd-run -p LoadCredential=passwd:/etc/passwd \
            -p LoadCredential=shadow:/etc/shadow \
            -p SetCredential=dog:wuff \
            -p DynamicUser=1 \
            --wait \
            --pipe \
            cat '${CREDENTIALS_DIRECTORY}/passwd' '${CREDENTIALS_DIRECTORY}/shadow' '${CREDENTIALS_DIRECTORY}/dog' >/tmp/ts54-concat
( cat /etc/passwd /etc/shadow && echo -n wuff ) | cmp /tmp/ts54-concat
rm /tmp/ts54-concat

# Verify that the creds are immutable
systemd-run -p LoadCredential=passwd:/etc/passwd \
            -p DynamicUser=1 \
            --wait \
            touch '${CREDENTIALS_DIRECTORY}/passwd' \
    && { echo 'unexpected success'; exit 1; }
systemd-run -p LoadCredential=passwd:/etc/passwd \
            -p DynamicUser=1 \
            --wait \
            rm '${CREDENTIALS_DIRECTORY}/passwd' \
    && { echo 'unexpected success'; exit 1; }

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
