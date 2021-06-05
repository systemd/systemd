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

systemd-analyze log-level info

echo OK >/testok

exit 0
