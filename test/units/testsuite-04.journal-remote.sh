#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# shellcheck disable=SC2016
set -eux
set -o pipefail

if [[ ! -x /usr/lib/systemd/systemd-journal-remote || ! -x /usr/lib/systemd/systemd-journal-upload ]]; then
    echo "Built without systemd-journal-remote/upload support, skipping the test"
    exit 0
fi

if ! command -v openssl >/dev/null; then
    echo "openssl command not available, skipping the tests"
    exit 0
fi

at_exit() {
    set +e

    systemctl stop systemd-journal-upload
    systemctl stop systemd-journal-remote.{socket,service}
    # Remove any remote journals on exit, so we don't try to export them together
    # with the local journals, causing a mess
    rm -rf /var/log/journal/remote
}

trap at_exit EXIT

TEST_MESSAGE="-= This is a test message $RANDOM =-"
TEST_TAG="$(systemd-id128 new)"

echo "$TEST_MESSAGE" | systemd-cat -t "$TEST_TAG"
journalctl --sync

/usr/lib/systemd/systemd-journal-remote --version
/usr/lib/systemd/systemd-journal-remote --help
/usr/lib/systemd/systemd-journal-upload --version
/usr/lib/systemd/systemd-journal-upload --help

# Generate a self-signed certificate for systemd-journal-remote
#
# Note: older OpenSSL requires a config file with some extra options, unfortunately
# Note2: /run here is used on purpose, since the systemd-journal-remote service uses PrivateTmp=yes
mkdir -p /run/systemd/journal-remote-tls
cat >/tmp/openssl.conf <<EOF
[ req ]
prompt = no
distinguished_name = req_distinguished_name

[ req_distinguished_name ]
C = CZ
L = Brno
O = Foo
OU = Bar
CN = localhost
EOF
openssl req -x509 -nodes -newkey rsa:2048 -sha256 -days 7 \
            -config /tmp/openssl.conf \
            -keyout /run/systemd/journal-remote-tls/key.pem \
            -out /run/systemd/journal-remote-tls/cert.pem
chown -R systemd-journal-remote /run/systemd/journal-remote-tls

# Configure journal-upload to upload journals to journal-remote without client certificates
mkdir -p /run/systemd/journal-{remote,upload}.conf.d
cat >/run/systemd/journal-remote.conf.d/99-test.conf <<EOF
[Remote]
SplitMode=host
ServerKeyFile=/run/systemd/journal-remote-tls/key.pem
ServerCertificateFile=/run/systemd/journal-remote-tls/cert.pem
TrustedCertificateFile=-
EOF
cat >/run/systemd/journal-upload.conf.d/99-test.conf <<EOF
[Upload]
URL=https://localhost:19532
ServerKeyFile=-
ServerCertificateFile=-
TrustedCertificateFile=-
EOF
systemd-analyze cat-config systemd/journal-remote.conf
systemd-analyze cat-config systemd/journal-upload.conf

systemctl restart systemd-journal-remote.socket
systemctl restart systemd-journal-upload
timeout 15 bash -xec 'until systemctl -q is-active systemd-journal-remote.service; do sleep 1; done'
systemctl status systemd-journal-{remote,upload}

# It may take a bit until the whole journal is transferred
timeout 30 bash -xec "until journalctl --directory=/var/log/journal/remote --identifier='$TEST_TAG' --grep='$TEST_MESSAGE'; do sleep 1; done"

systemctl stop systemd-journal-upload
systemctl stop systemd-journal-remote.{socket,service}
rm -rf /var/log/journal/remote/*

# Now let's do the same, but with a full PKI setup
#
# journal-upload keeps the cursor of the last uploaded message, so let's send a fresh one
echo "$TEST_MESSAGE" | systemd-cat -t "$TEST_TAG"
journalctl --sync

mkdir /run/systemd/remote-pki
cat >/run/systemd/remote-pki/ca.conf <<EOF
[ req ]
prompt = no
distinguished_name = req_distinguished_name

[ req_distinguished_name ]
C = CZ
L = Brno
O = Foo
OU = Bar
CN = Test CA
EOF
cat >/run/systemd/remote-pki/client.conf <<EOF
[ req ]
prompt = no
distinguished_name = req_distinguished_name

[ req_distinguished_name ]
C = CZ
L = Brno
O = Foo
OU = Bar
CN = Test Client
EOF
cat >/run/systemd/remote-pki/server.conf <<EOF
[ req ]
prompt = no
distinguished_name = req_distinguished_name

[ req_distinguished_name ]
C = CZ
L = Brno
O = Foo
OU = Bar
CN = localhost
EOF
# Generate a dummy CA
openssl req -x509 -nodes -newkey rsa:2048 -sha256 -days 7 \
            -config /run/systemd/remote-pki/ca.conf \
            -keyout /run/systemd/remote-pki/ca.key \
            -out /run/systemd/remote-pki/ca.crt
echo 01 >/run/systemd/remote-pki/ca.srl
# Generate a client key and signing request
openssl req -nodes -newkey rsa:2048 -sha256 \
            -config /run/systemd/remote-pki/client.conf \
            -keyout /run/systemd/remote-pki/client.key \
            -out /run/systemd/remote-pki/client.csr
# Sign the request with the CA key
openssl x509 -req -days 7 \
             -in /run/systemd/remote-pki/client.csr \
             -CA /run/systemd/remote-pki/ca.crt \
             -CAkey /run/systemd/remote-pki/ca.key \
             -out /run/systemd/remote-pki/client.crt
# And do the same for the server
openssl req -nodes -newkey rsa:2048 -sha256 \
            -config /run/systemd/remote-pki/server.conf \
            -keyout /run/systemd/remote-pki/server.key \
            -out /run/systemd/remote-pki/server.csr
openssl x509 -req -days 7 \
             -in /run/systemd/remote-pki/server.csr \
             -CA /run/systemd/remote-pki/ca.crt \
             -CAkey /run/systemd/remote-pki/ca.key \
             -out /run/systemd/remote-pki/server.crt
chown -R systemd-journal-remote:systemd-journal /run/systemd/remote-pki
chmod -R g+rwX /run/systemd/remote-pki

# Reconfigure journal-upload/journal remote with the new keys
cat >/run/systemd/journal-remote.conf.d/99-test.conf <<EOF
[Remote]
SplitMode=host
ServerKeyFile=/run/systemd/remote-pki/server.key
ServerCertificateFile=/run/systemd/remote-pki/server.crt
TrustedCertificateFile=/run/systemd/remote-pki/ca.crt
EOF
cat >/run/systemd/journal-upload.conf.d/99-test.conf <<EOF
[Upload]
URL=https://localhost:19532
ServerKeyFile=/run/systemd/remote-pki/client.key
ServerCertificateFile=/run/systemd/remote-pki/client.crt
TrustedCertificateFile=/run/systemd/remote-pki/ca.crt
EOF
systemd-analyze cat-config systemd/journal-remote.conf
systemd-analyze cat-config systemd/journal-upload.conf

systemctl restart systemd-journal-remote.socket
systemctl restart systemd-journal-upload
timeout 15 bash -xec 'until systemctl -q is-active systemd-journal-remote.service; do sleep 1; done'
systemctl status systemd-journal-{remote,upload}

# It may take a bit until the whole journal is transferred
timeout 30 bash -xec "until journalctl --directory=/var/log/journal/remote --identifier='$TEST_TAG' --grep='$TEST_MESSAGE'; do sleep 1; done"

systemctl stop systemd-journal-upload
systemctl stop systemd-journal-remote.{socket,service}

# Let's test if journal-remote refuses connection from journal-upload with invalid client certs
#
# We should end up with something like this:
#    systemd-journal-remote[726]: Client is not authorized
#    systemd-journal-upload[738]: Upload to https://localhost:19532/upload failed with code 401:
#    systemd[1]: systemd-journal-upload.service: Main process exited, code=exited, status=1/FAILURE
#    systemd[1]: systemd-journal-upload.service: Failed with result 'exit-code'.
#
cat >/run/systemd/journal-upload.conf.d/99-test.conf <<EOF
[Upload]
URL=https://localhost:19532
ServerKeyFile=/run/systemd/journal-remote-tls/key.pem
ServerCertificateFile=/run/systemd/journal-remote-tls/cert.pem
TrustedCertificateFile=/run/systemd/remote-pki/ca.crt
EOF
systemd-analyze cat-config systemd/journal-upload.conf
mkdir -p /run/systemd/system/systemd-journal-upload.service.d
cat >/run/systemd/system/systemd-journal-upload.service.d/99-test.conf <<EOF
[Service]
Restart=no
EOF
systemctl daemon-reload
chgrp -R systemd-journal /run/systemd/journal-remote-tls
chmod -R g+rwX /run/systemd/journal-remote-tls

systemctl restart systemd-journal-upload
timeout 10 bash -xec 'while [[ "$(systemctl show -P ActiveState systemd-journal-upload)" != failed ]]; do sleep 1; done'
(! systemctl status systemd-journal-upload)
