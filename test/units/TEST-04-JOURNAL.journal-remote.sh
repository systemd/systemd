#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# shellcheck disable=SC2016
set -eux
set -o pipefail

if [[ ! -x /usr/lib/systemd/systemd-journal-remote || ! -x /usr/lib/systemd/systemd-journal-upload ]]; then
    echo "Built without systemd-journal-remote/upload support, skipping the test"
    exit 77
fi

if ! command -v openssl >/dev/null; then
    echo "openssl command not available, skipping the tests"
    exit 77
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
mkdir -pZ /run/systemd/journal-remote-tls
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
mkdir -pZ /run/systemd/journal-{remote,upload}.conf.d
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

mkdir -pZ /run/systemd/remote-pki
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

[ v3_ca ]
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer:always
basicConstraints = CA:true
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
            -extensions v3_ca \
            -config /run/systemd/remote-pki/ca.conf \
            -keyout /run/systemd/remote-pki/ca.key \
            -out /run/systemd/remote-pki/ca.crt
openssl x509 -in /run/systemd/remote-pki/ca.crt -noout -text
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

systemctl stop systemd-journal-upload
systemctl stop systemd-journal-remote.{socket,service}
rm -rf /var/log/journal/remote/*

# Let's test sending data with compression enabled
for c in none xz lz4 zstd; do
    echo "$TEST_MESSAGE" | systemd-cat -t "$TEST_TAG"
    journalctl --sync

    cat >/run/systemd/journal-remote.conf.d/99-test.conf <<EOF
[Remote]
SplitMode=host
Compression=zstd xz
Compression=lz4
ServerKeyFile=/run/systemd/remote-pki/server.key
ServerCertificateFile=/run/systemd/remote-pki/server.crt
TrustedCertificateFile=/run/systemd/remote-pki/ca.crt
EOF
    cat >/run/systemd/journal-upload.conf.d/99-test.conf <<EOF
[Upload]
URL=https://localhost:19532
Compression=${c}:3
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
    rm -rf /var/log/journal/remote/*
    rm /run/systemd/journal-upload.conf.d/99-test.conf
    rm /run/systemd/journal-remote.conf.d/99-test.conf
done

# Let's test sending data with custom headers
echo "$TEST_MESSAGE" | systemd-cat -t "$TEST_TAG"
journalctl --sync

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
Header=TestHeader: TestValue
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
rm -rf /var/log/journal/remote/*
rm /run/systemd/journal-upload.conf.d/99-test.conf

# Reuse the trusted HTTPS receiver to check attribution and replacement of supplied fields.
max_fields="$(getconf IOV_MAX)"
for setting in '' yes; do
    if [[ -n "$setting" ]]; then
        echo "AddClientCertificateSubject=$setting" >>/run/systemd/journal-remote.conf.d/99-test.conf
    fi
    {
        printf '%s\n' '__REALTIME_TIMESTAMP=1700000000000000' '__MONOTONIC_TIMESTAMP=1000000' \
            '_BOOT_ID=0123456789abcdef0123456789abcdef' 'MESSAGE=field-limit-test'
        for ((i = 2; i < max_fields; i++)); do
            printf 'FIELD_%s=value\n' "$i"
        done
        printf '\n'
        printf '%s\n\n' '_REMOTE_CERTIFICATE_SUBJECT=CN=forged-only'
        printf '%s\n' '__REALTIME_TIMESTAMP=1700000000000000' '__MONOTONIC_TIMESTAMP=1000000' \
            '_BOOT_ID=0123456789abcdef0123456789abcdef' \
            '_REMOTE_CERTIFICATE_SUBJECT=CN=forged-one' 'MESSAGE=certificate-subject-test' \
            '_REMOTE_CERTIFICATE_SUBJECT=CN=forged-two' '_HOSTNAME=sender-claimed-host'
        printf '_REMOTE_CERTIFICATE_SUBJECT\n\x03\0\0\0\0\0\0\0a\0b\n\n'
    } >/run/systemd/remote-pki/subject.export
    systemctl restart systemd-journal-remote.socket
    for _ in 1 2; do
        curl --silent --show-error --fail --max-time 15 \
            --cacert /run/systemd/remote-pki/ca.crt \
            --cert /run/systemd/remote-pki/client.crt \
            --key /run/systemd/remote-pki/client.key \
            --header 'Content-Type: application/vnd.fdo.journal' \
            --data-binary @/run/systemd/remote-pki/subject.export https://localhost:19532/upload
    done
    expected_entries=6
    expected='["CN=forged-one","CN=forged-two",[97,0,98]]'
    if [[ "$setting" == yes ]]; then
        expected_entries=4
        expected=null
        if /usr/lib/systemd/systemd-journal-remote --version | grep -F +GNUTLS >/dev/null; then
            expected='"C=CZ,L=Brno,O=Foo,OU=Bar,CN=Test Client"'
        fi
    fi
    journalctl --directory=/var/log/journal/remote -o json --all |
        jq -se --argjson expected "$expected" --argjson count "$expected_entries" '
            length == $count and ([.[] | select(.MESSAGE == "certificate-subject-test")] |
            length == 2 and all(.[];
                ._REMOTE_CERTIFICATE_SUBJECT == $expected and ._HOSTNAME == "sender-claimed-host"))'
    systemctl stop systemd-journal-remote.{socket,service}
    rm -rf /var/log/journal/remote/*

    /usr/lib/systemd/systemd-journal-remote --split-mode=none \
        --output=/run/systemd/remote-pki/import.journal /run/systemd/remote-pki/subject.export
    expected_entries=3
    if [[ "$setting" == yes ]]; then
        expected_entries=2
        expected=null
    fi
    journalctl --file='/run/systemd/remote-pki/import*.journal' -o json --all |
        jq -se --argjson expected "$expected" --argjson count "$expected_entries" 'length == $count and
            ([.[] | select(.MESSAGE == "certificate-subject-test")] | length == 1 and
            .[0]._REMOTE_CERTIFICATE_SUBJECT == $expected and .[0]._HOSTNAME == "sender-claimed-host")'
    rm /run/systemd/remote-pki/import*.journal
done
mkdir -p /run/systemd/system/systemd-journal-remote.service.d
cat >/run/systemd/system/systemd-journal-remote.service.d/99-retention.conf <<EOF
[Service]
ExecStart=
ExecStart=/usr/lib/systemd/systemd-journal-remote --listen-https=-3
EOF
systemctl daemon-reload
curl_args=(--silent --show-error --fail --max-time 15
           --cacert /run/systemd/remote-pki/ca.crt
           --cert /run/systemd/remote-pki/client.crt --key /run/systemd/remote-pki/client.key
           --header 'Content-Type: application/vnd.fdo.journal'
           --data-binary @/run/systemd/remote-pki/retention.export https://localhost:19532/upload)
while read -r split file_age retention expected; do
    cat >>/run/systemd/journal-remote.conf.d/99-test.conf <<EOF_CONFIG
SplitMode=$split
MaxFileSec=$file_age
MaxRetentionSec=$retention
EOF_CONFIG
    systemctl restart systemd-journal-remote.socket
    systemctl start systemd-journal-remote.service
    if [[ "$expected" == mixed ]]; then
        printf '%s\n' '__REALTIME_TIMESTAMP=1700000000000000' '__MONOTONIC_TIMESTAMP=1000000' \
            '_BOOT_ID=0123456789abcdef0123456789abcdef' 'MESSAGE=backlog' '' \
            >/run/systemd/remote-pki/retention.export
        curl "${curl_args[@]}"
    fi
    printf '%s\n' "__REALTIME_TIMESTAMP=$(date +%s%6N)" '__MONOTONIC_TIMESTAMP=1000000' \
        '_BOOT_ID=0123456789abcdef0123456789abcdef' "MESSAGE=retention-test-$expected" '' \
        >/run/systemd/remote-pki/retention.export
    curl "${curl_args[@]}"
    journalctl --directory=/var/log/journal/remote -o cat --quiet | grep -Fx "retention-test-$expected"
    case "$expected" in
        retained)
            sleep 3
            journalctl --directory=/var/log/journal/remote -o cat --quiet | grep -Fx "retention-test-$expected"
            (! compgen -G '/var/log/journal/remote/*@*.journal')
            ;;
        rotated|mixed)
            timeout 30 bash -xec 'until compgen -G "/var/log/journal/remote/*@*.journal"; do sleep .2; done'
            journalctl --directory=/var/log/journal/remote -o cat --quiet | grep -Fx "retention-test-$expected"
            ;;
        expired)
            timeout 30 bash -xec 'while journalctl --directory=/var/log/journal/remote -o cat --quiet | grep -F retention-test-expired; do sleep .2; done'
            (! compgen -G '/var/log/journal/remote/*@*.journal')
            ;;
        batches)
            curl "${curl_args[@]}"
            curl "${curl_args[@]}"
            journalctl --directory=/var/log/journal/remote -o json --all | jq -se 'length == 3'
            (! compgen -G '/var/log/journal/remote/*@*.journal')
            ;;
        history)
            timeout 30 bash -xec 'until compgen -G "/var/log/journal/remote/*@*.journal"; do sleep .2; done'
            printf '%s\n' "__REALTIME_TIMESTAMP=$(date +%s%6N)" '__MONOTONIC_TIMESTAMP=1000000' \
                '_BOOT_ID=0123456789abcdef0123456789abcdef' 'MESSAGE=recent-history' '' \
                >/run/systemd/remote-pki/retention.export
            curl "${curl_args[@]}"
            timeout 30 bash -xec 'while journalctl --directory=/var/log/journal/remote -o cat --quiet | grep -Fx retention-test-history; do sleep .2; done'
            journalctl --directory=/var/log/journal/remote -o cat --quiet | grep -Fx recent-history
            ;;
    esac
    systemctl is-active systemd-journal-remote.service
    systemctl stop systemd-journal-remote.{socket,service}
    rm -rf /var/log/journal/remote/*
done <<EOF_CASES
none 0 0 retained
none infinity infinity retained
none 5s 0 rotated
host 5s 0 rotated
none 1h 10s expired
host 1h 10s expired
none 0 10s expired
host 0 10s expired
none 2s 10s mixed
host 1h 1h batches
none 1h 10s history
EOF_CASES

cat >>/run/systemd/journal-remote.conf.d/99-test.conf <<EOF
SplitMode=none
MaxFileSec=1h
MaxRetentionSec=1h
EOF
{
    for i in {1..8}; do
        printf '%s\n' '__REALTIME_TIMESTAMP=1700000000000000' '__MONOTONIC_TIMESTAMP=1000000' \
            '_BOOT_ID=0123456789abcdef0123456789abcdef' "MESSAGE=backlog-$i" ''
    done
} >/run/systemd/remote-pki/retention.export
/usr/lib/systemd/systemd-journal-remote --output=/run/systemd/remote-pki/backlog.journal \
    /run/systemd/remote-pki/retention.export
[[ -f /run/systemd/remote-pki/backlog.journal ]]
(! compgen -G '/run/systemd/remote-pki/backlog@*.journal')
journalctl --file=/run/systemd/remote-pki/backlog.journal -o json --all | jq -se 'length == 8'
rm /run/systemd/remote-pki/backlog.journal
rm /run/systemd/system/systemd-journal-remote.service.d/99-retention.conf
systemctl daemon-reload

rm /run/systemd/journal-remote.conf.d/99-test.conf

DOS_DIR="$(mktemp -d)"
{ head -c $((5 * 1024 * 1024)) /dev/zero | tr '\0' 'A'; printf '\n'; } >"$DOS_DIR/no-separator.export"
{ head -c $((5 * 1024 * 1024)) /dev/zero | tr '\0' 'A'; printf '=value\n'; } >"$DOS_DIR/long-field-name.export"
for export_file in "$DOS_DIR"/no-separator.export "$DOS_DIR"/long-field-name.export; do
    rm -f "$DOS_DIR"/*.journal
    timeout 30 /usr/lib/systemd/systemd-journal-remote \
                    --split-mode=none \
                    --output="$DOS_DIR/dos.journal" \
                    "$export_file" || [[ $? -lt 124 ]]
done
rm -rf "$DOS_DIR"
