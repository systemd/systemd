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

python3 - "$TEST_TAG" "$TEST_MESSAGE" <<'PY'
import hashlib
import lzma
import socket
import subprocess
import sys
import tempfile
import time
import zlib
from pathlib import Path

tag, message = sys.argv[1:]
message += "-" + hashlib.shake_256(b"journal-remote split upload").hexdigest(256 * 1024)
payload = (
    "__REALTIME_TIMESTAMP=1700000000000000\n"
    "__MONOTONIC_TIMESTAMP=1000000\n"
    "_BOOT_ID=f446871715504074bf7049ef0718fa93\n"
    "_MACHINE_ID=69121ca41d12c1b69a7960174c27b618\n"
    f"SYSLOG_IDENTIFIER={tag}\n"
    f"MESSAGE={message}\n\n"
).encode()
frame = lzma.compress(payload)
# The compressed frame exceeds JOURNAL_SERVER_MEMORY_MAX, forcing multiple MHD callbacks.
assert len(frame) > 128 * 1024

with tempfile.TemporaryDirectory() as directory:
    output = Path(directory) / "remote.journal"
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]

    receiver = subprocess.Popen(
        [
            "/usr/lib/systemd/systemd-journal-remote",
            f"--listen-http=127.0.0.1:{port}",
            f"--output={output}",
            "--split-mode=none",
        ]
    )
    try:
        for _ in range(50):
            if receiver.poll() is not None:
                raise AssertionError("journal-remote exited before listening")
            try:
                connection = socket.create_connection(("127.0.0.1", port), 0.1)
                break
            except OSError:
                time.sleep(0.1)
        else:
            raise AssertionError("journal-remote did not listen")

        with connection:
            connection.settimeout(15)
            connection.sendall(
                (
                    "POST /upload HTTP/1.1\r\n"
                    "Host: localhost\r\n"
                    "Content-Type: application/vnd.fdo.journal\r\n"
                    "Content-Encoding: xz\r\n"
                    "Transfer-Encoding: chunked\r\n"
                    "Connection: close\r\n\r\n"
                    f"{len(frame):x}\r\n"
                ).encode()
            )
            connection.sendall(frame + b"\r\n0\r\n\r\n")
            response = bytearray()
            while chunk := connection.recv(4096):
                response.extend(chunk)

        assert response.startswith(b"HTTP/1.1 202 "), response

        # Declare a 128 MiB dictionary, above JOURNAL_REMOTE_DECOMPRESSOR_MEMORY_MAX, by patching
        # the block header of a small-dictionary stream: encoding with a real 128 MiB dictionary
        # would need over 1 GiB of memory. The decoder checks the declared size before decoding.
        oversized_dictionary = bytearray(
            lzma.compress(payload[:128], filters=[{"id": lzma.FILTER_LZMA2, "dict_size": 1 << 20}])
        )
        header_end = 12 + (oversized_dictionary[12] + 1) * 4
        # Block flags (one filter, no sizes), LZMA2 filter ID, filter properties size.
        assert oversized_dictionary[13:16] == b"\x00\x21\x01", oversized_dictionary[12:header_end]
        oversized_dictionary[16] = 30  # (2 | (30 & 1)) << (30 // 2 + 11) = 128 MiB
        oversized_dictionary[header_end - 4:header_end] = zlib.crc32(
            oversized_dictionary[12:header_end - 4]
        ).to_bytes(4, "little")
        with socket.create_connection(("127.0.0.1", port), 5) as connection:
            connection.settimeout(15)
            connection.sendall(
                (
                    "POST /upload HTTP/1.1\r\n"
                    "Host: localhost\r\n"
                    "Content-Type: application/vnd.fdo.journal\r\n"
                    "Content-Encoding: xz\r\n"
                    f"Content-Length: {len(oversized_dictionary)}\r\n"
                    "Connection: close\r\n\r\n"
                ).encode()
                + oversized_dictionary
            )
            response = bytearray()
            while chunk := connection.recv(4096):
                response.extend(chunk)

        # libmicrohttpd refuses to queue a response while the request body is still being
        # received, so the rejection may arrive as a closed connection instead of a 400.
        assert not response or response.startswith(b"HTTP/1.1 400 "), response
    finally:
        receiver.terminate()
        receiver.wait(timeout=5)

    imported = subprocess.check_output(
        ["journalctl", "--no-pager", f"--file={output}", "-o", "cat"]
    )
    assert message.encode() in imported.splitlines(), imported
PY

# A request may outlive the entry deadline as long as complete entries keep arriving, but a request
# that trickles bytes without storing an entry is closed.
python3 - "$TEST_TAG" <<'PY'
import os
import select
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

tag = sys.argv[1]
deadline = 2


def entry(i, message):
    return (
        f"__REALTIME_TIMESTAMP={1700000000000000 + i}\n"
        f"__MONOTONIC_TIMESTAMP={1000000 + i}\n"
        "_BOOT_ID=f446871715504074bf7049ef0718fa93\n"
        "_MACHINE_ID=69121ca41d12c1b69a7960174c27b618\n"
        f"SYSLOG_IDENTIFIER={tag}\n"
        f"MESSAGE={message}\n\n"
    ).encode()


def chunk(data):
    return f"{len(data):x}\r\n".encode() + data + b"\r\n"


def open_upload(port):
    connection = socket.create_connection(("127.0.0.1", port), 5)
    connection.settimeout(15)
    connection.sendall(
        b"POST /upload HTTP/1.1\r\n"
        b"Host: localhost\r\n"
        b"Content-Type: application/vnd.fdo.journal\r\n"
        b"Transfer-Encoding: chunked\r\n"
        b"Connection: close\r\n\r\n"
    )
    return connection


def closed_by_peer(connection):
    readable, _, _ = select.select([connection], [], [], 0)
    try:
        return bool(readable) and connection.recv(4096) == b""
    except ConnectionResetError:
        return True


def assert_closed_by_deadline(port, pieces):
    """Send one piece every half second and expect the entry deadline to close the connection."""
    start = time.monotonic()
    with open_upload(port) as connection:
        for piece in pieces:
            if closed_by_peer(connection):
                break
            try:
                connection.sendall(chunk(piece))
            except (BrokenPipeError, ConnectionResetError):
                break
            time.sleep(0.5)
        else:
            raise AssertionError(f"journal-remote kept a stalled request open: {pieces[:2]}")
    elapsed = time.monotonic() - start

    assert deadline <= elapsed < deadline + 5, elapsed


with tempfile.TemporaryDirectory() as directory:
    output = Path(directory) / "remote.journal"
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]

    receiver = subprocess.Popen(
        [
            "/usr/lib/systemd/systemd-journal-remote",
            f"--listen-http=127.0.0.1:{port}",
            f"--output={output}",
            "--split-mode=none",
        ],
        env=os.environ | {"SYSTEMD_JOURNAL_REMOTE_ENTRY_TIMEOUT_SEC": str(deadline)},
    )
    try:
        for _ in range(50):
            if receiver.poll() is not None:
                raise AssertionError("journal-remote exited before listening")
            try:
                socket.create_connection(("127.0.0.1", port), 0.1).close()
                break
            except OSError:
                time.sleep(0.1)
        else:
            raise AssertionError("journal-remote did not listen")

        # One complete entry per second for three deadlines.
        entries = 3 * deadline
        with open_upload(port) as connection:
            for i in range(entries):
                connection.sendall(chunk(entry(i, f"deadline-stream-{i}")))
                time.sleep(1)
            connection.sendall(b"0\r\n\r\n")
            response = bytearray()
            while data := connection.recv(4096):
                response.extend(data)

        assert response.startswith(b"HTTP/1.1 202 "), response

        # One byte of a single entry at a time; the entry would take far longer than the deadline
        # to complete.
        partial = entry(entries, "deadline-partial")
        assert_closed_by_deadline(port, [partial[i : i + 1] for i in range(len(partial))])

        # Blank lines terminate empty records, which are skipped and store nothing.
        assert_closed_by_deadline(port, [b"\n"] * 40)
    finally:
        receiver.terminate()
        receiver.wait(timeout=5)

    imported = subprocess.check_output(
        ["journalctl", "--no-pager", f"--file={output}", "-o", "cat"]
    ).splitlines()
    assert imported == [f"deadline-stream-{i}".encode() for i in range(entries)], imported
PY

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
