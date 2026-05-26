#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

# Unset $PAGER so we don't have to use --no-pager everywhere
export PAGER=

REPORT=/usr/lib/systemd/systemd-report

"$REPORT" --help
"$REPORT" help
"$REPORT" --version
"$REPORT" --json=help

"$REPORT" metrics
"$REPORT" metrics -j
"$REPORT" metrics --no-legend
"$REPORT" describe
"$REPORT" describe -j
"$REPORT" describe --no-legend
"$REPORT" list-sources
"$REPORT" list-sources -j
"$REPORT" list-sources --no-legend

"$REPORT" metrics io
"$REPORT" metrics io.systemd piff
"$REPORT" metrics piff
"$REPORT" describe io
"$REPORT" describe io.systemd piff
"$REPORT" describe piff

# test io.systemd.CGroup Metrics
systemctl start systemd-report-cgroup.socket
varlinkctl info /run/systemd/report/io.systemd.CGroup
varlinkctl list-methods /run/systemd/report/io.systemd.CGroup
varlinkctl --more call /run/systemd/report/io.systemd.CGroup io.systemd.Metrics.List {}
varlinkctl --more call /run/systemd/report/io.systemd.CGroup io.systemd.Metrics.Describe {}

# CpuUsage emits one row per (cgroup, type) where type is total, user, or system.
# Confirm all three are present.
cgroup_metrics=$(varlinkctl --more --json=short call /run/systemd/report/io.systemd.CGroup io.systemd.Metrics.List {})
echo "$cgroup_metrics" | grep '"name":"io.systemd.CGroup.CpuUsage"' | grep '"type":"total"' >/dev/null
echo "$cgroup_metrics" | grep '"name":"io.systemd.CGroup.CpuUsage"' | grep '"type":"user"' >/dev/null
echo "$cgroup_metrics" | grep '"name":"io.systemd.CGroup.CpuUsage"' | grep '"type":"system"' >/dev/null

# test io.systemd.Network Metrics
varlinkctl info /run/systemd/report/io.systemd.Network
varlinkctl list-methods /run/systemd/report/io.systemd.Network
varlinkctl --more call /run/systemd/report/io.systemd.Network io.systemd.Metrics.List {}
varlinkctl --more call /run/systemd/report/io.systemd.Network io.systemd.Metrics.Describe {}

# test io.systemd.Basic Metrics
# ensure the socket is running, as some distros don't enable it by default
systemctl start systemd-report-basic.socket
varlinkctl info /run/systemd/report/io.systemd.Basic
varlinkctl list-methods /run/systemd/report/io.systemd.Basic
varlinkctl --more call /run/systemd/report/io.systemd.Basic io.systemd.Metrics.List {}
varlinkctl --more call /run/systemd/report/io.systemd.Basic io.systemd.Metrics.Describe {}

id1="$(varlinkctl call --more /run/systemd/report/io.systemd.Basic io.systemd.Metrics.List {} | jq --seq -r 'select(.name == "io.systemd.Basic.OSRelease.ID") | .value')"
id2="$(. /etc/os-release; echo "$ID")"
[ "$id1" = "$id2" ]

# test io.systemd.Basic load average and swap metrics
basic_metrics="$(varlinkctl call --more /run/systemd/report/io.systemd.Basic io.systemd.Metrics.List {})"
# NB: '| tostring' turns the numeric value into a raw string, so 'jq -r' prints it cleanly
# (numbers, unlike strings, are otherwise still emitted with the json-seq record separator).
basic_value() { echo "$basic_metrics" | jq --seq -r "select(.name == \"$1\") | .value | tostring"; }

# The three classic load average fields must be present and numeric (jq's 'numbers' filter
# emits the value only if it is a JSON number, so a non-empty result confirms both).
for field in LoadAverage1Min LoadAverage5Min LoadAverage15Min; do
    loadavg="$(echo "$basic_metrics" | jq --seq -r "select(.name == \"io.systemd.Basic.$field\") | .value | numbers | tostring")"
    test -n "$loadavg"
done

# SwapBytes must match the total the kernel reports in /proc/meminfo (which is in kB).
swap_reported="$(basic_value io.systemd.Basic.SwapBytes)"
swap_expected=$(( $(awk '/^SwapTotal:/ { print $2; found=1 } END { if (!found) print 0 }' /proc/meminfo) * 1024 ))
[ "$swap_reported" = "$swap_expected" ]

# io.systemd.Manager.Version should be non-empty and match what `systemctl --version` reports
metrics_version="$(varlinkctl call --more /run/systemd/report/io.systemd.Manager io.systemd.Metrics.List {} | jq --seq -r 'select(.name == "io.systemd.Manager.Version") | .value')"
[ -n "$metrics_version" ]
systemctl --version | grep -F "($metrics_version)" >/dev/null

# Boot timeline timestamps. The kernel CLOCK_MONOTONIC is 0 by definition, so only its realtime is
# reported; userspace reports both realtime and monotonic. We don't check FinishTimestamp here:
# the test runs as a service, so manager_check_finished() typically hasn't fired yet and the
# timestamp is unset (the metric is then suppressed). Likewise KernelTimestamp is cleared when
# systemd runs inside a container (see main.c), so the metric is suppressed there too.
manager_metrics="$(varlinkctl call --more /run/systemd/report/io.systemd.Manager io.systemd.Metrics.List {})"
metric_value() { echo "$manager_metrics" | jq --seq -r "select(.name == \"io.systemd.Manager.$1\") | .value | tostring"; }
if ! systemd-detect-virt --quiet --container; then
    [ "$(metric_value KernelTimestamp.Realtime)" -gt 0 ]
fi
[ "$(metric_value UserspaceTimestamp.Realtime)" -gt 0 ]
[ "$(metric_value UserspaceTimestamp.Monotonic)" -gt 0 ]

# test io.systemd.Basic.MachineInfo.* metrics, sourced from /etc/machine-info
if [ -e /etc/machine-info ]; then
    MACHINE_INFO_BACKUP="$(mktemp)"
    cp /etc/machine-info "$MACHINE_INFO_BACKUP"
    MACHINE_INFO_EXISTED=1
else
    MACHINE_INFO_EXISTED=0
fi

restore_machine_info() {
    set +e
    if [ "$MACHINE_INFO_EXISTED" = 1 ]; then
        cp "$MACHINE_INFO_BACKUP" /etc/machine-info
        rm -f "$MACHINE_INFO_BACKUP"
    else
        rm -f /etc/machine-info
    fi
    set -e
}
trap restore_machine_info EXIT

cat >/etc/machine-info <<EOF
PRETTY_HOSTNAME="Test Machine"
DEPLOYMENT=test
LOCATION="Test Lab, Rack 3"
TAGS=foo:bar:baz
EOF

# The metric source re-reads /etc/machine-info on every call, so no service restart is needed.
machine_info_metrics="$(varlinkctl call --more /run/systemd/report/io.systemd.Basic io.systemd.Metrics.List {})"
machine_info_value() { echo "$machine_info_metrics" | jq --seq -r "select(.name == \"$1\") | .value"; }

[ "$(machine_info_value io.systemd.Basic.MachineInfo.PRETTY_HOSTNAME)" = "Test Machine" ]
[ "$(machine_info_value io.systemd.Basic.MachineInfo.DEPLOYMENT)" = "test" ]
[ "$(machine_info_value io.systemd.Basic.MachineInfo.LOCATION)" = "Test Lab, Rack 3" ]
[ "$(machine_info_value io.systemd.Basic.MachineInfo.TAGS)" = "foo:bar:baz" ]

restore_machine_info
trap - EXIT

# Test HTTP upload (plain http)
FAKE_SERVER=/usr/lib/systemd/tests/integration-tests/TEST-74-AUX-UTILS/TEST-74-AUX-UTILS.units/fake-report-server.py
CERTDIR=$(mktemp -d)

at_exit() {
    set +e
    systemctl stop fake-report-server fake-report-server-tls
    systemctl stop systemd-report.socket systemd-report-files.socket systemd-report-sign-plain.socket
    rm -f /run/systemd/report.files/testreportfile /run/systemd/report.files/binaryfile
    rm -rf "$CERTDIR" "${SIGN_WORK:-}"
}
trap at_exit EXIT

systemd-run -p Type=notify --unit=fake-report-server "$FAKE_SERVER"
systemctl status fake-report-server

"$REPORT" generate io.systemd.Manager.UnitsTotal

"$REPORT" generate io.systemd.Manager.UnitsTotal | jq .

"$REPORT" upload --url=http://localhost:8089/

# Test HTTPS upload with generated TLS certificates
openssl req -x509 -newkey rsa:2048 -keyout "$CERTDIR/server.key" -out "$CERTDIR/server.crt" \
    -days 1 -nodes -subj "/CN=localhost" 2>/dev/null

systemd-run -p Type=notify --unit=fake-report-server-tls \
    "$FAKE_SERVER" --cert="$CERTDIR/server.crt" --key="$CERTDIR/server.key" --port=8090
systemctl status fake-report-server-tls

"$REPORT" upload --url=https://localhost:8090/ --key=- --trust="$CERTDIR/server.crt" \
          --extra-header='Authorization: Bearer magic string'

# -----------------------------------------------------------------------------
# Test the systemd-report-files@.service metric provider: files dropped into one
# of the report.files directories are exposed verbatim as io.systemd.Files.*
# metrics, keyed by their file name.
mkdir -p /run/systemd/report.files
REPORT_FILE_CONTENT="hello from the report files metric provider"
printf '%s' "$REPORT_FILE_CONTENT" >/run/systemd/report.files/testreportfile

systemctl start systemd-report-files.socket
varlinkctl info /run/systemd/report/io.systemd.Files
varlinkctl list-methods /run/systemd/report/io.systemd.Files

# The metric value must be the exact file contents.
files_metrics="$(varlinkctl call --more /run/systemd/report/io.systemd.Files io.systemd.Metrics.List {})"
files_value() { echo "$files_metrics" | jq --seq -r "select(.name == \"$1\") | .value"; }
[ "$(files_value io.systemd.Files.testreportfile)" = "$REPORT_FILE_CONTENT" ]

# Describe must list the very same metric, of type string.
files_describe="$(varlinkctl call --more /run/systemd/report/io.systemd.Files io.systemd.Metrics.Describe {})"
echo "$files_describe" | jq --seq -r 'select(.name == "io.systemd.Files.testreportfile") | .type' | grep -wx string >/dev/null

# Files that aren't valid UTF-8 text must be skipped silently (the value is a
# JSON string, so only text files can be reported).
printf '\xff\xfe binary garbage' >/run/systemd/report.files/binaryfile
files_metrics="$(varlinkctl call --more /run/systemd/report/io.systemd.Files io.systemd.Metrics.List {})"
[ -z "$(files_value io.systemd.Files.binaryfile)" ]
rm -f /run/systemd/report.files/binaryfile

# -----------------------------------------------------------------------------
# Test report signing through the plain software backend, driven entirely via
# the io.systemd.Report Varlink interface (the GenerateSigned method). The plain
# backend is only built/installed with OpenSSL support, so skip if unavailable.
if ! systemctl cat systemd-report-sign-plain.socket &>/dev/null; then
    echo "systemd-report-sign-plain.socket is not installed, skipping report signing test."
    exit 0
fi

systemctl start systemd-report.socket
systemctl start systemd-report-sign-plain.socket

SIGN_WORK="$(mktemp -d)"

# Ask systemd-report to generate a *signed* report over Varlink. The reply
# carries the signed report as base64-encoded JSON-SEQ data.
varlinkctl call /run/systemd/io.systemd.Report io.systemd.Report.GenerateSigned \
    '{"matches":["io.systemd.Manager.UnitsTotal"]}' | jq -r .reportData | base64 -d >"$SIGN_WORK/report.seq"

# The first JSON-SEQ record is the report itself. This is exactly the byte
# sequence that got signed, including the leading record separator (0x1e) and
# the trailing newline, so 'head -n1' reproduces it verbatim.
head -n1 "$SIGN_WORK/report.seq" >"$SIGN_WORK/message.bin"
tr -d '\036' <"$SIGN_WORK/message.bin" | jq -e '.mediaType == "application/vnd.io.systemd.report"' >/dev/null

# The remaining record(s) are signature objects. With only the plain backend
# enabled there is exactly one, with mechanism "plain".
sig_json="$(tail -n +2 "$SIGN_WORK/report.seq" | tr -d '\036')"
[ "$(echo "$sig_json" | jq -r .mechanism)" = "plain" ]
[ "$(echo "$sig_json" | jq -r .mediaType)" = "application/vnd.io.systemd.report.signature" ]

# The sha256 recorded in the signature must match the digest of the report bytes.
[ "$(echo "$sig_json" | jq -r .sha256)" = "$(sha256sum "$SIGN_WORK/message.bin" | cut -d' ' -f1)" ]

# Extract the embedded public key and the raw Ed25519 signature.
echo "$sig_json" | jq -r .data.key >"$SIGN_WORK/pub.pem"
echo "$sig_json" | jq -r .data.signature | base64 -d >"$SIGN_WORK/sig.bin"

# The signature is made over the SHA256 digest bytes directly (Ed25519, the
# signer does not pre-hash), so verify the raw digest against the signature.
openssl dgst -sha256 -binary "$SIGN_WORK/message.bin" >"$SIGN_WORK/digest.bin"
openssl pkeyutl -verify -pubin -inkey "$SIGN_WORK/pub.pem" -rawin \
    -in "$SIGN_WORK/digest.bin" -sigfile "$SIGN_WORK/sig.bin"

# The public key embedded in the report must be the very key the plain backend
# generated and persisted on disk.
diff <(openssl pkey -pubin -in "$SIGN_WORK/pub.pem" -pubout) \
     <(openssl pkey -pubin -in /var/lib/systemd/report.sign.plain/local.public -pubout)

# A tampered report must no longer verify against the signature.
printf 'x' >>"$SIGN_WORK/message.bin"
openssl dgst -sha256 -binary "$SIGN_WORK/message.bin" >"$SIGN_WORK/digest-bad.bin"
if openssl pkeyutl -verify -pubin -inkey "$SIGN_WORK/pub.pem" -rawin \
    -in "$SIGN_WORK/digest-bad.bin" -sigfile "$SIGN_WORK/sig.bin"; then
    echo "Signature verification unexpectedly succeeded for tampered report" >&2
    exit 1
fi

# -----------------------------------------------------------------------------
# The plain backend also acts as a metric provider, exposing its public signing
# key as the io.systemd.Report.SignPlain.PublicKey metric. This is served off the
# very same socket as the signer, reachable in the metrics directory under
# /run/systemd/report/ (the signer endpoint is just a symlink into the root-only
# /run/systemd/report.sign/ directory pointing at the same socket).
varlinkctl info /run/systemd/report/io.systemd.Report.SignPlain
varlinkctl list-methods /run/systemd/report/io.systemd.Report.SignPlain

# The exposed public key must be the very key persisted on disk.
sign_metrics="$(varlinkctl call --more /run/systemd/report/io.systemd.Report.SignPlain io.systemd.Metrics.List {})"
echo "$sign_metrics" | jq --seq -r 'select(.name == "io.systemd.Report.SignPlain.PublicKey") | .value' >"$SIGN_WORK/metric-pub.pem"
diff <(openssl pkey -pubin -in "$SIGN_WORK/metric-pub.pem" -pubout) \
     <(openssl pkey -pubin -in /var/lib/systemd/report.sign.plain/local.public -pubout)

# Describe must list the very same metric, of type string.
varlinkctl call --more /run/systemd/report/io.systemd.Report.SignPlain io.systemd.Metrics.Describe {} |
    jq --seq -r 'select(.name == "io.systemd.Report.SignPlain.PublicKey") | .type' | grep -wx string >/dev/null
