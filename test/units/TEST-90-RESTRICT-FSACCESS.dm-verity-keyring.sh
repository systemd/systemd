#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# Exercise the dedicated .dm-verity keyring trust path (kernel commit
# 033724b1c627, v7.0+): boot with linux-noinitrd so .platform stays empty,
# provision the mkosi cert into .dm-verity via keyctl, then verify a signed
# verity image still loads and execs under the BPF policy.
set -eux
set -o pipefail

# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh

if systemctl --version | grep -F -- "-BPF_FRAMEWORK" >/dev/null; then
    echo "BPF framework not compiled in, skipping"
    exit 77
fi

if ! kernel_supports_lsm bpf; then
    echo "BPF LSM not available in kernel, skipping"
    exit 77
fi

if command -v bpftool >/dev/null 2>&1; then
    if ! bpftool btf dump file /sys/kernel/btf/vmlinux 2>/dev/null | grep 'bpf_lsm_bdev_setintegrity' >/dev/null; then
        echo "Kernel lacks bdev_setintegrity LSM hook, skipping"
        exit 77
    fi
fi

if [[ -v ASAN_OPTIONS ]]; then
    echo "Skipping under sanitizers"
    exit 77
fi

HELPER="/usr/lib/systemd/tests/unit-tests/manual/test-bpf-restrict-fsaccess"
if [[ ! -x "$HELPER" ]]; then
    echo "ERROR: test-bpf-restrict-fsaccess helper not found at $HELPER" >&2
    exit 1
fi

# Helper exits 77 when systemd was built with bpf-framework=enabled but no
# vmlinux.h (HAVE_LSM_INTEGRITY_TYPE=0), so the BPF program isn't compiled in.
rc=0
"$HELPER" check >/dev/null 2>&1 || rc=$?
if [[ "$rc" -eq 77 ]]; then
    echo "test-bpf-restrict-fsaccess built without BPF attach support, skipping"
    exit 77
fi

if [[ ! -e /sys/module/dm_verity/parameters/require_signatures ]]; then
    modprobe dm_verity 2>/dev/null || true
fi
val="$(cat /sys/module/dm_verity/parameters/require_signatures 2>/dev/null || echo)"
if [[ "$val" != "Y" && "$val" != "1" ]]; then
    echo "require_signatures not enabled, skipping"
    exit 77
fi

if ! grep -E ' keyring +\.dm-verity: ' /proc/keys >/dev/null; then
    echo ".dm-verity keyring not available (kernel < v7.0?), skipping"
    exit 77
fi

# systemd-keyring-setup.service provisions the keyring at boot and seals it
# (permission mask 08070000), after which only certificates signed by an
# enrolled key can be added and the certificate must already be in place.
# Provision by hand only otherwise.
if grep -E '^[0-9a-f]+ [^ ]+ +[0-9]+ +[^ ]+ +08070000 +[0-9]+ +[0-9]+ +keyring +\.dm-verity: [0-9]+$' /proc/keys >/dev/null; then
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -subj /CN=stranger -days 1 \
        -keyout /dev/null -out /tmp/stranger.pem
    openssl x509 -in /tmp/stranger.pem -outform DER -out /tmp/stranger.der
    if keyctl padd asymmetric '' %:.dm-verity </tmp/stranger.der 2>/dev/null; then
        echo "ERROR: sealed .dm-verity keyring accepted a stranger" >&2
        exit 1
    fi
    echo ".dm-verity keyring already provisioned and sealed at boot"
elif grep -E ' +08070000 +[0-9]+ +[0-9]+ +keyring +\.dm-verity: empty$' /proc/keys >/dev/null; then
    echo "ERROR: .dm-verity keyring sealed empty, systemd-keyring-setup enrolled nothing" >&2
    exit 1
else
    # With the keyring left open by the kernel and systemd-keyring-setup enabled,
    # getting here means the service did not provision it
    if systemctl -q is-enabled systemd-keyring-setup.service 2>/dev/null &&
       [[ "$(cat /sys/module/dm_verity/parameters/keyring_unsealed 2>/dev/null)" == "Y" ]]; then
        echo "ERROR: .dm-verity keyring left open, systemd-keyring-setup did not provision it" >&2
        exit 1
    fi
    # Empty description lets the kernel derive one from the X.509 subject so
    # machine_supports_verity_keyring finds the CN.
    openssl x509 -in /usr/share/mkosi.crt -outform DER -out /tmp/mkosi.der
    keyid=$(keyctl padd asymmetric '' %:.dm-verity </tmp/mkosi.der 2>/dev/null) || keyid=""
    if [[ -z "$keyid" ]]; then
        echo ".dm-verity keyring sealed by the kernel at boot (no dm_verity.keyring_unsealed=1), skipping"
        exit 77
    fi
    if ! keyctl restrict_keyring %:.dm-verity; then
        keyctl unlink "$keyid" %:.dm-verity 2>/dev/null || true
        echo "ERROR: keyctl restrict_keyring failed" >&2
        exit 1
    fi
    echo "Provisioned .dm-verity keyring with mkosi.crt"
fi

at_exit() {
    set +e
    [[ -n "${HELPER_PID:-}" ]] && kill "$HELPER_PID" 2>/dev/null && wait "$HELPER_PID" 2>/dev/null || true
    rm -rf /tmp/restrict-fsaccess-dvk-attach.out
}
trap at_exit EXIT

HELPER_PID=
exec 3< <(exec "$HELPER" attach)
HELPER_PID=$!
while IFS= read -r -t 60 line <&3; do
    echo "$line"
    [[ "$line" == LINK_IDS=* ]] && break
done >/tmp/restrict-fsaccess-dvk-attach.out

# Fail closed if helper died before printing the full handshake: an unattached
# program would let the subsequent verity exec test pass trivially.
if ! kill -0 "$HELPER_PID" 2>/dev/null; then
    echo "ERROR: helper exited before BPF programs were attached" >&2
    exit 1
fi
grep -E '^LINK_IDS="[^"]+"' /tmp/restrict-fsaccess-dvk-attach.out >/dev/null || {
    echo "ERROR: helper did not report LINK_IDS, BPF programs not attached" >&2
    exit 1
}

# Run a binary off the signed minimal_0 verity image. Trust path is exclusively
# the .dm-verity keyring we just provisioned; .platform is empty under
# linux-noinitrd.
systemd-run --pipe --wait \
    --property RootImage=/usr/share/minimal_0.raw \
    bash --version >/dev/null
echo "Execution from signed dm-verity device (via .dm-verity keyring): OK"
