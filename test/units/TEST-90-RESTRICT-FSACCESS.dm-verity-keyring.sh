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
    exit 0
fi

if ! kernel_supports_lsm bpf; then
    echo "BPF LSM not available in kernel, skipping"
    exit 0
fi

if command -v bpftool >/dev/null 2>&1; then
    if ! bpftool btf dump file /sys/kernel/btf/vmlinux 2>/dev/null | grep 'bpf_lsm_bdev_setintegrity' >/dev/null; then
        echo "Kernel lacks bdev_setintegrity LSM hook, skipping"
        exit 0
    fi
fi

if [[ -v ASAN_OPTIONS ]]; then
    echo "Skipping under sanitizers"
    exit 0
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
    exit 0
fi

if [[ ! -e /sys/module/dm_verity/parameters/require_signatures ]]; then
    modprobe dm_verity 2>/dev/null || true
fi
val="$(cat /sys/module/dm_verity/parameters/require_signatures 2>/dev/null || echo)"
if [[ "$val" != "Y" && "$val" != "1" ]]; then
    echo "require_signatures not enabled, skipping"
    exit 0
fi

# Provision the .dm-verity keyring. Empty description lets the kernel derive
# one from the X.509 subject so machine_supports_verity_keyring finds the CN.
keyid=$(openssl x509 -in /usr/share/mkosi.crt -outform DER |
            keyctl padd asymmetric '' %:.dm-verity 2>/dev/null) || keyid=""
if [[ -z "$keyid" ]]; then
    echo ".dm-verity keyring not provisionable (kernel < v7.0?), skipping"
    exit 0
fi
if ! keyctl restrict_keyring %:.dm-verity; then
    keyctl unlink "$keyid" %:.dm-verity 2>/dev/null || true
    echo "ERROR: keyctl restrict_keyring failed" >&2
    exit 1
fi
echo "Provisioned .dm-verity keyring with mkosi.crt"

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
done > /tmp/restrict-fsaccess-dvk-attach.out

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
