#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

# Tests the TPM2_EK_TEMPLATES= hwdb property, which tells systemd which EK templates to use on TPMs that
# have no EK certificate (such as the swtpm used in QEMU guests): both the creation of a new EK at
# 0x81010001, and the discovery of EKs that were pre-provisioned at a profile specific handle.

# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh

SD_TPM2SETUP="/usr/lib/systemd/systemd-tpm2-setup"
TPM_DEVICE="/dev/tpmrm0"
HWDB_FILE="/etc/udev/hwdb.d/99-test-tpm2-ek.hwdb"
HWDB_BIN="/etc/udev/hwdb.bin"

EK_HANDLE=0x81010001
EK_HANDLE_P384=0x81010016

if [[ ! -x "$SD_TPM2SETUP" ]]; then
    echo "$SD_TPM2SETUP not found, skipping."
    exit 77
fi

for cmd in systemd-hwdb tpm2_createprimary tpm2_createek tpm2_evictcontrol tpm2_getcap tpm2_readpublic; do
    if ! command -v "$cmd" >/dev/null; then
        echo "$cmd not found, skipping."
        exit 77
    fi
done

if [[ ! -c "$TPM_DEVICE" ]]; then
    echo "$TPM_DEVICE not found, skipping."
    exit 77
fi

if [[ -z "$(udevadm info --query=property --property=ID_TPM2_MODALIAS --value "$TPM_DEVICE")" ]]; then
    echo "$TPM_DEVICE has no TPM2 modalias, so hwdb is not consulted for it, skipping."
    exit 77
fi

# EK certificates are ignored if the hwdb property is set, but some tests below run without the
# property set and expect that no EK is created or found. The swtpm in our VM currently has no,
# EK certificates, but fail loudly rather than silently losing test coverage should that ever change.
if tpm2_getcap handles-nv-index | grep -E '0x1[cC]000(02|0[aA]|12|14|16|1[cC])\b' >/dev/null; then
    echo >&2 "TPM has EK certificates, this test needs to be adapted."
    exit 1
fi

persistent_handle_exists() {
    tpm2_getcap handles-persistent | grep -i "\b${1:?}\b" >/dev/null
}

WORK="$(mktemp -d)"
HWDB_BIN_EXISTED=0
[[ -e "$HWDB_BIN" ]] && HWDB_BIN_EXISTED=1

evict_test_handles() {
    local handle

    for handle in "$EK_HANDLE" "$EK_HANDLE_P384"; do
        if persistent_handle_exists "$handle"; then
            tpm2_evictcontrol -C o -c "$handle"
        fi
    done
}

# Start from a clean slate, in case an earlier subtest left an EK behind.
evict_test_handles

set_hwdb_ek_templates() {
    if [[ $# -gt 0 ]]; then
        mkdir -p "$(dirname "$HWDB_FILE")"
        # Our VM only has a single TPM, so match all of them.
        cat >"$HWDB_FILE" <<EOF
tpm2:*
 TPM2_EK_TEMPLATES=$*
EOF
    else
        rm -f "$HWDB_FILE"
    fi

    if [[ -e "$HWDB_FILE" || "$HWDB_BIN_EXISTED" -eq 1 ]]; then
        systemd-hwdb update
    else
        rm -f "$HWDB_BIN"
    fi

    # udevd only checks whether hwdb changed every few seconds, so make sure it is reloaded right away.
    udevadm control --reload
    udevadm trigger --settle --action=change "$TPM_DEVICE"
    assert_eq "$(udevadm info --query=property --property=TPM2_EK_TEMPLATES --value "$TPM_DEVICE")" "$*"
}

at_exit() {
    set +e
    evict_test_handles
    set_hwdb_ek_templates
    rm -rf "$WORK"
}
trap at_exit EXIT

# Runs systemd-tpm2-setup, which creates the EK if necessary, and saves its debug output in $WORK/log.
# systemd-tpm2-setup returns EX_UNAVAILABLE (69) rather than 0 if it couldn't find or create an EK, but
# also if it can't set up something else (such as NvPCRs), so we check its output instead.
run_tpm2_setup() {
    local rc=0

    SYSTEMD_LOG_LEVEL=debug "$SD_TPM2SETUP" --tpm2-device="$TPM_DEVICE" --early=no &>"$WORK/log" || rc=$?
    cat "$WORK/log"
    [[ "$rc" -eq 0 || "$rc" -eq 69 ]]
}

log_has() {
    grep -F "${1:?}" "$WORK/log" >/dev/null
}

# Creates a primary key from the default ecc-nist-p384 (H-3) EK template in the specified hierarchy, and
# persists it at the handle that the TCG registry of reserved handles reserves for this template.
#
# The template is specified in section B.4.6 of the "TCG EK Credential Profile for TPM Family 2.0" spec.
# The auth policy is PolicyB_SHA384: TPM2_PolicySecret(TPM_RH_ENDORSEMENT) OR
# TPM2_PolicyAuthorizeNV(0x01C07F02).
preprovision_p384_ek() {
    local hierarchy="${1:?}"

    printf '%b' '\xb2\x6e\x7d\x28\xd1\x1a\x50\xbc\x53\xd8\x82\xbc\xf5\xfd\x3a\x1a' \
                '\x07\x41\x48\xbb\x35\xd3\xb4\xe4\xcb\x1c\x0a\xd9\xbd\xe4\x19\xca' \
                '\xcb\x47\xba\x09\x69\x96\x46\x15\x0f\x9f\xc0\x00\xf3\xf8\x0e\x12' >"$WORK/policy-b-sha384"

    tpm2_createprimary \
        -C "$hierarchy" \
        -g sha384 \
        -G ecc384:null:aes256cfb \
        -a "fixedtpm|fixedparent|sensitivedataorigin|userwithauth|adminwithpolicy|restricted|decrypt" \
        -L "$WORK/policy-b-sha384" \
        -c "$WORK/ek.ctx"
    tpm2_evictcontrol -C o -c "$WORK/ek.ctx" "$EK_HANDLE_P384"
    rm -f "$WORK/ek.ctx"
}

# Prints the name of the object at the specified persistent handle.
object_name() {
    tpm2_readpublic -c "${1:?}" -n "$WORK/name" >/dev/null
    od -An -tx1 -v "$WORK/name" | tr -d ' \n'
}

# 1) Without hwdb property and without a certificate, no EK is created.
set_hwdb_ek_templates
run_tpm2_setup
log_has "No TPM2_EK_TEMPLATES property"
log_has "No usable EK certificate or hwdb EK template found"
(! persistent_handle_exists "$EK_HANDLE")

# 2) With the hwdb property, an EK is created at 0x81010001 using the listed template that comes first in
#    our order of preference, regardless of the order in which they are listed. Running
#    systemd-tpm2-setup again then finds the EK that was just created.
set_hwdb_ek_templates rsa-2048-legacy ecc-nist-p384
run_tpm2_setup
log_has "Trying to create EK with template 'ECC NIST P384 (H-3)' from hwdb, without EK certificate"
(! log_has "Trying to create EK with template 'RSA 2048 (L-1)' from hwdb")
persistent_handle_exists "$EK_HANDLE"
(! persistent_handle_exists "$EK_HANDLE_P384")
EK_NAME="$(object_name "$EK_HANDLE")"

run_tpm2_setup
(! log_has "Trying to create EK")

# The EK was created from the default template, so it is the same key as one that we create from the
# default template ourselves. This also checks that the key we use in the tests below is valid.
evict_test_handles
preprovision_p384_ek e
assert_eq "$(object_name "$EK_HANDLE_P384")" "$EK_NAME"
evict_test_handles

# 3) With the hwdb property, an EK that was pre-provisioned with a listed template at its profile specific
#    handle is used, and no new EK is created.
preprovision_p384_ek e
run_tpm2_setup
log_has "Using pre-provisioned EK with template 'ECC NIST P384 (H-3)' at 0x81010016 from hwdb, without EK certificate"
(! log_has "Trying to create EK")
(! persistent_handle_exists "$EK_HANDLE")
evict_test_handles

# 4) Without the hwdb property, a pre-provisioned EK can only be validated with a certificate, so it is
#    not used.
set_hwdb_ek_templates
preprovision_p384_ek e
run_tpm2_setup
(! log_has "Using pre-provisioned EK")
log_has "No usable EK certificate or hwdb EK template found"
(! persistent_handle_exists "$EK_HANDLE")
persistent_handle_exists "$EK_HANDLE_P384"
evict_test_handles

# 5) A pre-provisioned EK is only used if its template is listed. Instead, a new EK is created with the
#    listed template, and the pre-provisioned one is left alone.
set_hwdb_ek_templates rsa-2048-legacy
preprovision_p384_ek e
run_tpm2_setup
(! log_has "Using pre-provisioned EK")
log_has "Trying to create EK with template 'RSA 2048 (L-1)' from hwdb, without EK certificate"
persistent_handle_exists "$EK_HANDLE"
persistent_handle_exists "$EK_HANDLE_P384"
assert_in "rsa" "$(tpm2_readpublic -c "$EK_HANDLE")"
evict_test_handles

# 6) An object at the pre-provisioned EK handle that matches the template but isn't a primary key in the
#    endorsement hierarchy is not used, and a new EK is created instead.
set_hwdb_ek_templates ecc-nist-p384
preprovision_p384_ek o
run_tpm2_setup
log_has "Object is not a primary key in the endorsement hierarchy."
(! log_has "Using pre-provisioned EK")
log_has "Trying to create EK with template 'ECC NIST P384 (H-3)' from hwdb, without EK certificate"
persistent_handle_exists "$EK_HANDLE"
assert_eq "$(object_name "$EK_HANDLE")" "$EK_NAME"
evict_test_handles

# 7) Like on EC2, an EK with a listed template is provisioned at 0x81010001 and another one is
#    pre-provisioned at its profile specific handle. The one whose template comes first in our order of
#    preference is used, regardless of the order in which they are listed.
set_hwdb_ek_templates rsa-2048-legacy ecc-nist-p384
tpm2_createek -G rsa -c "$EK_HANDLE"
preprovision_p384_ek e
run_tpm2_setup
log_has "Using pre-provisioned EK with template 'ECC NIST P384 (H-3)' at 0x81010016 from hwdb, without EK certificate"
(! log_has "Trying to create EK")
evict_test_handles
