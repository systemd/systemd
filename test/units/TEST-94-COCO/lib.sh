# SPDX-License-Identifier: LGPL-2.1-or-later
# shellcheck shell=bash
#
# Host-side helpers for the confidential computing integration test (TEST-94-COCO).
# Sourced by the TEST-94-COCO.sh driver.

if [[ "${BASH_SOURCE[0]}" -ef "$0" ]]; then
    echo >&2 "This file should not be executed directly"
    exit 1
fi

# shellcheck source=test/units/TEST-94-COCO/fixtures.sh
. "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")/fixtures.sh"

# Exit status the guest test runner reports on success (its unit's SuccessActionExitStatus=). vmspawn
# forwards the guest PID1's EXIT_STATUS over the vsock notify socket and exits with it.
_COCO_GUEST_PASS=123
# vsock port the host listens on for the guest's per-check result records, distinct from vmspawn's own
# (kernel-assigned) notify port. The host binds CID_ANY:PORT; the guest connects to CID 2 (host):PORT.
_COCO_RESULT_PORT=4321

# _coco_guest_unit COCO_TYPE UNITS_DIR [MATCH]
# Emit the one-shot unit that runs the guest test runner: passes the coco type, result port and
# optional testcase filter via the environment, and relays the aggregate verdict via
# SuccessAction/EXIT_STATUS.
_coco_guest_unit() {
    local coco_type="${1:?}" units_dir="${2:?}" match="${3:-}"
    cat <<EOF
[Unit]
Description=coco guest self-check
After=basic.target
SuccessAction=exit
SuccessActionExitStatus=$_COCO_GUEST_PASS
FailureAction=exit
FailureActionExitStatus=1
[Service]
Type=oneshot
Environment=COCO_TYPE=$coco_type
Environment=COCO_RESULT_PORT=$_COCO_RESULT_PORT
Environment="TEST_MATCH_TESTCASE=$match"
ExecStart=$units_dir/guest-test-runner.sh
EOF
}

# _coco_guest_dropin
# Emit the multi-user.target drop-in that pulls the guest self-check unit into the boot.
_coco_guest_dropin() {
    cat <<EOF
[Unit]
Wants=$COCO_GUEST_UNIT
After=$COCO_GUEST_UNIT
EOF
}

# vmspawn_boot_coco MACHINE COCO_TYPE WORKDIR MATCH [systemd-vmspawn args...]
# Boot a confidential guest with systemd-vmspawn, running the coco guest test runner (restricted to
# testcases matching MATCH, empty for all). The caller supplies the boot-path-specific launch args —
# --image/--linux/--initrd and the guest kernel command line — plus any extra flags via "$@", so each
# per-boot-path scenario stays configurable. Per-check records shipped by the guest are collected over
# a vsock socket into WORKDIR/results and echoed; returns 0 iff the guest reported the success
# aggregate, otherwise dumps the console. (The adversarial subtests will add a qemu_boot_coco sibling
# that drives QEMU directly.)
vmspawn_boot_coco() {
    local machine="${1:?}" coco_type="${2:?}" workdir="${3:?}" match="${4-}"
    shift 4

    local units_dir results console guest_unit guest_dropin rc=0 listener_pid=""
    units_dir="$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")"
    results="$workdir/results"
    console="$workdir/console.log"
    : >"$results"

    guest_unit="$(_coco_guest_unit "$coco_type" "$units_dir" "$match")"
    guest_dropin="$(_coco_guest_dropin)"

    # Collect the per-check records the guest ships over vsock (single connection, guest closes when
    # done). Best-effort: the aggregate exit status below is the authoritative pass/fail, so a vsock
    # hiccup only costs the per-check breakdown, never the verdict.
    socat -u "VSOCK-LISTEN:$_COCO_RESULT_PORT" "OPEN:$results,creat" &
    listener_pid=$!

    timeout -k 30 300 systemd-vmspawn \
        --machine="$machine" \
        --coco="$coco_type" \
        --ram=1G \
        --ephemeral \
        --tpm=no \
        --console=read-only \
        --set-credential="systemd.extra-unit.$COCO_GUEST_UNIT:$guest_unit" \
        --set-credential="systemd.unit-dropin.multi-user.target:$guest_dropin" \
        "$@" \
        2>&1 | tee "$console" || rc="${PIPESTATUS[0]}"

    kill "$listener_pid" 2>/dev/null || :
    wait "$listener_pid" 2>/dev/null || :

    if [[ -s "$results" ]]; then
        echo "coco guest per-check results:"
        cat "$results"
    fi

    if [[ "$rc" -eq 124 || "$rc" -eq 137 ]]; then
        echo "systemd-vmspawn was killed by timeout (exit $rc)" >&2
        cat "$console" >&2
        return 1
    fi
    if [[ "$rc" -ne "$_COCO_GUEST_PASS" ]]; then
        echo "coco guest test runner failed: vmspawn exit $rc (expected $_COCO_GUEST_PASS)" >&2
        cat "$console" >&2
        return 1
    fi
    return 0
}
