#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# Runs inside the confidential guest launched by TEST-94-COCO.sh. Runs the requested guest-side checks
# (testcase_coco_* from guest-test.sh), ships a per-check result record plus any artifacts the checks
# exported to the host over the vsock result socket, and lets the injected unit's
# SuccessAction/FailureAction relay the aggregate verdict to the host via vmspawn's exit status.

set -eux
set -o pipefail

_COCO_DIR="$(dirname "$(readlink -f "$0")")"
# util.sh (assert_*) lives one level up in the shared units dir.
# shellcheck source=test/units/util.sh
. "$(dirname "$_COCO_DIR")/util.sh"
# shellcheck source=test/units/TEST-94-COCO/guest-test.sh
. "$_COCO_DIR/guest-test.sh"

# Ship the accumulated result records to the host's vsock listener (CID 2 = host). Best-effort: the
# aggregate verdict travels independently via the unit's exit status, so a vsock hiccup never masks a
# pass/fail — it only drops the per-check breakdown.
_coco_ship_results() {
    local records="${1:?}"
    [[ -n "${COCO_RESULT_PORT:-}" ]] || return 0
    socat -u "OPEN:$records,rdonly" "VSOCK-CONNECT:2:$COCO_RESULT_PORT" ||
        echo >&2 "WARNING: failed to ship coco results over vsock port $COCO_RESULT_PORT"
}

# Run the guest-side checks named by $COCO_TESTCASES (testcase_coco_* names without the prefix),
# record pass/fail per check, and ship the records. Each named check is something its boot scenario
# exists to prove, so an unknown name or an empty request fails the aggregate rather than letting the
# boot pass without having verified anything. Files a check drops into $COCO_ARTIFACTS_DIR ride the
# same connection as ARTIFACT= records, for the host to verify.
_coco_run_tests() {
    local testcases testcase rc result failed=0 records artifact
    records="$(mktemp)"
    COCO_ARTIFACTS_DIR="$(mktemp -d)"
    export COCO_ARTIFACTS_DIR

    read -ra testcases <<<"${COCO_TESTCASES:-}"
    if [[ "${#testcases[@]}" -eq 0 ]]; then
        echo >&2 "No coco testcases requested via \$COCO_TESTCASES"
        return 1
    fi
    testcases=("${testcases[@]/#/testcase_coco_}")

    for testcase in "${testcases[@]}"; do
        if ! declare -F "$testcase" >/dev/null; then
            echo >&2 "Requested coco testcase '$testcase' is not defined"
            printf 'ID=%s RESULT=missing\n' "$testcase" >>"$records"
            failed=1
            continue
        fi
        # Subshell so a testcase's RETURN trap can't fire twice (see run_testcases in test-control.sh).
        # Bash disables 'set -e' throughout a function called in a context that tests its exit status,
        # so '("$testcase") || rc=$?' would let a testcase run past its first failed assertion and
        # report only its last one. Reading $? from a standalone call avoids that context; the inner
        # 'set -e' re-arms what the surrounding 'set +e' turned off.
        set +e
        (set -e; "$testcase")
        rc=$?
        set -e
        if [[ "$rc" -eq 0 ]]; then
            result=pass
        else
            result=fail
            failed=1
        fi
        echo "coco check $testcase: $result (rc=$rc)"
        printf 'ID=%s RESULT=%s\n' "$testcase" "$result" >>"$records"
    done

    for artifact in "$COCO_ARTIFACTS_DIR"/*; do
        [[ -e "$artifact" ]] || continue
        printf 'ARTIFACT=%s DATA=%s\n' "$(basename "$artifact")" "$(base64 -w0 <"$artifact")" >>"$records"
    done

    _coco_ship_results "$records"
    return "$failed"
}

_coco_run_tests
