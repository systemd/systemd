#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# Runs inside the confidential guest launched by TEST-94-COCO.sh. Runs each guest-side check
# (testcase_coco_* from guest-test.sh), ships a per-check result record to the host over the vsock
# result socket, and lets the injected unit's SuccessAction/FailureAction relay the aggregate verdict
# to the host via vmspawn's exit status.
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

# Run every testcase_coco_* (optionally filtered by $TEST_MATCH_TESTCASE), record pass/skip/fail per
# check, ship the records, and return non-zero if any check failed.
_coco_run_tests() {
    local testcases testcase rc result failed=0 matched=0 records
    records="$(mktemp)"

    mapfile -t testcases < <(declare -F | awk '$3 ~ /^testcase_coco_/ { print $3 }')
    if [[ "${#testcases[@]}" -eq 0 ]]; then
        echo >&2 "No coco testcases found"
        return 1
    fi

    for testcase in "${testcases[@]}"; do
        if [[ -n "${TEST_MATCH_TESTCASE:-}" ]] && ! [[ "$testcase" =~ $TEST_MATCH_TESTCASE ]]; then
            continue
        fi
        matched=$((matched + 1))
        # Subshell so a testcase's RETURN trap can't fire twice (see run_testcases in test-control.sh).
        # Bash disables 'set -e' throughout a function called in a context that tests its exit status,
        # so '("$testcase") || rc=$?' would let a testcase run past its first failed assertion and
        # report only its last one. Reading $? from a standalone call avoids that context; the inner
        # 'set -e' re-arms what the surrounding 'set +e' turned off.
        set +e
        (set -e; "$testcase")
        rc=$?
        set -e
        case "$rc" in
            0)  result=pass ;;
            77) result=skip ;;
            *)  result=fail; failed=1 ;;
        esac
        echo "coco check $testcase: $result (rc=$rc)"
        printf 'ID=%s RESULT=%s\n' "$testcase" "$result" >>"$records"
    done

    if [[ "$matched" -eq 0 ]]; then
        echo >&2 "No coco testcases matched '${TEST_MATCH_TESTCASE:-}'"
        return 1
    fi

    _coco_ship_results "$records"
    return "$failed"
}

_coco_run_tests
