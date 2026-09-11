# SPDX-License-Identifier: LGPL-2.1-or-later
# shellcheck shell=bash
#
# Guest-side checks for the confidential computing integration test (TEST-94-COCO). Sourced by
# guest-test-runner.sh inside the confidential guest; each testcase_coco_* function is one
# sub-subtest, and a boot scenario names the checks it requires via $COCO_TESTCASES.

if [[ "${BASH_SOURCE[0]}" -ef "$0" ]]; then
    echo >&2 "This file should not be executed directly"
    exit 1
fi

# shellcheck source=test/units/TEST-94-COCO/fixtures.sh
. "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")/fixtures.sh"

# Assert the guest observes the confidential-virtualization technology the host launched it with.
# COCO_TYPE is provided by the injected guest unit (Environment=, see lib.sh).
testcase_coco_detect_virt() {
    assert_eq "$(systemd-detect-virt --cvm)" "${COCO_TYPE:?}"
}

# Assert a credential handed to systemd-vmspawn --set-credential lands in the trusted bucket.
#
# SNP: creds should be delivered via the initrd cpio channel.
testcase_coco_creds_vmspawn() {
    assert_eq "$(systemd-creds --system cat "$COCO_CRED_TRUSTED_ID")" "$COCO_CRED_TRUSTED_VALUE"
    assert_not_in "$COCO_CRED_TRUSTED_ID" "$(</proc/cmdline)"
}

# Assert a credential passed on the kernel command line lands in the trusted bucket.
#
# Credentials passed on the cmdline should be accepted on every coco platform.
testcase_coco_creds_cmdline() {
    assert_in "systemd.set_credential=$COCO_CRED_CMDLINE_ID:$COCO_CRED_CMDLINE_VALUE" "$(</proc/cmdline)"
    assert_eq "$(systemd-creds --system cat "$COCO_CRED_CMDLINE_ID")" "$COCO_CRED_CMDLINE_VALUE"
}
