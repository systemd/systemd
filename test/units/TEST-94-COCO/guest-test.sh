# SPDX-License-Identifier: LGPL-2.1-or-later
# shellcheck shell=bash
#
# Guest-side checks for the confidential computing integration test (TEST-94-COCO). Sourced by
# guest-test-runner.sh inside the confidential guest; each testcase_coco_* function is one
# sub-subtest. The upcoming credential-trust checks land here as further functions.

if [[ "${BASH_SOURCE[0]}" -ef "$0" ]]; then
    echo >&2 "This file should not be executed directly"
    exit 1
fi

# Assert the guest observes the confidential-virtualization technology the host launched it with.
# COCO_TYPE is provided by the injected guest unit (Environment=, see lib.sh).
testcase_coco_detect_virt() {
    assert_eq "$(systemd-detect-virt --cvm)" "${COCO_TYPE:?}"
}
