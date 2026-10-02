# SPDX-License-Identifier: LGPL-2.1-or-later
# shellcheck shell=bash
# Every constant here is consumed by whichever side sources this file, never by this file itself.
# shellcheck disable=SC2034
#
# Fixtures for the confidential computing integration test (TEST-94-COCO). Shared by the host-side
# boot scenarios, which deliver these credentials over trusted and untrusted channels alike, and by
# the guest-side checks, which assert where each one ended up, so the two sides cannot drift apart.

if [[ "${BASH_SOURCE[0]}" -ef "$0" ]]; then
    echo >&2 "This file should not be executed directly"
    exit 1
fi

# Name of the guest self-check unit lib.sh injects.
COCO_GUEST_UNIT="coco-guest.service"

# Artifacts the guest checks export for host-side verification, by file name:
# written to $COCO_ARTIFACTS_DIR by the guest (see guest-test-runner.sh)
# collected into WORKDIR/artifacts on the host (see lib.sh)
COCO_ARTIFACT_SIGNED_REPORT="signed-report.seq"

# Credentials by channel
COCO_CRED_TRUSTED_ID="coco.trusted"
COCO_CRED_TRUSTED_VALUE="trusted-via-vmspawn"
COCO_CRED_CMDLINE_ID="coco.cmdline"
COCO_CRED_CMDLINE_VALUE="trusted-via-cmdline"
COCO_CRED_SMBIOS_ID="coco.hostile.smbios"
COCO_CRED_SMBIOS_VALUE="injected-via-smbios"
COCO_CRED_FWCFG_ID="coco.hostile.fwcfg"
COCO_CRED_FWCFG_VALUE="injected-via-fwcfg"
