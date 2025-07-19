#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

# shellcheck source=test/units/test-control.sh
. "$(dirname "$0")"/test-control.sh

bootctl status
SYSTEMD_LOG_LEVEL=debug systemd-analyze has-tpm2
SYSTEMD_LOG_LEVEL=debug /usr/lib/systemd/systemd-pcrlock is-supported

run_subtests

touch /testok
