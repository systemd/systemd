#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

# shellcheck source=test/units/test-control.sh
. "$(dirname "$0")"/test-control.sh

# Note: the signal shenanigans are necessary for the Upholds= tests
run_subtests_with_signals SIGUSR1 SIGUSR2 SIGRTMIN+1

touch /testok
