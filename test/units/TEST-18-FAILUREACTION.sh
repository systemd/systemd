#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

systemd-run --wait -p FailureAction=poweroff true
(! systemd-run --wait -p SuccessAction=poweroff false)

if ! test -f /firstphase ; then
    echo OK >/firstphase
    systemd-run --wait -p SuccessAction=reboot true
else
    echo OK >/testok
    systemd-run --wait -p FailureAction=exit -p FailureActionExitStatus=123 false
fi

sleep infinity
