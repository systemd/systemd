#!/bin/bash
# -*- mode: shell-script; indent-tabs-mode: nil; sh-basic-offset: 4; -*-
# ex: ts=8 sw=4 sts=4 et filetype=sh
set -ex
set -o pipefail

systemd-run --wait -p FailureAction=poweroff true
! systemd-run --wait -p SuccessAction=poweroff false

if test -f /firstphase ; then
    echo OK > /firstphase
    systemd-run --wait -p SuccessAction=reboot true
else
    echo OK > /testok
    systemd-run --wait -p FailureAction=poweroff false
fi

sleep infinity
