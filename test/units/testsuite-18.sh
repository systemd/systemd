#!/usr/bin/env bash
set -eux
set -o pipefail

systemd-run --wait -p FailureAction=poweroff true
systemd-run --wait -p SuccessAction=poweroff false && { echo 'unexpected success'; exit 1; }

if ! test -f /firstphase ; then
    echo OK >/firstphase
    systemd-run --wait -p SuccessAction=reboot true
else
    echo OK >/testok
    systemd-run --wait -p FailureAction=poweroff false
fi

sleep infinity
