#!/bin/bash
# -*- mode: shell-script; indent-tabs-mode: nil; sh-basic-offset: 4; -*-
# ex: ts=8 sw=4 sts=4 et filetype=sh
set -ex
set -o pipefail

mkdir -p /run/udev/rules.d/

! test -f /run/udev/tags/added/c1:3 &&
    ! test -f /run/udev/tags/changed/c1:3 &&
    udevadm info /dev/null | grep -q -v 'E: TAGS=.*:added:.*' &&
    udevadm info /dev/null | grep -q -v 'E: CURRENT_TAGS=.*:added:.*' &&
    udevadm info /dev/null | grep -q -v 'E: TAGS=.*:changed:.*' &&
    udevadm info /dev/null | grep -q -v 'E: CURRENT_TAGS=.*:changed:.*'

cat > /run/udev/rules.d/50-testsuite.rules <<EOF
ACTION=="add", SUBSYSTEM=="mem", KERNEL=="null", TAG+="added"
ACTION=="change", SUBSYSTEM=="mem", KERNEL=="null", TAG+="changed"
EOF

udevadm control --reload
udevadm trigger -c add /dev/null

while : ; do
    test -f /run/udev/tags/added/c1:3 &&
        ! test -f /run/udev/tags/changed/c1:3 &&
        udevadm info /dev/null | grep -q 'E: TAGS=.*:added:.*' &&
        udevadm info /dev/null | grep -q 'E: CURRENT_TAGS=.*:added:.*' &&
        udevadm info /dev/null | grep -q -v 'E: TAGS=.*:changed:.*' &&
        udevadm info /dev/null | grep -q -v 'E: CURRENT_TAGS=.*:changed:.*' &&
        break

    sleep .5
done

udevadm control --reload
udevadm trigger -c change /dev/null

while : ; do
    test -f /run/udev/tags/added/c1:3 &&
        test -f /run/udev/tags/changed/c1:3 &&
        udevadm info /dev/null | grep -q 'E: TAGS=.*:added:.*' &&
        udevadm info /dev/null | grep -q -v 'E: CURRENT_TAGS=.*:added:.*' &&
        udevadm info /dev/null | grep -q 'E: TAGS=.*:changed:.*' &&
        udevadm info /dev/null | grep -q 'E: CURRENT_TAGS=.*:changed:.*' &&
        break

    sleep .5
done

udevadm control --reload
udevadm trigger -c add /dev/null

while : ; do
    test -f /run/udev/tags/added/c1:3 &&
        test -f /run/udev/tags/changed/c1:3 &&
        udevadm info /dev/null | grep -q 'E: TAGS=.*:added:.*' &&
        udevadm info /dev/null | grep -q 'E: CURRENT_TAGS=.*:added:.*' &&
        udevadm info /dev/null | grep -q 'E: TAGS=.*:changed:.*' &&
        udevadm info /dev/null | grep -q -v 'E: CURRENT_TAGS=.*:changed:.*' &&
        break

    sleep .5
done

echo OK > /testok

exit 0
