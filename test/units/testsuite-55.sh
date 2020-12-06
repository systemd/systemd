#!/bin/bash
set -ex
set -o pipefail

function has_tag_internal() {
    udevadm info /dev/null | sed -n '/E: '$1'=/ {s/E: '$1'=/:/; s/$/:/; p}' | grep -q ":$2:"
}

function has_tag() {
    has_tag_internal TAGS $1
}

function has_current_tag() {
    has_tag_internal CURRENT_TAGS $1
}

mkdir -p /run/udev/rules.d/

! test -f /run/udev/tags/added/c1:3 &&
    ! test -f /run/udev/tags/changed/c1:3 &&
    ! has_tag added &&
    ! has_current_tag added &&
    ! has_tag changed &&
    ! has_current_tag changed

cat > /run/udev/rules.d/50-testsuite.rules <<EOF
ACTION=="add", SUBSYSTEM=="mem", KERNEL=="null", TAG+="added"
ACTION=="change", SUBSYSTEM=="mem", KERNEL=="null", TAG+="changed"
EOF

udevadm control --reload
udevadm trigger -c add /dev/null

while : ; do
    test -f /run/udev/tags/added/c1:3 &&
        ! test -f /run/udev/tags/changed/c1:3 &&
        has_tag added &&
        has_current_tag added &&
        ! has_tag changed &&
        ! has_current_tag changed &&
        break

    sleep .5
done

udevadm control --reload
udevadm trigger -c change /dev/null

while : ; do
    test -f /run/udev/tags/added/c1:3 &&
        test -f /run/udev/tags/changed/c1:3 &&
        has_tag added &&
        ! has_current_tag added &&
        has_tag changed &&
        has_current_tag changed &&
        break

    sleep .5
done

udevadm control --reload
udevadm trigger -c add /dev/null

while : ; do
    test -f /run/udev/tags/added/c1:3 &&
        test -f /run/udev/tags/changed/c1:3 &&
        has_tag added &&
        has_current_tag added &&
        has_tag changed &&
        ! has_current_tag changed &&
        break

    sleep .5
done

echo OK > /testok

exit 0
