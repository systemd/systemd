#!/bin/bash
set -ex
set -o pipefail

mkdir -p /run/udev/rules.d/

cat > /run/udev/rules.d/50-testsuite.rules <<EOF
SUBSYSTEM=="mem", KERNEL=="null", OPTIONS="log_level=debug"
ACTION=="add", SUBSYSTEM=="mem", KERNEL=="null", IMPORT{program}="/bin/echo -e HOGE=aa\\\\x20\\\\x20\\\\x20bb\nFOO=\\\\x20aaa\\\\x20\n\n\n"
EOF

udevadm control --reload
udevadm trigger -c add /dev/null

while : ; do
    test -f /run/udev/data/c1:3 &&
        udevadm info /dev/null | grep -q 'E: HOGE=aa\\x20\\x20\\x20bb' &&
        udevadm info /dev/null | grep -q 'E: FOO=\\x20aaa\\x20' &&
        break

    sleep .5
done

exit 0
