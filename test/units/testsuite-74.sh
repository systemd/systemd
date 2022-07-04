#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

cat >/etc/systemd/system/tmp-tempb.mount <<EOF
[Mount]
What=tmpfs
Where=/tmp/tempb
Options=bind
EOF

mv /bin/mount /bin/mount.orig
cat >/bin/mount <<EOF
#!/bin/bash

sleep ".$RANDOM"
exec -- /bin/mount.orig "$@"
EOF
chmod +x /bin/mount

for ((i = 0; i < 50; i++)); do
        systemctl --no-block start tmp-tempb.mount
        sleep ".$RANDOM"
        systemctl daemon-reexec

        if [[ "$(systemctl is-failed tmp-tempb.mount)" == "failed" ]] || \
           journalctl -u tmp-tempb.mount -q --grep "but there is no mount"; then
                echo failed >/failed
                exit 1
        fi

        systemctl stop tmp-tempb.mount
done

mv -f /bin/mount.orig /bin/mount
echo OK >/testok
exit 0
