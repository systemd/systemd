#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

# shellcheck source=test/units/test-control.sh
. "$(dirname "$0")"/test-control.sh

# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh

# Check that our disks are setup as expected
test "$(findmnt -n -o FSTYPE /)" = tmpfs
test "$(findmnt -n -o FSTYPE /usr)" = erofs

# Build sysext
extension=/run/extensions/repro
mkdir -p "$extension/usr/lib/extension-release.d"
cat >"$extension/usr/lib/extension-release.d/extension-release.repro" <<EOF
ID=_any
ARCHITECTURE=_any
EOF

systemctl stop boot.automount boot.mount || :
systemctl daemon-reload
test "$(systemctl show --property=LoadState --value boot.mount)" = loaded

systemd-sysext merge --no-reload
test "$(stat --file-system --format=%T /usr)" = overlayfs
test -s /usr/.systemd-sysext/backing

systemctl daemon-reload
test "$(systemctl show --property=LoadState --value boot.mount)" = loaded

touch /testok
