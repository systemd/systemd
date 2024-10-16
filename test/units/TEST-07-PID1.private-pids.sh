#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# shellcheck disable=SC2016
set -eux
set -o pipefail

# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh

systemd-run -p PrivatePIDs=yes --expand-environment=no --wait --pipe bash -c 'test $$ == 1'

systemd-run \
    -p PrivatePIDs=yes  \
    -p RootDirectory=/usr/share/TEST-13-NSPAWN-container-template \
    -p MountAPIVFS=yes \
    -p ProcSubset=pid \
    -p BindReadOnlyPaths=/usr/share \
    -p NoNewPrivileges=yes \
    -p ProtectSystem=strict \
    -p User=testuser\
    -p Group=testuser \
    -p RuntimeDirectory=abc \
    -p StateDirectory=qed \
    -p InaccessiblePaths=/usr/include \
    -p TemporaryFileSystem=/home \
    -p PrivateTmp=yes \
    -p PrivateDevices=yes \
    -p PrivateNetwork=yes \
    -p PrivateUsersEx=self \
    -p PrivateIPC=yes \
    -p ProtectHostname=yes \
    -p ProtectClock=yes \
    -p ProtectKernelTunables=yes \
    -p ProtectKernelModules=yes \
    -p ProtectKernelLogs=yes \
    -p ProtectControlGroups=yes \
    -p LockPersonality=yes \
    -p Environment=ABC=QED \
    --wait \
    --pipe \
    true

# systemd-run -p PrivatePIDs=yes -p RootImage=/usr/share/minimal_0.raw --wait --pipe true
# systemd-run -p PrivatePIDs=yes -p RootImage=/usr/share/minimal_0.raw --wait --pipe true
# systemd-run -p PrivatePIDs=yes -p RootDirectory=/usr/share/TEST-13-NSPAWN-container-template  --wait --pipe true
