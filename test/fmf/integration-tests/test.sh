#!/bin/bash
# SPDX-License-Identifier: LGPL-2.1-or-later

set -eux
set -o pipefail

# Switch SELinux to permissive, since the tests don't set proper contexts
setenforce 0

# Prepare systemd source tree
git clone "$PACKIT_TARGET_URL" systemd
pushd systemd
# If we're running in a pull request job, merge the remote branch into the current main
if [[ -n "${PACKIT_SOURCE_URL:-}" ]]; then
    git remote add pr "${PACKIT_SOURCE_URL:?}"
    git fetch pr "${PACKIT_SOURCE_BRANCH:?}"
    git merge "pr/$PACKIT_SOURCE_BRANCH"
fi
git log --oneline -5
popd

# Now prepare mkosi, possibly at the same version required by the systemd repo
git clone https://github.com/systemd/mkosi
# If we have it, pin the mkosi version to the same one used by Github Actions, to ensure consistency
if [ -f .github/workflows/mkosi.yml ]; then
    mkosi_hash="$(grep systemd/mkosi@ .github/workflows/mkosi.yml | sed "s|.*systemd/mkosi@||g")"
    git -C mkosi checkout "$mkosi_hash"
fi

export PATH="$PWD/mkosi/bin:$PATH"

pushd systemd

# shellcheck source=/dev/null
. /etc/os-release || . /usr/lib/os-release

tee mkosi.local.conf <<EOF
[Distribution]
Release=${VERSION_ID:-rawhide}

[Build]
ToolsTreeDistribution=$ID
ToolsTreeRelease=${VERSION_ID:-rawhide}
ToolsTreeSandboxTrees=
        /etc/yum.repos.d/:/etc/yum.repos.d/
        /var/share/test-artifacts/:/var/share/test-artifacts/
SandboxTrees=
        /etc/yum.repos.d/:/etc/yum.repos.d/
        /var/share/test-artifacts/:/var/share/test-artifacts/
Environment=NO_BUILD=1
EOF

# Ensure packages built for this test have highest priority
echo -e "\npriority=1" >> /etc/yum.repos.d/copr_build*

# Disable mkosi's own repository logic
touch /etc/yum.repos.d/mkosi.repo

# TODO: drop once BTRFS regression is fixed in kernel 6.13
sed -i "s/Format=btrfs/Format=ext4/" mkosi.repart/10-root.conf

# If we don't have KVM, skip running in qemu, as it's too slow. But try to load the module first.
modprobe kvm || true
if [[ ! -e /dev/kvm ]]; then
    export TEST_NO_QEMU=1
fi

# Create missing mountpoint for mkosi sandbox.
mkdir -p /etc/pacman.d/gnupg

mkosi summary
mkosi -f sandbox meson setup --buildtype=debugoptimized -Dintegration-tests=true build
mkosi genkey
mkosi -f sandbox meson compile -C build mkosi
mkosi -f sandbox \
    meson test \
    -C build \
    --no-rebuild \
    --suite integration-tests \
    --print-errorlogs \
    --no-stdsplit \
    --num-processes "$(($(nproc) - 1))"

popd
