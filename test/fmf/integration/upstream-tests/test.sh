#!/bin/bash
# SPDX-License-Identifier: LGPL-2.1-or-later

set -eux
set -o pipefail

WORKDIR="$(mktemp --directory --tmpdir=/var/tmp)"
pushd "$WORKDIR"

cleanup () {
    if [ -f "${WORKDIR}/systemd/build/meson-logs/testlog.txt" ]; then
        cp "${WORKDIR}/systemd/build/meson-logs/testlog.txt" "$TMT_TEST_DATA"
    fi
    if [ -d "${WORKDIR}/systemd/build/test/journal" ]; then
        cp -r "${WORKDIR}/systemd/build/test/journal" "$TMT_TEST_DATA"
    fi

    rm -rf "$WORKDIR"
}

# Workaround for https://gitlab.com/testing-farm/oculus/-/issues/19
# shellcheck disable=SC2064
trap cleanup EXIT

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

. /etc/os-release || . /usr/lib/os-release

tee mkosi.local.conf <<EOF
[Output]
Format=disk

[Distribution]
Release=${VERSION_ID:-rawhide}

[Build]
SandboxTrees=/etc/yum.repos.d/:/etc/yum.repos.d/
SandboxTrees=/var/share/test-artifacts/:/var/share/test-artifacts/
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
if [ ! -e /dev/kvm ]; then
    export TEST_NO_QEMU=1
fi

export TEST_SAVE_JOURNAL=fail

mkosi summary
meson setup build -Dintegration-tests=true
mkosi genkey
meson compile -C build mkosi
meson test -C build -v --no-rebuild --suite integration-tests --print-errorlogs --no-stdsplit

popd
