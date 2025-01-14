#!/bin/bash
# SPDX-License-Identifier: LGPL-2.1-or-later

set -eux
set -o pipefail

# Switch SELinux to permissive if possible, since the tests don't set proper contexts
setenforce 0 || true

echo "CPU and Memory information:"
lscpu
lsmem

echo "Clock source: $(cat /sys/devices/system/clocksource/clocksource0/current_clocksource)"

# Bump inotify limits so nspawn containers don't run out of inotify file descriptors.
sysctl fs.inotify.max_user_watches=65536
sysctl fs.inotify.max_user_instances=1024

# Allow running the integration tests downstream in dist-git with something like
# the following snippet which makes the dist-git sources available in $TMT_SOURCE_DIR:
#
# summary: systemd Fedora test suite
# discover:
#   how: fmf
#   dist-git-source: true
#   dist-git-install-builddeps: false
# prepare:
#   - name: systemd
#     how: install
#     exclude:
#       - systemd-standalone-.*
# execute:
#   how: tmt

shopt -s extglob

if [[ -n "${TMT_SOURCE_DIR:-}" ]]; then
    # Match either directories ending with branch names (e.g. systemd-fmf) or releases (e.g systemd-257.1).
    pushd "$TMT_SOURCE_DIR"/systemd-+([0-9a-z.~])/
elif [[ -n "${PACKIT_TARGET_URL:-}" ]]; then
    # Prepare systemd source tree
    git clone "$PACKIT_TARGET_URL" systemd --branch "$PACKIT_TARGET_BRANCH"
    pushd systemd

    # If we're running in a pull request job, merge the remote branch into the current main
    if [[ -n "${PACKIT_SOURCE_URL:-}" ]]; then
        git remote add pr "${PACKIT_SOURCE_URL:?}"
        git fetch pr "${PACKIT_SOURCE_BRANCH:?}"
        git merge "pr/$PACKIT_SOURCE_BRANCH"
    fi

    git log --oneline -5
else
    echo "Not running within packit or Fedora CI"
    exit 1
fi

# Now prepare mkosi, possibly at the same version required by the systemd repo
git clone https://github.com/systemd/mkosi
mkosi_hash="$(grep systemd/mkosi@ .github/workflows/mkosi.yml | sed "s|.*systemd/mkosi@||g")"
git -C mkosi checkout "$mkosi_hash"

export PATH="$PWD/mkosi/bin:$PATH"

# shellcheck source=/dev/null
. /etc/os-release || . /usr/lib/os-release

tee mkosi.local.conf <<EOF
[Distribution]
Release=${VERSION_ID:-rawhide}

[Build]
ToolsTreeDistribution=$ID
ToolsTreeRelease=${VERSION_ID:-rawhide}
EOF

if [[ -n "${TEST_SELINUX_CHECK_AVCS:-}" ]]; then
    tee --append mkosi.local.conf <<EOF
[Runtime]
KernelCommandLineExtra=systemd.setenv=TEST_SELINUX_CHECK_AVCS=$TEST_SELINUX_CHECK_AVCS
EOF
fi

if [[ -n "${TESTING_FARM_REQUEST_ID:-}" ]]; then
    tee --append mkosi.local.conf <<EOF
[Content]
SELinuxRelabel=yes

[Build]
ToolsTreeSandboxTrees=
        /etc/yum.repos.d/:/etc/yum.repos.d/
        /var/share/test-artifacts/:/var/share/test-artifacts/
SandboxTrees=
        /etc/yum.repos.d/:/etc/yum.repos.d/
        /var/share/test-artifacts/:/var/share/test-artifacts/
Environment=NO_BUILD=1
EOF

    cat /etc/dnf/dnf.conf
    cat /etc/yum.repos.d/*

    # Ensure packages built for this test have highest priority
    echo -e "\npriority=1" >> /etc/yum.repos.d/copr_build*

    # Disable mkosi's own repository logic
    touch /etc/yum.repos.d/mkosi.repo
fi

# TODO: drop once BTRFS regression is fixed in kernel 6.13
sed -i "s/Format=btrfs/Format=ext4/" mkosi.repart/10-root.conf

# If we don't have KVM, skip running in qemu, as it's too slow. But try to load the module first.
modprobe kvm || true
if [[ ! -e /dev/kvm ]]; then
    export TEST_NO_QEMU=1
fi

NPROC="$(nproc)"
if [[ "$NPROC" -ge 10 ]]; then
    export TEST_JOURNAL_USE_TMP=1
    NPROC="$((NPROC / 3))"
else
    NPROC="$((NPROC - 1))"
fi

# This test is only really useful if we're building with sanitizers and takes a long time, so let's skip it
# for now.
export TEST_SKIP="TEST-21-DFUZZER"

# Create missing mountpoint for mkosi sandbox.
mkdir -p /etc/pacman.d/gnupg

mkosi summary
mkosi -f sandbox true
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
    --num-processes "$NPROC" && EC=0 || EC=$?

[[ -d build/meson-logs ]] && find build/meson-logs -type f -exec mv {} "$TMT_TEST_DATA" \;
[[ -d build/test/journal ]] && find build/test/journal -type f -exec mv {} "$TMT_TEST_DATA" \;

popd

exit "$EC"
