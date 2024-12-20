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

    chmod -R o+rX "$TMT_TEST_DATA"

    rm -rf "$WORKDIR"
}

# Workaround for https://gitlab.com/testing-farm/oculus/-/issues/19
# shellcheck disable=SC2064
trap cleanup EXIT

# Switch SELinux to permissive, since the tests don't set proper contexts
setenforce 0

# Prepare systemd source tree
if [[ -n "${PACKIT_TARGET_URL:-}" ]]; then
    # Install systemd's build dependencies, as some of the integration tests setup stuff
    # requires pkg-config files
    git clone "$PACKIT_TARGET_URL" systemd
    cd systemd
    git checkout "$PACKIT_TARGET_BRANCH"
    # If we're running in a pull request job, merge the remote branch into the current main
    if [[ -n "${PACKIT_SOURCE_URL:-}" ]]; then
        git remote add pr "${PACKIT_SOURCE_URL:?}"
        git fetch pr "${PACKIT_SOURCE_BRANCH:?}"
        git merge "pr/$PACKIT_SOURCE_BRANCH"
    fi
    git log --oneline -5

    # Now prepare mkosi, possibly at the same version required by the systemd repo
    mkosi_tree="${PWD}/../mkosi"
    git clone https://github.com/systemd/mkosi.git "$mkosi_tree"
    # If we have it, pin the mkosi version to the same one used by Github Actions, to ensure consistency
    if [ -f .github/workflows/mkosi.yml ]; then
        mkosi_hash="$(grep systemd/mkosi@ .github/workflows/mkosi.yml | sed "s|.*systemd/mkosi@||g")"
        git -C "$mkosi_tree" checkout "$mkosi_hash"
    fi
    export PATH="${mkosi_tree}/bin:$PATH"
else
    # If we're running outside of Packit, download SRPM for the currently installed build
    if ! dnf download --source "$(rpm -q systemd)"; then
        # If the build is recent enough it might not be on the mirrors yet, so try koji as well
        koji download-build --arch=src "$(rpm -q systemd --qf "%{sourcerpm}")"
    fi
    dnf install --allowerasing -y mkosi
    rpmbuild --nodeps --define="_topdir $PWD" -rp ./systemd-*.src.rpm
    # Little hack to get to the correct directory without having to figure out
    # the exact name
    cd BUILD/*/test/../
fi

. /etc/os-release || . /usr/lib/os-release

tee mkosi.local.conf <<EOF
[Output]
Format=disk

[Distribution]
Release=${VERSION_ID:-rawhide}

[Build]
SandboxTrees=/etc/yum.repos.d/:/etc/yum.repos.d/
SandboxTrees=/var/share/test-artifacts/:/var/share/test-artifacts/
Environment=NO_BUILD=1 ARTIFACT_DIRECTORY="${TMT_TEST_DATA:?}" TEST_SAVE_JOURNAL=fail TEST_SHOW_JOURNAL=warning
Incremental=no

[Host]
RuntimeBuildSources=no
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
    export TEST_NO_KVM=1
    export TEST_NO_QEMU=1
fi

# Skip TEST-64-UDEV-STORAGE for now, as it takes a really long time without KVM
# FIXME: screen 5.0.0 is FUBAR and break this test, re-enable once the issue is fixed
# See: https://bugzilla.redhat.com/show_bug.cgi?id=2309284
export TEST_SKIP="TEST-64-UDEV-STORAGE TEST-69-SHUTDOWN"
export ARTIFACT_DIRECTORY="${TMT_TEST_DATA:?}"
export SPLIT_TEST_LOGS=1
export TEST_SAVE_JOURNAL=fail
export TEST_SHOW_JOURNAL=warning
export NO_BUILD=1
export QEMU_TIMEOUT=1800
export NSPAWN_TIMEOUT=1200
export SYSTEMD_INTEGRATION_TESTS=1

mkosi summary
meson setup build -Dintegration-tests=true -Dtests=true
mkosi --debug genkey
cp mkosi.key mkosi.crt build
meson compile -C build mkosi
meson test -C build -v --no-rebuild --suite integration-tests --print-errorlogs --no-stdsplit

popd
