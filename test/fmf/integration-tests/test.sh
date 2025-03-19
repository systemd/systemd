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

# Bump inotify limits if we can so nspawn containers don't run out of inotify file descriptors.
sysctl fs.inotify.max_user_watches=65536 || true
sysctl fs.inotify.max_user_instances=1024 || true

if [[ -n "${KOJI_TASK_ID:-}" ]]; then
    koji download-task --noprogress --arch="src,noarch,$(rpm --eval '%{_arch}')" "$KOJI_TASK_ID"
elif [[ -n "${CBS_TASK_ID:-}" ]]; then
    cbs download-task --noprogress --arch="src,noarch,$(rpm --eval '%{_arch}')" "$CBS_TASK_ID"
elif [[ -n "${PACKIT_SRPM_URL:-}" ]]; then
    COPR_BUILD_ID="$(basename "$(dirname "$PACKIT_SRPM_URL")")"
    COPR_CHROOT="$(basename "$(dirname "$(dirname "$PACKIT_BUILD_LOG_URL")")")"
    copr download-build --rpms --chroot "$COPR_CHROOT" "$COPR_BUILD_ID"
    mv "$COPR_CHROOT"/* .
else
    echo "Not running within packit and no CBS/koji task ID provided"
    exit 1
fi

mkdir systemd
rpm2cpio ./systemd-*.src.rpm | cpio --to-stdout --extract './systemd-*.tar.gz' | tar xz --strip-components=1 -C systemd
pushd systemd

# Now prepare mkosi at the same version required by the systemd repo.
git clone https://github.com/systemd/mkosi
mkosi_hash="$(grep systemd/mkosi@ .github/workflows/mkosi.yml | sed "s|.*systemd/mkosi@||g")"
git -C mkosi checkout "$mkosi_hash"

export PATH="$PWD/mkosi/bin:$PATH"

# shellcheck source=/dev/null
. /etc/os-release || . /usr/lib/os-release

tee mkosi.local.conf <<EOF
[Distribution]
Distribution=${MKOSI_DISTRIBUTION:-$ID}
Release=${MKOSI_RELEASE:-${VERSION_ID:-rawhide}}
PackageDirectories=.

[Content]
SELinuxRelabel=yes

[Build]
ToolsTreeDistribution=${MKOSI_DISTRIBUTION:-$ID}
ToolsTreeRelease=${MKOSI_RELEASE:-${VERSION_ID:-rawhide}}
Environment=NO_BUILD=1
WithTests=yes
EOF

if [[ -n "${TEST_SELINUX_CHECK_AVCS:-}" ]]; then
    tee --append mkosi.local.conf <<EOF
[Runtime]
KernelCommandLineExtra=systemd.setenv=TEST_SELINUX_CHECK_AVCS=$TEST_SELINUX_CHECK_AVCS
EOF
fi

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

mkosi summary
mkosi -f sandbox -- true
mkosi -f sandbox -- meson setup --buildtype=debugoptimized -Dintegration-tests=true build
mkosi genkey
mkosi -f sandbox -- meson compile -C build mkosi
mkosi -f sandbox -- \
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
