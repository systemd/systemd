#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# shellcheck disable=SC2016
set -eux
set -o pipefail

systemd-analyze log-level debug

test_quotas() {

    local directory="$1"
    local exec_directory_directive="$2"
    local exec_quota_directive="$3"
    local mountpoint="/datadrive"

    dev_num=$(lsblk | grep "498M" | awk '{print $1}' | sed 's/[^a-zA-Z0-9]*//g')

    if ! tune2fs -Q prjquota "/dev/${dev_num}"; then
        return
    fi
    mkdir -p "${mountpoint}"
    mount "/dev/${dev_num}" "${mountpoint}"

    mv /var/lib/ "${mountpoint}"
    rm -rf /var/lib/ && ln -s "${mountpoint}/lib/" /var/

    rm -rf "${directory}/quotadir"

    cat >/run/systemd/system/testservice-07-check-quotas.service <<EOF
[Unit]
Description=Check quotas with ExecDirectory

[Service]
# Relevant only for sanitizer runs
EnvironmentFile=-/usr/lib/systemd/systemd-asan-env
Type=oneshot

MountAPIVFS=yes
DynamicUser=yes
PrivateUsers=yes
TemporaryFileSystem=/run /var/opt /var/lib /vol
${exec_directory_directive}
${exec_quota_directive}
ExecStart=bash -c ' \
    set -eux; \
    set -o pipefail; \
    touch ${directory}/quotadir/testfile; \
'
EOF

    systemctl daemon-reload
    systemctl start testservice-07-check-quotas.service

    proj_id=$(lsattr -p "${directory}" | grep "quotadir" | awk '{print $1}')
    [[ $proj_id -gt 0 ]]

    block_limit=$(repquota -P "${mountpoint}" | grep -E "#$proj_id " | awk '{print $5}')
    inode_limit=$(repquota -P "${mountpoint}" | grep -E "#$proj_id " | awk '{print $8}')
    [[ $block_limit -gt 0 ]]
    [[ $inode_limit -gt 0 ]]

    # Test exceed limit
    rm -rf "${directory}/quotadir"

    cat >/run/systemd/system/testservice-07-check-quotas.service <<EOF
[Unit]
Description=Check quotas with ExecDirectory

[Service]
# Relevant only for sanitizer runs
EnvironmentFile=-/usr/lib/systemd/systemd-asan-env
Type=oneshot

MountAPIVFS=yes
DynamicUser=yes
PrivateUsers=yes
TemporaryFileSystem=/run /var/opt /var/lib /vol
${exec_directory_directive}
${exec_quota_directive}
ExecStart=bash -c ' \
    set -eux; \
    set -o pipefail; \
    (! fallocate -l 10000G ${directory}/quotadir/largefile); \
'
EOF

    systemctl daemon-reload
    systemctl start testservice-07-check-quotas.service
}

test_quotas "/var/lib/private" "StateDirectory=quotadir" "StateDirectoryQuota=1%"

systemd-analyze log-level info

touch /testok
