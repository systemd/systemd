#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh

at_exit() {
    set +e
    systemctl stop test-tags.service test-tags-transient.service 2>/dev/null
    rm -f /run/systemd/system/test-tags.service
    systemctl daemon-reload
}

trap at_exit EXIT

tag_xattr_value() {
    local cgroup tags tag
    cgroup="/sys/fs/cgroup$(systemctl show -P ControlGroup "$1")"
    tags="$(getfattr --only-values --absolute-names -n "user.tags" "$cgroup" | tr '\0' '\n')"

    while IFS= read -r tag; do
        if [[ "$tag" == "$2="* ]]; then
            printf '%s\n' "${tag#*=}"
            return 0;
        fi
    done <<< "$tags"
}

validate_tags() {
    local unit="$1"
    local tags status

    tags="$(systemctl show -P Tags "$unit")"
    assert_in "company.foobar" "$tags"
    assert_in "company.backend.trigger-reason=api-event-123456789" "$tags"
    assert_in "app.tier=db" "$tags"

    status="$(systemctl status "$unit")"
    assert_in "Tags:" "$status"
    assert_in "company.foobar" "$status"
    assert_in "app.tier=db" "$status"

    tag_xattr_value "$unit" "company.foobar" >/dev/null
    assert_eq "$(tag_xattr_value "$unit" "company.foobar")" ""
    assert_eq "$(tag_xattr_value "$unit" "company.backend.trigger-reason")" "api-event-123456789"
    assert_eq "$(tag_xattr_value "$unit" "app.tier")" "db"
}

mkdir -p /run/systemd/system
cat >/run/systemd/system/test-tags.service <<EOF
[Unit]
Tags=company.foobar company.backend.trigger-reason=api-event-123456789 app.tier=db

[Service]
ExecStart=sleep infinity
EOF
systemctl daemon-reload
systemctl start test-tags.service
validate_tags test-tags.service

systemd-run -u test-tags-transient.service \
            -p "Tags=company.foobar company.backend.trigger-reason=api-event-123456789 app.tier=db" \
            sleep infinity
validate_tags test-tags-transient.service
