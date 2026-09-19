#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# shellcheck disable=SC2016
set -eux
set -o pipefail

systemd-run -p PrivateUsers=yes --wait bash -c 'test "$(cat /proc/self/uid_map)" == "         0          0          1"'
systemd-run -p PrivateUsers=yes --wait bash -c 'test "$(cat /proc/self/gid_map)" == "         0          0          1"'
systemd-run -p PrivateUsersEx=yes --wait bash -c 'test "$(cat /proc/self/setgroups)" == "deny"'
systemd-run -p PrivateUsersEx=self --wait bash -c 'test "$(cat /proc/self/uid_map)" == "         0          0          1"'
systemd-run -p PrivateUsersEx=self --wait bash -c 'test "$(cat /proc/self/gid_map)" == "         0          0          1"'
systemd-run -p PrivateUsersEx=self --wait bash -c 'test "$(cat /proc/self/setgroups)" == "deny"'
systemd-run -p PrivateUsersEx=identity --wait bash -c 'test "$(cat /proc/self/uid_map)" == "         0          0      65536"'
systemd-run -p PrivateUsersEx=identity --wait bash -c 'test "$(cat /proc/self/gid_map)" == "         0          0      65536"'
systemd-run -p PrivateUsersEx=full --wait bash -c 'test "$(cat /proc/self/uid_map)" == "         0          0 4294967295"'
systemd-run -p PrivateUsersEx=full --wait bash -c 'test "$(cat /proc/self/gid_map)" == "         0          0 4294967295"'
systemd-run -p PrivateUsersEx=full --wait bash -c 'test "$(cat /proc/self/setgroups)" == "allow"'

# Regression test for https://github.com/systemd/systemd/issues/41994. Verify that supplementary GIDs
# are mapped for both dynamic and static users and that duplicate mappings are suppressed.
if ! command -v groupadd >/dev/null ||
    ! command -v useradd >/dev/null ||
    ! command -v systemd-sysusers >/dev/null; then
    echo "groupadd, useradd, or systemd-sysusers is not installed, skipping the supplementary group checks."
    exit 0
fi

test_id="test-07-pu-$$"
test_user="$test_id"
test_unit="$test_id.service"
test_helper="/run/$test_id.sh"
groups=()
created_groups=()
created_user=false
created_unit=false

cleanup() {
    set +e
    if $created_unit; then
        systemctl stop "$test_unit"
        rm -f "/run/systemd/system/$test_unit" "$test_helper"
        systemctl daemon-reload
    fi
    if $created_user; then
        userdel "$test_user"
    fi
    for group in "${created_groups[@]}"; do
        groupdel "$group"
    done
}
trap cleanup EXIT

if getent passwd "$test_user" >/dev/null; then
    echo "Test user $test_user already exists, refusing to modify it."
    exit 1
fi

for i in {0..3}; do
    group="$test_id-$i"
    if getent group "$group" >/dev/null; then
        echo "Test group $group already exists, refusing to modify it."
        exit 1
    fi

    groupadd "$group"
    groups+=("$group")
    created_groups+=("$group")
done

gids=()
for group in "${groups[@]}"; do
    gids+=("$(getent group "$group" | cut -d: -f3)")
done

verify_groups='count_gid_map_extents() {
    awk -v gid="$1" '\''$1 == gid && $2 == gid && $3 == 1 { n++ } END { print n + 0 }'\'' /proc/self/gid_map
}
test "$(count_gid_map_extents 0)" -eq 1
primary_gid="$(id -g)"
test "$(count_gid_map_extents "$primary_gid")" -eq 1
for gid; do
    test "$(id -G | tr " " "\n" | grep -cx "$gid")" -eq 1
    test "$(count_gid_map_extents "$gid")" -eq 1
done'

systemd-run --wait \
    -p EnvironmentFile=-/usr/lib/systemd/systemd-asan-env \
    -p PrivateUsers=yes \
    -p DynamicUser=yes \
    -p SupplementaryGroups="${groups[0]} ${groups[1]} ${groups[1]} ${groups[2]} ${groups[3]}" \
    bash -euxc "$verify_groups" -- "${gids[@]}"

# Exercise gid_map truncation with more entries than the kernel permits. The GIDs must themselves be
# mapped in the current user namespace, otherwise setgroups() cannot install them before the child namespace
# is created. Create the groups in one systemd-sysusers invocation so they can also be resolved through NSS.
truncation_gids=()
while read -r inside _ length; do
    start=$((inside > 10000 ? inside : 10000))
    end=$((inside + length))
    for ((gid = start; gid < end && ${#truncation_gids[@]} < 400; gid++)); do
        getent group "$gid" >/dev/null || truncation_gids+=("$gid")
    done
    ((${#truncation_gids[@]} >= 400)) && break
done </proc/self/gid_map

if ((${#truncation_gids[@]} >= 400)); then
    truncation_groups=()
    sysusers_args=()
    for i in "${!truncation_gids[@]}"; do
        printf -v group "%s-t%03d" "$test_id" "$i"
        if getent group "$group" >/dev/null; then
            echo "Test group $group already exists, refusing to modify it."
            exit 1
        fi

        truncation_groups+=("$group")
        sysusers_args+=("g $group ${truncation_gids[$i]}")
    done
    created_groups+=("${truncation_groups[@]}")
    systemd-sysusers --inline "${sysusers_args[@]}"

    systemd-run --wait \
        -p EnvironmentFile=-/usr/lib/systemd/systemd-asan-env \
        -p PrivateUsers=yes \
        -p DynamicUser=yes \
        -p SupplementaryGroups="${truncation_groups[*]}" \
        bash -euxc '
            first="$1"
            last="$2"
            n_extents="$(wc -l </proc/self/gid_map)"
            awk -v gid="$first" \
                '\''$1 == gid && $2 == gid && $3 == 1 { found = 1 } END { exit !found }'\'' /proc/self/gid_map
            ! awk -v gid="$last" \
                '\''$1 == gid && $2 == gid && $3 == 1 { found = 1 } END { exit !found }'\'' /proc/self/gid_map
            test "$(id -G | tr " " "\n" | grep -cx 65534)" -ge 1
            test "$n_extents" -gt 2
            test "$n_extents" -lt 402
        ' -- "${truncation_gids[0]}" "${truncation_gids[-1]}"
else
    echo "Current user namespace has fewer than 400 unused mapped GIDs, skipping truncation check."
fi

useradd --no-create-home --gid "${groups[0]}" --groups "${groups[1]}" "$test_user"
created_user=true

systemd-run --wait \
    -p EnvironmentFile=-/usr/lib/systemd/systemd-asan-env \
    -p PrivateUsers=yes \
    -p User="$test_user" \
    -p Group="${groups[0]}" \
    -p SupplementaryGroups="root ${groups[0]} ${groups[2]} ${groups[2]} ${groups[3]}" \
    bash -euxc "$verify_groups" -- "${gids[@]}"

# Also cover supplementary groups obtained solely from the user database.
systemd-run --wait \
    -p EnvironmentFile=-/usr/lib/systemd/systemd-asan-env \
    -p PrivateUsers=yes \
    -p User="$test_user" \
    -p Group="${groups[0]}" \
    bash -euxc "$verify_groups" -- "${gids[0]}" "${gids[1]}"

# The ! command prefix skips the final UID/GID switch. Map only the effective supplementary credentials
# retained by that path, rather than groups that would have been applied by SupplementaryGroups=.
created_unit=true
cat >"$test_helper" <<'EOF'
#!/usr/bin/env bash
set -eux
count_gid_map_extents() {
    awk -v gid="$1" '$1 == gid && $2 == gid && $3 == 1 { n++ } END { print n + 0 }' /proc/self/gid_map
}
test "$(id -u)" -eq 0
for gid; do
    test "$(id -G | tr " " "\n" | grep -cx "$gid")" -eq 1
    test "$(count_gid_map_extents "$gid")" -eq 1
done
EOF
chmod +x "$test_helper"
cat >"/run/systemd/system/$test_unit" <<EOF
[Service]
Type=oneshot
EnvironmentFile=-/usr/lib/systemd/systemd-asan-env
PrivateUsers=yes
User=$test_user
Group=${groups[0]}
ExecStart=!$test_helper ${gids[0]} ${gids[1]}
EOF
systemctl daemon-reload
systemctl start "$test_unit"
