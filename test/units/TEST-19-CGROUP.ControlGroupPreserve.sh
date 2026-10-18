#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

# Test that ControlGroupPreserve= keeps the cgroup of a unit when it goes down, so that memory charged to it,
# e.g. memory backing stored file descriptors, stays accounted to the unit.

# shellcheck source=test/units/test-control.sh
. "$(dirname "$0")"/test-control.sh
# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh

if ! grep -qw memory /sys/fs/cgroup/cgroup.controllers; then
    echo "Memory controller not available, skipping."
    exit 77
fi

UNIT=test19preserve.service
SLICE=test19preserve.slice
OTHER_SLICE=test19preserve-other.slice
CGROUP=/sys/fs/cgroup/$SLICE/$UNIT
PAYLOAD=/run/test19preserve.sh
SIZE_MB=64

cleanup_unit() {
    local unit

    for unit in "$UNIT" "$SLICE"; do
        systemctl stop "$unit" || :
    done
    systemctl clean --what=fdstore "$UNIT" || :
    systemctl reset-failed "$UNIT" || :
    rm -rf /run/systemd/system/"$UNIT" /run/systemd/system/"$UNIT".d
    systemctl daemon-reload

    # Once the unit is gone, its cgroup is not kept anymore, and neither are those of the slices
    wait_for_removal /sys/fs/cgroup/"$SLICE"
}

setup_unit() {
    cleanup_unit

    systemctl edit --runtime --stdin --full --force "$UNIT" <<EOF
[Service]
Type=notify
NotifyAccess=all
ExecStart=$PAYLOAD $SIZE_MB
FileDescriptorStoreMax=1
FileDescriptorStorePreserve=yes
MemoryAccounting=yes
MemorySwapMax=0
Slice=$SLICE
ControlGroupPreserve=yes
$(printf '%s\n' "$@")
EOF
}

add_dropin() {
    printf '[Service]\n%s\n' "$@" | systemctl edit --runtime --stdin --drop-in=50-test.conf "$UNIT"
}

cgroup_id() {
    systemctl show -P ControlGroupId "$UNIT"
}

bpf_links() {(
    set +x
    local fd n=0

    # PID 1 might close any of its fds meanwhile
    for fd in /proc/1/fd/*; do
        [[ "$(readlink "$fd")" == anon_inode:bpf_link ]] && n=$((n + 1))
    done
    echo "$n"
)}

assert_memory_kept() {
    assert_eq "$(systemctl show -P NFileDescriptorStore "$UNIT")" 1
    assert_ge "$(systemctl show -P MemoryCurrent "$UNIT")" "$((SIZE_MB * 1024 * 1024))"
}

assert_invocation_id() {
    local n=0 value xattr

    # The cgroup must be labelled with the current invocation, not the one it was created for. Either xattr
    # might be unavailable (e.g. trusted.* in a container), but not both.
    for xattr in trusted.invocation_id user.invocation_id; do
        value="$(getfattr --name="$xattr" --absolute-names --only-values "$CGROUP" 2>/dev/null)" || continue
        assert_eq "$value" "$(systemctl show -P InvocationID "$UNIT")"
        n=$((n + 1))
    done
    assert_ge "$n" 1
}

wait_for_substate() {
    timeout 30 bash -c "until [[ \$(systemctl show -P SubState $1) == $2 ]]; do sleep .5; done"
}

wait_for_removal() {
    timeout 30 bash -c "while [[ -e $1 ]]; do sleep .5; done"
}

at_exit() {
    set +e

    systemctl stop test19preserve.socket
    rm -f /run/systemd/system/test19preserve.socket /run/systemd/system/test19preserve-closed.slice
    cleanup_unit
    nft delete table inet test19preserve &>/dev/null
    rm -f "$PAYLOAD"
}

trap at_exit EXIT

# Store a file on tmpfs of as many MiB as given, unless one is stored already
cat >"$PAYLOAD" <<'EOF'
#!/usr/bin/env bash
set -eux
set -o pipefail

if [[ -n "${TEST_DELEGATE:-}" ]]; then
    # Move ourselves into a subgroup and enable the memory controller for it, like a delegated payload might
    cg="/sys/fs/cgroup$(cut -d: -f3- /proc/self/cgroup)"
    mkdir "$cg/payload"
    echo $$ >"$cg/payload/cgroup.procs"
    echo +memory >"$cg/cgroup.subtree_control"
fi

if [[ "${LISTEN_FDNAMES:-}" != data ]]; then
    f="$(mktemp /dev/shm/test19preserve.XXXXXX)"
    dd if=/dev/zero of="$f" bs=1M count="${1:?}" status=none
    systemd-notify --fd=3 --fdname=data --pid=parent 3<"$f"
    rm "$f"
fi

systemd-notify --ready
exec sleep infinity
EOF
chmod +x "$PAYLOAD"

testcase_no() {
    local id

    # Without it, the unit is given a new cgroup whenever it is started, and the memory backing the stored
    # file stays charged to the old one, i.e. to the slice
    setup_unit ControlGroupPreserve=no
    assert_eq "$(systemctl show -P ControlGroupPreserve "$UNIT")" no
    systemctl start "$UNIT"
    id="$(cgroup_id)"
    assert_memory_kept

    systemctl restart "$UNIT"
    assert_eq "$(systemctl show -P NFileDescriptorStore "$UNIT")" 1
    assert_neq "$(cgroup_id)" "$id"
    assert_le "$(systemctl show -P MemoryCurrent "$UNIT")" "$((SIZE_MB * 1024 * 1024 / 2))"

    systemctl stop "$UNIT"
    test ! -e "$CGROUP"
}

testcase_yes() {
    local id

    setup_unit
    assert_eq "$(systemctl show -P ControlGroupPreserve "$UNIT")" yes
    systemctl start "$UNIT"
    id="$(cgroup_id)"
    assert_memory_kept

    systemctl restart "$UNIT"
    assert_eq "$(cgroup_id)" "$id"
    assert_memory_kept
    assert_invocation_id

    # The cgroup is kept across a stop too, also across a reload and a reexec
    systemctl stop "$UNIT"
    assert_eq "$(systemctl show -P SubState "$UNIT")" dead-resources-pinned
    assert_eq "$(cgroup_id)" "$id"
    assert_memory_kept
    systemctl daemon-reload
    systemctl daemon-reexec
    assert_eq "$(cgroup_id)" "$id"
    assert_memory_kept

    systemctl start "$UNIT"
    assert_eq "$(cgroup_id)" "$id"
    assert_memory_kept
    assert_invocation_id
}

testcase_turned_off() {
    local how id

    # Once the unit doesn't keep its cgroup anymore, the kept one is removed, and the unit is started in a
    # new one
    for how in stop auto-restart; do
        setup_unit Restart=always RestartSec=1h
        systemctl start "$UNIT"
        id="$(cgroup_id)"
        if [[ "$how" == stop ]]; then
            systemctl stop "$UNIT"
        else
            systemctl kill --kill-whom=main --signal=KILL "$UNIT"
            wait_for_substate "$UNIT" auto-restart
        fi
        assert_eq "$(cgroup_id)" "$id"

        sed -i '/^ControlGroupPreserve=/d' /run/systemd/system/"$UNIT"
        systemctl daemon-reload
        systemctl start "$UNIT"
        assert_neq "$(cgroup_id)" "$id"
        assert_eq "$(systemctl show -P NFileDescriptorStore "$UNIT")" 1
        assert_le "$(systemctl show -P MemoryCurrent "$UNIT")" "$((SIZE_MB * 1024 * 1024 / 2))"
    done
}

testcase_auto_restart() {
    local id

    setup_unit Restart=always RestartSec=1h
    systemctl start "$UNIT"
    id="$(cgroup_id)"

    # Make the main process die, so that the unit waits for RestartSec= in the auto-restart state, where it
    # is not running anything
    systemctl kill --kill-whom=main --signal=KILL "$UNIT"
    wait_for_substate "$UNIT" auto-restart
    assert_eq "$(cgroup_id)" "$id"
    assert_memory_kept

    systemctl start "$UNIT"
    assert_eq "$(systemctl show -P SubState "$UNIT")" running
    assert_eq "$(cgroup_id)" "$id"
    assert_invocation_id
}

testcase_failed() {
    local id

    setup_unit
    systemctl start "$UNIT"
    id="$(cgroup_id)"

    add_dropin ExecStartPre=false
    (! systemctl restart "$UNIT")
    assert_eq "$(systemctl show -P ActiveState "$UNIT")" failed
    assert_eq "$(cgroup_id)" "$id"
    assert_memory_kept

    add_dropin ExecStartPre=
    systemctl start "$UNIT"
    assert_eq "$(cgroup_id)" "$id"
}

testcase_delegate() {
    local id uid

    uid="$(id -u nobody)"
    setup_unit Delegate=yes User=nobody Environment=TEST_DELEGATE=1
    systemctl start "$UNIT"
    id="$(cgroup_id)"
    test -d "$CGROUP/payload"
    grep -qw memory "$CGROUP/cgroup.subtree_control"
    assert_eq "$(stat -c %u "$CGROUP")" "$uid"

    # Subgroups are removed as if the cgroup was removed, their memory stays accounted to the cgroup. The
    # payload's ownership of the cgroup ends with it too.
    systemctl stop "$UNIT"
    assert_eq "$(cgroup_id)" "$id"
    test ! -e "$CGROUP/payload"
    assert_memory_kept
    assert_eq "$(stat -c %u:%g "$CGROUP")" 0:0
    assert_eq "$(stat -c %u:%g "$CGROUP/cgroup.procs")" 0:0

    # The controllers enabled by the previous payload are disabled before the start, as otherwise we could
    # not spawn into the cgroup, and the payload is given the cgroup and sets up its subgroup again
    systemctl start "$UNIT"
    assert_eq "$(cgroup_id)" "$id"
    test -d "$CGROUP/payload"
    assert_eq "$(stat -c %u "$CGROUP")" "$uid"
    assert_memory_kept

    # Without delegation, it is not given the cgroup anymore
    systemctl stop "$UNIT"
    add_dropin Delegate=no Environment=TEST_DELEGATE=
    systemctl start "$UNIT"
    assert_eq "$(cgroup_id)" "$id"
    assert_eq "$(stat -c %u:%g "$CGROUP")" 0:0
    assert_memory_kept
}

testcase_restrict_filesystems() {
    local id

    if [[ -v ASAN_OPTIONS ]] || ! systemctl --version | grep -F -- "+BPF_FRAMEWORK" >/dev/null ||
       ! kernel_supports_lsm bpf; then
        echo "RestrictFileSystems= not supported, skipping."
        return 0
    fi

    setup_unit "RestrictFileSystems=~sysfs" "ExecStartPost=bash -c '! ls /sys'"
    systemctl start "$UNIT"
    id="$(cgroup_id)"

    # The settings of the previous invocation do not stick to the kept cgroup, the unit is set up with its
    # current ones when it is started again, as in a new cgroup
    systemctl stop "$UNIT"
    add_dropin RestrictFileSystems= ExecStartPost= "ExecStartPost=ls /sys"
    systemctl start "$UNIT"
    assert_eq "$(cgroup_id)" "$id"
}

testcase_device_policy() {
    local id

    if systemd-detect-virt -cq; then
        echo "/dev/kmsg not available in a container, skipping."
        return 0
    fi

    setup_unit DevicePolicy=closed "ExecStartPost=bash -c '! : </dev/kmsg'"
    systemctl start "$UNIT"
    id="$(cgroup_id)"

    systemctl stop "$UNIT"
    add_dropin DevicePolicy=auto ExecStartPost= "ExecStartPost=bash -c ': </dev/kmsg'"
    systemctl start "$UNIT"
    assert_eq "$(cgroup_id)" "$id"
}

testcase_controller_added() {
    local m n

    if systemctl --version | grep -F -- "-BPF_FRAMEWORK" >/dev/null; then
        echo "SocketBindDeny= not supported, skipping."
        return 0
    fi
    if ! grep -qw cpu /sys/fs/cgroup/cgroup.controllers; then
        echo "CPU controller not available, skipping."
        return 0
    fi

    setup_unit SocketBindDeny=any
    n="$(bpf_links)"
    systemctl start "$UNIT"
    m="$(bpf_links)"
    if [[ "$m" -eq "$n" ]]; then
        echo "SocketBindDeny= not supported, skipping."
        return 0
    fi

    # The BPF programs go with the previous invocation, and are attached only once again for the next one,
    # also if the cgroup is realized again meanwhile, e.g. because a controller was added
    systemctl stop "$UNIT"
    assert_eq "$(bpf_links)" "$n"
    add_dropin CPUWeight=50
    systemctl start "$UNIT"
    assert_eq "$(bpf_links)" "$m"
}

testcase_left_over() {
    local id n pid

    if systemctl --version | grep -F -- "-BPF_FRAMEWORK" >/dev/null; then
        echo "SocketBindDeny= not supported, skipping."
        return 0
    fi

    setup_unit KillMode=process SocketBindDeny=any
    n="$(bpf_links)"
    systemctl start "$UNIT"
    id="$(cgroup_id)"
    if [[ "$(bpf_links)" -eq "$n" ]]; then
        echo "SocketBindDeny= not supported, skipping."
        return 0
    fi

    # With processes left behind, the cgroup is left as it is, as if we couldn't remove it, rather than set
    # up anew for the next invocation, which would attach the BPF programs to it a second time
    n="$(bpf_links)"
    sleep infinity &>/dev/null &
    pid=$!
    echo "$pid" >"$CGROUP"/cgroup.procs
    systemctl restart "$UNIT"
    assert_eq "$(cgroup_id)" "$id"
    assert_eq "$(bpf_links)" "$n"

    kill "$pid"
    wait "$pid" || :
}

testcase_nft_set() {
    local cursor

    if ! command -v nft >/dev/null; then
        echo "nftables not installed, skipping."
        return 0
    fi

    # The cgroup is in the set only while the unit runs, as if it was removed when the unit went down
    nft add table inet test19preserve
    nft add set inet test19preserve c '{ type cgroupsv2; }'
    setup_unit NFTSet=cgroup:inet:test19preserve:c
    cursor="$(mktemp)"
    journalctl -q -n0 --cursor-file="$cursor"
    systemctl start "$UNIT"
    assert_in "$UNIT" "$(nft list set inet test19preserve c)"
    systemctl stop "$UNIT"
    test -d "$CGROUP"
    assert_not_in elements "$(nft list set inet test19preserve c)"

    systemctl start "$UNIT"
    assert_in "$UNIT" "$(nft list set inet test19preserve c)"

    # Removing the cgroup once it is not kept anymore finds nothing to delete from the set, which is fine
    systemctl stop "$UNIT"
    add_dropin ControlGroupPreserve=no
    wait_for_removal "$CGROUP"
    assert_not_in elements "$(nft list set inet test19preserve c)"
    journalctl --sync
    (! journalctl -q -p warning --cursor-file="$cursor" --grep "Failed to delete NFT set entry")
    rm "$cursor"
    nft delete table inet test19preserve
}

testcase_memory_max() {
    local id

    # Starting in a cgroup over its MemoryMax= with nothing to kill makes the openSUSE kernel loop in the OOM
    # killer, see TEST-19-CGROUP.abort-on-cgroup-creation-failure.sh
    . /etc/os-release
    if [[ "$ID" =~ opensuse ]]; then
        echo "Skipping cgroup test with too small MemoryMax= setting on openSUSE."
        return 0
    fi

    setup_unit
    systemctl start "$UNIT"
    id="$(cgroup_id)"

    # The limit applies to the memory charged by earlier invocations too. Depending on where the kernel
    # notices, the start fails while spawning the process already, or the process is OOM-killed.
    systemctl stop "$UNIT"
    add_dropin MemoryMax=$((SIZE_MB / 2))M
    (! systemctl start "$UNIT")
    wait_for_substate "$UNIT" failed
    assert_in '^(resources|oom-kill)$' "$(systemctl show -P Result "$UNIT")"
    assert_eq "$(cgroup_id)" "$id"
    assert_memory_kept

    add_dropin MemoryMax=infinity
    systemctl start "$UNIT"
    assert_eq "$(cgroup_id)" "$id"
}

testcase_removed() {
    local id

    setup_unit
    systemctl start "$UNIT"
    id="$(cgroup_id)"

    # If the kept cgroup is removed behind our back, start in a new one
    systemctl stop "$UNIT"
    rmdir "$CGROUP"
    mkdir "$CGROUP"
    systemctl start "$UNIT"
    assert_neq "$(cgroup_id)" "$id"
    assert_invocation_id
}

testcase_slice_change() {
    local id

    setup_unit
    systemctl start "$UNIT"
    id="$(cgroup_id)"

    # Charges cannot follow the unit into the new slice, so its old cgroup is removed once it is moved (shortly
    # after the reload), and it is started in a new one there
    systemctl stop "$UNIT"
    add_dropin Slice="$OTHER_SLICE"
    wait_for_removal "$CGROUP"
    systemctl start "$UNIT"
    assert_eq "$(systemctl show -P ControlGroup "$UNIT")" "/$SLICE/$OTHER_SLICE/$UNIT"
    assert_eq "$(systemctl show -P NFileDescriptorStore "$UNIT")" 1
    assert_neq "$(cgroup_id)" "$id"
}

testcase_slice() {
    local id pid nested=test19preserve-nested.slice

    setup_unit Slice="$nested"
    systemctl start "$UNIT"
    id="$(cgroup_id)"
    pid="$(systemctl show -P MainPID "$UNIT")"

    # Restarting the slices restarts the unit too, which keeps its cgroup, and so do the slices. We only wait
    # for the job of the outer slice, so wait for the unit to be up again.
    systemctl restart "$SLICE"
    wait_for_substate "$UNIT" running
    assert_neq "$(systemctl show -P MainPID "$UNIT")" "$pid"
    assert_eq "$(cgroup_id)" "$id"
    assert_memory_kept

    # Stopping them stops the unit, which keeps its cgroup, and so do the slices
    systemctl stop "$SLICE"
    assert_eq "$(systemctl show -P ActiveState "$UNIT")" inactive
    assert_eq "$(systemctl show -P ActiveState "$nested")" inactive
    assert_eq "$(cgroup_id)" "$id"

    systemctl start "$UNIT"
    assert_eq "$(cgroup_id)" "$id"
    assert_memory_kept
}

testcase_slice_device_policy() {
    local nested=test19preserve-closed.slice

    if systemd-detect-virt -cq; then
        echo "/dev/kmsg not available in a container, skipping."
        return 0
    fi

    # A stopped slice whose member keeps its cgroup leaves its own set up as it is, so that its settings apply
    # to members started in it before the slice is started again, as they would in a new cgroup
    printf '[Slice]\nDevicePolicy=closed\n' >/run/systemd/system/"$nested"
    setup_unit Slice="$nested"
    systemctl start "$UNIT"
    systemctl stop "$nested"
    assert_eq "$(systemctl show -P ActiveState "$UNIT")" inactive
    test -d /sys/fs/cgroup/"$SLICE/$nested/$UNIT"

    systemd-run --job-mode=ignore-requirements --slice="$nested" --service-type=oneshot bash -c '! : </dev/kmsg'
    assert_eq "$(systemctl show -P ActiveState "$nested")" inactive

    cleanup_unit
    rm /run/systemd/system/"$nested"
    systemctl daemon-reload
}

testcase_socket() {
    local id mode socket=test19preserve.socket

    # Other units that can be started again keep their cgroup just the same
    setup_unit
    for mode in no yes; do
        systemctl edit --runtime --stdin --full --force "$socket" <<EOF
[Socket]
ListenStream=/run/test19preserve.sock
ExecStartPre=true
Slice=$SLICE
ControlGroupPreserve=$mode
EOF
        systemctl start "$socket"
        id="$(systemctl show -P ControlGroupId "$socket")"
        test -d /sys/fs/cgroup/"$SLICE/$socket"

        systemctl stop "$socket"
        systemctl start "$socket"
        if [[ "$mode" == yes ]]; then
            assert_eq "$(systemctl show -P ControlGroupId "$socket")" "$id"
        else
            assert_neq "$(systemctl show -P ControlGroupId "$socket")" "$id"
        fi
        systemctl stop "$socket"
    done
    rm /run/systemd/system/"$socket"
    systemctl daemon-reload
    wait_for_removal /sys/fs/cgroup/"$SLICE/$socket"
}

run_testcases
