#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

if (( EUID != 0 )); then
    echo "Root is required to change the test units' cgroup properties."
    exit 77
fi

if [[ ! -f /sys/fs/cgroup/cgroup.controllers ]] ||
    ! grep -w cpuset /sys/fs/cgroup/cgroup.controllers >/dev/null; then
    echo "The cgroup v2 cpuset controller is unavailable."
    exit 77
fi

case "$(systemctl show --property=SystemState --value)" in
    running|degraded) ;;
    *) echo "The startup CPU policy is still active; skipping."; exit 77 ;;
esac

parent=$(systemctl show system.slice --property=ControlGroup --value)
cpu_file="/sys/fs/cgroup${parent}/cpuset.cpus.effective"
mem_file="/sys/fs/cgroup${parent}/cpuset.mems.effective"
[[ -r "$cpu_file" ]] || cpu_file=/sys/fs/cgroup/cpuset.cpus.effective
[[ -r "$mem_file" ]] || mem_file=/sys/fs/cgroup/cpuset.mems.effective
parent_cpus=$(<"$cpu_file")
parent_mems=$(<"$mem_file")
cpu=${parent_cpus%%[-,]*}
mem=${parent_mems%%[-,]*}
[[ -n "$mem" ]]

if [[ -z "$cpu" || "$parent_cpus" == "$cpu" ]]; then
    echo "At least two available CPUs are required for the inheritance check."
    exit 77
fi

units=()
# Called through the EXIT trap below; ShellCheck cannot see the indirect invocation.
# shellcheck disable=SC2329
cleanup() {
    for unit in "${units[@]}"; do
        systemctl stop "$unit" || :
        systemctl reset-failed "$unit" || :
    done
}
trap cleanup EXIT

probe_empty_cpuset() {
    python3 - "$1" <<'PY'
import errno
import os
import sys

fd = os.open(sys.argv[1], os.O_WRONLY | os.O_CLOEXEC)
try:
    if os.write(fd, b"\n") != 1:
        raise RuntimeError("Short write while probing a cpuset attribute")
except OSError as exc:
    if exc.errno == errno.ENOSPC:
        print(exc, file=sys.stderr)
        sys.exit(77)
    raise
finally:
    os.close(fd)
PY
}

read_cpuset_attribute() {
    local value

    if value=$(cat "$1"); then
        printf '%s\n' "$value"
    elif [[ ! -e "$1" ]]; then
        printf '%s\n' '<controller absent>'
    else
        echo "Failed to read the existing cpuset attribute '$1'." >&2
        return 1
    fi
}

systemctl --version
uname -r

# Probe the kernel independently of systemctl set-property: older kernels reject clearing a non-empty
# cpuset while it contains a process, even on cgroup v2. Only that specific ENOSPC permits skipping.
probe_unit="test-allowed-cpus-reset-probe-$$.service"
units+=("$probe_unit")
systemd-run --unit="$probe_unit" --collect -p Type=exec \
    -p "AllowedCPUs=$cpu" -p "AllowedMemoryNodes=$mem" /usr/bin/sleep infinity
probe_cgroup=$(systemctl show "$probe_unit" --property=ControlGroup --value)
probe_pid=$(systemctl show "$probe_unit" --property=MainPID --value)
(( probe_pid > 0 ))
[[ "$(cat "/sys/fs/cgroup${probe_cgroup}/cpuset.cpus")" == "$cpu" ]]
[[ "$(cat "/sys/fs/cgroup${probe_cgroup}/cpuset.mems")" == "$mem" ]]
grep -Fx "$probe_pid" "/sys/fs/cgroup${probe_cgroup}/cgroup.procs" >/dev/null

probe_rc=0
probe_empty_cpuset "/sys/fs/cgroup${probe_cgroup}/cpuset.cpus" || probe_rc=$?
if (( probe_rc == 77 )); then
    [[ "$(cat "/sys/fs/cgroup${probe_cgroup}/cpuset.cpus")" == "$cpu" ]]
    [[ "$(systemctl show "$probe_unit" --property=MainPID --value)" == "$probe_pid" ]]
    echo "The kernel rejects clearing a populated cpuset with ENOSPC; skipping live-service checks."
    exit 77
fi
(( probe_rc == 0 ))
probe_configured=$(cat "/sys/fs/cgroup${probe_cgroup}/cpuset.cpus")
[[ -z "$probe_configured" ]]
[[ "$(systemctl show "$probe_unit" --property=MainPID --value)" == "$probe_pid" ]]

# Probe memory-node reset separately, so a kernel rejecting it does not suppress the CPU scenarios.
probe_rc=0
probe_empty_cpuset "/sys/fs/cgroup${probe_cgroup}/cpuset.mems" || probe_rc=$?
if (( probe_rc == 77 )); then
    [[ "$(cat "/sys/fs/cgroup${probe_cgroup}/cpuset.mems")" == "$mem" ]]
    memory_reset_supported=no
else
    (( probe_rc == 0 ))
    probe_configured=$(cat "/sys/fs/cgroup${probe_cgroup}/cpuset.mems")
    [[ -z "$probe_configured" ]]
    memory_reset_supported=yes
fi
[[ "$(systemctl show "$probe_unit" --property=MainPID --value)" == "$probe_pid" ]]
systemctl stop "$probe_unit"
units=()

failed=0

for scenario in cpu-only memory-control startup-control; do
    unit="test-allowed-cpus-reset-${scenario}-$$.service"
    properties=(-p "AllowedCPUs=$cpu")
    case "$scenario" in
        memory-control) properties+=(-p "AllowedMemoryNodes=$mem") ;;
        startup-control) properties+=(-p "StartupAllowedCPUs=$cpu") ;;
    esac

    units+=("$unit")
    systemd-run --unit="$unit" --collect -p Type=exec "${properties[@]}" /usr/bin/sleep infinity
    cgroup=$(systemctl show "$unit" --property=ControlGroup --value)
    pid_before=$(systemctl show "$unit" --property=MainPID --value)
    (( pid_before > 0 ))
    [[ "$(cat "/sys/fs/cgroup${cgroup}/cpuset.cpus")" == "$cpu" ]]

    systemctl set-property --runtime "$unit" AllowedCPUs=

    pid_after=$(systemctl show "$unit" --property=MainPID --value)
    allowed=$(systemctl show "$unit" --property=AllowedCPUs --value)
    effective=$(systemctl show "$unit" --property=EffectiveCPUs --value)
    task_cpus=$(awk '/^Cpus_allowed_list:/ { print $2 }' "/proc/$pid_after/status")
    configured=$(read_cpuset_attribute "/sys/fs/cgroup${cgroup}/cpuset.cpus")

    printf '%s: PID %s -> %s; AllowedCPUs=%q; cpuset.cpus=%q; EffectiveCPUs=%q; task=%q; parent=%q\n' \
        "$scenario" "$pid_before" "$pid_after" "$allowed" "$configured" \
        "$effective" "$task_cpus" "$parent_cpus"

    if [[ "$pid_before" != "$pid_after" || -n "$allowed" || "$task_cpus" != "$parent_cpus" ]] ||
        [[ -n "$configured" && "$configured" != "<controller absent>" ]]; then
        echo "FAIL: $scenario did not clear the live CPU restriction without restarting."
        failed=1
    else
        echo "PASS: $scenario restored CPU inheritance without restarting."
    fi

    if [[ "$scenario" == memory-control ]]; then
        # Clearing CPUs must not discard the memory-node setting that keeps the controller in use.
        [[ "$(cat "/sys/fs/cgroup${cgroup}/cpuset.mems")" == "$mem" ]]
        [[ "$(awk '/^Mems_allowed_list:/ { print $2 }' "/proc/$pid_after/status")" == "$mem" ]]

        if [[ "$memory_reset_supported" == yes ]]; then
            # Now remove the last cpuset setting, without restarting the service.
            systemctl set-property --runtime "$unit" AllowedMemoryNodes=
            pid_after=$(systemctl show "$unit" --property=MainPID --value)
            allowed_mems=$(systemctl show "$unit" --property=AllowedMemoryNodes --value)
            configured_mems=$(read_cpuset_attribute "/sys/fs/cgroup${cgroup}/cpuset.mems")
            task_mems=$(awk '/^Mems_allowed_list:/ { print $2 }' "/proc/$pid_after/status")

            printf 'mem reset: PID %s -> %s; AllowedMemoryNodes=%q; cpuset.mems=%q; task=%q; parent=%q\n' \
                "$pid_before" "$pid_after" "$allowed_mems" "$configured_mems" "$task_mems" "$parent_mems"
            [[ "$pid_after" == "$pid_before" && -z "$allowed_mems" && "$task_mems" == "$parent_mems" ]]
            [[ -z "$configured_mems" || "$configured_mems" == "<controller absent>" ]]

            # Non-empty memory-node settings must still apply to the same process after the reset.
            systemctl set-property --runtime "$unit" "AllowedMemoryNodes=$mem"
            [[ "$(cat "/sys/fs/cgroup${cgroup}/cpuset.mems")" == "$mem" ]]
            [[ "$(systemctl show "$unit" --property=MainPID --value)" == "$pid_before" ]]
        else
            echo "SKIP: kernel rejects clearing populated cpuset.mems with ENOSPC."
        fi
    fi

    # Keep a positive control: a new non-empty restriction must still be applied to the same process.
    systemctl set-property --runtime "$unit" "AllowedCPUs=$cpu"
    [[ "$(cat "/sys/fs/cgroup${cgroup}/cpuset.cpus")" == "$cpu" ]]
    [[ "$(systemctl show "$unit" --property=MainPID --value)" == "$pid_before" ]]
    systemctl stop "$unit"
    units=()
done

exit "$failed"
