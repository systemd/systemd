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

if [[ -z "$cpu" || "$parent_cpus" == "$cpu" ]]; then
    echo "At least two available CPUs are required for the inheritance check."
    exit 77
fi

units=()
cleanup() {
    for unit in "${units[@]}"; do
        systemctl stop "$unit" || :
        systemctl reset-failed "$unit" || :
    done
}
trap cleanup EXIT

systemctl --version
uname -r
failed=0

for scenario in cpu-only memory-control startup-control; do
    unit="test-allowed-cpus-reset-${scenario}-$$.service"
    properties=(-p "AllowedCPUs=$cpu")
    case "$scenario" in
        memory-control) properties+=(-p "AllowedMemoryNodes=$parent_mems") ;;
        startup-control) properties+=(-p "StartupAllowedCPUs=$cpu") ;;
    esac

    systemd-run --unit="$unit" --collect -p Type=exec "${properties[@]}" /usr/bin/sleep infinity
    units+=("$unit")
    cgroup=$(systemctl show "$unit" --property=ControlGroup --value)
    pid_before=$(systemctl show "$unit" --property=MainPID --value)
    (( pid_before > 0 ))
    [[ "$(cat "/sys/fs/cgroup${cgroup}/cpuset.cpus")" == "$cpu" ]]

    systemctl set-property --runtime "$unit" AllowedCPUs=

    pid_after=$(systemctl show "$unit" --property=MainPID --value)
    allowed=$(systemctl show "$unit" --property=AllowedCPUs --value)
    effective=$(systemctl show "$unit" --property=EffectiveCPUs --value)
    task_cpus=$(awk '/^Cpus_allowed_list:/ { print $2 }' "/proc/$pid_after/status")
    if [[ -e "/sys/fs/cgroup${cgroup}/cpuset.cpus" ]]; then
        configured=$(cat "/sys/fs/cgroup${cgroup}/cpuset.cpus")
    else
        configured="<controller absent>"
    fi

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

    # Keep a positive control: a new non-empty restriction must still be applied to the same process.
    systemctl set-property --runtime "$unit" "AllowedCPUs=$cpu"
    [[ "$(cat "/sys/fs/cgroup${cgroup}/cpuset.cpus")" == "$cpu" ]]
    [[ "$(systemctl show "$unit" --property=MainPID --value)" == "$pid_before" ]]
    systemctl stop "$unit"
    units=()
done

exit "$failed"
