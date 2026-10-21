#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh

manager=(org.freedesktop.systemd1 /org/freedesktop/systemd1 org.freedesktop.systemd1.Manager)
unit=(org.freedesktop.systemd1 /org/freedesktop/systemd1/unit/enqueue_2djob_2dbus_2dpolicy_2dallowed_2etarget org.freedesktop.systemd1.Unit)
allowed=enqueue-job-bus-policy-allowed.target
other=enqueue-job-bus-policy-other.target
denied=enqueue-job-bus-policy-denied.target
rule=/etc/polkit-1/rules.d/00-enqueue-job-bus-policy.rules

cleanup() {
    systemctl stop "$allowed" "$other" "$denied" || :
    rm -f "/run/systemd/system/$allowed" "/run/systemd/system/$other" "/run/systemd/system/$denied"
    systemctl daemon-reload
    if [[ -e "$rule" ]]; then
        rm -f "$rule"
        systemctl try-reload-or-restart polkit.service
    fi
}
trap cleanup EXIT

for name in "$allowed" "$other" "$denied"; do
    cat >"/run/systemd/system/$name" <<EOF
[Unit]
Description=Job enqueue authorization test
EOF
done
systemctl daemon-reload

assert_denied() {
    local output

    output=$(runas testuser busctl --system --allow-interactive-authorization=no call "$@" 2>&1) && assert_not_reached
    # A bus policy denial has a different message. Verify that PID 1 refused authorization.
    assert_in 'Call failed: (Access denied|Interactive authentication required)' "$output"
}

# These methods must reach PID 1 for unprivileged clients, so that PID 1 can perform
# authorization. An invalid job type distinguishes its response from a bus policy denial.
# https://github.com/systemd/systemd/issues/44289
for method in EnqueueUnitJob EnqueueUnitJobMany EnqueueJob; do
    destination=("${manager[@]}")
    case "$method" in
        EnqueueUnitJob)
            args=(sss "$allowed" invalid-job-type replace)
            ;;
        EnqueueUnitJobMany)
            args=(assst 2 "$allowed" "$other" invalid-job-type replace 0)
            ;;
        EnqueueJob)
            destination=("${unit[@]}")
            args=(ss invalid-job-type replace)
            ;;
    esac

    output=$(runas testuser busctl --system --allow-interactive-authorization=no call \
        "${destination[@]}" "$method" "${args[@]}" 2>&1) && assert_not_reached
    assert_in 'Job type invalid-job-type invalid' "$output"
done

output=$(runas testuser busctl --system --allow-interactive-authorization=no call \
    "${manager[@]}" StartUnitWithFlags sst "$allowed" replace 1 2>&1) && assert_not_reached
assert_in "Invalid 'flags' parameter" "$output"

# Valid arguments must still be rejected without authorization, including job types that can start
# an inactive unit. Nothing in the batch may be started when authorization fails.
for job_type in start reload-or-start; do
    assert_denied "${manager[@]}" EnqueueUnitJob sss "$allowed" "$job_type" replace
    assert_denied "${manager[@]}" EnqueueUnitJobMany assst 2 "$allowed" "$other" "$job_type" replace 0
    assert_denied "${unit[@]}" EnqueueJob ss "$job_type" replace
    assert_eq "$(systemctl show "$allowed" -P ActiveState)" inactive
    assert_eq "$(systemctl show "$other" -P ActiveState)" inactive
done

assert_denied "${manager[@]}" StartUnitWithFlags sst "$allowed" replace 0
systemctl set-property --runtime "$allowed" Markers=needs-start
assert_denied "${manager[@]}" EnqueueMarkedJobs
assert_eq "$(systemctl show "$allowed" -P ActiveState)" inactive
systemctl set-property --runtime "$allowed" Markers=

# Unit-scoped rules also need to work for batches, including asynchronous authorization of more
# than one unit. This part requires polkit; the tests above also run without it.
if ! command -v pkcheck >/dev/null; then
    exit 0
fi

mkdir -p "$(dirname "$rule")"
cat >"$rule" <<EOF
polkit.addRule(function(action, subject) {
    if (action.id == "org.freedesktop.systemd1.manage-units" && subject.user == "testuser") {
        if ((action.lookup("unit") == "$allowed" || action.lookup("unit") == "$other") &&
            action.lookup("verb") == "start")
            return polkit.Result.YES;
        return polkit.Result.NO;
    }
});
EOF
systemctl reload-or-restart polkit.service

assert_denied "${manager[@]}" EnqueueUnitJobMany assst 2 "$allowed" "$denied" start replace 0
assert_denied "${manager[@]}" EnqueueUnitJobMany assst 2 "$denied" "$allowed" start replace 0
for name in "$allowed" "$other" "$denied"; do
    assert_eq "$(systemctl show "$name" -P ActiveState)" inactive
done

# The rule authorizes starting these units, but not stopping them.
assert_denied "${manager[@]}" EnqueueUnitJobMany assst 2 "$allowed" "$other" stop replace 0
runas testuser busctl --system --allow-interactive-authorization=no call \
    "${manager[@]}" EnqueueUnitJobMany assst 2 "$allowed" "$other" start replace 0
# The method returns when jobs are queued, before they necessarily finish.
for name in "$allowed" "$other"; do
    # shellcheck disable=SC2016
    timeout 30s bash -c 'until [[ "$(systemctl show "$1" -P ActiveState)" == active ]]; do sleep 0.1; done' _ "$name"
    assert_eq "$(systemctl show "$name" -P ActiveState)" active
done
assert_eq "$(systemctl show "$denied" -P ActiveState)" inactive
