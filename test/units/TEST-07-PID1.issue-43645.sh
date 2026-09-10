#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later

set -eux
set -o pipefail

# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh

# FailureAction=exit made the manager exit 0 when the unit failed before any of its
# processes could run.
# Issue: https://github.com/systemd/systemd/issues/43645

UNITS="$(mktemp -d)"
XDG="$(mktemp -d)"
CG="/sys/fs/cgroup$(cut -d: -f3 /proc/self/cgroup)/issue-43645"

cleanup() {
    rm -rf "$UNITS" "$XDG" || :
    rmdir "$CG/app.slice" "$CG" 2>/dev/null || :
}

trap cleanup EXIT

cp /usr/lib/systemd/user/{basic,exit,paths,shutdown,sockets,timers}.target \
   /usr/lib/systemd/user/systemd-exit.service "$UNITS/"

cat >"$UNITS/issue-43645.target" <<EOF
[Unit]
Requires=issue-43645.service
After=issue-43645.service
EOF

cat >"$UNITS/issue-43645.service" <<EOF
[Unit]
FailureAction=exit

[Service]
Type=oneshot
Slice=app.slice
ExecStart=false
EOF

# Move into a cgroup of our own, so that the manager we exec adopts it as its root.
cat >"$UNITS/wrapper.sh" <<EOF
#!/usr/bin/env bash
set -eu
mkdir -p "$CG"
echo \$\$ >"$CG/cgroup.procs"
exec "\$@"
EOF
chmod +x "$UNITS/wrapper.sh"

# Runs a nested user manager, so that we can observe what it exits with.
run_manager() {
    local rc=0

    rm -rf "$XDG" || :
    mkdir -p "$XDG"
    chmod 0700 "$XDG"

    XDG_RUNTIME_DIR="$XDG" SYSTEMD_UNIT_PATH="$UNITS" \
        timeout 60 "$UNITS/wrapper.sh" /usr/lib/systemd/systemd --user --unit=issue-43645.target || rc=$?

    return $rc
}

# ExecStart= runs and fails: its exit status is propagated.
assert_rc 1 run_manager

# Now forbid the slice the unit lands in any descendants, so that creating the unit's
# own cgroup fails. An ENOMEM fails the very same mkdir().
mkdir -p "$CG/app.slice"
echo 0 >"$CG/app.slice/cgroup.max.descendants"

# The unit now fails before ExecStart= could run: no exit status to propagate, but the
# manager must still not report success.
assert_rc 255 run_manager
