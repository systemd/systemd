#!/usr/bin/env bash
set -x
set -e

>/failed

die () {
  {
    echo "ERROR: $1"
    systemctl status my-test.timer || :
    systemctl list-timers my-test.timer || :
    echo "next_elapsed=${next_elapsed}"
  } | tee /failed
  exit 1
}

cat <<'EOL' >/etc/systemd/system/my-test.service
[Service]
Type=oneshot
ExecStart=/bin/echo Timer runs me
EOL

cat <<'EOL' >/etc/systemd/system/my-test.timer
[Timer]
OnCalendar=*:14,44:0
EOL

systemctl daemon-reload

systemctl start my-test.timer

next_elapsed=$(systemctl show -p NextElapseUSecRealtime --value my-test.timer)
[[ "${next_elapsed}" = *:[14]4:00* ]] || {
  die "Failed to schedule initial timer."
}

# Now update the timer specification and confirm that a simple
# `systemctl daemon-reload` is enough to update it.

cat <<'EOL' >/etc/systemd/system/my-test.timer
[Timer]
OnCalendar=*:18,48:0
EOL

systemctl daemon-reload

next_elapsed=$(systemctl show -p NextElapseUSecRealtime --value my-test.timer)
[[ "${next_elapsed}" = *:[14]8:00* ]] || {
  die "Failed to update timer with a simple daemon-reload."
}

# Update the timer and include separate OnCalendar= specifications, with a
# single invalid entry. Confirm that `systemctl daemon-reload` will update it,
# but it will not break it.

cat <<'EOL' >/etc/systemd/system/my-test.timer
[Timer]
OnCalendar=*:22:0
OnCalendar=*:52:0
OnCalendar=*:82:0
EOL

systemctl daemon-reload

next_elapsed=$(systemctl show -p NextElapseUSecRealtime --value my-test.timer)
[[ "${next_elapsed}" = *:[25]2:00* ]] || {
  die "A single broken entry unexpectedly broke the timer."
}

# Go back to the last entry. daemon-reload still works.

cat <<'EOL' >/etc/systemd/system/my-test.timer
[Timer]
OnCalendar=*:18,48:0
EOL

systemctl daemon-reload

next_elapsed=$(systemctl show -p NextElapseUSecRealtime --value my-test.timer)
[[ "${next_elapsed}" = *:[14]8:00* ]] || {
  die "Failed to go back to a single calendar with a simple daemon-reload."
}

# Now break the timer with an invalid time and confirm that
# `systemctl daemon-reload` will indeed break it.

cat <<'EOL' >/etc/systemd/system/my-test.timer
[Timer]
OnCalendar=*:22,52,82:0
EOL

systemctl daemon-reload

next_elapsed=$(systemctl show -p NextElapseUSecRealtime --value my-test.timer)
[[ "${next_elapsed}" = "" ]] || {
  die "Expected timer to have broken with invalid specification, but it didn't."
}

# Fix it back. `systemctl daemon-reload` currently is not enough to fix it.

cat <<'EOL' >/etc/systemd/system/my-test.timer
[Timer]
OnCalendar=*:18,48:0
EOL

systemctl daemon-reload

next_elapsed=$(systemctl show -p NextElapseUSecRealtime --value my-test.timer)
[[ "${next_elapsed}" = "" ]] || {
  die "Expected daemon-reload not to fix it (Is this a bug?)."
}

# Need to restart the timer to actually fix it here.

systemctl restart my-test.timer

next_elapsed=$(systemctl show -p NextElapseUSecRealtime --value my-test.timer)
[[ "${next_elapsed}" = *:[14]8:00* ]] || {
  die "Expected timer to have been fixed after a restart."
}

touch /testok
rm /failed
