#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# shellcheck disable=SC2002
set -eux
set -o pipefail

# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh

BASE=test-"$RANDOM"
SERVICE_NAME_SHORT=invocation-id-"$BASE"
SERVICE_NAME="$SERVICE_NAME_SHORT".service
SERVICE_NAME_GLOB="invocation-*-${BASE}.service"

TMP_DIR=$(mktemp -d)

# FIXME: if the maximum log level of PID1 is debug, then journal entries of
# service stdout will not contain _SYSTEMD_INVOCATION_ID field.
SAVED_LOG_LEVEL=$(systemctl log-level)
systemctl log-level info

# Note, if the service exits extremely fast, journald cannot find the source of the
# stream. Hence, we need to call 'journalctl --sync' before service exits.
for i in {1..10}; do
    systemd-run --wait -u "$SERVICE_NAME" bash -c "echo invocation ${i} \$INVOCATION_ID; journalctl --sync"
done

# Sync journal again here to ensure the following message is stored to journal.
# systemd[1]: invocation-id-test-26448.service: Deactivated successfully.
journalctl --sync

journalctl --list-invocation -u "$SERVICE_NAME_SHORT" | tee "$TMP_DIR"/short
journalctl --list-invocation -u "$SERVICE_NAME_GLOB" | tee "$TMP_DIR"/glob
journalctl --list-invocation -u "$SERVICE_NAME" | tee "$TMP_DIR"/10
journalctl --list-invocation -u "$SERVICE_NAME" --reverse | tee "$TMP_DIR"/10-r
journalctl --list-invocation -u "$SERVICE_NAME" -n +10 | tee "$TMP_DIR"/p10
journalctl --list-invocation -u "$SERVICE_NAME" -n +10 --reverse | tee "$TMP_DIR"/p10-r
journalctl --list-invocation -u "$SERVICE_NAME" -n 5 | tee "$TMP_DIR"/5
journalctl --list-invocation -u "$SERVICE_NAME" -n 5 --reverse | tee "$TMP_DIR"/5-r
journalctl --list-invocation -u "$SERVICE_NAME" -n +5 | tee "$TMP_DIR"/p5
journalctl --list-invocation -u "$SERVICE_NAME" -n +5 --reverse | tee "$TMP_DIR"/p5-r

[[ $(cat "$TMP_DIR"/10 | wc -l) == 11 ]]
[[ $(cat "$TMP_DIR"/10-r | wc -l) == 11 ]]
[[ $(cat "$TMP_DIR"/p10 | wc -l) == 11 ]]
[[ $(cat "$TMP_DIR"/p10-r | wc -l) == 11 ]]
[[ $(cat "$TMP_DIR"/5 | wc -l) == 6 ]]
[[ $(cat "$TMP_DIR"/5-r | wc -l) == 6 ]]
[[ $(cat "$TMP_DIR"/p5 | wc -l) == 6 ]]
[[ $(cat "$TMP_DIR"/p5-r | wc -l) == 6 ]]

diff "$TMP_DIR"/10 "$TMP_DIR"/short
diff "$TMP_DIR"/10 "$TMP_DIR"/glob
diff <(tail -n 10 "$TMP_DIR"/10 | tac) <(tail -n 10 "$TMP_DIR"/10-r)
diff <(tail -n 5 "$TMP_DIR"/10) <(tail -n 5 "$TMP_DIR"/5)
diff <(tail -n 5 "$TMP_DIR"/10 | tac) <(tail -n 5 "$TMP_DIR"/5-r)
diff <(tail -n 10 "$TMP_DIR"/p10 | tac) <(tail -n 10 "$TMP_DIR"/p10-r)
diff <(tail -n 10 "$TMP_DIR"/p10 | head -n 5) <(tail -n 5 "$TMP_DIR"/p5)
diff <(tail -n 10 "$TMP_DIR"/p10 | head -n 5 | tac) <(tail -n 5 "$TMP_DIR"/p5-r)

tail -n 10 "$TMP_DIR"/10 |
    while read -r idx invocation _; do
        i="$(( idx + 10 ))"
        assert_in "invocation ${i} ${invocation}" "$(journalctl --no-hostname -n 1 -t bash --invocation="${i}" -u "$SERVICE_NAME_SHORT")"
        assert_in "invocation ${i} ${invocation}" "$(journalctl --no-hostname -n 1 -t bash --invocation="${idx}" -u "$SERVICE_NAME_SHORT")"
        assert_in "invocation ${i} ${invocation}" "$(journalctl --no-hostname -n 1 -t bash --invocation="${i}" -u "$SERVICE_NAME_GLOB")"
        assert_in "invocation ${i} ${invocation}" "$(journalctl --no-hostname -n 1 -t bash --invocation="${idx}" -u "$SERVICE_NAME_GLOB")"
        assert_in "invocation ${i} ${invocation}" "$(journalctl --no-hostname -n 1 -t bash --invocation="${i}" -u "$SERVICE_NAME")"
        assert_in "invocation ${i} ${invocation}" "$(journalctl --no-hostname -n 1 -t bash --invocation="${idx}" -u "$SERVICE_NAME")"
        assert_in "invocation ${i} ${invocation}" "$(journalctl --no-hostname -n 1 -t bash --invocation="${invocation}")"
    done

tail -n 10 "$TMP_DIR"/p10 |
    while read -r i invocation _; do
        idx="$(( i - 10 ))"
        assert_in "invocation ${i} ${invocation}" "$(journalctl --no-hostname -n 1 -t bash --invocation="${i}" -u "$SERVICE_NAME_SHORT")"
        assert_in "invocation ${i} ${invocation}" "$(journalctl --no-hostname -n 1 -t bash --invocation="${idx}" -u "$SERVICE_NAME_SHORT")"
        assert_in "invocation ${i} ${invocation}" "$(journalctl --no-hostname -n 1 -t bash --invocation="${i}" -u "$SERVICE_NAME_GLOB")"
        assert_in "invocation ${i} ${invocation}" "$(journalctl --no-hostname -n 1 -t bash --invocation="${idx}" -u "$SERVICE_NAME_GLOB")"
        assert_in "invocation ${i} ${invocation}" "$(journalctl --no-hostname -n 1 -t bash --invocation="${i}" -u "$SERVICE_NAME")"
        assert_in "invocation ${i} ${invocation}" "$(journalctl --no-hostname -n 1 -t bash --invocation="${idx}" -u "$SERVICE_NAME")"
        assert_in "invocation ${i} ${invocation}" "$(journalctl --no-hostname -n 1 -t bash --invocation="${invocation}")"
    done

# Restore the log level.
systemctl log-level "$SAVED_LOG_LEVEL"
