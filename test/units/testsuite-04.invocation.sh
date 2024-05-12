#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# shellcheck disable=SC2002
set -eux
set -o pipefail

# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh

SERVICE_NAME=invocation-id-test-"$RANDOM".service

TMP_DIR=$(mktemp -d)

for i in {1..10}; do
    systemd-run --wait -u "$SERVICE_NAME" bash -c "echo invocation ${i} \$INVOCATION_ID; journalctl --sync"
done

journalctl --list-invocation -u "$SERVICE_NAME" | tee "$TMP_DIR"/10
journalctl --list-invocation -u "$SERVICE_NAME" --reverse | tee "$TMP_DIR"/10-r
journalctl --list-invocation -u "$SERVICE_NAME" -n +10| tee "$TMP_DIR"/p10
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

diff <(tail -n 10 "$TMP_DIR"/10 | tac) <(tail -n 10 "$TMP_DIR"/10-r)
diff <(tail -n 5 "$TMP_DIR"/10) <(tail -n 5 "$TMP_DIR"/5)
diff <(tail -n 5 "$TMP_DIR"/10 | tac) <(tail -n 5 "$TMP_DIR"/5-r)
diff <(tail -n 10 "$TMP_DIR"/p10 | tac) <(tail -n 10 "$TMP_DIR"/p10-r)
diff <(tail -n 10 "$TMP_DIR"/p10 | head -n 5) <(tail -n 5 "$TMP_DIR"/p5)
diff <(tail -n 10 "$TMP_DIR"/p10 | head -n 5 | tac) <(tail -n 5 "$TMP_DIR"/p5-r)

tail -n 10 "$TMP_DIR"/10 |
    while read -r idx invocation remaining; do
        i="$(( idx + 10 ))"
        assert_in "invocation ${i} ${invocation}" "$(journalctl --no-hostname -n 1 -t bash --invocation="${i}" -u "$SERVICE_NAME")"
        assert_in "invocation ${i} ${invocation}" "$(journalctl --no-hostname -n 1 -t bash --invocation="${idx}" -u "$SERVICE_NAME")"
        assert_in "invocation ${i} ${invocation}" "$(journalctl --no-hostname -n 1 -t bash --invocation="${invocation}")"
    done

tail -n 10 "$TMP_DIR"/p10 |
    while read -r i invocation remaining; do
        idx="$(( i - 10 ))"
        assert_in "invocation ${i} ${invocation}" "$(journalctl --no-hostname -n 1 -t bash --invocation="${i}" -u "$SERVICE_NAME")"
        assert_in "invocation ${i} ${invocation}" "$(journalctl --no-hostname -n 1 -t bash --invocation="${idx}" -u "$SERVICE_NAME")"
        assert_in "invocation ${i} ${invocation}" "$(journalctl --no-hostname -n 1 -t bash --invocation="${invocation}")"
    done
