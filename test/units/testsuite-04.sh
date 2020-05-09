#!/usr/bin/env bash
set -x
set -e
set -o pipefail

# Test stdout stream

# Skip empty lines
ID=$(journalctl --new-id128 | sed -n 2p)
>/expected
printf $'\n\n\n' | systemd-cat -t "$ID" --level-prefix false
journalctl --sync
journalctl -b -o cat -t "$ID" >/output
cmp /expected /output

ID=$(journalctl --new-id128 | sed -n 2p)
>/expected
printf $'<5>\n<6>\n<7>\n' | systemd-cat -t "$ID" --level-prefix true
journalctl --sync
journalctl -b -o cat -t "$ID" >/output
cmp /expected /output

# Remove trailing spaces
ID=$(journalctl --new-id128 | sed -n 2p)
printf "Trailing spaces\n">/expected
printf $'<5>Trailing spaces \t \n' | systemd-cat -t "$ID" --level-prefix true
journalctl --sync
journalctl -b -o cat -t "$ID" >/output
cmp /expected /output

ID=$(journalctl --new-id128 | sed -n 2p)
printf "Trailing spaces\n">/expected
printf $'Trailing spaces \t \n' | systemd-cat -t "$ID" --level-prefix false
journalctl --sync
journalctl -b -o cat -t "$ID" >/output
cmp /expected /output

# Don't remove leading spaces
ID=$(journalctl --new-id128 | sed -n 2p)
printf $' \t Leading spaces\n'>/expected
printf $'<5> \t Leading spaces\n' | systemd-cat -t "$ID" --level-prefix true
journalctl --sync
journalctl -b -o cat -t "$ID" >/output
cmp /expected /output

ID=$(journalctl --new-id128 | sed -n 2p)
printf $' \t Leading spaces\n'>/expected
printf $' \t Leading spaces\n' | systemd-cat -t "$ID" --level-prefix false
journalctl --sync
journalctl -b -o cat -t "$ID" >/output
cmp /expected /output

# --output-fields restricts output
ID=$(journalctl --new-id128 | sed -n 2p)
printf $'foo' | systemd-cat -t "$ID" --level-prefix false
journalctl --sync
journalctl -b -o export --output-fields=MESSAGE,FOO --output-fields=PRIORITY,MESSAGE -t "$ID" >/output
[[ `grep -c . /output` -eq 6 ]]
grep -q '^__CURSOR=' /output
grep -q '^MESSAGE=foo$' /output
grep -q '^PRIORITY=6$' /output
! grep -q '^FOO=' /output
! grep -q '^SYSLOG_FACILITY=' /output

# `-b all` negates earlier use of -b (-b and -m are otherwise exclusive)
journalctl -b -1 -b all -m > /dev/null

# -b always behaves like -b0
journalctl -q -b-1 -b0 | head -1 > /expected
journalctl -q -b-1 -b  | head -1 > /output
cmp /expected /output
# ... even when another option follows (both of these should fail due to -m)
{ journalctl -ball -b0 -m 2>&1 || :; } | head -1 > /expected
{ journalctl -ball -b  -m 2>&1 || :; } | head -1 > /output
cmp /expected /output

# https://github.com/systemd/systemd/issues/13708
ID=$(systemd-id128 new)
systemd-cat -t "$ID" bash -c 'echo parent; (echo child) & wait' &
PID=$!
wait %%
journalctl --sync
# We can drop this grep when https://github.com/systemd/systemd/issues/13937
# has a fix.
journalctl -b -o export -t "$ID" --output-fields=_PID | grep '^_PID=' >/output
[[ `grep -c . /output` -eq 2 ]]
grep -q "^_PID=$PID" /output
grep -vq "^_PID=$PID" /output

# https://github.com/systemd/systemd/issues/15654
ID=$(journalctl --new-id128 | sed -n 2p)
printf "This will\nusually fail\nand be truncated\n">/expected
systemd-cat -t "$ID" /bin/sh -c 'env echo -n "This will";echo;env echo -n "usually fail";echo;env echo -n "and be truncated";echo;'
journalctl --sync
journalctl -b -o cat -t "$ID" >/output
cmp /expected /output
[[ $(journalctl -b -o cat -t "$ID" --output-fields=_TRANSPORT | grep -Pc "^stdout$") -eq 3 ]]
[[ $(journalctl -b -o cat -t "$ID" --output-fields=_LINE_BREAK | grep -Pc "^pid-change$") -eq 3 ]]
[[ $(journalctl -b -o cat -t "$ID" --output-fields=_PID | sort -u | grep -c "^.*$") -eq 3 ]]
[[ $(journalctl -b -o cat -t "$ID" --output-fields=MESSAGE | grep -Pc "^(This will|usually fail|and be truncated)$") -eq 3 ]]

# Add new tests before here, the journald restarts below
# may make tests flappy.

# Don't lose streams on restart
systemctl start forever-print-hola
sleep 3
systemctl restart systemd-journald
sleep 3
systemctl stop forever-print-hola
[[ ! -f "/i-lose-my-logs" ]]

# https://github.com/systemd/systemd/issues/4408
rm -f /i-lose-my-logs
systemctl start forever-print-hola
sleep 3
systemctl kill --signal=SIGKILL systemd-journald
sleep 3
[[ ! -f "/i-lose-my-logs" ]]

# https://github.com/systemd/systemd/issues/15528
journalctl --follow --file=/var/log/journal/*/* | head -n1 || [[ $? -eq 1 ]]

touch /testok
