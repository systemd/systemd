#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# shellcheck disable=SC2016
set -eux
set -o pipefail

# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh

MACHINE_ID="$(</etc/machine-id)"
SYSLOG_ID="$(systemd-id128 new)"

write_to_journal() {
    local service="test-${RANDOM}.service"

    systemd-run -q --wait -u "$service" bash -c "echo service=$service invocation=\$INVOCATION_ID; journalctl --sync"
    echo "$service"
}

verify_journals() {
    local service="${1:?}"
    local expected_storage="${2:?}"

    local run_expected var_expected
    if [[ "$expected_storage" == runtime ]]; then
        run_expected=0
        var_expected=1
    elif [[ "$expected_storage" == persistent ]]; then
        run_expected=1
        var_expected=0
    else
        echo "unexpected storage: $expected_storage"
        exit 1
    fi

    assert_rc "$run_expected" journalctl -q -D "/run/log/journal/$MACHINE_ID/" -u "$service" --grep "service=$service"
    assert_rc "$var_expected" journalctl -q -D "/var/log/journal/$MACHINE_ID/" -u "$service" --grep "service=$service"
}

get_num_archived_journals() {
    local prefix=${1:?}

    find "/$prefix/log/journal/$MACHINE_ID/" -type f -name "system@*.journal" | wc -l
}

cleanup() {
    set +e
    rm -rf /run/systemd/journald.conf.d
    systemctl reload systemd-journald.service
}

trap cleanup EXIT ERR INT TERM

mkdir -p /run/systemd/journald.conf.d
cat <<EOF >/run/systemd/journald.conf.d/reload.conf
[Journal]
Storage=persistent
EOF
systemctl restart systemd-journald.service

: "Add entries in system."
journalctl --flush
VAL1=$(write_to_journal)
verify_journals "$VAL1" persistent

: "Reload journald (persistent->persistent)"
systemctl reload systemd-journald.service

: "Reload should persist persistent journal."
verify_journals "$VAL1" persistent

: "Add entries in runtime"
journalctl --relinquish
VAL2=$(write_to_journal)
verify_journals "$VAL2" runtime

: "Reload journald after relinquish (persistent->persistent)"
systemctl reload systemd-journald.service

: "System journal entries should stay in system journal, runtime in runtime."
verify_journals "$VAL1" persistent
verify_journals "$VAL2" runtime

: "Write new message and confirm it's written to runtime."
VAL=$(write_to_journal)
verify_journals "$VAL" runtime

: "Flush and confirm that messages are written to system."
journalctl --flush
VAL=$(write_to_journal)
verify_journals "$VAL" persistent

# Test persistent->volatile
cat <<EOF >/run/systemd/journald.conf.d/reload.conf
[Journal]
Storage=volatile
EOF

: "Confirm old message exists where it was written to persistent journal."
systemctl reload systemd-journald.service
verify_journals "$VAL" persistent

: "Confirm that new message is written to runtime journal."
VAL=$(write_to_journal)
verify_journals "$VAL" runtime

: "Test volatile works and logs are NOT getting written to system journal despite flush."
journalctl --flush
VAL=$(write_to_journal)
verify_journals "$VAL" runtime

: "Disable compression"
cat <<EOF >/run/systemd/journald.conf.d/reload.conf
[Journal]
Storage=volatile
Compress=no
EOF
systemctl reload systemd-journald.service

: "write 2MB of data to runtime journal"
set +x
dd if=/dev/urandom bs=1M count=2 | base64 | systemd-cat -t "$SYSLOG_ID"
set -x
journalctl --sync
journalctl --rotate

ls -l "/run/log/journal/$MACHINE_ID"

max_size=$((1 * 1024 * 1024))
total_size=$(du -sb "/run/log/journal/$MACHINE_ID" | cut -f1)
if (( total_size < max_size )); then
    echo "ERROR: runtime journal size is smaller than 1MB."
    exit 1
fi

: "Reload with RuntimeMaxUse=1M."
cat <<EOF >/run/systemd/journald.conf.d/reload.conf
[Journal]
Storage=volatile
RuntimeMaxUse=1M
EOF
systemctl reload systemd-journald.service

ls -l "/run/log/journal/$MACHINE_ID"

: "Confirm that runtime journal size shrunk to <= 1MB."
total_size=$(du -sb "/run/log/journal/$MACHINE_ID" | cut -f1)
num_archived_journals=$(get_num_archived_journals run)
if (( total_size > max_size )) && (( num_archived_journals > 0 )); then
    echo "ERROR: Journal size exceeds RuntimeMaxUse= limit and exists archived journals."
    exit 1
fi

: "Write a message to runtime journal"
VAL=$(write_to_journal)
verify_journals "$VAL" runtime

: "Reload volatile->persistent"
cat <<EOF >/run/systemd/journald.conf.d/reload.conf
[Journal]
Storage=persistent
EOF
systemctl reload systemd-journald.service

: "Confirm that previous message is still in runtime journal."
verify_journals "$VAL" runtime

: "Confirm that new messages are written to runtime journal."
VAL=$(write_to_journal)
verify_journals "$VAL" runtime

: "Confirm that flushing writes to system journal."
journalctl --flush
verify_journals "$VAL" persistent

: "Disable compression"
cat <<EOF >/run/systemd/journald.conf.d/reload.conf
[Journal]
Storage=persistent
Compress=no
EOF
systemctl reload systemd-journald.service

: "Write 2MB of data to volatile journal"
set +x
dd if=/dev/urandom bs=1M count=2 | base64 | systemd-cat -t "$SYSLOG_ID"
set -x
journalctl --sync

max_size=$((1 * 1024 * 1024))
total_size=$(du -sb "/var/log/journal/$MACHINE_ID" | cut -f1)
if (( total_size < max_size )); then
    echo "ERROR: volatile journal size is smaller than 1MB."
    exit 1
fi

: "Creating archive files."
limit_var_journals=3
for (( i = 0; i < limit_var_journals; i++ )); do
    write_to_journal
    journalctl --rotate
done

ls -l "/var/log/journal/$MACHINE_ID"

num_archived_journals=$(get_num_archived_journals var)
if (( num_archived_journals < limit_var_journals )); then
    echo "ERROR: Number of archived system journal files is ${num_archived_journals} < ${limit_var_journals}."
    exit 1
fi

: "Reload with less SystemMaxUse= and SystemMaxFiles=."
cat <<EOF >/run/systemd/journald.conf.d/reload.conf
[Journal]
Storage=persistent
RuntimeMaxUse=2M
SystemMaxUse=1M
SystemMaxFiles=3
EOF
systemctl reload systemd-journald.service

ls -l "/var/log/journal/$MACHINE_ID"

: "Check number of the system journal files"
num_archived_journals=$(get_num_archived_journals var)
if (( num_archived_journals >= limit_var_journals )); then
    echo "ERROR: Number of system journal files is ${num_archived_journals} >= ${limit_var_journals}."
    exit 1
fi

: "Check the size of the system journal"
total_size=$(du -sb "/var/log/journal/$MACHINE_ID" | cut -f1)
if (( total_size > max_size )) && (( num_archived_journals > 0)); then
    echo "ERROR: Journal size exceeds SystemMaxUse limit and there exist archived journals."
    exit 1
fi
