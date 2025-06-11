#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# shellcheck disable=SC2016
set -eux
set -o pipefail

MACHINE_ID="$(</etc/machine-id)"
TEST_MSG_PREFIX="JOURNAL-RELOAD TEST"
SYSLOG_ID="$(systemd-id128 new)"

write_to_journal() {
    local rand_val

    rand_val=$(head /dev/urandom | tr -dc A-Za-z0-9 | head -c 14)
    echo "$TEST_MSG_PREFIX $rand_val" | systemd-cat -t "$SYSLOG_ID"
    journalctl --sync

    echo "$rand_val"
}

verify_journal() {
    local msg="$1"
    local entry_expected="$2"
    local test_name="$3"
    local journal_path_prefix="$4"

    local path="/$journal_path_prefix/log/journal/$MACHINE_ID/system.journal"

    if [ ! -e "$path" ] || ! grep -Fxq "MESSAGE=$TEST_MSG_PREFIX $msg" "$path"; then
        if [ "$entry_expected" == true ]; then
            echo "$test_name ERROR: Message not present in $journal_path_prefix journal"
            cleanup
            exit 1
        fi
    else
        if [ "$entry_expected" == false ]; then
            echo "$test_name ERROR: Message present in $journal_path_prefix journal"
            cleanup
            exit 1
        fi
    fi
}

verify_journals() {
    local msg="$1"
    local runtime_expected="$2"
    local system_expected="$3"
    local test_name="$4"

    local failed=false

    verify_journal "$msg" "$runtime_expected" "$test_name" "run"
    if ! verify_journal "$msg" "$runtime_expected" "$test_name" "run"; then
        failed=true
    fi

    if ! verify_journal "$msg" "$system_expected" "$test_name" "var"; then
        failed=true
    fi

    if [ "$failed" == true ]; then
        cleanup
        exit 1
    fi
}

get_num_archived_journals() {
    local journal_path_prefix="$1"

    local journal_dir="/$journal_path_prefix/log/journal/$MACHINE_ID/"
    num_journal_files=$(find "$journal_dir" -type f -name "*.journal" ! -name "system.journal" | wc -l)

    echo "$num_journal_files"
}

cleanup() {
    rm /run/systemd/journald.conf.d/reload.conf
    systemctl log-level "$SAVED_LOG_LEVEL"
    journalctl --vacuum-size=1M
    systemctl daemon-reload
    systemctl reload systemd-journald.service
}

# Start clean slate.
mkdir -p /run/systemd/journald.conf.d
cat <<EOF >/run/systemd/journald.conf.d/reload.conf
[Journal]
Storage=persistent
EOF

systemctl daemon-reload
systemctl restart systemd-journald.service

# Add entries in system.
journalctl --flush
rand_val1=$(write_to_journal)
verify_journals "$rand_val1" false true "Confirming test setup after flush."

# Reload journald (persistent->persistent)
systemctl reload systemd-journald.service

# Reload should persist persistent journal.
verify_journals "$rand_val1" false true "Persistent->Persistent System Reload: "

rand_val1=$(write_to_journal)
verify_journals "$rand_val1" false true "Persistent->Persistent System Post-Reload: "

# Add entries in runtime
journalctl --relinquish
rand_val2=$(write_to_journal)
verify_journals "$rand_val2" true false "Confirming test setup after relinquish."

# Reload journald (persistent->persistent)
systemctl reload systemd-journald.service

# System journal entries should stay in system journal, runtime in runtime.
verify_journals "$rand_val1" false true "Persistent->Persistent Runtime Reload 1: "
verify_journals "$rand_val2" true false "Persistent->Persistent Runtime Reload 2: "

# Write new message and confirm it's written to runtime.
rand_val=$(write_to_journal)
verify_journals "$rand_val" true false "Persistent->Persistent New Message After Reload: "

# Flush and confirm that messages are written to system.
journalctl --flush
rand_val=$(write_to_journal)
verify_journals "$rand_val" false true "Persistent->Volatile New Message Before Reload: "

# Test persistent->volatile
cat <<EOF >/run/systemd/journald.conf.d/reload.conf
[Journal]
Storage=volatile
EOF

# Confirm old message exists where it was written to (storage->storage).
systemctl reload systemd-journald.service
verify_journals "$rand_val" false true "Persistent->Volatile Reload: "

# Confirm that messages are written to only runtime journal.
rand_val=$(write_to_journal)
verify_journals "$rand_val" true false "Persistent->Volatile New Message After Reload: "

# Test volatile works and logs are NOT getting written to system journal despite flush.
journalctl --flush
rand_val=$(write_to_journal)
verify_journals "$rand_val" true false "Persistent->Volatile New Message After Flush: "

# Test that the new limits (e.g., RuntimeMaxUse) take effect on reload.
# Write 1M of data to runtime journal
max_size=$((1 * 1024 * 1024))
set +x
dd if=/dev/urandom bs=1M count=5 | base64 | systemd-cat -t "$SYSLOG_ID"
set -x
journalctl --vacuum-size=2M

total_size=$(du -sb "/run/log/journal/$MACHINE_ID" | cut -f1)
if [ "$total_size" -lt "$max_size" ]; then
    echo "ERROR: Journal size does not exceed RuntimeMaxUse limit"
    cleanup
    exit 1
fi

# Reload with RuntimeMaxUse=1M.
cat <<EOF >/run/systemd/journald.conf.d/reload.conf
[Journal]
Storage=volatile
RuntimeMaxUse=1M
EOF

# systemctl daemon-reload
systemctl reload systemd-journald.service

sleep 10 # Wait for RuntimeMaxUse change to take effect.

# Confirm that runtime journal size shrunk to <=1M.
total_size=$(du -sb "/run/log/journal/$MACHINE_ID" | cut -f1)
if [ "$total_size" -gt "$max_size" ]; then
    echo "ERROR: Journal size exceeds RuntimeMaxUse limit"
    cleanup
    exit 1
fi

# Prepare for volatile->persistent by getting rid of runtime limit. Otherwise, it will not write.
cat <<EOF >/run/systemd/journald.conf.d/reload.conf
[Journal]
Storage=volatile
EOF
systemctl daemon-reload
systemctl reload systemd-journald.service
sleep 5 # Wait for RuntimeMaxUse change to take effect.

rand_val=$(write_to_journal)
verify_journals "$rand_val" true false "Volatile->Persistent New Message Before Reload: "

# Reload volatile->persistent
cat <<EOF >/run/systemd/journald.conf.d/reload.conf
[Journal]
Storage=persistent
EOF

systemctl reload systemd-journald.service

# Confirm that previous message is still in runtime journal.
verify_journals "$rand_val" true false "Volatile->Persistent Reload: "

# Confirm that new messages are written to runtime journal.
rand_val=$(write_to_journal)
verify_journals "$rand_val" true false "Volatile->Persistent New Message After Reload: "

# Confirm that flushing writes to system journal.
journalctl --flush
verify_journals "$rand_val" false true "Volatile->Persistent New Message After Flush: "

set +x
dd if=/dev/urandom bs=1M count=5 | base64 | systemd-cat -t "$SYSLOG_ID"
set -x

max_size=$((2 * 1024 * 1024))
total_size=$(du -sb "/var/log/journal/$MACHINE_ID" | cut -f1)
if [ "$total_size" -lt "$max_size" ]; then
    echo "ERROR: Journal size does not exceed SystemMaxUse limit"
    cleanup
    exit 1
fi

# Ensure reloading without limit does not interfere with SystemMaxUse test.
systemctl reload systemd-journald.service
total_size=$(du -sb "/var/log/journal/$MACHINE_ID" | cut -f1)
if [ "$total_size" -lt "$max_size" ]; then
    echo "ERROR: Journal size does not exceed SystemMaxUse limit"
    cleanup
    exit 1
fi

# Write to storage to prepare for SystemMaxFiles test.
journalctl --flush

num_var_journals=$(get_num_archived_journals "var")
limit_var_journals=3
if [ "$num_var_journals" -lt "$limit_var_journals" ]; then
    echo "Creating archive files."
    for (( i=0; i<=num_var_journals; i++ ))
    do
        echo "$TEST_MSG_PREFIX" | systemd-cat -t "$SYSLOG_ID"
        journalctl --rotate
    done

    num_var_journals=$(get_num_archived_journals "var")
    if [ "$num_var_journals" -lt "$limit_var_journals" ]; then
        echo "ERROR: Number of journal files in /var/log/journal/$MACHINE_ID/ is less than $limit_var_journals"
        cleanup
        exit 1
    fi
fi

# Reload with less SystemMaxUse and SystemMaxFiles.
cat <<EOF >/run/systemd/journald.conf.d/reload.conf
[Journal]
Storage=persistent
RuntimeMaxUse=2M
SystemMaxUse=2M
SystemMaxFiles=3
EOF

systemctl daemon-reload
systemctl reload systemd-journald.service

# New system journal needs to be created with the new configuration for change to take effect.
journalctl --flush

# Check SystemMaxFiles
num_var_journals=$(get_num_archived_journals "var")
if [ "$num_var_journals" -gt "$limit_var_journals" ]; then
    echo "ERROR: Number of journal files in /var/log/journal/$MACHINE_ID/ is greater than $limit_var_journals"
    cleanup
    exit 1
fi

sleep 5

# Check SystemMaxUse
total_size=$(du -sb "/var/log/journal/$MACHINE_ID" | cut -f1)
if [ "$total_size" -gt "$max_size" ]; then
    echo "ERROR: Journal size exceeds SystemMaxUse limit"
    cleanup
    exit 1
fi

rm /run/systemd/journald.conf.d/reload.conf
journalctl --vacuum-size=1M
systemctl daemon-reload
systemctl reload systemd-journald.service