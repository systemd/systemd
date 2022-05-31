#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later

set -eux
set -o pipefail

setup_cron() {
    # Setup test user and cron
    useradd test
    echo "test" | passwd --stdin test
    crond -s -n &
    # Install crontab for the test user that runs sleep every minute. But let's sleep for
    # 65 seconds to make sure there is overlap between two consecutive runs, i.e. we have
    # always a cron session running.
    crontab -u test - <<EOF
RANDOM_DELAY=0
* * * * * /bin/sleep 65
EOF
    # Let's wait one interval to make sure that cron session is started already
    sleep 65
}

teardown_cron() {
    set +e

    pkill -u "$(id -u test)"
    pkill crond
    crontab -r -u test
    userdel -r test
}

test_no_user_instance_for_cron() {
    # We actually want to run error code path in case any of the needed binaries are not present.
    # shellcheck disable=SC2015
    command -v passwd && command -v useradd && command -v userdel && command -v crond && command -v crontab || {
        echo >&2 "Missing support for running tasks via crond under non-root user."
        return 1
    }

    trap teardown_cron EXIT
    setup_cron

    [[ $(loginctl --no-legend list-sessions | grep -c test) -ge 1 ]] || {
        echo >&2 '"test" user should have at least one session'
        loginctl list-sessions
        return 1
    }

    # Check that all sessions of test users have class=background and no user instance was started
    # the test user.
    while read -r s _; do
        local class

        class=$(loginctl --property Class --value show-session "$s")
        [[  "$class" = "background" ]] || {
            echo >&2 "Session has incorrect class, expected \"background\", got \"$class\"."
            return 1
        }
    done < <(loginctl --no-legend list-sessions | grep test)

    state=$(systemctl --property ActiveState --value show user@"$(id -u test)".service)
    [[ "$state" = "inactive" ]] || {
        echo >&2 "User instance state is unexpected, expected \"inactive\", got \"$state\""
        return 1
    }

    state=$(systemctl --property SubState --value show user@"$(id -u test)".service)
    [[ "$state" = "dead" ]] || {
        echo >&2 "User instance state is unexpected, expected \"dead\", got \"$state\""
        return 1
    }

    return 0
}

: > /failed

test_no_user_instance_for_cron

rm /failed
: > /testok
