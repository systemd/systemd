#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later

set -eux
set -o pipefail

# Test OnSuccess= + Uphold= + PropagatesStopTo= + BindsTo=

systemd-analyze log-level debug
systemd-analyze log-target journal

# Idea is this:
#    1. we start TEST-23-UNIT-FILE-success.service
#    2. which through OnSuccess= starts TEST-23-UNIT-FILE-fail.service,
#    3. which through OnFailure= starts TEST-23-UNIT-FILE-uphold.service,
#    4. which through Uphold= starts/keeps TEST-23-UNIT-FILE-short-lived.service running,
#    5. which will sleep 1s when invoked, and on the 5th invocation send us a SIGUSR1
#    6. once we got that we finish cleanly

sigusr1=0
trap sigusr1=1 SIGUSR1

trap -p SIGUSR1

systemctl start TEST-23-UNIT-FILE-success.service

while [ "$sigusr1" -eq 0 ] ; do
    sleep .5
done

systemctl stop TEST-23-UNIT-FILE-uphold.service

systemctl enable TEST-23-UNIT-FILE-upheldby-install.service

# Idea is this:
#    1. we start TEST-23-UNIT-FILE-retry-uphold.service
#    2. which through Uphold= starts TEST-23-UNIT-FILE-retry-upheld.service
#    3. which through Requires= starts TEST-23-UNIT-FILE-retry-fail.service
#    4. which fails as /tmp/TEST-23-UNIT-FILE-retry-fail does not exist, so TEST-23-UNIT-FILE-retry-upheld.service
#       is no longer restarted
#    5. we create /tmp/TEST-23-UNIT-FILE-retry-fail
#    6. now TEST-23-UNIT-FILE-retry-upheld.service will be restarted since upheld, and its dependency will
#       be satisfied

rm -f /tmp/TEST-23-UNIT-FILE-retry-fail
systemctl start TEST-23-UNIT-FILE-retry-uphold.service
systemctl is-active TEST-23-UNIT-FILE-upheldby-install.service

until systemctl is-failed TEST-23-UNIT-FILE-retry-fail.service ; do
    sleep .5
done

(! systemctl is-active TEST-23-UNIT-FILE-retry-upheld.service)

touch /tmp/TEST-23-UNIT-FILE-retry-fail

until systemctl is-active TEST-23-UNIT-FILE-retry-upheld.service ; do
    sleep .5
done

systemctl stop TEST-23-UNIT-FILE-retry-uphold.service TEST-23-UNIT-FILE-retry-fail.service TEST-23-UNIT-FILE-retry-upheld.service

# Idea is this:
#    1. we start TEST-23-UNIT-FILE-prop-stop-one.service
#    2. which through Wants=/After= pulls in TEST-23-UNIT-FILE-prop-stop-two.service as well
#    3. TEST-23-UNIT-FILE-prop-stop-one.service then sleeps indefinitely
#    4. TEST-23-UNIT-FILE-prop-stop-two.service sleeps a short time and exits
#    5. the StopPropagatedFrom= dependency between the two should ensure *both* will exit as result
#    6. an ExecStopPost= line on TEST-23-UNIT-FILE-prop-stop-one.service will send us a SIGUSR2
#    7. once we got that we finish cleanly

sigusr2=0
trap sigusr2=1 SIGUSR2

systemctl start TEST-23-UNIT-FILE-prop-stop-one.service

while [ "$sigusr2" -eq 0 ] ; do
    sleep .5
done


# Idea is this:
#    1. we start TEST-23-UNIT-FILE-binds-to.service
#    2. which through BindsTo=/After= pulls in TEST-23-UNIT-FILE-bound-by.service as well
#    3. TEST-23-UNIT-FILE-bound-by.service suddenly dies
#    4. TEST-23-UNIT-FILE-binds-to.service should then also be pulled down (it otherwise just hangs)
#    6. an ExecStopPost= line on TEST-23-UNIT-FILE-binds-to.service will send us a SIGRTMIN1+1
#    7. once we got that we finish cleanly

sigrtmin1=0
trap sigrtmin1=1 SIGRTMIN+1

systemctl start TEST-23-UNIT-FILE-binds-to.service

while [ "$sigrtmin1" -eq 0 ] ; do
    sleep .5
done

systemd-analyze log-level info
