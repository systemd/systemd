#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later

set -eux
set -o pipefail

systemd-analyze log-level debug
systemd-analyze log-target journal

# Idea is this:
#    1. we start testsuite-57-success.service
#    2. which through OnSuccess= starts testsuite-57-fail.service,
#    3. which through OnFailure= starts testsuite-57-uphold.service,
#    4. which through Uphold= starts/keeps testsuite-57-short-lived.service running,
#    5. which will sleep 1s when invoked, and on the 5th invocation send us a SIGUSR1
#    6. once we got that we finish cleanly

sigusr1=0
trap sigusr1=1 SIGUSR1

systemctl start testsuite-57-success.service

while [ "$sigusr1" -eq 0 ] ; do
    sleep .5
done

systemctl stop testsuite-57-uphold.service

# Idea is this:
#    1. we start testsuite-57-prop-stop-one.service
#    2. which through Wants=/After= pulls in testsuite-57-prop-stop-two.service as well
#    3. testsuite-57-prop-stop-one.service then sleeps indefinitely
#    4. testsuite-57-prop-stop-two.service sleeps a short time and exits
#    5. the StopPropagatedFrom= dependency between the two should ensure *both* will exit as result
#    6. an ExecStopPost= line on testsuite-57-prop-stop-one.service will send us a SIGUSR2
#    7. once we got that we finish cleanly

sigusr2=0
trap sigusr2=1 SIGUSR2

systemctl start testsuite-57-prop-stop-one.service

while [ "$sigusr2" -eq 0 ] ; do
    sleep .5
done


# Idea is this:
#    1. we start testsuite-57-binds-to.service
#    2. which through BindsTo=/After= pulls in testsuite-57-bound-by.service as well
#    3. testsuite-57-bound-by.service suddenly dies
#    4. testsuite-57-binds-to.service should then also be pulled down (it otherwise just hangs)
#    6. an ExecStopPost= line on testsuite-57-binds-to.service will send us a SIGRTMIN1+1
#    7. once we got that we finish cleanly

sigrtmin1=0
trap sigrtmin1=1 SIGRTMIN+1

systemctl start testsuite-57-binds-to.service

while [ "$sigrtmin1" -eq 0 ] ; do
    sleep .5
done

systemd-analyze log-level info

echo OK >/testok

exit 0
