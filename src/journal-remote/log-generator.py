#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later

import sys
import argparse

PARSER = argparse.ArgumentParser()
PARSER.add_argument('n', type=int)
PARSER.add_argument('--dots', action='store_true')
PARSER.add_argument('-m', '--message-size', type=int, default=200)
PARSER.add_argument('-d', '--data-size', type=int, default=4000)
PARSER.add_argument('--data-type', choices={'random', 'simple'})
OPTIONS = PARSER.parse_args()

template = """\
__CURSOR=s=6863c726210b4560b7048889d8ada5c5;i=3e931;b=f446871715504074bf7049ef0718fa93;m={m:x};t=4fd05c
__REALTIME_TIMESTAMP={realtime_ts}
__MONOTONIC_TIMESTAMP={monotonic_ts}
_BOOT_ID=f446871715504074bf7049ef0718fa93
_TRANSPORT=syslog
PRIORITY={priority}
SYSLOG_FACILITY={facility}
SYSLOG_IDENTIFIER=/USR/SBIN/CRON
MESSAGE={message}
_UID=0
_GID=0
_MACHINE_ID=69121ca41d12c1b69a7960174c27b618
_HOSTNAME=hostname
SYSLOG_PID=25721
_PID=25721
_SOURCE_REALTIME_TIMESTAMP={source_realtime_ts}
DATA={data}
"""

priority = 3
facility = 6

src = open('/dev/urandom', 'rb')

bytes = 0
counter = 0

for i in range(OPTIONS.n):
    message = src.read(OPTIONS.message_size)
    message = repr(message)[2:-1]

    if OPTIONS.data_type == 'random':
        data = repr(src.read(OPTIONS.data_size))
    else:
        # keep the pattern non-repeating so we get a different blob every time
        data = '{:0{}}'.format(counter, OPTIONS.data_size)
        counter += 1

    entry = template.format(m=0x198603b12d7 + i,
                            realtime_ts=1404101101501873 + i,
                            monotonic_ts=1753961140951 + i,
                            source_realtime_ts=1404101101483516 + i,
                            priority=priority,
                            facility=facility,
                            message=message,
                            data=data)

    bytes += len(entry)

    print(entry)

    if OPTIONS.dots:
        print('.', file=sys.stderr, end='', flush=True)

if OPTIONS.dots:
    print(file=sys.stderr)
print('Wrote {} bytes'.format(bytes), file=sys.stderr)
