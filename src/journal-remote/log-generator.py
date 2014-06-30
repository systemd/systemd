#!/usr/bin/python
from __future__ import print_function
import sys
import argparse

PARSER = argparse.ArgumentParser()
PARSER.add_argument('n', type=int)
PARSER.add_argument('--dots', action='store_true')
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

m  = 0x198603b12d7
realtime_ts = 1404101101501873
monotonic_ts = 1753961140951
source_realtime_ts = 1404101101483516
priority = 3
facility = 6

src = open('/dev/urandom', 'rb')

bytes = 0

for i in range(OPTIONS.n):
    message = repr(src.read(2000))
    data = repr(src.read(4000))

    entry = template.format(m=m,
                            realtime_ts=realtime_ts,
                            monotonic_ts=monotonic_ts,
                            source_realtime_ts=source_realtime_ts,
                            priority=priority,
                            facility=facility,
                            message=message,
                            data=data)
    m += 1
    realtime_ts += 1
    monotonic_ts += 1
    source_realtime_ts += 1

    bytes += len(entry)

    print(entry)

    if OPTIONS.dots:
        print('.', file=sys.stderr, end='', flush=True)

if OPTIONS.dots:
        print(file=sys.stderr)
print('Wrote {} bytes'.format(bytes), file=sys.stderr)
