#!/usr/bin/python3
# SPDX-License-Identifier: LGPL-2.1-or-later

import subprocess
import syslog

if __name__ == '__main__':
    syslog.openlog(ident="logs-filtering", logoption=syslog.LOG_PID)
    syslog.syslog(syslog.LOG_NOTICE, "Logging from the service, and ~more~ foo bar")

    subprocess.check_output(
        ['journalctl', '--sync'],
        stdin=subprocess.DEVNULL,
        text=True)
