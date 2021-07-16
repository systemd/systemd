#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later

import pexpect
import re
import sys


def run() -> None:
    p = pexpect.spawnu(" ".join(sys.argv[1:]), logfile=sys.stdout, timeout=300)

    # distro-independent root prompt
    p.expect(re.compile("~[^#]{0,3}#"))
    p.sendline("systemctl poweroff")

    p.expect(pexpect.EOF)


try:
    run()
except pexpect.EOF:
    print("UNEXPECTED EOF")
    sys.exit(1)
except pexpect.TIMEOUT:
    print("TIMED OUT")
    sys.exit(1)
