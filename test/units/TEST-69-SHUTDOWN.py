#!/usr/bin/python3
# SPDX-License-Identifier: LGPL-2.1-or-later
# pylint: disable=broad-except

import logging
import sys

import pexpect


def main():
    # TODO: drop once https://bugs.debian.org/1075733 is fixed
    with open("/usr/lib/os-release") as f:
        for line in f:
            if line.startswith("ID="):
                if "debian" in line or "ubuntu" in line:
                    sys.exit(77)

    logger = logging.getLogger("test-shutdown")

    consoles = []
    for _ in range(2):
        # Use script to allocate a separate pseudo tty to run the login shell in.
        console = pexpect.spawn(
            "script", ["--quiet", "--return", "--flush", "--command", "login -f root", "/dev/null"],
            logfile=sys.stdout,
            env={"TERM": "dumb"},
            encoding="utf-8",
            timeout=60,
        )

        logger.info("waiting for login prompt")
        console.expect(".*# ", 10)

        consoles += [console]

    consoles[1].sendline("tty")
    consoles[1].expect(r"/dev/(pts/\d+)")
    pty = console.match.group(1)
    logger.info("window 1 at tty %s", pty)

    logger.info("schedule reboot")
    consoles[1].sendline("shutdown -r")
    consoles[1].expect("Reboot scheduled for (?P<date>.*), use 'shutdown -c' to cancel", 2)
    date = consoles[1].match.group("date")
    logger.info("reboot scheduled for %s", date)

    logger.info("verify broadcast message")
    consoles[0].expect(f"Broadcast message from root@H on {pty}", 2)
    consoles[0].expect(f"The system will reboot at {date}!", 2)

    logger.info("check show output")
    consoles[1].sendline("shutdown --show")
    consoles[1].expect(f"Reboot scheduled for {date}, use 'shutdown -c' to cancel", 2)

    logger.info("cancel shutdown")
    consoles[1].sendline("shutdown -c")
    consoles[0].expect("System shutdown has been cancelled", 2)

    consoles[0].sendline("> /testok")

if __name__ == "__main__":
    main()

# vim: sw=4 et
