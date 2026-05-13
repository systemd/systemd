#!/usr/bin/python3
# SPDX-License-Identifier: LGPL-2.1-or-later
# pylint: disable=broad-except

import argparse
import logging
import signal
import sys
import time

import pexpect


def run(args):
    ret = 1
    logger = logging.getLogger("test-shutdown")
    logfile = None

    if args.logfile:
        logger.debug("Logging pexpect IOs to %s", args.logfile)
        logfile = open(args.logfile, 'w')
    elif args.verbose:
        logfile = sys.stdout

    logger.info("spawning test")
    console = pexpect.spawn(args.command, args.arg, logfile=logfile, env={
            "TERM": "dumb",
        }, encoding='utf-8', timeout=60)

    logger.debug("child pid %d", console.pid)

    try:
        logger.info("waiting for login prompt")
        console.expect('H login: ', 10)

        logger.info("log in and start screen")
        console.sendline('root')
        console.expect('bash.*# ', 10)
        console.sendline('screen')
        console.expect('screen0 ', 10)
        console.sendcontrol('a')
        console.send('c')
        console.expect('screen1 ', 10)

        logger.info('wait for the machine to fully boot')
        console.sendline('systemctl is-system-running --wait')
        console.expect(r'\b(running|degraded)\b', 60)

#        console.interact()

        console.sendline('tty')
        console.expect(r'/dev/(pts/\d+)')
        pty = console.match.group(1)
        logger.info("window 1 at tty %s", pty)

        logger.info("schedule reboot")
        console.sendline('shutdown -r')
        console.expect("Reboot scheduled for (?P<date>.*), use 'shutdown -c' to cancel", 2)
        date = console.match.group('date')
        logger.info("reboot scheduled for %s", date)

        console.sendcontrol('a')
        console.send('0')
        logger.info("verify broadcast message")
        console.expect(f'Broadcast message from root@H on {pty}', 2)
        console.expect(f'The system will reboot at {date}', 2)

        logger.info("check show output")
        console.sendline('shutdown --show')
        console.expect(f"Reboot scheduled for {date}, use 'shutdown -c' to cancel", 2)

        logger.info("cancel shutdown")
        console.sendline('shutdown -c')
        console.sendcontrol('a')
        console.send('1')
        console.expect('System shutdown has been cancelled', 2)

        logger.info("call for reboot")
        console.sendline('sleep 10; shutdown -r now')
        console.sendcontrol('a')
        console.send('0')
        console.expect("The system will reboot now!", 12)

        logger.info("waiting for reboot")

        console.expect('H login: ', 60)
        console.sendline('root')
        console.expect('bash.*# ', 10)

        console.sendline('> /testok')

        logger.info("power off")
        console.sendline('poweroff')

        logger.info("expect termination now")
        console.expect(pexpect.EOF)

        ret = 0
    except Exception as e:
        logger.error(e)
        logger.info("killing child pid %d", console.pid)

        # Ask systemd-nspawn to stop and release the container's resources properly.
        console.kill(signal.SIGTERM)

        for _ in range(10):
            if not console.isalive():
                break

            time.sleep(1)
        else:
            # We haven't exited the loop early, so check if the process is
            # still alive - if so, force-kill it.
            if console.isalive():
                console.terminate(force=True)

    return ret

def main():
    parser = argparse.ArgumentParser(description='test logind shutdown feature')
    parser.add_argument("-v", "--verbose", action="store_true", help="verbose")
    parser.add_argument("--logfile", metavar='FILE', help="Save all test input/output to the given path")
    parser.add_argument("command", help="command to run")
    parser.add_argument("arg", nargs='*', help="args for command")

    args = parser.parse_args()

    if args.verbose:
        level = logging.DEBUG
    else:
        level = logging.INFO

    logging.basicConfig(level=level)

    return run(args)

if __name__ == '__main__':
    sys.exit(main())

# vim: sw=4 et
