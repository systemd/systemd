#!/usr/bin/python3
# SPDX-License-Identifier: LGPL-2.1-or-later
#

import argparse
import logging
import sys

import pexpect


def run(args):

    ret = 1
    logger = logging.getLogger("test-shutdown")

    logger.info("spawning test")
    console = pexpect.spawn(args.command, args.arg, env={
            "TERM": "linux",
        }, encoding='utf-8', timeout=30)

    if args.verbose:
        console.logfile = sys.stdout

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

#        console.interact()

        console.sendline('tty')
        console.expect(r'/dev/(pts/\d+)')
        pty = console.match.group(1)
        logger.info("window 1 at line %s", pty)

        logger.info("schedule reboot")
        console.sendline('shutdown -r')
        console.expect("Reboot scheduled for (?P<date>.*), use 'shutdown -c' to cancel", 2)
        date = console.match.group('date')
        logger.info("reboot scheduled for %s", date)

        console.sendcontrol('a')
        console.send('0')
        logger.info("verify broadcast message")
        console.expect('Broadcast message from root@H on %s' % pty, 2)
        console.expect('The system will reboot at %s' % date, 2)

        logger.info("check show output")
        console.sendline('shutdown --show')
        console.expect("Reboot scheduled for %s, use 'shutdown -c' to cancel" % date, 2)

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

        console.expect('H login: ', 30)
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
        console.terminate()

    return ret

def main():
    parser = argparse.ArgumentParser(description='test logind shutdown feature')
    parser.add_argument("-v", "--verbose", action="store_true", help="verbose")
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
