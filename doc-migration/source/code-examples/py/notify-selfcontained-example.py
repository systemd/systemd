#!/usr/bin/env python3
# SPDX-License-Identifier: MIT-0
#
# Implement the systemd notify protocol without external dependencies.
# Supports both readiness notification on startup and on reloading,
# according to the protocol defined at:
# https://www.freedesktop.org/software/systemd/man/latest/sd_notify.html
# This protocol is guaranteed to be stable as per:
# https://systemd.io/PORTABILITY_AND_STABILITY/

import errno
import os
import signal
import socket
import sys
import time

reloading = False
terminating = False

def notify(message):
    if not message:
        raise ValueError("notify() requires a message")

    socket_path = os.environ.get("NOTIFY_SOCKET")
    if not socket_path:
        return

    if socket_path[0] not in ("/", "@"):
        raise OSError(errno.EAFNOSUPPORT, "Unsupported socket type")

    # Handle abstract socket.
    if socket_path[0] == "@":
        socket_path = "\0" + socket_path[1:]

    with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM | socket.SOCK_CLOEXEC) as sock:
        sock.connect(socket_path)
        sock.sendall(message)

def notify_ready():
    notify(b"READY=1")

def notify_reloading():
    microsecs = time.clock_gettime_ns(time.CLOCK_MONOTONIC) // 1000
    notify(f"RELOADING=1\nMONOTONIC_USEC={microsecs}".encode())

def notify_stopping():
    notify(b"STOPPING=1")

def reload(signum, frame):
    global reloading
    reloading = True

def terminate(signum, frame):
    global terminating
    terminating = True

def main():
    print("Doing initial setup")
    global reloading, terminating

    # Set up signal handlers.
    print("Setting up signal handlers")
    signal.signal(signal.SIGHUP, reload)
    signal.signal(signal.SIGINT, terminate)
    signal.signal(signal.SIGTERM, terminate)

    # Do any other setup work here.

    # Once all setup is done, signal readiness.
    print("Done setting up")
    notify_ready()

    print("Starting loop")
    while not terminating:
        if reloading:
            print("Reloading")
            reloading = False

            # Support notifying the manager when reloading configuration.
            # This allows accurate state tracking as well as automatically
            # enabling 'systemctl reload' without needing to manually
            # specify an ExecReload= line in the unit file.

            notify_reloading()

            # Do some reconfiguration work here.

            print("Done reloading")
            notify_ready()

        # Do the real work here ...

        print("Sleeping for five seconds")
        time.sleep(5)

    print("Terminating")
    notify_stopping()

if __name__ == "__main__":
    sys.stdout.reconfigure(line_buffering=True)
    print("Starting app")
    main()
    print("Stopped app")
