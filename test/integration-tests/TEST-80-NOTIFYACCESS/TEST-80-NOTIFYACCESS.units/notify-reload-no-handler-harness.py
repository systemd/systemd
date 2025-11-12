#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later

import os
import signal
import socket
import sys

def send_notify(message):
    """Send a message to the systemd notify socket."""
    socket_path = os.environ.get('NOTIFY_SOCKET')
    if not socket_path:
        print("NOTIFY_SOCKET not set", file=sys.stderr)
        return False

    # Handle abstract sockets (start with @)
    if socket_path.startswith('@'):
        socket_path = '\0' + socket_path[1:]

    try:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        sock.connect(socket_path)
        sock.send(message.encode())
        sock.close()
        return True
    except Exception as e:
        print(f"Failed to send notify: {e}", file=sys.stderr)
        return False

def main():
    # Explicitly set SIGHUP to default disposition.
    # This ensures SIGHUP is NOT in SigCgt, which is what we want to test.
    # systemd should detect this and fail the service startup.
    signal.signal(signal.SIGHUP, signal.SIG_DFL)

    # Send READY=1 - systemd should check for signal handler and fail
    if not send_notify("READY=1\nSTATUS=Started with mode=no-handler"):
        return 1

    # If we get here, wait forever (but we shouldn't, systemd should kill us)
    while True:
        signal.pause()

    return 0

if __name__ == "__main__":
    sys.exit(main())
