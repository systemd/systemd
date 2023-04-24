#!/usr/bin/env python3

import asyncio
import logging
import os
import signal
import socket
import sys

import systemd.daemon

signaled = 0

def signal_handler():
    global signaled
    signaled = 1

async def on_client(connection, id):
    for i in range(5):
        connection.sendall(f"GENERATION_ID={id}\n".encode())
        await asyncio.sleep(1)

    connection.close()

async def main():
    tasks = []

    id = os.getenv("GENERATION_ID")
    if id is None:
        logging.error("GENERATION_ID environment variable is not set")
        sys.exit(1)

    fds = systemd.daemon.listen_fds();
    if len(fds) != 1:
        logging.error("Unexpected number of file descriptors received from manager")
        sys.exit(1)

    fd = fds[0]

    if not systemd.daemon.is_socket_unix(fd):
        logging.error("Passed file descriptor doesn't refer to UNIX socket")
        sys.exit(1)

    sock = socket.fromfd(fd, socket.AF_UNIX, socket.SOCK_STREAM)
    sock.listen()
    sock.setblocking(False)

    loop = asyncio.get_event_loop()
    loop.add_signal_handler(signal.SIGUSR1, signal_handler)

    while not signaled:
        try:
            async with asyncio.timeout(1):
                conn, _ = await loop.sock_accept(sock)
                tasks.append(loop.create_task(on_client(conn, id)))
        except TimeoutError:
            pass

    for t in tasks:
        await asyncio.wait_for(t, 5)

if __name__ == '__main__':
    asyncio.run(main())
