#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later

import contextlib
import http.client
import os
import select
import socket
import subprocess
import tempfile
import time
import unittest
from pathlib import Path

REMOTE = os.getenv('JOURNAL_REMOTE', '/usr/lib/systemd/systemd-journal-remote')
JOURNALCTL = os.getenv('JOURNALCTL', 'journalctl')

IDLE_TIMEOUT = 30
DEADLINE = 2


def entry(message):
    return (
        '__REALTIME_TIMESTAMP=1700000000000000\n'
        '__MONOTONIC_TIMESTAMP=1000000\n'
        '_BOOT_ID=f446871715504074bf7049ef0718fa93\n'
        '_MACHINE_ID=69121ca41d12c1b69a7960174c27b618\n'
        f'MESSAGE={message}\n\n'
    ).encode()


class Connection(socket.socket):
    def __init__(self, port):
        super().__init__(fileno=socket.create_connection(('127.0.0.1', port)).detach())
        self.settimeout(60)

    def begin(self, encoding=None, keep_alive=False, length=None):
        headers = [
            'POST /upload HTTP/1.1',
            'Host: localhost',
            'Content-Type: application/vnd.fdo.journal',
            'Transfer-Encoding: chunked' if length is None else f'Content-Length: {length}',
        ]
        if encoding:
            headers.append(f'Content-Encoding: {encoding}')
        if not keep_alive:
            headers.append('Connection: close')
        self.sendall('\r\n'.join(headers + ['', '']).encode())

    def chunk(self, data):
        self.sendall(b'%x\r\n%s\r\n' % (len(data), data))

    def request(self, body, encoding=None, keep_alive=False, chunked=True):
        if chunked:
            self.begin(encoding, keep_alive)
            self.chunk(body)
            self.chunk(b'')
        else:
            self.begin(encoding, keep_alive, len(body))
            self.sendall(body)

    def status(self):
        response = http.client.HTTPResponse(self)
        response.begin()
        response.read()
        return response.status

    def post(self, body, encoding=None, keep_alive=False, chunked=True):
        self.request(body, encoding, keep_alive, chunked)
        return self.status()

    def closed(self, timeout):
        if not select.select([self], [], [], timeout)[0]:
            return False
        with contextlib.suppress(ConnectionResetError):
            data = self.recv(4096)
            assert not data, data
        return True


class ReceiverTestCase(unittest.TestCase):
    environment = {}

    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.output = Path(directory.name) / 'remote.journal'
        with socket.socket() as listener:
            listener.bind(('127.0.0.1', 0))
            self.port = listener.getsockname()[1]
        self.process = subprocess.Popen(
            [REMOTE, f'--listen-http=127.0.0.1:{self.port}', f'--output={self.output}', '--split-mode=none'],
            env=os.environ | self.environment,
        )
        self.addCleanup(self.process.wait, 5)
        self.addCleanup(self.process.terminate)

        for _ in range(100):
            self.assertIsNone(self.process.poll(), 'receiver exited')
            with contextlib.suppress(ConnectionRefusedError), self.connect() as connection:
                connection.sendall(b'GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n')
                connection.status()
                return
            time.sleep(0.1)
        self.fail('receiver did not listen')

    def connect(self):
        return Connection(self.port)

    def post(self, body, encoding=None):
        with self.connect() as connection:
            return connection.post(body, encoding)

    def journal(self):
        return subprocess.check_output(
            [JOURNALCTL, f'--file={self.output}', '-o', 'cat'],
            text=True,
        ).splitlines()

    def assert_closes_after(self, connection, seconds, activity=lambda: None):
        start = time.monotonic()
        with contextlib.suppress(ConnectionError):
            while not connection.closed(0.5):
                self.assertLess(time.monotonic() - start, seconds + 5, 'connection stayed open')
                activity()
        self.assertGreaterEqual(time.monotonic() - start, seconds - 0.1)


class ConnectionTests(ReceiverTestCase):
    environment = {'SYSTEMD_JOURNAL_REMOTE_MAX_CONNECTIONS': '1'}

    def test_count_and_recovery(self):
        with self.connect() as occupying:
            self.assertEqual(occupying.post(entry('occupy'), keep_alive=True), 202)
            with self.connect() as pending:
                pending.request(entry('pending'))
                # The kernel accepts the connection into the listen backlog, but the server
                # does not process the request until the occupying connection closes.
                self.assertFalse(select.select([pending], [], [], 0.5)[0])
                occupying.close()
                self.assertEqual(pending.status(), 202)
        self.assertEqual(self.post(entry('recovered')), 202)

    def test_idle_timeout(self):
        with self.connect() as connection:
            self.assertEqual(connection.post(entry('idle'), keep_alive=True), 202)
            self.assert_closes_after(connection, IDLE_TIMEOUT)
        self.assertEqual(self.post(entry('after-idle')), 202)


class EntryDeadlineTests(ReceiverTestCase):
    environment = {'SYSTEMD_JOURNAL_REMOTE_ENTRY_TIMEOUT_SEC': str(DEADLINE)}

    def test_stored_entries_renew(self):
        messages = [f'renewed-{i}' for i in range(3 * DEADLINE)]
        with self.connect() as connection:
            connection.begin()
            for message in messages:
                connection.chunk(entry(message))
                self.assertFalse(connection.closed(1))
            connection.chunk(b'')
            self.assertEqual(connection.status(), 202)
        self.assertEqual(self.journal(), messages)

    def test_activity_without_entries(self):
        partial = iter(entry('partial'))
        with self.connect() as connection:
            connection.begin()
            self.assert_closes_after(connection, DEADLINE, lambda: connection.chunk(bytes([next(partial)])))
        self.assertEqual(self.journal(), [])
        self.assertEqual(self.post(entry('after-deadline')), 202)

    def test_incomplete_headers(self):
        with self.connect() as connection:
            connection.sendall(b'POST /upload HTTP/1.1\r\nHost:')
            self.assert_closes_after(connection, DEADLINE)

    def test_empty_requests_do_not_renew(self):
        with self.connect() as connection:
            self.assertEqual(connection.post(entry('initial'), keep_alive=True), 202)
            self.assert_closes_after(
                connection,
                DEADLINE,
                lambda: self.assertEqual(connection.post(b'\n', keep_alive=True, chunked=False), 202),
            )


if __name__ == '__main__':
    unittest.main()
