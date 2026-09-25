#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later

import contextlib
import hashlib
import http.client
import lzma
import os
import select
import signal
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


def zstd_rle_frame(entries):
    """Return entries padded with 64 MiB cursor values, which the importer discards."""

    def raw(data):
        return (len(data) << 3).to_bytes(3, 'little') + data

    rle = (128 * 1024 << 3 | 2).to_bytes(3, 'little') + b'A'
    padded_entry = raw(b'__CURSOR=') + rle * 512 + raw(b'\n' + entry('padded'))
    header = bytes.fromhex('28b52ffd0050')  # Zstandard magic number and 1 MiB window descriptor
    return header + padded_entry * entries + b'\x01\x00\x00'


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

    def journal(self, field='MESSAGE'):
        return subprocess.check_output(
            [JOURNALCTL, f'--file={self.output}', '-o', 'cat', f'--output-fields={field}'],
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


class StreamingTests:
    """Base test suite parameterized across supported compression formats."""

    def compressed(self, message):
        return self.compress(entry(message))

    def assert_rejected(self, body, status=400):
        # The server may close the connection before the error response is read.
        with contextlib.suppress(ConnectionError):
            self.assertEqual(self.post(body, self.encoding), status)
        self.assertEqual(self.post(entry('after-rejection')), 202)
        self.assertIn('after-rejection', self.journal())

    def test_split_upload(self):
        message = hashlib.shake_256(b'journal-remote split upload').hexdigest(256 * 1024)
        body = self.compressed(message)
        # The payload exceeds the libmicrohttpd connection memory limit and is
        # received across multiple callbacks.
        self.assertGreater(len(body), 128 * 1024)
        self.assertEqual(self.post(body, self.encoding), 202)
        self.assertEqual(self.journal(), [message])

    def test_decoder_is_per_request(self):
        with self.connect() as connection:
            self.assertEqual(connection.post(self.compressed('first'), self.encoding, keep_alive=True), 202)
            self.assertEqual(connection.post(self.compressed('second'), self.encoding, chunked=False), 202)
        self.assertEqual(self.journal(), ['first', 'second'])

    def test_truncated_upload(self):
        self.assert_rejected(self.compressed('truncated')[:-1])


class XzStreamingTests(StreamingTests, ReceiverTestCase):
    encoding = 'xz'

    def compress(self, data):
        return lzma.compress(data)


class ZstdStreamingTests(StreamingTests, ReceiverTestCase):
    encoding = 'zstd'

    def compress(self, data):
        return subprocess.check_output(['zstd', '-q', '-c'], input=data)

    def test_window_limit(self):
        # The frame specifies a 128 MiB window, exceeding the 64 MiB maximum
        # window size permitted by the server.
        body = bytes.fromhex('28b52ffd0088010000')
        self.assertEqual(subprocess.check_output(['zstd', '-q', '-d', '-c', '--long=27'], input=body), b'')
        self.assert_rejected(body)

    def test_callback_output_limit(self):
        # The thirteen entries decode to 832 MiB in total, exceeding the 768 MiB
        # (DATA_SIZE_MAX) decompression limit for a single callback.
        body = zstd_rle_frame(13)
        # The compressed payload must fit within the initial receive buffer so
        # that libmicrohttpd processes it in a single callback.
        self.assertLess(len(body), 32 * 1024)
        with self.connect() as connection, contextlib.suppress(ConnectionError):
            connection.begin(self.encoding)
            # Suspend the server process during transmission to ensure the
            # payload is buffered in the socket and processed in a single
            # callback rather than incrementally.
            self.process.send_signal(signal.SIGSTOP)
            _, status = os.waitpid(self.process.pid, os.WUNTRACED)
            try:
                self.assertTrue(os.WIFSTOPPED(status))
                connection.chunk(body)
                connection.chunk(b'')
            finally:
                self.process.send_signal(signal.SIGCONT)
            self.assertEqual(connection.status(), 413)
        # Decompression exceeds the limit during the twelfth entry, so only the
        # eleven preceding complete entries are stored.
        self.assertEqual(len(self.journal('_BOOT_ID')), 11)
        self.assertEqual(self.post(entry('after-output-limit')), 202)
        self.assertEqual(len(self.journal('_BOOT_ID')), 12)


if __name__ == '__main__':
    unittest.main()
