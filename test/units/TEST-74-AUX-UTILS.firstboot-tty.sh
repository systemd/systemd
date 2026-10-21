#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

if ! command -v systemd-firstboot >/dev/null; then
    echo "systemd-firstboot not found, skipping the test"
    exit 77
fi

python3 <<'PY'
import fcntl
import os
import select
import subprocess
import tempfile
import termios
import time


def test_password_prompt(have_controlling_terminal):
    master, peer = os.openpty()
    other_master, other_peer = os.openpty()
    saved = termios.tcgetattr(peer)
    output = bytearray()
    process = None

    def acquire_controlling_terminal():
        os.setsid()
        fcntl.ioctl(other_peer, termios.TIOCSCTTY, 0)

    def expect_prompt(text):
        deadline = time.monotonic() + 10
        # The prompt is written before echo is disabled. Wait for both before entering the password.
        while text not in output or termios.tcgetattr(peer)[3] & termios.ECHO:
            remaining = deadline - time.monotonic()
            assert remaining > 0, output.decode(errors='replace')
            if select.select([master], [], [], min(remaining, 0.1))[0]:
                data = os.read(master, 65536)
                assert data, output.decode(errors='replace')
                output.extend(data)

    env = os.environ.copy()
    env['SYSTEMD_COLORS'] = '0'
    for name in ('CREDENTIALS_DIRECTORY', 'ENCRYPTED_CREDENTIALS_DIRECTORY'):
        env.pop(name, None)

    try:
        with tempfile.TemporaryDirectory(prefix='firstboot-tty-', dir='/tmp') as root:
            # stdin is a terminal, but /dev/tty is either absent or refers to a different terminal.
            process = subprocess.Popen(
                ['systemd-firstboot', '--root=' + root, '--prompt-root-password', '--welcome=no', '--chrome=no'],
                stdin=peer,
                stdout=peer,
                stderr=peer,
                env=env,
                start_new_session=not have_controlling_terminal,
                preexec_fn=acquire_controlling_terminal if have_controlling_terminal else None,
                pass_fds=(other_peer,) if have_controlling_terminal else (),
            )

            password = b'firstboot-test-password-7!'
            expect_prompt(b'Please enter the new root password (empty to skip):')
            os.write(master, password + b'\n')
            expect_prompt(b'Please enter the new root password again:')
            os.write(master, password + b'\n')

            status = process.wait(timeout=10)
            while select.select([master], [], [], 0)[0]:
                output.extend(os.read(master, 65536))

            assert status == 0, output.decode(errors='replace')
            assert password not in output, output.decode(errors='replace')
            assert termios.tcgetattr(peer) == saved
            assert not select.select([other_master], [], [], 0)[0], 'Prompt appeared on the controlling terminal'
    finally:
        if process is not None and process.poll() is None:
            process.kill()
            process.wait()
        for fd in (master, peer, other_master, other_peer):
            os.close(fd)


test_password_prompt(have_controlling_terminal=False)
test_password_prompt(have_controlling_terminal=True)
PY
