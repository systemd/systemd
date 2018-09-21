#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1+
# systemd-socket-activate tests

import os
import sys
import unittest
import subprocess
import socket
import shutil

systemd_unit_path='/var/run/systemd/system'
socket_activate_service='systemd-socket-activate.service'

class SystemdSocketActivateTests(unittest.TestCase):
    def setUp(self):
        shutil.copy(socket_activate_service, systemd_unit_path)

        subprocess.check_output(['systemctl', 'start', socket_activate_service])
        output = subprocess.check_output(['systemctl', 'status', socket_activate_service]).rstrip().decode('utf-8')
        print(output)

    def tearDown(self):
        subprocess.check_output(['systemctl', 'stop', socket_activate_service])
        os.remove(os.path.join(systemd_unit_path, socket_activate_service))

    def test_simple_echo(self):

        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.connect(('0.0.0.0', 2000))
        client.send('hello'.encode('utf-8'))

        response = client.recv(4096)
        client.close()

        self.assertEqual(response.decode('utf-8'), 'hello')


if __name__ == '__main__':
    unittest.main(testRunner=unittest.TextTestRunner(stream=sys.stdout,
                                                     verbosity=3))
