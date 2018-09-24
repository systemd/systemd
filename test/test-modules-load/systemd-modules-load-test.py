#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1+
# systemd-modules-load tests

import os
import sys
import unittest
import subprocess
import shutil

class SystemdModulesLoadTests(unittest.TestCase):
     def setUp(self):
          shutil.copy('ipip.conf', '/etc/modules-load.d/ipip.conf')

     def tearDown(self):
          subprocess.check_call('rmmod ipip', shell=True)
          os.remove(os.path.join('/etc/modules-load.d', 'ipip.conf'))

     def test_ipip_module_getting_loaded(self):
          subprocess.check_call('/usr/lib/systemd/systemd-modules-load /etc/modules-load.d/ipip.conf', shell=True)
          subprocess.check_call('modinfo ipip', shell=True)

if __name__ == '__main__':
    unittest.main(testRunner=unittest.TextTestRunner(stream=sys.stdout,
                                                     verbosity=3))
