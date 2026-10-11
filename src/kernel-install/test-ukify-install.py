#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later

import os
import runpy
import subprocess
import sys
import unittest.mock

ns = runpy.run_path(sys.argv[1], run_name='not_main')


class FakePath:
    files = {
        '/conf-root/cmdline': 'root=conf\n# ignored\nquiet splash\n',
        '/proc/cmdline': 'BOOT_IMAGE=/vmlinuz initrd=/initrd root=fake quiet\n',
    }

    def __init__(self, path):
        self.path = os.fspath(path)

    def __truediv__(self, name):
        return type(self)(os.path.join(self.path, name))

    def exists(self):
        return self.path in self.files

    def read_text(self):
        return self.files[self.path]


module_globals = ns['kernel_cmdline_base'].__globals__
module_globals['Path'] = FakePath

# Mock subprocess.run to simulate not being in a container, so the test
# works regardless of the environment (including container-based CI).
os.environ.pop('KERNEL_INSTALL_CONF_ROOT', None)
with unittest.mock.patch.object(subprocess, 'run', return_value=subprocess.CompletedProcess([], 1)):
    assert ns['kernel_cmdline_base']() == ['root=fake', 'quiet']

os.environ['KERNEL_INSTALL_CONF_ROOT'] = '/conf-root'
assert ns['kernel_cmdline_base']() == ['root=conf', 'quiet', 'splash']

os.environ['KERNEL_INSTALL_CONF_ROOT'] = '/empty-conf-root'
assert ns['kernel_cmdline_base']() == []

# Test that /proc/cmdline is skipped in containers
os.environ.pop('KERNEL_INSTALL_CONF_ROOT', None)
with unittest.mock.patch.object(subprocess, 'run', return_value=subprocess.CompletedProcess([], 0)):
    assert ns['kernel_cmdline_base']() == [], 'should return empty in container'
