#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
# pylint: disable=line-too-long,too-many-lines,too-many-branches,too-many-statements,too-many-arguments
# pylint: disable=too-many-public-methods,too-many-boolean-expressions,invalid-name,no-self-use
# pylint: disable=missing-function-docstring,missing-class-docstring,missing-module-docstring
#
#  Copyright © 2017 Michal Sekletar <msekleta@redhat.com>

# ATTENTION: This uses the *installed* systemd, not the one from the built
# source tree.

import os
import subprocess
import sys
import time
import unittest
import uuid
from enum import Enum

class InstallChange(Enum):
    NO_CHANGE = 0
    LINES_SWAPPED = 1
    COMMAND_ADDED_BEFORE = 2
    COMMAND_ADDED_AFTER = 3
    COMMAND_INTERLEAVED = 4
    REMOVAL = 5

class ExecutionResumeTest(unittest.TestCase):
    def setUp(self):
        self.unit = 'test-issue-518.service'
        self.unitfile_path = f'/run/systemd/system/{self.unit}'
        self.output_file = f"/tmp/test-issue-518-{uuid.uuid4()}"
        self.unit_files = {}

        unit_file_content = f'''
        [Service]
        Type=oneshot
        ExecStart=/bin/sleep 3
        ExecStart=/bin/bash -c "echo foo >> {self.output_file}"
        '''
        self.unit_files[InstallChange.NO_CHANGE] = unit_file_content

        unit_file_content = f'''
        [Service]
        Type=oneshot
        ExecStart=/bin/bash -c "echo foo >> {self.output_file}"
        ExecStart=/bin/sleep 3
        '''
        self.unit_files[InstallChange.LINES_SWAPPED] = unit_file_content

        unit_file_content = f'''
        [Service]
        Type=oneshot
        ExecStart=/bin/bash -c "echo bar >> {self.output_file}"
        ExecStart=/bin/sleep 3
        ExecStart=/bin/bash -c "echo foo >> {self.output_file}"
        '''
        self.unit_files[InstallChange.COMMAND_ADDED_BEFORE] = unit_file_content

        unit_file_content = f'''
        [Service]
        Type=oneshot
        ExecStart=/bin/sleep 3
        ExecStart=/bin/bash -c "echo foo >> {self.output_file}"
        ExecStart=/bin/bash -c "echo bar >> {self.output_file}"
        '''
        self.unit_files[InstallChange.COMMAND_ADDED_AFTER] = unit_file_content

        unit_file_content = f'''
        [Service]
        Type=oneshot
        ExecStart=/bin/bash -c "echo baz >> {self.output_file}"
        ExecStart=/bin/sleep 3
        ExecStart=/bin/bash -c "echo foo >> {self.output_file}"
        ExecStart=/bin/bash -c "echo bar >> {self.output_file}"
        '''
        self.unit_files[InstallChange.COMMAND_INTERLEAVED] = unit_file_content

        unit_file_content = f'''
        [Service]
        Type=oneshot
        ExecStart=/bin/bash -c "echo bar >> {self.output_file}"
        ExecStart=/bin/bash -c "echo baz >> {self.output_file}"
        '''
        self.unit_files[InstallChange.REMOVAL] = unit_file_content

    def reload(self):
        subprocess.check_call(['systemctl', 'daemon-reload'])

    def write_unit_file(self, unit_file_change):
        if not isinstance(unit_file_change, InstallChange):
            raise ValueError('Unknown unit file change')

        content = self.unit_files[unit_file_change]

        with open(self.unitfile_path, 'w', encoding='utf-8') as f:
            f.write(content)

        self.reload()

    def check_output(self, expected_output):
        for _ in range(15):
            # Wait until the unit finishes so we don't check an incomplete log
            if subprocess.call(['systemctl', '-q', 'is-active', self.unit]) == 0:
                continue

            os.sync()

            try:
                with open(self.output_file, 'r', encoding='utf-8') as log:
                    output = log.read()
                    self.assertEqual(output, expected_output)
                    return
            except IOError:
                pass

            time.sleep(1)

        self.fail(f'Timed out while waiting for the output file {self.output_file} to appear')

    def setup_unit(self):
        self.write_unit_file(InstallChange.NO_CHANGE)
        subprocess.check_call(['systemctl', '--job-mode=replace', '--no-block', 'start', self.unit])
        time.sleep(1)

    def test_no_change(self):
        expected_output = 'foo\n'

        self.setup_unit()
        self.reload()

        self.check_output(expected_output)

    def test_swapped(self):
        self.setup_unit()
        self.write_unit_file(InstallChange.LINES_SWAPPED)
        self.reload()

        self.assertTrue(not os.path.exists(self.output_file))

    def test_added_before(self):
        expected_output = 'foo\n'

        self.setup_unit()
        self.write_unit_file(InstallChange.COMMAND_ADDED_BEFORE)
        self.reload()

        self.check_output(expected_output)

    def test_added_after(self):
        expected_output = 'foo\nbar\n'

        self.setup_unit()
        self.write_unit_file(InstallChange.COMMAND_ADDED_AFTER)
        self.reload()

        self.check_output(expected_output)

    def test_interleaved(self):
        expected_output = 'foo\nbar\n'

        self.setup_unit()
        self.write_unit_file(InstallChange.COMMAND_INTERLEAVED)
        self.reload()

        self.check_output(expected_output)

    def test_removal(self):
        self.setup_unit()
        self.write_unit_file(InstallChange.REMOVAL)
        self.reload()

        self.assertTrue(not os.path.exists(self.output_file))

    def test_issue_6533(self):
        unit = "test-issue-6533.service"
        unitfile_path = f"/run/systemd/system/{unit}"

        content = '''
        [Service]
        ExecStart=/bin/sleep 5
        '''

        with open(unitfile_path, 'w', encoding='utf-8') as f:
            f.write(content)

        self.reload()

        subprocess.check_call(['systemctl', '--job-mode=replace', '--no-block', 'start', unit])
        time.sleep(2)

        content = '''
        [Service]
        ExecStart=/bin/sleep 5
        ExecStart=/bin/true
        '''

        with open(unitfile_path, 'w', encoding='utf-8') as f:
            f.write(content)

        self.reload()
        time.sleep(5)

        self.assertNotEqual(subprocess.call("journalctl -b _PID=1 | grep -q 'Freezing execution'", shell=True), 0)

    def tearDown(self):
        for f in [self.output_file, self.unitfile_path]:
            try:
                os.remove(f)
            except OSError:
                # ignore error if log file doesn't exist
                pass

        self.reload()

if __name__ == '__main__':
    unittest.main(testRunner=unittest.TextTestRunner(stream=sys.stdout, verbosity=3))
