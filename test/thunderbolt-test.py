#!/usr/bin/python3
#
# Thunderbolt test suite
#
# PATH=build:$PATH test/thunderbolt-test.py
#
# Copyright: (C) 2017 Christian J. Kellner <ckellner@redhat.com>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

import json
import os
import shutil
import sys
import subprocess
import unittest
import uuid
import tempfile
import time

try:
    import gi
    from gi.repository import GLib
    from gi.repository import Gio
except ImportError as e:
    sys.stderr.write('Skipping thunderbolt test. Imports missing: %s\n' % str(e))
    sys.exit(0)

try:
    gi.require_version('UMockdev', '1.0')
    from gi.repository import UMockdev
except ImportError:
    sys.stderr.write('Skipping thunderbolt test, umockdev not available');
    sys.exit(0)


class TbtTest(unittest.TestCase):
    """Main Thunderbolt test suite"""

    @classmethod
    def setUpClass(cls):
        cls.tbtctl_bin = shutil.which('tbtctl')
        print('Using "tbtctl" at "%s"' % cls.tbtctl_bin, file=sys.stderr)
        assert os.access(cls.tbtctl_bin, os.X_OK), "could not execute @ " + cls.tbtctl_bin
        cls.do_debug = True

    def debug(self, msg):
        if not self.do_debug:
            return
        print(msg, file=sys.stderr)

    def setUp(self):
        self.testbed = UMockdev.Testbed.new()
        self.host_uuid = '3b7d4bad-4fdf-44ff-8730-ffffdeadbabe'
        self.debug("/sys @ %s" % (self.testbed.get_root_dir()))
        self.devid = 1
        self.dbpath = tempfile.mkdtemp()
        self.debug("Thunderbolt DB @ %s" % (self.dbpath))
        self.efi = os.path.join(self.testbed.get_root_dir(), "/sys/firmware/efi/efivars/")
        os.makedirs(self.efi, exist_ok=True)

    def tearDown(self):
        shutil.rmtree(self.dbpath)
        del self.testbed

    def tbtctl(self, *args, do_json=True):
        env = os.environ.copy()
        env['UMOCKDEV_DIR'] = self.testbed.get_root_dir()
        env['SYSTEMD_THUNDERBOLT_DB_PATH'] = self.dbpath
        args = [self.tbtctl_bin, '--noroot'] + list(args)
        if do_json:
             args += ['--json']
        self.debug('Calling: ' + " ".join(args))
        process = subprocess.Popen(args,
                                   env=env,
                                   stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE)

        stdout, stderr = process.communicate()
        if do_json:
            stdout = json.loads(stdout)
        return stdout, stderr, process.returncode

    def add_host(self, domain=0, security='user'):
        dc = self.testbed.add_device('thunderbolt', 'domain%d' % domain, None,
                                     ['security', security],
                                     ['DEVTYPE', 'thunderbolt_domain'])

        host = self.testbed.add_device('thunderbolt', "%d-0" % domain, dc,
                                       ['device_name', 'Host',
                                        'device', '0x23',
                                        'vendor_name', 'GNOME.org',
                                        'vendor', '0x23',
                                        'authorized', '1',
                                        'unique_id', self.host_uuid],
                                       ['DEVTYPE', 'thunderbolt_device'])
        return dc, host

    def add_device(self, name, parent, uid=None, domain=0, authorized=0):
        self.devid += 1
        if uid is None:
            uid = uuid.uuid4()
        d = self.testbed.add_device('thunderbolt',
                                    "%d-%d" % (domain, self.devid),
                                    parent,
                                    ['device_name', name,
                                     'device', '0x23',
                                     'vendor_name', 'GNOME.org',
                                     'vendor', '0x23',
                                     'authorized', '%d' % authorized,
                                     'key', '',
                                     'unique_id', str(uid)],
                                    ['DEVTYPE', 'thunderbolt_device'])
        return d;

    def find_device(self, lst, name):
        for d in lst:
            if d['name'] == name:
                return d
            elif d['uuid'] == name:
                return d
        return None

    def test_list(self):
        dc, host = self.add_host()
        out, _, _ = self.tbtctl('list')
        self.assertEqual(len(out), 1)
        d = out[0]
        self.assertEqual(self.host_uuid, d['uuid'])
        self.assertEqual('Host', d['name'])
        self.assertEqual('GNOME.org', d['vendor'])
        self.assertIn('authorized', d['status'])
        self.assertEqual(True, d['authorized'])
        self.assertEqual("user", d['auth-method'])

        c1 = self.add_device('Cable', host)
        dock = self.add_device('Dock', c1)

        out, _, _ = self.tbtctl('list')
        self.assertEqual(len(out), 3)
        d = self.find_device(out, 'Cable')
        self.assertIn('unauthorized', d['status'])
        self.assertEqual(False, d['authorized'])

    def test_authorize(self):
        dc, host = self.add_host()
        dock = self.add_device('Dock', host)

        out, _, _ = self.tbtctl('list')
        d = self.find_device(out, 'Dock')
        self.assertEqual(False, d['authorized'])

        out, err, ret = self.tbtctl('authorize', dock, do_json=False)
        self.assertEqual(ret, 0)

        out, _, _ = self.tbtctl('list')
        d = self.find_device(out, 'Dock')
        self.assertEqual(True, d['authorized'])
        self.assertEqual(True, d['stored'])



if __name__ == '__main__':
    # run ourselves under umockdev
    if 'umockdev' not in os.environ.get('LD_PRELOAD', ''):
        os.execvp('umockdev-wrapper', ['umockdev-wrapper'] + sys.argv)

    unittest.main()
