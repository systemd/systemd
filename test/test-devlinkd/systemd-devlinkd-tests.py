#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
# systemd-devlinkd tests

# These tests can be executed in the systemd mkosi image when booted in QEMU. After booting the QEMU VM,
# simply run this file which can be found in the VM at /usr/lib/systemd/tests/testdata/test-devlinkd/systemd-devlinkd-tests.py.
#
# To run an individual test, specify it as a command line argument in the form
# of <class>.<test_function>. E.g. the DevlinkdTests class has a test
# function called test_port_split(). To run just that test use:
#
#    sudo ./systemd-devlinkd-tests.py DevlinkdTests.test_port_split

import os
import subprocess
import unittest
import json
import shutil

CONF_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), 'conf'))
RUNTIME_DEVLINK_DIR = '/run/systemd/devlink'
NETDEVSIM_ID = 99
NETDEVSIM_HANDLE = f'netdevsim/netdevsim{NETDEVSIM_ID}'

def check_output(*command, **kwargs):
    # This checks the result and returns stdout (and stderr) on success.
    command = command[0].split() + list(command[1:])
    ret = subprocess.run(command, check=False, universal_newlines=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, **kwargs)
    if ret.returncode == 0:
        return ret.stdout.rstrip()
    # When returncode != 0, print stdout and stderr, then trigger CalledProcessError.
    print(ret.stdout)
    ret.check_returncode()

def call(*command, **kwargs):
    # This returns returncode. stdout and stderr are merged and shown in console
    command = command[0].split() + list(command[1:])
    return subprocess.run(command, check=False, universal_newlines=True, stderr=subprocess.DEVNULL, **kwargs).returncode

def call_quiet(*command, **kwargs):
    command = command[0].split() + list(command[1:])
    return subprocess.run(command, check=False, universal_newlines=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, **kwargs).returncode

def netdevsim_new():
    with open('/sys/bus/netdevsim/new_device', 'w') as f:
        f.write(f'{NETDEVSIM_ID} 1')

class DevlinkdTestHelpers:
    def cleanup_configs(self):
        for fname in os.listdir(RUNTIME_DEVLINK_DIR):
            if fname.endswith('.devlink'):
                os.remove(os.path.join(RUNTIME_DEVLINK_DIR, fname))

    def install_conf(self, conf_name):
        src = os.path.join(CONF_DIR, conf_name)
        dst = os.path.join(RUNTIME_DEVLINK_DIR, conf_name)
        shutil.copy(src, dst)

    def reload_devlinkd(self):
        check_output('systemctl reload-or-restart systemd-devlinkd.service')

    def run_devlink(self, command, **kwargs):
        output = check_output(f'devlink -j {command}', **kwargs)
        return json.loads(output)

def expectedFailureIfNetdevsimPortSplitIsNotAvailable():
    def f(func):
        def finalize(func, supported):
            call_quiet('rmmod netdevsim')
            return func if supported else unittest.expectedFailure(func)

        call_quiet('rmmod netdevsim')
        if call_quiet('modprobe netdevsim') != 0:
            return finalize(func, False)

        try:
            netdevsim_new()
        except OSError:
            return finalize(func, False)

        ret = call('devlink port split netdevsim/netdevsim99/0 count 2')
        return finalize(func, ret == 0)
    return f

class DevlinkdTests(unittest.TestCase, DevlinkdTestHelpers):
    def setUp(self):
        call_quiet('modprobe netdevsim')
        netdevsim_new()

        os.makedirs(RUNTIME_DEVLINK_DIR, exist_ok=True)
        self.cleanup_configs()
        self.reload_devlinkd()

    def tearDown(self):
        call_quiet('rmmod netdevsim')
        self.cleanup_configs()
        self.reload_devlinkd()

    def test_eswitch_mode(self):
        self.install_conf('10-eswitch-mode.devlink')
        self.reload_devlinkd()
        output = self.run_devlink(f'dev eswitch show {NETDEVSIM_HANDLE}')
        print(output)
        mode = None
        if NETDEVSIM_HANDLE in output.get('dev', {}):
            mode = output.get('dev', {}).get(NETDEVSIM_HANDLE).get('mode')
        self.assertEqual(mode, 'switchdev')

    def test_param_set(self):
        self.install_conf('10-param-set-test1.devlink')
        self.install_conf('10-param-set-max_macs.devlink')
        self.reload_devlinkd()
        output = self.run_devlink('dev param show')
        print(output)
        test1_value = None
        max_macs_value = None
        params = output.get('param', {}).get(NETDEVSIM_HANDLE, [])
        for param in params:
            if param.get('name') == 'test1':
                if param.get('values'):
                    test1_value = param['values'][0].get('value')
            if param.get('name') == 'max_macs':
                if param.get('values'):
                    max_macs_value = param['values'][0].get('value')
        self.assertFalse(test1_value)
        self.assertEqual(max_macs_value, 64)

    def test_health_reporter(self):
        self.install_conf('10-health-reporter.devlink')
        self.reload_devlinkd()
        output = self.run_devlink('health show')
        print(output)
        reporter = None
        reporters = output.get('health', {}).get(NETDEVSIM_HANDLE, [])
        for rep in reporters:
            if rep.get('reporter') == 'dummy':
                reporter = rep
                break
        self.assertIsNotNone(reporter, 'Health reporter "dummy" not found')
        self.assertEqual(reporter.get('grace_period'), 40000)
        self.assertFalse(reporter.get('auto_recover'))
        self.assertFalse(reporter.get('auto_dump'))

    @expectedFailureIfNetdevsimPortSplitIsNotAvailable()
    def test_port_split(self):
        self.install_conf('10-port-split.devlink')
        self.reload_devlinkd()
        output = self.run_devlink('port show')
        ports = output.get('port', {})
        self.assertEqual(len(ports), 2, 'Port splitting did not result in multiple ports')

    @expectedFailureIfNetdevsimPortSplitIsNotAvailable()
    def test_port_split_ifname(self):
        self.install_conf('10-port-split-ifname.devlink')
        self.reload_devlinkd()
        output = self.run_devlink('port show')
        ports = output.get('port', {})
        self.assertEqual(len(ports), 2, 'Port splitting did not result in multiple ports')

    # Add more tests for additional devlinkd features as needed

if __name__ == '__main__':
    unittest.main()