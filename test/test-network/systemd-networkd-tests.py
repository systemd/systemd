#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
# systemd-networkd tests

# These tests can be executed in the systemd mkosi image when booted in QEMU. After booting the QEMU VM,
# simply run this file which can be found in the VM at /usr/lib/systemd/tests/testdata/test-network/systemd-networkd-tests.py.
#
# To run an individual test, specify it as a command line argument in the form
# of <class>.<test_function>. E.g. the NetworkdMTUTests class has a test
# function called test_ipv6_mtu().  To run just that test use:
#
#    sudo ./systemd-networkd-tests.py NetworkdMTUTests.test_ipv6_mtu
#
# Similarly, other individual tests can be run, eg.:
#
#    sudo ./systemd-networkd-tests.py NetworkdNetworkTests.test_ipv6_neigh_retrans_time

import argparse
import datetime
import enum
import errno
import itertools
import ipaddress
import json
import os
import pathlib
import random
import re
import shutil
import signal
import socket
import struct
import subprocess
import sys
import time
import unittest

import psutil

network_unit_dir = '/run/systemd/network'
networkd_conf_dropin_dir = '/run/systemd/networkd.conf.d'
networkd_ci_temp_dir = '/run/networkd-ci'
udev_rules_dir = '/run/udev/rules.d'
credstore_dir = '/run/credstore'

dnsmasq_pid_file = '/run/networkd-ci/test-dnsmasq.pid'
dnsmasq_log_file = '/run/networkd-ci/test-dnsmasq.log'
dnsmasq_lease_file = '/run/networkd-ci/test-dnsmasq.lease'

isc_dhcpd_pid_file = '/run/networkd-ci/test-isc-dhcpd.pid'
isc_dhcpd_lease_file = '/run/networkd-ci/test-isc-dhcpd.lease'

radvd_pid_file = '/run/networkd-ci/test-radvd.pid'

systemd_lib_paths = ['/usr/lib/systemd', '/lib/systemd']
which_paths = ':'.join(systemd_lib_paths + os.getenv('PATH', os.defpath).lstrip(':').split(':'))

networkd_bin = shutil.which('systemd-networkd', path=which_paths)
resolved_bin = shutil.which('systemd-resolved', path=which_paths)
timesyncd_bin = shutil.which('systemd-timesyncd', path=which_paths)
wait_online_bin = shutil.which('systemd-networkd-wait-online', path=which_paths)
networkctl_bin = shutil.which('networkctl', path=which_paths)
resolvectl_bin = shutil.which('resolvectl', path=which_paths)
timedatectl_bin = shutil.which('timedatectl', path=which_paths)
udevadm_bin = shutil.which('udevadm', path=which_paths)
test_ndisc_send = None
build_dir = None
source_dir = None

use_valgrind = False
valgrind_cmd = ''
enable_debug = True
env = {}
wait_online_env = {}
asan_options = None
lsan_options = None
ubsan_options = None
with_coverage = False
show_journal = True # When true, show journal on stopping networkd.

active_units = []
protected_links = {
    'erspan0',
    'gre0',
    'gretap0',
    'ifb0',
    'ifb1',
    'ip6_vti0',
    'ip6gre0',
    'ip6tnl0',
    'ip_vti0',
    'lo',
    'sit0',
    'tunl0',
}
saved_routes = None
saved_ipv4_rules = None
saved_ipv6_rules = None
saved_timezone = None

def rm_f(path):
    if os.path.exists(path):
        os.remove(path)

def rm_rf(path):
    shutil.rmtree(path, ignore_errors=True)

def cp(src, dst):
    shutil.copy(src, dst)

def cp_r(src, dst):
    shutil.copytree(src, dst, copy_function=shutil.copy, dirs_exist_ok=True)

def mkdir_p(path):
    os.makedirs(path, exist_ok=True)

def touch(path):
    pathlib.Path(path).touch()

# pylint: disable=R1710
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
    return subprocess.run(command, check=False, universal_newlines=True, stderr=subprocess.STDOUT, **kwargs).returncode

def call_check(*command, **kwargs):
    # Same as call() above, but it triggers CalledProcessError if rc != 0
    command = command[0].split() + list(command[1:])
    return subprocess.run(command, check=False, universal_newlines=True, stderr=subprocess.STDOUT, **kwargs).check_returncode()

def call_quiet(*command, **kwargs):
    command = command[0].split() + list(command[1:])
    return subprocess.run(command, check=False, universal_newlines=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, **kwargs).returncode

def run(*command, **kwargs):
    # This returns CompletedProcess instance.
    command = command[0].split() + list(command[1:])
    return subprocess.run(command, check=False, universal_newlines=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, **kwargs)

def check_json(string):
    try:
        json.loads(string)
    except json.JSONDecodeError:
        print(f"String is not a valid JSON: '{string}'")
        raise

def is_module_available(*module_names):
    for module_name in module_names:
        lsmod_output = check_output('lsmod')
        module_re = re.compile(rf'^{re.escape(module_name)}\b', re.MULTILINE)
        if not module_re.search(lsmod_output) and call_quiet('modprobe', module_name) != 0:
            return False
    return True

def expectedFailureIfModuleIsNotAvailable(*module_names):
    def f(func):
        return func if is_module_available(*module_names) else unittest.expectedFailure(func)

    return f

def expectedFailureIfERSPANv0IsNotSupported():
    # erspan version 0 is supported since f989d546a2d5a9f001f6f8be49d98c10ab9b1897 (v5.8)
    def f(func):
        rc = call_quiet('ip link add dev erspan99 type erspan seq key 30 local 192.168.1.4 remote 192.168.1.1 erspan_ver 0')
        remove_link('erspan99')
        return func if rc == 0 else unittest.expectedFailure(func)

    return f

def expectedFailureIfERSPANv2IsNotSupported():
    # erspan version 2 is supported since f551c91de262ba36b20c3ac19538afb4f4507441 (v4.16)
    def f(func):
        rc = call_quiet('ip link add dev erspan99 type erspan seq key 30 local 192.168.1.4 remote 192.168.1.1 erspan_ver 2')
        remove_link('erspan99')
        return func if rc == 0 else unittest.expectedFailure(func)

    return f

def expectedFailureIfRoutingPolicyPortRangeIsNotAvailable():
    def f(func):
        rc = call_quiet('ip rule add from 192.168.100.19 sport 1123-1150 dport 3224-3290 table 7')
        call_quiet('ip rule del from 192.168.100.19 sport 1123-1150 dport 3224-3290 table 7')
        return func if rc == 0 else unittest.expectedFailure(func)

    return f

def expectedFailureIfRoutingPolicyIPProtoIsNotAvailable():
    def f(func):
        # IP protocol name is parsed by getprotobyname(), and it requires /etc/protocols.
        # Hence. here we use explicit number: 6 == tcp.
        rc = call_quiet('ip rule add not from 192.168.100.19 ipproto 6 table 7')
        call_quiet('ip rule del not from 192.168.100.19 ipproto 6 table 7')
        return func if rc == 0 else unittest.expectedFailure(func)

    return f

def expectedFailureIfRoutingPolicyUIDRangeIsNotAvailable():
    def f(func):
        supported = False
        if call_quiet('ip rule add from 192.168.100.19 table 7 uidrange 200-300') == 0:
            ret = run('ip rule list from 192.168.100.19 table 7')
            supported = ret.returncode == 0 and 'uidrange 200-300' in ret.stdout
            call_quiet('ip rule del from 192.168.100.19 table 7 uidrange 200-300')
        return func if supported else unittest.expectedFailure(func)

    return f

def expectedFailureIfRoutingPolicyL3MasterDeviceIsNotAvailable():
    def f(func):
        rc = call_quiet('ip rule add not from 192.168.100.19 l3mdev')
        call_quiet('ip rule del not from 192.168.100.19 l3mdev')
        return func if rc == 0 else unittest.expectedFailure(func)

    return f

def expectedFailureIfNexthopIsNotAvailable():
    def f(func):
        rc = call_quiet('ip nexthop list')
        return func if rc == 0 else unittest.expectedFailure(func)

    return f

def expectedFailureIfRTA_VIAIsNotSupported():
    def f(func):
        call_quiet('ip link add dummy98 type dummy')
        call_quiet('ip link set up dev dummy98')
        call_quiet('ip route add 2001:1234:5:8fff:ff:ff:ff:fe/128 dev dummy98')
        rc = call_quiet('ip route add 10.10.10.10 via inet6 2001:1234:5:8fff:ff:ff:ff:fe dev dummy98')
        remove_link('dummy98')
        return func if rc == 0 else unittest.expectedFailure(func)

    return f

def expectedFailureIfAlternativeNameIsNotAvailable():
    def f(func):
        call_quiet('ip link add dummy98 type dummy')
        supported = \
            call_quiet('ip link prop add dev dummy98 altname hogehogehogehogehoge') == 0 and \
            call_quiet('ip link show dev hogehogehogehogehoge') == 0
        remove_link('dummy98')
        return func if supported else unittest.expectedFailure(func)

    return f

def expectedFailureIfNetdevsimWithSRIOVIsNotAvailable():
    def f(func):
        def finalize(func, supported):
            call_quiet('rmmod netdevsim')
            return func if supported else unittest.expectedFailure(func)

        call_quiet('rmmod netdevsim')
        if call_quiet('modprobe netdevsim') != 0:
            return finalize(func, False)

        try:
            with open('/sys/bus/netdevsim/new_device', mode='w', encoding='utf-8') as f:
                f.write('99 1')
        except OSError:
            return finalize(func, False)

        return finalize(func, os.path.exists('/sys/bus/netdevsim/devices/netdevsim99/sriov_numvfs'))

    return f

def expectedFailureIfKernelReturnsInvalidFlags():
    '''
    This checks the kernel bug caused by 3ddc2231c8108302a8229d3c5849ee792a63230d (v6.9),
    fixed by 1af7f88af269c4e06a4dc3bc920ff6cdf7471124 (v6.10, backported to 6.9.3).
    '''
    def f(func):
        call_quiet('ip link add dummy98 type dummy')
        call_quiet('ip link set up dev dummy98')
        call_quiet('ip address add 192.0.2.1/24 dev dummy98 noprefixroute')
        output = check_output('ip address show dev dummy98')
        remove_link('dummy98')
        return func if 'noprefixroute' in output else unittest.expectedFailure(func)

    return f

# pylint: disable=C0415
def compare_kernel_version(min_kernel_version):
    try:
        import platform
        from packaging import version
    except ImportError:
        print('Failed to import either platform or packaging module, assuming the comparison failed')
        return False

    # Get only the actual kernel version without any build/distro/arch stuff
    # e.g. '5.18.5-200.fc36.x86_64' -> '5.18.5'
    kver = platform.release().split('-')[0]
    # Get also rid of '+'
    kver = kver.split('+')[0]

    return version.parse(kver) >= version.parse(min_kernel_version)

def copy_network_unit(*units, copy_dropins=True):
    """
    Copy networkd unit files into the testbed.

    Any networkd unit file type can be specified, as well as drop-in files.

    By default, all drop-ins for a specified unit file are copied in;
    to avoid that specify dropins=False.

    When a drop-in file is specified, its unit file is also copied in automatically.
    """
    has_link = False
    mkdir_p(network_unit_dir)
    for unit in units:
        if copy_dropins and os.path.exists(os.path.join(networkd_ci_temp_dir, unit + '.d')):
            cp_r(os.path.join(networkd_ci_temp_dir, unit + '.d'), os.path.join(network_unit_dir, unit + '.d'))

        if unit.endswith('.conf'):
            dropin = unit
            unit = os.path.dirname(dropin).rstrip('.d')
            dropindir = os.path.join(network_unit_dir, unit + '.d')
            mkdir_p(dropindir)
            cp(os.path.join(networkd_ci_temp_dir, dropin), dropindir)

        cp(os.path.join(networkd_ci_temp_dir, unit), network_unit_dir)

        if unit.endswith('.link'):
            has_link = True

    if has_link:
        udevadm_reload()

def copy_credential(src, target):
        mkdir_p(credstore_dir)
        cp(os.path.join(networkd_ci_temp_dir, src),
           os.path.join(credstore_dir, target))

def remove_network_unit(*units):
    """
    Remove previously copied unit files from the testbed.

    Drop-ins will be removed automatically.
    """
    has_link = False
    for unit in units:
        rm_f(os.path.join(network_unit_dir, unit))
        rm_rf(os.path.join(network_unit_dir, unit + '.d'))

        if unit.endswith('.link') or unit.endswith('.link.d'):
            has_link = True

    if has_link:
        udevadm_reload()

def touch_network_unit(*units):
    for unit in units:
        touch(os.path.join(network_unit_dir, unit))

def clear_network_units():
    has_link = False
    if os.path.exists(network_unit_dir):
        units = os.listdir(network_unit_dir)
        for unit in units:
            if unit.endswith('.link') or unit.endswith('.link.d'):
                has_link = True

    rm_rf(network_unit_dir)

    if has_link:
        udevadm_reload()

def copy_networkd_conf_dropin(*dropins):
    """Copy networkd.conf dropin files into the testbed."""
    mkdir_p(networkd_conf_dropin_dir)
    for dropin in dropins:
        cp(os.path.join(networkd_ci_temp_dir, dropin), networkd_conf_dropin_dir)

def remove_networkd_conf_dropin(*dropins):
    """Remove previously copied networkd.conf dropin files from the testbed."""
    for dropin in dropins:
        rm_f(os.path.join(networkd_conf_dropin_dir, dropin))

def clear_networkd_conf_dropins():
    rm_rf(networkd_conf_dropin_dir)

def setup_systemd_udev_rules():
    if not build_dir and not source_dir:
        return

    mkdir_p(udev_rules_dir)

    for path in [build_dir, source_dir]:
        if not path:
            continue

        path = os.path.join(path, "rules.d")
        print(f"Copying udev rules from {path} to {udev_rules_dir}")

        for rule in os.listdir(path):
            if not rule.endswith(".rules"):
                continue
            cp(os.path.join(path, rule), udev_rules_dir)

def clear_networkd_state_files():
    rm_rf('/var/lib/systemd/network/')

def copy_udev_rule(*rules):
    """Copy udev rules"""
    mkdir_p(udev_rules_dir)
    for rule in rules:
        cp(os.path.join(networkd_ci_temp_dir, rule), udev_rules_dir)

def remove_udev_rule(*rules):
    """Remove previously copied udev rules"""
    for rule in rules:
        rm_f(os.path.join(udev_rules_dir, rule))

def clear_udev_rules():
    rm_rf(udev_rules_dir)

def save_active_units():
    for u in ['systemd-networkd.socket', 'systemd-networkd.service',
              'systemd-resolved.service', 'systemd-timesyncd.service',
              'firewalld.service']:
        if call(f'systemctl is-active --quiet {u}') == 0:
            call(f'systemctl stop {u}')
            active_units.append(u)

def restore_active_units():
    if 'systemd-networkd.socket' in active_units:
        call('systemctl stop systemd-networkd.socket systemd-networkd.service')
    for u in active_units:
        call(f'systemctl restart {u}')

def create_unit_dropin(unit, contents):
    mkdir_p(f'/run/systemd/system/{unit}.d')
    with open(f'/run/systemd/system/{unit}.d/00-override.conf', mode='w', encoding='utf-8') as f:
        f.write('\n'.join(contents))

def create_service_dropin(service, command, additional_settings=None):
    drop_in = ['[Service]']
    if command:
        drop_in += [
            'ExecStart=',
            f'ExecStart=!!{valgrind_cmd}{command}',
        ]
    if enable_debug:
        drop_in += ['Environment=SYSTEMD_LOG_LEVEL=debug']
    if asan_options:
        drop_in += [f'Environment=ASAN_OPTIONS="{asan_options}"']
    if lsan_options:
        drop_in += [f'Environment=LSAN_OPTIONS="{lsan_options}"']
    if ubsan_options:
        drop_in += [f'Environment=UBSAN_OPTIONS="{ubsan_options}"']
    if asan_options or lsan_options or ubsan_options:
        drop_in += ['SystemCallFilter=']
    if use_valgrind or asan_options or lsan_options or ubsan_options:
        drop_in += ['MemoryDenyWriteExecute=no']
    if use_valgrind:
        drop_in += [
            'Environment=SYSTEMD_MEMPOOL=0',
            'PrivateTmp=yes',
        ]
    if with_coverage:
        drop_in += [
            'ProtectSystem=no',
            'ProtectHome=no',
        ]
    if additional_settings:
        drop_in += additional_settings

    create_unit_dropin(f'{service}.service', drop_in)

def setup_system_units():
    if build_dir or source_dir:
        mkdir_p('/run/systemd/system/')

        for unit in [
                'systemd-networkd.service',
                'systemd-networkd.socket',
                'systemd-networkd-persistent-storage.service',
                'systemd-resolved.service',
                'systemd-timesyncd.service',
                'systemd-udevd.service',
        ]:
            for path in [build_dir, source_dir]:
                if not path:
                    continue

                fullpath = os.path.join(os.path.join(path, "units"), unit)
                if os.path.exists(fullpath):
                    print(f"Copying unit file from {fullpath} to /run/systemd/system/")
                    cp(fullpath, '/run/systemd/system/')
                    break

    create_service_dropin('systemd-networkd', networkd_bin,
                          ['[Service]',
                           'Restart=no',
                           'Environment=SYSTEMD_NETWORK_TEST_MODE=yes',
                           '[Unit]',
                           'StartLimitIntervalSec=0'])
    create_service_dropin('systemd-resolved', resolved_bin)
    create_service_dropin('systemd-timesyncd', timesyncd_bin)

    # TODO: also run udevd with sanitizers, valgrind, or coverage
    create_unit_dropin(
        'systemd-udevd.service',
        [
            '[Service]',
            'ExecStart=',
            f'ExecStart=!!@{udevadm_bin} systemd-udevd',
        ]
    )
    create_unit_dropin(
        'systemd-networkd.socket',
        [
            '[Unit]',
            'StartLimitIntervalSec=0',
        ]
    )
    create_unit_dropin(
        'systemd-networkd-persistent-storage.service',
        [
            '[Unit]',
            'StartLimitIntervalSec=0',
            '[Service]',
            'ExecStart=',
            f'ExecStart={networkctl_bin} persistent-storage yes',
            'ExecStop=',
            f'ExecStop={networkctl_bin} persistent-storage no',
            'Environment=SYSTEMD_LOG_LEVEL=debug' if enable_debug else '',
        ]
    )

    check_output('systemctl daemon-reload')
    print(check_output('systemctl cat systemd-networkd.service'))
    print(check_output('systemctl cat systemd-networkd-persistent-storage.service'))
    print(check_output('systemctl cat systemd-resolved.service'))
    print(check_output('systemctl cat systemd-timesyncd.service'))
    print(check_output('systemctl cat systemd-udevd.service'))
    check_output('systemctl restart systemd-resolved.service')
    check_output('systemctl restart systemd-timesyncd.service')
    check_output('systemctl restart systemd-udevd.service')

def clear_system_units():
    def rm_unit(name):
        rm_f(f'/run/systemd/system/{name}')
        rm_rf(f'/run/systemd/system/{name}.d')

    rm_unit('systemd-networkd.service')
    rm_unit('systemd-networkd.socket')
    rm_unit('systemd-networkd-persistent-storage.service')
    rm_unit('systemd-resolved.service')
    rm_unit('systemd-timesyncd.service')
    rm_unit('systemd-udevd.service')
    check_output('systemctl daemon-reload')
    check_output('systemctl restart systemd-udevd.service')

def link_exists(*links):
    for link in links:
        if call_quiet(f'ip link show {link}') != 0:
            return False
    return True

def link_resolve(link):
    return check_output(f'ip link show {link}').split(':')[1].strip().split('@')[0]

def remove_link(*links, protect=False):
    for link in links:
        if protect and link in protected_links:
            continue
        if link_exists(link):
            call(f'ip link del dev {link}')

def save_existing_links():
    links = os.listdir('/sys/class/net')
    for link in links:
        if link_exists(link):
            protected_links.add(link)

    print('### The following links will be protected:')
    print(', '.join(sorted(list(protected_links))))

def unmanage_existing_links():
    mkdir_p(network_unit_dir)

    with open(os.path.join(network_unit_dir, '00-unmanaged.network'), mode='w', encoding='utf-8') as f:
        f.write('[Match]\n')
        for link in protected_links:
            f.write(f'Name={link}\n')
        f.write('\n[Link]\nUnmanaged=yes\n')

def flush_links():
    links = os.listdir('/sys/class/net')
    remove_link(*links, protect=True)

def flush_nexthops():
    # Currently, the 'ip nexthop' command does not have 'save' and 'restore'.
    # Hence, we cannot restore nexthops in a simple way.
    # Let's assume there is no nexthop used in the system
    call_quiet('ip nexthop flush')

def save_routes():
    # pylint: disable=global-statement
    global saved_routes
    saved_routes = check_output('ip route show table all')
    print('### The following routes will be protected:')
    print(saved_routes)

def flush_routes():
    have = False
    output = check_output('ip route show table all')
    for line in output.splitlines():
        if line in saved_routes:
            continue
        if 'proto kernel' in line:
            continue
        if ' dev ' in line and not ' dev lo ' in line:
            continue
        if not have:
            have = True
            print('### Removing routes that did not exist when the test started.')
        print(f'# {line}')
        call(f'ip route del {line}')

def save_routing_policy_rules():
    # pylint: disable=global-statement
    global saved_ipv4_rules, saved_ipv6_rules
    def save(ipv):
        output = check_output(f'ip -{ipv} rule show')
        print(f'### The following IPv{ipv} routing policy rules will be protected:')
        print(output)
        return output

    saved_ipv4_rules = save(4)
    saved_ipv6_rules = save(6)

def flush_routing_policy_rules():
    def flush(ipv, saved_rules):
        have = False
        output = check_output(f'ip -{ipv} rule show')
        for line in output.splitlines():
            if line in saved_rules:
                continue
            if not have:
                have = True
                print(f'### Removing IPv{ipv} routing policy rules that did not exist when the test started.')
            print(f'# {line}')
            words = line.replace('lookup [l3mdev-table]', 'l3mdev').replace('[detached]', '').split()
            priority = words[0].rstrip(':')
            call(f'ip -{ipv} rule del priority {priority} ' + ' '.join(words[1:]))

    flush(4, saved_ipv4_rules)
    flush(6, saved_ipv6_rules)

def flush_fou_ports():
    ret = run('ip fou show')
    if ret.returncode != 0:
        return # fou may not be supported
    for line in ret.stdout.splitlines():
        port = line.split()[1]
        call(f'ip fou del port {port}')

def flush_l2tp_tunnels():
    tids = []
    ret = run('ip l2tp show tunnel')
    if ret.returncode != 0:
        return # l2tp may not be supported
    for line in ret.stdout.splitlines():
        words = line.split()
        if words[0] == 'Tunnel':
            tid = words[1].rstrip(',')
            call(f'ip l2tp del tunnel tunnel_id {tid}')
            tids.append(tid)

    # Removing L2TP tunnel is asynchronous and slightly takes a time.
    for tid in tids:
        for _ in range(50):
            r = run(f'ip l2tp show tunnel tunnel_id {tid}')
            if r.returncode != 0 or len(r.stdout.rstrip()) == 0:
                break
            time.sleep(.2)
        else:
            print(f'Cannot remove L2TP tunnel {tid}, ignoring.')

def save_timezone():
    # pylint: disable=global-statement
    global saved_timezone
    r = run(*timedatectl_cmd, 'show', '--value', '--property', 'Timezone', env=env)
    if r.returncode == 0:
        saved_timezone = r.stdout.rstrip()
        print(f'### Saved timezone: {saved_timezone}')

def restore_timezone():
    if saved_timezone:
        call(*timedatectl_cmd, 'set-timezone', f'{saved_timezone}', env=env)

def read_link_attr(*args):
    with open(os.path.join('/sys/class/net', *args), encoding='utf-8') as f:
        return f.readline().strip()

def read_manager_state_file():
    with open('/run/systemd/netif/state', encoding='utf-8') as f:
        return f.read()

def read_link_state_file(link):
    ifindex = read_link_attr(link, 'ifindex')
    path = os.path.join('/run/systemd/netif/links', ifindex)
    with open(path, encoding='utf-8') as f:
        return f.read()

def read_ip_sysctl_attr(link, attribute, ipv):
    with open(os.path.join('/proc/sys/net', ipv, 'conf', link, attribute), encoding='utf-8') as f:
        return f.readline().strip()

def read_ip_neigh_sysctl_attr(link, attribute, ipv):
    with open(os.path.join('/proc/sys/net', ipv, 'neigh', link, attribute), encoding='utf-8') as f:
        return f.readline().strip()

def read_ipv6_sysctl_attr(link, attribute):
    return read_ip_sysctl_attr(link, attribute, 'ipv6')

def read_ipv6_neigh_sysctl_attr(link, attribute):
    return read_ip_neigh_sysctl_attr(link, attribute, 'ipv6')

def read_ipv4_sysctl_attr(link, attribute):
    return read_ip_sysctl_attr(link, attribute, 'ipv4')

def read_mpls_sysctl_attr(link, attribute):
    return read_ip_sysctl_attr(link, attribute, 'mpls')

def stop_by_pid_file(pid_file):
    if not os.path.exists(pid_file):
        return
    with open(pid_file, 'r', encoding='utf-8') as f:
        pid = f.read().rstrip(' \t\r\n\0')
        os.kill(int(pid), signal.SIGTERM)
        for _ in range(25):
            try:
                os.kill(int(pid), 0)
                print(f"PID {pid} is still alive, waiting...")
                time.sleep(.2)
            except OSError as e:
                if e.errno == errno.ESRCH:
                    break
                print(f"Unexpected exception when waiting for {pid} to die: {e.errno}")
    rm_f(pid_file)

def dnr_v4_instance_data(adn, addrs=None, prio=1, alpns=("dot",), dohpath=None):
    b = bytes()
    pack = lambda c, w=1: struct.pack('>' + "_BH_I"[w], len(c)) + c
    pyton = lambda n, w=2: struct.pack('>' + "_BH_I"[w], n)
    ipv4 = ipaddress.IPv4Address
    class SvcParam(enum.Enum):
        ALPN = 1
        DOHPATH = 7

    data = pyton(prio)

    adn = adn.rstrip('.') + '.'
    data += pack(b.join(pack(label.encode('ascii')) for label in adn.split('.')))

    if not addrs: # adn-only mode
        return pack(data, 2)

    data += pack(b.join(ipv4(addr).packed for addr in addrs))
    data += pyton(SvcParam.ALPN.value) + pack(b.join(pack(alpn.encode('ascii')) for alpn in alpns), 2)
    if dohpath is not None:
        data += pyton(SvcParam.DOHPATH.value) + pack(dohpath.encode('utf-8'), 2)

    return pack(data, 2)

def dnr_v6_instance_data(adn, addrs=None, prio=1, alpns=("dot",), dohpath=None):
    b = bytes()
    pack = lambda c, w=1: struct.pack('>' + "_BH_I"[w], len(c)) + c
    pyton = lambda n, w=2: struct.pack('>' + "_BH_I"[w], n)
    ipv6 = ipaddress.IPv6Address
    class SvcParam(enum.Enum):
        ALPN = 1
        DOHPATH = 7

    data = pyton(prio)

    adn = adn.rstrip('.') + '.'
    data += pack(b.join(pack(label.encode('ascii')) for label in adn.split('.')), 2)

    if not addrs: # adn-only mode
        return data

    data += pack(b.join(ipv6(addr).packed for addr in addrs), 2)
    data += pyton(SvcParam.ALPN.value) + pack(b.join(pack(alpn.encode('ascii')) for alpn in alpns), 2)
    if dohpath is not None:
        data += pyton(SvcParam.DOHPATH.value) + pack(dohpath.encode('utf-8'), 2)

    return data

def start_dnsmasq(*additional_options, interface='veth-peer', ra_mode=None, ipv4_range='192.168.5.10,192.168.5.200', ipv4_router='192.168.5.1', ipv6_range='2600::10,2600::20'):
    if ra_mode:
        ra_mode = f',{ra_mode}'
    else:
        ra_mode = ''

    command = (
        'dnsmasq',
        f'--log-facility={dnsmasq_log_file}',
        '--log-queries=extra',
        '--log-dhcp',
        f'--pid-file={dnsmasq_pid_file}',
        '--conf-file=/dev/null',
        '--bind-interfaces',
        f'--interface={interface}',
        f'--dhcp-leasefile={dnsmasq_lease_file}',
        '--enable-ra',
        f'--dhcp-range={ipv6_range}{ra_mode},2m',
        f'--dhcp-range={ipv4_range},2m',
        '--dhcp-option=option:mtu,1492',
        f'--dhcp-option=option:router,{ipv4_router}',
        '--port=0',
        '--no-resolv',
    ) + additional_options
    check_output(*command)

def stop_dnsmasq():
    stop_by_pid_file(dnsmasq_pid_file)
    rm_f(dnsmasq_lease_file)
    rm_f(dnsmasq_log_file)

def read_dnsmasq_log_file():
    with open(dnsmasq_log_file, encoding='utf-8') as f:
        return f.read()

def start_isc_dhcpd(conf_file, ipv, interface='veth-peer'):
    conf_file_path = os.path.join(networkd_ci_temp_dir, conf_file)
    isc_dhcpd_command = f'dhcpd {ipv} -cf {conf_file_path} -lf {isc_dhcpd_lease_file} -pf {isc_dhcpd_pid_file} {interface}'
    touch(isc_dhcpd_lease_file)
    check_output(isc_dhcpd_command)

def stop_isc_dhcpd():
    stop_by_pid_file(isc_dhcpd_pid_file)
    rm_f(isc_dhcpd_lease_file)

def get_dbus_link_path(link):
    out = subprocess.check_output(['busctl', 'call', 'org.freedesktop.network1',
                                   '/org/freedesktop/network1', 'org.freedesktop.network1.Manager',
                                   'GetLinkByName', 's', link])

    assert out.startswith(b'io ')
    out = out.strip()
    assert out.endswith(b'"')
    out = out.decode()
    return out[:-1].split('"')[1]

def get_dhcp_client_state(link, family):
    link_path = get_dbus_link_path(link)

    out = subprocess.check_output(['busctl', 'get-property', 'org.freedesktop.network1',
                                   link_path, f'org.freedesktop.network1.DHCPv{family}Client', 'State'])
    assert out.startswith(b's "')
    out = out.strip()
    assert out.endswith(b'"')
    return out[3:-1].decode()

def get_dhcp4_client_state(link):
    return get_dhcp_client_state(link, '4')

def get_dhcp6_client_state(link):
    return get_dhcp_client_state(link, '6')

def get_link_description(link):
    link_path = get_dbus_link_path(link)

    out = subprocess.check_output(['busctl', 'call', 'org.freedesktop.network1',
                                   link_path, 'org.freedesktop.network1.Link', 'Describe'])
    assert out.startswith(b's "')
    out = out.strip()
    assert out.endswith(b'"')
    json_raw = out[2:].decode()
    check_json(json_raw)
    description = json.loads(json_raw) # Convert from escaped sequences to json
    check_json(description)
    return json.loads(description) # Now parse the json

def start_radvd(*additional_options, config_file):
    config_file_path = os.path.join(networkd_ci_temp_dir, 'radvd', config_file)
    command = (
        'radvd',
        f'--pidfile={radvd_pid_file}',
        f'--config={config_file_path}',
        '--logmethod=stderr',
    ) + additional_options
    check_output(*command)

def stop_radvd():
    stop_by_pid_file(radvd_pid_file)

def radvd_check_config(config_file):
    if not shutil.which('radvd'):
        print('radvd is not installed, assuming the config check failed')
        return False

    # Note: can't use networkd_ci_temp_dir here, as this command may run before that dir is
    #       set up (one instance is @unittest.skipX())
    config_file_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'conf/radvd', config_file)
    return call(f'radvd --config={config_file_path} --configtest') == 0

def networkd_invocation_id():
    return check_output('systemctl show --value -p InvocationID systemd-networkd.service')

def networkd_pid():
    return check_output('systemctl show --value -p MainPID systemd-networkd.service')

def read_networkd_log(invocation_id=None, since=None):
    if not invocation_id:
        invocation_id = networkd_invocation_id()
    command = [
        'journalctl',
        '--no-hostname',
        '--output=short-monotonic',
        f'_SYSTEMD_INVOCATION_ID={invocation_id}',
    ]
    if since:
        command.append(f'--since={since}')
    check_output('journalctl --sync')
    return check_output(*command)

def networkd_is_failed():
    return call_quiet('systemctl is-failed -q systemd-networkd.service') != 1

def stop_networkd(show_logs=True, check_failed=True):
    global show_journal
    show_logs = show_logs and show_journal
    if show_logs:
        invocation_id = networkd_invocation_id()

    if check_failed:
        check_output('systemctl stop systemd-networkd.socket')
        check_output('systemctl stop systemd-networkd.service')
    else:
        call('systemctl stop systemd-networkd.socket')
        call('systemctl stop systemd-networkd.service')

    if show_logs:
        print(read_networkd_log(invocation_id))

    # Check if networkd exits cleanly.
    if check_failed:
        assert not networkd_is_failed()

def start_networkd():
    check_output('systemctl start systemd-networkd')
    invocation_id = networkd_invocation_id()
    pid = networkd_pid()
    print(f'Started systemd-networkd.service: PID={pid}, Invocation ID={invocation_id}')

def restart_networkd(show_logs=True):
    global show_journal
    show_logs = show_logs and show_journal
    if show_logs:
        invocation_id = networkd_invocation_id()
    check_output('systemctl restart systemd-networkd.service')
    if show_logs:
        print(read_networkd_log(invocation_id))

    invocation_id = networkd_invocation_id()
    pid = networkd_pid()
    print(f'Restarted systemd-networkd.service: PID={pid}, Invocation ID={invocation_id}')

def networkd_pid():
    return int(check_output('systemctl show --value -p MainPID systemd-networkd.service'))

def networkctl(*args):
    # Do not call networkctl if networkd is in failed state.
    # Otherwise, networkd may be restarted and we may get wrong results.
    assert not networkd_is_failed()
    return check_output(*(networkctl_cmd + list(args)), env=env)

def networkctl_status(*args):
    return networkctl('-n', '0', 'status', *args)

def networkctl_json(*args):
    return networkctl('--json=short', 'status', *args)

def networkctl_reconfigure(*links):
    networkctl('reconfigure', *links)

def networkctl_reload():
    networkctl('reload')

def resolvectl(*args):
    return check_output(*(resolvectl_cmd + list(args)), env=env)

def timedatectl(*args):
    return check_output(*(timedatectl_cmd + list(args)), env=env)

def udevadm(*args):
    return check_output(*(udevadm_cmd + list(args)))

def udevadm_reload():
    udevadm('control', '--reload')

def udevadm_trigger(*args, action='add'):
    udevadm('trigger', '--settle', f'--action={action}', *args)

def setup_common():
    # Protect existing links
    unmanage_existing_links()

    # We usually show something in each test. So, let's break line to make the title of a test and output
    # from the test mixed. Then, flush stream buffer and journals.
    print()
    sys.stdout.flush()
    check_output('journalctl --sync')

def tear_down_common():
    # 1. stop DHCP/RA servers
    stop_dnsmasq()
    stop_isc_dhcpd()
    stop_radvd()

    # 2. remove modules
    call_quiet('rmmod netdevsim')
    call_quiet('rmmod sch_teql')

    # 3. remove network namespace
    call_quiet('ip netns del ns99')

    # 4. remove links
    flush_l2tp_tunnels()
    flush_links()

    # 5. stop networkd
    stop_networkd(check_failed=False)

    # 6. remove configs
    clear_network_units()
    clear_networkd_conf_dropins()
    clear_networkd_state_files()

    # 7. flush settings
    flush_fou_ports()
    flush_nexthops()
    flush_routing_policy_rules()
    flush_routes()

    # 8. flush stream buffer and journals to make not any output from the test with the next one
    sys.stdout.flush()
    check_output('journalctl --sync')

    # 9. check the status of networkd
    assert not networkd_is_failed()

def setUpModule():
    rm_rf(networkd_ci_temp_dir)
    cp_r(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'conf'), networkd_ci_temp_dir)

    clear_network_units()
    clear_networkd_conf_dropins()
    clear_networkd_state_files()
    clear_udev_rules()

    setup_systemd_udev_rules()
    copy_udev_rule('00-debug-net.rules')

    # Save current state
    save_active_units()
    save_existing_links()
    save_routes()
    save_routing_policy_rules()
    save_timezone()

    setup_system_units()

def tearDownModule():
    rm_rf(networkd_ci_temp_dir)
    clear_udev_rules()
    clear_network_units()
    clear_networkd_conf_dropins()
    clear_networkd_state_files()

    restore_timezone()

    clear_system_units()
    restore_active_units()

    # Flush stream buffer and journals before showing the test summary.
    sys.stdout.flush()
    check_output('journalctl --sync')

class Utilities():
    # pylint: disable=no-member

    def check_link_exists(self, *link, expected=True):
        if expected:
            self.assertTrue(link_exists(*link))
        else:
            self.assertFalse(link_exists(*link))

    def check_link_attr(self, *args):
        self.assertEqual(read_link_attr(*args[:-1]), args[-1])

    def check_bridge_port_attr(self, master, port, attribute, expected, allow_enoent=False):
        path = os.path.join('/sys/devices/virtual/net', master, 'lower_' + port, 'brport', attribute)
        if allow_enoent and not os.path.exists(path):
            return
        with open(path, encoding='utf-8') as f:
            self.assertEqual(f.readline().strip(), expected)

    def check_ipv4_sysctl_attr(self, link, attribute, expected):
        self.assertEqual(read_ipv4_sysctl_attr(link, attribute), expected)

    def check_ipv6_sysctl_attr(self, link, attribute, expected):
        self.assertEqual(read_ipv6_sysctl_attr(link, attribute), expected)

    def check_ipv6_neigh_sysctl_attr(self, link, attribute, expected):
        self.assertEqual(read_ipv6_neigh_sysctl_attr(link, attribute), expected)

    def check_mpls_sysctl_attr(self, link, attribute, expected):
        self.assertEqual(read_mpls_sysctl_attr(link, attribute), expected)

    def wait_links(self, *links, trial=40):
        for _ in range(trial):
            if link_exists(*links):
                break
            time.sleep(0.5)
        else:
            self.fail('Timed out waiting for all links to be created: ' + ', '.join(list(links)))

    def wait_activated(self, link, state='down', trial=40):
        # wait for the interface is activated.
        needle = f'{link}: Bringing link {state}'
        flag = state.upper()
        self.wait_links(link, trial=trial)
        self.check_networkd_log(needle, trial=trial)
        for _ in range(trial):
            if flag in check_output(f'ip link show {link}'):
                break
            time.sleep(0.5)
        else:
            self.fail(f'Timed out waiting for {link} activated.')

    def wait_operstate(self, link, operstate='degraded', setup_state='configured', setup_timeout=5, fail_assert=True):
        """Wait for the link to reach the specified operstate and/or setup state.

        Specify None or '' for either operstate or setup_state to ignore that state.
        This will recheck until the state conditions are met or the timeout expires.

        If the link successfully matches the requested state, this returns True.
        If this times out waiting for the link to match, the behavior depends on the
        'fail_assert' parameter; if True, this causes a test assertion failure,
        otherwise this returns False.  The default is to cause assertion failure.

        Note that this function matches on *exactly* the given operstate and setup_state.
        To wait for a link to reach *or exceed* a given operstate, use wait_online().
        """
        if not operstate:
            operstate = r'\S+'
        if not setup_state:
            setup_state = r'\S+'

        for _ in range(setup_timeout * 2):
            if not link_exists(link):
                time.sleep(0.5)
                continue
            output = networkctl_status(link)
            if re.search(rf'(?m)^\s*State:\s+{operstate}\s+\({setup_state}\)\s*$', output):
                return True
            time.sleep(0.5)

        if fail_assert:
            self.fail(f'Timed out waiting for {link} to reach state {operstate}/{setup_state}')
        return False

    def wait_online(self, *links_with_operstate, timeout='20s', bool_any=False, ipv4=False, ipv6=False, setup_state='configured', setup_timeout=5, bool_dns=False):
        """Wait for the links to reach the specified operstate and/or setup state.

        This is similar to wait_operstate() but can be used for multiple links,
        and it also calls systemd-networkd-wait-online to wait for the given operstate.
        The operstate should be specified in the link name, like 'eth0:degraded'.
        If just a link name is provided, wait-online's default operstate to wait for is degraded.

        The 'timeout' parameter controls the systemd-networkd-wait-online timeout, and the
        'setup_timeout' controls the per-link timeout waiting for the setup_state.

        Set 'bool_any' to True to wait for any (instead of all) of the given links.
        If this is set, no setup_state checks are done.

        Set 'bool_dns' to True to wait for DNS servers to be accessible.

        Set 'ipv4' or 'ipv6' to True to wait for IPv4 address or IPv6 address, respectively, of each of the given links.
        This is applied only for the operational state 'degraded' or above.

        Note that this function waits for the links to reach *or exceed* the given operstate.
        However, the setup_state, if specified, must be matched *exactly*.

        This returns if the links reached the requested operstate/setup_state; otherwise it
        raises CalledProcessError or fails test assertion.
        """
        args = wait_online_cmd + [f'--timeout={timeout}'] + [f'--interface={link}' for link in links_with_operstate] + [f'--ignore={link}' for link in protected_links]
        if bool_any:
            args += ['--any']
        if bool_dns:
            args += ['--dns']
        if ipv4:
            args += ['--ipv4']
        if ipv6:
            args += ['--ipv6']
        try:
            check_output(*args, env=wait_online_env)
        except subprocess.CalledProcessError:
            if networkd_is_failed():
                print('!!!!! systemd-networkd.service is failed !!!!!')
                call('systemctl status systemd-networkd.service')
            else:
                # show detailed status on failure
                for link in links_with_operstate:
                    name = link.split(':')[0]
                    if link_exists(name):
                        print(networkctl_status(name))
                    else:
                        print(f'Interface {name} not found.')
            raise
        if not bool_any and setup_state:
            for link in links_with_operstate:
                self.wait_operstate(link.split(':')[0], None, setup_state, setup_timeout)

    def wait_address(self, link, address_regex, scope='global', ipv='', timeout_sec=100):
        for _ in range(timeout_sec * 2):
            output = check_output(f'ip {ipv} address show dev {link} scope {scope}')
            if re.search(address_regex, output) and 'tentative' not in output:
                break
            time.sleep(0.5)

        self.assertRegex(output, address_regex)

    def wait_address_dropped(self, link, address_regex, scope='global', ipv='', timeout_sec=100):
        for _ in range(timeout_sec * 2):
            output = check_output(f'ip {ipv} address show dev {link} scope {scope}')
            if not re.search(address_regex, output):
                break
            time.sleep(0.5)

        self.assertNotRegex(output, address_regex)

    def wait_route(self, link, route_regex, table='main', ipv='', timeout_sec=100):
        for _ in range(timeout_sec * 2):
            output = check_output(f'ip {ipv} route show dev {link} table {table}')
            if re.search(route_regex, output):
                break
            time.sleep(0.5)

        self.assertRegex(output, route_regex)

    def wait_route_dropped(self, link, route_regex, table='main', ipv='', timeout_sec=100):
        for _ in range(timeout_sec * 2):
            output = check_output(f'ip {ipv} route show dev {link} table {table}')
            if not re.search(route_regex, output):
                break
            time.sleep(0.5)

        self.assertNotRegex(output, route_regex)

    def check_netlabel(self, interface, address, label='system_u:object_r:root_t:s0'):
        if not shutil.which('selinuxenabled'):
            print('## Checking NetLabel skipped: selinuxenabled command not found.')
        elif call_quiet('selinuxenabled') != 0:
            print('## Checking NetLabel skipped: SELinux disabled.')
        elif not shutil.which('netlabelctl'): # not packaged by all distros
            print('## Checking NetLabel skipped: netlabelctl command not found.')
        else:
            output = check_output('netlabelctl unlbl list')
            print(output)
            self.assertRegex(output, f'interface:{interface},address:{address},label:"{label}"')

    def setup_nftset(self, filter_name, filter_type, flags=''):
        if not shutil.which('nft'):
            print('## Setting up NFT sets skipped: nft command not found.')
        else:
            if call(f'nft add table inet sd_test') != 0:
                print('## Setting up NFT table failed.')
                self.fail()
            if call(f'nft add set inet sd_test {filter_name} {{ type {filter_type}; {flags} }}') != 0:
                print('## Setting up NFT sets failed.')
                self.fail()

    def teardown_nftset(self, *filters):
        if not shutil.which('nft'):
            print('## Tearing down NFT sets skipped: nft command not found.')
        else:
            for filter_name in filters:
                if call(f'nft delete set inet sd_test {filter_name}') != 0:
                    print('## Tearing down NFT sets failed.')
                    self.fail()
            if call(f'nft delete table inet sd_test') != 0:
                print('## Tearing down NFT table failed.')
                self.fail()

    def check_nftset(self, filter_name, contents):
        if not shutil.which('nft'):
            print('## Checking NFT sets skipped: nft command not found.')
        else:
            output = check_output(f'nft list set inet sd_test {filter_name}')
            print(output)
            self.assertRegex(output, r'.*elements = { [^}]*' + contents + r'[^}]* }.*')

    def check_networkd_log(self, contents, since=None, trial=20):
        for _ in range(trial):
            if contents in read_networkd_log(since=since):
                break
            time.sleep(0.5)
        else:
            self.fail(f'"{contents}" not found in journal.')

    def networkctl_check_unit(self, ifname, netdev_file=None, network_file=None, link_file=None):
        output = networkctl_status(ifname)
        print(output)
        if netdev_file:
            self.assertRegex(output, rf'NetDev File: .*/{netdev_file}\.netdev')
        else:
            self.assertNotIn('NetDev File:', output)
        if network_file:
            self.assertRegex(output, rf'Network File: .*/{network_file}\.network')
        else:
            self.assertIn('Network File: n/a', output)
        if link_file:
            self.assertRegex(output, rf'Link File: .*/{link_file}\.link')

class NetworkctlTests(unittest.TestCase, Utilities):

    def setUp(self):
        setup_common()

    def tearDown(self):
        tear_down_common()

    @expectedFailureIfAlternativeNameIsNotAvailable()
    def test_altname(self):
        copy_network_unit('26-netdev-link-local-addressing-yes.network', '12-dummy.netdev', '12-dummy.link')
        start_networkd()
        self.wait_online('dummy98:degraded')

        output = networkctl_status('dummy98')
        self.assertRegex(output, 'hogehogehogehogehogehoge')

    @expectedFailureIfAlternativeNameIsNotAvailable()
    def test_rename_to_altname(self):
        copy_network_unit('26-netdev-link-local-addressing-yes.network',
                          '12-dummy.netdev', '12-dummy-rename-to-altname.link')
        start_networkd()
        self.wait_online('dummyalt:degraded')

        output = networkctl_status('dummyalt')
        self.assertIn('hogehogehogehogehogehoge', output)
        self.assertNotIn('dummy98', output)

    def test_reconfigure(self):
        copy_network_unit('25-address-static.network', '12-dummy.netdev', copy_dropins=False)
        start_networkd()
        self.wait_online('dummy98:routable')

        output = check_output('ip -4 address show dev dummy98')
        print(output)
        self.assertIn('inet 10.1.2.3/16 brd 10.1.255.255 scope global dummy98', output)
        self.assertIn('inet 10.1.2.4/16 brd 10.1.255.255 scope global secondary dummy98', output)
        self.assertIn('inet 10.2.2.4/16 brd 10.2.255.255 scope global dummy98', output)

        check_output('ip address del 10.1.2.3/16 dev dummy98')
        check_output('ip address del 10.1.2.4/16 dev dummy98')
        check_output('ip address del 10.2.2.4/16 dev dummy98')

        networkctl_reconfigure('dummy98')
        self.wait_online('dummy98:routable')

        output = check_output('ip -4 address show dev dummy98')
        print(output)
        self.assertIn('inet 10.1.2.3/16 brd 10.1.255.255 scope global dummy98', output)
        self.assertIn('inet 10.1.2.4/16 brd 10.1.255.255 scope global secondary dummy98', output)
        self.assertIn('inet 10.2.2.4/16 brd 10.2.255.255 scope global dummy98', output)

        remove_network_unit('25-address-static.network')

        networkctl_reload()
        self.wait_operstate('dummy98', 'degraded', setup_state='unmanaged')

        output = check_output('ip -4 address show dev dummy98')
        print(output)
        self.assertNotIn('inet 10.1.2.3/16 brd 10.1.255.255 scope global dummy98', output)
        self.assertNotIn('inet 10.1.2.4/16 brd 10.1.255.255 scope global secondary dummy98', output)
        self.assertNotIn('inet 10.2.2.4/16 brd 10.2.255.255 scope global dummy98', output)

        copy_network_unit('25-address-static.network', copy_dropins=False)
        networkctl_reload()
        self.wait_online('dummy98:routable')

        output = check_output('ip -4 address show dev dummy98')
        print(output)
        self.assertIn('inet 10.1.2.3/16 brd 10.1.255.255 scope global dummy98', output)
        self.assertIn('inet 10.1.2.4/16 brd 10.1.255.255 scope global secondary dummy98', output)
        self.assertIn('inet 10.2.2.4/16 brd 10.2.255.255 scope global dummy98', output)

    def test_renew(self):
        def check():
            self.wait_online('veth99:routable', 'veth-peer:routable')
            output = networkctl_status('veth99')
            print(output)
            self.assertRegex(output, r'Address: 192.168.5.[0-9]* \(DHCPv4 via 192.168.5.1\)')
            self.assertIn('Gateway: 192.168.5.3', output)
            self.assertRegex(output, 'DNS: 192.168.5.1\n *192.168.5.10')
            self.assertRegex(output, 'NTP: 192.168.5.1\n *192.168.5.11')

        copy_network_unit('25-veth.netdev', '25-dhcp-client.network', '25-dhcp-server.network')
        start_networkd()
        check()
        check_json(networkctl_json('--lines=0', '--stats', '--all', '--full'))

        for verb in ['renew', 'forcerenew']:
            networkctl(verb, 'veth99')
            check()
            networkctl(verb, 'veth99', 'veth99', 'veth99')
            check()

    def test_up_down(self):
        copy_network_unit('25-address-static.network', '12-dummy.netdev', copy_dropins=False)
        start_networkd()
        self.wait_online('dummy98:routable')

        networkctl('down', 'dummy98')
        self.wait_online('dummy98:off')
        networkctl('up', 'dummy98')
        self.wait_online('dummy98:routable')
        networkctl('down', 'dummy98', 'dummy98', 'dummy98')
        self.wait_online('dummy98:off')
        networkctl('up', 'dummy98', 'dummy98', 'dummy98')
        self.wait_online('dummy98:routable')

    def test_reload(self):
        start_networkd()

        copy_network_unit('11-dummy.netdev')
        networkctl_reload()
        self.wait_operstate('test1', 'off', setup_state='unmanaged')

        copy_network_unit('11-dummy.network')
        networkctl_reload()
        self.wait_online('test1:degraded')

        remove_network_unit('11-dummy.network')
        networkctl_reload()
        self.wait_operstate('test1', 'degraded', setup_state='unmanaged')

        remove_network_unit('11-dummy.netdev')
        networkctl_reload()
        self.wait_operstate('test1', 'degraded', setup_state='unmanaged')

        copy_network_unit('11-dummy.netdev', '11-dummy.network')
        networkctl_reload()
        self.wait_operstate('test1', 'degraded')

    def test_glob(self):
        copy_network_unit('11-dummy.netdev', '11-dummy.network')
        start_networkd()

        self.wait_online('test1:degraded')

        output = networkctl('list')
        self.assertRegex(output, '1 lo ')
        self.assertRegex(output, 'test1')

        output = networkctl('list', 'test1')
        self.assertNotRegex(output, '1 lo ')
        self.assertRegex(output, 'test1')

        output = networkctl('list', 'te*')
        self.assertNotRegex(output, '1 lo ')
        self.assertRegex(output, 'test1')

        output = networkctl_status('te*')
        self.assertNotRegex(output, '1: lo ')
        self.assertRegex(output, 'test1')

        output = networkctl_status('tes[a-z][0-9]')
        self.assertNotRegex(output, '1: lo ')
        self.assertRegex(output, 'test1')

    def test_mtu(self):
        copy_network_unit('11-dummy-mtu.netdev', '11-dummy.network')
        start_networkd()

        self.wait_online('test1:degraded')

        output = networkctl_status('test1')
        self.assertRegex(output, 'MTU: 1600')

    def test_type(self):
        copy_network_unit('11-dummy.netdev', '11-dummy.network')
        start_networkd()
        self.wait_online('test1:degraded')

        output = networkctl_status('test1')
        print(output)
        self.assertRegex(output, 'Type: ether')

        output = networkctl_status('lo')
        print(output)
        self.assertRegex(output, 'Type: loopback')

    def test_unit_file(self):
        copy_network_unit('11-test-unit-file.netdev', '11-test-unit-file.network', '11-test-unit-file.link')
        start_networkd()
        self.wait_online('test1:degraded')

        output = networkctl_status('test1')
        print(output)
        self.assertIn('Link File: /run/systemd/network/11-test-unit-file.link', output)
        self.assertIn('/run/systemd/network/11-test-unit-file.link.d/dropin.conf', output)
        self.assertIn('Network File: /run/systemd/network/11-test-unit-file.network', output)
        self.assertIn('/run/systemd/network/11-test-unit-file.network.d/dropin.conf', output)

        self.check_networkd_log('test1: Configuring with /run/systemd/network/11-test-unit-file.network (dropins: /run/systemd/network/11-test-unit-file.network.d/dropin.conf).')

        # This test may be run on the system that has older udevd than 70f32a260b5ebb68c19ecadf5d69b3844896ba55 (v249).
        # In that case, the udev DB for the loopback network interface may already have ID_NET_LINK_FILE property.
        # Let's reprocess the interface and drop the property.
        udevadm_trigger('/sys/class/net/lo')
        output = networkctl_status('lo')
        print(output)
        self.assertIn('Link File: n/a', output)
        self.assertIn('Network File: n/a', output)

    def test_delete_links(self):
        copy_network_unit('11-dummy.netdev', '25-veth.netdev')
        start_networkd()
        self.wait_links('test1', 'veth99', 'veth-peer')
        networkctl('delete', 'test1', 'veth99')
        self.check_link_exists('test1', 'veth99', 'veth-peer', expected=False)

    def test_label(self):
        networkctl('label')

class NetworkdMatchTests(unittest.TestCase, Utilities):

    def setUp(self):
        setup_common()

    def tearDown(self):
        tear_down_common()

    @expectedFailureIfAlternativeNameIsNotAvailable()
    def test_match(self):
        copy_network_unit('12-dummy-mac.netdev',
                          '12-dummy-match-mac-01.network',
                          '12-dummy-match-mac-02.network',
                          '12-dummy-match-renamed.network',
                          '12-dummy-match-altname.network',
                          '12-dummy-altname.link')
        start_networkd()

        self.wait_online('dummy98:routable')
        output = networkctl_status('dummy98')
        self.assertIn('Network File: /run/systemd/network/12-dummy-match-mac-01.network', output)
        output = check_output('ip -4 address show dev dummy98')
        self.assertIn('10.0.0.1/16', output)

        check_output('ip link set dev dummy98 down')
        check_output('ip link set dev dummy98 address 12:34:56:78:9a:02')

        self.wait_address('dummy98', '10.0.0.2/16', ipv='-4', timeout_sec=10)
        self.wait_online('dummy98:routable')
        output = networkctl_status('dummy98')
        self.assertIn('Network File: /run/systemd/network/12-dummy-match-mac-02.network', output)

        check_output('ip link set dev dummy98 down')
        check_output('ip link set dev dummy98 name dummy98-1')

        self.wait_address('dummy98-1', '10.0.1.2/16', ipv='-4', timeout_sec=10)
        self.wait_online('dummy98-1:routable')
        output = networkctl_status('dummy98-1')
        self.assertIn('Network File: /run/systemd/network/12-dummy-match-renamed.network', output)

        check_output('ip link set dev dummy98-1 down')
        check_output('ip link set dev dummy98-1 name dummy98-2')
        udevadm_trigger('/sys/class/net/dummy98-2')

        self.wait_address('dummy98-2', '10.0.2.2/16', ipv='-4', timeout_sec=10)
        self.wait_online('dummy98-2:routable')
        output = networkctl_status('dummy98-2')
        self.assertIn('Network File: /run/systemd/network/12-dummy-match-altname.network', output)

    def test_match_udev_property(self):
        copy_network_unit('12-dummy.netdev', '13-not-match-udev-property.network', '14-match-udev-property.network')
        start_networkd()
        self.wait_online('dummy98:routable')

        output = networkctl_status('dummy98')
        print(output)
        self.assertRegex(output, 'Network File: /run/systemd/network/14-match-udev-property')

class WaitOnlineTests(unittest.TestCase, Utilities):

    def setUp(self):
        setup_common()

    def tearDown(self):
        tear_down_common()

    def test_wait_online_any(self):
        copy_network_unit('25-bridge.netdev', '25-bridge.network', '11-dummy.netdev', '11-dummy.network')
        start_networkd()

        self.wait_online('bridge99', 'test1:degraded', bool_any=True)

        self.wait_operstate('bridge99', '(off|no-carrier)', setup_state='configuring')
        self.wait_operstate('test1', 'degraded')

    def do_test_wait_online_dns(
        self,
        global_dns='',
        fallback_dns='',
        expect_timeout=False,
        network_dropin=None,
    ):
        global wait_online_env

        if network_dropin is not None:
            network_dropin_path = os.path.join(
                network_unit_dir,
                '25-dhcp-client-use-dns-ipv4.network.d/test.conf'
            )
            mkdir_p(os.path.dirname(network_dropin_path))
            with open(network_dropin_path, 'w') as f:
                f.write(network_dropin)

        copy_network_unit(
            '25-veth.netdev',
            '25-dhcp-client-use-dns-ipv4.network',
            '25-dhcp-server.network'
        )
        start_networkd()
        self.wait_online('veth-peer:routable')

        # Unless given, clear global DNS configuration
        resolved_dropin = '/run/systemd/resolved.conf.d/global-dns.conf'
        mkdir_p(os.path.dirname(resolved_dropin))
        with open(resolved_dropin, 'w') as f:
            f.write((
                '[Resolve]\n'
                f'DNS={global_dns}\n'
                f'FallbackDNS={fallback_dns}\n'
            ))
        self.addCleanup(os.remove, resolved_dropin)
        check_output('systemctl reload systemd-resolved')

        try:
            wait_online_env_copy = wait_online_env.copy()

            wait_online_env['SYSTEMD_LOG_LEVEL'] = 'debug'
            wait_online_env['SYSTEMD_LOG_TARGET'] = 'console'

            self.wait_online('veth99:routable', bool_dns=True)

            if expect_timeout:
                # The above should have thrown an exception.
                self.fail(
                    'Expected systemd-networkd-wait-online to time out'
                )

        except subprocess.CalledProcessError as e:
            if expect_timeout:
                self.assertRegex(
                    e.output,
                    f'veth99: No link-specific DNS server is accessible',
                    f'Missing expected log message:\n{e.output}'
                )
            else:
                self.fail(
                    f'Command timed out:\n{e.output}'
                )
        finally:
            wait_online_env = wait_online_env_copy

    def test_wait_online_dns(self):
        ''' test systemd-networkd-wait-online with --dns '''
        self.do_test_wait_online_dns()

    def test_wait_online_dns_global(self):
        '''
        test systemd-networkd-wait-online with --dns, expect pass due to global DNS
        '''

        # Set UseDNS=no, and allow global DNS to be used.
        self.do_test_wait_online_dns(
            global_dns='192.168.5.1',
            network_dropin=(
                '[DHCPv4]\n'
                'UseDNS=no\n'
            )
        )

    def test_wait_online_dns_expect_timeout(self):
        ''' test systemd-networkd-wait-online with --dns, and expect timeout '''

        # Explicitly set DNSDefaultRoute=yes, and require link-specific DNS to be used.
        self.do_test_wait_online_dns(
            expect_timeout=True,
            network_dropin=(
                '[Network]\n'
                'DNSDefaultRoute=yes\n'
                '[DHCPv4]\n'
                'UseDNS=no\n'
            )
        )

    def test_wait_online_dns_expect_timeout_global(self):
        '''
        test systemd-networkd-wait-online with --dns, and expect timeout
        despite global DNS
        '''

        # Configure Domains=~., and expect timeout despite global DNS servers
        # being available.
        self.do_test_wait_online_dns(
            expect_timeout=True,
            global_dns='192.168.5.1',
            network_dropin=(
                '[Network]\n'
                'Domains=~.\n'
                '[DHCPv4]\n'
                'UseDNS=no\n'
            )
        )


class NetworkdNetDevTests(unittest.TestCase, Utilities):

    def setUp(self):
        setup_common()

    def tearDown(self):
        tear_down_common()

    def test_dropin_and_name_conflict(self):
        copy_network_unit('10-dropin-test.netdev', '15-name-conflict-test.netdev')
        start_networkd()

        self.wait_online('dropin-test:off', setup_state='unmanaged')

        output = check_output('ip link show dropin-test')
        print(output)
        self.assertRegex(output, '00:50:56:c0:00:28')

    @expectedFailureIfModuleIsNotAvailable('bareudp')
    def test_bareudp(self):
        copy_network_unit('25-bareudp.netdev', '26-netdev-link-local-addressing-yes.network')
        start_networkd()

        self.wait_online('bareudp99:degraded')
        self.networkctl_check_unit('bareudp99', '25-bareudp', '26-netdev-link-local-addressing-yes')

        output = check_output('ip -d link show bareudp99')
        print(output)
        self.assertRegex(output, 'dstport 1000 ')
        self.assertRegex(output, 'ethertype ip ')
        self.assertRegex(output, 'srcportmin 1001 ')

        touch_network_unit('25-bareudp.netdev', '26-netdev-link-local-addressing-yes.network')
        networkctl_reload()
        self.wait_online('bareudp99:degraded')

    @expectedFailureIfModuleIsNotAvailable('batman-adv')
    def test_batadv(self):
        copy_network_unit('25-batadv.netdev', '26-netdev-link-local-addressing-yes.network')
        start_networkd()

        self.wait_online('batadv99:degraded')
        self.networkctl_check_unit('batadv99', '25-batadv', '26-netdev-link-local-addressing-yes')

        output = check_output('ip -d link show batadv99')
        print(output)
        self.assertRegex(output, 'batadv')

        touch_network_unit('25-batadv.netdev', '26-netdev-link-local-addressing-yes.network')
        networkctl_reload()
        self.wait_online('batadv99:degraded')

    def test_bridge(self):
        copy_network_unit('25-bridge.netdev', '25-bridge-configure-without-carrier.network')
        start_networkd()

        self.wait_online('bridge99:no-carrier')
        self.networkctl_check_unit('bridge99', '25-bridge', '25-bridge-configure-without-carrier')

        tick = os.sysconf('SC_CLK_TCK')
        self.assertEqual(9, round(float(read_link_attr('bridge99', 'bridge', 'hello_time')) / tick))
        self.assertEqual(9, round(float(read_link_attr('bridge99', 'bridge', 'max_age')) / tick))
        self.assertEqual(9, round(float(read_link_attr('bridge99', 'bridge', 'forward_delay')) / tick))
        self.assertEqual(9, round(float(read_link_attr('bridge99', 'bridge', 'ageing_time')) / tick))
        self.assertEqual(9,         int(read_link_attr('bridge99', 'bridge', 'priority')))
        self.assertEqual(1,         int(read_link_attr('bridge99', 'bridge', 'multicast_querier')))
        self.assertEqual(1,         int(read_link_attr('bridge99', 'bridge', 'multicast_snooping')))
        self.assertEqual(1,         int(read_link_attr('bridge99', 'bridge', 'stp_state')))
        self.assertEqual(3,         int(read_link_attr('bridge99', 'bridge', 'multicast_igmp_version')))
        self.assertEqual(1,         int(read_link_attr('bridge99', 'bridge', 'no_linklocal_learn')))

        output = networkctl_status('bridge99')
        print(output)
        self.assertRegex(output, 'Priority: 9')
        self.assertRegex(output, 'STP: yes')
        self.assertRegex(output, 'Multicast IGMP Version: 3')
        if 'FDB Max Learned' in output:
            self.assertRegex(output, 'FDB Max Learned: 4')

        output = check_output('ip -d link show bridge99')
        print(output)
        self.assertIn('vlan_filtering 1 ', output)
        self.assertIn('vlan_protocol 802.1ad ', output)
        self.assertIn('vlan_default_pvid 9 ', output)
        if 'fdb_max_learned' in output:
            self.assertIn('fdb_max_learned 4 ', output)

    def test_bond(self):
        copy_network_unit('25-bond.netdev', '25-bond-balanced-tlb.netdev', '25-bond-property.netdev')
        start_networkd()

        self.wait_online('bond99:off', 'bond98:off', 'bond97:off', setup_state='unmanaged')
        self.networkctl_check_unit('bond99', '25-bond')
        self.networkctl_check_unit('bond98', '25-bond-balanced-tlb')
        self.networkctl_check_unit('bond97', '25-bond-property')

        self.check_link_attr('bond99', 'bonding', 'mode',              '802.3ad 4')
        self.check_link_attr('bond99', 'bonding', 'xmit_hash_policy',  'layer3+4 1')
        self.check_link_attr('bond99', 'bonding', 'miimon',            '1000')
        self.check_link_attr('bond99', 'bonding', 'lacp_rate',         'fast 1')
        self.check_link_attr('bond99', 'bonding', 'updelay',           '2000')
        self.check_link_attr('bond99', 'bonding', 'downdelay',         '2000')
        self.check_link_attr('bond99', 'bonding', 'resend_igmp',       '4')
        self.check_link_attr('bond99', 'bonding', 'min_links',         '1')
        self.check_link_attr('bond99', 'bonding', 'ad_actor_sys_prio', '1218')
        self.check_link_attr('bond99', 'bonding', 'ad_user_port_key',  '811')
        self.check_link_attr('bond99', 'bonding', 'ad_actor_system',   '00:11:22:33:44:55')

        self.check_link_attr('bond98', 'bonding', 'mode',              'balance-tlb 5')
        self.check_link_attr('bond98', 'bonding', 'tlb_dynamic_lb',    '1')

        output = networkctl_status('bond99')
        print(output)
        self.assertIn('Mode: 802.3ad', output)
        self.assertIn('Miimon: 1s', output)
        self.assertIn('Updelay: 2s', output)
        self.assertIn('Downdelay: 2s', output)

        output = networkctl_status('bond98')
        print(output)
        self.assertIn('Mode: balance-tlb', output)

        output = networkctl_status('bond97')
        print(output)

        self.check_link_attr('bond97', 'bonding', 'arp_missed_max',    '10')
        self.check_link_attr('bond97', 'bonding', 'peer_notif_delay', '300000')

    def check_vlan(self, id, flags):
        self.wait_online('test1:degraded', 'vlan99:routable')
        self.networkctl_check_unit('vlan99', '21-vlan', '21-vlan')
        self.networkctl_check_unit('test1', '11-dummy', '21-vlan-test1')

        output = check_output('ip -d link show test1')
        print(output)
        self.assertRegex(output, ' mtu 2000 ')

        output = check_output('ip -d link show vlan99')
        print(output)
        self.assertIn(' mtu 2000 ', output)
        if flags:
            self.assertIn('REORDER_HDR', output)
            self.assertIn('LOOSE_BINDING', output)
            self.assertIn('GVRP', output)
            self.assertIn('MVRP', output)
        else:
            self.assertNotIn('REORDER_HDR', output)
            self.assertNotIn('LOOSE_BINDING', output)
            self.assertNotIn('GVRP', output)
            self.assertNotIn('MVRP', output)
        self.assertIn(f' id {id} ', output)
        self.assertIn('ingress-qos-map { 4:100 7:13 }', output)
        self.assertIn('egress-qos-map { 0:1 1:3 6:6 7:7 10:3 }', output)

        output = check_output('ip -4 address show dev test1')
        print(output)
        self.assertRegex(output, 'inet 192.168.24.5/24 brd 192.168.24.255 scope global test1')
        self.assertRegex(output, 'inet 192.168.25.5/24 brd 192.168.25.255 scope global test1')

        output = check_output('ip -4 address show dev vlan99')
        print(output)
        self.assertRegex(output, 'inet 192.168.23.5/24 brd 192.168.23.255 scope global vlan99')

    def test_vlan(self):
        copy_network_unit('21-vlan.netdev', '11-dummy.netdev',
                          '21-vlan.network', '21-vlan-test1.network')
        start_networkd()
        self.check_vlan(id=99, flags=True)

        # Test for reloading .netdev file. See issue #34907.
        with open(os.path.join(network_unit_dir, '21-vlan.netdev.d/override.conf'), mode='a', encoding='utf-8') as f:
            f.write('[VLAN]\nId=42\n')

        # VLAN ID cannot be changed, so we need to remove the existing netdev.
        check_output("ip link del vlan99")
        networkctl_reload()
        self.check_vlan(id=42, flags=True)

        with open(os.path.join(network_unit_dir, '21-vlan.netdev.d/override.conf'), mode='a', encoding='utf-8') as f:
            f.write('[VLAN]\n'
                    'GVRP=no\n'
                    'MVRP=no\n'
                    'LooseBinding=no\n'
                    'ReorderHeader=no\n')

        # flags can be changed, hence it is not necessary to remove the existing netdev.
        networkctl_reload()
        self.check_vlan(id=42, flags=False)

    def test_vlan_on_bond(self):
        # For issue #24377 (https://github.com/systemd/systemd/issues/24377),
        # which is fixed by b05e52000b4eee764b383cc3031da0a3739e996e (PR#24020).

        copy_network_unit('21-bond-802.3ad.netdev', '21-bond-802.3ad.network',
                          '21-vlan-on-bond.netdev', '21-vlan-on-bond.network')
        start_networkd()
        self.wait_online('bond99:off')
        self.wait_operstate('vlan99', operstate='off', setup_state='configuring', setup_timeout=10)
        self.networkctl_check_unit('vlan99', '21-vlan-on-bond', '21-vlan-on-bond')
        self.networkctl_check_unit('bond99', '21-bond-802.3ad', '21-bond-802.3ad')

        self.check_networkd_log('vlan99: Could not bring up interface, ignoring: Network is down')

        copy_network_unit('11-dummy.netdev', '12-dummy.netdev', '21-dummy-bond-slave.network')
        networkctl_reload()
        self.wait_online('test1:enslaved', 'dummy98:enslaved', 'bond99:carrier', 'vlan99:routable')

    def test_macvtap(self):
        first = True
        for mode in ['private', 'vepa', 'bridge', 'passthru']:
            if first:
                first = False
            else:
                self.tearDown()

            print(f'### test_macvtap(mode={mode})')
            with self.subTest(mode=mode):
                copy_network_unit('21-macvtap.netdev', '26-netdev-link-local-addressing-yes.network',
                                  '11-dummy.netdev', '25-macvtap.network')
                with open(os.path.join(network_unit_dir, '21-macvtap.netdev'), mode='a', encoding='utf-8') as f:
                    f.write('[MACVTAP]\nMode=' + mode)
                start_networkd()

                self.wait_online('macvtap99:degraded',
                                 'test1:carrier' if mode == 'passthru' else 'test1:degraded')
                self.networkctl_check_unit('macvtap99', '21-macvtap', '26-netdev-link-local-addressing-yes')
                self.networkctl_check_unit('test1', '11-dummy', '25-macvtap')

                output = check_output('ip -d link show macvtap99')
                print(output)
                self.assertRegex(output, 'macvtap mode ' + mode + ' ')

                touch_network_unit('21-macvtap.netdev')
                networkctl_reload()
                self.wait_online('macvtap99:degraded',
                                 'test1:carrier' if mode == 'passthru' else 'test1:degraded')

    @expectedFailureIfModuleIsNotAvailable('macvlan')
    def test_macvlan(self):
        first = True
        for mode in ['private', 'vepa', 'bridge', 'passthru']:
            if first:
                first = False
            else:
                self.tearDown()

            print(f'### test_macvlan(mode={mode})')
            with self.subTest(mode=mode):
                copy_network_unit('21-macvlan.netdev', '26-netdev-link-local-addressing-yes.network',
                                  '11-dummy.netdev', '25-macvlan.network')
                with open(os.path.join(network_unit_dir, '21-macvlan.netdev'), mode='a', encoding='utf-8') as f:
                    f.write('[MACVLAN]\nMode=' + mode)
                start_networkd()

                self.wait_online('macvlan99:degraded',
                                 'test1:carrier' if mode == 'passthru' else 'test1:degraded')
                self.networkctl_check_unit('macvlan99', '21-macvlan', '26-netdev-link-local-addressing-yes')
                self.networkctl_check_unit('test1', '11-dummy', '25-macvlan')

                output = check_output('ip -d link show test1')
                print(output)
                self.assertIn(' mtu 2000 ', output)

                output = check_output('ip -d link show macvlan99')
                print(output)
                self.assertIn(' mtu 2000 ', output)
                self.assertIn(f' macvlan mode {mode} ', output)

                remove_link('test1')
                time.sleep(1)

                check_output("ip link add test1 type dummy")
                self.wait_online('macvlan99:degraded',
                                 'test1:carrier' if mode == 'passthru' else 'test1:degraded')

                output = check_output('ip -d link show test1')
                print(output)
                self.assertIn(' mtu 2000 ', output)

                output = check_output('ip -d link show macvlan99')
                print(output)
                self.assertIn(' mtu 2000 ', output)
                self.assertIn(f' macvlan mode {mode} ', output)
                self.assertIn(' bcqueuelen 1234 ', output)
                if ' bclim ' in output: # This is new in kernel and iproute2 v6.4
                    self.assertIn(' bclim 2147483647 ', output)

                touch_network_unit('21-macvlan.netdev')
                networkctl_reload()
                self.wait_online('macvlan99:degraded',
                                 'test1:carrier' if mode == 'passthru' else 'test1:degraded')

    @expectedFailureIfModuleIsNotAvailable('ipvlan')
    def test_ipvlan(self):
        first = True
        for mode, flag in [['L2', 'private'], ['L3', 'vepa'], ['L3S', 'bridge']]:
            if first:
                first = False
            else:
                self.tearDown()

            print(f'### test_ipvlan(mode={mode}, flag={flag})')
            with self.subTest(mode=mode, flag=flag):
                copy_network_unit('25-ipvlan.netdev', '26-netdev-link-local-addressing-yes.network',
                                  '11-dummy.netdev', '25-ipvlan.network')
                with open(os.path.join(network_unit_dir, '25-ipvlan.netdev'), mode='a', encoding='utf-8') as f:
                    f.write('[IPVLAN]\nMode=' + mode + '\nFlags=' + flag)

                start_networkd()
                self.wait_online('ipvlan99:degraded', 'test1:degraded')
                self.networkctl_check_unit('ipvlan99', '25-ipvlan', '26-netdev-link-local-addressing-yes')
                self.networkctl_check_unit('test1', '11-dummy', '25-ipvlan')

                output = check_output('ip -d link show ipvlan99')
                print(output)
                self.assertRegex(output, 'ipvlan  *mode ' + mode.lower() + ' ' + flag)

                touch_network_unit('25-ipvlan.netdev')
                networkctl_reload()
                self.wait_online('ipvlan99:degraded', 'test1:degraded')

    @expectedFailureIfModuleIsNotAvailable('ipvtap')
    def test_ipvtap(self):
        first = True
        for mode, flag in [['L2', 'private'], ['L3', 'vepa'], ['L3S', 'bridge']]:
            if first:
                first = False
            else:
                self.tearDown()

            print(f'### test_ipvtap(mode={mode}, flag={flag})')
            with self.subTest(mode=mode, flag=flag):
                copy_network_unit('25-ipvtap.netdev', '26-netdev-link-local-addressing-yes.network',
                                  '11-dummy.netdev', '25-ipvtap.network')
                with open(os.path.join(network_unit_dir, '25-ipvtap.netdev'), mode='a', encoding='utf-8') as f:
                    f.write('[IPVTAP]\nMode=' + mode + '\nFlags=' + flag)

                start_networkd()
                self.wait_online('ipvtap99:degraded', 'test1:degraded')
                self.networkctl_check_unit('ipvtap99', '25-ipvtap', '26-netdev-link-local-addressing-yes')
                self.networkctl_check_unit('test1', '11-dummy', '25-ipvtap')

                output = check_output('ip -d link show ipvtap99')
                print(output)
                self.assertRegex(output, 'ipvtap  *mode ' + mode.lower() + ' ' + flag)

                touch_network_unit('25-ipvtap.netdev')
                networkctl_reload()
                self.wait_online('ipvtap99:degraded', 'test1:degraded')

    def test_veth(self):
        copy_network_unit('25-veth.netdev', '26-netdev-link-local-addressing-yes.network',
                          '25-veth-mtu.netdev')
        start_networkd()

        self.wait_online('veth99:degraded', 'veth-peer:degraded', 'veth-mtu:degraded', 'veth-mtu-peer:degraded')
        self.networkctl_check_unit('veth99', '25-veth', '26-netdev-link-local-addressing-yes')
        self.networkctl_check_unit('veth-peer', '25-veth', '26-netdev-link-local-addressing-yes')
        self.networkctl_check_unit('veth-mtu', '25-veth-mtu', '26-netdev-link-local-addressing-yes')
        self.networkctl_check_unit('veth-mtu-peer', '25-veth-mtu', '26-netdev-link-local-addressing-yes')

        output = check_output('ip -d link show veth99')
        print(output)
        self.assertRegex(output, 'link/ether 12:34:56:78:9a:bc')
        output = check_output('ip -d link show veth-peer')
        print(output)
        self.assertRegex(output, 'link/ether 12:34:56:78:9a:bd')

        output = check_output('ip -d link show veth-mtu')
        print(output)
        self.assertRegex(output, 'link/ether 12:34:56:78:9a:be')
        self.assertRegex(output, 'mtu 1800')
        output = check_output('ip -d link show veth-mtu-peer')
        print(output)
        self.assertRegex(output, 'link/ether 12:34:56:78:9a:bf')
        self.assertRegex(output, 'mtu 1800')

        touch_network_unit(
            '25-veth.netdev',
            '26-netdev-link-local-addressing-yes.network',
            '25-veth-mtu.netdev')
        networkctl_reload()
        self.wait_online(
            'veth99:degraded',
            'veth-peer:degraded',
            'veth-mtu:degraded',
            'veth-mtu-peer:degraded')

    def check_tuntap(self, attached):
        pid = networkd_pid()
        name = psutil.Process(pid).name()[:15]

        output = check_output('ip -d -oneline tuntap show')
        print(output)
        self.assertRegex(output, r'testtap99: tap pi (multi_queue |)vnet_hdr persist filter.*\tAttached to processes:')
        self.assertRegex(output, r'testtun99: tun pi (multi_queue |)vnet_hdr persist filter.*\tAttached to processes:')

        if attached:
            self.assertRegex(output, fr'testtap99: .*{name}\({pid}\)')
            self.assertRegex(output, fr'testtun99: .*{name}\({pid}\)')
            self.assertRegex(output, r'testtap99: .*systemd\(1\)')
            self.assertRegex(output, r'testtun99: .*systemd\(1\)')

            output = check_output('ip -d link show testtun99')
            print(output)
            # Old ip command does not support IFF_ flags
            self.assertRegex(output, 'tun (type tun pi on vnet_hdr on multi_queue|addrgenmode) ')
            self.assertIn('UP,LOWER_UP', output)

            output = check_output('ip -d link show testtap99')
            print(output)
            self.assertRegex(output, 'tun (type tap pi on vnet_hdr on multi_queue|addrgenmode) ')
            self.assertIn('UP,LOWER_UP', output)

        else:
            self.assertNotIn(f'{name}({pid})', output)
            self.assertNotIn('systemd(1)', output)

            for _ in range(20):
                output = check_output('ip -d link show testtun99')
                print(output)
                self.assertRegex(output, 'tun (type tun pi on vnet_hdr on multi_queue|addrgenmode) ')
                if 'NO-CARRIER' in output:
                    break
                time.sleep(0.5)
            else:
                self.fail()

            for _ in range(20):
                output = check_output('ip -d link show testtap99')
                print(output)
                self.assertRegex(output, 'tun (type tap pi on vnet_hdr on multi_queue|addrgenmode) ')
                if 'NO-CARRIER' in output:
                    break
                time.sleep(0.5)
            else:
                self.fail()

    def test_tuntap(self):
        copy_network_unit('25-tun.netdev', '25-tap.netdev', '26-netdev-link-local-addressing-yes.network')
        start_networkd()
        self.wait_online('testtun99:degraded', 'testtap99:degraded')
        self.networkctl_check_unit('testtap99', '25-tap', '26-netdev-link-local-addressing-yes')
        self.networkctl_check_unit('testtun99', '25-tun', '26-netdev-link-local-addressing-yes')

        self.check_tuntap(True)

        touch_network_unit('25-tun.netdev', '25-tap.netdev', '26-netdev-link-local-addressing-yes.network')
        networkctl_reload()
        self.wait_online('testtun99:degraded', 'testtap99:degraded')

        self.check_tuntap(True)

        remove_network_unit('26-netdev-link-local-addressing-yes.network')
        restart_networkd()
        self.wait_online('testtun99:degraded', 'testtap99:degraded', setup_state='unmanaged')
        self.networkctl_check_unit('testtap99', '25-tap')
        self.networkctl_check_unit('testtun99', '25-tun')

        self.check_tuntap(True)

        clear_network_units()
        unmanage_existing_links()
        restart_networkd()
        self.wait_online('testtun99:off', 'testtap99:off', setup_state='unmanaged')
        self.networkctl_check_unit('testtap99')
        self.networkctl_check_unit('testtun99')

        self.check_tuntap(False)

    @expectedFailureIfModuleIsNotAvailable('vrf')
    def test_vrf(self):
        copy_network_unit('25-vrf.netdev', '26-netdev-link-local-addressing-yes.network')
        start_networkd()

        self.wait_online('vrf99:carrier')
        self.networkctl_check_unit('vrf99', '25-vrf', '26-netdev-link-local-addressing-yes')

        touch_network_unit('25-vrf.netdev', '26-netdev-link-local-addressing-yes.network')
        networkctl()
        self.wait_online('vrf99:carrier')

    @expectedFailureIfModuleIsNotAvailable('vcan')
    def test_vcan(self):
        copy_network_unit('25-vcan.netdev', '26-netdev-link-local-addressing-yes.network',
                          '25-vcan98.netdev', '25-vcan98.network')
        start_networkd()

        self.wait_online('vcan99:carrier', 'vcan98:carrier')
        # For can devices, 'carrier' is the default required operational state.
        self.wait_online('vcan99', 'vcan98')
        self.networkctl_check_unit('vcan99', '25-vcan', '26-netdev-link-local-addressing-yes')
        self.networkctl_check_unit('vcan98', '25-vcan98', '25-vcan98')

        # https://github.com/systemd/systemd/issues/30140
        output = check_output('ip -d link show vcan99')
        print(output)
        self.assertIn('mtu 16 ', output)

        output = check_output('ip -d link show vcan98')
        print(output)
        self.assertIn('mtu 16 ', output)

        touch_network_unit(
            '25-vcan.netdev',
            '26-netdev-link-local-addressing-yes.network',
            '25-vcan98.netdev',
            '25-vcan98.network')
        networkctl_reload()
        self.wait_online('vcan99:carrier', 'vcan98:carrier')

    @expectedFailureIfModuleIsNotAvailable('vxcan')
    def test_vxcan(self):
        copy_network_unit('25-vxcan.netdev', '26-netdev-link-local-addressing-yes.network')
        start_networkd()

        self.wait_online('vxcan99:carrier', 'vxcan-peer:carrier')
        # For can devices, 'carrier' is the default required operational state.
        self.wait_online('vxcan99', 'vxcan-peer')
        self.networkctl_check_unit('vxcan99', '25-vxcan', '26-netdev-link-local-addressing-yes')
        self.networkctl_check_unit('vxcan-peer', '25-vxcan', '26-netdev-link-local-addressing-yes')

        touch_network_unit('25-vxcan.netdev', '26-netdev-link-local-addressing-yes.network')
        networkctl()
        self.wait_online('vxcan99:carrier', 'vxcan-peer:carrier')

    @expectedFailureIfModuleIsNotAvailable('wireguard')
    def test_wireguard(self):
        copy_credential('25-wireguard-endpoint-peer0-cred.txt', 'network.wireguard.peer0.endpoint')
        copy_credential('25-wireguard-preshared-key-peer2-cred.txt', 'network.wireguard.peer2.psk')
        copy_credential('25-wireguard-no-peer-private-key-cred.txt', 'network.wireguard.private.25-wireguard-no-peer')

        copy_network_unit('25-wireguard.netdev', '25-wireguard.network',
                          '25-wireguard-23-peers.netdev', '25-wireguard-23-peers.network',
                          '25-wireguard-public-key.txt', '25-wireguard-preshared-key.txt', '25-wireguard-private-key.txt',
                          '25-wireguard-no-peer.netdev', '25-wireguard-no-peer.network')
        start_networkd()
        self.wait_online('wg99:routable', 'wg98:routable', 'wg97:carrier')
        self.networkctl_check_unit('wg99', '25-wireguard', '25-wireguard')
        self.networkctl_check_unit('wg98', '25-wireguard-23-peers', '25-wireguard-23-peers')
        self.networkctl_check_unit('wg97', '25-wireguard-no-peer', '25-wireguard-no-peer')

        output = check_output('ip -4 address show dev wg99')
        print(output)
        self.assertIn('inet 192.168.124.1/24 scope global wg99', output)

        output = check_output('ip -4 address show dev wg99')
        print(output)
        self.assertIn('inet 169.254.11.1/24 scope link wg99', output)

        output = check_output('ip -6 address show dev wg99')
        print(output)
        self.assertIn('inet6 fe80::1/64 scope link', output)

        output = check_output('ip -4 address show dev wg98')
        print(output)
        self.assertIn('inet 192.168.123.123/24 scope global wg98', output)

        output = check_output('ip -6 address show dev wg98')
        print(output)
        self.assertIn('inet6 fd8d:4d6d:3ccb:500::1/64 scope global', output)

        output = check_output('ip -4 route show dev wg99 table 1234')
        print(output)
        self.assertIn('192.168.26.0/24 proto static scope link metric 123', output)

        output = check_output('ip -6 route show dev wg99 table 1234')
        print(output)
        self.assertIn('fd31:bf08:57cb::/48 proto static metric 123 pref medium', output)

        output = check_output('ip -6 route show dev wg98 table 1234')
        print(output)
        self.assertIn('fd8d:4d6d:3ccb:500:c79:2339:edce:ece1 proto static metric 123 pref medium', output)
        self.assertIn('fd8d:4d6d:3ccb:500:1dbf:ca8a:32d3:dd81 proto static metric 123 pref medium', output)
        self.assertIn('fd8d:4d6d:3ccb:500:1e54:1415:35d0:a47c proto static metric 123 pref medium', output)
        self.assertIn('fd8d:4d6d:3ccb:500:270d:b5dd:4a3f:8909 proto static metric 123 pref medium', output)
        self.assertIn('fd8d:4d6d:3ccb:500:5660:679d:3532:94d8 proto static metric 123 pref medium', output)
        self.assertIn('fd8d:4d6d:3ccb:500:6825:573f:30f3:9472 proto static metric 123 pref medium', output)
        self.assertIn('fd8d:4d6d:3ccb:500:6f2e:6888:c6fd:dfb9 proto static metric 123 pref medium', output)
        self.assertIn('fd8d:4d6d:3ccb:500:8d4d:bab:7280:a09a proto static metric 123 pref medium', output)
        self.assertIn('fd8d:4d6d:3ccb:500:900c:d437:ec27:8822 proto static metric 123 pref medium', output)
        self.assertIn('fd8d:4d6d:3ccb:500:9742:9931:5217:18d5 proto static metric 123 pref medium', output)
        self.assertIn('fd8d:4d6d:3ccb:500:9c11:d820:2e96:9be0 proto static metric 123 pref medium', output)
        self.assertIn('fd8d:4d6d:3ccb:500:a072:80da:de4f:add1 proto static metric 123 pref medium', output)
        self.assertIn('fd8d:4d6d:3ccb:500:a3f3:df38:19b0:721 proto static metric 123 pref medium', output)
        self.assertIn('fd8d:4d6d:3ccb:500:a94b:cd6a:a32d:90e6 proto static metric 123 pref medium', output)
        self.assertIn('fd8d:4d6d:3ccb:500:b39c:9cdc:755a:ead3 proto static metric 123 pref medium', output)
        self.assertIn('fd8d:4d6d:3ccb:500:b684:4f81:2e3e:132e proto static metric 123 pref medium', output)
        self.assertIn('fd8d:4d6d:3ccb:500:bad5:495d:8e9c:3427 proto static metric 123 pref medium', output)
        self.assertIn('fd8d:4d6d:3ccb:500:bfe5:c3c3:5d77:fcb proto static metric 123 pref medium', output)
        self.assertIn('fd8d:4d6d:3ccb:500:c624:6bf7:4c09:3b59 proto static metric 123 pref medium', output)
        self.assertIn('fd8d:4d6d:3ccb:500:d4f9:5dc:9296:a1a proto static metric 123 pref medium', output)
        self.assertIn('fd8d:4d6d:3ccb:500:dcdd:d33b:90c9:6088 proto static metric 123 pref medium', output)
        self.assertIn('fd8d:4d6d:3ccb:500:e2e1:ae15:103f:f376 proto static metric 123 pref medium', output)
        self.assertIn('fd8d:4d6d:3ccb:500:f349:c4f0:10c1:6b4 proto static metric 123 pref medium', output)
        self.assertIn('fd8d:4d6d:3ccb:c79:2339:edce::/96 proto static metric 123 pref medium', output)
        self.assertIn('fd8d:4d6d:3ccb:1dbf:ca8a:32d3::/96 proto static metric 123 pref medium', output)
        self.assertIn('fd8d:4d6d:3ccb:1e54:1415:35d0::/96 proto static metric 123 pref medium', output)
        self.assertIn('fd8d:4d6d:3ccb:270d:b5dd:4a3f::/96 proto static metric 123 pref medium', output)
        self.assertIn('fd8d:4d6d:3ccb:5660:679d:3532::/96 proto static metric 123 pref medium', output)
        self.assertIn('fd8d:4d6d:3ccb:6825:573f:30f3::/96 proto static metric 123 pref medium', output)
        self.assertIn('fd8d:4d6d:3ccb:6f2e:6888:c6fd::/96 proto static metric 123 pref medium', output)
        self.assertIn('fd8d:4d6d:3ccb:8d4d:bab:7280::/96 proto static metric 123 pref medium', output)
        self.assertIn('fd8d:4d6d:3ccb:900c:d437:ec27::/96 proto static metric 123 pref medium', output)
        self.assertIn('fd8d:4d6d:3ccb:9742:9931:5217::/96 proto static metric 123 pref medium', output)
        self.assertIn('fd8d:4d6d:3ccb:9c11:d820:2e96::/96 proto static metric 123 pref medium', output)
        self.assertIn('fd8d:4d6d:3ccb:a072:80da:de4f::/96 proto static metric 123 pref medium', output)
        self.assertIn('fd8d:4d6d:3ccb:a3f3:df38:19b0::/96 proto static metric 123 pref medium', output)
        self.assertIn('fd8d:4d6d:3ccb:a94b:cd6a:a32d::/96 proto static metric 123 pref medium', output)
        self.assertIn('fd8d:4d6d:3ccb:b39c:9cdc:755a::/96 proto static metric 123 pref medium', output)
        self.assertIn('fd8d:4d6d:3ccb:b684:4f81:2e3e::/96 proto static metric 123 pref medium', output)
        self.assertIn('fd8d:4d6d:3ccb:bad5:495d:8e9c::/96 proto static metric 123 pref medium', output)
        self.assertIn('fd8d:4d6d:3ccb:bfe5:c3c3:5d77::/96 proto static metric 123 pref medium', output)
        self.assertIn('fd8d:4d6d:3ccb:c624:6bf7:4c09::/96 proto static metric 123 pref medium', output)
        self.assertIn('fd8d:4d6d:3ccb:d4f9:5dc:9296::/96 proto static metric 123 pref medium', output)
        self.assertIn('fd8d:4d6d:3ccb:dcdd:d33b:90c9::/96 proto static metric 123 pref medium', output)
        self.assertIn('fd8d:4d6d:3ccb:e2e1:ae15:103f::/96 proto static metric 123 pref medium', output)
        self.assertIn('fd8d:4d6d:3ccb:f349:c4f0:10c1::/96 proto static metric 123 pref medium', output)

        if shutil.which('wg'):
            call('wg')

            output = check_output('wg show wg99 listen-port')
            self.assertEqual(output, '51820')
            output = check_output('wg show wg99 fwmark')
            self.assertEqual(output, '0x4d2')
            output = check_output('wg show wg99 private-key')
            self.assertEqual(output, 'EEGlnEPYJV//kbvvIqxKkQwOiS+UENyPncC4bF46ong=')
            output = check_output('wg show wg99 allowed-ips')
            self.assertIn('9uioxkGzjvGjkse3V35I9AhorWfIjBcrf3UPMS0bw2c=\t192.168.124.3/32', output)
            self.assertIn('TTiCUpCxS7zDn/ax4p5W6Evg41r8hOrnWQw2Sq6Nh10=\t192.168.124.2/32', output)
            self.assertIn('lsDtM3AbjxNlauRKzHEPfgS1Zp7cp/VX5Use/P4PQSc=\tfdbc:bae2:7871:e1fe:793:8636::/96 fdbc:bae2:7871:500:e1fe:793:8636:dad1/128', output)
            self.assertIn('RDf+LSpeEre7YEIKaxg+wbpsNV7du+ktR99uBEtIiCA=\t192.168.26.0/24 fd31:bf08:57cb::/48', output)
            output = check_output('wg show wg99 persistent-keepalive')
            self.assertIn('9uioxkGzjvGjkse3V35I9AhorWfIjBcrf3UPMS0bw2c=\toff', output)
            self.assertIn('TTiCUpCxS7zDn/ax4p5W6Evg41r8hOrnWQw2Sq6Nh10=\toff', output)
            self.assertIn('lsDtM3AbjxNlauRKzHEPfgS1Zp7cp/VX5Use/P4PQSc=\toff', output)
            self.assertIn('RDf+LSpeEre7YEIKaxg+wbpsNV7du+ktR99uBEtIiCA=\t20', output)
            output = check_output('wg show wg99 endpoints')
            self.assertIn('9uioxkGzjvGjkse3V35I9AhorWfIjBcrf3UPMS0bw2c=\t(none)', output)
            self.assertIn('TTiCUpCxS7zDn/ax4p5W6Evg41r8hOrnWQw2Sq6Nh10=\t(none)', output)
            self.assertIn('lsDtM3AbjxNlauRKzHEPfgS1Zp7cp/VX5Use/P4PQSc=\t(none)', output)
            self.assertIn('RDf+LSpeEre7YEIKaxg+wbpsNV7du+ktR99uBEtIiCA=\t192.168.27.3:51820', output)
            output = check_output('wg show wg99 preshared-keys')
            self.assertIn('9uioxkGzjvGjkse3V35I9AhorWfIjBcrf3UPMS0bw2c=\t6Fsg8XN0DE6aPQgAX4r2oazEYJOGqyHUz3QRH/jCB+I=', output)
            self.assertIn('TTiCUpCxS7zDn/ax4p5W6Evg41r8hOrnWQw2Sq6Nh10=\tit7nd33chCT/tKT2ZZWfYyp43Zs+6oif72hexnSNMqA=', output)
            self.assertIn('lsDtM3AbjxNlauRKzHEPfgS1Zp7cp/VX5Use/P4PQSc=\tcPLOy1YUrEI0EMMIycPJmOo0aTu3RZnw8bL5meVD6m0=', output)
            self.assertIn('RDf+LSpeEre7YEIKaxg+wbpsNV7du+ktR99uBEtIiCA=\tIIWIV17wutHv7t4cR6pOT91z6NSz/T8Arh0yaywhw3M=', output)

            output = check_output('wg show wg98 private-key')
            self.assertEqual(output, 'CJQUtcS9emY2fLYqDlpSZiE/QJyHkPWr+WHtZLZ90FU=')

            output = check_output('wg show wg97 listen-port')
            self.assertEqual(output, '51821')
            output = check_output('wg show wg97 fwmark')
            self.assertEqual(output, '0x4d3')

        touch_network_unit(
            '25-wireguard.netdev', '25-wireguard.network',
            '25-wireguard-23-peers.netdev', '25-wireguard-23-peers.network',
            '25-wireguard-public-key.txt', '25-wireguard-preshared-key.txt', '25-wireguard-private-key.txt',
            '25-wireguard-no-peer.netdev', '25-wireguard-no-peer.network')
        networkctl_reload()
        self.wait_online('wg99:routable', 'wg98:routable', 'wg97:carrier')

    def test_geneve(self):
        copy_network_unit('25-geneve.netdev', '26-netdev-link-local-addressing-yes.network')
        start_networkd()

        self.wait_online('geneve99:degraded')
        self.networkctl_check_unit('geneve99', '25-geneve', '26-netdev-link-local-addressing-yes')

        output = check_output('ip -d link show geneve99')
        print(output)
        self.assertRegex(output, '192.168.22.1')
        self.assertRegex(output, '6082')
        self.assertRegex(output, 'udpcsum')
        self.assertRegex(output, 'udp6zerocsumrx')

        touch_network_unit('25-geneve.netdev', '26-netdev-link-local-addressing-yes.network')
        networkctl_reload()
        self.wait_online('geneve99:degraded')

    def test_ipip_tunnel(self):
        copy_network_unit('12-dummy.netdev', '25-ipip.network',
                          '25-ipip-tunnel.netdev', '25-tunnel.network',
                          '25-ipip-tunnel-local-any.netdev', '25-tunnel-local-any.network',
                          '25-ipip-tunnel-remote-any.netdev', '25-tunnel-remote-any.network',
                          '25-ipip-tunnel-any-any.netdev', '25-tunnel-any-any.network')
        start_networkd()
        self.wait_online('ipiptun99:routable', 'ipiptun98:routable', 'ipiptun97:routable', 'ipiptun96:routable', 'dummy98:degraded')

        output = check_output('ip -d link show ipiptun99')
        print(output)
        self.assertRegex(output, 'ipip (ipip )?remote 192.169.224.239 local 192.168.223.238 dev dummy98')
        output = check_output('ip -d link show ipiptun98')
        print(output)
        self.assertRegex(output, 'ipip (ipip )?remote 192.169.224.239 local any dev dummy98')
        output = check_output('ip -d link show ipiptun97')
        print(output)
        self.assertRegex(output, 'ipip (ipip )?remote any local 192.168.223.238 dev dummy98')
        output = check_output('ip -d link show ipiptun96')
        print(output)
        self.assertRegex(output, 'ipip (ipip )?remote any local any dev dummy98')

        touch_network_unit(
            '25-ipip-tunnel.netdev',
            '25-ipip-tunnel-local-any.netdev',
            '25-ipip-tunnel-remote-any.netdev',
            '25-ipip-tunnel-any-any.netdev')
        networkctl_reload()
        self.wait_online(
            'ipiptun99:routable',
            'ipiptun98:routable',
            'ipiptun97:routable',
            'ipiptun96:routable',
            'dummy98:degraded')

    def test_gre_tunnel(self):
        copy_network_unit('12-dummy.netdev', '25-gretun.network',
                          '25-gre-tunnel.netdev', '25-tunnel.network',
                          '25-gre-tunnel-local-any.netdev', '25-tunnel-local-any.network',
                          '25-gre-tunnel-remote-any.netdev', '25-tunnel-remote-any.network',
                          '25-gre-tunnel-any-any.netdev', '25-tunnel-any-any.network')
        start_networkd()
        self.wait_online('gretun99:routable', 'gretun98:routable', 'gretun97:routable', 'gretun96:routable', 'dummy98:degraded')
        self.networkctl_check_unit('gretun99', '25-gre-tunnel', '25-tunnel')
        self.networkctl_check_unit('gretun98', '25-gre-tunnel-local-any', '25-tunnel-local-any')
        self.networkctl_check_unit('gretun97', '25-gre-tunnel-remote-any', '25-tunnel-remote-any')
        self.networkctl_check_unit('gretun96', '25-gre-tunnel-any-any', '25-tunnel-any-any')
        self.networkctl_check_unit('dummy98', '12-dummy', '25-gretun')

        output = check_output('ip -d link show gretun99')
        print(output)
        self.assertRegex(output, 'gre remote 10.65.223.239 local 10.65.223.238 dev dummy98')
        self.assertRegex(output, 'ikey 1.2.3.103')
        self.assertRegex(output, 'okey 1.2.4.103')
        self.assertRegex(output, 'iseq')
        self.assertRegex(output, 'oseq')
        output = check_output('ip -d link show gretun98')
        print(output)
        self.assertRegex(output, 'gre remote 10.65.223.239 local any dev dummy98')
        self.assertRegex(output, 'ikey 0.0.0.104')
        self.assertRegex(output, 'okey 0.0.0.104')
        self.assertNotRegex(output, 'iseq')
        self.assertNotRegex(output, 'oseq')
        output = check_output('ip -d link show gretun97')
        print(output)
        self.assertRegex(output, 'gre remote any local 10.65.223.238 dev dummy98')
        self.assertRegex(output, 'ikey 0.0.0.105')
        self.assertRegex(output, 'okey 0.0.0.105')
        self.assertNotRegex(output, 'iseq')
        self.assertNotRegex(output, 'oseq')
        output = check_output('ip -d link show gretun96')
        print(output)
        self.assertRegex(output, 'gre remote any local any dev dummy98')
        self.assertRegex(output, 'ikey 0.0.0.106')
        self.assertRegex(output, 'okey 0.0.0.106')
        self.assertNotRegex(output, 'iseq')
        self.assertNotRegex(output, 'oseq')

        touch_network_unit(
            '25-gre-tunnel.netdev',
            '25-gre-tunnel-local-any.netdev',
            '25-gre-tunnel-remote-any.netdev',
            '25-gre-tunnel-any-any.netdev')
        networkctl_reload()
        self.wait_online(
            'gretun99:routable',
            'gretun98:routable',
            'gretun97:routable',
            'gretun96:routable',
            'dummy98:degraded')

    def test_ip6gre_tunnel(self):
        copy_network_unit('12-dummy.netdev', '25-ip6gretun.network',
                          '25-ip6gre-tunnel.netdev', '25-tunnel.network',
                          '25-ip6gre-tunnel-local-any.netdev', '25-tunnel-local-any.network',
                          '25-ip6gre-tunnel-remote-any.netdev', '25-tunnel-remote-any.network',
                          '25-ip6gre-tunnel-any-any.netdev', '25-tunnel-any-any.network')
        start_networkd()

        # Old kernels seem not to support IPv6LL address on ip6gre tunnel, So please do not use wait_online() here.

        self.wait_links('dummy98', 'ip6gretun99', 'ip6gretun98', 'ip6gretun97', 'ip6gretun96')

        output = check_output('ip -d link show ip6gretun99')
        print(output)
        self.assertRegex(output, 'ip6gre remote 2001:473:fece:cafe::5179 local 2a00:ffde:4567:edde::4987 dev dummy98')
        output = check_output('ip -d link show ip6gretun98')
        print(output)
        self.assertRegex(output, 'ip6gre remote 2001:473:fece:cafe::5179 local any dev dummy98')
        output = check_output('ip -d link show ip6gretun97')
        print(output)
        self.assertRegex(output, 'ip6gre remote any local 2a00:ffde:4567:edde::4987 dev dummy98')
        output = check_output('ip -d link show ip6gretun96')
        print(output)
        self.assertRegex(output, 'ip6gre remote any local any dev dummy98')

        touch_network_unit(
            '25-ip6gre-tunnel.netdev',
            '25-ip6gre-tunnel-local-any.netdev',
            '25-ip6gre-tunnel-remote-any.netdev',
            '25-ip6gre-tunnel-any-any.netdev')
        networkctl_reload()
        self.wait_links(
            'dummy98',
            'ip6gretun99',
            'ip6gretun98',
            'ip6gretun97',
            'ip6gretun96')

    def test_gretap_tunnel(self):
        copy_network_unit('12-dummy.netdev', '25-gretap.network',
                          '25-gretap-tunnel.netdev', '25-tunnel.network',
                          '25-gretap-tunnel-local-any.netdev', '25-tunnel-local-any.network')
        start_networkd()
        self.wait_online('gretap99:routable', 'gretap98:routable', 'dummy98:degraded')
        self.networkctl_check_unit('gretap99', '25-gretap-tunnel', '25-tunnel')
        self.networkctl_check_unit('gretap98', '25-gretap-tunnel-local-any', '25-tunnel-local-any')
        self.networkctl_check_unit('dummy98', '12-dummy', '25-gretap')

        output = check_output('ip -d link show gretap99')
        print(output)
        self.assertRegex(output, 'gretap remote 10.65.223.239 local 10.65.223.238 dev dummy98')
        self.assertRegex(output, 'ikey 0.0.0.106')
        self.assertRegex(output, 'okey 0.0.0.106')
        self.assertRegex(output, 'iseq')
        self.assertRegex(output, 'oseq')
        self.assertIn('nopmtudisc', output)
        self.assertIn('ignore-df', output)
        output = check_output('ip -d link show gretap98')
        print(output)
        self.assertRegex(output, 'gretap remote 10.65.223.239 local any dev dummy98')
        self.assertRegex(output, 'ikey 0.0.0.107')
        self.assertRegex(output, 'okey 0.0.0.107')
        self.assertRegex(output, 'iseq')
        self.assertRegex(output, 'oseq')

        touch_network_unit(
            '25-gretap-tunnel.netdev',
            '25-gretap-tunnel-local-any.netdev')
        networkctl_reload()
        self.wait_online(
            'gretap99:routable',
            'gretap98:routable',
            'dummy98:degraded')

    def test_ip6gretap_tunnel(self):
        copy_network_unit('12-dummy.netdev', '25-ip6gretap.network',
                          '25-ip6gretap-tunnel.netdev', '25-tunnel.network',
                          '25-ip6gretap-tunnel-local-any.netdev', '25-tunnel-local-any.network')
        start_networkd()
        self.wait_online('ip6gretap99:routable', 'ip6gretap98:routable', 'dummy98:degraded')
        self.networkctl_check_unit('ip6gretap99', '25-ip6gretap-tunnel', '25-tunnel')
        self.networkctl_check_unit('ip6gretap98', '25-ip6gretap-tunnel-local-any', '25-tunnel-local-any')
        self.networkctl_check_unit('dummy98', '12-dummy', '25-ip6gretap')

        output = check_output('ip -d link show ip6gretap99')
        print(output)
        self.assertRegex(output, 'ip6gretap remote 2001:473:fece:cafe::5179 local 2a00:ffde:4567:edde::4987 dev dummy98')
        output = check_output('ip -d link show ip6gretap98')
        print(output)
        self.assertRegex(output, 'ip6gretap remote 2001:473:fece:cafe::5179 local any dev dummy98')

        touch_network_unit(
            '25-ip6gretap-tunnel.netdev',
            '25-ip6gretap-tunnel-local-any.netdev')
        networkctl_reload()
        self.wait_online(
            'ip6gretap99:routable',
            'ip6gretap98:routable',
            'dummy98:degraded')

    def test_vti_tunnel(self):
        copy_network_unit('12-dummy.netdev', '25-vti.network',
                          '25-vti-tunnel.netdev', '25-tunnel.network',
                          '25-vti-tunnel-local-any.netdev', '25-tunnel-local-any.network',
                          '25-vti-tunnel-remote-any.netdev', '25-tunnel-remote-any.network',
                          '25-vti-tunnel-any-any.netdev', '25-tunnel-any-any.network')
        start_networkd()
        self.wait_online('vtitun99:routable', 'vtitun98:routable', 'vtitun97:routable', 'vtitun96:routable', 'dummy98:degraded')
        self.networkctl_check_unit('vtitun99', '25-vti-tunnel', '25-tunnel')
        self.networkctl_check_unit('vtitun98', '25-vti-tunnel-local-any', '25-tunnel-local-any')
        self.networkctl_check_unit('vtitun97', '25-vti-tunnel-remote-any', '25-tunnel-remote-any')
        self.networkctl_check_unit('vtitun96', '25-vti-tunnel-any-any', '25-tunnel-any-any')
        self.networkctl_check_unit('dummy98', '12-dummy', '25-vti')

        output = check_output('ip -d link show vtitun99')
        print(output)
        self.assertRegex(output, 'vti remote 10.65.223.239 local 10.65.223.238 dev dummy98')
        output = check_output('ip -d link show vtitun98')
        print(output)
        self.assertRegex(output, 'vti remote 10.65.223.239 local any dev dummy98')
        output = check_output('ip -d link show vtitun97')
        print(output)
        self.assertRegex(output, 'vti remote any local 10.65.223.238 dev dummy98')
        output = check_output('ip -d link show vtitun96')
        print(output)
        self.assertRegex(output, 'vti remote any local any dev dummy98')

        touch_network_unit(
            '25-vti-tunnel.netdev',
            '25-vti-tunnel-local-any.netdev',
            '25-vti-tunnel-remote-any.netdev',
            '25-vti-tunnel-any-any.netdev')
        networkctl_reload()
        self.wait_online(
            'vtitun99:routable',
            'vtitun98:routable',
            'vtitun97:routable',
            'vtitun96:routable',
            'dummy98:degraded')

    def test_vti6_tunnel(self):
        copy_network_unit('12-dummy.netdev', '25-vti6.network',
                          '25-vti6-tunnel.netdev', '25-tunnel.network',
                          '25-vti6-tunnel-local-any.netdev', '25-tunnel-local-any.network',
                          '25-vti6-tunnel-remote-any.netdev', '25-tunnel-remote-any.network')
        start_networkd()
        self.wait_online('vti6tun99:routable', 'vti6tun98:routable', 'vti6tun97:routable', 'dummy98:degraded')
        self.networkctl_check_unit('vti6tun99', '25-vti6-tunnel', '25-tunnel')
        self.networkctl_check_unit('vti6tun98', '25-vti6-tunnel-local-any', '25-tunnel-local-any')
        self.networkctl_check_unit('vti6tun97', '25-vti6-tunnel-remote-any', '25-tunnel-remote-any')
        self.networkctl_check_unit('dummy98', '12-dummy', '25-vti6')

        output = check_output('ip -d link show vti6tun99')
        print(output)
        self.assertRegex(output, 'vti6 remote 2001:473:fece:cafe::5179 local 2a00:ffde:4567:edde::4987 dev dummy98')
        output = check_output('ip -d link show vti6tun98')
        print(output)
        self.assertRegex(output, 'vti6 remote 2001:473:fece:cafe::5179 local (any|::) dev dummy98')
        output = check_output('ip -d link show vti6tun97')
        print(output)
        self.assertRegex(output, 'vti6 remote (any|::) local 2a00:ffde:4567:edde::4987 dev dummy98')

        touch_network_unit(
            '25-vti6-tunnel.netdev',
            '25-vti6-tunnel-local-any.netdev',
            '25-vti6-tunnel-remote-any.netdev')
        networkctl_reload()
        self.wait_online(
            'vti6tun99:routable',
            'vti6tun98:routable',
            'vti6tun97:routable',
            'dummy98:degraded')

    def test_ip6tnl_tunnel(self):
        copy_network_unit('12-dummy.netdev', '25-ip6tnl.network',
                          '25-ip6tnl-tunnel.netdev', '25-tunnel.network',
                          '25-ip6tnl-tunnel-local-any.netdev', '25-tunnel-local-any.network',
                          '25-ip6tnl-tunnel-remote-any.netdev', '25-tunnel-remote-any.network',
                          '25-veth.netdev', '25-ip6tnl-slaac.network', '25-ipv6-prefix.network',
                          '25-ip6tnl-tunnel-local-slaac.netdev', '25-ip6tnl-tunnel-local-slaac.network',
                          '25-ip6tnl-tunnel-external.netdev', '26-netdev-link-local-addressing-yes.network')
        start_networkd()
        self.wait_online('ip6tnl99:routable', 'ip6tnl98:routable', 'ip6tnl97:routable',
                         'ip6tnl-slaac:degraded', 'ip6tnl-external:degraded',
                         'dummy98:degraded', 'veth99:routable', 'veth-peer:degraded')
        self.networkctl_check_unit('ip6tnl99', '25-ip6tnl-tunnel', '25-tunnel')
        self.networkctl_check_unit('ip6tnl98', '25-ip6tnl-tunnel-local-any', '25-tunnel-local-any')
        self.networkctl_check_unit('ip6tnl97', '25-ip6tnl-tunnel-remote-any', '25-tunnel-remote-any')
        self.networkctl_check_unit('ip6tnl-slaac', '25-ip6tnl-tunnel-local-slaac', '25-ip6tnl-tunnel-local-slaac')
        self.networkctl_check_unit('ip6tnl-external', '25-ip6tnl-tunnel-external', '26-netdev-link-local-addressing-yes')
        self.networkctl_check_unit('dummy98', '12-dummy', '25-ip6tnl')
        self.networkctl_check_unit('veth99', '25-veth', '25-ip6tnl-slaac')
        self.networkctl_check_unit('veth-peer', '25-veth', '25-ipv6-prefix')

        output = check_output('ip -d link show ip6tnl99')
        print(output)
        self.assertIn('ip6tnl ip6ip6 remote 2001:473:fece:cafe::5179 local 2a00:ffde:4567:edde::4987 dev dummy98', output)
        output = check_output('ip -d link show ip6tnl98')
        print(output)
        self.assertRegex(output, 'ip6tnl ip6ip6 remote 2001:473:fece:cafe::5179 local (any|::) dev dummy98')
        output = check_output('ip -d link show ip6tnl97')
        print(output)
        self.assertRegex(output, 'ip6tnl ip6ip6 remote (any|::) local 2a00:ffde:4567:edde::4987 dev dummy98')
        output = check_output('ip -d link show ip6tnl-external')
        print(output)
        self.assertIn('ip6tnl-external@NONE:', output)
        self.assertIn('ip6tnl external ', output)
        output = check_output('ip -d link show ip6tnl-slaac')
        print(output)
        self.assertIn('ip6tnl ip6ip6 remote 2001:473:fece:cafe::5179 local 2002:da8:1:0:1034:56ff:fe78:9abc dev veth99', output)

        output = check_output('ip -6 address show veth99')
        print(output)
        self.assertIn('inet6 2002:da8:1:0:1034:56ff:fe78:9abc/64 scope global dynamic', output)

        output = check_output('ip -4 route show default')
        print(output)
        self.assertIn('default dev ip6tnl-slaac proto static', output)

        touch_network_unit(
            '25-ip6tnl-tunnel.netdev',
            '25-ip6tnl-tunnel-local-any.netdev',
            '25-ip6tnl-tunnel-remote-any.netdev',
            '25-ip6tnl-tunnel-local-slaac.netdev',
            '25-ip6tnl-tunnel-external.netdev')
        networkctl_reload()
        self.wait_online(
            'ip6tnl99:routable',
            'ip6tnl98:routable',
            'ip6tnl97:routable',
            'ip6tnl-slaac:degraded',
            'ip6tnl-external:degraded',
            'dummy98:degraded',
            'veth99:routable',
            'veth-peer:degraded')

    def test_sit_tunnel(self):
        copy_network_unit('12-dummy.netdev', '25-sit.network',
                          '25-sit-tunnel.netdev', '25-tunnel.network',
                          '25-sit-tunnel-local-any.netdev', '25-tunnel-local-any.network',
                          '25-sit-tunnel-remote-any.netdev', '25-tunnel-remote-any.network',
                          '25-sit-tunnel-any-any.netdev', '25-tunnel-any-any.network')
        start_networkd()
        self.wait_online('sittun99:routable', 'sittun98:routable', 'sittun97:routable', 'sittun96:routable', 'dummy98:degraded')
        self.networkctl_check_unit('sittun99', '25-sit-tunnel', '25-tunnel')
        self.networkctl_check_unit('sittun98', '25-sit-tunnel-local-any', '25-tunnel-local-any')
        self.networkctl_check_unit('sittun97', '25-sit-tunnel-remote-any', '25-tunnel-remote-any')
        self.networkctl_check_unit('sittun96', '25-sit-tunnel-any-any', '25-tunnel-any-any')
        self.networkctl_check_unit('dummy98', '12-dummy', '25-sit')

        output = check_output('ip -d link show sittun99')
        print(output)
        self.assertRegex(output, "sit (ip6ip )?remote 10.65.223.239 local 10.65.223.238 dev dummy98")
        output = check_output('ip -d link show sittun98')
        print(output)
        self.assertRegex(output, "sit (ip6ip )?remote 10.65.223.239 local any dev dummy98")
        output = check_output('ip -d link show sittun97')
        print(output)
        self.assertRegex(output, "sit (ip6ip )?remote any local 10.65.223.238 dev dummy98")
        output = check_output('ip -d link show sittun96')
        print(output)
        self.assertRegex(output, "sit (ip6ip )?remote any local any dev dummy98")

        touch_network_unit(
            '25-sit-tunnel.netdev',
            '25-sit-tunnel-local-any.netdev',
            '25-sit-tunnel-remote-any.netdev',
            '25-sit-tunnel-any-any.netdev')
        networkctl_reload()
        self.wait_online(
            'sittun99:routable',
            'sittun98:routable',
            'sittun97:routable',
            'sittun96:routable',
            'dummy98:degraded')

    def test_isatap_tunnel(self):
        copy_network_unit('12-dummy.netdev', '25-isatap.network',
                          '25-isatap-tunnel.netdev', '25-tunnel.network')
        start_networkd()
        self.wait_online('isataptun99:routable', 'dummy98:degraded')
        self.networkctl_check_unit('isataptun99', '25-isatap-tunnel', '25-tunnel')
        self.networkctl_check_unit('dummy98', '12-dummy', '25-isatap')

        output = check_output('ip -d link show isataptun99')
        print(output)
        self.assertRegex(output, "isatap ")

        touch_network_unit('25-isatap-tunnel.netdev')
        networkctl_reload()
        self.wait_online('isataptun99:routable', 'dummy98:degraded')

    def test_6rd_tunnel(self):
        copy_network_unit('12-dummy.netdev', '25-6rd.network',
                          '25-6rd-tunnel.netdev', '25-tunnel.network')
        start_networkd()
        self.wait_online('sittun99:routable', 'dummy98:degraded')
        self.networkctl_check_unit('sittun99', '25-6rd-tunnel', '25-tunnel')
        self.networkctl_check_unit('dummy98', '12-dummy', '25-6rd')

        output = check_output('ip -d link show sittun99')
        print(output)
        self.assertRegex(output, '6rd-prefix 2602::/24')

        touch_network_unit('25-6rd-tunnel.netdev')
        networkctl_reload()
        self.wait_online('sittun99:routable', 'dummy98:degraded')

    @expectedFailureIfERSPANv0IsNotSupported()
    def test_erspan_tunnel_v0(self):
        copy_network_unit('12-dummy.netdev', '25-erspan.network',
                          '25-erspan0-tunnel.netdev', '25-tunnel.network',
                          '25-erspan0-tunnel-local-any.netdev', '25-tunnel-local-any.network')
        start_networkd()
        self.wait_online('erspan99:routable', 'erspan98:routable', 'dummy98:degraded')
        self.networkctl_check_unit('erspan99', '25-erspan0-tunnel', '25-tunnel')
        self.networkctl_check_unit('erspan98', '25-erspan0-tunnel-local-any', '25-tunnel-local-any')
        self.networkctl_check_unit('dummy98', '12-dummy', '25-erspan')

        output = check_output('ip -d link show erspan99')
        print(output)
        self.assertIn('erspan remote 172.16.1.100 local 172.16.1.200', output)
        self.assertIn('erspan_ver 0', output)
        self.assertNotIn('erspan_index 123', output)
        self.assertNotIn('erspan_dir ingress', output)
        self.assertNotIn('erspan_hwid 1f', output)
        self.assertIn('ikey 0.0.0.101', output)
        self.assertIn('iseq', output)
        self.assertIn('nopmtudisc', output)
        self.assertIn('ignore-df', output)
        output = check_output('ip -d link show erspan98')
        print(output)
        self.assertIn('erspan remote 172.16.1.100 local any', output)
        self.assertIn('erspan_ver 0', output)
        self.assertNotIn('erspan_index 124', output)
        self.assertNotIn('erspan_dir egress', output)
        self.assertNotIn('erspan_hwid 2f', output)
        self.assertIn('ikey 0.0.0.102', output)
        self.assertIn('iseq', output)

        touch_network_unit(
            '25-erspan0-tunnel.netdev',
            '25-erspan0-tunnel-local-any.netdev')
        networkctl_reload()
        self.wait_online(
            'erspan99:routable',
            'erspan98:routable',
            'dummy98:degraded')

    def test_erspan_tunnel_v1(self):
        copy_network_unit('12-dummy.netdev', '25-erspan.network',
                          '25-erspan1-tunnel.netdev', '25-tunnel.network',
                          '25-erspan1-tunnel-local-any.netdev', '25-tunnel-local-any.network')
        start_networkd()
        self.wait_online('erspan99:routable', 'erspan98:routable', 'dummy98:degraded')
        self.networkctl_check_unit('erspan99', '25-erspan1-tunnel', '25-tunnel')
        self.networkctl_check_unit('erspan98', '25-erspan1-tunnel-local-any', '25-tunnel-local-any')
        self.networkctl_check_unit('dummy98', '12-dummy', '25-erspan')

        output = check_output('ip -d link show erspan99')
        print(output)
        self.assertIn('erspan remote 172.16.1.100 local 172.16.1.200', output)
        self.assertIn('erspan_ver 1', output)
        self.assertIn('erspan_index 123', output)
        self.assertNotIn('erspan_dir ingress', output)
        self.assertNotIn('erspan_hwid 1f', output)
        self.assertIn('ikey 0.0.0.101', output)
        self.assertIn('okey 0.0.0.101', output)
        self.assertIn('iseq', output)
        self.assertIn('oseq', output)
        output = check_output('ip -d link show erspan98')
        print(output)
        self.assertIn('erspan remote 172.16.1.100 local any', output)
        self.assertIn('erspan_ver 1', output)
        self.assertIn('erspan_index 124', output)
        self.assertNotIn('erspan_dir egress', output)
        self.assertNotIn('erspan_hwid 2f', output)
        self.assertIn('ikey 0.0.0.102', output)
        self.assertIn('okey 0.0.0.102', output)
        self.assertIn('iseq', output)
        self.assertIn('oseq', output)

        touch_network_unit(
            '25-erspan1-tunnel.netdev',
            '25-erspan1-tunnel-local-any.netdev')
        networkctl_reload()
        self.wait_online(
            'erspan99:routable',
            'erspan98:routable',
            'dummy98:degraded')

    @expectedFailureIfERSPANv2IsNotSupported()
    def test_erspan_tunnel_v2(self):
        copy_network_unit('12-dummy.netdev', '25-erspan.network',
                          '25-erspan2-tunnel.netdev', '25-tunnel.network',
                          '25-erspan2-tunnel-local-any.netdev', '25-tunnel-local-any.network')
        start_networkd()
        self.wait_online('erspan99:routable', 'erspan98:routable', 'dummy98:degraded')
        self.networkctl_check_unit('erspan99', '25-erspan2-tunnel', '25-tunnel')
        self.networkctl_check_unit('erspan98', '25-erspan2-tunnel-local-any', '25-tunnel-local-any')
        self.networkctl_check_unit('dummy98', '12-dummy', '25-erspan')

        output = check_output('ip -d link show erspan99')
        print(output)
        self.assertIn('erspan remote 172.16.1.100 local 172.16.1.200', output)
        self.assertIn('erspan_ver 2', output)
        self.assertNotIn('erspan_index 123', output)
        self.assertIn('erspan_dir ingress', output)
        self.assertIn('erspan_hwid 0x1f', output)
        self.assertIn('ikey 0.0.0.101', output)
        self.assertIn('okey 0.0.0.101', output)
        self.assertIn('iseq', output)
        self.assertIn('oseq', output)
        output = check_output('ip -d link show erspan98')
        print(output)
        self.assertIn('erspan remote 172.16.1.100 local any', output)
        self.assertIn('erspan_ver 2', output)
        self.assertNotIn('erspan_index 124', output)
        self.assertIn('erspan_dir egress', output)
        self.assertIn('erspan_hwid 0x2f', output)
        self.assertIn('ikey 0.0.0.102', output)
        self.assertIn('okey 0.0.0.102', output)
        self.assertIn('iseq', output)
        self.assertIn('oseq', output)

        touch_network_unit(
            '25-erspan2-tunnel.netdev',
            '25-erspan2-tunnel-local-any.netdev')
        networkctl_reload()
        self.wait_online(
            'erspan99:routable',
            'erspan98:routable',
            'dummy98:degraded')

    def test_tunnel_independent(self):
        copy_network_unit('25-ipip-tunnel-independent.netdev', '26-netdev-link-local-addressing-yes.network')
        start_networkd()

        self.wait_online('ipiptun99:carrier')
        self.networkctl_check_unit('ipiptun99', '25-ipip-tunnel-independent', '26-netdev-link-local-addressing-yes')

    def test_tunnel_independent_loopback(self):
        copy_network_unit('25-ipip-tunnel-independent-loopback.netdev', '26-netdev-link-local-addressing-yes.network')
        start_networkd()

        self.wait_online('ipiptun99:carrier')
        self.networkctl_check_unit('ipiptun99', '25-ipip-tunnel-independent-loopback', '26-netdev-link-local-addressing-yes')

    @expectedFailureIfModuleIsNotAvailable('xfrm_interface')
    def test_xfrm(self):
        copy_network_unit('12-dummy.netdev', '25-xfrm.network',
                          '25-xfrm.netdev', '25-xfrm-independent.netdev',
                          '26-netdev-link-local-addressing-yes.network')
        start_networkd()

        self.wait_online('dummy98:degraded', 'xfrm98:degraded', 'xfrm99:degraded')
        self.networkctl_check_unit('dummy98', '12-dummy', '25-xfrm')
        self.networkctl_check_unit('xfrm98', '25-xfrm', '26-netdev-link-local-addressing-yes')
        self.networkctl_check_unit('xfrm99', '25-xfrm-independent', '26-netdev-link-local-addressing-yes')

        output = check_output('ip -d link show dev xfrm98')
        print(output)
        self.assertIn('xfrm98@dummy98:', output)
        self.assertIn('xfrm if_id 0x98 ', output)

        output = check_output('ip -d link show dev xfrm99')
        print(output)
        self.assertIn('xfrm99@lo:', output)
        self.assertIn('xfrm if_id 0x99 ', output)

        touch_network_unit('25-xfrm.netdev')
        networkctl_reload()
        self.wait_online('dummy98:degraded', 'xfrm98:degraded', 'xfrm99:degraded')

    @expectedFailureIfModuleIsNotAvailable('fou')
    def test_fou(self):
        copy_network_unit('25-fou-ipproto-ipip.netdev', '25-fou-ipproto-gre.netdev',
                          '25-fou-ipip.netdev', '25-fou-sit.netdev',
                          '25-fou-gre.netdev', '25-fou-gretap.netdev')
        start_networkd()

        self.wait_online('ipiptun96:off', 'sittun96:off', 'gretun96:off', 'gretap96:off', setup_state='unmanaged')
        self.networkctl_check_unit('ipiptun96', '25-fou-ipip')
        self.networkctl_check_unit('sittun96', '25-fou-sit')
        self.networkctl_check_unit('gretun96', '25-fou-gre')
        self.networkctl_check_unit('gretap96', '25-fou-gretap')

        output = check_output('ip fou show')
        print(output)
        self.assertRegex(output, 'port 55555 ipproto 4')
        self.assertRegex(output, 'port 55556 ipproto 47')

        output = check_output('ip -d link show ipiptun96')
        print(output)
        self.assertRegex(output, 'encap fou encap-sport auto encap-dport 55555')
        output = check_output('ip -d link show sittun96')
        print(output)
        self.assertRegex(output, 'encap fou encap-sport auto encap-dport 55555')
        output = check_output('ip -d link show gretun96')
        print(output)
        self.assertRegex(output, 'encap fou encap-sport 1001 encap-dport 55556')
        output = check_output('ip -d link show gretap96')
        print(output)
        self.assertRegex(output, 'encap fou encap-sport auto encap-dport 55556')

        touch_network_unit(
            '25-fou-ipproto-ipip.netdev', '25-fou-ipproto-gre.netdev',
            '25-fou-ipip.netdev', '25-fou-sit.netdev',
            '25-fou-gre.netdev', '25-fou-gretap.netdev')
        networkctl_reload()
        self.wait_online('ipiptun96:off', 'sittun96:off', 'gretun96:off', 'gretap96:off', setup_state='unmanaged')

    def test_vxlan(self):
        copy_network_unit('11-dummy.netdev', '25-vxlan-test1.network',
                          '25-vxlan.netdev', '25-vxlan.network',
                          '25-vxlan-ipv6.netdev', '25-vxlan-ipv6.network',
                          '25-vxlan-independent.netdev', '26-netdev-link-local-addressing-yes.network',
                          '25-veth.netdev', '25-vxlan-veth99.network', '25-ipv6-prefix.network',
                          '25-vxlan-local-slaac.netdev', '25-vxlan-local-slaac.network')
        start_networkd()

        self.wait_online('test1:degraded', 'veth99:routable', 'veth-peer:degraded',
                         'vxlan99:degraded', 'vxlan98:degraded', 'vxlan97:degraded', 'vxlan-slaac:degraded')
        self.networkctl_check_unit('test1', '11-dummy', '25-vxlan-test1')
        self.networkctl_check_unit('veth99', '25-veth', '25-vxlan-veth99')
        self.networkctl_check_unit('veth-peer', '25-veth', '25-ipv6-prefix')
        self.networkctl_check_unit('vxlan99', '25-vxlan', '25-vxlan')
        self.networkctl_check_unit('vxlan98', '25-vxlan-independent', '26-netdev-link-local-addressing-yes')
        self.networkctl_check_unit('vxlan97', '25-vxlan-ipv6', '25-vxlan-ipv6')
        self.networkctl_check_unit('vxlan-slaac', '25-vxlan-local-slaac', '25-vxlan-local-slaac')

        output = check_output('ip -d -d link show vxlan99')
        print(output)
        self.assertIn('999', output)
        self.assertIn('5555', output)
        self.assertIn('l2miss', output)
        self.assertIn('l3miss', output)
        self.assertIn('gbp', output)
        # Since [0] some of the options use slightly different names and some
        # options with default values are shown only if the -d(etails) setting
        # is repeated
        # [0] https://git.kernel.org/pub/scm/network/iproute2/iproute2.git/commit/?id=1215e9d3862387353d8672296cb4c6c16e8cbb72
        self.assertRegex(output, '(udpcsum|udp_csum)')
        self.assertRegex(output, '(udp6zerocsumtx|udp_zero_csum6_tx)')
        self.assertRegex(output, '(udp6zerocsumrx|udp_zero_csum6_rx)')
        self.assertRegex(output, '(remcsumtx|remcsum_tx)')
        self.assertRegex(output, '(remcsumrx|remcsum_rx)')

        output = check_output('bridge fdb show dev vxlan99')
        print(output)
        self.assertIn('00:11:22:33:44:55 dst 10.0.0.5 self permanent', output)
        self.assertIn('00:11:22:33:44:66 dst 10.0.0.6 self permanent', output)
        self.assertIn('00:11:22:33:44:77 dst 10.0.0.7 via test1 self permanent', output)

        output = networkctl_status('vxlan99')
        print(output)
        self.assertIn('VNI: 999', output)
        self.assertIn('Destination Port: 5555', output)
        self.assertIn('Underlying Device: test1', output)

        output = check_output('bridge fdb show dev vxlan97')
        print(output)
        self.assertIn('00:00:00:00:00:00 dst fe80::23b:d2ff:fe95:967f via test1 self permanent', output)
        self.assertIn('00:00:00:00:00:00 dst fe80::27c:16ff:fec0:6c74 via test1 self permanent', output)
        self.assertIn('00:00:00:00:00:00 dst fe80::2a2:e4ff:fef9:2269 via test1 self permanent', output)

        output = check_output('ip -d link show vxlan-slaac')
        print(output)
        self.assertIn('vxlan id 4831584 local 2002:da8:1:0:1034:56ff:fe78:9abc dev veth99', output)

        output = check_output('ip -6 address show veth99')
        print(output)
        self.assertIn('inet6 2002:da8:1:0:1034:56ff:fe78:9abc/64 scope global dynamic', output)

    @unittest.skipUnless(compare_kernel_version("6"), reason="Causes kernel panic on unpatched kernels: https://bugzilla.kernel.org/show_bug.cgi?id=208315")
    def test_macsec(self):
        copy_network_unit('25-macsec.netdev', '25-macsec.network', '25-macsec.key',
                          '26-macsec.network', '12-dummy.netdev')
        start_networkd()

        self.wait_online('dummy98:degraded', 'macsec99:routable')
        self.networkctl_check_unit('dummy98', '12-dummy', '26-macsec')
        self.networkctl_check_unit('macsec99', '25-macsec', '25-macsec')

        output = check_output('ip -d link show macsec99')
        print(output)
        self.assertRegex(output, 'macsec99@dummy98')
        self.assertRegex(output, 'macsec sci [0-9a-f]*000b')
        self.assertRegex(output, 'encrypt on')

        output = check_output('ip macsec show macsec99')
        print(output)
        self.assertRegex(output, 'encrypt on')
        self.assertRegex(output, 'TXSC: [0-9a-f]*000b on SA 1')
        self.assertRegex(output, '0: PN [0-9]*, state on, key 01000000000000000000000000000000')
        self.assertRegex(output, '1: PN [0-9]*, state on, key 02030000000000000000000000000000')
        self.assertRegex(output, 'RXSC: c619528fe6a00100, state on')
        self.assertRegex(output, '0: PN [0-9]*, state on, key 02030405000000000000000000000000')
        self.assertRegex(output, '1: PN [0-9]*, state on, key 02030405060000000000000000000000')
        self.assertRegex(output, '2: PN [0-9]*, state off, key 02030405060700000000000000000000')
        self.assertRegex(output, '3: PN [0-9]*, state off, key 02030405060708000000000000000000')
        self.assertNotRegex(output, 'key 02030405067080900000000000000000')
        self.assertRegex(output, 'RXSC: 8c16456c83a90002, state on')
        self.assertRegex(output, '0: PN [0-9]*, state off, key 02030400000000000000000000000000')

        touch_network_unit('25-macsec.netdev')
        networkctl_reload()
        self.wait_online('dummy98:degraded', 'macsec99:routable')

    def test_nlmon(self):
        copy_network_unit('25-nlmon.netdev', '26-netdev-link-local-addressing-yes.network')
        start_networkd()

        self.wait_online('nlmon99:carrier')
        self.networkctl_check_unit('nlmon99', '25-nlmon', '26-netdev-link-local-addressing-yes')

        touch_network_unit('25-nlmon.netdev', '26-netdev-link-local-addressing-yes.network')
        networkctl_reload()
        self.wait_online('nlmon99:carrier')

    @expectedFailureIfModuleIsNotAvailable('ifb')
    def test_ifb(self):
        copy_network_unit('25-ifb.netdev', '26-netdev-link-local-addressing-yes.network')
        start_networkd()

        self.wait_online('ifb99:degraded')
        self.networkctl_check_unit('ifb99', '25-ifb', '26-netdev-link-local-addressing-yes')

        touch_network_unit('25-ifb.netdev', '26-netdev-link-local-addressing-yes.network')
        networkctl_reload()
        self.wait_online('ifb99:degraded')

    @unittest.skipUnless(os.cpu_count() >= 2, reason="CPU count should be >= 2 to pass this test")
    def test_rps_cpu_1(self):
        copy_network_unit('12-dummy.netdev', '12-dummy.network', '25-rps-cpu-1.link')
        start_networkd()

        self.wait_online('dummy98:carrier')
        self.networkctl_check_unit('dummy98', '12-dummy', '12-dummy', '25-rps-cpu-1')

        output = check_output('cat /sys/class/net/dummy98/queues/rx-0/rps_cpus')
        print(output)
        self.assertEqual(int(output.replace(',', ''), base=16), 2)

    @unittest.skipUnless(os.cpu_count() >= 2, reason="CPU count should be >= 2 to pass this test")
    def test_rps_cpu_0_1(self):
        copy_network_unit('12-dummy.netdev', '12-dummy.network', '25-rps-cpu-0-1.link')
        start_networkd()

        self.wait_online('dummy98:carrier')
        self.networkctl_check_unit('dummy98', '12-dummy', '12-dummy', '25-rps-cpu-0-1')

        output = check_output('cat /sys/class/net/dummy98/queues/rx-0/rps_cpus')
        print(output)
        self.assertEqual(int(output.replace(',', ''), base=16), 3)

    @unittest.skipUnless(os.cpu_count() >= 4, reason="CPU count should be >= 4 to pass this test")
    def test_rps_cpu_multi(self):
        copy_network_unit('12-dummy.netdev', '12-dummy.network', '25-rps-cpu-multi.link')
        start_networkd()

        self.wait_online('dummy98:carrier')
        self.networkctl_check_unit('dummy98', '12-dummy', '12-dummy', '25-rps-cpu-multi')

        output = check_output('cat /sys/class/net/dummy98/queues/rx-0/rps_cpus')
        print(output)
        self.assertEqual(int(output.replace(',', ''), base=16), 15)

    def test_rps_cpu(self):
        cpu_count = os.cpu_count()

        copy_network_unit('12-dummy.netdev', '12-dummy.network')
        start_networkd()

        self.wait_online('dummy98:carrier')
        self.networkctl_check_unit('dummy98', '12-dummy', '12-dummy')

        # 0
        copy_network_unit('25-rps-cpu-0.link')
        udevadm_trigger('/sys/class/net/dummy98')
        self.networkctl_check_unit('dummy98', '12-dummy', '12-dummy', '25-rps-cpu-0')
        output = check_output('cat /sys/class/net/dummy98/queues/rx-0/rps_cpus')
        print(output)
        self.assertEqual(int(output.replace(',', ''), base=16), 1)
        remove_network_unit('25-rps-cpu-0.link')

        # all
        copy_network_unit('25-rps-cpu-all.link')
        udevadm_trigger('/sys/class/net/dummy98')
        self.networkctl_check_unit('dummy98', '12-dummy', '12-dummy', '25-rps-cpu-all')
        output = check_output('cat /sys/class/net/dummy98/queues/rx-0/rps_cpus')
        print(output)
        self.assertEqual(f"{int(output.replace(',', ''), base=16):x}", f'{(1 << cpu_count) - 1:x}')
        remove_network_unit('25-rps-cpu-all.link')

        # disable
        copy_network_unit('24-rps-cpu-disable.link')
        udevadm_trigger('/sys/class/net/dummy98')
        self.networkctl_check_unit('dummy98', '12-dummy', '12-dummy', '24-rps-cpu-disable')
        output = check_output('cat /sys/class/net/dummy98/queues/rx-0/rps_cpus')
        print(output)
        self.assertEqual(int(output.replace(',', ''), base=16), 0)
        remove_network_unit('24-rps-cpu-disable.link')

        # set all again
        copy_network_unit('25-rps-cpu-all.link')
        udevadm_trigger('/sys/class/net/dummy98')
        self.networkctl_check_unit('dummy98', '12-dummy', '12-dummy', '25-rps-cpu-all')
        output = check_output('cat /sys/class/net/dummy98/queues/rx-0/rps_cpus')
        print(output)
        self.assertEqual(f"{int(output.replace(',', ''), base=16):x}", f'{(1 << cpu_count) - 1:x}')
        remove_network_unit('25-rps-cpu-all.link')

        # empty -> unchanged
        copy_network_unit('24-rps-cpu-empty.link')
        udevadm_trigger('/sys/class/net/dummy98')
        self.networkctl_check_unit('dummy98', '12-dummy', '12-dummy', '24-rps-cpu-empty')
        output = check_output('cat /sys/class/net/dummy98/queues/rx-0/rps_cpus')
        print(output)
        self.assertEqual(f"{int(output.replace(',', ''), base=16):x}", f'{(1 << cpu_count) - 1:x}')
        remove_network_unit('24-rps-cpu-empty.link')

        # 0, then empty -> unchanged
        copy_network_unit('25-rps-cpu-0-empty.link')
        udevadm_trigger('/sys/class/net/dummy98')
        self.networkctl_check_unit('dummy98', '12-dummy', '12-dummy', '25-rps-cpu-0-empty')
        output = check_output('cat /sys/class/net/dummy98/queues/rx-0/rps_cpus')
        print(output)
        self.assertEqual(f"{int(output.replace(',', ''), base=16):x}", f'{(1 << cpu_count) - 1:x}')
        remove_network_unit('25-rps-cpu-0-empty.link')

        # 0, then invalid -> 0
        copy_network_unit('25-rps-cpu-0-invalid.link')
        udevadm_trigger('/sys/class/net/dummy98')
        self.networkctl_check_unit('dummy98', '12-dummy', '12-dummy', '25-rps-cpu-0-invalid')
        output = check_output('cat /sys/class/net/dummy98/queues/rx-0/rps_cpus')
        print(output)
        self.assertEqual(int(output.replace(',', ''), base=16), 1)
        remove_network_unit('25-rps-cpu-0-invalid.link')

        # invalid -> unchanged
        copy_network_unit('24-rps-cpu-invalid.link')
        udevadm_trigger('/sys/class/net/dummy98')
        self.networkctl_check_unit('dummy98', '12-dummy', '12-dummy', '24-rps-cpu-invalid')
        output = check_output('cat /sys/class/net/dummy98/queues/rx-0/rps_cpus')
        print(output)
        self.assertEqual(int(output.replace(',', ''), base=16), 1)
        remove_network_unit('24-rps-cpu-invalid.link')

class NetworkdL2TPTests(unittest.TestCase, Utilities):

    def setUp(self):
        setup_common()

    def tearDown(self):
        tear_down_common()

    @expectedFailureIfModuleIsNotAvailable('l2tp_eth', 'l2tp_netlink')
    def test_l2tp_udp(self):
        copy_network_unit('11-dummy.netdev', '25-l2tp-dummy.network',
                          '25-l2tp-udp.netdev', '25-l2tp.network')
        start_networkd()

        self.wait_online('test1:routable', 'l2tp-ses1:degraded', 'l2tp-ses2:degraded')
        self.networkctl_check_unit('test1', '11-dummy', '25-l2tp-dummy')
        self.networkctl_check_unit('l2tp-ses1', '25-l2tp-udp', '25-l2tp')
        self.networkctl_check_unit('l2tp-ses2', '25-l2tp-udp', '25-l2tp')

        output = check_output('ip l2tp show tunnel tunnel_id 10')
        print(output)
        self.assertRegex(output, "Tunnel 10, encap UDP")
        self.assertRegex(output, "From 192.168.30.100 to 192.168.30.101")
        self.assertRegex(output, "Peer tunnel 11")
        self.assertRegex(output, "UDP source / dest ports: 3000/4000")
        self.assertRegex(output, "UDP checksum: enabled")

        output = check_output('ip l2tp show session tid 10 session_id 15')
        print(output)
        self.assertRegex(output, "Session 15 in tunnel 10")
        self.assertRegex(output, "Peer session 16, tunnel 11")
        self.assertRegex(output, "interface name: l2tp-ses1")

        output = check_output('ip l2tp show session tid 10 session_id 17')
        print(output)
        self.assertRegex(output, "Session 17 in tunnel 10")
        self.assertRegex(output, "Peer session 18, tunnel 11")
        self.assertRegex(output, "interface name: l2tp-ses2")

        touch_network_unit(
            '11-dummy.netdev', '25-l2tp-dummy.network',
            '25-l2tp-udp.netdev', '25-l2tp.network')
        networkctl_reload()
        self.wait_online('test1:routable', 'l2tp-ses1:degraded', 'l2tp-ses2:degraded')

    @expectedFailureIfModuleIsNotAvailable('l2tp_eth', 'l2tp_ip', 'l2tp_netlink')
    def test_l2tp_ip(self):
        copy_network_unit('11-dummy.netdev', '25-l2tp-dummy.network',
                          '25-l2tp-ip.netdev', '25-l2tp.network')
        start_networkd()

        self.wait_online('test1:routable', 'l2tp-ses3:degraded', 'l2tp-ses4:degraded')
        self.networkctl_check_unit('test1', '11-dummy', '25-l2tp-dummy')
        self.networkctl_check_unit('l2tp-ses3', '25-l2tp-ip', '25-l2tp')
        self.networkctl_check_unit('l2tp-ses4', '25-l2tp-ip', '25-l2tp')

        output = check_output('ip l2tp show tunnel tunnel_id 10')
        print(output)
        self.assertRegex(output, "Tunnel 10, encap IP")
        self.assertRegex(output, "From 192.168.30.100 to 192.168.30.101")
        self.assertRegex(output, "Peer tunnel 12")

        output = check_output('ip l2tp show session tid 10 session_id 25')
        print(output)
        self.assertRegex(output, "Session 25 in tunnel 10")
        self.assertRegex(output, "Peer session 26, tunnel 12")
        self.assertRegex(output, "interface name: l2tp-ses3")

        output = check_output('ip l2tp show session tid 10 session_id 27')
        print(output)
        self.assertRegex(output, "Session 27 in tunnel 10")
        self.assertRegex(output, "Peer session 28, tunnel 12")
        self.assertRegex(output, "interface name: l2tp-ses4")

        touch_network_unit(
            '11-dummy.netdev', '25-l2tp-dummy.network',
            '25-l2tp-ip.netdev', '25-l2tp.network')
        networkctl_reload()
        self.wait_online('test1:routable', 'l2tp-ses3:degraded', 'l2tp-ses4:degraded')

class NetworkdNetworkTests(unittest.TestCase, Utilities):

    def setUp(self):
        setup_common()

    def tearDown(self):
        tear_down_common()

    def verify_address_static(
            self,
            label1: str,
            label2: str,
            label3: str,
            broadcast1: str,
            broadcast2: str,
            broadcast3: str,
            peer1: str,
            peer2: str,
            peer3: str,
            peer4: str,
            peer5: str,
            peer6: str,
            scope1: str,
            scope2: str,
            deprecated1: str,
            deprecated2: str,
            deprecated3: str,
            deprecated4: str,
            route_metric: int,
            flag1: str,
            flag2: str,
            flag3: str,
            flag4: str,
            ip4_null_16: str,
            ip4_null_24: str,
            ip6_null_73: str,
            ip6_null_74: str,
    ):
        output = check_output('ip address show dev dummy98')
        print(output)

        # simple settings
        self.assertIn('inet 10.1.2.3/16 brd 10.1.255.255 scope global dummy98', output)
        self.assertIn('inet 10.1.2.4/16 brd 10.1.255.255 scope global secondary dummy98', output)
        self.assertIn('inet 10.2.2.4/16 brd 10.2.255.255 scope global dummy98', output)
        self.assertIn('inet6 2001:db8:0:f101::15/64 scope global', output)
        self.assertIn('inet6 2001:db8:0:f101::16/64 scope global', output)
        self.assertIn('inet6 2001:db8:0:f102::15/64 scope global', output)

        # label
        self.assertIn(f'inet 10.3.1.1/24 brd 10.3.1.255 scope global {label1}', output)
        self.assertIn(f'inet 10.3.2.1/24 brd 10.3.2.255 scope global {label2}', output)
        self.assertIn(f'inet 10.3.3.1/24 brd 10.3.3.255 scope global {label3}', output)

        # broadcast
        self.assertIn(f'inet 10.4.1.1/24{broadcast1} scope global dummy98', output)
        self.assertIn(f'inet 10.4.2.1/24{broadcast2} scope global dummy98', output)
        self.assertIn(f'inet 10.4.3.1/24{broadcast3} scope global dummy98', output)

        # peer
        self.assertIn(f'inet 10.5.1.1{peer1} scope global dummy98', output)
        self.assertIn(f'inet 10.5.2.1{peer2} scope global dummy98', output)
        self.assertIn(f'inet 10.5.3.1{peer3} scope global dummy98', output)
        self.assertIn(f'inet6 2001:db8:0:f103::1{peer4} scope global', output)
        self.assertIn(f'inet6 2001:db8:0:f103::2{peer5} scope global', output)
        self.assertIn(f'inet6 2001:db8:0:f103::3{peer6} scope global', output)

        # scope
        self.assertIn(f'inet 10.6.1.1/24 brd 10.6.1.255 scope {scope1} dummy98', output)
        self.assertIn(f'inet 10.6.2.1/24 brd 10.6.2.255 scope {scope2} dummy98', output)

        # lifetime
        self.assertIn(f'inet 10.7.1.1/24 brd 10.7.1.255 scope global{deprecated1} dummy98', output)
        self.assertIn(f'inet 10.7.2.1/24 brd 10.7.2.255 scope global{deprecated2} dummy98', output)
        self.assertIn(f'inet6 2001:db8:0:f104::1/64 scope global{deprecated3}', output)
        self.assertIn(f'inet6 2001:db8:0:f104::2/64 scope global{deprecated4}', output)

        # route metric
        self.assertRegex(output, rf'inet 10.8.1.1/24 (metric {route_metric} |)brd 10.8.1.255 scope global dummy98')
        self.assertRegex(output, rf'inet6 2001:db8:0:f105::1/64 (metric {route_metric} |)scope global')

        output_route = check_output('ip -4 route show dev dummy98 10.8.1.0/24')
        print(output_route)
        self.assertIn(f'10.8.1.0/24 proto kernel scope link src 10.8.1.1 metric {route_metric}', output_route)

        output_route = check_output('ip -6 route show dev dummy98 2001:db8:0:f105::/64')
        print(output_route)
        self.assertIn(f'2001:db8:0:f105::/64 proto kernel metric {route_metric}', output_route)

        # flags
        self.assertIn(f'inet 10.9.1.1/24 brd 10.9.1.255 scope global{flag1} dummy98', output)
        self.assertIn(f'inet 10.9.2.1/24 brd 10.9.2.255 scope global{flag2} dummy98', output)
        self.assertIn(f'inet6 2001:db8:0:f106::1/64 scope global{flag3}', output)
        self.assertIn(f'inet6 2001:db8:0:f106::2/64 scope global{flag4}', output)

        # null address
        self.assertTrue(ip4_null_16.endswith('.0.1'))
        prefix16 = ip4_null_16[:-len('.0.1')]
        self.assertTrue(ip4_null_24.endswith('.1'))
        prefix24 = ip4_null_24[:-len('.1')]
        self.assertIn(f'inet {ip4_null_16}/16 brd {prefix16}.255.255 scope global subnet16', output)
        self.assertIn(f'inet {ip4_null_24}/24 brd {prefix24}.255 scope global subnet24', output)
        self.assertIn(f'inet6 {ip6_null_73}/73 scope global', output)
        self.assertIn(f'inet6 {ip6_null_74}/74 scope global', output)

        # invalid sections
        self.assertNotIn('10.4.4.1', output)
        self.assertNotIn('10.5.4.1', output)
        self.assertNotIn('10.5.5.1', output)
        self.assertNotIn('10.8.2.1', output)
        self.assertNotIn('10.9.3.1', output)
        self.assertNotIn('2001:db8:0:f101::2', output)
        self.assertNotIn('2001:db8:0:f103::4', output)

        # netlabel
        self.check_netlabel('dummy98', r'10\.10\.1\.0/24')

        check_json(networkctl_json())

    @expectedFailureIfKernelReturnsInvalidFlags()
    def test_address_static(self):
        copy_network_unit('25-address-static.network', '12-dummy.netdev', copy_dropins=False)
        self.setup_nftset('addr4', 'ipv4_addr')
        self.setup_nftset('network4', 'ipv4_addr', 'flags interval;')
        self.setup_nftset('ifindex', 'iface_index')
        start_networkd()

        self.wait_online('dummy98:routable')

        ip4_null_16 = None
        ip4_null_24 = None
        output = check_output('ip -4 --json address show dev dummy98')
        for i in json.loads(output)[0]['addr_info']:
            if i['label'] == 'subnet16':
                ip4_null_16 = i['local']
            elif i['label'] == 'subnet24':
                ip4_null_24 = i['local']
        self.assertTrue(ip4_null_16.endswith('.0.1'))
        self.assertTrue(ip4_null_24.endswith('.1'))

        ip6_null_73 = None
        ip6_null_74 = None
        output = check_output('ip -6 --json address show dev dummy98')
        for i in json.loads(output)[0]['addr_info']:
            if i['prefixlen'] == 73:
                ip6_null_73 = i['local']
            elif i['prefixlen'] == 74:
                ip6_null_74 = i['local']
        self.assertTrue(ip6_null_73.endswith(':1'))
        self.assertTrue(ip6_null_74.endswith(':1'))

        self.verify_address_static(
            label1='label1',
            label2='label2',
            label3='dummy98',
            broadcast1='',
            broadcast2=' brd 10.4.2.255',
            broadcast3=' brd 10.4.3.63',
            peer1=' peer 10.5.1.101/24',
            peer2=' peer 10.5.2.101/24',
            peer3='/24 brd 10.5.3.255',
            peer4=' peer 2001:db8:0:f103::101/128',
            peer5=' peer 2001:db8:0:f103::102/128',
            peer6='/128',
            scope1='global',
            scope2='link',
            deprecated1='',
            deprecated2=' deprecated',
            deprecated3='',
            deprecated4=' deprecated',
            route_metric=128,
            flag1=' noprefixroute',
            flag2='',
            flag3=' noprefixroute',
            flag4=' home mngtmpaddr',
            ip4_null_16=ip4_null_16,
            ip4_null_24=ip4_null_24,
            ip6_null_73=ip6_null_73,
            ip6_null_74=ip6_null_74,
        )
        # nft set
        self.check_nftset('addr4', r'10\.10\.1\.1')
        self.check_nftset('network4', r'10\.10\.1\.0/24')
        self.check_nftset('ifindex', 'dummy98')

        self.teardown_nftset('addr4', 'network4', 'ifindex')

        copy_network_unit('25-address-static.network.d/10-override.conf')
        networkctl_reload()
        self.wait_online('dummy98:routable')
        self.verify_address_static(
            label1='new-label1',
            label2='dummy98',
            label3='new-label3',
            broadcast1=' brd 10.4.1.255',
            broadcast2='',
            broadcast3=' brd 10.4.3.31',
            peer1=' peer 10.5.1.102/24',
            peer2='/24 brd 10.5.2.255',
            peer3=' peer 10.5.3.102/24',
            peer4=' peer 2001:db8:0:f103::201/128',
            peer5='/128',
            peer6=' peer 2001:db8:0:f103::203/128',
            scope1='link',
            scope2='global',
            deprecated1=' deprecated',
            deprecated2='',
            deprecated3=' deprecated',
            deprecated4='',
            route_metric=256,
            flag1='',
            flag2=' noprefixroute',
            flag3=' home mngtmpaddr',
            flag4=' noprefixroute',
            ip4_null_16=ip4_null_16,
            ip4_null_24=ip4_null_24,
            ip6_null_73=ip6_null_73,
            ip6_null_74=ip6_null_74,
        )

        networkctl_reconfigure('dummy98')
        self.wait_online('dummy98:routable')
        self.verify_address_static(
            label1='new-label1',
            label2='dummy98',
            label3='new-label3',
            broadcast1=' brd 10.4.1.255',
            broadcast2='',
            broadcast3=' brd 10.4.3.31',
            peer1=' peer 10.5.1.102/24',
            peer2='/24 brd 10.5.2.255',
            peer3=' peer 10.5.3.102/24',
            peer4=' peer 2001:db8:0:f103::201/128',
            peer5='/128',
            peer6=' peer 2001:db8:0:f103::203/128',
            scope1='link',
            scope2='global',
            deprecated1=' deprecated',
            deprecated2='',
            deprecated3=' deprecated',
            deprecated4='',
            route_metric=256,
            flag1='',
            flag2=' noprefixroute',
            flag3=' home mngtmpaddr',
            flag4=' noprefixroute',
            ip4_null_16=ip4_null_16,
            ip4_null_24=ip4_null_24,
            ip6_null_73=ip6_null_73,
            ip6_null_74=ip6_null_74,
        )

        # Tests for #20891.
        # 1. set preferred lifetime forever to drop the deprecated flag for testing #20891.
        check_output('ip address change 10.7.1.1/24 dev dummy98 preferred_lft forever')
        check_output('ip address change 2001:db8:0:f104::1/64 dev dummy98 preferred_lft forever')
        output = check_output('ip address show dev dummy98')
        print(output)
        self.assertNotRegex(output, '10.7.1.1/24 .* deprecated')
        self.assertNotRegex(output, '2001:db8:0:f104::1/64 .* deprecated')

        # 2. reconfigure the interface, and check the deprecated flag is set again
        networkctl_reconfigure('dummy98')
        self.wait_online('dummy98:routable')
        self.verify_address_static(
            label1='new-label1',
            label2='dummy98',
            label3='new-label3',
            broadcast1=' brd 10.4.1.255',
            broadcast2='',
            broadcast3=' brd 10.4.3.31',
            peer1=' peer 10.5.1.102/24',
            peer2='/24 brd 10.5.2.255',
            peer3=' peer 10.5.3.102/24',
            peer4=' peer 2001:db8:0:f103::201/128',
            peer5='/128',
            peer6=' peer 2001:db8:0:f103::203/128',
            scope1='link',
            scope2='global',
            deprecated1=' deprecated',
            deprecated2='',
            deprecated3=' deprecated',
            deprecated4='',
            route_metric=256,
            flag1='',
            flag2=' noprefixroute',
            flag3=' home mngtmpaddr',
            flag4=' noprefixroute',
            ip4_null_16=ip4_null_16,
            ip4_null_24=ip4_null_24,
            ip6_null_73=ip6_null_73,
            ip6_null_74=ip6_null_74,
        )

        # test for ENOBUFS issue #17012 (with reload)
        copy_network_unit('25-address-static.network.d/10-many-address.conf')
        networkctl_reload()
        self.wait_online('dummy98:routable')
        output = check_output('ip -4 address show dev dummy98')
        for i in range(1, 254):
            self.assertIn(f'inet 10.3.3.{i}/16 brd 10.3.255.255', output)

        # (with reconfigure)
        networkctl_reconfigure('dummy98')
        self.wait_online('dummy98:routable')
        output = check_output('ip -4 address show dev dummy98')
        for i in range(1, 254):
            self.assertIn(f'inet 10.3.3.{i}/16 brd 10.3.255.255', output)

        # test for an empty string assignment for Address= in [Network]
        copy_network_unit('25-address-static.network.d/20-clear-addresses.conf')
        networkctl_reload()
        self.wait_online('dummy98:routable')
        output = check_output('ip -4 address show dev dummy98')
        for i in range(1, 254):
            self.assertNotIn(f'inet 10.3.3.{i}/16 brd 10.3.255.255', output)
        self.assertIn('inet 10.4.0.1/16 brd 10.4.255.255', output)

    def test_address_ipv4acd(self):
        check_output('ip netns add ns99')
        check_output('ip link add veth99 type veth peer veth-peer')
        check_output('ip link set veth-peer netns ns99')
        check_output('ip link set veth99 up')
        check_output('ip netns exec ns99 ip link set veth-peer up')
        check_output('ip netns exec ns99 ip address add 192.168.100.10/24 dev veth-peer')

        copy_network_unit('25-address-ipv4acd-veth99.network', copy_dropins=False)
        start_networkd()
        self.wait_online('veth99:routable')

        output = check_output('ip -4 address show dev veth99')
        print(output)
        self.assertNotIn('192.168.100.10/24', output)
        self.assertIn('192.168.100.11/24', output)

        copy_network_unit('25-address-ipv4acd-veth99.network.d/conflict-address.conf')
        networkctl_reload()
        self.wait_operstate('veth99', operstate='routable', setup_state='configuring', setup_timeout=10)

        output = check_output('ip -4 address show dev veth99')
        print(output)
        self.assertNotIn('192.168.100.10/24', output)
        self.assertIn('192.168.100.11/24', output)

    def test_address_peer_ipv4(self):
        # test for issue #17304
        copy_network_unit('25-address-peer-ipv4.network', '12-dummy.netdev')

        for trial in range(2):
            if trial == 0:
                start_networkd()
            else:
                restart_networkd()

            self.wait_online('dummy98:routable')

            output = check_output('ip -4 address show dev dummy98')
            self.assertIn('inet 100.64.0.1 peer 100.64.0.2/32 scope global', output)

    @expectedFailureIfModuleIsNotAvailable('vrf')
    def test_prefix_route(self):
        copy_network_unit('25-prefix-route-with-vrf.network', '12-dummy.netdev',
                          '25-prefix-route-without-vrf.network', '11-dummy.netdev',
                          '25-vrf.netdev', '25-vrf.network')
        for trial in range(2):
            if trial == 0:
                start_networkd()
            else:
                restart_networkd()

            self.wait_online('dummy98:routable', 'test1:routable', 'vrf99:carrier')

            output = check_output('ip route show table 42 dev dummy98')
            print('### ip route show table 42 dev dummy98')
            print(output)
            self.assertRegex(output, 'local 10.20.22.1 proto kernel scope host src 10.20.22.1')
            self.assertRegex(output, '10.20.33.0/24 proto kernel scope link src 10.20.33.1')
            self.assertRegex(output, 'local 10.20.33.1 proto kernel scope host src 10.20.33.1')
            self.assertRegex(output, 'broadcast 10.20.33.255 proto kernel scope link src 10.20.33.1')
            self.assertRegex(output, 'local 10.20.44.1 proto kernel scope host src 10.20.44.1')
            self.assertRegex(output, 'local 10.20.55.1 proto kernel scope host src 10.20.55.1')
            self.assertRegex(output, 'broadcast 10.20.55.255 proto kernel scope link src 10.20.55.1')
            output = check_output('ip -6 route show table 42 dev dummy98')
            print('### ip -6 route show table 42 dev dummy98')
            print(output)
            if trial == 0:
                # Kernel's bug?
                self.assertRegex(output, 'local fdde:11:22::1 proto kernel metric 0 pref medium')
            #self.assertRegex(output, 'fdde:11:22::1 proto kernel metric 256 pref medium')
            self.assertRegex(output, 'local fdde:11:33::1 proto kernel metric 0 pref medium')
            self.assertRegex(output, 'fdde:11:33::/64 proto kernel metric 256 pref medium')
            self.assertRegex(output, 'local fdde:11:44::1 proto kernel metric 0 pref medium')
            self.assertRegex(output, 'local fdde:11:55::1 proto kernel metric 0 pref medium')
            self.assertRegex(output, 'fe80::/64 proto kernel metric 256 pref medium')
            self.assertRegex(output, 'ff00::/8 (proto kernel )?metric 256 (linkdown )?pref medium')

            print()

            output = check_output('ip route show dev test1')
            print('### ip route show dev test1')
            print(output)
            self.assertRegex(output, '10.21.33.0/24 proto kernel scope link src 10.21.33.1')
            output = check_output('ip route show table local dev test1')
            print('### ip route show table local dev test1')
            print(output)
            self.assertRegex(output, 'local 10.21.22.1 proto kernel scope host src 10.21.22.1')
            self.assertRegex(output, 'local 10.21.33.1 proto kernel scope host src 10.21.33.1')
            self.assertRegex(output, 'broadcast 10.21.33.255 proto kernel scope link src 10.21.33.1')
            self.assertRegex(output, 'local 10.21.44.1 proto kernel scope host src 10.21.44.1')
            self.assertRegex(output, 'local 10.21.55.1 proto kernel scope host src 10.21.55.1')
            self.assertRegex(output, 'broadcast 10.21.55.255 proto kernel scope link src 10.21.55.1')
            output = check_output('ip -6 route show dev test1')
            print('### ip -6 route show dev test1')
            print(output)
            self.assertRegex(output, 'fdde:12:22::1 proto kernel metric 256 pref medium')
            self.assertRegex(output, 'fdde:12:33::/64 proto kernel metric 256 pref medium')
            self.assertRegex(output, 'fe80::/64 proto kernel metric 256 pref medium')
            output = check_output('ip -6 route show table local dev test1')
            print('### ip -6 route show table local dev test1')
            print(output)
            self.assertRegex(output, 'local fdde:12:22::1 proto kernel metric 0 pref medium')
            self.assertRegex(output, 'local fdde:12:33::1 proto kernel metric 0 pref medium')
            self.assertRegex(output, 'local fdde:12:44::1 proto kernel metric 0 pref medium')
            self.assertRegex(output, 'local fdde:12:55::1 proto kernel metric 0 pref medium')
            self.assertRegex(output, 'ff00::/8 (proto kernel )?metric 256 (linkdown )?pref medium')

    def test_configure_without_carrier(self):
        copy_network_unit('11-dummy.netdev')
        start_networkd()
        self.wait_operstate('test1', 'off', '')
        check_output('ip link set dev test1 up carrier off')

        copy_network_unit('25-test1.network.d/configure-without-carrier.conf', copy_dropins=False)
        restart_networkd()
        self.wait_online('test1:no-carrier')

        carrier_map = {'on': '1', 'off': '0'}
        routable_map = {'on': 'routable', 'off': 'no-carrier'}
        for carrier in ['off', 'on', 'off']:
            with self.subTest(carrier=carrier):
                if carrier_map[carrier] != read_link_attr('test1', 'carrier'):
                    check_output(f'ip link set dev test1 carrier {carrier}')
                self.wait_online(f'test1:{routable_map[carrier]}:{routable_map[carrier]}')

                output = networkctl_status('test1')
                print(output)
                self.assertRegex(output, '192.168.0.15')
                self.assertRegex(output, '192.168.0.1')
                self.assertRegex(output, routable_map[carrier])

    def test_configure_without_carrier_yes_ignore_carrier_loss_no(self):
        copy_network_unit('11-dummy.netdev')
        start_networkd()
        self.wait_operstate('test1', 'off', '')
        check_output('ip link set dev test1 up carrier off')

        copy_network_unit('25-test1.network')
        restart_networkd()
        self.wait_online('test1:no-carrier')

        carrier_map = {'on': '1', 'off': '0'}
        routable_map = {'on': 'routable', 'off': 'no-carrier'}
        for (carrier, have_config) in [('off', True), ('on', True), ('off', False)]:
            with self.subTest(carrier=carrier, have_config=have_config):
                if carrier_map[carrier] != read_link_attr('test1', 'carrier'):
                    check_output(f'ip link set dev test1 carrier {carrier}')
                self.wait_online(f'test1:{routable_map[carrier]}:{routable_map[carrier]}')

                output = networkctl_status('test1')
                print(output)
                if have_config:
                    self.assertRegex(output, '192.168.0.15')
                    self.assertRegex(output, '192.168.0.1')
                else:
                    self.assertNotRegex(output, '192.168.0.15')
                    self.assertNotRegex(output, '192.168.0.1')
                self.assertRegex(output, routable_map[carrier])

    def check_routing_policy_rule_test1(self):
        print('### Checking routing policy rules requested by test1')

        output = check_output('ip rule list iif test1 priority 111')
        print(output)
        self.assertRegex(output, r'111:	from 192.168.100.18 tos (0x08|throughput) iif test1 oif test1 lookup 7')

        output = check_output('ip -6 rule list iif test1 priority 100')
        print(output)
        self.assertIn('100:	from all iif test1 lookup 8', output)

        output = check_output('ip rule list iif test1 priority 101')
        print(output)
        self.assertIn('101:	from all iif test1 lookup 9', output)

        output = check_output('ip -6 rule list iif test1 priority 101')
        print(output)
        self.assertIn('101:	from all iif test1 lookup 9', output)

        output = check_output('ip rule list iif test1 priority 102')
        print(output)
        self.assertIn('102:	from 0.0.0.0/8 iif test1 lookup 10', output)

        output = check_output('ip rule list iif test1 priority 103')
        print(output)
        self.assertIn('103:	from 10.0.0.0/16 iif test1 lookup 11 goto 111', output)

        output = check_output('ip rule list iif test1 priority 104')
        print(output)
        self.assertIn('104:	from 10.1.0.0/16 iif test1 lookup 12 nop', output)

        output = check_output('ip rule list to 192.0.2.0/26')
        print(output)
        self.assertIn('to 192.0.2.0/26 lookup 1001', output)

        output = check_output('ip rule list to 192.0.2.64/26')
        print(output)
        self.assertIn('to 192.0.2.64/26 lookup 1001', output)

        output = check_output('ip rule list to 192.0.2.128/26')
        print(output)
        self.assertIn('to 192.0.2.128/26 lookup 1001', output)

        output = check_output('ip rule list to 192.0.2.192/26')
        print(output)
        self.assertIn('to 192.0.2.192/26 lookup 1001', output)

    def check_routing_policy_rule_dummy98(self):
        print('### Checking routing policy rules requested by dummy98')

        output = check_output('ip rule list priority 112')
        print(output)
        self.assertRegex(output, r'112:	from 192.168.101.18 tos (0x08|throughput) iif dummy98 oif dummy98 lookup 8')

    def _test_routing_policy_rule(self, manage_foreign_routes):
        if not manage_foreign_routes:
            copy_networkd_conf_dropin('networkd-manage-foreign-rules-no.conf')
        copy_network_unit('25-routing-policy-rule-test1.network', '11-dummy.netdev')

        stop_networkd()

        check_output('ip -4 rule add priority 20001 table 9999 from 10.10.0.0/16')
        check_output('ip -6 rule add priority 20001 table 9999 from 2001:db8:0:1::/64')

        start_networkd()
        self.wait_online('test1:degraded')

        self.check_routing_policy_rule_test1()
        check_json(networkctl_json())

        output = check_output('ip -4 rule list priority 20001 table 9999 from 10.10.0.0/16')
        print(output)
        if manage_foreign_routes:
            self.assertEqual(output, '')
        else:
            self.assertIn(output, '20001:	from 10.10.0.0/16 lookup 9999')
            check_output('ip -4 rule del priority 20001 table 9999 from 10.10.0.0/16')

        output = check_output('ip -6 rule list priority 20001 table 9999 from 2001:db8:0:1::/64')
        print(output)
        if manage_foreign_routes:
            self.assertEqual(output, '')
        else:
            self.assertIn(output, '20001:	from 2001:db8:0:1::/64 lookup 9999')
            check_output('ip -6 rule del priority 20001 table 9999 from 2001:db8:0:1::/64')

    def test_routing_policy_rule(self):
        first = True
        for manage_foreign_routes in [True, False]:
            if first:
                first = False
            else:
                self.tearDown()

            print(f'### test_routing_policy_rule(manage_foreign_routes={manage_foreign_routes})')
            with self.subTest(manage_foreign_routes=manage_foreign_routes):
                self._test_routing_policy_rule(manage_foreign_routes)

    def test_routing_policy_rule_restart_and_reconfigure(self):
        copy_network_unit('25-routing-policy-rule-test1.network', '11-dummy.netdev',
                          '25-routing-policy-rule-dummy98.network', '12-dummy.netdev')

        # For #11280 and #34068.

        for trial in range(3):
            restart_networkd(show_logs=(trial > 0))
            self.wait_online('test1:degraded', 'dummy98:degraded')

            self.check_routing_policy_rule_test1()
            self.check_routing_policy_rule_dummy98()

            networkctl_reconfigure('test1')
            self.wait_online('test1:degraded')

            self.check_routing_policy_rule_test1()
            self.check_routing_policy_rule_dummy98()

            networkctl_reconfigure('dummy98')
            self.wait_online('dummy98:degraded')

            self.check_routing_policy_rule_test1()
            self.check_routing_policy_rule_dummy98()

    def test_routing_policy_rule_reconfigure(self):
        copy_network_unit('25-routing-policy-rule-reconfigure2.network', '11-dummy.netdev')
        start_networkd()
        self.wait_online('test1:degraded')

        output = check_output('ip rule list table 1011')
        print(output)
        self.assertIn('10111:	from all fwmark 0x3f3 lookup 1011', output)
        self.assertIn('10112:	from all oif test1 lookup 1011', output)
        self.assertIn('10113:	from all iif test1 lookup 1011', output)
        self.assertIn('10114:	from 192.168.8.254 lookup 1011', output)

        output = check_output('ip -6 rule list table 1011')
        print(output)
        self.assertIn('10112:	from all oif test1 lookup 1011', output)

        copy_network_unit('25-routing-policy-rule-reconfigure1.network', '11-dummy.netdev')
        networkctl_reload()
        self.wait_online('test1:degraded')

        output = check_output('ip rule list table 1011')
        print(output)
        self.assertIn('10111:	from all fwmark 0x3f3 lookup 1011', output)
        self.assertIn('10112:	from all oif test1 lookup 1011', output)
        self.assertIn('10113:	from all iif test1 lookup 1011', output)
        self.assertIn('10114:	from 192.168.8.254 lookup 1011', output)

        output = check_output('ip -6 rule list table 1011')
        print(output)
        self.assertNotIn('10112:	from all oif test1 lookup 1011', output)
        self.assertIn('10113:	from all iif test1 lookup 1011', output)

        call('ip rule delete priority 10111')
        call('ip rule delete priority 10112')
        call('ip rule delete priority 10113')
        call('ip rule delete priority 10114')
        call('ip -6 rule delete priority 10113')

        output = check_output('ip rule list table 1011')
        print(output)
        self.assertEqual(output, '')

        output = check_output('ip -6 rule list table 1011')
        print(output)
        self.assertEqual(output, '')

        networkctl_reconfigure('test1')
        self.wait_online('test1:degraded')

        output = check_output('ip rule list table 1011')
        print(output)
        self.assertIn('10111:	from all fwmark 0x3f3 lookup 1011', output)
        self.assertIn('10112:	from all oif test1 lookup 1011', output)
        self.assertIn('10113:	from all iif test1 lookup 1011', output)
        self.assertIn('10114:	from 192.168.8.254 lookup 1011', output)

        output = check_output('ip -6 rule list table 1011')
        print(output)
        self.assertIn('10113:	from all iif test1 lookup 1011', output)

    def test_routing_policy_rule_manual(self):
        # For issue #36244.
        copy_network_unit(
            '11-dummy.netdev',
            '25-routing-policy-rule-manual.network')
        start_networkd()
        self.wait_operstate('test1', operstate='off', setup_state='configuring', setup_timeout=20)

        check_output('ip link add test2 type dummy')
        self.wait_operstate('test2', operstate='off', setup_state='configuring', setup_timeout=20)

        networkctl('up', 'test2')
        self.wait_online('test2:degraded')

        # The request for the routing policy rules are bound to test1. Hence, we need to wait for the rules
        # being configured explicitly.
        for _ in range(20):
            time.sleep(0.5)

            output = check_output('ip -4 rule list table 51819')
            if output != '10:	from all lookup 51819 suppress_prefixlength 0 proto static':
                continue

            output = check_output('ip -6 rule list table 51819')
            if output != '10:	from all lookup 51819 suppress_prefixlength 0 proto static':
                continue

            output = check_output('ip -4 rule list table 51820')
            if output != '11:	not from all fwmark 0x38f lookup 51820 proto static':
                continue

            output = check_output('ip -6 rule list table 51820')
            if output != '11:	not from all fwmark 0x38f lookup 51820 proto static':
                continue

            break
        else:
            self.assertFalse(True)

    @expectedFailureIfRoutingPolicyPortRangeIsNotAvailable()
    def test_routing_policy_rule_port_range(self):
        copy_network_unit('25-fibrule-port-range.network', '11-dummy.netdev')
        start_networkd()
        self.wait_online('test1:degraded')

        output = check_output('ip rule')
        print(output)
        self.assertIn('111:', output)
        self.assertIn('from 192.168.100.18 ', output)
        self.assertIn('sport 1123-1150 ', output)
        self.assertIn('dport 3224-3290 ', output)
        self.assertRegex(output, 'ipproto (tcp|ipproto-6) ')
        self.assertIn('lookup 7 ', output)

    @expectedFailureIfRoutingPolicyIPProtoIsNotAvailable()
    def test_routing_policy_rule_invert(self):
        copy_network_unit('25-fibrule-invert.network', '11-dummy.netdev')
        start_networkd()
        self.wait_online('test1:degraded')

        output = check_output('ip rule')
        print(output)
        self.assertIn('111:', output)
        self.assertIn('not ', output)
        self.assertIn('from 192.168.100.18 ', output)
        self.assertRegex(output, 'ipproto (tcp|ipproto-6) ')
        self.assertIn('lookup 7 ', output)

    @expectedFailureIfRoutingPolicyL3MasterDeviceIsNotAvailable()
    def test_routing_policy_rule_l3mdev(self):
        copy_network_unit('25-fibrule-l3mdev.network', '11-dummy.netdev')
        start_networkd()
        self.wait_online('test1:degraded')

        output = check_output('ip rule')
        print(output)
        self.assertIn('1500:	from all lookup [l3mdev-table]', output)
        self.assertIn('2000:	from all lookup [l3mdev-table] unreachable', output)

    @expectedFailureIfRoutingPolicyUIDRangeIsNotAvailable()
    def test_routing_policy_rule_uidrange(self):
        copy_network_unit('25-fibrule-uidrange.network', '11-dummy.netdev')
        start_networkd()
        self.wait_online('test1:degraded')

        output = check_output('ip rule')
        print(output)
        self.assertIn('111:', output)
        self.assertIn('from 192.168.100.18 ', output)
        self.assertIn('lookup 7 ', output)
        self.assertIn('uidrange 100-200 ', output)

    def _check_route_static(self, test1_is_managed: bool):
        output = networkctl_status('dummy98')
        print(output)
        output = networkctl_status('test1')
        print(output)

        print('### ip -6 route show dev dummy98')
        output = check_output('ip -6 route show dev dummy98')
        print(output)
        self.assertIn('2001:1234:5:8fff:ff:ff:ff:ff proto static', output)
        self.assertIn('2001:1234:5:8f63::1 proto kernel', output)
        self.assertIn('2001:1234:5:afff:ff:ff:ff:ff via fe80:0:222:4dff:ff:ff:ff:ff proto static', output)

        print('### ip -6 route show default')
        output = check_output('ip -6 route show default')
        print(output)
        self.assertIn('default', output)
        self.assertIn('via 2001:1234:5:8fff:ff:ff:ff:ff', output)

        print('### ip -4 route show dev dummy98')
        output = check_output('ip -4 route show dev dummy98')
        print(output)
        self.assertIn('149.10.124.48/28 proto kernel scope link src 149.10.124.58', output)
        self.assertIn('149.10.124.64 proto static scope link', output)
        self.assertIn('169.254.0.0/16 proto static scope link metric 2048', output)
        self.assertIn('192.168.1.1 proto static scope link initcwnd 20', output)
        self.assertIn('192.168.1.2 proto static scope link initrwnd 30', output)
        self.assertIn('192.168.1.3 proto static scope link advmss 30', output)
        self.assertIn('192.168.1.4 proto static scope link hoplimit 122', output)
        self.assertIn('multicast 149.10.123.4 proto static', output)

        print('### ip -4 route show dev dummy98 default')
        output = check_output('ip -4 route show dev dummy98 default')
        print(output)
        self.assertIn('default via 149.10.125.65 proto static onlink', output)
        self.assertIn('default via 149.10.124.64 proto static', output)
        self.assertIn('default proto static', output)
        self.assertIn('default via 1.1.8.104 proto static', output)

        print('### ip -4 route show table local dev dummy98')
        output = check_output('ip -4 route show table local dev dummy98')
        print(output)
        self.assertIn('local 149.10.123.1 proto static scope host', output)
        self.assertIn('anycast 149.10.123.2 proto static scope link', output)
        self.assertIn('broadcast 149.10.123.3 proto static scope link', output)

        print('### ip -4 route show type blackhole')
        output = check_output('ip -4 route show type blackhole')
        print(output)
        self.assertIn('blackhole 202.54.1.2 proto static', output)

        print('### ip -4 route show type unreachable')
        output = check_output('ip -4 route show type unreachable')
        print(output)
        self.assertIn('unreachable 202.54.1.3 proto static', output)

        print('### ip -4 route show type prohibit')
        output = check_output('ip -4 route show type prohibit')
        print(output)
        self.assertIn('prohibit 202.54.1.4 proto static', output)

        print('### ip -6 route show type blackhole')
        output = check_output('ip -6 route show type blackhole')
        print(output)
        self.assertIn('blackhole 2001:1234:5678::2 dev lo proto static', output)

        print('### ip -6 route show type unreachable')
        output = check_output('ip -6 route show type unreachable')
        print(output)
        self.assertIn('unreachable 2001:1234:5678::3 dev lo proto static', output)

        print('### ip -6 route show type prohibit')
        output = check_output('ip -6 route show type prohibit')
        print(output)
        self.assertIn('prohibit 2001:1234:5678::4 dev lo proto static', output)

        print('### ip route show 192.168.10.1')
        output = check_output('ip route show 192.168.10.1')
        print(output)
        self.assertIn('192.168.10.1 proto static', output)
        self.assertIn('nexthop via 149.10.123.59 dev test1 weight 20', output)
        self.assertIn('nexthop via 149.10.123.60 dev test1 weight 30', output)
        self.assertIn('nexthop via 149.10.124.59 dev dummy98 weight 10', output)
        self.assertIn('nexthop via 149.10.124.60 dev dummy98 weight 5', output)

        print('### ip route show 192.168.10.2')
        output = check_output('ip route show 192.168.10.2')
        print(output)
        # old ip command does not show IPv6 gateways...
        self.assertIn('192.168.10.2 proto static', output)
        self.assertIn('nexthop', output)
        self.assertIn('dev test1 weight 20', output)
        self.assertIn('dev test1 weight 30', output)
        self.assertIn('dev dummy98 weight 10', output)
        self.assertIn('dev dummy98 weight 5', output)

        print('### ip -6 route show 2001:1234:5:bfff:ff:ff:ff:ff')
        output = check_output('ip -6 route show 2001:1234:5:bfff:ff:ff:ff:ff')
        print(output)
        # old ip command does not show 'nexthop' keyword and weight...
        self.assertIn('2001:1234:5:bfff:ff:ff:ff:ff', output)
        if test1_is_managed:
            self.assertIn('via 2001:1234:5:6fff:ff:ff:ff:ff dev test1', output)
            self.assertIn('via 2001:1234:5:7fff:ff:ff:ff:ff dev test1', output)
        self.assertIn('via 2001:1234:5:8fff:ff:ff:ff:ff dev dummy98', output)
        self.assertIn('via 2001:1234:5:9fff:ff:ff:ff:ff dev dummy98', output)

        check_json(networkctl_json())

    def _check_unreachable_routes_removed(self):
        print('### ip -4 route show type blackhole')
        output = check_output('ip -4 route show type blackhole')
        print(output)
        self.assertEqual(output, '')

        print('### ip -4 route show type unreachable')
        output = check_output('ip -4 route show type unreachable')
        print(output)
        self.assertEqual(output, '')

        print('### ip -4 route show type prohibit')
        output = check_output('ip -4 route show type prohibit')
        print(output)
        self.assertEqual(output, '')

        print('### ip -6 route show type blackhole')
        output = check_output('ip -6 route show type blackhole')
        print(output)
        self.assertEqual(output, '')

        print('### ip -6 route show type unreachable')
        output = check_output('ip -6 route show type unreachable')
        print(output)
        self.assertEqual(output, '')

        print('### ip -6 route show type prohibit')
        output = check_output('ip -6 route show type prohibit')
        print(output)
        self.assertEqual(output, '')

        check_json(networkctl_json())

    def _test_route_static(self, manage_foreign_routes):
        if not manage_foreign_routes:
            copy_networkd_conf_dropin('networkd-manage-foreign-routes-no.conf')

        copy_network_unit('25-route-static.network', '12-dummy.netdev',
                          '25-route-static-test1.network', '11-dummy.netdev')
        start_networkd()
        self.wait_online('dummy98:routable', 'test1:routable')
        self._check_route_static(test1_is_managed=True)

        # unmanaging test1
        remove_network_unit('25-route-static-test1.network')
        networkctl_reload()
        self.wait_online('dummy98:routable')
        self.wait_operstate('test1', setup_state='unmanaged')
        self._check_route_static(test1_is_managed=False)

        # managing test1 again
        copy_network_unit('25-route-static-test1.network')
        networkctl_reload()
        self.wait_online('dummy98:routable', 'test1:routable')
        self._check_route_static(test1_is_managed=True)

        # adding an unmanaged interface
        check_output('ip link add test2 type dummy')
        self.wait_operstate('test2', operstate='off', setup_state='unmanaged')
        self._check_route_static(test1_is_managed=True)

        # reconfiguring with another config, and check all routes managed by Manager are removed
        copy_network_unit('25-address-static.network', copy_dropins=False)
        networkctl_reload()
        self.wait_online('dummy98:routable')
        self._check_unreachable_routes_removed()

        # reconfiguring the original config again
        remove_network_unit('25-address-static.network')
        networkctl_reload()
        self.wait_online('dummy98:routable')
        self._check_route_static(test1_is_managed=True)

        # removing interface, and check all routes managed by Manager are removed
        remove_link('dummy98')
        time.sleep(2)
        self._check_unreachable_routes_removed()

    def test_route_static(self):
        first = True
        for manage_foreign_routes in [True, False]:
            if first:
                first = False
            else:
                self.tearDown()

            print(f'### test_route_static(manage_foreign_routes={manage_foreign_routes})')
            with self.subTest(manage_foreign_routes=manage_foreign_routes):
                self._test_route_static(manage_foreign_routes)

    def test_route_static_issue_35047(self):
        copy_network_unit(
            '25-route-static-issue-35047.network',
            '25-route-static-issue-35047.network.d/step1.conf',
            '12-dummy.netdev',
            copy_dropins=False)
        start_networkd()
        self.wait_online('dummy98:routable')

        print('### ip -4 route show table all dev dummy98')
        output = check_output('ip -4 route show table all dev dummy98')
        print(output)
        self.assertIn('192.0.2.2 proto kernel scope link src 192.0.2.1', output)
        self.assertIn('local 192.0.2.1 table local proto kernel scope host src 192.0.2.1', output)
        self.assertIn('198.51.100.0/24 via 192.0.2.2 proto static', output)

        check_output('ip link set dev dummy98 down')
        self.wait_route_dropped('dummy98', '192.0.2.2 proto kernel scope link src 192.0.2.1', ipv='-4', table='all', timeout_sec=10)
        self.wait_route_dropped('dummy98', 'local 192.0.2.1 table local proto kernel scope host src 192.0.2.1', ipv='-4', table='all', timeout_sec=10)
        self.wait_route_dropped('dummy98', '198.51.100.0/24 via 192.0.2.2 proto static', ipv='-4', table='all', timeout_sec=10)

        print('### ip -4 route show table all dev dummy98')
        output = check_output('ip -4 route show table all dev dummy98')
        print(output)
        self.assertNotIn('192.0.2.2', output)
        self.assertNotIn('192.0.2.1', output)
        self.assertNotIn('198.51.100.0/24', output)

        remove_network_unit('25-route-static-issue-35047.network.d/step1.conf')
        copy_network_unit('25-route-static-issue-35047.network.d/step2.conf')
        networkctl_reload()
        self.wait_online('dummy98:routable')

        print('### ip -4 route show table all dev dummy98')
        output = check_output('ip -4 route show table all dev dummy98')
        print(output)
        self.assertIn('192.0.2.2 proto static scope link', output)
        self.assertIn('local 192.0.2.1 table local proto kernel scope host src 192.0.2.1', output)
        self.assertIn('198.51.100.0/24 via 192.0.2.2 proto static', output)

    @expectedFailureIfRTA_VIAIsNotSupported()
    def test_route_via_ipv6(self):
        copy_network_unit('25-route-via-ipv6.network', '12-dummy.netdev')
        start_networkd()
        self.wait_online('dummy98:routable')

        output = networkctl_status('dummy98')
        print(output)

        print('### ip -6 route show dev dummy98')
        output = check_output('ip -6 route show dev dummy98')
        print(output)
        self.assertRegex(output, '2001:1234:5:8fff:ff:ff:ff:ff proto static')
        self.assertRegex(output, '2001:1234:5:8f63::1 proto kernel')

        print('### ip -4 route show dev dummy98')
        output = check_output('ip -4 route show dev dummy98')
        print(output)
        self.assertRegex(output, '149.10.124.48/28 proto kernel scope link src 149.10.124.58')
        self.assertRegex(output, '149.10.124.66 via inet6 2001:1234:5:8fff:ff:ff:ff:ff proto static')

    @expectedFailureIfModuleIsNotAvailable('tcp_dctcp')
    def test_route_congctl(self):
        copy_network_unit('25-route-congctl.network', '12-dummy.netdev')
        start_networkd()
        self.wait_online('dummy98:routable')

        print('### ip -6 route show dev dummy98 2001:1234:5:8fff:ff:ff:ff:ff')
        output = check_output('ip -6 route show dev dummy98 2001:1234:5:8fff:ff:ff:ff:ff')
        print(output)
        self.assertIn('2001:1234:5:8fff:ff:ff:ff:ff proto static', output)
        self.assertIn('congctl dctcp', output)

        print('### ip -4 route show dev dummy98 149.10.124.66')
        output = check_output('ip -4 route show dev dummy98 149.10.124.66')
        print(output)
        self.assertIn('149.10.124.66 proto static', output)
        self.assertIn('congctl dctcp', output)
        self.assertIn('rto_min 300s', output)

    @expectedFailureIfModuleIsNotAvailable('vrf')
    def test_route_vrf(self):
        copy_network_unit('25-route-vrf.network', '12-dummy.netdev',
                          '25-vrf.netdev', '25-vrf.network')
        start_networkd()
        self.wait_online('dummy98:routable', 'vrf99:carrier')

        output = check_output('ip route show vrf vrf99')
        print(output)
        self.assertRegex(output, 'default via 192.168.100.1')

        output = check_output('ip route show')
        print(output)
        self.assertNotRegex(output, 'default via 192.168.100.1')

    def test_gateway_reconfigure(self):
        copy_network_unit('25-gateway-static.network', '12-dummy.netdev')
        start_networkd()
        self.wait_online('dummy98:routable')
        print('### ip -4 route show dev dummy98 default')
        output = check_output('ip -4 route show dev dummy98 default')
        print(output)
        self.assertIn('default via 149.10.124.59 proto static', output)
        self.assertNotIn('149.10.124.60', output)

        remove_network_unit('25-gateway-static.network')
        copy_network_unit('25-gateway-next-static.network')
        networkctl_reload()
        self.wait_online('dummy98:routable')
        print('### ip -4 route show dev dummy98 default')
        output = check_output('ip -4 route show dev dummy98 default')
        print(output)
        self.assertNotIn('149.10.124.59', output)
        self.assertIn('default via 149.10.124.60 proto static', output)

    def test_ip_route_ipv6_src_route(self):
        # a dummy device does not make the addresses go through tentative state, so we
        # reuse a bond from an earlier test, which does make the addresses go through
        # tentative state, and do our test on that
        copy_network_unit('23-active-slave.network', '25-route-ipv6-src.network', '25-bond-active-backup-slave.netdev', '12-dummy.netdev')
        start_networkd()
        self.wait_online('dummy98:enslaved', 'bond199:routable')

        output = check_output('ip -6 route list dev bond199')
        print(output)
        self.assertIn('abcd::/16 via 2001:1234:56:8f63::1:1 proto static src 2001:1234:56:8f63::2', output)

    def test_route_preferred_source_with_existing_address(self):
        # See issue #28009.
        copy_network_unit('25-route-preferred-source.network', '12-dummy.netdev')
        start_networkd()

        for i in range(3):
            if i != 0:
                networkctl_reconfigure('dummy98')

            self.wait_online('dummy98:routable')

            output = check_output('ip -6 route list dev dummy98')
            print(output)
            self.assertIn('abcd::/16 via 2001:1234:56:8f63::1:1 proto static src 2001:1234:56:8f63::1', output)

            output = check_output('ip -4 route list dev dummy98')
            print(output)
            self.assertIn('10.123.0.0/16 via 192.168.30.1 proto static src 10.10.10.1', output)

    def test_ip_link_mac_address(self):
        copy_network_unit('25-address-link-section.network', '12-dummy.netdev')
        start_networkd()
        self.wait_online('dummy98:degraded')

        output = check_output('ip link show dummy98')
        print(output)
        self.assertRegex(output, '00:01:02:aa:bb:cc')

    def test_ip_link_unmanaged(self):
        copy_network_unit('25-link-section-unmanaged.network', '12-dummy.netdev')
        start_networkd()

        self.wait_operstate('dummy98', 'off', setup_state='unmanaged')

    def test_ipv6_address_label(self):
        copy_network_unit('25-ipv6-address-label-section.network', '12-dummy.netdev')
        copy_networkd_conf_dropin('networkd-address-label.conf')
        start_networkd()
        self.wait_online('dummy98:degraded')

        output = check_output('ip addrlabel list')
        print(output)
        self.assertRegex(output, '2004:da8:1::/64 dev dummy98 label 4444')
        self.assertRegex(output, '2004:da8:2::/64 label 5555')

    def test_ipv6_proxy_ndp(self):
        copy_network_unit('25-ipv6-proxy-ndp.network', '12-dummy.netdev')
        start_networkd()

        self.wait_online('dummy98:routable')

        output = check_output('ip neighbor show proxy dev dummy98')
        print(output)
        for i in range(1, 5):
            self.assertRegex(output, f'2607:5300:203:5215:{i}::1 *proxy')

    def test_ipv6_neigh_retrans_time(self):
        link='test25'
        copy_network_unit('25-dummy.netdev', '25-dummy.network')
        start_networkd()

        self.wait_online(f'{link}:degraded')
        remove_network_unit('25-dummy.network')

        # expect retrans_time_ms updated
        copy_network_unit('25-ipv6-neigh-retrans-time-3s.network')
        networkctl_reload()
        self.wait_online(f'{link}:degraded')
        self.check_ipv6_neigh_sysctl_attr(link, 'retrans_time_ms', '3000')
        remove_network_unit('25-ipv6-neigh-retrans-time-3s.network')

        # expect retrans_time_ms unchanged
        copy_network_unit('25-ipv6-neigh-retrans-time-0s.network')
        networkctl_reload()
        self.wait_online(f'{link}:degraded')
        self.check_ipv6_neigh_sysctl_attr(link, 'retrans_time_ms', '3000')
        remove_network_unit('25-ipv6-neigh-retrans-time-0s.network')

        # expect retrans_time_ms unchanged
        copy_network_unit('25-ipv6-neigh-retrans-time-toobig.network')
        networkctl_reload()
        self.wait_online(f'{link}:degraded')
        self.check_ipv6_neigh_sysctl_attr(link, 'retrans_time_ms', '3000')
        remove_network_unit('25-ipv6-neigh-retrans-time-toobig.network')

        # expect retrans_time_ms unchanged
        copy_network_unit('25-ipv6-neigh-retrans-time-infinity.network')
        networkctl_reload()
        self.wait_online(f'{link}:degraded')
        self.check_ipv6_neigh_sysctl_attr(link, 'retrans_time_ms', '3000')
        remove_network_unit('25-ipv6-neigh-retrans-time-infinity.network')

        # expect retrans_time_ms unchanged
        copy_network_unit('25-ipv6-neigh-retrans-time-invalid.network')
        networkctl_reload()
        self.wait_online(f'{link}:degraded')
        self.check_ipv6_neigh_sysctl_attr(link, 'retrans_time_ms', '3000')
        remove_network_unit('25-ipv6-neigh-retrans-time-invalid.network')

        # expect retrans_time_ms updated
        copy_network_unit('25-ipv6-neigh-retrans-time-4s.network')
        networkctl_reload()
        self.wait_online(f'{link}:degraded')
        self.check_ipv6_neigh_sysctl_attr(link, 'retrans_time_ms', '4000')
        remove_network_unit('25-ipv6-neigh-retrans-time-4s.network')

    def test_neighbor(self):
        copy_network_unit('12-dummy.netdev', '25-neighbor-dummy.network', '25-neighbor-dummy.network.d/10-step1.conf',
                          '25-gre-tunnel-remote-any.netdev', '25-neighbor-ip.network',
                          '25-ip6gre-tunnel-remote-any.netdev', '25-neighbor-ipv6.network',
                          copy_dropins=False)
        start_networkd()
        self.wait_online('dummy98:degraded', 'gretun97:routable', 'ip6gretun97:routable')

        print('### ip neigh list dev gretun97')
        output = check_output('ip neigh list dev gretun97')
        print(output)
        self.assertIn('10.0.0.22 lladdr 10.65.223.239 PERMANENT', output)
        self.assertNotIn('10.0.0.23', output)

        print('### ip neigh list dev ip6gretun97')
        output = check_output('ip neigh list dev ip6gretun97')
        print(output)
        self.assertRegex(output, '2001:db8:0:f102::17 lladdr 2a:?00:ff:?de:45:?67:ed:?de:[0:]*:49:?88 PERMANENT')
        self.assertNotIn('2001:db8:0:f102::18', output)

        print('### ip neigh list dev dummy98')
        output = check_output('ip neigh list dev dummy98')
        print(output)
        self.assertIn('192.168.10.1 lladdr 00:00:5e:00:02:65 PERMANENT', output)
        self.assertIn('2004:da8:1::1 lladdr 00:00:5e:00:02:66 PERMANENT', output)
        self.assertNotIn('2004:da8:1:0::2', output)
        self.assertNotIn('192.168.10.2', output)
        self.assertNotIn('00:00:5e:00:02:67', output)

        check_json(networkctl_json())

        # Here, 10-step1.conf is intendedly kept, to verify that 10-step2.conf overrides
        # the valid configurations in 10-step1.conf.
        copy_network_unit('25-neighbor-dummy.network.d/10-step2.conf')
        networkctl_reload()
        self.wait_online('dummy98:degraded')

        print('### ip neigh list dev dummy98')
        output = check_output('ip neigh list dev dummy98')
        print(output)
        self.assertIn('192.168.10.1 lladdr 00:00:5e:00:03:65 PERMANENT', output)
        self.assertIn('2004:da8:1::1 lladdr 00:00:5e:00:03:66 PERMANENT', output)
        self.assertNotIn('2004:da8:1:0::2', output)
        self.assertNotIn('192.168.10.2', output)
        self.assertNotIn('00:00:5e:00:02:67', output)

        check_json(networkctl_json())

        remove_network_unit('25-neighbor-dummy.network.d/10-step1.conf',
                            '25-neighbor-dummy.network.d/10-step2.conf')
        copy_network_unit('25-neighbor-dummy.network.d/10-step3.conf')
        networkctl_reload()
        self.wait_online('dummy98:degraded')

        print('### ip neigh list dev dummy98')
        output = check_output('ip neigh list dev dummy98')
        print(output)
        self.assertIn('192.168.10.1 lladdr 00:00:5e:00:03:66 PERMANENT', output)
        self.assertNotIn('00:00:5e:00:02:65', output)
        self.assertNotIn('00:00:5e:00:02:66', output)
        self.assertNotIn('00:00:5e:00:03:65', output)
        self.assertNotIn('2004:da8:1::1', output)

    def test_link_local_addressing(self):
        copy_network_unit('25-link-local-addressing-yes.network', '11-dummy.netdev',
                          '25-link-local-addressing-no.network', '12-dummy.netdev')
        start_networkd()
        self.wait_online('test1:degraded', 'dummy98:carrier')

        output = check_output('ip address show dev test1')
        print(output)
        self.assertRegex(output, 'inet .* scope link')
        self.assertRegex(output, 'inet6 .* scope link')

        output = check_output('ip address show dev dummy98')
        print(output)
        self.assertNotRegex(output, 'inet6* .* scope link')

        # Documentation/networking/ip-sysctl.txt
        #
        # addr_gen_mode - INTEGER
        # Defines how link-local and autoconf addresses are generated.
        #
        # 0: generate address based on EUI64 (default)
        # 1: do no generate a link-local address, use EUI64 for addresses generated
        #    from autoconf
        # 2: generate stable privacy addresses, using the secret from
        #    stable_secret (RFC7217)
        # 3: generate stable privacy addresses, using a random secret if unset

        self.check_ipv6_sysctl_attr('test1', 'stable_secret', '0123:4567:89ab:cdef:0123:4567:89ab:cdef')
        self.check_ipv6_sysctl_attr('test1', 'addr_gen_mode', '2')
        self.check_ipv6_sysctl_attr('dummy98', 'addr_gen_mode', '1')

    def test_link_local_addressing_ipv6ll(self):
        copy_network_unit('26-link-local-addressing-ipv6.network', '12-dummy.netdev')
        start_networkd()
        self.wait_online('dummy98:degraded')

        # An IPv6LL address exists by default.
        output = check_output('ip address show dev dummy98')
        print(output)
        self.assertRegex(output, 'inet6 .* scope link')

        copy_network_unit('25-link-local-addressing-no.network')
        networkctl_reload()
        self.wait_online('dummy98:carrier')

        # Check if the IPv6LL address is removed.
        output = check_output('ip address show dev dummy98')
        print(output)
        self.assertNotRegex(output, 'inet6 .* scope link')

        remove_network_unit('25-link-local-addressing-no.network')
        networkctl_reload()
        self.wait_online('dummy98:degraded')

        # Check if a new IPv6LL address is assigned.
        output = check_output('ip address show dev dummy98')
        print(output)
        self.assertRegex(output, 'inet6 .* scope link')

    def test_sysctl(self):
        copy_networkd_conf_dropin('25-global-ipv6-privacy-extensions.conf')
        copy_network_unit('25-sysctl.network', '12-dummy.netdev', copy_dropins=False)
        start_networkd()
        self.wait_online('dummy98:degraded')

        self.check_ipv6_sysctl_attr('dummy98', 'forwarding', '1')
        self.check_ipv6_sysctl_attr('dummy98', 'use_tempaddr', '1')
        self.check_ipv6_sysctl_attr('dummy98', 'dad_transmits', '3')
        self.check_ipv6_sysctl_attr('dummy98', 'hop_limit', '5')
        self.check_ipv6_sysctl_attr('dummy98', 'proxy_ndp', '1')
        self.check_ipv4_sysctl_attr('dummy98', 'forwarding', '1')
        self.check_ipv4_sysctl_attr('dummy98', 'proxy_arp', '1')
        self.check_ipv4_sysctl_attr('dummy98', 'proxy_arp_pvlan', '1')
        self.check_ipv4_sysctl_attr('dummy98', 'accept_local', '1')
        self.check_ipv4_sysctl_attr('dummy98', 'rp_filter', '0')
        self.check_ipv4_sysctl_attr('dummy98', 'force_igmp_version', '1')

        copy_network_unit('25-sysctl.network.d/25-ipv6-privacy-extensions.conf')
        networkctl_reload()
        self.wait_online('dummy98:degraded')

        self.check_ipv6_sysctl_attr('dummy98', 'use_tempaddr', '2')

    def test_sysctl_disable_ipv6(self):
        copy_network_unit('25-sysctl-disable-ipv6.network', '12-dummy.netdev')

        print('## Disable ipv6')
        check_output('sysctl net.ipv6.conf.all.disable_ipv6=1')
        check_output('sysctl net.ipv6.conf.default.disable_ipv6=1')

        start_networkd()
        self.wait_online('dummy98:routable')

        output = check_output('ip -4 address show dummy98')
        print(output)
        self.assertRegex(output, 'inet 10.2.3.4/16 brd 10.2.255.255 scope global dummy98')
        output = check_output('ip -6 address show dummy98')
        print(output)
        self.assertRegex(output, 'inet6 2607:5300:203:3906::/64 scope global')
        self.assertRegex(output, 'inet6 .* scope link')
        output = check_output('ip -4 route show dev dummy98')
        print(output)
        self.assertRegex(output, '10.2.0.0/16 proto kernel scope link src 10.2.3.4')
        output = check_output('ip -6 route show default')
        print(output)
        self.assertRegex(output, 'default')
        self.assertRegex(output, 'via 2607:5300:203:39ff:ff:ff:ff:ff')

        remove_link('dummy98')

        print('## Enable ipv6')
        check_output('sysctl net.ipv6.conf.all.disable_ipv6=0')
        check_output('sysctl net.ipv6.conf.default.disable_ipv6=0')

        restart_networkd()
        self.wait_online('dummy98:routable')

        output = check_output('ip -4 address show dummy98')
        print(output)
        self.assertRegex(output, 'inet 10.2.3.4/16 brd 10.2.255.255 scope global dummy98')
        output = check_output('ip -6 address show dummy98')
        print(output)
        self.assertRegex(output, 'inet6 2607:5300:203:3906::/64 scope global')
        self.assertRegex(output, 'inet6 .* scope link')
        output = check_output('ip -4 route show dev dummy98')
        print(output)
        self.assertRegex(output, '10.2.0.0/16 proto kernel scope link src 10.2.3.4')
        output = check_output('ip -6 route show default')
        print(output)
        self.assertRegex(output, 'via 2607:5300:203:39ff:ff:ff:ff:ff')

    @expectedFailureIfModuleIsNotAvailable('mpls_router')
    def test_sysctl_mpls(self):
        check_output('modprobe mpls_router')
        copy_network_unit('25-sysctl-mpls.network', '12-dummy.netdev')
        start_networkd()
        self.wait_online('dummy98:degraded')

        self.check_mpls_sysctl_attr('dummy98', 'input', '1')

    def test_bind_carrier(self):
        copy_network_unit('25-bind-carrier.network', '11-dummy.netdev')
        start_networkd()

        # no bound interface.
        self.wait_operstate('test1', 'off', setup_state='configuring')
        output = check_output('ip address show test1')
        print(output)
        self.assertNotIn('UP,LOWER_UP', output)
        self.assertIn('DOWN', output)
        self.assertNotIn('192.168.10', output)

        # add one bound interface. The interface will be up.
        check_output('ip link add dummy98 type dummy')
        check_output('ip link set dummy98 up')
        self.wait_online('test1:routable')
        output = check_output('ip address show test1')
        print(output)
        self.assertIn('UP,LOWER_UP', output)
        self.assertIn('inet 192.168.10.30/24 brd 192.168.10.255 scope global test1', output)

        # add another bound interface. The interface is still up.
        check_output('ip link add dummy99 type dummy')
        check_output('ip link set dummy99 up')
        self.wait_operstate('dummy99', 'degraded', setup_state='unmanaged')
        output = check_output('ip address show test1')
        print(output)
        self.assertIn('UP,LOWER_UP', output)
        self.assertIn('inet 192.168.10.30/24 brd 192.168.10.255 scope global test1', output)

        # remove one of the bound interfaces. The interface is still up
        remove_link('dummy98')
        output = check_output('ip address show test1')
        print(output)
        self.assertIn('UP,LOWER_UP', output)
        self.assertIn('inet 192.168.10.30/24 brd 192.168.10.255 scope global test1', output)

        # bring down the remaining bound interface. The interface will be down.
        check_output('ip link set dummy99 down')
        self.wait_operstate('test1', 'off')
        self.wait_address_dropped('test1', r'192.168.10', ipv='-4', timeout_sec=10)
        output = check_output('ip address show test1')
        print(output)
        self.assertNotIn('UP,LOWER_UP', output)
        self.assertIn('DOWN', output)
        self.assertNotIn('192.168.10', output)

        # bring up the bound interface. The interface will be up.
        check_output('ip link set dummy99 up')
        self.wait_online('test1:routable')
        output = check_output('ip address show test1')
        print(output)
        self.assertIn('UP,LOWER_UP', output)
        self.assertIn('inet 192.168.10.30/24 brd 192.168.10.255 scope global test1', output)

        # remove the remaining bound interface. The interface will be down.
        remove_link('dummy99')
        self.wait_operstate('test1', 'off')
        self.wait_address_dropped('test1', r'192.168.10', ipv='-4', timeout_sec=10)
        output = check_output('ip address show test1')
        print(output)
        self.assertNotIn('UP,LOWER_UP', output)
        self.assertIn('DOWN', output)
        self.assertNotIn('192.168.10', output)

        # re-add one bound interface. The interface will be up.
        check_output('ip link add dummy98 type dummy')
        check_output('ip link set dummy98 up')
        self.wait_online('test1:routable')
        output = check_output('ip address show test1')
        print(output)
        self.assertIn('UP,LOWER_UP', output)
        self.assertIn('inet 192.168.10.30/24 brd 192.168.10.255 scope global test1', output)

    def _test_activation_policy(self, interface, test):
        conffile = '25-activation-policy.network'
        if test:
            conffile = f'{conffile}.d/{test}.conf'
        if interface == 'vlan99':
            copy_network_unit('21-vlan.netdev', '21-vlan-test1.network')
        copy_network_unit('11-dummy.netdev', conffile, copy_dropins=False)
        start_networkd()

        always = test.startswith('always')
        initial_up = test != 'manual' and not test.endswith('down') # note: default is up
        expect_up = initial_up
        next_up = not expect_up

        if test.endswith('down'):
            self.wait_activated(interface)

        for iteration in range(4):
            with self.subTest(iteration=iteration, expect_up=expect_up):
                operstate = 'routable' if expect_up else 'off'
                setup_state = 'configured' if expect_up else ('configuring' if iteration == 0 else None)
                self.wait_operstate(interface, operstate, setup_state=setup_state, setup_timeout=20)

                if expect_up:
                    self.assertIn('UP', check_output(f'ip link show {interface}'))
                    self.assertIn('192.168.10.30/24', check_output(f'ip address show {interface}'))
                    self.assertIn('default via 192.168.10.1', check_output(f'ip route show dev {interface}'))
                else:
                    self.assertIn('DOWN', check_output(f'ip link show {interface}'))

            if next_up:
                check_output(f'ip link set dev {interface} up')
            else:
                check_output(f'ip link set dev {interface} down')
            expect_up = initial_up if always else next_up
            next_up = not next_up
            if always:
                time.sleep(1)

    def test_activation_policy(self):
        first = True
        for interface in ['test1', 'vlan99']:
            for test in ['up', 'always-up', 'manual', 'always-down', 'down', '']:
                if first:
                    first = False
                else:
                    self.tearDown()

                print(f'### test_activation_policy(interface={interface}, test={test})')
                with self.subTest(interface=interface, test=test):
                    self._test_activation_policy(interface, test)

    def _test_activation_policy_required_for_online(self, policy, required):
        conffile = '25-activation-policy.network'
        units = ['11-dummy.netdev', '12-dummy.netdev', '12-dummy.network', conffile]
        if policy:
            units += [f'{conffile}.d/{policy}.conf']
        if required:
            units += [f'{conffile}.d/required-{required}.conf']
        copy_network_unit(*units, copy_dropins=False)
        start_networkd()

        if policy.endswith('down'):
            self.wait_activated('test1')

        if policy.endswith('down') or policy == 'manual':
            self.wait_operstate('test1', 'off', setup_state='configuring')
        else:
            self.wait_online('test1')

        if policy == 'always-down':
            # if always-down, required for online is forced to no
            expected = False
        elif required:
            # otherwise if required for online is specified, it should match that
            expected = required == 'yes'
        elif policy:
            # otherwise if only policy specified, required for online defaults to
            # true if policy is up, always-up, or bound
            expected = policy.endswith('up') or policy == 'bound'
        else:
            # default is true, if neither are specified
            expected = True

        output = networkctl_status('test1')
        print(output)

        yesno = 'yes' if expected else 'no'
        self.assertRegex(output, f'Required For Online: {yesno}')

    def test_activation_policy_required_for_online(self):
        first = True
        for policy in ['up', 'always-up', 'manual', 'always-down', 'down', 'bound', '']:
            for required in ['yes', 'no', '']:
                if first:
                    first = False
                else:
                    self.tearDown()

                print(f'### test_activation_policy_required_for_online(policy={policy}, required={required})')
                with self.subTest(policy=policy, required=required):
                    self._test_activation_policy_required_for_online(policy, required)

    def test_domain(self):
        copy_network_unit('12-dummy.netdev', '24-search-domain.network')
        start_networkd()
        self.wait_online('dummy98:routable')

        output = networkctl_status('dummy98')
        print(output)
        self.assertRegex(output, 'Address: 192.168.42.100')
        self.assertRegex(output, 'DNS: 192.168.42.1')
        self.assertRegex(output, 'Search Domains: one')

    def test_keep_configuration_yes(self):
        check_output('ip link add dummy98 type dummy')
        check_output('ip link set dev dummy98 up')
        check_output('ip address add 198.51.100.1/24 brd 198.51.100.255 dev dummy98')
        check_output('ip route add 203.0.113.0/24 via 198.51.100.10 dev dummy98 proto boot')

        copy_network_unit('24-keep-configuration-yes.network')
        start_networkd()
        self.wait_online('dummy98:routable')

        output = check_output('ip address show dummy98')
        print(output)
        self.assertIn('inet 198.51.100.1/24 brd 198.51.100.255 scope global dummy98', output)

        output = check_output('ip -d -4 route show dev dummy98')
        print(output)
        self.assertIn('203.0.113.0/24 via 198.51.100.10 proto boot', output)

    def test_keep_configuration_static(self):
        check_output('ip link add name dummy98 type dummy')
        check_output('ip address add 10.1.2.3/16 dev dummy98')
        check_output('ip address add 10.2.3.4/16 dev dummy98 valid_lft 600 preferred_lft 500')
        output = check_output('ip address show dummy98')
        print(output)
        self.assertRegex(output, 'inet 10.1.2.3/16 scope global dummy98')
        self.assertRegex(output, 'inet 10.2.3.4/16 scope global dynamic dummy98')
        output = check_output('ip route show dev dummy98')
        print(output)

        copy_network_unit('24-keep-configuration-static.network')
        start_networkd()
        self.wait_online('dummy98:routable')

        output = check_output('ip address show dummy98')
        print(output)
        self.assertRegex(output, 'inet 10.1.2.3/16 scope global dummy98')
        self.assertNotRegex(output, 'inet 10.2.3.4/16 scope global dynamic dummy98')

    def check_nexthop(self, manage_foreign_nexthops, first):
        self.wait_online('veth99:routable', 'veth-peer:routable', 'dummy98:routable')

        output = check_output('ip nexthop list dev veth99')
        print(output)
        if first:
            self.assertIn('id 1 via 192.168.5.1 dev veth99', output)
            self.assertIn('id 2 via 2001:1234:5:8f63::2 dev veth99', output)
        else:
            self.assertIn('id 6 via 192.168.5.1 dev veth99', output)
            self.assertIn('id 7 via 2001:1234:5:8f63::2 dev veth99', output)
        self.assertIn('id 3 dev veth99', output)
        self.assertIn('id 4 dev veth99', output)
        if first:
            self.assertRegex(output, 'id 5 via 192.168.10.1 dev veth99 .*onlink')
        else:
            self.assertIn('id 5 via 192.168.5.3 dev veth99', output)
            self.assertNotRegex(output, 'id 5 via 192.168.5.3 dev veth99 .*onlink')
        self.assertIn('id 8 via fe80:0:222:4dff:ff:ff:ff:ff dev veth99', output)
        if manage_foreign_nexthops:
            self.assertRegex(output, r'id [0-9]* via 192.168.5.2 dev veth99')

        output = check_output('ip nexthop list dev dummy98')
        print(output)
        if first:
            self.assertIn('id 20 via 192.168.20.1 dev dummy98', output)
        else:
            self.assertIn('id 21 via 192.168.20.1 dev dummy98', output)
        if manage_foreign_nexthops:
            self.assertNotIn('id 42 via 192.168.20.2 dev dummy98', output)
        else:
            self.assertIn('id 42 via 192.168.20.2 dev dummy98', output)

        # kernel manages blackhole nexthops on lo
        output = check_output('ip nexthop list dev lo')
        print(output)
        if first:
            self.assertIn('id 6 blackhole', output)
            self.assertIn('id 7 blackhole', output)
        else:
            self.assertIn('id 1 blackhole', output)
            self.assertIn('id 2 blackhole', output)

        # group nexthops are shown with -0 option
        if first:
            output = check_output('ip -0 nexthop list id 21')
            print(output)
            self.assertRegex(output, r'id 21 group (1,3/20|20/1,3)')
        else:
            output = check_output('ip -0 nexthop list id 20')
            print(output)
            self.assertRegex(output, r'id 20 group (5,3/21|21/5,3)')

        output = check_output('ip route show dev veth99 10.10.10.10')
        print(output)
        if first:
            self.assertEqual('10.10.10.10 nhid 1 via 192.168.5.1 proto static', output)
        else:
            self.assertEqual('10.10.10.10 nhid 6 via 192.168.5.1 proto static', output)

        output = check_output('ip route show dev veth99 10.10.10.11')
        print(output)
        if first:
            self.assertEqual('10.10.10.11 nhid 2 via inet6 2001:1234:5:8f63::2 proto static', output)
        else:
            self.assertEqual('10.10.10.11 nhid 7 via inet6 2001:1234:5:8f63::2 proto static', output)

        output = check_output('ip route show dev veth99 10.10.10.12')
        print(output)
        if first:
            self.assertEqual('10.10.10.12 nhid 5 via 192.168.10.1 proto static onlink', output)
        else:
            self.assertEqual('10.10.10.12 nhid 5 via 192.168.5.3 proto static', output)

        output = check_output('ip -6 route show dev veth99 2001:1234:5:8f62::1')
        print(output)
        if first:
            self.assertEqual('2001:1234:5:8f62::1 nhid 2 via 2001:1234:5:8f63::2 proto static metric 1024 pref medium', output)
        else:
            self.assertEqual('2001:1234:5:8f62::1 nhid 7 via 2001:1234:5:8f63::2 proto static metric 1024 pref medium', output)

        output = check_output('ip route show 10.10.10.13')
        print(output)
        if first:
            self.assertEqual('blackhole 10.10.10.13 nhid 6 dev lo proto static', output)
        else:
            self.assertEqual('blackhole 10.10.10.13 nhid 1 dev lo proto static', output)

        output = check_output('ip -6 route show 2001:1234:5:8f62::2')
        print(output)
        if first:
            self.assertEqual('blackhole 2001:1234:5:8f62::2 nhid 7 dev lo proto static metric 1024 pref medium', output)
        else:
            self.assertEqual('blackhole 2001:1234:5:8f62::2 nhid 2 dev lo proto static metric 1024 pref medium', output)

        output = check_output('ip route show 10.10.10.14')
        print(output)
        if first:
            self.assertIn('10.10.10.14 nhid 21 proto static', output)
            self.assertIn('nexthop via 192.168.5.1 dev veth99 weight 3', output)
        else:
            self.assertIn('10.10.10.14 nhid 20 proto static', output)
            self.assertIn('nexthop via 192.168.5.3 dev veth99 weight 3', output)
        self.assertIn('nexthop via 192.168.20.1 dev dummy98 weight 1', output)

        output = networkctl_json()
        check_json(output)
        self.assertNotIn('"Destination":[10.10.10.14]', output)

    def _test_nexthop(self, manage_foreign_nexthops):
        if not manage_foreign_nexthops:
            copy_networkd_conf_dropin('networkd-manage-foreign-nexthops-no.conf')

        check_output('ip link add dummy98 type dummy')
        check_output('ip link set dummy98 up')
        check_output('ip address add 192.168.20.20/24 dev dummy98')
        check_output('ip nexthop add id 42 via 192.168.20.2 dev dummy98')

        copy_network_unit('25-nexthop-1.network', '25-veth.netdev', '25-veth-peer.network',
                          '12-dummy.netdev', '25-nexthop-dummy-1.network')
        start_networkd()

        self.check_nexthop(manage_foreign_nexthops, first=True)

        remove_network_unit('25-nexthop-1.network', '25-nexthop-dummy-1.network')
        copy_network_unit('25-nexthop-2.network', '25-nexthop-dummy-2.network')
        networkctl_reload()
        self.check_nexthop(manage_foreign_nexthops, first=False)

        remove_network_unit('25-nexthop-2.network')
        copy_network_unit('25-nexthop-nothing.network')
        networkctl_reload()
        self.wait_online('veth99:routable', 'veth-peer:routable')

        output = check_output('ip nexthop list dev veth99')
        print(output)
        self.assertEqual(output, '')
        output = check_output('ip nexthop list dev lo')
        print(output)
        self.assertEqual(output, '')

        remove_network_unit('25-nexthop-nothing.network', '25-nexthop-dummy-2.network')
        copy_network_unit('25-nexthop-1.network', '25-nexthop-dummy-1.network')
        # Of course, networkctl_reconfigure() below is unnecessary in normal operation, but it is intentional
        # here to test reconfiguring with different .network files does not trigger race.
        # See also comments in link_drop_requests().
        networkctl_reconfigure('dummy98') # reconfigured with 25-nexthop-dummy-2.network
        networkctl_reload()               # reconfigured with 25-nexthop-dummy-1.network

        self.check_nexthop(manage_foreign_nexthops, first=True)

        # Remove nexthop with ID 20
        check_output('ip nexthop del id 20')

        # Check the nexthop ID 20 is dropped from the group nexthop.
        output = check_output('ip -0 nexthop list id 21')
        print(output)
        self.assertRegex(output, r'id 21 group 1,3')

        # Remove nexthop with ID 21
        check_output('ip nexthop del id 21')
        copy_network_unit('11-dummy.netdev', '25-nexthop-test1.network')
        networkctl_reload()

        # 25-nexthop-test1.network requests a route with nexthop ID 21, which is removed in the above,
        # hence test1 should be stuck in the configuring state.
        self.wait_operstate('test1', operstate='routable', setup_state='configuring')

        # Wait for a while, and check if the interface is still in the configuring state.
        time.sleep(1)
        output = networkctl_status('test1')
        self.assertIn('State: routable (configuring)', output)

        # Check if the route which needs nexthop 21 are forgotten.
        output = networkctl_json()
        check_json(output)
        self.assertNotIn('"Destination":[10.10.10.14]', output)

        # Reconfigure the interface that has nexthop with ID 20 and 21,
        # then the route requested by test1 can be configured.
        networkctl_reconfigure('dummy98')
        self.wait_online('test1:routable')

        # Check if the requested route actually configured.
        output = check_output('ip route show 10.10.11.10')
        print(output)
        self.assertIn('10.10.11.10 nhid 21 proto static', output)
        self.assertIn('nexthop via 192.168.5.1 dev veth99 weight 3', output)
        self.assertIn('nexthop via 192.168.20.1 dev dummy98 weight 1', output)

        remove_link('veth99')
        time.sleep(2)

        output = check_output('ip nexthop list dev lo')
        print(output)
        self.assertEqual(output, '')

    @expectedFailureIfNexthopIsNotAvailable()
    def test_nexthop(self):
        first = True
        for manage_foreign_nexthops in [True, False]:
            if first:
                first = False
            else:
                self.tearDown()

            print(f'### test_nexthop(manage_foreign_nexthops={manage_foreign_nexthops})')
            with self.subTest(manage_foreign_nexthops=manage_foreign_nexthops):
                self._test_nexthop(manage_foreign_nexthops)

class NetworkdTCTests(unittest.TestCase, Utilities):

    def setUp(self):
        setup_common()

    def tearDown(self):
        tear_down_common()

    @expectedFailureIfModuleIsNotAvailable('sch_cake')
    def test_qdisc_cake(self):
        copy_network_unit('25-qdisc-cake.network', '12-dummy.netdev')
        start_networkd()
        self.wait_online('dummy98:routable')

        output = check_output('tc qdisc show dev dummy98')
        print(output)
        self.assertIn('qdisc cake 3a: root', output)
        self.assertIn('bandwidth 500Mbit', output)
        self.assertIn('autorate-ingress', output)
        self.assertIn('diffserv8', output)
        self.assertIn('dual-dsthost', output)
        self.assertIn(' nat', output)
        self.assertIn(' wash', output)
        self.assertIn(' split-gso', output)
        self.assertIn(' raw', output)
        self.assertIn(' atm', output)
        self.assertIn('overhead 128', output)
        self.assertIn('mpu 20', output)
        self.assertIn('fwmark 0xff00', output)
        self.assertIn('rtt 1s', output)
        self.assertIn('ack-filter-aggressive', output)

        # Test for replacing existing qdisc. See #31226.
        with open(os.path.join(network_unit_dir, '25-qdisc-cake.network'), mode='a', encoding='utf-8') as f:
            f.write('Bandwidth=250M\n')

        networkctl_reload()
        self.wait_online('dummy98:routable')

        output = check_output('tc qdisc show dev dummy98')
        print(output)
        self.assertIn('bandwidth 250Mbit', output)

    @expectedFailureIfModuleIsNotAvailable('sch_codel')
    def test_qdisc_codel(self):
        copy_network_unit('25-qdisc-codel.network', '12-dummy.netdev')
        start_networkd()
        self.wait_online('dummy98:routable')

        output = check_output('tc qdisc show dev dummy98')
        print(output)
        self.assertRegex(output, 'qdisc codel 33: root')
        self.assertRegex(output, 'limit 2000p target 10(.0)?ms ce_threshold 100(.0)?ms interval 50(.0)?ms ecn')

    @expectedFailureIfModuleIsNotAvailable('sch_drr')
    def test_qdisc_drr(self):
        copy_network_unit('25-qdisc-drr.network', '12-dummy.netdev')
        start_networkd()
        self.wait_online('dummy98:routable')

        output = check_output('tc qdisc show dev dummy98')
        print(output)
        self.assertRegex(output, 'qdisc drr 2: root')
        output = check_output('tc class show dev dummy98')
        print(output)
        self.assertRegex(output, 'class drr 2:30 root quantum 2000b')

    @expectedFailureIfModuleIsNotAvailable('sch_ets')
    def test_qdisc_ets(self):
        copy_network_unit('25-qdisc-ets.network', '12-dummy.netdev')
        start_networkd()
        self.wait_online('dummy98:routable')

        output = check_output('tc qdisc show dev dummy98')
        print(output)

        self.assertRegex(output, 'qdisc ets 3a: root')
        self.assertRegex(output, 'bands 10 strict 3')
        self.assertRegex(output, 'quanta 1 2 3 4 5')
        self.assertRegex(output, 'priomap 3 4 5 6 7')

    @expectedFailureIfModuleIsNotAvailable('sch_fq')
    def test_qdisc_fq(self):
        copy_network_unit('25-qdisc-fq.network', '12-dummy.netdev')
        start_networkd()
        self.wait_online('dummy98:routable')

        output = check_output('tc qdisc show dev dummy98')
        print(output)
        self.assertRegex(output, 'qdisc fq 32: root')
        self.assertRegex(output, 'limit 1000p flow_limit 200p buckets 512 orphan_mask 511')
        self.assertRegex(output, 'quantum 1500')
        self.assertRegex(output, 'initial_quantum 13000')
        self.assertRegex(output, 'maxrate 1Mbit')

    @expectedFailureIfModuleIsNotAvailable('sch_fq_codel')
    def test_qdisc_fq_codel(self):
        copy_network_unit('25-qdisc-fq_codel.network', '12-dummy.netdev')
        start_networkd()
        self.wait_online('dummy98:routable')

        output = check_output('tc qdisc show dev dummy98')
        print(output)
        self.assertRegex(output, 'qdisc fq_codel 34: root')
        self.assertRegex(output, 'limit 20480p flows 2048 quantum 1400 target 10(.0)?ms ce_threshold 100(.0)?ms interval 200(.0)?ms memory_limit 64Mb ecn')

    @expectedFailureIfModuleIsNotAvailable('sch_fq_pie')
    def test_qdisc_fq_pie(self):
        copy_network_unit('25-qdisc-fq_pie.network', '12-dummy.netdev')
        start_networkd()
        self.wait_online('dummy98:routable')

        output = check_output('tc qdisc show dev dummy98')
        print(output)

        self.assertRegex(output, 'qdisc fq_pie 3a: root')
        self.assertRegex(output, 'limit 200000p')

    @expectedFailureIfModuleIsNotAvailable('sch_gred')
    def test_qdisc_gred(self):
        copy_network_unit('25-qdisc-gred.network', '12-dummy.netdev')
        start_networkd()
        self.wait_online('dummy98:routable')

        output = check_output('tc qdisc show dev dummy98')
        print(output)
        self.assertRegex(output, 'qdisc gred 38: root')
        self.assertRegex(output, 'vqs 12 default 10 grio')

    @expectedFailureIfModuleIsNotAvailable('sch_hhf')
    def test_qdisc_hhf(self):
        copy_network_unit('25-qdisc-hhf.network', '12-dummy.netdev')
        start_networkd()
        self.wait_online('dummy98:routable')

        output = check_output('tc qdisc show dev dummy98')
        print(output)
        self.assertRegex(output, 'qdisc hhf 3a: root')
        self.assertRegex(output, 'limit 1022p')

    @expectedFailureIfModuleIsNotAvailable('sch_htb')
    def test_qdisc_htb_fifo(self):
        copy_network_unit('25-qdisc-htb-fifo.network', '12-dummy.netdev')
        start_networkd()
        self.wait_online('dummy98:routable')

        output = check_output('tc qdisc show dev dummy98')
        print(output)
        self.assertRegex(output, 'qdisc htb 2: root')
        self.assertRegex(output, r'default (0x30|30)')

        self.assertRegex(output, 'qdisc pfifo 37: parent 2:37')
        self.assertRegex(output, 'limit 100000p')

        self.assertRegex(output, 'qdisc bfifo 3a: parent 2:3a')
        self.assertRegex(output, 'limit 1000000')

        self.assertRegex(output, 'qdisc pfifo_head_drop 3b: parent 2:3b')
        self.assertRegex(output, 'limit 1023p')

        self.assertRegex(output, 'qdisc pfifo_fast 3c: parent 2:3c')

        output = check_output('tc -d class show dev dummy98')
        print(output)
        # Here (:|prio) is a workaround for a bug in iproute2 v6.2.0 caused by
        # https://github.com/shemminger/iproute2/commit/010a8388aea11e767ba3a2506728b9ad9760df0e
        # which is fixed in v6.3.0 by
        # https://github.com/shemminger/iproute2/commit/4e0e56e0ef05387f7f5d8ab41fe6ec6a1897b26d
        self.assertRegex(output, 'class htb 2:37 root leaf 37(:|prio) ')
        self.assertRegex(output, 'class htb 2:3a root leaf 3a(:|prio) ')
        self.assertRegex(output, 'class htb 2:3b root leaf 3b(:|prio) ')
        self.assertRegex(output, 'class htb 2:3c root leaf 3c(:|prio) ')
        self.assertRegex(output, 'prio 1 quantum 4000 rate 1Mbit overhead 100 ceil 500Kbit')
        self.assertRegex(output, 'burst 123456')
        self.assertRegex(output, 'cburst 123457')

    @expectedFailureIfModuleIsNotAvailable('sch_ingress')
    def test_qdisc_ingress(self):
        copy_network_unit('25-qdisc-clsact.network', '12-dummy.netdev',
                          '25-qdisc-ingress.network', '11-dummy.netdev')
        start_networkd()
        self.wait_online('dummy98:routable', 'test1:routable')

        output = check_output('tc qdisc show dev dummy98')
        print(output)
        self.assertRegex(output, 'qdisc clsact')

        output = check_output('tc qdisc show dev test1')
        print(output)
        self.assertRegex(output, 'qdisc ingress')

    def test_qdisc_mq(self):
        copy_network_unit('25-tun.netdev', '25-tap.netdev', '25-qdisc-mq.network')
        start_networkd()
        self.wait_online('testtun99:degraded', 'testtap99:degraded')

        output = check_output('tc qdisc show dev testtun99')
        print(output)
        self.assertIn('qdisc mq 2: root', output)

    @expectedFailureIfModuleIsNotAvailable('sch_multiq')
    def test_qdisc_multiq(self):
        copy_network_unit('25-tun.netdev', '25-tap.netdev', '25-qdisc-multiq.network')
        start_networkd()
        self.wait_online('testtun99:degraded', 'testtap99:degraded')

        output = check_output('tc qdisc show dev testtun99')
        print(output)
        self.assertIn('qdisc multiq 2: root', output)

    @expectedFailureIfModuleIsNotAvailable('sch_netem')
    def test_qdisc_netem(self):
        copy_network_unit('25-qdisc-netem.network', '12-dummy.netdev',
                          '25-qdisc-netem-compat.network', '11-dummy.netdev')
        start_networkd()
        self.wait_online('dummy98:routable', 'test1:routable')

        output = check_output('tc qdisc show dev dummy98')
        print(output)
        self.assertRegex(output, 'qdisc netem 30: root')
        self.assertRegex(output, 'limit 100 delay 50(.0)?ms  10(.0)?ms loss 20%')

        output = check_output('tc qdisc show dev test1')
        print(output)
        self.assertRegex(output, 'qdisc netem [0-9a-f]*: root')
        self.assertRegex(output, 'limit 100 delay 50(.0)?ms  10(.0)?ms loss 20%')

    @expectedFailureIfModuleIsNotAvailable('sch_pie')
    def test_qdisc_pie(self):
        copy_network_unit('25-qdisc-pie.network', '12-dummy.netdev')
        start_networkd()
        self.wait_online('dummy98:routable')

        output = check_output('tc qdisc show dev dummy98')
        print(output)
        self.assertRegex(output, 'qdisc pie 3a: root')
        self.assertRegex(output, 'limit 200000')

    @expectedFailureIfModuleIsNotAvailable('sch_qfq')
    def test_qdisc_qfq(self):
        copy_network_unit('25-qdisc-qfq.network', '12-dummy.netdev')
        start_networkd()
        self.wait_online('dummy98:routable')

        output = check_output('tc qdisc show dev dummy98')
        print(output)
        self.assertRegex(output, 'qdisc qfq 2: root')
        output = check_output('tc class show dev dummy98')
        print(output)
        self.assertRegex(output, 'class qfq 2:30 root weight 2 maxpkt 16000')
        self.assertRegex(output, 'class qfq 2:31 root weight 10 maxpkt 8000')

    @expectedFailureIfModuleIsNotAvailable('sch_sfb')
    def test_qdisc_sfb(self):
        copy_network_unit('25-qdisc-sfb.network', '12-dummy.netdev')
        start_networkd()
        self.wait_online('dummy98:routable')

        output = check_output('tc qdisc show dev dummy98')
        print(output)
        self.assertRegex(output, 'qdisc sfb 39: root')
        self.assertRegex(output, 'limit 200000')

    @expectedFailureIfModuleIsNotAvailable('sch_sfq')
    def test_qdisc_sfq(self):
        copy_network_unit('25-qdisc-sfq.network', '12-dummy.netdev')
        start_networkd()
        self.wait_online('dummy98:routable')

        output = check_output('tc qdisc show dev dummy98')
        print(output)
        self.assertRegex(output, 'qdisc sfq 36: root')
        self.assertRegex(output, 'perturb 5sec')

    @expectedFailureIfModuleIsNotAvailable('sch_tbf')
    def test_qdisc_tbf(self):
        copy_network_unit('25-qdisc-tbf.network', '12-dummy.netdev')
        start_networkd()
        self.wait_online('dummy98:routable')

        output = check_output('tc qdisc show dev dummy98')
        print(output)
        self.assertRegex(output, 'qdisc tbf 35: root')
        self.assertRegex(output, 'rate 1Gbit burst 5000b peakrate 100Gbit minburst 987500b lat 70(.0)?ms')

    @expectedFailureIfModuleIsNotAvailable('sch_teql')
    def test_qdisc_teql(self):
        call_quiet('rmmod sch_teql')

        copy_network_unit('25-qdisc-teql.network', '12-dummy.netdev')
        start_networkd()
        self.wait_links('dummy98')
        check_output('modprobe sch_teql max_equalizers=2')
        self.wait_online('dummy98:routable')

        output = check_output('tc qdisc show dev dummy98')
        print(output)
        self.assertRegex(output, 'qdisc teql1 31: root')

    @expectedFailureIfModuleIsNotAvailable('sch_fq', 'sch_sfq', 'sch_tbf')
    def test_qdisc_drop(self):
        copy_network_unit('12-dummy.netdev', '12-dummy.network')
        start_networkd()
        self.wait_online('dummy98:routable')

        # Test case for issue #32247 and #32254.
        for _ in range(20):
            check_output('tc qdisc replace dev dummy98 root fq')
            self.assertFalse(networkd_is_failed())
            check_output('tc qdisc replace dev dummy98 root fq pacing')
            self.assertFalse(networkd_is_failed())
            check_output('tc qdisc replace dev dummy98 handle 10: root tbf rate 0.5mbit burst 5kb latency 70ms peakrate 1mbit minburst 1540')
            self.assertFalse(networkd_is_failed())
            check_output('tc qdisc add dev dummy98 parent 10:1 handle 100: sfq')
            self.assertFalse(networkd_is_failed())

class NetworkdStateFileTests(unittest.TestCase, Utilities):

    def setUp(self):
        setup_common()

    def tearDown(self):
        tear_down_common()

    def test_state_file(self):
        copy_network_unit('12-dummy.netdev', '25-state-file-tests.network')
        start_networkd()
        self.wait_online('dummy98:routable')

        # make link state file updated
        resolvectl('revert', 'dummy98')

        check_json(networkctl_json())

        output = read_link_state_file('dummy98')
        print(output)
        self.assertIn('IPV4_ADDRESS_STATE=routable', output)
        self.assertIn('IPV6_ADDRESS_STATE=routable', output)
        self.assertIn('ADMIN_STATE=configured', output)
        self.assertIn('OPER_STATE=routable', output)
        self.assertIn('REQUIRED_FOR_ONLINE=yes', output)
        self.assertIn('REQUIRED_OPER_STATE_FOR_ONLINE=routable', output)
        self.assertIn('REQUIRED_FAMILY_FOR_ONLINE=both', output)
        self.assertIn('ACTIVATION_POLICY=up', output)
        self.assertIn('NETWORK_FILE=/run/systemd/network/25-state-file-tests.network', output)
        self.assertIn('DNS=10.10.10.10#aaa.com 10.10.10.11:1111#bbb.com [1111:2222::3333]:1234#ccc.com', output)
        self.assertIn('NTP=0.fedora.pool.ntp.org 1.fedora.pool.ntp.org', output)
        self.assertIn('DOMAINS=hogehoge', output)
        self.assertIn('ROUTE_DOMAINS=foofoo', output)
        self.assertIn('LLMNR=no', output)
        self.assertIn('MDNS=yes', output)
        self.assertIn('DNSSEC=no', output)

        resolvectl('dns', 'dummy98', '10.10.10.12#ccc.com', '10.10.10.13', '1111:2222::3333')
        resolvectl('domain', 'dummy98', 'hogehogehoge', '~foofoofoo')
        resolvectl('llmnr', 'dummy98', 'yes')
        resolvectl('mdns', 'dummy98', 'no')
        resolvectl('dnssec', 'dummy98', 'yes')
        timedatectl('ntp-servers', 'dummy98', '2.fedora.pool.ntp.org', '3.fedora.pool.ntp.org')

        check_json(networkctl_json())

        output = read_link_state_file('dummy98')
        print(output)
        self.assertIn('DNS=10.10.10.12#ccc.com 10.10.10.13 1111:2222::3333', output)
        self.assertIn('NTP=2.fedora.pool.ntp.org 3.fedora.pool.ntp.org', output)
        self.assertIn('DOMAINS=hogehogehoge', output)
        self.assertIn('ROUTE_DOMAINS=foofoofoo', output)
        self.assertIn('LLMNR=yes', output)
        self.assertIn('MDNS=no', output)
        self.assertIn('DNSSEC=yes', output)

        timedatectl('revert', 'dummy98')

        check_json(networkctl_json())

        output = read_link_state_file('dummy98')
        print(output)
        self.assertIn('DNS=10.10.10.12#ccc.com 10.10.10.13 1111:2222::3333', output)
        self.assertIn('NTP=0.fedora.pool.ntp.org 1.fedora.pool.ntp.org', output)
        self.assertIn('DOMAINS=hogehogehoge', output)
        self.assertIn('ROUTE_DOMAINS=foofoofoo', output)
        self.assertIn('LLMNR=yes', output)
        self.assertIn('MDNS=no', output)
        self.assertIn('DNSSEC=yes', output)

        resolvectl('revert', 'dummy98')

        check_json(networkctl_json())

        output = read_link_state_file('dummy98')
        print(output)
        self.assertIn('DNS=10.10.10.10#aaa.com 10.10.10.11:1111#bbb.com [1111:2222::3333]:1234#ccc.com', output)
        self.assertIn('NTP=0.fedora.pool.ntp.org 1.fedora.pool.ntp.org', output)
        self.assertIn('DOMAINS=hogehoge', output)
        self.assertIn('ROUTE_DOMAINS=foofoo', output)
        self.assertIn('LLMNR=no', output)
        self.assertIn('MDNS=yes', output)
        self.assertIn('DNSSEC=no', output)

    def test_address_state(self):
        copy_network_unit('12-dummy.netdev', '12-dummy-no-address.network')
        start_networkd()

        self.wait_online('dummy98:degraded')

        output = read_link_state_file('dummy98')
        self.assertIn('IPV4_ADDRESS_STATE=off', output)
        self.assertIn('IPV6_ADDRESS_STATE=degraded', output)

        # with a routable IPv4 address
        check_output('ip address add 10.1.2.3/16 dev dummy98')
        self.wait_online('dummy98:routable', ipv4=True)
        self.wait_online('dummy98:routable')

        output = read_link_state_file('dummy98')
        self.assertIn('IPV4_ADDRESS_STATE=routable', output)
        self.assertIn('IPV6_ADDRESS_STATE=degraded', output)

        check_output('ip address del 10.1.2.3/16 dev dummy98')

        # with a routable IPv6 address
        check_output('ip address add 2002:da8:1:0:1034:56ff:fe78:9abc/64 dev dummy98')
        self.wait_online('dummy98:routable', ipv6=True)
        self.wait_online('dummy98:routable')

        output = read_link_state_file('dummy98')
        self.assertIn('IPV4_ADDRESS_STATE=off', output)
        self.assertIn('IPV6_ADDRESS_STATE=routable', output)

class NetworkdBondTests(unittest.TestCase, Utilities):

    def setUp(self):
        setup_common()

    def tearDown(self):
        tear_down_common()

    def test_bond_keep_master(self):
        check_output('ip link add bond199 type bond mode active-backup')
        check_output('ip link add dummy98 type dummy')
        check_output('ip link set dummy98 master bond199')

        copy_network_unit('23-keep-master.network')
        start_networkd()
        self.wait_online('dummy98:enslaved')

        output = check_output('ip -d link show bond199')
        print(output)
        self.assertRegex(output, 'active_slave dummy98')

        output = check_output('ip -d link show dummy98')
        print(output)
        self.assertRegex(output, 'master bond199')

    def test_bond_active_slave(self):
        copy_network_unit('23-active-slave.network', '23-bond199.network', '25-bond-active-backup-slave.netdev', '12-dummy.netdev')
        start_networkd()
        self.wait_online('dummy98:enslaved', 'bond199:degraded')

        output = check_output('ip -d link show bond199')
        print(output)
        self.assertIn('active_slave dummy98', output)

        # test case for issue #31165.
        since = datetime.datetime.now()
        networkctl_reconfigure('dummy98')
        self.wait_online('dummy98:enslaved', 'bond199:degraded')
        self.assertNotIn('dummy98: Bringing link down', read_networkd_log(since=since))

        # test for reloading.
        touch_network_unit(
            '23-active-slave.network',
            '23-bond199.network',
            '25-bond-active-backup-slave.netdev',
            '12-dummy.netdev')
        networkctl_reload()
        self.wait_online('dummy98:enslaved', 'bond199:degraded')

    def test_bond_primary_slave(self):
        copy_network_unit('23-primary-slave.network', '23-bond199.network', '25-bond-active-backup-slave.netdev', '12-dummy.netdev')
        start_networkd()
        self.wait_online('dummy98:enslaved', 'bond199:degraded')

        output = check_output('ip -d link show bond199')
        print(output)
        self.assertIn('primary dummy98', output)

        # for issue #25627
        mkdir_p(os.path.join(network_unit_dir, '23-bond199.network.d'))
        for mac in ['00:11:22:33:44:55', '00:11:22:33:44:56']:
            with open(os.path.join(network_unit_dir, '23-bond199.network.d/mac.conf'), mode='w', encoding='utf-8') as f:
                f.write(f'[Link]\nMACAddress={mac}\n')

            networkctl_reload()
            self.wait_online('dummy98:enslaved', 'bond199:degraded')

            output = check_output('ip -d link show bond199')
            print(output)
            self.assertIn(f'link/ether {mac}', output)

    def test_bond_operstate(self):
        copy_network_unit('25-bond.netdev', '11-dummy.netdev', '12-dummy.netdev',
                          '25-bond99.network', '25-bond-slave.network')
        start_networkd()
        self.wait_online('dummy98:enslaved', 'test1:enslaved', 'bond99:routable')

        output = check_output('ip -d link show dummy98')
        print(output)
        self.assertRegex(output, 'SLAVE,UP,LOWER_UP')

        output = check_output('ip -d link show test1')
        print(output)
        self.assertRegex(output, 'SLAVE,UP,LOWER_UP')

        output = check_output('ip -d link show bond99')
        print(output)
        self.assertRegex(output, 'MASTER,UP,LOWER_UP')

        self.wait_operstate('dummy98', 'enslaved')
        self.wait_operstate('test1', 'enslaved')
        self.wait_operstate('bond99', 'routable')

        check_output('ip link set dummy98 down')

        self.wait_operstate('dummy98', 'off')
        self.wait_operstate('test1', 'enslaved')
        self.wait_operstate('bond99', 'routable')

        check_output('ip link set dummy98 up')

        self.wait_operstate('dummy98', 'enslaved')
        self.wait_operstate('test1', 'enslaved')
        self.wait_operstate('bond99', 'routable')

        check_output('ip link set dummy98 down')
        check_output('ip link set test1 down')

        self.wait_operstate('dummy98', 'off')
        self.wait_operstate('test1', 'off')

        if not self.wait_operstate('bond99', 'no-carrier', setup_timeout=30, fail_assert=False):
            # Huh? Kernel does not recognize that all slave interfaces are down?
            # Let's confirm that networkd's operstate is consistent with ip's result.
            self.assertNotRegex(output, 'NO-CARRIER')

class NetworkdBridgeTests(unittest.TestCase, Utilities):

    def setUp(self):
        setup_common()

    def tearDown(self):
        tear_down_common()

    def test_bridge_mac_none(self):
        copy_network_unit('12-dummy-mac.netdev', '26-bridge-mac-slave.network',
                          '26-bridge-mac.netdev', '26-bridge-mac-master.network', '26-bridge-mac.link')
        start_networkd()
        self.wait_online('dummy98:enslaved', 'bridge99:degraded')

        output = check_output('ip link show dev dummy98')
        print(output)
        self.assertIn('link/ether 12:34:56:78:9a:01', output)

        output = check_output('ip link show dev bridge99')
        print(output)
        self.assertIn('link/ether 12:34:56:78:9a:01', output)

    def test_bridge_vlan(self):
        copy_network_unit('11-dummy.netdev', '26-bridge-vlan-slave.network',
                          '26-bridge.netdev', '26-bridge-vlan-master.network',
                          copy_dropins=False)
        start_networkd()
        self.wait_online('test1:enslaved', 'bridge99:degraded')

        output = check_output('bridge vlan show dev test1')
        print(output)
        # check if the default VID is removed
        self.assertNotIn('1 Egress Untagged', output)
        for i in range(1000, 3000):
            if i == 1010:
                self.assertIn(f'{i} PVID', output)
            elif i in range(1012, 1016) or i in range(1103, 1109):
                self.assertIn(f'{i} Egress Untagged', output)
            elif i in range(1008, 1014) or i in range(1100, 1111):
                self.assertIn(f'{i}', output)
            else:
                self.assertNotIn(f'{i}', output)

        output = check_output('bridge vlan show dev bridge99')
        print(output)
        # check if the default VID is removed
        self.assertNotIn('1 Egress Untagged', output)
        for i in range(1000, 3000):
            if i == 1020:
                self.assertIn(f'{i} PVID', output)
            elif i in range(1022, 1026) or i in range(1203, 1209):
                self.assertIn(f'{i} Egress Untagged', output)
            elif i in range(1018, 1024) or i in range(1200, 1211):
                self.assertIn(f'{i}', output)
            else:
                self.assertNotIn(f'{i}', output)

        # Change vlan IDs
        copy_network_unit('26-bridge-vlan-slave.network.d/10-override.conf',
                          '26-bridge-vlan-master.network.d/10-override.conf')
        networkctl_reload()
        self.wait_online('test1:enslaved', 'bridge99:degraded')

        output = check_output('bridge vlan show dev test1')
        print(output)
        for i in range(1000, 3000):
            if i == 2010:
                self.assertIn(f'{i} PVID', output)
            elif i in range(2012, 2016) or i in range(2103, 2109):
                self.assertIn(f'{i} Egress Untagged', output)
            elif i in range(2008, 2014) or i in range(2100, 2111):
                self.assertIn(f'{i}', output)
            else:
                self.assertNotIn(f'{i}', output)

        output = check_output('bridge vlan show dev bridge99')
        print(output)
        for i in range(1000, 3000):
            if i == 2020:
                self.assertIn(f'{i} PVID', output)
            elif i in range(2022, 2026) or i in range(2203, 2209):
                self.assertIn(f'{i} Egress Untagged', output)
            elif i in range(2018, 2024) or i in range(2200, 2211):
                self.assertIn(f'{i}', output)
            else:
                self.assertNotIn(f'{i}', output)

        # Remove several vlan IDs
        copy_network_unit('26-bridge-vlan-slave.network.d/20-override.conf',
                          '26-bridge-vlan-master.network.d/20-override.conf')
        networkctl_reload()
        self.wait_online('test1:enslaved', 'bridge99:degraded')

        output = check_output('bridge vlan show dev test1')
        print(output)
        for i in range(1000, 3000):
            if i == 2010:
                self.assertIn(f'{i} PVID', output)
            elif i in range(2012, 2016):
                self.assertIn(f'{i} Egress Untagged', output)
            elif i in range(2008, 2014):
                self.assertIn(f'{i}', output)
            else:
                self.assertNotIn(f'{i}', output)

        output = check_output('bridge vlan show dev bridge99')
        print(output)
        for i in range(1000, 3000):
            if i == 2020:
                self.assertIn(f'{i} PVID', output)
            elif i in range(2022, 2026):
                self.assertIn(f'{i} Egress Untagged', output)
            elif i in range(2018, 2024):
                self.assertIn(f'{i}', output)
            else:
                self.assertNotIn(f'{i}', output)

        # Remove all vlan IDs
        copy_network_unit('26-bridge-vlan-slave.network.d/30-override.conf',
                          '26-bridge-vlan-master.network.d/30-override.conf')
        networkctl_reload()
        self.wait_online('test1:enslaved', 'bridge99:degraded')

        output = check_output('bridge vlan show dev test1')
        print(output)
        self.assertNotIn('PVID', output)
        for i in range(1000, 3000):
            self.assertNotIn(f'{i}', output)

        output = check_output('bridge vlan show dev bridge99')
        print(output)
        self.assertNotIn('PVID', output)
        for i in range(1000, 3000):
            self.assertNotIn(f'{i}', output)

    def test_bridge_vlan_issue_20373(self):
        copy_network_unit('11-dummy.netdev', '26-bridge-vlan-slave-issue-20373.network',
                          '26-bridge-issue-20373.netdev', '26-bridge-vlan-master-issue-20373.network',
                          '21-vlan.netdev', '21-vlan.network')
        start_networkd()
        self.wait_online('test1:enslaved', 'bridge99:degraded', 'vlan99:routable')

        output = check_output('bridge vlan show dev test1')
        print(output)
        self.assertIn('100 PVID Egress Untagged', output)
        self.assertIn('560', output)
        self.assertIn('600', output)

        output = check_output('bridge vlan show dev bridge99')
        print(output)
        self.assertIn('1 PVID Egress Untagged', output)
        self.assertIn('100', output)
        self.assertIn('600', output)

    def test_bridge_mdb(self):
        copy_network_unit('11-dummy.netdev', '26-bridge-mdb-slave.network',
                          '26-bridge.netdev', '26-bridge-mdb-master.network')
        start_networkd()
        self.wait_online('test1:enslaved', 'bridge99:degraded')

        output = check_output('bridge mdb show dev bridge99')
        print(output)
        self.assertRegex(output, 'dev bridge99 port test1 grp ff02:aaaa:fee5::1:3 permanent *vid 4064')
        self.assertRegex(output, 'dev bridge99 port test1 grp 224.0.1.1 permanent *vid 4065')

        # Old kernel may not support bridge MDB entries on bridge master
        if call_quiet('bridge mdb add dev bridge99 port bridge99 grp 224.0.1.3 temp vid 4068') == 0:
            self.assertRegex(output, 'dev bridge99 port bridge99 grp ff02:aaaa:fee5::1:4 temp *vid 4066')
            self.assertRegex(output, 'dev bridge99 port bridge99 grp 224.0.1.2 temp *vid 4067')

        # Old kernel may not support L2 bridge MDB entries
        if call_quiet('bridge mdb add dev bridge99 port bridge99 grp 01:80:c2:00:00:0f permanent vid 4070') == 0:
            self.assertRegex(output, 'dev bridge99 port bridge99 grp 01:80:c2:00:00:0e permanent *vid 4069')

    def test_bridge_keep_master(self):
        check_output('ip link add bridge99 type bridge')
        check_output('ip link set bridge99 up')
        check_output('ip link add dummy98 type dummy')
        check_output('ip link set dummy98 master bridge99')

        copy_network_unit('23-keep-master.network')
        start_networkd()
        self.wait_online('dummy98:enslaved')

        output = check_output('ip -d link show dummy98')
        print(output)
        self.assertRegex(output, 'master bridge99')
        self.assertRegex(output, 'bridge')

        output = check_output('bridge -d link show dummy98')
        print(output)
        self.check_bridge_port_attr('bridge99', 'dummy98', 'path_cost',            '400')
        self.check_bridge_port_attr('bridge99', 'dummy98', 'hairpin_mode',         '1')
        self.check_bridge_port_attr('bridge99', 'dummy98', 'multicast_fast_leave', '1')
        self.check_bridge_port_attr('bridge99', 'dummy98', 'unicast_flood',        '1')
        self.check_bridge_port_attr('bridge99', 'dummy98', 'multicast_flood',      '0')
        # CONFIG_BRIDGE_IGMP_SNOOPING=y
        self.check_bridge_port_attr('bridge99', 'dummy98', 'multicast_to_unicast', '1', allow_enoent=True)
        self.check_bridge_port_attr('bridge99', 'dummy98', 'neigh_suppress',       '1', allow_enoent=True)
        self.check_bridge_port_attr('bridge99', 'dummy98', 'learning',             '0')
        self.check_bridge_port_attr('bridge99', 'dummy98', 'priority',             '23')
        self.check_bridge_port_attr('bridge99', 'dummy98', 'bpdu_guard',           '0')
        self.check_bridge_port_attr('bridge99', 'dummy98', 'root_block',           '0')

    def check_bridge_property(self):
        self.wait_online('dummy98:enslaved', 'test1:enslaved', 'bridge99:routable')

        output = check_output('ip -d link show bridge99')
        print(output)
        self.assertIn('mtu 9000 ', output)

        output = check_output('ip -d link show test1')
        print(output)
        self.assertIn('master bridge99 ', output)
        self.assertIn('bridge_slave', output)
        self.assertIn('mtu 9000 ', output)

        output = check_output('ip -d link show dummy98')
        print(output)
        self.assertIn('master bridge99 ', output)
        self.assertIn('bridge_slave', output)
        self.assertIn('mtu 9000 ', output)

        output = check_output('ip addr show bridge99')
        print(output)
        self.assertIn('192.168.0.15/24', output)

        output = check_output('bridge -d link show dummy98')
        print(output)
        self.check_bridge_port_attr('bridge99', 'dummy98', 'path_cost',            '400')
        self.check_bridge_port_attr('bridge99', 'dummy98', 'hairpin_mode',         '1')
        self.check_bridge_port_attr('bridge99', 'dummy98', 'isolated',             '1')
        self.check_bridge_port_attr('bridge99', 'dummy98', 'multicast_fast_leave', '1')
        self.check_bridge_port_attr('bridge99', 'dummy98', 'unicast_flood',        '1')
        self.check_bridge_port_attr('bridge99', 'dummy98', 'multicast_flood',      '0')
        # CONFIG_BRIDGE_IGMP_SNOOPING=y
        self.check_bridge_port_attr('bridge99', 'dummy98', 'multicast_to_unicast', '1', allow_enoent=True)
        self.check_bridge_port_attr('bridge99', 'dummy98', 'neigh_suppress',       '1', allow_enoent=True)
        self.check_bridge_port_attr('bridge99', 'dummy98', 'learning',             '0')
        self.check_bridge_port_attr('bridge99', 'dummy98', 'priority',             '23')
        self.check_bridge_port_attr('bridge99', 'dummy98', 'bpdu_guard',           '0')
        self.check_bridge_port_attr('bridge99', 'dummy98', 'root_block',           '0')

        output = check_output('bridge -d link show test1')
        print(output)
        self.check_bridge_port_attr('bridge99', 'test1', 'priority',               '0')
        self.assertIn('locked on', output)
        if ' mab ' in output: # This is new in kernel and iproute2 v6.2
            self.assertIn('mab on', output)

    def test_bridge_property(self):
        copy_network_unit('11-dummy.netdev', '12-dummy.netdev', '26-bridge.netdev',
                          '26-bridge-slave-interface-1.network', '26-bridge-slave-interface-2.network',
                          '25-bridge99.network')
        start_networkd()
        self.check_bridge_property()

        # test reload
        touch_network_unit(
            '11-dummy.netdev',
            '12-dummy.netdev',
            '26-bridge.netdev',
            '26-bridge-slave-interface-1.network',
            '26-bridge-slave-interface-2.network',
            '25-bridge99.network')
        networkctl_reload()
        self.check_bridge_property()

        check_output('ip address add 192.168.0.16/24 dev bridge99')
        output = check_output('ip addr show bridge99')
        print(output)
        self.assertIn('192.168.0.16/24', output)

        # for issue #6088
        print('### ip -6 route list table all dev bridge99')
        output = check_output('ip -6 route list table all dev bridge99')
        print(output)
        self.assertRegex(output, 'ff00::/8 table local (proto kernel )?metric 256 (linkdown )?pref medium')

        remove_link('test1')
        self.wait_operstate('bridge99', 'routable')

        output = check_output('ip -d link show bridge99')
        print(output)
        self.assertIn('mtu 9000 ', output)

        output = check_output('ip -d link show dummy98')
        print(output)
        self.assertIn('master bridge99 ', output)
        self.assertIn('bridge_slave', output)
        self.assertIn('mtu 9000 ', output)

        remove_link('dummy98')
        self.wait_operstate('bridge99', 'no-carrier')

        output = check_output('ip -d link show bridge99')
        print(output)
        # When no carrier, the kernel may reset the MTU
        self.assertIn('NO-CARRIER', output)

        output = check_output('ip address show bridge99')
        print(output)
        self.assertNotIn('192.168.0.15/24', output)
        self.assertIn('192.168.0.16/24', output) # foreign address is kept

        print('### ip -6 route list table all dev bridge99')
        output = check_output('ip -6 route list table all dev bridge99')
        print(output)
        self.assertRegex(output, 'ff00::/8 table local (proto kernel )?metric 256 (linkdown )?pref medium')

        check_output('ip link add dummy98 type dummy')
        self.wait_online('dummy98:enslaved', 'bridge99:routable')

        output = check_output('ip -d link show bridge99')
        print(output)
        self.assertIn('mtu 9000 ', output)

        output = check_output('ip -d link show dummy98')
        print(output)
        self.assertIn('master bridge99 ', output)
        self.assertIn('bridge_slave', output)
        self.assertIn('mtu 9000 ', output)

    def test_bridge_configure_without_carrier(self):
        copy_network_unit('26-bridge.netdev', '26-bridge-configure-without-carrier.network',
                          '11-dummy.netdev')
        start_networkd()

        # With ConfigureWithoutCarrier=yes, the bridge should remain configured for all these situations
        for test in ['no-slave', 'add-slave', 'slave-up', 'slave-no-carrier', 'slave-carrier', 'slave-down']:
            with self.subTest(test=test):
                if test == 'no-slave':
                    # bridge has no slaves; it's up but *might* not have carrier
                    self.wait_operstate('bridge99', operstate=r'(no-carrier|routable)', setup_state=None, setup_timeout=30)
                    # due to a bug in the kernel, newly-created bridges are brought up
                    # *with* carrier, unless they have had any setting changed; e.g.
                    # their mac set, priority set, etc.  Then, they will lose carrier
                    # as soon as a (down) slave interface is added, and regain carrier
                    # again once the slave interface is brought up.
                    #self.check_link_attr('bridge99', 'carrier', '0')
                elif test == 'add-slave':
                    # add slave to bridge, but leave it down; bridge is definitely no-carrier
                    self.check_link_attr('test1', 'operstate', 'down')
                    check_output('ip link set dev test1 master bridge99')
                    self.wait_operstate('bridge99', operstate='no-carrier', setup_state=None)
                    self.check_link_attr('bridge99', 'carrier', '0')
                elif test == 'slave-up':
                    # bring up slave, which will have carrier; bridge gains carrier
                    check_output('ip link set dev test1 up')
                    self.wait_online('bridge99:routable')
                    self.check_link_attr('bridge99', 'carrier', '1')
                elif test == 'slave-no-carrier':
                    # drop slave carrier; bridge loses carrier
                    check_output('ip link set dev test1 carrier off')
                    self.wait_online('bridge99:no-carrier:no-carrier')
                    self.check_link_attr('bridge99', 'carrier', '0')
                elif test == 'slave-carrier':
                    # restore slave carrier; bridge gains carrier
                    check_output('ip link set dev test1 carrier on')
                    self.wait_online('bridge99:routable')
                    self.check_link_attr('bridge99', 'carrier', '1')
                elif test == 'slave-down':
                    # bring down slave; bridge loses carrier
                    check_output('ip link set dev test1 down')
                    self.wait_online('bridge99:no-carrier:no-carrier')
                    self.check_link_attr('bridge99', 'carrier', '0')

                output = networkctl_status('bridge99')
                self.assertRegex(output, '10.1.2.3')
                self.assertRegex(output, '10.1.2.1')

    def test_bridge_ignore_carrier_loss(self):
        copy_network_unit('11-dummy.netdev', '12-dummy.netdev', '26-bridge.netdev',
                          '26-bridge-slave-interface-1.network', '26-bridge-slave-interface-2.network',
                          '25-bridge99-ignore-carrier-loss.network')
        start_networkd()
        self.wait_online('dummy98:enslaved', 'test1:enslaved', 'bridge99:routable')

        check_output('ip address add 192.168.0.16/24 dev bridge99')
        remove_link('test1', 'dummy98')
        time.sleep(3)

        output = check_output('ip address show bridge99')
        print(output)
        self.assertRegex(output, 'NO-CARRIER')
        self.assertRegex(output, 'inet 192.168.0.15/24 brd 192.168.0.255 scope global bridge99')
        self.assertRegex(output, 'inet 192.168.0.16/24 scope global secondary bridge99')

    def test_bridge_ignore_carrier_loss_frequent_loss_and_gain(self):
        copy_network_unit('26-bridge.netdev', '26-bridge-slave-interface-1.network',
                          '25-bridge99-ignore-carrier-loss.network')
        start_networkd()
        self.wait_online('bridge99:no-carrier')

        for trial in range(4):
            check_output('ip link add dummy98 type dummy')
            check_output('ip link set dummy98 up')
            if trial < 3:
                remove_link('dummy98')

        self.wait_online('bridge99:routable', 'dummy98:enslaved')

        output = check_output('ip address show bridge99')
        print(output)
        self.assertRegex(output, 'inet 192.168.0.15/24 brd 192.168.0.255 scope global bridge99')

        output = check_output('ip rule list table 100')
        print(output)
        self.assertIn('from all to 8.8.8.8 lookup 100', output)

class NetworkdSRIOVTests(unittest.TestCase, Utilities):

    def setUp(self):
        setup_common()

    def tearDown(self):
        tear_down_common()

    def setup_netdevsim(self, id=99, num_ports=1, num_vfs=0):
        call('modprobe netdevsim')

        # Create netdevsim device.
        with open('/sys/bus/netdevsim/new_device', mode='w', encoding='utf-8') as f:
            f.write(f'{id} {num_ports}')

        # Create VF.
        if num_vfs > 0:
            with open(f'/sys/bus/netdevsim/devices/netdevsim{id}/sriov_numvfs', mode='w', encoding='utf-8') as f:
                f.write(f'{num_vfs}')

    @expectedFailureIfNetdevsimWithSRIOVIsNotAvailable()
    def test_sriov(self):
        copy_network_unit('25-netdevsim.link', '25-sriov.network')

        self.setup_netdevsim(num_vfs=3)

        start_networkd()
        self.wait_online('sim99:routable')

        output = check_output('ip link show dev sim99')
        print(output)
        self.assertRegex(output,
                         'vf 0 .*00:11:22:33:44:55.*vlan 5, qos 1, vlan protocol 802.1ad, spoof checking on, link-state enable, trust on, query_rss on\n *'
                         'vf 1 .*00:11:22:33:44:56.*vlan 6, qos 2, spoof checking off, link-state disable, trust off, query_rss off\n *'
                         'vf 2 .*00:11:22:33:44:57.*vlan 7, qos 3, spoof checking off, link-state auto, trust off, query_rss off'
                         )

    @expectedFailureIfNetdevsimWithSRIOVIsNotAvailable()
    def test_sriov_udev(self):
        copy_network_unit('25-sriov.link', '25-sriov-udev.network')

        self.setup_netdevsim()

        start_networkd()
        self.wait_online('sim99:routable')

        # The name sim99 is an alternative name, and cannot be used by udevadm below.
        ifname = link_resolve('sim99')

        output = check_output('ip link show dev sim99')
        print(output)
        self.assertRegex(output,
                         'vf 0 .*00:11:22:33:44:55.*vlan 5, qos 1, vlan protocol 802.1ad, spoof checking on, link-state enable, trust on, query_rss on\n *'
                         'vf 1 .*00:11:22:33:44:56.*vlan 6, qos 2, spoof checking off, link-state disable, trust off, query_rss off\n *'
                         'vf 2 .*00:11:22:33:44:57.*vlan 7, qos 3, spoof checking off, link-state auto, trust off, query_rss off'
                         )
        self.assertNotIn('vf 3', output)
        self.assertNotIn('vf 4', output)

        with open(os.path.join(network_unit_dir, '25-sriov.link'), mode='a', encoding='utf-8') as f:
            f.write('[Link]\nSR-IOVVirtualFunctions=4\n')

        udevadm_reload()
        udevadm_trigger(f'/sys/devices/netdevsim99/net/{ifname}')

        output = check_output('ip link show dev sim99')
        print(output)
        self.assertRegex(output,
                         'vf 0 .*00:11:22:33:44:55.*vlan 5, qos 1, vlan protocol 802.1ad, spoof checking on, link-state enable, trust on, query_rss on\n *'
                         'vf 1 .*00:11:22:33:44:56.*vlan 6, qos 2, spoof checking off, link-state disable, trust off, query_rss off\n *'
                         'vf 2 .*00:11:22:33:44:57.*vlan 7, qos 3, spoof checking off, link-state auto, trust off, query_rss off\n *'
                         'vf 3'
                         )
        self.assertNotIn('vf 4', output)

        with open(os.path.join(network_unit_dir, '25-sriov.link'), mode='a', encoding='utf-8') as f:
            f.write('[Link]\nSR-IOVVirtualFunctions=\n')

        udevadm_reload()
        udevadm_trigger(f'/sys/devices/netdevsim99/net/{ifname}')

        output = check_output('ip link show dev sim99')
        print(output)
        self.assertRegex(output,
                         'vf 0 .*00:11:22:33:44:55.*vlan 5, qos 1, vlan protocol 802.1ad, spoof checking on, link-state enable, trust on, query_rss on\n *'
                         'vf 1 .*00:11:22:33:44:56.*vlan 6, qos 2, spoof checking off, link-state disable, trust off, query_rss off\n *'
                         'vf 2 .*00:11:22:33:44:57.*vlan 7, qos 3, spoof checking off, link-state auto, trust off, query_rss off\n *'
                         'vf 3'
                         )
        self.assertNotIn('vf 4', output)

        with open(os.path.join(network_unit_dir, '25-sriov.link'), mode='a', encoding='utf-8') as f:
            f.write('[Link]\nSR-IOVVirtualFunctions=2\n')

        udevadm_reload()
        udevadm_trigger(f'/sys/devices/netdevsim99/net/{ifname}')

        output = check_output('ip link show dev sim99')
        print(output)
        self.assertRegex(output,
                         'vf 0 .*00:11:22:33:44:55.*vlan 5, qos 1, vlan protocol 802.1ad, spoof checking on, link-state enable, trust on, query_rss on\n *'
                         'vf 1 .*00:11:22:33:44:56.*vlan 6, qos 2, spoof checking off, link-state disable, trust off, query_rss off'
                         )
        self.assertNotIn('vf 2', output)
        self.assertNotIn('vf 3', output)
        self.assertNotIn('vf 4', output)

        with open(os.path.join(network_unit_dir, '25-sriov.link'), mode='a', encoding='utf-8') as f:
            f.write('[Link]\nSR-IOVVirtualFunctions=\n')

        udevadm_reload()
        udevadm_trigger(f'/sys/devices/netdevsim99/net/{ifname}')

        output = check_output('ip link show dev sim99')
        print(output)
        self.assertRegex(output,
                         'vf 0 .*00:11:22:33:44:55.*vlan 5, qos 1, vlan protocol 802.1ad, spoof checking on, link-state enable, trust on, query_rss on\n *'
                         'vf 1 .*00:11:22:33:44:56.*vlan 6, qos 2, spoof checking off, link-state disable, trust off, query_rss off\n *'
                         'vf 2 .*00:11:22:33:44:57.*vlan 7, qos 3, spoof checking off, link-state auto, trust off, query_rss off'
                         )
        self.assertNotIn('vf 3', output)
        self.assertNotIn('vf 4', output)

class NetworkdLLDPTests(unittest.TestCase, Utilities):

    def setUp(self):
        setup_common()

    def tearDown(self):
        tear_down_common()

    def test_lldp(self):
        copy_network_unit('23-emit-lldp.network', '24-lldp.network', '25-veth.netdev')
        start_networkd()
        self.wait_online('veth99:degraded', 'veth-peer:degraded')

        for _ in range(20):
            output = networkctl('lldp')
            print(output)
            if re.search(r'veth99 .* veth-peer .* .......a...', output):
                break
            time.sleep(0.5)
        else:
            self.fail()

        # With interface name
        output = networkctl('lldp', 'veth99');
        print(output)
        self.assertRegex(output, r'veth99 .* veth-peer .* .......a...')

        # With interface name pattern
        output = networkctl('lldp', 've*9');
        print(output)
        self.assertRegex(output, r'veth99 .* veth-peer .* .......a...')

        # json format
        output = networkctl('--json=short', 'lldp')
        print(output)
        self.assertIn('"InterfaceName":"veth99"', output)
        self.assertIn('"PortID":"veth-peer"', output)
        self.assertIn('"EnabledCapabilities":128', output)

        # json format with interface name
        output = networkctl('--json=short', 'lldp', 'veth99')
        print(output)
        self.assertIn('"InterfaceName":"veth99"', output)
        self.assertIn('"PortID":"veth-peer"', output)
        self.assertIn('"EnabledCapabilities":128', output)

        # json format with interface name pattern
        output = networkctl('--json=short', 'lldp', 've*9')
        print(output)
        self.assertIn('"InterfaceName":"veth99"', output)
        self.assertIn('"PortID":"veth-peer"', output)
        self.assertIn('"EnabledCapabilities":128', output)

        # LLDP neighbors in status
        output = networkctl_status('veth99')
        print(output)
        self.assertRegex(output, r'Connected To: .* on port veth-peer')

        # enable forwarding, to enable the Router flag
        with open(os.path.join(network_unit_dir, '23-emit-lldp.network'), mode='a', encoding='utf-8') as f:
            f.write('[Network]\nIPv4Forwarding=yes\n')

        networkctl_reload()
        self.wait_online('veth-peer:degraded')

        for _ in range(20):
            output = networkctl('lldp')
            print(output)
            if re.search(r'veth99 .* veth-peer .* ....r......', output):
                break
            time.sleep(0.5)
        else:
            self.fail()

        # With interface name
        output = networkctl('lldp', 'veth99');
        print(output)
        self.assertRegex(output, r'veth99 .* veth-peer .* ....r......')

        # With interface name pattern
        output = networkctl('lldp', 've*9');
        print(output)
        self.assertRegex(output, r'veth99 .* veth-peer .* ....r......')

        # json format
        output = networkctl('--json=short', 'lldp')
        print(output)
        self.assertIn('"InterfaceName":"veth99"', output)
        self.assertIn('"PortID":"veth-peer"', output)
        self.assertIn('"EnabledCapabilities":16', output)

        # json format with interface name
        output = networkctl('--json=short', 'lldp', 'veth99')
        print(output)
        self.assertIn('"InterfaceName":"veth99"', output)
        self.assertIn('"PortID":"veth-peer"', output)
        self.assertIn('"EnabledCapabilities":16', output)

        # json format with interface name pattern
        output = networkctl('--json=short', 'lldp', 've*9')
        print(output)
        self.assertIn('"InterfaceName":"veth99"', output)
        self.assertIn('"PortID":"veth-peer"', output)
        self.assertIn('"EnabledCapabilities":16', output)

        # LLDP neighbors in status
        output = networkctl_status('veth99')
        print(output)
        self.assertRegex(output, r'Connected To: .* on port veth-peer')

class NetworkdRATests(unittest.TestCase, Utilities):

    def setUp(self):
        setup_common()

    def tearDown(self):
        tear_down_common()

    def test_ipv6_prefix_delegation(self):
        copy_network_unit('25-veth.netdev', '25-ipv6-prefix.network', '25-ipv6-prefix-veth.network')
        self.setup_nftset('addr6', 'ipv6_addr')
        self.setup_nftset('network6', 'ipv6_addr', 'flags interval;')
        self.setup_nftset('ifindex', 'iface_index')
        start_networkd()
        self.wait_online('veth99:routable', 'veth-peer:degraded')

        # IPv6SendRA=yes implies IPv6Forwarding.
        self.check_ipv6_sysctl_attr('veth-peer', 'forwarding', '1')

        output = resolvectl('dns', 'veth99')
        print(output)
        self.assertRegex(output, 'fe80::')
        self.assertRegex(output, '2002:da8:1::1')

        output = resolvectl('domain', 'veth99')
        print(output)
        self.assertIn('hogehoge.test', output)

        output = networkctl_status('veth99')
        print(output)
        self.assertRegex(output, '2002:da8:1:0')

        self.check_ipv6_neigh_sysctl_attr('veth99', 'base_reachable_time_ms', '42000')
        self.check_ipv6_neigh_sysctl_attr('veth99', 'retrans_time_ms', '500')

        self.check_netlabel('veth99', '2002:da8:1::/64')
        self.check_netlabel('veth99', '2002:da8:2::/64')

        self.check_nftset('addr6', '2002:da8:1:[0-9a-f]*:[0-9a-f]*:[0-9a-f]*:[0-9a-f]*:[0-9a-f]*')
        self.check_nftset('addr6', '2002:da8:2:[0-9a-f]*:[0-9a-f]*:[0-9a-f]*:[0-9a-f]*:[0-9a-f]*')
        self.check_nftset('network6', '2002:da8:1::/64')
        self.check_nftset('network6', '2002:da8:2::/64')
        self.check_nftset('ifindex', 'veth99')

        self.teardown_nftset('addr6', 'network6', 'ifindex')

    def check_ipv6_token_static(self):
        self.wait_online('veth99:routable', 'veth-peer:degraded')

        output = networkctl_status('veth99')
        print(output)
        self.assertRegex(output, '2002:da8:1:0:1a:2b:3c:4d')
        self.assertRegex(output, '2002:da8:1:0:fa:de:ca:fe')
        self.assertRegex(output, '2002:da8:2:0:1a:2b:3c:4d')
        self.assertRegex(output, '2002:da8:2:0:fa:de:ca:fe')

    def test_ipv6_token_static(self):
        copy_network_unit('25-veth.netdev', '25-ipv6-prefix.network', '25-ipv6-prefix-veth-token-static.network')
        start_networkd()

        self.check_ipv6_token_static()

        for _ in range(20):
            check_output('ip link set veth99 down')
            check_output('ip link set veth99 up')

        self.check_ipv6_token_static()

        for _ in range(20):
            check_output('ip link set veth99 down')
            time.sleep(random.uniform(0, 0.1))
            check_output('ip link set veth99 up')
            time.sleep(random.uniform(0, 0.1))

        self.check_ipv6_token_static()

    def test_ndisc_redirect(self):
        if not os.path.exists(test_ndisc_send):
            self.skipTest(f"{test_ndisc_send} does not exist.")

        copy_network_unit('25-veth.netdev', '25-ipv6-prefix.network', '25-ipv6-prefix-veth-token-static.network')
        start_networkd()

        self.check_ipv6_token_static()

        # Introduce three redirect routes.
        check_output(f'{test_ndisc_send} --interface veth-peer --type redirect --target-address 2002:da8:1:1:1a:2b:3c:4d --redirect-destination 2002:da8:1:1:1a:2b:3c:4d')
        check_output(f'{test_ndisc_send} --interface veth-peer --type redirect --target-address 2002:da8:1:2:1a:2b:3c:4d --redirect-destination 2002:da8:1:2:1a:2b:3c:4d')
        check_output(f'{test_ndisc_send} --interface veth-peer --type redirect --target-address 2002:da8:1:3:1a:2b:3c:4d --redirect-destination 2002:da8:1:3:1a:2b:3c:4d')
        self.wait_route('veth99', '2002:da8:1:1:1a:2b:3c:4d proto redirect', ipv='-6', timeout_sec=10)
        self.wait_route('veth99', '2002:da8:1:2:1a:2b:3c:4d proto redirect', ipv='-6', timeout_sec=10)
        self.wait_route('veth99', '2002:da8:1:3:1a:2b:3c:4d proto redirect', ipv='-6', timeout_sec=10)

        # Change the target address of the redirects.
        check_output(f'{test_ndisc_send} --interface veth-peer --type redirect --target-address fe80::1 --redirect-destination 2002:da8:1:1:1a:2b:3c:4d')
        check_output(f'{test_ndisc_send} --interface veth-peer --type redirect --target-address fe80::2 --redirect-destination 2002:da8:1:2:1a:2b:3c:4d')
        self.wait_route_dropped('veth99', '2002:da8:1:1:1a:2b:3c:4d proto redirect', ipv='-6', timeout_sec=10)
        self.wait_route_dropped('veth99', '2002:da8:1:2:1a:2b:3c:4d proto redirect', ipv='-6', timeout_sec=10)
        self.wait_route('veth99', r'2002:da8:1:1:1a:2b:3c:4d nhid [0-9]* via fe80::1 proto redirect', ipv='-6', timeout_sec=10)
        self.wait_route('veth99', r'2002:da8:1:2:1a:2b:3c:4d nhid [0-9]* via fe80::2 proto redirect', ipv='-6', timeout_sec=10)

        # Send Neighbor Advertisement without the router flag to announce the default router is not available anymore.
        # Then, verify that all redirect routes and the default route are dropped.
        output = check_output('ip -6 address show dev veth-peer scope link')
        veth_peer_ipv6ll = re.search('fe80:[:0-9a-f]*', output).group()
        print(f'veth-peer IPv6LL address: {veth_peer_ipv6ll}')
        check_output(f'{test_ndisc_send} --interface veth-peer --type neighbor-advertisement --target-address {veth_peer_ipv6ll} --is-router no')
        self.wait_route_dropped('veth99', 'proto ra', ipv='-6', timeout_sec=10)
        self.wait_route_dropped('veth99', 'proto redirect', ipv='-6', timeout_sec=10)

        # Check if sd-radv refuses RS from the same interface.
        # See https://github.com/systemd/systemd/pull/32267#discussion_r1566721306
        since = datetime.datetime.now()
        check_output(f'{test_ndisc_send} --interface veth-peer --type rs --dest {veth_peer_ipv6ll}')
        self.check_networkd_log('veth-peer: RADV: Received RS from the same interface, ignoring.', since=since)

    def check_ndisc_mtu(self, mtu):
        for _ in range(20):
            output = read_ipv6_sysctl_attr('veth99', 'mtu')
            if output == f'{mtu}':
                break
            time.sleep(0.5)
        else:
            self.fail(f'IPv6 MTU does not matches: value={output}, expected={mtu}')

    def test_ndisc_mtu(self):
        if not os.path.exists(test_ndisc_send):
            self.skipTest(f"{test_ndisc_send} does not exist.")

        copy_network_unit('25-veth.netdev',
                          '25-veth-peer-no-address.network',
                          '25-ipv6-prefix-veth-token-static.network')
        start_networkd()
        self.wait_online('veth-peer:degraded')

        self.check_networkd_log('veth99: NDISC: Started IPv6 Router Solicitation client')

        check_output(f'{test_ndisc_send} --interface veth-peer --type ra --lifetime 1hour --mtu 1400')
        self.check_ndisc_mtu(1400)

        check_output(f'{test_ndisc_send} --interface veth-peer --type ra --lifetime 1hour --mtu 1410')
        self.check_ndisc_mtu(1410)

        check_output('ip link set dev veth99 mtu 1600')
        check_output('ip link set dev veth-peer mtu 1600')
        self.check_ndisc_mtu(1410)

        check_output(f'{test_ndisc_send} --interface veth-peer --type ra --lifetime 1hour --mtu 1700')
        self.check_ndisc_mtu(1600)

        check_output('ip link set dev veth99 mtu 1800')
        check_output('ip link set dev veth-peer mtu 1800')
        self.check_ndisc_mtu(1700)

    def test_ipv6_token_prefixstable(self):
        copy_network_unit('25-veth.netdev', '25-ipv6-prefix.network', '25-ipv6-prefix-veth-token-prefixstable.network')
        start_networkd()
        self.wait_online('veth99:routable', 'veth-peer:degraded')

        output = check_output('ip -6 address show dev veth99')
        print(output)
        self.assertIn('2002:da8:1:0:b47e:7975:fc7a:7d6e/64', output) # the 1st prefixstable
        self.assertIn('2002:da8:2:0:1034:56ff:fe78:9abc/64', output) # EUI64

        with open(os.path.join(network_unit_dir, '25-ipv6-prefix-veth-token-prefixstable.network'), mode='a', encoding='utf-8') as f:
            f.write('\n[IPv6AcceptRA]\nPrefixAllowList=2002:da8:1:0::/64\n')

        networkctl_reload()
        self.wait_online('veth99:routable')

        output = check_output('ip -6 address show dev veth99')
        print(output)
        self.assertIn('2002:da8:1:0:b47e:7975:fc7a:7d6e/64', output) # the 1st prefixstable
        self.assertNotIn('2002:da8:2:0:1034:56ff:fe78:9abc/64', output) # EUI64

        check_output('ip address del 2002:da8:1:0:b47e:7975:fc7a:7d6e/64 dev veth99')
        check_output('ip address add 2002:da8:1:0:b47e:7975:fc7a:7d6e/64 dev veth-peer nodad')

        networkctl_reconfigure('veth99')
        self.wait_online('veth99:routable')
        self.wait_address('veth99', '2002:da8:1:0:da5d:e50a:43fd:5d0f/64', ipv='-6', timeout_sec=10) # the 2nd prefixstable
        self.wait_address_dropped('veth99', '2002:da8:1:0:b47e:7975:fc7a:7d6e/64', ipv='-6', timeout_sec=10) # the 1st prefixstable

        check_output('ip address del 2002:da8:1:0:da5d:e50a:43fd:5d0f/64 dev veth99')
        check_output('ip address add 2002:da8:1:0:da5d:e50a:43fd:5d0f/64 dev veth-peer nodad')

        networkctl_reconfigure('veth99')
        self.wait_online('veth99:routable')
        self.wait_address('veth99', '2002:da8:1:0:c7e4:77ec:eb31:1b0d/64', ipv='-6', timeout_sec=10) # the 3rd prefixstable
        self.wait_address_dropped('veth99', '2002:da8:1:0:da5d:e50a:43fd:5d0f/64', ipv='-6', timeout_sec=10) # the 2nd prefixstable
        self.wait_address_dropped('veth99', '2002:da8:1:0:b47e:7975:fc7a:7d6e/64', ipv='-6', timeout_sec=10) # the 1st prefixstable

    def test_ipv6_token_prefixstable_without_address(self):
        copy_network_unit('25-veth.netdev', '25-ipv6-prefix.network', '25-ipv6-prefix-veth-token-prefixstable-without-address.network')
        start_networkd()
        self.wait_online('veth99:routable', 'veth-peer:degraded')

        output = networkctl_status('veth99')
        print(output)
        self.assertIn('2002:da8:1:0:b47e:7975:fc7a:7d6e', output)
        self.assertIn('2002:da8:2:0:f689:561a:8eda:7443', output)

    def test_router_hop_limit(self):
        copy_network_unit('25-veth-client.netdev',
                          '25-veth-router.netdev',
                          '26-bridge.netdev',
                          '25-veth-bridge.network',
                          '25-veth-client.network',
                          '25-veth-router-hop-limit.network',
                          '25-bridge99.network')
        start_networkd()
        self.wait_online('client:routable', 'client-p:enslaved',
                         'router:degraded', 'router-p:enslaved',
                         'bridge99:routable')

        self.check_ipv6_sysctl_attr('client', 'hop_limit', '42')

        with open(os.path.join(network_unit_dir, '25-veth-router-hop-limit.network'), mode='a', encoding='utf-8') as f:
            f.write('\n[IPv6SendRA]\nHopLimit=43\n')

        networkctl_reload()

        for _ in range(20):
            output = read_ipv6_sysctl_attr('client', 'hop_limit')
            if output == '43':
                break
            time.sleep(0.5)

        self.check_ipv6_sysctl_attr('client', 'hop_limit', '43')

    def check_router_preference(self, suffix, metric_1, preference_1, metric_2, preference_2):
        self.wait_online('client:routable')
        self.wait_address('client', f'2002:da8:1:99:1034:56ff:fe78:9a{suffix}/64', ipv='-6', timeout_sec=10)
        self.wait_address('client', f'2002:da8:1:98:1034:56ff:fe78:9a{suffix}/64', ipv='-6', timeout_sec=10)
        self.wait_route('client', rf'default nhid [0-9]* via fe80::1034:56ff:fe78:9a99 proto ra metric {metric_1}', ipv='-6', timeout_sec=10)
        self.wait_route('client', rf'default nhid [0-9]* via fe80::1034:56ff:fe78:9a98 proto ra metric {metric_2}', ipv='-6', timeout_sec=10)

        print('### ip -6 route show dev client default')
        output = check_output('ip -6 route show dev client default')
        print(output)
        self.assertRegex(output, rf'default nhid [0-9]* via fe80::1034:56ff:fe78:9a99 proto ra metric {metric_1} expires [0-9]*sec pref {preference_1}')
        self.assertRegex(output, rf'default nhid [0-9]* via fe80::1034:56ff:fe78:9a98 proto ra metric {metric_2} expires [0-9]*sec pref {preference_2}')

        for i in [100, 200, 300, 512, 1024, 2048]:
            if i not in [metric_1, metric_2]:
                self.assertNotIn(f'metric {i} ', output)

        for i in ['low', 'medium', 'high']:
            if i not in [preference_1, preference_2]:
                self.assertNotIn(f'pref {i}', output)

    def test_router_preference(self):
        copy_network_unit('25-veth-client.netdev',
                          '25-veth-router-high.netdev',
                          '25-veth-router-low.netdev',
                          '26-bridge.netdev',
                          '25-veth-bridge.network',
                          '25-veth-client.network',
                          '25-veth-router-high.network',
                          '25-veth-router-low.network',
                          '25-bridge99.network')
        start_networkd()
        self.wait_online('client-p:enslaved',
                         'router-high:degraded', 'router-high-p:enslaved',
                         'router-low:degraded', 'router-low-p:enslaved',
                         'bridge99:routable')

        networkctl_reconfigure('client')
        self.wait_online('client:routable')
        self.check_router_preference('00', 512, 'high', 2048, 'low')

        # change the map from preference to metric.
        with open(os.path.join(network_unit_dir, '25-veth-client.network'), mode='a', encoding='utf-8') as f:
            f.write('\n[Link]\nMACAddress=12:34:56:78:9a:01\n[IPv6AcceptRA]\nRouteMetric=100:200:300\n')
        networkctl_reload()
        self.check_router_preference('01', 100, 'high', 300, 'low')

        # swap the preference (for issue #28439)
        with open(os.path.join(network_unit_dir, '25-veth-router-high.network'), mode='a', encoding='utf-8') as f:
            f.write('\n[IPv6SendRA]\nRouterPreference=low\n')
        with open(os.path.join(network_unit_dir, '25-veth-router-low.network'), mode='a', encoding='utf-8') as f:
            f.write('\n[IPv6SendRA]\nRouterPreference=high\n')
        networkctl_reload()
        self.check_router_preference('01', 300, 'low', 100, 'high')

        # Use the same preference, and check if the two routes are not coalesced. See issue #33470.
        with open(os.path.join(network_unit_dir, '25-veth-router-high.network'), mode='a', encoding='utf-8') as f:
            f.write('\n[IPv6SendRA]\nRouterPreference=medium\n')
        with open(os.path.join(network_unit_dir, '25-veth-router-low.network'), mode='a', encoding='utf-8') as f:
            f.write('\n[IPv6SendRA]\nRouterPreference=medium\n')
        networkctl_reload()
        self.check_router_preference('01', 200, 'medium', 200, 'medium')

        # Use route options to configure default routes.
        # The preference specified in the RA header should be ignored. See issue #33468.
        with open(os.path.join(network_unit_dir, '25-veth-router-high.network'), mode='a', encoding='utf-8') as f:
            f.write('\n[IPv6SendRA]\nRouterPreference=high\n[IPv6RoutePrefix]\nRoute=::/0\nLifetimeSec=1200\n')
        with open(os.path.join(network_unit_dir, '25-veth-router-low.network'), mode='a', encoding='utf-8') as f:
            f.write('\n[IPv6SendRA]\nRouterPreference=low\n[IPv6RoutePrefix]\nRoute=::/0\nLifetimeSec=1200\n')
        networkctl_reload()
        self.check_router_preference('01', 200, 'medium', 200, 'medium')

        # Set zero lifetime to the route options.
        # The preference specified in the RA header should be used.
        with open(os.path.join(network_unit_dir, '25-veth-router-high.network'), mode='a', encoding='utf-8') as f:
            f.write('LifetimeSec=0\n')
        with open(os.path.join(network_unit_dir, '25-veth-router-low.network'), mode='a', encoding='utf-8') as f:
            f.write('LifetimeSec=0\n')
        networkctl_reload()
        self.check_router_preference('01', 100, 'high', 300, 'low')

        # Use route options with preference to configure default routes.
        with open(os.path.join(network_unit_dir, '25-veth-router-high.network'), mode='a', encoding='utf-8') as f:
            f.write('LifetimeSec=1200\nPreference=low\n')
        with open(os.path.join(network_unit_dir, '25-veth-router-low.network'), mode='a', encoding='utf-8') as f:
            f.write('LifetimeSec=1200\nPreference=high\n')
        networkctl_reload()
        self.check_router_preference('01', 300, 'low', 100, 'high')

        # Set zero lifetime again to the route options.
        with open(os.path.join(network_unit_dir, '25-veth-router-high.network'), mode='a', encoding='utf-8') as f:
            f.write('LifetimeSec=0\n')
        with open(os.path.join(network_unit_dir, '25-veth-router-low.network'), mode='a', encoding='utf-8') as f:
            f.write('LifetimeSec=0\n')
        networkctl_reload()
        self.check_router_preference('01', 100, 'high', 300, 'low')

    def _test_ndisc_vs_static_route(self, manage_foreign_nexthops):
        if not manage_foreign_nexthops:
            copy_networkd_conf_dropin('networkd-manage-foreign-nexthops-no.conf')
        copy_network_unit('25-veth.netdev', '25-ipv6-prefix.network', '25-ipv6-prefix-veth-static-route.network')
        start_networkd()
        self.wait_online('veth99:routable', 'veth-peer:degraded')

        # If a conflicting static route is already configured, do not override the static route.
        print('### ip -6 route show dev veth99 default')
        output = check_output('ip -6 route show dev veth99 default')
        print(output)
        self.assertIn('via fe80::1034:56ff:fe78:9abd proto static metric 256 pref medium', output)
        if manage_foreign_nexthops:
            self.assertRegex(output, r'default nhid [0-9]* via fe80::1034:56ff:fe78:9abd proto ra metric 256 expires [0-9]*sec pref medium')
        else:
            self.assertNotIn('proto ra', output)

        print('### ip -6 nexthop show dev veth99')
        output = check_output('ip -6 nexthop show dev veth99')
        print(output)
        if manage_foreign_nexthops:
            self.assertRegex(output, r'id [0-9]* via fe80::1034:56ff:fe78:9abd dev veth99 scope link proto ra')
        else:
            self.assertEqual(output, '')

        # Also check if the static route is protected from RA with zero lifetime
        with open(os.path.join(network_unit_dir, '25-ipv6-prefix.network'), mode='a', encoding='utf-8') as f:
            f.write('\n[Network]\nIPv6SendRA=no\n')
        networkctl_reload() # This makes veth-peer being reconfigured, and send RA with zero lifetime
        self.wait_route_dropped('veth99', r'default (nhid [0-9]* |)via fe80::1034:56ff:fe78:9abd proto ra metric 256', ipv='-6', timeout_sec=10)

        print('### ip -6 route show dev veth99 default')
        output = check_output('ip -6 route show dev veth99 default')
        print(output)
        self.assertIn('via fe80::1034:56ff:fe78:9abd proto static metric 256 pref medium', output)
        self.assertNotIn('proto ra', output)

        # Check if nexthop is removed.
        print('### ip -6 nexthop show dev veth99')
        output = check_output('ip -6 nexthop show dev veth99')
        print(output)
        self.assertEqual(output, '')

    def test_ndisc_vs_static_route(self):
        first = True
        for manage_foreign_nexthops in [True, False]:
            if first:
                first = False
            else:
                self.tearDown()

            print(f'### test_ndisc_vs_static_route(manage_foreign_nexthops={manage_foreign_nexthops})')
            with self.subTest(manage_foreign_nexthops=manage_foreign_nexthops):
                self._test_ndisc_vs_static_route(manage_foreign_nexthops)

    # radvd supports captive portal since v2.20.
    # https://github.com/radvd-project/radvd/commit/791179a7f730decbddb2290ef0e34aa85d71b1bc
    @unittest.skipUnless(radvd_check_config('captive-portal.conf'), "Installed radvd doesn't support captive portals")
    def test_captive_portal(self):
        copy_network_unit('25-veth-client.netdev',
                          '25-veth-router-captive.netdev',
                          '26-bridge.netdev',
                          '25-veth-client-captive.network',
                          '25-veth-router-captive.network',
                          '25-veth-bridge-captive.network',
                          '25-bridge99.network')
        start_networkd()
        self.wait_online('bridge99:routable', 'client-p:enslaved',
                          'router-captive:degraded', 'router-captivep:enslaved')

        start_radvd(config_file='captive-portal.conf')
        networkctl_reconfigure('client')
        self.wait_online('client:routable')

        self.wait_address('client', '2002:da8:1:99:1034:56ff:fe78:9a00/64', ipv='-6', timeout_sec=10)
        output = networkctl_status('client')
        print(output)
        self.assertIn('Captive Portal: http://systemd.io', output)

    @unittest.skipUnless(radvd_check_config('captive-portal.conf'), "Installed radvd doesn't support captive portals")
    def test_invalid_captive_portal(self):
        def radvd_write_config(captive_portal_uri):
            with open(os.path.join(networkd_ci_temp_dir, 'radvd/bogus-captive-portal.conf'), mode='w', encoding='utf-8') as f:
                f.write(f'interface router-captive {{ AdvSendAdvert on; AdvCaptivePortalAPI "{captive_portal_uri}"; prefix 2002:da8:1:99::/64 {{ AdvOnLink on; AdvAutonomous on; }}; }};')

        captive_portal_uris = [
            "42ěščěškd ěšč ě s",
            "                 ",
            "🤔",
        ]

        copy_network_unit('25-veth-client.netdev',
                          '25-veth-router-captive.netdev',
                          '26-bridge.netdev',
                          '25-veth-client-captive.network',
                          '25-veth-router-captive.network',
                          '25-veth-bridge-captive.network',
                          '25-bridge99.network')
        start_networkd()
        self.wait_online('bridge99:routable', 'client-p:enslaved',
                         'router-captive:degraded', 'router-captivep:enslaved')

        for uri in captive_portal_uris:
            print(f"Captive portal: {uri}")
            radvd_write_config(uri)
            stop_radvd()
            start_radvd(config_file='bogus-captive-portal.conf')
            networkctl_reconfigure('client')
            self.wait_online('client:routable')

            self.wait_address('client', '2002:da8:1:99:1034:56ff:fe78:9a00/64', ipv='-6', timeout_sec=10)
            output = networkctl_status('client')
            print(output)
            self.assertNotIn('Captive Portal:', output)

class NetworkdDHCPServerTests(unittest.TestCase, Utilities):

    def setUp(self):
        setup_common()

    def tearDown(self):
        tear_down_common()

    def check_dhcp_server(self, persist_leases=True):
        output = networkctl_status('veth99')
        print(output)
        self.assertRegex(output, r'Address: 192.168.5.[0-9]* \(DHCPv4 via 192.168.5.1\)')
        self.assertIn('Gateway: 192.168.5.3', output)
        self.assertRegex(output, 'DNS: 192.168.5.1\n *192.168.5.10')
        self.assertRegex(output, 'NTP: 192.168.5.1\n *192.168.5.11')

        output = networkctl_status('veth-peer')
        print(output)
        self.assertRegex(output, "Offered DHCP leases: 192.168.5.[0-9]*")

        if persist_leases:
            with open('/var/lib/systemd/network/dhcp-server-lease/veth-peer', encoding='utf-8') as f:
                check_json(f.read())
        else:
            self.assertFalse(os.path.exists('/var/lib/systemd/network/dhcp-server-lease/veth-peer'))

    def test_dhcp_server(self):
        copy_network_unit('25-veth.netdev', '25-dhcp-client.network', '25-dhcp-server.network')
        start_networkd()
        self.wait_online('veth99:routable', 'veth-peer:routable')

        self.check_dhcp_server()

        networkctl_reconfigure('veth-peer')
        self.wait_online('veth-peer:routable')

        for _ in range(10):
            output = check_output(*networkctl_cmd, '-n', '0', 'status', 'veth-peer', env=env)
            if 'Offered DHCP leases: 192.168.5.' in output:
                break
            time.sleep(.2)
        else:
            self.fail()

    def test_dhcp_server_persist_leases_no(self):
        copy_networkd_conf_dropin('persist-leases-no.conf')
        copy_network_unit('25-veth.netdev', '25-dhcp-client.network', '25-dhcp-server.network')
        start_networkd()
        self.wait_online('veth99:routable', 'veth-peer:routable')

        self.check_dhcp_server(persist_leases=False)

        remove_networkd_conf_dropin('persist-leases-no.conf')
        with open(os.path.join(network_unit_dir, '25-dhcp-server.network'), mode='a', encoding='utf-8') as f:
            f.write('[DHCPServer]\nPersistLeases=no')
        restart_networkd()
        self.wait_online('veth99:routable', 'veth-peer:routable')

        self.check_dhcp_server(persist_leases=False)

    def test_dhcp_server_null_server_address(self):
        copy_network_unit('25-veth.netdev', '25-dhcp-client.network', '25-dhcp-server-null-server-address.network')
        start_networkd()
        self.wait_online('veth99:routable', 'veth-peer:routable')

        output = check_output('ip --json address show dev veth-peer')
        server_address = json.loads(output)[0]['addr_info'][0]['local']
        print(server_address)

        output = check_output('ip --json address show dev veth99')
        client_address = json.loads(output)[0]['addr_info'][0]['local']
        print(client_address)

        output = networkctl_status('veth99')
        print(output)
        self.assertRegex(output, rf'Address: {client_address} \(DHCPv4 via {server_address}\)')
        self.assertIn(f'Gateway: {server_address}', output)
        self.assertIn(f'DNS: {server_address}', output)
        self.assertIn(f'NTP: {server_address}', output)

        output = networkctl_status('veth-peer')
        self.assertIn(f'Offered DHCP leases: {client_address}', output)

        # Check if the same addresses are used even if the service is restarted.
        restart_networkd()
        self.wait_online('veth99:routable', 'veth-peer:routable')

        output = check_output('ip -4 address show dev veth-peer')
        print(output)
        self.assertIn(f'{server_address}', output)

        output = check_output('ip -4 address show dev veth99')
        print(output)
        self.assertIn(f'{client_address}', output)

        output = networkctl_status('veth99')
        print(output)
        self.assertRegex(output, rf'Address: {client_address} \(DHCPv4 via {server_address}\)')
        self.assertIn(f'Gateway: {server_address}', output)
        self.assertIn(f'DNS: {server_address}', output)
        self.assertIn(f'NTP: {server_address}', output)

        output = networkctl_status('veth-peer')
        self.assertIn(f'Offered DHCP leases: {client_address}', output)

    def test_dhcp_server_with_uplink(self):
        copy_network_unit('25-veth.netdev', '25-dhcp-client.network', '25-dhcp-server-downstream.network',
                          '12-dummy.netdev', '25-dhcp-server-uplink.network')
        start_networkd()
        self.wait_online('veth99:routable', 'veth-peer:routable')

        output = networkctl_status('veth99')
        print(output)
        self.assertRegex(output, r'Address: 192.168.5.[0-9]* \(DHCPv4 via 192.168.5.1\)')
        self.assertIn('Gateway: 192.168.5.3', output)
        self.assertIn('DNS: 192.168.5.1', output)
        self.assertIn('NTP: 192.168.5.1', output)

    def test_emit_router_timezone(self):
        copy_network_unit('25-veth.netdev', '25-dhcp-client-timezone-router.network', '25-dhcp-server-timezone-router.network')
        start_networkd()
        self.wait_online('veth99:routable', 'veth-peer:routable')

        output = networkctl_status('veth99')
        print(output)
        self.assertRegex(output, r'Address: 192.168.5.[0-9]* \(DHCPv4 via 192.168.5.1\)')
        self.assertIn('Gateway: 192.168.5.1', output)
        self.assertIn('Time Zone: Europe/Berlin', output)

    def test_dhcp_server_static_lease_mac_by_network(self):
        copy_network_unit('25-veth.netdev', '25-dhcp-client-static-lease.network', '25-dhcp-server-static-lease.network')
        copy_networkd_conf_dropin('10-dhcp-client-id-duid.conf')
        start_networkd()
        self.wait_online('veth99:routable', 'veth-peer:routable')

        output = networkctl_status('veth99')
        print(output)
        self.assertIn('Address: 10.1.1.200 (DHCPv4 via 10.1.1.1)', output)
        self.assertIn('DHCPv4 Client ID: 12:34:56:78:9a:bc', output)

    def test_dhcp_server_static_lease_mac_by_global(self):
        copy_network_unit('25-veth.netdev', '25-dhcp-client.network', '25-dhcp-server-static-lease.network')
        copy_networkd_conf_dropin('10-dhcp-client-id-mac.conf')
        start_networkd()
        self.wait_online('veth99:routable', 'veth-peer:routable')

        output = networkctl_status('veth99')
        print(output)
        self.assertIn('Address: 10.1.1.200 (DHCPv4 via 10.1.1.1)', output)
        self.assertIn('DHCPv4 Client ID: 12:34:56:78:9a:bc', output)

    def test_dhcp_server_static_lease_duid(self):
        copy_network_unit('25-veth.netdev', '25-dhcp-client.network', '25-dhcp-server-static-lease.network')
        start_networkd()
        self.wait_online('veth99:routable', 'veth-peer:routable')

        output = networkctl_status('veth99')
        print(output)
        self.assertIn('Address: 10.1.1.200 (DHCPv4 via 10.1.1.1)', output)
        self.assertRegex(output, 'DHCPv4 Client ID: IAID:[0-9a-z]*/DUID')

class NetworkdDHCPServerRelayAgentTests(unittest.TestCase, Utilities):

    def setUp(self):
        setup_common()

    def tearDown(self):
        tear_down_common()

    def test_relay_agent(self):
        copy_network_unit('25-agent-veth-client.netdev',
                          '25-agent-veth-server.netdev',
                          '25-agent-client.network',
                          '25-agent-server.network',
                          '25-agent-client-peer.network',
                          '25-agent-server-peer.network')
        start_networkd()

        self.wait_online('client:routable')

        output = networkctl_status('client')
        print(output)
        self.assertRegex(output, r'Address: 192.168.5.150 \(DHCPv4 via 192.168.5.1\)')

    def test_relay_agent_on_bridge(self):
        copy_network_unit('25-agent-bridge.netdev',
                          '25-agent-veth-client.netdev',
                          '25-agent-bridge.network',
                          '25-agent-bridge-port.network',
                          '25-agent-client.network')
        start_networkd()
        self.wait_online('bridge-relay:routable', 'client-peer:enslaved')

        # For issue #30763.
        self.check_networkd_log('bridge-relay: DHCPv4 server: STARTED')

class NetworkdDHCPClientTests(unittest.TestCase, Utilities):

    def setUp(self):
        setup_common()

    def tearDown(self):
        tear_down_common()

    def test_dhcp_client_ipv6_only(self):
        copy_network_unit('25-veth.netdev', '25-dhcp-server-veth-peer.network', '25-dhcp-client-ipv6-only.network')

        start_networkd()
        self.wait_online('veth-peer:carrier')

        # information request mode
        # The name ipv6-only option may not be supported by older dnsmasq
        # start_dnsmasq('--dhcp-option=option:ipv6-only,300')
        start_dnsmasq('--dhcp-option=108,00:00:02:00',
                      '--dhcp-option=option6:dns-server,[2600::ee]',
                      '--dhcp-option=option6:ntp-server,[2600::ff]',
                      ra_mode='ra-stateless')
        self.wait_online('veth99:routable', 'veth-peer:routable')

        # DHCPv6 REPLY for INFORMATION-REQUEST may be received after the link entered configured state.
        # Let's wait for the expected DNS server being listed in the state file.
        for _ in range(100):
            output = read_link_state_file('veth99')
            if 'DNS=2600::ee' in output:
                break
            time.sleep(.2)

        # Check link state file
        print('## link state file')
        output = read_link_state_file('veth99')
        print(output)
        self.assertIn('DNS=2600::ee', output)
        self.assertIn('NTP=2600::ff', output)

        # Check manager state file
        print('## manager state file')
        output = read_manager_state_file()
        print(output)
        self.assertRegex(output, 'DNS=.*2600::ee')
        self.assertRegex(output, 'NTP=.*2600::ff')

        print('## dnsmasq log')
        output = read_dnsmasq_log_file()
        print(output)
        self.assertIn('DHCPINFORMATION-REQUEST(veth-peer)', output)
        self.assertNotIn('DHCPSOLICIT(veth-peer)', output)
        self.assertNotIn('DHCPADVERTISE(veth-peer)', output)
        self.assertNotIn('DHCPREQUEST(veth-peer)', output)
        self.assertNotIn('DHCPREPLY(veth-peer)', output)

        # Check json format
        check_json(networkctl_json('veth99'))

        # solicit mode
        stop_dnsmasq()
        start_dnsmasq('--dhcp-option=108,00:00:02:00',
                      '--dhcp-option=option6:dns-server,[2600::ee]',
                      '--dhcp-option=option6:ntp-server,[2600::ff]')
        networkctl_reconfigure('veth99')
        self.wait_online('veth99:routable', 'veth-peer:routable')

        # checking address
        output = check_output('ip address show dev veth99 scope global')
        print(output)
        self.assertRegex(output, r'inet6 2600::[0-9a-f:]*/128 scope global dynamic noprefixroute')
        self.assertNotIn('192.168.5', output)

        # checking semi-static route
        output = check_output('ip -6 route list dev veth99 2001:1234:5:9fff:ff:ff:ff:ff')
        print(output)
        self.assertRegex(output, 'via fe80::1034:56ff:fe78:9abd')

        # Confirm that ipv6 token is not set in the kernel
        output = check_output('ip token show dev veth99')
        print(output)
        self.assertRegex(output, 'token :: dev veth99')

        # Make manager and link state file updated
        resolvectl('revert', 'veth99')

        # Check link state file
        print('## link state file')
        output = read_link_state_file('veth99')
        print(output)
        self.assertIn('DNS=2600::ee', output)
        self.assertIn('NTP=2600::ff', output)

        # Check manager state file
        print('## manager state file')
        output = read_manager_state_file()
        print(output)
        self.assertRegex(output, 'DNS=.*2600::ee')
        self.assertRegex(output, 'NTP=.*2600::ff')

        print('## dnsmasq log')
        output = read_dnsmasq_log_file()
        print(output)
        self.assertNotIn('DHCPINFORMATION-REQUEST(veth-peer)', output)
        self.assertIn('DHCPSOLICIT(veth-peer)', output)
        self.assertNotIn('DHCPADVERTISE(veth-peer)', output)
        self.assertNotIn('DHCPREQUEST(veth-peer)', output)
        self.assertIn('DHCPREPLY(veth-peer)', output)
        self.assertIn('sent size:  0 option: 14 rapid-commit', output)

        # Check json format
        check_json(networkctl_json('veth99'))

        # Testing without rapid commit support
        with open(os.path.join(network_unit_dir, '25-dhcp-client-ipv6-only.network'), mode='a', encoding='utf-8') as f:
            f.write('\n[DHCPv6]\nRapidCommit=no\n')

        stop_dnsmasq()
        start_dnsmasq('--dhcp-option=108,00:00:02:00',
                      '--dhcp-option=option6:dns-server,[2600::ee]',
                      '--dhcp-option=option6:ntp-server,[2600::ff]')

        networkctl_reload()
        self.wait_online('veth99:routable', 'veth-peer:routable')

        # checking address
        output = check_output('ip address show dev veth99 scope global')
        print(output)
        self.assertRegex(output, r'inet6 2600::[0-9a-f:]*/128 scope global dynamic noprefixroute')
        self.assertNotIn('192.168.5', output)

        # checking semi-static route
        output = check_output('ip -6 route list dev veth99 2001:1234:5:9fff:ff:ff:ff:ff')
        print(output)
        self.assertRegex(output, 'via fe80::1034:56ff:fe78:9abd')

        # Make manager and link state file updated
        resolvectl('revert', 'veth99')

        # Check link state file
        print('## link state file')
        output = read_link_state_file('veth99')
        print(output)
        self.assertIn('DNS=2600::ee', output)
        self.assertIn('NTP=2600::ff', output)

        # Check manager state file
        print('## manager state file')
        output = read_manager_state_file()
        print(output)
        self.assertRegex(output, 'DNS=.*2600::ee')
        self.assertRegex(output, 'NTP=.*2600::ff')

        print('## dnsmasq log')
        output = read_dnsmasq_log_file()
        print(output)
        self.assertNotIn('DHCPINFORMATION-REQUEST(veth-peer)', output)
        self.assertIn('DHCPSOLICIT(veth-peer)', output)
        self.assertIn('DHCPADVERTISE(veth-peer)', output)
        self.assertIn('DHCPREQUEST(veth-peer)', output)
        self.assertIn('DHCPREPLY(veth-peer)', output)
        self.assertNotIn('rapid-commit', output)

        # Check json format
        check_json(networkctl_json('veth99'))

    def test_dhcp_client_ipv6_dbus_status(self):
        copy_network_unit('25-veth.netdev', '25-dhcp-server-veth-peer.network', '25-dhcp-client-ipv6-only.network')
        start_networkd()
        self.wait_online('veth-peer:carrier')

        # Note that at this point the DHCPv6 client has not been started because no RA (with managed
        # bit set) has yet been received and the configuration does not include WithoutRA=true
        state = get_dhcp6_client_state('veth99')
        print(f"DHCPv6 client state = {state}")
        self.assertEqual(state, 'stopped')

        state = get_dhcp4_client_state('veth99')
        print(f"DHCPv4 client state = {state}")
        self.assertEqual(state, 'selecting')

        start_dnsmasq('--dhcp-option=108,00:00:02:00')
        self.wait_online('veth99:routable', 'veth-peer:routable')

        state = get_dhcp6_client_state('veth99')
        print(f"DHCPv6 client state = {state}")
        self.assertEqual(state, 'bound')

        # DHCPv4 client will stop after an DHCPOFFER message received, so we need to wait for a while.
        for _ in range(100):
            state = get_dhcp4_client_state('veth99')
            if state == 'stopped':
                break
            time.sleep(.2)

        print(f"DHCPv4 client state = {state}")
        self.assertEqual(state, 'stopped')

        # restart dnsmasq to clear log
        stop_dnsmasq()
        start_dnsmasq('--dhcp-option=108,00:00:02:00')

        # Test renew command
        # See https://github.com/systemd/systemd/pull/29472#issuecomment-1759092138
        networkctl('renew', 'veth99')

        for _ in range(100):
            state = get_dhcp4_client_state('veth99')
            if state == 'stopped':
                break
            time.sleep(.2)

        print(f"DHCPv4 client state = {state}")
        self.assertEqual(state, 'stopped')

        print('## dnsmasq log')
        output = read_dnsmasq_log_file()
        print(output)
        self.assertIn('DHCPDISCOVER(veth-peer) 12:34:56:78:9a:bc', output)
        self.assertIn('DHCPOFFER(veth-peer)', output)
        self.assertNotIn('DHCPREQUEST(veth-peer)', output)
        self.assertNotIn('DHCPACK(veth-peer)', output)

    def test_dhcp_client_ipv6_only_with_custom_client_identifier(self):
        copy_network_unit('25-veth.netdev', '25-dhcp-server-veth-peer.network', '25-dhcp-client-ipv6-only-custom-client-identifier.network')

        start_networkd()
        self.wait_online('veth-peer:carrier')
        start_dnsmasq()
        self.wait_online('veth99:routable', 'veth-peer:routable')

        # checking address
        output = check_output('ip address show dev veth99 scope global')
        print(output)
        self.assertRegex(output, r'inet6 2600::[0-9a-f:]*/128 scope global dynamic noprefixroute')
        self.assertNotIn('192.168.5', output)

        print('## dnsmasq log')
        output = read_dnsmasq_log_file()
        print(output)
        self.assertIn('DHCPSOLICIT(veth-peer) 00:42:00:00:ab:11:f9:2a:c2:77:29:f9:5c:00', output)
        self.assertNotIn('DHCPADVERTISE(veth-peer)', output)
        self.assertNotIn('DHCPREQUEST(veth-peer)', output)
        self.assertIn('DHCPREPLY(veth-peer)', output)
        self.assertIn('sent size:  0 option: 14 rapid-commit', output)

    @expectedFailureIfKernelReturnsInvalidFlags()
    def test_dhcp_client_ipv4_only(self):
        copy_network_unit('25-veth.netdev', '25-dhcp-server-veth-peer.network', '25-dhcp-client-ipv4-only.network',
                          '25-sit-dhcp4.netdev', '25-sit-dhcp4.network')

        self.setup_nftset('addr4', 'ipv4_addr')
        self.setup_nftset('network4', 'ipv4_addr', 'flags interval;')
        self.setup_nftset('ifindex', 'iface_index')

        start_networkd()
        self.wait_online('veth-peer:carrier')
        start_dnsmasq('--dhcp-option=option:dns-server,192.168.5.6,192.168.5.7',
                      '--dhcp-option=option:sip-server,192.168.5.21,192.168.5.22',
                      '--dhcp-option=option:domain-search,example.com',
                      '--dhcp-alternate-port=67,5555',
                      ipv4_range='192.168.5.110,192.168.5.119')
        self.wait_online('veth99:routable', 'veth-peer:routable', 'sit-dhcp4:carrier')
        self.wait_address('veth99', r'inet 192.168.5.11[0-9]*/24', ipv='-4')

        print('## ip address show dev veth99 scope global')
        output = check_output('ip address show dev veth99 scope global')
        print(output)
        self.assertIn('mtu 1492', output)
        self.assertIn('inet 192.168.5.250/24 brd 192.168.5.255 scope global veth99', output)
        self.assertRegex(output, r'inet 192.168.5.11[0-9]/24 metric 24 brd 192.168.5.255 scope global secondary dynamic noprefixroute test-label')
        self.assertNotIn('2600::', output)

        output = check_output('ip -4 --json address show dev veth99')
        for i in json.loads(output)[0]['addr_info']:
            if i['label'] == 'test-label':
                address1 = i['local']
                break
        else:
            self.assertFalse(True)

        self.assertRegex(address1, r'^192.168.5.11[0-9]$')

        print('## ip route show table main dev veth99')
        output = check_output('ip route show table main dev veth99')
        print(output)
        # no DHCP routes assigned to the main table
        self.assertNotIn('proto dhcp', output)
        # static routes
        self.assertIn('192.168.5.0/24 proto kernel scope link src 192.168.5.250', output)
        self.assertIn('192.168.5.0/24 proto static scope link', output)
        self.assertIn('192.168.6.0/24 proto static scope link', output)
        self.assertIn('192.168.7.0/24 proto static scope link', output)

        print('## ip route show table 211 dev veth99')
        output = check_output('ip route show table 211 dev veth99')
        print(output)
        self.assertRegex(output, f'default via 192.168.5.1 proto dhcp src {address1} metric 24')
        self.assertRegex(output, f'192.168.5.0/24 proto dhcp scope link src {address1} metric 24')
        self.assertRegex(output, f'192.168.5.1 proto dhcp scope link src {address1} metric 24')
        self.assertRegex(output, f'192.168.5.6 proto dhcp scope link src {address1} metric 24')
        self.assertRegex(output, f'192.168.5.7 proto dhcp scope link src {address1} metric 24')
        self.assertRegex(output, f'192.0.2.0/24 via 192.168.5.1 proto dhcp src {address1}')

        print('## ip route show table 212 dev veth99')
        output = check_output('ip route show table 212 dev veth99')
        print(output)
        self.assertRegex(output, f'192.168.5.0/24 proto dhcp scope link src {address1} metric 24')
        self.assertRegex(output, f'192.168.5.1 proto dhcp scope link src {address1} metric 24')
        self.assertRegex(output, f'198.51.100.0/24 via 192.168.5.1 proto dhcp src {address1}')

        print('## link state file')
        output = read_link_state_file('veth99')
        print(output)
        # checking DNS server, SIP server, and Domains
        self.assertIn('DNS=192.168.5.6 192.168.5.7', output)
        self.assertIn('SIP=192.168.5.21 192.168.5.22', output)
        self.assertIn('DOMAINS=example.com', output)

        print('## json')
        j = json.loads(networkctl_json('veth99'))

        self.assertEqual(len(j['DNS']), 2)
        for i in j['DNS']:
            print(i)
            self.assertEqual(i['Family'], 2)
            a = socket.inet_ntop(socket.AF_INET, bytearray(i['Address']))
            self.assertRegex(a, '^192.168.5.[67]$')
            self.assertEqual(i['ConfigSource'], 'DHCPv4')
            a = socket.inet_ntop(socket.AF_INET, bytearray(i['ConfigProvider']))
            self.assertEqual('192.168.5.1', a)

        self.assertEqual(len(j['SIP']), 2)
        for i in j['SIP']:
            print(i)
            self.assertEqual(i['Family'], 2)
            a = socket.inet_ntop(socket.AF_INET, bytearray(i['Address']))
            self.assertRegex(a, '^192.168.5.2[12]$')
            self.assertEqual(i['ConfigSource'], 'DHCPv4')
            a = socket.inet_ntop(socket.AF_INET, bytearray(i['ConfigProvider']))
            self.assertEqual('192.168.5.1', a)

        print('## tunnel')
        output = check_output('ip -d link show sit-dhcp4')
        print(output)
        self.assertRegex(output, fr'sit (ip6ip )?remote any local {address1} dev veth99')

        print('## dnsmasq log')
        output = read_dnsmasq_log_file()
        print(output)
        self.assertIn('vendor class: FooBarVendorTest', output)
        self.assertIn('DHCPDISCOVER(veth-peer) 192.168.5.110 12:34:56:78:9a:bc', output)
        self.assertIn('client provides name: test-hostname', output)
        self.assertIn('26:mtu', output)

        # change address range, DNS servers, and Domains
        stop_dnsmasq()
        start_dnsmasq('--dhcp-option=option:dns-server,192.168.5.1,192.168.5.7,192.168.5.8',
                      '--dhcp-option=option:sip-server,192.168.5.23,192.168.5.24',
                      '--dhcp-option=option:domain-search,foo.example.com',
                      '--dhcp-alternate-port=67,5555',
                      ipv4_range='192.168.5.120,192.168.5.129',)

        # Sleep for 120 sec as the dnsmasq minimum lease time can only be set to 120
        print('Wait for the DHCP lease to be expired')
        self.wait_address_dropped('veth99', f'inet {address1}/24', ipv='-4', timeout_sec=120)
        self.wait_address('veth99', r'inet 192.168.5.12[0-9]*/24', ipv='-4')

        self.wait_online('veth99:routable', 'veth-peer:routable')

        print('## ip address show dev veth99 scope global')
        output = check_output('ip address show dev veth99 scope global')
        print(output)
        self.assertIn('mtu 1492', output)
        self.assertIn('inet 192.168.5.250/24 brd 192.168.5.255 scope global veth99', output)
        self.assertNotIn(f'{address1}', output)
        self.assertRegex(output, r'inet 192.168.5.12[0-9]/24 metric 24 brd 192.168.5.255 scope global secondary dynamic noprefixroute test-label')
        self.assertNotIn('2600::', output)

        output = check_output('ip -4 --json address show dev veth99')
        for i in json.loads(output)[0]['addr_info']:
            if i['label'] == 'test-label':
                address2 = i['local']
                break
        else:
            self.assertFalse(True)

        self.assertRegex(address2, r'^192.168.5.12[0-9]$')

        print('## ip route show table main dev veth99')
        output = check_output('ip route show table main dev veth99')
        print(output)
        # no DHCP routes assigned to the main table
        self.assertNotIn('proto dhcp', output)
        # static routes
        self.assertIn('192.168.5.0/24 proto kernel scope link src 192.168.5.250', output)
        self.assertIn('192.168.5.0/24 proto static scope link', output)
        self.assertIn('192.168.6.0/24 proto static scope link', output)
        self.assertIn('192.168.7.0/24 proto static scope link', output)

        print('## ip route show table 211 dev veth99')
        output = check_output('ip route show table 211 dev veth99')
        print(output)
        self.assertRegex(output, f'default via 192.168.5.1 proto dhcp src {address2} metric 24')
        self.assertRegex(output, f'192.168.5.0/24 proto dhcp scope link src {address2} metric 24')
        self.assertRegex(output, f'192.168.5.1 proto dhcp scope link src {address2} metric 24')
        self.assertNotIn('192.168.5.6', output)
        self.assertRegex(output, f'192.168.5.7 proto dhcp scope link src {address2} metric 24')
        self.assertRegex(output, f'192.168.5.8 proto dhcp scope link src {address2} metric 24')
        self.assertRegex(output, f'192.0.2.0/24 via 192.168.5.1 proto dhcp src {address2}')

        print('## ip route show table 212 dev veth99')
        output = check_output('ip route show table 212 dev veth99')
        print(output)
        self.assertRegex(output, f'192.168.5.0/24 proto dhcp scope link src {address2} metric 24')
        self.assertRegex(output, f'192.168.5.1 proto dhcp scope link src {address2} metric 24')
        self.assertRegex(output, f'198.51.100.0/24 via 192.168.5.1 proto dhcp src {address2}')

        print('## link state file')
        output = read_link_state_file('veth99')
        print(output)
        # checking DNS server, SIP server, and Domains
        self.assertIn('DNS=192.168.5.1 192.168.5.7 192.168.5.8', output)
        self.assertIn('SIP=192.168.5.23 192.168.5.24', output)
        self.assertIn('DOMAINS=foo.example.com', output)

        print('## json')
        j = json.loads(networkctl_json('veth99'))

        self.assertEqual(len(j['DNS']), 3)
        for i in j['DNS']:
            print(i)
            self.assertEqual(i['Family'], 2)
            a = socket.inet_ntop(socket.AF_INET, bytearray(i['Address']))
            self.assertRegex(a, '^192.168.5.[178]$')
            self.assertEqual(i['ConfigSource'], 'DHCPv4')
            a = socket.inet_ntop(socket.AF_INET, bytearray(i['ConfigProvider']))
            self.assertEqual('192.168.5.1', a)

        self.assertEqual(len(j['SIP']), 2)
        for i in j['SIP']:
            print(i)
            self.assertEqual(i['Family'], 2)
            a = socket.inet_ntop(socket.AF_INET, bytearray(i['Address']))
            self.assertRegex(a, '^192.168.5.2[34]$')
            self.assertEqual(i['ConfigSource'], 'DHCPv4')
            a = socket.inet_ntop(socket.AF_INET, bytearray(i['ConfigProvider']))
            self.assertEqual('192.168.5.1', a)

        print('## tunnel')
        output = check_output('ip -d link show sit-dhcp4')
        print(output)
        self.assertRegex(output, fr'sit (ip6ip )?remote any local {address2} dev veth99')

        print('## dnsmasq log')
        output = read_dnsmasq_log_file()
        print(output)
        self.assertIn('vendor class: FooBarVendorTest', output)
        self.assertIn(f'DHCPDISCOVER(veth-peer) {address1} 12:34:56:78:9a:bc', output)
        self.assertIn('client provides name: test-hostname', output)
        self.assertIn('26:mtu', output)

        self.check_netlabel('veth99', r'192\.168\.5\.0/24')

        self.check_nftset('addr4', r'192\.168\.5\.1')
        self.check_nftset('network4', r'192\.168\.5\.0/24')
        self.check_nftset('ifindex', 'veth99')

        # Check if DHCPv4 address and routes are removed on stop. For issue #34837.
        stop_networkd(show_logs=False)
        self.wait_address_dropped('veth99', f'inet {address2}/24', ipv='-4', timeout_sec=120)

        print('## ip address show dev veth99 scope global')
        output = check_output('ip address show dev veth99 scope global')
        print(output)
        self.assertNotIn(f'{address2}', output)

        print('## ip route show table main dev veth99')
        output = check_output('ip route show table main dev veth99')
        print(output)
        self.assertNotIn(f'{address2}', output)

        print('## ip route show table 211 dev veth99')
        output = check_output('ip route show table 211 dev veth99')
        print(output)
        self.assertNotIn(f'{address2}', output)

        print('## ip route show table 212 dev veth99')
        output = check_output('ip route show table 212 dev veth99')
        print(output)
        self.assertNotIn(f'{address2}', output)

        self.teardown_nftset('addr4', 'network4', 'ifindex')

    def test_dhcp_client_ipv4_dbus_status(self):
        copy_network_unit('25-veth.netdev', '25-dhcp-server-veth-peer.network', '25-dhcp-client-ipv4-only.network')
        start_networkd()
        self.wait_online('veth-peer:carrier')

        state = get_dhcp4_client_state('veth99')
        print(f"State = {state}")
        self.assertEqual(state, 'rebooting')

        start_dnsmasq('--dhcp-option=option:dns-server,192.168.5.6,192.168.5.7',
                      '--dhcp-option=option:domain-search,example.com',
                      '--dhcp-alternate-port=67,5555',
                      ipv4_range='192.168.5.110,192.168.5.119')
        self.wait_online('veth99:routable', 'veth-peer:routable')
        self.wait_address('veth99', r'inet 192.168.5.11[0-9]*/24', ipv='-4')

        state = get_dhcp4_client_state('veth99')
        print(f"State = {state}")
        self.assertEqual(state, 'bound')

    def test_dhcp_client_allow_list(self):
        copy_network_unit('25-veth.netdev', '25-dhcp-server-veth-peer.network', '25-dhcp-client-allow-list.network', copy_dropins=False)

        start_networkd()
        self.wait_online('veth-peer:carrier')
        since = datetime.datetime.now()
        start_dnsmasq()

        self.check_networkd_log('veth99: DHCPv4 server IP address 192.168.5.1 not found in allow-list, ignoring offer.', since=since)

        copy_network_unit('25-dhcp-client-allow-list.network.d/00-allow-list.conf')
        since = datetime.datetime.now()
        networkctl_reload()

        self.check_networkd_log('veth99: DHCPv4 server IP address 192.168.5.1 not found in allow-list, ignoring offer.', since=since)

        copy_network_unit('25-dhcp-client-allow-list.network.d/10-deny-list.conf')
        since = datetime.datetime.now()
        networkctl_reload()

        self.check_networkd_log('veth99: DHCPv4 server IP address 192.168.5.1 found in deny-list, ignoring offer.', since=since)

    @unittest.skipUnless("--dhcp-rapid-commit" in run("dnsmasq --help").stdout, reason="dnsmasq is missing dhcp-rapid-commit support")
    def test_dhcp_client_rapid_commit(self):
        copy_network_unit('25-veth.netdev', '25-dhcp-server-veth-peer.network', '25-dhcp-client.network')
        start_networkd()
        self.wait_online('veth-peer:carrier')

        start_dnsmasq('--dhcp-rapid-commit')
        self.wait_online('veth99:routable', 'veth-peer:routable')
        self.wait_address('veth99', r'inet 192.168.5.[0-9]*/24', ipv='-4')

        state = get_dhcp4_client_state('veth99')
        print(f"DHCPv4 client state = {state}")
        self.assertEqual(state, 'bound')

        output = read_dnsmasq_log_file()
        self.assertIn('DHCPDISCOVER(veth-peer)', output)
        self.assertNotIn('DHCPOFFER(veth-peer)', output)
        self.assertNotIn('DHCPREQUEST(veth-peer)', output)
        self.assertIn('DHCPACK(veth-peer)', output)

    def test_bootp_client(self):
        copy_network_unit('25-veth.netdev', '25-dhcp-server-veth-peer.network', '25-bootp-client.network')
        start_networkd()
        self.wait_online('veth-peer:carrier')

        start_dnsmasq('--dhcp-host=12:34:56:78:9a:bc,192.168.5.42,trixie-mule')
        # def wait_online(self, *links_with_operstate, timeout='20s', bool_any=False, ipv4=False, ipv6=False, setup_state='configured', setup_timeout=5):
        self.wait_online('veth99:routable', 'veth-peer:routable')
        self.wait_address('veth99', r'inet 192.168.5.[0-9]*/24', ipv='-4')

        state = get_dhcp4_client_state('veth99')
        print(f"DHCPv4 client state = {state}")
        self.assertEqual(state, 'bound')

        output = read_dnsmasq_log_file()
        self.assertIn('BOOTP(veth-peer)', output)
        self.assertNotIn('DHCPDISCOVER(veth-peer)', output)
        self.assertNotIn('DHCPOFFER(veth-peer)', output)
        self.assertNotIn('DHCPREQUEST(veth-peer)', output)
        self.assertNotIn('DHCPACK(veth-peer)', output)

    def test_dhcp_client_ipv6_only_mode_without_ipv6_connectivity(self):
        copy_network_unit('25-veth.netdev',
                          '25-dhcp-server-ipv6-only-mode.network',
                          '25-dhcp-client-ipv6-only-mode.network')
        start_networkd()
        self.wait_online('veth99:routable', 'veth-peer:routable', timeout='40s')
        self.wait_address('veth99', r'inet 192.168.5.[0-9]*/24', ipv='-4')

        state = get_dhcp4_client_state('veth99')
        print(f"State = {state}")
        self.assertEqual(state, 'bound')

    def test_dhcp_client_ipv4_use_routes_gateway(self):
        first = True
        for (routes, gateway, dns_and_ntp_routes, classless) in itertools.product([True, False], repeat=4):
            if first:
                first = False
            else:
                self.tearDown()

            print(f'### test_dhcp_client_ipv4_use_routes_gateway(routes={routes}, gateway={gateway}, dns_and_ntp_routes={dns_and_ntp_routes}, classless={classless})')
            with self.subTest(routes=routes, gateway=gateway, dns_and_ntp_routes=dns_and_ntp_routes, classless=classless):
                self._test_dhcp_client_ipv4_use_routes_gateway(routes, gateway, dns_and_ntp_routes, classless)

    def _test_dhcp_client_ipv4_use_routes_gateway(self, use_routes, use_gateway, dns_and_ntp_routes, classless):
        testunit = '25-dhcp-client-ipv4-use-routes-use-gateway.network'
        testunits = ['25-veth.netdev', '25-dhcp-server-veth-peer.network', testunit]
        testunits.append(f'{testunit}.d/use-routes-{use_routes}.conf')
        testunits.append(f'{testunit}.d/use-gateway-{use_gateway}.conf')
        testunits.append(f'{testunit}.d/use-dns-and-ntp-routes-{dns_and_ntp_routes}.conf')
        copy_network_unit(*testunits, copy_dropins=False)

        start_networkd()
        self.wait_online('veth-peer:carrier')
        additional_options = [
            '--dhcp-option=option:dns-server,192.168.5.10,8.8.8.8',
            '--dhcp-option=option:ntp-server,192.168.5.11,9.9.9.9',
            '--dhcp-option=option:static-route,192.168.6.100,192.168.5.2,8.8.8.8,192.168.5.3'
        ]
        if classless:
            additional_options += [
                '--dhcp-option=option:classless-static-route,0.0.0.0/0,192.168.5.4,8.0.0.0/8,192.168.5.5,192.168.5.64/26,192.168.5.5'
            ]
        start_dnsmasq(*additional_options)
        self.wait_online('veth99:routable', 'veth-peer:routable')

        output = check_output('ip -4 route show dev veth99')
        print(output)

        # Check UseRoutes=
        if use_routes:
            if classless:
                self.assertRegex(output, r'default via 192.168.5.4 proto dhcp src 192.168.5.[0-9]* metric 1024')
                self.assertRegex(output, r'8.0.0.0/8 via 192.168.5.5 proto dhcp src 192.168.5.[0-9]* metric 1024')
                self.assertRegex(output, r'192.168.5.64/26 via 192.168.5.5 proto dhcp src 192.168.5.[0-9]* metric 1024')
                self.assertRegex(output, r'192.168.5.4 proto dhcp scope link src 192.168.5.[0-9]* metric 1024')
                self.assertRegex(output, r'192.168.5.5 proto dhcp scope link src 192.168.5.[0-9]* metric 1024')
            else:
                self.assertRegex(output, r'192.168.6.0/24 via 192.168.5.2 proto dhcp src 192.168.5.[0-9]* metric 1024')
                self.assertRegex(output, r'8.0.0.0/8 via 192.168.5.3 proto dhcp src 192.168.5.[0-9]* metric 1024')
                self.assertRegex(output, r'192.168.5.2 proto dhcp scope link src 192.168.5.[0-9]* metric 1024')
                self.assertRegex(output, r'192.168.5.3 proto dhcp scope link src 192.168.5.[0-9]* metric 1024')
        else:
            self.assertNotRegex(output, r'default via 192.168.5.4 proto dhcp src 192.168.5.[0-9]* metric 1024')
            self.assertNotRegex(output, r'8.0.0.0/8 via 192.168.5.5 proto dhcp src 192.168.5.[0-9]* metric 1024')
            self.assertNotRegex(output, r'192.168.5.4 proto dhcp scope link src 192.168.5.[0-9]* metric 1024')
            self.assertNotRegex(output, r'192.168.5.5 proto dhcp scope link src 192.168.5.[0-9]* metric 1024')
            self.assertNotRegex(output, r'192.168.6.0/24 via 192.168.5.2 proto dhcp src 192.168.5.[0-9]* metric 1024')
            self.assertNotRegex(output, r'8.0.0.0/8 via 192.168.5.3 proto dhcp src 192.168.5.[0-9]* metric 1024')
            self.assertNotRegex(output, r'192.168.5.2 proto dhcp scope link src 192.168.5.[0-9]* metric 1024')
            self.assertNotRegex(output, r'192.168.5.3 proto dhcp scope link src 192.168.5.[0-9]* metric 1024')

        # Check UseGateway=
        if use_gateway and (not classless or not use_routes):
            self.assertRegex(output, r'default via 192.168.5.1 proto dhcp src 192.168.5.[0-9]* metric 1024')
        else:
            self.assertNotRegex(output, r'default via 192.168.5.1 proto dhcp src 192.168.5.[0-9]* metric 1024')

        # Check route to gateway
        if (use_gateway or dns_and_ntp_routes) and (not classless or not use_routes):
            self.assertRegex(output, r'192.168.5.1 proto dhcp scope link src 192.168.5.[0-9]* metric 1024')
        else:
            self.assertNotRegex(output, r'192.168.5.1 proto dhcp scope link src 192.168.5.[0-9]* metric 1024')

        # Check RoutesToDNS= and RoutesToNTP=
        if dns_and_ntp_routes:
            self.assertRegex(output, r'192.168.5.10 proto dhcp scope link src 192.168.5.[0-9]* metric 1024')
            self.assertRegex(output, r'192.168.5.11 proto dhcp scope link src 192.168.5.[0-9]* metric 1024')
            if use_routes:
                if classless:
                    self.assertRegex(output, r'8.8.8.8 via 192.168.5.5 proto dhcp src 192.168.5.[0-9]* metric 1024')
                    self.assertRegex(output, r'9.9.9.9 via 192.168.5.4 proto dhcp src 192.168.5.[0-9]* metric 1024')
                else:
                    self.assertRegex(output, r'8.8.8.8 via 192.168.5.3 proto dhcp src 192.168.5.[0-9]* metric 1024')
                    self.assertRegex(output, r'9.9.9.9 via 192.168.5.1 proto dhcp src 192.168.5.[0-9]* metric 1024')
            else:
                self.assertRegex(output, r'8.8.8.8 via 192.168.5.1 proto dhcp src 192.168.5.[0-9]* metric 1024')
                self.assertRegex(output, r'9.9.9.9 via 192.168.5.1 proto dhcp src 192.168.5.[0-9]* metric 1024')
        else:
            self.assertNotRegex(output, r'192.168.5.10 proto dhcp scope link src 192.168.5.[0-9]* metric 1024')
            self.assertNotRegex(output, r'192.168.5.11 proto dhcp scope link src 192.168.5.[0-9]* metric 1024')
            self.assertNotRegex(output, r'8.8.8.8 via 192.168.5.[0-9]* proto dhcp src 192.168.5.[0-9]* metric 1024')
            self.assertNotRegex(output, r'9.9.9.9 via 192.168.5.[0-9]* proto dhcp src 192.168.5.[0-9]* metric 1024')

        check_json(networkctl_json())

    def test_dhcp_client_settings_anonymize(self):
        copy_network_unit('25-veth.netdev', '25-dhcp-server-veth-peer.network', '25-dhcp-client-anonymize.network')
        start_networkd()
        self.wait_online('veth-peer:carrier')
        start_dnsmasq()
        self.wait_online('veth99:routable', 'veth-peer:routable')

        print('## dnsmasq log')
        output = read_dnsmasq_log_file()
        print(output)
        self.assertNotIn('VendorClassIdentifier=SusantVendorTest', output)
        self.assertNotIn('test-hostname', output)
        self.assertNotIn('26:mtu', output)

    def test_dhcp_keep_configuration_dynamic(self):
        copy_network_unit('25-veth.netdev',
                          '25-dhcp-server-veth-peer.network',
                          '25-dhcp-client-keep-configuration-dynamic.network')
        start_networkd()
        self.wait_online('veth-peer:carrier')
        start_dnsmasq()
        self.wait_online('veth99:routable', 'veth-peer:routable')

        output = check_output('ip address show dev veth99 scope global')
        print(output)
        self.assertRegex(output, r'inet 192.168.5.[0-9]*/24 metric 1024 brd 192.168.5.255 scope global veth99\n *'
                         'valid_lft forever preferred_lft forever')

        # Stopping dnsmasq as networkd won't be allowed to renew the DHCP lease.
        stop_dnsmasq()

        # Sleep for 120 sec as the dnsmasq minimum lease time can only be set to 120
        print('Wait for the DHCP lease to be expired')
        time.sleep(120)

        # The lease address should be kept after the lease expired
        output = check_output('ip address show dev veth99 scope global')
        print(output)
        self.assertRegex(output, r'inet 192.168.5.[0-9]*/24 metric 1024 brd 192.168.5.255 scope global veth99\n *'
                         'valid_lft forever preferred_lft forever')

        stop_networkd()

        # The lease address should be kept after networkd stopped
        output = check_output('ip address show dev veth99 scope global')
        print(output)
        self.assertRegex(output, r'inet 192.168.5.[0-9]*/24 metric 1024 brd 192.168.5.255 scope global veth99\n *'
                         'valid_lft forever preferred_lft forever')

        with open(os.path.join(network_unit_dir, '25-dhcp-client-keep-configuration-dynamic.network'), mode='a', encoding='utf-8') as f:
            f.write('[Network]\nDHCP=no\n')

        start_networkd()
        self.wait_online('veth99:routable', 'veth-peer:routable')

        # Still the lease address should be kept after networkd restarted
        output = check_output('ip address show dev veth99 scope global')
        print(output)
        self.assertRegex(output, r'inet 192.168.5.[0-9]*/24 metric 1024 brd 192.168.5.255 scope global veth99\n *'
                         'valid_lft forever preferred_lft forever')

    def test_dhcp_keep_configuration_dynamic_on_stop(self):
        copy_network_unit('25-veth.netdev',
                          '25-dhcp-server-veth-peer.network',
                          '25-dhcp-client-keep-configuration-dynamic-on-stop.network')
        start_networkd()
        self.wait_online('veth-peer:carrier')
        start_dnsmasq()
        self.wait_online('veth99:routable', 'veth-peer:routable')

        output = check_output('ip address show dev veth99 scope global')
        print(output)
        self.assertRegex(output, r'inet 192.168.5.[0-9]*/24 metric 1024 brd 192.168.5.255 scope global dynamic veth99')

        stop_dnsmasq()
        stop_networkd()

        output = check_output('ip address show dev veth99 scope global')
        print(output)
        self.assertRegex(output, r'inet 192.168.5.[0-9]*/24 metric 1024 brd 192.168.5.255 scope global dynamic veth99')

        start_networkd()
        self.wait_online('veth-peer:routable')

        output = check_output('ip address show dev veth99 scope global')
        print(output)
        self.assertNotIn('192.168.5.', output)

    def test_dhcp_client_reuse_address_as_static(self):
        copy_network_unit('25-veth.netdev', '25-dhcp-server-veth-peer.network', '25-dhcp-client.network')
        start_networkd()
        self.wait_online('veth-peer:carrier')
        start_dnsmasq()
        self.wait_online('veth99:routable', 'veth-peer:routable')

        # link become 'routable' when at least one protocol provide an valid address.
        self.wait_address('veth99', r'inet 192.168.5.[0-9]*/24 metric 1024 brd 192.168.5.255 scope global dynamic', ipv='-4')
        self.wait_address('veth99', r'inet6 2600::[0-9a-f]*/128 scope global (dynamic noprefixroute|noprefixroute dynamic)', ipv='-6')

        output = check_output('ip address show dev veth99 scope global')
        ipv4_address = re.search(r'192.168.5.[0-9]*/24', output).group()
        ipv6_address = re.search(r'2600::[0-9a-f:]*/128', output).group()
        static_network = '\n'.join(['[Match]', 'Name=veth99', '[Network]', 'IPv6AcceptRA=no', 'Address=' + ipv4_address, 'Address=' + ipv6_address])
        print(static_network)

        remove_network_unit('25-dhcp-client.network')

        with open(os.path.join(network_unit_dir, '25-static.network'), mode='w', encoding='utf-8') as f:
            f.write(static_network)

        restart_networkd()
        self.wait_online('veth99:routable')

        output = check_output('ip -4 address show dev veth99 scope global')
        print(output)
        self.assertRegex(output, f'inet {ipv4_address} brd 192.168.5.255 scope global veth99\n *'
                         'valid_lft forever preferred_lft forever')

        output = check_output('ip -6 address show dev veth99 scope global')
        print(output)
        self.assertRegex(output, f'inet6 {ipv6_address} scope global *\n *'
                         'valid_lft forever preferred_lft forever')

    @expectedFailureIfModuleIsNotAvailable('vrf')
    def test_dhcp_client_vrf(self):
        copy_network_unit('25-veth.netdev', '25-dhcp-server-veth-peer.network', '25-dhcp-client-vrf.network',
                          '25-vrf.netdev', '25-vrf.network')
        start_networkd()
        self.wait_online('veth-peer:carrier')
        start_dnsmasq()
        self.wait_online('veth99:routable', 'veth-peer:routable', 'vrf99:carrier')

        # link become 'routable' when at least one protocol provide an valid address.
        self.wait_address('veth99', r'inet 192.168.5.[0-9]*/24 metric 1024 brd 192.168.5.255 scope global dynamic', ipv='-4')
        self.wait_address('veth99', r'inet6 2600::[0-9a-f]*/128 scope global (dynamic noprefixroute|noprefixroute dynamic)', ipv='-6')

        print('## ip -d link show dev vrf99')
        output = check_output('ip -d link show dev vrf99')
        print(output)
        self.assertRegex(output, 'vrf table 42')

        print('## ip address show vrf vrf99')
        output = check_output('ip address show vrf vrf99')
        print(output)
        self.assertRegex(output, 'inet 192.168.5.[0-9]*/24 metric 1024 brd 192.168.5.255 scope global dynamic veth99')
        self.assertRegex(output, 'inet6 2600::[0-9a-f]*/128 scope global (dynamic noprefixroute|noprefixroute dynamic)')
        self.assertRegex(output, 'inet6 .* scope link')

        print('## ip address show dev veth99')
        output = check_output('ip address show dev veth99')
        print(output)
        self.assertRegex(output, 'inet 192.168.5.[0-9]*/24 metric 1024 brd 192.168.5.255 scope global dynamic veth99')
        self.assertRegex(output, 'inet6 2600::[0-9a-f]*/128 scope global (dynamic noprefixroute|noprefixroute dynamic)')
        self.assertRegex(output, 'inet6 .* scope link')

        print('## ip route show vrf vrf99')
        output = check_output('ip route show vrf vrf99')
        print(output)
        self.assertRegex(output, 'default via 192.168.5.1 dev veth99 proto dhcp src 192.168.5.')
        self.assertRegex(output, '192.168.5.0/24 dev veth99 proto kernel scope link src 192.168.5')
        self.assertRegex(output, '192.168.5.1 dev veth99 proto dhcp scope link src 192.168.5')

        print('## ip route show table main dev veth99')
        output = check_output('ip route show table main dev veth99')
        print(output)
        self.assertEqual(output, '')

    def test_dhcp_client_gateway_onlink_implicit(self):
        copy_network_unit('25-veth.netdev', '25-dhcp-server-veth-peer.network',
                          '25-dhcp-client-gateway-onlink-implicit.network')
        start_networkd()
        self.wait_online('veth-peer:carrier')
        start_dnsmasq()
        self.wait_online('veth99:routable', 'veth-peer:routable')

        output = networkctl_status('veth99')
        print(output)
        self.assertRegex(output, '192.168.5')

        output = check_output('ip route list dev veth99 10.0.0.0/8')
        print(output)
        self.assertRegex(output, 'onlink')
        output = check_output('ip route list dev veth99 192.168.100.0/24')
        print(output)
        self.assertRegex(output, 'onlink')

    def test_dhcp_client_with_ipv4ll(self):
        copy_network_unit('25-veth.netdev', '25-dhcp-server-veth-peer.network',
                          '25-dhcp-client-with-ipv4ll.network')
        start_networkd()
        # we need to increase timeout above default, as this will need to wait for
        # systemd-networkd to get the dhcpv4 transient failure event
        self.wait_online('veth99:degraded', 'veth-peer:routable', timeout='60s')

        output = check_output('ip -4 address show dev veth99')
        print(output)
        self.assertNotIn('192.168.5.', output)
        self.assertIn('inet 169.254.133.11/16 metric 2048 brd 169.254.255.255 scope link', output)

        start_dnsmasq()
        print('Wait for a DHCP lease to be acquired and the IPv4LL address to be dropped')
        self.wait_address('veth99', r'inet 192\.168\.5\.\d+/24 metric 1024 brd 192\.168\.5\.255 scope global dynamic', ipv='-4')
        self.wait_address_dropped('veth99', r'inet 169\.254\.\d+\.\d+/16 metric 2048 brd 169\.254\.255\.255 scope link', scope='link', ipv='-4')
        self.wait_online('veth99:routable')

        output = check_output('ip -4 address show dev veth99')
        print(output)
        self.assertRegex(output, r'inet 192\.168\.5\.\d+/24 metric 1024 brd 192\.168\.5\.255 scope global dynamic veth99')
        self.assertNotIn('169.254.', output)
        self.assertNotIn('scope link', output)

        stop_dnsmasq()
        print('Wait for the DHCP lease to be expired and an IPv4LL address to be acquired')
        self.wait_address_dropped('veth99', r'inet 192\.168\.5\.\d+/24 metric 1024 brd 192\.168\.5\.255 scope global dynamic', ipv='-4', timeout_sec=130)
        self.wait_address('veth99', r'inet 169\.254\.133\.11/16 metric 2048 brd 169\.254\.255\.255 scope link', scope='link', ipv='-4')

        output = check_output('ip -4 address show dev veth99')
        print(output)
        self.assertNotIn('192.168.5.', output)
        self.assertIn('inet 169.254.133.11/16 metric 2048 brd 169.254.255.255 scope link', output)

    def test_dhcp_client_use_dns(self):
        def check(self, ipv4, ipv6, needs_reconfigure=False):
            os.makedirs(os.path.join(network_unit_dir, '25-dhcp-client.network.d'), exist_ok=True)
            with open(os.path.join(network_unit_dir, '25-dhcp-client.network.d/override.conf'), mode='w', encoding='utf-8') as f:
                f.write('[DHCPv4]\nUseDNS=')
                f.write('yes' if ipv4 else 'no')
                f.write('\n[DHCPv6]\nUseDNS=')
                f.write('yes' if ipv6 else 'no')
                f.write('\n[IPv6AcceptRA]\nUseDNS=no')

            networkctl_reload()
            if needs_reconfigure:
                networkctl_reconfigure('veth99')
            self.wait_online('veth99:routable')

            # link becomes 'routable' when at least one protocol provide an valid address. Hence, we need to explicitly wait for both addresses.
            self.wait_address('veth99', r'inet 192.168.5.[0-9]*/24 metric 1024 brd 192.168.5.255 scope global dynamic', ipv='-4')
            self.wait_address('veth99', r'inet6 2600::[0-9a-f]*/128 scope global (dynamic noprefixroute|noprefixroute dynamic)', ipv='-6')

            # make resolved re-read the link state file
            resolvectl('revert', 'veth99')

            output = resolvectl('dns', 'veth99')
            print(output)
            if ipv4:
                self.assertIn('192.168.5.1', output)
            else:
                self.assertNotIn('192.168.5.1', output)
            if ipv6:
                self.assertIn('2600::1', output)
            else:
                self.assertNotIn('2600::1', output)

            check_json(networkctl_json())

        copy_network_unit('25-veth.netdev', '25-dhcp-server-veth-peer.network', '25-dhcp-client.network', copy_dropins=False)

        start_networkd()
        self.wait_online('veth-peer:carrier')
        start_dnsmasq('--dhcp-option=option:dns-server,192.168.5.1',
                      '--dhcp-option=option6:dns-server,[2600::1]')

        check(self, True, True)
        check(self, True, False)
        check(self, False, True, needs_reconfigure=True)
        check(self, False, False)

    def test_dhcp_client_default_use_domains(self):
        def check(self, common, ipv4, ipv6):
            mkdir_p(networkd_conf_dropin_dir)
            with open(os.path.join(networkd_conf_dropin_dir, 'default_use_domains.conf'), mode='w', encoding='utf-8') as f:
                f.write('[Network]\nUseDomains=')
                f.write('yes\n' if common else 'no\n')
                f.write('[DHCPv4]\nUseDomains=')
                f.write('yes\n' if ipv4 else 'no\n')
                f.write('[DHCPv6]\nUseDomains=')
                f.write('yes\n' if ipv6 else 'no\n')

            restart_networkd()
            self.wait_online('veth-peer:carrier')
            start_dnsmasq('--dhcp-option=option:dns-server,192.168.5.1',
                          '--dhcp-option=option6:dns-server,[2600::1]',
                          '--dhcp-option=option:domain-search,example.com',
                          '--dhcp-option=option6:domain-search,example.com')

            self.wait_online('veth99:routable')

            # link becomes 'routable' when at least one protocol provide an valid address. Hence, we need to explicitly wait for both addresses.
            self.wait_address('veth99', r'inet 192.168.5.[0-9]*/24 metric 1024 brd 192.168.5.255 scope global dynamic', ipv='-4')
            self.wait_address('veth99', r'inet6 2600::[0-9a-f]*/128 scope global (dynamic noprefixroute|noprefixroute dynamic)', ipv='-6')

            for _ in range(20):
                output = resolvectl('domain', 'veth99')
                if common or ipv4 or ipv6:
                    if 'example.com' in output:
                        break
                else:
                    if 'example.com' not in output:
                        break
                time.sleep(0.5)
            else:
                print(output)
                print(read_link_state_file('veth99'))
                self.fail('unexpected domain setting in resolved...')

            stop_dnsmasq()
            remove_networkd_conf_dropin('default_use_domains.conf')

        copy_network_unit('25-veth.netdev', '25-dhcp-server-veth-peer.network', '25-dhcp-client.network', copy_dropins=False)
        check(self, True, False, False)
        check(self, False, True, True)
        check(self, False, True, False)
        check(self, False, False, True)
        check(self, False, False, False)

    def test_dhcp_client_use_dnr(self):
        def check(self, ipv4, ipv6, needs_reconfigure=False):
            os.makedirs(os.path.join(network_unit_dir, '25-dhcp-client.network.d'), exist_ok=True)
            with open(os.path.join(network_unit_dir, '25-dhcp-client.network.d/override.conf'), mode='w', encoding='utf-8') as f:
                f.write('[DHCPv4]\nUseDNS=')
                f.write('yes' if ipv4 else 'no')
                f.write('\n[DHCPv6]\nUseDNS=')
                f.write('yes' if ipv6 else 'no')
                f.write('\n[IPv6AcceptRA]\nUseDNS=no')

            networkctl_reload()
            if needs_reconfigure:
                networkctl_reconfigure('veth99')
            self.wait_online('veth99:routable')

            # link becomes 'routable' when at least one protocol provide an valid address. Hence, we need to explicitly wait for both addresses.
            self.wait_address('veth99', r'inet 192.168.5.[0-9]*/24 metric 1024 brd 192.168.5.255 scope global dynamic', ipv='-4')
            self.wait_address('veth99', r'inet6 2600::[0-9a-f]*/128 scope global (dynamic noprefixroute|noprefixroute dynamic)', ipv='-6')

            # make resolved re-read the link state file
            resolvectl('revert', 'veth99')

            output = resolvectl('dns', 'veth99')
            print(output)
            if ipv4:
                self.assertIn('8.8.8.8#dns.google', output)
                self.assertIn('0.7.4.2#homer.simpson', output)
            else:
                self.assertNotIn('8.8.8.8#dns.google', output)
            if ipv6:
                self.assertIn('2001:4860:4860::8888#dns.google', output)
            else:
                self.assertNotIn('2001:4860:4860::8888#dns.google', output)

            check_json(networkctl_json())

        copy_network_unit('25-veth.netdev', '25-dhcp-server-veth-peer.network', '25-dhcp-client.network', copy_dropins=False)

        start_networkd()
        self.wait_online('veth-peer:carrier')
        dnr_v4 = dnr_v4_instance_data(adn = "dns.google", addrs = ["8.8.8.8", "8.8.4.4"])
        dnr_v4 += dnr_v4_instance_data(adn = "homer.simpson", addrs = ["0.7.4.2"], alpns = ("dot","h2","h3"), dohpath = "/springfield{?dns}")
        dnr_v6 = dnr_v6_instance_data(adn = "dns.google", addrs = ["2001:4860:4860::8888", "2001:4860:4860::8844"])
        masq = lambda bs: ':'.join(f"{b:02x}" for b in bs)
        start_dnsmasq(f'--dhcp-option=162,{masq(dnr_v4)}',
                      f'--dhcp-option=option6:144,{masq(dnr_v6)}')

        check(self, True, True)
        check(self, True, False)
        check(self, False, True, needs_reconfigure=True)
        check(self, False, False)

    def test_dhcp_client_use_captive_portal(self):
        def check(self, ipv4, ipv6, needs_reconfigure=False):
            os.makedirs(os.path.join(network_unit_dir, '25-dhcp-client.network.d'), exist_ok=True)
            with open(os.path.join(network_unit_dir, '25-dhcp-client.network.d/override.conf'), mode='w', encoding='utf-8') as f:
                f.write('[DHCPv4]\nUseCaptivePortal=')
                f.write('yes' if ipv4 else 'no')
                f.write('\n[DHCPv6]\nUseCaptivePortal=')
                f.write('yes' if ipv6 else 'no')
                f.write('\n[IPv6AcceptRA]\nUseCaptivePortal=no')

            networkctl_reload()
            if needs_reconfigure:
                networkctl_reconfigure('veth99')
            self.wait_online('veth99:routable')

            # link becomes 'routable' when at least one protocol provide an valid address. Hence, we need to explicitly wait for both addresses.
            self.wait_address('veth99', r'inet 192.168.5.[0-9]*/24 metric 1024 brd 192.168.5.255 scope global dynamic', ipv='-4')
            self.wait_address('veth99', r'inet6 2600::[0-9a-f]*/128 scope global (dynamic noprefixroute|noprefixroute dynamic)', ipv='-6')

            output = networkctl_status('veth99')
            print(output)
            if ipv4 or ipv6:
                self.assertIn('Captive Portal: http://systemd.io', output)
            else:
                self.assertNotIn('Captive Portal: http://systemd.io', output)

            check_json(networkctl_json())

        copy_network_unit('25-veth.netdev', '25-dhcp-server-veth-peer.network', '25-dhcp-client.network', copy_dropins=False)

        start_networkd()
        self.wait_online('veth-peer:carrier')
        start_dnsmasq('--dhcp-option=114,http://systemd.io',
                      '--dhcp-option=option6:103,http://systemd.io')

        check(self, True, True)
        check(self, True, False)
        check(self, False, True, needs_reconfigure=True)
        check(self, False, False)

    def test_dhcp_client_reject_captive_portal(self):
        def check(self, ipv4, ipv6):
            os.makedirs(os.path.join(network_unit_dir, '25-dhcp-client.network.d'), exist_ok=True)
            with open(os.path.join(network_unit_dir, '25-dhcp-client.network.d/override.conf'), mode='w', encoding='utf-8') as f:
                f.write('[DHCPv4]\nUseCaptivePortal=')
                f.write('yes' if ipv4 else 'no')
                f.write('\n[DHCPv6]\nUseCaptivePortal=')
                f.write('yes' if ipv6 else 'no')
                f.write('\n[IPv6AcceptRA]\nUseCaptivePortal=no')

            networkctl_reload()
            self.wait_online('veth99:routable')

            # link becomes 'routable' when at least one protocol provide an valid address. Hence, we need to explicitly wait for both addresses.
            self.wait_address('veth99', r'inet 192.168.5.[0-9]*/24 metric 1024 brd 192.168.5.255 scope global dynamic', ipv='-4')
            self.wait_address('veth99', r'inet6 2600::[0-9a-f]*/128 scope global (dynamic noprefixroute|noprefixroute dynamic)', ipv='-6')

            output = networkctl_status('veth99')
            print(output)
            self.assertNotIn('Captive Portal: ', output)
            self.assertNotIn('invalid/url', output)

            check_json(networkctl_json())

        copy_network_unit('25-veth.netdev', '25-dhcp-server-veth-peer.network', '25-dhcp-client.network', copy_dropins=False)

        start_networkd()
        self.wait_online('veth-peer:carrier')
        masq = lambda bs: ':'.join(f'{b:02x}' for b in bs)
        start_dnsmasq('--dhcp-option=114,' + masq(b'http://\x00invalid/url'),
                      '--dhcp-option=option6:103,' + masq(b'http://\x00/invalid/url'))

        check(self, True, True)
        check(self, True, False)
        check(self, False, True)
        check(self, False, False)

class NetworkdDHCPPDTests(unittest.TestCase, Utilities):

    def setUp(self):
        setup_common()

    def tearDown(self):
        tear_down_common()

    def check_dhcp6_prefix(self, link):
        description = get_link_description(link)

        self.assertIn('DHCPv6Client', description.keys())
        self.assertIn('Prefixes', description['DHCPv6Client'])

        prefixInfo = description['DHCPv6Client']['Prefixes']

        self.assertEqual(len(prefixInfo), 1)

        self.assertIn('Prefix', prefixInfo[0].keys())
        self.assertIn('PrefixLength', prefixInfo[0].keys())
        self.assertIn('PreferredLifetimeUSec', prefixInfo[0].keys())
        self.assertIn('ValidLifetimeUSec', prefixInfo[0].keys())

        self.assertEqual(prefixInfo[0]['Prefix'][0:6], [63, 254, 5, 1, 255, 255])
        self.assertEqual(prefixInfo[0]['PrefixLength'], 56)
        self.assertGreater(prefixInfo[0]['PreferredLifetimeUSec'], 0)
        self.assertGreater(prefixInfo[0]['ValidLifetimeUSec'], 0)

    @unittest.skipUnless(shutil.which('dhcpd'), reason="dhcpd is not available")
    def test_dhcp6pd_no_address(self):
        # For issue #29979.
        copy_network_unit('25-veth.netdev', '25-dhcp6pd-server.network', '25-dhcp6pd-upstream-no-address.network')

        start_networkd()
        self.wait_online('veth-peer:routable')
        start_isc_dhcpd(conf_file='isc-dhcpd-dhcp6pd.conf', ipv='-6')
        self.wait_online('veth99:degraded')

        print('### ip -6 address show dev veth99 scope global')
        output = check_output('ip -6 address show dev veth99 scope global')
        print(output)
        self.assertNotIn('inet6 3ffe:501:ffff', output)

        print('### ip -6 route show dev lo')
        output = check_output('ip -6 route show dev lo')
        print(output)
        self.assertNotRegex(output, '3ffe:501:ffff:[2-9a-f]00::/56')

        self.check_dhcp6_prefix('veth99')

    @unittest.skipUnless(shutil.which('dhcpd'), reason="dhcpd is not available")
    def test_dhcp6pd_no_assign(self):
        # Similar to test_dhcp6pd_no_assign(), but in this case UseAddress=yes (default),
        # However, the server does not provide IA_NA. For issue #31349.
        copy_network_unit('25-veth.netdev', '25-dhcp6pd-server.network', '25-dhcp6pd-upstream-no-assign.network')

        start_networkd()
        self.wait_online('veth-peer:routable')
        start_isc_dhcpd(conf_file='isc-dhcpd-dhcp6pd-no-range.conf', ipv='-6')
        self.wait_online('veth99:degraded')

        print('### ip -6 address show dev veth99 scope global')
        output = check_output('ip -6 address show dev veth99 scope global')
        print(output)
        self.assertNotIn('inet6 3ffe:501:ffff', output)

        print('### ip -6 route show type blackhole')
        output = check_output('ip -6 route show type blackhole')
        print(output)
        self.assertRegex(output, 'blackhole 3ffe:501:ffff:[2-9a-f]00::/56 dev lo proto dhcp')

        self.check_dhcp6_prefix('veth99')

    @unittest.skipUnless(shutil.which('dhcpd'), reason="dhcpd is not available")
    def test_dhcp6pd(self):
        copy_network_unit('25-veth.netdev', '25-dhcp6pd-server.network', '25-dhcp6pd-upstream.network',
                          '25-veth-downstream-veth97.netdev', '25-dhcp-pd-downstream-veth97.network', '25-dhcp-pd-downstream-veth97-peer.network',
                          '25-veth-downstream-veth98.netdev', '25-dhcp-pd-downstream-veth98.network', '25-dhcp-pd-downstream-veth98-peer.network',
                          '11-dummy.netdev', '25-dhcp-pd-downstream-test1.network',
                          '25-dhcp-pd-downstream-dummy97.network',
                          '12-dummy.netdev', '25-dhcp-pd-downstream-dummy98.network',
                          '13-dummy.netdev', '25-dhcp-pd-downstream-dummy99.network')

        start_networkd()
        self.wait_online('veth-peer:routable')
        start_isc_dhcpd(conf_file='isc-dhcpd-dhcp6pd.conf', ipv='-6')
        self.wait_online('veth99:routable', 'test1:routable', 'dummy98:routable', 'dummy99:degraded',
                         'veth97:routable', 'veth97-peer:routable', 'veth98:routable', 'veth98-peer:routable')

        self.setup_nftset('addr6', 'ipv6_addr')
        self.setup_nftset('network6', 'ipv6_addr', 'flags interval;')
        self.setup_nftset('ifindex', 'iface_index')

        # Check DBus assigned prefix information to veth99
        self.check_dhcp6_prefix('veth99')

        print('### ip -6 address show dev veth-peer scope global')
        output = check_output('ip -6 address show dev veth-peer scope global')
        print(output)
        self.assertIn('inet6 3ffe:501:ffff:100::1/64 scope global', output)

        # Link     Subnet IDs
        # test1:   0x00
        # dummy97: 0x01 (The link will appear later)
        # dummy98: 0x00
        # dummy99: auto -> 0x02 (No address assignment)
        # veth97:  0x08
        # veth98:  0x09
        # veth99:  0x10

        print('### ip -6 address show dev veth99 scope global')
        output = check_output('ip -6 address show dev veth99 scope global')
        print(output)
        # IA_NA
        self.assertRegex(output, 'inet6 3ffe:501:ffff:100::[0-9]*/128 scope global (dynamic noprefixroute|noprefixroute dynamic)')
        # address in IA_PD (Token=static)
        self.assertRegex(output, 'inet6 3ffe:501:ffff:[2-9a-f]10:1a:2b:3c:4d/64 (metric 256 |)scope global dynamic')
        # address in IA_PD (Token=eui64)
        self.assertRegex(output, 'inet6 3ffe:501:ffff:[2-9a-f]10:1034:56ff:fe78:9abc/64 (metric 256 |)scope global dynamic')
        # address in IA_PD (temporary)
        # Note that the temporary addresses may appear after the link enters configured state
        self.wait_address('veth99', 'inet6 3ffe:501:ffff:[2-9a-f]10:[0-9a-f]*:[0-9a-f]*:[0-9a-f]*:[0-9a-f]*/64 (metric 256 |)scope global temporary dynamic', ipv='-6')

        print('### ip -6 address show dev test1 scope global')
        output = check_output('ip -6 address show dev test1 scope global')
        print(output)
        # address in IA_PD (Token=static)
        self.assertRegex(output, 'inet6 3ffe:501:ffff:[2-9a-f]00:1a:2b:3c:4d/64 (metric 256 |)scope global dynamic mngtmpaddr')
        # address in IA_PD (temporary)
        self.wait_address('test1', 'inet6 3ffe:501:ffff:[2-9a-f]00:[0-9a-f]*:[0-9a-f]*:[0-9a-f]*:[0-9a-f]*/64 (metric 256 |)scope global temporary dynamic', ipv='-6')

        print('### ip -6 address show dev dummy98 scope global')
        output = check_output('ip -6 address show dev dummy98 scope global')
        print(output)
        # address in IA_PD (Token=static)
        self.assertRegex(output, 'inet6 3ffe:501:ffff:[2-9a-f]00:1a:2b:3c:4d/64 (metric 256 |)scope global dynamic mngtmpaddr')
        # address in IA_PD (temporary)
        self.wait_address('dummy98', 'inet6 3ffe:501:ffff:[2-9a-f]00:[0-9a-f]*:[0-9a-f]*:[0-9a-f]*:[0-9a-f]*/64 (metric 256 |)scope global temporary dynamic', ipv='-6')

        print('### ip -6 address show dev dummy99 scope global')
        output = check_output('ip -6 address show dev dummy99 scope global')
        print(output)
        # Assign=no
        self.assertNotRegex(output, 'inet6 3ffe:501:ffff:[2-9a-f]02')

        print('### ip -6 address show dev veth97 scope global')
        output = check_output('ip -6 address show dev veth97 scope global')
        print(output)
        # address in IA_PD (Token=static)
        self.assertRegex(output, 'inet6 3ffe:501:ffff:[2-9a-f]08:1a:2b:3c:4d/64 (metric 256 |)scope global dynamic mngtmpaddr')
        # address in IA_PD (Token=eui64)
        self.assertRegex(output, 'inet6 3ffe:501:ffff:[2-9a-f]08:1034:56ff:fe78:9ace/64 (metric 256 |)scope global dynamic mngtmpaddr')
        # address in IA_PD (temporary)
        self.wait_address('veth97', 'inet6 3ffe:501:ffff:[2-9a-f]08:[0-9a-f]*:[0-9a-f]*:[0-9a-f]*:[0-9a-f]*/64 (metric 256 |)scope global temporary dynamic', ipv='-6')

        print('### ip -6 address show dev veth97-peer scope global')
        output = check_output('ip -6 address show dev veth97-peer scope global')
        print(output)
        # NDisc address (Token=static)
        self.assertRegex(output, 'inet6 3ffe:501:ffff:[2-9a-f]08:1a:2b:3c:4e/64 (metric 256 |)scope global dynamic mngtmpaddr')
        # NDisc address (Token=eui64)
        self.assertRegex(output, 'inet6 3ffe:501:ffff:[2-9a-f]08:1034:56ff:fe78:9acf/64 (metric 256 |)scope global dynamic mngtmpaddr')
        # NDisc address (temporary)
        self.wait_address('veth97-peer', 'inet6 3ffe:501:ffff:[2-9a-f]08:[0-9a-f]*:[0-9a-f]*:[0-9a-f]*:[0-9a-f]*/64 (metric 256 |)scope global temporary dynamic', ipv='-6')

        print('### ip -6 address show dev veth98 scope global')
        output = check_output('ip -6 address show dev veth98 scope global')
        print(output)
        # address in IA_PD (Token=static)
        self.assertRegex(output, 'inet6 3ffe:501:ffff:[2-9a-f]09:1a:2b:3c:4d/64 (metric 256 |)scope global dynamic mngtmpaddr')
        # address in IA_PD (Token=eui64)
        self.assertRegex(output, 'inet6 3ffe:501:ffff:[2-9a-f]09:1034:56ff:fe78:9abe/64 (metric 256 |)scope global dynamic mngtmpaddr')
        # address in IA_PD (temporary)
        self.wait_address('veth98', 'inet6 3ffe:501:ffff:[2-9a-f]09:[0-9a-f]*:[0-9a-f]*:[0-9a-f]*:[0-9a-f]*/64 (metric 256 |)scope global temporary dynamic', ipv='-6')

        print('### ip -6 address show dev veth98-peer scope global')
        output = check_output('ip -6 address show dev veth98-peer scope global')
        print(output)
        # NDisc address (Token=static)
        self.assertRegex(output, 'inet6 3ffe:501:ffff:[2-9a-f]09:1a:2b:3c:4e/64 (metric 256 |)scope global dynamic mngtmpaddr')
        # NDisc address (Token=eui64)
        self.assertRegex(output, 'inet6 3ffe:501:ffff:[2-9a-f]09:1034:56ff:fe78:9abf/64 (metric 256 |)scope global dynamic mngtmpaddr')
        # NDisc address (temporary)
        self.wait_address('veth98-peer', 'inet6 3ffe:501:ffff:[2-9a-f]09:[0-9a-f]*:[0-9a-f]*:[0-9a-f]*:[0-9a-f]*/64 (metric 256 |)scope global temporary dynamic', ipv='-6')

        print('### ip -6 route show type unreachable')
        output = check_output('ip -6 route show type unreachable')
        print(output)
        self.assertRegex(output, 'unreachable 3ffe:501:ffff:[2-9a-f]00::/56 dev lo proto dhcp')

        print('### ip -6 route show dev veth99')
        output = check_output('ip -6 route show dev veth99')
        print(output)
        self.assertRegex(output, '3ffe:501:ffff:[2-9a-f]10::/64 proto kernel metric [0-9]* expires')

        print('### ip -6 route show dev test1')
        output = check_output('ip -6 route show dev test1')
        print(output)
        self.assertRegex(output, '3ffe:501:ffff:[2-9a-f]00::/64 proto kernel metric [0-9]* expires')

        print('### ip -6 route show dev dummy98')
        output = check_output('ip -6 route show dev dummy98')
        print(output)
        self.assertRegex(output, '3ffe:501:ffff:[2-9a-f]00::/64 proto kernel metric [0-9]* expires')

        print('### ip -6 route show dev dummy99')
        output = check_output('ip -6 route show dev dummy99')
        print(output)
        self.assertRegex(output, '3ffe:501:ffff:[2-9a-f]02::/64 proto dhcp metric [0-9]* expires')

        print('### ip -6 route show dev veth97')
        output = check_output('ip -6 route show dev veth97')
        print(output)
        self.assertRegex(output, '3ffe:501:ffff:[2-9a-f]08::/64 proto kernel metric [0-9]* expires')

        print('### ip -6 route show dev veth97-peer')
        output = check_output('ip -6 route show dev veth97-peer')
        print(output)
        self.assertRegex(output, '3ffe:501:ffff:[2-9a-f]08::/64 proto ra metric [0-9]* expires')

        print('### ip -6 route show dev veth98')
        output = check_output('ip -6 route show dev veth98')
        print(output)
        self.assertRegex(output, '3ffe:501:ffff:[2-9a-f]09::/64 proto kernel metric [0-9]* expires')

        print('### ip -6 route show dev veth98-peer')
        output = check_output('ip -6 route show dev veth98-peer')
        print(output)
        self.assertRegex(output, '3ffe:501:ffff:[2-9a-f]09::/64 proto ra metric [0-9]* expires')

        # Test case for a downstream which appears later
        check_output('ip link add dummy97 type dummy')
        self.wait_online('dummy97:routable')

        print('### ip -6 address show dev dummy97 scope global')
        output = check_output('ip -6 address show dev dummy97 scope global')
        print(output)
        # address in IA_PD (Token=static)
        self.assertRegex(output, 'inet6 3ffe:501:ffff:[2-9a-f]01:1a:2b:3c:4d/64 (metric 256 |)scope global dynamic mngtmpaddr')
        # address in IA_PD (temporary)
        self.wait_address('dummy97', 'inet6 3ffe:501:ffff:[2-9a-f]01:[0-9a-f]*:[0-9a-f]*:[0-9a-f]*:[0-9a-f]*/64 (metric 256 |)scope global temporary dynamic', ipv='-6')

        print('### ip -6 route show dev dummy97')
        output = check_output('ip -6 route show dev dummy97')
        print(output)
        self.assertRegex(output, '3ffe:501:ffff:[2-9a-f]01::/64 proto kernel metric [0-9]* expires')

        # Test case for reconfigure
        networkctl_reconfigure('dummy98', 'dummy99')
        self.wait_online('dummy98:routable', 'dummy99:degraded')

        print('### ip -6 address show dev dummy98 scope global')
        output = check_output('ip -6 address show dev dummy98 scope global')
        print(output)
        # address in IA_PD (Token=static)
        self.assertRegex(output, 'inet6 3ffe:501:ffff:[2-9a-f]00:1a:2b:3c:4d/64 (metric 256 |)scope global dynamic mngtmpaddr')
        # address in IA_PD (temporary)
        self.wait_address('dummy98', 'inet6 3ffe:501:ffff:[2-9a-f]00:[0-9a-f]*:[0-9a-f]*:[0-9a-f]*:[0-9a-f]*/64 (metric 256 |)scope global temporary dynamic', ipv='-6')

        print('### ip -6 address show dev dummy99 scope global')
        output = check_output('ip -6 address show dev dummy99 scope global')
        print(output)
        # Assign=no
        self.assertNotRegex(output, 'inet6 3ffe:501:ffff:[2-9a-f]02')

        print('### ip -6 route show dev dummy98')
        output = check_output('ip -6 route show dev dummy98')
        print(output)
        self.assertRegex(output, '3ffe:501:ffff:[2-9a-f]00::/64 proto kernel metric [0-9]* expires')

        print('### ip -6 route show dev dummy99')
        output = check_output('ip -6 route show dev dummy99')
        print(output)
        self.assertRegex(output, '3ffe:501:ffff:[2-9a-f]02::/64 proto dhcp metric [0-9]* expires')

        self.check_netlabel('dummy98', '3ffe:501:ffff:[2-9a-f]00::/64')

        self.check_nftset('addr6', '3ffe:501:ffff:[2-9a-f]00:1a:2b:3c:4d')
        self.check_nftset('addr6', '3ffe:501:ffff:[2-9a-f]00:[0-9a-f]*:[0-9a-f]*:[0-9a-f]*:[0-9a-f]*')
        self.check_nftset('network6', '3ffe:501:ffff:[2-9a-f]00::/64')
        self.check_nftset('ifindex', 'dummy98')

        self.teardown_nftset('addr6', 'network6', 'ifindex')

    def verify_dhcp4_6rd(self, tunnel_name, address_prefix, border_router):
        print('### ip -4 address show dev veth-peer scope global')
        output = check_output('ip -4 address show dev veth-peer scope global')
        print(output)
        self.assertIn('inet 10.0.0.1/8 brd 10.255.255.255 scope global veth-peer', output)

        # Link     Subnet IDs
        # test1:   0x00
        # dummy97: 0x01 (The link will appear later)
        # dummy98: 0x00
        # dummy99: auto -> 0x0[23] (No address assignment)
        # 6rd-XXX: auto -> 0x0[23]
        # veth97:  0x08
        # veth98:  0x09
        # veth99:  0x10

        print('### ip -4 address show dev veth99 scope global')
        output = check_output('ip -4 address show dev veth99 scope global')
        print(output)
        self.assertRegex(output, fr'inet {address_prefix}[0-9]*/8 (metric 1024 |)brd 10.255.255.255 scope global dynamic veth99')

        print('### ip -6 address show dev veth99 scope global')
        output = check_output('ip -6 address show dev veth99 scope global')
        print(output)
        # address in IA_PD (Token=static)
        self.assertRegex(output, 'inet6 2001:db8:6464:[0-9a-f]+10:1a:2b:3c:4d/64 (metric 256 |)scope global dynamic mngtmpaddr')
        # address in IA_PD (Token=eui64)
        self.assertRegex(output, 'inet6 2001:db8:6464:[0-9a-f]+10:1034:56ff:fe78:9abc/64 (metric 256 |)scope global dynamic mngtmpaddr')
        # address in IA_PD (temporary)
        # Note that the temporary addresses may appear after the link enters configured state
        self.wait_address('veth99', 'inet6 2001:db8:6464:[0-9a-f]+10:[0-9a-f]*:[0-9a-f]*:[0-9a-f]*:[0-9a-f]*/64 (metric 256 |)scope global temporary dynamic', ipv='-6')

        print('### ip -6 address show dev test1 scope global')
        output = check_output('ip -6 address show dev test1 scope global')
        print(output)
        # address in IA_PD (Token=static)
        self.assertRegex(output, 'inet6 2001:db8:6464:[0-9a-f]+00:1a:2b:3c:4d/64 (metric 256 |)scope global dynamic mngtmpaddr')
        # address in IA_PD (temporary)
        self.wait_address('test1', 'inet6 2001:db8:6464:[0-9a-f]+00:[0-9a-f]*:[0-9a-f]*:[0-9a-f]*:[0-9a-f]*/64 (metric 256 |)scope global temporary dynamic', ipv='-6')

        print('### ip -6 address show dev dummy98 scope global')
        output = check_output('ip -6 address show dev dummy98 scope global')
        print(output)
        # address in IA_PD (Token=static)
        self.assertRegex(output, 'inet6 2001:db8:6464:[0-9a-f]+00:1a:2b:3c:4d/64 (metric 256 |)scope global dynamic mngtmpaddr')
        # address in IA_PD (temporary)
        self.wait_address('dummy98', 'inet6 2001:db8:6464:[0-9a-f]+00:[0-9a-f]*:[0-9a-f]*:[0-9a-f]*:[0-9a-f]*/64 (metric 256 |)scope global temporary dynamic', ipv='-6')

        print('### ip -6 address show dev dummy99 scope global')
        output = check_output('ip -6 address show dev dummy99 scope global')
        print(output)
        # Assign=no
        self.assertNotRegex(output, 'inet6 2001:db8:6464:[0-9a-f]+0[23]')

        print('### ip -6 address show dev veth97 scope global')
        output = check_output('ip -6 address show dev veth97 scope global')
        print(output)
        # address in IA_PD (Token=static)
        self.assertRegex(output, 'inet6 2001:db8:6464:[0-9a-f]+08:1a:2b:3c:4d/64 (metric 256 |)scope global dynamic mngtmpaddr')
        # address in IA_PD (Token=eui64)
        self.assertRegex(output, 'inet6 2001:db8:6464:[0-9a-f]+08:1034:56ff:fe78:9ace/64 (metric 256 |)scope global dynamic mngtmpaddr')
        # address in IA_PD (temporary)
        self.wait_address('veth97', 'inet6 2001:db8:6464:[0-9a-f]+08:[0-9a-f]*:[0-9a-f]*:[0-9a-f]*:[0-9a-f]*/64 (metric 256 |)scope global temporary dynamic', ipv='-6')

        print('### ip -6 address show dev veth97-peer scope global')
        output = check_output('ip -6 address show dev veth97-peer scope global')
        print(output)
        # NDisc address (Token=static)
        self.assertRegex(output, 'inet6 2001:db8:6464:[0-9a-f]+08:1a:2b:3c:4e/64 (metric 256 |)scope global dynamic mngtmpaddr')
        # NDisc address (Token=eui64)
        self.assertRegex(output, 'inet6 2001:db8:6464:[0-9a-f]+08:1034:56ff:fe78:9acf/64 (metric 256 |)scope global dynamic mngtmpaddr')
        # NDisc address (temporary)
        self.wait_address('veth97-peer', 'inet6 2001:db8:6464:[0-9a-f]+08:[0-9a-f]*:[0-9a-f]*:[0-9a-f]*:[0-9a-f]*/64 (metric 256 |)scope global temporary dynamic', ipv='-6')

        print('### ip -6 address show dev veth98 scope global')
        output = check_output('ip -6 address show dev veth98 scope global')
        print(output)
        # address in IA_PD (Token=static)
        self.assertRegex(output, 'inet6 2001:db8:6464:[0-9a-f]+09:1a:2b:3c:4d/64 (metric 256 |)scope global dynamic mngtmpaddr')
        # address in IA_PD (Token=eui64)
        self.assertRegex(output, 'inet6 2001:db8:6464:[0-9a-f]+09:1034:56ff:fe78:9abe/64 (metric 256 |)scope global dynamic mngtmpaddr')
        # address in IA_PD (temporary)
        self.wait_address('veth98', 'inet6 2001:db8:6464:[0-9a-f]+09:[0-9a-f]*:[0-9a-f]*:[0-9a-f]*:[0-9a-f]*/64 (metric 256 |)scope global temporary dynamic', ipv='-6')

        print('### ip -6 address show dev veth98-peer scope global')
        output = check_output('ip -6 address show dev veth98-peer scope global')
        print(output)
        # NDisc address (Token=static)
        self.assertRegex(output, 'inet6 2001:db8:6464:[0-9a-f]+09:1a:2b:3c:4e/64 (metric 256 |)scope global dynamic mngtmpaddr')
        # NDisc address (Token=eui64)
        self.assertRegex(output, 'inet6 2001:db8:6464:[0-9a-f]+09:1034:56ff:fe78:9abf/64 (metric 256 |)scope global dynamic mngtmpaddr')
        # NDisc address (temporary)
        self.wait_address('veth98-peer', 'inet6 2001:db8:6464:[0-9a-f]+09:[0-9a-f]*:[0-9a-f]*:[0-9a-f]*:[0-9a-f]*/64 (metric 256 |)scope global temporary dynamic', ipv='-6')

        print('### ip -6 route show type unreachable')
        output = check_output('ip -6 route show type unreachable')
        print(output)
        self.assertRegex(output, 'unreachable 2001:db8:6464:[0-9a-f]+00::/56 dev lo proto dhcp')

        print('### ip -6 route show dev veth99')
        output = check_output('ip -6 route show dev veth99')
        print(output)
        self.assertRegex(output, '2001:db8:6464:[0-9a-f]+10::/64 proto kernel metric [0-9]* expires')

        print('### ip -6 route show dev test1')
        output = check_output('ip -6 route show dev test1')
        print(output)
        self.assertRegex(output, '2001:db8:6464:[0-9a-f]+00::/64 proto kernel metric [0-9]* expires')

        print('### ip -6 route show dev dummy98')
        output = check_output('ip -6 route show dev dummy98')
        print(output)
        self.assertRegex(output, '2001:db8:6464:[0-9a-f]+00::/64 proto kernel metric [0-9]* expires')

        print('### ip -6 route show dev dummy99')
        output = check_output('ip -6 route show dev dummy99')
        print(output)
        self.assertRegex(output, '2001:db8:6464:[0-9a-f]+0[23]::/64 proto dhcp metric [0-9]* expires')

        print('### ip -6 route show dev veth97')
        output = check_output('ip -6 route show dev veth97')
        print(output)
        self.assertRegex(output, '2001:db8:6464:[0-9a-f]+08::/64 proto kernel metric [0-9]* expires')

        print('### ip -6 route show dev veth97-peer')
        output = check_output('ip -6 route show dev veth97-peer')
        print(output)
        self.assertRegex(output, '2001:db8:6464:[0-9a-f]+08::/64 proto ra metric [0-9]* expires')

        print('### ip -6 route show dev veth98')
        output = check_output('ip -6 route show dev veth98')
        print(output)
        self.assertRegex(output, '2001:db8:6464:[0-9a-f]+09::/64 proto kernel metric [0-9]* expires')

        print('### ip -6 route show dev veth98-peer')
        output = check_output('ip -6 route show dev veth98-peer')
        print(output)
        self.assertRegex(output, '2001:db8:6464:[0-9a-f]+09::/64 proto ra metric [0-9]* expires')

        print('### ip -6 address show dev dummy97 scope global')
        output = check_output('ip -6 address show dev dummy97 scope global')
        print(output)
        # address in IA_PD (Token=static)
        self.assertRegex(output, 'inet6 2001:db8:6464:[0-9a-f]+01:1a:2b:3c:4d/64 (metric 256 |)scope global dynamic mngtmpaddr')
        # address in IA_PD (temporary)
        self.wait_address('dummy97', 'inet6 2001:db8:6464:[0-9a-f]+01:[0-9a-f]*:[0-9a-f]*:[0-9a-f]*:[0-9a-f]*/64 (metric 256 |)scope global temporary dynamic', ipv='-6')

        print('### ip -6 route show dev dummy97')
        output = check_output('ip -6 route show dev dummy97')
        print(output)
        self.assertRegex(output, '2001:db8:6464:[0-9a-f]+01::/64 proto kernel metric [0-9]* expires')

        print(f'### ip -d link show dev {tunnel_name}')
        output = check_output(f'ip -d link show dev {tunnel_name}')
        print(output)
        self.assertIn(f'link/sit {address_prefix}', output)
        self.assertIn(f'local {address_prefix}', output)
        self.assertIn('ttl 64', output)
        self.assertIn('6rd-prefix 2001:db8::/32', output)
        self.assertIn('6rd-relay_prefix 10.0.0.0/8', output)

        print(f'### ip -6 address show dev {tunnel_name}')
        output = check_output(f'ip -6 address show dev {tunnel_name}')
        print(output)
        self.assertRegex(output, 'inet6 2001:db8:6464:[0-9a-f]+0[23]:[0-9a-f]*:[0-9a-f]*:[0-9a-f]*:[0-9a-f]*/64 (metric 256 |)scope global dynamic')
        self.assertRegex(output, fr'inet6 ::{address_prefix}[0-9]+/96 scope global')

        print(f'### ip -6 route show dev {tunnel_name}')
        output = check_output(f'ip -6 route show dev {tunnel_name}')
        print(output)
        self.assertRegex(output, '2001:db8:6464:[0-9a-f]+0[23]::/64 proto kernel metric [0-9]* expires')
        self.assertRegex(output, '::/96 proto kernel metric [0-9]*')

        print('### ip -6 route show default')
        output = check_output('ip -6 route show default')
        print(output)
        self.assertIn('default', output)
        self.assertIn(f'via ::{border_router} dev {tunnel_name}', output)

    def test_dhcp4_6rd(self):
        def get_dhcp_6rd_prefix(link):
            description = get_link_description(link)

            self.assertIn('DHCPv4Client', description.keys())
            self.assertIn('6rdPrefix', description['DHCPv4Client'].keys())

            prefixInfo = description['DHCPv4Client']['6rdPrefix']
            self.assertIn('Prefix', prefixInfo.keys())
            self.assertIn('PrefixLength', prefixInfo.keys())
            self.assertIn('IPv4MaskLength', prefixInfo.keys())
            self.assertIn('BorderRouters', prefixInfo.keys())

            return prefixInfo

        copy_network_unit('25-veth.netdev', '25-dhcp4-6rd-server.network', '25-dhcp4-6rd-upstream.network',
                          '25-veth-downstream-veth97.netdev', '25-dhcp-pd-downstream-veth97.network', '25-dhcp-pd-downstream-veth97-peer.network',
                          '25-veth-downstream-veth98.netdev', '25-dhcp-pd-downstream-veth98.network', '25-dhcp-pd-downstream-veth98-peer.network',
                          '11-dummy.netdev', '25-dhcp-pd-downstream-test1.network',
                          '25-dhcp-pd-downstream-dummy97.network',
                          '12-dummy.netdev', '25-dhcp-pd-downstream-dummy98.network',
                          '13-dummy.netdev', '25-dhcp-pd-downstream-dummy99.network',
                          '80-6rd-tunnel.network')

        start_networkd()
        self.wait_online('veth-peer:routable')

        # ipv4masklen: 8
        # 6rd-prefix: 2001:db8::/32
        # br-addresss: 10.0.0.1

        start_dnsmasq('--dhcp-option=212,08:20:20:01:0d:b8:00:00:00:00:00:00:00:00:00:00:00:00:0a:00:00:01',
                      ipv4_range='10.100.100.100,10.100.100.200',
                      ipv4_router='10.0.0.1')
        self.wait_online('veth99:routable', 'test1:routable', 'dummy98:routable', 'dummy99:degraded',
                         'veth97:routable', 'veth97-peer:routable', 'veth98:routable', 'veth98-peer:routable')

        # Check the DBus interface for assigned prefix information
        prefixInfo = get_dhcp_6rd_prefix('veth99')

        self.assertEqual(prefixInfo['Prefix'], [32,1,13,184,0,0,0,0,0,0,0,0,0,0,0,0]) # 2001:db8::
        self.assertEqual(prefixInfo['PrefixLength'], 32)
        self.assertEqual(prefixInfo['IPv4MaskLength'], 8)
        self.assertEqual(prefixInfo['BorderRouters'], [[10,0,0,1]])

        # Test case for a downstream which appears later
        check_output('ip link add dummy97 type dummy')
        self.wait_online('dummy97:routable')

        # Find tunnel name
        tunnel_name = None
        for name in os.listdir('/sys/class/net/'):
            if name.startswith('6rd-'):
                tunnel_name = name
                break

        self.wait_online(f'{tunnel_name}:routable')

        self.verify_dhcp4_6rd(tunnel_name, '10.100.100.1', '10.0.0.1')

        # Test case for reconfigure
        networkctl_reconfigure('dummy98', 'dummy99')
        self.wait_online('dummy98:routable', 'dummy99:degraded')

        self.verify_dhcp4_6rd(tunnel_name, '10.100.100.1', '10.0.0.1')

        # Change the address range and (border) router, then if check the same tunnel is reused.
        stop_dnsmasq()
        start_dnsmasq('--dhcp-option=212,08:20:20:01:0d:b8:00:00:00:00:00:00:00:00:00:00:00:00:0a:00:00:02',
                      ipv4_range='10.100.100.200,10.100.100.250',
                      ipv4_router='10.0.0.2')

        print('Wait for the DHCP lease to be renewed/rebind')
        time.sleep(120)

        self.wait_online('veth99:routable', 'test1:routable', 'dummy97:routable', 'dummy98:routable', 'dummy99:degraded',
                         'veth97:routable', 'veth97-peer:routable', 'veth98:routable', 'veth98-peer:routable')

        self.verify_dhcp4_6rd(tunnel_name, '10.100.100.2', '10.0.0.2')

class NetworkdIPv6PrefixTests(unittest.TestCase, Utilities):

    def setUp(self):
        setup_common()

    def tearDown(self):
        tear_down_common()

    def test_ipv6_route_prefix(self):
        copy_network_unit('25-veth.netdev', '25-ipv6ra-prefix-client.network', '25-ipv6ra-prefix.network',
                          '12-dummy.netdev', '25-ipv6ra-uplink.network')

        start_networkd()
        self.wait_online('veth99:routable', 'veth-peer:routable', 'dummy98:routable')

        print('### ip -6 address show dev veth-peer')
        output = check_output('ip -6 address show dev veth-peer')
        print(output)
        self.assertIn('inet6 2001:db8:0:1:', output)
        self.assertNotIn('inet6 2001:db8:0:2:', output)
        self.assertNotIn('inet6 2001:db8:0:3:', output)

        print('### ip -6 route show dev veth-peer')
        output = check_output('ip -6 route show dev veth-peer')
        print(output)
        self.assertIn('2001:db8:0:1::/64 proto ra', output)
        self.assertNotIn('2001:db8:0:2::/64 proto ra', output)
        self.assertNotIn('2001:db8:0:3::/64 proto ra', output)
        self.assertRegex(output, r'2001:db0:fff::/64 nhid [0-9]* via fe80::1034:56ff:fe78:9abc')
        self.assertNotIn('2001:db1:fff::/64', output)
        self.assertNotIn('2001:db2:fff::/64', output)

        print('### ip -6 nexthop show dev veth-peer')
        output = check_output('ip -6 nexthop show dev veth-peer')
        print(output)
        self.assertRegex(output, r'id [0-9]* via fe80::1034:56ff:fe78:9abc dev veth-peer scope link proto ra')

        print('### ip -6 address show dev veth99')
        output = check_output('ip -6 address show dev veth99')
        print(output)
        self.assertNotIn('inet6 2001:db8:0:1:', output)
        self.assertIn('inet6 2001:db8:0:2:1a:2b:3c:4d', output)
        self.assertIn('inet6 2001:db8:0:2:fa:de:ca:fe', output)
        self.assertNotIn('inet6 2001:db8:0:3:', output)

        output = resolvectl('dns', 'veth-peer')
        print(output)
        self.assertRegex(output, '2001:db8:1:1::2')

        output = resolvectl('domain', 'veth-peer')
        print(output)
        self.assertIn('example.com', output)

        check_json(networkctl_json())

        output = networkctl_json('veth-peer')
        check_json(output)

        # PREF64 or NAT64
        pref64 = json.loads(output)['NDisc']['PREF64'][0]

        prefix = socket.inet_ntop(socket.AF_INET6, bytearray(pref64['Prefix']))
        self.assertEqual(prefix, '64:ff9b::')

        prefix_length = pref64['PrefixLength']
        self.assertEqual(prefix_length, 96)

    def test_ipv6_route_prefix_deny_list(self):
        copy_network_unit('25-veth.netdev', '25-ipv6ra-prefix-client-deny-list.network', '25-ipv6ra-prefix.network',
                          '12-dummy.netdev', '25-ipv6ra-uplink.network')

        start_networkd()
        self.wait_online('veth99:routable', 'veth-peer:routable', 'dummy98:routable')

        print('### ip -6 address show dev veth-peer')
        output = check_output('ip -6 address show dev veth-peer')
        print(output)
        self.assertIn('inet6 2001:db8:0:1:', output)
        self.assertNotIn('inet6 2001:db8:0:2:', output)

        print('### ip -6 route show dev veth-peer')
        output = check_output('ip -6 route show dev veth-peer')
        print(output)
        self.assertIn('2001:db8:0:1::/64 proto ra', output)
        self.assertNotIn('2001:db8:0:2::/64 proto ra', output)
        self.assertRegex(output, r'2001:db0:fff::/64 nhid [0-9]* via fe80::1034:56ff:fe78:9abc')
        self.assertNotIn('2001:db1:fff::/64', output)

        print('### ip -6 nexthop show dev veth-peer')
        output = check_output('ip -6 nexthop show dev veth-peer')
        print(output)
        self.assertRegex(output, r'id [0-9]* via fe80::1034:56ff:fe78:9abc dev veth-peer scope link proto ra')

        print('### ip -6 address show dev veth99')
        output = check_output('ip -6 address show dev veth99')
        print(output)
        self.assertNotIn('inet6 2001:db8:0:1:', output)
        self.assertIn('inet6 2001:db8:0:2:', output)

        output = resolvectl('dns', 'veth-peer')
        print(output)
        self.assertRegex(output, '2001:db8:1:1::2')

        output = resolvectl('domain', 'veth-peer')
        print(output)
        self.assertIn('example.com', output)

class NetworkdMTUTests(unittest.TestCase, Utilities):

    def setUp(self):
        setup_common()

    def tearDown(self):
        tear_down_common()

    def check_mtu(self, mtu, ipv6_mtu=None, reset=True):
        if not ipv6_mtu:
            ipv6_mtu = mtu

        # test normal start
        start_networkd()
        self.wait_online('dummy98:routable')
        self.check_link_attr('dummy98', 'mtu', mtu)
        self.check_ipv6_sysctl_attr('dummy98', 'mtu', ipv6_mtu)

        # test normal restart
        restart_networkd()
        self.wait_online('dummy98:routable')
        self.check_link_attr('dummy98', 'mtu', mtu)
        self.check_ipv6_sysctl_attr('dummy98', 'mtu', ipv6_mtu)

        if reset:
            self.reset_check_mtu(mtu, ipv6_mtu)

    def reset_check_mtu(self, mtu, ipv6_mtu=None):
        ''' test setting mtu/ipv6_mtu with interface already up '''
        stop_networkd()

        # note - changing the device mtu resets the ipv6 mtu
        check_output('ip link set up mtu 1501 dev dummy98')
        check_output('ip link set up mtu 1500 dev dummy98')
        self.check_link_attr('dummy98', 'mtu', '1500')
        self.check_ipv6_sysctl_attr('dummy98', 'mtu', '1500')

        self.check_mtu(mtu, ipv6_mtu, reset=False)

    def test_mtu_network(self):
        copy_network_unit('12-dummy.netdev', '12-dummy.network.d/mtu.conf')
        self.check_mtu('1600')

    def test_mtu_netdev(self):
        copy_network_unit('12-dummy-mtu.netdev', '12-dummy.network', copy_dropins=False)
        # note - MTU set by .netdev happens ONLY at device creation!
        self.check_mtu('1600', reset=False)

    def test_mtu_link(self):
        copy_network_unit('12-dummy.netdev', '12-dummy-mtu.link', '12-dummy.network', copy_dropins=False)
        # note - MTU set by .link happens ONLY at udev processing of device 'add' uevent!
        self.check_mtu('1600', reset=False)

    def test_ipv6_mtu(self):
        ''' set ipv6 mtu without setting device mtu '''
        copy_network_unit('12-dummy.netdev', '12-dummy.network.d/ipv6-mtu-1400.conf')
        self.check_mtu('1500', '1400')

    def test_ipv6_mtu_toolarge(self):
        ''' try set ipv6 mtu over device mtu (it shouldn't work) '''
        copy_network_unit('12-dummy.netdev', '12-dummy.network.d/ipv6-mtu-1550.conf')
        self.check_mtu('1500', '1500')

    def test_mtu_network_ipv6_mtu(self):
        ''' set ipv6 mtu and set device mtu via network file '''
        copy_network_unit('12-dummy.netdev', '12-dummy.network.d/mtu.conf', '12-dummy.network.d/ipv6-mtu-1550.conf')
        self.check_mtu('1600', '1550')

    def test_mtu_netdev_ipv6_mtu(self):
        ''' set ipv6 mtu and set device mtu via netdev file '''
        copy_network_unit('12-dummy-mtu.netdev', '12-dummy.network.d/ipv6-mtu-1550.conf')
        self.check_mtu('1600', '1550', reset=False)

    def test_mtu_link_ipv6_mtu(self):
        ''' set ipv6 mtu and set device mtu via link file '''
        copy_network_unit('12-dummy.netdev', '12-dummy-mtu.link', '12-dummy.network.d/ipv6-mtu-1550.conf')
        self.check_mtu('1600', '1550', reset=False)

class NetworkdSysctlTest(unittest.TestCase, Utilities):

    def setUp(self):
        setup_common()

    def tearDown(self):
        tear_down_common()

    @unittest.skipUnless(compare_kernel_version("6.12"), reason="On kernels <= 6.12, bpf_current_task_under_cgroup() isn't available for program types BPF_PROG_TYPE_CGROUP_SYSCTL")
    def check_sysctl_watch(self):
        copy_network_unit('12-dummy.network', '12-dummy.netdev', '12-dummy.link')
        start_networkd()

        self.wait_online('dummy98:routable')

        # Change managed sysctls
        call('sysctl -w net.ipv6.conf.dummy98.accept_ra=1')
        call('sysctl -w net.ipv6.conf.dummy98.mtu=1360')
        call('sysctl -w net.ipv4.conf.dummy98.promote_secondaries=0')
        call('sysctl -w net.ipv6.conf.dummy98.proxy_ndp=1')

        # And unmanaged ones
        call('sysctl -w net.ipv6.conf.dummy98.hop_limit=4')
        call('sysctl -w net.ipv6.conf.dummy98.max_addresses=10')

        log=read_networkd_log()
        self.assertRegex(log, r"Foreign process 'sysctl\[\d+\]' changed sysctl '/proc/sys/net/ipv6/conf/dummy98/accept_ra' from '0' to '1', conflicting with our setting to '0'")
        self.assertRegex(log, r"Foreign process 'sysctl\[\d+\]' changed sysctl '/proc/sys/net/ipv6/conf/dummy98/mtu' from '1550' to '1360', conflicting with our setting to '1550'")
        self.assertRegex(log, r"Foreign process 'sysctl\[\d+\]' changed sysctl '/proc/sys/net/ipv4/conf/dummy98/promote_secondaries' from '1' to '0', conflicting with our setting to '1'")
        self.assertRegex(log, r"Foreign process 'sysctl\[\d+\]' changed sysctl '/proc/sys/net/ipv6/conf/dummy98/proxy_ndp' from '0' to '1', conflicting with our setting to '0'")
        self.assertNotIn("changed sysctl '/proc/sys/net/ipv6/conf/dummy98/hop_limit'", log)
        self.assertNotIn("changed sysctl '/proc/sys/net/ipv6/conf/dummy98/max_addresses'", log)

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--build-dir', help='Path to build dir', dest='build_dir')
    parser.add_argument('--source-dir', help='Path to source dir/git tree', dest='source_dir')
    parser.add_argument('--valgrind', help='Enable valgrind', dest='use_valgrind', type=bool, nargs='?', const=True, default=use_valgrind)
    parser.add_argument('--debug', help='Generate debugging logs', dest='enable_debug', type=bool, nargs='?', const=True, default=enable_debug)
    parser.add_argument('--asan-options', help='ASAN options', dest='asan_options')
    parser.add_argument('--lsan-options', help='LSAN options', dest='lsan_options')
    parser.add_argument('--ubsan-options', help='UBSAN options', dest='ubsan_options')
    parser.add_argument('--with-coverage', help='Loosen certain sandbox restrictions to make gcov happy', dest='with_coverage', type=bool, nargs='?', const=True, default=with_coverage)
    parser.add_argument('--no-journal', help='Do not show journal of systemd-networkd on stop', dest='show_journal', action='store_false')
    ns, unknown_args = parser.parse_known_args(namespace=unittest)

    if ns.build_dir:
        networkd_bin = os.path.join(ns.build_dir, 'systemd-networkd')
        resolved_bin = os.path.join(ns.build_dir, 'systemd-resolved')
        timesyncd_bin = os.path.join(ns.build_dir, 'systemd-timesyncd')
        wait_online_bin = os.path.join(ns.build_dir, 'systemd-networkd-wait-online')
        networkctl_bin = os.path.join(ns.build_dir, 'networkctl')
        resolvectl_bin = os.path.join(ns.build_dir, 'resolvectl')
        timedatectl_bin = os.path.join(ns.build_dir, 'timedatectl')
        udevadm_bin = os.path.join(ns.build_dir, 'udevadm')
        build_dir = ns.build_dir

    if ns.source_dir:
        source_dir = ns.source_dir
        assert os.path.exists(os.path.join(source_dir, "meson_options.txt")), f"{source_dir} doesn't appear to be a systemd source tree."
    elif os.path.exists(os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "../../meson_options.txt"))):
        source_dir = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "../../"))
    else:
        source_dir = None

    use_valgrind = ns.use_valgrind
    enable_debug = ns.enable_debug
    asan_options = ns.asan_options
    lsan_options = ns.lsan_options
    ubsan_options = ns.ubsan_options
    with_coverage = ns.with_coverage or "COVERAGE_BUILD_DIR" in os.environ
    show_journal = ns.show_journal

    if use_valgrind:
        # Do not forget the trailing space.
        valgrind_cmd = 'valgrind --track-origins=yes --leak-check=full --show-leak-kinds=all '

    networkctl_cmd = valgrind_cmd.split() + [networkctl_bin]
    resolvectl_cmd = valgrind_cmd.split() + [resolvectl_bin]
    timedatectl_cmd = valgrind_cmd.split() + [timedatectl_bin]
    udevadm_cmd = valgrind_cmd.split() + [udevadm_bin]
    wait_online_cmd = valgrind_cmd.split() + [wait_online_bin]

    if build_dir:
        test_ndisc_send = os.path.normpath(os.path.join(build_dir, 'test-ndisc-send'))
    else:
        test_ndisc_send = '/usr/lib/tests/test-ndisc-send'

    if asan_options:
        env.update({'ASAN_OPTIONS': asan_options})
    if lsan_options:
        env.update({'LSAN_OPTIONS': lsan_options})
    if ubsan_options:
        env.update({'UBSAN_OPTIONS': ubsan_options})
    if use_valgrind:
        env.update({'SYSTEMD_MEMPOOL': '0'})

    wait_online_env = env.copy()
    if enable_debug:
        wait_online_env.update({'SYSTEMD_LOG_LEVEL': 'debug'})

    unittest.main(
        verbosity=3,
        argv=[
            sys.argv[0],
            *unknown_args,
            *(["-k", match] if (match := os.getenv("TEST_MATCH_TESTCASE")) else [])
        ],
    )
