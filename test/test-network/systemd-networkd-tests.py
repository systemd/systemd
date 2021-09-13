#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
# systemd-networkd tests

import argparse
import itertools
import os
import re
import shutil
import signal
import subprocess
import sys
import time
import unittest
from shutil import copytree

network_unit_file_path='/run/systemd/network'
networkd_runtime_directory='/run/systemd/netif'
networkd_conf_dropin_path='/run/systemd/networkd.conf.d'
networkd_ci_path='/run/networkd-ci'
network_sysctl_ipv6_path='/proc/sys/net/ipv6/conf'
network_sysctl_ipv4_path='/proc/sys/net/ipv4/conf'

dnsmasq_pid_file='/run/networkd-ci/test-test-dnsmasq.pid'
dnsmasq_log_file='/run/networkd-ci/test-dnsmasq-log-file'

systemd_lib_paths=['/usr/lib/systemd', '/lib/systemd']
which_paths=':'.join(systemd_lib_paths + os.getenv('PATH', os.defpath).lstrip(':').split(':'))

networkd_bin=shutil.which('systemd-networkd', path=which_paths)
resolved_bin=shutil.which('systemd-resolved', path=which_paths)
udevd_bin=shutil.which('systemd-udevd', path=which_paths)
wait_online_bin=shutil.which('systemd-networkd-wait-online', path=which_paths)
networkctl_bin=shutil.which('networkctl', path=which_paths)
resolvectl_bin=shutil.which('resolvectl', path=which_paths)
timedatectl_bin=shutil.which('timedatectl', path=which_paths)

use_valgrind=False
enable_debug=True
env = {}
asan_options=None
lsan_options=None
ubsan_options=None

running_units = []

def check_output(*command, **kwargs):
    # This replaces both check_output and check_call (output can be ignored)
    command = command[0].split() + list(command[1:])
    return subprocess.check_output(command, universal_newlines=True, **kwargs).rstrip()

def call(*command, **kwargs):
    command = command[0].split() + list(command[1:])
    return subprocess.call(command, universal_newlines=True, **kwargs)

def run(*command, **kwargs):
    command = command[0].split() + list(command[1:])
    return subprocess.run(command, universal_newlines=True, **kwargs)

def is_module_available(module_name):
    lsmod_output = check_output('lsmod')
    module_re = re.compile(rf'^{re.escape(module_name)}\b', re.MULTILINE)
    return module_re.search(lsmod_output) or not call('modprobe', module_name, stderr=subprocess.DEVNULL)

def expectedFailureIfModuleIsNotAvailable(module_name):
    def f(func):
        if not is_module_available(module_name):
            return unittest.expectedFailure(func)
        return func

    return f

def expectedFailureIfERSPANModuleIsNotAvailable():
    def f(func):
        rc = call('ip link add dev erspan99 type erspan seq key 30 local 192.168.1.4 remote 192.168.1.1 erspan_ver 1 erspan 123', stderr=subprocess.DEVNULL)
        if rc == 0:
            call('ip link del erspan99')
            return func
        else:
            return unittest.expectedFailure(func)

    return f

def expectedFailureIfRoutingPolicyPortRangeIsNotAvailable():
    def f(func):
        rc = call('ip rule add from 192.168.100.19 sport 1123-1150 dport 3224-3290 table 7', stderr=subprocess.DEVNULL)
        if rc == 0:
            call('ip rule del from 192.168.100.19 sport 1123-1150 dport 3224-3290 table 7')
            return func
        else:
            return unittest.expectedFailure(func)

    return f

def expectedFailureIfRoutingPolicyIPProtoIsNotAvailable():
    def f(func):
        rc = call('ip rule add not from 192.168.100.19 ipproto tcp table 7', stderr=subprocess.DEVNULL)
        if rc == 0:
            call('ip rule del not from 192.168.100.19 ipproto tcp table 7')
            return func
        else:
            return unittest.expectedFailure(func)

    return f

def expectedFailureIfRoutingPolicyUIDRangeIsNotAvailable():
    def f(func):
        support = False
        rc = call('ip rule add from 192.168.100.19 table 7 uidrange 200-300', stderr=subprocess.DEVNULL)
        if rc == 0:
            ret = run('ip rule list from 192.168.100.19 table 7', stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            if ret.returncode == 0 and 'uidrange 200-300' in ret.stdout.rstrip():
                support = True
            call('ip rule del from 192.168.100.19 table 7 uidrange 200-300')

        if support:
            return func
        else:
            return unittest.expectedFailure(func)

    return f

def expectedFailureIfLinkFileFieldIsNotSet():
    def f(func):
        support = False
        rc = call('ip link add name dummy99 type dummy', stderr=subprocess.DEVNULL)
        if rc == 0:
            ret = run('udevadm info -w10s /sys/class/net/dummy99', stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            if ret.returncode == 0 and 'E: ID_NET_LINK_FILE=' in ret.stdout.rstrip():
                support = True
            call('ip link del dummy99')

        if support:
            return func
        else:
            return unittest.expectedFailure(func)

    return f

def expectedFailureIfNexthopIsNotAvailable():
    def f(func):
        rc = call('ip nexthop list', stderr=subprocess.DEVNULL)
        if rc == 0:
            return func
        else:
            return unittest.expectedFailure(func)

    return f

def expectedFailureIfRTA_VIAIsNotSupported():
    def f(func):
        call('ip link add dummy98 type dummy', stderr=subprocess.DEVNULL)
        call('ip link set up dev dummy98', stderr=subprocess.DEVNULL)
        call('ip route add 2001:1234:5:8fff:ff:ff:ff:fe/128 dev dummy98', stderr=subprocess.DEVNULL)
        rc = call('ip route add 10.10.10.10 via inet6 2001:1234:5:8fff:ff:ff:ff:fe dev dummy98', stderr=subprocess.DEVNULL)
        call('ip link del dummy98', stderr=subprocess.DEVNULL)
        if rc == 0:
            return func
        else:
            return unittest.expectedFailure(func)

    return f

def expectedFailureIfAlternativeNameIsNotAvailable():
    def f(func):
        call('ip link add dummy98 type dummy', stderr=subprocess.DEVNULL)
        rc = call('ip link prop add dev dummy98 altname hogehogehogehogehoge', stderr=subprocess.DEVNULL)
        call('ip link del dummy98', stderr=subprocess.DEVNULL)
        if rc == 0:
            return func
        else:
            return unittest.expectedFailure(func)

    return f

def expectedFailureIfNetdevsimWithSRIOVIsNotAvailable():
    def f(func):
        call('rmmod netdevsim', stderr=subprocess.DEVNULL)
        rc = call('modprobe netdevsim', stderr=subprocess.DEVNULL)
        if rc != 0:
            return unittest.expectedFailure(func)

        try:
            with open('/sys/bus/netdevsim/new_device', mode='w') as f:
                f.write('99 1')
        except Exception as error:
            return unittest.expectedFailure(func)

        call('udevadm settle')
        call('udevadm info -w10s /sys/devices/netdevsim99/net/eni99np1', stderr=subprocess.DEVNULL)
        try:
            with open('/sys/class/net/eni99np1/device/sriov_numvfs', mode='w') as f:
                f.write('3')
        except Exception as error:
            call('rmmod netdevsim', stderr=subprocess.DEVNULL)
            return unittest.expectedFailure(func)

        call('rmmod netdevsim', stderr=subprocess.DEVNULL)
        return func

    return f

def expectedFailureIfCAKEIsNotAvailable():
    def f(func):
        call('ip link add dummy98 type dummy', stderr=subprocess.DEVNULL)
        rc = call('tc qdisc add dev dummy98 parent root cake', stderr=subprocess.DEVNULL)
        call('ip link del dummy98', stderr=subprocess.DEVNULL)
        if rc == 0:
            return func
        else:
            return unittest.expectedFailure(func)

    return f

def expectedFailureIfPIEIsNotAvailable():
    def f(func):
        call('ip link add dummy98 type dummy', stderr=subprocess.DEVNULL)
        rc = call('tc qdisc add dev dummy98 parent root pie', stderr=subprocess.DEVNULL)
        call('ip link del dummy98', stderr=subprocess.DEVNULL)
        if rc == 0:
            return func
        else:
            return unittest.expectedFailure(func)

    return f

def expectedFailureIfHHFIsNotAvailable():
    def f(func):
        call('ip link add dummy98 type dummy', stderr=subprocess.DEVNULL)
        rc = call('tc qdisc add dev dummy98 parent root hhf', stderr=subprocess.DEVNULL)
        call('ip link del dummy98', stderr=subprocess.DEVNULL)
        if rc == 0:
            return func
        else:
            return unittest.expectedFailure(func)

    return f

def expectedFailureIfETSIsNotAvailable():
    def f(func):
        call('ip link add dummy98 type dummy', stderr=subprocess.DEVNULL)
        rc = call('tc qdisc add dev dummy98 parent root ets bands 10', stderr=subprocess.DEVNULL)
        call('ip link del dummy98', stderr=subprocess.DEVNULL)
        if rc == 0:
            return func
        else:
            return unittest.expectedFailure(func)

    return f

def expectedFailureIfFQPIEIsNotAvailable():
    def f(func):
        call('ip link add dummy98 type dummy', stderr=subprocess.DEVNULL)
        rc = call('tc qdisc add dev dummy98 parent root fq_pie', stderr=subprocess.DEVNULL)
        call('ip link del dummy98', stderr=subprocess.DEVNULL)
        if rc == 0:
            return func
        else:
            return unittest.expectedFailure(func)

    return f

def setUpModule():
    global running_units

    os.makedirs(network_unit_file_path, exist_ok=True)
    os.makedirs(networkd_conf_dropin_path, exist_ok=True)
    os.makedirs(networkd_ci_path, exist_ok=True)

    shutil.rmtree(networkd_ci_path)
    copytree(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'conf'), networkd_ci_path)

    for u in ['systemd-networkd.socket', 'systemd-networkd.service', 'systemd-resolved.service',
              'systemd-udevd-kernel.socket', 'systemd-udevd-control.socket', 'systemd-udevd.service',
              'firewalld.service']:
        if call(f'systemctl is-active --quiet {u}') == 0:
            check_output(f'systemctl stop {u}')
            running_units.append(u)

    drop_in = [
        '[Unit]',
        'StartLimitIntervalSec=0',
        '[Service]',
        'Restart=no',
        'ExecStart=',
    ]
    if use_valgrind:
        drop_in += [
            'ExecStart=!!valgrind --track-origins=yes --leak-check=full --show-leak-kinds=all ' + networkd_bin,
            'PrivateTmp=yes'
        ]
    else:
        drop_in += ['ExecStart=!!' + networkd_bin]
    if enable_debug:
        drop_in += ['Environment=SYSTEMD_LOG_LEVEL=debug']
    if asan_options:
        drop_in += ['Environment=ASAN_OPTIONS="' + asan_options + '"']
    if lsan_options:
        drop_in += ['Environment=LSAN_OPTIONS="' + lsan_options + '"']
    if ubsan_options:
        drop_in += ['Environment=UBSAN_OPTIONS="' + ubsan_options + '"']
    if asan_options or lsan_options or ubsan_options:
        drop_in += ['SystemCallFilter=']
    if use_valgrind or asan_options or lsan_options or ubsan_options:
        drop_in += ['MemoryDenyWriteExecute=no']

    os.makedirs('/run/systemd/system/systemd-networkd.service.d', exist_ok=True)
    with open('/run/systemd/system/systemd-networkd.service.d/00-override.conf', mode='w') as f:
        f.write('\n'.join(drop_in))

    drop_in = [
        '[Service]',
        'Restart=no',
        'ExecStart=',
    ]
    if use_valgrind:
        drop_in += ['ExecStart=!!valgrind --track-origins=yes --leak-check=full --show-leak-kinds=all ' + resolved_bin]
    else:
        drop_in += ['ExecStart=!!' + resolved_bin]
    if enable_debug:
        drop_in += ['Environment=SYSTEMD_LOG_LEVEL=debug']
    if asan_options:
        drop_in += ['Environment=ASAN_OPTIONS="' + asan_options + '"']
    if lsan_options:
        drop_in += ['Environment=LSAN_OPTIONS="' + lsan_options + '"']
    if ubsan_options:
        drop_in += ['Environment=UBSAN_OPTIONS="' + ubsan_options + '"']
    if asan_options or lsan_options or ubsan_options:
        drop_in += ['SystemCallFilter=']
    if use_valgrind or asan_options or lsan_options or ubsan_options:
        drop_in += ['MemoryDenyWriteExecute=no']

    os.makedirs('/run/systemd/system/systemd-resolved.service.d', exist_ok=True)
    with open('/run/systemd/system/systemd-resolved.service.d/00-override.conf', mode='w') as f:
        f.write('\n'.join(drop_in))

    drop_in = [
        '[Service]',
        'ExecStart=',
        'ExecStart=!!' + udevd_bin,
    ]

    os.makedirs('/run/systemd/system/systemd-udevd.service.d', exist_ok=True)
    with open('/run/systemd/system/systemd-udevd.service.d/00-override.conf', mode='w') as f:
        f.write('\n'.join(drop_in))

    check_output('systemctl daemon-reload')
    print(check_output('systemctl cat systemd-networkd.service'))
    print(check_output('systemctl cat systemd-resolved.service'))
    print(check_output('systemctl cat systemd-udevd.service'))
    check_output('systemctl restart systemd-resolved')
    check_output('systemctl restart systemd-udevd')

def tearDownModule():
    global running_units

    shutil.rmtree(networkd_ci_path)

    for u in ['systemd-networkd.socket', 'systemd-networkd.service', 'systemd-resolved.service']:
        check_output(f'systemctl stop {u}')

    shutil.rmtree('/run/systemd/system/systemd-networkd.service.d')
    shutil.rmtree('/run/systemd/system/systemd-resolved.service.d')
    shutil.rmtree('/run/systemd/system/systemd-udevd.service.d')
    check_output('systemctl daemon-reload')
    check_output('systemctl restart systemd-udevd.service')

    for u in running_units:
        check_output(f'systemctl start {u}')

def read_link_attr(*args):
    with open(os.path.join('/sys/class/net/', *args)) as f:
        return f.readline().strip()

def read_bridge_port_attr(bridge, link, attribute):
    path_bridge = os.path.join('/sys/devices/virtual/net', bridge)
    path_port = 'lower_' + link + '/brport'
    path = os.path.join(path_bridge, path_port)

    with open(os.path.join(path, attribute)) as f:
        return f.readline().strip()

def link_exists(link):
    return os.path.exists(os.path.join('/sys/class/net', link))

def remove_links(links):
    for link in links:
        if link_exists(link):
            call('ip link del dev', link)
    time.sleep(1)

def remove_fou_ports(ports):
    for port in ports:
        call('ip fou del port', port, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def remove_routing_policy_rule_tables(tables):
    for table in tables:
        rc = 0
        while rc == 0:
            rc = call('ip rule del table', table, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        rc = 0
        while rc == 0:
            rc = call('ip -6 rule del table', table, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def remove_routes(routes):
    for route_type, addr in routes:
        call('ip route del', route_type, addr, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def remove_blackhole_nexthops():
    ret = run('ip nexthop show dev lo', stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    if ret.returncode == 0:
        for line in ret.stdout.rstrip().splitlines():
            id = line.split()[1]
            call(f'ip nexthop del id {id}')

def remove_l2tp_tunnels(tunnel_ids):
    output = check_output('ip l2tp show tunnel')
    for tid in tunnel_ids:
        words='Tunnel ' + tid + ', encap'
        if words in output:
            call('ip l2tp del tunnel tid', tid)
    time.sleep(1)

def read_ipv6_sysctl_attr(link, attribute):
    with open(os.path.join(os.path.join(network_sysctl_ipv6_path, link), attribute)) as f:
        return f.readline().strip()

def read_ipv4_sysctl_attr(link, attribute):
    with open(os.path.join(os.path.join(network_sysctl_ipv4_path, link), attribute)) as f:
        return f.readline().strip()

def copy_unit_to_networkd_unit_path(*units, dropins=True):
    """Copy networkd unit files into the testbed.

    Any networkd unit file type can be specified, as well as drop-in files.

    By default, all drop-ins for a specified unit file are copied in;
    to avoid that specify dropins=False.

    When a drop-in file is specified, its unit file is also copied in automatically.
    """
    print()
    for unit in units:
        if dropins and os.path.exists(os.path.join(networkd_ci_path, unit + '.d')):
            copytree(os.path.join(networkd_ci_path, unit + '.d'), os.path.join(network_unit_file_path, unit + '.d'))
        if unit.endswith('.conf'):
            dropin = unit
            dropindir = os.path.join(network_unit_file_path, os.path.dirname(dropin))
            os.makedirs(dropindir, exist_ok=True)
            shutil.copy(os.path.join(networkd_ci_path, dropin), dropindir)
            unit = os.path.dirname(dropin).rstrip('.d')
        shutil.copy(os.path.join(networkd_ci_path, unit), network_unit_file_path)

def remove_unit_from_networkd_path(units):
    """Remove previously copied unit files from the testbed.

    Drop-ins will be removed automatically.
    """
    for unit in units:
        if (os.path.exists(os.path.join(network_unit_file_path, unit))):
            os.remove(os.path.join(network_unit_file_path, unit))
            if (os.path.exists(os.path.join(network_unit_file_path, unit + '.d'))):
                shutil.rmtree(os.path.join(network_unit_file_path, unit + '.d'))

def copy_networkd_conf_dropin(*dropins):
    """Copy networkd.conf dropin files into the testbed."""
    for dropin in dropins:
        shutil.copy(os.path.join(networkd_ci_path, dropin), networkd_conf_dropin_path)

def remove_networkd_conf_dropin(dropins):
    """Remove previously copied networkd.conf dropin files from the testbed."""
    for dropin in dropins:
        if (os.path.exists(os.path.join(networkd_conf_dropin_path, dropin))):
            os.remove(os.path.join(networkd_conf_dropin_path, dropin))

def start_dnsmasq(additional_options='', ipv4_range='192.168.5.10,192.168.5.200', ipv6_range='2600::10,2600::20', lease_time='1h'):
    dnsmasq_command = f'dnsmasq -8 /var/run/networkd-ci/test-dnsmasq-log-file --log-queries=extra --log-dhcp --pid-file=/var/run/networkd-ci/test-test-dnsmasq.pid --conf-file=/dev/null --interface=veth-peer --enable-ra --dhcp-range={ipv6_range},{lease_time} --dhcp-range={ipv4_range},{lease_time} -R --dhcp-leasefile=/var/run/networkd-ci/lease --dhcp-option=26,1492 --dhcp-option=option:router,192.168.5.1 --port=0 ' + additional_options
    check_output(dnsmasq_command)

def stop_dnsmasq(pid_file):
    if os.path.exists(pid_file):
        with open(pid_file, 'r') as f:
            pid = f.read().rstrip(' \t\r\n\0')
            os.kill(int(pid), signal.SIGTERM)

        os.remove(pid_file)

def search_words_in_dnsmasq_log(words, show_all=False):
    if os.path.exists(dnsmasq_log_file):
        with open (dnsmasq_log_file) as in_file:
            contents = in_file.read()
            if show_all:
                print(contents)
            for line in contents.splitlines():
                if words in line:
                    in_file.close()
                    print("%s, %s" % (words, line))
                    return True
    return False

def remove_lease_file():
    if os.path.exists(os.path.join(networkd_ci_path, 'lease')):
        os.remove(os.path.join(networkd_ci_path, 'lease'))

def remove_log_file():
    if os.path.exists(dnsmasq_log_file):
        os.remove(dnsmasq_log_file)

def remove_networkd_state_files():
    if os.path.exists(os.path.join(networkd_runtime_directory, 'state')):
        os.remove(os.path.join(networkd_runtime_directory, 'state'))

def stop_networkd(show_logs=True, remove_state_files=True):
    if show_logs:
        invocation_id = check_output('systemctl show systemd-networkd -p InvocationID --value')
    check_output('systemctl stop systemd-networkd.socket')
    check_output('systemctl stop systemd-networkd.service')
    if show_logs:
        print(check_output('journalctl _SYSTEMD_INVOCATION_ID=' + invocation_id))
    if remove_state_files:
        remove_networkd_state_files()

def start_networkd(sleep_sec=0):
    check_output('systemctl start systemd-networkd')
    if sleep_sec > 0:
        time.sleep(sleep_sec)

def restart_networkd(sleep_sec=0, show_logs=True, remove_state_files=True):
    stop_networkd(show_logs, remove_state_files)
    start_networkd(sleep_sec)


class Utilities():
    def check_link_exists(self, link):
        self.assertTrue(link_exists(link))

    def check_link_attr(self, *args):
        self.assertEqual(read_link_attr(*args[:-1]), args[-1]);

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

        for secs in range(setup_timeout + 1):
            output = check_output(*networkctl_cmd, '-n', '0', 'status', link, env=env)
            print(output)
            if re.search(rf'(?m)^\s*State:\s+{operstate}\s+\({setup_state}\)\s*$', output):
                return True
            # don't bother sleeping if time is up
            if secs < setup_timeout:
                time.sleep(1)
        if fail_assert:
            self.fail(f'Timed out waiting for {link} to reach state {operstate}/{setup_state}')
        return False

    def wait_online(self, links_with_operstate, timeout='20s', bool_any=False, ipv4=False, ipv6=False, setup_state='configured', setup_timeout=5):
        """Wait for the link(s) to reach the specified operstate and/or setup state.

        This is similar to wait_operstate() but can be used for multiple links,
        and it also calls systemd-networkd-wait-online to wait for the given operstate.
        The operstate should be specified in the link name, like 'eth0:degraded'.
        If just a link name is provided, wait-online's default operstate to wait for is degraded.

        The 'timeout' parameter controls the systemd-networkd-wait-online timeout, and the
        'setup_timeout' controls the per-link timeout waiting for the setup_state.

        Set 'bool_any' to True to wait for any (instead of all) of the given links.
        If this is set, no setup_state checks are done.

        Set 'ipv4' or 'ipv6' to True to wait for IPv4 address or IPv6 address, respectively, of each of the given links.
        This is applied only for the operational state 'degraded' or above.

        Note that this function waits for the link(s) to reach *or exceed* the given operstate.
        However, the setup_state, if specified, must be matched *exactly*.

        This returns if the link(s) reached the requested operstate/setup_state; otherwise it
        raises CalledProcessError or fails test assertion.
        """
        args = wait_online_cmd + [f'--timeout={timeout}'] + [f'--interface={link}' for link in links_with_operstate]
        if bool_any:
            args += ['--any']
        if ipv4:
            args += ['--ipv4']
        if ipv6:
            args += ['--ipv6']
        try:
            check_output(*args, env=env)
        except subprocess.CalledProcessError:
            for link in links_with_operstate:
                output = check_output(*networkctl_cmd, '-n', '0', 'status', link.split(':')[0], env=env)
                print(output)
            raise
        if not bool_any and setup_state:
            for link in links_with_operstate:
                self.wait_operstate(link.split(':')[0], None, setup_state, setup_timeout)

    def wait_address(self, link, address_regex, scope='global', ipv='', timeout_sec=100):
        for i in range(timeout_sec):
            if i > 0:
                time.sleep(1)
            output = check_output(f'ip {ipv} address show dev {link} scope {scope}')
            if re.search(address_regex, output) and 'tentative' not in output:
                break

        self.assertRegex(output, address_regex)

    def wait_address_dropped(self, link, address_regex, scope='global', ipv='', timeout_sec=100):
        for i in range(timeout_sec):
            if i > 0:
                time.sleep(1)
            output = check_output(f'ip {ipv} address show dev {link} scope {scope}')
            if not re.search(address_regex, output):
                break

        self.assertNotRegex(output, address_regex)

class NetworkctlTests(unittest.TestCase, Utilities):

    links = [
        'dummy98',
        'test1',
        'veth99',
    ]

    units = [
        '11-dummy.netdev',
        '11-dummy-mtu.netdev',
        '11-dummy.network',
        '12-dummy.netdev',
        '12-dummy.link',
        '25-address-static.network',
        '25-veth.netdev',
        'netdev-link-local-addressing-yes.network',
    ]

    def setUp(self):
        remove_links(self.links)
        stop_networkd(show_logs=False)

    def tearDown(self):
        remove_links(self.links)
        remove_unit_from_networkd_path(self.units)
        stop_networkd(show_logs=True)

    @expectedFailureIfAlternativeNameIsNotAvailable()
    def test_altname(self):
        copy_unit_to_networkd_unit_path('netdev-link-local-addressing-yes.network', '12-dummy.netdev', '12-dummy.link')
        check_output('udevadm control --reload')
        start_networkd()
        self.wait_online(['dummy98:degraded'])

        output = check_output(*networkctl_cmd, '-n', '0', 'status', 'dummy98', env=env)
        self.assertRegex(output, 'hogehogehogehogehogehoge')

    def test_reconfigure(self):
        copy_unit_to_networkd_unit_path('25-address-static.network', '12-dummy.netdev')
        start_networkd()
        self.wait_online(['dummy98:routable'])

        output = check_output('ip -4 address show dev dummy98')
        print(output)
        self.assertRegex(output, 'inet 10.1.2.3/16 brd 10.1.255.255 scope global dummy98')
        self.assertRegex(output, 'inet 10.1.2.4/16 brd 10.1.255.255 scope global secondary dummy98')
        self.assertRegex(output, 'inet 10.2.2.4/16 brd 10.2.255.255 scope global dummy98')

        check_output('ip address del 10.1.2.3/16 dev dummy98')
        check_output('ip address del 10.1.2.4/16 dev dummy98')
        check_output('ip address del 10.2.2.4/16 dev dummy98')

        check_output(*networkctl_cmd, 'reconfigure', 'dummy98', env=env)
        self.wait_online(['dummy98:routable'])

        output = check_output('ip -4 address show dev dummy98')
        print(output)
        self.assertRegex(output, 'inet 10.1.2.3/16 brd 10.1.255.255 scope global dummy98')
        self.assertRegex(output, 'inet 10.1.2.4/16 brd 10.1.255.255 scope global secondary dummy98')
        self.assertRegex(output, 'inet 10.2.2.4/16 brd 10.2.255.255 scope global dummy98')

    def test_reload(self):
        start_networkd(3)

        copy_unit_to_networkd_unit_path('11-dummy.netdev')
        check_output(*networkctl_cmd, 'reload', env=env)
        self.wait_operstate('test1', 'off', setup_state='unmanaged')

        copy_unit_to_networkd_unit_path('11-dummy.network')
        check_output(*networkctl_cmd, 'reload', env=env)
        self.wait_online(['test1:degraded'])

        remove_unit_from_networkd_path(['11-dummy.network'])
        check_output(*networkctl_cmd, 'reload', env=env)
        self.wait_operstate('test1', 'degraded', setup_state='unmanaged')

        remove_unit_from_networkd_path(['11-dummy.netdev'])
        check_output(*networkctl_cmd, 'reload', env=env)
        self.wait_operstate('test1', 'degraded', setup_state='unmanaged')

        copy_unit_to_networkd_unit_path('11-dummy.netdev', '11-dummy.network')
        check_output(*networkctl_cmd, 'reload', env=env)
        self.wait_operstate('test1', 'degraded')

    def test_glob(self):
        copy_unit_to_networkd_unit_path('11-dummy.netdev', '11-dummy.network')
        start_networkd()

        self.wait_online(['test1:degraded'])

        output = check_output(*networkctl_cmd, 'list', env=env)
        self.assertRegex(output, '1 lo ')
        self.assertRegex(output, 'test1')

        output = check_output(*networkctl_cmd, 'list', 'test1', env=env)
        self.assertNotRegex(output, '1 lo ')
        self.assertRegex(output, 'test1')

        output = check_output(*networkctl_cmd, 'list', 'te*', env=env)
        self.assertNotRegex(output, '1 lo ')
        self.assertRegex(output, 'test1')

        output = check_output(*networkctl_cmd, '-n', '0', 'status', 'te*', env=env)
        self.assertNotRegex(output, '1: lo ')
        self.assertRegex(output, 'test1')

        output = check_output(*networkctl_cmd, '-n', '0', 'status', 'tes[a-z][0-9]', env=env)
        self.assertNotRegex(output, '1: lo ')
        self.assertRegex(output, 'test1')

    def test_mtu(self):
        copy_unit_to_networkd_unit_path('11-dummy-mtu.netdev', '11-dummy.network')
        start_networkd()

        self.wait_online(['test1:degraded'])

        output = check_output(*networkctl_cmd, '-n', '0', 'status', 'test1', env=env)
        self.assertRegex(output, 'MTU: 1600')

    def test_type(self):
        copy_unit_to_networkd_unit_path('11-dummy.netdev', '11-dummy.network')
        start_networkd()
        self.wait_online(['test1:degraded'])

        output = check_output(*networkctl_cmd, '-n', '0', 'status', 'test1', env=env)
        print(output)
        self.assertRegex(output, 'Type: ether')

        output = check_output(*networkctl_cmd, '-n', '0', 'status', 'lo', env=env)
        print(output)
        self.assertRegex(output, 'Type: loopback')

    @expectedFailureIfLinkFileFieldIsNotSet()
    def test_udev_link_file(self):
        copy_unit_to_networkd_unit_path('11-dummy.netdev', '11-dummy.network')
        start_networkd()
        self.wait_online(['test1:degraded'])

        output = check_output(*networkctl_cmd, '-n', '0', 'status', 'test1', env=env)
        print(output)
        self.assertRegex(output, r'Link File: (/usr)?/lib/systemd/network/99-default.link')
        self.assertRegex(output, r'Network File: /run/systemd/network/11-dummy.network')

        output = check_output(*networkctl_cmd, '-n', '0', 'status', 'lo', env=env)
        print(output)
        self.assertRegex(output, r'Link File: n/a')
        self.assertRegex(output, r'Network File: n/a')

    def test_delete_links(self):
        copy_unit_to_networkd_unit_path('11-dummy.netdev', '11-dummy.network',
                                        '25-veth.netdev', 'netdev-link-local-addressing-yes.network')
        start_networkd()

        self.wait_online(['test1:degraded', 'veth99:degraded', 'veth-peer:degraded'])

        check_output(*networkctl_cmd, 'delete', 'test1', 'veth99', env=env)
        self.assertFalse(link_exists('test1'))
        self.assertFalse(link_exists('veth99'))
        self.assertFalse(link_exists('veth-peer'))

class NetworkdNetDevTests(unittest.TestCase, Utilities):

    links_remove_earlier = [
        'xfrm99',
    ]

    links = [
        '6rdtun99',
        'bareudp99',
        'batadv99',
        'bond98',
        'bond99',
        'bridge99',
        'dropin-test',
        'dummy98',
        'erspan98',
        'erspan99',
        'geneve99',
        'gretap96',
        'gretap98',
        'gretap99',
        'gretun96',
        'gretun97',
        'gretun98',
        'gretun99',
        'ifb99',
        'ip6gretap98',
        'ip6gretap99',
        'ip6gretun96',
        'ip6gretun97',
        'ip6gretun98',
        'ip6gretun99',
        'ip6tnl97',
        'ip6tnl98',
        'ip6tnl99',
        'ipiptun96',
        'ipiptun97',
        'ipiptun98',
        'ipiptun99',
        'ipvlan99',
        'ipvtap99',
        'isataptun99',
        'macvlan99',
        'macvtap99',
        'nlmon99',
        'sittun96',
        'sittun97',
        'sittun98',
        'sittun99',
        'tap99',
        'test1',
        'tun99',
        'vcan99',
        'veth99',
        'vlan99',
        'vrf99',
        'vti6tun97',
        'vti6tun98',
        'vti6tun99',
        'vtitun96',
        'vtitun97',
        'vtitun98',
        'vtitun99',
        'vxcan99',
        'vxlan98',
        'vxlan99',
        'wg97',
        'wg98',
        'wg99',
    ]

    units = [
        '10-dropin-test.netdev',
        '11-dummy.netdev',
        '11-dummy.network',
        '12-dummy.netdev',
        '13-not-match-udev-property.network',
        '14-match-udev-property.network',
        '15-name-conflict-test.netdev',
        '21-macvlan.netdev',
        '21-macvtap.netdev',
        '21-vlan-test1.network',
        '21-vlan.netdev',
        '21-vlan.network',
        '25-6rd-tunnel.netdev',
        '25-bareudp.netdev',
        '25-batadv.netdev',
        '25-bond.netdev',
        '25-bond-balanced-tlb.netdev',
        '25-bridge.netdev',
        '25-bridge-configure-without-carrier.network',
        '25-bridge.network',
        '25-erspan-tunnel-local-any.netdev',
        '25-erspan-tunnel.netdev',
        '25-fou-gretap.netdev',
        '25-fou-gre.netdev',
        '25-fou-ipip.netdev',
        '25-fou-ipproto-gre.netdev',
        '25-fou-ipproto-ipip.netdev',
        '25-fou-sit.netdev',
        '25-geneve.netdev',
        '25-gretap-tunnel-local-any.netdev',
        '25-gretap-tunnel.netdev',
        '25-gre-tunnel-any-any.netdev',
        '25-gre-tunnel-local-any.netdev',
        '25-gre-tunnel-remote-any.netdev',
        '25-gre-tunnel.netdev',
        '25-ifb.netdev',
        '25-ip6gretap-tunnel-local-any.netdev',
        '25-ip6gretap-tunnel.netdev',
        '25-ip6gre-tunnel-any-any.netdev',
        '25-ip6gre-tunnel-local-any.netdev',
        '25-ip6gre-tunnel-remote-any.netdev',
        '25-ip6gre-tunnel.netdev',
        '25-ip6tnl-tunnel-any-any.netdev',
        '25-ip6tnl-tunnel-local-any.netdev',
        '25-ip6tnl-tunnel-remote-any.netdev',
        '25-ip6tnl-tunnel.netdev',
        '25-ipip-tunnel-any-any.netdev',
        '25-ipip-tunnel-independent.netdev',
        '25-ipip-tunnel-independent-loopback.netdev',
        '25-ipip-tunnel-local-any.netdev',
        '25-ipip-tunnel-remote-any.netdev',
        '25-ipip-tunnel.netdev',
        '25-ipvlan.netdev',
        '25-ipvtap.netdev',
        '25-isatap-tunnel.netdev',
        '25-macsec.key',
        '25-macsec.netdev',
        '25-macsec.network',
        '25-nlmon.netdev',
        '25-sit-tunnel-any-any.netdev',
        '25-sit-tunnel-local-any.netdev',
        '25-sit-tunnel-remote-any.netdev',
        '25-sit-tunnel.netdev',
        '25-tap.netdev',
        '25-tun.netdev',
        '25-tunnel-any-any.network',
        '25-tunnel-local-any.network',
        '25-tunnel-remote-any.network',
        '25-tunnel.network',
        '25-vcan.netdev',
        '25-veth.netdev',
        '25-vrf.netdev',
        '25-vti6-tunnel-any-any.netdev',
        '25-vti6-tunnel-local-any.netdev',
        '25-vti6-tunnel-remote-any.netdev',
        '25-vti6-tunnel.netdev',
        '25-vti-tunnel-any-any.netdev',
        '25-vti-tunnel-local-any.netdev',
        '25-vti-tunnel-remote-any.netdev',
        '25-vti-tunnel.netdev',
        '25-vxcan.netdev',
        '25-vxlan-independent.netdev',
        '25-vxlan.netdev',
        '25-wireguard-23-peers.netdev',
        '25-wireguard-23-peers.network',
        '25-wireguard-no-peer.netdev',
        '25-wireguard-no-peer.network',
        '25-wireguard-preshared-key.txt',
        '25-wireguard-private-key.txt',
        '25-wireguard.netdev',
        '25-wireguard.network',
        '25-xfrm.netdev',
        '25-xfrm-independent.netdev',
        '6rd.network',
        'erspan.network',
        'gre.network',
        'gretap.network',
        'gretun.network',
        'ip6gretap.network',
        'ip6gretun.network',
        'ip6tnl.network',
        'ipip.network',
        'ipvlan.network',
        'ipvtap.network',
        'isatap.network',
        'macsec.network',
        'macvlan.network',
        'macvtap.network',
        'netdev-link-local-addressing-yes.network',
        'sit.network',
        'vti6.network',
        'vti.network',
        'vxlan-test1.network',
        'vxlan.network',
        'xfrm.network',
    ]

    fou_ports = [
        '55555',
        '55556']

    def setUp(self):
        remove_fou_ports(self.fou_ports)
        remove_links(self.links_remove_earlier)
        remove_links(self.links)
        stop_networkd(show_logs=False)

    def tearDown(self):
        remove_fou_ports(self.fou_ports)
        remove_links(self.links_remove_earlier)
        remove_links(self.links)
        remove_unit_from_networkd_path(self.units)
        stop_networkd(show_logs=True)

    def test_dropin_and_name_conflict(self):
        copy_unit_to_networkd_unit_path('10-dropin-test.netdev', '15-name-conflict-test.netdev')
        start_networkd()

        self.wait_online(['dropin-test:off'], setup_state='unmanaged')

        output = check_output('ip link show dropin-test')
        print(output)
        self.assertRegex(output, '00:50:56:c0:00:28')

    def test_match_udev_property(self):
        copy_unit_to_networkd_unit_path('12-dummy.netdev', '13-not-match-udev-property.network', '14-match-udev-property.network')
        start_networkd()
        self.wait_online(['dummy98:routable'])

        output = check_output(*networkctl_cmd, '-n', '0', 'status', 'dummy98', env=env)
        print(output)
        self.assertRegex(output, 'Network File: /run/systemd/network/14-match-udev-property')

    def test_wait_online_any(self):
        copy_unit_to_networkd_unit_path('25-bridge.netdev', '25-bridge.network', '11-dummy.netdev', '11-dummy.network')
        start_networkd()

        self.wait_online(['bridge99', 'test1:degraded'], bool_any=True)

        self.wait_operstate('bridge99', '(off|no-carrier)', setup_state='configuring')
        self.wait_operstate('test1', 'degraded')

    @expectedFailureIfModuleIsNotAvailable('bareudp')
    def test_bareudp(self):
        copy_unit_to_networkd_unit_path('25-bareudp.netdev', 'netdev-link-local-addressing-yes.network')
        start_networkd()

        self.wait_online(['bareudp99:degraded'])

        output = check_output('ip -d link show bareudp99')
        print(output)
        self.assertRegex(output, 'dstport 1000 ')
        self.assertRegex(output, 'ethertype ip ')

    @expectedFailureIfModuleIsNotAvailable('batman-adv')
    def test_batadv(self):
        copy_unit_to_networkd_unit_path('25-batadv.netdev', 'netdev-link-local-addressing-yes.network')
        start_networkd()

        self.wait_online(['batadv99:degraded'])

        output = check_output('ip -d link show batadv99')
        print(output)
        self.assertRegex(output, 'batadv')

    def test_bridge(self):
        copy_unit_to_networkd_unit_path('25-bridge.netdev', '25-bridge-configure-without-carrier.network')
        start_networkd()

        self.wait_online(['bridge99:no-carrier'])

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

        output = check_output(*networkctl_cmd, '-n', '0', 'status', 'bridge99', env=env)
        print(output)
        self.assertRegex(output, 'Priority: 9')
        self.assertRegex(output, 'STP: yes')
        self.assertRegex(output, 'Multicast IGMP Version: 3')

    def test_bond(self):
        copy_unit_to_networkd_unit_path('25-bond.netdev', '25-bond-balanced-tlb.netdev')
        start_networkd()

        self.wait_online(['bond99:off', 'bond98:off'], setup_state='unmanaged')

        self.assertEqual('802.3ad 4',         read_link_attr('bond99', 'bonding', 'mode'))
        self.assertEqual('layer3+4 1',        read_link_attr('bond99', 'bonding', 'xmit_hash_policy'))
        self.assertEqual('1000',              read_link_attr('bond99', 'bonding', 'miimon'))
        self.assertEqual('fast 1',            read_link_attr('bond99', 'bonding', 'lacp_rate'))
        self.assertEqual('2000',              read_link_attr('bond99', 'bonding', 'updelay'))
        self.assertEqual('2000',              read_link_attr('bond99', 'bonding', 'downdelay'))
        self.assertEqual('4',                 read_link_attr('bond99', 'bonding', 'resend_igmp'))
        self.assertEqual('1',                 read_link_attr('bond99', 'bonding', 'min_links'))
        self.assertEqual('1218',              read_link_attr('bond99', 'bonding', 'ad_actor_sys_prio'))
        self.assertEqual('811',               read_link_attr('bond99', 'bonding', 'ad_user_port_key'))
        self.assertEqual('00:11:22:33:44:55', read_link_attr('bond99', 'bonding', 'ad_actor_system'))

        self.assertEqual('balance-tlb 5',     read_link_attr('bond98', 'bonding', 'mode'))
        self.assertEqual('1',                 read_link_attr('bond98', 'bonding', 'tlb_dynamic_lb'))

    def test_vlan(self):
        copy_unit_to_networkd_unit_path('21-vlan.netdev', '11-dummy.netdev',
                                        '21-vlan.network', '21-vlan-test1.network')
        start_networkd()

        self.wait_online(['test1:degraded', 'vlan99:routable'])

        output = check_output('ip -d link show test1')
        print(output)
        self.assertRegex(output, ' mtu 2000 ')

        output = check_output('ip -d link show vlan99')
        print(output)
        self.assertRegex(output, ' mtu 2000 ')
        self.assertRegex(output, 'REORDER_HDR')
        self.assertRegex(output, 'LOOSE_BINDING')
        self.assertRegex(output, 'GVRP')
        self.assertRegex(output, 'MVRP')
        self.assertRegex(output, ' id 99 ')

        output = check_output('ip -4 address show dev test1')
        print(output)
        self.assertRegex(output, 'inet 192.168.24.5/24 brd 192.168.24.255 scope global test1')
        self.assertRegex(output, 'inet 192.168.25.5/24 brd 192.168.25.255 scope global test1')

        output = check_output('ip -4 address show dev vlan99')
        print(output)
        self.assertRegex(output, 'inet 192.168.23.5/24 brd 192.168.23.255 scope global vlan99')

    def test_macvtap(self):
        for mode in ['private', 'vepa', 'bridge', 'passthru']:
            with self.subTest(mode=mode):
                if mode != 'private':
                    self.tearDown()
                copy_unit_to_networkd_unit_path('21-macvtap.netdev', 'netdev-link-local-addressing-yes.network',
                                                '11-dummy.netdev', 'macvtap.network')
                with open(os.path.join(network_unit_file_path, '21-macvtap.netdev'), mode='a') as f:
                    f.write('[MACVTAP]\nMode=' + mode)
                start_networkd()

                self.wait_online(['macvtap99:degraded', 'test1:degraded'])

                output = check_output('ip -d link show macvtap99')
                print(output)
                self.assertRegex(output, 'macvtap mode ' + mode + ' ')

    def test_macvlan(self):
        for mode in ['private', 'vepa', 'bridge', 'passthru']:
            with self.subTest(mode=mode):
                if mode != 'private':
                    self.tearDown()
                copy_unit_to_networkd_unit_path('21-macvlan.netdev', 'netdev-link-local-addressing-yes.network',
                                                '11-dummy.netdev', 'macvlan.network')
                with open(os.path.join(network_unit_file_path, '21-macvlan.netdev'), mode='a') as f:
                    f.write('[MACVLAN]\nMode=' + mode)
                start_networkd()

                self.wait_online(['macvlan99:degraded', 'test1:degraded'])

                output = check_output('ip -d link show test1')
                print(output)
                self.assertRegex(output, ' mtu 2000 ')

                output = check_output('ip -d link show macvlan99')
                print(output)
                self.assertRegex(output, ' mtu 2000 ')
                self.assertRegex(output, 'macvlan mode ' + mode + ' ')

    @expectedFailureIfModuleIsNotAvailable('ipvlan')
    def test_ipvlan(self):
        for mode, flag in [['L2', 'private'], ['L3', 'vepa'], ['L3S', 'bridge']]:
            with self.subTest(mode=mode, flag=flag):
                if mode != 'L2':
                    self.tearDown()
                copy_unit_to_networkd_unit_path('25-ipvlan.netdev', 'netdev-link-local-addressing-yes.network',
                                                '11-dummy.netdev', 'ipvlan.network')
                with open(os.path.join(network_unit_file_path, '25-ipvlan.netdev'), mode='a') as f:
                    f.write('[IPVLAN]\nMode=' + mode + '\nFlags=' + flag)

                start_networkd()
                self.wait_online(['ipvlan99:degraded', 'test1:degraded'])

                output = check_output('ip -d link show ipvlan99')
                print(output)
                self.assertRegex(output, 'ipvlan  *mode ' + mode.lower() + ' ' + flag)

    @expectedFailureIfModuleIsNotAvailable('ipvtap')
    def test_ipvtap(self):
        for mode, flag in [['L2', 'private'], ['L3', 'vepa'], ['L3S', 'bridge']]:
            with self.subTest(mode=mode, flag=flag):
                if mode != 'L2':
                    self.tearDown()
                copy_unit_to_networkd_unit_path('25-ipvtap.netdev', 'netdev-link-local-addressing-yes.network',
                                                '11-dummy.netdev', 'ipvtap.network')
                with open(os.path.join(network_unit_file_path, '25-ipvtap.netdev'), mode='a') as f:
                    f.write('[IPVTAP]\nMode=' + mode + '\nFlags=' + flag)

                start_networkd()
                self.wait_online(['ipvtap99:degraded', 'test1:degraded'])

                output = check_output('ip -d link show ipvtap99')
                print(output)
                self.assertRegex(output, 'ipvtap  *mode ' + mode.lower() + ' ' + flag)

    def test_veth(self):
        copy_unit_to_networkd_unit_path('25-veth.netdev', 'netdev-link-local-addressing-yes.network')
        start_networkd()

        self.wait_online(['veth99:degraded', 'veth-peer:degraded'])

        output = check_output('ip -d link show veth99')
        print(output)
        self.assertRegex(output, 'link/ether 12:34:56:78:9a:bc')
        output = check_output('ip -d link show veth-peer')
        print(output)
        self.assertRegex(output, 'link/ether 12:34:56:78:9a:bd')

    def test_tun(self):
        copy_unit_to_networkd_unit_path('25-tun.netdev')
        start_networkd()

        self.wait_online(['tun99:off'], setup_state='unmanaged')

        output = check_output('ip -d link show tun99')
        print(output)
        # Old ip command does not support IFF_ flags
        self.assertRegex(output, 'tun (type tun pi on vnet_hdr on multi_queue|addrgenmode) ')

    def test_tap(self):
        copy_unit_to_networkd_unit_path('25-tap.netdev')
        start_networkd()

        self.wait_online(['tap99:off'], setup_state='unmanaged')

        output = check_output('ip -d link show tap99')
        print(output)
        # Old ip command does not support IFF_ flags
        self.assertRegex(output, 'tun (type tap pi on vnet_hdr on multi_queue|addrgenmode) ')

    @expectedFailureIfModuleIsNotAvailable('vrf')
    def test_vrf(self):
        copy_unit_to_networkd_unit_path('25-vrf.netdev', 'netdev-link-local-addressing-yes.network')
        start_networkd()

        self.wait_online(['vrf99:carrier'])

    @expectedFailureIfModuleIsNotAvailable('vcan')
    def test_vcan(self):
        copy_unit_to_networkd_unit_path('25-vcan.netdev', 'netdev-link-local-addressing-yes.network')
        start_networkd()

        self.wait_online(['vcan99:carrier'])

    @expectedFailureIfModuleIsNotAvailable('vxcan')
    def test_vxcan(self):
        copy_unit_to_networkd_unit_path('25-vxcan.netdev', 'netdev-link-local-addressing-yes.network')
        start_networkd()

        self.wait_online(['vxcan99:carrier', 'vxcan-peer:carrier'])

    @expectedFailureIfModuleIsNotAvailable('wireguard')
    def test_wireguard(self):
        copy_unit_to_networkd_unit_path('25-wireguard.netdev', '25-wireguard.network',
                                        '25-wireguard-23-peers.netdev', '25-wireguard-23-peers.network',
                                        '25-wireguard-preshared-key.txt', '25-wireguard-private-key.txt',
                                        '25-wireguard-no-peer.netdev', '25-wireguard-no-peer.network')
        start_networkd()
        self.wait_online(['wg99:routable', 'wg98:routable', 'wg97:carrier'])

        output = check_output('ip -4 address show dev wg99')
        print(output)
        self.assertIn('inet 192.168.124.1/24 scope global wg99', output)

        output = check_output('ip -4 address show dev wg98')
        print(output)
        self.assertIn('inet 192.168.123.123/24 scope global wg98', output)

        output = check_output('ip -6 address show dev wg98')
        print(output)
        self.assertIn('inet6 fd8d:4d6d:3ccb:500::1/64 scope global', output)

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

    def test_geneve(self):
        copy_unit_to_networkd_unit_path('25-geneve.netdev', 'netdev-link-local-addressing-yes.network')
        start_networkd()

        self.wait_online(['geneve99:degraded'])

        output = check_output('ip -d link show geneve99')
        print(output)
        self.assertRegex(output, '192.168.22.1')
        self.assertRegex(output, '6082')
        self.assertRegex(output, 'udpcsum')
        self.assertRegex(output, 'udp6zerocsumrx')

    def test_ipip_tunnel(self):
        copy_unit_to_networkd_unit_path('12-dummy.netdev', 'ipip.network',
                                        '25-ipip-tunnel.netdev', '25-tunnel.network',
                                        '25-ipip-tunnel-local-any.netdev', '25-tunnel-local-any.network',
                                        '25-ipip-tunnel-remote-any.netdev', '25-tunnel-remote-any.network',
                                        '25-ipip-tunnel-any-any.netdev', '25-tunnel-any-any.network')
        start_networkd()
        self.wait_online(['ipiptun99:routable', 'ipiptun98:routable', 'ipiptun97:routable', 'ipiptun96:routable', 'dummy98:degraded'])

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

    def test_gre_tunnel(self):
        copy_unit_to_networkd_unit_path('12-dummy.netdev', 'gretun.network',
                                        '25-gre-tunnel.netdev', '25-tunnel.network',
                                        '25-gre-tunnel-local-any.netdev', '25-tunnel-local-any.network',
                                        '25-gre-tunnel-remote-any.netdev', '25-tunnel-remote-any.network',
                                        '25-gre-tunnel-any-any.netdev', '25-tunnel-any-any.network')
        start_networkd()
        self.wait_online(['gretun99:routable', 'gretun98:routable', 'gretun97:routable', 'gretun96:routable', 'dummy98:degraded'])

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

    def test_ip6gre_tunnel(self):
        copy_unit_to_networkd_unit_path('12-dummy.netdev', 'ip6gretun.network',
                                        '25-ip6gre-tunnel.netdev', '25-tunnel.network',
                                        '25-ip6gre-tunnel-local-any.netdev', '25-tunnel-local-any.network',
                                        '25-ip6gre-tunnel-remote-any.netdev', '25-tunnel-remote-any.network',
                                        '25-ip6gre-tunnel-any-any.netdev', '25-tunnel-any-any.network')
        start_networkd(5)

        # Old kernels seem not to support IPv6LL address on ip6gre tunnel, So please do not use wait_online() here.

        self.check_link_exists('dummy98')
        self.check_link_exists('ip6gretun99')
        self.check_link_exists('ip6gretun98')
        self.check_link_exists('ip6gretun97')
        self.check_link_exists('ip6gretun96')

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

    def test_gretap_tunnel(self):
        copy_unit_to_networkd_unit_path('12-dummy.netdev', 'gretap.network',
                                        '25-gretap-tunnel.netdev', '25-tunnel.network',
                                        '25-gretap-tunnel-local-any.netdev', '25-tunnel-local-any.network')
        start_networkd()
        self.wait_online(['gretap99:routable', 'gretap98:routable', 'dummy98:degraded'])

        output = check_output('ip -d link show gretap99')
        print(output)
        self.assertRegex(output, 'gretap remote 10.65.223.239 local 10.65.223.238 dev dummy98')
        self.assertRegex(output, 'ikey 0.0.0.106')
        self.assertRegex(output, 'okey 0.0.0.106')
        self.assertRegex(output, 'iseq')
        self.assertRegex(output, 'oseq')
        output = check_output('ip -d link show gretap98')
        print(output)
        self.assertRegex(output, 'gretap remote 10.65.223.239 local any dev dummy98')
        self.assertRegex(output, 'ikey 0.0.0.107')
        self.assertRegex(output, 'okey 0.0.0.107')
        self.assertRegex(output, 'iseq')
        self.assertRegex(output, 'oseq')

    def test_ip6gretap_tunnel(self):
        copy_unit_to_networkd_unit_path('12-dummy.netdev', 'ip6gretap.network',
                                        '25-ip6gretap-tunnel.netdev', '25-tunnel.network',
                                        '25-ip6gretap-tunnel-local-any.netdev', '25-tunnel-local-any.network')
        start_networkd()
        self.wait_online(['ip6gretap99:routable', 'ip6gretap98:routable', 'dummy98:degraded'])

        output = check_output('ip -d link show ip6gretap99')
        print(output)
        self.assertRegex(output, 'ip6gretap remote 2001:473:fece:cafe::5179 local 2a00:ffde:4567:edde::4987 dev dummy98')
        output = check_output('ip -d link show ip6gretap98')
        print(output)
        self.assertRegex(output, 'ip6gretap remote 2001:473:fece:cafe::5179 local any dev dummy98')

    def test_vti_tunnel(self):
        copy_unit_to_networkd_unit_path('12-dummy.netdev', 'vti.network',
                                        '25-vti-tunnel.netdev', '25-tunnel.network',
                                        '25-vti-tunnel-local-any.netdev', '25-tunnel-local-any.network',
                                        '25-vti-tunnel-remote-any.netdev', '25-tunnel-remote-any.network',
                                        '25-vti-tunnel-any-any.netdev', '25-tunnel-any-any.network')
        start_networkd()
        self.wait_online(['vtitun99:routable', 'vtitun98:routable', 'vtitun97:routable', 'vtitun96:routable', 'dummy98:degraded'])

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

    def test_vti6_tunnel(self):
        copy_unit_to_networkd_unit_path('12-dummy.netdev', 'vti6.network',
                                        '25-vti6-tunnel.netdev', '25-tunnel.network',
                                        '25-vti6-tunnel-local-any.netdev', '25-tunnel-local-any.network',
                                        '25-vti6-tunnel-remote-any.netdev', '25-tunnel-remote-any.network')
        start_networkd()
        self.wait_online(['vti6tun99:routable', 'vti6tun98:routable', 'vti6tun97:routable', 'dummy98:degraded'])

        output = check_output('ip -d link show vti6tun99')
        print(output)
        self.assertRegex(output, 'vti6 remote 2001:473:fece:cafe::5179 local 2a00:ffde:4567:edde::4987 dev dummy98')
        output = check_output('ip -d link show vti6tun98')
        print(output)
        self.assertRegex(output, 'vti6 remote 2001:473:fece:cafe::5179 local (any|::) dev dummy98')
        output = check_output('ip -d link show vti6tun97')
        print(output)
        self.assertRegex(output, 'vti6 remote (any|::) local 2a00:ffde:4567:edde::4987 dev dummy98')

    def test_ip6tnl_tunnel(self):
        copy_unit_to_networkd_unit_path('12-dummy.netdev', 'ip6tnl.network',
                                        '25-ip6tnl-tunnel.netdev', '25-tunnel.network',
                                        '25-ip6tnl-tunnel-local-any.netdev', '25-tunnel-local-any.network',
                                        '25-ip6tnl-tunnel-remote-any.netdev', '25-tunnel-remote-any.network')
        start_networkd()
        self.wait_online(['ip6tnl99:routable', 'ip6tnl98:routable', 'ip6tnl97:routable', 'dummy98:degraded'])

        output = check_output('ip -d link show ip6tnl99')
        print(output)
        self.assertRegex(output, 'ip6tnl ip6ip6 remote 2001:473:fece:cafe::5179 local 2a00:ffde:4567:edde::4987 dev dummy98')
        output = check_output('ip -d link show ip6tnl98')
        print(output)
        self.assertRegex(output, 'ip6tnl ip6ip6 remote 2001:473:fece:cafe::5179 local (any|::) dev dummy98')
        output = check_output('ip -d link show ip6tnl97')
        print(output)
        self.assertRegex(output, 'ip6tnl ip6ip6 remote (any|::) local 2a00:ffde:4567:edde::4987 dev dummy98')

    def test_sit_tunnel(self):
        copy_unit_to_networkd_unit_path('12-dummy.netdev', 'sit.network',
                                        '25-sit-tunnel.netdev', '25-tunnel.network',
                                        '25-sit-tunnel-local-any.netdev', '25-tunnel-local-any.network',
                                        '25-sit-tunnel-remote-any.netdev', '25-tunnel-remote-any.network',
                                        '25-sit-tunnel-any-any.netdev', '25-tunnel-any-any.network')
        start_networkd()
        self.wait_online(['sittun99:routable', 'sittun98:routable', 'sittun97:routable', 'sittun96:routable', 'dummy98:degraded'])

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

    def test_isatap_tunnel(self):
        copy_unit_to_networkd_unit_path('12-dummy.netdev', 'isatap.network',
                                        '25-isatap-tunnel.netdev', '25-tunnel.network')
        start_networkd()
        self.wait_online(['isataptun99:routable', 'dummy98:degraded'])

        output = check_output('ip -d link show isataptun99')
        print(output)
        self.assertRegex(output, "isatap ")

    def test_6rd_tunnel(self):
        copy_unit_to_networkd_unit_path('12-dummy.netdev', '6rd.network',
                                        '25-6rd-tunnel.netdev', '25-tunnel.network')
        start_networkd()
        self.wait_online(['sittun99:routable', 'dummy98:degraded'])

        output = check_output('ip -d link show sittun99')
        print(output)
        self.assertRegex(output, '6rd-prefix 2602::/24')

    @expectedFailureIfERSPANModuleIsNotAvailable()
    def test_erspan_tunnel(self):
        copy_unit_to_networkd_unit_path('12-dummy.netdev', 'erspan.network',
                                        '25-erspan-tunnel.netdev', '25-tunnel.network',
                                        '25-erspan-tunnel-local-any.netdev', '25-tunnel-local-any.network')
        start_networkd()
        self.wait_online(['erspan99:routable', 'erspan98:routable', 'dummy98:degraded'])

        output = check_output('ip -d link show erspan99')
        print(output)
        self.assertRegex(output, 'erspan remote 172.16.1.100 local 172.16.1.200')
        self.assertRegex(output, 'ikey 0.0.0.101')
        self.assertRegex(output, 'okey 0.0.0.101')
        self.assertRegex(output, 'iseq')
        self.assertRegex(output, 'oseq')
        output = check_output('ip -d link show erspan98')
        print(output)
        self.assertRegex(output, 'erspan remote 172.16.1.100 local any')
        self.assertRegex(output, '102')
        self.assertRegex(output, 'ikey 0.0.0.102')
        self.assertRegex(output, 'okey 0.0.0.102')
        self.assertRegex(output, 'iseq')
        self.assertRegex(output, 'oseq')

    def test_tunnel_independent(self):
        copy_unit_to_networkd_unit_path('25-ipip-tunnel-independent.netdev', 'netdev-link-local-addressing-yes.network')
        start_networkd()

        self.wait_online(['ipiptun99:carrier'])

    def test_tunnel_independent_loopback(self):
        copy_unit_to_networkd_unit_path('25-ipip-tunnel-independent-loopback.netdev', 'netdev-link-local-addressing-yes.network')
        start_networkd()

        self.wait_online(['ipiptun99:carrier'])

    @expectedFailureIfModuleIsNotAvailable('xfrm_interface')
    def test_xfrm(self):
        copy_unit_to_networkd_unit_path('12-dummy.netdev', 'xfrm.network',
                                        '25-xfrm.netdev', 'netdev-link-local-addressing-yes.network')
        start_networkd()

        self.wait_online(['xfrm99:degraded', 'dummy98:degraded'])

        output = check_output('ip link show dev xfrm99')
        print(output)

    @expectedFailureIfModuleIsNotAvailable('xfrm_interface')
    def test_xfrm_independent(self):
        copy_unit_to_networkd_unit_path('25-xfrm-independent.netdev', 'netdev-link-local-addressing-yes.network')
        start_networkd()

        self.wait_online(['xfrm99:degraded'])

    @expectedFailureIfModuleIsNotAvailable('fou')
    def test_fou(self):
        # The following redundant check is necessary for CentOS CI.
        # Maybe, error handling in lookup_id() in sd-netlink/generic-netlink.c needs to be updated.
        self.assertTrue(is_module_available('fou'))

        copy_unit_to_networkd_unit_path('25-fou-ipproto-ipip.netdev', '25-fou-ipproto-gre.netdev',
                                        '25-fou-ipip.netdev', '25-fou-sit.netdev',
                                        '25-fou-gre.netdev', '25-fou-gretap.netdev')
        start_networkd()

        self.wait_online(['ipiptun96:off', 'sittun96:off', 'gretun96:off', 'gretap96:off'], setup_state='unmanaged')

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

    def test_vxlan(self):
        copy_unit_to_networkd_unit_path('25-vxlan.netdev', 'vxlan.network',
                                        '25-vxlan-independent.netdev', 'netdev-link-local-addressing-yes.network',
                                        '11-dummy.netdev', 'vxlan-test1.network')
        start_networkd()

        self.wait_online(['test1:degraded', 'vxlan99:degraded', 'vxlan98:degraded'])

        output = check_output('ip -d link show vxlan99')
        print(output)
        self.assertRegex(output, '999')
        self.assertRegex(output, '5555')
        self.assertRegex(output, 'l2miss')
        self.assertRegex(output, 'l3miss')
        self.assertRegex(output, 'udpcsum')
        self.assertRegex(output, 'udp6zerocsumtx')
        self.assertRegex(output, 'udp6zerocsumrx')
        self.assertRegex(output, 'remcsumtx')
        self.assertRegex(output, 'remcsumrx')
        self.assertRegex(output, 'gbp')

        output = check_output('bridge fdb show dev vxlan99')
        print(output)
        self.assertRegex(output, '00:11:22:33:44:55 dst 10.0.0.5 self permanent')
        self.assertRegex(output, '00:11:22:33:44:66 dst 10.0.0.6 self permanent')
        self.assertRegex(output, '00:11:22:33:44:77 dst 10.0.0.7 via test1 self permanent')

        output = check_output(*networkctl_cmd, '-n', '0', 'status', 'vxlan99', env=env)
        print(output)
        self.assertRegex(output, 'VNI: 999')
        self.assertRegex(output, 'Destination Port: 5555')
        self.assertRegex(output, 'Underlying Device: test1')

    def test_macsec(self):
        copy_unit_to_networkd_unit_path('25-macsec.netdev', '25-macsec.network', '25-macsec.key',
                                        'macsec.network', '12-dummy.netdev')
        start_networkd()

        self.wait_online(['dummy98:degraded', 'macsec99:routable'])

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

    def test_nlmon(self):
        copy_unit_to_networkd_unit_path('25-nlmon.netdev', 'netdev-link-local-addressing-yes.network')
        start_networkd()

        self.wait_online(['nlmon99:carrier'])

    @expectedFailureIfModuleIsNotAvailable('ifb')
    def test_ifb(self):
        copy_unit_to_networkd_unit_path('25-ifb.netdev', 'netdev-link-local-addressing-yes.network')
        start_networkd()

        self.wait_online(['ifb99:degraded'])

class NetworkdL2TPTests(unittest.TestCase, Utilities):

    links =[
        'l2tp-ses1',
        'l2tp-ses2',
        'l2tp-ses3',
        'l2tp-ses4',
        'test1']

    units = [
        '11-dummy.netdev',
        '25-l2tp-dummy.network',
        '25-l2tp.network',
        '25-l2tp-ip.netdev',
        '25-l2tp-udp.netdev']

    l2tp_tunnel_ids = [ '10' ]

    def setUp(self):
        remove_l2tp_tunnels(self.l2tp_tunnel_ids)
        remove_links(self.links)
        stop_networkd(show_logs=False)

    def tearDown(self):
        remove_l2tp_tunnels(self.l2tp_tunnel_ids)
        remove_links(self.links)
        remove_unit_from_networkd_path(self.units)
        stop_networkd(show_logs=True)

    @expectedFailureIfModuleIsNotAvailable('l2tp_eth')
    def test_l2tp_udp(self):
        copy_unit_to_networkd_unit_path('11-dummy.netdev', '25-l2tp-dummy.network',
                                        '25-l2tp-udp.netdev', '25-l2tp.network')
        start_networkd()

        self.wait_online(['test1:routable', 'l2tp-ses1:degraded', 'l2tp-ses2:degraded'])

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

    @expectedFailureIfModuleIsNotAvailable('l2tp_ip')
    def test_l2tp_ip(self):
        copy_unit_to_networkd_unit_path('11-dummy.netdev', '25-l2tp-dummy.network',
                                        '25-l2tp-ip.netdev', '25-l2tp.network')
        start_networkd()

        self.wait_online(['test1:routable', 'l2tp-ses3:degraded', 'l2tp-ses4:degraded'])

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

class NetworkdNetworkTests(unittest.TestCase, Utilities):
    links = [
        'bond199',
        'dummy98',
        'dummy99',
        'gretun97',
        'ip6gretun97',
        'test1',
        'veth-peer',
        'veth99',
        'vrf99',
    ]

    units = [
        '11-dummy.netdev',
        '12-dummy.netdev',
        '12-dummy.network',
        '23-active-slave.network',
        '24-keep-configuration-static.network',
        '24-search-domain.network',
        '25-address-ipv4acd-veth99.network',
        '25-address-link-section.network',
        '25-address-peer-ipv4.network',
        '25-address-static.network',
        '25-activation-policy.network',
        '25-bind-carrier.network',
        '25-bond-active-backup-slave.netdev',
        '25-fibrule-invert.network',
        '25-fibrule-port-range.network',
        '25-fibrule-uidrange.network',
        '25-gre-tunnel-remote-any.netdev',
        '25-ip6gre-tunnel-remote-any.netdev',
        '25-ipv6-address-label-section.network',
        '25-ipv6-proxy-ndp.network',
        '25-link-local-addressing-no.network',
        '25-link-local-addressing-yes.network',
        '25-link-section-unmanaged.network',
        '25-neighbor-section.network',
        '25-neighbor-next.network',
        '25-neighbor-ipv6.network',
        '25-neighbor-ip-dummy.network',
        '25-neighbor-ip.network',
        '25-nexthop-dummy.network',
        '25-nexthop-nothing.network',
        '25-nexthop.network',
        '25-qdisc-cake.network',
        '25-qdisc-clsact-and-htb.network',
        '25-qdisc-drr.network',
        '25-qdisc-ets.network',
        '25-qdisc-fq_pie.network',
        '25-qdisc-hhf.network',
        '25-qdisc-ingress-netem-compat.network',
        '25-qdisc-pie.network',
        '25-qdisc-qfq.network',
        '25-prefix-route-with-vrf.network',
        '25-prefix-route-without-vrf.network',
        '25-route-ipv6-src.network',
        '25-route-static.network',
        '25-route-via-ipv6.network',
        '25-route-vrf.network',
        '25-gateway-static.network',
        '25-gateway-next-static.network',
        '25-sriov.network',
        '25-sysctl-disable-ipv6.network',
        '25-sysctl.network',
        '25-test1.network',
        '25-veth-peer.network',
        '25-veth.netdev',
        '25-vrf.netdev',
        '25-vrf.network',
        '26-link-local-addressing-ipv6.network',
        'dhcp-client-ipv4-ipv6ra-prefix-client-with-delay.network',
        'dhcp-server-with-ipv6-prefix.network',
        'ipv6ra-prefix-client-with-static-ipv4-address.network',
        'ipv6-prefix-with-delay.network',
        'routing-policy-rule-dummy98.network',
        'routing-policy-rule-test1.network',
        'routing-policy-rule-reconfigure1.network',
        'routing-policy-rule-reconfigure2.network',
    ]

    networkd_conf_dropins = [
        'networkd-manage-foreign-routes-no.conf',
    ]

    routing_policy_rule_tables = ['7', '8', '9', '10', '1011']
    routes = [['blackhole', '202.54.1.2'], ['unreachable', '202.54.1.3'], ['prohibit', '202.54.1.4']]

    def setUp(self):
        remove_blackhole_nexthops()
        remove_routing_policy_rule_tables(self.routing_policy_rule_tables)
        remove_routes(self.routes)
        remove_links(self.links)
        stop_networkd(show_logs=False)
        call('ip netns del ns99', stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    def tearDown(self):
        remove_blackhole_nexthops()
        remove_routing_policy_rule_tables(self.routing_policy_rule_tables)
        remove_routes(self.routes)
        remove_links(self.links)
        remove_unit_from_networkd_path(self.units)
        remove_networkd_conf_dropin(self.networkd_conf_dropins)
        stop_networkd(show_logs=True)
        call('ip netns del ns99', stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    def test_address_static(self):
        copy_unit_to_networkd_unit_path('25-address-static.network', '12-dummy.netdev')
        start_networkd()

        self.wait_online(['dummy98:routable'])

        output = check_output('ip -4 address show dev dummy98')
        print(output)
        self.assertIn('inet 10.1.2.3/16 brd 10.1.255.255 scope global dummy98', output)
        self.assertIn('inet 10.1.2.4/16 brd 10.1.255.255 scope global secondary dummy98', output)
        self.assertIn('inet 10.2.2.4/16 brd 10.2.255.255 scope global dummy98', output)
        self.assertIn('inet 10.7.8.9/16 brd 10.7.255.255 scope link deprecated dummy98', output)
        self.assertIn('inet 10.8.8.1/16 scope global dummy98', output)

        # test for ENOBUFS issue #17012
        for i in range(1,254):
            self.assertIn(f'inet 10.3.3.{i}/16 brd 10.3.255.255', output)

        # invalid sections
        self.assertNotIn('10.10.0.1/16', output)
        self.assertNotIn('10.10.0.2/16', output)

        output = check_output('ip -4 address show dev dummy98 label 32')
        self.assertIn('inet 10.3.2.3/16 brd 10.3.255.255 scope global 32', output)

        output = check_output('ip -4 address show dev dummy98 label 33')
        self.assertIn('inet 10.4.2.3 peer 10.4.2.4/16 scope global 33', output)

        output = check_output('ip -4 address show dev dummy98 label 34')
        self.assertRegex(output, r'inet 192.168.[0-9]*.1/24 brd 192.168.[0-9]*.255 scope global 34')

        output = check_output('ip -4 address show dev dummy98 label 35')
        self.assertRegex(output, r'inet 172.[0-9]*.0.1/16 brd 172.[0-9]*.255.255 scope global 35')

        output = check_output('ip -6 address show dev dummy98')
        print(output)
        self.assertIn('inet6 2001:db8:0:f101::15/64 scope global', output)
        self.assertIn('inet6 2001:db8:0:f101::16/64 scope global', output)
        self.assertIn('inet6 2001:db8:0:f102::15/64 scope global', output)
        self.assertIn('inet6 2001:db8:0:f102::16/64 scope global', output)
        self.assertIn('inet6 2001:db8:0:f103::20 peer 2001:db8:0:f103::10/128 scope global', output)
        self.assertIn('inet6 2001:db8:1:f101::1/64 scope global deprecated', output)
        self.assertRegex(output, r'inet6 fd[0-9a-f:]*1/64 scope global')

        restart_networkd()
        self.wait_online(['dummy98:routable'])

        # test for ENOBUFS issue #17012
        output = check_output('ip -4 address show dev dummy98')
        for i in range(1,254):
            self.assertIn(f'inet 10.3.3.{i}/16 brd 10.3.255.255', output)

    def test_address_ipv4acd(self):
        check_output('ip netns add ns99')
        check_output('ip link add veth99 type veth peer veth-peer')
        check_output('ip link set veth-peer netns ns99')
        check_output('ip link set veth99 up')
        check_output('ip netns exec ns99 ip link set veth-peer up')
        check_output('ip netns exec ns99 ip address add 192.168.100.10/24 dev veth-peer')

        copy_unit_to_networkd_unit_path('25-address-ipv4acd-veth99.network', dropins=False)
        start_networkd()
        self.wait_online(['veth99:routable'])

        output = check_output('ip -4 address show dev veth99')
        print(output)
        self.assertNotIn('192.168.100.10/24', output)
        self.assertIn('192.168.100.11/24', output)

        copy_unit_to_networkd_unit_path('25-address-ipv4acd-veth99.network.d/conflict-address.conf')
        run(*networkctl_cmd, 'reload', env=env)
        time.sleep(1)
        rc = call(*wait_online_cmd, '--timeout=10s', '--interface=veth99:routable', env=env)
        self.assertTrue(rc == 1)

        output = check_output('ip -4 address show dev veth99')
        print(output)
        self.assertNotIn('192.168.100.10/24', output)
        self.assertIn('192.168.100.11/24', output)

    def test_address_peer_ipv4(self):
        # test for issue #17304
        copy_unit_to_networkd_unit_path('25-address-peer-ipv4.network', '12-dummy.netdev')

        for trial in range(2):
            if trial == 0:
                start_networkd()
            else:
                restart_networkd()

            self.wait_online(['dummy98:routable'])

            output = check_output('ip -4 address show dev dummy98')
            self.assertIn('inet 100.64.0.1 peer 100.64.0.2/32 scope global', output)

    @expectedFailureIfModuleIsNotAvailable('vrf')
    def test_prefix_route(self):
        copy_unit_to_networkd_unit_path('25-prefix-route-with-vrf.network', '12-dummy.netdev',
                                        '25-prefix-route-without-vrf.network', '11-dummy.netdev',
                                        '25-vrf.netdev', '25-vrf.network')
        for trial in range(2):
            if trial == 0:
                start_networkd()
            else:
                restart_networkd(3)

            self.wait_online(['dummy98:routable', 'test1:routable', 'vrf99:carrier'])

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
        copy_unit_to_networkd_unit_path('11-dummy.netdev')
        start_networkd()
        self.wait_operstate('test1', 'off', '')
        check_output('ip link set dev test1 up carrier off')

        copy_unit_to_networkd_unit_path('25-test1.network.d/configure-without-carrier.conf', dropins=False)
        restart_networkd()
        self.wait_online(['test1:no-carrier'])

        carrier_map = {'on': '1', 'off': '0'}
        routable_map = {'on': 'routable', 'off': 'no-carrier'}
        for carrier in ['off', 'on', 'off']:
            with self.subTest(carrier=carrier):
                if carrier_map[carrier] != read_link_attr('test1', 'carrier'):
                    check_output(f'ip link set dev test1 carrier {carrier}')
                self.wait_online([f'test1:{routable_map[carrier]}:{routable_map[carrier]}'])

                output = check_output(*networkctl_cmd, '-n', '0', 'status', 'test1', env=env)
                print(output)
                self.assertRegex(output, '192.168.0.15')
                self.assertRegex(output, '192.168.0.1')
                self.assertRegex(output, routable_map[carrier])

    def test_configure_without_carrier_yes_ignore_carrier_loss_no(self):
        copy_unit_to_networkd_unit_path('11-dummy.netdev')
        start_networkd()
        self.wait_operstate('test1', 'off', '')
        check_output('ip link set dev test1 up carrier off')

        copy_unit_to_networkd_unit_path('25-test1.network')
        restart_networkd()
        self.wait_online(['test1:no-carrier'])

        carrier_map = {'on': '1', 'off': '0'}
        routable_map = {'on': 'routable', 'off': 'no-carrier'}
        for (carrier, have_config) in [('off', True), ('on', True), ('off', False)]:
            with self.subTest(carrier=carrier, have_config=have_config):
                if carrier_map[carrier] != read_link_attr('test1', 'carrier'):
                    check_output(f'ip link set dev test1 carrier {carrier}')
                self.wait_online([f'test1:{routable_map[carrier]}:{routable_map[carrier]}'])

                output = check_output(*networkctl_cmd, '-n', '0', 'status', 'test1', env=env)
                print(output)
                if have_config:
                    self.assertRegex(output, '192.168.0.15')
                    self.assertRegex(output, '192.168.0.1')
                else:
                    self.assertNotRegex(output, '192.168.0.15')
                    self.assertNotRegex(output, '192.168.0.1')
                self.assertRegex(output, routable_map[carrier])

    def test_routing_policy_rule(self):
        copy_unit_to_networkd_unit_path('routing-policy-rule-test1.network', '11-dummy.netdev')
        start_networkd()
        self.wait_online(['test1:degraded'])

        output = check_output('ip rule list iif test1 priority 111')
        print(output)
        self.assertRegex(output, '111:')
        self.assertRegex(output, 'from 192.168.100.18')
        self.assertRegex(output, r'tos (0x08|throughput)\s')
        self.assertRegex(output, 'iif test1')
        self.assertRegex(output, 'oif test1')
        self.assertRegex(output, 'lookup 7')

        output = check_output('ip rule list iif test1 priority 101')
        print(output)
        self.assertRegex(output, '101:')
        self.assertRegex(output, 'from all')
        self.assertRegex(output, 'iif test1')
        self.assertRegex(output, 'lookup 9')

        output = check_output('ip -6 rule list iif test1 priority 100')
        print(output)
        self.assertRegex(output, '100:')
        self.assertRegex(output, 'from all')
        self.assertRegex(output, 'iif test1')
        self.assertRegex(output, 'lookup 8')

        output = check_output('ip rule list iif test1 priority 102')
        print(output)
        self.assertRegex(output, '102:')
        self.assertRegex(output, 'from 0.0.0.0/8')
        self.assertRegex(output, 'iif test1')
        self.assertRegex(output, 'lookup 10')

    def test_routing_policy_rule_issue_11280(self):
        copy_unit_to_networkd_unit_path('routing-policy-rule-test1.network', '11-dummy.netdev',
                                        'routing-policy-rule-dummy98.network', '12-dummy.netdev')

        for trial in range(3):
            # Remove state files only first time
            start_networkd(3)
            self.wait_online(['test1:degraded', 'dummy98:degraded'])
            time.sleep(1)

            output = check_output('ip rule list table 7')
            print(output)
            self.assertRegex(output, '111:	from 192.168.100.18 tos (0x08|throughput) iif test1 oif test1 lookup 7')

            output = check_output('ip rule list table 8')
            print(output)
            self.assertRegex(output, '112:	from 192.168.101.18 tos (0x08|throughput) iif dummy98 oif dummy98 lookup 8')

            stop_networkd(remove_state_files=False)

    def test_routing_policy_rule_reconfigure(self):
        copy_unit_to_networkd_unit_path('routing-policy-rule-reconfigure2.network', '11-dummy.netdev')
        start_networkd()
        self.wait_online(['test1:degraded'])

        output = check_output('ip rule list table 1011')
        print(output)
        self.assertIn('10111:	from all fwmark 0x3f3 lookup 1011', output)
        self.assertIn('10112:	from all oif test1 lookup 1011', output)
        self.assertIn('10113:	from all iif test1 lookup 1011', output)
        self.assertIn('10114:	from 192.168.8.254 lookup 1011', output)

        output = check_output('ip -6 rule list table 1011')
        print(output)
        self.assertIn('10112:	from all oif test1 lookup 1011', output)

        copy_unit_to_networkd_unit_path('routing-policy-rule-reconfigure1.network', '11-dummy.netdev')
        run(*networkctl_cmd, 'reload', env=env)
        time.sleep(1)
        self.wait_online(['test1:degraded'])

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

        run('ip rule delete priority 10111')
        run('ip rule delete priority 10112')
        run('ip rule delete priority 10113')
        run('ip rule delete priority 10114')
        run('ip -6 rule delete priority 10113')

        output = check_output('ip rule list table 1011')
        print(output)
        self.assertEqual(output, '')

        output = check_output('ip -6 rule list table 1011')
        print(output)
        self.assertEqual(output, '')

        run(*networkctl_cmd, 'reconfigure', 'test1', env=env)
        self.wait_online(['test1:degraded'])

        output = check_output('ip rule list table 1011')
        print(output)
        self.assertIn('10111:	from all fwmark 0x3f3 lookup 1011', output)
        self.assertIn('10112:	from all oif test1 lookup 1011', output)
        self.assertIn('10113:	from all iif test1 lookup 1011', output)
        self.assertIn('10114:	from 192.168.8.254 lookup 1011', output)

        output = check_output('ip -6 rule list table 1011')
        print(output)
        self.assertIn('10113:	from all iif test1 lookup 1011', output)

    @expectedFailureIfRoutingPolicyPortRangeIsNotAvailable()
    def test_routing_policy_rule_port_range(self):
        copy_unit_to_networkd_unit_path('25-fibrule-port-range.network', '11-dummy.netdev')
        start_networkd()
        self.wait_online(['test1:degraded'])

        output = check_output('ip rule')
        print(output)
        self.assertRegex(output, '111')
        self.assertRegex(output, 'from 192.168.100.18')
        self.assertRegex(output, '1123-1150')
        self.assertRegex(output, '3224-3290')
        self.assertRegex(output, 'tcp')
        self.assertRegex(output, 'lookup 7')

    @expectedFailureIfRoutingPolicyIPProtoIsNotAvailable()
    def test_routing_policy_rule_invert(self):
        copy_unit_to_networkd_unit_path('25-fibrule-invert.network', '11-dummy.netdev')
        start_networkd()
        self.wait_online(['test1:degraded'])

        output = check_output('ip rule')
        print(output)
        self.assertRegex(output, '111')
        self.assertRegex(output, 'not.*?from.*?192.168.100.18')
        self.assertRegex(output, 'tcp')
        self.assertRegex(output, 'lookup 7')

    @expectedFailureIfRoutingPolicyUIDRangeIsNotAvailable()
    def test_routing_policy_rule_uidrange(self):
        copy_unit_to_networkd_unit_path('25-fibrule-uidrange.network', '11-dummy.netdev')
        start_networkd()
        self.wait_online(['test1:degraded'])

        output = check_output('ip rule')
        print(output)
        self.assertRegex(output, '111')
        self.assertRegex(output, 'from 192.168.100.18')
        self.assertRegex(output, 'lookup 7')
        self.assertRegex(output, 'uidrange 100-200')

    def _test_route_static(self, manage_foreign_routes):
        if not manage_foreign_routes:
            copy_networkd_conf_dropin('networkd-manage-foreign-routes-no.conf')

        copy_unit_to_networkd_unit_path('25-route-static.network', '12-dummy.netdev')
        start_networkd()
        self.wait_online(['dummy98:routable'])

        output = check_output(*networkctl_cmd, '-n', '0', 'status', 'dummy98', env=env)
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
        self.assertIn('192.168.1.1 proto static initcwnd 20', output)
        self.assertIn('192.168.1.2 proto static initrwnd 30', output)
        self.assertIn('192.168.1.3 proto static advmss 30', output)
        self.assertIn('multicast 149.10.123.4 proto static', output)

        print('### ip -4 route show dev dummy98 default')
        output = check_output('ip -4 route show dev dummy98 default')
        print(output)
        self.assertIn('default via 149.10.125.65 proto static onlink', output)
        self.assertIn('default via 149.10.124.64 proto static', output)
        self.assertIn('default proto static', output)

        print('### ip -4 route show table local dev dummy98')
        output = check_output('ip -4 route show table local dev dummy98')
        print(output)
        self.assertIn('local 149.10.123.1 proto static scope host', output)
        self.assertIn('anycast 149.10.123.2 proto static scope link', output)
        self.assertIn('broadcast 149.10.123.3 proto static scope link', output)

        print('### ip route show type blackhole')
        output = check_output('ip route show type blackhole')
        print(output)
        self.assertIn('blackhole 202.54.1.2 proto static', output)

        print('### ip route show type unreachable')
        output = check_output('ip route show type unreachable')
        print(output)
        self.assertIn('unreachable 202.54.1.3 proto static', output)

        print('### ip route show type prohibit')
        output = check_output('ip route show type prohibit')
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
        self.assertIn('nexthop via 149.10.124.59 dev dummy98 weight 10', output)
        self.assertIn('nexthop via 149.10.124.60 dev dummy98 weight 5', output)

        print('### ip route show 192.168.10.2')
        output = check_output('ip route show 192.168.10.2')
        print(output)
        # old ip command does not show IPv6 gateways...
        self.assertIn('192.168.10.2 proto static', output)
        self.assertIn('nexthop', output)
        self.assertIn('dev dummy98 weight 10', output)
        self.assertIn('dev dummy98 weight 5', output)

        print('### ip -6 route show 2001:1234:5:7fff:ff:ff:ff:ff')
        output = check_output('ip -6 route show 2001:1234:5:7fff:ff:ff:ff:ff')
        print(output)
        # old ip command does not show 'nexthop' keyword and weight...
        self.assertIn('2001:1234:5:7fff:ff:ff:ff:ff', output)
        self.assertIn('via 2001:1234:5:8fff:ff:ff:ff:ff dev dummy98', output)
        self.assertIn('via 2001:1234:5:9fff:ff:ff:ff:ff dev dummy98', output)

        copy_unit_to_networkd_unit_path('25-address-static.network')
        check_output(*networkctl_cmd, 'reload', env=env)
        time.sleep(1)
        self.wait_online(['dummy98:routable'])

        # check all routes managed by Manager are removed
        print('### ip route show type blackhole')
        output = check_output('ip route show type blackhole')
        print(output)
        self.assertEqual(output, '')

        print('### ip route show type unreachable')
        output = check_output('ip route show type unreachable')
        print(output)
        self.assertEqual(output, '')

        print('### ip route show type prohibit')
        output = check_output('ip route show type prohibit')
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

        remove_unit_from_networkd_path(['25-address-static.network'])
        check_output(*networkctl_cmd, 'reload', env=env)
        time.sleep(1)
        self.wait_online(['dummy98:routable'])

        # check all routes managed by Manager are reconfigured
        print('### ip route show type blackhole')
        output = check_output('ip route show type blackhole')
        print(output)
        self.assertIn('blackhole 202.54.1.2 proto static', output)

        print('### ip route show type unreachable')
        output = check_output('ip route show type unreachable')
        print(output)
        self.assertIn('unreachable 202.54.1.3 proto static', output)

        print('### ip route show type prohibit')
        output = check_output('ip route show type prohibit')
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

        rc = call("ip link del dummy98")
        self.assertEqual(rc, 0)
        time.sleep(2)

        # check all routes managed by Manager are removed
        print('### ip route show type blackhole')
        output = check_output('ip route show type blackhole')
        print(output)
        self.assertEqual(output, '')

        print('### ip route show type unreachable')
        output = check_output('ip route show type unreachable')
        print(output)
        self.assertEqual(output, '')

        print('### ip route show type prohibit')
        output = check_output('ip route show type prohibit')
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

        self.tearDown()

    def test_route_static(self):
        for manage_foreign_routes in [True, False]:
            with self.subTest(manage_foreign_routes=manage_foreign_routes):
                self._test_route_static(manage_foreign_routes)

    @expectedFailureIfRTA_VIAIsNotSupported()
    def test_route_via_ipv6(self):
        copy_unit_to_networkd_unit_path('25-route-via-ipv6.network', '12-dummy.netdev')
        start_networkd()
        self.wait_online(['dummy98:routable'])

        output = check_output(*networkctl_cmd, '-n', '0', 'status', 'dummy98', env=env)
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

    @expectedFailureIfModuleIsNotAvailable('vrf')
    def test_route_vrf(self):
        copy_unit_to_networkd_unit_path('25-route-vrf.network', '12-dummy.netdev',
                                        '25-vrf.netdev', '25-vrf.network')
        start_networkd()
        self.wait_online(['dummy98:routable', 'vrf99:carrier'])

        output = check_output('ip route show vrf vrf99')
        print(output)
        self.assertRegex(output, 'default via 192.168.100.1')

        output = check_output('ip route show')
        print(output)
        self.assertNotRegex(output, 'default via 192.168.100.1')

    def test_gateway_reconfigure(self):
        copy_unit_to_networkd_unit_path('25-gateway-static.network', '12-dummy.netdev')
        start_networkd()
        self.wait_online(['dummy98:routable'])
        print('### ip -4 route show dev dummy98 default')
        output = check_output('ip -4 route show dev dummy98 default')
        print(output)
        self.assertRegex(output, 'default via 149.10.124.59 proto static')
        self.assertNotRegex(output, '149.10.124.60')

        remove_unit_from_networkd_path(['25-gateway-static.network'])
        copy_unit_to_networkd_unit_path('25-gateway-next-static.network')
        restart_networkd(3)
        self.wait_online(['dummy98:routable'])
        print('### ip -4 route show dev dummy98 default')
        output = check_output('ip -4 route show dev dummy98 default')
        print(output)
        self.assertNotRegex(output, '149.10.124.59')
        self.assertRegex(output, 'default via 149.10.124.60 proto static')

    def test_ip_route_ipv6_src_route(self):
        # a dummy device does not make the addresses go through tentative state, so we
        # reuse a bond from an earlier test, which does make the addresses go through
        # tentative state, and do our test on that
        copy_unit_to_networkd_unit_path('23-active-slave.network', '25-route-ipv6-src.network', '25-bond-active-backup-slave.netdev', '12-dummy.netdev')
        start_networkd()
        self.wait_online(['dummy98:enslaved', 'bond199:routable'])

        output = check_output('ip -6 route list dev bond199')
        print(output)
        self.assertRegex(output, 'abcd::/16')
        self.assertRegex(output, 'src')
        self.assertRegex(output, '2001:1234:56:8f63::2')

    def test_ip_link_mac_address(self):
        copy_unit_to_networkd_unit_path('25-address-link-section.network', '12-dummy.netdev')
        start_networkd()
        self.wait_online(['dummy98:degraded'])

        output = check_output('ip link show dummy98')
        print(output)
        self.assertRegex(output, '00:01:02:aa:bb:cc')

    def test_ip_link_unmanaged(self):
        copy_unit_to_networkd_unit_path('25-link-section-unmanaged.network', '12-dummy.netdev')
        start_networkd(5)

        self.check_link_exists('dummy98')

        self.wait_operstate('dummy98', 'off', setup_state='unmanaged')

    def test_ipv6_address_label(self):
        copy_unit_to_networkd_unit_path('25-ipv6-address-label-section.network', '12-dummy.netdev')
        start_networkd()
        self.wait_online(['dummy98:degraded'])

        output = check_output('ip addrlabel list')
        print(output)
        self.assertRegex(output, '2004:da8:1::/64')

    def test_ipv6_proxy_ndp(self):
        copy_unit_to_networkd_unit_path('25-ipv6-proxy-ndp.network', '12-dummy.netdev')
        start_networkd()

        self.wait_online(['dummy98:routable'])

        output = check_output('ip neighbor show proxy dev dummy98')
        print(output)
        for i in range(1,5):
            self.assertRegex(output, f'2607:5300:203:5215:{i}::1 *proxy')

    def test_neighbor_section(self):
        copy_unit_to_networkd_unit_path('25-neighbor-section.network', '12-dummy.netdev')
        start_networkd()
        self.wait_online(['dummy98:degraded'], timeout='40s')

        print('### ip neigh list dev dummy98')
        output = check_output('ip neigh list dev dummy98')
        print(output)
        self.assertRegex(output, '192.168.10.1.*00:00:5e:00:02:65.*PERMANENT')
        self.assertRegex(output, '2004:da8:1::1.*00:00:5e:00:02:66.*PERMANENT')

    def test_neighbor_reconfigure(self):
        copy_unit_to_networkd_unit_path('25-neighbor-section.network', '12-dummy.netdev')
        start_networkd()
        self.wait_online(['dummy98:degraded'], timeout='40s')

        print('### ip neigh list dev dummy98')
        output = check_output('ip neigh list dev dummy98')
        print(output)
        self.assertRegex(output, '192.168.10.1.*00:00:5e:00:02:65.*PERMANENT')
        self.assertRegex(output, '2004:da8:1::1.*00:00:5e:00:02:66.*PERMANENT')

        remove_unit_from_networkd_path(['25-neighbor-section.network'])
        copy_unit_to_networkd_unit_path('25-neighbor-next.network')
        restart_networkd(3)
        self.wait_online(['dummy98:degraded'], timeout='40s')
        print('### ip neigh list dev dummy98')
        output = check_output('ip neigh list dev dummy98')
        print(output)
        self.assertNotRegex(output, '192.168.10.1.*00:00:5e:00:02:65.*PERMANENT')
        self.assertRegex(output, '192.168.10.1.*00:00:5e:00:02:66.*PERMANENT')
        self.assertNotRegex(output, '2004:da8:1::1.*PERMANENT')

    def test_neighbor_gre(self):
        copy_unit_to_networkd_unit_path('25-neighbor-ip.network', '25-neighbor-ipv6.network', '25-neighbor-ip-dummy.network',
                                        '12-dummy.netdev', '25-gre-tunnel-remote-any.netdev', '25-ip6gre-tunnel-remote-any.netdev')
        start_networkd()
        self.wait_online(['dummy98:degraded', 'gretun97:routable', 'ip6gretun97:routable'], timeout='40s')

        output = check_output('ip neigh list dev gretun97')
        print(output)
        self.assertRegex(output, '10.0.0.22 lladdr 10.65.223.239 PERMANENT')

        output = check_output('ip neigh list dev ip6gretun97')
        print(output)
        self.assertRegex(output, '2001:db8:0:f102::17 lladdr 2a:?00:ff:?de:45:?67:ed:?de:[0:]*:49:?88 PERMANENT')

    def test_link_local_addressing(self):
        copy_unit_to_networkd_unit_path('25-link-local-addressing-yes.network', '11-dummy.netdev',
                                        '25-link-local-addressing-no.network', '12-dummy.netdev')
        start_networkd()
        self.wait_online(['test1:degraded', 'dummy98:carrier'])

        output = check_output('ip address show dev test1')
        print(output)
        self.assertRegex(output, 'inet .* scope link')
        self.assertRegex(output, 'inet6 .* scope link')

        output = check_output('ip address show dev dummy98')
        print(output)
        self.assertNotRegex(output, 'inet6* .* scope link')

        '''
        Documentation/networking/ip-sysctl.txt

        addr_gen_mode - INTEGER
        Defines how link-local and autoconf addresses are generated.

        0: generate address based on EUI64 (default)
        1: do no generate a link-local address, use EUI64 for addresses generated
           from autoconf
        2: generate stable privacy addresses, using the secret from
           stable_secret (RFC7217)
        3: generate stable privacy addresses, using a random secret if unset
        '''

        self.assertEqual(read_ipv6_sysctl_attr('test1', 'stable_secret'), '0123:4567:89ab:cdef:0123:4567:89ab:cdef')
        self.assertEqual(read_ipv6_sysctl_attr('test1', 'addr_gen_mode'), '2')
        self.assertEqual(read_ipv6_sysctl_attr('dummy98', 'addr_gen_mode'), '1')

    def test_link_local_addressing_remove_ipv6ll(self):
        copy_unit_to_networkd_unit_path('26-link-local-addressing-ipv6.network', '12-dummy.netdev')
        start_networkd()
        self.wait_online(['dummy98:degraded'])

        output = check_output('ip address show dev dummy98')
        print(output)
        self.assertRegex(output, 'inet6 .* scope link')

        copy_unit_to_networkd_unit_path('25-link-local-addressing-no.network')
        restart_networkd(1)
        self.wait_online(['dummy98:carrier'])

        output = check_output('ip address show dev dummy98')
        print(output)
        self.assertNotRegex(output, 'inet6* .* scope link')

    def test_sysctl(self):
        copy_unit_to_networkd_unit_path('25-sysctl.network', '12-dummy.netdev')
        start_networkd()
        self.wait_online(['dummy98:degraded'])

        self.assertEqual(read_ipv6_sysctl_attr('dummy98', 'forwarding'), '1')
        self.assertEqual(read_ipv6_sysctl_attr('dummy98', 'use_tempaddr'), '2')
        self.assertEqual(read_ipv6_sysctl_attr('dummy98', 'dad_transmits'), '3')
        self.assertEqual(read_ipv6_sysctl_attr('dummy98', 'hop_limit'), '5')
        self.assertEqual(read_ipv6_sysctl_attr('dummy98', 'proxy_ndp'), '1')
        self.assertEqual(read_ipv4_sysctl_attr('dummy98', 'forwarding'),'1')
        self.assertEqual(read_ipv4_sysctl_attr('dummy98', 'proxy_arp'), '1')
        self.assertEqual(read_ipv4_sysctl_attr('dummy98', 'accept_local'), '1')

    def test_sysctl_disable_ipv6(self):
        copy_unit_to_networkd_unit_path('25-sysctl-disable-ipv6.network', '12-dummy.netdev')

        print('## Disable ipv6')
        check_output('sysctl net.ipv6.conf.all.disable_ipv6=1')
        check_output('sysctl net.ipv6.conf.default.disable_ipv6=1')

        start_networkd()
        self.wait_online(['dummy98:routable'])

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

        check_output('ip link del dummy98')

        print('## Enable ipv6')
        check_output('sysctl net.ipv6.conf.all.disable_ipv6=0')
        check_output('sysctl net.ipv6.conf.default.disable_ipv6=0')

        restart_networkd(3)
        self.wait_online(['dummy98:routable'])

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

    def test_bind_carrier(self):
        check_output('ip link add dummy98 type dummy')
        check_output('ip link set dummy98 up')
        time.sleep(2)

        copy_unit_to_networkd_unit_path('25-bind-carrier.network', '11-dummy.netdev')
        start_networkd()
        self.wait_online(['test1:routable'])

        output = check_output('ip address show test1')
        print(output)
        self.assertRegex(output, 'UP,LOWER_UP')
        self.assertRegex(output, 'inet 192.168.10.30/24 brd 192.168.10.255 scope global test1')
        self.wait_operstate('test1', 'routable')

        check_output('ip link add dummy99 type dummy')
        check_output('ip link set dummy99 up')
        time.sleep(2)
        output = check_output('ip address show test1')
        print(output)
        self.assertRegex(output, 'UP,LOWER_UP')
        self.assertRegex(output, 'inet 192.168.10.30/24 brd 192.168.10.255 scope global test1')
        self.wait_operstate('test1', 'routable')

        check_output('ip link del dummy98')
        time.sleep(2)
        output = check_output('ip address show test1')
        print(output)
        self.assertRegex(output, 'UP,LOWER_UP')
        self.assertRegex(output, 'inet 192.168.10.30/24 brd 192.168.10.255 scope global test1')
        self.wait_operstate('test1', 'routable')

        check_output('ip link set dummy99 down')
        time.sleep(2)
        output = check_output('ip address show test1')
        print(output)
        self.assertNotRegex(output, 'UP,LOWER_UP')
        self.assertRegex(output, 'DOWN')
        self.assertNotRegex(output, '192.168.10')
        self.wait_operstate('test1', 'off')

        check_output('ip link set dummy99 up')
        time.sleep(2)
        output = check_output('ip address show test1')
        print(output)
        self.assertRegex(output, 'UP,LOWER_UP')
        self.assertRegex(output, 'inet 192.168.10.30/24 brd 192.168.10.255 scope global test1')
        self.wait_operstate('test1', 'routable')

    def _test_activation_policy(self, test):
        self.setUp()
        conffile = '25-activation-policy.network'
        if test:
            conffile = f'{conffile}.d/{test}.conf'
        copy_unit_to_networkd_unit_path('11-dummy.netdev', conffile, dropins=False)
        start_networkd()

        always = test.startswith('always')
        if test == 'manual':
            initial_up = 'UP' in check_output('ip link show test1')
        else:
            initial_up = not test.endswith('down') # note: default is up
        expect_up = initial_up
        next_up = not expect_up

        for iteration in range(4):
            with self.subTest(iteration=iteration, expect_up=expect_up):
                operstate = 'routable' if expect_up else 'off'
                setup_state = 'configured' if expect_up else ('configuring' if iteration == 0 else None)
                self.wait_operstate('test1', operstate, setup_state=setup_state, setup_timeout=20)

                if expect_up:
                    self.assertIn('UP', check_output('ip link show test1'))
                    self.assertIn('192.168.10.30/24', check_output('ip address show test1'))
                    self.assertIn('default via 192.168.10.1', check_output('ip route show dev test1'))
                else:
                    self.assertIn('DOWN', check_output('ip link show test1'))

            if next_up:
                check_output('ip link set dev test1 up')
            else:
                check_output('ip link set dev test1 down')
            expect_up = initial_up if always else next_up
            next_up = not next_up

        self.tearDown()

    def test_activation_policy(self):
        for test in ['up', 'always-up', 'manual', 'always-down', 'down', '']:
            with self.subTest(test=test):
                self._test_activation_policy(test)

    def _test_activation_policy_required_for_online(self, policy, required):
        self.setUp()
        conffile = '25-activation-policy.network'
        units = ['11-dummy.netdev', '12-dummy.netdev', '12-dummy.network', conffile]
        if policy:
            units += [f'{conffile}.d/{policy}.conf']
        if required:
            units += [f'{conffile}.d/required-{required}.conf']
        copy_unit_to_networkd_unit_path(*units, dropins=False)
        start_networkd()

        if policy.endswith('down') or policy == 'manual':
            self.wait_operstate('test1', 'off', setup_state='configuring')
        else:
            self.wait_online(['test1'])

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

        output = check_output(*networkctl_cmd, '-n', '0', 'status', 'test1', env=env)
        print(output)

        yesno = 'yes' if expected else 'no'
        self.assertRegex(output, f'Required For Online: {yesno}')

        self.tearDown()

    def test_activation_policy_required_for_online(self):
        for policy in ['up', 'always-up', 'manual', 'always-down', 'down', 'bound', '']:
            for required in ['yes', 'no', '']:
                with self.subTest(policy=policy, required=required):
                    self._test_activation_policy_required_for_online(policy, required)

    def test_domain(self):
        copy_unit_to_networkd_unit_path('12-dummy.netdev', '24-search-domain.network')
        start_networkd()
        self.wait_online(['dummy98:routable'])

        output = check_output(*networkctl_cmd, '-n', '0', 'status', 'dummy98', env=env)
        print(output)
        self.assertRegex(output, 'Address: 192.168.42.100')
        self.assertRegex(output, 'DNS: 192.168.42.1')
        self.assertRegex(output, 'Search Domains: one')

    def test_keep_configuration_static(self):
        check_output('systemctl stop systemd-networkd.socket')
        check_output('systemctl stop systemd-networkd.service')

        check_output('ip link add name dummy98 type dummy')
        check_output('ip address add 10.1.2.3/16 dev dummy98')
        check_output('ip address add 10.2.3.4/16 dev dummy98 valid_lft 600 preferred_lft 500')
        output = check_output('ip address show dummy98')
        print(output)
        self.assertRegex(output, 'inet 10.1.2.3/16 scope global dummy98')
        self.assertRegex(output, 'inet 10.2.3.4/16 scope global dynamic dummy98')
        output = check_output('ip route show dev dummy98')
        print(output)

        copy_unit_to_networkd_unit_path('24-keep-configuration-static.network')
        start_networkd()
        self.wait_online(['dummy98:routable'])

        output = check_output('ip address show dummy98')
        print(output)
        self.assertRegex(output, 'inet 10.1.2.3/16 scope global dummy98')
        self.assertNotRegex(output, 'inet 10.2.3.4/16 scope global dynamic dummy98')

    @expectedFailureIfNexthopIsNotAvailable()
    def test_nexthop(self):
        def check_nexthop(self):
            self.wait_online(['veth99:routable', 'veth-peer:routable', 'dummy98:routable'])

            output = check_output('ip nexthop list dev veth99')
            print(output)
            self.assertIn('id 1 via 192.168.5.1 dev veth99', output)
            self.assertIn('id 2 via 2001:1234:5:8f63::2 dev veth99', output)
            self.assertIn('id 3 dev veth99', output)
            self.assertIn('id 4 dev veth99', output)
            self.assertRegex(output, 'id 5 via 192.168.10.1 dev veth99 .*onlink')
            self.assertIn('id 8 via fe80:0:222:4dff:ff:ff:ff:ff dev veth99', output)
            self.assertRegex(output, r'id [0-9]* via 192.168.5.2 dev veth99')

            output = check_output('ip nexthop list dev dummy98')
            print(output)
            self.assertIn('id 20 via 192.168.20.1 dev dummy98', output)

            # kernel manages blackhole nexthops on lo
            output = check_output('ip nexthop list dev lo')
            print(output)
            self.assertIn('id 6 blackhole', output)
            self.assertIn('id 7 blackhole', output)

            # group nexthops are shown with -0 option
            output = check_output('ip -0 nexthop list id 21')
            print(output)
            self.assertRegex(output, r'id 21 group (1,3/20|20/1,3)')

            output = check_output('ip route show dev veth99 10.10.10.10')
            print(output)
            self.assertEqual('10.10.10.10 nhid 1 via 192.168.5.1 proto static', output)

            output = check_output('ip route show dev veth99 10.10.10.11')
            print(output)
            self.assertEqual('10.10.10.11 nhid 2 via inet6 2001:1234:5:8f63::2 proto static', output)

            output = check_output('ip route show dev veth99 10.10.10.12')
            print(output)
            self.assertEqual('10.10.10.12 nhid 5 via 192.168.10.1 proto static onlink', output)

            output = check_output('ip -6 route show dev veth99 2001:1234:5:8f62::1')
            print(output)
            self.assertEqual('2001:1234:5:8f62::1 nhid 2 via 2001:1234:5:8f63::2 proto static metric 1024 pref medium', output)

            output = check_output('ip route show 10.10.10.13')
            print(output)
            self.assertEqual('blackhole 10.10.10.13 nhid 6 dev lo proto static', output)

            output = check_output('ip -6 route show 2001:1234:5:8f62::2')
            print(output)
            self.assertEqual('blackhole 2001:1234:5:8f62::2 nhid 7 dev lo proto static metric 1024 pref medium', output)

            output = check_output('ip route show 10.10.10.14')
            print(output)
            self.assertIn('10.10.10.14 nhid 21 proto static', output)
            self.assertIn('nexthop via 192.168.20.1 dev dummy98 weight 1', output)
            self.assertIn('nexthop via 192.168.5.1 dev veth99 weight 3', output)

        copy_unit_to_networkd_unit_path('25-nexthop.network', '25-veth.netdev', '25-veth-peer.network',
                                        '12-dummy.netdev', '25-nexthop-dummy.network')
        start_networkd()

        check_nexthop(self)

        remove_unit_from_networkd_path(['25-nexthop.network'])
        copy_unit_to_networkd_unit_path('25-nexthop-nothing.network')
        rc = call(*networkctl_cmd, 'reload', env=env)
        self.assertEqual(rc, 0)
        time.sleep(1)

        self.wait_online(['veth99:routable', 'veth-peer:routable'])

        output = check_output('ip nexthop list dev veth99')
        print(output)
        self.assertEqual(output, '')
        output = check_output('ip nexthop list dev lo')
        print(output)
        self.assertEqual(output, '')

        remove_unit_from_networkd_path(['25-nexthop-nothing.network'])
        copy_unit_to_networkd_unit_path('25-nexthop.network')
        rc = call(*networkctl_cmd, 'reconfigure', 'dummy98', env=env)
        self.assertEqual(rc, 0)
        rc = call(*networkctl_cmd, 'reload', env=env)
        self.assertEqual(rc, 0)
        time.sleep(1)

        check_nexthop(self)

        rc = call('ip link del veth99')
        self.assertEqual(rc, 0)
        time.sleep(2)

        output = check_output('ip nexthop list dev lo')
        print(output)
        self.assertEqual(output, '')

    def test_qdisc(self):
        copy_unit_to_networkd_unit_path('25-qdisc-clsact-and-htb.network', '12-dummy.netdev',
                                        '25-qdisc-ingress-netem-compat.network', '11-dummy.netdev')
        check_output('modprobe sch_teql max_equalizers=2')
        start_networkd()

        self.wait_online(['dummy98:routable', 'test1:routable'])

        output = check_output('tc qdisc show dev test1')
        print(output)
        self.assertRegex(output, 'qdisc netem')
        self.assertRegex(output, 'limit 100 delay 50(.0)?ms  10(.0)?ms loss 20%')
        self.assertRegex(output, 'qdisc ingress')

        output = check_output('tc qdisc show dev dummy98')
        print(output)
        self.assertRegex(output, 'qdisc clsact')

        self.assertRegex(output, 'qdisc htb 2: root')
        self.assertRegex(output, r'default (0x30|30)')

        self.assertRegex(output, 'qdisc netem 30: parent 2:30')
        self.assertRegex(output, 'limit 100 delay 50(.0)?ms  10(.0)?ms loss 20%')
        self.assertRegex(output, 'qdisc fq_codel')
        self.assertRegex(output, 'limit 20480p flows 2048 quantum 1400 target 10(.0)?ms ce_threshold 100(.0)?ms interval 200(.0)?ms memory_limit 64Mb ecn')

        self.assertRegex(output, 'qdisc teql1 31: parent 2:31')

        self.assertRegex(output, 'qdisc fq 32: parent 2:32')
        self.assertRegex(output, 'limit 1000p flow_limit 200p buckets 512 orphan_mask 511')
        self.assertRegex(output, 'quantum 1500')
        self.assertRegex(output, 'initial_quantum 13000')
        self.assertRegex(output, 'maxrate 1Mbit')

        self.assertRegex(output, 'qdisc codel 33: parent 2:33')
        self.assertRegex(output, 'limit 2000p target 10(.0)?ms ce_threshold 100(.0)?ms interval 50(.0)?ms ecn')

        self.assertRegex(output, 'qdisc fq_codel 34: parent 2:34')
        self.assertRegex(output, 'limit 20480p flows 2048 quantum 1400 target 10(.0)?ms ce_threshold 100(.0)?ms interval 200(.0)?ms memory_limit 64Mb ecn')

        self.assertRegex(output, 'qdisc tbf 35: parent 2:35')
        self.assertRegex(output, 'rate 1Gbit burst 5000b peakrate 100Gbit minburst 987500b lat 70(.0)?ms')

        self.assertRegex(output, 'qdisc sfq 36: parent 2:36')
        self.assertRegex(output, 'perturb 5sec')

        self.assertRegex(output, 'qdisc pfifo 37: parent 2:37')
        self.assertRegex(output, 'limit 100000p')

        self.assertRegex(output, 'qdisc gred 38: parent 2:38')
        self.assertRegex(output, 'vqs 12 default 10 grio')

        self.assertRegex(output, 'qdisc sfb 39: parent 2:39')
        self.assertRegex(output, 'limit 200000')

        self.assertRegex(output, 'qdisc bfifo 3a: parent 2:3a')
        self.assertRegex(output, 'limit 1000000')

        self.assertRegex(output, 'qdisc pfifo_head_drop 3b: parent 2:3b')
        self.assertRegex(output, 'limit 1023p')

        self.assertRegex(output, 'qdisc pfifo_fast 3c: parent 2:3c')

        output = check_output('tc -d class show dev dummy98')
        print(output)
        self.assertRegex(output, 'class htb 2:30 root leaf 30:')
        self.assertRegex(output, 'class htb 2:31 root leaf 31:')
        self.assertRegex(output, 'class htb 2:32 root leaf 32:')
        self.assertRegex(output, 'class htb 2:33 root leaf 33:')
        self.assertRegex(output, 'class htb 2:34 root leaf 34:')
        self.assertRegex(output, 'class htb 2:35 root leaf 35:')
        self.assertRegex(output, 'class htb 2:36 root leaf 36:')
        self.assertRegex(output, 'class htb 2:37 root leaf 37:')
        self.assertRegex(output, 'class htb 2:38 root leaf 38:')
        self.assertRegex(output, 'class htb 2:39 root leaf 39:')
        self.assertRegex(output, 'class htb 2:3a root leaf 3a:')
        self.assertRegex(output, 'class htb 2:3b root leaf 3b:')
        self.assertRegex(output, 'class htb 2:3c root leaf 3c:')
        self.assertRegex(output, 'prio 1 quantum 4000 rate 1Mbit overhead 100 ceil 500Kbit')
        self.assertRegex(output, 'burst 123456')
        self.assertRegex(output, 'cburst 123457')

    def test_qdisc2(self):
        copy_unit_to_networkd_unit_path('25-qdisc-drr.network', '12-dummy.netdev',
                                        '25-qdisc-qfq.network', '11-dummy.netdev')
        start_networkd()

        self.wait_online(['dummy98:routable', 'test1:routable'])

        output = check_output('tc qdisc show dev dummy98')
        print(output)
        self.assertRegex(output, 'qdisc drr 2: root')
        output = check_output('tc class show dev dummy98')
        print(output)
        self.assertRegex(output, 'class drr 2:30 root quantum 2000b')

        output = check_output('tc qdisc show dev test1')
        print(output)
        self.assertRegex(output, 'qdisc qfq 2: root')
        output = check_output('tc class show dev test1')
        print(output)
        self.assertRegex(output, 'class qfq 2:30 root weight 2 maxpkt 16000')
        self.assertRegex(output, 'class qfq 2:31 root weight 10 maxpkt 8000')

    @expectedFailureIfCAKEIsNotAvailable()
    def test_qdisc_cake(self):
        copy_unit_to_networkd_unit_path('25-qdisc-cake.network', '12-dummy.netdev')
        start_networkd()
        self.wait_online(['dummy98:routable'])

        output = check_output('tc qdisc show dev dummy98')
        print(output)
        self.assertRegex(output, 'qdisc cake 3a: root')
        self.assertRegex(output, 'bandwidth 500Mbit')
        self.assertRegex(output, 'overhead 128')

    @expectedFailureIfPIEIsNotAvailable()
    def test_qdisc_pie(self):
        copy_unit_to_networkd_unit_path('25-qdisc-pie.network', '12-dummy.netdev')
        start_networkd()
        self.wait_online(['dummy98:routable'])

        output = check_output('tc qdisc show dev dummy98')
        print(output)
        self.assertRegex(output, 'qdisc pie 3a: root')
        self.assertRegex(output, 'limit 200000')

    @expectedFailureIfHHFIsNotAvailable()
    def test_qdisc_hhf(self):
        copy_unit_to_networkd_unit_path('25-qdisc-hhf.network', '12-dummy.netdev')
        start_networkd()
        self.wait_online(['dummy98:routable'])

        output = check_output('tc qdisc show dev dummy98')
        print(output)
        self.assertRegex(output, 'qdisc hhf 3a: root')
        self.assertRegex(output, 'limit 1022p')

    @expectedFailureIfETSIsNotAvailable()
    def test_qdisc_ets(self):
        copy_unit_to_networkd_unit_path('25-qdisc-ets.network', '12-dummy.netdev')
        start_networkd()
        self.wait_online(['dummy98:routable'])

        output = check_output('tc qdisc show dev dummy98')
        print(output)

        self.assertRegex(output, 'qdisc ets 3a: root')
        self.assertRegex(output, 'bands 10 strict 3')
        self.assertRegex(output, 'quanta 1 2 3 4 5')
        self.assertRegex(output, 'priomap 3 4 5 6 7')

    @expectedFailureIfFQPIEIsNotAvailable()
    def test_qdisc_fq_pie(self):
        copy_unit_to_networkd_unit_path('25-qdisc-fq_pie.network', '12-dummy.netdev')
        start_networkd()
        self.wait_online(['dummy98:routable'])

        output = check_output('tc qdisc show dev dummy98')
        print(output)

        self.assertRegex(output, 'qdisc fq_pie 3a: root')
        self.assertRegex(output, 'limit 200000p')

    @expectedFailureIfNetdevsimWithSRIOVIsNotAvailable()
    def test_sriov(self):
        call('rmmod netdevsim', stderr=subprocess.DEVNULL)
        call('modprobe netdevsim', stderr=subprocess.DEVNULL)
        with open('/sys/bus/netdevsim/new_device', mode='w') as f:
            f.write('99 1')

        call('udevadm settle')
        call('udevadm info -w10s /sys/devices/netdevsim99/net/eni99np1', stderr=subprocess.DEVNULL)
        with open('/sys/class/net/eni99np1/device/sriov_numvfs', mode='w') as f:
            f.write('3')

        copy_unit_to_networkd_unit_path('25-sriov.network')
        start_networkd()
        self.wait_online(['eni99np1:routable'])

        output = check_output('ip link show dev eni99np1')
        print(output)
        self.assertRegex(output,
                         'vf 0 .*00:11:22:33:44:55.*vlan 5, qos 1, vlan protocol 802.1ad, spoof checking on, link-state enable, trust on, query_rss on\n *'
                         'vf 1 .*00:11:22:33:44:56.*vlan 6, qos 2, spoof checking off, link-state disable, trust off, query_rss off\n *'
                         'vf 2 .*00:11:22:33:44:57.*vlan 7, qos 3, spoof checking off, link-state auto, trust off, query_rss off'
        )

        call('rmmod netdevsim', stderr=subprocess.DEVNULL)

    def test_wait_online_ipv4(self):
        copy_unit_to_networkd_unit_path('25-veth.netdev', 'dhcp-server-with-ipv6-prefix.network', 'dhcp-client-ipv4-ipv6ra-prefix-client-with-delay.network')
        start_networkd()

        self.wait_online(['veth99:routable'], ipv4=True)

        self.wait_address('veth99', r'192.168.5.[0-9]+', ipv='-4', timeout_sec=1)

    def test_wait_online_ipv6(self):
        copy_unit_to_networkd_unit_path('25-veth.netdev', 'ipv6-prefix-with-delay.network', 'ipv6ra-prefix-client-with-static-ipv4-address.network')
        start_networkd()

        self.wait_online(['veth99:routable'], ipv6=True)

        self.wait_address('veth99', r'2002:da8:1:0:1034:56ff:fe78:9abc', ipv='-6', timeout_sec=1)

class NetworkdStateFileTests(unittest.TestCase, Utilities):
    links = [
        'dummy98',
    ]

    units = [
        '12-dummy.netdev',
        'state-file-tests.network',
    ]

    def setUp(self):
        remove_links(self.links)
        stop_networkd(show_logs=False)

    def tearDown(self):
        remove_links(self.links)
        remove_unit_from_networkd_path(self.units)
        stop_networkd(show_logs=True)

    def test_state_file(self):
        copy_unit_to_networkd_unit_path('12-dummy.netdev', 'state-file-tests.network')
        start_networkd()
        self.wait_online(['dummy98:routable'])

        output = check_output(*networkctl_cmd, '--no-legend', 'list', 'dummy98', env=env)
        print(output)
        ifindex = output.split()[0]

        path = os.path.join('/run/systemd/netif/links/', ifindex)
        self.assertTrue(os.path.exists(path))

        # make link state file updated
        check_output(*resolvectl_cmd, 'revert', 'dummy98', env=env)

        with open(path) as f:
            data = f.read()
            self.assertRegex(data, r'IPV4_ADDRESS_STATE=routable')
            self.assertRegex(data, r'IPV6_ADDRESS_STATE=routable')
            self.assertRegex(data, r'ADMIN_STATE=configured')
            self.assertRegex(data, r'OPER_STATE=routable')
            self.assertRegex(data, r'REQUIRED_FOR_ONLINE=yes')
            self.assertRegex(data, r'REQUIRED_OPER_STATE_FOR_ONLINE=routable')
            self.assertRegex(data, r'REQUIRED_FAMILY_FOR_ONLINE=both')
            self.assertRegex(data, r'ACTIVATION_POLICY=up')
            self.assertRegex(data, r'NETWORK_FILE=/run/systemd/network/state-file-tests.network')
            self.assertRegex(data, r'DNS=10.10.10.10#aaa.com 10.10.10.11:1111#bbb.com \[1111:2222::3333\]:1234#ccc.com')
            self.assertRegex(data, r'NTP=0.fedora.pool.ntp.org 1.fedora.pool.ntp.org')
            self.assertRegex(data, r'DOMAINS=hogehoge')
            self.assertRegex(data, r'ROUTE_DOMAINS=foofoo')
            self.assertRegex(data, r'LLMNR=no')
            self.assertRegex(data, r'MDNS=yes')
            self.assertRegex(data, r'DNSSEC=no')

        check_output(*resolvectl_cmd, 'dns', 'dummy98', '10.10.10.12#ccc.com', '10.10.10.13', '1111:2222::3333', env=env)
        check_output(*resolvectl_cmd, 'domain', 'dummy98', 'hogehogehoge', '~foofoofoo', env=env)
        check_output(*resolvectl_cmd, 'llmnr', 'dummy98', 'yes', env=env)
        check_output(*resolvectl_cmd, 'mdns', 'dummy98', 'no', env=env)
        check_output(*resolvectl_cmd, 'dnssec', 'dummy98', 'yes', env=env)
        check_output(*timedatectl_cmd, 'ntp-servers', 'dummy98', '2.fedora.pool.ntp.org', '3.fedora.pool.ntp.org', env=env)

        with open(path) as f:
            data = f.read()
            self.assertRegex(data, r'DNS=10.10.10.12#ccc.com 10.10.10.13 1111:2222::3333')
            self.assertRegex(data, r'NTP=2.fedora.pool.ntp.org 3.fedora.pool.ntp.org')
            self.assertRegex(data, r'DOMAINS=hogehogehoge')
            self.assertRegex(data, r'ROUTE_DOMAINS=foofoofoo')
            self.assertRegex(data, r'LLMNR=yes')
            self.assertRegex(data, r'MDNS=no')
            self.assertRegex(data, r'DNSSEC=yes')

        check_output(*timedatectl_cmd, 'revert', 'dummy98', env=env)

        with open(path) as f:
            data = f.read()
            self.assertRegex(data, r'DNS=10.10.10.12#ccc.com 10.10.10.13 1111:2222::3333')
            self.assertRegex(data, r'NTP=0.fedora.pool.ntp.org 1.fedora.pool.ntp.org')
            self.assertRegex(data, r'DOMAINS=hogehogehoge')
            self.assertRegex(data, r'ROUTE_DOMAINS=foofoofoo')
            self.assertRegex(data, r'LLMNR=yes')
            self.assertRegex(data, r'MDNS=no')
            self.assertRegex(data, r'DNSSEC=yes')

        check_output(*resolvectl_cmd, 'revert', 'dummy98', env=env)

        with open(path) as f:
            data = f.read()
            self.assertRegex(data, r'DNS=10.10.10.10#aaa.com 10.10.10.11:1111#bbb.com \[1111:2222::3333\]:1234#ccc.com')
            self.assertRegex(data, r'NTP=0.fedora.pool.ntp.org 1.fedora.pool.ntp.org')
            self.assertRegex(data, r'DOMAINS=hogehoge')
            self.assertRegex(data, r'ROUTE_DOMAINS=foofoo')
            self.assertRegex(data, r'LLMNR=no')
            self.assertRegex(data, r'MDNS=yes')
            self.assertRegex(data, r'DNSSEC=no')

class NetworkdBondTests(unittest.TestCase, Utilities):
    links = [
        'bond199',
        'bond99',
        'dummy98',
        'test1']

    units = [
        '11-dummy.netdev',
        '12-dummy.netdev',
        '23-active-slave.network',
        '23-bond199.network',
        '23-primary-slave.network',
        '25-bond-active-backup-slave.netdev',
        '25-bond.netdev',
        'bond99.network',
        'bond-slave.network']

    def setUp(self):
        remove_links(self.links)
        stop_networkd(show_logs=False)

    def tearDown(self):
        remove_links(self.links)
        remove_unit_from_networkd_path(self.units)
        stop_networkd(show_logs=True)

    def test_bond_active_slave(self):
        copy_unit_to_networkd_unit_path('23-active-slave.network', '23-bond199.network', '25-bond-active-backup-slave.netdev', '12-dummy.netdev')
        start_networkd()
        self.wait_online(['dummy98:enslaved', 'bond199:degraded'])

        output = check_output('ip -d link show bond199')
        print(output)
        self.assertRegex(output, 'active_slave dummy98')

    def test_bond_primary_slave(self):
        copy_unit_to_networkd_unit_path('23-primary-slave.network', '23-bond199.network', '25-bond-active-backup-slave.netdev', '12-dummy.netdev')
        start_networkd()
        self.wait_online(['dummy98:enslaved', 'bond199:degraded'])

        output = check_output('ip -d link show bond199')
        print(output)
        self.assertRegex(output, 'primary dummy98')

    def test_bond_operstate(self):
        copy_unit_to_networkd_unit_path('25-bond.netdev', '11-dummy.netdev', '12-dummy.netdev',
                                        'bond99.network','bond-slave.network')
        start_networkd()
        self.wait_online(['dummy98:enslaved', 'test1:enslaved', 'bond99:routable'])

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
        self.wait_operstate('bond99', 'degraded-carrier')

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
    links = [
        'bridge99',
        'dummy98',
        'test1']

    units = [
        '11-dummy.netdev',
        '12-dummy.netdev',
        '26-bridge.netdev',
        '26-bridge-configure-without-carrier.network',
        '26-bridge-mdb-master.network',
        '26-bridge-mdb-slave.network',
        '26-bridge-slave-interface-1.network',
        '26-bridge-slave-interface-2.network',
        '26-bridge-vlan-master.network',
        '26-bridge-vlan-slave.network',
        'bridge99-ignore-carrier-loss.network',
        'bridge99.network']

    routing_policy_rule_tables = ['100']

    def setUp(self):
        remove_routing_policy_rule_tables(self.routing_policy_rule_tables)
        remove_links(self.links)
        stop_networkd(show_logs=False)

    def tearDown(self):
        remove_routing_policy_rule_tables(self.routing_policy_rule_tables)
        remove_links(self.links)
        remove_unit_from_networkd_path(self.units)
        stop_networkd(show_logs=True)

    def test_bridge_vlan(self):
        copy_unit_to_networkd_unit_path('11-dummy.netdev', '26-bridge-vlan-slave.network',
                                        '26-bridge.netdev', '26-bridge-vlan-master.network')
        start_networkd()
        self.wait_online(['test1:enslaved', 'bridge99:degraded'])

        output = check_output('bridge vlan show dev test1')
        print(output)
        self.assertNotRegex(output, '4063')
        for i in range(4064, 4095):
            self.assertRegex(output, f'{i}')
        self.assertNotRegex(output, '4095')

        output = check_output('bridge vlan show dev bridge99')
        print(output)
        self.assertNotRegex(output, '4059')
        for i in range(4060, 4095):
            self.assertRegex(output, f'{i}')
        self.assertNotRegex(output, '4095')

    def test_bridge_mdb(self):
        copy_unit_to_networkd_unit_path('11-dummy.netdev', '26-bridge-mdb-slave.network',
                                        '26-bridge.netdev', '26-bridge-mdb-master.network')
        start_networkd()
        self.wait_online(['test1:enslaved', 'bridge99:degraded'])

        output = check_output('bridge mdb show dev bridge99')
        print(output)
        self.assertRegex(output, 'dev bridge99 port test1 grp ff02:aaaa:fee5::1:3 permanent *vid 4064')
        self.assertRegex(output, 'dev bridge99 port test1 grp 224.0.1.1 permanent *vid 4065')

        # Old kernel may not support bridge MDB entries on bridge master
        if call('bridge mdb add dev bridge99 port bridge99 grp 224.0.1.3 temp vid 4068', stderr=subprocess.DEVNULL) == 0:
            self.assertRegex(output, 'dev bridge99 port bridge99 grp ff02:aaaa:fee5::1:4 temp *vid 4066')
            self.assertRegex(output, 'dev bridge99 port bridge99 grp 224.0.1.2 temp *vid 4067')

    def test_bridge_property(self):
        copy_unit_to_networkd_unit_path('11-dummy.netdev', '12-dummy.netdev', '26-bridge.netdev',
                                        '26-bridge-slave-interface-1.network', '26-bridge-slave-interface-2.network',
                                        'bridge99.network')
        start_networkd()
        self.wait_online(['dummy98:enslaved', 'test1:enslaved', 'bridge99:routable'])

        output = check_output('ip -d link show test1')
        print(output)
        self.assertRegex(output, 'master')
        self.assertRegex(output, 'bridge')

        output = check_output('ip -d link show dummy98')
        print(output)
        self.assertRegex(output, 'master')
        self.assertRegex(output, 'bridge')

        output = check_output('ip addr show bridge99')
        print(output)
        self.assertRegex(output, '192.168.0.15/24')

        output = check_output('bridge -d link show dummy98')
        print(output)
        self.assertEqual(read_bridge_port_attr('bridge99', 'dummy98', 'path_cost'), '400')
        self.assertEqual(read_bridge_port_attr('bridge99', 'dummy98', 'hairpin_mode'), '1')
        self.assertEqual(read_bridge_port_attr('bridge99', 'dummy98', 'multicast_fast_leave'), '1')
        self.assertEqual(read_bridge_port_attr('bridge99', 'dummy98', 'unicast_flood'), '1')
        self.assertEqual(read_bridge_port_attr('bridge99', 'dummy98', 'multicast_flood'), '0')
        # CONFIG_BRIDGE_IGMP_SNOOPING=y
        if (os.path.exists('/sys/devices/virtual/net/bridge00/lower_dummy98/brport/multicast_to_unicast')):
            self.assertEqual(read_bridge_port_attr('bridge99', 'dummy98', 'multicast_to_unicast'), '1')
        if (os.path.exists('/sys/devices/virtual/net/bridge99/lower_dummy98/brport/neigh_suppress')):
            self.assertEqual(read_bridge_port_attr('bridge99', 'dummy98', 'neigh_suppress'), '1')
        self.assertEqual(read_bridge_port_attr('bridge99', 'dummy98', 'learning'), '0')
        self.assertEqual(read_bridge_port_attr('bridge99', 'dummy98', 'priority'), '23')
        self.assertEqual(read_bridge_port_attr('bridge99', 'dummy98', 'bpdu_guard'), '1')
        self.assertEqual(read_bridge_port_attr('bridge99', 'dummy98', 'root_block'), '1')

        output = check_output('bridge -d link show test1')
        print(output)
        self.assertEqual(read_bridge_port_attr('bridge99', 'test1', 'priority'), '0')

        check_output('ip address add 192.168.0.16/24 dev bridge99')
        time.sleep(1)

        output = check_output('ip addr show bridge99')
        print(output)
        self.assertRegex(output, '192.168.0.16/24')

        # for issue #6088
        print('### ip -6 route list table all dev bridge99')
        output = check_output('ip -6 route list table all dev bridge99')
        print(output)
        self.assertRegex(output, 'ff00::/8 table local (proto kernel )?metric 256 (linkdown )?pref medium')

        self.assertEqual(call('ip link del test1'), 0)

        self.wait_operstate('bridge99', 'degraded-carrier')

        check_output('ip link del dummy98')

        self.wait_operstate('bridge99', 'no-carrier')

        output = check_output('ip address show bridge99')
        print(output)
        self.assertRegex(output, 'NO-CARRIER')
        self.assertNotRegex(output, '192.168.0.15/24')
        self.assertNotRegex(output, '192.168.0.16/24')

        print('### ip -6 route list table all dev bridge99')
        output = check_output('ip -6 route list table all dev bridge99')
        print(output)
        self.assertRegex(output, 'ff00::/8 table local (proto kernel )?metric 256 (linkdown )?pref medium')

    def test_bridge_configure_without_carrier(self):
        copy_unit_to_networkd_unit_path('26-bridge.netdev', '26-bridge-configure-without-carrier.network',
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
                    self.wait_online(['bridge99:routable'])
                    self.check_link_attr('bridge99', 'carrier', '1')
                elif test == 'slave-no-carrier':
                    # drop slave carrier; bridge loses carrier
                    check_output('ip link set dev test1 carrier off')
                    self.wait_online(['bridge99:no-carrier:no-carrier'])
                    self.check_link_attr('bridge99', 'carrier', '0')
                elif test == 'slave-carrier':
                    # restore slave carrier; bridge gains carrier
                    check_output('ip link set dev test1 carrier on')
                    self.wait_online(['bridge99:routable'])
                    self.check_link_attr('bridge99', 'carrier', '1')
                elif test == 'slave-down':
                    # bring down slave; bridge loses carrier
                    check_output('ip link set dev test1 down')
                    self.wait_online(['bridge99:no-carrier:no-carrier'])
                    self.check_link_attr('bridge99', 'carrier', '0')

                output = check_output(*networkctl_cmd, '-n', '0', 'status', 'bridge99', env=env)
                self.assertRegex(output, '10.1.2.3')
                self.assertRegex(output, '10.1.2.1')

    def test_bridge_ignore_carrier_loss(self):
        copy_unit_to_networkd_unit_path('11-dummy.netdev', '12-dummy.netdev', '26-bridge.netdev',
                                        '26-bridge-slave-interface-1.network', '26-bridge-slave-interface-2.network',
                                        'bridge99-ignore-carrier-loss.network')
        start_networkd()
        self.wait_online(['dummy98:enslaved', 'test1:enslaved', 'bridge99:routable'])

        check_output('ip address add 192.168.0.16/24 dev bridge99')
        time.sleep(1)

        check_output('ip link del test1')
        check_output('ip link del dummy98')
        time.sleep(3)

        output = check_output('ip address show bridge99')
        print(output)
        self.assertRegex(output, 'NO-CARRIER')
        self.assertRegex(output, 'inet 192.168.0.15/24 brd 192.168.0.255 scope global bridge99')
        self.assertRegex(output, 'inet 192.168.0.16/24 scope global secondary bridge99')

    def test_bridge_ignore_carrier_loss_frequent_loss_and_gain(self):
        copy_unit_to_networkd_unit_path('26-bridge.netdev', '26-bridge-slave-interface-1.network',
                                        'bridge99-ignore-carrier-loss.network')
        start_networkd()
        self.wait_online(['bridge99:no-carrier'])

        for trial in range(4):
            check_output('ip link add dummy98 type dummy')
            check_output('ip link set dummy98 up')
            if trial < 3:
                check_output('ip link del dummy98')

        self.wait_online(['bridge99:routable', 'dummy98:enslaved'])

        output = check_output('ip address show bridge99')
        print(output)
        self.assertRegex(output, 'inet 192.168.0.15/24 brd 192.168.0.255 scope global bridge99')

        output = check_output('ip rule list table 100')
        print(output)
        self.assertIn('from all to 8.8.8.8 lookup 100', output)

class NetworkdLLDPTests(unittest.TestCase, Utilities):
    links = ['veth99']

    units = [
        '23-emit-lldp.network',
        '24-lldp.network',
        '25-veth.netdev']

    def setUp(self):
        remove_links(self.links)
        stop_networkd(show_logs=False)

    def tearDown(self):
        remove_links(self.links)
        remove_unit_from_networkd_path(self.units)
        stop_networkd(show_logs=True)

    def test_lldp(self):
        copy_unit_to_networkd_unit_path('23-emit-lldp.network', '24-lldp.network', '25-veth.netdev')
        start_networkd()
        self.wait_online(['veth99:degraded', 'veth-peer:degraded'])

        for trial in range(10):
            if trial > 0:
                time.sleep(1)

            output = check_output(*networkctl_cmd, 'lldp', env=env)
            print(output)
            if re.search(r'veth99 .* veth-peer', output):
                break
        else:
            self.fail()

class NetworkdRATests(unittest.TestCase, Utilities):
    links = ['veth99']

    units = [
        '25-veth.netdev',
        'ipv6-prefix.network',
        'ipv6-prefix-veth.network',
        'ipv6-prefix-veth-token-static.network',
        'ipv6-prefix-veth-token-prefixstable.network',
        'ipv6-prefix-veth-token-prefixstable-without-address.network']

    def setUp(self):
        remove_links(self.links)
        stop_networkd(show_logs=False)

    def tearDown(self):
        remove_links(self.links)
        remove_unit_from_networkd_path(self.units)
        stop_networkd(show_logs=True)

    def test_ipv6_prefix_delegation(self):
        copy_unit_to_networkd_unit_path('25-veth.netdev', 'ipv6-prefix.network', 'ipv6-prefix-veth.network')
        start_networkd()
        self.wait_online(['veth99:routable', 'veth-peer:degraded'])

        output = check_output(*resolvectl_cmd, 'dns', 'veth99', env=env)
        print(output)
        self.assertRegex(output, 'fe80::')
        self.assertRegex(output, '2002:da8:1::1')

        output = check_output(*resolvectl_cmd, 'domain', 'veth99', env=env)
        print(output)
        self.assertIn('hogehoge.test', output)

        output = check_output(*networkctl_cmd, '-n', '0', 'status', 'veth99', env=env)
        print(output)
        self.assertRegex(output, '2002:da8:1:0')

    def test_ipv6_token_static(self):
        copy_unit_to_networkd_unit_path('25-veth.netdev', 'ipv6-prefix.network', 'ipv6-prefix-veth-token-static.network')
        start_networkd()
        self.wait_online(['veth99:routable', 'veth-peer:degraded'])

        output = check_output(*networkctl_cmd, '-n', '0', 'status', 'veth99', env=env)
        print(output)
        self.assertRegex(output, '2002:da8:1:0:1a:2b:3c:4d')
        self.assertRegex(output, '2002:da8:1:0:fa:de:ca:fe')
        self.assertRegex(output, '2002:da8:2:0:1a:2b:3c:4d')
        self.assertRegex(output, '2002:da8:2:0:fa:de:ca:fe')

    def test_ipv6_token_prefixstable(self):
        copy_unit_to_networkd_unit_path('25-veth.netdev', 'ipv6-prefix.network', 'ipv6-prefix-veth-token-prefixstable.network')
        start_networkd()
        self.wait_online(['veth99:routable', 'veth-peer:degraded'])

        output = check_output(*networkctl_cmd, '-n', '0', 'status', 'veth99', env=env)
        print(output)
        self.assertRegex(output, '2002:da8:1:0')
        self.assertRegex(output, '2002:da8:2:0.*78:9abc') # EUI

    def test_ipv6_token_prefixstable_without_address(self):
        copy_unit_to_networkd_unit_path('25-veth.netdev', 'ipv6-prefix.network', 'ipv6-prefix-veth-token-prefixstable-without-address.network')
        start_networkd()
        self.wait_online(['veth99:routable', 'veth-peer:degraded'])

        output = check_output(*networkctl_cmd, '-n', '0', 'status', 'veth99', env=env)
        print(output)
        self.assertRegex(output, '2002:da8:1:0')
        self.assertRegex(output, '2002:da8:2:0')

class NetworkdDHCPServerTests(unittest.TestCase, Utilities):
    links = [
        'dummy98',
        'veth99',
    ]

    units = [
        '12-dummy.netdev',
        '25-veth.netdev',
        'dhcp-client.network',
        'dhcp-client-static-lease.network',
        'dhcp-client-timezone-router.network',
        'dhcp-server.network',
        'dhcp-server-static-lease.network',
        'dhcp-server-timezone-router.network',
        'dhcp-server-uplink.network',
    ]

    def setUp(self):
        remove_links(self.links)
        stop_networkd(show_logs=False)

    def tearDown(self):
        remove_links(self.links)
        remove_unit_from_networkd_path(self.units)
        stop_networkd(show_logs=True)

    def test_dhcp_server(self):
        copy_unit_to_networkd_unit_path('25-veth.netdev', 'dhcp-client.network', 'dhcp-server.network',
                                        '12-dummy.netdev', 'dhcp-server-uplink.network')
        start_networkd()
        self.wait_online(['veth99:routable', 'veth-peer:routable'])

        output = check_output(*networkctl_cmd, '-n', '0', 'status', 'veth99', env=env)
        print(output)
        self.assertRegex(output, '192.168.5.*')
        self.assertRegex(output, 'Gateway: 192.168.5.1')
        self.assertRegex(output, 'DNS: 192.168.5.1')
        self.assertRegex(output, 'NTP: 192.168.5.1')

    def test_emit_router_timezone(self):
        copy_unit_to_networkd_unit_path('25-veth.netdev', 'dhcp-client-timezone-router.network', 'dhcp-server-timezone-router.network')
        start_networkd()
        self.wait_online(['veth99:routable', 'veth-peer:routable'])

        output = check_output(*networkctl_cmd, '-n', '0', 'status', 'veth99', env=env)
        print(output)
        self.assertRegex(output, 'Gateway: 192.168.5.*')
        self.assertRegex(output, '192.168.5.*')
        self.assertRegex(output, 'Europe/Berlin')

    def test_dhcp_server_static_lease(self):
        copy_unit_to_networkd_unit_path('25-veth.netdev', 'dhcp-client-static-lease.network', 'dhcp-server-static-lease.network')
        start_networkd()
        self.wait_online(['veth99:routable', 'veth-peer:routable'])

        output = check_output(*networkctl_cmd, '-n', '0', 'status', 'veth99', env=env)
        print(output)
        self.assertIn('10.1.1.3 (DHCP4 via 10.1.1.1)', output)

class NetworkdDHCPServerRelayAgentTests(unittest.TestCase, Utilities):
    links = [
        'client',
        'server',
        'client-peer',
        'server-peer',
        ]

    units = [
        'agent-veth-client.netdev',
        'agent-veth-server.netdev',
        'agent-client.network',
        'agent-server.network',
        'agent-client-peer.network',
        'agent-server-peer.network',
        ]

    def setUp(self):
        remove_links(self.links)
        stop_networkd(show_logs=False)

    def tearDown(self):
        remove_links(self.links)
        remove_unit_from_networkd_path(self.units)
        stop_networkd(show_logs=True)

    def test_relay_agent(self):
        copy_unit_to_networkd_unit_path(*self.units)
        start_networkd()

        self.wait_online(['client:routable'])

        output = check_output(*networkctl_cmd, '-n', '0', 'status', 'client', env=env)
        print(output)
        self.assertRegex(output, 'Address: 192.168.5.150 \(DHCP4 via 192.168.5.1\)')

class NetworkdDHCPClientTests(unittest.TestCase, Utilities):
    links = [
        'veth99',
        'vrf99']

    units = [
        '25-veth.netdev',
        '25-vrf.netdev',
        '25-vrf.network',
        'dhcp-client-anonymize.network',
        'dhcp-client-decline.network',
        'dhcp-client-gateway-ipv4.network',
        'dhcp-client-gateway-ipv6.network',
        'dhcp-client-gateway-onlink-implicit.network',
        'dhcp-client-ipv4-dhcp-settings.network',
        'dhcp-client-ipv4-only-ipv6-disabled.network',
        'dhcp-client-ipv4-only.network',
        'dhcp-client-ipv4-use-routes-use-gateway.network',
        'dhcp-client-ipv6-only.network',
        'dhcp-client-ipv6-rapid-commit.network',
        'dhcp-client-keep-configuration-dhcp-on-stop.network',
        'dhcp-client-keep-configuration-dhcp.network',
        'dhcp-client-listen-port.network',
        'dhcp-client-reassign-static-routes-ipv4.network',
        'dhcp-client-reassign-static-routes-ipv6.network',
        'dhcp-client-route-metric.network',
        'dhcp-client-route-table.network',
        'dhcp-client-use-dns-ipv4-and-ra.network',
        'dhcp-client-use-dns-ipv4.network',
        'dhcp-client-use-dns-no.network',
        'dhcp-client-use-dns-yes.network',
        'dhcp-client-use-domains.network',
        'dhcp-client-vrf.network',
        'dhcp-client-with-ipv4ll.network',
        'dhcp-client-with-static-address.network',
        'dhcp-client.network',
        'dhcp-server-decline.network',
        'dhcp-server-veth-peer.network',
        'dhcp-v4-server-veth-peer.network',
        'static.network']

    def setUp(self):
        stop_dnsmasq(dnsmasq_pid_file)
        remove_links(self.links)
        stop_networkd(show_logs=False)

    def tearDown(self):
        stop_dnsmasq(dnsmasq_pid_file)
        remove_lease_file()
        remove_log_file()
        remove_links(self.links)
        remove_unit_from_networkd_path(self.units)
        stop_networkd(show_logs=True)

    def test_dhcp_client_ipv6_only(self):
        copy_unit_to_networkd_unit_path('25-veth.netdev', 'dhcp-server-veth-peer.network', 'dhcp-client-ipv6-only.network')

        start_networkd()
        self.wait_online(['veth-peer:carrier'])
        start_dnsmasq()
        self.wait_online(['veth99:routable', 'veth-peer:routable'])

        output = check_output(*networkctl_cmd, '-n', '0', 'status', 'veth99', env=env)
        print(output)
        self.assertRegex(output, '2600::')
        self.assertNotRegex(output, '192.168.5')

        output = check_output('ip addr show dev veth99')
        print(output)
        self.assertRegex(output, '2600::')
        self.assertNotRegex(output, '192.168.5')
        self.assertNotRegex(output, 'tentative')

        # Confirm that ipv6 token is not set in the kernel
        output = check_output('ip token show dev veth99')
        print(output)
        self.assertRegex(output, 'token :: dev veth99')

    def test_dhcp_client_ipv4_only(self):
        copy_unit_to_networkd_unit_path('25-veth.netdev', 'dhcp-server-veth-peer.network', 'dhcp-client-ipv4-only-ipv6-disabled.network')

        start_networkd()
        self.wait_online(['veth-peer:carrier'])
        start_dnsmasq(additional_options='--dhcp-option=option:dns-server,192.168.5.6,192.168.5.7', lease_time='2m')
        self.wait_online(['veth99:routable', 'veth-peer:routable'])

        output = check_output(*networkctl_cmd, '-n', '0', 'status', 'veth99', env=env)
        print(output)
        self.assertNotRegex(output, '2600::')
        self.assertRegex(output, '192.168.5')
        self.assertRegex(output, '192.168.5.6')
        self.assertRegex(output, '192.168.5.7')

        # checking routes to DNS servers
        output = check_output('ip route show dev veth99')
        print(output)
        self.assertRegex(output, r'192.168.5.1 proto dhcp scope link src 192.168.5.181 metric 1024')
        self.assertRegex(output, r'192.168.5.6 proto dhcp scope link src 192.168.5.181 metric 1024')
        self.assertRegex(output, r'192.168.5.7 proto dhcp scope link src 192.168.5.181 metric 1024')

        stop_dnsmasq(dnsmasq_pid_file)
        start_dnsmasq(additional_options='--dhcp-option=option:dns-server,192.168.5.1,192.168.5.7,192.168.5.8', lease_time='2m')

        # Sleep for 120 sec as the dnsmasq minimum lease time can only be set to 120
        print('Wait for the dynamic address to be renewed')
        time.sleep(125)

        self.wait_online(['veth99:routable', 'veth-peer:routable'])

        output = check_output(*networkctl_cmd, '-n', '0', 'status', 'veth99', env=env)
        print(output)
        self.assertNotRegex(output, '2600::')
        self.assertRegex(output, '192.168.5')
        self.assertNotRegex(output, '192.168.5.6')
        self.assertRegex(output, '192.168.5.7')
        self.assertRegex(output, '192.168.5.8')

        # checking routes to DNS servers
        output = check_output('ip route show dev veth99')
        print(output)
        self.assertNotRegex(output, r'192.168.5.6')
        self.assertRegex(output, r'192.168.5.1 proto dhcp scope link src 192.168.5.181 metric 1024')
        self.assertRegex(output, r'192.168.5.7 proto dhcp scope link src 192.168.5.181 metric 1024')
        self.assertRegex(output, r'192.168.5.8 proto dhcp scope link src 192.168.5.181 metric 1024')

    def test_dhcp_client_ipv4_use_routes_gateway(self):
        for (routes, gateway, dns_and_ntp_routes, classless) in itertools.product([True, False], repeat=4):
            self.setUp()
            with self.subTest(routes=routes, gateway=gateway, dns_and_ntp_routes=dns_and_ntp_routes, classless=classless):
                self._test_dhcp_client_ipv4_use_routes_gateway(routes, gateway, dns_and_ntp_routes, classless)
            self.tearDown()

    def _test_dhcp_client_ipv4_use_routes_gateway(self, use_routes, use_gateway, dns_and_ntp_routes, classless):
        testunit = 'dhcp-client-ipv4-use-routes-use-gateway.network'
        testunits = ['25-veth.netdev', 'dhcp-server-veth-peer.network', testunit]
        testunits.append(f'{testunit}.d/use-routes-{use_routes}.conf');
        testunits.append(f'{testunit}.d/use-gateway-{use_gateway}.conf');
        testunits.append(f'{testunit}.d/use-dns-and-ntp-routes-{dns_and_ntp_routes}.conf');
        copy_unit_to_networkd_unit_path(*testunits, dropins=False)

        start_networkd()
        self.wait_online(['veth-peer:carrier'])
        additional_options = '--dhcp-option=option:dns-server,192.168.5.10,8.8.8.8 --dhcp-option=option:ntp-server,192.168.5.11,9.9.9.9 --dhcp-option=option:static-route,192.168.5.100,192.168.5.2,8.8.8.8,192.168.5.3'
        if classless:
            additional_options += ' --dhcp-option=option:classless-static-route,0.0.0.0/0,192.168.5.4,8.0.0.0/8,192.168.5.5'
        start_dnsmasq(additional_options=additional_options, lease_time='2m')
        self.wait_online(['veth99:routable', 'veth-peer:routable'])

        output = check_output('ip -4 route show dev veth99')
        print(output)

        # Check UseRoutes=
        if use_routes:
            if classless:
                self.assertRegex(output, r'default via 192.168.5.4 proto dhcp src 192.168.5.[0-9]* metric 1024')
                self.assertRegex(output, r'8.0.0.0/8 via 192.168.5.5 proto dhcp src 192.168.5.[0-9]* metric 1024')
                self.assertRegex(output, r'192.168.5.4 proto dhcp scope link src 192.168.5.[0-9]* metric 1024')
                self.assertRegex(output, r'192.168.5.5 proto dhcp scope link src 192.168.5.[0-9]* metric 1024')
            else:
                self.assertRegex(output, r'192.168.5.0/24 proto dhcp scope link src 192.168.5.[0-9]* metric 1024')
                self.assertRegex(output, r'8.0.0.0/8 via 192.168.5.3 proto dhcp src 192.168.5.[0-9]* metric 1024')
                self.assertRegex(output, r'192.168.5.3 proto dhcp scope link src 192.168.5.[0-9]* metric 1024')
        else:
            self.assertNotRegex(output, r'default via 192.168.5.4 proto dhcp src 192.168.5.[0-9]* metric 1024')
            self.assertNotRegex(output, r'8.0.0.0/8 via 192.168.5.5 proto dhcp src 192.168.5.[0-9]* metric 1024')
            self.assertNotRegex(output, r'192.168.5.4 proto dhcp scope link src 192.168.5.[0-9]* metric 1024')
            self.assertNotRegex(output, r'192.168.5.5 proto dhcp scope link src 192.168.5.[0-9]* metric 1024')
            self.assertNotRegex(output, r'192.168.5.0/24 proto dhcp scope link src 192.168.5.[0-9]* metric 1024')
            self.assertNotRegex(output, r'8.0.0.0/8 via 192.168.5.3 proto dhcp src 192.168.5.[0-9]* metric 1024')
            self.assertNotRegex(output, r'192.168.5.3 proto dhcp scope link src 192.168.5.[0-9]* metric 1024')

        # Check UseGateway=
        if use_gateway and (not classless or not use_routes):
            self.assertRegex(output, r'default via 192.168.5.1 proto dhcp src 192.168.5.[0-9]* metric 1024')
            self.assertRegex(output, r'192.168.5.1 proto dhcp scope link src 192.168.5.[0-9]* metric 1024')
        else:
            self.assertNotRegex(output, r'default via 192.168.5.1 proto dhcp src 192.168.5.[0-9]* metric 1024')
            self.assertNotRegex(output, r'192.168.5.1 proto dhcp scope link src 192.168.5.[0-9]* metric 1024')

        # Check RoutesToDNS= and RoutesToNTP=
        if dns_and_ntp_routes:
            self.assertRegex(output, r'192.168.5.10 proto dhcp scope link src 192.168.5.[0-9]* metric 1024')
            self.assertRegex(output, r'192.168.5.11 proto dhcp scope link src 192.168.5.[0-9]* metric 1024')
            if classless and use_routes:
                self.assertRegex(output, r'8.8.8.8 via 192.168.5.4 proto dhcp src 192.168.5.[0-9]* metric 1024')
                self.assertRegex(output, r'9.9.9.9 via 192.168.5.4 proto dhcp src 192.168.5.[0-9]* metric 1024')
            elif use_gateway:
                self.assertRegex(output, r'8.8.8.8 via 192.168.5.1 proto dhcp src 192.168.5.[0-9]* metric 1024')
                self.assertRegex(output, r'9.9.9.9 via 192.168.5.1 proto dhcp src 192.168.5.[0-9]* metric 1024')
            else:
                self.assertNotRegex(output, r'8.8.8.8 via 192.168.5.[0-9]* proto dhcp src 192.168.5.[0-9]* metric 1024')
                self.assertNotRegex(output, r'9.9.9.9 via 192.168.5.[0-9]* proto dhcp src 192.168.5.[0-9]* metric 1024')
        else:
            self.assertNotRegex(output, r'192.168.5.10 proto dhcp scope link src 192.168.5.[0-9]* metric 1024')
            self.assertNotRegex(output, r'192.168.5.11 proto dhcp scope link src 192.168.5.[0-9]* metric 1024')
            self.assertNotRegex(output, r'8.8.8.8 via 192.168.5.[0-9]* proto dhcp src 192.168.5.[0-9]* metric 1024')
            self.assertNotRegex(output, r'9.9.9.9 via 192.168.5.[0-9]* proto dhcp src 192.168.5.[0-9]* metric 1024')

    def test_dhcp_client_ipv4_ipv6(self):
        copy_unit_to_networkd_unit_path('25-veth.netdev', 'dhcp-server-veth-peer.network', 'dhcp-client-ipv6-only.network',
                                        'dhcp-client-ipv4-only.network')
        start_networkd()
        self.wait_online(['veth-peer:carrier'])
        start_dnsmasq()
        self.wait_online(['veth99:routable', 'veth-peer:routable'])

        # link become 'routable' when at least one protocol provide an valid address.
        self.wait_address('veth99', r'inet 192.168.5.[0-9]*/24 metric 1024 brd 192.168.5.255 scope global dynamic', ipv='-4')
        self.wait_address('veth99', r'inet6 2600::[0-9a-f]*/128 scope global (dynamic noprefixroute|noprefixroute dynamic)', ipv='-6')

        output = check_output(*networkctl_cmd, '-n', '0', 'status', 'veth99', env=env)
        print(output)
        self.assertRegex(output, '2600::')
        self.assertRegex(output, '192.168.5')

    def test_dhcp_client_settings(self):
        copy_unit_to_networkd_unit_path('25-veth.netdev', 'dhcp-server-veth-peer.network', 'dhcp-client-ipv4-dhcp-settings.network')

        start_networkd()
        self.wait_online(['veth-peer:carrier'])
        start_dnsmasq()
        self.wait_online(['veth99:routable', 'veth-peer:routable'])

        print('## ip address show dev veth99')
        output = check_output('ip address show dev veth99')
        print(output)
        self.assertRegex(output, '12:34:56:78:9a:bc')
        self.assertRegex(output, '192.168.5')
        self.assertRegex(output, '1492')

        print('## ip route show table main dev veth99')
        output = check_output('ip route show table main dev veth99')
        print(output)
        # See issue #8726
        main_table_is_empty = output == ''
        if not main_table_is_empty:
            self.assertNotRegex(output, 'proto dhcp')

        print('## ip route show table 211 dev veth99')
        output = check_output('ip route show table 211 dev veth99')
        print(output)
        self.assertRegex(output, 'default via 192.168.5.1 proto dhcp')
        if main_table_is_empty:
            self.assertRegex(output, '192.168.5.0/24 proto dhcp')
        self.assertRegex(output, '192.168.5.1 proto dhcp scope link')

        print('## dnsmasq log')
        self.assertTrue(search_words_in_dnsmasq_log('vendor class: SusantVendorTest', True))
        self.assertTrue(search_words_in_dnsmasq_log('DHCPDISCOVER(veth-peer) 12:34:56:78:9a:bc'))
        self.assertTrue(search_words_in_dnsmasq_log('client provides name: test-hostname'))
        self.assertTrue(search_words_in_dnsmasq_log('26:mtu'))

    def test_dhcp6_client_settings_rapidcommit_true(self):
        copy_unit_to_networkd_unit_path('25-veth.netdev', 'dhcp-server-veth-peer.network', 'dhcp-client-ipv6-only.network')
        start_networkd()
        self.wait_online(['veth-peer:carrier'])
        start_dnsmasq()
        self.wait_online(['veth99:routable', 'veth-peer:routable'])

        output = check_output('ip address show dev veth99')
        print(output)
        self.assertRegex(output, '12:34:56:78:9a:bc')
        self.assertTrue(search_words_in_dnsmasq_log('14:rapid-commit', True))

    def test_dhcp6_client_settings_rapidcommit_false(self):
        copy_unit_to_networkd_unit_path('25-veth.netdev', 'dhcp-server-veth-peer.network', 'dhcp-client-ipv6-rapid-commit.network')
        start_networkd()
        self.wait_online(['veth-peer:carrier'])
        start_dnsmasq()
        self.wait_online(['veth99:routable', 'veth-peer:routable'])

        output = check_output('ip address show dev veth99')
        print(output)
        self.assertRegex(output, '12:34:56:78:9a:bc')
        self.assertFalse(search_words_in_dnsmasq_log('14:rapid-commit', True))

    def test_dhcp_client_settings_anonymize(self):
        copy_unit_to_networkd_unit_path('25-veth.netdev', 'dhcp-server-veth-peer.network', 'dhcp-client-anonymize.network')
        start_networkd()
        self.wait_online(['veth-peer:carrier'])
        start_dnsmasq()
        self.wait_online(['veth99:routable', 'veth-peer:routable'])

        self.assertFalse(search_words_in_dnsmasq_log('VendorClassIdentifier=SusantVendorTest', True))
        self.assertFalse(search_words_in_dnsmasq_log('test-hostname'))
        self.assertFalse(search_words_in_dnsmasq_log('26:mtu'))

    def test_dhcp_client_listen_port(self):
        copy_unit_to_networkd_unit_path('25-veth.netdev', 'dhcp-server-veth-peer.network', 'dhcp-client-listen-port.network')
        start_networkd()
        self.wait_online(['veth-peer:carrier'])
        start_dnsmasq('--dhcp-alternate-port=67,5555')
        self.wait_online(['veth99:routable', 'veth-peer:routable'])

        output = check_output('ip -4 address show dev veth99')
        print(output)
        self.assertRegex(output, '192.168.5.* dynamic')

    def test_dhcp_client_with_static_address(self):
        copy_unit_to_networkd_unit_path('25-veth.netdev', 'dhcp-v4-server-veth-peer.network',
                                        'dhcp-client-with-static-address.network')
        start_networkd()
        self.wait_online(['veth-peer:carrier'])
        start_dnsmasq()
        self.wait_online(['veth99:routable', 'veth-peer:routable'])

        output = check_output('ip address show dev veth99 scope global')
        print(output)
        self.assertRegex(output, r'inet 192.168.5.250/24 brd 192.168.5.255 scope global veth99')
        self.assertRegex(output, r'inet 192.168.5.[0-9]*/24 metric 1024 brd 192.168.5.255 scope global secondary dynamic veth99')

        output = check_output('ip route show dev veth99')
        print(output)
        self.assertRegex(output, r'default via 192.168.5.1 proto dhcp src 192.168.5.[0-9]* metric 1024')
        self.assertRegex(output, r'192.168.5.0/24 proto kernel scope link src 192.168.5.250')
        self.assertRegex(output, r'192.168.5.1 proto dhcp scope link src 192.168.5.[0-9]* metric 1024')

    def test_dhcp_route_table_id(self):
        copy_unit_to_networkd_unit_path('25-veth.netdev', 'dhcp-v4-server-veth-peer.network', 'dhcp-client-route-table.network')
        start_networkd()
        self.wait_online(['veth-peer:carrier'])
        start_dnsmasq()
        self.wait_online(['veth99:routable', 'veth-peer:routable'])

        output = check_output('ip route show table 12')
        print(output)
        self.assertRegex(output, 'veth99 proto dhcp')
        self.assertRegex(output, '192.168.5.1')

    def test_dhcp_route_metric(self):
        copy_unit_to_networkd_unit_path('25-veth.netdev', 'dhcp-v4-server-veth-peer.network', 'dhcp-client-route-metric.network')
        start_networkd()
        self.wait_online(['veth-peer:carrier'])
        start_dnsmasq()
        self.wait_online(['veth99:routable', 'veth-peer:routable'])

        output = check_output('ip route show dev veth99')
        print(output)
        self.assertIn('default via 192.168.5.1 proto dhcp src 192.168.5.181 metric 24', output)
        self.assertIn('192.168.5.0/24 proto kernel scope link src 192.168.5.181 metric 24', output)
        self.assertIn('192.168.5.1 proto dhcp scope link src 192.168.5.181 metric 24', output)

    def test_dhcp_client_reassign_static_routes_ipv4(self):
        copy_unit_to_networkd_unit_path('25-veth.netdev', 'dhcp-server-veth-peer.network',
                                        'dhcp-client-reassign-static-routes-ipv4.network')
        start_networkd()
        self.wait_online(['veth-peer:carrier'])
        start_dnsmasq(lease_time='2m')
        self.wait_online(['veth99:routable', 'veth-peer:routable'])

        output = check_output('ip address show dev veth99 scope global')
        print(output)
        self.assertRegex(output, r'inet 192.168.5.[0-9]*/24 metric 1024 brd 192.168.5.255 scope global dynamic veth99')

        output = check_output('ip route show dev veth99')
        print(output)
        self.assertRegex(output, r'192.168.5.0/24 proto kernel scope link src 192.168.5.[0-9]*')
        self.assertRegex(output, r'192.168.5.0/24 proto static')
        self.assertRegex(output, r'192.168.6.0/24 proto static')
        self.assertRegex(output, r'192.168.7.0/24 proto static')

        stop_dnsmasq(dnsmasq_pid_file)
        start_dnsmasq(ipv4_range='192.168.5.210,192.168.5.220', lease_time='2m')

        # Sleep for 120 sec as the dnsmasq minimum lease time can only be set to 120
        print('Wait for the dynamic address to be renewed')
        time.sleep(125)

        self.wait_online(['veth99:routable'])

        output = check_output('ip route show dev veth99')
        print(output)
        self.assertRegex(output, r'192.168.5.0/24 proto kernel scope link src 192.168.5.[0-9]*')
        self.assertRegex(output, r'192.168.5.0/24 proto static')
        self.assertRegex(output, r'192.168.6.0/24 proto static')
        self.assertRegex(output, r'192.168.7.0/24 proto static')

    def test_dhcp_client_reassign_static_routes_ipv6(self):
        copy_unit_to_networkd_unit_path('25-veth.netdev', 'dhcp-server-veth-peer.network',
                                        'dhcp-client-reassign-static-routes-ipv6.network')
        start_networkd()
        self.wait_online(['veth-peer:carrier'])
        start_dnsmasq(lease_time='2m')
        self.wait_online(['veth99:routable', 'veth-peer:routable'])

        output = check_output('ip address show dev veth99 scope global')
        print(output)
        self.assertRegex(output, r'inet6 2600::[0-9a-f]*/128 scope global (noprefixroute dynamic|dynamic noprefixroute)')

        output = check_output('ip -6 route show dev veth99')
        print(output)
        self.assertRegex(output, r'2600::/64 proto ra metric 1024')
        self.assertRegex(output, r'2600:0:0:1::/64 proto static metric 1024 pref medium')

        stop_dnsmasq(dnsmasq_pid_file)
        start_dnsmasq(ipv6_range='2600::30,2600::40', lease_time='2m')

        # Sleep for 120 sec as the dnsmasq minimum lease time can only be set to 120
        print('Wait for the dynamic address to be renewed')
        time.sleep(125)

        self.wait_online(['veth99:routable'])

        output = check_output('ip -6 route show dev veth99')
        print(output)
        self.assertRegex(output, r'2600::/64 proto ra metric 1024')
        self.assertRegex(output, r'2600:0:0:1::/64 proto static metric 1024 pref medium')

    def test_dhcp_keep_configuration_dhcp(self):
        copy_unit_to_networkd_unit_path('25-veth.netdev', 'dhcp-v4-server-veth-peer.network', 'dhcp-client-keep-configuration-dhcp.network')
        start_networkd()
        self.wait_online(['veth-peer:carrier'])
        start_dnsmasq(lease_time='2m')
        self.wait_online(['veth99:routable', 'veth-peer:routable'])

        output = check_output('ip address show dev veth99 scope global')
        print(output)
        self.assertRegex(output, r'192.168.5.*')

        output = check_output(*networkctl_cmd, '-n', '0', 'status', 'veth99', env=env)
        print(output)
        self.assertRegex(output, r'192.168.5.*')

        # Stopping dnsmasq as networkd won't be allowed to renew the DHCP lease.
        stop_dnsmasq(dnsmasq_pid_file)

        # Sleep for 120 sec as the dnsmasq minimum lease time can only be set to 120
        print('Wait for the dynamic address to be expired')
        time.sleep(125)

        print('The lease address should be kept after lease expired')
        output = check_output('ip address show dev veth99 scope global')
        print(output)
        self.assertRegex(output, r'192.168.5.*')

        output = check_output(*networkctl_cmd, '-n', '0', 'status', 'veth99', env=env)
        print(output)
        self.assertRegex(output, r'192.168.5.*')

        check_output('systemctl stop systemd-networkd.socket')
        check_output('systemctl stop systemd-networkd.service')

        print('The lease address should be kept after networkd stopped')
        output = check_output('ip address show dev veth99 scope global')
        print(output)
        self.assertRegex(output, r'192.168.5.*')

        output = check_output(*networkctl_cmd, '-n', '0', 'status', 'veth99', env=env)
        print(output)
        self.assertRegex(output, r'192.168.5.*')

        start_networkd(3)
        self.wait_online(['veth-peer:routable'])

        print('Still the lease address should be kept after networkd restarted')
        output = check_output('ip address show dev veth99 scope global')
        print(output)
        self.assertRegex(output, r'192.168.5.*')

        output = check_output(*networkctl_cmd, '-n', '0', 'status', 'veth99', env=env)
        print(output)
        self.assertRegex(output, r'192.168.5.*')

    def test_dhcp_keep_configuration_dhcp_on_stop(self):
        copy_unit_to_networkd_unit_path('25-veth.netdev', 'dhcp-v4-server-veth-peer.network', 'dhcp-client-keep-configuration-dhcp-on-stop.network')
        start_networkd()
        self.wait_online(['veth-peer:carrier'])
        start_dnsmasq(lease_time='2m')
        self.wait_online(['veth99:routable', 'veth-peer:routable'])

        output = check_output('ip address show dev veth99 scope global')
        print(output)
        self.assertRegex(output, r'192.168.5.*')

        stop_dnsmasq(dnsmasq_pid_file)
        check_output('systemctl stop systemd-networkd.socket')
        check_output('systemctl stop systemd-networkd.service')

        output = check_output('ip address show dev veth99 scope global')
        print(output)
        self.assertRegex(output, r'192.168.5.*')

        restart_networkd(3)
        self.wait_online(['veth-peer:routable'])

        output = check_output('ip address show dev veth99 scope global')
        print(output)
        self.assertNotRegex(output, r'192.168.5.*')

    def test_dhcp_client_reuse_address_as_static(self):
        copy_unit_to_networkd_unit_path('25-veth.netdev', 'dhcp-server-veth-peer.network', 'dhcp-client.network')
        start_networkd()
        self.wait_online(['veth-peer:carrier'])
        start_dnsmasq()
        self.wait_online(['veth99:routable', 'veth-peer:routable'])

        # link become 'routable' when at least one protocol provide an valid address.
        self.wait_address('veth99', r'inet 192.168.5.[0-9]*/24 metric 1024 brd 192.168.5.255 scope global dynamic', ipv='-4')
        self.wait_address('veth99', r'inet6 2600::[0-9a-f]*/128 scope global (dynamic noprefixroute|noprefixroute dynamic)', ipv='-6')

        output = check_output('ip address show dev veth99 scope global')
        print(output)
        self.assertRegex(output, '192.168.5')
        self.assertRegex(output, '2600::')

        ipv4_address = re.search(r'192.168.5.[0-9]*/24', output)
        ipv6_address = re.search(r'2600::[0-9a-f:]*/128', output)
        static_network = '\n'.join(['[Match]', 'Name=veth99', '[Network]', 'IPv6AcceptRA=no', 'Address=' + ipv4_address.group(), 'Address=' + ipv6_address.group()])
        print(static_network)

        remove_unit_from_networkd_path(['dhcp-client.network'])

        with open(os.path.join(network_unit_file_path, 'static.network'), mode='w') as f:
            f.write(static_network)

        # When networkd started, the links are already configured, so let's wait for 5 seconds
        # the links to be re-configured.
        restart_networkd(5)
        self.wait_online(['veth99:routable', 'veth-peer:routable'])

        output = check_output('ip -4 address show dev veth99 scope global')
        print(output)
        self.assertRegex(output, '192.168.5')
        self.assertRegex(output, 'valid_lft forever preferred_lft forever')

        output = check_output('ip -6 address show dev veth99 scope global')
        print(output)
        self.assertRegex(output, '2600::')
        self.assertRegex(output, 'valid_lft forever preferred_lft forever')

    @expectedFailureIfModuleIsNotAvailable('vrf')
    def test_dhcp_client_vrf(self):
        copy_unit_to_networkd_unit_path('25-veth.netdev', 'dhcp-server-veth-peer.network', 'dhcp-client-vrf.network',
                                        '25-vrf.netdev', '25-vrf.network')
        start_networkd()
        self.wait_online(['veth-peer:carrier'])
        start_dnsmasq()
        self.wait_online(['veth99:routable', 'veth-peer:routable', 'vrf99:carrier'])

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

    def test_dhcp_client_gateway_ipv4(self):
        copy_unit_to_networkd_unit_path('25-veth.netdev', 'dhcp-server-veth-peer.network',
                                        'dhcp-client-gateway-ipv4.network')
        start_networkd()
        self.wait_online(['veth-peer:carrier'])
        start_dnsmasq()
        self.wait_online(['veth99:routable', 'veth-peer:routable'])

        output = check_output('ip route list dev veth99 10.0.0.0/8')
        print(output)
        self.assertRegex(output, '10.0.0.0/8 via 192.168.5.1 proto dhcp')

    def test_dhcp_client_gateway_ipv6(self):
        copy_unit_to_networkd_unit_path('25-veth.netdev', 'dhcp-server-veth-peer.network',
                                        'dhcp-client-gateway-ipv6.network')
        start_networkd()
        self.wait_online(['veth-peer:carrier'])
        start_dnsmasq()
        self.wait_online(['veth99:routable', 'veth-peer:routable'])

        output = check_output('ip -6 route list dev veth99 2001:1234:5:9fff:ff:ff:ff:ff')
        print(output)
        self.assertRegex(output, 'via fe80::1034:56ff:fe78:9abd')

    def test_dhcp_client_gateway_onlink_implicit(self):
        copy_unit_to_networkd_unit_path('25-veth.netdev', 'dhcp-server-veth-peer.network',
                                        'dhcp-client-gateway-onlink-implicit.network')
        start_networkd()
        self.wait_online(['veth-peer:carrier'])
        start_dnsmasq()
        self.wait_online(['veth99:routable', 'veth-peer:routable'])

        output = check_output(*networkctl_cmd, '-n', '0', 'status', 'veth99', env=env)
        print(output)
        self.assertRegex(output, '192.168.5')

        output = check_output('ip route list dev veth99 10.0.0.0/8')
        print(output)
        self.assertRegex(output, 'onlink')
        output = check_output('ip route list dev veth99 192.168.100.0/24')
        print(output)
        self.assertRegex(output, 'onlink')

    def test_dhcp_client_with_ipv4ll_with_dhcp_server(self):
        copy_unit_to_networkd_unit_path('25-veth.netdev', 'dhcp-server-veth-peer.network',
                                        'dhcp-client-with-ipv4ll.network')
        start_networkd()
        self.wait_online(['veth-peer:carrier'])
        start_dnsmasq(lease_time='2m')
        self.wait_online(['veth99:routable', 'veth-peer:routable'])

        output = check_output('ip address show dev veth99')
        print(output)

        output = check_output('ip -6 address show dev veth99 scope global dynamic')
        self.assertNotRegex(output, r'inet6 2600::[0-9a-f]+/128 scope global dynamic')
        output = check_output('ip -6 address show dev veth99 scope link')
        self.assertRegex(output, r'inet6 .* scope link')
        output = check_output('ip -4 address show dev veth99 scope global dynamic')
        self.assertRegex(output, r'inet 192\.168\.5\.\d+/24 metric 1024 brd 192\.168\.5\.255 scope global dynamic veth99')
        output = check_output('ip -4 address show dev veth99 scope link')
        self.assertNotRegex(output, r'inet 169\.254\.\d+\.\d+/16 metric 2048 brd 169\.254\.255\.255 scope link')

        print('Wait for the dynamic address to be expired')
        time.sleep(130)

        output = check_output('ip address show dev veth99')
        print(output)

        output = check_output('ip -6 address show dev veth99 scope global dynamic')
        self.assertNotRegex(output, r'inet6 2600::[0-9a-f]+/128 scope global dynamic')
        output = check_output('ip -6 address show dev veth99 scope link')
        self.assertRegex(output, r'inet6 .* scope link')
        output = check_output('ip -4 address show dev veth99 scope global dynamic')
        self.assertRegex(output, r'inet 192\.168\.5\.\d+/24 metric 1024 brd 192\.168\.5\.255 scope global dynamic veth99')
        output = check_output('ip -4 address show dev veth99 scope link')
        self.assertNotRegex(output, r'inet 169\.254\.\d+\.\d+/16 metric 2048 brd 169\.254\.255\.255 scope link')

        search_words_in_dnsmasq_log('DHCPOFFER', show_all=True)

    def test_dhcp_client_with_ipv4ll_without_dhcp_server(self):
        copy_unit_to_networkd_unit_path('25-veth.netdev', 'dhcp-server-veth-peer.network',
                                        'dhcp-client-with-ipv4ll.network')
        start_networkd()
        # we need to increase timeout above default, as this will need to wait for
        # systemd-networkd to get the dhcpv4 transient failure event
        self.wait_online(['veth99:degraded', 'veth-peer:routable'], timeout='60s')

        output = check_output('ip address show dev veth99')
        print(output)

        output = check_output('ip -6 address show dev veth99 scope global dynamic')
        self.assertNotRegex(output, r'inet6 2600::[0-9a-f]+/128 scope global dynamic')
        output = check_output('ip -6 address show dev veth99 scope link')
        self.assertRegex(output, r'inet6 .* scope link')
        output = check_output('ip -4 address show dev veth99 scope global dynamic')
        self.assertNotRegex(output, r'inet 192\.168\.5\.\d+/24 metric 1024 brd 192\.168\.5\.255 scope global dynamic veth99')
        output = check_output('ip -4 address show dev veth99 scope link')
        self.assertRegex(output, r'inet 169\.254\.\d+\.\d+/16 metric 2048 brd 169\.254\.255\.255 scope link')

        start_dnsmasq(lease_time='2m')
        self.wait_address('veth99', r'inet 192\.168\.5\.\d+/24 metric 1024 brd 192\.168\.5\.255 scope global dynamic', ipv='-4')
        self.wait_address_dropped('veth99', r'inet 169\.254\.\d+\.\d+/16 metric 2048 brd 169\.255\.255\.255 scope link', scope='link', ipv='-4')

    def test_dhcp_client_route_remove_on_renew(self):
        copy_unit_to_networkd_unit_path('25-veth.netdev', 'dhcp-server-veth-peer.network',
                                        'dhcp-client-ipv4-only-ipv6-disabled.network')
        start_networkd()
        self.wait_online(['veth-peer:carrier'])
        start_dnsmasq(ipv4_range='192.168.5.100,192.168.5.199', lease_time='2m')
        self.wait_online(['veth99:routable', 'veth-peer:routable'])

        # test for issue #12490

        output = check_output('ip -4 address show dev veth99 scope global dynamic')
        print(output)
        self.assertRegex(output, 'inet 192.168.5.1[0-9]*/24 metric 1024 brd 192.168.5.255 scope global dynamic veth99')
        address1=None
        for line in output.splitlines():
            if 'brd 192.168.5.255 scope global dynamic veth99' in line:
                address1 = line.split()[1].split('/')[0]
                break

        output = check_output('ip -4 route show dev veth99')
        print(output)
        self.assertRegex(output, f'default via 192.168.5.1 proto dhcp src {address1} metric 1024')
        self.assertRegex(output, f'192.168.5.1 proto dhcp scope link src {address1} metric 1024')

        stop_dnsmasq(dnsmasq_pid_file)
        start_dnsmasq(ipv4_range='192.168.5.200,192.168.5.250', lease_time='2m')

        print('Wait for the dynamic address to be expired')
        time.sleep(130)

        output = check_output('ip -4 address show dev veth99 scope global dynamic')
        print(output)
        self.assertRegex(output, 'inet 192.168.5.2[0-9]*/24 metric 1024 brd 192.168.5.255 scope global dynamic veth99')
        address2=None
        for line in output.splitlines():
            if 'metric 1024 brd 192.168.5.255 scope global dynamic veth99' in line:
                address2 = line.split()[1].split('/')[0]
                break

        self.assertNotEqual(address1, address2)

        output = check_output('ip -4 route show dev veth99')
        print(output)
        self.assertNotRegex(output, f'default via 192.168.5.1 proto dhcp src {address1} metric 1024')
        self.assertNotRegex(output, f'192.168.5.1 proto dhcp scope link src {address1} metric 1024')
        self.assertRegex(output, f'default via 192.168.5.1 proto dhcp src {address2} metric 1024')
        self.assertRegex(output, f'192.168.5.1 proto dhcp scope link src {address2} metric 1024')

    def test_dhcp_client_use_dns_yes(self):
        copy_unit_to_networkd_unit_path('25-veth.netdev', 'dhcp-server-veth-peer.network', 'dhcp-client-use-dns-yes.network')

        start_networkd()
        self.wait_online(['veth-peer:carrier'])
        start_dnsmasq('--dhcp-option=option:dns-server,192.168.5.1 --dhcp-option=option6:dns-server,[2600::1]')
        self.wait_online(['veth99:routable', 'veth-peer:routable'])

        # link become 'routable' when at least one protocol provide an valid address.
        self.wait_address('veth99', r'inet 192.168.5.[0-9]*/24 metric 1024 brd 192.168.5.255 scope global dynamic', ipv='-4')
        self.wait_address('veth99', r'inet6 2600::[0-9a-f]*/128 scope global (dynamic noprefixroute|noprefixroute dynamic)', ipv='-6')

        time.sleep(3)
        output = check_output(*resolvectl_cmd, 'dns', 'veth99', env=env)
        print(output)
        self.assertRegex(output, '192.168.5.1')
        self.assertRegex(output, '2600::1')

    def test_dhcp_client_use_dns_no(self):
        copy_unit_to_networkd_unit_path('25-veth.netdev', 'dhcp-server-veth-peer.network', 'dhcp-client-use-dns-no.network')

        start_networkd()
        self.wait_online(['veth-peer:carrier'])
        start_dnsmasq('--dhcp-option=option:dns-server,192.168.5.1 --dhcp-option=option6:dns-server,[2600::1]')
        self.wait_online(['veth99:routable', 'veth-peer:routable'])

        # link become 'routable' when at least one protocol provide an valid address.
        self.wait_address('veth99', r'inet 192.168.5.[0-9]*/24 metric 1024 brd 192.168.5.255 scope global dynamic', ipv='-4')
        self.wait_address('veth99', r'inet6 2600::[0-9a-f]*/128 scope global (dynamic noprefixroute|noprefixroute dynamic)', ipv='-6')

        time.sleep(3)
        output = check_output(*resolvectl_cmd, 'dns', 'veth99', env=env)
        print(output)
        self.assertNotRegex(output, '192.168.5.1')
        self.assertNotRegex(output, '2600::1')

    def test_dhcp_client_use_dns_ipv4(self):
        copy_unit_to_networkd_unit_path('25-veth.netdev', 'dhcp-server-veth-peer.network', 'dhcp-client-use-dns-ipv4.network')

        start_networkd()
        self.wait_online(['veth-peer:carrier'])
        start_dnsmasq('--dhcp-option=option:dns-server,192.168.5.1 --dhcp-option=option6:dns-server,[2600::1]')
        self.wait_online(['veth99:routable', 'veth-peer:routable'])

        # link become 'routable' when at least one protocol provide an valid address.
        self.wait_address('veth99', r'inet 192.168.5.[0-9]*/24 metric 1024 brd 192.168.5.255 scope global dynamic', ipv='-4')
        self.wait_address('veth99', r'inet6 2600::[0-9a-f]*/128 scope global (dynamic noprefixroute|noprefixroute dynamic)', ipv='-6')

        time.sleep(3)
        output = check_output(*resolvectl_cmd, 'dns', 'veth99', env=env)
        print(output)
        self.assertRegex(output, '192.168.5.1')
        self.assertNotRegex(output, '2600::1')

    def test_dhcp_client_use_dns_ipv4_and_ra(self):
        copy_unit_to_networkd_unit_path('25-veth.netdev', 'dhcp-server-veth-peer.network', 'dhcp-client-use-dns-ipv4-and-ra.network')

        start_networkd()
        self.wait_online(['veth-peer:carrier'])
        start_dnsmasq('--dhcp-option=option:dns-server,192.168.5.1 --dhcp-option=option6:dns-server,[2600::1]')
        self.wait_online(['veth99:routable', 'veth-peer:routable'])

        # link become 'routable' when at least one protocol provide an valid address.
        self.wait_address('veth99', r'inet 192.168.5.[0-9]*/24 metric 1024 brd 192.168.5.255 scope global dynamic', ipv='-4')
        self.wait_address('veth99', r'inet6 2600::[0-9a-f]*/128 scope global (dynamic noprefixroute|noprefixroute dynamic)', ipv='-6')

        time.sleep(3)
        output = check_output(*resolvectl_cmd, 'dns', 'veth99', env=env)
        print(output)
        self.assertRegex(output, '192.168.5.1')
        self.assertRegex(output, '2600::1')

    def test_dhcp_client_use_domains(self):
        copy_unit_to_networkd_unit_path('25-veth.netdev', 'dhcp-server-veth-peer.network', 'dhcp-client-use-domains.network')

        start_networkd()
        self.wait_online(['veth-peer:carrier'])
        start_dnsmasq('--dhcp-option=option:domain-search,example.com')
        self.wait_online(['veth99:routable', 'veth-peer:routable'])

        output = check_output(*networkctl_cmd, '-n', '0', 'status', 'veth99', env=env)
        print(output)
        self.assertRegex(output, 'Search Domains: example.com')

        time.sleep(3)
        output = check_output(*resolvectl_cmd, 'domain', 'veth99', env=env)
        print(output)
        self.assertRegex(output, 'example.com')

    def test_dhcp_client_decline(self):
        copy_unit_to_networkd_unit_path('25-veth.netdev', 'dhcp-server-decline.network', 'dhcp-client-decline.network')

        start_networkd()
        self.wait_online(['veth99:routable', 'veth-peer:routable'])

        output = check_output('ip -4 address show dev veth99 scope global dynamic')
        print(output)
        self.assertRegex(output, 'inet 192.168.5.[0-9]*/24 metric 1024 brd 192.168.5.255 scope global dynamic veth99')

class NetworkdIPv6PrefixTests(unittest.TestCase, Utilities):
    links = ['veth99']

    units = [
        '25-veth.netdev',
        'ipv6ra-prefix-client-deny-list.network',
        'ipv6ra-prefix-client.network',
        'ipv6ra-prefix.network'
        ]

    def setUp(self):
        remove_links(self.links)
        stop_networkd(show_logs=False)

    def tearDown(self):
        remove_log_file()
        remove_links(self.links)
        remove_unit_from_networkd_path(self.units)
        stop_networkd(show_logs=True)

    def test_ipv6_route_prefix(self):
        copy_unit_to_networkd_unit_path('25-veth.netdev', 'ipv6ra-prefix-client.network', 'ipv6ra-prefix.network')

        start_networkd()
        self.wait_online(['veth99:routable', 'veth-peer:routable'])

        output = check_output('ip address show dev veth-peer')
        print(output)
        self.assertIn('inet6 2001:db8:0:1:', output)
        self.assertNotIn('inet6 2001:db8:0:2:', output)

        output = check_output('ip -6 route show dev veth-peer')
        print(output)
        self.assertIn('2001:db8:0:1::/64 proto ra', output)
        self.assertNotIn('2001:db8:0:2::/64 proto ra', output)
        self.assertIn('2001:db0:fff::/64 via ', output)
        self.assertNotIn('2001:db1:fff::/64 via ', output)

        output = check_output('ip address show dev veth99')
        print(output)
        self.assertNotIn('inet6 2001:db8:0:1:', output)
        self.assertIn('inet6 2001:db8:0:2:', output)

    def test_ipv6_route_prefix_deny_list(self):
        copy_unit_to_networkd_unit_path('25-veth.netdev', 'ipv6ra-prefix-client-deny-list.network', 'ipv6ra-prefix.network')

        start_networkd()
        self.wait_online(['veth99:routable', 'veth-peer:routable'])

        output = check_output('ip address show dev veth-peer')
        print(output)
        self.assertIn('inet6 2001:db8:0:1:', output)
        self.assertNotIn('inet6 2001:db8:0:2:', output)

        output = check_output('ip -6 route show dev veth-peer')
        print(output)
        self.assertIn('2001:db8:0:1::/64 proto ra', output)
        self.assertNotIn('2001:db8:0:2::/64 proto ra', output)
        self.assertIn('2001:db0:fff::/64 via ', output)
        self.assertNotIn('2001:db1:fff::/64 via ', output)

        output = check_output('ip address show dev veth99')
        print(output)
        self.assertNotIn('inet6 2001:db8:0:1:', output)
        self.assertIn('inet6 2001:db8:0:2:', output)

class NetworkdMTUTests(unittest.TestCase, Utilities):
    links = ['dummy98']

    units = [
        '12-dummy.netdev',
        '12-dummy-mtu.netdev',
        '12-dummy-mtu.link',
        '12-dummy.network',
        ]

    def setUp(self):
        remove_links(self.links)
        stop_networkd(show_logs=False)

    def tearDown(self):
        remove_log_file()
        remove_links(self.links)
        remove_unit_from_networkd_path(self.units)
        stop_networkd(show_logs=True)

    def check_mtu(self, mtu, ipv6_mtu=None, reset=True):
        if not ipv6_mtu:
            ipv6_mtu = mtu

        # test normal start
        start_networkd()
        self.wait_online(['dummy98:routable'])
        self.assertEqual(read_ipv6_sysctl_attr('dummy98', 'mtu'), ipv6_mtu)
        self.assertEqual(read_link_attr('dummy98', 'mtu'), mtu)

        # test normal restart
        restart_networkd()
        self.wait_online(['dummy98:routable'])
        self.assertEqual(read_ipv6_sysctl_attr('dummy98', 'mtu'), ipv6_mtu)
        self.assertEqual(read_link_attr('dummy98', 'mtu'), mtu)

        if reset:
            self.reset_check_mtu(mtu, ipv6_mtu)

    def reset_check_mtu(self, mtu, ipv6_mtu=None):
        ''' test setting mtu/ipv6_mtu with interface already up '''
        stop_networkd()

        # note - changing the device mtu resets the ipv6 mtu
        run('ip link set up mtu 1501 dev dummy98')
        run('ip link set up mtu 1500 dev dummy98')
        self.assertEqual(read_link_attr('dummy98', 'mtu'), '1500')
        self.assertEqual(read_ipv6_sysctl_attr('dummy98', 'mtu'), '1500')

        self.check_mtu(mtu, ipv6_mtu, reset=False)

    def test_mtu_network(self):
        copy_unit_to_networkd_unit_path('12-dummy.netdev', '12-dummy.network.d/mtu.conf')
        self.check_mtu('1600')

    def test_mtu_netdev(self):
        copy_unit_to_networkd_unit_path('12-dummy-mtu.netdev', '12-dummy.network', dropins=False)
        # note - MTU set by .netdev happens ONLY at device creation!
        self.check_mtu('1600', reset=False)

    def test_mtu_link(self):
        copy_unit_to_networkd_unit_path('12-dummy.netdev', '12-dummy-mtu.link', '12-dummy.network', dropins=False)
        # must reload udev because it only picks up new files after 3 second delay
        call('udevadm control --reload')
        # note - MTU set by .link happens ONLY at udev processing of device 'add' uevent!
        self.check_mtu('1600', reset=False)

    def test_ipv6_mtu(self):
        ''' set ipv6 mtu without setting device mtu '''
        copy_unit_to_networkd_unit_path('12-dummy.netdev', '12-dummy.network.d/ipv6-mtu-1400.conf')
        self.check_mtu('1500', '1400')

    def test_ipv6_mtu_toolarge(self):
        ''' try set ipv6 mtu over device mtu (it shouldn't work) '''
        copy_unit_to_networkd_unit_path('12-dummy.netdev', '12-dummy.network.d/ipv6-mtu-1550.conf')
        self.check_mtu('1500', '1500')

    def test_mtu_network_ipv6_mtu(self):
        ''' set ipv6 mtu and set device mtu via network file '''
        copy_unit_to_networkd_unit_path('12-dummy.netdev', '12-dummy.network.d/mtu.conf', '12-dummy.network.d/ipv6-mtu-1550.conf')
        self.check_mtu('1600', '1550')

    def test_mtu_netdev_ipv6_mtu(self):
        ''' set ipv6 mtu and set device mtu via netdev file '''
        copy_unit_to_networkd_unit_path('12-dummy-mtu.netdev', '12-dummy.network.d/ipv6-mtu-1550.conf')
        self.check_mtu('1600', '1550', reset=False)

    def test_mtu_link_ipv6_mtu(self):
        ''' set ipv6 mtu and set device mtu via link file '''
        copy_unit_to_networkd_unit_path('12-dummy.netdev', '12-dummy-mtu.link', '12-dummy.network.d/ipv6-mtu-1550.conf')
        # must reload udev because it only picks up new files after 3 second delay
        call('udevadm control --reload')
        self.check_mtu('1600', '1550', reset=False)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--build-dir', help='Path to build dir', dest='build_dir')
    parser.add_argument('--networkd', help='Path to systemd-networkd', dest='networkd_bin')
    parser.add_argument('--resolved', help='Path to systemd-resolved', dest='resolved_bin')
    parser.add_argument('--udevd', help='Path to systemd-udevd', dest='udevd_bin')
    parser.add_argument('--wait-online', help='Path to systemd-networkd-wait-online', dest='wait_online_bin')
    parser.add_argument('--networkctl', help='Path to networkctl', dest='networkctl_bin')
    parser.add_argument('--resolvectl', help='Path to resolvectl', dest='resolvectl_bin')
    parser.add_argument('--timedatectl', help='Path to timedatectl', dest='timedatectl_bin')
    parser.add_argument('--valgrind', help='Enable valgrind', dest='use_valgrind', type=bool, nargs='?', const=True, default=use_valgrind)
    parser.add_argument('--debug', help='Generate debugging logs', dest='enable_debug', type=bool, nargs='?', const=True, default=enable_debug)
    parser.add_argument('--asan-options', help='ASAN options', dest='asan_options')
    parser.add_argument('--lsan-options', help='LSAN options', dest='lsan_options')
    parser.add_argument('--ubsan-options', help='UBSAN options', dest='ubsan_options')
    ns, args = parser.parse_known_args(namespace=unittest)

    if ns.build_dir:
        if ns.networkd_bin or ns.resolved_bin or ns.udevd_bin or ns.wait_online_bin or ns.networkctl_bin or ns.resolvectl_bin or ns.timedatectl_bin:
            print('WARNING: --networkd, --resolved, --wait-online, --networkctl, --resolvectl, or --timedatectl options are ignored when --build-dir is specified.')
        networkd_bin = os.path.join(ns.build_dir, 'systemd-networkd')
        resolved_bin = os.path.join(ns.build_dir, 'systemd-resolved')
        udevd_bin = os.path.join(ns.build_dir, 'systemd-udevd')
        wait_online_bin = os.path.join(ns.build_dir, 'systemd-networkd-wait-online')
        networkctl_bin = os.path.join(ns.build_dir, 'networkctl')
        resolvectl_bin = os.path.join(ns.build_dir, 'resolvectl')
        timedatectl_bin = os.path.join(ns.build_dir, 'timedatectl')
    else:
        if ns.networkd_bin:
            networkd_bin = ns.networkd_bin
        if ns.resolved_bin:
            resolved_bin = ns.resolved_bin
        if ns.udevd_bin:
            udevd_bin = ns.udevd_bin
        if ns.wait_online_bin:
            wait_online_bin = ns.wait_online_bin
        if ns.networkctl_bin:
            networkctl_bin = ns.networkctl_bin
        if ns.resolvectl_bin:
            resolvectl_bin = ns.resolvectl_bin
        if ns.timedatectl_bin:
            timedatectl_bin = ns.timedatectl_bin

    use_valgrind = ns.use_valgrind
    enable_debug = ns.enable_debug
    asan_options = ns.asan_options
    lsan_options = ns.lsan_options
    ubsan_options = ns.ubsan_options

    if use_valgrind:
        networkctl_cmd = ['valgrind', '--track-origins=yes', '--leak-check=full', '--show-leak-kinds=all', networkctl_bin]
        resolvectl_cmd = ['valgrind', '--track-origins=yes', '--leak-check=full', '--show-leak-kinds=all', resolvectl_bin]
        timedatectl_cmd = ['valgrind', '--track-origins=yes', '--leak-check=full', '--show-leak-kinds=all', timedatectl_bin]
        wait_online_cmd = ['valgrind', '--track-origins=yes', '--leak-check=full', '--show-leak-kinds=all', wait_online_bin]
    else:
        networkctl_cmd = [networkctl_bin]
        resolvectl_cmd = [resolvectl_bin]
        timedatectl_cmd = [timedatectl_bin]
        wait_online_cmd = [wait_online_bin]

    if enable_debug:
        env.update({ 'SYSTEMD_LOG_LEVEL' : 'debug' })
    if asan_options:
        env.update({ 'ASAN_OPTIONS' : asan_options })
    if lsan_options:
        env.update({ 'LSAN_OPTIONS' : lsan_options })
    if ubsan_options:
        env.update({ 'UBSAN_OPTIONS' : ubsan_options })

    sys.argv[1:] = args
    unittest.main(testRunner=unittest.TextTestRunner(stream=sys.stdout,
                                                     verbosity=3))
