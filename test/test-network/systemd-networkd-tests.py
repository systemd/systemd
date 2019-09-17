#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1+
# systemd-networkd tests

import argparse
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
networkd_ci_path='/run/networkd-ci'
network_sysctl_ipv6_path='/proc/sys/net/ipv6/conf'
network_sysctl_ipv4_path='/proc/sys/net/ipv4/conf'

dnsmasq_pid_file='/run/networkd-ci/test-test-dnsmasq.pid'
dnsmasq_log_file='/run/networkd-ci/test-dnsmasq-log-file'

networkd_bin='/usr/lib/systemd/systemd-networkd'
resolved_bin='/usr/lib/systemd/systemd-resolved'
wait_online_bin='/usr/lib/systemd/systemd-networkd-wait-online'
networkctl_bin='/usr/bin/networkctl'
resolvectl_bin='/usr/bin/resolvectl'
timedatectl_bin='/usr/bin/timedatectl'
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
    return module_re.search(lsmod_output) or not call('modprobe', module_name)

def expectedFailureIfModuleIsNotAvailable(module_name):
    def f(func):
        if not is_module_available(module_name):
            return unittest.expectedFailure(func)
        return func

    return f

def expectedFailureIfERSPANModuleIsNotAvailable():
    def f(func):
        rc = call('ip link add dev erspan99 type erspan seq key 30 local 192.168.1.4 remote 192.168.1.1 erspan_ver 1 erspan 123')
        if rc == 0:
            call('ip link del erspan99')
            return func
        else:
            return unittest.expectedFailure(func)

    return f

def expectedFailureIfRoutingPolicyPortRangeIsNotAvailable():
    def f(func):
        rc = call('ip rule add from 192.168.100.19 sport 1123-1150 dport 3224-3290 table 7')
        if rc == 0:
            call('ip rule del from 192.168.100.19 sport 1123-1150 dport 3224-3290 table 7')
            return func
        else:
            return unittest.expectedFailure(func)

    return f

def expectedFailureIfRoutingPolicyIPProtoIsNotAvailable():
    def f(func):
        rc = call('ip rule add not from 192.168.100.19 ipproto tcp table 7')
        if rc == 0:
            call('ip rule del not from 192.168.100.19 ipproto tcp table 7')
            return func
        else:
            return unittest.expectedFailure(func)

    return f

def expectedFailureIfLinkFileFieldIsNotSet():
    def f(func):
        support = False
        rc = call('ip link add name dummy99 type dummy')
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

def setUpModule():
    global running_units

    os.makedirs(network_unit_file_path, exist_ok=True)
    os.makedirs(networkd_ci_path, exist_ok=True)

    shutil.rmtree(networkd_ci_path)
    copytree(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'conf'), networkd_ci_path)

    for u in ['systemd-networkd.socket', 'systemd-networkd.service', 'systemd-resolved.service', 'firewalld.service']:
        if call(f'systemctl is-active --quiet {u}') == 0:
            check_output(f'systemctl stop {u}')
            running_units.append(u)

    drop_in = [
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

    check_output('systemctl daemon-reload')
    print(check_output('systemctl cat systemd-networkd.service'))
    print(check_output('systemctl cat systemd-resolved.service'))
    check_output('systemctl restart systemd-resolved')

def tearDownModule():
    global running_units

    shutil.rmtree(networkd_ci_path)

    for u in ['systemd-networkd.service', 'systemd-resolved.service']:
        check_output(f'systemctl stop {u}')

    shutil.rmtree('/run/systemd/system/systemd-networkd.service.d')
    shutil.rmtree('/run/systemd/system/systemd-resolved.service.d')
    check_output('systemctl daemon-reload')

    for u in running_units:
        check_output(f'systemctl start {u}')

def read_link_attr(link, dev, attribute):
    with open(os.path.join(os.path.join(os.path.join('/sys/class/net/', link), dev), attribute)) as f:
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

def remove_routes(routes):
    for route_type, addr in routes:
        call('ip route del', route_type, addr, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

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

def copy_unit_to_networkd_unit_path(*units):
    print()
    for unit in units:
        shutil.copy(os.path.join(networkd_ci_path, unit), network_unit_file_path)
        if (os.path.exists(os.path.join(networkd_ci_path, unit + '.d'))):
            copytree(os.path.join(networkd_ci_path, unit + '.d'), os.path.join(network_unit_file_path, unit + '.d'))

def remove_unit_from_networkd_path(units):
    for unit in units:
        if (os.path.exists(os.path.join(network_unit_file_path, unit))):
            os.remove(os.path.join(network_unit_file_path, unit))
            if (os.path.exists(os.path.join(network_unit_file_path, unit + '.d'))):
                shutil.rmtree(os.path.join(network_unit_file_path, unit + '.d'))

def start_dnsmasq(additional_options='', ipv4_range='192.168.5.10,192.168.5.200', ipv6_range='2600::10,2600::20', lease_time='1h'):
    dnsmasq_command = f'dnsmasq -8 /var/run/networkd-ci/test-dnsmasq-log-file --log-queries=extra --log-dhcp --pid-file=/var/run/networkd-ci/test-test-dnsmasq.pid --conf-file=/dev/null --interface=veth-peer --enable-ra --dhcp-range={ipv6_range},{lease_time} --dhcp-range={ipv4_range},{lease_time} -R --dhcp-leasefile=/var/run/networkd-ci/lease --dhcp-option=26,1492 --dhcp-option=option:router,192.168.5.1 --dhcp-option=33,192.168.5.4,192.168.5.5 --port=0 ' + additional_options
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
    check_output('systemctl stop systemd-networkd')
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

def get_operstate(link, show_status=True, setup_state='configured'):
    output = check_output(*networkctl_cmd, 'status', link, env=env)
    if show_status:
        print(output)
    for line in output.splitlines():
        if 'State:' in line and (not setup_state or setup_state in line):
            return line.split()[1]
    return None

class Utilities():
    def check_link_exists(self, link):
        self.assertTrue(link_exists(link))

    def check_operstate(self, link, expected, show_status=True, setup_state='configured'):
        self.assertRegex(get_operstate(link, show_status, setup_state), expected)

    def wait_online(self, links_with_operstate, timeout='20s', bool_any=False, setup_state='configured'):
        args = wait_online_cmd + [f'--timeout={timeout}'] + [f'--interface={link}' for link in links_with_operstate]
        if bool_any:
            args += ['--any']
        try:
            check_output(*args, env=env)
        except subprocess.CalledProcessError:
            for link in links_with_operstate:
                output = check_output(*networkctl_cmd, 'status', link.split(':')[0], env=env)
                print(output)
            raise
        if not bool_any:
            for link in links_with_operstate:
                output = check_output(*networkctl_cmd, 'status', link.split(':')[0])
                print(output)
                for line in output.splitlines():
                    if 'State:' in line:
                        self.assertRegex(line, setup_state)

    def wait_address(self, link, address_regex, scope='global', ipv='', timeout_sec=100):
        for i in range(timeout_sec):
            if i > 0:
                time.sleep(1)
            output = check_output(f'ip {ipv} address show dev {link} scope {scope}')
            if re.search(address_regex, output):
                break
        else:
            self.assertRegex(output, address_regex)

class NetworkctlTests(unittest.TestCase, Utilities):

    links = [
        'test1',
        'veth99',
    ]

    units = [
        '11-dummy.netdev',
        '11-dummy-mtu.netdev',
        '11-dummy.network',
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

        output = check_output(*networkctl_cmd, 'status', 'te*', env=env)
        self.assertNotRegex(output, '1: lo ')
        self.assertRegex(output, 'test1')

        output = check_output(*networkctl_cmd, 'status', 'tes[a-z][0-9]', env=env)
        self.assertNotRegex(output, '1: lo ')
        self.assertRegex(output, 'test1')

    def test_mtu(self):
        copy_unit_to_networkd_unit_path('11-dummy-mtu.netdev', '11-dummy.network')
        start_networkd()

        self.wait_online(['test1:degraded'])

        output = check_output(*networkctl_cmd, 'status', 'test1', env=env)
        self.assertRegex(output, 'MTU: 1600')

    def test_type(self):
        copy_unit_to_networkd_unit_path('11-dummy.netdev', '11-dummy.network')
        start_networkd()
        self.wait_online(['test1:degraded'])

        output = check_output(*networkctl_cmd, 'status', 'test1')
        print(output)
        self.assertRegex(output, 'Type: ether')

        output = check_output(*networkctl_cmd, 'status', 'lo')
        print(output)
        self.assertRegex(output, 'Type: loopback')

    @expectedFailureIfLinkFileFieldIsNotSet()
    def test_udev_link_file(self):
        copy_unit_to_networkd_unit_path('11-dummy.netdev', '11-dummy.network')
        start_networkd()
        self.wait_online(['test1:degraded'])

        output = check_output(*networkctl_cmd, 'status', 'test1')
        print(output)
        self.assertRegex(output, r'Link File: (?:/usr)/lib/systemd/network/99-default.link')
        self.assertRegex(output, r'Network File: /run/systemd/network/11-dummy.network')

        output = check_output(*networkctl_cmd, 'status', 'lo')
        print(output)
        self.assertRegex(output, r'Link File: (?:/usr)/lib/systemd/network/99-default.link')
        self.assertRegex(output, r'Network File: n/a')

    def test_delete_links(self):
        copy_unit_to_networkd_unit_path('11-dummy.netdev', '11-dummy.network',
                                        '25-veth.netdev', 'netdev-link-local-addressing-yes.network')
        start_networkd()

        self.wait_online(['test1:degraded', 'veth99:degraded', 'veth-peer:degraded'])

        check_output(*networkctl_cmd, 'delete', 'test1', 'veth99')
        self.assertFalse(link_exists('test1'))
        self.assertFalse(link_exists('veth99'))
        self.assertFalse(link_exists('veth-peer'))

class NetworkdNetDevTests(unittest.TestCase, Utilities):

    links_remove_earlier = [
        'xfrm99',
    ]

    links = [
        '6rdtun99',
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
        'vxlan99',
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
        '25-vxlan.netdev',
        '25-wireguard-23-peers.netdev',
        '25-wireguard-23-peers.network',
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

        output = check_output('networkctl status dummy98')
        print(output)
        self.assertRegex(output, 'Network File: /run/systemd/network/14-match-udev-property')

    def test_wait_online_any(self):
        copy_unit_to_networkd_unit_path('25-bridge.netdev', '25-bridge.network', '11-dummy.netdev', '11-dummy.network')
        start_networkd()

        self.wait_online(['bridge99', 'test1:degraded'], bool_any=True)

        self.check_operstate('bridge99', '(?:off|no-carrier)', setup_state='configuring')
        self.check_operstate('test1', 'degraded')

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

        output = check_output(*networkctl_cmd, 'status', 'bridge99')
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
        self.assertRegex(output, 'tun (?:type tun pi on vnet_hdr on multi_queue|addrgenmode) ')

    def test_tap(self):
        copy_unit_to_networkd_unit_path('25-tap.netdev')
        start_networkd()

        self.wait_online(['tap99:off'], setup_state='unmanaged')

        output = check_output('ip -d link show tap99')
        print(output)
        # Old ip command does not support IFF_ flags
        self.assertRegex(output, 'tun (?:type tap pi on vnet_hdr on multi_queue|addrgenmode) ')

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
                                        '25-wireguard-preshared-key.txt', '25-wireguard-private-key.txt')
        start_networkd()
        self.wait_online(['wg99:carrier', 'wg98:routable'])

        if shutil.which('wg'):
            call('wg')

            output = check_output('wg show wg99 listen-port')
            self.assertRegex(output, '51820')
            output = check_output('wg show wg99 fwmark')
            self.assertRegex(output, '0x4d2')
            output = check_output('wg show wg99 allowed-ips')
            self.assertRegex(output, r'RDf\+LSpeEre7YEIKaxg\+wbpsNV7du\+ktR99uBEtIiCA=\t192.168.26.0/24 fd31:bf08:57cb::/48')
            self.assertRegex(output, r'lsDtM3AbjxNlauRKzHEPfgS1Zp7cp/VX5Use/P4PQSc=\tfdbc:bae2:7871:e1fe:793:8636::/96 fdbc:bae2:7871:500:e1fe:793:8636:dad1/128')
            output = check_output('wg show wg99 persistent-keepalive')
            self.assertRegex(output, r'RDf\+LSpeEre7YEIKaxg\+wbpsNV7du\+ktR99uBEtIiCA=\t20')
            output = check_output('wg show wg99 endpoints')
            self.assertRegex(output, r'RDf\+LSpeEre7YEIKaxg\+wbpsNV7du\+ktR99uBEtIiCA=\t192.168.27.3:51820')
            output = check_output('wg show wg99 private-key')
            self.assertRegex(output, r'EEGlnEPYJV//kbvvIqxKkQwOiS\+UENyPncC4bF46ong=')
            output = check_output('wg show wg99 preshared-keys')
            self.assertRegex(output, r'RDf\+LSpeEre7YEIKaxg\+wbpsNV7du\+ktR99uBEtIiCA=	IIWIV17wutHv7t4cR6pOT91z6NSz/T8Arh0yaywhw3M=')
            self.assertRegex(output, r'lsDtM3AbjxNlauRKzHEPfgS1Zp7cp/VX5Use/P4PQSc=	cPLOy1YUrEI0EMMIycPJmOo0aTu3RZnw8bL5meVD6m0=')

            output = check_output('wg show wg98 private-key')
            self.assertRegex(output, r'CJQUtcS9emY2fLYqDlpSZiE/QJyHkPWr\+WHtZLZ90FU=')

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
        self.assertRegex(output, 'ipip (?:ipip |)remote 192.169.224.239 local 192.168.223.238 dev dummy98')
        output = check_output('ip -d link show ipiptun98')
        print(output)
        self.assertRegex(output, 'ipip (?:ipip |)remote 192.169.224.239 local any dev dummy98')
        output = check_output('ip -d link show ipiptun97')
        print(output)
        self.assertRegex(output, 'ipip (?:ipip |)remote any local 192.168.223.238 dev dummy98')
        output = check_output('ip -d link show ipiptun96')
        print(output)
        self.assertRegex(output, 'ipip (?:ipip |)remote any local any dev dummy98')

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
        self.assertRegex(output, 'vti6 remote 2001:473:fece:cafe::5179 local (?:any|::) dev dummy98')
        output = check_output('ip -d link show vti6tun97')
        print(output)
        self.assertRegex(output, 'vti6 remote (?:any|::) local 2a00:ffde:4567:edde::4987 dev dummy98')

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
        self.assertRegex(output, 'ip6tnl ip6ip6 remote 2001:473:fece:cafe::5179 local (?:any|::) dev dummy98')
        output = check_output('ip -d link show ip6tnl97')
        print(output)
        self.assertRegex(output, 'ip6tnl ip6ip6 remote (?:any|::) local 2a00:ffde:4567:edde::4987 dev dummy98')

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
        self.assertRegex(output, "sit (?:ip6ip |)remote 10.65.223.239 local 10.65.223.238 dev dummy98")
        output = check_output('ip -d link show sittun98')
        print(output)
        self.assertRegex(output, "sit (?:ip6ip |)remote 10.65.223.239 local any dev dummy98")
        output = check_output('ip -d link show sittun97')
        print(output)
        self.assertRegex(output, "sit (?:ip6ip |)remote any local 10.65.223.238 dev dummy98")
        output = check_output('ip -d link show sittun96')
        print(output)
        self.assertRegex(output, "sit (?:ip6ip |)remote any local any dev dummy98")

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
                                        '11-dummy.netdev', 'vxlan-test1.network')
        start_networkd()

        self.wait_online(['test1:degraded', 'vxlan99:degraded'])

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
        self.assertRegex(output, '00:11:22:33:44:77 dst 10.0.0.7 self permanent')

        output = check_output(*networkctl_cmd, 'status', 'vxlan99')
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
        'test1'
    ]

    units = [
        '11-dummy.netdev',
        '12-dummy.netdev',
        '23-active-slave.network',
        '24-keep-configuration-static.network',
        '24-search-domain.network',
        '25-address-link-section.network',
        '25-address-preferred-lifetime-zero.network',
        '25-address-static.network',
        '25-bind-carrier.network',
        '25-bond-active-backup-slave.netdev',
        '25-fibrule-invert.network',
        '25-fibrule-port-range.network',
        '25-gre-tunnel-remote-any.netdev',
        '25-ip6gre-tunnel-remote-any.netdev',
        '25-ipv6-address-label-section.network',
        '25-neighbor-section.network',
        '25-neighbor-next.network',
        '25-neighbor-ipv6.network',
        '25-neighbor-ip-dummy.network',
        '25-neighbor-ip.network',
        '25-link-local-addressing-no.network',
        '25-link-local-addressing-yes.network',
        '25-link-section-unmanaged.network',
        '25-route-ipv6-src.network',
        '25-route-static.network',
        '25-gateway-static.network',
        '25-gateway-next-static.network',
        '25-sysctl-disable-ipv6.network',
        '25-sysctl.network',
        '26-link-local-addressing-ipv6.network',
        'configure-without-carrier.network',
        'routing-policy-rule-dummy98.network',
        'routing-policy-rule-test1.network']

    routing_policy_rule_tables = ['7', '8', '9']
    routes = [['blackhole', '202.54.1.2'], ['unreachable', '202.54.1.3'], ['prohibit', '202.54.1.4']]

    def setUp(self):
        remove_routing_policy_rule_tables(self.routing_policy_rule_tables)
        remove_routes(self.routes)
        remove_links(self.links)
        stop_networkd(show_logs=False)

    def tearDown(self):
        remove_routing_policy_rule_tables(self.routing_policy_rule_tables)
        remove_routes(self.routes)
        remove_links(self.links)
        remove_unit_from_networkd_path(self.units)
        stop_networkd(show_logs=True)

    def test_address_static(self):
        copy_unit_to_networkd_unit_path('25-address-static.network', '12-dummy.netdev')
        start_networkd()

        self.wait_online(['dummy98:routable'])

        output = check_output('ip -4 address show dev dummy98')
        print(output)
        self.assertRegex(output, 'inet 10.1.2.3/16 brd 10.1.255.255 scope global dummy98')
        self.assertRegex(output, 'inet 10.1.2.4/16 brd 10.1.255.255 scope global secondary dummy98')
        self.assertRegex(output, 'inet 10.2.2.4/16 brd 10.2.255.255 scope global dummy98')

        # invalid sections
        self.assertNotRegex(output, '10.10.0.1/16')
        self.assertNotRegex(output, '10.10.0.2/16')

        output = check_output('ip -4 address show dev dummy98 label 32')
        self.assertRegex(output, 'inet 10.3.2.3/16 brd 10.3.255.255 scope global 32')

        output = check_output('ip -4 address show dev dummy98 label 33')
        self.assertRegex(output, 'inet 10.4.2.3 peer 10.4.2.4/16 scope global 33')

        output = check_output('ip -4 address show dev dummy98 label 34')
        self.assertRegex(output, 'inet 192.168.[0-9]*.1/24 brd 192.168.[0-9]*.255 scope global 34')

        output = check_output('ip -4 address show dev dummy98 label 35')
        self.assertRegex(output, 'inet 172.[0-9]*.0.1/16 brd 172.[0-9]*.255.255 scope global 35')

        output = check_output('ip -6 address show dev dummy98')
        print(output)
        self.assertRegex(output, 'inet6 2001:db8:0:f101::15/64 scope global')
        self.assertRegex(output, 'inet6 2001:db8:0:f101::16/64 scope global')
        self.assertRegex(output, 'inet6 2001:db8:0:f102::15/64 scope global')
        self.assertRegex(output, 'inet6 2001:db8:0:f102::16/64 scope global')
        self.assertRegex(output, 'inet6 2001:db8:0:f103::20 peer 2001:db8:0:f103::10/128 scope global')
        self.assertRegex(output, 'inet6 fd[0-9a-f:]*1/64 scope global')

    def test_address_preferred_lifetime_zero_ipv6(self):
        copy_unit_to_networkd_unit_path('25-address-preferred-lifetime-zero.network', '12-dummy.netdev')
        start_networkd(5)

        self.wait_online(['dummy98:routable'])

        output = check_output('ip address show dummy98')
        print(output)
        self.assertRegex(output, 'inet 10.2.3.4/16 brd 10.2.255.255 scope link deprecated dummy98')
        self.assertRegex(output, 'inet6 2001:db8:0:f101::1/64 scope global')

        output = check_output('ip route show dev dummy98')
        print(output)
        self.assertRegex(output, 'default via 20.20.20.1 proto static')

    def test_configure_without_carrier(self):
        copy_unit_to_networkd_unit_path('configure-without-carrier.network', '11-dummy.netdev')
        start_networkd()
        self.wait_online(['test1:routable'])

        output = check_output(*networkctl_cmd, 'status', 'test1')
        print(output)
        self.assertRegex(output, '192.168.0.15')
        self.assertRegex(output, '192.168.0.1')
        self.assertRegex(output, 'routable')

    def test_routing_policy_rule(self):
        copy_unit_to_networkd_unit_path('routing-policy-rule-test1.network', '11-dummy.netdev')
        start_networkd()
        self.wait_online(['test1:degraded'])

        output = check_output('ip rule list iif test1 priority 111')
        print(output)
        self.assertRegex(output, '111:')
        self.assertRegex(output, 'from 192.168.100.18')
        self.assertRegex(output, r'tos (?:0x08|throughput)\s')
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

        output = check_output('ip -6 rule list iif test1 priority 101')
        print(output)
        self.assertRegex(output, '101:')
        self.assertRegex(output, 'from all')
        self.assertRegex(output, 'iif test1')
        self.assertRegex(output, 'lookup 9')

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
            self.assertRegex(output, '111:	from 192.168.100.18 tos (?:0x08|throughput) iif test1 oif test1 lookup 7')

            output = check_output('ip rule list table 8')
            print(output)
            self.assertRegex(output, '112:	from 192.168.101.18 tos (?:0x08|throughput) iif dummy98 oif dummy98 lookup 8')

            stop_networkd(remove_state_files=False)

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

    def test_route_static(self):
        copy_unit_to_networkd_unit_path('25-route-static.network', '12-dummy.netdev')
        start_networkd()
        self.wait_online(['dummy98:routable'])

        output = check_output(*networkctl_cmd, 'status', 'dummy98', env=env)
        print(output)

        print('### ip -6 route show dev dummy98')
        output = check_output('ip -6 route show dev dummy98')
        print(output)
        self.assertRegex(output, '2001:1234:5:8fff:ff:ff:ff:ff proto static')
        self.assertRegex(output, '2001:1234:5:8f63::1 proto kernel')

        print('### ip -6 route show dev dummy98 default')
        output = check_output('ip -6 route show dev dummy98 default')
        print(output)
        self.assertRegex(output, 'default via 2001:1234:5:8fff:ff:ff:ff:ff proto static metric 1024 pref medium')

        print('### ip -4 route show dev dummy98')
        output = check_output('ip -4 route show dev dummy98')
        print(output)
        self.assertRegex(output, '149.10.124.48/28 proto kernel scope link src 149.10.124.58')
        self.assertRegex(output, '149.10.124.64 proto static scope link')
        self.assertRegex(output, '169.254.0.0/16 proto static scope link metric 2048')
        self.assertRegex(output, '192.168.1.1 proto static initcwnd 20')
        self.assertRegex(output, '192.168.1.2 proto static initrwnd 30')
        self.assertRegex(output, 'multicast 149.10.123.4 proto static')

        print('### ip -4 route show dev dummy98 default')
        output = check_output('ip -4 route show dev dummy98 default')
        print(output)
        self.assertRegex(output, 'default via 149.10.125.65 proto static onlink')
        self.assertRegex(output, 'default via 149.10.124.64 proto static')
        self.assertRegex(output, 'default proto static')

        print('### ip -4 route show table local dev dummy98')
        output = check_output('ip -4 route show table local dev dummy98')
        print(output)
        self.assertRegex(output, 'local 149.10.123.1 proto static scope host')
        self.assertRegex(output, 'anycast 149.10.123.2 proto static scope link')
        self.assertRegex(output, 'broadcast 149.10.123.3 proto static scope link')

        print('### ip route show type blackhole')
        output = check_output('ip route show type blackhole')
        print(output)
        self.assertRegex(output, 'blackhole 202.54.1.2 proto static')

        print('### ip route show type unreachable')
        output = check_output('ip route show type unreachable')
        print(output)
        self.assertRegex(output, 'unreachable 202.54.1.3 proto static')

        print('### ip route show type prohibit')
        output = check_output('ip route show type prohibit')
        print(output)
        self.assertRegex(output, 'prohibit 202.54.1.4 proto static')

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

        self.check_operstate('dummy98', 'off', setup_state='unmanaged')

    def test_ipv6_address_label(self):
        copy_unit_to_networkd_unit_path('25-ipv6-address-label-section.network', '12-dummy.netdev')
        start_networkd()
        self.wait_online(['dummy98:degraded'])

        output = check_output('ip addrlabel list')
        print(output)
        self.assertRegex(output, '2004:da8:1::/64')

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

        test1_addr_gen_mode = ''
        if os.path.exists(os.path.join(os.path.join(network_sysctl_ipv6_path, 'test1'), 'stable_secret')):
            with open(os.path.join(os.path.join(network_sysctl_ipv6_path, 'test1'), 'stable_secret')) as f:
                try:
                    f.readline()
                except IOError:
                    # if stable_secret is unset, then EIO is returned
                    test1_addr_gen_mode = '0'
                else:
                    test1_addr_gen_mode = '2'
        else:
            test1_addr_gen_mode = '0'

        if os.path.exists(os.path.join(os.path.join(network_sysctl_ipv6_path, 'test1'), 'addr_gen_mode')):
            self.assertEqual(read_ipv6_sysctl_attr('test1', 'addr_gen_mode'), test1_addr_gen_mode)

        if os.path.exists(os.path.join(os.path.join(network_sysctl_ipv6_path, 'dummy98'), 'addr_gen_mode')):
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
        self.assertEqual(output, '10.2.0.0/16 proto kernel scope link src 10.2.3.4')
        output = check_output('ip -6 route show dev dummy98')
        print(output)
        self.assertRegex(output, 'default via 2607:5300:203:39ff:ff:ff:ff:ff proto static')

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
        self.assertEqual(output, '10.2.0.0/16 proto kernel scope link src 10.2.3.4')
        output = check_output('ip -6 route show dev dummy98')
        print(output)
        self.assertRegex(output, 'default via 2607:5300:203:39ff:ff:ff:ff:ff proto static')

    def test_bind_carrier(self):
        copy_unit_to_networkd_unit_path('25-bind-carrier.network', '11-dummy.netdev')
        start_networkd()
        self.wait_online(['test1:routable'])

        check_output('ip link add dummy98 type dummy')
        check_output('ip link set dummy98 up')
        time.sleep(2)
        output = check_output('ip address show test1')
        print(output)
        self.assertRegex(output, 'UP,LOWER_UP')
        self.assertRegex(output, 'inet 192.168.10.30/24 brd 192.168.10.255 scope global test1')
        self.check_operstate('test1', 'routable')

        check_output('ip link add dummy99 type dummy')
        check_output('ip link set dummy99 up')
        time.sleep(2)
        output = check_output('ip address show test1')
        print(output)
        self.assertRegex(output, 'UP,LOWER_UP')
        self.assertRegex(output, 'inet 192.168.10.30/24 brd 192.168.10.255 scope global test1')
        self.check_operstate('test1', 'routable')

        check_output('ip link del dummy98')
        time.sleep(2)
        output = check_output('ip address show test1')
        print(output)
        self.assertRegex(output, 'UP,LOWER_UP')
        self.assertRegex(output, 'inet 192.168.10.30/24 brd 192.168.10.255 scope global test1')
        self.check_operstate('test1', 'routable')

        check_output('ip link del dummy99')
        time.sleep(2)
        output = check_output('ip address show test1')
        print(output)
        self.assertNotRegex(output, 'UP,LOWER_UP')
        self.assertRegex(output, 'DOWN')
        self.assertNotRegex(output, '192.168.10')
        self.check_operstate('test1', 'off')

        check_output('ip link add dummy98 type dummy')
        check_output('ip link set dummy98 up')
        time.sleep(2)
        output = check_output('ip address show test1')
        print(output)
        self.assertRegex(output, 'UP,LOWER_UP')
        self.assertRegex(output, 'inet 192.168.10.30/24 brd 192.168.10.255 scope global test1')
        self.check_operstate('test1', 'routable')

    def test_domain(self):
        copy_unit_to_networkd_unit_path('12-dummy.netdev', '24-search-domain.network')
        start_networkd()
        self.wait_online(['dummy98:routable'])

        output = check_output(*networkctl_cmd, 'status', 'dummy98', env=env)
        print(output)
        self.assertRegex(output, 'Address: 192.168.42.100')
        self.assertRegex(output, 'DNS: 192.168.42.1')
        self.assertRegex(output, 'Search Domains: one')

    def test_keep_configuration_static(self):
        check_output('systemctl stop systemd-networkd')

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
        time.sleep(2)

        with open(path) as f:
            data = f.read()
            self.assertRegex(data, r'ADMIN_STATE=configured')
            self.assertRegex(data, r'OPER_STATE=routable')
            self.assertRegex(data, r'REQUIRED_FOR_ONLINE=yes')
            self.assertRegex(data, r'REQUIRED_OPER_STATE_FOR_ONLINE=routable')
            self.assertRegex(data, r'NETWORK_FILE=/run/systemd/network/state-file-tests.network')
            self.assertRegex(data, r'DNS=10.10.10.10 10.10.10.11')
            self.assertRegex(data, r'NTP=0.fedora.pool.ntp.org 1.fedora.pool.ntp.org')
            self.assertRegex(data, r'DOMAINS=hogehoge')
            self.assertRegex(data, r'ROUTE_DOMAINS=foofoo')
            self.assertRegex(data, r'LLMNR=no')
            self.assertRegex(data, r'MDNS=yes')
            self.assertRegex(data, r'DNSSEC=no')
            self.assertRegex(data, r'ADDRESSES=192.168.(?:10.10|12.12)/24 192.168.(?:12.12|10.10)/24')

        check_output(*resolvectl_cmd, 'dns', 'dummy98', '10.10.10.12', '10.10.10.13', env=env)
        check_output(*resolvectl_cmd, 'domain', 'dummy98', 'hogehogehoge', '~foofoofoo', env=env)
        check_output(*resolvectl_cmd, 'llmnr', 'dummy98', 'yes', env=env)
        check_output(*resolvectl_cmd, 'mdns', 'dummy98', 'no', env=env)
        check_output(*resolvectl_cmd, 'dnssec', 'dummy98', 'yes', env=env)
        check_output(*timedatectl_cmd, 'ntp-servers', 'dummy98', '2.fedora.pool.ntp.org', '3.fedora.pool.ntp.org', env=env)
        time.sleep(2)

        with open(path) as f:
            data = f.read()
            self.assertRegex(data, r'DNS=10.10.10.12 10.10.10.13')
            self.assertRegex(data, r'NTP=2.fedora.pool.ntp.org 3.fedora.pool.ntp.org')
            self.assertRegex(data, r'DOMAINS=hogehogehoge')
            self.assertRegex(data, r'ROUTE_DOMAINS=foofoofoo')
            self.assertRegex(data, r'LLMNR=yes')
            self.assertRegex(data, r'MDNS=no')
            self.assertRegex(data, r'DNSSEC=yes')

        check_output(*timedatectl_cmd, 'revert', 'dummy98', env=env)
        time.sleep(2)

        with open(path) as f:
            data = f.read()
            self.assertRegex(data, r'DNS=10.10.10.12 10.10.10.13')
            self.assertRegex(data, r'NTP=0.fedora.pool.ntp.org 1.fedora.pool.ntp.org')
            self.assertRegex(data, r'DOMAINS=hogehogehoge')
            self.assertRegex(data, r'ROUTE_DOMAINS=foofoofoo')
            self.assertRegex(data, r'LLMNR=yes')
            self.assertRegex(data, r'MDNS=no')
            self.assertRegex(data, r'DNSSEC=yes')

        check_output(*resolvectl_cmd, 'revert', 'dummy98', env=env)
        time.sleep(2)

        with open(path) as f:
            data = f.read()
            self.assertRegex(data, r'DNS=10.10.10.10 10.10.10.11')
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

        self.check_operstate('dummy98', 'enslaved')
        self.check_operstate('test1', 'enslaved')
        self.check_operstate('bond99', 'routable')

        check_output('ip link set dummy98 down')
        time.sleep(2)

        self.check_operstate('dummy98', 'off')
        self.check_operstate('test1', 'enslaved')
        self.check_operstate('bond99', 'degraded-carrier')

        check_output('ip link set dummy98 up')
        time.sleep(2)

        self.check_operstate('dummy98', 'enslaved')
        self.check_operstate('test1', 'enslaved')
        self.check_operstate('bond99', 'routable')

        check_output('ip link set dummy98 down')
        check_output('ip link set test1 down')
        time.sleep(2)

        self.check_operstate('dummy98', 'off')
        self.check_operstate('test1', 'off')

        for trial in range(30):
            if trial > 0:
                time.sleep(1)
            output = check_output('ip address show bond99')
            print(output)
            if get_operstate('bond99') == 'no-carrier':
                break
        else:
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
        self.assertRegex(output, 'ff00::/8 table local metric 256 pref medium')

        self.assertEqual(call('ip link del test1'), 0)
        time.sleep(3)

        self.check_operstate('bridge99', 'degraded-carrier')

        check_output('ip link del dummy98')
        time.sleep(3)

        self.check_operstate('bridge99', 'no-carrier')

        output = check_output('ip address show bridge99')
        print(output)
        self.assertRegex(output, 'NO-CARRIER')
        self.assertNotRegex(output, '192.168.0.15/24')
        self.assertNotRegex(output, '192.168.0.16/24')

        print('### ip -6 route list table all dev bridge99')
        output = check_output('ip -6 route list table all dev bridge99')
        print(output)
        self.assertRegex(output, 'ff00::/8 table local metric 256 (?:linkdown |)pref medium')

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
        self.assertEqual(output, '0:	from all to 8.8.8.8 lookup 100')

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

        output = check_output(*networkctl_cmd, 'lldp', env=env)
        print(output)
        self.assertRegex(output, 'veth-peer')
        self.assertRegex(output, 'veth99')

class NetworkdRATests(unittest.TestCase, Utilities):
    links = ['veth99']

    units = [
        '25-veth.netdev',
        'ipv6-prefix.network',
        'ipv6-prefix-veth.network']

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

        output = check_output(*networkctl_cmd, 'status', 'veth99', env=env)
        print(output)
        self.assertRegex(output, '2002:da8:1:0')

class NetworkdDHCPServerTests(unittest.TestCase, Utilities):
    links = ['veth99']

    units = [
        '25-veth.netdev',
        'dhcp-client.network',
        'dhcp-client-timezone-router.network',
        'dhcp-server.network',
        'dhcp-server-timezone-router.network']

    def setUp(self):
        remove_links(self.links)
        stop_networkd(show_logs=False)

    def tearDown(self):
        remove_links(self.links)
        remove_unit_from_networkd_path(self.units)
        stop_networkd(show_logs=True)

    def test_dhcp_server(self):
        copy_unit_to_networkd_unit_path('25-veth.netdev', 'dhcp-client.network', 'dhcp-server.network')
        start_networkd()
        self.wait_online(['veth99:routable', 'veth-peer:routable'])

        output = check_output(*networkctl_cmd, 'status', 'veth99', env=env)
        print(output)
        self.assertRegex(output, '192.168.5.*')
        self.assertRegex(output, 'Gateway: 192.168.5.1')
        self.assertRegex(output, 'DNS: 192.168.5.1')
        self.assertRegex(output, 'NTP: 192.168.5.1')

    def test_emit_router_timezone(self):
        copy_unit_to_networkd_unit_path('25-veth.netdev', 'dhcp-client-timezone-router.network', 'dhcp-server-timezone-router.network')
        start_networkd()
        self.wait_online(['veth99:routable', 'veth-peer:routable'])

        output = check_output(*networkctl_cmd, 'status', 'veth99', env=env)
        print(output)
        self.assertRegex(output, 'Gateway: 192.168.5.*')
        self.assertRegex(output, '192.168.5.*')
        self.assertRegex(output, 'Europe/Berlin')

class NetworkdDHCPClientTests(unittest.TestCase, Utilities):
    links = [
        'veth99',
        'vrf99']

    units = [
        '25-veth.netdev',
        '25-vrf.netdev',
        '25-vrf.network',
        'dhcp-client-anonymize.network',
        'dhcp-client-gateway-onlink-implicit.network',
        'dhcp-client-ipv4-dhcp-settings.network',
        'dhcp-client-ipv4-only-ipv6-disabled.network',
        'dhcp-client-ipv4-only.network',
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
        'dhcp-client-use-routes-no.network',
        'dhcp-client-vrf.network',
        'dhcp-client-with-ipv4ll-fallback-with-dhcp-server.network',
        'dhcp-client-with-ipv4ll-fallback-without-dhcp-server.network',
        'dhcp-client-with-static-address.network',
        'dhcp-client.network',
        'dhcp-server-veth-peer.network',
        'dhcp-v4-server-veth-peer.network',
        'dhcp-client-use-domains.network',
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

        output = check_output(*networkctl_cmd, 'status', 'veth99', env=env)
        print(output)
        self.assertRegex(output, '2600::')
        self.assertNotRegex(output, '192.168.5')

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

        output = check_output(*networkctl_cmd, 'status', 'veth99', env=env)
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

        output = check_output(*networkctl_cmd, 'status', 'veth99', env=env)
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

    def test_dhcp_client_ipv4_ipv6(self):
        copy_unit_to_networkd_unit_path('25-veth.netdev', 'dhcp-server-veth-peer.network', 'dhcp-client-ipv6-only.network',
                                        'dhcp-client-ipv4-only.network')
        start_networkd()
        self.wait_online(['veth-peer:carrier'])
        start_dnsmasq()
        self.wait_online(['veth99:routable', 'veth-peer:routable'])

        # link become 'routable' when at least one protocol provide an valid address.
        self.wait_address('veth99', r'inet 192.168.5.[0-9]*/24 brd 192.168.5.255 scope global dynamic', ipv='-4')
        self.wait_address('veth99', r'inet6 2600::[0-9a-f]*/128 scope global (?:dynamic noprefixroute|noprefixroute dynamic)', ipv='-6')

        output = check_output(*networkctl_cmd, 'status', 'veth99', env=env)
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

        # issue #8726
        print('## ip route show table main dev veth99')
        output = check_output('ip route show table main dev veth99')
        print(output)
        self.assertNotRegex(output, 'proto dhcp')

        print('## ip route show table 211 dev veth99')
        output = check_output('ip route show table 211 dev veth99')
        print(output)
        self.assertRegex(output, 'default via 192.168.5.1 proto dhcp')
        self.assertRegex(output, '192.168.5.0/24 via 192.168.5.5 proto dhcp')
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
        self.assertRegex(output, r'inet 192.168.5.[0-9]*/24 brd 192.168.5.255 scope global secondary dynamic veth99')

        output = check_output('ip route show dev veth99')
        print(output)
        self.assertRegex(output, r'default via 192.168.5.1 proto dhcp src 192.168.5.[0-9]* metric 1024')
        self.assertRegex(output, r'192.168.5.0/24 proto kernel scope link src 192.168.5.250')
        self.assertRegex(output, r'192.168.5.0/24 via 192.168.5.5 proto dhcp src 192.168.5.[0-9]* metric 1024')
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
        self.assertRegex(output, 'metric 24')

    def test_dhcp_client_reassign_static_routes_ipv4(self):
        copy_unit_to_networkd_unit_path('25-veth.netdev', 'dhcp-server-veth-peer.network',
                                        'dhcp-client-reassign-static-routes-ipv4.network')
        start_networkd()
        self.wait_online(['veth-peer:carrier'])
        start_dnsmasq(lease_time='2m')
        self.wait_online(['veth99:routable', 'veth-peer:routable'])

        output = check_output('ip address show dev veth99 scope global')
        print(output)
        self.assertRegex(output, r'inet 192.168.5.[0-9]*/24 brd 192.168.5.255 scope global dynamic veth99')

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
        self.assertRegex(output, r'inet6 2600::[0-9a-f]*/128 scope global (?:noprefixroute dynamic|dynamic noprefixroute)')

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

        output = check_output(*networkctl_cmd, 'status', 'veth99', env=env)
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

        output = check_output(*networkctl_cmd, 'status', 'veth99', env=env)
        print(output)
        self.assertRegex(output, r'192.168.5.*')

        check_output('systemctl stop systemd-networkd')

        print('The lease address should be kept after networkd stopped')
        output = check_output('ip address show dev veth99 scope global')
        print(output)
        self.assertRegex(output, r'192.168.5.*')

        output = check_output(*networkctl_cmd, 'status', 'veth99', env=env)
        print(output)
        self.assertRegex(output, r'192.168.5.*')

        start_networkd(3)
        self.wait_online(['veth-peer:routable'])

        print('Still the lease address should be kept after networkd restarted')
        output = check_output('ip address show dev veth99 scope global')
        print(output)
        self.assertRegex(output, r'192.168.5.*')

        output = check_output(*networkctl_cmd, 'status', 'veth99', env=env)
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
        check_output('systemctl stop systemd-networkd')

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
        self.wait_address('veth99', r'inet 192.168.5.[0-9]*/24 brd 192.168.5.255 scope global dynamic', ipv='-4')
        self.wait_address('veth99', r'inet6 2600::[0-9a-f]*/128 scope global (?:dynamic noprefixroute|noprefixroute dynamic)', ipv='-6')

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
        self.wait_address('veth99', r'inet 192.168.5.[0-9]*/24 brd 192.168.5.255 scope global dynamic', ipv='-4')
        self.wait_address('veth99', r'inet6 2600::[0-9a-f]*/128 scope global (?:dynamic noprefixroute|noprefixroute dynamic)', ipv='-6')

        print('## ip -d link show dev vrf99')
        output = check_output('ip -d link show dev vrf99')
        print(output)
        self.assertRegex(output, 'vrf table 42')

        print('## ip address show vrf vrf99')
        output = check_output('ip address show vrf vrf99')
        print(output)
        self.assertRegex(output, 'inet 169.254.[0-9]*.[0-9]*/16 brd 169.254.255.255 scope link veth99')
        self.assertRegex(output, 'inet 192.168.5.[0-9]*/24 brd 192.168.5.255 scope global dynamic veth99')
        self.assertRegex(output, 'inet6 2600::[0-9a-f]*/128 scope global (?:dynamic noprefixroute|noprefixroute dynamic)')
        self.assertRegex(output, 'inet6 .* scope link')

        print('## ip address show dev veth99')
        output = check_output('ip address show dev veth99')
        print(output)
        self.assertRegex(output, 'inet 169.254.[0-9]*.[0-9]*/16 brd 169.254.255.255 scope link veth99')
        self.assertRegex(output, 'inet 192.168.5.[0-9]*/24 brd 192.168.5.255 scope global dynamic veth99')
        self.assertRegex(output, 'inet6 2600::[0-9a-f]*/128 scope global (?:dynamic noprefixroute|noprefixroute dynamic)')
        self.assertRegex(output, 'inet6 .* scope link')

        print('## ip route show vrf vrf99')
        output = check_output('ip route show vrf vrf99')
        print(output)
        self.assertRegex(output, 'default via 192.168.5.1 dev veth99 proto dhcp src 192.168.5.')
        self.assertRegex(output, '169.254.0.0/16 dev veth99 proto kernel scope link src 169.254')
        self.assertRegex(output, '192.168.5.0/24 dev veth99 proto kernel scope link src 192.168.5')
        self.assertRegex(output, '192.168.5.0/24 via 192.168.5.5 dev veth99 proto dhcp')
        self.assertRegex(output, '192.168.5.1 dev veth99 proto dhcp scope link src 192.168.5')

        print('## ip route show table main dev veth99')
        output = check_output('ip route show table main dev veth99')
        print(output)
        self.assertEqual(output, '')

    def test_dhcp_client_gateway_onlink_implicit(self):
        copy_unit_to_networkd_unit_path('25-veth.netdev', 'dhcp-server-veth-peer.network',
                                        'dhcp-client-gateway-onlink-implicit.network')
        start_networkd()
        self.wait_online(['veth-peer:carrier'])
        start_dnsmasq()
        self.wait_online(['veth99:routable', 'veth-peer:routable'])

        output = check_output(*networkctl_cmd, 'status', 'veth99', env=env)
        print(output)
        self.assertRegex(output, '192.168.5')

        output = check_output('ip route list dev veth99 10.0.0.0/8')
        print(output)
        self.assertRegex(output, 'onlink')
        output = check_output('ip route list dev veth99 192.168.100.0/24')
        print(output)
        self.assertRegex(output, 'onlink')

    def test_dhcp_client_with_ipv4ll_fallback_with_dhcp_server(self):
        copy_unit_to_networkd_unit_path('25-veth.netdev', 'dhcp-server-veth-peer.network',
                                        'dhcp-client-with-ipv4ll-fallback-with-dhcp-server.network')
        start_networkd()
        self.wait_online(['veth-peer:carrier'])
        start_dnsmasq(lease_time='2m')
        self.wait_online(['veth99:routable', 'veth-peer:routable'])

        output = check_output('ip address show dev veth99')
        print(output)

        output = check_output('ip -6 address show dev veth99 scope global dynamic')
        self.assertNotRegex(output, 'inet6 2600::[0-9a-f]*/128 scope global dynamic')
        output = check_output('ip -6 address show dev veth99 scope link')
        self.assertRegex(output, 'inet6 .* scope link')
        output = check_output('ip -4 address show dev veth99 scope global dynamic')
        self.assertRegex(output, 'inet 192.168.5.[0-9]*/24 brd 192.168.5.255 scope global dynamic veth99')
        output = check_output('ip -4 address show dev veth99 scope link')
        self.assertNotRegex(output, 'inet .* scope link')

        print('Wait for the dynamic address to be expired')
        time.sleep(130)

        output = check_output('ip address show dev veth99')
        print(output)

        output = check_output('ip -6 address show dev veth99 scope global dynamic')
        self.assertNotRegex(output, 'inet6 2600::[0-9a-f]*/128 scope global dynamic')
        output = check_output('ip -6 address show dev veth99 scope link')
        self.assertRegex(output, 'inet6 .* scope link')
        output = check_output('ip -4 address show dev veth99 scope global dynamic')
        self.assertRegex(output, 'inet 192.168.5.[0-9]*/24 brd 192.168.5.255 scope global dynamic veth99')
        output = check_output('ip -4 address show dev veth99 scope link')
        self.assertNotRegex(output, 'inet .* scope link')

        search_words_in_dnsmasq_log('DHCPOFFER', show_all=True)

    def test_dhcp_client_with_ipv4ll_fallback_without_dhcp_server(self):
        copy_unit_to_networkd_unit_path('25-veth.netdev', 'dhcp-server-veth-peer.network',
                                        'dhcp-client-with-ipv4ll-fallback-without-dhcp-server.network')
        start_networkd()
        self.wait_online(['veth99:degraded', 'veth-peer:routable'])

        output = check_output('ip address show dev veth99')
        print(output)

        output = check_output('ip -6 address show dev veth99 scope global dynamic')
        self.assertNotRegex(output, 'inet6 2600::[0-9a-f]*/128 scope global dynamic')
        output = check_output('ip -6 address show dev veth99 scope link')
        self.assertRegex(output, 'inet6 .* scope link')
        output = check_output('ip -4 address show dev veth99 scope global dynamic')
        self.assertNotRegex(output, 'inet 192.168.5.[0-9]*/24 brd 192.168.5.255 scope global dynamic veth99')
        output = check_output('ip -4 address show dev veth99 scope link')
        self.assertRegex(output, 'inet .* scope link')

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
        self.assertRegex(output, 'inet 192.168.5.1[0-9]*/24 brd 192.168.5.255 scope global dynamic veth99')
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
        self.assertRegex(output, 'inet 192.168.5.2[0-9]*/24 brd 192.168.5.255 scope global dynamic veth99')
        address2=None
        for line in output.splitlines():
            if 'brd 192.168.5.255 scope global dynamic veth99' in line:
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
        self.wait_address('veth99', r'inet 192.168.5.[0-9]*/24 brd 192.168.5.255 scope global dynamic', ipv='-4')
        self.wait_address('veth99', r'inet6 2600::[0-9a-f]*/128 scope global (?:dynamic noprefixroute|noprefixroute dynamic)', ipv='-6')

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
        self.wait_address('veth99', r'inet 192.168.5.[0-9]*/24 brd 192.168.5.255 scope global dynamic', ipv='-4')
        self.wait_address('veth99', r'inet6 2600::[0-9a-f]*/128 scope global (?:dynamic noprefixroute|noprefixroute dynamic)', ipv='-6')

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
        self.wait_address('veth99', r'inet 192.168.5.[0-9]*/24 brd 192.168.5.255 scope global dynamic', ipv='-4')
        self.wait_address('veth99', r'inet6 2600::[0-9a-f]*/128 scope global (?:dynamic noprefixroute|noprefixroute dynamic)', ipv='-6')

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
        self.wait_address('veth99', r'inet 192.168.5.[0-9]*/24 brd 192.168.5.255 scope global dynamic', ipv='-4')
        self.wait_address('veth99', r'inet6 2600::[0-9a-f]*/128 scope global (?:dynamic noprefixroute|noprefixroute dynamic)', ipv='-6')

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

        output = check_output(*networkctl_cmd, 'status', 'veth99', env=env)
        print(output)
        self.assertRegex(output, 'Search Domains: example.com')

        time.sleep(3)
        output = check_output(*resolvectl_cmd, 'domain', 'veth99', env=env)
        print(output)
        self.assertRegex(output, 'example.com')

class NetworkdIPv6PrefixTests(unittest.TestCase, Utilities):
    links = ['veth99']

    units = [
        '25-veth.netdev',
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
        self.wait_online(['veth-peer:carrier'])
        start_dnsmasq()
        self.wait_online(['veth99:routable', 'veth-peer:routable'])

        output = check_output('ip', '-6', 'route', 'show', 'dev', 'veth-peer')
        print(output)
        self.assertRegex(output, '2001:db8:0:1::/64 proto ra')

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--build-dir', help='Path to build dir', dest='build_dir')
    parser.add_argument('--networkd', help='Path to systemd-networkd', dest='networkd_bin')
    parser.add_argument('--resolved', help='Path to systemd-resolved', dest='resolved_bin')
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
        if ns.networkd_bin or ns.resolved_bin or ns.wait_online_bin or ns.networkctl_bin or ns.resolvectl_bin or ns.timedatectl_bin:
            print('WARNING: --networkd, --resolved, --wait-online, --networkctl, --resolvectl, or --timedatectl options are ignored when --build-dir is specified.')
        networkd_bin = os.path.join(ns.build_dir, 'systemd-networkd')
        resolved_bin = os.path.join(ns.build_dir, 'systemd-resolved')
        wait_online_bin = os.path.join(ns.build_dir, 'systemd-networkd-wait-online')
        networkctl_bin = os.path.join(ns.build_dir, 'networkctl')
        resolvectl_bin = os.path.join(ns.build_dir, 'resolvectl')
        timedatectl_bin = os.path.join(ns.build_dir, 'timedatectl')
    else:
        if ns.networkd_bin:
            networkd_bin = ns.networkd_bin
        if ns.resolved_bin:
            resolved_bin = ns.resolved_bin
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
