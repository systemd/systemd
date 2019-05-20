#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1+
# systemd-networkd tests

import os
import re
import shutil
import signal
import socket
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

wait_online_bin='/usr/lib/systemd/systemd-networkd-wait-online'

def is_module_available(module_name):
    lsmod_output = subprocess.check_output('lsmod', universal_newlines=True)
    module_re = re.compile(r'^{0}\b'.format(re.escape(module_name)), re.MULTILINE)
    return module_re.search(lsmod_output) or not subprocess.call(["modprobe", module_name])

def expectedFailureIfModuleIsNotAvailable(module_name):
    def f(func):
        if not is_module_available(module_name):
            return unittest.expectedFailure(func)
        return func

    return f

def expectedFailureIfERSPANModuleIsNotAvailable():
    def f(func):
        rc = subprocess.call(['ip', 'link', 'add', 'dev', 'erspan99', 'type', 'erspan', 'seq', 'key', '30', 'local', '192.168.1.4', 'remote', '192.168.1.1', 'erspan_ver', '1', 'erspan', '123'])
        if rc == 0:
            subprocess.call(['ip', 'link', 'del', 'erspan99'])
            return func
        else:
            return unittest.expectedFailure(func)

    return f

def expectedFailureIfRoutingPolicyPortRangeIsNotAvailable():
    def f(func):
        rc = subprocess.call(['ip', 'rule', 'add', 'from', '192.168.100.19', 'sport', '1123-1150', 'dport', '3224-3290', 'table', '7'])
        if rc == 0:
            subprocess.call(['ip', 'rule', 'del', 'from', '192.168.100.19', 'sport', '1123-1150', 'dport', '3224-3290', 'table', '7'])
            return func
        else:
            return unittest.expectedFailure(func)

    return f

def expectedFailureIfRoutingPolicyIPProtoIsNotAvailable():
    def f(func):
        rc = subprocess.call(['ip', 'rule', 'add', 'not', 'from', '192.168.100.19', 'ipproto', 'tcp', 'table', '7'])
        if rc == 0:
            subprocess.call(['ip', 'rule', 'del', 'not', 'from', '192.168.100.19', 'ipproto', 'tcp', 'table', '7'])
            return func
        else:
            return unittest.expectedFailure(func)

    return f

def expectedFailureIf_ip6gre_do_not_support_ipv6ll():
    def f(func):
        success = False
        rc = subprocess.call(['ip', 'link', 'add', 'name', 'test1', 'type', 'dummy'])
        if rc == 0:
            time.sleep(1)
            rc = subprocess.call(['ip', 'tunnel', 'add', 'tun99', 'local', '2a00:ffde:4567:edde::4986', 'remote', '2001:473:fece:cafe::5178', 'mode', 'ip6gre', 'dev', 'test1'])
            if rc == 0:
                time.sleep(1)
                # Not sure why, but '0' or '2' do not work.
                subprocess.call(['sysctl', '-w', 'net.ipv6.conf.tun99.addr_gen_mode=3'])

                output = subprocess.check_output(['ip', '-6', 'address', 'show', 'dev', 'tun99', 'scope', 'link'], universal_newlines=True).rstrip()
                print(output)
                success = 'inet6' in output

                subprocess.run(['ip', 'tunnel', 'del', 'tun99'])

            subprocess.run(['ip', 'link', 'del', 'test1'])

        if success:
            return func
        else:
            return unittest.expectedFailure(func)

    return f

def setUpModule():
    os.makedirs(network_unit_file_path, exist_ok=True)
    os.makedirs(networkd_ci_path, exist_ok=True)

    shutil.rmtree(networkd_ci_path)
    copytree(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'conf'), networkd_ci_path)

    subprocess.check_call('systemctl stop systemd-networkd.socket', shell=True)

def tearDownModule():
    shutil.rmtree(networkd_ci_path)

    subprocess.check_call('systemctl stop systemd-networkd.service', shell=True)
    subprocess.check_call('systemctl start systemd-networkd.socket', shell=True)
    subprocess.check_call('systemctl start systemd-networkd.service', shell=True)

class Utilities():
    def read_link_attr(self, link, dev, attribute):
        with open(os.path.join(os.path.join(os.path.join('/sys/class/net/', link), dev), attribute)) as f:
            return f.readline().strip()

    def read_bridge_port_attr(self, bridge, link, attribute):

        path_bridge = os.path.join('/sys/devices/virtual/net', bridge)
        path_port = 'lower_' + link + '/brport'
        path = os.path.join(path_bridge, path_port)

        with open(os.path.join(path, attribute)) as f:
            return f.readline().strip()

    def link_exists(self, link):
        return os.path.exists(os.path.join('/sys/class/net', link))

    def check_link_exists(self, link):
        self.assertTrue(self.link_exists(link))

    def link_remove(self, links):
        for link in links:
            if self.link_exists(link):
                subprocess.call(['ip', 'link', 'del', 'dev', link])
        time.sleep(1)

    def l2tp_tunnel_remove(self, tunnel_ids):
        output = subprocess.check_output(['ip', 'l2tp', 'show', 'tunnel'], universal_newlines=True).rstrip()
        for tid in tunnel_ids:
            words='Tunnel ' + tid + ', encap'
            if words in output:
                subprocess.call(['ip', 'l2tp', 'del', 'tunnel', 'tid', tid])
        time.sleep(1)

    def read_ipv6_sysctl_attr(self, link, attribute):
        with open(os.path.join(os.path.join(network_sysctl_ipv6_path, link), attribute)) as f:
            return f.readline().strip()

    def read_ipv4_sysctl_attr(self, link, attribute):
        with open(os.path.join(os.path.join(network_sysctl_ipv4_path, link), attribute)) as f:
            return f.readline().strip()

    def copy_unit_to_networkd_unit_path(self, *units):
        print()
        for unit in units:
            shutil.copy(os.path.join(networkd_ci_path, unit), network_unit_file_path)
            if (os.path.exists(os.path.join(networkd_ci_path, unit + '.d'))):
                copytree(os.path.join(networkd_ci_path, unit + '.d'), os.path.join(network_unit_file_path, unit + '.d'))

    def remove_unit_from_networkd_path(self, units):
        for unit in units:
            if (os.path.exists(os.path.join(network_unit_file_path, unit))):
                os.remove(os.path.join(network_unit_file_path, unit))
                if (os.path.exists(os.path.join(network_unit_file_path, unit + '.d'))):
                    shutil.rmtree(os.path.join(network_unit_file_path, unit + '.d'))

    def start_dnsmasq(self, additional_options='', lease_time='1h'):
        dnsmasq_command = f'dnsmasq -8 /var/run/networkd-ci/test-dnsmasq-log-file --log-queries=extra --log-dhcp --pid-file=/var/run/networkd-ci/test-test-dnsmasq.pid --conf-file=/dev/null --interface=veth-peer --enable-ra --dhcp-range=2600::10,2600::20,{lease_time} --dhcp-range=192.168.5.10,192.168.5.200,{lease_time} -R --dhcp-leasefile=/var/run/networkd-ci/lease --dhcp-option=26,1492 --dhcp-option=option:router,192.168.5.1 --dhcp-option=33,192.168.5.4,192.168.5.5 --port=0 ' + additional_options
        subprocess.check_call(dnsmasq_command, shell=True)

        time.sleep(10)

    def stop_dnsmasq(self, pid_file):
        if os.path.exists(pid_file):
            with open(pid_file, 'r') as f:
                pid = f.read().rstrip(' \t\r\n\0')
                os.kill(int(pid), signal.SIGTERM)

            os.remove(pid_file)

    def search_words_in_dnsmasq_log(self, words, show_all=False):
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

    def remove_lease_file(self):
        if os.path.exists(os.path.join(networkd_ci_path, 'lease')):
            os.remove(os.path.join(networkd_ci_path, 'lease'))

    def remove_log_file(self):
        if os.path.exists(dnsmasq_log_file):
            os.remove(dnsmasq_log_file)

    def start_networkd(self, sleep_sec=5, remove_state_files=True):
        if (remove_state_files and
            os.path.exists(os.path.join(networkd_runtime_directory, 'state'))):
            subprocess.check_call('systemctl stop systemd-networkd', shell=True)
            os.remove(os.path.join(networkd_runtime_directory, 'state'))
            subprocess.check_call('systemctl start systemd-networkd', shell=True)
        else:
            subprocess.check_call('systemctl restart systemd-networkd', shell=True)
        if sleep_sec > 0:
            time.sleep(sleep_sec)

    def wait_online(self, links_with_operstate, timeout='20s', bool_any=False):
        args = [wait_online_bin, f'--timeout={timeout}'] + [f'--interface={link}' for link in links_with_operstate]
        if bool_any:
            args += ['--any']
        try:
            subprocess.check_call(args)
        except subprocess.CalledProcessError:
            for link in links_with_operstate:
                output = subprocess.check_output(['networkctl', 'status', link.split(':')[0]], universal_newlines=True).rstrip()
                print(output)
            raise

    def get_operstate(self, link, show_status=True, setup_state='configured'):
        output = subprocess.check_output(['networkctl', 'status', link], universal_newlines=True).rstrip()
        if show_status:
            print(output)
        for line in output.splitlines():
            if 'State:' in line and (not setup_state or setup_state in line):
                return line.split()[1]
        return None

    def check_operstate(self, link, expected, show_status=True, setup_state='configured'):
        self.assertRegex(self.get_operstate(link, show_status, setup_state), expected)


class NetworkdNetDevTests(unittest.TestCase, Utilities):

    links =[
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
        'vtitun97',
        'vtitun98',
        'vtitun99',
        'vxlan99',
        'wg98',
        'wg99']

    units = [
        '10-dropin-test.netdev',
        '11-dummy.netdev',
        '11-dummy.network',
        '12-dummy.netdev',
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
        '25-gre-tunnel-local-any.netdev',
        '25-gre-tunnel-remote-any.netdev',
        '25-gre-tunnel.netdev',
        '25-ip6gretap-tunnel-local-any.netdev',
        '25-ip6gretap-tunnel.netdev',
        '25-ip6gre-tunnel-local-any.netdev',
        '25-ip6gre-tunnel-remote-any.netdev',
        '25-ip6gre-tunnel.netdev',
        '25-ip6tnl-tunnel-remote-any.netdev',
        '25-ip6tnl-tunnel-local-any.netdev',
        '25-ip6tnl-tunnel.netdev',
        '25-ipip-tunnel-independent.netdev',
        '25-ipip-tunnel-local-any.netdev',
        '25-ipip-tunnel-remote-any.netdev',
        '25-ipip-tunnel.netdev',
        '25-ipvlan.netdev',
        '25-ipvtap.netdev',
        '25-isatap-tunnel.netdev',
        '25-macsec.key',
        '25-macsec.netdev',
        '25-macsec.network',
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
        '25-vti6-tunnel-local-any.netdev',
        '25-vti6-tunnel-remote-any.netdev',
        '25-vti6-tunnel.netdev',
        '25-vti-tunnel-local-any.netdev',
        '25-vti-tunnel-remote-any.netdev',
        '25-vti-tunnel.netdev',
        '25-vxlan.netdev',
        '25-wireguard-23-peers.netdev',
        '25-wireguard-23-peers.network',
        '25-wireguard-preshared-key.txt',
        '25-wireguard-private-key.txt',
        '25-wireguard.netdev',
        '25-wireguard.network',
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
        'sit.network',
        'vti6.network',
        'vti.network',
        'vxlan-test1.network',
        'vxlan.network']

    def setUp(self):
        self.link_remove(self.links)

    def tearDown(self):
        self.link_remove(self.links)
        self.remove_unit_from_networkd_path(self.units)

    def test_dropin_and_networkctl_glob(self):
        self.copy_unit_to_networkd_unit_path('10-dropin-test.netdev', '15-name-conflict-test.netdev')
        self.start_networkd(0)

        self.wait_online(['dropin-test:off'])

        # This also tests NetDev.Name= conflict and basic networkctl functionalities

        output = subprocess.check_output(['ip', 'link', 'show', 'dropin-test'], universal_newlines=True).rstrip()
        print(output)
        self.assertRegex(output, '00:50:56:c0:00:28')

        output = subprocess.check_output(['networkctl', 'list'], universal_newlines=True).rstrip()
        self.assertRegex(output, '1 lo ')
        self.assertRegex(output, 'dropin-test')

        output = subprocess.check_output(['networkctl', 'list', 'dropin-test'], universal_newlines=True).rstrip()
        self.assertNotRegex(output, '1 lo ')
        self.assertRegex(output, 'dropin-test')

        output = subprocess.check_output(['networkctl', 'list', 'dropin-*'], universal_newlines=True).rstrip()
        self.assertNotRegex(output, '1 lo ')
        self.assertRegex(output, 'dropin-test')

        output = subprocess.check_output(['networkctl', 'status', 'dropin-*'], universal_newlines=True).rstrip()
        self.assertNotRegex(output, '1: lo ')
        self.assertRegex(output, 'dropin-test')

        ret = subprocess.run(['ethtool', '--driver', 'dropin-test'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, universal_newlines=True)
        print(ret.stdout.rstrip())
        if ret.returncode == 0 and re.search('driver: dummy', ret.stdout.rstrip()) != None:
            self.assertRegex(output, 'Driver: dummy')
        else:
            print('ethtool does not support driver field at least for dummy interfaces, skipping test for Driver field of networkctl.')

    def test_wait_online_any(self):
        self.copy_unit_to_networkd_unit_path('25-bridge.netdev', '25-bridge.network', '11-dummy.netdev', '11-dummy.network')
        self.start_networkd(0)

        self.wait_online(['bridge99', 'test1:degraded'], bool_any=True)
        self.check_link_exists('bridge99')
        self.check_link_exists('test1')

        self.check_operstate('bridge99', '(?:off|no-carrier)', setup_state='configuring')
        self.check_operstate('test1', 'degraded')

    def test_bridge(self):
        self.copy_unit_to_networkd_unit_path('25-bridge.netdev')
        self.start_networkd(0)

        self.wait_online(['bridge99:off'])

        tick = os.sysconf('SC_CLK_TCK')
        self.assertEqual(9, round(float(self.read_link_attr('bridge99', 'bridge', 'hello_time')) / tick))
        self.assertEqual(9, round(float(self.read_link_attr('bridge99', 'bridge', 'max_age')) / tick))
        self.assertEqual(9, round(float(self.read_link_attr('bridge99', 'bridge','forward_delay')) / tick))
        self.assertEqual(9, round(float(self.read_link_attr('bridge99', 'bridge','ageing_time')) / tick))
        self.assertEqual(9,         int(self.read_link_attr('bridge99', 'bridge','priority')))
        self.assertEqual(1,         int(self.read_link_attr('bridge99', 'bridge','multicast_querier')))
        self.assertEqual(1,         int(self.read_link_attr('bridge99', 'bridge','multicast_snooping')))
        self.assertEqual(1,         int(self.read_link_attr('bridge99', 'bridge','stp_state')))

    def test_bond(self):
        self.copy_unit_to_networkd_unit_path('25-bond.netdev', '25-bond-balanced-tlb.netdev')
        self.start_networkd(0)

        self.wait_online(['bond99:off', 'bond98:off'])

        self.assertEqual('802.3ad 4',         self.read_link_attr('bond99', 'bonding', 'mode'))
        self.assertEqual('layer3+4 1',        self.read_link_attr('bond99', 'bonding', 'xmit_hash_policy'))
        self.assertEqual('1000',              self.read_link_attr('bond99', 'bonding', 'miimon'))
        self.assertEqual('fast 1',            self.read_link_attr('bond99', 'bonding', 'lacp_rate'))
        self.assertEqual('2000',              self.read_link_attr('bond99', 'bonding', 'updelay'))
        self.assertEqual('2000',              self.read_link_attr('bond99', 'bonding', 'downdelay'))
        self.assertEqual('4',                 self.read_link_attr('bond99', 'bonding', 'resend_igmp'))
        self.assertEqual('1',                 self.read_link_attr('bond99', 'bonding', 'min_links'))
        self.assertEqual('1218',              self.read_link_attr('bond99', 'bonding', 'ad_actor_sys_prio'))
        self.assertEqual('811',               self.read_link_attr('bond99', 'bonding', 'ad_user_port_key'))
        self.assertEqual('00:11:22:33:44:55', self.read_link_attr('bond99', 'bonding', 'ad_actor_system'))

        self.assertEqual('balance-tlb 5',     self.read_link_attr('bond98', 'bonding', 'mode'))
        self.assertEqual('1',                 self.read_link_attr('bond98', 'bonding', 'tlb_dynamic_lb'))

    def test_vlan(self):
        self.copy_unit_to_networkd_unit_path('21-vlan.netdev', '11-dummy.netdev',
                                             '21-vlan.network', '21-vlan-test1.network')
        self.start_networkd(0)

        self.wait_online(['test1', 'vlan99'])

        output = subprocess.check_output(['ip', '-d', 'link', 'show', 'test1'], universal_newlines=True).rstrip()
        print(output)
        self.assertRegex(output, ' mtu 2000 ')

        output = subprocess.check_output(['ip', '-d', 'link', 'show', 'vlan99'], universal_newlines=True).rstrip()
        print(output)
        self.assertRegex(output, ' mtu 2000 ')
        self.assertRegex(output, 'REORDER_HDR')
        self.assertRegex(output, 'LOOSE_BINDING')
        self.assertRegex(output, 'GVRP')
        self.assertRegex(output, 'MVRP')
        self.assertRegex(output, ' id 99 ')

        output = subprocess.check_output(['ip', '-4', 'address', 'show', 'dev', 'test1'], universal_newlines=True).rstrip()
        print(output)
        self.assertRegex(output, 'inet 192.168.24.5/24 brd 192.168.24.255 scope global test1')
        self.assertRegex(output, 'inet 192.168.25.5/24 brd 192.168.25.255 scope global test1')

        output = subprocess.check_output(['ip', '-4', 'address', 'show', 'dev', 'vlan99'], universal_newlines=True).rstrip()
        print(output)
        self.assertRegex(output, 'inet 192.168.23.5/24 brd 192.168.23.255 scope global vlan99')

    def test_macvtap(self):
        self.copy_unit_to_networkd_unit_path('21-macvtap.netdev', '11-dummy.netdev', 'macvtap.network')
        self.start_networkd(0)

        self.wait_online(['macvtap99:off', 'test1:degraded'])

    def test_macvlan(self):
        self.copy_unit_to_networkd_unit_path('21-macvlan.netdev', '11-dummy.netdev', 'macvlan.network')
        self.start_networkd(0)

        self.wait_online(['macvlan99:off', 'test1:degraded'])

        output = subprocess.check_output(['ip', '-d', 'link', 'show', 'test1'], universal_newlines=True).rstrip()
        print(output)
        self.assertRegex(output, ' mtu 2000 ')

        output = subprocess.check_output(['ip', '-d', 'link', 'show', 'macvlan99'], universal_newlines=True).rstrip()
        print(output)
        self.assertRegex(output, ' mtu 2000 ')

    @expectedFailureIfModuleIsNotAvailable('ipvlan')
    def test_ipvlan(self):
        self.copy_unit_to_networkd_unit_path('25-ipvlan.netdev', '11-dummy.netdev', 'ipvlan.network')
        self.start_networkd(0)

        self.wait_online(['ipvlan99:off', 'test1:degraded'])

    @expectedFailureIfModuleIsNotAvailable('ipvtap')
    def test_ipvtap(self):
        self.copy_unit_to_networkd_unit_path('25-ipvtap.netdev', '11-dummy.netdev', 'ipvtap.network')
        self.start_networkd(0)

        self.wait_online(['ipvtap99:off', 'test1:degraded'])

    def test_veth(self):
        self.copy_unit_to_networkd_unit_path('25-veth.netdev')
        self.start_networkd(0)

        self.wait_online(['veth99:off', 'veth-peer:off'])

    def test_dummy(self):
        self.copy_unit_to_networkd_unit_path('11-dummy.netdev')
        self.start_networkd(0)

        self.wait_online(['test1:off'])

    def test_tun(self):
        self.copy_unit_to_networkd_unit_path('25-tun.netdev')
        self.start_networkd(0)

        self.wait_online(['tun99:off'])

    def test_tap(self):
        self.copy_unit_to_networkd_unit_path('25-tap.netdev')
        self.start_networkd(0)

        self.wait_online(['tap99:off'])

    @expectedFailureIfModuleIsNotAvailable('vrf')
    def test_vrf(self):
        self.copy_unit_to_networkd_unit_path('25-vrf.netdev')
        self.start_networkd(0)

        self.wait_online(['vrf99:off'])

    @expectedFailureIfModuleIsNotAvailable('vcan')
    def test_vcan(self):
        self.copy_unit_to_networkd_unit_path('25-vcan.netdev')
        self.start_networkd(0)

        self.wait_online(['vcan99:off'])

    @expectedFailureIfModuleIsNotAvailable('wireguard')
    def test_wireguard(self):
        self.copy_unit_to_networkd_unit_path('25-wireguard.netdev', '25-wireguard.network',
                                             '25-wireguard-23-peers.netdev', '25-wireguard-23-peers.network',
                                             '25-wireguard-preshared-key.txt', '25-wireguard-private-key.txt')
        self.start_networkd(0)
        self.wait_online(['wg99:carrier', 'wg98:routable'])

        if shutil.which('wg'):
            subprocess.call('wg')

            output = subprocess.check_output(['wg', 'show', 'wg99', 'listen-port'], universal_newlines=True).rstrip()
            self.assertRegex(output, '51820')
            output = subprocess.check_output(['wg', 'show', 'wg99', 'fwmark'], universal_newlines=True).rstrip()
            self.assertRegex(output, '0x4d2')
            output = subprocess.check_output(['wg', 'show', 'wg99', 'allowed-ips'], universal_newlines=True).rstrip()
            self.assertRegex(output, 'RDf\+LSpeEre7YEIKaxg\+wbpsNV7du\+ktR99uBEtIiCA=\t192.168.26.0/24 fd31:bf08:57cb::/48')
            self.assertRegex(output, 'lsDtM3AbjxNlauRKzHEPfgS1Zp7cp/VX5Use/P4PQSc=\tfdbc:bae2:7871:e1fe:793:8636::/96 fdbc:bae2:7871:500:e1fe:793:8636:dad1/128')
            output = subprocess.check_output(['wg', 'show', 'wg99', 'persistent-keepalive'], universal_newlines=True).rstrip()
            self.assertRegex(output, 'RDf\+LSpeEre7YEIKaxg\+wbpsNV7du\+ktR99uBEtIiCA=\t20')
            output = subprocess.check_output(['wg', 'show', 'wg99', 'endpoints'], universal_newlines=True).rstrip()
            self.assertRegex(output, 'RDf\+LSpeEre7YEIKaxg\+wbpsNV7du\+ktR99uBEtIiCA=\t192.168.27.3:51820')
            output = subprocess.check_output(['wg', 'show', 'wg99', 'private-key'], universal_newlines=True).rstrip()
            self.assertRegex(output, 'EEGlnEPYJV//kbvvIqxKkQwOiS\+UENyPncC4bF46ong=')
            output = subprocess.check_output(['wg', 'show', 'wg99', 'preshared-keys'], universal_newlines=True).rstrip()
            self.assertRegex(output, 'RDf\+LSpeEre7YEIKaxg\+wbpsNV7du\+ktR99uBEtIiCA=	IIWIV17wutHv7t4cR6pOT91z6NSz/T8Arh0yaywhw3M=')
            self.assertRegex(output, 'lsDtM3AbjxNlauRKzHEPfgS1Zp7cp/VX5Use/P4PQSc=	cPLOy1YUrEI0EMMIycPJmOo0aTu3RZnw8bL5meVD6m0=')

            output = subprocess.check_output(['wg', 'show', 'wg98', 'private-key'], universal_newlines=True).rstrip()
            self.assertRegex(output, 'CJQUtcS9emY2fLYqDlpSZiE/QJyHkPWr\+WHtZLZ90FU=')

    def test_geneve(self):
        self.copy_unit_to_networkd_unit_path('25-geneve.netdev')
        self.start_networkd(0)

        self.wait_online(['geneve99:off'])

        output = subprocess.check_output(['ip', '-d', 'link', 'show', 'geneve99'], universal_newlines=True).rstrip()
        print(output)
        self.assertRegex(output, '192.168.22.1')
        self.assertRegex(output, '6082')
        self.assertRegex(output, 'udpcsum')
        self.assertRegex(output, 'udp6zerocsumrx')

    def test_ipip_tunnel(self):
        self.copy_unit_to_networkd_unit_path('12-dummy.netdev', 'ipip.network',
                                             '25-ipip-tunnel.netdev', '25-tunnel.network',
                                             '25-ipip-tunnel-local-any.netdev', '25-tunnel-local-any.network',
                                             '25-ipip-tunnel-remote-any.netdev', '25-tunnel-remote-any.network')
        self.start_networkd(0)
        self.wait_online(['ipiptun99:routable', 'ipiptun98:routable', 'ipiptun97:routable', 'dummy98:degraded'])

        output = subprocess.check_output(['ip', '-d', 'link', 'show', 'ipiptun99'], universal_newlines=True).rstrip()
        print(output)
        self.assertRegex(output, 'ipip (?:ipip |)remote 192.169.224.239 local 192.168.223.238 dev dummy98')
        output = subprocess.check_output(['ip', '-d', 'link', 'show', 'ipiptun98'], universal_newlines=True).rstrip()
        print(output)
        self.assertRegex(output, 'ipip (?:ipip |)remote 192.169.224.239 local any dev dummy98')
        output = subprocess.check_output(['ip', '-d', 'link', 'show', 'ipiptun97'], universal_newlines=True).rstrip()
        print(output)
        self.assertRegex(output, 'ipip (?:ipip |)remote any local 192.168.223.238 dev dummy98')

    def test_gre_tunnel(self):
        self.copy_unit_to_networkd_unit_path('12-dummy.netdev', 'gretun.network',
                                             '25-gre-tunnel.netdev', '25-tunnel.network',
                                             '25-gre-tunnel-local-any.netdev', '25-tunnel-local-any.network',
                                             '25-gre-tunnel-remote-any.netdev', '25-tunnel-remote-any.network')
        self.start_networkd(0)
        self.wait_online(['gretun99:routable', 'gretun98:routable', 'gretun97:routable', 'dummy98:degraded'])

        output = subprocess.check_output(['ip', '-d', 'link', 'show', 'gretun99'], universal_newlines=True).rstrip()
        print(output)
        self.assertRegex(output, 'gre remote 10.65.223.239 local 10.65.223.238 dev dummy98')
        self.assertRegex(output, 'ikey 1.2.3.103')
        self.assertRegex(output, 'okey 1.2.4.103')
        self.assertRegex(output, 'iseq')
        self.assertRegex(output, 'oseq')
        output = subprocess.check_output(['ip', '-d', 'link', 'show', 'gretun98'], universal_newlines=True).rstrip()
        print(output)
        self.assertRegex(output, 'gre remote 10.65.223.239 local any dev dummy98')
        self.assertRegex(output, 'ikey 0.0.0.104')
        self.assertRegex(output, 'okey 0.0.0.104')
        self.assertNotRegex(output, 'iseq')
        self.assertNotRegex(output, 'oseq')
        output = subprocess.check_output(['ip', '-d', 'link', 'show', 'gretun97'], universal_newlines=True).rstrip()
        print(output)
        self.assertRegex(output, 'gre remote any local 10.65.223.238 dev dummy98')
        self.assertRegex(output, 'ikey 0.0.0.105')
        self.assertRegex(output, 'okey 0.0.0.105')
        self.assertNotRegex(output, 'iseq')
        self.assertNotRegex(output, 'oseq')

    @expectedFailureIf_ip6gre_do_not_support_ipv6ll()
    def test_ip6gre_tunnel(self):
        self.copy_unit_to_networkd_unit_path('12-dummy.netdev', 'ip6gretun.network',
                                             '25-ip6gre-tunnel.netdev', '25-tunnel.network',
                                             '25-ip6gre-tunnel-local-any.netdev', '25-tunnel-local-any.network',
                                             '25-ip6gre-tunnel-remote-any.netdev', '25-tunnel-remote-any.network')
        self.start_networkd()

        self.check_link_exists('dummy98')
        self.check_link_exists('ip6gretun99')
        self.check_link_exists('ip6gretun98')
        self.check_link_exists('ip6gretun97')

        output = subprocess.check_output(['ip', '-d', 'link', 'show', 'ip6gretun99'], universal_newlines=True).rstrip()
        print(output)
        self.assertRegex(output, 'ip6gre remote 2001:473:fece:cafe::5179 local 2a00:ffde:4567:edde::4987 dev dummy98')
        output = subprocess.check_output(['ip', '-d', 'link', 'show', 'ip6gretun98'], universal_newlines=True).rstrip()
        print(output)
        self.assertRegex(output, 'ip6gre remote 2001:473:fece:cafe::5179 local any dev dummy98')
        output = subprocess.check_output(['ip', '-d', 'link', 'show', 'ip6gretun97'], universal_newlines=True).rstrip()
        print(output)
        self.assertRegex(output, 'ip6gre remote any local 2a00:ffde:4567:edde::4987 dev dummy98')

        # Old kernels may not support IPv6LL address on ip6gre tunnel, and the following test may fails.
        self.wait_online(['ip6gretun99:routable', 'ip6gretun98:routable', 'ip6gretun97:routable', 'dummy98:degraded'])

    def test_gretap_tunnel(self):
        self.copy_unit_to_networkd_unit_path('12-dummy.netdev', 'gretap.network',
                                             '25-gretap-tunnel.netdev', '25-tunnel.network',
                                             '25-gretap-tunnel-local-any.netdev', '25-tunnel-local-any.network')
        self.start_networkd(0)
        self.wait_online(['gretap99:routable', 'gretap98:routable', 'dummy98:degraded'])

        output = subprocess.check_output(['ip', '-d', 'link', 'show', 'gretap99'], universal_newlines=True).rstrip()
        print(output)
        self.assertRegex(output, 'gretap remote 10.65.223.239 local 10.65.223.238 dev dummy98')
        self.assertRegex(output, 'ikey 0.0.0.106')
        self.assertRegex(output, 'okey 0.0.0.106')
        self.assertRegex(output, 'iseq')
        self.assertRegex(output, 'oseq')
        output = subprocess.check_output(['ip', '-d', 'link', 'show', 'gretap98'], universal_newlines=True).rstrip()
        print(output)
        self.assertRegex(output, 'gretap remote 10.65.223.239 local any dev dummy98')
        self.assertRegex(output, 'ikey 0.0.0.107')
        self.assertRegex(output, 'okey 0.0.0.107')
        self.assertRegex(output, 'iseq')
        self.assertRegex(output, 'oseq')

    def test_ip6gretap_tunnel(self):
        self.copy_unit_to_networkd_unit_path('12-dummy.netdev', 'ip6gretap.network',
                                             '25-ip6gretap-tunnel.netdev', '25-tunnel.network',
                                             '25-ip6gretap-tunnel-local-any.netdev', '25-tunnel-local-any.network')
        self.start_networkd(0)
        self.wait_online(['ip6gretap99:routable', 'ip6gretap98:routable', 'dummy98:degraded'])

        output = subprocess.check_output(['ip', '-d', 'link', 'show', 'ip6gretap99'], universal_newlines=True).rstrip()
        print(output)
        self.assertRegex(output, 'ip6gretap remote 2001:473:fece:cafe::5179 local 2a00:ffde:4567:edde::4987 dev dummy98')
        output = subprocess.check_output(['ip', '-d', 'link', 'show', 'ip6gretap98'], universal_newlines=True).rstrip()
        print(output)
        self.assertRegex(output, 'ip6gretap remote 2001:473:fece:cafe::5179 local any dev dummy98')

    def test_vti_tunnel(self):
        self.copy_unit_to_networkd_unit_path('12-dummy.netdev', 'vti.network',
                                             '25-vti-tunnel.netdev', '25-tunnel.network',
                                             '25-vti-tunnel-local-any.netdev', '25-tunnel-local-any.network',
                                             '25-vti-tunnel-remote-any.netdev', '25-tunnel-remote-any.network')
        self.start_networkd(0)
        self.wait_online(['vtitun99:routable', 'vtitun98:routable', 'vtitun97:routable', 'dummy98:degraded'])

        output = subprocess.check_output(['ip', '-d', 'link', 'show', 'vtitun99'], universal_newlines=True).rstrip()
        print(output)
        self.assertRegex(output, 'vti remote 10.65.223.239 local 10.65.223.238 dev dummy98')
        output = subprocess.check_output(['ip', '-d', 'link', 'show', 'vtitun98'], universal_newlines=True).rstrip()
        print(output)
        self.assertRegex(output, 'vti remote 10.65.223.239 local any dev dummy98')
        output = subprocess.check_output(['ip', '-d', 'link', 'show', 'vtitun97'], universal_newlines=True).rstrip()
        print(output)
        self.assertRegex(output, 'vti remote any local 10.65.223.238 dev dummy98')

    def test_vti6_tunnel(self):
        self.copy_unit_to_networkd_unit_path('12-dummy.netdev', 'vti6.network',
                                             '25-vti6-tunnel.netdev', '25-tunnel.network',
                                             '25-vti6-tunnel-local-any.netdev', '25-tunnel-local-any.network',
                                             '25-vti6-tunnel-remote-any.netdev', '25-tunnel-remote-any.network')
        self.start_networkd(0)
        self.wait_online(['vti6tun99:routable', 'vti6tun98:routable', 'vti6tun97:routable', 'dummy98:degraded'])

        output = subprocess.check_output(['ip', '-d', 'link', 'show', 'vti6tun99'], universal_newlines=True).rstrip()
        print(output)
        self.assertRegex(output, 'vti6 remote 2001:473:fece:cafe::5179 local 2a00:ffde:4567:edde::4987 dev dummy98')
        output = subprocess.check_output(['ip', '-d', 'link', 'show', 'vti6tun98'], universal_newlines=True).rstrip()
        print(output)
        self.assertRegex(output, 'vti6 remote 2001:473:fece:cafe::5179 local (?:any|::) dev dummy98')
        output = subprocess.check_output(['ip', '-d', 'link', 'show', 'vti6tun97'], universal_newlines=True).rstrip()
        print(output)
        self.assertRegex(output, 'vti6 remote (?:any|::) local 2a00:ffde:4567:edde::4987 dev dummy98')

    def test_ip6tnl_tunnel(self):
        self.copy_unit_to_networkd_unit_path('12-dummy.netdev', 'ip6tnl.network',
                                             '25-ip6tnl-tunnel.netdev', '25-tunnel.network',
                                             '25-ip6tnl-tunnel-local-any.netdev', '25-tunnel-local-any.network',
                                             '25-ip6tnl-tunnel-remote-any.netdev', '25-tunnel-remote-any.network')
        self.start_networkd(0)
        self.wait_online(['ip6tnl99:routable', 'ip6tnl98:routable', 'ip6tnl97:routable', 'dummy98:degraded'])

        output = subprocess.check_output(['ip', '-d', 'link', 'show', 'ip6tnl99'], universal_newlines=True).rstrip()
        print(output)
        self.assertRegex(output, 'ip6tnl ip6ip6 remote 2001:473:fece:cafe::5179 local 2a00:ffde:4567:edde::4987 dev dummy98')
        output = subprocess.check_output(['ip', '-d', 'link', 'show', 'ip6tnl98'], universal_newlines=True).rstrip()
        print(output)
        self.assertRegex(output, 'ip6tnl ip6ip6 remote 2001:473:fece:cafe::5179 local (?:any|::) dev dummy98')
        output = subprocess.check_output(['ip', '-d', 'link', 'show', 'ip6tnl97'], universal_newlines=True).rstrip()
        print(output)
        self.assertRegex(output, 'ip6tnl ip6ip6 remote (?:any|::) local 2a00:ffde:4567:edde::4987 dev dummy98')

    def test_sit_tunnel(self):
        self.copy_unit_to_networkd_unit_path('12-dummy.netdev', 'sit.network',
                                             '25-sit-tunnel.netdev', '25-tunnel.network',
                                             '25-sit-tunnel-local-any.netdev', '25-tunnel-local-any.network',
                                             '25-sit-tunnel-remote-any.netdev', '25-tunnel-remote-any.network')
        self.start_networkd(0)
        self.wait_online(['sittun99:routable', 'sittun98:routable', 'sittun97:routable', 'dummy98:degraded'])

        output = subprocess.check_output(['ip', '-d', 'link', 'show', 'sittun99'], universal_newlines=True).rstrip()
        print(output)
        self.assertRegex(output, "sit (?:ip6ip |)remote 10.65.223.239 local 10.65.223.238 dev dummy98")
        output = subprocess.check_output(['ip', '-d', 'link', 'show', 'sittun98'], universal_newlines=True).rstrip()
        print(output)
        self.assertRegex(output, "sit (?:ip6ip |)remote 10.65.223.239 local any dev dummy98")
        output = subprocess.check_output(['ip', '-d', 'link', 'show', 'sittun97'], universal_newlines=True).rstrip()
        print(output)
        self.assertRegex(output, "sit (?:ip6ip |)remote any local 10.65.223.238 dev dummy98")

    def test_isatap_tunnel(self):
        self.copy_unit_to_networkd_unit_path('12-dummy.netdev', 'isatap.network',
                                             '25-isatap-tunnel.netdev', '25-tunnel.network')
        self.start_networkd(0)
        self.wait_online(['isataptun99:routable', 'dummy98:degraded'])

        self.check_link_exists('dummy98')
        self.check_link_exists('isataptun99')

        output = subprocess.check_output(['ip', '-d', 'link', 'show', 'isataptun99'], universal_newlines=True).rstrip()
        print(output)
        self.assertRegex(output, "isatap ")

    def test_6rd_tunnel(self):
        self.copy_unit_to_networkd_unit_path('12-dummy.netdev', '6rd.network',
                                             '25-6rd-tunnel.netdev', '25-tunnel.network')
        self.start_networkd(0)
        self.wait_online(['sittun99:routable', 'dummy98:degraded'])

        output = subprocess.check_output(['ip', '-d', 'link', 'show', 'sittun99'], universal_newlines=True).rstrip()
        print(output)
        self.assertRegex(output, '6rd-prefix 2602::/24')

    @expectedFailureIfERSPANModuleIsNotAvailable()
    def test_erspan_tunnel(self):
        self.copy_unit_to_networkd_unit_path('12-dummy.netdev', 'erspan.network',
                                             '25-erspan-tunnel.netdev', '25-tunnel.network',
                                             '25-erspan-tunnel-local-any.netdev', '25-tunnel-local-any.network')
        self.start_networkd(0)
        self.wait_online(['erspan99:routable', 'erspan98:routable', 'dummy98:degraded'])

        output = subprocess.check_output(['ip', '-d', 'link', 'show', 'erspan99'], universal_newlines=True).rstrip()
        print(output)
        self.assertRegex(output, 'erspan remote 172.16.1.100 local 172.16.1.200')
        self.assertRegex(output, 'ikey 0.0.0.101')
        self.assertRegex(output, 'okey 0.0.0.101')
        self.assertRegex(output, 'iseq')
        self.assertRegex(output, 'oseq')
        output = subprocess.check_output(['ip', '-d', 'link', 'show', 'erspan98'], universal_newlines=True).rstrip()
        print(output)
        self.assertRegex(output, 'erspan remote 172.16.1.100 local any')
        self.assertRegex(output, '102')
        self.assertRegex(output, 'ikey 0.0.0.102')
        self.assertRegex(output, 'okey 0.0.0.102')
        self.assertRegex(output, 'iseq')
        self.assertRegex(output, 'oseq')

    def test_tunnel_independent(self):
        self.copy_unit_to_networkd_unit_path('25-ipip-tunnel-independent.netdev')
        self.start_networkd(0)

        self.wait_online(['ipiptun99:off'])

    @expectedFailureIfModuleIsNotAvailable('fou')
    def test_fou(self):
        # The following redundant check is necessary for CentOS CI.
        # Maybe, error handling in lookup_id() in sd-netlink/generic-netlink.c needs to be updated.
        self.assertTrue(is_module_available('fou'))

        self.copy_unit_to_networkd_unit_path('25-fou-ipproto-ipip.netdev', '25-fou-ipproto-gre.netdev',
                                             '25-fou-ipip.netdev', '25-fou-sit.netdev',
                                             '25-fou-gre.netdev', '25-fou-gretap.netdev')
        self.start_networkd(0)

        self.wait_online(['ipiptun96:off', 'sittun96:off', 'gretun96:off', 'gretap96:off'])

        output = subprocess.check_output(['ip', 'fou', 'show'], universal_newlines=True).rstrip()
        print(output)
        self.assertRegex(output, 'port 55555 ipproto 4')
        self.assertRegex(output, 'port 55556 ipproto 47')

        output = subprocess.check_output(['ip', '-d', 'link', 'show', 'ipiptun96'], universal_newlines=True).rstrip()
        print(output)
        self.assertRegex(output, 'encap fou encap-sport auto encap-dport 55555')
        output = subprocess.check_output(['ip', '-d', 'link', 'show', 'sittun96'], universal_newlines=True).rstrip()
        print(output)
        self.assertRegex(output, 'encap fou encap-sport auto encap-dport 55555')
        output = subprocess.check_output(['ip', '-d', 'link', 'show', 'gretun96'], universal_newlines=True).rstrip()
        print(output)
        self.assertRegex(output, 'encap fou encap-sport 1001 encap-dport 55556')
        output = subprocess.check_output(['ip', '-d', 'link', 'show', 'gretap96'], universal_newlines=True).rstrip()
        print(output)
        self.assertRegex(output, 'encap fou encap-sport auto encap-dport 55556')

        subprocess.call(['ip', 'fou', 'del', 'port', '55555'])
        subprocess.call(['ip', 'fou', 'del', 'port', '55556'])

    def test_vxlan(self):
        self.copy_unit_to_networkd_unit_path('25-vxlan.netdev', 'vxlan.network',
                                             '11-dummy.netdev', 'vxlan-test1.network')
        self.start_networkd(0)

        self.wait_online(['test1:degraded', 'vxlan99:degraded'])

        output = subprocess.check_output(['ip', '-d', 'link', 'show', 'vxlan99'], universal_newlines=True).rstrip()
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

        output = subprocess.check_output(['bridge', 'fdb', 'show', 'dev', 'vxlan99'], universal_newlines=True).rstrip()
        print(output)
        self.assertRegex(output, '00:11:22:33:44:55 dst 10.0.0.5 self permanent')
        self.assertRegex(output, '00:11:22:33:44:66 dst 10.0.0.6 self permanent')
        self.assertRegex(output, '00:11:22:33:44:77 dst 10.0.0.7 self permanent')

    def test_macsec(self):
        self.copy_unit_to_networkd_unit_path('25-macsec.netdev', '25-macsec.network', '25-macsec.key',
                                             'macsec.network', '12-dummy.netdev')
        self.start_networkd(0)

        self.wait_online(['dummy98:degraded', 'macsec99:routable'])

        output = subprocess.check_output(['ip', '-d', 'link', 'show', 'macsec99'], universal_newlines=True).rstrip()
        print(output)
        self.assertRegex(output, 'macsec99@dummy98')
        self.assertRegex(output, 'macsec sci [0-9a-f]*000b')
        self.assertRegex(output, 'encrypt on')

        output = subprocess.check_output(['ip', 'macsec', 'show', 'macsec99'], universal_newlines=True).rstrip()
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
        '25-l2tp-ip.netdev',
        '25-l2tp-udp.netdev']

    l2tp_tunnel_ids = [ '10' ]

    def setUp(self):
        self.l2tp_tunnel_remove(self.l2tp_tunnel_ids)
        self.link_remove(self.links)

    def tearDown(self):
        self.l2tp_tunnel_remove(self.l2tp_tunnel_ids)
        self.link_remove(self.links)
        self.remove_unit_from_networkd_path(self.units)

    @expectedFailureIfModuleIsNotAvailable('l2tp_eth')
    def test_l2tp_udp(self):
        self.copy_unit_to_networkd_unit_path('11-dummy.netdev', '25-l2tp-dummy.network', '25-l2tp-udp.netdev')
        self.start_networkd(0)

        self.wait_online(['test1:routable', 'l2tp-ses1:off', 'l2tp-ses2:off'])

        output = subprocess.check_output(['ip', 'l2tp', 'show', 'tunnel', 'tunnel_id', '10'], universal_newlines=True).rstrip()
        print(output)
        self.assertRegex(output, "Tunnel 10, encap UDP")
        self.assertRegex(output, "From 192.168.30.100 to 192.168.30.101")
        self.assertRegex(output, "Peer tunnel 11")
        self.assertRegex(output, "UDP source / dest ports: 3000/4000")
        self.assertRegex(output, "UDP checksum: enabled")

        output = subprocess.check_output(['ip', 'l2tp', 'show', 'session', 'tid', '10', 'session_id', '15'], universal_newlines=True).rstrip()
        print(output)
        self.assertRegex(output, "Session 15 in tunnel 10")
        self.assertRegex(output, "Peer session 16, tunnel 11")
        self.assertRegex(output, "interface name: l2tp-ses1")

        output = subprocess.check_output(['ip', 'l2tp', 'show', 'session', 'tid', '10', 'session_id', '17'], universal_newlines=True).rstrip()
        print(output)
        self.assertRegex(output, "Session 17 in tunnel 10")
        self.assertRegex(output, "Peer session 18, tunnel 11")
        self.assertRegex(output, "interface name: l2tp-ses2")

    @expectedFailureIfModuleIsNotAvailable('l2tp_ip')
    def test_l2tp_ip(self):
        self.copy_unit_to_networkd_unit_path('11-dummy.netdev', '25-l2tp-dummy.network', '25-l2tp-ip.netdev')
        self.start_networkd(0)

        self.wait_online(['test1:routable', 'l2tp-ses3:off', 'l2tp-ses4:off'])

        output = subprocess.check_output(['ip', 'l2tp', 'show', 'tunnel', 'tunnel_id', '10'], universal_newlines=True).rstrip()
        print(output)
        self.assertRegex(output, "Tunnel 10, encap IP")
        self.assertRegex(output, "From 192.168.30.100 to 192.168.30.101")
        self.assertRegex(output, "Peer tunnel 12")

        output = subprocess.check_output(['ip', 'l2tp', 'show', 'session', 'tid', '10', 'session_id', '25'], universal_newlines=True).rstrip()
        print(output)
        self.assertRegex(output, "Session 25 in tunnel 10")
        self.assertRegex(output, "Peer session 26, tunnel 12")
        self.assertRegex(output, "interface name: l2tp-ses3")

        output = subprocess.check_output(['ip', 'l2tp', 'show', 'session', 'tid', '10', 'session_id', '27'], universal_newlines=True).rstrip()
        print(output)
        self.assertRegex(output, "Session 27 in tunnel 10")
        self.assertRegex(output, "Peer session 28, tunnel 12")
        self.assertRegex(output, "interface name: l2tp-ses4")

class NetworkdNetWorkTests(unittest.TestCase, Utilities):
    links = [
        'bond199',
        'dummy98',
        'dummy99',
        'test1']

    units = [
        '11-dummy.netdev',
        '12-dummy.netdev',
        '23-active-slave.network',
        '25-address-link-section.network',
        '25-address-preferred-lifetime-zero-ipv6.network',
        '25-address-static.network',
        '25-bind-carrier.network',
        '25-bond-active-backup-slave.netdev',
        '25-fibrule-invert.network',
        '25-fibrule-port-range.network',
        '25-ipv6-address-label-section.network',
        '25-neighbor-section.network',
        '25-link-local-addressing-no.network',
        '25-link-local-addressing-yes.network',
        '25-link-section-unmanaged.network',
        '25-route-ipv6-src.network',
        '25-route-static.network',
        '25-sysctl-disable-ipv6.network',
        '25-sysctl.network',
        'configure-without-carrier.network',
        'routing-policy-rule-dummy98.network',
        'routing-policy-rule-test1.network']

    def setUp(self):
        self.link_remove(self.links)

    def tearDown(self):
        self.link_remove(self.links)
        self.remove_unit_from_networkd_path(self.units)

    def test_address_static(self):
        self.copy_unit_to_networkd_unit_path('25-address-static.network', '12-dummy.netdev')
        self.start_networkd(0)

        self.wait_online(['dummy98:routable'])

        output = subprocess.check_output(['ip', '-4', 'address', 'show', 'dev', 'dummy98'], universal_newlines=True).rstrip()
        print(output)
        self.assertRegex(output, 'inet 10.1.2.3/16 brd 10.1.255.255 scope global dummy98')
        self.assertRegex(output, 'inet 10.1.2.4/16 brd 10.1.255.255 scope global secondary dummy98')
        self.assertRegex(output, 'inet 10.2.2.4/16 brd 10.2.255.255 scope global dummy98')

        # invalid sections
        self.assertNotRegex(output, '10.10.0.1/16')
        self.assertNotRegex(output, '10.10.0.2/16')

        output = subprocess.check_output(['ip', '-4', 'address', 'show', 'dev', 'dummy98', 'label', '32'], universal_newlines=True).rstrip()
        self.assertRegex(output, 'inet 10.3.2.3/16 brd 10.3.255.255 scope global 32')

        output = subprocess.check_output(['ip', '-4', 'address', 'show', 'dev', 'dummy98', 'label', '33'], universal_newlines=True).rstrip()
        self.assertRegex(output, 'inet 10.4.2.3 peer 10.4.2.4/16 scope global 33')

        output = subprocess.check_output(['ip', '-4', 'address', 'show', 'dev', 'dummy98', 'label', '34'], universal_newlines=True).rstrip()
        self.assertRegex(output, 'inet 192.168.[0-9]*.1/24 brd 192.168.[0-9]*.255 scope global 34')

        output = subprocess.check_output(['ip', '-4', 'address', 'show', 'dev', 'dummy98', 'label', '35'], universal_newlines=True).rstrip()
        self.assertRegex(output, 'inet 172.[0-9]*.0.1/16 brd 172.[0-9]*.255.255 scope global 35')

        output = subprocess.check_output(['ip', '-6', 'address', 'show', 'dev', 'dummy98'], universal_newlines=True).rstrip()
        print(output)
        self.assertRegex(output, 'inet6 2001:db8:0:f101::15/64 scope global')
        self.assertRegex(output, 'inet6 2001:db8:0:f101::16/64 scope global')
        self.assertRegex(output, 'inet6 2001:db8:0:f102::15/64 scope global')
        self.assertRegex(output, 'inet6 2001:db8:0:f102::16/64 scope global')
        self.assertRegex(output, 'inet6 2001:db8:0:f103::20 peer 2001:db8:0:f103::10/128 scope global')
        self.assertRegex(output, 'inet6 fd[0-9a-f:]*1/64 scope global')

    def test_address_preferred_lifetime_zero_ipv6(self):
        self.copy_unit_to_networkd_unit_path('25-address-preferred-lifetime-zero-ipv6.network', '12-dummy.netdev')
        self.start_networkd()

        self.check_link_exists('dummy98')

        self.check_operstate('dummy98', 'routable', setup_state='configuring')

        output = subprocess.check_output(['ip', 'address', 'show', 'dummy98'], universal_newlines=True).rstrip()
        print(output)
        self.assertRegex(output, 'inet 10.2.3.4/16 brd 10.2.255.255 scope link deprecated dummy98')
        self.assertRegex(output, 'inet6 2001:db8:0:f101::1/64 scope global')

    def test_configure_without_carrier(self):
        self.copy_unit_to_networkd_unit_path('configure-without-carrier.network', '11-dummy.netdev')
        self.start_networkd()

        self.check_link_exists('test1')

        output = subprocess.check_output(['networkctl', 'status', 'test1'], universal_newlines=True).rstrip()
        print(output)
        self.assertRegex(output, '192.168.0.15')
        self.assertRegex(output, '192.168.0.1')
        self.assertRegex(output, 'routable')

    def test_routing_policy_rule(self):
        self.copy_unit_to_networkd_unit_path('routing-policy-rule-test1.network', '11-dummy.netdev')

        subprocess.call(['ip', 'rule', 'del', 'table', '7'])

        self.start_networkd()

        self.check_link_exists('test1')

        output = subprocess.check_output(['ip', 'rule'], universal_newlines=True).rstrip()
        print(output)
        self.assertRegex(output, '111')
        self.assertRegex(output, 'from 192.168.100.18')
        self.assertRegex(output, r'tos (?:0x08|throughput)\s')
        self.assertRegex(output, 'iif test1')
        self.assertRegex(output, 'oif test1')
        self.assertRegex(output, 'lookup 7')

        subprocess.call(['ip', 'rule', 'del', 'table', '7'])

    def test_routing_policy_rule_issue_11280(self):
        self.copy_unit_to_networkd_unit_path('routing-policy-rule-test1.network', '11-dummy.netdev',
                                             'routing-policy-rule-dummy98.network', '12-dummy.netdev')

        subprocess.call(['ip', 'rule', 'del', 'table', '7'])
        subprocess.call(['ip', 'rule', 'del', 'table', '8'])

        for trial in range(3):
            # Remove state files only first time
            self.start_networkd(remove_state_files=(trial == 0))

            self.check_link_exists('test1')
            self.check_link_exists('dummy98')

            output = subprocess.check_output(['ip', 'rule', 'list', 'table', '7'], universal_newlines=True).rstrip()
            print(output)
            self.assertRegex(output, '111:	from 192.168.100.18 tos (?:0x08|throughput) iif test1 oif test1 lookup 7')

            output = subprocess.check_output(['ip', 'rule', 'list', 'table', '8'], universal_newlines=True).rstrip()
            print(output)
            self.assertRegex(output, '112:	from 192.168.101.18 tos (?:0x08|throughput) iif dummy98 oif dummy98 lookup 8')

        subprocess.call(['ip', 'rule', 'del', 'table', '7'])
        subprocess.call(['ip', 'rule', 'del', 'table', '8'])

    @expectedFailureIfRoutingPolicyPortRangeIsNotAvailable()
    def test_routing_policy_rule_port_range(self):
        self.copy_unit_to_networkd_unit_path('25-fibrule-port-range.network', '11-dummy.netdev')

        subprocess.call(['ip', 'rule', 'del', 'table', '7'])

        self.start_networkd()

        self.check_link_exists('test1')

        output = subprocess.check_output(['ip', 'rule'], universal_newlines=True).rstrip()
        print(output)
        self.assertRegex(output, '111')
        self.assertRegex(output, 'from 192.168.100.18')
        self.assertRegex(output, '1123-1150')
        self.assertRegex(output, '3224-3290')
        self.assertRegex(output, 'tcp')
        self.assertRegex(output, 'lookup 7')

        subprocess.call(['ip', 'rule', 'del', 'table', '7'])

    @expectedFailureIfRoutingPolicyIPProtoIsNotAvailable()
    def test_routing_policy_rule_invert(self):
        self.copy_unit_to_networkd_unit_path('25-fibrule-invert.network', '11-dummy.netdev')

        subprocess.call(['ip', 'rule', 'del', 'table', '7'])

        self.start_networkd()

        self.check_link_exists('test1')

        output = subprocess.check_output(['ip', 'rule'], universal_newlines=True).rstrip()
        print(output)
        self.assertRegex(output, '111')
        self.assertRegex(output, 'not.*?from.*?192.168.100.18')
        self.assertRegex(output, 'tcp')
        self.assertRegex(output, 'lookup 7')

        subprocess.call(['ip', 'rule', 'del', 'table', '7'])

    def test_route_static(self):
        self.copy_unit_to_networkd_unit_path('25-route-static.network', '12-dummy.netdev')
        self.start_networkd(0)

        self.wait_online(['dummy98:routable'])

        output = subprocess.check_output(['ip', '-6', 'route', 'show', 'dev', 'dummy98'], universal_newlines=True).rstrip()
        print(output)
        self.assertRegex(output, '2001:1234:5:8fff:ff:ff:ff:ff proto static')
        self.assertRegex(output, '2001:1234:5:8f63::1 proto kernel')

        output = subprocess.check_output(['ip', '-6', 'route', 'show', 'dev', 'dummy98', 'default'], universal_newlines=True).rstrip()
        self.assertRegex(output, 'default via 2001:1234:5:8fff:ff:ff:ff:ff proto static metric 1024 pref medium')

        output = subprocess.check_output(['ip', '-4', 'route', 'show', 'dev', 'dummy98'], universal_newlines=True).rstrip()
        print(output)
        self.assertRegex(output, '149.10.124.48/28 proto kernel scope link src 149.10.124.58')
        self.assertRegex(output, '149.10.124.64 proto static scope link')
        self.assertRegex(output, '169.254.0.0/16 proto static scope link metric 2048')
        self.assertRegex(output, '192.168.1.1 proto static initcwnd 20')
        self.assertRegex(output, '192.168.1.2 proto static initrwnd 30')

        output = subprocess.check_output(['ip', '-4', 'route', 'show', 'dev', 'dummy98', 'default'], universal_newlines=True).rstrip()
        self.assertRegex(output, 'default via 149.10.125.65 proto static onlink')
        self.assertRegex(output, 'default via 149.10.124.64 proto static')
        self.assertRegex(output, 'default proto static')

        output = subprocess.check_output(['ip', 'route', 'show', 'type', 'blackhole'], universal_newlines=True).rstrip()
        print(output)
        self.assertRegex(output, 'blackhole 202.54.1.2 proto static')

        output = subprocess.check_output(['ip', 'route', 'show', 'type', 'unreachable'], universal_newlines=True).rstrip()
        print(output)
        self.assertRegex(output, 'unreachable 202.54.1.3 proto static')

        output = subprocess.check_output(['ip', 'route', 'show', 'type', 'prohibit'], universal_newlines=True).rstrip()
        print(output)
        self.assertRegex(output, 'prohibit 202.54.1.4 proto static')

        subprocess.call(['ip', 'route', 'del', 'blackhole', '202.54.1.2'])
        subprocess.call(['ip', 'route', 'del', 'unreachable', '202.54.1.3'])
        subprocess.call(['ip', 'route', 'del', 'prohibit', '202.54.1.4'])

    def test_ip_route_ipv6_src_route(self):
        # a dummy device does not make the addresses go through tentative state, so we
        # reuse a bond from an earlier test, which does make the addresses go through
        # tentative state, and do our test on that
        self.copy_unit_to_networkd_unit_path('23-active-slave.network', '25-route-ipv6-src.network', '25-bond-active-backup-slave.netdev', '12-dummy.netdev')
        self.start_networkd()

        self.check_link_exists('dummy98')
        self.check_link_exists('bond199')

        output = subprocess.check_output(['ip', '-6', 'route', 'list', 'dev', 'bond199'], universal_newlines=True).rstrip()
        print(output)
        self.assertRegex(output, 'abcd::/16')
        self.assertRegex(output, 'src')
        self.assertRegex(output, '2001:1234:56:8f63::2')

    def test_ip_link_mac_address(self):
        self.copy_unit_to_networkd_unit_path('25-address-link-section.network', '12-dummy.netdev')
        self.start_networkd()

        self.check_link_exists('dummy98')

        output = subprocess.check_output(['ip', 'link', 'show', 'dummy98'], universal_newlines=True).rstrip()
        print(output)
        self.assertRegex(output, '00:01:02:aa:bb:cc')

    def test_ip_link_unmanaged(self):
        self.copy_unit_to_networkd_unit_path('25-link-section-unmanaged.network', '12-dummy.netdev')
        self.start_networkd()

        self.check_link_exists('dummy98')

        output = subprocess.check_output(['networkctl', 'status', 'dummy98'], universal_newlines=True).rstrip()
        print(output)
        self.assertRegex(output, 'unmanaged')

    def test_ipv6_address_label(self):
        self.copy_unit_to_networkd_unit_path('25-ipv6-address-label-section.network', '12-dummy.netdev')
        self.start_networkd()

        self.check_link_exists('dummy98')

        output = subprocess.check_output(['ip', 'addrlabel', 'list'], universal_newlines=True).rstrip()
        print(output)
        self.assertRegex(output, '2004:da8:1::/64')

    def test_ipv6_neighbor(self):
        self.copy_unit_to_networkd_unit_path('25-neighbor-section.network', '12-dummy.netdev')
        self.start_networkd()

        self.check_link_exists('dummy98')

        output = subprocess.check_output(['ip', 'neigh', 'list'], universal_newlines=True).rstrip()
        print(output)
        self.assertRegex(output, '192.168.10.1.*00:00:5e:00:02:65.*PERMANENT')
        self.assertRegex(output, '2004:da8:1::1.*00:00:5e:00:02:66.*PERMANENT')

    def test_link_local_addressing(self):
        self.copy_unit_to_networkd_unit_path('25-link-local-addressing-yes.network', '11-dummy.netdev',
                                             '25-link-local-addressing-no.network', '12-dummy.netdev')
        self.start_networkd(0)
        self.wait_online(['test1:degraded', 'dummy98:carrier'])

        self.check_link_exists('test1')
        self.check_link_exists('dummy98')

        output = subprocess.check_output(['ip', 'address', 'show', 'dev', 'test1'], universal_newlines=True).rstrip()
        print(output)
        self.assertRegex(output, 'inet .* scope link')
        self.assertRegex(output, 'inet6 .* scope link')

        output = subprocess.check_output(['ip', 'address', 'show', 'dev', 'dummy98'], universal_newlines=True).rstrip()
        print(output)
        self.assertNotRegex(output, 'inet6* .* scope link')

        self.check_operstate('test1', 'degraded')
        self.check_operstate('dummy98', 'carrier')

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
            self.assertEqual(self.read_ipv6_sysctl_attr('test1', 'addr_gen_mode'), test1_addr_gen_mode)

        if os.path.exists(os.path.join(os.path.join(network_sysctl_ipv6_path, 'dummy98'), 'addr_gen_mode')):
            self.assertEqual(self.read_ipv6_sysctl_attr('dummy98', 'addr_gen_mode'), '1')

    def test_sysctl(self):
        self.copy_unit_to_networkd_unit_path('25-sysctl.network', '12-dummy.netdev')
        self.start_networkd(0)
        self.wait_online(['dummy98:degraded'])

        self.check_link_exists('dummy98')

        self.assertEqual(self.read_ipv6_sysctl_attr('dummy98', 'forwarding'), '1')
        self.assertEqual(self.read_ipv6_sysctl_attr('dummy98', 'use_tempaddr'), '2')
        self.assertEqual(self.read_ipv6_sysctl_attr('dummy98', 'dad_transmits'), '3')
        self.assertEqual(self.read_ipv6_sysctl_attr('dummy98', 'hop_limit'), '5')
        self.assertEqual(self.read_ipv6_sysctl_attr('dummy98', 'proxy_ndp'), '1')
        self.assertEqual(self.read_ipv4_sysctl_attr('dummy98', 'forwarding'),'1')
        self.assertEqual(self.read_ipv4_sysctl_attr('dummy98', 'proxy_arp'), '1')

    def test_sysctl_disable_ipv6(self):
        self.copy_unit_to_networkd_unit_path('25-sysctl-disable-ipv6.network', '12-dummy.netdev')

        print('## Disable ipv6')
        self.assertEqual(subprocess.call(['sysctl', 'net.ipv6.conf.all.disable_ipv6=1']), 0)
        self.assertEqual(subprocess.call(['sysctl', 'net.ipv6.conf.default.disable_ipv6=1']), 0)

        self.start_networkd(0)
        self.wait_online(['dummy98:routable'])

        self.check_link_exists('dummy98')

        output = subprocess.check_output(['ip', '-4', 'address', 'show', 'dummy98'], universal_newlines=True).rstrip()
        print(output)
        self.assertRegex(output, 'inet 10.2.3.4/16 brd 10.2.255.255 scope global dummy98')
        output = subprocess.check_output(['ip', '-6', 'address', 'show', 'dummy98'], universal_newlines=True).rstrip()
        print(output)
        self.assertEqual(output, '')
        self.check_operstate('dummy98', 'routable')

        self.assertEqual(subprocess.call(['ip', 'link', 'del', 'dummy98']), 0)

        print('## Enable ipv6')
        self.assertEqual(subprocess.call(['sysctl', 'net.ipv6.conf.all.disable_ipv6=0']), 0)
        self.assertEqual(subprocess.call(['sysctl', 'net.ipv6.conf.default.disable_ipv6=0']), 0)

        self.start_networkd(0)
        self.wait_online(['dummy98:routable'])

        self.check_link_exists('dummy98')

        output = subprocess.check_output(['ip', '-4', 'address', 'show', 'dummy98'], universal_newlines=True).rstrip()
        print(output)
        self.assertRegex(output, 'inet 10.2.3.4/16 brd 10.2.255.255 scope global dummy98')
        output = subprocess.check_output(['ip', '-6', 'address', 'show', 'dummy98'], universal_newlines=True).rstrip()
        print(output)
        self.assertRegex(output, 'inet6 .* scope link')
        self.check_operstate('dummy98', 'routable')

    def test_bind_carrier(self):
        self.copy_unit_to_networkd_unit_path('25-bind-carrier.network', '11-dummy.netdev')
        self.start_networkd()

        self.check_link_exists('test1')

        self.assertEqual(subprocess.call(['ip', 'link', 'add', 'dummy98', 'type', 'dummy']), 0)
        self.assertEqual(subprocess.call(['ip', 'link', 'set', 'dummy98', 'up']), 0)
        time.sleep(2)
        output = subprocess.check_output(['ip', 'address', 'show', 'test1'], universal_newlines=True).rstrip()
        print(output)
        self.assertRegex(output, 'UP,LOWER_UP')
        self.assertRegex(output, 'inet 192.168.10.30/24 brd 192.168.10.255 scope global test1')
        self.check_operstate('test1', 'routable')

        self.assertEqual(subprocess.call(['ip', 'link', 'add', 'dummy99', 'type', 'dummy']), 0)
        self.assertEqual(subprocess.call(['ip', 'link', 'set', 'dummy99', 'up']), 0)
        time.sleep(2)
        output = subprocess.check_output(['ip', 'address', 'show', 'test1'], universal_newlines=True).rstrip()
        print(output)
        self.assertRegex(output, 'UP,LOWER_UP')
        self.assertRegex(output, 'inet 192.168.10.30/24 brd 192.168.10.255 scope global test1')
        self.check_operstate('test1', 'routable')

        self.assertEqual(subprocess.call(['ip', 'link', 'del', 'dummy98']), 0)
        time.sleep(2)
        output = subprocess.check_output(['ip', 'address', 'show', 'test1'], universal_newlines=True).rstrip()
        print(output)
        self.assertRegex(output, 'UP,LOWER_UP')
        self.assertRegex(output, 'inet 192.168.10.30/24 brd 192.168.10.255 scope global test1')
        self.check_operstate('test1', 'routable')

        self.assertEqual(subprocess.call(['ip', 'link', 'del', 'dummy99']), 0)
        time.sleep(2)
        output = subprocess.check_output(['ip', 'address', 'show', 'test1'], universal_newlines=True).rstrip()
        print(output)
        self.assertNotRegex(output, 'UP,LOWER_UP')
        self.assertRegex(output, 'DOWN')
        self.assertNotRegex(output, '192.168.10')
        self.check_operstate('test1', 'off')

        self.assertEqual(subprocess.call(['ip', 'link', 'add', 'dummy98', 'type', 'dummy']), 0)
        self.assertEqual(subprocess.call(['ip', 'link', 'set', 'dummy98', 'up']), 0)
        time.sleep(2)
        output = subprocess.check_output(['ip', 'address', 'show', 'test1'], universal_newlines=True).rstrip()
        print(output)
        self.assertRegex(output, 'UP,LOWER_UP')
        self.assertRegex(output, 'inet 192.168.10.30/24 brd 192.168.10.255 scope global test1')
        self.check_operstate('test1', 'routable')

class NetworkdNetWorkBondTests(unittest.TestCase, Utilities):
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
        '23-test1-bond199.network',
        '25-bond-active-backup-slave.netdev',
        '25-bond.netdev',
        'bond99.network',
        'bond-slave.network']

    def setUp(self):
        self.link_remove(self.links)

    def tearDown(self):
        self.link_remove(self.links)
        self.remove_unit_from_networkd_path(self.units)

    def test_bond_active_slave(self):
        self.copy_unit_to_networkd_unit_path('23-active-slave.network', '23-bond199.network', '25-bond-active-backup-slave.netdev', '12-dummy.netdev')
        self.start_networkd()

        self.check_link_exists('dummy98')
        self.check_link_exists('bond199')

        output = subprocess.check_output(['ip', '-d', 'link', 'show', 'bond199'], universal_newlines=True).rstrip()
        print(output)
        self.assertRegex(output, 'active_slave dummy98')

    def test_bond_primary_slave(self):
        self.copy_unit_to_networkd_unit_path('23-primary-slave.network', '23-test1-bond199.network', '25-bond-active-backup-slave.netdev', '11-dummy.netdev')
        self.start_networkd()

        self.check_link_exists('test1')
        self.check_link_exists('bond199')

        output = subprocess.check_output(['ip', '-d', 'link', 'show', 'bond199'], universal_newlines=True).rstrip()
        print(output)
        self.assertRegex(output, 'primary test1')

    def test_bond_operstate(self):
        self.copy_unit_to_networkd_unit_path('25-bond.netdev', '11-dummy.netdev', '12-dummy.netdev',
                                             'bond99.network','bond-slave.network')
        self.start_networkd()

        self.check_link_exists('bond99')
        self.check_link_exists('dummy98')
        self.check_link_exists('test1')

        output = subprocess.check_output(['ip', '-d', 'link', 'show', 'dummy98'], universal_newlines=True).rstrip()
        print(output)
        self.assertRegex(output, 'SLAVE,UP,LOWER_UP')

        output = subprocess.check_output(['ip', '-d', 'link', 'show', 'test1'], universal_newlines=True).rstrip()
        print(output)
        self.assertRegex(output, 'SLAVE,UP,LOWER_UP')

        output = subprocess.check_output(['ip', '-d', 'link', 'show', 'bond99'], universal_newlines=True).rstrip()
        print(output)
        self.assertRegex(output, 'MASTER,UP,LOWER_UP')

        self.check_operstate('dummy98', 'enslaved')
        self.check_operstate('test1', 'enslaved')
        self.check_operstate('bond99', 'routable')

        self.assertEqual(subprocess.call(['ip', 'link', 'set', 'dummy98', 'down']), 0)
        time.sleep(2)

        self.check_operstate('dummy98', 'off')
        self.check_operstate('test1', 'enslaved')
        self.check_operstate('bond99', 'degraded-carrier')

        self.assertEqual(subprocess.call(['ip', 'link', 'set', 'dummy98', 'up']), 0)
        time.sleep(2)

        self.check_operstate('dummy98', 'enslaved')
        self.check_operstate('test1', 'enslaved')
        self.check_operstate('bond99', 'routable')

        self.assertEqual(subprocess.call(['ip', 'link', 'set', 'dummy98', 'down']), 0)
        self.assertEqual(subprocess.call(['ip', 'link', 'set', 'test1', 'down']), 0)
        time.sleep(2)

        self.check_operstate('dummy98', 'off')
        self.check_operstate('test1', 'off')

        bond_has_no_carrier=False
        for trial in range(30):
            if trial > 0:
                time.sleep(1)
            output = subprocess.check_output(['ip', 'address', 'show', 'bond99'], universal_newlines=True).rstrip()
            print(output)
            if self.get_operstate('bond99') == 'no-carrier':
                break
        else:
            # Huh? Kernel does not recognize that all slave interfaces are down?
            # Let's confirm that networkd's operstate is consistent with ip's result.
            self.assertNotRegex(output, 'NO-CARRIER')

class NetworkdNetWorkBridgeTests(unittest.TestCase, Utilities):
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
        'bridge99-ignore-carrier-loss.network',
        'bridge99.network']

    def setUp(self):
        self.link_remove(self.links)

    def tearDown(self):
        self.link_remove(self.links)
        self.remove_unit_from_networkd_path(self.units)

    def test_bridge_property(self):
        self.copy_unit_to_networkd_unit_path('11-dummy.netdev', '12-dummy.netdev', '26-bridge.netdev',
                                             '26-bridge-slave-interface-1.network', '26-bridge-slave-interface-2.network',
                                             'bridge99.network')
        self.start_networkd()

        self.check_link_exists('dummy98')
        self.check_link_exists('test1')
        self.check_link_exists('bridge99')

        output = subprocess.check_output(['ip', '-d', 'link', 'show', 'test1'], universal_newlines=True).rstrip()
        print(output)
        self.assertRegex(output, 'master')
        self.assertRegex(output, 'bridge')

        output = subprocess.check_output(['ip', '-d', 'link', 'show', 'dummy98'], universal_newlines=True).rstrip()
        print(output)
        self.assertRegex(output, 'master')
        self.assertRegex(output, 'bridge')

        output = subprocess.check_output(['ip', 'addr', 'show', 'bridge99'], universal_newlines=True).rstrip()
        print(output)
        self.assertRegex(output, '192.168.0.15/24')

        output = subprocess.check_output(['bridge', '-d', 'link', 'show', 'dummy98'], universal_newlines=True).rstrip()
        print(output)
        self.assertEqual(self.read_bridge_port_attr('bridge99', 'dummy98', 'hairpin_mode'), '1')
        self.assertEqual(self.read_bridge_port_attr('bridge99', 'dummy98', 'path_cost'), '400')
        self.assertEqual(self.read_bridge_port_attr('bridge99', 'dummy98', 'unicast_flood'), '1')
        self.assertEqual(self.read_bridge_port_attr('bridge99', 'dummy98', 'multicast_flood'), '0')
        self.assertEqual(self.read_bridge_port_attr('bridge99', 'dummy98', 'multicast_fast_leave'), '1')
        if (os.path.exists('/sys/devices/virtual/net/bridge99/lower_dummy98/brport/neigh_suppress')):
            self.assertEqual(self.read_bridge_port_attr('bridge99', 'dummy98', 'neigh_suppress'), '1')
        self.assertEqual(self.read_bridge_port_attr('bridge99', 'dummy98', 'learning'), '0')

        # CONFIG_BRIDGE_IGMP_SNOOPING=y
        if (os.path.exists('/sys/devices/virtual/net/bridge00/lower_dummy98/brport/multicast_to_unicast')):
            self.assertEqual(self.read_bridge_port_attr('bridge99', 'dummy98', 'multicast_to_unicast'), '1')

        self.check_operstate('test1', 'enslaved')
        self.check_operstate('dummy98', 'enslaved')
        self.check_operstate('bridge99', 'routable')

        self.assertEqual(subprocess.call(['ip', 'address', 'add', '192.168.0.16/24', 'dev', 'bridge99']), 0)
        time.sleep(1)

        output = subprocess.check_output(['ip', 'addr', 'show', 'bridge99'], universal_newlines=True).rstrip()
        print(output)
        self.assertRegex(output, '192.168.0.16/24')

        self.check_operstate('bridge99', 'routable')

        self.assertEqual(subprocess.call(['ip', 'link', 'del', 'test1']), 0)
        time.sleep(3)

        self.check_operstate('bridge99', 'degraded-carrier')

        self.assertEqual(subprocess.call(['ip', 'link', 'del', 'dummy98']), 0)
        time.sleep(3)

        self.check_operstate('bridge99', 'no-carrier')

        output = subprocess.check_output(['ip', 'address', 'show', 'bridge99'], universal_newlines=True).rstrip()
        print(output)
        self.assertRegex(output, 'NO-CARRIER')
        self.assertNotRegex(output, '192.168.0.15/24')
        self.assertNotRegex(output, '192.168.0.16/24')

    def test_bridge_ignore_carrier_loss(self):
        self.copy_unit_to_networkd_unit_path('11-dummy.netdev', '12-dummy.netdev', '26-bridge.netdev',
                                             '26-bridge-slave-interface-1.network', '26-bridge-slave-interface-2.network',
                                             'bridge99-ignore-carrier-loss.network')

        subprocess.call(['ip', 'rule', 'del', 'table', '100'])

        self.start_networkd()

        self.check_link_exists('dummy98')
        self.check_link_exists('test1')
        self.check_link_exists('bridge99')

        self.assertEqual(subprocess.call(['ip', 'address', 'add', '192.168.0.16/24', 'dev', 'bridge99']), 0)
        time.sleep(1)

        self.assertEqual(subprocess.call(['ip', 'link', 'del', 'test1']), 0)
        self.assertEqual(subprocess.call(['ip', 'link', 'del', 'dummy98']), 0)
        time.sleep(3)

        output = subprocess.check_output(['ip', 'address', 'show', 'bridge99'], universal_newlines=True).rstrip()
        print(output)
        self.assertRegex(output, 'NO-CARRIER')
        self.assertRegex(output, 'inet 192.168.0.15/24 brd 192.168.0.255 scope global bridge99')
        self.assertRegex(output, 'inet 192.168.0.16/24 scope global secondary bridge99')

        subprocess.call(['ip', 'rule', 'del', 'table', '100'])

    def test_bridge_ignore_carrier_loss_frequent_loss_and_gain(self):
        self.copy_unit_to_networkd_unit_path('26-bridge.netdev', '26-bridge-slave-interface-1.network',
                                             'bridge99-ignore-carrier-loss.network')

        subprocess.call(['ip', 'rule', 'del', 'table', '100'])

        self.start_networkd()

        self.check_link_exists('bridge99')

        self.assertEqual(subprocess.call(['ip', 'link', 'add', 'dummy98', 'type', 'dummy']), 0)
        self.assertEqual(subprocess.call(['ip', 'link', 'set', 'dummy98', 'up']), 0)
        self.assertEqual(subprocess.call(['ip', 'link', 'del', 'dummy98']), 0)

        self.assertEqual(subprocess.call(['ip', 'link', 'add', 'dummy98', 'type', 'dummy']), 0)
        self.assertEqual(subprocess.call(['ip', 'link', 'set', 'dummy98', 'up']), 0)
        self.assertEqual(subprocess.call(['ip', 'link', 'del', 'dummy98']), 0)

        self.assertEqual(subprocess.call(['ip', 'link', 'add', 'dummy98', 'type', 'dummy']), 0)
        self.assertEqual(subprocess.call(['ip', 'link', 'set', 'dummy98', 'up']), 0)
        self.assertEqual(subprocess.call(['ip', 'link', 'del', 'dummy98']), 0)

        self.assertEqual(subprocess.call(['ip', 'link', 'add', 'dummy98', 'type', 'dummy']), 0)
        self.assertEqual(subprocess.call(['ip', 'link', 'set', 'dummy98', 'up']), 0)

        time.sleep(3)

        output = subprocess.check_output(['ip', 'address', 'show', 'bridge99'], universal_newlines=True).rstrip()
        print(output)
        self.assertRegex(output, 'inet 192.168.0.15/24 brd 192.168.0.255 scope global bridge99')

        self.check_operstate('bridge99', 'routable')
        self.check_operstate('dummy98', 'enslaved')

        output = subprocess.check_output(['ip', 'rule', 'list', 'table', '100'], universal_newlines=True).rstrip()
        print(output)
        self.assertEqual(output, '0:	from all to 8.8.8.8 lookup 100')

        subprocess.call(['ip', 'rule', 'del', 'table', '100'])

class NetworkdNetWorkLLDPTests(unittest.TestCase, Utilities):
    links = ['veth99']

    units = [
        '23-emit-lldp.network',
        '24-lldp.network',
        '25-veth.netdev']

    def setUp(self):
        self.link_remove(self.links)

    def tearDown(self):
        self.link_remove(self.links)
        self.remove_unit_from_networkd_path(self.units)

    def test_lldp(self):
        self.copy_unit_to_networkd_unit_path('23-emit-lldp.network', '24-lldp.network', '25-veth.netdev')
        self.start_networkd()

        self.check_link_exists('veth99')

        output = subprocess.check_output(['networkctl', 'lldp'], universal_newlines=True).rstrip()
        print(output)
        self.assertRegex(output, 'veth-peer')
        self.assertRegex(output, 'veth99')

class NetworkdNetworkRATests(unittest.TestCase, Utilities):
    links = ['veth99']

    units = [
        '25-veth.netdev',
        'ipv6-prefix.network',
        'ipv6-prefix-veth.network']

    def setUp(self):
        self.link_remove(self.links)

    def tearDown(self):
        self.link_remove(self.links)
        self.remove_unit_from_networkd_path(self.units)

    def test_ipv6_prefix_delegation(self):
        self.copy_unit_to_networkd_unit_path('25-veth.netdev', 'ipv6-prefix.network', 'ipv6-prefix-veth.network')
        self.start_networkd()

        self.check_link_exists('veth99')

        output = subprocess.check_output(['networkctl', 'status', 'veth99'], universal_newlines=True).rstrip()
        print(output)
        self.assertRegex(output, '2002:da8:1:0')

class NetworkdNetworkDHCPServerTests(unittest.TestCase, Utilities):
    links = [
        'dummy98',
        'veth99']

    units = [
        '12-dummy.netdev',
        '24-search-domain.network',
        '25-veth.netdev',
        'dhcp-client.network',
        'dhcp-client-timezone-router.network',
        'dhcp-server.network',
        'dhcp-server-timezone-router.network']

    def setUp(self):
        self.link_remove(self.links)

    def tearDown(self):
        self.link_remove(self.links)
        self.remove_unit_from_networkd_path(self.units)

    def test_dhcp_server(self):
        self.copy_unit_to_networkd_unit_path('25-veth.netdev', 'dhcp-client.network', 'dhcp-server.network')
        self.start_networkd()

        self.check_link_exists('veth99')

        output = subprocess.check_output(['networkctl', 'status', 'veth99'], universal_newlines=True).rstrip()
        print(output)
        self.assertRegex(output, '192.168.5.*')
        self.assertRegex(output, 'Gateway: 192.168.5.1')
        self.assertRegex(output, 'DNS: 192.168.5.1')
        self.assertRegex(output, 'NTP: 192.168.5.1')

    def test_domain(self):
        self.copy_unit_to_networkd_unit_path('12-dummy.netdev', '24-search-domain.network')
        self.start_networkd()

        self.check_link_exists('dummy98')

        output = subprocess.check_output(['networkctl', 'status', 'dummy98'], universal_newlines=True).rstrip()
        print(output)
        self.assertRegex(output, 'Address: 192.168.42.100')
        self.assertRegex(output, 'DNS: 192.168.42.1')
        self.assertRegex(output, 'Search Domains: one')

    def test_emit_router_timezone(self):
        self.copy_unit_to_networkd_unit_path('25-veth.netdev', 'dhcp-client-timezone-router.network', 'dhcp-server-timezone-router.network')
        self.start_networkd()

        self.check_link_exists('veth99')

        output = subprocess.check_output(['networkctl', 'status', 'veth99'], universal_newlines=True).rstrip()
        print(output)
        self.assertRegex(output, 'Gateway: 192.168.5.*')
        self.assertRegex(output, '192.168.5.*')
        self.assertRegex(output, 'Europe/Berlin')

class NetworkdNetworkDHCPClientTests(unittest.TestCase, Utilities):
    links = [
        'dummy98',
        'veth99',
        'vrf99']

    units = [
        '25-veth.netdev',
        '25-vrf.netdev',
        '25-vrf.network',
        'dhcp-client-anonymize.network',
        'dhcp-client-critical-connection.network',
        'dhcp-client-gateway-onlink-implicit.network',
        'dhcp-client-ipv4-dhcp-settings.network',
        'dhcp-client-ipv4-only-ipv6-disabled.network',
        'dhcp-client-ipv4-only.network',
        'dhcp-client-ipv6-only.network',
        'dhcp-client-ipv6-rapid-commit.network',
        'dhcp-client-listen-port.network',
        'dhcp-client-route-metric.network',
        'dhcp-client-route-table.network',
        'dhcp-client-vrf.network',
        'dhcp-client-with-ipv4ll-fallback-with-dhcp-server.network',
        'dhcp-client-with-ipv4ll-fallback-without-dhcp-server.network',
        'dhcp-client.network',
        'dhcp-server-veth-peer.network',
        'dhcp-v4-server-veth-peer.network',
        'static.network']

    def setUp(self):
        self.link_remove(self.links)
        self.stop_dnsmasq(dnsmasq_pid_file)

    def tearDown(self):
        self.link_remove(self.links)
        self.remove_unit_from_networkd_path(self.units)
        self.stop_dnsmasq(dnsmasq_pid_file)
        self.remove_lease_file()
        self.remove_log_file()

    def test_dhcp_client_ipv6_only(self):
        self.copy_unit_to_networkd_unit_path('25-veth.netdev', 'dhcp-server-veth-peer.network', 'dhcp-client-ipv6-only.network')

        self.start_networkd(0)
        self.wait_online(['veth-peer:carrier'])
        self.start_dnsmasq()
        self.wait_online(['veth99:routable', 'veth-peer:routable'])

        output = subprocess.check_output(['networkctl', 'status', 'veth99'], universal_newlines=True).rstrip()
        print(output)
        self.assertRegex(output, '2600::')
        self.assertNotRegex(output, '192.168.5')

        # Confirm that ipv6 token is not set in the kernel
        output = subprocess.check_output(['ip', 'token', 'show', 'dev', 'veth99'], universal_newlines=True).rstrip()
        print(output)
        self.assertRegex(output, 'token :: dev veth99')

    def test_dhcp_client_ipv4_only(self):
        self.copy_unit_to_networkd_unit_path('25-veth.netdev', 'dhcp-server-veth-peer.network', 'dhcp-client-ipv4-only-ipv6-disabled.network')
        self.start_networkd()

        self.check_link_exists('veth99')

        self.start_dnsmasq()

        output = subprocess.check_output(['networkctl', 'status', 'veth99'], universal_newlines=True).rstrip()
        print(output)
        self.assertNotRegex(output, '2600::')
        self.assertRegex(output, '192.168.5')

    def test_dhcp_client_ipv4_ipv6(self):
        self.copy_unit_to_networkd_unit_path('25-veth.netdev', 'dhcp-server-veth-peer.network', 'dhcp-client-ipv6-only.network',
                                             'dhcp-client-ipv4-only.network')
        self.start_networkd()

        self.check_link_exists('veth99')

        self.start_dnsmasq()

        output = subprocess.check_output(['networkctl', 'status', 'veth99'], universal_newlines=True).rstrip()
        print(output)
        self.assertRegex(output, '2600::')
        self.assertRegex(output, '192.168.5')

    def test_dhcp_client_settings(self):
        self.copy_unit_to_networkd_unit_path('25-veth.netdev', 'dhcp-server-veth-peer.network', 'dhcp-client-ipv4-dhcp-settings.network')
        self.start_networkd()

        self.check_link_exists('veth99')

        self.start_dnsmasq()

        print('## ip address show dev veth99')
        output = subprocess.check_output(['ip', 'address', 'show', 'dev', 'veth99'], universal_newlines=True).rstrip()
        print(output)
        self.assertRegex(output, '12:34:56:78:9a:bc')
        self.assertRegex(output, '192.168.5')
        self.assertRegex(output, '1492')

        # issue #8726
        print('## ip route show table main dev veth99')
        output = subprocess.check_output(['ip', 'route', 'show', 'table', 'main', 'dev', 'veth99'], universal_newlines=True).rstrip()
        print(output)
        self.assertNotRegex(output, 'proto dhcp')

        print('## ip route show table 211 dev veth99')
        output = subprocess.check_output(['ip', 'route', 'show', 'table', '211', 'dev', 'veth99'], universal_newlines=True).rstrip()
        print(output)
        self.assertRegex(output, 'default via 192.168.5.1 proto dhcp')
        self.assertRegex(output, '192.168.5.0/24 via 192.168.5.5 proto dhcp')
        self.assertRegex(output, '192.168.5.1 proto dhcp scope link')

        print('## dnsmasq log')
        self.assertTrue(self.search_words_in_dnsmasq_log('vendor class: SusantVendorTest', True))
        self.assertTrue(self.search_words_in_dnsmasq_log('DHCPDISCOVER(veth-peer) 12:34:56:78:9a:bc'))
        self.assertTrue(self.search_words_in_dnsmasq_log('client provides name: test-hostname'))
        self.assertTrue(self.search_words_in_dnsmasq_log('26:mtu'))

    def test_dhcp6_client_settings_rapidcommit_true(self):
        self.copy_unit_to_networkd_unit_path('25-veth.netdev', 'dhcp-server-veth-peer.network', 'dhcp-client-ipv6-only.network')
        self.start_networkd()

        self.check_link_exists('veth99')

        self.start_dnsmasq()

        output = subprocess.check_output(['ip', 'address', 'show', 'dev', 'veth99'], universal_newlines=True).rstrip()
        print(output)
        self.assertRegex(output, '12:34:56:78:9a:bc')
        self.assertTrue(self.search_words_in_dnsmasq_log('14:rapid-commit', True))

    def test_dhcp6_client_settings_rapidcommit_false(self):
        self.copy_unit_to_networkd_unit_path('25-veth.netdev', 'dhcp-server-veth-peer.network', 'dhcp-client-ipv6-rapid-commit.network')
        self.start_networkd()

        self.check_link_exists('veth99')

        self.start_dnsmasq()

        output = subprocess.check_output(['ip', 'address', 'show', 'dev', 'veth99'], universal_newlines=True).rstrip()
        print(output)
        self.assertRegex(output, '12:34:56:78:9a:bc')
        self.assertFalse(self.search_words_in_dnsmasq_log('14:rapid-commit', True))

    def test_dhcp_client_settings_anonymize(self):
        self.copy_unit_to_networkd_unit_path('25-veth.netdev', 'dhcp-server-veth-peer.network', 'dhcp-client-anonymize.network')
        self.start_networkd()

        self.check_link_exists('veth99')

        self.start_dnsmasq()

        self.assertFalse(self.search_words_in_dnsmasq_log('VendorClassIdentifier=SusantVendorTest', True))
        self.assertFalse(self.search_words_in_dnsmasq_log('test-hostname'))
        self.assertFalse(self.search_words_in_dnsmasq_log('26:mtu'))

    def test_dhcp_client_listen_port(self):
        self.copy_unit_to_networkd_unit_path('25-veth.netdev', 'dhcp-server-veth-peer.network', 'dhcp-client-listen-port.network')
        self.start_networkd()

        self.check_link_exists('veth99')

        self.start_dnsmasq('--dhcp-alternate-port=67,5555')

        output = subprocess.check_output(['ip', '-4', 'address', 'show', 'dev', 'veth99'], universal_newlines=True).rstrip()
        print(output)
        self.assertRegex(output, '192.168.5.* dynamic')

    def test_dhcp_route_table_id(self):
        self.copy_unit_to_networkd_unit_path('25-veth.netdev', 'dhcp-v4-server-veth-peer.network', 'dhcp-client-route-table.network')
        self.start_networkd()

        self.check_link_exists('veth99')

        self.start_dnsmasq()

        output = subprocess.check_output(['ip', 'route', 'show', 'table', '12'], universal_newlines=True).rstrip()
        print(output)
        self.assertRegex(output, 'veth99 proto dhcp')
        self.assertRegex(output, '192.168.5.1')

    def test_dhcp_route_metric(self):
        self.copy_unit_to_networkd_unit_path('25-veth.netdev', 'dhcp-v4-server-veth-peer.network', 'dhcp-client-route-metric.network')
        self.start_networkd()

        self.check_link_exists('veth99')

        self.start_dnsmasq()

        output = subprocess.check_output(['ip', 'route', 'show', 'dev', 'veth99'], universal_newlines=True).rstrip()
        print(output)
        self.assertRegex(output, 'metric 24')

    def test_dhcp_route_criticalconnection_true(self):
        self.copy_unit_to_networkd_unit_path('25-veth.netdev', 'dhcp-v4-server-veth-peer.network', 'dhcp-client-critical-connection.network')
        self.start_networkd()

        self.check_link_exists('veth99')

        self.start_dnsmasq()

        output = subprocess.check_output(['networkctl', 'status', 'veth99'], universal_newlines=True).rstrip()
        print(output)
        self.assertRegex(output, '192.168.5.*')

        # Stopping dnsmasq as networkd won't be allowed to renew the DHCP lease.
        self.stop_dnsmasq(dnsmasq_pid_file)

        # Sleep for 120 sec as the dnsmasq minimum lease time can only be set to 120
        time.sleep(125)

        output = subprocess.check_output(['networkctl', 'status', 'veth99'], universal_newlines=True).rstrip()
        print(output)
        self.assertRegex(output, '192.168.5.*')

    def test_dhcp_client_reuse_address_as_static(self):
        self.copy_unit_to_networkd_unit_path('25-veth.netdev', 'dhcp-server-veth-peer.network', 'dhcp-client.network')
        self.start_networkd()

        self.check_link_exists('veth99')

        self.start_dnsmasq()

        output = subprocess.check_output(['ip', 'address', 'show', 'dev', 'veth99', 'scope', 'global'], universal_newlines=True).rstrip()
        print(output)
        self.assertRegex(output, '192.168.5')
        self.assertRegex(output, '2600::')

        ipv4_address = re.search('192\.168\.5\.[0-9]*/24', output)
        ipv6_address = re.search('2600::[0-9a-f:]*/128', output)
        static_network = '\n'.join(['[Match]', 'Name=veth99', '[Network]', 'IPv6AcceptRA=no', 'Address=' + ipv4_address.group(), 'Address=' + ipv6_address.group()])
        print(static_network)

        self.remove_unit_from_networkd_path(['dhcp-client.network'])

        with open(os.path.join(network_unit_file_path, 'static.network'), mode='w') as f:
            f.write(static_network)

        self.start_networkd()

        self.check_link_exists('veth99')

        output = subprocess.check_output(['ip', '-4', 'address', 'show', 'dev', 'veth99', 'scope', 'global'], universal_newlines=True).rstrip()
        print(output)
        self.assertRegex(output, '192.168.5')
        self.assertRegex(output, 'valid_lft forever preferred_lft forever')

        output = subprocess.check_output(['ip', '-6', 'address', 'show', 'dev', 'veth99', 'scope', 'global'], universal_newlines=True).rstrip()
        print(output)
        self.assertRegex(output, '2600::')
        self.assertRegex(output, 'valid_lft forever preferred_lft forever')

    @expectedFailureIfModuleIsNotAvailable('vrf')
    def test_dhcp_client_vrf(self):
        self.copy_unit_to_networkd_unit_path('25-veth.netdev', 'dhcp-server-veth-peer.network', 'dhcp-client-vrf.network',
                                             '25-vrf.netdev', '25-vrf.network')
        self.start_networkd()

        self.check_link_exists('veth99')
        self.check_link_exists('vrf99')

        self.start_dnsmasq()

        print('## ip -d link show dev vrf99')
        output = subprocess.check_output(['ip', '-d', 'link', 'show', 'dev', 'vrf99'], universal_newlines=True).rstrip()
        print(output)
        self.assertRegex(output, 'vrf table 42')

        print('## ip address show vrf vrf99')
        output_ip_vrf = subprocess.check_output(['ip', 'address', 'show', 'vrf', 'vrf99'], universal_newlines=True).rstrip()
        print(output_ip_vrf)

        print('## ip address show dev veth99')
        output = subprocess.check_output(['ip', 'address', 'show', 'dev', 'veth99'], universal_newlines=True).rstrip()
        print(output)
        self.assertEqual(output, output_ip_vrf)
        self.assertRegex(output, 'inet 169.254.[0-9]*.[0-9]*/16 brd 169.254.255.255 scope link veth99')
        self.assertRegex(output, 'inet 192.168.5.[0-9]*/24 brd 192.168.5.255 scope global dynamic veth99')
        self.assertRegex(output, 'inet6 2600::[0-9a-f]*/128 scope global dynamic noprefixroute')
        self.assertRegex(output, 'inet6 .* scope link')

        print('## ip route show vrf vrf99')
        output = subprocess.check_output(['ip', 'route', 'show', 'vrf', 'vrf99'], universal_newlines=True).rstrip()
        print(output)
        self.assertRegex(output, 'default via 192.168.5.1 dev veth99 proto dhcp src 192.168.5.')
        self.assertRegex(output, 'default dev veth99 proto static scope link')
        self.assertRegex(output, '169.254.0.0/16 dev veth99 proto kernel scope link src 169.254')
        self.assertRegex(output, '192.168.5.0/24 dev veth99 proto kernel scope link src 192.168.5')
        self.assertRegex(output, '192.168.5.0/24 via 192.168.5.5 dev veth99 proto dhcp')
        self.assertRegex(output, '192.168.5.1 dev veth99 proto dhcp scope link src 192.168.5')

        print('## ip route show table main dev veth99')
        output = subprocess.check_output(['ip', 'route', 'show', 'table', 'main', 'dev', 'veth99'], universal_newlines=True).rstrip()
        print(output)
        self.assertEqual(output, '')

        self.check_operstate('vrf99', 'carrier')
        self.check_operstate('veth99', 'routable')

    def test_dhcp_client_gateway_onlink_implicit(self):
        self.copy_unit_to_networkd_unit_path('25-veth.netdev', 'dhcp-server-veth-peer.network',
                                             'dhcp-client-gateway-onlink-implicit.network')
        self.start_networkd()

        self.check_link_exists('veth99')

        self.start_dnsmasq()

        output = subprocess.check_output(['networkctl', 'status', 'veth99'], universal_newlines=True).rstrip()
        print(output)
        self.assertRegex(output, '192.168.5')

        output = subprocess.check_output(['ip', 'route', 'list', 'dev', 'veth99', '10.0.0.0/8'], universal_newlines=True).rstrip()
        print(output)
        self.assertRegex(output, 'onlink')
        output = subprocess.check_output(['ip', 'route', 'list', 'dev', 'veth99', '192.168.100.0/24'], universal_newlines=True).rstrip()
        print(output)
        self.assertRegex(output, 'onlink')

    def test_dhcp_client_with_ipv4ll_fallback_with_dhcp_server(self):
        self.copy_unit_to_networkd_unit_path('25-veth.netdev', 'dhcp-server-veth-peer.network',
                                             'dhcp-client-with-ipv4ll-fallback-with-dhcp-server.network')
        self.start_networkd(0)
        self.wait_online(['veth-peer:carrier'])
        self.start_dnsmasq(lease_time='2m')
        self.wait_online(['veth99:routable', 'veth-peer:routable'])

        output = subprocess.check_output(['ip', 'address', 'show', 'dev', 'veth99'], universal_newlines=True).rstrip()
        print(output)

        output = subprocess.check_output(['ip', '-6', 'address', 'show', 'dev', 'veth99', 'scope', 'global', 'dynamic'], universal_newlines=True).rstrip()
        self.assertNotRegex(output, 'inet6 2600::[0-9a-f]*/128 scope global dynamic')
        output = subprocess.check_output(['ip', '-6', 'address', 'show', 'dev', 'veth99', 'scope', 'link'], universal_newlines=True).rstrip()
        self.assertRegex(output, 'inet6 .* scope link')
        output = subprocess.check_output(['ip', '-4', 'address', 'show', 'dev', 'veth99', 'scope', 'global', 'dynamic'], universal_newlines=True).rstrip()
        self.assertRegex(output, 'inet 192.168.5.[0-9]*/24 brd 192.168.5.255 scope global dynamic veth99')
        output = subprocess.check_output(['ip', '-4', 'address', 'show', 'dev', 'veth99', 'scope', 'link'], universal_newlines=True).rstrip()
        self.assertNotRegex(output, 'inet .* scope link')

        print('Wait for the dynamic address to be expired')
        time.sleep(130)

        output = subprocess.check_output(['ip', 'address', 'show', 'dev', 'veth99'], universal_newlines=True).rstrip()
        print(output)

        output = subprocess.check_output(['ip', '-6', 'address', 'show', 'dev', 'veth99', 'scope', 'global', 'dynamic'], universal_newlines=True).rstrip()
        self.assertNotRegex(output, 'inet6 2600::[0-9a-f]*/128 scope global dynamic')
        output = subprocess.check_output(['ip', '-6', 'address', 'show', 'dev', 'veth99', 'scope', 'link'], universal_newlines=True).rstrip()
        self.assertRegex(output, 'inet6 .* scope link')
        output = subprocess.check_output(['ip', '-4', 'address', 'show', 'dev', 'veth99', 'scope', 'global', 'dynamic'], universal_newlines=True).rstrip()
        self.assertRegex(output, 'inet 192.168.5.[0-9]*/24 brd 192.168.5.255 scope global dynamic veth99')
        output = subprocess.check_output(['ip', '-4', 'address', 'show', 'dev', 'veth99', 'scope', 'link'], universal_newlines=True).rstrip()
        self.assertNotRegex(output, 'inet .* scope link')

        self.search_words_in_dnsmasq_log('DHCPOFFER', show_all=True)

    def test_dhcp_client_with_ipv4ll_fallback_without_dhcp_server(self):
        self.copy_unit_to_networkd_unit_path('25-veth.netdev', 'dhcp-server-veth-peer.network',
                                             'dhcp-client-with-ipv4ll-fallback-without-dhcp-server.network')
        self.start_networkd(0)
        self.wait_online(['veth99:degraded', 'veth-peer:routable'])

        output = subprocess.check_output(['ip', 'address', 'show', 'dev', 'veth99'], universal_newlines=True).rstrip()
        print(output)

        output = subprocess.check_output(['ip', '-6', 'address', 'show', 'dev', 'veth99', 'scope', 'global', 'dynamic'], universal_newlines=True).rstrip()
        self.assertNotRegex(output, 'inet6 2600::[0-9a-f]*/128 scope global dynamic')
        output = subprocess.check_output(['ip', '-6', 'address', 'show', 'dev', 'veth99', 'scope', 'link'], universal_newlines=True).rstrip()
        self.assertRegex(output, 'inet6 .* scope link')
        output = subprocess.check_output(['ip', '-4', 'address', 'show', 'dev', 'veth99', 'scope', 'global', 'dynamic'], universal_newlines=True).rstrip()
        self.assertNotRegex(output, 'inet 192.168.5.[0-9]*/24 brd 192.168.5.255 scope global dynamic veth99')
        output = subprocess.check_output(['ip', '-4', 'address', 'show', 'dev', 'veth99', 'scope', 'link'], universal_newlines=True).rstrip()
        self.assertRegex(output, 'inet .* scope link')

if __name__ == '__main__':
    unittest.main(testRunner=unittest.TextTestRunner(stream=sys.stdout,
                                                     verbosity=3))
