#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# networkd integration test
# This uses temporary configuration in /run and temporary veth devices, and
# does not write anything on disk or change any system configuration;
# but it assumes (and checks at the beginning) that networkd is not currently
# running.
#
# This can be run on a normal installation, in qemu, systemd-nspawn (with
# --private-network), LXD (with "--config raw.lxc=lxc.aa_profile=unconfined"),
# or LXC system containers. You need at least the "ip" tool from the iproute
# package; it is recommended to install dnsmasq too to get full test coverage.
#
# ATTENTION: This uses the *installed* networkd, not the one from the built
# source tree.
#
# © 2015 Canonical Ltd.
# Author: Martin Pitt <martin.pitt@ubuntu.com>

import errno
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import unittest

HAVE_DNSMASQ = shutil.which('dnsmasq') is not None
IS_CONTAINER = subprocess.call(['systemd-detect-virt', '--quiet', '--container']) == 0

NETWORK_UNITDIR = '/run/systemd/network'

NETWORKD_WAIT_ONLINE = shutil.which('systemd-networkd-wait-online',
                                    path='/usr/lib/systemd:/lib/systemd')

RESOLV_CONF = '/run/systemd/resolve/resolv.conf'

tmpmounts = []
running_units = []
stopped_units = []


def setUpModule():
    global tmpmounts

    """Initialize the environment, and perform sanity checks on it."""
    if NETWORKD_WAIT_ONLINE is None:
        raise OSError(errno.ENOENT, 'systemd-networkd-wait-online not found')

    # Do not run any tests if the system is using networkd already and it's not virtualized
    if (subprocess.call(['systemctl', 'is-active', '--quiet', 'systemd-networkd.service']) == 0 and
            subprocess.call(['systemd-detect-virt', '--quiet']) != 0):
        raise unittest.SkipTest('not virtualized and networkd is already active')

    # Ensure we don't mess with an existing networkd config
    for u in ['systemd-networkd.socket', 'systemd-networkd', 'systemd-resolved']:
        if subprocess.call(['systemctl', 'is-active', '--quiet', u]) == 0:
            subprocess.call(['systemctl', 'stop', u])
            running_units.append(u)
        else:
            stopped_units.append(u)

    # Generate debugging logs.
    os.makedirs('/run/systemd/system/systemd-networkd.service.d', exist_ok=True)
    with open(f'/run/systemd/system/systemd-networkd.service.d/00-debug.conf', mode='w', encoding='utf-8') as f:
        f.write('[Service]\nEnvironment=SYSTEMD_LOG_LEVEL=debug\n')

    subprocess.call(['systemctl', 'daemon-reload'])

    # create static systemd-network user for networkd-test-router.service (it
    # needs to do some stuff as root and can't start as user; but networkd
    # still insists on the user)
    if subprocess.call(['getent', 'passwd', 'systemd-network']) != 0:
        subprocess.call(['useradd', '--system', '--no-create-home', 'systemd-network'])

    for d in ['/etc/systemd/network', '/run/systemd/network',
              '/run/systemd/netif', '/run/systemd/resolve']:
        if os.path.isdir(d):
            subprocess.check_call(["mount", "-t", "tmpfs", "none", d])
            tmpmounts.append(d)
    if os.path.isdir('/run/systemd/resolve'):
        os.chmod('/run/systemd/resolve', 0o755)
        shutil.chown('/run/systemd/resolve', 'systemd-resolve', 'systemd-resolve')
    if os.path.isdir('/run/systemd/netif'):
        os.chmod('/run/systemd/netif', 0o755)
        shutil.chown('/run/systemd/netif', 'systemd-network', 'systemd-network')

    # Avoid "Failed to open /dev/tty" errors in containers.
    os.environ['SYSTEMD_LOG_TARGET'] = 'journal'

    # Ensure the unit directory exists so tests can dump files into it.
    os.makedirs(NETWORK_UNITDIR, exist_ok=True)

    # mask all default .network files
    if os.path.exists('/usr/lib/systemd/network'):
        for unit in os.listdir('/usr/lib/systemd/network'):
            if unit.endswith('.network'):
                os.symlink('/dev/null', os.path.join(NETWORK_UNITDIR, unit))


def tearDownModule():
    global tmpmounts
    for d in tmpmounts:
        subprocess.check_call(["umount", "--lazy", d])
    for u in stopped_units:
        subprocess.call(["systemctl", "stop", u])
    for u in running_units:
        subprocess.call(["systemctl", "restart", u])


class NetworkdTestingUtilities:
    """Provide a set of utility functions to facilitate networkd tests.

    This class must be inherited along with unittest.TestCase to define
    some required methods.
    """

    def add_veth_pair(self, veth, peer, veth_options=(), peer_options=()):
        """Add a veth interface pair, and queue them to be removed."""
        subprocess.check_call(['ip', 'link', 'add', 'name', veth] +
                              list(veth_options) +
                              ['type', 'veth', 'peer', 'name', peer] +
                              list(peer_options))
        self.addCleanup(subprocess.call, ['ip', 'link', 'del', 'dev', peer])

    def write_config(self, path, contents):
        """"Write a configuration file, and queue it to be removed."""

        with open(path, 'w') as f:
            f.write(contents)

        self.addCleanup(os.remove, path)

    def write_network(self, unit_name, contents):
        """Write a network unit file, and queue it to be removed."""
        self.write_config(os.path.join(NETWORK_UNITDIR, unit_name), contents)

    def write_network_dropin(self, unit_name, dropin_name, contents):
        """Write a network unit drop-in, and queue it to be removed."""
        dropin_dir = os.path.join(NETWORK_UNITDIR, "{}.d".format(unit_name))
        dropin_path = os.path.join(dropin_dir, "{}.conf".format(dropin_name))

        os.makedirs(dropin_dir, exist_ok=True)
        self.addCleanup(os.rmdir, dropin_dir)
        with open(dropin_path, 'w') as dropin:
            dropin.write(contents)
        self.addCleanup(os.remove, dropin_path)

    def read_attr(self, link, attribute):
        """Read a link attributed from the sysfs."""
        # Note we don't want to check if interface `link' is managed, we
        # want to evaluate link variable and pass the value of the link to
        # assert_link_states e.g. eth0=managed.
        self.assert_link_states(**{link:'managed'})
        with open(os.path.join('/sys/class/net', link, attribute)) as f:
            return f.readline().strip()

    def assert_link_states(self, **kwargs):
        """Match networkctl link states to the given ones.

        Each keyword argument should be the name of a network interface
        with its expected value of the "SETUP" column in output from
        networkctl.  The interfaces have five seconds to come online
        before the check is performed.  Every specified interface must
        be present in the output, and any other interfaces found in the
        output are ignored.

        A special interface state "managed" is supported, which matches
        any value in the "SETUP" column other than "unmanaged".
        """
        if not kwargs:
            return
        interfaces = set(kwargs)

        # Wait for the requested interfaces, but don't fail for them.
        subprocess.call([NETWORKD_WAIT_ONLINE, '--timeout=5'] +
                        ['--interface={}'.format(iface) for iface in kwargs])

        # Validate each link state found in the networkctl output.
        out = subprocess.check_output(['networkctl', '--no-legend']).rstrip()
        for line in out.decode('utf-8').split('\n'):
            fields = line.split()
            if len(fields) >= 5 and fields[1] in kwargs:
                iface = fields[1]
                expected = kwargs[iface]
                actual = fields[-1]
                if (actual != expected and
                        not (expected == 'managed' and actual != 'unmanaged')):
                    self.fail("Link {} expects state {}, found {}".format(iface, expected, actual))
                interfaces.remove(iface)

        # Ensure that all requested interfaces have been covered.
        if interfaces:
            self.fail("Missing links in status output: {}".format(interfaces))


class BridgeTest(NetworkdTestingUtilities, unittest.TestCase):
    """Provide common methods for testing networkd against servers."""

    def wait_online(self):
        try:
            subprocess.check_call([NETWORKD_WAIT_ONLINE, '--interface', 'port1', '--interface', 'port2', '--timeout=10'])
        except (AssertionError, subprocess.CalledProcessError):
            # show networkd status, journal, and DHCP server log on failure
            print('---- interface status ----')
            sys.stdout.flush()
            subprocess.call(['ip', 'a', 'show', 'dev', 'mybridge'])
            subprocess.call(['ip', 'a', 'show', 'dev', 'port1'])
            subprocess.call(['ip', 'a', 'show', 'dev', 'port2'])
            print('---- networkctl status ----')
            sys.stdout.flush()
            rc = subprocess.call(['networkctl', '-n', '0', 'status', 'mybridge', 'port1', 'port2'])
            if rc != 0:
                print(f"'networkctl status' exited with an unexpected code {rc}")
            print('---- journal ----')
            subprocess.check_output(['journalctl', '--sync'])
            sys.stdout.flush()
            subprocess.call(['journalctl', '-b', '--no-pager', '--quiet', '-I', '-u', 'systemd-networkd.service'])
            raise

    def setUp(self):
        self.write_network('50-port1.netdev', '''\
[NetDev]
Name=port1
Kind=dummy
MACAddress=12:34:56:78:9a:bc
''')
        self.write_network('50-port2.netdev', '''\
[NetDev]
Name=port2
Kind=dummy
MACAddress=12:34:56:78:9a:bd
''')
        self.write_network('50-mybridge.netdev', '''\
[NetDev]
Name=mybridge
Kind=bridge
''')
        self.write_network('50-port1.network', '''\
[Match]
Name=port1
[Network]
Bridge=mybridge
''')
        self.write_network('50-port2.network', '''\
[Match]
Name=port2
[Network]
Bridge=mybridge
''')
        self.write_network('50-mybridge.network', '''\
[Match]
Name=mybridge
[Network]
IPv6AcceptRA=no
DNS=192.168.250.1
Address=192.168.250.33/24
Gateway=192.168.250.1
''')
        subprocess.call(['systemctl', 'reset-failed', 'systemd-networkd', 'systemd-resolved'])
        subprocess.check_call(['systemctl', 'restart', 'systemd-networkd'])
        self.wait_online()

    def tearDown(self):
        subprocess.check_call(['systemctl', 'stop', 'systemd-networkd.socket'])
        subprocess.check_call(['systemctl', 'stop', 'systemd-networkd.service'])
        subprocess.check_call(['ip', 'link', 'del', 'mybridge'])
        subprocess.check_call(['ip', 'link', 'del', 'port1'])
        subprocess.check_call(['ip', 'link', 'del', 'port2'])

    def test_bridge_init(self):
        self.assert_link_states(
            port1='managed',
            port2='managed',
            mybridge='managed')

    def test_bridge_port_priority(self):
        self.assertEqual(self.read_attr('port1', 'brport/priority'), '32')
        self.write_network_dropin('50-port1.network', 'priority', '''\
[Bridge]
Priority=28
''')
        subprocess.check_call(['ip', 'link', 'set', 'dev', 'port1', 'down'])
        subprocess.check_call(['systemctl', 'restart', 'systemd-networkd'])
        self.wait_online()
        self.assertEqual(self.read_attr('port1', 'brport/priority'), '28')

    def test_bridge_port_priority_set_zero(self):
        """It should be possible to set the bridge port priority to 0"""
        self.assertEqual(self.read_attr('port2', 'brport/priority'), '32')
        self.write_network_dropin('50-port2.network', 'priority', '''\
[Bridge]
Priority=0
''')
        subprocess.check_call(['ip', 'link', 'set', 'dev', 'port2', 'down'])
        subprocess.check_call(['systemctl', 'restart', 'systemd-networkd'])
        self.wait_online()
        self.assertEqual(self.read_attr('port2', 'brport/priority'), '0')

    def test_bridge_port_property(self):
        """Test the "[Bridge]" section keys"""
        self.assertEqual(self.read_attr('port2', 'brport/priority'), '32')
        self.write_network_dropin('50-port2.network', 'property', '''\
[Bridge]
UnicastFlood=true
HairPin=true
Isolated=true
UseBPDU=true
FastLeave=true
AllowPortToBeRoot=true
Cost=555
Priority=23
''')
        subprocess.check_call(['ip', 'link', 'set', 'dev', 'port2', 'down'])
        subprocess.check_call(['systemctl', 'restart', 'systemd-networkd'])
        self.wait_online()

        self.assertEqual(self.read_attr('port2', 'brport/priority'), '23')
        self.assertEqual(self.read_attr('port2', 'brport/hairpin_mode'), '1')
        self.assertEqual(self.read_attr('port2', 'brport/isolated'), '1')
        self.assertEqual(self.read_attr('port2', 'brport/path_cost'), '555')
        self.assertEqual(self.read_attr('port2', 'brport/multicast_fast_leave'), '1')
        self.assertEqual(self.read_attr('port2', 'brport/unicast_flood'), '1')
        self.assertEqual(self.read_attr('port2', 'brport/bpdu_guard'), '0')
        self.assertEqual(self.read_attr('port2', 'brport/root_block'), '0')

class ClientTestBase(NetworkdTestingUtilities):
    """Provide common methods for testing networkd against servers."""

    @classmethod
    def setUpClass(klass):
        klass.orig_log_level = subprocess.check_output(
            ['systemctl', 'show', '--value', '--property', 'LogLevel'],
            universal_newlines=True).strip()
        subprocess.check_call(['systemd-analyze', 'log-level', 'debug'])

    @classmethod
    def tearDownClass(klass):
        subprocess.check_call(['systemd-analyze', 'log-level', klass.orig_log_level])

    def setUp(self):
        self.iface = 'test_eth42'
        self.if_router = 'router_eth42'
        self.workdir_obj = tempfile.TemporaryDirectory()
        self.workdir = self.workdir_obj.name
        self.config = '50-test_eth42.network'

        # get current journal cursor
        subprocess.check_output(['journalctl', '--sync'])
        out = subprocess.check_output(['journalctl', '-b', '--quiet',
                                       '--no-pager', '-n0', '--show-cursor'],
                                      universal_newlines=True)
        self.assertTrue(out.startswith('-- cursor:'))
        self.journal_cursor = out.split()[-1]

        subprocess.call(['systemctl', 'reset-failed', 'systemd-networkd', 'systemd-resolved'])

    def tearDown(self):
        self.shutdown_iface()
        subprocess.call(['systemctl', 'stop', 'systemd-networkd.socket'])
        subprocess.call(['systemctl', 'stop', 'systemd-networkd.service'])
        subprocess.call(['ip', 'link', 'del', 'dummy0'],
                        stderr=subprocess.DEVNULL)

    def show_journal(self, unit):
        '''Show journal of given unit since start of the test'''

        print('---- {} ----'.format(unit))
        subprocess.check_output(['journalctl', '--sync'])
        sys.stdout.flush()
        subprocess.call(['journalctl', '-b', '--no-pager', '--quiet',
                         '--cursor', self.journal_cursor, '-u', unit])

    def show_ifaces(self):
        '''Show network interfaces'''

        print('--- networkctl ---')
        sys.stdout.flush()
        subprocess.call(['networkctl', 'status', '-n', '0', '-a'])

    def show_resolvectl(self):
        '''Show resolved settings'''

        print('--- resolvectl ---')
        sys.stdout.flush()
        subprocess.call(['resolvectl'])

    def create_iface(self, ipv6=False):
        '''Create test interface with DHCP server behind it'''

        raise NotImplementedError('must be implemented by a subclass')

    def shutdown_iface(self):
        '''Remove test interface and stop DHCP server'''

        raise NotImplementedError('must be implemented by a subclass')

    def print_server_log(self):
        '''Print DHCP server log for debugging failures'''

        raise NotImplementedError('must be implemented by a subclass')

    def start_unit(self, unit):
        try:
            # The service may be already started. Hence, restart it.
            subprocess.check_call(['systemctl', 'restart', unit])
        except subprocess.CalledProcessError:
            self.show_journal(unit)
            raise

    def do_test(self, coldplug=True, ipv6=False, extra_opts='',
                online_timeout=10, dhcp_mode='yes'):
        self.start_unit('systemd-resolved')
        self.write_network(self.config, '''\
[Match]
Name={iface}
[Network]
DHCP={dhcp_mode}
{extra_opts}
'''.format(iface=self.iface, dhcp_mode=dhcp_mode, extra_opts=extra_opts))

        if coldplug:
            # create interface first, then start networkd
            self.create_iface(ipv6=ipv6)
            self.start_unit('systemd-networkd')
        elif coldplug is not None:
            # start networkd first, then create interface
            self.start_unit('systemd-networkd')
            self.create_iface(ipv6=ipv6)
        else:
            # "None" means test sets up interface by itself
            self.start_unit('systemd-networkd')

        try:
            subprocess.check_call([NETWORKD_WAIT_ONLINE, '--interface',
                                   self.iface, '--timeout=%i' % online_timeout])

            if ipv6:
                # check iface state and IP 6 address; FIXME: we need to wait a bit
                # longer, as the iface is "configured" already with IPv4 *or*
                # IPv6, but we want to wait for both
                for _ in range(10):
                    out = subprocess.check_output(['ip', 'a', 'show', 'dev', self.iface])
                    if b'state UP' in out and b'inet6 2600' in out and b'inet 192.168' in out and b'tentative' not in out:
                        break
                    time.sleep(1)
                else:
                    self.fail('timed out waiting for IPv6 configuration')

                self.assertRegex(out, b'inet6 2600::.* scope global .*dynamic')
                self.assertRegex(out, b'inet6 fe80::.* scope link')
            else:
                # should have link-local address on IPv6 only
                out = subprocess.check_output(['ip', '-6', 'a', 'show', 'dev', self.iface])
                self.assertRegex(out, br'inet6 fe80::.* scope link')
                self.assertNotIn(b'scope global', out)

            # should have IPv4 address
            out = subprocess.check_output(['ip', '-4', 'a', 'show', 'dev', self.iface])
            self.assertIn(b'state UP', out)
            self.assertRegex(out, br'inet 192.168.5.\d+/.* scope global dynamic')

            # check networkctl state
            out = subprocess.check_output(['networkctl'])
            self.assertRegex(out, (r'{}\s+ether\s+[a-z-]+\s+unmanaged'.format(self.if_router)).encode())
            self.assertRegex(out, (r'{}\s+ether\s+routable\s+configured'.format(self.iface)).encode())

            out = subprocess.check_output(['networkctl', '-n', '0', 'status', self.iface])
            self.assertRegex(out, br'Type:\s+ether')
            self.assertRegex(out, br'State:\s+routable.*configured')
            self.assertRegex(out, br'Online state:\s+online')
            self.assertRegex(out, br'Address:\s+192.168.5.\d+')
            if ipv6:
                self.assertRegex(out, br'2600::')
            else:
                self.assertNotIn(br'2600::', out)
            self.assertRegex(out, br'fe80::')
            self.assertRegex(out, br'Gateway:\s+192.168.5.1')
            self.assertRegex(out, br'DNS:\s+192.168.5.1')
        except (AssertionError, subprocess.CalledProcessError):
            # show networkd status, journal, and DHCP server log on failure
            with open(os.path.join(NETWORK_UNITDIR, self.config)) as f:
                print('\n---- {} ----\n{}'.format(self.config, f.read()))
            print('---- interface status ----')
            sys.stdout.flush()
            subprocess.call(['ip', 'a', 'show', 'dev', self.iface])
            print('---- networkctl status {} ----'.format(self.iface))
            sys.stdout.flush()
            rc = subprocess.call(['networkctl', '-n', '0', 'status', self.iface])
            if rc != 0:
                print("'networkctl status' exited with an unexpected code {}".format(rc))
            self.show_journal('systemd-networkd.service')
            self.print_server_log()
            raise

        for timeout in range(50):
            with open(RESOLV_CONF) as f:
                contents = f.read()
            if 'nameserver 192.168.5.1\n' in contents:
                break
            time.sleep(0.1)
        else:
            self.fail('nameserver 192.168.5.1 not found in ' + RESOLV_CONF)

        if coldplug is False:
            # check post-down.d hook
            self.shutdown_iface()

    def test_coldplug_dhcp_yes_ip4(self):
        # we have a 12s timeout on RA, so we need to wait longer
        self.do_test(coldplug=True, ipv6=False, online_timeout=15)

    def test_coldplug_dhcp_yes_ip4_no_ra(self):
        # with disabling RA explicitly things should be fast
        self.do_test(coldplug=True, ipv6=False,
                     extra_opts='IPv6AcceptRA=no')

    def test_coldplug_dhcp_ip4_only(self):
        # we have a 12s timeout on RA, so we need to wait longer
        self.do_test(coldplug=True, ipv6=False, dhcp_mode='ipv4',
                     online_timeout=15)

    def test_coldplug_dhcp_ip4_only_no_ra(self):
        # with disabling RA explicitly things should be fast
        self.do_test(coldplug=True, ipv6=False, dhcp_mode='ipv4',
                     extra_opts='IPv6AcceptRA=no')

    def test_coldplug_dhcp_ip6(self):
        self.do_test(coldplug=True, ipv6=True)

    def test_hotplug_dhcp_ip4(self):
        # With IPv4 only we have a 12s timeout on RA, so we need to wait longer
        self.do_test(coldplug=False, ipv6=False, online_timeout=15)

    def test_hotplug_dhcp_ip6(self):
        self.do_test(coldplug=False, ipv6=True)

    def test_route_only_dns(self):
        self.write_network('50-myvpn.netdev', '''\
[NetDev]
Name=dummy0
Kind=dummy
MACAddress=12:34:56:78:9a:bc
''')
        self.write_network('50-myvpn.network', '''\
[Match]
Name=dummy0
[Network]
IPv6AcceptRA=no
Address=192.168.42.100/24
DNS=192.168.42.1
Domains= ~company
''')

        try:
            self.do_test(coldplug=True, ipv6=False,
                         extra_opts='IPv6AcceptRA=no')
        except subprocess.CalledProcessError as e:
            # networkd often fails to start in LXC: https://github.com/systemd/systemd/issues/11848
            if IS_CONTAINER and e.cmd == ['systemctl', 'restart', 'systemd-networkd']:
                raise unittest.SkipTest('https://github.com/systemd/systemd/issues/11848')
            else:
                raise

        with open(RESOLV_CONF) as f:
            contents = f.read()
            # ~company is not a search domain, only a routing domain
            self.assertNotRegex(contents, 'search.*company')
            # our global server should appear
            self.assertIn('nameserver 192.168.5.1\n', contents)
            # should not have domain-restricted server as global server
            self.assertNotIn('nameserver 192.168.42.1\n', contents)

    def test_route_only_dns_all_domains(self):
        self.write_network('50-myvpn.netdev', '''[NetDev]
Name=dummy0
Kind=dummy
MACAddress=12:34:56:78:9a:bc
''')
        self.write_network('50-myvpn.network', '''[Match]
Name=dummy0
[Network]
IPv6AcceptRA=no
Address=192.168.42.100/24
DNS=192.168.42.1
Domains= ~company ~.
''')

        try:
            self.do_test(coldplug=True, ipv6=False,
                         extra_opts='IPv6AcceptRA=no')
        except subprocess.CalledProcessError as e:
            # networkd often fails to start in LXC: https://github.com/systemd/systemd/issues/11848
            if IS_CONTAINER and e.cmd == ['systemctl', 'restart', 'systemd-networkd']:
                raise unittest.SkipTest('https://github.com/systemd/systemd/issues/11848')
            else:
                raise

        with open(RESOLV_CONF) as f:
            contents = f.read()

        # ~company is not a search domain, only a routing domain
        self.assertNotRegex(contents, 'search.*company')

        # our global server should appear
        self.assertIn('nameserver 192.168.5.1\n', contents)
        # should have company server as global server due to ~.
        self.assertIn('nameserver 192.168.42.1\n', contents)


@unittest.skipUnless(HAVE_DNSMASQ, 'dnsmasq not installed')
class DnsmasqClientTest(ClientTestBase, unittest.TestCase):
    '''Test networkd client against dnsmasq'''

    def setUp(self):
        super().setUp()
        self.dnsmasq = None
        self.iface_mac = 'de:ad:be:ef:47:11'

    def create_iface(self, ipv6=False, dnsmasq_opts=None):
        '''Create test interface with DHCP server behind it'''

        # add veth pair
        subprocess.check_call(['ip', 'link', 'add', 'name', self.iface,
                               'address', self.iface_mac,
                               'type', 'veth', 'peer', 'name', self.if_router])

        # give our router an IP
        subprocess.check_call(['ip', 'a', 'flush', 'dev', self.if_router])
        subprocess.check_call(['ip', 'a', 'add', '192.168.5.1/24', 'dev', self.if_router])
        if ipv6:
            subprocess.check_call(['ip', 'a', 'add', '2600::1/64', 'dev', self.if_router])
        subprocess.check_call(['ip', 'link', 'set', self.if_router, 'up'])

        # add DHCP server
        self.dnsmasq_log = os.path.join(self.workdir, 'dnsmasq.log')
        lease_file = os.path.join(self.workdir, 'dnsmasq.leases')
        if ipv6:
            extra_opts = ['--enable-ra', '--dhcp-range=2600::10,2600::20']
        else:
            extra_opts = []
        if dnsmasq_opts:
            extra_opts += dnsmasq_opts
        self.dnsmasq = subprocess.Popen(
            ['dnsmasq', '--keep-in-foreground', '--log-queries=extra', '--log-dhcp',
             '--log-facility=' + self.dnsmasq_log, '--conf-file=/dev/null',
             '--dhcp-leasefile=' + lease_file, '--bind-interfaces',
             '--interface=' + self.if_router, '--except-interface=lo',
             '--dhcp-range=192.168.5.10,192.168.5.200'] + extra_opts)

    def shutdown_iface(self):
        '''Remove test interface and stop DHCP server'''

        if self.if_router:
            subprocess.check_call(['ip', 'link', 'del', 'dev', self.if_router])
            self.if_router = None
        if self.dnsmasq:
            self.dnsmasq.kill()
            self.dnsmasq.wait()
            self.dnsmasq = None

    def print_server_log(self, log_file=None):
        '''Print DHCP server log for debugging failures'''

        path = log_file if log_file else self.dnsmasq_log
        with open(path) as f:
            sys.stdout.write('\n\n---- {} ----\n{}\n------\n\n'.format(os.path.basename(path), f.read()))

    def test_resolved_domain_restricted_dns(self):
        '''resolved: domain-restricted DNS servers'''

        # enable DNSSEC in allow downgrade mode, and turn off stuff we don't want to test to make looking at logs easier
        conf = '/run/systemd/resolved.conf.d/test-enable-dnssec.conf'
        os.makedirs(os.path.dirname(conf), exist_ok=True)
        with open(conf, 'w') as f:
            f.write('[Resolve]\nDNSSEC=allow-downgrade\nLLMNR=no\nMulticastDNS=no\nDNSOverTLS=no\nDNS=\n')
        self.addCleanup(os.remove, conf)

        # create interface for generic connections; this will map all DNS names
        # to 192.168.42.1
        self.create_iface(dnsmasq_opts=['--address=/#/192.168.42.1'])
        self.write_network('50-general.network', '''\
[Match]
Name={}
[Network]
DHCP=ipv4
IPv6AcceptRA=no
DNSSECNegativeTrustAnchors=search.example.com
'''.format(self.iface))

        # create second device/dnsmasq for a .company/.lab VPN interface
        # static IPs for simplicity
        self.add_veth_pair('testvpnclient', 'testvpnrouter')
        subprocess.check_call(['ip', 'a', 'flush', 'dev', 'testvpnrouter'])
        subprocess.check_call(['ip', 'a', 'add', '10.241.3.1/24', 'dev', 'testvpnrouter'])
        subprocess.check_call(['ip', 'link', 'set', 'testvpnrouter', 'up'])

        vpn_dnsmasq_log = os.path.join(self.workdir, 'dnsmasq-vpn.log')
        vpn_dnsmasq = subprocess.Popen(
            ['dnsmasq', '--keep-in-foreground', '--log-queries=extra',
             '--log-facility=' + vpn_dnsmasq_log, '--conf-file=/dev/null',
             '--dhcp-leasefile=/dev/null', '--bind-interfaces',
             '--interface=testvpnrouter', '--except-interface=lo',
             '--address=/math.lab/10.241.3.3', '--address=/cantina.company/10.241.4.4'])
        self.addCleanup(vpn_dnsmasq.wait)
        self.addCleanup(vpn_dnsmasq.kill)

        self.write_network('50-vpn.network', '''\
[Match]
Name=testvpnclient
[Network]
IPv6AcceptRA=no
Address=10.241.3.2/24
DNS=10.241.3.1
Domains=~company ~lab
DNSSECNegativeTrustAnchors=company lab
''')

        self.start_unit('systemd-networkd')
        subprocess.check_call([NETWORKD_WAIT_ONLINE, '--interface', self.iface,
                               '--interface=testvpnclient', '--timeout=20'])

        # ensure we start fresh with every test
        subprocess.check_call(['systemctl', 'restart', 'systemd-resolved'])
        subprocess.check_call(['systemctl', 'service-log-level', 'systemd-resolved', 'debug'])

        try:
            # test vpnclient specific domains; these should *not* be answered by
            # the general DNS
            out = subprocess.check_output(['resolvectl', 'query', '-4', 'math.lab'])
            self.assertIn(b'math.lab: 10.241.3.3', out)
            out = subprocess.check_output(['resolvectl', 'query', '-4', 'kettle.cantina.company'])
            self.assertIn(b'kettle.cantina.company: 10.241.4.4', out)

            # test general domains
            out = subprocess.check_output(['resolvectl', 'query', '-4', 'search.example.com'])
            self.assertIn(b'search.example.com: 192.168.42.1', out)

            with open(self.dnsmasq_log) as f:
                general_log = f.read()
            with open(vpn_dnsmasq_log) as f:
                vpn_log = f.read()

            # VPN domains should only be sent to VPN DNS
            self.assertRegex(vpn_log, 'query.*math.lab')
            self.assertRegex(vpn_log, 'query.*cantina.company')
            self.assertNotIn('.lab', general_log)
            self.assertNotIn('.company', general_log)

            # general domains should not be sent to the VPN DNS
            self.assertRegex(general_log, 'query.*search.example.com')
            self.assertNotIn('search.example.com', vpn_log)

        except (AssertionError, subprocess.CalledProcessError):
            self.show_journal('systemd-resolved.service')
            self.print_server_log()
            self.print_server_log(vpn_dnsmasq_log)
            self.show_ifaces()
            self.show_resolvectl()
            raise

    def test_resolved_etc_hosts(self):
        '''resolved queries to /etc/hosts'''

        # enabled DNSSEC in allow-downgrade mode
        conf = '/run/systemd/resolved.conf.d/test-enable-dnssec.conf'
        os.makedirs(os.path.dirname(conf), exist_ok=True)
        with open(conf, 'w') as f:
            f.write('[Resolve]\nDNSSEC=allow-downgrade\nLLMNR=no\nMulticastDNS=no\nDNSOverTLS=no\nDNS=\n')
        self.addCleanup(os.remove, conf)

        # Add example.com to NTA list for this test
        negative = '/run/dnssec-trust-anchors.d/example.com.negative'
        os.makedirs(os.path.dirname(negative), exist_ok=True)
        with open(negative, 'w') as f:
            f.write('example.com\n16.172.in-addr.arpa\n')
        self.addCleanup(os.remove, negative)

        # create /etc/hosts bind mount which resolves my.example.com for IPv4
        hosts = os.path.join(self.workdir, 'hosts')
        with open(hosts, 'w') as f:
            f.write('172.16.99.99  my.example.com\n')
        subprocess.check_call(['mount', '--bind', hosts, '/etc/hosts'])
        self.addCleanup(subprocess.call, ['umount', '/etc/hosts'])
        subprocess.check_call(['systemctl', 'restart', 'systemd-resolved.service'])
        subprocess.check_call(['systemctl', 'service-log-level', 'systemd-resolved.service', 'debug'])

        # note: different IPv4 address here, so that it's easy to tell apart
        # what resolved the query
        self.create_iface(dnsmasq_opts=['--host-record=my.example.com,172.16.99.1,2600::99:99',
                                        '--host-record=other.example.com,172.16.0.42,2600::42',
                                        '--mx-host=example.com,mail.example.com'],
                          ipv6=True)
        self.do_test(coldplug=None, ipv6=True)

        try:
            # family specific queries
            out = subprocess.check_output(['resolvectl', 'query', '-4', 'my.example.com'])
            self.assertIn(b'my.example.com: 172.16.99.99', out)
            # we don't expect an IPv6 answer; if /etc/hosts has any IP address,
            # it's considered a sufficient source
            self.assertNotEqual(subprocess.call(['resolvectl', 'query', '-6', 'my.example.com']), 0)
            # "any family" query; IPv4 should come from /etc/hosts
            out = subprocess.check_output(['resolvectl', 'query', 'my.example.com'])
            self.assertIn(b'my.example.com: 172.16.99.99', out)
            # IP → name lookup; again, takes the /etc/hosts one
            out = subprocess.check_output(['resolvectl', 'query', '172.16.99.99'])
            self.assertIn(b'172.16.99.99: my.example.com', out)

            # non-address RRs should fall back to DNS
            out = subprocess.check_output(['resolvectl', 'query', '--type=MX', 'example.com'])
            self.assertIn(b'example.com IN MX 1 mail.example.com', out)

            # other domains query DNS
            out = subprocess.check_output(['resolvectl', 'query', 'other.example.com'])
            self.assertIn(b'172.16.0.42', out)
            out = subprocess.check_output(['resolvectl', 'query', '172.16.0.42'])
            self.assertIn(b'172.16.0.42: other.example.com', out)
        except (AssertionError, subprocess.CalledProcessError):
            self.show_journal('systemd-resolved.service')
            self.print_server_log()
            self.show_ifaces()
            self.show_resolvectl()
            raise

    def test_transient_hostname(self):
        '''networkd sets transient hostname from DHCP'''

        orig_hostname = socket.gethostname()
        self.addCleanup(socket.sethostname, orig_hostname)
        # temporarily move /etc/hostname away; restart hostnamed to pick it up
        if os.path.exists('/etc/hostname'):
            subprocess.check_call(['mount', '--bind', '/dev/null', '/etc/hostname'])
            self.addCleanup(subprocess.call, ['umount', '/etc/hostname'])
        subprocess.check_call(['systemctl', 'stop', 'systemd-hostnamed.service'])
        self.addCleanup(subprocess.call, ['systemctl', 'stop', 'systemd-hostnamed.service'])

        self.create_iface(dnsmasq_opts=['--dhcp-host={},192.168.5.210,testgreen'.format(self.iface_mac)])
        self.do_test(coldplug=None, extra_opts='IPv6AcceptRA=no', dhcp_mode='ipv4')

        try:
            # should have received the fixed IP above
            out = subprocess.check_output(['ip', '-4', 'a', 'show', 'dev', self.iface])
            self.assertRegex(out, b'inet 192.168.5.210/24 .* scope global dynamic')
            # should have set transient hostname in hostnamed; this is
            # sometimes a bit lagging (issue #4753), so retry a few times
            for retry in range(1, 6):
                out = subprocess.check_output(['hostnamectl'])
                if b'testgreen' in out:
                    break
                time.sleep(5)
                sys.stdout.write('[retry %i] ' % retry)
                sys.stdout.flush()
            else:
                self.fail('Transient hostname not found in hostnamectl:\n{}'.format(out.decode()))
            # and also applied to the system
            self.assertEqual(socket.gethostname(), 'testgreen')
        except AssertionError:
            self.show_journal('systemd-networkd.service')
            self.show_journal('systemd-hostnamed.service')
            self.print_server_log()
            raise

    def test_transient_hostname_with_static(self):
        '''transient hostname is not applied if static hostname exists'''

        orig_hostname = socket.gethostname()
        self.addCleanup(socket.sethostname, orig_hostname)

        if not os.path.exists('/etc/hostname'):
            self.write_config('/etc/hostname', "foobarqux")
        else:
            self.write_config('/run/hostname.tmp', "foobarqux")
            subprocess.check_call(['mount', '--bind', '/run/hostname.tmp', '/etc/hostname'])
            self.addCleanup(subprocess.call, ['umount', '/etc/hostname'])

        socket.sethostname("foobarqux");

        subprocess.check_call(['systemctl', 'stop', 'systemd-hostnamed.service'])
        self.addCleanup(subprocess.call, ['systemctl', 'stop', 'systemd-hostnamed.service'])

        self.create_iface(dnsmasq_opts=['--dhcp-host={},192.168.5.210,testgreen'.format(self.iface_mac)])
        self.do_test(coldplug=None, extra_opts='IPv6AcceptRA=no', dhcp_mode='ipv4')

        try:
            # should have received the fixed IP above
            out = subprocess.check_output(['ip', '-4', 'a', 'show', 'dev', self.iface])
            self.assertRegex(out, b'inet 192.168.5.210/24 .* scope global dynamic')
            # static hostname wins over transient one, thus *not* applied
            self.assertEqual(socket.gethostname(), "foobarqux")
        except AssertionError:
            self.show_journal('systemd-networkd.service')
            self.show_journal('systemd-hostnamed.service')
            self.print_server_log()
            raise


class NetworkdClientTest(ClientTestBase, unittest.TestCase):
    '''Test networkd client against networkd server'''

    def setUp(self):
        super().setUp()
        self.dnsmasq = None

    def create_iface(self, ipv6=False, dhcpserver_opts=None):
        '''Create test interface with DHCP server behind it'''

        # run "router-side" networkd in own mount namespace to shield it from
        # "client-side" configuration and networkd
        (fd, script) = tempfile.mkstemp(prefix='networkd-router.sh')
        self.addCleanup(os.remove, script)
        with os.fdopen(fd, 'w+') as f:
            f.write('''\
#!/bin/sh
set -eu
mkdir -p /run/systemd/network
mkdir -p /run/systemd/netif
mkdir -p /var/lib/systemd/network
mount -t tmpfs none /run/systemd/network
mount -t tmpfs none /run/systemd/netif
mount -t tmpfs none /var/lib/systemd/network
[ ! -e /run/dbus ] || mount -t tmpfs none /run/dbus
# create router/client veth pair
cat <<EOF >/run/systemd/network/50-test.netdev
[NetDev]
Name={ifr}
Kind=veth

[Peer]
Name={ifc}
EOF

cat <<EOF >/run/systemd/network/50-test.network
[Match]
Name={ifr}

[Network]
IPv6AcceptRA=no
Address=192.168.5.1/24
{addr6}
DHCPServer=yes

[DHCPServer]
PoolOffset=10
PoolSize=50
DNS=192.168.5.1
{dhopts}
EOF

# For the networkd instance invoked below cannot support varlink connection.
# Hence, 'networkctl persistent-storage yes' cannot be used.
export SYSTEMD_NETWORK_PERSISTENT_STORAGE_READY=1

# Generate debugging logs.
export SYSTEMD_LOG_LEVEL=debug

# run networkd as in systemd-networkd.service
exec $(systemctl cat systemd-networkd.service | sed -n '/^ExecStart=/ {{ s/^.*=//; s/^[@+-]//; s/^!*//; p}}')
'''.format(ifr=self.if_router,
           ifc=self.iface,
           addr6=('Address=2600::1/64' if ipv6 else ''),
           dhopts=(dhcpserver_opts or '')))

            os.fchmod(fd, 0o755)

        subprocess.check_call(['systemd-run', '--unit=networkd-test-router.service',
                               '-p', 'InaccessibleDirectories=-/etc/systemd/network',
                               '-p', 'InaccessibleDirectories=-/run/systemd/network',
                               '-p', 'InaccessibleDirectories=-/run/systemd/netif',
                               '-p', 'InaccessibleDirectories=-/var/lib/systemd/network',
                               '--service-type=notify', script])

        # wait until devices got created
        for _ in range(50):
            if subprocess.run(['ip', 'link', 'show', 'dev', self.if_router],
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0:
                break
            time.sleep(0.1)
        else:
            subprocess.call(['ip', 'link', 'show', 'dev', self.if_router])
            self.fail('Timed out waiting for {ifr} created.'.format(ifr=self.if_router))

    def shutdown_iface(self):
        '''Remove test interface and stop DHCP server'''

        if self.if_router:
            subprocess.check_call(['systemctl', 'stop', 'networkd-test-router.service'])
            # ensure failed transient unit does not stay around
            subprocess.call(['systemctl', 'reset-failed', 'networkd-test-router.service'])
            subprocess.call(['ip', 'link', 'del', 'dev', self.if_router])
            self.if_router = None

    def print_server_log(self):
        '''Print DHCP server log for debugging failures'''

        self.show_journal('networkd-test-router.service')

    @unittest.skip('networkd does not have DHCPv6 server support')
    def test_hotplug_dhcp_ip6(self):
        pass

    @unittest.skip('networkd does not have DHCPv6 server support')
    def test_coldplug_dhcp_ip6(self):
        pass

    def test_search_domains(self):

        # we don't use this interface for this test
        self.if_router = None

        self.write_network('50-test.netdev', '''\
[NetDev]
Name=dummy0
Kind=dummy
MACAddress=12:34:56:78:9a:bc
''')
        self.write_network('50-test.network', '''\
[Match]
Name=dummy0
[Network]
IPv6AcceptRA=no
Address=192.168.42.100/24
DNS=192.168.42.1
Domains= one two three four five six seven eight nine ten
''')

        self.start_unit('systemd-networkd')

        for timeout in range(50):
            with open(RESOLV_CONF) as f:
                contents = f.read()
            if ' one' in contents:
                break
            time.sleep(0.1)
        self.assertRegex(contents, 'search .*one two three four five six seven eight nine ten')

    def test_dropin(self):
        # we don't use this interface for this test
        self.if_router = None

        self.write_network('50-test.netdev', '''\
[NetDev]
Name=dummy0
Kind=dummy
MACAddress=12:34:56:78:9a:bc
''')
        self.write_network('50-test.network', '''\
[Match]
Name=dummy0
[Network]
IPv6AcceptRA=no
Address=192.168.42.100/24
DNS=192.168.42.1
''')
        self.write_network_dropin('50-test.network', 'dns', '''\
[Network]
DNS=127.0.0.1
''')

        self.start_unit('systemd-resolved')
        self.start_unit('systemd-networkd')

        subprocess.check_call([NETWORKD_WAIT_ONLINE, '--interface', 'dummy0', '--timeout=10'])

        out = subprocess.check_output(['networkctl', 'status', 'dummy0'])
        self.assertIn(b'50-test.netdev', out)
        self.assertIn(b'50-test.network.d/dns.conf', out)

        for _ in range(50):
            with open(RESOLV_CONF) as f:
                contents = f.read()
            if 'nameserver 127.0.0.1\n' in contents and 'nameserver 192.168.42.1\n' in contents:
                break
            time.sleep(0.1)
        else:
            self.fail(f'Expected DNS servers not found in resolv.conf: {contents}')

    def test_dhcp_timezone(self):
        '''networkd sets time zone from DHCP'''

        def get_tz():
            out = subprocess.check_output(['busctl', 'get-property', 'org.freedesktop.timedate1',
                                           '/org/freedesktop/timedate1', 'org.freedesktop.timedate1', 'Timezone'])
            assert out.startswith(b's "')
            out = out.strip()
            assert out.endswith(b'"')
            return out[3:-1].decode()

        orig_timezone = get_tz()
        self.addCleanup(subprocess.call, ['timedatectl', 'set-timezone', orig_timezone])

        self.create_iface(dhcpserver_opts='EmitTimezone=yes\nTimezone=Pacific/Honolulu')
        self.do_test(coldplug=None, extra_opts='IPv6AcceptRA=false\n[DHCP]\nUseTimezone=true', dhcp_mode='ipv4')

        # Should have applied the received timezone. This is asynchronous, so we need to wait for a while:
        for _ in range(20):
            tz = get_tz()
            if tz == 'Pacific/Honolulu':
                break
            time.sleep(0.5)
        else:
            self.show_journal('systemd-networkd.service')
            self.show_journal('systemd-timedated.service')
            self.fail(f'Timezone: {tz}, expected: Pacific/Honolulu')


class MatchClientTest(unittest.TestCase, NetworkdTestingUtilities):
    """Test [Match] sections in .network files.

    Be aware that matching the test host's interfaces will wipe their
    configuration, so as a precaution, all network files should have a
    restrictive [Match] section to only ever interfere with the
    temporary veth interfaces created here.
    """

    def tearDown(self):
        """Stop networkd."""
        subprocess.call(['systemctl', 'stop', 'systemd-networkd.socket'])
        subprocess.call(['systemctl', 'stop', 'systemd-networkd.service'])

    def test_basic_matching(self):
        """Verify the Name= line works throughout this class."""
        self.add_veth_pair('test_if1', 'fake_if2')
        self.write_network('50-test.network', '''\
[Match]
Name=test_*
[Network]
IPv6AcceptRA=no
''')
        subprocess.check_call(['systemctl', 'restart', 'systemd-networkd'])
        self.assert_link_states(test_if1='managed', fake_if2='unmanaged')

    def test_inverted_matching(self):
        """Verify that a '!'-prefixed value inverts the match."""
        # Use a MAC address as the interfaces' common matching attribute
        # to avoid depending on udev, to support testing in containers.
        mac = '00:01:02:03:98:99'
        self.add_veth_pair('test_veth', 'test_peer',
                           ['addr', mac], ['addr', mac])
        self.write_network('50-no-veth.network', '''\
[Match]
MACAddress={}
Name=!nonexistent *peer*
[Network]
IPv6AcceptRA=no
'''.format(mac))
        subprocess.check_call(['systemctl', 'restart', 'systemd-networkd'])
        self.assert_link_states(test_veth='managed', test_peer='unmanaged')


class UnmanagedClientTest(unittest.TestCase, NetworkdTestingUtilities):
    """Test if networkd manages the correct interfaces."""

    def setUp(self):
        """Write .network files to match the named veth devices."""
        # Define the veth+peer pairs to be created.
        # Their pairing doesn't actually matter, only their names do.
        self.veths = {
            'm1def': 'm0unm',
            'm1man': 'm1unm',
        }

        # Define the contents of .network files to be read in order.
        self.configs = (
            "[Match]\nName=m1def\n",
            "[Match]\nName=m1unm\n[Link]\nUnmanaged=yes\n",
            "[Match]\nName=m1*\n[Link]\nUnmanaged=no\n",
        )

        # Write out the .network files to be cleaned up automatically.
        for i, config in enumerate(self.configs):
            self.write_network("%02d-test.network" % i, config)

    def tearDown(self):
        """Stop networkd."""
        subprocess.call(['systemctl', 'stop', 'systemd-networkd.socket'])
        subprocess.call(['systemctl', 'stop', 'systemd-networkd.service'])

    def create_iface(self):
        """Create temporary veth pairs for interface matching."""
        for veth, peer in self.veths.items():
            self.add_veth_pair(veth, peer)

    def test_unmanaged_setting(self):
        """Verify link states with Unmanaged= settings, hot-plug."""
        subprocess.check_call(['systemctl', 'restart', 'systemd-networkd'])
        self.create_iface()
        self.assert_link_states(m1def='managed',
                                m1man='managed',
                                m1unm='unmanaged',
                                m0unm='unmanaged')

    def test_unmanaged_setting_coldplug(self):
        """Verify link states with Unmanaged= settings, cold-plug."""
        self.create_iface()
        subprocess.check_call(['systemctl', 'restart', 'systemd-networkd'])
        self.assert_link_states(m1def='managed',
                                m1man='managed',
                                m1unm='unmanaged',
                                m0unm='unmanaged')

    def test_catchall_config(self):
        """Verify link states with a catch-all config, hot-plug."""
        # Don't actually catch ALL interfaces.  It messes up the host.
        self.write_network('50-all.network', "[Match]\nName=m[01]???\n")
        subprocess.check_call(['systemctl', 'restart', 'systemd-networkd'])
        self.create_iface()
        self.assert_link_states(m1def='managed',
                                m1man='managed',
                                m1unm='unmanaged',
                                m0unm='managed')

    def test_catchall_config_coldplug(self):
        """Verify link states with a catch-all config, cold-plug."""
        # Don't actually catch ALL interfaces.  It messes up the host.
        self.write_network('50-all.network', "[Match]\nName=m[01]???\n")
        self.create_iface()
        subprocess.check_call(['systemctl', 'restart', 'systemd-networkd'])
        self.assert_link_states(m1def='managed',
                                m1man='managed',
                                m1unm='unmanaged',
                                m0unm='managed')


if __name__ == '__main__':
    unittest.main(testRunner=unittest.TextTestRunner(stream=sys.stdout,
                                                     verbosity=2))
