#!/usr/bin/env python3
#
# networkd integration test
# This uses temporary configuration in /run and temporary veth devices, and
# does not write anything on disk or change any system configuration;
# but it assumes (and checks at the beginning) that networkd is not currently
# running.
#
# This can be run on a normal installation, in QEMU, nspawn (with
# --private-network), LXD (with "--config raw.lxc=lxc.aa_profile=unconfined"),
# or LXC system containers. You need at least the "ip" tool from the iproute
# package; it is recommended to install dnsmasq too to get full test coverage.
#
# ATTENTION: This uses the *installed* networkd, not the one from the built
# source tree.
#
# (C) 2015 Canonical Ltd.
# Author: Martin Pitt <martin.pitt@ubuntu.com>
#
# systemd is free software; you can redistribute it and/or modify it
# under the terms of the GNU Lesser General Public License as published by
# the Free Software Foundation; either version 2.1 of the License, or
# (at your option) any later version.

# systemd is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with systemd; If not, see <http://www.gnu.org/licenses/>.

import os
import sys
import time
import unittest
import tempfile
import subprocess
import shutil

networkd_active = subprocess.call(['systemctl', 'is-active', '--quiet',
                                   'systemd-networkd']) == 0
have_dnsmasq = shutil.which('dnsmasq')


@unittest.skipIf(networkd_active,
                 'networkd is already active')
class ClientTestBase:
    def setUp(self):
        self.iface = 'test_eth42'
        self.if_router = 'router_eth42'
        self.workdir_obj = tempfile.TemporaryDirectory()
        self.workdir = self.workdir_obj.name
        self.config = '/run/systemd/network/test_eth42.network'
        os.makedirs(os.path.dirname(self.config), exist_ok=True)

        # avoid "Failed to open /dev/tty" errors in containers
        os.environ['SYSTEMD_LOG_TARGET'] = 'journal'

        # determine path to systemd-networkd-wait-online
        for p in ['/usr/lib/systemd/systemd-networkd-wait-online',
                  '/lib/systemd/systemd-networkd-wait-online']:
            if os.path.exists(p):
                self.networkd_wait_online = p
                break
        else:
            self.fail('systemd-networkd-wait-online not found')

        # get current journal cursor
        out = subprocess.check_output(['journalctl', '-b', '--quiet',
                                       '--no-pager', '-n0', '--show-cursor'],
                                      universal_newlines=True)
        self.assertTrue(out.startswith('-- cursor:'))
        self.journal_cursor = out.split()[-1]

    def tearDown(self):
        self.shutdown_iface()
        if os.path.exists(self.config):
            os.unlink(self.config)
        subprocess.call(['systemctl', 'stop', 'systemd-networkd'])

    def show_journal(self, unit):
        '''Show journal of given unit since start of the test'''

        print('---- %s ----' % unit)
        sys.stdout.flush()
        subprocess.call(['journalctl', '-b', '--no-pager', '--quiet',
                         '--cursor', self.journal_cursor, '-u', unit])

    def create_iface(self, ipv6=False):
        '''Create test interface with DHCP server behind it'''

        raise NotImplementedError('must be implemented by a subclass')

    def shutdown_iface(self):
        '''Remove test interface and stop DHCP server'''

        raise NotImplementedError('must be implemented by a subclass')

    def print_server_log(self):
        '''Print DHCP server log for debugging failures'''

        raise NotImplementedError('must be implemented by a subclass')

    def do_test(self, coldplug=True, ipv6=False, extra_opts='',
                online_timeout=10, dhcp_mode='yes'):
        with open(self.config, 'w') as f:
            f.write('''[Match]
Name=%s
[Network]
DHCP=%s
%s''' % (self.iface, dhcp_mode, extra_opts))

        if coldplug:
            # create interface first, then start networkd
            self.create_iface(ipv6=ipv6)
            subprocess.check_call(['systemctl', 'start', 'systemd-networkd'])
        else:
            # start networkd first, then create interface
            subprocess.check_call(['systemctl', 'start', 'systemd-networkd'])
            self.create_iface(ipv6=ipv6)

        try:
            subprocess.check_call([self.networkd_wait_online, '--interface',
                                   self.iface, '--timeout=%i' % online_timeout])

            if ipv6:
                # check iface state and IP 6 address; FIXME: we need to wait a bit
                # longer, as the iface is "configured" already with IPv4 *or*
                # IPv6, but we want to wait for both
                for timeout in range(10):
                    out = subprocess.check_output(['ip', 'a', 'show', 'dev', self.iface])
                    if b'state UP' in out and b'inet6 2600' in out and b'inet 192.168' in out:
                        break
                    time.sleep(1)
                else:
                    self.fail('timed out waiting for IPv6 configuration')

                self.assertRegex(out, b'inet6 2600::.* scope global .*dynamic')
                self.assertRegex(out, b'inet6 fe80::.* scope link')
            else:
                # should have link-local address on IPv6 only
                out = subprocess.check_output(['ip', '-6', 'a', 'show', 'dev', self.iface])
                self.assertRegex(out, b'inet6 fe80::.* scope link')
                self.assertNotIn(b'scope global', out)

            # should have IPv4 address
            out = subprocess.check_output(['ip', '-4', 'a', 'show', 'dev', self.iface])
            self.assertIn(b'state UP', out)
            self.assertRegex(out, b'inet 192.168.5.\d+/.* scope global dynamic')

            # check networkctl state
            out = subprocess.check_output(['networkctl'])
            self.assertRegex(out, ('%s\s+ether\s+routable\s+unmanaged' % self.if_router).encode())
            self.assertRegex(out, ('%s\s+ether\s+routable\s+configured' % self.iface).encode())

            out = subprocess.check_output(['networkctl', 'status', self.iface])
            self.assertRegex(out, b'Type:\s+ether')
            self.assertRegex(out, b'State:\s+routable.*configured')
            self.assertRegex(out, b'Address:\s+192.168.5.\d+')
            if ipv6:
                self.assertRegex(out, b'2600::')
            else:
                self.assertNotIn(b'2600::', out)
            self.assertRegex(out, b'fe80::')
            self.assertRegex(out, b'Gateway:\s+192.168.5.1')
            self.assertRegex(out, b'DNS:\s+192.168.5.1')
        except (AssertionError, subprocess.CalledProcessError):
            # show networkd status, journal, and DHCP server log on failure
            with open(self.config) as f:
                print('\n---- %s ----\n%s' % (self.config, f.read()))
            print('---- interface status ----')
            sys.stdout.flush()
            subprocess.call(['ip', 'a', 'show', 'dev', self.iface])
            print('---- networkctl status %s ----' % self.iface)
            sys.stdout.flush()
            subprocess.call(['networkctl', 'status', self.iface])
            self.show_journal('systemd-networkd.service')
            self.print_server_log()
            raise

        # verify resolv.conf if it gets dynamically managed
        if os.path.islink('/etc/resolv.conf'):
            for timeout in range(50):
                with open('/etc/resolv.conf') as f:
                    contents = f.read()
                if 'nameserver 192.168.5.1\n' in contents:
                    break
                # resolv.conf can have at most three nameservers; if we already
                # have three different ones, that's also okay
                if contents.count('nameserver ') >= 3:
                    break
                time.sleep(0.1)
            else:
                self.fail('nameserver 192.168.5.1 not found in /etc/resolv.conf')

        if not coldplug:
            # check post-down.d hook
            self.shutdown_iface()

    def test_coldplug_dhcp_yes_ip4(self):
        # we have a 12s timeout on RA, so we need to wait longer
        self.do_test(coldplug=True, ipv6=False, online_timeout=15)

    def test_coldplug_dhcp_yes_ip4_no_ra(self):
        # with disabling RA explicitly things should be fast
        self.do_test(coldplug=True, ipv6=False,
                     extra_opts='IPv6AcceptRouterAdvertisements=False')

    def test_coldplug_dhcp_ip4_only(self):
        # we have a 12s timeout on RA, so we need to wait longer
        self.do_test(coldplug=True, ipv6=False, dhcp_mode='ipv4',
                     online_timeout=15)

    def test_coldplug_dhcp_ip4_only_no_ra(self):
        # with disabling RA explicitly things should be fast
        self.do_test(coldplug=True, ipv6=False, dhcp_mode='ipv4',
                     extra_opts='IPv6AcceptRouterAdvertisements=False')

    def test_coldplug_dhcp_ip6(self):
        self.do_test(coldplug=True, ipv6=True)

    def test_hotplug_dhcp_ip4(self):
        # With IPv4 only we have a 12s timeout on RA, so we need to wait longer
        self.do_test(coldplug=False, ipv6=False, online_timeout=15)

    def test_hotplug_dhcp_ip6(self):
        self.do_test(coldplug=False, ipv6=True)


@unittest.skipUnless(have_dnsmasq, 'dnsmasq not installed')
class DnsmasqClientTest(ClientTestBase, unittest.TestCase):
    '''Test networkd client against dnsmasq'''

    def setUp(self):
        super().setUp()
        self.dnsmasq = None

    def create_iface(self, ipv6=False):
        '''Create test interface with DHCP server behind it'''

        # add veth pair
        subprocess.check_call(['ip', 'link', 'add', 'name', self.iface, 'type',
                               'veth', 'peer', 'name', self.if_router])

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
        self.dnsmasq = subprocess.Popen(
            ['dnsmasq', '--keep-in-foreground', '--log-queries',
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

    def print_server_log(self):
        '''Print DHCP server log for debugging failures'''

        with open(self.dnsmasq_log) as f:
            sys.stdout.write('\n\n---- dnsmasq log ----\n%s\n------\n\n' % f.read())


class NetworkdClientTest(ClientTestBase, unittest.TestCase):
    '''Test networkd client against networkd server'''

    def setUp(self):
        super().setUp()
        self.dnsmasq = None

    def create_iface(self, ipv6=False):
        '''Create test interface with DHCP server behind it'''

        # run "router-side" networkd in own mount namespace to shield it from
        # "client-side" configuration and networkd
        (fd, script) = tempfile.mkstemp(prefix='networkd-router.sh')
        self.addCleanup(os.remove, script)
        with os.fdopen(fd, 'w+') as f:
            f.write('''#!/bin/sh -eu
mkdir -p /run/systemd/network
mkdir -p /run/systemd/netif
mount -t tmpfs none /run/systemd/network
mount -t tmpfs none /run/systemd/netif
[ ! -e /run/dbus ] || mount -t tmpfs none /run/dbus
# create router/client veth pair
cat << EOF > /run/systemd/network/test.netdev
[NetDev]
Name=%(ifr)s
Kind=veth

[Peer]
Name=%(ifc)s
EOF

cat << EOF > /run/systemd/network/test.network
[Match]
Name=%(ifr)s

[Network]
Address=192.168.5.1/24
%(addr6)s
DHCPServer=yes

[DHCPServer]
PoolOffset=10
PoolSize=50
DNS=192.168.5.1
EOF

# run networkd as in systemd-networkd.service
exec $(systemctl cat systemd-networkd.service | sed -n '/^ExecStart=/ { s/^.*=//; p}')
''' % {'ifr': self.if_router, 'ifc': self.iface, 'addr6': ipv6 and 'Address=2600::1/64' or ''})

            os.fchmod(fd, 0o755)

        subprocess.check_call(['systemd-run', '--unit=networkd-test-router.service',
                               '-p', 'InaccessibleDirectories=-/etc/systemd/network',
                               '-p', 'InaccessibleDirectories=-/run/systemd/network',
                               '-p', 'InaccessibleDirectories=-/run/systemd/netif',
                               '--service-type=notify', script])

        # wait until devices got created
        for timeout in range(50):
            out = subprocess.check_output(['ip', 'a', 'show', 'dev', self.if_router])
            if b'state UP' in out and b'scope global' in out:
                break
            time.sleep(0.1)

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


if __name__ == '__main__':
    unittest.main(testRunner=unittest.TextTestRunner(stream=sys.stdout,
                                                     verbosity=2))
