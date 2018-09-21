#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1+
# systemd-resolve tests

import os
import sys
import unittest
import subprocess
import re

resolv_file='/etc/resolv.conf'
systemd_resolved_conf_file='/etc/systemd/resolved.conf'

class SystemdResolveTests(unittest.TestCase):
    def setUp(self):
        self.set_resolve_conf()

    def set_resolve_conf(self):
        resolvers = []
        dns = ''

        with open(resolv_file) as resolvconf:
            for line in resolvconf:
                for line in resolvconf:
                    match = re.match("^nameserver\s+(\S+)", line)
                    if match is not None:
                        resolvers.append(match.group(1))

        resolvconf.close()

        dns = ' '.join(resolvers)

        with open(systemd_resolved_conf_file, "w") as f:
            f.write("[Resolve]\nDNS=%s\nFallbackDNS=8.8.8.8 8.8.4.4 2001:4860:4860::8888 2001:4860:4860::8844\n" % (dns))
            f.close()

    def find_ip_address(self, s):
        ip_list = []

        ip_list = re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', s).group()
        return ip_list

    def test_A_and_AAAA(self):

         output = subprocess.check_output(['systemd-resolve', '-4', 'redhat.com']).rstrip().decode('utf-8')
         print(output)

         ip_list = self.find_ip_address(output)
         print(ip_list)

         if not ip_list:
             self.assertFalse(0)

         output = subprocess.check_output(['systemd-resolve', '-4', 'google.com']).rstrip().decode('utf-8')
         ip_list = self.find_ip_address(output)
         print(ip_list)

         if not ip_list:
             self.assertFalse(0)

         subprocess.check_call('systemd-resolve -6 google.com', shell=True)

    def test_retrieve_domain_of_ip(self):

         output = subprocess.check_output(['systemd-resolve', '85.214.157.71']).rstrip().decode('utf-8')
         print(output)
         self.assertRegex(output, '85.214.157.71')

    def test_retrieve_MX_yahoo(self):

         output = subprocess.check_output(['systemd-resolve', '-t', 'MX' , 'yahoo.com', '--legend=no', 'yahoo.com']).rstrip().decode('utf-8')
         print(output)
         self.assertRegex(output, 'yahoo.com')
         self.assertRegex(output, 'MX')

    def test_retrieve_service(self):

         subprocess.check_call('systemd-resolve --service _xmpp-server._tcp gmail.com', shell=True)

    def test_retrieve_via_tls(self):

        subprocess.check_call('systemd-resolve --tlsa=tcp fedoraproject.org:443', shell=True)


if __name__ == '__main__':
    unittest.main(testRunner=unittest.TextTestRunner(stream=sys.stdout,
                                                     verbosity=3))
