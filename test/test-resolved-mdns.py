#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# pylint: disable=line-too-long, disable=invalid-name
# pylint: disable=broad-except, disable=too-many-statements
# pylint: disable=unsupported-membership-test, disable=too-many-branches

'''
    Test mDNS service browse and resolve.
'''
import logging
import sys
import os
import time
import pexpect
from mdns_publisher import publish_mdns_service, remove_services, get_ipv4_addr, get_ipv6_addr

def run_test():
    '''
    Run mDNS browse and resolve tests.
    Returns 0 if passed, 1 if any step fails.
    '''

    logger = logging.getLogger("test-resolved-mdns")
    txt_string = ("\"rm=\" \"ve=05\" \"md=Chromecast Ultra\" \"ic=/setup/icon.png\""
            " \"fn=LivingRoom\" \"ca=4101\" \"st=0\" \"bs=FA8FCA7EO948\" \"rs=0\"")
    ret = 0

    logger.info("spawning test")
    console = pexpect.spawn("systemd-nspawn -M testcont -bi ../mkosi.output/system --network-veth", [], env={
        "TERM": "linux",
    }, encoding='utf-8', timeout=60)
    time.sleep(2)
    console.logfile = sys.stdout

    logger.debug("child pid %d", console.pid)
    try:
        console.expect("Press any key to proceed", 30)
        console.sendline("")
        console.expect("Please enter a new root password", 10)
        console.sendline("")
        console.sendline("uname -n")
        console.expect("testcont")

        # Setup
        logger.info("configure network")
        retval = os.system("systemctl status NetworkManager --no-pager")
        if retval == 0:
            os.system("systemctl disable NetworkManager")
            os.system("systemctl stop NetworkManager")
        os.system("systemctl enable systemd-networkd")
        time.sleep(2)
        os.system("systemctl start systemd-networkd")
        time.sleep(1)
        console.sendline("systemctl enable systemd-networkd")
        console.expect("#", 1)
        console.sendline("systemctl start systemd-networkd")
        console.expect("#", 1)
        console.sendline("systemctl enable --now systemd-resolved")
        console.expect("#", 1)
        console.sendline("echo $?")
        console.expect("0\r", 2)
        console.sendline("systemd-resolve --set-mdns=yes --interface=host0")
        console.expect("#", 1)
        console.sendline("echo $?")
        console.expect('0\r', 2)

        # Wait for the network interface to be configured. Timeout after 20 seconds
        retval = -1
        retry = 0
        while(retry < 20 and retval != 0):
            console.sendline('networkctl | grep host0')
            retval = console.expect(['configured', pexpect.EOF, pexpect.TIMEOUT], 1)
            retry = retry+1

        if retry >= 20:
            raise Exception("Failed to configure network.\n")

        # Test continuous browse and resolve.
        # (1) Publish 10 instances of mDNS service and check if services are listed along with
        #     resolved data.
        # (2) Then remove all 10 instances by sending goodbye packets and check if notifications of
        #     removal are received.
        # (3) Repeat 1 and 2.
        console.sendline("mdns-browse-services --domain _googlecast._tcp.local --interface host0"
                        " --resolve")
        source_ip4=get_ipv4_addr('ve-testcont')
        source_ip6=get_ipv6_addr('ve-testcont')
        for _ in range(2):
            id_list = publish_mdns_service(100, 10, 0)
            for s in id_list:
                console.expect("\\+  host0 AF_INET Chromecast-Ultra-"+s+" _googlecast._tcp     local", 10)
                console.expect("hostname = \\["+s+".local\\]")
                console.expect("port = \\[8009\\]")
                console.expect("address = \\["+source_ip4+"\\]")
                console.expect("txt = \\[\"id="+s+"\" "+txt_string+"\\]")
                console.expect("\\+  host0 AF_INET6 Chromecast-Ultra-"+s+" _googlecast._tcp     local", 10)
                console.expect("hostname = \\["+s+".local\\]")
                console.expect("port = \\[8009\\]")
                console.expect("address = \\["+source_ip6+"\\]")
                console.expect("txt = \\[\"id="+s+"\" "+txt_string+"\\]")
            logger.info("Removing services..")
            remove_services(id_list)

        time.sleep(2)
        console.sendcontrol('c')
        console.expect("#", 5)

        for s in id_list:
            v4teststr="-  host0 AF_INET Chromecast-Ultra-"+s+" _googlecast._tcp     local"
            if v4teststr not in console.before:
                raise Exception("Exception in remove services: \nService not removed: " + v4teststr)
            v6teststr="-  host0 AF_INET6 Chromecast-Ultra-"+s+" _googlecast._tcp     local"
            if v6teststr not in console.before:
                raise Exception("Exception in remove services: \nService not removed: " + v6teststr)
        time.sleep(2)

        # Test when services are available before the client is started and multiple restarts of the client.
        id_list = publish_mdns_service(100, 10, 0)
        id_list.reverse()
        time.sleep(2)
        for _ in range(3):
            console.sendline("mdns-browse-services --domain _googlecast._tcp.local --interface host0"
                        " --resolve")
            for s in id_list:
                console.expect("\\+  host0 AF_INET6 Chromecast-Ultra-"+s+" _googlecast._tcp     local", 10)
                console.expect("hostname = \\["+s+".local\\]")
                console.expect("port = \\[8009\\]")
                console.expect("address = \\["+source_ip6+"\\]")
                console.expect("txt = \\[\"id="+s+"\" "+txt_string+"\\]")
            for s in id_list:
                console.expect("\\+  host0 AF_INET Chromecast-Ultra-"+s+" _googlecast._tcp     local", 10)
                console.expect("hostname = \\["+s+".local\\]")
                console.expect("port = \\[8009\\]")
                console.expect("address = \\["+source_ip4+"\\]")
                console.expect("txt = \\[\"id="+s+"\" "+txt_string+"\\]")

            console.sendcontrol('c')
            console.expect("#", 5)
            time.sleep(2)

        # Test cache maintenance.
        # Publish 5 instances of mDNS service with 5 seconds between each.
        # Check if notifications of removal are received when TTL of each instance expires.
        console.sendline("mdns-browse-services --domain _googlecast._tcp.local --interface host0")
        id_list = publish_mdns_service(20, 5, 5)
        logger.info("Test cache maintenance..")
        console.expect("\\+  host0 AF_INET Chromecast-Ultra-"+id_list[0]+" _googlecast._tcp     local", 6)
        for s in id_list:
            console.expect("\\-  host0 (\\w+) Chromecast-Ultra-"+s+" _googlecast._tcp     local", 21)
            proto = console.match.group(1)
            proto1 = "AF_INET" if "AF_INET6" in proto else "AF_INET6"
            console.expect("\\-  host0 "+ proto1 + " Chromecast-Ultra-"+s+" _googlecast._tcp     local", 5)
        console.sendcontrol('c')
        console.expect("#", 5)
        console.sendline("poweroff")
        console.expect(pexpect.EOF, 3)

    except Exception as e:
        ret = 1
        console.sendcontrol('c')
        console.sendline("poweroff")
        time.sleep(1)
        logger.error(e)
        logger.info("killing child pid %d", console.pid)
        console.terminate()

    return ret

if __name__ == "__main__":
    run_test()
