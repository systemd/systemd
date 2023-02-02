# SPDX-License-Identifier: LGPL-2.1-or-later
# pylint: disable=line-too-long, disable=broad-except
"""
    Helper module for mocking mDNS services.
"""

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

import random
import time
from scapy.arch import get_if_addr
from scapy.arch.linux import in6_getifaddr
from scapy.layers.dns import DNS, DNSRR, DNSRRSRV
from scapy.layers.inet import IP, UDP, Ether
from scapy.layers.inet6 import IPv6
from scapy.sendrecv import sendp

MCAST_ADDR_4 = "224.0.0.251"
MCAST_ADDR_6 = "FF02::FB"

def get_ipv4_addr(interface):
    '''
    Get IPv4 addr for specified interface
    '''
    myip = ""
    try:
        myip = get_if_addr(interface)
        return myip
    except Exception as err:
        print("Failed to get IPv4 addr for interface.",interface)
        print(err)
        return ""

def get_ipv6_addr(interface):
    '''
    Get IPv6 addr for specified interface
    '''
    myip = ""
    try:
        for ifaces in in6_getifaddr():
            if ifaces[2] == interface:
                if not myip:
                    myip = ifaces[0]
                elif myip[0:6] == "fe80::":
                    myip = ifaces[0]
        return myip
    except Exception as err:
        print("Failed to get IPv6 addr for interface.",interface)
        print(err)
        return ""

def publish_mdns_service(m_ttl, n_inst, delay):
    '''
    Publish n mock instances of googlecast mDNS service with TTL=m_ttl
    Arg delay (in seconds) introduces a delay between each instance being published
    Returns a list of unique IDs of service instances published
    '''
    id_list = []
    if delay == 0:
        time.sleep(5)
    qname='_googlecast._tcp.local'
    source_ipv4 = get_ipv4_addr('ve-testcont')
    source_ipv6 = get_ipv6_addr('ve-testcont')
    for _ in range(n_inst):
        uid = f'{random.randrange(16**32):032x}'
        uid = uid[:8] + '-' + uid[8:12] + '-' + uid[12:16] + '-' + uid[16:20] + '-' + uid[20:]
        id_list.append(uid)
        txt_rdata = ['id='+uid,'rm=','ve=05','md=Chromecast Ultra','ic=/setup/icon.png','fn=LivingRoom','ca=4101','st=0','bs=FA8FCA7EO948','rs=0']
        ptr_pkt = DNSRR(rrname='_googlecast._tcp.local',type="PTR",rclass=1,ttl=m_ttl,rdata="Chromecast-Ultra-"+uid+"."+qname)
        srv_pkt = DNSRRSRV(rrname="Chromecast-Ultra-"+uid+"."+qname,ttl=100,type="SRV",rclass=32769,priority=0,weight=0,port=8009,target=uid+".local")
        txt_pkt = DNSRR(rrname="Chromecast-Ultra-"+uid+"."+qname,type="TXT",ttl=100,rclass=32769,rdata=txt_rdata)
        addr_pkt = DNSRR(rrname=uid+".local",ttl=m_ttl,type="A",rclass=32769,rdata=source_ipv4)
        addr_pkt6 = DNSRR(rrname=uid+".local",ttl=m_ttl,type="AAAA",rclass=32769,rdata=source_ipv6)
        if delay != 0:
            time.sleep(delay)
        sendp(Ether()/IP(dst=MCAST_ADDR_4)/UDP(sport=5353,dport=5353)/DNS(aa=1,qr=1,rd=0,ancount=1,arcount=3)/ptr_pkt/txt_pkt/srv_pkt/addr_pkt,iface='ve-testcont',verbose=False)
        sendp(Ether()/IPv6(dst=MCAST_ADDR_6)/UDP(sport=5353,dport=5353)/DNS(aa=1,qr=1,rd=0,ancount=4,arcount=0)/ptr_pkt/txt_pkt/srv_pkt/addr_pkt6,iface='ve-testcont',verbose=False)

    return id_list

def remove_services(id_list):
    '''
    Sends goodbye packets for each unique ID in id_list
    '''
    for uid in id_list:
        ptr_pkt = DNSRR(rrname='_googlecast._tcp.local',type="PTR",rclass=1,ttl=0,rdata="Chromecast-Ultra-"+uid+"."+'_googlecast._tcp.local')
        sendp(Ether()/IP(dst=MCAST_ADDR_4)/UDP(sport=5353,dport=5353)/DNS(aa=1,qr=1,rd=0,ancount=1,arcount=0)/ptr_pkt,iface='ve-testcont',verbose=False)
        sendp(Ether()/IPv6(dst=MCAST_ADDR_6)/UDP(sport=5353,dport=5353)/DNS(aa=1,qr=1,rd=0,ancount=1,arcount=0)/ptr_pkt,iface='ve-testcont',verbose=False)
