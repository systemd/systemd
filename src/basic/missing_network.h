/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include <linux/loop.h>
#include <linux/rtnetlink.h>
#include <net/ethernet.h>

#include "missing_ethtool.h"
#include "missing_fib_rules.h"
#include "missing_fou.h"
#include "missing_if_bridge.h"
#include "missing_if_link.h"
#include "missing_if_tunnel.h"
#include "missing_vxcan.h"

/* if.h */
/* The following two defines are actually available in the kernel headers for longer, but we define them here
 * anyway, since that makes it easier to use them in conjunction with the glibc net/if.h header which
 * conflicts with linux/if.h. */
#ifndef IF_OPER_UNKNOWN
#define IF_OPER_UNKNOWN 0
#endif

#ifndef IF_OPER_UP
#define IF_OPER_UP 6
#endif

#ifndef IFF_LOWER_UP
#define IFF_LOWER_UP 0x10000
#endif

#ifndef IFF_DORMANT
#define IFF_DORMANT 0x20000
#endif

/* if_addr.h */
#if !HAVE_IFA_FLAGS
#define IFA_FLAGS 8
#endif

#ifndef IFA_F_MANAGETEMPADDR
#define IFA_F_MANAGETEMPADDR 0x100
#endif

#ifndef IFA_F_NOPREFIXROUTE
#define IFA_F_NOPREFIXROUTE 0x200
#endif

#ifndef IFA_F_MCAUTOJOIN
#define IFA_F_MCAUTOJOIN 0x400
#endif

/* if_arp.h */
#ifndef ARPHRD_IP6GRE
#define ARPHRD_IP6GRE 823
#endif

/* if_bonding.h */
#ifndef BOND_XMIT_POLICY_ENCAP23
#define BOND_XMIT_POLICY_ENCAP23 3
#endif

#ifndef BOND_XMIT_POLICY_ENCAP34
#define BOND_XMIT_POLICY_ENCAP34 4
#endif

/* if_tun.h */
#ifndef IFF_MULTI_QUEUE
#define IFF_MULTI_QUEUE 0x100
#endif

/* in6.h */
#ifndef IPV6_UNICAST_IF
#define IPV6_UNICAST_IF 76
#endif

/* ip.h */
#ifndef IPV4_MIN_MTU
#define IPV4_MIN_MTU 68
#endif

/* ipv6.h */
#ifndef IPV6_MIN_MTU
#define IPV6_MIN_MTU 1280
#endif

/* loop.h */
#if !HAVE_LO_FLAGS_PARTSCAN
#define LO_FLAGS_PARTSCAN 8
#endif

#ifndef LOOP_CTL_REMOVE
#define LOOP_CTL_REMOVE 0x4C81
#endif

#ifndef LOOP_CTL_GET_FREE
#define LOOP_CTL_GET_FREE 0x4C82
#endif

/* netdevice.h */
#ifndef NET_ADDR_RANDOM
#define NET_ADDR_RANDOM 1
#endif

#ifndef NET_NAME_UNKNOWN
#define NET_NAME_UNKNOWN 0
#endif

#ifndef NET_NAME_ENUM
#define NET_NAME_ENUM 1
#endif

#ifndef NET_NAME_PREDICTABLE
#define NET_NAME_PREDICTABLE 2
#endif

#ifndef NET_NAME_USER
#define NET_NAME_USER 3
#endif

#ifndef NET_NAME_RENAMED
#define NET_NAME_RENAMED 4
#endif

/* netlink.h */
#ifndef NETLINK_LIST_MEMBERSHIPS /* b42be38b2778eda2237fc759e55e3b698b05b315 (4.2) */
#define NETLINK_LIST_MEMBERSHIPS 9
#endif

/* rtnetlink.h */
#ifndef RTA_PREF
#define RTA_PREF 20
#endif

#ifndef RTAX_QUICKACK
#define RTAX_QUICKACK 15
#endif

#ifndef RTA_EXPIRES
#define RTA_EXPIRES 23
#endif

/* Note that LOOPBACK_IFINDEX is currently not exported by the
 * kernel/glibc, but hardcoded internally by the kernel.  However, as
 * it is exported to userspace indirectly via rtnetlink and the
 * ioctls, and made use of widely we define it here too, in a way that
 * is compatible with the kernel's internal definition. */
#ifndef LOOPBACK_IFINDEX
#define LOOPBACK_IFINDEX 1
#endif

/* Not exposed yet. Similar values are defined in net/ethernet.h */
#ifndef ETHERTYPE_LLDP
#define ETHERTYPE_LLDP 0x88cc
#endif
