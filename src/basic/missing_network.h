/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include <net/ethernet.h>

/* The following two defines are actually available in the kernel headers for longer, but we define them here anyway,
 * since that makes it easier to use them in conjunction with the glibc net/if.h header which conflicts with
 * linux/if.h. */
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

/* if_arp.h */
#ifndef ARPHRD_IP6GRE
#define ARPHRD_IP6GRE 823
#endif

/* linux/in6.h or netinet/in.h */
#ifndef IPV6_UNICAST_IF
#define IPV6_UNICAST_IF 76
#endif

/* Not exposed but defined at include/net/ip.h */
#ifndef IPV4_MIN_MTU
#define IPV4_MIN_MTU 68
#endif

/* linux/ipv6.h */
#ifndef IPV6_MIN_MTU
#define IPV6_MIN_MTU 1280
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
