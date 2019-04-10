/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

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

/* Note that LOOPBACK_IFINDEX is currently not exposed by the
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
