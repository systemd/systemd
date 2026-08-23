/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

/* glibc's netinet/if_ether.h does the following:
 * - include linux/if_ether.h, net/ethernet.h, and net/if_arp.h,
 * - define struct ether_arp, and relevant macros,
 * - define ETHER_MAP_IP_MULTICAST() macro (currently we do not use it).
 * However, musl's netinet/if_ether.h conflicts with linux/if_ether.h.
 * Let's use the same way that glibc uses. */

#include <linux/if_ether.h>     /* IWYU pragma: export */
#include <net/ethernet.h>       /* IWYU pragma: export */
#include <net/if_arp.h>         /* IWYU pragma: export */

/*
 * Ethernet Address Resolution Protocol.
 *
 * See RFC 826 for protocol description.  Structure below is adapted
 * to resolving internet addresses.  Field names used correspond to
 * RFC 826.
 */
struct  ether_arp {
        struct  arphdr ea_hdr;          /* fixed-size header */
        uint8_t arp_sha[ETH_ALEN];      /* sender hardware address */
        uint8_t arp_spa[4];             /* sender protocol address */
        uint8_t arp_tha[ETH_ALEN];      /* target hardware address */
        uint8_t arp_tpa[4];             /* target protocol address */
};
#define arp_hrd ea_hdr.ar_hrd
#define arp_pro ea_hdr.ar_pro
#define arp_hln ea_hdr.ar_hln
#define arp_pln ea_hdr.ar_pln
#define arp_op  ea_hdr.ar_op
