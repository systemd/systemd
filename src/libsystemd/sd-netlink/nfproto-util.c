/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/socket.h>
#include <linux/netfilter.h>

#include "nfproto-util.h"
#include "string-table.h"

static const char *const nfproto_table[] = {
        [NFPROTO_INET]   = "inet",
        [NFPROTO_IPV4]   = "ipv4",
        [NFPROTO_ARP]    = "arp",
        [NFPROTO_NETDEV] = "netdev",
        [NFPROTO_BRIDGE] = "bridge",
        [NFPROTO_IPV6]   = "ipv6",
        [NFPROTO_DECNET] = "decnet",
};

DEFINE_STRING_TABLE_LOOKUP(nfproto, int);

bool nfproto_is_valid(int n) {
        return n == NFPROTO_UNSPEC || !!nfproto_to_string(n);
}

int af_to_nfproto(int af) {
        switch (af) {
        case AF_UNSPEC:
                return NFPROTO_UNSPEC;
        case AF_INET:
                return NFPROTO_IPV4;
        case AF_BRIDGE:
                return NFPROTO_BRIDGE;
        case AF_INET6:
                return NFPROTO_IPV6;
        case AF_DECnet:
                return NFPROTO_DECNET;
        default:
                return -EINVAL;
        }
}

int nfproto_to_af(int n) {
        switch (n) {
        case NFPROTO_UNSPEC:
                return AF_UNSPEC;
        case NFPROTO_IPV4:
                return AF_INET;
        case NFPROTO_BRIDGE:
                return AF_BRIDGE;
        case NFPROTO_IPV6:
                return AF_INET6;
        case NFPROTO_DECNET:
                return AF_DECnet;
        default:
                return -EINVAL;
        }
}
