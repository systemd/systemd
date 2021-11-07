/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <netinet/in.h>
#include <linux/if_arp.h>
#include <linux/if_infiniband.h>
#include <string.h>

#include "arphrd-util.h"
#include "macro.h"

static const struct arphrd_name* lookup_arphrd(register const char *str, register GPERF_LEN_TYPE len);

#include "arphrd-from-name.h"
#include "arphrd-to-name.h"

int arphrd_from_name(const char *name) {
        const struct arphrd_name *sc;

        assert(name);

        sc = lookup_arphrd(name, strlen(name));
        if (!sc)
                return -EINVAL;

        return sc->id;
}

size_t arphrd_to_hw_addr_len(uint16_t arphrd) {
        switch (arphrd) {
        case ARPHRD_ETHER:
                return ETH_ALEN;
        case ARPHRD_INFINIBAND:
                return INFINIBAND_ALEN;
        case ARPHRD_TUNNEL:
        case ARPHRD_SIT:
        case ARPHRD_IPGRE:
                return sizeof(struct in_addr);
        case ARPHRD_TUNNEL6:
        case ARPHRD_IP6GRE:
                return sizeof(struct in6_addr);
        default:
                return 0;
        }
}
