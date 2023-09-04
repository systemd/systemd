/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "format-util.h"
#include "network-common.h"

int get_ifname(int ifindex, char **ifname) {
        assert(ifname);

        /* This sets ifname only when it is not set yet. */

        if (*ifname)
                return 0;

        return format_ifname_alloc(ifindex, ifname);
}

usec_t be32_sec_to_usec(be32_t t) {
        uint32_t s = be32toh(t);

        if (s == UINT32_MAX)
                return USEC_INFINITY;

        return s * USEC_PER_SEC;
}

usec_t time_span_to_stamp(usec_t span, usec_t base) {
        if (span == 0)
                return 0;

        return usec_add(base, span);
}
