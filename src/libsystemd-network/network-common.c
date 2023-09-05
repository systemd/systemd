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

usec_t be32_msec_to_usec(be32_t t) {
        uint32_t s = be32toh(t);

        if (s == UINT32_MAX)
                return USEC_INFINITY;

        return s * USEC_PER_MSEC;
}

usec_t be16_sec_to_usec(be16_t t) {
        uint16_t s = be16toh(t);

        if (s == UINT16_MAX)
                return USEC_INFINITY;

        return s * USEC_PER_SEC;
}

be32_t usec_to_be32_sec(usec_t t) {
        if (t == USEC_INFINITY)
                /* UINT32_MAX may be handled as infinity. */
                return htobe32(UINT32_MAX);

        t = DIV_ROUND_UP(t, USEC_PER_SEC);
        if (t >= UINT32_MAX)
                /* Finite but too large. Let's use the largest finite value. */
                return htobe32(UINT32_MAX - 1);

        return htobe32(t);
}

be32_t usec_to_be32_msec(usec_t t) {
        if (t == USEC_INFINITY)
                /* UINT32_MAX is handled as infinity. */
                return htobe32(UINT32_MAX);

        t = DIV_ROUND_UP(t, USEC_PER_MSEC);
        if (t >= UINT32_MAX)
                /* Finite but too large. Let's use the largest finite value. */
                return htobe32(UINT32_MAX - 1);

        return htobe32(t);
}

be16_t usec_to_be16_sec(usec_t t) {
        if (t == USEC_INFINITY)
                /* UINT32_MAX may be handled as infinity. */
                return htobe32(UINT16_MAX);

        t = DIV_ROUND_UP(t, USEC_PER_SEC);
        if (t >= UINT16_MAX)
                /* Finite but too large. Let's use the largest finite value. */
                return htobe32(UINT16_MAX - 1);

        return htobe16(t);
}

usec_t time_span_to_stamp(usec_t span, usec_t base) {
        if (span == 0)
                return 0;

        return usec_add(base, span);
}
