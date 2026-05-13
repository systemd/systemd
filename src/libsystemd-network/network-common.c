/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "env-util.h"
#include "format-ifname.h"
#include "network-common.h"
#include "socket-util.h"
#include "unaligned.h"

int get_ifname(int ifindex, char **ifname) {
        assert(ifname);

        /* This sets ifname only when it is not set yet. */

        if (*ifname)
                return 0;

        return format_ifname_alloc(ifindex, ifname);
}

usec_t unaligned_be32_sec_to_usec(const void *p, bool max_as_infinity) {
        uint32_t s = unaligned_read_be32(ASSERT_PTR(p));

        if (s == UINT32_MAX && max_as_infinity)
                return USEC_INFINITY;

        return s * USEC_PER_SEC;
}

usec_t be32_sec_to_usec(be32_t t, bool max_as_infinity) {
        uint32_t s = be32toh(t);

        if (s == UINT32_MAX && max_as_infinity)
                return USEC_INFINITY;

        return s * USEC_PER_SEC;
}

usec_t be32_msec_to_usec(be32_t t, bool max_as_infinity) {
        uint32_t s = be32toh(t);

        if (s == UINT32_MAX && max_as_infinity)
                return USEC_INFINITY;

        return s * USEC_PER_MSEC;
}

usec_t be16_sec_to_usec(be16_t t, bool max_as_infinity) {
        uint16_t s = be16toh(t);

        if (s == UINT16_MAX && max_as_infinity)
                return USEC_INFINITY;

        return s * USEC_PER_SEC;
}

be32_t usec_to_be32_sec(usec_t t) {
        if (t == USEC_INFINITY)
                /* Some settings, e.g. a lifetime of an address, UINT32_MAX is handled as infinity. so let's
                 * map USEC_INFINITY to UINT32_MAX. */
                return htobe32(UINT32_MAX);

        if (t >= (UINT32_MAX - 1) * USEC_PER_SEC)
                /* Finite but too large. Let's use the largest (or off-by-one from the largest) finite value. */
                return htobe32(UINT32_MAX - 1);

        return htobe32((uint32_t) DIV_ROUND_UP(t, USEC_PER_SEC));
}

be32_t usec_to_be32_msec(usec_t t) {
        if (t == USEC_INFINITY)
                return htobe32(UINT32_MAX);

        if (t >= (UINT32_MAX - 1) * USEC_PER_MSEC)
                return htobe32(UINT32_MAX - 1);

        return htobe32((uint32_t) DIV_ROUND_UP(t, USEC_PER_MSEC));
}

be16_t usec_to_be16_sec(usec_t t) {
        if (t == USEC_INFINITY)
                return htobe16(UINT16_MAX);

        if (t >= (UINT16_MAX - 1) * USEC_PER_SEC)
                return htobe16(UINT16_MAX - 1);

        return htobe16((uint16_t) DIV_ROUND_UP(t, USEC_PER_SEC));
}

usec_t time_span_to_stamp(usec_t span, usec_t base) {
        /* Typically, 0 lifetime (timespan) indicates the corresponding configuration (address or so) must be
         * dropped. So, when the timespan is zero, here we return 0 rather than 'base'. This makes the caller
         * easily understand that the configuration needs to be dropped immediately. */
        if (span == 0)
                return 0;

        return usec_add(base, span);
}

bool network_test_mode_enabled(void) {
        static int test_mode = -1;
        int r;

        if (test_mode < 0) {
                r = getenv_bool("SYSTEMD_NETWORK_TEST_MODE");
                if (r < 0) {
                        if (r != -ENXIO)
                                log_debug_errno(r, "Failed to parse $SYSTEMD_NETWORK_TEST_MODE environment variable, ignoring: %m");

                        test_mode = false;
                } else
                        test_mode = r;
        }

        return test_mode;
}

triple_timestamp* triple_timestamp_from_cmsg(triple_timestamp *t, struct msghdr *mh) {
        assert(t);
        assert(mh);

        struct timeval *tv = CMSG_FIND_AND_COPY_DATA(mh, SOL_SOCKET, SCM_TIMESTAMP, struct timeval);
        if (tv)
                return triple_timestamp_from_realtime(t, timeval_load(tv));

        return triple_timestamp_now(t);
}
