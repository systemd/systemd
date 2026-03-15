/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <string.h>

#include "ip-util.h"

static uint64_t complement_sum(uint64_t a, uint64_t b) {
        if (a < UINT64_MAX - b)
                return a + b;

        return a - (UINT64_MAX - b);
}

static uint64_t checksum_buffer(uint64_t sum, const void *buf, size_t len) {
        const uint64_t *p = ASSERT_PTR(buf);

        while (len >= sizeof(uint64_t)) {
                sum = complement_sum(sum, *p);
                len -= sizeof(uint64_t);
                p++;
        }

        if (len > 0) {
                uint64_t t = 0;
                memcpy(&t, p, len);
                sum = complement_sum(sum, t);
        }

        return sum;
}

static uint16_t checksum_finalize(uint64_t sum) {
        while (sum >> 16)
                sum = (sum & 0xffff) + (sum >> 16);

        return ~sum;
}

uint16_t ip_checksum(const void *buf, size_t len) {
        /* See RFC1071 */
        return checksum_finalize(checksum_buffer(0, buf, len));
}
