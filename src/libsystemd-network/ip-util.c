/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <string.h>

#include "iovec-util.h"
#include "ip-util.h"

static uint64_t complement_sum(uint64_t a, uint64_t b) {
        if (a <= UINT64_MAX - b)
                return a + b;

        return a - (UINT64_MAX - b);
}

static uint64_t checksum_iov(uint64_t sum, const struct iovec *iov) {
        assert(iov);

        for (struct iovec i = *iov; iovec_is_set(&i); iovec_inc(&i, sizeof(uint64_t))) {
                uint64_t t = 0;
                memcpy(&t, i.iov_base, MIN(i.iov_len, sizeof(uint64_t)));
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
        return checksum_finalize(checksum_iov(0, &IOVEC_MAKE(buf, len)));
}
