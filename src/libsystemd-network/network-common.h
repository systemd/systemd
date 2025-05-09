/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "forward.h"
#include "log-link.h"
#include "sparse-endian.h"
#include "time-util.h"

#define log_interface_prefix_full_errno_zerook(prefix, type, val, error, fmt, ...) \
        ({                                                              \
                int _e = (error);                                       \
                if (DEBUG_LOGGING) {                                    \
                        const char *_n = NULL;                          \
                        type *_v = (val);                               \
                                                                        \
                        if (_v)                                         \
                                (void) type##_get_ifname(_v, &_n);      \
                        log_interface_full_errno_zerook(                \
                                _n, LOG_DEBUG, _e, prefix fmt,          \
                                ##__VA_ARGS__);                         \
                }                                                       \
                -ERRNO_VALUE(_e);                                       \
        })

#define log_interface_prefix_full_errno(prefix, type, val, error, fmt, ...) \
        ({                                                              \
                int _error = (error);                                   \
                ASSERT_NON_ZERO(_error);                                \
                log_interface_prefix_full_errno_zerook(                 \
                        prefix, type, val, _error, fmt, ##__VA_ARGS__); \
        })

int get_ifname(int ifindex, char **ifname);

usec_t unaligned_be32_sec_to_usec(const void *p, bool max_as_infinity);
usec_t be32_sec_to_usec(be32_t t, bool max_as_infinity);
usec_t be32_msec_to_usec(be32_t t, bool max_as_infinity);
usec_t be16_sec_to_usec(be16_t t, bool max_as_infinity);
be32_t usec_to_be32_sec(usec_t t);
be32_t usec_to_be32_msec(usec_t t);
be16_t usec_to_be16_sec(usec_t t);
usec_t time_span_to_stamp(usec_t span, usec_t base);

bool network_test_mode_enabled(void);

triple_timestamp* triple_timestamp_from_cmsg(triple_timestamp *t, struct msghdr *mh);
#define TRIPLE_TIMESTAMP_FROM_CMSG(mh)          \
        triple_timestamp_from_cmsg(&(triple_timestamp) {}, mh)
