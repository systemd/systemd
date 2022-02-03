/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "log-link.h"

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
