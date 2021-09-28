/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "log.h"

#define log_interface_full_errno_zerook(ifname, level, error, ...)      \
        ({                                                              \
                const char *_ifname = (ifname);                         \
                _ifname ? log_object_internal(level, error, PROJECT_FILE, __LINE__, __func__, "INTERFACE=", _ifname, NULL, NULL, ##__VA_ARGS__) : \
                        log_internal(level, error, PROJECT_FILE, __LINE__, __func__, ##__VA_ARGS__); \
        })

#define log_interface_full_errno(ifname, level, error, ...)             \
        ({                                                              \
                int _error = (error);                                   \
                ASSERT_NON_ZERO(_error);                                \
                log_interface_full_errno_zerook(ifname, level, _error, __VA_ARGS__); \
        })

/*
 * The following macros append INTERFACE= to the message.
 * The macros require a struct named 'Link' which contains 'char *ifname':
 *
 *         typedef struct Link {
 *                 char *ifname;
 *         } Link;
 *
 * See, network/networkd-link.h for example.
 */

#define log_link_full_errno_zerook(link, level, error, ...)             \
        ({                                                              \
                const Link *_l = (link);                                \
                log_interface_full_errno_zerook(_l ? _l->ifname : NULL, level, error, __VA_ARGS__); \
        })

#define log_link_full_errno(link, level, error, ...)                    \
        ({                                                              \
                int _error = (error);                                   \
                ASSERT_NON_ZERO(_error);                                \
                log_link_full_errno_zerook(link, level, _error, __VA_ARGS__); \
        })

#define log_link_full(link, level, ...) (void) log_link_full_errno_zerook(link, level, 0, __VA_ARGS__)

#define log_link_debug(link, ...)   log_link_full(link, LOG_DEBUG, __VA_ARGS__)
#define log_link_info(link, ...)    log_link_full(link, LOG_INFO, __VA_ARGS__)
#define log_link_notice(link, ...)  log_link_full(link, LOG_NOTICE, __VA_ARGS__)
#define log_link_warning(link, ...) log_link_full(link, LOG_WARNING, __VA_ARGS__)
#define log_link_error(link, ...)   log_link_full(link, LOG_ERR, __VA_ARGS__)

#define log_link_debug_errno(link, error, ...)   log_link_full_errno(link, LOG_DEBUG, error, __VA_ARGS__)
#define log_link_info_errno(link, error, ...)    log_link_full_errno(link, LOG_INFO, error, __VA_ARGS__)
#define log_link_notice_errno(link, error, ...)  log_link_full_errno(link, LOG_NOTICE, error, __VA_ARGS__)
#define log_link_warning_errno(link, error, ...) log_link_full_errno(link, LOG_WARNING, error, __VA_ARGS__)
#define log_link_error_errno(link, error, ...)   log_link_full_errno(link, LOG_ERR, error, __VA_ARGS__)

#define LOG_LINK_MESSAGE(link, fmt, ...) "MESSAGE=%s: " fmt, (link)->ifname, ##__VA_ARGS__
#define LOG_LINK_INTERFACE(link) "INTERFACE=%s", (link)->ifname
