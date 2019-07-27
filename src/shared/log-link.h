/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include "log.h"

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

#define log_link_full(link, level, error, ...)                          \
        ({                                                              \
                const Link *_l = (link);                                \
                (_l && _l->ifname) ? log_object_internal(level, error, PROJECT_FILE, __LINE__, __func__, "INTERFACE=", _l->ifname, NULL, NULL, ##__VA_ARGS__) : \
                        log_internal(level, error, PROJECT_FILE, __LINE__, __func__, ##__VA_ARGS__); \
        })                                                              \

#define log_link_debug(link, ...)   log_link_full(link, LOG_DEBUG, 0, ##__VA_ARGS__)
#define log_link_info(link, ...)    log_link_full(link, LOG_INFO, 0, ##__VA_ARGS__)
#define log_link_notice(link, ...)  log_link_full(link, LOG_NOTICE, 0, ##__VA_ARGS__)
#define log_link_warning(link, ...) log_link_full(link, LOG_WARNING, 0, ##__VA_ARGS__)
#define log_link_error(link, ...)   log_link_full(link, LOG_ERR, 0, ##__VA_ARGS__)

#define log_link_debug_errno(link, error, ...)   log_link_full(link, LOG_DEBUG, error, ##__VA_ARGS__)
#define log_link_info_errno(link, error, ...)    log_link_full(link, LOG_INFO, error, ##__VA_ARGS__)
#define log_link_notice_errno(link, error, ...)  log_link_full(link, LOG_NOTICE, error, ##__VA_ARGS__)
#define log_link_warning_errno(link, error, ...) log_link_full(link, LOG_WARNING, error, ##__VA_ARGS__)
#define log_link_error_errno(link, error, ...)   log_link_full(link, LOG_ERR, error, ##__VA_ARGS__)

#define LOG_LINK_MESSAGE(link, fmt, ...) "MESSAGE=%s: " fmt, (link)->ifname, ##__VA_ARGS__
#define LOG_LINK_INTERFACE(link) "INTERFACE=%s", (link)->ifname
