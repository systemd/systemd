/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "sd-resolve.h"

int resolve_getaddrinfo_with_destroy_callback(
                sd_resolve *resolve, sd_resolve_query **q,
                const char *node, const char *service, const struct addrinfo *hints,
                sd_resolve_getaddrinfo_handler_t callback,
                sd_resolve_destroy_t destroy_callback, void *userdata);
int resolve_getnameinfo_with_destroy_callback(
                sd_resolve *resolve, sd_resolve_query **q,
                const struct sockaddr *sa, socklen_t salen, int flags, uint64_t get,
                sd_resolve_getnameinfo_handler_t callback,
                sd_resolve_destroy_t destroy_callback, void *userdata);

#define resolve_getaddrinfo(resolve, ret_query, node, service, hints, callback, destroy_callback, userdata) \
        ({                                                              \
                int (*_callback_)(sd_resolve_query*, int, const struct addrinfo*, typeof(userdata)) = callback; \
                void (*_destroy_)(typeof(userdata)) = destroy_callback; \
                resolve_getaddrinfo_with_destroy_callback(              \
                        resolve, ret_query,                             \
                        node, service, hints,                           \
                        (sd_resolve_getaddrinfo_handler_t) _callback_,  \
                        (sd_resolve_destroy_t) _destroy_,               \
                        userdata);                                      \
        })

#define resolve_getnameinfo(resolve, ret_query, sa, salen, flags, get, callback, destroy_callback, userdata) \
        ({                                                              \
                int (*_callback_)(sd_resolve_query*, int, const char*, const char*, typeof(userdata)) = callback; \
                void (*_destroy_)(typeof(userdata)) = destroy_callback; \
                resolve_getaddrinfo_with_destroy_callback(              \
                        resolve, ret_query,                             \
                        sa, salen, flags, get,                          \
                        (sd_resolve_getnameinfo_handler_t) _callback_,  \
                        (sd_resolve_destroy_t) _destroy_,               \
                        userdata);                                      \
        })
