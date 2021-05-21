/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <inttypes.h>

typedef struct Link Link;
typedef struct Request Request;

typedef enum SetLinkMode {
        SET_LINK_FLAGS, /* Setting IFF_NOARP or friends. */
        SET_LINK_MTU, /* Setting MTU. */
        _SET_LINK_MODE_MAX,
        _SET_LINK_MODE_INVALID = -EINVAL,
} SetLinkMode;

int link_request_to_set_flags(Link *link);
int link_request_to_set_mtu(Link *link, uint32_t mtu);

int request_process_set_link(Request *req);
