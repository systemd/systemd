/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <inttypes.h>

typedef struct Link Link;
typedef struct Request Request;

typedef enum SetLinkFlag {
        SET_LINK_MTU            = 1 << 0,
} SetLinkFlag;

int link_request_to_set_mtu(Link *link, uint32_t mtu);

int request_process_set_link(Request *req);
