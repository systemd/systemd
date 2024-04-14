/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

/***
  Copyright © 2014-2015 Intel Corporation. All rights reserved.
***/

#include <net/ethernet.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <sys/uio.h>

#include "time-util.h"

#define IN6_ADDR_ALL_ROUTERS_MULTICAST                                  \
        ((const struct in6_addr) { { {                                  \
                0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,         \
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,         \
         } } } )

#define IN6_ADDR_ALL_NODES_MULTICAST                                    \
        ((const struct in6_addr) { { {                                  \
                0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,         \
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,         \
         } } } )

int icmp6_bind(int ifindex, bool is_router);
int icmp6_send(int fd, const struct in6_addr *dst, const struct iovec *iov, size_t n_iov);
int icmp6_receive(
                int fd,
                void *buffer,
                size_t size,
                struct in6_addr *ret_sender,
                triple_timestamp *ret_timestamp);
