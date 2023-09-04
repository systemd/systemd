/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

/***
  Copyright © 2014-2015 Intel Corporation. All rights reserved.
***/

#include <net/ethernet.h>

#include "time-util.h"

#define IN6ADDR_ALL_ROUTERS_MULTICAST_INIT \
        { { { 0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, \
              0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02 } } }

#define IN6ADDR_ALL_NODES_MULTICAST_INIT \
        { { { 0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, \
              0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 } } }

int icmp6_bind_router_solicitation(int ifindex);
int icmp6_bind_router_advertisement(int ifindex);
int icmp6_send_router_solicitation(int s, const struct ether_addr *ether_addr);
int icmp6_receive(
                int fd,
                void *buffer,
                size_t size,
                struct in6_addr *ret_sender,
                triple_timestamp *ret_timestamp);
