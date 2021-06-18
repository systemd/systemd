/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

/***
  Copyright © 2014 Axis Communications AB. All rights reserved.
***/

#include <net/ethernet.h>

#include "socket-util.h"
#include "sparse-endian.h"

int arp_network_bind_raw_socket(int index, be32_t address, const struct ether_addr *eth_mac);

int arp_send_packet(
                int fd,
                int ifindex,
                be32_t pa,
                const struct ether_addr *ha,
                bool announce);
static inline int arp_send_probe(
                int fd,
                int ifindex,
                be32_t pa,
                const struct ether_addr *ha) {
        return arp_send_packet(fd, ifindex, pa, ha, false);
}
static inline int arp_send_announcement(
                int fd,
                int ifindex,
                be32_t pa,
                const struct ether_addr *ha) {
        return arp_send_packet(fd, ifindex, pa, ha, true);
}
