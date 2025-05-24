/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "forward.h"
#include "sparse-endian.h"

int dhcp_network_bind_raw_socket(
                int ifindex,
                union sockaddr_union *link,
                uint32_t xid,
                const struct hw_addr_data *hw_addr,
                const struct hw_addr_data *bcast_addr,
                uint16_t arp_type,
                uint16_t port,
                bool so_priority_set,
                int so_priority);
int dhcp_network_bind_udp_socket(
                int ifindex,
                be32_t address,
                uint16_t port,
                int ip_service_type);
int dhcp_network_send_raw_socket(
                int s,
                const union sockaddr_union *link,
                const void *packet,
                size_t len);
int dhcp_network_send_udp_socket(
                int s,
                be32_t address,
                uint16_t port,
                const void *packet,
                size_t len);
