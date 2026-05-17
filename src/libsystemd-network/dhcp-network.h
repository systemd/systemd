/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "sd-forward.h"
#include "sparse-endian.h"

int dhcp_network_bind_udp_socket(
                int ifindex,
                be32_t address,
                uint16_t port,
                int ip_service_type);
int dhcp_network_send_raw_socket(
                int fd,
                const union sockaddr_union *link,
                const struct iovec_wrapper *iovw);
