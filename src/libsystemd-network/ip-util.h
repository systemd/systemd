/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "sd-forward.h"

#include "sparse-endian.h"

uint16_t ip_checksum(const void *buf, size_t len);

int udp_packet_build(
                be32_t source_addr,
                uint16_t source_port,
                be32_t destination_addr,
                uint16_t destination_port,
                int ip_service_type,
                const struct iovec *payload,
                struct iovec_wrapper *ret);
