/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <netinet/ip.h>
#include <netinet/udp.h>

#include "sd-forward.h"

#include "sparse-endian.h"

/* RFC 791
 * Fragmentation and Reassembly.
 * Every internet destination must be able to receive a datagram of 576 octets either in one piece or in
 * fragments to be reassembled. */
#define IPV4_MIN_REASSEMBLY_SIZE 576u

/* This is a maximal UDP payload size in a packet when its IP header does not contain options. When a packet
 * contains some IP options, then of course the allowed UDP payload size in the packet becomes smaller. */
#define UDP_PAYLOAD_MAX_SIZE (UINT16_MAX - sizeof(struct iphdr) - sizeof(struct udphdr))

uint16_t ip_checksum(const void *buf, size_t len);

int udp_packet_build(
                be32_t source_addr,
                uint16_t source_port,
                be32_t destination_addr,
                uint16_t destination_port,
                int ip_service_type,
                const struct iovec_wrapper *payload,
                struct iphdr *ret_iphdr,
                struct udphdr *ret_udphdr);

int udp_packet_verify(
                const struct iovec *packet,
                uint16_t port,
                bool checksum,
                struct iovec *ret_payload);
