/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "resolved-forward.h"

#define MDNS_PORT 5353
#define MDNS_ANNOUNCE_DELAY (1 * USEC_PER_SEC)

/* RFC 6762 § 17: "Even when fragmentation is used, a Multicast DNS packet, including IP and UDP
 * headers, MUST NOT exceed 9000 bytes." */
#define MDNS_PACKET_FRAGMENTED_SIZE_MAX 9000U

/* What to assume when the interface MTU is unknown: the largest datagram every host of the family
 * must accept without fragmentation -- RFC 791 section 3.1 for IPv4, RFC 8200 section 5's minimum
 * link MTU for IPv6. */
#define MDNS_PACKET_UNKNOWN_MTU_IPV4 576U
#define MDNS_PACKET_UNKNOWN_MTU_IPV6 1280U

int manager_mdns_ipv4_fd(Manager *m);
int manager_mdns_ipv6_fd(Manager *m);

void manager_mdns_stop(Manager *m);
void manager_mdns_maybe_stop(Manager *m);
int manager_mdns_start(Manager *m);

void mdns_announcement_max_sizes(
                int family,
                size_t link_mtu,
                size_t *ret_max_size,
                size_t *ret_fragmented_max);
int mdns_announcement_packetize(
                DnsAnswer *answer,
                size_t max_size,
                size_t fragmented_max,
                DnsPacket ***ret_packets,
                size_t *ret_n_packets);
