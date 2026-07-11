/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "resolved-forward.h"

#define MDNS_PORT 5353
/* RFC 6762 § 8.3: unsolicited announcements are to be sent at least twice, one second apart. That
 * repetition covers goodbyes, so this spaces the withdrawal retransmissions as well as the initial
 * announcement pair -- which a goodbye does not join, see dns_scope_announce(). */
#define MDNS_ANNOUNCE_DELAY (1 * USEC_PER_SEC)

/* RFC 6762 section 17: "Even when fragmentation is used, a Multicast DNS packet, including IP and UDP
 * headers, MUST NOT exceed 9000 bytes." */
#define MDNS_PACKET_FRAGMENTED_SIZE_MAX 9000U

/* What to assume while the interface MTU is not known yet: the datagram size every host of the
 * family must be able to accept, RFC 791 section 3.1 -- whole or reassembled from fragments. (For
 * IPv6 the corresponding bound is IPV6_MIN_MTU, RFC 8200 section 5's minimum link MTU, which is a
 * stronger guarantee: no link fragments a datagram that size.) */
#define MDNS_PACKET_UNKNOWN_MTU_IPV4 576U

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
