/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "resolved-forward.h"

#define MDNS_PORT 5353
#define MDNS_ANNOUNCE_DELAY (1 * USEC_PER_SEC)
/* RFC 6762 section 10.1: the records of a goodbye packet expire one second after it was received.
 * This bounds how far ahead the goodbye timer looks: both the arm on receipt and the callback's
 * re-arm only take on an expiry that falls within it. */
#define MDNS_GOODBYE_DELAY (1 * USEC_PER_SEC)
/* Lower bound on the interval between two goodbye passes, so a burst of goodbyes cannot drive one
 * prune-and-reconcile pass per record. Delays a removal by at most this much. */
#define MDNS_GOODBYE_MIN_INTERVAL (MDNS_GOODBYE_DELAY / 4)

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

/* Exposed for testing only. */
bool mdns_answer_rewrite_goodbye_ttls(DnsAnswer *answer);
void mdns_goodbye_arm_on_receipt(DnsScope *scope);
/* 's' must be the scope's own goodbye source: the handler may release it, so a direct caller has to
 * hold a reference of its own to keep it alive across the call. */
int mdns_goodbye_callback(sd_event_source *s, uint64_t usec, void *userdata);
