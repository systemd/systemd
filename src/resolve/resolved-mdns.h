/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "resolved-forward.h"

#define MDNS_PORT 5353
/* RFC 6762 § 8.3: unsolicited announcements are to be sent at least twice, one second apart. That
 * repetition covers goodbyes, so this spaces the withdrawal retransmissions as well as the initial
 * announcement pair -- which a goodbye does not join, see dns_scope_announce(). */
#define MDNS_ANNOUNCE_DELAY (1 * USEC_PER_SEC)

/* RFC 6762 § 17: "Even when fragmentation is used, a Multicast DNS packet, including IP and UDP
 * headers, MUST NOT exceed 9000 bytes." */
#define MDNS_PACKET_FRAGMENTED_SIZE_MAX 9000U

int manager_mdns_ipv4_fd(Manager *m);
int manager_mdns_ipv6_fd(Manager *m);

void manager_mdns_stop(Manager *m);
void manager_mdns_maybe_stop(Manager *m);
int manager_mdns_start(Manager *m);

int mdns_enumeration_service_ptr_new(const char *service_type, DnsResourceRecord **ret);
